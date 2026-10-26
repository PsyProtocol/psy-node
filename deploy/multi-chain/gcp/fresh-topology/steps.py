#!/usr/bin/env python3
"""Plan or run one split-fleet fresh-deployment step. No implicit reset or VM resize."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
PROFILE = HERE.parent
ROOT = PROFILE.parents[2]
ORDER = ("12-coordinator-edges", "12-realm0-edges", "12-realm1-edges",
         "12-coordinator-processor", "12-realm0-processor", "12-realm1-processor",
         "12-services", "12-indexers", "13-faucet", "14-workers", "16-relayer", "17-caddy")
PRIVATE_NETS = tuple(ipaddress.ip_network(cidr) for cidr in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validate(t):
    if t["schema_version"] != 1 or t["mode"] != "fresh-same-fleet":
        raise ValueError("unsupported topology schema/mode")
    for name, host in t["hosts"].items():
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", name):
            raise ValueError("invalid SSH host alias")
        if host["ip"] is not None:
            address = ipaddress.ip_address(host["ip"])
            if not any(address in net for net in PRIVATE_NETS):
                raise ValueError(f"non-private address: {name}")
    if [r["id"] for r in t["realms"]] != [0, 1]:
        raise ValueError("this profile requires realms 0 and 1")
    if t["chains"] != [dict(name="sepolia", index=0, chain_id=11155111),
                       dict(name="bscTestnet", index=1, chain_id=97),
                       dict(name="baseSepolia", index=2, chain_id=84532)]:
        raise ValueError("chain index / chain ID mapping changed")
    sockets, units = set(), set()
    for role, group in [("coordinator", t["coordinator"])] + [
            ("realm", r) for r in t["realms"]]:
        if not group["edges"]:
            raise ValueError("empty edge pool")
        for edge in group["edges"]:
            host = edge["host"]
            if host not in t["hosts"] or t["hosts"][host]["ip"] is None:
                raise ValueError("edge needs an explicit private IP")
            if not re.fullmatch(r"[0-9]+", edge["instance"]):
                raise ValueError("invalid edge instance")
            if type(edge["port"]) is not int or not 1024 <= edge["port"] <= 65535:
                raise ValueError("invalid edge port")
            socket = (host, edge["port"])
            unit = (host, role, edge["instance"])
            if socket in sockets or unit in units:
                raise ValueError("duplicate edge socket or systemd instance")
            sockets.add(socket)
            units.add(unit)
        for key in ("processor", "indexer"):
            if group[key] not in t["hosts"]:
                raise ValueError(f"unknown {key} host")
    for entry in (t["services"], t["faucet"], t["workers"], t["relayer"]):
        if entry["host"] not in t["hosts"]:
            raise ValueError("unknown service host")
    for host in t["infrastructure"].values():
        if host not in t["hosts"] or t["hosts"][host]["ip"] is None:
            raise ValueError("infrastructure needs a private IP")
    for name in ("coordinator", "realm_0", "realm_1"):
        count = t["workers"][name]
        if type(count) is not int or not 1 <= count <= 32:
            raise ValueError("worker count out of range")
    keys = t["workers"].get("key_indexes")
    expected_workers = {f"coordinator-{i}" for i in range(t["workers"]["coordinator"])}
    expected_workers.update(f"realm-{r}-{i}" for r in (0, 1)
                            for i in range(t["workers"][f"realm_{r}"]))
    if keys is not None and (not isinstance(keys, dict) or set(keys) != expected_workers
                             or any(type(k) is not int or k < 0 for k in keys.values())):
        raise ValueError("worker key_indexes must explicitly map every worker to a Genesis key index")
    weights = t["proxies"]["user_weights"]
    if any(h not in t["hosts"] or type(w) is not int or w < 0 for h, w in weights.items()):
        raise ValueError("invalid user proxy weights")
    if sum(weights.values()) != 100:
        raise ValueError("user proxy weights must total 100")
    if any(w and h not in t["proxies"]["installed_user_hosts"] for h, w in weights.items()):
        raise ValueError("weighted user proxy is not installed")
    for h in [t["proxies"]["user_entry"], t["proxies"]["system_host"],
              *t["proxies"]["installed_user_hosts"]]:
        if h not in t["hosts"]:
            raise ValueError("unknown proxy host")


def address(t, host):
    value = t["hosts"][host]["ip"]
    if value is None:
        raise ValueError(f"missing private IP: {host}")
    return value


def edge_urls(t, group):
    return [f'http://{address(t, e["host"])}:{e["port"]}' for e in group["edges"]]


def shared(t):
    infra = t["infrastructure"]
    ip = lambda role: address(t, infra[role])
    return {
        "SCYLLA_HOST": ip("scylla"), "SCYLLA_DB_URL": ip("scylla") + ":9042",
        "REDIS_HOST": ip("redis"), "REDIS_URL": "redis://" + ip("redis") + ":6379",
        "PSY_SERVICES_REDIS_URL": "redis://" + ip("redis") + ":6379",
        "NATS_HOST": ip("nats"), "NATS_JETSTREAM_URL": "nats://" + ip("nats") + ":4222",
        "POSTGRES_HOST": ip("postgres"), "POSTGRES_VM_NAME": infra["postgres"],
        "ENVIO_HOST": ip("envio"), "ENVIO_VM_NAME": infra["envio"],
        "INDEXER_GRAPHQL_URL": "http://" + ip("envio") + ":18080/v1/graphql",
        "PSY_NODE_URL": edge_urls(t, t["coordinator"])[0],
        "PSY_SERVICES_URL": f'http://{address(t, t["services"]["host"])}:{t["services"]["port"]}',
        "NOSTR_VM_NAME": infra["caddy"],
        "PROVE_PROXY_HOST": ip("gateway"),
        "FAUCET_HOST": address(t, t["faucet"]["host"]),
    }


def operations(t):
    result = {s: [] for s in ORDER}

    def add(step, script, host, **env):
        result[step].append({"script": script, "host": host,
                             "env": {**shared(t), "NODE_VM_NAME": host,
                                     **{k: str(v) for k, v in env.items()}}})

    c = t["coordinator"]
    for e in c["edges"]:
        add("12-coordinator-edges", "deploy-coordinator-edge.sh", e["host"],
            DEPLOY_INSTANCE=e["instance"], COORDINATOR_EDGE_PORT=e["port"],
            COORDINATOR_EDGE_HEALTHCHECK_JSONRPC_URL=f'http://{address(t, e["host"])}:{e["port"]}',
            COORDINATOR_ID=0, COORDINATOR_SUB_ID=0, COORDINATOR_DB_NAMESPACE="coordinator",
            LISTEN_ADDR=address(t, e["host"]))
    add("12-coordinator-processor", "deploy-coordinator-processor.sh", c["processor"],
        COORDINATOR_ID=0, COORDINATOR_SUB_ID=0, COORDINATOR_DB_NAMESPACE="coordinator")
    add("12-indexers", "deploy-psy-indexer.sh", c["indexer"], DEPLOY_INSTANCE="coordinator",
        PSY_INDEXER_MODE="coordinator", PSY_EDGE_RPC_URL=edge_urls(t, c)[0])
    for r in t["realms"]:
        rid = r["id"]
        env = dict(REALM_ID=rid, REALM_SUB_ID=r["sub_id"], REALM_DB_NAMESPACE=f"realm_{rid}")
        for e in r["edges"]:
            add(f"12-realm{rid}-edges", "deploy-realm-edge.sh", e["host"], **env,
                DEPLOY_INSTANCE=e["instance"], REALM_EDGE_PORT=e["port"],
                REALM_EDGE_HEALTHCHECK_JSONRPC_URL=f'http://{address(t, e["host"])}:{e["port"]}',
                LISTEN_ADDR=address(t, e["host"]))
        add(f"12-realm{rid}-processor", "deploy-realm-processor.sh", r["processor"], **env,
            DEPLOY_INSTANCE=rid, COORDINATOR_API_URLS=",".join(edge_urls(t, c)))
        add("12-indexers", "deploy-psy-indexer.sh", r["indexer"], **env,
            DEPLOY_INSTANCE=f"realm-{rid}", PSY_INDEXER_MODE="realm",
            PSY_EDGE_RPC_URL=edge_urls(t, r)[0])
    add("12-services", "deploy-psy-services.sh", t["services"]["host"],
        PSY_SERVICES_PORT=t["services"]["port"])
    f = t["faucet"]
    add("13-faucet", "deploy-faucet-server.sh", f["host"], FAUCET_VM_NAME=f["host"],
        PSY_FAUCET_PORT=f["port"], PSY_FAUCET_LISTEN_ADDR=f'{address(t, f["host"])}:{f["port"]}')
    w = t["workers"]
    for role, group, count in [("coordinator", c, w["coordinator"])] + [
            ("realm", r, w[f'realm_{r["id"]}']) for r in t["realms"]]:
        for i in range(count):
            rid = group.get("id", 0)
            instance = f"coordinator-{i}" if role == "coordinator" else f"realm-{rid}-{i}"
            identity = {"WORKER_KEY_INDEX": w["key_indexes"][instance]} if w.get("key_indexes") is not None else {}
            add("14-workers", "deploy-worker.sh", w["host"], WORKER_VM_NAME=w["host"],
                **identity,
                WORKER_ROLE=role, WORKER_INDEX=i, REALM_ID=rid, DEPLOY_INSTANCE=instance,
                COORDINATOR_API_URLS=",".join(edge_urls(t, c)) if role == "coordinator" else "",
                REALM_API_URLS=",".join(edge_urls(t, group)) if role == "realm" else "",
                COMPLETED_JOBS_LOG_FILE=f"/var/lib/parth/checkpoints/{instance}.backup")
    add("16-relayer", "deploy-relayer.sh", t["relayer"]["host"],
        RELAYER_VM_NAME=t["relayer"]["host"],
        RELAYER_MAX_CHECKPOINT_BATCH=t["relayer"]["batch_size"],
        RELAYER_SERVICES_URL=shared(t)["PSY_SERVICES_URL"])
    upstream = lambda group: " ".join(u.removeprefix("http://") for u in edge_urls(t, group))
    add("17-caddy", "create-nostr.sh", t["infrastructure"]["caddy"],
        PUBLIC_COORDINATOR_UPSTREAM=upstream(c), PUBLIC_REALM_UPSTREAM=upstream(t["realms"][0]),
        PUBLIC_REALM1_UPSTREAM=upstream(t["realms"][1]),
        PUBLIC_PSY_SERVICES_UPSTREAM=f'{address(t, t["services"]["host"])}:{t["services"]["port"]}',
        PUBLIC_FAUCET_UPSTREAM=f'{address(t, f["host"])}:{f["port"]}',
        PUBLIC_INDEXER_UPSTREAM=f'{address(t, t["infrastructure"]["envio"])}:18080',
        PUBLIC_PROVE_PROXY_UPSTREAM=f'{address(t, t["infrastructure"]["gateway"])}:19999')
    return result


def overlay(config, env):
    # Applied AFTER the private config on every nested source, not just exported:
    # the legacy installers source config.env again and can overwrite exports.
    return "source " + shlex.quote(str(config)) + "\n" + "\n".join(
        "export " + k + "=" + shlex.quote(v) for k, v in sorted(env.items())) + "\n"


def check_private_config(env):
    # Reject even DNS aliases here: the reviewed topology uses explicit VPC IPs.
    # Report variable names only, never URLs containing passwords.
    for key in ("SCYLLA_DB_URL", "REDIS_URL", "NATS_JETSTREAM_URL",
                "PSY_SERVICES_REDIS_URL", "PSY_SERVICES_DATABASE_URL",
                "ENVIO_DATABASE_URL", "POSTGRES_HOST", "ENVIO_PG_HOST",
                "INDEXER_GRAPHQL_URL"):
        value = env.get(key, "")
        if not value:
            continue
        try:
            hostname = urlsplit(value if "://" in value else "tcp://" + value).hostname
            address = ipaddress.ip_address(hostname)
            if not any(address in net for net in PRIVATE_NETS):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError(f"{key} must use an explicit private database/queue endpoint") from None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("step", choices=(*ORDER, "12-nodes", "plan", "readiness", "check-private-config"))
    p.add_argument("--topology", type=Path, default=HERE / "topology.json")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--config", type=Path)
    p.add_argument("--versions", type=Path)
    args = p.parse_args()
    if args.step == "check-private-config":
        check_private_config(os.environ)
        return 0
    t = json.loads(args.topology.read_text())
    validate(t)
    ops = operations(t)
    if args.step == "readiness":
        for item in t["release_blockers"]:
            print("BLOCKED: " + item)
        return 2 if t["release_blockers"] else 0
    selected = (ORDER if args.step == "plan" else
                [s for s in ORDER if s.startswith("12-")] if args.step == "12-nodes" else [args.step])
    for step in selected:
        for op in ops[step]:
            print(f'{step}: {op["host"]} -> {op["script"]} '
                  f'instance={op["env"].get("DEPLOY_INSTANCE", "singleton")}', flush=True)
    if not args.apply:
        print("PLAN ONLY: no SSH, build, reset, deployment or config sourcing performed.")
        return 0
    if args.step == "plan":
        p.error("run one named step at a time; plan cannot apply")
    if t["release_blockers"]:
        p.error("fresh release is not ready; resolve documented blockers before activation")
    if "14-workers" in selected and t["workers"].get("key_indexes") is None:
        p.error("worker key_indexes require explicit confirmation against the new Genesis")
    if os.environ.get("CONFIRM_FULL_FRESH_DEPLOY") != "1":
        p.error("CONFIRM_FULL_FRESH_DEPLOY=1 is required; never use this for a hotfix")
    if not args.config or not args.versions:
        p.error("--config and --versions are required; no historical source-pin fallback")
    config, versions = args.config.resolve(strict=True), args.versions.resolve(strict=True)
    env = dict(os.environ, GCP_DEPLOY_CONFIG=str(config), DEPLOY_SOURCE_VERSIONS_FILE=str(versions))
    subprocess.run(["bash", str(PROFILE / "preflight.sh")], env=env, check=True)
    for step in selected:
        for op in ops[step]:
            with tempfile.TemporaryDirectory(prefix="psy-topology-") as directory:
                path = Path(directory) / "config.env"
                path.write_text(overlay(config, op["env"]))
                path.chmod(0o600)
                # Some legacy installers capture these inputs BEFORE sourcing
                # config, then restore them. Override both channels consistently.
                component_env = dict(env, **op["env"], GCP_DEPLOY_CONFIG=str(path))
                subprocess.run(["bash", "-c", 'set -a; source "$1"; exec python3 "$2" check-private-config',
                                "validate", str(path), str(HERE / "steps.py")], env=component_env, check=True)
                subprocess.run(["bash", str(ROOT / "deploy/gcp" / op["script"])],
                               env=component_env, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
