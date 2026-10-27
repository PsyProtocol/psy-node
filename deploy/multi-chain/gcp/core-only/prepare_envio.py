#!/usr/bin/env python3
"""Prepare isolated Envio inputs locally; never install, connect to a DB or start services."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit

import yaml

from prepare_host_packages import publish_packages, write_new


SOURCE = "da6391549e44d49c07e856eaeb5d0b8d7902ef17"
SOURCE_DIR = "psy_cli/psy_relayer_cli/indexer/envio"
SOURCE_FILES = ("package.json", "handlers.ts", "schema.graphql", "schema.ts",
                "envio-env.d.ts", "pnpm-workspace.yaml", "config.template.yaml")
PATCHES = {
    "history.py": "39ba5c386edad2e4dfa5a191160ac8abd995afdd0215337309ac605d332b9a64",
    "polling.py": "0b929faf38cf8fd1d40fccdf8ec743174ec12f252cec4a2660884c048bdf2ac9",
    "ordered.py": "846f282659a65bb33f44a11b0c5e0fd992b58a082dba1ae35ac5a113a76154a6",
    "reorg.py": "8739c575630a57d831cd4063f48033ffc7c8c27dde62ace310ec22e5f0e1bebf",
    "deposit-indexes.py": "c2fcf5d23d3568706f2fc5b263b92dc52821dba96e30effbb232cf723d634711",
}
CHAINS = {"sepolia": (0, 11155111, 8), "bscTestnet": (1, 97, 200), "baseSepolia": (2, 84532, 64)}
DATABASE = "envio_bridge_fresh_20261027_r3"
PROJECT = "psy-envio-fresh-20261027-r3"
RELEASE = "/opt/psy-envio/releases/core-testnet-20261027-r3"
L1_DOCUMENT_ROOT = "psy-fresh20261027r3b"
RPC_URLS = {name: f"http://10.148.0.32:{port}" for name, port in
            zip(CHAINS, (18545, 18645, 18945))}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def read(path, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute input path required")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink input rejected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 16 * 1024 * 1024, "invalid input file")
        if private:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    "operator spec must be owned by this user and mode 0600")
        raw = stream.read(16 * 1024 * 1024 + 1)
        require(len(raw) <= 16 * 1024 * 1024, "input size exceeded")
        return raw


def artifact(value):
    require(isinstance(value, dict) and set(value) == {"path", "sha256"}, "artifact fields mismatch")
    raw = read(value["path"])
    require(digest(raw) == value["sha256"], "artifact hash mismatch")
    return raw


def source_files(repo):
    result = {}
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    for name in SOURCE_FILES:
        process = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "show", f"{SOURCE}:{SOURCE_DIR}/{name}"],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        result[name] = process.stdout
    require(json.loads(result["package.json"])["devDependencies"]["envio"] == "2.32.10",
            "unexpected Envio dependency")
    return result


def private_ip(value):
    address = ipaddress.IPv4Address(value)
    require(isinstance(value, str) and str(address) == value and any(address in ipaddress.ip_network(cidr)
            for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")), "RFC1918 IPv4 required")
    return value


def port(value):
    require(type(value) is int and 1024 <= value <= 65535, "invalid private port")
    return value


def validate_placement(value):
    require(set(value) == {"postgres_host", "postgres_port", "postgres_user", "hasura_bind",
                           "hasura_port", "indexer_port"}, "placement fields mismatch")
    private_ip(value["postgres_host"])
    private_ip(value["hasura_bind"])
    for key in ("postgres_port", "hasura_port", "indexer_port"):
        port(value[key])
    require(len({value[key] for key in ("postgres_port", "hasura_port", "indexer_port")}) == 3
            and value["hasura_port"] == 38081
            and value["indexer_port"] == 29899, "fresh r3 ports required")
    require(isinstance(value["postgres_user"], str)
            and re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", value["postgres_user"])
            and value["postgres_user"] != "postgres", "dedicated database role required")


def validate_routes(routes):
    require(set(routes) == set(CHAINS), "all three RPC routes required")
    for name, route in routes.items():
        require(set(route) == {"urls", "confirmed_block_threshold"}, "RPC route fields mismatch")
        urls = route["urls"]
        require(urls == [RPC_URLS[name]], "only the protected Alchemy forward is allowed; no node fallback")
        for url in urls:
            require(isinstance(url, str) and not any(c.isspace() for c in url), "invalid RPC URL")
            parsed = urlsplit(url)
            require(parsed.scheme in ("http", "https") and not parsed.username and not parsed.password
                    and not parsed.query and not parsed.fragment and "$" not in url, "private credential-free RPC required")
            private_ip(parsed.hostname)
            if parsed.port is not None:
                port(parsed.port)
        depth = route["confirmed_block_threshold"]
        require(type(depth) is int and CHAINS[name][2] <= depth <= 10000, "reorg window below reviewed minimum")


def l1_files(documents):
    require(set(documents) == set(CHAINS), "three complete real L1 document sets required")
    files, networks = {}, []
    roots = set()
    for name, (index, chain_id, _) in CHAINS.items():
        row = documents[name]
        require(set(row) == {"summary", "bridge_receipt", "state_manager_receipt"}, "L1 document fields mismatch")
        for descriptor in row.values():
            path = Path(descriptor["path"])
            require(path.parent.name == name and path.parent.parent.name == "deployments"
                    and path.parent.parent.parent.name == L1_DOCUMENT_ROOT,
                    "final r3b deployment documents required; partial/old cohort rejected")
            roots.add(path.parent.parent.parent)
        require(len(roots) == 1, "mixed deployment document roots rejected")
        raw = {key: artifact(value) for key, value in row.items()}
        summary = json.loads(raw["summary"])
        chain = summary["protocol"]["chain"]
        require(summary["network"] == name and str(summary["chainId"]) == str(chain_id)
                and str(chain["l1ChainId"]) == str(chain_id)
                and type(chain["l1ChainIndex"]) is int and chain["l1ChainIndex"] == index, "L1 network mismatch")
        contracts, blocks = [], []
        for contract, field in (("Bridge", "bridge_receipt"), ("StateManager", "state_manager_receipt")):
            receipt = json.loads(raw[field])
            address = summary["core"][contract]
            require(isinstance(address, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", address)
                    and int(address, 16) != 0 and receipt["address"].lower() == address.lower()
                    and summary["contracts"][contract].lower() == address.lower()
                    and summary["proxies"][contract + "_Proxy"].lower() == address.lower(), "L1 address mismatch")
            mined = receipt["receipt"]
            require(type(mined["status"]) is int and mined["status"] == 1
                    and type(mined["blockNumber"]) is int and 0 < mined["blockNumber"] < 2**53
                    and re.fullmatch(r"0x[0-9a-fA-F]{64}", mined["transactionHash"])
                    and int(mined["transactionHash"], 16) != 0, "successful mined receipt required")
            require(mined["contractAddress"].lower() == address.lower() and mined["to"] is None
                    and receipt["transactionHash"].lower() == mined["transactionHash"].lower(),
                    "proxy creation receipt required")
            if contract == "Bridge":
                require(type(summary["deploymentBlock"]) is int
                        and summary["deploymentBlock"] == mined["blockNumber"], "exported Bridge deployment block mismatch")
            blocks.append(mined["blockNumber"])
            contracts.append({"name": contract, "address": [address]})
        require(contracts[0]["address"] != contracts[1]["address"], "distinct proxy addresses required")
        networks.append({"id": chain_id, "start_block": min(blocks), "contracts": contracts})
        # Publish only verified public fields, never arbitrary deployment output.
        public_summary = {key: summary[key] for key in ("network", "chainId", "deploymentBlock")}
        public_summary.update({"protocol": {"chain": {"l1ChainId": chain_id, "l1ChainIndex": index}},
                               "core": {key: summary["core"][key] for key in ("Bridge", "StateManager")}})
        files[f"l1/{name}/summary.json"] = encode(public_summary)
        for key in ("bridge_receipt", "state_manager_receipt"):
            receipt = json.loads(raw[key])
            files[f"l1/{name}/{key}.json"] = encode({
                "address": receipt["address"], "transactionHash": receipt["transactionHash"],
                "receipt": {field: receipt["receipt"][field] for field in
                            ("status", "blockNumber", "contractAddress", "to", "transactionHash")}})
        files[f"l1/{name}/source-hashes.json"] = encode({key: digest(value) for key, value in raw.items()})
    return files, networks


def config_bytes(template, networks, routes):
    config = yaml.safe_load(template)
    config["name"] = PROJECT
    config["networks"] = networks
    for name, network in zip(CHAINS, networks):
        route = routes[name]
        network["confirmed_block_threshold"] = route["confirmed_block_threshold"]
        network["rpc"] = [{"url": url, "for": "sync" if i == 0 else "fallback",
                           "initial_block_interval": 50000, "backoff_multiplicative": 0.8,
                           "acceleration_additive": 10000, "interval_ceiling": 100000,
                           "backoff_millis": 5000, "fallback_stall_timeout": 10000,
                           "query_timeout_millis": 20000} for i, url in enumerate(route["urls"])]
    return yaml.safe_dump(config, sort_keys=False).encode()


def compose(value):
    database_url = (f'postgresql://{value["postgres_user"]}:'
                    '${ENVIO_POSTGRES_PASSWORD_ENCODED:?URL-encoded private password required}'
                    f'@{value["postgres_host"]}:{value["postgres_port"]}/{DATABASE}')
    return {"name": PROJECT, "services": {"graphql-engine": {
        "image": "hasura/graphql-engine:v2.43.0", "user": "1001:1001", "restart": "no",
        "ports": [{"target": 8080, "published": str(value["hasura_port"]), "host_ip": value["hasura_bind"], "protocol": "tcp"}],
        "ulimits": {"nofile": {"soft": 65536, "hard": 524288}},
        "logging": {"driver": "json-file", "options": {"max-size": "100m", "max-file": "100", "compress": "true"}},
        "environment": {"HASURA_GRAPHQL_DATABASE_URL": database_url,
                        "HASURA_GRAPHQL_METADATA_DATABASE_URL": database_url,
                        "HASURA_GRAPHQL_ADMIN_SECRET": "${HASURA_GRAPHQL_ADMIN_SECRET:?private secret required}",
                        "HASURA_GRAPHQL_ENABLE_CONSOLE": "false", "HASURA_GRAPHQL_STRINGIFY_NUMERIC_TYPES": "true",
                        "HASURA_GRAPHQL_UNAUTHORIZED_ROLE": "public", "HASURA_GRAPHQL_NO_OF_RETRIES": "10"}}}}


def build_files(spec, repo):
    require(set(spec) == {"version", "patches", "dependency_lock", "placement", "rpc_routes", "l1_documents"}
            and type(spec["version"]) is int and spec["version"] == 1, "operator spec fields mismatch")
    files = source_files(repo)
    source_hashes = {name: digest(raw) for name, raw in files.items()}
    require(set(spec["patches"]) == set(PATCHES), "all five pinned patch inputs required")
    for name, expected in PATCHES.items():
        raw = artifact(spec["patches"][name])
        require(digest(raw) == expected, "reviewed patch mismatch")
        files[f"patches/{name}"] = raw
    if spec["dependency_lock"] is not None:
        raw = artifact(spec["dependency_lock"])
        lock = yaml.safe_load(raw)
        package = json.loads(files["package.json"])
        require(str(lock["lockfileVersion"]) == "9.0" and set(lock["importers"]) == {"."}, "source-only pnpm lock required")
        require(not lock.get("overrides") and not lock.get("patchedDependencies"), "unexpected dependency overrides")
        for kind in ("dependencies", "devDependencies"):
            require({key: value["specifier"] for key, value in lock["importers"]["."][kind].items()}
                    == package[kind], "lock does not match pinned package")
        files["pnpm-lock.yaml"] = raw
    if spec["rpc_routes"]:
        validate_routes(spec["rpc_routes"])
    if spec["placement"] is not None:
        value = spec["placement"]
        validate_placement(value)
        files["compose.hasura.json"] = encode(compose(value))
        environment = {
            "ENVIO_PG_HOST": value["postgres_host"], "ENVIO_PG_PORT": str(value["postgres_port"]),
            "ENVIO_PG_USER": value["postgres_user"], "ENVIO_PG_DATABASE": DATABASE,
            "ENVIO_PG_PUBLIC_SCHEMA": "envio", "ENVIO_PG_SSL_MODE": "false", "ENVIO_HASURA": "true",
            "ENVIO_INDEXER_PORT": str(value["indexer_port"]), "TUI_OFF": "true",
            "HASURA_GRAPHQL_ENDPOINT": f'http://{value["hasura_bind"]}:{value["hasura_port"]}/v1/metadata',
            "ENVIO_RPC_POLLING_INTERVAL_MILLIS": "12000", "PSY_ENVIO_FRESH_REORG_PARENT": "1"}
        if spec["rpc_routes"]:
            environment["PSY_ENVIO_ORDERED_FAILOVER"] = "1" if any(len(r["urls"]) > 1 for r in spec["rpc_routes"].values()) else "0"
        files["runtime-env.json"] = encode(environment)
    if spec["l1_documents"]:
        require(bool(spec["rpc_routes"]), "L1 configuration requires all private RPC routes")
        documents, networks = l1_files(spec["l1_documents"])
        files.update(documents)
        files["config.yaml"] = config_bytes(files["config.template.yaml"], networks, spec["rpc_routes"])
    report = {"source_commit": SOURCE, "source_files": source_hashes, "database": DATABASE,
              "l1_document_cohort": L1_DOCUMENT_ROOT, "rpc_policy": "protected-alchemy-only-no-fallback",
              "compose_project": PROJECT, "release_path": RELEASE, "unit_name": PROJECT + ".service",
              "l1_documents_pending": not bool(spec["l1_documents"]),
              "placement_pending": spec["placement"] is None, "rpc_routes_pending": not bool(spec["rpc_routes"]),
              "dependency_lock_pending": spec["dependency_lock"] is None,
              "dependencies_built": False, "patches_applied": False, "database_created": False,
              "installed": False, "started": False, "deployment_ready": False, "release_approved": False,
              "files": {name: digest(raw) for name, raw in files.items()}}
    files["manifest.json"] = encode(report)
    return files, report


def prepare(args):
    raw = read(args.spec, private=True)
    require(digest(raw) == args.spec_sha256, "operator spec pin mismatch")
    files, report = build_files(json.loads(raw), args.source_repo)
    output = args.output.absolute()
    require(".." not in output.parts and not os.path.lexists(output), "new output directory required")
    for parent in (output.parent, *output.parent.parents):
        require(not parent.is_symlink(), "symlink output ancestor rejected")
        require(not (parent / ".git/HEAD").exists() and not (parent / ".git").is_file(), "output must be outside Git")
    stage = Path(tempfile.mkdtemp(prefix=".envio-prepare-", dir=output.parent))
    try:
        for name, content in files.items():
            write_new(stage / name, content)
        publish_packages(stage, output)
    except BaseException:
        shutil.rmtree(stage)
        raise
    return {key: report[key] for key in ("source_commit", "database", "l1_documents_pending",
                                        "dependencies_built", "installed", "started", "deployment_ready", "release_approved")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(prepare(args), sort_keys=True))
    except Exception:
        raise SystemExit("Envio prepare refused; no existing output replaced") from None


if __name__ == "__main__":
    main()
