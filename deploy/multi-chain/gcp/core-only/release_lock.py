#!/usr/bin/env python3
"""Validate the release lock that pins every deployment constant; never touches a host."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


HERE = Path(__file__).resolve().parent
MAX_BYTES = 4 * 1024 * 1024
TOP_LEVEL = ("schema_version", "release_id", "network", "network_magic", "inputs", "sources", "binaries", "paths",
             "units", "hosts", "services", "envio", "faucet", "images", "groth16", "l1", "ingress", "gates",
             "tool_sha256")
INPUTS = ("release_profile", "topology", "artifacts", "runtime_config", "canonical_config", "genesis",
          "worker_whitelist", "risk_acceptance", "retired_state", "retained_paths")
SOURCES = ("runtime", "guardian_key", "compiler", "genesis", "contracts", "services", "indexer")
CLI_BINARIES = ("psy_dev_cli", "psy_node_cli", "psy_relayer_cli", "psy_user_cli", "psy_worker_cli")
SERVICE_BINARIES = ("psy-services", "psy-indexer")
PATH_ROLES = ("core", "guardian", "relayer", "worker", "proxy", "faucet", "services", "envio")
UNITS = ("core_prefix", "core_namespace_prefix", "guardian_prefix", "relayer", "worker_prefix", "proxy_prefix", "faucet", "services",
         "indexer_prefix", "envio")
IMAGES = ("scylla", "valkey", "nats", "postgres", "nostr")
CHAINS = ("sepolia", "bscTestnet", "baseSepolia")
GROTH16_VERIFIERS = ("gnark_groth16_verifier", "deposit_batch_verifier", "withdrawal_claim_verifier")
# Every file that is loaded or executed on a remote host, keyed by file name in this directory.
TOOL_NAMES = ("activate_bridge.py", "activate_host.py", "activate_services.py", "enable_services_nostr.py",
              "fresh_l1.cjs", "fresh_l1.py", "guardian_exec.py", "indexer_backup_mirror.py", "install_envio.py",
              "install_guardian.py", "install_host.py", "install_relayer.py", "install_services.py",
              "prepare_bridge_forwarders.py", "prepare_faucet.py", "prepare_proxies.py",
              "prepare_relayer_credential.py", "prepare_workers.py", "relayer_exec.py")
SECRET_MARKERS = ("keystore", "/keys", ".key", ".cred", "operator", "/wireguard", "id_ed25519", "credential", "/.ssh",
                  "/etc/ssh", ".psy")
ALL_HOSTS = ("gcp-cp-ce", "gcp-realm-processor", "realm-processors-b", "realm-processors-c", "gcp-edge-1", "gcp-edge-2",
             "guardian-next-1", "guardian-next-2", "guardian-next-3", "gcp-psy-service", "gcp-coordinator-worker",
             "gcp-gateway", "gcp-faucet", "gcp-scylla", "gcp-redis", "gcp-nats", "gcp-postgres", "gcp-nostr",
             "gcp-c4d-1", "arc99x1", "arc99x2", "arc99x3")
# Needles that every retain list must still contain: SSH, WireGuard, credential secret, signer custody, forwarders, L1 nodes.
REQUIRED_RETAIN = {alias: ["/etc/ssh"] for alias in ALL_HOSTS}
for _alias, _needles in {
        "gcp-cp-ce": ["/var/lib/parth/.ssh", "/var/lib/parth/.psy/keystore", "psy-core/core-testnet-20261026/keys"],
        "gcp-edge-1": ["psy-core/core-testnet-20261027-r3/keys"], "gcp-edge-2": ["psy-core/core-testnet-20261027-r3/keys"],
        "gcp-realm-processor": ["psy-core/core-testnet-20261027-r3/keys"],
        "realm-processors-b": ["psy-core/core-testnet-20261027-r3/keys"],
        "realm-processors-c": ["psy-core/core-testnet-20261027-r3/keys"],
        "guardian-next-1": ["psy-guardian-custody", "credential.secret", "psy-core-client-18545.service"],
        "guardian-next-2": ["psy-guardian-custody", "credential.secret", "psy-core-client-18545.service"],
        "guardian-next-3": ["psy-guardian-custody", "credential.secret", "psy-core-client-18545.service"],
        "gcp-coordinator-worker": ["l1-password.cred", "credential.secret", "operator.json", "/var/lib/parth/.ssh",
                                   "psy-core-client-18545.service"],
        "gcp-faucet": ["l1-password.cred", "credential.secret", "/var/lib/parth/.psy/keystore",
                       "psy-core-client-18545.service", "psy-relayer-migrated-history.service"],
        "gcp-gateway": ["/etc/wireguard", "psy-bridge-private-edge-15370.service", "psy-faucet-x2-ingress.service",
                        "psy-relayer-selfhosted-sepolia-r3.service", "bsc-rpc-forward.service",
                        "sepolia-rpc-forward.service"],
        "gcp-nostr": ["/etc/wireguard", "caddy_data", "/var/lib/parth/.ssh", "/.psy/keystore"],
        "gcp-c4d-1": ["/etc/parth/c4d-workers"],
        "arc99x1": ["/etc/wireguard", "base-sepolia-execution.service", "bsc-testnet.service", "sepolia-reth.service",
                    "sepolia-lighthouse.service"],
        "arc99x2": ["/etc/wireguard", "credential.secret", "/var/lib/parth/.psy", "/etc/psy-faucet"],
        "arc99x3": ["/etc/wireguard", "credential.secret"]}.items():
    REQUIRED_RETAIN[_alias] += _needles
HASH = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_regular(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular file required")
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "file exceeds size limit")
    return raw


def parse(raw):
    document = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(document, dict), "object required")
    return document


def read_document(path):
    return parse(read_regular(path))


def sha256_file(path):
    return hashlib.sha256(read_regular(path)).hexdigest()


def read_release_lock(path):
    return read_document(path)


def load_release_lock(path, expected_sha256):
    raw = read_regular(path)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "release lock hash mismatch")
    return parse(raw)


def load_checked_release_lock(path, expected_sha256):
    lock = load_release_lock(path, expected_sha256)
    validate_release_lock(lock, Path(path).resolve().parent, False)
    return lock


def fields(value, names, label):
    require(isinstance(value, dict) and set(value) == set(names), f"{label} fields")
    return value


class Walk:
    """Rejects malformed values at once and records the empty ones that are still pending."""

    def __init__(self):
        self.pending = []

    def text(self, value, label):
        require(isinstance(value, str) and value, f"{label} must be a non-empty string")

    def digest(self, value, label):
        require(isinstance(value, str) and (value == "" or HASH.fullmatch(value)), f"{label} must be sha256 hex")
        if value == "":
            self.pending.append(label)

    def commit(self, value, label):
        require(isinstance(value, str) and (value == "" or COMMIT.fullmatch(value)), f"{label} must be a commit")
        if value == "":
            self.pending.append(label)

    def number(self, value, label, low, high):
        require(type(value) is int and low <= value <= high, f"{label} out of range")

    def absolute(self, value, label):
        require(isinstance(value, str) and value.startswith("/") and ".." not in value.split("/"),
                f"{label} must be an absolute path")

    def image(self, value, label):
        require(isinstance(value, str) and IMAGE.fullmatch(value), f"{label} image must be pinned by digest")


def check_profile(lock, release, artifacts):
    for key in ("schema_version", "release_id", "network", "network_magic"):
        require(type(lock[key]) is type(release.get(key)) and lock[key] == release[key],
                f"{key} differs from the release profile")
    inputs = lock["inputs"]
    require(inputs["runtime_config"] == release["runtime_config_sha256"],
            "runtime_config hash differs from the release profile")
    require(inputs["canonical_config"] == release["canonical_config_sha256"],
            "canonical_config hash differs from the release profile")
    require(inputs["genesis"] == artifacts["genesis_sha256"], "genesis hash differs from artifacts")
    require(lock["units"]["core_namespace_prefix"] == release["namespace_prefix"],
            "core_namespace_prefix differs from the release profile")
    require(type(lock["gates"]["worker_queue_ack_wait_ms"]) is type(release["worker_queue_ack_wait_ms"])
            and lock["gates"]["worker_queue_ack_wait_ms"] == release["worker_queue_ack_wait_ms"],
            "worker_queue_ack_wait_ms differs from the release profile")
    sources = lock["sources"]
    require(sources["runtime"] == release["runtime_candidate_commit"], "runtime commit differs from the release profile")
    for name in ("compiler", "genesis"):
        require(sources[name] == artifacts["preparation_commits"][name], f"{name} commit differs from artifacts")
    for name in CLI_BINARIES:
        require(lock["binaries"][name] == artifacts["binaries"][name], f"{name} hash differs from artifacts")


def input_files(release_dir, private_dir=None):
    files = {"release_profile": release_dir / "release.json", "topology": release_dir / "topology.json",
             "artifacts": release_dir / "artifacts.json", "risk_acceptance": release_dir / "risk-acceptance.md",
             "worker_whitelist": release_dir.parent / "core-only" / "worker-whitelist.json"}
    if private_dir is not None:
        files["retired_state"] = Path(private_dir) / "retired-state.json"
        files["retained_paths"] = Path(private_dir) / "retained-paths.json"
    return files


def check_input_files(lock, release_dir, private_dir=None):
    for name, path in input_files(release_dir, private_dir).items():
        require(lock["inputs"][name] == sha256_file(path), f"input hash differs from file: {name}")


def check_names(lock, release, topology):
    namespace = release["namespace_prefix"]
    for name, value in lock["units"].items():
        require(namespace in value, f"unit name must carry the namespace: {name}")
    for role, group in lock["paths"].items():
        for name in ("release", "state"):
            require(release["release_id"] in group[name] or namespace in group[name],
                    f"path must carry the release id or namespace: {role}.{name}")
    for alias, address in lock["hosts"].items():
        require(alias not in topology["hosts"], f"host duplicates the topology: {alias}")
        require(ipaddress.ip_address(address).is_private, f"host address must be private: {alias}")


def check_shape(lock, walk):
    fields(lock, TOP_LEVEL, "release lock")
    walk.number(lock["schema_version"], "schema_version", 1, 1)
    for name in ("release_id", "network", "network_magic"):
        walk.text(lock[name], name)
    for name in INPUTS:
        walk.digest(fields(lock["inputs"], INPUTS, "inputs")[name], "inputs." + name)
    for name in SOURCES:
        walk.commit(fields(lock["sources"], SOURCES, "sources")[name], "sources." + name)
    for name in CLI_BINARIES + SERVICE_BINARIES:
        walk.digest(fields(lock["binaries"], CLI_BINARIES + SERVICE_BINARIES, "binaries")[name], "binaries." + name)
    fields(lock["paths"], PATH_ROLES, "paths")
    for role in PATH_ROLES:
        for name in ("release", "config", "state"):
            walk.absolute(fields(lock["paths"][role], ("release", "config", "state"), "paths." + role)[name],
                          f"paths.{role}.{name}")
    for name in UNITS:
        walk.text(fields(lock["units"], UNITS, "units")[name], "units." + name)
    require(isinstance(lock["hosts"], dict) and lock["hosts"], "hosts fields")


def check_services(lock, walk):
    services = fields(lock["services"], ("database", "owner", "redis_db", "key_prefix", "listen", "backups",
                                         "mirror"), "services")
    for name in ("database", "owner", "key_prefix", "listen"):
        walk.text(services[name], "services." + name)
    walk.number(services["redis_db"], "services.redis_db", 0, 15)
    walk.absolute(services["backups"], "services.backups")
    walk.absolute(services["mirror"], "services.mirror")
    envio = fields(lock["envio"], ("database", "project", "image", "graphql_port", "hasura_port", "rpc_routes"), "envio")
    for name in ("database", "project"):
        walk.text(envio[name], "envio." + name)
    walk.image(envio["image"], "envio")
    for name in ("graphql_port", "hasura_port"):
        walk.number(envio[name], "envio." + name, 1, 65535)
    routes = fields(envio["rpc_routes"], CHAINS, "envio.rpc_routes")
    for chain, url in routes.items():
        require(isinstance(url, str) and re.fullmatch(r"http://[0-9.]+:[0-9]+", url), f"envio.rpc_routes.{chain} url")
    faucet = fields(lock["faucet"], ("account", "listen_port", "operators_sha256"), "faucet")
    walk.text(faucet["account"], "faucet.account")
    walk.number(faucet["listen_port"], "faucet.listen_port", 1, 65535)
    walk.digest(faucet["operators_sha256"], "faucet.operators_sha256")


def check_chain_values(lock, walk):
    images = fields(lock["images"], IMAGES, "images")
    for name in IMAGES:
        walk.image(images[name], name)
    groth16 = fields(lock["groth16"], ("setup_manifest_sha256", "verifiers"), "groth16")
    walk.digest(groth16["setup_manifest_sha256"], "groth16.setup_manifest_sha256")
    for name in GROTH16_VERIFIERS:
        walk.digest(fields(groth16["verifiers"], GROTH16_VERIFIERS, "groth16.verifiers")[name],
                    "groth16.verifiers." + name)
    l1 = fields(lock["l1"], ("signer", "signer_host", "output_root", "bundle_sha256", "policy_sha256", "gas_budget_sha256"), "l1")
    require(isinstance(l1["signer"], str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", l1["signer"]), "l1.signer address")
    require(l1["signer_host"] in ALL_HOSTS, "l1.signer_host must be a known host alias")
    walk.absolute(l1["output_root"], "l1.output_root")
    walk.digest(l1["bundle_sha256"], "l1.bundle_sha256")
    walk.digest(l1["policy_sha256"], "l1.policy_sha256")
    for chain in CHAINS:
        walk.digest(fields(l1["gas_budget_sha256"], CHAINS, "l1.gas_budget_sha256")[chain],
                    "l1.gas_budget_sha256." + chain)
    ingress = fields(lock["ingress"], ("fenced_hosts", "faucet_hosts", "maintenance_tag"), "ingress")
    for name in ("fenced_hosts", "faucet_hosts"):
        require(isinstance(ingress[name], list) and ingress[name] and all(
            isinstance(host, str) and host for host in ingress[name]), f"ingress.{name} must list hosts")
    walk.text(ingress["maintenance_tag"], "ingress.maintenance_tag")
    gates = fields(lock["gates"], ("l2_stability_checkpoint_count", "worker_queue_ack_wait_ms"), "gates")
    walk.number(gates["worker_queue_ack_wait_ms"], "gates.worker_queue_ack_wait_ms", 1, 2**63 - 1)
    require(type(gates["l2_stability_checkpoint_count"]) is int and gates["l2_stability_checkpoint_count"] == 100,
            "gates.l2_stability_checkpoint_count must be 100")
    tools = lock["tool_sha256"]
    require(isinstance(tools, dict) and set(tools) == set(TOOL_NAMES), "tool_sha256 fields")
    for name in TOOL_NAMES:
        require(isinstance(tools[name], str) and HASH.fullmatch(tools[name]), f"tool_sha256.{name} must be sha256 hex")


def validate_release_lock(lock, release_dir, is_complete, private_dir=None):
    release_dir = Path(release_dir)
    require(private_dir is not None or not is_complete, "complete check requires the private directory")
    walk = Walk()
    check_shape(lock, walk)
    check_services(lock, walk)
    check_chain_values(lock, walk)
    release = read_document(release_dir / "release.json")
    artifacts = read_document(release_dir / "artifacts.json")
    check_profile(lock, release, artifacts)
    check_input_files(lock, release_dir, private_dir)
    if private_dir is not None:
        validate_retirement(read_document(Path(private_dir) / "retired-state.json"),
                            read_document(Path(private_dir) / "retained-paths.json"))
    check_names(lock, release, read_document(release_dir / "topology.json"))
    require(not (is_complete and walk.pending), "release lock incomplete: " + ", ".join(walk.pending))


def validate_retirement(retired, retained):
    fields(retired, ("hosts",), "retired state")
    hosts = retired["hosts"]
    keep = {}
    for alias, entry in hosts.items():
        fields(entry, ("stop", "containers", "retain", "clear"), f"retired state {alias}")
        for name in ("stop", "containers", "retain", "clear"):
            require(isinstance(entry[name], list) and all(isinstance(i, str) and i for i in entry[name]),
                    f"{alias}.{name} must list strings")
        require(not any("/" in i or i.startswith("docker:") for i in entry["stop"] + entry["containers"]),
                f"{alias} stop and containers hold names, not paths")
        require(len(entry["clear"]) == len(set(entry["clear"])), f"{alias} clear lists a path twice")
        require(len(entry["retain"]) == len(set(entry["retain"])), f"{alias} retain lists a path twice")
        require(not set(entry["stop"]) & set(entry["containers"]), f"{alias} lists a name in stop and containers")
        stopped_retained = set(entry["stop"]) & {Path(i).name for i in entry["retain"] if i.startswith("/")}
        require(not stopped_retained, f"{alias} stops a retained unit: {sorted(stopped_retained)[0] if stopped_retained else ''}")
        for item in entry["retain"] + entry["clear"]:
            require(item.startswith("/") and ".." not in item.split("/") and (item == "/" or not item.endswith("/")),
                    f"{alias} path must be absolute and normal: {item}")
        keep[alias] = [Path(i) for i in entry["retain"]]
        for item in entry["clear"]:
            require(not any(marker in item for marker in SECRET_MARKERS), f"{alias} clear names key material: {item}")
            clear = Path(item)
            for kept in keep[alias]:
                require(clear != kept and kept not in clear.parents and clear not in kept.parents,
                        f"{alias} clear touches retain: {item}")
    require(set(hosts) == set(ALL_HOSTS), "retired state host set")
    for alias, needles in REQUIRED_RETAIN.items():
        joined = "\n".join(hosts[alias]["retain"])
        for needle in needles:
            require(needle in joined, f"{alias} must retain {needle}")
    fields(retained, ("paths",), "retained paths")
    listed = {}
    for item in retained["paths"]:
        fields(item, ("host", "path", "kind"), "retained path")
        require(item["kind"] in ("secret", "infrastructure"), "retained path kind")
        require(item["host"] == "local" or item["host"] in hosts, f"retained path for unknown host: {item['host']}")
        require(item["kind"] == "secret" or not any(m in item["path"] for m in SECRET_MARKERS),
                f"infrastructure kind on secret path: {item['path']}")
        listed.setdefault(item["host"], set()).add(item["path"])
    require(".private" in " ".join(listed.get("local", ())), "local .private material must be retained")
    for alias, entry in hosts.items():
        require(listed.get(alias, set()) == set(entry["retain"]), f"retained paths differ from retain list: {alias}")


def write_inputs(lock_path, release_dir, private_dir=None):
    lock = read_release_lock(lock_path)
    release = read_document(release_dir / "release.json")
    artifacts = read_document(release_dir / "artifacts.json")
    inputs = dict(lock["inputs"])
    for name, path in input_files(release_dir, private_dir).items():
        inputs[name] = sha256_file(path)
    inputs["runtime_config"] = release["runtime_config_sha256"]
    inputs["canonical_config"] = release["canonical_config_sha256"]
    inputs["genesis"] = artifacts["genesis_sha256"]
    lock["inputs"] = inputs
    replace_lock(lock_path, lock)


def check_tool_hashes(lock, tools_dir):
    for name in TOOL_NAMES:
        require(lock["tool_sha256"].get(name) == sha256_file(Path(tools_dir) / name), f"tool hash differs: {name}")


def write_tool_hashes(lock_path, tools_dir=HERE):
    lock = read_release_lock(lock_path)
    lock["tool_sha256"] = {name: sha256_file(Path(tools_dir) / name) for name in TOOL_NAMES}
    replace_lock(lock_path, lock)


def replace_lock(lock_path, lock):
    text = json.dumps(lock, indent=2) + "\n"
    directory = Path(lock_path).resolve().parent
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".release-lock-")
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)
        os.chmod(temporary, 0o644)
        os.replace(temporary, lock_path)
    except BaseException:
        os.unlink(temporary)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="validate the lock, its input files and the tool hashes")
    check.add_argument("--lock", type=Path, required=True)
    check.add_argument("--require-complete", action="store_true")
    check.add_argument("--private-dir", type=Path)
    update = commands.add_parser("update-tools", help="rewrite tool_sha256 from the files in this directory")
    update.add_argument("--lock", type=Path, required=True)
    inputs = commands.add_parser("update-inputs", help="rewrite inputs from the current files")
    inputs.add_argument("--lock", type=Path, required=True)
    inputs.add_argument("--private-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            lock = read_release_lock(args.lock)
            validate_release_lock(lock, args.lock.resolve().parent, args.require_complete, args.private_dir)
            check_tool_hashes(lock, HERE)
            print("release lock ok")
        elif args.command == "update-inputs":
            write_inputs(args.lock, args.lock.resolve().parent, args.private_dir)
            print("inputs updated")
        else:
            write_tool_hashes(args.lock)
            print("tool hashes updated")
    except (OSError, ValueError, KeyError) as error:
        print(f"release lock rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
