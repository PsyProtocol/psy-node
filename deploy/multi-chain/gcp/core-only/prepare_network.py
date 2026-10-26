#!/usr/bin/env python3
"""Assemble public core-network inputs offline; never generate or load secrets.

Stage 1: --config-out PATH. Stage 2: --genesis-in PATH --genesis-out PATH
(--config-out may be omitted). All five public input arguments, including a
testnet worker whitelist, are required in both stages. Existing P2P identities
and Guardian commitments are always reused; there is no key-generation path.
Outputs must be new files outside Git checkouts. Runtime key
possession, curve-point validation and circuit acceptance remain separate gates.
"""

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys


SOURCE_BASE = "de539f565ec1a92f91bb4e9686e1442e89ba8639"
SLOTS = (((0, 0), (4, 262144), (6, 786432)),
         ((1, 1048576), (3, 1572864), (5, 1310720)))
CONSENSUS = {"magic": "0x1337CF514544CF69", "users_per_realm": 1048576,
             "global_user_tree_height": 32, "realm_user_tree_height": 20,
             "group_realm_height": 1, "p2p": {"checkpoints_per_epoch": 10}}
GUARDIANS = [
    {"id": i, "listen_address": f"10.148.0.{38 + i}:{15440 + i}",
     "rpc_url": f"http://10.148.0.{38 + i}:{15440 + i}"}
    for i in (1, 2, 3)
]
PERIPHERAL_LISTS = ("prove_proxy_url", "system_prove_proxy_url", "faucet_rpc_url",
                    "api_services_url", "indexer_graphql_url", "explorer_url",
                    "l1_rpc_urls", "bridge_url")
MEMBER_FIELDS = {"realm_id", "validator_user_id", "node_id", "bls_public_key"}


class PrepareError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PrepareError(message)


def fields(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected),
            f"{label}: unexpected or missing fields")


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, f"invalid {label}")
    return value


def public_hex(value, size, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{%d}" % (size * 2), value)
            and int(value, 16) != 0, f"invalid {label}")
    return value.lower()


def peer_id(node):
    raw = bytes.fromhex(public_hex(node, 38, "NodeId"))
    require(raw[:6] == bytes.fromhex("002408011220") and any(raw[6:]),
            "NodeId must contain an Ed25519 identity multihash")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value, encoded = int.from_bytes(raw, "big"), ""
    while value:
        value, digit = divmod(value, 58)
        encoded = alphabet[digit] + encoded
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded


def remap_address(node, addresses, host, port):
    expected_peer = peer_id(node)
    require(isinstance(addresses, list) and len(addresses) == 1,
            "exactly one source multiaddress required per identity")
    require(isinstance(addresses[0], str), "invalid source multiaddress")
    match = re.fullmatch(r"/(ip4|ip6|dns|dns4|dns6)/([^/\s]+)/tcp/([0-9]+)/p2p/([^/\s]+)",
                         addresses[0])
    require(match is not None, "unsupported source multiaddress")
    integer(int(match[3]), 1, 65535, "source TCP port")
    require(match[4] == expected_peer, "source PeerId does not match NodeId")
    return [f"/ip4/{host}/tcp/{port}/p2p/{expected_peer}"]


def private_ip(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        raise PrepareError("topology requires a private IPv4 address") from None
    require(isinstance(value, str) and str(address) == value and any(
        address in ipaddress.ip_network(network)
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
        "topology requires a private IPv4 address")
    return value


def validate_topology(topology):
    fields(topology, ("schema_version", "release_id", "runtime_commit",
                      "runtime_source_base", "runtime_patch_sha256", "psy_network",
                      "network", "proving_backend", "hosts", "infrastructure",
                      "coordinator", "realms", "faucet_operator_count"), "topology")
    integer(topology["faucet_operator_count"], 100, 100, "faucet operator count")
    integer(topology["schema_version"], 1, 1, "topology version")
    require(topology["runtime_source_base"] == SOURCE_BASE, "unexpected runtime source base")
    public_hex(topology["runtime_patch_sha256"], 32, "runtime patch SHA-256")
    require(topology["runtime_commit"] is None,
            "unpublished runtime candidate must have null runtime_commit")
    require(topology["psy_network"] == "testnet" and topology["network"] == "psy-public-testnet",
            "runtime requires PSY_NETWORK=testnet with --network psy-public-testnet")
    require(topology["proving_backend"] == "plonky2-poseidon-goldilocks", "unexpected backend")
    hosts = topology["hosts"]
    require(isinstance(hosts, dict) and hosts, "missing topology hosts")
    for value in hosts.values():
        private_ip(value)
    coordinator = topology["coordinator"]
    fields(coordinator, ("host", "namespace", "edge_ports"), "coordinator")
    require(hosts.get(coordinator["host"]) == "10.148.0.25"
            and coordinator["edge_ports"] == [15370, 15371, 15372],
            "coordinator must use 10.148.0.25 ports 15370/15371/15372")
    sockets = set()

    def socket(host, port):
        require(host in hosts, "unknown topology host")
        integer(port, 1, 65535, "topology port")
        endpoint = (hosts[host], port)
        require(endpoint not in sockets, "duplicate topology socket")
        sockets.add(endpoint)

    for port in coordinator["edge_ports"]:
        socket(coordinator["host"], port)
    realms = topology["realms"]
    require(isinstance(realms, list) and len(realms) == 2, "exactly two topology Realms required")
    for rid, realm in enumerate(realms):
        fields(realm, ("id", "validators"), "topology Realm")
        integer(realm["id"], rid, rid, "ordered Realm ID")
        require(isinstance(realm["validators"], list) and len(realm["validators"]) == 3,
                "exactly three topology validators per Realm required")
        for index, validator in enumerate(realm["validators"]):
            fields(validator, ("registration_id", "validator_user_id", "processor_host",
                               "processor_port", "edge_host", "edge_port", "http_port",
                               "namespace"), "topology validator")
            registration, uid = SLOTS[rid][index]
            integer(validator["registration_id"], registration, registration, "registration slot")
            integer(validator["validator_user_id"], uid, uid, "validator user ID")
            socket(validator["processor_host"], validator["processor_port"])
            socket(validator["edge_host"], validator["edge_port"])
            socket(validator["edge_host"], validator["http_port"])


def validate_consensus(network):
    require(isinstance(network, dict), "missing network configuration")
    for name, expected in CONSENSUS.items():
        require(json.dumps(network.get(name), sort_keys=True) == json.dumps(expected, sort_keys=True),
                f"consensus mismatch: {name}")


def ordered_realms(network):
    realms = network.get("realm_configs")
    require(isinstance(realms, list) and len(realms) == 2, "exactly two public Realms required")
    for rid, realm in enumerate(realms):
        require(isinstance(realm, dict), "invalid public Realm")
        integer(realm.get("id"), rid, rid, "ordered public Realm ID")
    return realms


def validate_whitelist(document):
    fields(document, ("networks",), "dedicated worker whitelist")
    fields(document["networks"], ("testnet",), "worker whitelist networks")
    fields(document["networks"]["testnet"], ("whitelist",), "worker network")
    policy = document["networks"]["testnet"]["whitelist"]
    fields(policy, ("enabled", "secp256k1"), "worker policy")
    require(policy["enabled"] is True, "worker whitelist must be enabled")
    keys = policy["secp256k1"]
    require(isinstance(keys, list) and 1 <= len(keys) <= 10000, "worker whitelist must not be empty")
    canonical = []
    prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    for key in keys:
        require(isinstance(key, str) and re.fullmatch(r"(?:0[xX])?0[23][0-9a-fA-F]{64}", key),
                "invalid compressed worker public key encoding")
        encoded = key.lower().removeprefix("0x")
        x = int(encoded[2:], 16)
        require(x < prime, "worker public key coordinate is outside secp256k1")
        # A compressed secp256k1 key must decompress to y^2 = x^3 + 7.
        rhs = (pow(x, 3, prime) + 7) % prime
        y = pow(rhs, (prime + 1) // 4, prime)
        require(pow(y, 2, prime) == rhs and (y != 0 or encoded[:2] == "02"),
                "worker public key is not a secp256k1 point")
        canonical.append(encoded)
    require(len(set(canonical)) == len(canonical), "duplicate worker public key")
    return copy.deepcopy(policy)


def assemble_config(canonical, p2p, commitments, topology, whitelist):
    validate_topology(topology)
    policy = validate_whitelist(whitelist)
    require(isinstance(canonical.get("networks"), dict), "missing canonical networks")
    selected = canonical["networks"].get("testnet")
    validate_consensus(selected)
    for realm in ordered_realms(selected):
        require(realm.get("validators", []) == [], "canonical input must have empty membership")
    require("guardian_initial_member_hashes" not in selected,
            "canonical input already contains a Guardian policy")
    source_name = p2p.get("defaultNetwork")
    require(source_name == "testnet", "P2P source defaultNetwork must be testnet")
    source = p2p.get("networks", {}).get(source_name)
    validate_consensus(source)
    source_realms = ordered_realms(source)
    # Existing custody provenance does not change when runtime source is patched.
    require(commitments.get("node_source") == SOURCE_BASE, "Guardian commitments source must be de539")
    hashes = commitments.get("guardian_initial_member_hashes")
    require(isinstance(hashes, list) and len(hashes) == 3, "three Guardian commitments required")
    normalized_hashes = [public_hex(value, 32, "Guardian commitment") for value in hashes]
    require(len(set(normalized_hashes)) == 3, "duplicate Guardian commitments")
    result = copy.deepcopy(canonical)
    public_realms, nodes, bls_keys = [], set(), set()
    for rid, layout in enumerate(topology["realms"]):
        members = source_realms[rid].get("validators")
        require(isinstance(members, list) and len(members) == 3,
                "exactly three generated validators per Realm required")
        public = {"id": rid, "rpc_url": [], "validators": []}
        for index, (member, placement) in enumerate(zip(members, layout["validators"])):
            fields(member, ("validator_user_id", "processor_node_id", "bls_public_key",
                            "processor_addresses", "edge_nodes"), "generated validator")
            uid = SLOTS[rid][index][1]
            integer(member["validator_user_id"], uid, uid, "generated validator order")
            edges = member["edge_nodes"]
            require(isinstance(edges, list) and len(edges) == 1, "exactly one edge per validator required")
            fields(edges[0], ("node_id", "addresses"), "generated edge")
            for node in (member["processor_node_id"], edges[0]["node_id"]):
                peer_id(node)
                normalized = node.lower()
                require(normalized not in nodes, "duplicate processor/edge NodeId")
                nodes.add(normalized)
            bls = public_hex(member["bls_public_key"], 48, "BLS public key")
            require(bls not in bls_keys, "duplicate BLS public key")
            bls_keys.add(bls)
            mapped = copy.deepcopy(member)
            processor_ip = topology["hosts"][placement["processor_host"]]
            edge_ip = topology["hosts"][placement["edge_host"]]
            mapped["processor_addresses"] = remap_address(
                member["processor_node_id"], member["processor_addresses"], processor_ip,
                placement["processor_port"])
            mapped["edge_nodes"][0]["addresses"] = remap_address(
                edges[0]["node_id"], edges[0]["addresses"], edge_ip, placement["edge_port"])
            public["validators"].append(mapped)
            public["rpc_url"].append(f'http://{edge_ip}:{placement["http_port"]}')
        public_realms.append(public)
    coordinator = [{"id": 0, "rpc_url": [f"http://10.148.0.25:{port}"
                    for port in topology["coordinator"]["edge_ports"]]}]
    network = result["networks"]["testnet"]
    network["realm_configs"] = public_realms
    network["coordinator_configs"] = coordinator
    network["guardian_initial_member_hashes"] = list(hashes)
    network["guardian_configs"] = copy.deepcopy(GUARDIANS)
    network["whitelist"] = policy
    for field in PERIPHERAL_LISTS:
        network[field] = []
    network["nostr_relay_url"] = ""
    for field in ("l1_config_url", "guardian_history", "guardian_authorization", "guardian_max_fee"):
        network.pop(field, None)
    result["defaultNetwork"] = "testnet"
    return result


def inject_genesis(genesis, config):
    require(isinstance(genesis, dict), "Genesis must be an object")
    expected = []
    # Exact de539 dev/locSetupV4.ts::realmGenesisValidators serialization.
    for realm in config["networks"]["testnet"]["realm_configs"]:
        for member in realm["validators"]:
            expected.append({"realm_id": realm["id"], "validator_user_id": member["validator_user_id"],
                             "node_id": member["processor_node_id"], "bls_public_key": member["bls_public_key"]})
    existing = genesis.get("validators", [])
    require(isinstance(existing, list), "malformed Genesis membership")
    if existing:
        for member in existing:
            fields(member, MEMBER_FIELDS, "Genesis validator")
            integer(member["realm_id"], 0, 1, "Genesis Realm ID")
            integer(member["validator_user_id"], 0, 2097151, "Genesis validator user ID")
        order = lambda member: (member["realm_id"], member["validator_user_id"])
        require(sorted(existing, key=order) == sorted(expected, key=order),
                "existing Genesis membership conflicts with generated P2P identities")
    users = genesis.get("users")
    require(isinstance(users, list) and len(users) == 107,
            "Genesis requires 7 reserved accounts and 100 faucet operators (107 users)")
    for slots in SLOTS:
        for registration, _ in slots:
            user = users[registration]
            require(isinstance(user, dict), "invalid Genesis user")
            key = user.get("public_key_info")
            fields(key, ("fingerprint", "public_key_param"), "Genesis public key info")
            for value in key.values():
                public_hex(value, 32, "Genesis public key info")
    result = copy.deepcopy(genesis)
    if not existing:
        result["validators"] = expected
    return result


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON field")
        result[name] = value
    return result


def reject_constant(_):
    raise PrepareError("non-finite JSON value")


def read_public_json(path):
    require(Path(path).suffix == ".json" and Path(path).name != "private_keys.json"
            and "keystore" not in Path(path).name.lower(), "only public JSON inputs are accepted")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 64 * 1024 * 1024,
                "public input must be a regular JSON file of at most 64 MiB")
        raw = handle.read(64 * 1024 * 1024 + 1)
    require(len(raw) <= 64 * 1024 * 1024, "public input exceeds size limit")
    value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    require(isinstance(value, dict), "public input must be a JSON object")
    return value


def output_directory(path):
    path = Path(path).absolute()
    require(".." not in path.parts and path.suffix == ".json", "output must be a new JSON path")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            try:
                marker = os.stat(".git", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                # Sandboxed workspace roots can have an empty protective .git
                # directory; actual repositories have HEAD or a worktree file.
                require(stat.S_ISDIR(marker.st_mode),
                        "outputs must be outside Git checkouts/submodules")
                try:
                    os.stat(".git/HEAD", dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise PrepareError("outputs must be outside Git checkouts/submodules")
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def write_new_outputs(outputs):
    require(len({str(Path(path).absolute()) for path, _ in outputs}) == len(outputs),
            "output paths must be distinct")
    encoded = [(path, (json.dumps(value, indent=2, allow_nan=False) + "\n").encode())
               for path, value in outputs]
    reservations, directories = [], []
    try:
        for path, payload in encoded:
            directory, name = output_directory(path)
            directories.append(directory)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o644, dir_fd=directory)
            reservations.append((directory, name, fd, os.fstat(fd), payload))
        for _, _, fd, _, payload in reservations:
            with os.fdopen(os.dup(fd), "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        for directory in directories:
            os.fsync(directory)
    except BaseException:
        for directory, name, _, original, _ in reservations:
            try:
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                    os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
        raise
    finally:
        for _, _, fd, _, _ in reservations:
            os.close(fd)
        for directory in directories:
            os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("canonical-config", "p2p-config", "guardian-commitments", "topology", "whitelist"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("config-out", "genesis-in", "genesis-out"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(argv)
    try:
        require(bool(args.genesis_in) == bool(args.genesis_out), "Genesis input/output must be paired")
        require(args.config_out or args.genesis_out, "at least one output is required")
        inputs = [args.canonical_config, args.p2p_config, args.guardian_commitments,
                  args.topology, args.whitelist]
        if args.genesis_in:
            inputs.append(args.genesis_in)
        outputs = [path for path in (args.config_out, args.genesis_out) if path]
        require(not ({path.resolve() for path in inputs} & {path.resolve() for path in outputs}),
                "output must not overwrite an input")
        config = assemble_config(*(read_public_json(path) for path in inputs[:5]))
        documents = [(args.config_out, config)] if args.config_out else []
        if args.genesis_in:
            documents.append((args.genesis_out, inject_genesis(read_public_json(args.genesis_in), config)))
        write_new_outputs(documents)
    except (PrepareError, OSError, ValueError, KeyError, TypeError) as error:
        message = str(error) if isinstance(error, PrepareError) else "invalid input or unavailable output path"
        print("prepare-network: " + message, file=sys.stderr)
        return 1
    print("Prepared public inputs: PSY_NETWORK=testnet; --network psy-public-testnet; defaultNetwork=testnet; 6 validators.")
    print("No Caddy/public exposure. Runtime provenance, key possession, build-stage agreement and proofs remain acceptance gates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
