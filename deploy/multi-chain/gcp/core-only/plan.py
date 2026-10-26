#!/usr/bin/env python3
"""Read-only core deployment planner. No subprocesses, network, or file writes."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
RUNTIME_SOURCE_BASE = "de539f565ec1a92f91bb4e9686e1442e89ba8639"
RUNTIME_PATCH_SHA256 = "d5d62decefd283fa9f9981b915595d3ebf1a1245d3319d050dbf308c5cbc32fa"
SLOTS = (((0, 0), (4, 262144), (6, 786432)),
         ((1, 1048576), (3, 1572864), (5, 1310720)))
PROCESSORS = ("gcp-realm-processor", "realm-processors-b", "realm-processors-c")
EDGES = ("gcp-edge-1", "gcp-edge-2")
HOSTS = {"gcp-cp-ce": "10.148.0.25", "gcp-realm-processor": "10.148.0.37",
         "realm-processors-b": "10.148.0.42", "realm-processors-c": "10.148.0.43",
         "gcp-edge-1": "10.148.0.36", "gcp-edge-2": "10.148.0.35"}
CONSENSUS = {"magic": "0x1337CF514544CF69", "users_per_realm": 1048576,
             "global_user_tree_height": 32, "realm_user_tree_height": 20,
             "group_realm_height": 1, "p2p": {"checkpoints_per_epoch": 10}}
RUNTIME_BLOCKER = ("Patched testnet runtime candidate is not published; runtime_commit is null. "
                   "runtime_source_base is only the de539 baseline, not a deployable candidate. "
                   "The patch SHA256 identifies source changes, not an approved release.")
PENDING = ["Binary checksums/build provenance and compiled circuit fingerprints",
           "Local Ed25519/BLS/ZK key possession and Genesis account authentication",
           "Cryptographic BLS/Ed25519/secp256k1 point validation by the pinned runtime",
           "Full Rust Genesis/config validation and Guardian policy-state commitment",
           "Host permissions, available memory, port reachability and storage ownership",
           "Worker reward mapping, installation and checkpoint/rotation/recovery acceptance"]


class PlanError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PlanError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def read_json(path):
    raw = Path(path).read_bytes()
    doc = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(doc, dict), "expected JSON object")
    return doc, hashlib.sha256(raw).hexdigest()


def fields(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected),
            f"{label}: unexpected or missing fields")


def number(value, low, high, label):
    require(type(value) is int and low <= value <= high, f"invalid {label}")


def private_ip(value):
    address = ipaddress.ip_address(value)
    require(address.version == 4 and any(address in ipaddress.ip_network(n)
            for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
            "explicit RFC1918 IPv4 required")


def validators(topology):
    for realm in topology["realms"]:
        for position, validator in enumerate(realm["validators"], 1):
            yield realm["id"], position, validator


def validate_topology(t):
    fields(t, ("schema_version", "release_id", "runtime_commit", "runtime_source_base",
               "runtime_patch_sha256", "psy_network",
               "network", "proving_backend", "hosts", "infrastructure", "coordinator",
               "realms", "faucet_operator_count"), "topology")
    number(t["faucet_operator_count"], 100, 100, "faucet operator count")
    require(type(t["schema_version"]) is int and t["schema_version"] == 1, "unsupported schema")
    require(t["runtime_commit"] is None, "unpublished runtime candidate must have null runtime_commit")
    require(t["runtime_source_base"] == RUNTIME_SOURCE_BASE, "runtime source base must remain de539")
    require(t["runtime_patch_sha256"] == RUNTIME_PATCH_SHA256, "runtime patch SHA256 mismatch")
    require(t["release_id"] == "core-testnet-20261026", "unexpected release ID")
    require(t["psy_network"] == "testnet" and t["network"] == "psy-public-testnet",
            "network selection must be testnet / psy-public-testnet")
    require(t["proving_backend"] == "plonky2-poseidon-goldilocks", "unexpected proving backend")
    require(t["hosts"] == HOSTS, "host inventory differs from approved placement")
    infra = t["infrastructure"]
    fields(infra, ("scylla_db_url", "redis_url", "nats_jetstream_url"), "infrastructure")
    for key, scheme in (("scylla_db_url", "tcp"), ("redis_url", "redis"),
                        ("nats_jetstream_url", "nats")):
        value = infra[key]
        require(isinstance(value, str), "invalid infrastructure URL")
        parsed = urlsplit("tcp://" + value if scheme == "tcp" else value)
        require(parsed.scheme == scheme and not parsed.username and not parsed.password
                and not parsed.path and not parsed.query and not parsed.fragment,
                "infrastructure requires a plain private host:port, without credentials")
        private_ip(parsed.hostname)
        number(parsed.port, 1, 65535, "infrastructure port")
        canonical = f"{parsed.hostname}:{parsed.port}"
        require(value == (canonical if scheme == "tcp" else f"{scheme}://{canonical}"),
                "infrastructure URL must be canonical, without whitespace or escapes")
    c = t["coordinator"]
    fields(c, ("host", "namespace", "edge_ports"), "coordinator")
    require(c["host"] == "gcp-cp-ce" and c["edge_ports"] == [15370, 15371, 15372],
            "coordinator placement/ports differ from approved plan")
    namespaces, sockets = set(), set()

    def namespace(value):
        require(isinstance(value, str) and re.fullmatch(r"fresh20261026_[a-z0-9_]+", value)
                and len(value) <= 48, "invalid fresh namespace")
        require(value not in namespaces, "shared namespace across validators/coordinator")
        namespaces.add(value)

    def socket(host, port, minimum):
        number(port, minimum, 65535, "listener port")
        identity = (t["hosts"][host], port)
        require(identity not in sockets, "duplicate host/listener port")
        sockets.add(identity)

    namespace(c["namespace"])
    for port in c["edge_ports"]:
        socket(c["host"], port, 15370)
    require(isinstance(t["realms"], list) and len(t["realms"]) == 2, "exactly two Realms required")
    for rid, realm in enumerate(t["realms"]):
        fields(realm, ("id", "validators"), "realm")
        require(type(realm["id"]) is int and realm["id"] == rid, "ordered Realm IDs must be 0,1")
        require(isinstance(realm["validators"], list) and len(realm["validators"]) == 3,
                "exactly three ordered validators per Realm required")
        for index, v in enumerate(realm["validators"]):
            fields(v, ("registration_id", "validator_user_id", "processor_host", "processor_port",
                       "edge_host", "edge_port", "http_port", "namespace"), "validator")
            number(v["registration_id"], 0, 6, "registration ID")
            number(v["validator_user_id"], 0, 2097151, "validator user ID")
            require((v["registration_id"], v["validator_user_id"]) == SLOTS[rid][index],
                    "validator registration/user order differs from approved slots")
            require(v["processor_host"] == PROCESSORS[index] and v["edge_host"] == EDGES[rid],
                    "validator host differs from approved placement")
            namespace(v["namespace"])
            socket(v["processor_host"], v["processor_port"], 15400)
            socket(v["edge_host"], v["edge_port"], 15400)
            socket(v["edge_host"], v["http_port"], 15380)


def hex_value(value, size, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{%d}" % (size * 2), value)
            and int(value, 16) != 0, f"invalid {label}")
    return value.lower()


def peer_id(node):
    raw = bytes.fromhex(hex_value(node, 38, "NodeId"))
    require(raw[:6] == bytes.fromhex("002408011220"), "NodeId must be Ed25519 identity multihash")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value, result = int.from_bytes(raw, "big"), ""
    while value:
        value, remainder = divmod(value, 58)
        result = alphabet[remainder] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def validate_whitelist(doc):
    fields(doc, ("networks",), "dedicated worker whitelist")
    fields(doc["networks"], ("testnet",), "runtime worker whitelist networks")
    fields(doc["networks"]["testnet"], ("whitelist",), "worker network")
    policy = doc["networks"]["testnet"]["whitelist"]
    fields(policy, ("enabled", "secp256k1"), "worker policy")
    require(policy["enabled"] is True, "worker whitelist must be enabled")
    keys = policy["secp256k1"]
    require(isinstance(keys, list) and 1 <= len(keys) <= 10000, "worker whitelist must not be empty")
    canonical = []
    for key in keys:
        require(isinstance(key, str) and re.fullmatch(r"(?:0[xX])?0[23][0-9a-fA-F]{64}", key),
                "invalid compressed worker public key encoding")
        canonical.append(key.lower().removeprefix("0x"))
    require(len(set(canonical)) == len(canonical), "duplicate worker public key")
    return policy


def validate_inputs(t, config, genesis, whitelist):
    policy = validate_whitelist(whitelist)
    require(config.get("defaultNetwork") == "testnet", "config.defaultNetwork must be testnet")
    networks = config.get("networks", {})
    selected = networks.get("testnet")
    require(isinstance(selected, dict), "testnet config required")
    for key, expected in CONSENSUS.items():
        require(selected.get(key) == expected and type(selected.get(key)) is type(expected),
                f"testnet consensus mismatch: {key}")
    require(selected.get("whitelist") == policy, "testnet whitelist differs from dedicated policy")
    for key in ("realm_configs", "coordinator_configs", "guardian_initial_member_hashes", "fees"):
        require(key in selected, f"testnet config missing: {key}")
    guardians = selected["guardian_initial_member_hashes"]
    require(isinstance(guardians, list) and len(guardians) == 3, "three Guardian commitments required")
    commitments = [hex_value(x, 32, "Guardian commitment") for x in guardians]
    require(len(set(commitments)) == 3, "duplicate Guardian commitments")
    c = t["coordinator"]
    coordinator_urls = [f'http://{t["hosts"][c["host"]]}:{p}' for p in c["edge_ports"]]
    require(selected["coordinator_configs"] == [{"id": 0, "rpc_url": coordinator_urls}],
            "coordinator RPC inventory mismatch")
    require(type(selected["coordinator_configs"][0]["id"]) is int, "invalid coordinator ID")
    public_realms = selected["realm_configs"]
    require(isinstance(public_realms, list) and len(public_realms) == 2, "two public Realms required")
    expected_genesis, nodes, bls_keys = [], set(), set()
    for rid, realm in enumerate(t["realms"]):
        public = public_realms[rid]
        require(type(public.get("id")) is int and public["id"] == rid, "public Realm order mismatch")
        expected_urls = [f'http://{t["hosts"][v["edge_host"]]}:{v["http_port"]}'
                         for v in realm["validators"]]
        require(public.get("rpc_url") == expected_urls, "Realm RPC inventory mismatch")
        members = public.get("validators")
        require(isinstance(members, list) and len(members) == 3, "three public validators required")
        for v, member in zip(realm["validators"], members):
            require(type(member.get("validator_user_id")) is int and
                    member["validator_user_id"] == v["validator_user_id"], "public validator order mismatch")
            node = hex_value(member.get("processor_node_id"), 38, "processor NodeId")
            bls = hex_value(member.get("bls_public_key"), 48, "BLS public key")
            require(bls not in bls_keys, "duplicate BLS public key")
            bls_keys.add(bls)
            edge_nodes = member.get("edge_nodes")
            require(isinstance(edge_nodes, list) and len(edge_nodes) == 1, "one edge per validator required")
            edge = hex_value(edge_nodes[0].get("node_id"), 38, "edge NodeId")
            for identity, addresses, host, port in (
                (node, member.get("processor_addresses"), v["processor_host"], v["processor_port"]),
                (edge, edge_nodes[0].get("addresses"), v["edge_host"], v["edge_port"]),
            ):
                require(identity not in nodes, "duplicate processor/edge identity")
                nodes.add(identity)
                address = f'/ip4/{t["hosts"][host]}/tcp/{port}/p2p/{peer_id(identity)}'
                require(addresses == [address], "P2P address/PeerId does not match approved host/port/identity")
            expected_genesis.append(dict(realm_id=rid, validator_user_id=v["validator_user_id"],
                                         node_id=node, bls_public_key=bls))
    actual = genesis.get("validators")
    require(isinstance(actual, list) and len(actual) == 6, "Genesis requires six validators")
    normalized = []
    for member in actual:
        fields(member, ("realm_id", "validator_user_id", "node_id", "bls_public_key"), "Genesis validator")
        number(member["realm_id"], 0, 1, "Genesis Realm ID")
        number(member["validator_user_id"], 0, 2097151, "Genesis validator user ID")
        normalized.append(dict(member, node_id=hex_value(member["node_id"], 38, "Genesis NodeId"),
                               bls_public_key=hex_value(member["bls_public_key"], 48, "Genesis BLS key")))
    order = lambda m: (m["realm_id"], m["validator_user_id"])
    require(sorted(normalized, key=order) == sorted(expected_genesis, key=order),
            "Genesis validator membership differs from public config")
    users = genesis.get("users")
    require(isinstance(users, list) and len(users) == 7 + t["faucet_operator_count"],
            "Genesis requires 7 reserved accounts and 100 faucet operators (107 users)")
    for _, _, v in validators(t):
        user = users[v["registration_id"]]
        require(isinstance(user, dict), "invalid Genesis validator registration")
        key = user.get("public_key_info")
        fields(key, ("fingerprint", "public_key_param"), "Genesis public key info")
        for field in ("fingerprint", "public_key_param"):
            hex_value(key[field], 32, "Genesis " + field)


def services(t):
    release = f'/opt/psy-core/releases/{t["release_id"]}'
    config_root = f'/etc/psy-core/{t["release_id"]}'
    state = f'/var/lib/psy-core/{t["release_id"]}'
    env = {"PSY_NETWORK": t["psy_network"], "PSY_CONFIG_PATH": config_root + "/config.json"}
    common = ["--network", t["network"], "--proving-backend", t["proving_backend"]]
    for key, value in t["infrastructure"].items():
        common.extend(["--" + key.replace("_", "-"), value])
    result = []

    def add(role, name, host, namespace, args):
        argv = [release + "/bin/psy_node_cli", "start-" + role, *common,
                "--db-namespace", namespace, *args]
        unit = "psy-core-" + name + ".service"
        quote = lambda value: '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        preview = "\n".join([
            "[Unit]", "Description=OFFLINE PREVIEW " + name, "After=network-online.target",
            "[Service]", "Type=simple", "User=psy-core", "Group=psy-core",
            "WorkingDirectory=" + release, "UMask=0077",
            *["Environment=" + quote(k + "=" + v) for k, v in env.items()],
            "ExecStart=" + " ".join(quote(arg) for arg in argv), "Restart=on-failure", "",
        ])
        result.append({"host": host, "unit": unit, "namespace": namespace,
                       "environment": dict(env), "argv": argv, "systemd_preview": preview,
                       "deployment_ready": False})

    c = t["coordinator"]
    coord_urls = [f'http://{t["hosts"][c["host"]]}:{p}' for p in c["edge_ports"]]
    coord_args = ["--coordinator-id", "0", "--coordinator-sub-id", "0"]
    backup = ["--genesis-data-path", config_root + "/genesis.json",
              "--checkpoint-backup-path", state + "/checkpoints"]
    policy = ["--worker-whitelist-config", env["PSY_CONFIG_PATH"]]
    add("coordinator-processor", "coordinator-processor", c["host"], c["namespace"], coord_args + backup)
    for index, port in enumerate(c["edge_ports"]):
        add("coordinator-edge", f"coordinator-edge-{index}", c["host"], c["namespace"],
            coord_args + ["--listen", t["hosts"][c["host"]], "--port", str(port)] + policy)
    for rid, position, v in validators(t):
        name = f"realm-{rid}-v{position}"
        key_root = config_root + "/keys/" + name
        processor = ["--realm-id", str(rid), *backup,
                     "--coordinator-api-urls", *coord_urls,
                     "--p2p-identity-key", key_root + "/processor_identity.key",
                     "--p2p-bls-key", key_root + "/bls.key",
                     "--p2p-zk-key", key_root + "/zk.key",
                     "--p2p-listen", f'/ip4/{t["hosts"][v["processor_host"]]}/tcp/{v["processor_port"]}']
        edge = ["--realm-id", str(rid), "--listen", t["hosts"][v["edge_host"]],
                "--port", str(v["http_port"]), *policy,
                "--p2p-identity-key", key_root + "/edge_identity.key",
                "--p2p-listen", f'/ip4/{t["hosts"][v["edge_host"]]}/tcp/{v["edge_port"]}']
        add("realm-processor", name + "-processor", v["processor_host"], v["namespace"], processor)
        add("realm-edge", name + "-edge", v["edge_host"], v["namespace"], edge)
    return result


def make_plan(topology, config=None, genesis=None, whitelist=None):
    validate_topology(topology)
    blockers = [RUNTIME_BLOCKER]
    inputs_valid = False
    if config is None or genesis is None or whitelist is None:
        blockers.append("Provide --config, --genesis and --whitelist for input consistency checks")
    else:
        validate_inputs(topology, config, genesis, whitelist)
        inputs_valid = True
    genesis_args = ["--faucet-operator-count", str(topology["faucet_operator_count"]),
                    "--relayer-registration-id", "2", "--relayer-user-id", "524288"]
    # The generator consumes dense registration order, not Realm membership order.
    for rid, position, validator in sorted(validators(topology), key=lambda item: item[2]["registration_id"]):
        genesis_args.extend(["--validator-slot", f'{rid},{position},{validator["registration_id"]}'])
    return {"mode": "offline-preview", "runtime_commit": topology["runtime_commit"],
            "genesis_account_plan": {
                "faucet_operator_count": topology["faucet_operator_count"],
                "reserved_account_count": 7, "total_user_count": 107,
                "faucet_registration_range": [7, 106],
                "required_generator_account_args": genesis_args,
                "operator_inventory_verified": False,
                "pending": "Verify 100 unique operator identities against Genesis and securely retain keys before Faucet startup"},
            "runtime_source_base": topology["runtime_source_base"],
            "runtime_patch_sha256": topology["runtime_patch_sha256"],
            "network_selection": {"build_stage": topology["psy_network"],
                                  "runtime_stage": topology["psy_network"],
                                  "cli_network": topology["network"],
                                  "proving_backend": topology["proving_backend"],
                                  "config_selector": "networks.testnet"},
            "input_consistency_passed": inputs_valid, "deployment_ready": False,
            "release_approved": False, "blockers": blockers, "pending_checks": PENDING,
            "services": services(topology)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", type=Path, default=HERE / "topology.json")
    for name in ("config", "genesis", "whitelist"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(argv)
    try:
        topology, digest = read_json(args.topology)
        hashes, inputs = {"topology": digest}, {}
        for name in ("config", "genesis", "whitelist"):
            path = getattr(args, name)
            if path is not None:
                inputs[name], hashes[name] = read_json(path)
        report = make_plan(topology, **inputs)
        report["input_sha256"] = hashes
    except (ValueError, OSError, KeyError, TypeError, AttributeError, IndexError) as error:
        message = str(error) if isinstance(error, PlanError) else "Malformed or unreadable input"
        report = {"mode": "offline-preview", "deployment_ready": False, "release_approved": False,
                  "blockers": [message], "services": []}
    print(json.dumps(report, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
