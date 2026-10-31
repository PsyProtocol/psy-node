#!/usr/bin/env python3
"""Read-only 192-cohort source/config preflight; never build, reset or activate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


HERE = Path(__file__).resolve().parent


def release_checks(release):
    expected = {"schema_version": 1, "deployment_branch": "deploy/testnet", "network": "testnet",
                "cli_network": "psy-public-testnet", "network_magic": "0x1337CF514544CF69",
                "proving_backend": "plonky2-poseidon-goldilocks", "checkpoints_per_epoch": 32,
                "sd_key_max_calldata_words": 192, "max_introspectable_transactions": 64,
                "faucet_operator_count": 100, "genesis_spec_version": 2,
                "account_identity_mode": "fresh-faucet-and-relayer",
                "native_deposits_allowed": False, "public_deposits_after_deploy": False,
                "bridge_reader_included": False, "deposit_tokens": {"PSY": 0, "pUSDT": 4},
                "withdrawal_append_supported_batch_sizes": [1, 2, 5], "withdrawal_append_max_batch_size": 5}
    for key, value in expected.items():
        if type(release.get(key)) is not type(value) or release[key] != value:
            raise ValueError("unsupported release choice")
    if not re.fullmatch(r"[0-9a-f]{40}", release["runtime_candidate_commit"]):
        raise ValueError("full runtime commit required")
    if type(release.get("runtime_inputs_frozen")) is not bool:
        raise ValueError("runtime input finality must be explicit")
    if not re.fullmatch(r"[0-9a-f]{64}", release["runtime_config_sha256"]):
        raise ValueError("runtime config hash required")
    lease = release.get("worker_queue_ack_wait_ms")
    if type(lease) is not int or not 1 <= lease < 2**63:
        raise ValueError("positive worker queue lease required")
    if release.get("redis_maxmemory_policy") != "noeviction":
        raise ValueError("replay protection requires noeviction Redis")
    if not re.fullmatch(r"fresh[0-9]{8}sd192", release["namespace_prefix"]):
        raise ValueError("invalid fresh namespace")
    if not re.fullmatch(r"core-testnet-[0-9]{8}-sd192", release["release_id"]):
        raise ValueError("invalid release id")
    if release["chains"] != [{"name": "sepolia", "index": 0, "chain_id": 11155111},
                             {"name": "bscTestnet", "index": 1, "chain_id": 97},
                             {"name": "baseSepolia", "index": 2, "chain_id": 84532}]:
        raise ValueError("chain identity mismatch")
    coordinators = release["coordinator_configs"]
    if coordinators != [{"id": 0, "rpc_url": [f"http://10.148.0.25:{port}" for port in (15370, 15371, 15372)]}]:
        raise ValueError("unapproved internal Coordinator placement")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def document(path, expected_sha256=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular public input required")
        raw = stream.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("public input exceeds size limit")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("public input hash mismatch")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError("object required")
    return value


def source_checks(source, release):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    def git(*args):
        return subprocess.check_output(
            ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(source), *args],
            text=True, stderr=subprocess.DEVNULL, env=environment).strip()
    if git("rev-parse", "HEAD") != release["runtime_candidate_commit"]:
        raise ValueError("source commit differs from the published 192 candidate")
    if git("status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"):
        raise ValueError("runtime source is not clean")
    code = (Path(source) / "client_prover/psy_core/psy_data/src/dpn/sd_key.rs").read_text()
    for name, field in (("SDKEY_MAX_CALLDATA_WORDS", "sd_key_max_calldata_words"),
                        ("MAX_INTROSPECTABLE_TRANSACTIONS", "max_introspectable_transactions")):
        match = re.search(rf"^pub const {name}: u32 = (\d+);$", code, re.MULTILINE)
        if not match or int(match[1]) != release[field]:
            raise ValueError("runtime SD-key capacity differs from the release profile")


def config_checks(config, release):
    if config.get("defaultNetwork") != "testnet":
        raise ValueError("runtime config must select testnet")
    network = config.get("networks", {}).get("testnet", {})
    if network.get("magic") != release["network_magic"]:
        raise ValueError("testnet magic mismatch")
    epoch = network.get("p2p", {}).get("checkpoints_per_epoch")
    if type(epoch) is not int or epoch != release["checkpoints_per_epoch"]:
        raise ValueError("testnet epoch must be 32, not the R3 epoch")
    if network.get("coordinator_configs") != release["coordinator_configs"]:
        raise ValueError("internal Coordinator endpoints differ from release")
    if network.get("guardian_configs") != release["guardian_configs"]:
        raise ValueError("Guardian endpoints differ from release")
    whitelist = network.get("whitelist", {})
    keys = whitelist.get("secp256k1", [])
    if whitelist.get("enabled") is not True or not isinstance(keys, list) or not keys:
        raise ValueError("owned worker whitelist must be enabled and nonempty")
    if any(not isinstance(key, str) or not re.fullmatch(r"0[23][0-9a-f]{64}", key) for key in keys) or len(set(keys)) != len(keys):
        raise ValueError("invalid or duplicate worker public keys")
    members = network.get("guardian_initial_member_hashes", [])
    if not isinstance(members, list) or len(members) != 3 or any(
            not isinstance(member, str) or not re.fullmatch(r"[0-9a-fA-F]{1,64}", member) or int(member, 16) == 0
            for member in members) or len({int(member, 16) for member in members}) != 3:
        raise ValueError("three distinct retained Guardian commitments required")
    realms = network.get("realm_configs", [])
    if not isinstance(realms, list) or len(realms) != 2:
        raise ValueError("two Realms with three retained validators each required")
    users, nodes, bls_keys = set(), set(), set()
    for index, realm in enumerate(realms):
        if not isinstance(realm, dict) or type(realm.get("id")) is not int or realm["id"] != index:
            raise ValueError("ordered Realm ids required")
        validators = realm.get("validators")
        if not isinstance(validators, list) or len(validators) != 3:
            raise ValueError("three validator objects per Realm required")
        for validator in validators:
            if not isinstance(validator, dict):
                raise ValueError("validator object required")
            user = validator.get("validator_user_id")
            if type(user) is not int or user < 0 or user >> 20 != index or user in users:
                raise ValueError("invalid or duplicate validator user id")
            users.add(user)
            key = validator.get("bls_public_key")
            if not isinstance(key, str) or not re.fullmatch(r"[0-9a-fA-F]{96}", key) or int(key, 16) == 0 or key.lower() in bls_keys:
                raise ValueError("invalid or duplicate validator BLS key")
            bls_keys.add(key.lower())
            edges = validator.get("edge_nodes")
            if not isinstance(edges, list) or len(edges) != 1 or not isinstance(edges[0], dict):
                raise ValueError("one edge identity per validator required")
            for member, field in ((validator, "processor_node_id"), (edges[0], "node_id")):
                node = member.get(field)
                if not isinstance(node, str) or not re.fullmatch(r"002408011220[0-9a-fA-F]{64}", node) or int(node[12:], 16) == 0 or node.lower() in nodes:
                    raise ValueError("invalid or duplicate validator NodeId")
                nodes.add(node.lower())
                addresses = member.get("processor_addresses" if field == "processor_node_id" else "addresses")
                if not isinstance(addresses, list) or not addresses or any(not isinstance(value, str) or not value for value in addresses):
                    raise ValueError("public peer addresses required")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    release = document(HERE / "release.json")
    try:
        release_checks(release)
    except (ValueError, KeyError, TypeError):
        print(json.dumps({"mode": "read-only-preflight", "deployment_ready": False,
                          "activation_authorized": False, "blockers": ["release profile failed validation"]}))
        return 2
    report = {"mode": "read-only-preflight", "release_id": release["release_id"],
              "runtime_candidate_commit": release["runtime_candidate_commit"],
              "source_preflight_passed": False, "config_preflight_passed": False,
              "deployment_ready": False, "activation_authorized": False,
              "blockers": [], "required_next_actions": release["required_next_actions"]}
    for name, path, check in (("source", args.source, source_checks), ("config", args.config, config_checks)):
        if path is None:
            report["blockers"].append(f"Provide --{name} for this preflight")
            continue
        try:
            check(path if name == "source" else document(path, release["runtime_config_sha256"]), release)
            report[f"{name}_preflight_passed"] = True
        except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError):
            report["blockers"].append(f"{name} input failed validation; no input values were logged")
    print(json.dumps(report, indent=2))
    return 0 if not report["blockers"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
