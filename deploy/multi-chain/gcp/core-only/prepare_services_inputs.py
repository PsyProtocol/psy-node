#!/usr/bin/env python3
"""Prepare public R3 Services/indexer inputs offline; never install or activate.

Uses the retained Services/Indexer builds and fresh core artifacts. No credentials,
old L1 documents, cursors, Nostr history or database contents are inputs. The
output deliberately contains no executable install/start entrypoint or final
Services configuration until fresh L1 documents and deployment guards are bound.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

SERVICES_COMMIT = "dfd4e4837a068d67c43cc013f204053e06d1a153"
INDEXER_COMMIT = "9de6b34671fb52addf6c5f4790eae932a363bc92"
NODE_BUILD_COMMIT = "da6391549e44d49c07e856eaeb5d0b8d7902ef17"
RUNTIME_COMMIT = "3d31758738f833a7eea6f9ff7fd680a69a0d9a44"
GENESIS_COMMIT = "9420e2c9799ce29487e9d0cca1d1121fbfb4cf40"
GENESIS_SHA256 = "f839b453ab130c29998620c4c5d4bf9a30ce341a2e7c480aa9dbd8ed10902173"
CONFIG_SHA256 = "c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0"
BINARY_SHA256 = {
    "psy-services": "27071ac53edf861e33a3c59d2ffce819bd6b84a9bf3cc85627b960cda6c6699e",
    "psy-indexer": "d2a1cd3c2ddaac55b7dc5d87471ea5aafe89d44448c732a1ab7ade5986d18a53",
}
BACKUPS = "/var/lib/psy-core/core-testnet-20261027-r3/checkpoints"
MIRROR = "/var/lib/psy-indexer-r3-mirror"
RELEASE = "/opt/psy-services/releases/core-testnet-20261027-dfd4e483-r3"
ABI_NAMES = ("PsyTokenContract", "MultisigPolicyContract", "PsyDepositTreeContract",
             "PsyWithdrawalTreeContract", "USDTTokenContract", "PsyFaucetContract")
HEIGHTS = (32, 4, 21, 15, 32, 31)
METHOD_COUNTS = (10, 2, 9, 7, 10, 1)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(), "regular input required")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def check_source(source, commit):
    require(git(source, "rev-parse", "HEAD") == commit, "source commit mismatch")
    require(not git(source, "status", "--porcelain", "--untracked-files=no"), "tracked source changes")


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as target:
        target.write(raw)


def write_json(path, value):
    write_new(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def read_abis(root):
    listing = json.loads((root / "abi_list.json").read_bytes())
    rows = listing["precompiles"]
    require(len(rows) == 6 and not listing["users"] and not listing["contracts"], "active ABI set mismatch")
    result = {"abi_list.json": (root / "abi_list.json").read_bytes()}
    for index, name in enumerate(ABI_NAMES):
        row = rows[index]
        require(row["contract_id"] == index and row["abi_path"] == name + ".json"
                and row["state_tree_height"] == HEIGHTS[index], "ABI slot mismatch")
        raw = (root / row["abi_path"]).read_bytes()
        contract = json.loads(raw)["contract"]
        methods = contract["methods"]
        require(contract["name"] == name and contract["state_tree_height"] == HEIGHTS[index]
                and len(methods) == METHOD_COUNTS[index], "ABI methods/height mismatch")
        require(len({method["method_id"] for method in methods}) == len(methods), "duplicate method")
        require(contract["state_layout"]["field_count"] > 0, "canonical layout missing")
        if index in (0, 4):
            require({"mint", "burn"} <= {method["name"] for method in methods}, "token mint/burn missing")
        if index == 3:
            require(any(method["name"] == "set_chain_root" and method["method_id"] == 4192350829
                        and method["input_felt_count"] == 10 and method["output_felt_count"] == 0
                        for method in methods), "withdrawal setter missing")
        result[row["abi_path"]] = raw
    return result


def realm_sources(realm):
    return {
        "coordinator_rpc_url": "http://10.148.0.25:15370",
        "coordinator_backup_base_dir": MIRROR + "/cp/checkpoints",
        "validators": [{
            "realm_sub_id": sub,
            "edge_rpc_url": f"http://10.148.0.{36 if realm == 0 else 35}:{15380 + realm * 3 + sub - 1}",
            "backup_base_dir": BACKUPS if sub == 1 else f"{MIRROR}/v{sub}/checkpoints",
        } for sub in (1, 2, 3)],
    }


def topology():
    return {
        "release": RELEASE, "credentials": "/etc/psy-services-fresh-20261027-r3",
        "database": "psy_services_fresh_20261027_r3", "database_owner": "psy_services_fresh_20261026",
        "postgres_host": "10.148.0.24", "redis_url": "redis://10.148.0.12:6379/14",
        "redis_prefix": "psy_svc_fresh_20261027_r3:", "backup_dir": BACKUPS,
        "cursor_dir": BACKUPS + "/indexer_state", "mirror_dir": MIRROR,
        "nostr_state": "/var/lib/psy-services-fresh-20261027-r3/nostr",
        "nostr_enabled": False, "bridge_reader_enabled": False,
        "services_url": "http://10.148.0.38:3001",
        "hasura_url": "http://10.148.0.24:38081/v1/graphql",
        "envio_database": "envio_bridge_fresh_20261027_r3",
        "envio_project": "psy-envio-fresh-20261027-r3",
        "envio_indexer_port": 29899,
        "roles": {
            "services": {"host": "10.148.0.38", "user": "parth"},
            "coordinator": {"host": "10.148.0.25", "user": "psy-core", "backup_subdir": "coordinator_0_0"},
            "realm0": {"host": "10.148.0.37", "user": "psy-core", "backup_subdir": "realm_0_1"},
            "realm1": {"host": "10.148.0.37", "user": "psy-core", "backup_subdir": "realm_1_1"},
        },
        "mirror_sources": {
            "cp": {"host": "10.148.0.25", "root": BACKUPS, "roles": ["coordinator_0_0"]},
            "v2": {"host": "10.148.0.42", "root": BACKUPS, "roles": ["realm_0_2", "realm_1_2"]},
            "v3": {"host": "10.148.0.43", "root": BACKUPS, "roles": ["realm_0_3", "realm_1_3"]},
        },
    }


def prepare(args):
    require(not os.path.lexists(args.output), "output already exists; preserve partial inputs")
    require(args.output.parent.is_dir(), "output parent missing")
    for path in (args.output.parent, *args.output.parent.parents):
        require(not path.is_symlink(), "output ancestor symlink")
    check_source(args.services_source, SERVICES_COMMIT)
    check_source(args.indexer_source, INDEXER_COMMIT)
    check_source(args.genesis_source, GENESIS_COMMIT)
    require(digest(args.genesis) == GENESIS_SHA256, "fresh Genesis mismatch")
    binaries = {"psy-services": args.services_binary, "psy-indexer": args.indexer_binary}
    for name, path in binaries.items():
        require(digest(path) == BINARY_SHA256[name], "binary hash mismatch: " + name)
    abis = read_abis(args.genesis_source / "genesis_abi")
    require(shutil.disk_usage(args.output.parent).free > args.genesis.stat().st_size + 128 * 1024**2,
            "insufficient staging capacity")
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    for name, source in binaries.items():
        write_new(args.output / name, source.read_bytes())
        (args.output / name).chmod(0o700)
    for name, raw in abis.items():
        write_new(args.output / "genesis_abi" / name, raw)
    for name in git(args.services_source, "ls-files", "migrations").splitlines():
        path = args.services_source / name
        require(not path.is_symlink() and path.is_file(), "migration source is not regular")
        write_new(args.output / name, path.read_bytes())
    subprocess.run(["zstd", "-q", "-T2", "-3", str(args.genesis), "-o", str(args.output / "genesis.json.zst")], check=True)
    with subprocess.Popen(["zstd", "-q", "-d", "-c", str(args.output / "genesis.json.zst")], stdout=subprocess.PIPE) as decoder:
        restored = hashlib.file_digest(decoder.stdout, "sha256").hexdigest()
        require(decoder.wait() == 0 and restored == GENESIS_SHA256, "compressed Genesis roundtrip mismatch")
    write_json(args.output / "topology.json", topology())
    for realm in (0, 1):
        write_json(args.output / f"realm{realm}.json", realm_sources(realm))
    write_new(args.output / "create-database.sql", b"CREATE DATABASE psy_services_fresh_20261027_r3 OWNER psy_services_fresh_20261026;\n")
    receipt = {
        "schema_version": 1, "scope": "offline-fresh-inputs-only", "installable": False, "started": False,
        "services_commit": SERVICES_COMMIT, "indexer_commit": INDEXER_COMMIT,
        "binary_node_dependency_commit": NODE_BUILD_COMMIT, "runtime_node_commit": RUNTIME_COMMIT,
        "genesis_artifacts_commit": GENESIS_COMMIT, "genesis_sha256": GENESIS_SHA256,
        "runtime_config_sha256": CONFIG_SHA256,
        "genesis_generation_provenance": "Retained f839 artifact; not regenerated or relabeled by this preparation.",
        "pending": ["Fresh three-chain deployment documents and hash-pinned Services L1 config",
                    "Fresh Envio database and isolated Hasura at port38081; never use old28080/28081",
                    "R3 install/activation and backup-mirror helpers with old-instance fencing",
                    "On-host create-only database and protected environment preparation",
                    "Retained Services binary preview of this Genesis/ABI; no database writes"],
        "files": {str(p.relative_to(args.output)): digest(p) for p in sorted(args.output.rglob("*")) if p.is_file()},
    }
    write_json(args.output / "input-manifest.json", receipt)
    return {"prepared": True, "installable": False, "manifest_sha256": digest(args.output / "input-manifest.json")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("services-source", "indexer-source", "genesis-source", "services-binary", "indexer-binary", "genesis", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    print(json.dumps(prepare(parser.parse_args()), sort_keys=True))
