#!/usr/bin/env python3
"""Prepare public Services/indexer inputs offline; never install or activate.

Uses the lock-pinned Services/Indexer builds and the lock-pinned Genesis. No credentials, L1 documents, cursors,
Nostr history or database contents are inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import release_lock

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


def prepare(args, lock):
    require(not os.path.lexists(args.output), "output already exists; preserve partial inputs")
    require(args.output.parent.is_dir(), "output parent missing")
    for path in (args.output.parent, *args.output.parent.parents):
        require(not path.is_symlink(), "output ancestor symlink")
    sources = lock["sources"]
    for label in ("services", "indexer", "genesis"):
        require(sources[label], f"sources.{label} is not pinned in the lock")
    check_source(args.services_source, sources["services"])
    check_source(args.indexer_source, sources["indexer"])
    check_source(args.genesis_source, sources["genesis"])
    genesis_sha256 = lock["inputs"]["genesis"]
    require(digest(args.genesis) == genesis_sha256, "Genesis differs from the lock")
    binaries = {"psy-services": args.services_binary, "psy-indexer": args.indexer_binary}
    for name, path in binaries.items():
        require(digest(path) == lock["binaries"][name], "binary hash mismatch: " + name)
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
        require(decoder.wait() == 0 and restored == genesis_sha256, "compressed Genesis roundtrip mismatch")
    receipt = {
        "schema_version": 2, "scope": "offline-inputs-only", "installable": False, "started": False,
        "services_commit": sources["services"], "indexer_commit": sources["indexer"],
        "runtime_node_commit": sources["runtime"], "genesis_artifacts_commit": sources["genesis"],
        "genesis_sha256": genesis_sha256,
        "files": {str(p.relative_to(args.output)): digest(p) for p in sorted(args.output.rglob("*")) if p.is_file()},
    }
    write_json(args.output / "input-manifest.json", receipt)
    return {"prepared": True, "installable": False, "manifest_sha256": digest(args.output / "input-manifest.json")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--release-lock-sha256", required=True)
    for name in ("services-source", "indexer-source", "genesis-source", "services-binary", "indexer-binary", "genesis", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parsed = parser.parse_args()
    lock = release_lock.load_checked_release_lock(parsed.release_lock, parsed.release_lock_sha256)
    print(json.dumps(prepare(parsed, lock), sort_keys=True))
