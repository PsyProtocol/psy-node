#!/usr/bin/env python3
"""Offline, import-only Genesis preparation. No remote or lifecycle operations.

plan/generate --spec PUBLIC.json --private-keys-in FILE
              --private-keys-sha256 SHA256 --output NEW_DIRECTORY

Spec v1: schema_version, block_time, inputs, compiler_artifacts. Each input is
{path: absolute_path, sha256: lowercase_hex}. inputs contains binary, config,
bundle, bundle_stamp, validator, measurements, build_identity, prior_genesis. compiler_artifacts
contains the six CONTRACTS below. build_identity is an operator-approved public
record with schema_version=1, source_commit, psy_network=testnet,
cli_network=psy-public-testnet, proving_backend=plonky2-poseidon-goldilocks,
private_keys_mode=import-only, binary_sha256, config_sha256. Its provenance is
caller-supplied; this tool does not build or attest binaries. measurements uses
the separately pinned typed validator's schema. No arbitrary child args/env.

prior_genesis is the retained public account/role baseline, not a private-key
source. It may contain legacy contracts without state_layout; only the native
generator validates its account identities and validator role/user-ID mapping.
It must be an existing input outside the new output directory, never a new output.
The source generator must implement --private-keys-in/--private-keys-sha256 and
--accounts-genesis-in/--accounts-genesis-sha256, with identity checks before writes.
There is no random-key fallback. ready_static never means deployment approval.
Child stdout/stderr are retained in exclusive mode-0600 logs in the protected
output directory. Treat both logs as private; never publish or stream their content.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
import prepare_network as network


CONTRACTS = ("token", "multisig_policy", "deposit_tree", "withdrawal_tree", "usdt_token", "faucet")
INPUTS = ("binary", "config", "bundle", "bundle_stamp", "validator", "measurements", "build_identity",
          "prior_genesis")
TIMEOUT = 7200
MAX_INPUT = 1024 * 1024 * 1024
require = network.require


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256")
    return value


def absolute_path(value, *, missing=False):
    require(isinstance(value, (str, Path)), "invalid input path")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "absolute paths without parent traversal required")
    for parent in reversed((path, *path.parents)):
        if missing and parent == path:
            require(not os.path.lexists(parent), "output already exists")
            continue
        info = parent.lstat()
        require(not stat.S_ISLNK(info.st_mode), "symlink path rejected")
        if parent != path:
            require(stat.S_ISDIR(info.st_mode), "non-directory ancestor")
    return path


def read_file(path, *, secret=False):
    path = absolute_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_INPUT,
                "input must be a bounded single-link regular file")
        if secret:
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    "private input/output must be owned mode 0600")
        data = handle.read(MAX_INPUT + 1)
        require(len(data) <= MAX_INPUT, "input size exceeded")
    return data, (info.st_dev, info.st_ino)


def document(raw):
    return json.loads(raw, object_pairs_hook=network.unique_object, parse_constant=network.reject_constant)


def pinned(entry, *, secret=False):
    network.fields(entry, ("path", "sha256"), "pinned input")
    raw, inode = read_file(entry["path"], secret=secret)
    require(sha256(raw) == digest(entry["sha256"]), "input SHA256 mismatch")
    return raw, inode


def account_args():
    slots = sorted((registration, rid, position) for rid, members in enumerate(network.SLOTS)
                   for position, (registration, _) in enumerate(members, 1))
    args = ["--faucet-operator-count", "100", "--relayer-registration-id", "2",
            "--relayer-user-id", "524288", "--coordinator-global-user-tree-height", "12",
            "--realm-global-user-tree-height", "20", "--group-realm-height", "1"]
    for registration, rid, position in slots:
        args.extend(["--validator-slot", f"{rid},{position},{registration}"])
    return args


def load(spec_path, keys_path, keys_sha, output):
    spec_raw, spec_inode = read_file(spec_path)
    spec = document(spec_raw)
    network.fields(spec, ("schema_version", "block_time", "inputs", "compiler_artifacts"), "Genesis spec")
    require(type(spec["schema_version"]) is int and spec["schema_version"] == 1, "unsupported spec")
    network.integer(spec["block_time"], 0, 18446744069414584320, "block time")
    network.fields(spec["inputs"], INPUTS, "Genesis inputs")
    network.fields(spec["compiler_artifacts"], CONTRACTS, "compiler artifacts")
    entries = dict(spec["inputs"])
    entries.update({"compiler_" + name: entry for name, entry in spec["compiler_artifacts"].items()})
    entries["private_keys"] = {"path": str(keys_path), "sha256": digest(keys_sha)}
    data, inodes = {}, {spec_inode}
    for name, entry in entries.items():
        raw, inode = pinned(entry, secret=name == "private_keys")
        require(inode not in inodes, "input paths alias one another")
        inodes.add(inode)
        if name != "private_keys":
            data[name] = raw
        # Do not retain key bytes in the public-input staging map.
        del raw
    for name in ("binary", "validator"):
        require(os.access(entries[name]["path"], os.X_OK), "pinned executable is not executable")
    out = absolute_path(output, missing=True)
    parent = out.parent.stat()
    require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
            "output parent must be owned and not writable by group/others")
    paths = [Path(spec_path), *(Path(entry["path"]) for entry in entries.values())]
    require(all(out != path and out not in path.parents for path in paths), "output aliases an input")

    identity = document(data["build_identity"])
    network.fields(identity, ("schema_version", "source_commit", "psy_network", "cli_network",
                            "proving_backend", "private_keys_mode", "binary_sha256", "config_sha256"),
                   "build identity")
    require(type(identity["schema_version"]) is int and identity["schema_version"] == 1,
            "unsupported build identity")
    require(isinstance(identity["source_commit"], str)
            and re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"]), "invalid source commit")
    require(identity["psy_network"] == "testnet" and identity["cli_network"] == "psy-public-testnet"
            and identity["proving_backend"] == "plonky2-poseidon-goldilocks"
            and identity["private_keys_mode"] == "import-only", "wrong build network/backend/key mode")
    require(identity["binary_sha256"] == entries["binary"]["sha256"]
            and identity["config_sha256"] == entries["config"]["sha256"], "build identity pins differ")
    measurements = document(data["measurements"])
    require(measurements.get("network") == "testnet"
            and measurements.get("node_source_commit") == identity["source_commit"]
            and measurements.get("config_sha256") == identity["config_sha256"], "measurement provenance mismatch")
    config = document(data["config"])
    require(config.get("defaultNetwork") == "testnet", "config must select testnet")
    selected = config["networks"]["testnet"]
    network.validate_consensus(selected)
    for rid, realm in enumerate(network.ordered_realms(selected)):
        members = realm["validators"]
        require(len(members) == len(network.SLOTS[rid]), "three validators per Realm required")
        for member, (_, uid) in zip(members, network.SLOTS[rid]):
            require(type(member["validator_user_id"]) is int and member["validator_user_id"] == uid,
                    "membership order differs from existing approved slots")
    # Full public membership validation remains owned by prepare_network/native generator.
    summary = {"schema_version": 1, "status": "PLANNED", "ready_static": False,
               "deployment_ready": False, "source_commit": identity["source_commit"],
               "spec_sha256": sha256(spec_raw), "input_sha256": {k: v["sha256"] for k, v in entries.items()},
               "users": 107, "validators": 6, "faucet_operators": 100,
               "key_mode": "import-only", "output": str(out)}
    return spec, entries, data, config, out, summary


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def write_json(path, value):
    write_new(path, (json.dumps(value, indent=2, allow_nan=False) + "\n").encode())


def recheck(entries):
    for name, entry in entries.items():
        pinned(entry, secret=name == "private_keys")


def run_child(command, repo, env, log_path):
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as log:
        try:
            subprocess.run(command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                           stdout=log, stderr=subprocess.STDOUT, timeout=TIMEOUT, check=True)
        finally:
            log.flush()
            os.fsync(log.fileno())


def verify_inventory(out, entry):
    # Equality/count checks only; native Rust owns key decoding and identity derivation.
    source = document(pinned(entry, secret=True)[0])
    retained = document(read_file(out / "private_keys.json", secret=True)[0])
    require(isinstance(source, list) and len(source) == 107 and source == retained,
            "imported private-key inventory was not retained exactly")
    operators = document(read_file(out / "faucetOperators.json", secret=True)[0]).get("operators")
    require(isinstance(operators, list) and len(operators) == 100, "100 faucet operators required")
    ids = [operator.get("userId") for operator in operators if isinstance(operator, dict)]
    require(len(ids) == 100 and all(isinstance(uid, str) and uid.isascii() and uid.isdecimal() for uid in ids)
            and len(set(ids)) == 100, "operator user IDs must be distinct decimal strings")


def generate(loaded):
    spec, entries, data, config, out, summary = loaded
    # Exclusive directory creation is the single-attempt boundary; never resume or clean it.
    old_umask = os.umask(0o077)
    created, stage = False, "reserve-output"
    try:
        out.mkdir(mode=0o700)
        created = True
        summary["child_logs"] = {}
        stage = "stage-public-inputs"
        work = out / "work"
        repo = work / "psy-node"
        public = repo / "psy-genesis"
        public.mkdir(parents=True, mode=0o700)
        home = out / "home"
        home.mkdir(mode=0o700)
        write_new(repo / ".env", b"")  # Stop dotenv searching shared ancestor directories.
        write_new(public / "config.json", data["config"])
        write_new(public / "genesis_contracts.json", data["bundle"])
        write_new(public / ".genesis_contracts.compiler-artifact.json", data["bundle_stamp"])
        write_new(out / "measurements.json", data["measurements"])
        for name in CONTRACTS:
            target = work / "psy-compiler" / "psy-precompiles" / name / "target"
            target.mkdir(parents=True, mode=0o700)
            write_new(target / (name + ".json"), data["compiler_" + name])
        write_json(out / "plan.json", summary)
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "PSY_NETWORK": "testnet",
               "PSY_CONFIG_PATH": str(public / "config.json"), "PSY_PROJECTS_DIR": str(work),
               "RUST_LOG": "off", "RUST_BACKTRACE": "0"}
        command = [entries["binary"]["path"], "generate-genesis-data", "--repo-root", str(repo),
                   "--genesis-contracts", str(public / "genesis_contracts.json"),
                   "--private-keys-in", entries["private_keys"]["path"],
                   "--private-keys-sha256", entries["private_keys"]["sha256"],
                   "--accounts-genesis-in", entries["prior_genesis"]["path"],
                   "--accounts-genesis-sha256", entries["prior_genesis"]["sha256"],
                   "--genesis-out", str(out / "generated-genesis.json"),
                   "--private-keys-out", str(out / "private_keys.json"),
                   "--faucet-operators-out", str(out / "faucetOperators.json"),
                   "--block-time", str(spec["block_time"]), *account_args()]
        stage = "generate-genesis-data"
        recheck(entries)
        log_path = out / "generate-genesis-data.private.log"
        summary["child_logs"][stage] = str(log_path)
        run_child(command, repo, env, log_path)
        recheck(entries)
        stage = "inject-membership"
        genesis = network.read_public_json(out / "generated-genesis.json", max_bytes=MAX_INPUT)
        genesis = network.inject_genesis(genesis, config)
        require(len(genesis["validators"]) == 6, "six injected validators required")
        write_json(out / "genesis.json", genesis)
        stage = "verify-imported-inventory"
        verify_inventory(out, entries["private_keys"])
        stage = "typed-cbor-validation"
        command = [entries["validator"]["path"], "--bundle", str(public / "genesis_contracts.json"),
                   "--genesis", str(out / "genesis.json"), "--measurements", str(out / "measurements.json")]
        log_path = out / "typed-cbor-validation.private.log"
        summary["child_logs"][stage] = str(log_path)
        run_child(command, repo, env, log_path)
        recheck(entries)
        summary.update(status="READY_STATIC", ready_static=True,
                       genesis_sha256=sha256(read_file(out / "genesis.json")[0]))
        write_json(out / "result.json", summary)
        return summary
    except BaseException:
        if created:
            summary.update(status="FAILED", ready_static=False, failed_stage=stage)
            write_json(out / "FAILED", summary)
        raise
    finally:
        os.umask(old_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "generate"))
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--private-keys-in", required=True, type=Path)
    parser.add_argument("--private-keys-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        loaded = load(args.spec, args.private_keys_in, args.private_keys_sha256, args.output)
        summary = loaded[-1] if args.mode == "plan" else generate(loaded)
    except (Exception, KeyboardInterrupt):
        # Never print exception strings: child argv, file content and JSON errors may contain secrets.
        failure = {"status": "FAILED", "ready_static": False, "deployment_ready": False,
                   "error": "Genesis preparation rejected; inspect protected FAILED marker if created"}
        if "loaded" in locals() and loaded[-1].get("status") == "FAILED":
            failure.update(failed_stage=loaded[-1]["failed_stage"], child_logs=loaded[-1].get("child_logs", {}))
        print(json.dumps(failure))
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
