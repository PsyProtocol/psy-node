#!/usr/bin/env python3
"""Prepare private, host-specific core packages locally; never SSH or start nodes."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

import plan


HERE = Path(__file__).resolve().parent
NODE_SHA256 = "9b7a792da5c8cb45ec1c2db022ac52ce405e5cd05d154a1c7ac7c4941faaf9cb"
CONFIG_SHA256 = "c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0"
GENESIS_SHA256 = "a5465bd712ceb66585660fddb4ac233afb747938395adaa200a63ead2f25f2c8"


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def regular(path, private=False):
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), "symlink input rejected")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), "regular input required")
    if private:
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "private input must be owned by this user and mode 0600")
    return path


def unit_text(service, release_id):
    quote = lambda value: '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    state = f"/var/lib/psy-core/{release_id}"
    env = dict(service["environment"], RUST_LOG="info", RUST_MIN_STACK="134217728",
               RAYON_NUM_THREADS="2")
    return "\n".join([
        "[Unit]", "Description=Psy testnet " + service["unit"],
        "Wants=network-online.target", "After=network-online.target",
        "StartLimitIntervalSec=600", "StartLimitBurst=3", "",
        "[Service]", "Type=simple", "User=psy-core", "Group=psy-core",
        f"WorkingDirectory=/opt/psy-core/releases/{release_id}", "UMask=0077",
        *["Environment=" + quote(k + "=" + v) for k, v in env.items()],
        "ExecStart=" + " ".join(quote(arg) for arg in service["argv"]),
        "Restart=on-failure", "RestartSec=10", "TimeoutStopSec=300",
        "KillSignal=SIGTERM", "LimitNOFILE=65536", "LimitCORE=0",
        "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true",
        "ProtectSystem=strict", "ReadWritePaths=" + state,
        "StandardOutput=journal", "StandardError=journal", "",
        "[Install]", "WantedBy=multi-user.target", "",
    ])


def write_new(path, content, mode=0o600):
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def publish_packages(source, destination):
    # Linux RENAME_NOREPLACE prevents replacing even a concurrently created empty directory.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        raise OSError(ctypes.get_errno(), "package publication failed; destination not replaced")


def prepare(args):
    require(NODE_SHA256 is not None and GENESIS_SHA256 is not None, "r2 artifact pins not frozen")
    topology, _ = plan.read_json(args.topology)
    config, config_hash = plan.read_json(regular(args.config))
    genesis, genesis_hash = plan.read_json(regular(args.genesis))
    whitelist, _ = plan.read_json(args.whitelist)
    report = plan.make_plan(topology, config, genesis, whitelist)
    require(report["input_consistency_passed"], "public inputs inconsistent")
    require(config_hash == CONFIG_SHA256, "config differs from compiled testnet config")
    require(genesis_hash == GENESIS_SHA256, "Genesis hash mismatch")
    node_hash = digest(regular(args.node_binary))
    require(node_hash == NODE_SHA256, "node binary hash mismatch")
    private_keys = json.loads(regular(args.private_keys, True).read_bytes())
    require(isinstance(private_keys, list) and len(private_keys) == 107 and private_keys[2] is None,
            "private registration inventory mismatch")
    secrets = [key for key in private_keys if key is not None]
    require(len(secrets) == 106 and len(set(secrets)) == 106
            and all(re.fullmatch(r"[0-9a-f]{64}", key) for key in secrets),
            "invalid private registration inventory")
    operators = json.loads(regular(args.faucet_operators, True).read_bytes())
    entries = operators.get("operators", [])
    require(len(entries) == 100 and len({x["userId"] for x in entries}) == 100,
            "faucet inventory must contain 100 unique user IDs")
    for index, operator in enumerate(entries, 7):
        # Strategy5: alternate Realms; bit-reverse the registration within each Realm.
        uid = ((index & 1) << 20) | int(f"{index >> 1:020b}"[::-1], 2)
        require(int(operator["userId"]) == uid and operator["privateKey"] == private_keys[index]
                and operator["fingerprint"] == genesis["users"][index]["public_key_info"]["fingerprint"],
                "faucet inventory does not match generated Genesis")
    key_inputs = {}
    for rid, position, validator in plan.validators(topology):
        stem = f"realm_{rid}_sub_{position}"
        key_inputs[(rid, position)] = {
            name: regular(args.p2p_keys / f"{stem}_{name}", True)
            for name in ("processor_identity.key", "edge_identity.key", "bls.key")
        }
    require(not os.path.lexists(args.output), "output already exists; refuse replacement")
    for parent in (args.output.parent, *args.output.parent.parents):
        require(not parent.is_symlink(), "symlink output ancestor rejected")
    staging = Path(tempfile.mkdtemp(prefix=".psy-core-packages-", dir=args.output.parent))
    try:
        build_packages(args, staging, topology, report, private_keys, key_inputs,
                       {"bin/psy_node_cli": node_hash, "config.json": config_hash, "genesis.json": genesis_hash})
        publish_packages(staging, args.output)
    except BaseException:
        shutil.rmtree(staging)
        raise
    print(json.dumps({"packages": len(topology["hosts"]), "services": len(report["services"]),
                      "faucet_operators": 100, "installed": False, "started": False}))


def build_packages(args, staging, topology, report, private_keys, key_inputs, hashes):
    for host, ip in topology["hosts"].items():
        root = staging / host
        root.mkdir(mode=0o700)
        for name, source in (("bin/psy_node_cli", args.node_binary), ("config.json", args.config),
                             ("genesis.json", args.genesis)):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, target)
            target.chmod(0o700 if name.startswith("bin/") else 0o600)
            require(digest(target) == hashes[name], f"copied {name} hash mismatch")
        services = [s for s in report["services"] if s["host"] == host]
        for service in services:
            write_new(root / "units" / service["unit"], unit_text(service, topology["release_id"]).encode())
        for rid, position, validator in plan.validators(topology):
            key_root = root / "keys" / f"realm-{rid}-v{position}"
            inputs = key_inputs[(rid, position)]
            if validator["processor_host"] == host:
                for name in ("processor_identity.key", "bls.key"):
                    write_new(key_root / name, inputs[name].read_bytes())
                write_new(key_root / "zk.key", (private_keys[validator["registration_id"]] + "\n").encode())
            if validator["edge_host"] == host:
                write_new(key_root / "edge_identity.key", inputs["edge_identity.key"].read_bytes())
        files = {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob("*")) if p.is_file()}
        require(all(files[name] == expected for name, expected in hashes.items()),
                "package payload differs from validated inputs")
        manifest = {"schema_version": 1, "release_id": topology["release_id"],
                    "source_commit": topology["runtime_commit"], "network": "testnet",
                    "host": host, "private_ip": ip, "files": files}
        write_new(root / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", type=Path, default=HERE / "topology.json")
    parser.add_argument("--whitelist", type=Path, default=HERE / "worker-whitelist.json")
    for name in ("config", "genesis", "node-binary", "private-keys", "faucet-operators", "p2p-keys", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
