#!/usr/bin/env python3
"""Assemble immutable per-host lab inputs locally; never connect/start/format hosts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "platform"))
import lab


def write(path, value):
    if not isinstance(value, str):
        value = json.dumps(value, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("x") as stream:
        stream.write(value)
    path.chmod(0o600)


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with source.open("rb") as src, target.open("xb") as dest:
        shutil.copyfileobj(src, dest)
    target.chmod(0o600)


def clean_revision():
    root = HERE.parents[2]
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    lab.require(not git("status", "--porcelain"), "Commit/review the source first; delivery provenance requires a clean checkout")
    return git("rev-parse", "HEAD")


def assemble(config, assets, output, revision):
    config = lab.validate(config)
    lab.require(lab.local_control(config), "Only the four-node local-control-plane topology is supported")
    # Verify all fixed assets before creating any output. Real images remain inputs,
    # never backing files or disks attached directly to a guest.
    for name, spec in lab.LOCK.items():
        lab.require(lab.digest(assets / name) == spec["sha256"], "Asset mismatch: " + name)
    lab.require(not output.exists(), "Delivery output already exists; use a new directory")
    lab.require(shutil.disk_usage(output.parent).free >= 4 * 2**30, "Need 4 GiB free for independent per-host input copies")
    output.mkdir(mode=0o700)
    bundle = output / "bundle"
    lab.render(config, bundle)
    lab.charts(bundle, assets)
    ready = config["network_confirmed"] and config["storage_confirmed"]
    for role in config["hosts"]:
        package = output / "host-packages" / role
        for source in (bundle / "hosts" / role).iterdir():
            lab.require(source.is_file(), "Unexpected nested host input")
            copy(source, package / source.name)
        node = next(n for n in config["nodes"] if n["host"] == role)
        for source in (bundle / "nodes" / node["name"]).iterdir():
            copy(source, package / "guest" / source.name)
        copy(assets / "ubuntu.img", package / "ubuntu.img")
        copy(assets / "k3s", package / "guest/k3s")
        copy(bundle / "assets.lock.json", package / "assets.lock.json")
        write(package / "provenance.json", {"source_revision": revision, "inventory_sha256": (bundle / "inventory.sha256").read_text().strip(), "role": role, "execution_enabled": ready})
        write(package / "README.txt", f'''Psy isolated lab input package: {role} / {node['name']}
Source: {revision}
Execution enabled: {ready}

Verify: sha256sum --check SHA256SUMS
Plan only: python3 create-vms.py --create {role}
Create only after all host/storage checks: python3 create-vms.py --create {role} --apply
Use the ordinary operator, never host sudo. No autostart is enabled.
guest/ is for this NEW VM after cloud-init/SSH, not the physical host.
No private key, token or kubeconfig is included. Use the separate lab runbook.
If execution is disabled, retain this package as preparation evidence and generate
a NEW package after prerequisites pass; do not edit confirmed flags inside it.
''')
        files = sorted(p for p in package.rglob("*") if p.is_file())
        write(package / "SHA256SUMS", "".join(lab.digest(p) + "  " + str(p.relative_to(package)) + "\n" for p in files))
    write(output / "delivery.json", {"source_revision": revision, "inventory_sha256": (bundle / "inventory.sha256").read_text().strip(), "execution_enabled": ready, "roles": list(config["hosts"]), "host_packages": "host-packages/", "platform_bundle": "bundle/platform/", "contains_private_credentials": False})
    print(json.dumps({"output": str(output), "source_revision": revision, "execution_enabled": ready, "host_packages": 4}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    assemble(json.loads(args.inventory.read_text()), args.assets.resolve(), args.output.resolve(), clean_revision())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
