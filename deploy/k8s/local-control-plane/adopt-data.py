#!/usr/bin/env python3
"""Adopt x4's already mounted SSD as psy; only create dedicated new directories."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "host-setup"))
import host_setup as setup

MOUNT = Path("/data")
ROOT = MOUNT / "psy-k8s-lab"
POOL = ROOT / "vm-data"
UUID = "d6d4015e-098a-4d6d-842d-6304bc015132"
SERIAL = "2113C4462901"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def inspect():
    cfg = setup.identity("x4")
    require(os.geteuid() == pwd.getpwnam(cfg["user"]).pw_uid != 0, "Use ordinary psy on x4; no sudo")
    require(not MOUNT.is_symlink() and MOUNT.is_mount(), "Existing /data mount required")
    require(setup.run("findmnt", "-n", "-o", "UUID", "-T", str(MOUNT)) == UUID, "Wrong /data filesystem UUID")
    require(setup.run("findmnt", "-n", "-o", "FSTYPE", "-T", str(MOUNT)) == "ext4", "Expected the mounted ext4 SSD")
    disks = setup.backing_disks(MOUNT)
    require(len(disks) == 1 and disks.isdisjoint(setup.backing_disks("/")) and disks.isdisjoint(setup.backing_disks("/home")), "Data SSD must differ from root/home disks")
    disk = next(iter(disks))
    require(setup.run("lsblk", "-dn", "-o", "SERIAL", "/dev/" + disk) == SERIAL, "Wrong SSD serial")
    require(shutil.disk_usage(MOUNT).free >= 288 * 2**30, "Need at least 288 GiB free")
    require(MOUNT.stat().st_uid == os.geteuid() and os.access(MOUNT, os.W_OK | os.X_OK), "psy must own and be able to write /data")
    emulator = setup.qemu_user()
    uid = pwd.getpwnam(emulator).pw_uid
    # Existing shared parents are inspected only, never chmod/chown/setfacl'd.
    for parent in (Path("/"), MOUNT):
        require(stat.S_IMODE(parent.stat().st_mode) & 0o111 == 0o111, "Parent traversal needs operator review")
        acl = setup.run("getfacl", "-cn", str(parent)).splitlines()
        require(not any(line.startswith("user:") and not line.startswith("user::") or line.startswith("group:") and not line.startswith("group::") for line in acl), "Extended parent ACL needs review; it will not be modified")
    receipt = {"hostname": "arc99x4", "mount": str(MOUNT), "uuid": UUID, "serial": SERIAL, "pool": str(POOL), "operator_uid": os.geteuid(), "qemu_uid": uid}
    return receipt


def verify_existing(receipt):
    marker = ROOT / "pool-receipt.json"
    for path in (ROOT, POOL, marker):
        require(not path.is_symlink() and path.exists() and path.stat().st_uid == os.geteuid(), "Existing path is not owned by this preparation")
    require(ROOT.is_dir() and POOL.is_dir() and marker.is_file() and json.loads(marker.read_text()) == receipt, "Existing different/partial pool; inspect, do not overwrite")
    require(POOL.stat().st_dev == MOUNT.stat().st_dev, "Pool is on another filesystem")
    for path, perms in ((ROOT, "--x"), (POOL, "r-x")):
        acl = setup.run("getfacl", "-cn", str(path)).splitlines()
        require(f"user:{receipt['qemu_uid']}:{perms}" in acl and f"mask::{perms}" in acl, "Prepared QEMU ACL changed; inspect manually")


def prepare(receipt):
    if ROOT.exists() or ROOT.is_symlink():
        verify_existing(receipt)
        return
    ROOT.mkdir(mode=0o700)
    POOL.mkdir(mode=0o700)
    # Remove inherited ACLs only on our newly created directories; no recursion.
    subprocess.run(["setfacl", "-b", "-k", str(ROOT), str(POOL)], check=True)
    for path, perms in ((ROOT, "--x"), (POOL, "r-x")):
        subprocess.run(["setfacl", "-m", f"u:{receipt['qemu_uid']}:{perms}", str(path)], check=True)
    marker = ROOT / "pool-receipt.json"
    with marker.open("x") as stream:
        stream.write(json.dumps(receipt, indent=2) + "\n")
    marker.chmod(0o600)
    verify_existing(receipt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    receipt = inspect()
    if args.apply:
        prepare(receipt)
    print(json.dumps({"disk": receipt, "free_gib": shutil.disk_usage(MOUNT).free // 2**30, "pool_ready": POOL.is_dir(), "applied": args.apply, "formats_or_mount_changes": False}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
