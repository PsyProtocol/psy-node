#!/usr/bin/env python3
"""Create exactly one lab VM as its authorized non-root libvirt operator.

Copied into each rendered hosts/<role> directory with host_setup.py. No host sudo,
network changes, chown, formatting, domain deletion or automatic retry cleanup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

import host_setup as setup


def require(ok, message):
    if not ok:
        raise ValueError(message)


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def check_xml(path, node, cfg):
    root = ET.parse(path).getroot()
    require(root.tag == "domain" and root.get("type") == "kvm" and root.findtext("name") == node["name"], "Unexpected VM domain identity")
    require(root.findtext("memory") == str(node["memory_gib"]) and root.find("memory").get("unit") == "GiB" and root.findtext("vcpu") == str(node["cpus"]), "XML resources differ from inventory")
    wanted = {
        "vda": (str(Path(cfg["os_pool"], node["name"] + ".qcow2")), "disk", "qcow2", "virtio"),
        "sda": (str(Path(cfg["os_pool"], node["name"] + "-seed.iso")), "cdrom", "raw", "sata"),
    }
    if node.get("data_gib"):
        wanted["vdb"] = (str(Path(cfg["data_pool"], node["name"] + "-data.qcow2")), "disk", "qcow2", "virtio")
    actual = {}
    for disk in root.findall("./devices/disk"):
        target = disk.find("target")
        require(target is not None and target.get("dev") not in actual, "Missing/duplicate disk target")
        require(disk.get("type") == "file" and disk.find("source") is not None and disk.find("driver") is not None, "Only dedicated file-backed disks supported")
        actual[target.get("dev")] = (disk.find("source").get("file"), disk.get("device"), disk.find("driver").get("type"), target.get("bus"))
    require(actual == wanted, "XML disks differ from dedicated lab paths")
    interfaces = root.findall("./devices/interface")
    require(len(interfaces) == 1 and interfaces[0].get("type") == "bridge" and interfaces[0].find("source").get("bridge") == "br0" and interfaces[0].find("mac").get("address") == node["mac"], "Unexpected VM network")
    require(not root.findall("./devices/hostdev") and not root.findall("./devices/filesystem"), "Host device/directory passthrough is not supported")
    return [Path(spec[0]) for spec in wanted.values()]


def preflight(role, cfg):
    host = setup.identity(role)
    require(os.geteuid() == pwd.getpwnam(host["user"]).pw_uid and os.geteuid() != 0, "Use the authorized ordinary operator; do not run with sudo")
    require(cfg.get("expected_hostname") == host["hostname"] and cfg.get("operator") == host["user"] and cfg.get("os_pool") == host["pool"] and cfg.get("bridge") == "br0", "Bundle does not match this operator/host/pool")
    require(subprocess.run(["systemd-detect-virt", "--quiet"]).returncode != 0, "Physical host required")
    nodes = cfg["nodes"]
    require(len(nodes) == 1, "Exactly one VM per host required")
    node = nodes[0]
    expected = "psy-lab-cp-local" if role == "local" else "psy-lab-work-" + role
    require(node["name"] == expected and node["host"] == role and node["role"] == ("server" if role == "local" else "agent"), "Unexpected node role/name")
    for key, low, high in (("cpus", 2, 12), ("memory_gib", 4, 44), ("os_gib", 40, 160)):
        require(type(node[key]) is int and low <= node[key] <= high, "Invalid VM resource: " + key)
    require(type(cfg["minimum_available_memory_gib"]) is int and cfg["minimum_available_memory_gib"] >= node["memory_gib"] + 2, "Host RAM reserve required")
    require(cfg["confirmed"] is True, "Network/storage not confirmed; render again after preparation")
    require(setup.check(host), "Host prerequisites incomplete; inspect checks above")
    # Match the installer assumptions without changing libvirt identity settings.
    setup.qemu_user()
    pool = Path(cfg["os_pool"])
    for path in (pool, *pool.parents):
        require(not path.is_symlink(), "Pool ancestor symlink rejected")
    require(pool.stat().st_uid == os.geteuid() and os.access(pool, os.W_OK | os.X_OK), "Operator must own and access pool")
    require(shutil.disk_usage(pool).free >= (node["os_gib"] + 16) * 2**30, "Insufficient OS pool capacity")
    mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    require(int(mem["MemAvailable"].split()[0]) / 2**20 >= cfg["minimum_available_memory_gib"], "Insufficient available RAM")
    if role == "x4":
        require(cfg.get("data_mount") == "/mnt/psy-k8s-lab" and cfg.get("data_pool") == "/mnt/psy-k8s-lab/vm-data", "Unexpected x4 data mount/pool")
        mount, data = Path(cfg["data_mount"]), Path(cfg["data_pool"])
        require(mount.is_mount() and not mount.is_symlink() and data.is_dir() and not data.is_symlink(), "Prepared x4 mount and pool required")
        require(data.stat().st_uid == os.geteuid() and data.stat().st_dev == mount.stat().st_dev and os.access(data, os.W_OK | os.X_OK), "Data pool must be owned, writable and on the mounted new disk")
        disks = setup.backing_disks(data)
        require(disks and disks.isdisjoint(setup.backing_disks("/")) and disks.isdisjoint(setup.backing_disks("/home")), "Data disk must differ from root and home")
        require(type(node.get("data_gib")) is int and 256 <= node["data_gib"] <= 2048, "x4 needs its new data disk")
        require(shutil.disk_usage(data).free >= (node["data_gib"] + 32) * 2**30, "Insufficient new data disk capacity")
    else:
        require(not node.get("data_gib") and "data_pool" not in cfg, "Only x4 gets a data disk")
    existing = set(run("virsh", "-c", "qemu:///system", "list", "--all", "--name").splitlines())
    require(expected not in existing, "Domain exists; inspect/resume manually, never overwrite")
    targets = check_xml(Path(expected + ".xml"), node, cfg)
    require(all(not p.exists() and not p.is_symlink() for p in targets), "Existing disk/seed; inspect partial construction manually")
    image = Path("ubuntu.img")
    lock = json.loads(Path("assets.lock.json").read_text())["assets"]["ubuntu.img"]
    with image.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == lock["sha256"], "Ubuntu image checksum mismatch")
    info = json.loads(run("qemu-img", "info", "--output=json", str(image)))
    require(info["format"] == "qcow2" and not info.get("backing-filename"), "Standalone qcow2 image required")
    for suffix in ("-network.json", "-user.yaml", "-meta.json"):
        require(Path(expected + suffix).is_file(), "Missing cloud-init input")
    return node


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create", choices=setup.HOSTS, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    os.chdir(Path(__file__).resolve().parent)
    cfg = json.loads(Path("host.json").read_text())
    if not args.apply:
        print(json.dumps({"host": args.create, "nodes": cfg["nodes"], "confirmed": cfg["confirmed"], "mutations": False, "instruction": "Ordinary operator only; --apply requires all host/network/storage checks"}, indent=2))
        return
    node = preflight(args.create, cfg)
    name = node["name"]
    disk = Path(cfg["os_pool"], name + ".qcow2")
    with Path("ubuntu.img").open("rb") as source, disk.open("xb") as target:
        shutil.copyfileobj(source, target)
    run("qemu-img", "resize", str(disk), str(node["os_gib"]) + "G")
    seed = Path(cfg["os_pool"], name + "-seed.iso")
    # Reserve output names exclusively. cloud-localds writes a completed temp ISO.
    with seed.open("xb") as target:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="psy-k8s-seed-") as temp:
            temp_iso = Path(temp, "seed.iso")
            run("cloud-localds", "--network-config=" + name + "-network.json", str(temp_iso), name + "-user.yaml", name + "-meta.json")
            with temp_iso.open("rb") as source:
                shutil.copyfileobj(source, target)
    if node.get("data_gib"):
        data = Path(cfg["data_pool"], name + "-data.qcow2")
        with data.open("xb"):
            pass
        run("qemu-img", "create", "-f", "qcow2", str(data), str(node["data_gib"]) + "G")
    run("virsh", "-c", "qemu:///system", "define", name + ".xml")
    run("virsh", "-c", "qemu:///system", "start", name)
    print("Started " + name + "; no autostart enabled. Verify cloud-init/SSH before acceptance.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, ET.ParseError) as exc:
        sys.exit(str(exc))
