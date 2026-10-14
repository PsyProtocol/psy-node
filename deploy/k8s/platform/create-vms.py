#!/usr/bin/env python3
"""Run on one physical Linux/libvirt host, with its rendered directory and assets."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        sys.exit(message)


def run(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def free(path):
    p = Path(path)
    while not p.exists():
        p = p.parent
    return shutil.disk_usage(p).free // 2**30


def check_pool(pool, qemu_user):
    require(Path(pool).is_dir(), "Pool must already exist; prepare its directory and permissions first: " + pool)
    require(subprocess.run(["runuser", "-u", qemu_user, "--", "test", "-x", pool]).returncode == 0, "qemu cannot traverse the complete pool path; operator must grant access")


def main():
    os.umask(0o077)
    os.chdir(Path(__file__).resolve().parent)
    cfg = json.loads(Path("host.json").read_text())
    require(len(sys.argv) == 3 and sys.argv[1] == "--create" and sys.argv[2] == cfg["ssh"], "Usage: sudo ./create-vms.py --create EXPECTED_SSH_ALIAS")
    require(cfg["confirmed"] is True, "Inventory network/storage not confirmed; render again")
    require(os.geteuid() == 0, "Run with sudo on the designated physical host")
    require(subprocess.run(["systemd-detect-virt", "--quiet"]).returncode != 0, "Must run on the physical host")
    # SSH aliases can differ from hostnames; require the operator to supply the
    # exact reported physical hostname in the rendered host.json before use.
    require(cfg.get("expected_hostname") == Path("/proc/sys/kernel/hostname").read_text().strip(), "Set hosts.<host>.expected_hostname from read-only preflight and render again")
    require(Path("/dev/kvm").exists(), "KVM unavailable")
    for tool in ("virsh", "qemu-img", "cloud-localds"):
        require(shutil.which(tool), "Missing host helper: " + tool)
    require(Path("/sys/class/net", cfg["bridge"], "bridge").is_dir(), "Confirmed pre-existing LAN bridge required")
    # Ensure the qemu user exists before any mutation.
    import pwd
    import grp
    qemu_user = cfg.get("qemu_user", "libvirt-qemu")
    qemu_group = cfg.get("qemu_group", "kvm")
    uid, gid = pwd.getpwnam(qemu_user).pw_uid, grp.getgrnam(qemu_group).gr_gid
    def qemu_file(path, mode=0o600):
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    require(len(cfg["nodes"]) == 2 and all(n["name"].startswith("psy-lab-") for n in cfg["nodes"]), "Two dedicated lab VMs required")
    require(free(cfg["os_pool"]) >= sum(n["os_gib"] for n in cfg["nodes"]) + 16, "Insufficient OS pool free space")
    mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    require(int(mem["MemAvailable"].split()[0]) / 2**20 >= cfg["minimum_available_memory_gib"], "Insufficient available RAM; do not add VMs on top of existing load")
    if "data_pool" in cfg:
        require(Path(cfg["data_pool"]).is_mount(), "x4 data_pool must already be the mounted new disk; no automatic formatting")
        require(run("findmnt", "-n", "-o", "SOURCE", "-T", cfg["data_pool"]) != run("findmnt", "-n", "-o", "SOURCE", "-T", "/"), "x4 data pool cannot be root filesystem")
        def backing_disks(pool):
            source = run("findmnt", "-n", "-o", "SOURCE", "-T", pool)
            info = json.loads(run("lsblk", "-J", "-s", "-o", "NAME,TYPE", source))
            def visit(items):
                found = set()
                for item in items:
                    if item["type"] == "disk":
                        found.add(item["name"])
                    found.update(visit(item.get("children", [])))
                return found
            return visit(info["blockdevices"])
        data_disks = backing_disks(cfg["data_pool"])
        require(data_disks and data_disks.isdisjoint(backing_disks("/")), "x4 data pool must be on a different physical disk from root")
        require(free(cfg["data_pool"]) >= sum(n.get("data_gib", 0) for n in cfg["nodes"]) + 32, "Insufficient x4 data pool free space")
    image = Path("ubuntu.img")
    lock = json.loads(Path("assets.lock.json").read_text())["assets"]["ubuntu.img"]
    with image.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == lock["sha256"], "Ubuntu image checksum mismatch")
    image_info = json.loads(run("qemu-img", "info", "--output=json", str(image)))
    require(image_info["format"] == "qcow2" and not image_info.get("backing-filename"), "Standalone qcow2 base image required")
    existing = set(run("virsh", "-c", "qemu:///system", "list", "--all", "--name").splitlines())
    for n in cfg["nodes"]:
        require(n["name"] not in existing, "Existing domain; inspect/resume manually: " + n["name"])
        xml = ET.parse(n["name"] + ".xml").getroot()
        require(xml.findtext("name") == n["name"], "XML name mismatch")
        for source in xml.findall("./devices/disk/source"):
            require(not Path(source.attrib["file"]).exists(), "Existing VM disk; inspect partial construction first")
    # Require complete pre-existing pools; never create/chmod shared ancestors.
    for pool in (cfg["os_pool"], cfg.get("data_pool")):
        if pool:
            check_pool(pool, qemu_user)
    # Preflight is complete. Nothing here stops an existing production service.
    for n in cfg["nodes"]:
        name = n["name"]
        disk = str(Path(cfg["os_pool"], name + ".qcow2"))
        with image.open("rb") as source, open(disk, "xb") as target:
            shutil.copyfileobj(source, target)
        run("qemu-img", "resize", disk, str(n["os_gib"]) + "G")
        qemu_file(disk)
        seed = str(Path(cfg["os_pool"], name + "-seed.iso"))
        run("cloud-localds", "--network-config=" + name + "-network.json", seed, name + "-user.yaml", name + "-meta.json")
        qemu_file(seed, 0o640)
        if n.get("data_gib"):
            data = str(Path(cfg["data_pool"], name + "-data.qcow2"))
            run("qemu-img", "create", "-f", "qcow2", data, str(n["data_gib"]) + "G")
            qemu_file(data)
        run("virsh", "-c", "qemu:///system", "define", name + ".xml")
        run("virsh", "-c", "qemu:///system", "start", name)
        print("Started " + name)
    print("No autostart enabled. Verify cloud-init and SSH; enable autostart after acceptance.")


if __name__ == "__main__":
    main()
