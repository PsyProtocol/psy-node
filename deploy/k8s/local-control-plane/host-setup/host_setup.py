#!/usr/bin/env python3
"""Operator-run Arch host preparation. No mutation without --apply; no sudo calls."""
import argparse
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

HOSTS = {
    "local": {"hostname": "arch3900x", "user": "peter", "nic": "enp5s0", "ip": "192.168.5.20", "mac": "14:d8:64:07:69:36", "manager": "NetworkManager", "pool": "/home/peter/git/bridge_zilong/k8s-local-control-plane/vm", "os_free_gib": 76},
    "x2": {"hostname": "arc99x2", "user": "psy", "nic": "enp3s0", "ip": "192.168.5.35", "mac": "00:e2:69:af:1e:91", "manager": "systemd-networkd", "pool": "/home/psy/k8s-lab/os", "os_free_gib": 56},
    "x3": {"hostname": "arc99x3", "user": "psy", "nic": "enp3s0", "ip": "192.168.5.41", "mac": "00:e2:69:af:1f:5a", "manager": "systemd-networkd", "pool": "/home/psy/k8s-lab/os", "os_free_gib": 56},
    "x4": {"hostname": "arc99x4", "user": "psy", "nic": "enp3s0", "ip": "192.168.5.43", "mac": "00:e2:69:af:1f:5c", "manager": "systemd-networkd", "pool": "/home/psy/k8s-lab/os", "os_free_gib": 56},
}
PACKAGES = ["qemu-base", "libvirt", "cloud-image-utils", "acl", "polkit"]
STATE = Path("/var/lib/psy-k8s-host-setup")
NETWORK_FILES = [Path("/etc/systemd/network") / name for name in (
    "00-psy-k8s-br0.netdev", "00-psy-k8s-br0.network", "00-psy-k8s-port.network")]
BRIDGE, PORT = "psy-k8s-br0", "psy-k8s-port"


def require(ok, why):
    if not ok:
        raise ValueError(why)


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def attempt(*args):
    try:
        return {"ok": True, "output": run(*args)}
    except (OSError, subprocess.CalledProcessError) as exc:
        return {"ok": False, "output": str(exc)}


def identity(name):
    cfg = HOSTS[name]
    actual = Path("/proc/sys/kernel/hostname").read_text().strip()
    require(actual == cfg["hostname"], f"Wrong machine: expected {cfg['hostname']}, got {actual}; x1 is excluded")
    require("ID=arch" in Path("/etc/os-release").read_text().splitlines(), "This bundle supports the inspected Arch hosts only")
    require(Path("/sys/class/net", cfg["nic"], "address").read_text().strip() == cfg["mac"], "Physical NIC/MAC changed; inspect and regenerate scripts")
    pwd.getpwnam(cfg["user"])
    return cfg


def nearest(path):
    p = Path(path)
    while not p.exists():
        p = p.parent
    return p


def owned_file(path, text, mode=0o644):
    """Write only a new owned path, or accept identical content; never overwrite."""
    require(not path.is_symlink(), f"Symlink rejected: {path}")
    if path.exists():
        require(path.is_file() and path.read_text() == text, f"Existing different configuration: {path}; inspect manually")
        require(path.stat().st_uid == 0, f"Existing configuration must be root-owned: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with path.open("x") as stream:
        stream.write(text)
    path.chmod(mode)


def qemu_user():
    cfg = Path("/etc/libvirt/qemu.conf")
    # Never override an administrator's explicit emulator identity.
    if cfg.exists():
        active = [line.strip() for line in cfg.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
        require(not any(line.split("=", 1)[0].strip() in {"user", "group", "dynamic_ownership"} for line in active), "Explicit qemu user/group/ownership configuration found; review before granting pool access")
    pwd.getpwnam("libvirt-qemu")
    return "libvirt-qemu"


def prepare_pool(path, user, emulator):
    account = pwd.getpwnam(user)
    p = Path(path)
    require(not p.is_symlink(), "Pool symlink rejected")
    for ancestor in p.parents:
        require(not ancestor.is_symlink(), f"Ancestor symlink rejected: {ancestor}")
    if p.exists():
        require(p.is_dir() and p.stat().st_uid == account.pw_uid, "Existing pool must be a directory owned by the operator")
    else:
        p.mkdir(parents=True, mode=0o750)
        os.chown(p, account.pw_uid, account.pw_gid)
    # Traversal only on ancestors, no recursive ownership/mode changes.
    for ancestor in reversed(p.parents):
        if subprocess.run(["runuser", "-u", emulator, "--", "test", "-x", str(ancestor)]).returncode:
            subprocess.run(["setfacl", "-m", f"u:{emulator}:--x", str(ancestor)], check=True)
    subprocess.run(["setfacl", "-m", f"u:{emulator}:r-x", str(p)], check=True)
    subprocess.run(["runuser", "-u", emulator, "--", "test", "-x", str(p)], check=True)
    subprocess.run(["runuser", "-u", user, "--", "test", "-w", str(p)], check=True)


def install(cfg):
    for unit in ("virtqemud.socket", "virtqemud.service"):
        require(subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode != 0, "Existing modular virtqemud setup; retain it and review compatible authorization instead of switching")
    require("svm" in Path("/proc/cpuinfo").read_text().split(), "AMD SVM is not exposed. Enable SVM/virtualization in BIOS/UEFI, boot normally and rerun; script does not reboot")
    subprocess.run(["modprobe", "kvm_amd"], check=True)
    require(Path("/dev/kvm").exists(), "KVM device unavailable after loading kvm_amd; inspect kernel/BIOS")
    # No pacman -Sy or implicit full-system upgrade. Operator already updated hosts.
    subprocess.run(["pacman", "-S", "--needed", "--noconfirm", *PACKAGES], check=True)
    emulator = qemu_user()
    for group in ("kvm", "libvirt"):
        grp.getgrnam(group)
    subprocess.run(["usermod", "-a", "-G", "kvm,libvirt", cfg["user"]], check=True)
    policy = '''// Psy local Kubernetes: trusted operator VM management, including SSH sessions.
polkit.addRule(function(action, subject) {
    if (action.id === "org.libvirt.unix.manage" &&
        subject.user === "%s" && subject.isInGroup("libvirt")) {
        return polkit.Result.YES;
    }
});
''' % cfg["user"]
    owned_file(Path("/etc/polkit-1/rules.d/50-psy-k8s-libvirt.rules"), policy)
    owned_file(Path("/etc/systemd/system/libvirtd.socket.d/50-psy-k8s.conf"), "[Socket]\nSocketGroup=libvirt\nSocketMode=0660\n")
    owned_file(Path("/etc/modules-load.d/psy-k8s.conf"), "kvm\nkvm_amd\n")
    prepare_pool(cfg["pool"], cfg["user"], emulator)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    # Use one daemon architecture. Never stop/switch an existing modular setup.
    subprocess.run(["systemctl", "start", "polkit.service"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "libvirtd.socket"], check=True)
    print("Installed. Open a NEW SSH/login session, then run check without sudo. No passwordless sudo rule was added.")


def network_texts(cfg):
    return [
        f"[NetDev]\nName=br0\nKind=bridge\nMACAddress={cfg['mac']}\n\n[Bridge]\nSTP=false\n",
        f"[Match]\nName=br0\n\n[Network]\nAddress={cfg['ip']}/24\nGateway=192.168.5.1\nDNS=192.168.5.1\nIPv6AcceptRA=yes\nDHCP=ipv6\nMulticastDNS=yes\n\n[DHCPv6]\nIAID=0xcb390ac7\n",
        f"[Match]\nName={cfg['nic']}\n\n[Network]\nBridge=br0\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n\n[Link]\nRequiredForOnline=enslaved\n",
    ]


def bridge(cfg):
    require(subprocess.run(["systemctl", "is-active", "--quiet", cfg["manager"]]).returncode == 0, "Unexpected network manager")
    require(not (STATE / "bridge.json").exists(), "Bridge receipt already exists; inspect or use rollback, do not overwrite")
    require(not Path("/sys/class/net/br0").exists(), "Existing br0; inspect rather than replacing")
    addresses = json.loads(run("ip", "-j", "-4", "address", "show", "dev", cfg["nic"]))
    require(any(a.get("local") == cfg["ip"] and a.get("prefixlen") == 24 for i in addresses for a in i["addr_info"]), "Inspected LAN address/prefix changed")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = {"hostname": cfg["hostname"], "manager": cfg["manager"], "state": "prepared"}
    if cfg["manager"] == "NetworkManager":
        names = run("nmcli", "-t", "-f", "NAME", "connection", "show").splitlines()
        require(BRIDGE not in names and PORT not in names, "Psy bridge connection name already exists")
        active = run("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", cfg["nic"])
        require(active and active != "--", "No active original NIC connection")
        receipt["original_connection_uuid"] = active
        receipt["created_connections"] = {BRIDGE: str(uuid.uuid4()), PORT: str(uuid.uuid4())}
    else:
        for path, text in zip(NETWORK_FILES, network_texts(cfg)):
            require(not path.exists() and not path.is_symlink(), f"Existing network path: {path}")
        # Verify our Match files would be selected; do not silently lose to an earlier file.
        earlier = list(Path("/etc/systemd/network").glob("00-*.network"))
        require(not earlier, "Earlier networkd Match files found; inspect precedence before installing bridge")
        receipt["network_files"] = dict(zip(map(str, NETWORK_FILES), network_texts(cfg)))
    owned_file(STATE / "bridge.json", json.dumps(receipt, indent=2) + "\n", 0o600)
    if cfg["manager"] == "NetworkManager":
        subprocess.run(["nmcli", "connection", "add", "type", "bridge", "ifname", "br0", "con-name", BRIDGE, "connection.uuid", receipt["created_connections"][BRIDGE], "bridge.stp", "no", "bridge.mac-address", cfg["mac"], "ipv4.method", "manual", "ipv4.addresses", cfg["ip"] + "/24", "ipv4.gateway", "192.168.5.1", "ipv4.dns", "192.168.5.1", "ipv6.method", "auto", "connection.autoconnect-priority", "999"], check=True)
        subprocess.run(["nmcli", "connection", "add", "type", "ethernet", "ifname", cfg["nic"], "con-name", PORT, "connection.uuid", receipt["created_connections"][PORT], "controller", receipt["created_connections"][BRIDGE], "port-type", "bridge", "connection.autoconnect-priority", "999"], check=True)
        subprocess.run(["nmcli", "connection", "up", PORT], check=True)
    else:
        for path, text in zip(NETWORK_FILES, network_texts(cfg)):
            owned_file(path, text)
        subprocess.run(["networkctl", "reload"], check=True)
        for _ in range(30):
            if Path("/sys/class/net/br0").exists():
                break
            time.sleep(0.1)
        require(Path("/sys/class/net/br0").exists(), "networkd did not create br0; use console rollback")
        subprocess.run(["networkctl", "reconfigure", cfg["nic"], "br0"], check=True)
    print("Bridge configured. Verify LAN IP/gateway/DNS and old services from another terminal. Original profiles were retained. Use rollback from console if needed.")


def rollback(cfg):
    path = STATE / "bridge.json"
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0, "No root-owned bridge receipt")
    receipt = json.loads(path.read_text())
    require(receipt["hostname"] == cfg["hostname"] and receipt["manager"] == cfg["manager"], "Receipt belongs to another host")
    if cfg["manager"] == "NetworkManager":
        require(set(receipt["created_connections"]) == {BRIDGE, PORT}, "Unexpected NetworkManager receipt")
        for name in (PORT, BRIDGE):
            connection_id = str(uuid.UUID(receipt["created_connections"][name]))
            if connection_id in run("nmcli", "-t", "-f", "UUID", "connection", "show").splitlines():
                subprocess.run(["nmcli", "connection", "delete", "uuid", connection_id], check=True)
        subprocess.run(["nmcli", "connection", "up", "uuid", receipt["original_connection_uuid"]], check=True)
    else:
        expected = dict(zip(map(str, NETWORK_FILES), network_texts(cfg)))
        require(receipt["network_files"] == expected, "Receipt paths/content mismatch")
        for filename, text in expected.items():
            p = Path(filename)
            require(not p.is_symlink() and (not p.exists() or p.read_text() == text), "Network files changed since setup; inspect manually")
        for filename in expected:
            Path(filename).unlink(missing_ok=True)
        subprocess.run(["networkctl", "reload"], check=True)
        if Path("/sys/class/net/br0").exists():
            subprocess.run(["ip", "link", "set", cfg["nic"], "nomaster"], check=True)
            subprocess.run(["ip", "link", "delete", "br0", "type", "bridge"], check=True)
        subprocess.run(["networkctl", "reconfigure", cfg["nic"]], check=True)
    path.rename(STATE / ("bridge-rolled-back-" + str(os.getpid()) + ".json"))
    print("Restored original LAN profile; verify connectivity")


def backing_disks(path):
    source = run("findmnt", "-n", "-o", "SOURCE", "-T", str(path))
    def visit(items):
        disks = set()
        for item in items:
            if item["type"] == "disk":
                disks.add(item["name"])
            disks.update(visit(item.get("children", [])))
        return disks
    return visit(json.loads(run("lsblk", "-J", "-s", "-o", "NAME,TYPE", source))["blockdevices"])


def storage(cfg, mount):
    # Adopt an already mounted new disk; never partition, format or edit fstab.
    p = Path(mount)
    require(cfg["hostname"] == "arc99x4" and str(p) == "/mnt/psy-k8s-lab", "Only x4's dedicated /mnt/psy-k8s-lab is supported")
    require(not p.is_symlink() and p.is_mount(), "Mount the expanded disk persistently first; empty directories are not a disk")
    actual = backing_disks(p)
    require(actual and actual.isdisjoint(backing_disks("/")) and actual.isdisjoint(backing_disks("/home")), "Data pool must be on a different physical disk from both root and home")
    require(shutil.disk_usage(p).free >= 288 * 2**30, "Need at least 288 GiB free for the 256 GiB virtual disk and reserve")
    leaf = p / "vm-data"
    prepare_pool(leaf, cfg["user"], qemu_user())
    print("Data VM pool ready: " + str(leaf))


def validate_blank_disk(cfg, device, serial):
    require(cfg["hostname"] == "arc99x4", "Only x4 may initialize a new data disk")
    require(Path(device).parent == Path("/dev/disk/by-id") and serial, "Use the new disk's stable by-id path and exact SERIAL")
    path = Path(device).resolve(strict=True)
    require(stat.S_ISBLK(path.stat().st_mode), "Not a block device")
    info = json.loads(run("lsblk", "-J", "-b", "-o", "NAME,TYPE,SIZE,SERIAL,MOUNTPOINTS", str(path)))["blockdevices"]
    require(len(info) == 1, "Ambiguous disk")
    disk = info[0]
    require(disk["type"] == "disk" and not disk.get("children"), "Need a whole blank disk with no partitions")
    require(isinstance(disk.get("serial"), str) and disk["serial"].strip() == serial, "Disk SERIAL mismatch")
    require(int(disk["size"]) >= 320 * 2**30, "New disk too small; need at least 320 GiB")
    require(not any(disk.get("mountpoints") or []), "Disk is mounted")
    require(disk["name"] not in backing_disks("/") | backing_disks("/home"), "Refusing root/home backing disk")
    require(not run("wipefs", "--no-act", "--noheadings", "--output", "TYPE", str(path)), "Disk has filesystem/partition signatures; refusing to format")
    return path


def initialize_disk(cfg, device, serial):
    path = validate_blank_disk(cfg, device, serial)
    mount = Path("/mnt/psy-k8s-lab")
    require(not mount.is_symlink() and not mount.is_mount(), "Data mount already exists or is a symlink")
    require(not mount.exists() or not any(mount.iterdir()), "Existing data mount directory is nonempty")
    fstab = Path("/etc/fstab")
    require(not fstab.is_symlink(), "fstab symlink rejected")
    before = fstab.read_text()
    entries = [line.split() for line in before.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    require(all(len(entry) < 2 or entry[1] != str(mount) for entry in entries), "fstab already has this mount; inspect rather than replace")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_file(STATE / "fstab.before-data-disk", before, 0o600)
    subprocess.run(["mkfs.ext4", "-L", "psy-k8s-data", str(path)], check=True)
    uuid = run("blkid", "-s", "UUID", "-o", "value", str(path))
    require(bool(uuid) and all(c in "0123456789abcdef-" for c in uuid), "Unexpected filesystem UUID")
    mount.mkdir(mode=0o755, exist_ok=True)
    updated = before.rstrip() + f"\n# Psy local Kubernetes expanded data disk\nUUID={uuid} {mount} ext4 defaults,nofail 0 2\n"
    # Preserve fstab metadata and replace atomically; the backup above is retained.
    meta = fstab.stat()
    with tempfile.NamedTemporaryFile(mode="w", dir=fstab.parent, prefix=".psy-k8s-fstab-", delete=False) as stream:
        temp = Path(stream.name)
        stream.write(updated)
        stream.flush()
        os.fsync(stream.fileno())
    os.chown(temp, meta.st_uid, meta.st_gid)
    temp.chmod(stat.S_IMODE(meta.st_mode))
    os.replace(temp, fstab)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["mount", str(mount)], check=True)
    storage(cfg, str(mount))


def check(cfg):
    user = cfg["user"]
    checks = {
        "kvm_exists": Path("/dev/kvm").exists(),
        "kvm_user_access": os.access("/dev/kvm", os.R_OK | os.W_OK),
        "svm_exposed": "svm" in Path("/proc/cpuinfo").read_text().split(),
        "helpers": all(shutil.which(t) for t in ("virsh", "qemu-img", "cloud-localds", "setfacl")),
        "pool_exists": Path(cfg["pool"]).is_dir(),
        "pool_capacity": shutil.disk_usage(nearest(cfg["pool"])).free >= cfg["os_free_gib"] * 2**30,
        "bridge_exists": Path("/sys/class/net/br0/bridge").is_dir(),
    }
    vm_access = attempt("virsh", "-c", "qemu:///system", "list", "--all", "--name")
    checks["libvirt_user_access"] = os.geteuid() == pwd.getpwnam(user).pw_uid and vm_access["ok"]
    print(json.dumps({"hostname": cfg["hostname"], "user": user, "pool": cfg["pool"], "free_gib": shutil.disk_usage(nearest(cfg["pool"])).free // 2**30, "required_free_gib": cfg["os_free_gib"], "checks": checks, "libvirt": vm_access}, indent=2))
    return all(checks.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=HOSTS)
    parser.add_argument("action", choices=("check", "install", "bridge", "rollback", "storage", "initialize-disk"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--console-confirmed", action="store_true")
    parser.add_argument("--ip-reservation-confirmed", action="store_true")
    parser.add_argument("--device")
    parser.add_argument("--serial")
    parser.add_argument("--initialize-blank-disk", action="store_true")
    args = parser.parse_args()
    cfg = identity(args.host)
    if args.action == "check":
        return 0 if check(cfg) else 2
    if not args.apply:
        print(json.dumps({"action": args.action, "machine": cfg, "packages": PACKAGES if args.action == "install" else [], "mutations": False, "instruction": "Review README; root plus --apply is required"}, indent=2))
        return 0
    require(os.geteuid() == 0, "Operator must run this action as root; this program never invokes sudo")
    os.umask(0o022)
    if args.action in ("bridge", "rollback"):
        require(args.console_confirmed, "Network changes require --console-confirmed and a physical/out-of-band console")
    if args.action == "bridge":
        require(args.ip_reservation_confirmed, "Reserve/exclude the existing host IPv4 in the router first, then add --ip-reservation-confirmed")
    if args.action == "install":
        install(cfg)
    elif args.action == "bridge":
        bridge(cfg)
    elif args.action == "rollback":
        rollback(cfg)
    elif args.action == "storage":
        storage(cfg, "/mnt/psy-k8s-lab")
    else:
        require(args.initialize_blank_disk and args.device and args.serial, "Need --initialize-blank-disk --device /dev/disk/by-id/... --serial EXACT_SERIAL")
        initialize_disk(cfg, args.device, args.serial)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
