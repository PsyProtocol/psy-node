#!/usr/bin/env python3
"""Prepare only private Bridge forwarding on the existing gateway.

preview prints the exact units. check-host (default) is read-only, requires root,
and checks host identity, listener conflicts, BPF attachment and backend RPC/TCP.
install requires --apply, creates only absent files, reloads systemd, and never
enables/starts anything. Repeat install accepts only byte-identical owned files.
--scope edges checks/installs only the nine Edge routes; --scope proxies selects
only the two prove-proxy routes. Omitted scope selects all eleven routes.
rollback --apply stops/removes only byte-identical owned units and helper files;
without --apply rollback only checks ownership. Transfer this reviewed script
unchanged to the gateway before running it. No SSH, packages, secrets, firewall,
WireGuard, Caddy, existing L1 forwarders, or L2 state are managed here.

Every command requires --topology FILE and --topology-sha256 HASH. The JSON has
exactly gateway (hostname, wireguard/cloud each with interface/address), edges
(coordinator, realm0, realm1 addresses), proxies (system/user addresses), and
cloud_clients (seven addresses). Offsite clients are the two proxy addresses.
The pinned /32 client lists are the trust boundary, not application authorization.
Kernel BPF queries use only BPF_PROG_QUERY, never load/attach/modify programs.
Every socket checks its own filters before binding; services check theirs before
exec. Root/systemd and the installed root-owned files are trusted. Actual allowed
and denied client connections remain a separate post-activation acceptance gate.
"""

import argparse
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys


PREFIX = "psy-bridge-private-"
UNITS = Path("/etc/systemd/system")
HELPER = Path("/usr/local/lib/psy-bridge-private/prepare_bridge_forwarders.py")
TOPOLOGY = HELPER.with_name("topology.json")
PROXY = "/usr/lib/systemd/systemd-socket-proxyd"
CGROUPS = Path("/sys/fs/cgroup")
EDGE_PORTS = {"coordinator": (15370, 15371, 15372), "realm0": (15380, 15381, 15382),
              "realm1": (15383, 15384, 15385)}


class ForwarderError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ForwarderError(message)


def validate_fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), "unexpected topology fields")


def validate_address(value):
    require(isinstance(value, str), "IPv4 address required")
    address = ipaddress.IPv4Address(value)
    number = int(address)
    require(number >> 24 == 10 or number >> 20 == 0xAC1 or number >> 16 == 0xC0A8,
            "only RFC1918 host addresses are allowed")
    return value


def validate_topology(topology):
    validate_fields(topology, ("gateway", "edges", "proxies", "cloud_clients"))
    gateway = topology["gateway"]
    validate_fields(gateway, ("hostname", "wireguard", "cloud"))
    require(isinstance(gateway["hostname"], str) and
            re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]", gateway["hostname"]),
            "invalid gateway hostname")
    for role in ("wireguard", "cloud"):
        validate_fields(gateway[role], ("interface", "address"))
        require(isinstance(gateway[role]["interface"], str) and
                re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,14}", gateway[role]["interface"]),
                "invalid gateway interface")
        validate_address(gateway[role]["address"])
    require(gateway["wireguard"]["interface"] != gateway["cloud"]["interface"], "distinct interfaces required")
    validate_fields(topology["edges"], EDGE_PORTS)
    validate_fields(topology["proxies"], ("system", "user"))
    hosts = [gateway[role]["address"] for role in ("wireguard", "cloud")]
    hosts += [validate_address(ip) for ip in topology["edges"].values()]
    hosts += [validate_address(ip) for ip in topology["proxies"].values()]
    require(len(set(hosts)) == len(hosts), "gateway, Edge and offsite hosts must be distinct")
    clients = topology["cloud_clients"]
    require(isinstance(clients, list) and len(clients) == 7, "seven owned cloud clients required")
    require(len({validate_address(ip) for ip in clients}) == 7, "distinct cloud clients required")
    require(not set(clients) & {gateway[role]["address"] for role in ("wireguard", "cloud")}
            and not set(clients) & set(topology["proxies"].values()), "cloud and offsite roles overlap")
    return topology


def read_topology(path, expected_hash):
    require(isinstance(expected_hash, str) and re.fullmatch(r"[0-9a-f]{64}", expected_hash),
            "lowercase SHA-256 topology pin required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        file_stat = os.fstat(stream.fileno())
        require(stat.S_ISREG(file_stat.st_mode) and file_stat.st_nlink == 1, "regular topology file required")
        raw = stream.read(65537)
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == expected_hash, "topology hash mismatch")
    def unique_fields(pairs):
        fields = {}
        for name, value in pairs:
            require(name not in fields, "duplicate topology field")
            fields[name] = value
        return fields
    return validate_topology(json.loads(raw, object_pairs_hook=unique_fields)), raw


@dataclass(frozen=True)
class Forwarder:
    name: str
    listen_address: str
    listen_port: int
    backend_address: str
    backend_port: int
    clients: tuple
    is_edge: bool

    def unit_name(self, suffix):
        return PREFIX + self.name + suffix


def build_forwarders(topology, scope="all"):
    gateway = topology["gateway"]
    offsite_clients = tuple(topology["proxies"][role] for role in ("system", "user"))
    edges = tuple(Forwarder(f"edge-{port}", gateway["wireguard"]["address"], port,
                            topology["edges"][role], port, offsite_clients, True)
                  for role, ports in EDGE_PORTS.items() for port in ports)
    proxies = (
        Forwarder("system", gateway["cloud"]["address"], 19998, topology["proxies"]["system"],
                  9998, tuple(topology["cloud_clients"]), False),
        Forwarder("user", gateway["cloud"]["address"], 19999, topology["proxies"]["user"],
                  9999, tuple(topology["cloud_clients"]), False),
    )
    require(scope in ("all", "edges", "proxies"), "invalid forwarder scope")
    return {"all": edges + proxies, "edges": edges, "proxies": proxies}[scope]


def build_filter(addresses):
    return "IPAddressDeny=any\n" + "".join(f"IPAddressAllow={ip}/32\n" for ip in addresses)


def build_units(topology, topology_hash, scope="all"):
    units = {}
    guard = f"/usr/bin/python3 -B {HELPER} --topology {TOPOLOGY} --topology-sha256 {topology_hash}"
    for forwarder in build_forwarders(topology, scope):
        socket_name = forwarder.unit_name(".socket")
        service_name = forwarder.unit_name(".service")
        units[socket_name] = (
            "[Unit]\nDescription=Private Bridge forwarding socket\n"
            "DefaultDependencies=no\nWants=network-online.target\nAfter=network-online.target\n"
            "Before=shutdown.target\nConflicts=shutdown.target\n\n[Socket]\n"
            f"ListenStream={forwarder.listen_address}:{forwarder.listen_port}\n"
            "Accept=no\nFreeBind=no\nReusePort=no\n"
            f"Service={service_name}\n"
            f"BindToDevice={topology['gateway']['wireguard' if forwarder.is_edge else 'cloud']['interface']}\n"
            f"ExecStartPre={guard} check-filter {socket_name}\n"
            "Slice=system.slice\nTimeoutSec=15\n" + build_filter(forwarder.clients) +
            "\n[Install]\nWantedBy=multi-user.target\n"
        )
        # Inherited sockets retain the socket's filters; new backend sockets use the service's.
        units[service_name] = (
            "[Unit]\nDescription=Private Bridge socket proxy\n"
            f"Requires={socket_name}\nAfter={socket_name}\nBindsTo={socket_name}\n\n"
            "[Service]\nType=simple\nSlice=system.slice\nUser=nobody\nGroup=nogroup\n"
            f"ExecStartPre=+{guard} check-filter {service_name}\n"
            f"ExecStart={PROXY} --connections-max=256 {forwarder.backend_address}:{forwarder.backend_port}\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\n"
            "RestrictAddressFamilies=AF_INET AF_UNIX\nTimeoutStartSec=15\nTimeoutStopSec=15\n" +
            build_filter((forwarder.backend_address,))
        )
    return units


class BPFQuery(ctypes.Structure):
    _fields_ = [("target_fd", ctypes.c_uint32), ("attach_type", ctypes.c_uint32),
                ("query_flags", ctypes.c_uint32), ("attach_flags", ctypes.c_uint32),
                ("prog_ids", ctypes.c_uint64), ("prog_cnt", ctypes.c_uint32),
                ("padding", ctypes.c_uint32)]


def get_filter_counts(cgroup):
    syscall_number = {"x86_64": 321, "aarch64": 280}.get(platform.machine())
    require(syscall_number is not None, "unsupported architecture for read-only BPF query")
    require((CGROUPS / "cgroup.controllers").is_file(), "unified cgroup v2 required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    fd = os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    counts = []
    try:
        for attach_type in (0, 1):
            program_ids = (ctypes.c_uint32 * 64)()
            query = BPFQuery(fd, attach_type, 0, 0, ctypes.addressof(program_ids), 64, 0)
            returned = libc.syscall(syscall_number, 16, ctypes.byref(query), ctypes.sizeof(query))
            require(returned == 0, f"BPF_PROG_QUERY failed (errno={ctypes.get_errno()})")
            counts.append(query.prog_cnt)
    finally:
        os.close(fd)
    return counts


def verify_filters(cgroup):
    counts = get_filter_counts(cgroup)
    require(len(counts) == 2 and all(count > 0 for count in counts),
            "missing ingress/egress BPF filters; refusing unfiltered forwarding")


def check_filter(unit, topology, topology_hash):
    require(unit in build_units(topology, topology_hash), "not an owned forwarder unit")
    expected = f"/system.slice/{unit}"
    require(Path("/proc/self/cgroup").read_text().splitlines() == ["0::" + expected],
            "filter guard must run in its own systemd unit cgroup")
    verify_filters(CGROUPS / expected.lstrip("/"))
    # Both policies exclude loopback: prove egress denial, not merely IP accounting attachment.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.settimeout(2)
        try:
            probe.sendto(b"", ("127.0.0.1", 9))
        except OSError as error:
            require(error.errno == errno.EPERM, "unexpected error probing excluded peer")
        else:
            raise ForwarderError("BPF did not deny excluded peer; refusing forwarding")


def run_command(argv):
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    diagnostic = " ".join(completed.stderr.split())[:1000]
    require(completed.returncode == 0, f"command failed: {argv[0]} {argv[1]}: {diagnostic}")
    return completed.stdout


def get_unit_properties(unit):
    output = run_command(["systemctl", "show", unit, "--no-pager",
                          "--property=LoadState,FragmentPath,DropInPaths,ActiveState,UnitFileState"])
    properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    require("LoadState" in properties and "ActiveState" in properties, "incomplete systemd unit state")
    return properties


def verify_host(topology):
    require(os.geteuid() == 0, "root required (use sudo -n)")
    gateway = topology["gateway"]
    require(socket.gethostname() == gateway["hostname"], "wrong gateway hostname")
    interfaces = json.loads(run_command(["ip", "-j", "-4", "address", "show"]))
    addresses = {(interface["ifname"], address["local"]) for interface in interfaces
                 for address in interface.get("addr_info", []) if address["family"] == "inet"}
    require(all((gateway[role]["interface"], gateway[role]["address"]) in addresses
                for role in ("wireguard", "cloud")),
            "wrong gateway private addresses/interfaces")


def get_listening_ports():
    ports = set()
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        for line in path.read_text().splitlines()[1:]:
            columns = line.split()
            if columns[3] == "0A":
                ports.add(int(columns[1].rsplit(":", 1)[1], 16))
    return ports


def verify_ports(topology, scope="all"):
    conflicts = get_listening_ports() & {f.listen_port for f in build_forwarders(topology, scope)}
    require(not conflicts, f"forwarder ports already listening (including wildcard/IPv6): {sorted(conflicts)}")


def check_backends(topology, scope="all"):
    checks = []
    for forwarder in build_forwarders(topology, scope):
        check = {"name": forwarder.name, "backend": f"{forwarder.backend_address}:{forwarder.backend_port}"}
        try:
            if forwarder.is_edge:
                check["checkpoint"] = get_checkpoint(forwarder)
            else:
                with socket.create_connection((forwarder.backend_address, forwarder.backend_port), timeout=3):
                    pass
            check["ready"] = True
        except (OSError, ValueError, http.client.HTTPException) as error:
            check.update(ready=False, error=type(error).__name__)
        checks.append(check)
    return checks


def get_checkpoint(forwarder):
    connection = http.client.HTTPConnection(forwarder.backend_address, forwarder.backend_port, timeout=3)
    try:
        connection.request("POST", "/", json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": "psy_get_latest_checkpoint_id", "params": []}),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(4097)
        require(response.status == 200 and len(raw) <= 4096, "invalid Edge HTTP response")
        reply = json.loads(raw)
        require(isinstance(reply, dict) and reply.get("jsonrpc") == "2.0"
                and type(reply.get("id")) is int and reply["id"] == 1
                and "error" not in reply and type(reply.get("result")) is int
                and 0 <= reply["result"] < 2 ** 64, "invalid Edge checkpoint RPC response")
        return reply["result"]
    finally:
        connection.close()


def build_files(topology, raw, scope="all"):
    topology_hash = hashlib.sha256(raw).hexdigest()
    files = {UNITS / name: content.encode() for name, content in build_units(topology, topology_hash, scope).items()}
    files[HELPER] = Path(__file__).read_bytes()
    files[TOPOLOGY] = raw
    return files


def verify_directory(path):
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                f"directory must be root-owned, non-symlink and not writable by others: {parent}")


def read_owned_file(path, expected):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == (0o600 if path == TOPOLOGY else 0o644),
                f"unsafe owned file: {path}")
        require(stream.read(len(expected) + 1) == expected, f"refusing changed/unowned file: {path}")
    return True


def verify_unit_overrides(names):
    roots = run_command(["systemd-analyze", "unit-paths"]).splitlines()
    require(roots and str(UNITS) in roots, "cannot determine systemd unit paths")
    for name in names:
        parts = name.rsplit(".", 1)
        dropins = [name + ".d", parts[1] + ".d", "psy-." + parts[1] + ".d",
                   "psy-bridge-." + parts[1] + ".d", PREFIX + "." + parts[1] + ".d"]
        if name.startswith(PREFIX + "edge-"):
            dropins.append(PREFIX + "edge-." + parts[1] + ".d")
        for root in roots:
            require(not any(os.path.lexists(Path(root) / directory) for directory in dropins),
                    f"unit drop-ins require separate review: {name}")
            candidate = Path(root) / name
            require(candidate == UNITS / name or not os.path.lexists(candidate),
                    f"foreign unit file shadows owned namespace: {name}")


def verify_owned_files(files, *, require_inactive):
    verify_directory(UNITS)
    verify_directory(HELPER.parent if HELPER.parent.exists() else HELPER.parent.parent)
    names = [path.name for path in files if path.parent == UNITS]
    verify_unit_overrides(names)
    present = {path for path, expected in files.items() if read_owned_file(path, expected)}
    for name in names:
        properties = get_unit_properties(name)
        require(not properties.get("DropInPaths"), f"unit has overrides: {name}")
        fragment = properties.get("FragmentPath", "")
        require(not fragment or (fragment == str(UNITS / name) and UNITS / name in present),
                f"foreign loaded unit: {name}")
        require(properties["LoadState"] in ("loaded", "not-found"), f"invalid unit load state: {name}")
        if require_inactive or UNITS / name not in present:
            require(properties["ActiveState"] == "inactive", f"unit must be inactive: {name}")
            require(properties.get("UnitFileState", "") in ("", "disabled", "static"),
                    f"unit must not be enabled: {name}")
    return present


def check_host(files, topology, scope="all"):
    verify_host(topology)
    verify_owned_files(files, require_inactive=True)
    verify_ports(topology, scope)
    require(os.access(PROXY, os.X_OK), "systemd-socket-proxyd missing; no packages will be installed")
    require("--connections-max=" in run_command([PROXY, "--help"]), "unsupported socket-proxyd")
    verify_filters(CGROUPS / "system.slice/systemd-journald.service")
    checks = check_backends(topology, scope)
    print(json.dumps({"mode": "read-only", "scope": scope, "backends": checks,
                      "per_unit_filter_check": "required before each bind/exec"}, sort_keys=True))
    require(all(check["ready"] for check in checks), "backend readiness failed; nothing changed")


def write_new(path, raw, mode):
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".forwarder-" + os.urandom(12).hex()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
            original = os.fstat(stream.fileno())
        os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
        return original
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def install_files(files):
    created = []
    has_created_directory = False
    has_reloaded = False
    try:
        if not HELPER.parent.exists():
            HELPER.parent.mkdir(mode=0o755)
            has_created_directory = True
        verify_directory(HELPER.parent)
        for path, expected in files.items():
            if read_owned_file(path, expected):
                continue
            original = write_new(path, expected, 0o600 if path == TOPOLOGY else 0o644)
            created.append((path, original))
        run_command(["systemd-analyze", "verify", *[str(path) for path in files if path.parent == UNITS]])
        if created:
            has_reloaded = True
            run_command(["systemctl", "daemon-reload"])
    except BaseException:
        for path, original in reversed(created):
            current = path.lstat()
            require((current.st_dev, current.st_ino) == (original.st_dev, original.st_ino),
                    "created file replaced during failed install; manual review required")
            path.unlink()
        if has_created_directory:
            HELPER.parent.rmdir()
        if has_reloaded:
            run_command(["systemctl", "daemon-reload"])
        raise


def rollback_files(files, present):
    names = [path.name for path in files if path.parent == UNITS and path in present]
    sockets = [name for name in names if name.endswith(".socket")]
    if sockets:
        run_command(["systemctl", "stop", *sockets])
    if names:
        run_command(["systemctl", "stop", *names])
        run_command(["systemctl", "disable", *names])
    for name in names:
        require(get_unit_properties(name)["ActiveState"] in ("inactive", "failed"),
                f"unit did not stop: {name}")
    remaining_units = any(path.name not in names for suffix in (".socket", ".service")
                          for path in UNITS.glob(PREFIX + "*" + suffix))
    removable = present - {HELPER, TOPOLOGY} if remaining_units else present
    for path in removable:
        require(read_owned_file(path, files[path]), f"owned file disappeared: {path}")
    try:
        for path in removable:
            path.unlink()
        if HELPER in removable and not any(HELPER.parent.iterdir()):
            HELPER.parent.rmdir()
    finally:
        if removable:
            run_command(["systemctl", "daemon-reload"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", default="check-host",
                        choices=("preview", "check-host", "install", "rollback", "check-filter"))
    parser.add_argument("unit", nargs="?")
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--topology-sha256", required=True)
    parser.add_argument("--scope", choices=("all", "edges", "proxies"), default="all")
    parser.add_argument("--apply", action="store_true", help="authorize install or rollback only")
    args = parser.parse_args(argv)
    try:
        require(not args.apply or args.command in ("install", "rollback"), "--apply is mutation-only")
        require((args.unit is not None) == (args.command == "check-filter"), "unit is only for check-filter")
        topology, raw = read_topology(args.topology, args.topology_sha256)
        if args.command == "preview":
            print(json.dumps(build_units(topology, args.topology_sha256, args.scope), indent=2, sort_keys=True))
            return 0
        if args.command == "check-filter":
            check_filter(args.unit, topology, args.topology_sha256)
            return 0
        files = build_files(topology, raw, args.scope)
        if args.command in ("check-host", "install"):
            check_host(files, topology, args.scope)
        else:
            verify_host(topology)
            verify_owned_files(files, require_inactive=False)
        if not args.apply:
            print("Read-only checks complete; no files or units changed.")
            return 0
        lock = os.open(UNITS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            present = verify_owned_files(files, require_inactive=args.command == "install")
            if args.command == "install":
                verify_ports(topology, args.scope)
                install_files(files)
                print("Owned files installed; no units enabled or started.")
            else:
                rollback_files(files, present)
                print("Only verified owned forwarder files and units removed.")
        finally:
            os.close(lock)
    except (ForwarderError, OSError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, (ForwarderError, OSError)) else type(error).__name__
        print("prepare-bridge-forwarders: " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
