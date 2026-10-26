#!/usr/bin/env python3
"""Install one staged core-only host package; never start or enable services.

Usage: sudo python3 install_host.py --package /private/host --check-only
       sudo python3 install_host.py --package /private/host

manifest.json must contain exactly:
  {"schema_version": 1, "release_id": "core-testnet-20261026-r2",
   "source_commit": "5d38eefc07b0925ed9875b74805d9c3fea73d998",
   "network": "testnet", "host": "<topology alias>",
   "private_ip": "<host RFC1918 IPv4>", "files": {"relative/path": "sha256"}}
files covers ALL payload files, excluding manifest.json itself. Allowed payloads:
bin/psy_node_cli, config.json, genesis.json, units/psy-core-*.service and this
host's keys/realm-R-vV/{processor_identity.key,bls.key,zk.key,edge_identity.key}.
The staging directory must be private (0700), owned by root or SUDO_UID, with
one owner and no links. Nonroot local readers may use their own UID.
The supplied manifest is a trusted deployment input, not a signed attestation
that proves binary build provenance. Binary, config and Genesis bytes must also
match this installer's release pins. The caller owns build/key/Genesis checks.

Both modes validate hashes, host IP, stopped core units and existing paths.
--check-only makes no writes and does not create the system account. Installation
creates psy-core, publishes only missing files without overwriting, and calls
daemon-reload. Exact existing bytes, modes and ownership are idempotent; any
conflict aborts. A partial install can be retried with the identical package.
Do not start services concurrently with installation. No database initialization,
key generation, package download, service start/enable, or parth changes occur.
"""

import argparse
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import sys
from urllib.parse import urlsplit


SOURCE_COMMIT = "5d38eefc07b0925ed9875b74805d9c3fea73d998"
# No r1 binary or Genesis may be accepted under the r2 release label.
PINNED_SHA256 = {
    "bin/psy_node_cli": "9b7a792da5c8cb45ec1c2db022ac52ce405e5cd05d154a1c7ac7c4941faaf9cb",
    "config.json": "c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0",
    "genesis.json": "a5465bd712ceb66585660fddb4ac233afb747938395adaa200a63ead2f25f2c8",
}
RELEASE_ID = "core-testnet-20261026-r2"
RELEASE = Path("/opt/psy-core/releases") / RELEASE_ID
CONFIG = Path("/etc/psy-core") / RELEASE_ID
STATE = Path("/var/lib/psy-core") / RELEASE_ID
UNITS = Path("/etc/systemd/system")
ROOT_UID = 0
ROOT_GID = 0
PROCESSORS = ("gcp-realm-processor", "realm-processors-b", "realm-processors-c")
EDGES = ("gcp-edge-1", "gcp-edge-2")
HOSTS = {"gcp-cp-ce": "10.148.0.25", "gcp-realm-processor": "10.148.0.37",
         "realm-processors-b": "10.148.0.42", "realm-processors-c": "10.148.0.43",
         "gcp-edge-1": "10.148.0.36", "gcp-edge-2": "10.148.0.35"}


class InstallError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InstallError(message)


def decode_json(raw):
    def unique(pairs):
        fields = {}
        for key, value in pairs:
            require(key not in fields, "duplicate JSON field")
            fields[key] = value
        return fields
    try:
        document = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise InstallError("invalid JSON") from None
    require(isinstance(document, dict), "expected JSON object")
    return document


def directory(path):
    path = Path(path).absolute()
    require(".." not in path.parts, "parent traversal forbidden")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "not a single-link regular file")
        return source.read(), info


def read_package(path):
    fd = directory(path)
    try:
        owner = os.fstat(fd)
        require(stat.S_IMODE(owner.st_mode) == 0o700, "package directory must be 0700")
        allowed_owners = {0, os.geteuid()}
        sudo_uid = os.environ.get("SUDO_UID")
        if sudo_uid is not None:
            require(re.fullmatch(r"[0-9]{1,10}", sudo_uid) and int(sudo_uid) < 2**32 - 1,
                    "invalid SUDO_UID")
            allowed_owners.add(int(sudo_uid))
        require(owner.st_uid in allowed_owners, "package owner must be root or invoking user")
        payloads, directories = {}, set()

        def read_tree(parent, prefix):
            for name in os.listdir(parent):
                relative = prefix + name
                require(re.fullmatch(r"[A-Za-z0-9_./-]+", relative), "invalid package path")
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(info.st_uid == owner.st_uid and not info.st_mode & 0o022,
                        "unsafe package ownership or permissions")
                if stat.S_ISDIR(info.st_mode):
                    directories.add(relative)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    try:
                        read_tree(child, relative + "/")
                    finally:
                        os.close(child)
                else:
                    raw, info = read_file(parent, name)
                    require(info.st_uid == owner.st_uid and not info.st_mode & 0o022,
                            "unsafe payload ownership or permissions")
                    require(not relative.startswith("keys/") or not info.st_mode & 0o077,
                            "keys must be private")
                    payloads[relative] = raw
        read_tree(fd, "")
    finally:
        os.close(fd)
    require("manifest.json" in payloads, "manifest missing")
    require(all(PINNED_SHA256.values()), "r2 artifact pins not frozen")
    manifest = decode_json(payloads["manifest.json"])
    require(set(manifest) == {"schema_version", "release_id", "source_commit", "network",
                              "host", "private_ip", "files"}, "unexpected manifest fields")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
            "unsupported manifest schema")
    require(manifest["release_id"] == RELEASE_ID and manifest["source_commit"] == SOURCE_COMMIT
            and manifest["network"] == "testnet", "release/source/network mismatch")
    validate_ip(manifest["private_ip"])
    expected_units, keys = host_inventory(manifest["host"])
    require(manifest["private_ip"] == HOSTS[manifest["host"]], "host alias/private IP mismatch")
    expected = {"bin/psy_node_cli", "config.json", "genesis.json"} | keys
    expected.update("units/" + unit for unit in expected_units)
    hashes = manifest["files"]
    require(isinstance(hashes, dict) and set(hashes) == expected, "manifest payload inventory mismatch")
    require(set(payloads) == expected | {"manifest.json"}, "unlisted or missing payload")
    expected_dirs = {str(parent) for name in expected for parent in Path(name).parents
                     if str(parent) != "."}
    require(directories == expected_dirs, "unexpected package directory")
    for name, digest in hashes.items():
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), "invalid SHA256")
        require(hashlib.sha256(payloads[name]).hexdigest() == digest, "payload SHA256 mismatch: " + name)
        require(name not in PINNED_SHA256 or digest == PINNED_SHA256[name], "release artifact pin mismatch: " + name)
        require(payloads[name], "empty payload: " + name)
    config = decode_json(payloads["config.json"])
    require(config.get("defaultNetwork") == "testnet"
            and isinstance(config.get("networks"), dict)
            and isinstance(config["networks"].get("testnet"), dict), "config must select testnet")
    for unit in expected_units:
        validate_unit(unit, payloads["units/" + unit], keys, manifest["host"])
    return manifest, payloads


def validate_ip(value):
    require(isinstance(value, str), "private IPv4 required")
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise InstallError("private IPv4 required") from None
    require(any(address in ipaddress.ip_network(block) for block in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")), "RFC1918 IPv4 required")


def host_inventory(host):
    require(isinstance(host, str), "invalid host alias")
    keys = set()
    if host == "gcp-cp-ce":
        names = ["coordinator-processor", *(f"coordinator-edge-{index}" for index in range(3))]
    elif host in PROCESSORS:
        position = PROCESSORS.index(host) + 1
        names = [f"realm-{realm}-v{position}-processor" for realm in range(2)]
        keys = {f"keys/realm-{realm}-v{position}/{name}.key" for realm in range(2)
                for name in ("processor_identity", "bls", "zk")}
    elif host in EDGES:
        realm = EDGES.index(host)
        names = [f"realm-{realm}-v{position}-edge" for position in range(1, 4)]
        keys = {f"keys/realm-{realm}-v{position}/edge_identity.key" for position in range(1, 4)}
    else:
        raise InstallError("unknown core host")
    return {"psy-core-r2-" + name + ".service" for name in names}, keys


def validate_unit(name, raw, keys, host):
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise InstallError("unit must be ASCII public text") from None
    require(not any(character in text for character in ("\\", "$", "%", "\r", "\x00")),
            "unit escapes/expansions forbidden")
    allowed = {
        "Unit": {"Description", "After", "Wants", "StartLimitIntervalSec", "StartLimitBurst"},
        "Service": {"Type", "User", "Group", "WorkingDirectory", "UMask", "Environment",
                    "ExecStart", "Restart", "RestartSec", "LimitNOFILE", "NoNewPrivileges",
                    "TimeoutStopSec", "KillSignal", "LimitCORE", "PrivateTmp", "ProtectHome",
                    "ProtectSystem", "ReadWritePaths", "StandardOutput", "StandardError"},
        "Install": {"WantedBy"},
    }
    section, values, environments = None, {}, []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            require(section in allowed, "unsupported unit section")
            continue
        key, separator, value = line.partition("=")
        require(separator and section in allowed and key in allowed[section], "unsupported unit directive")
        if key == "Environment":
            environments.extend(shlex.split(value))
        else:
            require((section, key) not in values, "duplicate unit directive")
            values[section, key] = value
    required_env = {"PSY_NETWORK=testnet", "PSY_CONFIG_PATH=" + str(CONFIG / "config.json")}
    optional_env = {"RUST_LOG=info", "RUST_MIN_STACK=134217728", "RAYON_NUM_THREADS=2"}
    require(required_env <= set(environments) <= required_env | optional_env
            and len(environments) == len(set(environments)), "unit environment must contain only approved public values")
    fixed = {
        ("Unit", "After"): "network-online.target", ("Unit", "Wants"): "network-online.target",
        ("Unit", "StartLimitIntervalSec"): "600", ("Unit", "StartLimitBurst"): "3",
        ("Install", "WantedBy"): "multi-user.target",
        ("Service", "Restart"): "on-failure", ("Service", "NoNewPrivileges"): "true",
        ("Service", "TimeoutStopSec"): "300", ("Service", "KillSignal"): "SIGTERM",
        ("Service", "LimitCORE"): "0", ("Service", "PrivateTmp"): "true",
        ("Service", "ProtectHome"): "true", ("Service", "ProtectSystem"): "strict",
        ("Service", "ReadWritePaths"): str(STATE), ("Service", "StandardOutput"): "journal",
        ("Service", "StandardError"): "journal",
    }
    for key, expected in fixed.items():
        require(key not in values or values[key] == expected, "unsafe unit directive value")
    for key in ("RestartSec", "LimitNOFILE"):
        require(("Service", key) not in values or re.fullmatch(r"[0-9]+", values["Service", key]),
                "invalid numeric unit directive")
    for key, expected in {"User": "psy-core", "Group": "psy-core", "Type": "simple",
                          "WorkingDirectory": str(RELEASE), "UMask": "0077"}.items():
        require(values.get(("Service", key)) == expected, "unsafe unit runtime settings")
    argv = shlex.split(values.get(("Service", "ExecStart"), ""))
    role = "realm-" + ("processor" if name.endswith("-processor.service") else "edge")
    if "coordinator" in name:
        role = "coordinator-processor" if name.endswith("-processor.service") else "coordinator-edge"
    require(argv[:2] == [str(RELEASE / "bin/psy_node_cli"), "start-" + role], "unexpected unit executable/role")
    options, current = {}, None
    for value in argv[2:]:
        if value.startswith("--"):
            require(value not in options, "duplicate node option")
            options[value], current = [], value
        else:
            require(current is not None, "invalid node argument")
            options[current].append(value)
    permitted = {"--network", "--proving-backend", "--scylla-db-url", "--redis-url",
                 "--nats-jetstream-url", "--db-namespace", "--coordinator-id", "--coordinator-sub-id",
                 "--genesis-data-path", "--checkpoint-backup-path", "--worker-whitelist-config",
                 "--listen", "--port", "--realm-id", "--coordinator-api-urls", "--p2p-identity-key",
                 "--p2p-bls-key", "--p2p-zk-key", "--p2p-listen"}
    require(set(options) <= permitted and all(options.values()), "unsupported node option")
    require(all(len(arguments) == 1 for option, arguments in options.items()
                if option != "--coordinator-api-urls"), "invalid node option arity")
    require(options.get("--network") == ["psy-public-testnet"] and
            options.get("--proving-backend") == ["plonky2-poseidon-goldilocks"], "unsafe node network/backend")
    namespace = options.get("--db-namespace", [])
    require(len(namespace) == 1 and re.fullmatch(r"fresh20261026r2_(coordinator|r[01]_v[123])", namespace[0]),
            "node namespace is not fresh")
    for option, scheme in (("--scylla-db-url", "tcp"), ("--redis-url", "redis"), ("--nats-jetstream-url", "nats")):
        require(option in options, "missing infrastructure option")
        endpoint = options[option][0]
        parsed = urlsplit("tcp://" + endpoint if scheme == "tcp" else endpoint)
        validate_ip(parsed.hostname)
        require(parsed.scheme == scheme and parsed.port is not None and not parsed.username
                and not parsed.password and not parsed.path and not parsed.query and not parsed.fragment,
                "unsafe infrastructure endpoint")
    paths = {"--genesis-data-path": CONFIG / "genesis.json",
             "--checkpoint-backup-path": STATE / "checkpoints", "--worker-whitelist-config": CONFIG / "config.json"}
    for option, expected in paths.items():
        require(option not in options or options[option] == [str(expected)], "node path escapes release")
    if role.endswith("processor"):
        require("--genesis-data-path" in options and "--checkpoint-backup-path" in options,
                "processor missing release paths")
    else:
        require("--worker-whitelist-config" in options, "edge missing worker whitelist")
    key_options = {"--p2p-identity-key": "processor_identity.key" if role.endswith("processor") else "edge_identity.key",
                   "--p2p-bls-key": "bls.key", "--p2p-zk-key": "zk.key"}
    required_keys = set()
    if role.startswith("realm"):
        slot = name.removeprefix("psy-core-r2-").rsplit("-", 1)[0]
        realm, position = slot.split("-")[1:]
        require(namespace == [f"fresh20261026r2_r{realm}_{position}"]
                and options.get("--realm-id") == [realm], "unit Realm/namespace mismatch")
        required_keys = {"--p2p-identity-key"}
        if role.endswith("processor"):
            required_keys.update(("--p2p-bls-key", "--p2p-zk-key"))
        for option in required_keys:
            relative = "keys/" + slot + "/" + key_options[option]
            require(relative in keys and options.get(option) == [str(CONFIG / relative)], "incorrect per-host key path")
    require(set(options) & set(key_options) == required_keys, "unexpected key option")
    if role.startswith("coordinator"):
        require(namespace == ["fresh20261026r2_coordinator"]
                and options.get("--coordinator-id") == ["0"]
                and options.get("--coordinator-sub-id") == ["0"], "unit Coordinator/namespace mismatch")
    endpoints = {}
    if role == "coordinator-edge":
        index = int(name.removeprefix("psy-core-r2-coordinator-edge-").removesuffix(".service"))
        endpoints = {"--listen": [HOSTS[host]], "--port": [str(15370 + index)]}
    elif role.startswith("realm"):
        realm_id, validator_position = int(realm), int(position.removeprefix("v"))
        port = (41000 if role == "realm-processor" else 41100) + realm_id * 20 + validator_position
        endpoints["--p2p-listen"] = [f"/ip4/{HOSTS[host]}/tcp/{port}"]
        if role == "realm-edge":
            endpoints.update({"--listen": [HOSTS[host]], "--port": [str(15379 + realm_id * 3 + validator_position)]})
        else:
            endpoints["--coordinator-api-urls"] = [f'http://{HOSTS["gcp-cp-ce"]}:{port}'
                                                  for port in (15370, 15371, 15372)]
    endpoint_options = {"--listen", "--port", "--p2p-listen", "--coordinator-api-urls"}
    require({key: value for key, value in options.items() if key in endpoint_options} == endpoints,
            "unit endpoints differ from approved host/role ports")


def command(argv):
    try:
        return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        raise InstallError("host command failed: " + argv[0]) from None


def check_host(manifest):
    addresses = json.loads(command(["ip", "-j", "-4", "address", "show"]))
    require(any(info.get("local") == manifest["private_ip"] for interface in addresses
                for info in interface.get("addr_info", [])), "host private IP mismatch")
    output = command(["systemctl", "list-units", "--all", "--type=service", "--no-legend",
                      "--plain", "--no-pager", "psy-core-*"])
    for line in output.splitlines():
        fields = line.split()
        require(len(fields) >= 4 and fields[0].startswith("psy-core-"), "unexpected systemctl output")
        require(fields[2] in {"inactive", "failed"} and fields[3] in {"dead", "failed"},
                "core unit is running or transitioning")
    jobs = command(["systemctl", "list-jobs", "--no-legend", "--no-pager"])
    require(not any(len(fields) > 1 and fields[1].startswith("psy-core-")
                    for fields in map(str.split, jobs.splitlines())), "core unit has queued job")


def get_runtime_user():
    try:
        user = pwd.getpwnam("psy-core")
    except KeyError:
        try:
            grp.getgrnam("psy-core")
        except KeyError:
            return None
        raise InstallError("psy-core group exists without account") from None
    group = grp.getgrnam("psy-core")
    require(0 < user.pw_uid < 1000 and user.pw_gid == group.gr_gid and group.gr_gid != 0
            and user.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")
            and user.pw_dir == "/nonexistent", "conflicting psy-core account")
    return user.pw_uid, user.pw_gid


def build_paths(payloads, user):
    uid, gid = user if user is not None else (-1, -1)
    files = {}
    for name, raw in payloads.items():
        if name.startswith("bin/"):
            target, mode, owner = RELEASE / name, 0o755, (ROOT_UID, ROOT_GID)
        elif name.startswith("units/"):
            target, mode, owner = UNITS / Path(name).name, 0o644, (ROOT_UID, ROOT_GID)
        else:
            secret = name.startswith("keys/")
            target, mode, owner = CONFIG / name, 0o600 if secret else 0o644, (uid, gid) if secret else (ROOT_UID, ROOT_GID)
        files[target] = (raw, mode, *owner)
    directories = {STATE: (0o700, uid, gid), STATE / "checkpoints": (0o700, uid, gid)}
    for target in list(files) + list(directories):
        for parent in target.parents:
            if parent == Path("/"):
                break
            directories.setdefault(parent, (0o755, ROOT_UID, ROOT_GID))
    for parent in directories:
        if parent == CONFIG / "keys" or CONFIG / "keys" in parent.parents:
            directories[parent] = (0o700, uid, gid)
    return files, directories


def check_paths(files, directories):
    managed = (RELEASE, CONFIG, STATE)
    for path, (mode, uid, gid) in sorted(directories.items(), key=lambda item: len(item[0].parts)):
        try:
            fd = directory(path)
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(fd)
            is_managed = any(path == root or root in path.parents for root in managed)
            if is_managed:
                require((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid),
                        "directory ownership/mode conflict: " + str(path))
            else:
                require(info.st_uid in {0, ROOT_UID} and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                        "unsafe destination ancestor: " + str(path))
            if is_managed and path != STATE / "checkpoints":
                require(all(path / name in files or path / name in directories for name in os.listdir(fd)),
                        "unexpected existing release path: " + str(path))
        finally:
            os.close(fd)
    for path, (raw, mode, uid, gid) in files.items():
        try:
            fd = directory(path.parent)
        except FileNotFoundError:
            continue
        try:
            try:
                existing, info = read_file(fd, path.name)
            except FileNotFoundError:
                continue
            require(existing == raw and (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid),
                    "existing file conflict: " + str(path))
        finally:
            os.close(fd)
    for path in files:
        if path.parent == UNITS:
            require(not os.path.lexists(str(path) + ".d"), "unit drop-in conflict")
            require(not os.path.lexists("/run/systemd/system/" + path.name)
                    and not os.path.lexists("/run/systemd/system/" + path.name + ".d"), "runtime unit override conflict")


def create_directory(path, mode, uid, gid):
    parent = directory(path.parent)
    try:
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            fd = directory(path)
            try:
                info = os.fstat(fd)
                if any(path == root or root in path.parents for root in (RELEASE, CONFIG, STATE)):
                    require((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid),
                            "directory ownership/mode conflict: " + str(path))
                else:
                    require(info.st_uid in {0, ROOT_UID} and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                            "unsafe destination ancestor: " + str(path))
            finally:
                os.close(fd)
            return
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def install_file(path, raw, mode, uid, gid):
    parent = directory(path.parent)
    temporary = None
    try:
        try:
            existing, info = read_file(parent, path.name)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            require(existing == raw and (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid),
                    "existing file conflict: " + str(path))
            return
        temporary = ".install-" + os.urandom(12).hex()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            target.write(raw)
            target.flush()
            os.fchown(target.fileno(), uid, gid)
            os.fchmod(target.fileno(), mode)
            os.fsync(target.fileno())
        # link publishes atomically without rename's overwrite race.
        os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.unlink(temporary, dir_fd=parent)
        temporary = None
        os.fsync(parent)
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def install_host(package, check_only=False):
    require(os.geteuid() == 0, "run with sudo/root, including --check-only")
    manifest, payloads = read_package(package)
    check_host(manifest)
    user = get_runtime_user()
    files, directories = build_paths(payloads, user)
    check_paths(files, directories)
    if check_only:
        return {"mode": "check-only", "host": manifest["host"], "files": len(files)}
    if user is None:
        command(["useradd", "--system", "--user-group", "--home-dir", "/nonexistent",
                 "--no-create-home", "--shell", "/usr/sbin/nologin", "psy-core"])
        user = get_runtime_user()
        require(user is not None, "psy-core account creation failed")
        files, directories = build_paths(payloads, user)
    check_host(manifest)
    for path, attributes in sorted(directories.items(), key=lambda item: len(item[0].parts)):
        create_directory(path, *attributes)
    for path, attributes in files.items():
        install_file(path, *attributes)
    command(["systemctl", "daemon-reload"])
    return {"mode": "installed", "host": manifest["host"], "files": len(files), "started": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--package", required=True, type=Path, help="private per-host staging directory")
    parser.add_argument("--check-only", action="store_true", help="read-only preflight; no account/file changes or reload")
    args = parser.parse_args(argv)
    try:
        report = install_host(args.package, args.check_only)
    except (InstallError, OSError, ValueError, TypeError, KeyError) as error:
        message = str(error) if isinstance(error, InstallError) else "unreadable or malformed host input"
        print(json.dumps({"error": message}), file=sys.stderr)
        return 1
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
