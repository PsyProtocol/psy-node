#!/usr/bin/env python3
"""Prepare/apply a temporary Realm 1 placement, without remote operations or starts.

prepare --packages <original-private-packages> --output <new-directory-outside-git>
apply --package <new-directory>/gcp-cp-ce [--check-only]
apply --package <new-directory>/gcp-edge-2 [--check-only]
rollback --package <host-package> [--check-only]

Host actions require root and the existing psy-core account. Original config,
Genesis, binaries, old-host units, existing keys and all state stay unchanged.
Rollback removes only this placement's exact config/units/drop-ins/slice; copied
keys and state remain. The operator must stop/mask the three old-host processors
and check remote exclusivity before any start. No start/enable/stop/mask occurs.
Run with install_host.py, prepare_host_packages.py and plan.py alongside this file.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import sys
import tempfile

import install_host as install
import prepare_host_packages as packages


CONFIG_NAME = "realm1-cp-ce-config.json"
SLICE = "psy-realm1.slice"
DROPIN = "50-realm1-cp-ce.conf"
HOSTS = ("gcp-cp-ce", "gcp-edge-2")
KEY_NAMES = ("processor_identity.key", "bls.key", "zk.key")
require = install.require


def unit_name(position, role):
    return f"psy-core-realm-1-v{position}-{role}.service"


def read_private(root, name):
    require(not Path(name).is_absolute() and ".." not in Path(name).parts, "invalid package path")
    fd = install.directory(root)
    try:
        owner = os.fstat(fd)
        require(owner.st_uid in {0, os.getuid(), int(os.environ.get("SUDO_UID", os.getuid()))}
                and stat.S_IMODE(owner.st_mode) == 0o700, "package root must be private and owned")
        for component in Path(name).parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid == owner.st_uid and stat.S_IMODE(info.st_mode) == 0o700,
                    "package directories must be private")
        source = os.open(Path(name).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner.st_uid
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 8 * 1024 * 1024,
                    "package input must be a private single-link regular file")
            raw = handle.read(8 * 1024 * 1024 + 1)
            require(len(raw) <= 8 * 1024 * 1024, "package input too large")
            return raw
    finally:
        os.close(fd)


def source_file(root, host, name):
    directory = root / host
    manifest = install.decode_json(read_private(directory, "manifest.json"))
    require(manifest.get("source_commit") == install.SOURCE_COMMIT
            and manifest.get("release_id") == install.RELEASE_ID and manifest.get("network") == "testnet"
            and manifest.get("host") == host and manifest.get("private_ip") == install.HOSTS[host],
            "original package provenance mismatch")
    require(all(manifest["files"].get(key) == value for key, value in install.PINNED_SHA256.items()),
            "original package release pins mismatch")
    raw = read_private(directory, name)
    require(hashlib.sha256(raw).hexdigest() == manifest["files"].get(name), "original package hash mismatch")
    return raw


def placement_config(raw):
    require(hashlib.sha256(raw).hexdigest() == install.PINNED_SHA256["config.json"], "original config pin mismatch")
    original = install.decode_json(raw)
    result = copy.deepcopy(original)
    realms = result["networks"]["testnet"]["realm_configs"]
    require(original["defaultNetwork"] == "testnet" and [r["id"] for r in realms] == [0, 1]
            and len(realms[1]["validators"]) == 3, "unexpected Realm membership")
    for position, member in enumerate(realms[1]["validators"], 1):
        addresses = member["processor_addresses"]
        require(isinstance(addresses, list) and len(addresses) == 1, "unexpected processor routes")
        parts = addresses[0].split("/")
        require(len(parts) == 7 and parts[1] == "ip4" and parts[2] == install.HOSTS[install.PROCESSORS[position - 1]]
                and parts[3:6] == ["tcp", str(41020 + position), "p2p"] and parts[6], "unexpected processor route")
        parts[2] = install.HOSTS["gcp-cp-ce"]
        member["processor_addresses"] = ["/".join(parts)]
    return (json.dumps(result, indent=2) + "\n").encode()


def processor_unit(raw, position):
    host = install.PROCESSORS[position - 1]
    _, keys = install.host_inventory(host)
    install.validate_unit(unit_name(position, "processor"), raw, keys, host)
    lines = raw.decode("ascii").splitlines()
    old_env = f'Environment="PSY_CONFIG_PATH={install.CONFIG / "config.json"}"'
    require(lines.count(old_env) == 1 and not any(line.startswith("Slice=") for line in lines),
            "unexpected original processor unit")
    lines[lines.index(old_env)] = f'Environment="PSY_CONFIG_PATH={install.CONFIG / CONFIG_NAME}"'
    index = next(i for i, line in enumerate(lines) if line.startswith("ExecStart="))
    argv = shlex.split(lines[index].removeprefix("ExecStart="))
    argv[argv.index("--p2p-listen") + 1] = f'/ip4/{install.HOSTS["gcp-cp-ce"]}/tcp/{41020 + position}'
    lines[index] = "ExecStart=" + " ".join('"' + arg + '"' for arg in argv)
    lines.insert(lines.index("[Service]") + 1, "Slice=" + SLICE)
    return ("\n".join(lines) + "\n").encode()


def build_payloads(host, sources):
    require(host in HOSTS, "unsupported placement host")
    payloads = dict(sources)
    payloads[CONFIG_NAME] = placement_config(sources["original-config.json"])
    role = "processor" if host == "gcp-cp-ce" else "edge"
    for position in range(1, 4):
        name = unit_name(position, role)
        original = sources["original-units/" + name]
        if role == "processor":
            payloads["units/" + name] = processor_unit(original, position)
        else:
            _, keys = install.host_inventory(host)
            install.validate_unit(name, original, keys, host)
            payloads[f"units/{name}.d/{DROPIN}"] = (
                f'[Service]\nEnvironment="PSY_CONFIG_PATH={install.CONFIG / CONFIG_NAME}"\n').encode()
    if role == "processor":
        payloads["units/" + SLICE] = b"[Slice]\nMemoryAccounting=true\nMemoryHigh=16G\nMemoryMax=18G\n"
    return payloads


def source_names(host):
    require(host in HOSTS, "unsupported placement host")
    role = "processor" if host == "gcp-cp-ce" else "edge"
    names = {"original-config.json"} | {"original-units/" + unit_name(p, role) for p in range(1, 4)}
    if role == "processor":
        names.update(f"keys/realm-1-v{p}/{name}" for p in range(1, 4) for name in KEY_NAMES)
    return names


def prepare(root, output):
    require(not os.path.lexists(output), "output already exists")
    parent = install.directory(output.parent)
    os.close(parent)
    for ancestor in (output.parent, *output.parent.parents):
        require(not os.path.lexists(ancestor / ".git"), "output must be outside Git")
    config = source_file(root, "gcp-cp-ce", "config.json")
    staging = Path(tempfile.mkdtemp(prefix=".realm1-placement-", dir=output.parent))
    try:
        for host in HOSTS:
            sources = {"original-config.json": config}
            for position in range(1, 4):
                old_host = install.PROCESSORS[position - 1] if host == "gcp-cp-ce" else host
                role = "processor" if host == "gcp-cp-ce" else "edge"
                name = unit_name(position, role)
                sources["original-units/" + name] = source_file(root, old_host, "units/" + name)
                if role == "processor":
                    for key in KEY_NAMES:
                        path = f"keys/realm-1-v{position}/{key}"
                        sources[path] = source_file(root, old_host, path)
            payloads = build_payloads(host, sources)
            for name, raw in payloads.items():
                packages.write_new(staging / host / name, raw)
            manifest = {"host": host, "source_commit": install.SOURCE_COMMIT,
                        "pins": install.PINNED_SHA256,
                        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()}}
            packages.write_new(staging / host / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
        packages.publish_packages(staging, output)
    except BaseException:
        shutil.rmtree(staging)
        raise
    return {"prepared": list(HOSTS), "started": False}


def read_package(root):
    manifest = install.decode_json(read_private(root, "manifest.json"))
    require(set(manifest) == {"host", "source_commit", "pins", "files"}
            and manifest["source_commit"] == install.SOURCE_COMMIT and manifest["pins"] == install.PINNED_SHA256,
            "placement package provenance mismatch")
    host = manifest["host"]
    sources = {name: read_private(root, name) for name in source_names(host)}
    expected = build_payloads(host, sources)
    require(set(manifest["files"]) == set(expected), "placement inventory mismatch")
    for name, raw in expected.items():
        require(raw == read_private(root, name) and hashlib.sha256(raw).hexdigest() == manifest["files"][name],
                "placement payload mismatch")
    return host, expected


def read_installed(path, mode, uid, gid, expected=None, digest=None):
    parent = install.directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid),
                    f"installed file ownership/mode conflict: {path}; expected {mode:04o} {uid}:{gid}; "
                    f"found {stat.S_IMODE(info.st_mode):04o} {info.st_uid}:{info.st_gid}")
            if digest is not None:
                require(hashlib.file_digest(handle, "sha256").hexdigest() == digest, "installed artifact pin mismatch: " + str(path))
            else:
                require(info.st_size == len(expected) and handle.read() == expected, "installed file content conflict: " + str(path))
    finally:
        os.close(parent)


def check_host(host):
    addresses = json.loads(install.command(["ip", "-j", "-4", "address", "show"]))
    require(any(info.get("local") == install.HOSTS[host] for interface in addresses
                for info in interface.get("addr_info", [])), "host private IP mismatch")
    role = "processor" if host == "gcp-cp-ce" else "edge"
    names = {unit_name(p, role) for p in range(1, 4)}
    output = install.command(["systemctl", "list-units", "--all", "--type=service", "--no-legend",
                              "--plain", "--no-pager", *sorted(names)])
    for line in output.splitlines():
        fields = line.split()
        require(len(fields) >= 4 and fields[0] in names and fields[2] == "inactive" and fields[3] == "dead",
                "Realm 1 target unit is not inactive/dead")
    jobs = install.command(["systemctl", "list-jobs", "--no-legend", "--no-pager"])
    require(not any(len(parts) > 1 and parts[1] in names | {SLICE} for parts in map(str.split, jobs.splitlines())),
            "Realm 1 unit has a queued job")
    for name in names | ({SLICE} if host == "gcp-cp-ce" else set()):
        require(not os.path.lexists("/run/systemd/system/" + name)
                and not os.path.lexists("/run/systemd/system/" + name + ".d"), "runtime override conflict")
        dropins = install.UNITS / (name + ".d")
        if os.path.lexists(dropins):
            fd = install.directory(dropins)
            try:
                require(role == "edge" and set(os.listdir(fd)) <= {DROPIN}, "unit drop-in conflict")
            finally:
                os.close(fd)


def apply(root, check_only=False, rollback=False):
    require(os.geteuid() == 0, "host actions require root")
    host, payloads = read_package(root)
    user = install.get_runtime_user()
    require(user is not None, "existing psy-core account required")
    check_host(host)
    owner = (install.ROOT_UID, install.ROOT_GID)
    for name, digest in install.PINNED_SHA256.items():
        path = install.RELEASE / name if name.startswith("bin/") else install.CONFIG / name
        read_installed(path, 0o755 if name.startswith("bin/") else 0o644, *owner, digest=digest)
    files = {}
    for name, raw in payloads.items():
        if name.startswith("original-"):
            if host == "gcp-edge-2" and name.startswith("original-units/"):
                read_installed(install.UNITS / Path(name).name, 0o644, *owner, expected=raw)
            continue
        secret = name.startswith("keys/")
        path = install.UNITS / name.removeprefix("units/") if name.startswith("units/") else install.CONFIG / name
        files[path] = (raw, 0o600 if secret else 0o644, *(user if secret else owner))
    directories = {}
    for path in files:
        for parent in path.parents:
            if parent == Path("/"):
                break
            secret = parent == install.CONFIG / "keys" or install.CONFIG / "keys" in parent.parents
            directories[parent] = (0o700, *user) if secret else (0o755, *owner)
    for path, attrs in sorted(directories.items(), key=lambda item: len(item[0].parts)):
        try:
            fd = install.directory(path)
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(fd)
            managed = any(path == base or base in path.parents for base in (install.CONFIG, install.UNITS))
            if managed:
                require((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == attrs,
                        f"destination directory conflict: {path}; expected {attrs[0]:04o} {attrs[1]}:{attrs[2]}; "
                        f"found {stat.S_IMODE(info.st_mode):04o} {info.st_uid}:{info.st_gid}")
            else:
                require(info.st_uid in {0, install.ROOT_UID}
                        and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                        "unsafe destination ancestor: " + str(path))
        finally:
            os.close(fd)
    for path, (raw, mode, uid, gid) in files.items():
        try:
            read_installed(path, mode, uid, gid, expected=raw)
        except FileNotFoundError:
            pass
    if check_only:
        return {"mode": "rollback-check" if rollback else "check-only", "host": host, "started": False}
    check_host(host)
    if rollback:
        for path, (raw, mode, uid, gid) in files.items():
            if install.CONFIG / "keys" in path.parents:
                continue
            try:
                read_installed(path, mode, uid, gid, expected=raw)
            except FileNotFoundError:
                continue
            parent = install.directory(path.parent)
            try:
                os.unlink(path.name, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
    else:
        for path, attrs in sorted(directories.items(), key=lambda item: len(item[0].parts)):
            install.create_directory(path, *attrs)
        for path, attrs in files.items():
            install.install_file(path, *attrs)
    install.command(["systemctl", "daemon-reload"])
    return {"mode": "rolled-back" if rollback else "installed", "host": host, "started": False,
            "old_host_exclusivity": "operator must verify before start"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--packages", required=True, type=Path)
    prepare_parser.add_argument("--output", required=True, type=Path)
    for action in ("apply", "rollback"):
        host_parser = sub.add_parser(action)
        host_parser.add_argument("--package", required=True, type=Path)
        host_parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = prepare(args.packages, args.output) if args.action == "prepare" else apply(
            args.package, args.check_only, args.action == "rollback")
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        if isinstance(error, install.InstallError):
            detail = str(error)
        elif isinstance(error, OSError):
            detail = f"OS error {error.errno}: {error.strerror}; path={error.filename}"
        else:
            detail = type(error).__name__ + " in package metadata"
        print("Realm 1 placement rejected; no service starts performed: " + detail, file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
