#!/usr/bin/env python3
"""Prepare/install workers; explicitly activate only the reviewed r3 worker units.

package --release-dir DIR --network-config FILE --build-attestation FILE --output NEW_DIR
check-host --package DIR             (sudo; read-only)
install --package DIR                (sudo; separately authorized; never starts)
activate --package DIR               (sudo; enables/starts only the three r3 units)

The existing parth system account is reused. Existing worker JSON credentials
are read only on-host. No Genesis private keys are inputs. Fresh installations
only: partial installs require inspection, never automatic deletion or repair.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
SOURCE = "3d31758738f833a7eea6f9ff7fd680a69a0d9a44"
RELEASE_ID = "core-testnet-20261027-r3"
WORKER_SHA256 = "08d76103fb40639ecbe8182113e7fc5df61ae9a408abefb2f96de9b0ad56238d"
CONFIG_SHA256 = "c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0"
TOPOLOGY_SHA256 = "78403e274c24dd8bbb44405775868477b3cfe0ad9c9a3815cb59a1f267e5675f"
BUILD_SHA256 = "4432ea02ead2f2fd48a723b911049f5dcdb8d1ef80072518361759ab77628072"
ATTESTATION_SHA256 = "f6fdece9553ac78e85a3d7636b1883b0efed5f9332c1628d38fc9729b2fa8acb"
ACTIVATION_INSTALLER_SHA256 = "302522b5e98d3469afc54bfcc8fd0ea60352237df5d68198f07a09dc56558ed8"
RELEASE = Path("/opt/psy-core-worker/releases") / RELEASE_ID
CONFIG = Path("/etc/psy-core-worker") / RELEASE_ID
STATE = Path("/var/lib/psy-core-worker") / RELEASE_ID
UNITS = Path("/etc/systemd/system")
UNIT_SEARCH = (UNITS, Path("/run/systemd/system"), Path("/usr/lib/systemd/system"))
SOURCES = {
    "coordinator": Path("/etc/parth/c4d-workers/coordinator-0.json"),
    "realm-0": Path("/etc/parth/c4d-workers/realm-0-0.json"),
    "realm-1": Path("/etc/parth/c4d-workers/realm-1-0.json"),
}
PUBLIC_KEYS = {
    "coordinator": "03c0a27e1918d34a2722b510f4f3d19640139b43333d419ee1b7d99f9340c0b224",
    "realm-0": "02a4a04c6745b49bf1abe78a86839c47e41db7f0e963acd0aa8af2af0fdd38ab50",
    "realm-1": "02a4a04c6745b49bf1abe78a86839c47e41db7f0e963acd0aa8af2af0fdd38ab50",
}
THREADS = {"coordinator": 4, "realm-0": 6, "realm-1": 6}
ROOT_UID = 0
ROOT_GID = 0


class WorkerError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise WorkerError(message)


def decode(raw):
    def unique(pairs):
        fields = {}
        for key, value in pairs:
            require(key not in fields, "duplicate JSON field")
            fields[key] = value
        return fields
    result = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(result, dict), "JSON object required")
    return result


def encode(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def directory(path):
    path = Path(path).absolute()
    require(".." not in path.parts, "path traversal rejected")
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


def read_file(path):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    "single-link regular file required")
            return stream.read(), info
    finally:
        os.close(parent)


def worker_configs(topology):
    coordinator = topology["coordinator"]
    host = topology["hosts"][coordinator["host"]]
    configs = {}
    for role in THREADS:
        urls = [f"http://{host}:{port}" for port in coordinator["edge_ports"]]
        realm_urls = []
        if role != "coordinator":
            realm = topology["realms"][int(role[-1])]
            realm_urls = [f"http://{topology['hosts'][v['edge_host']]}:{v['http_port']}"
                          for v in realm["validators"]]
            urls = []
        configs[role] = {
            "user": 1048576 if role == "realm-1" else 0,
            "network": "psy-public-testnet",
            "coordinator_api_urls": urls, "realm_api_urls": realm_urls,
            "url_rotation_strategy": "round-robin",
            "completed_jobs_log_file": str(STATE / role / "completed.backup"),
        }
    return configs


def unit_name(role):
    return "psy-core-worker-r3-" + role + ".service"


def worker_unit(role):
    return ("\n".join([
        "[Unit]", "Description=Psy testnet worker " + role,
        "Wants=network-online.target", "After=network-online.target",
        "StartLimitIntervalSec=600", "StartLimitBurst=3", "",
        "[Service]", "Type=simple", "User=parth", "Group=parth", "UMask=0077",
        "Slice=psy-core-worker-r3.slice", "WorkingDirectory=" + str(RELEASE),
        "Environment=PSY_NETWORK=testnet", "Environment=PSY_CONFIG_PATH=" + str(CONFIG / "network.json"),
        "Environment=RUST_LOG=info", "Environment=RUST_MIN_STACK=134217728",
        "Environment=RAYON_NUM_THREADS=" + str(THREADS[role]), "Environment=TOKIO_WORKER_THREADS=2",
        "ExecStart=" + str(RELEASE / "psy_worker_cli") + " worker --config " + str(CONFIG / (role + ".json"))
        + " --network psy-public-testnet --proving-backend plonky2-poseidon-goldilocks"
        + " --url-rotation-strategy round-robin --batch-size 1 --proving-pools per-job"
        + " --threads-per-job " + str(THREADS[role]),
        "Restart=on-failure", "RestartSec=15", "TimeoutStopSec=300", "LimitNOFILE=65536",
        "LimitCORE=0", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true",
        "ProtectSystem=strict", "ReadWritePaths=" + str(STATE / role),
        "StandardOutput=journal", "StandardError=journal", "",
        "[Install]", "WantedBy=multi-user.target", "",
    ])).encode()


def payloads(inputs):
    require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (WORKER_SHA256, CONFIG_SHA256, TOPOLOGY_SHA256, BUILD_SHA256, ATTESTATION_SHA256)),
            "r3 artifact pins not frozen")
    require(digest(inputs["psy_worker_cli"]) == WORKER_SHA256, "worker binary hash mismatch")
    require(digest(inputs["network.json"]) == CONFIG_SHA256, "compiled network config hash mismatch")
    require(digest(inputs["topology.json"]) == TOPOLOGY_SHA256, "reviewed topology hash mismatch")
    require(digest(inputs["build.json"]) == BUILD_SHA256, "original build manifest hash mismatch")
    require(digest(inputs["attestation.json"]) == ATTESTATION_SHA256, "build attestation hash mismatch")
    build = decode(inputs["build.json"])
    attestation = decode(inputs["attestation.json"])
    require(type(attestation["schema_version"]) is int and attestation["schema_version"] == 1
            and attestation["kind"] == "packaging-build-attestation"
            and attestation["build_manifest_sha256"] == BUILD_SHA256,
            "attestation does not bind original build manifest")
    require(all(attestation[field] == build[field] for field in
                ("source_commit", "config_sha256", "network", "network_magic", "binaries")),
            "attestation differs from original build manifest")
    require(build["source_commit"] == SOURCE and build["network"] == "testnet"
            and build["network_magic"] == "0x1337CF514544CF69"
            and attestation["cli_network"] == "psy-public-testnet"
            and attestation["backend"] == "plonky2-poseidon-goldilocks"
            and build["config_sha256"] == CONFIG_SHA256
            and build["binaries"]["psy_worker_cli"] == WORKER_SHA256, "build provenance mismatch")
    topology = decode(inputs["topology.json"])
    require(topology["runtime_commit"] == SOURCE and topology["release_id"] == RELEASE_ID,
            "topology release mismatch")
    config = decode(inputs["network.json"])
    whitelist = config["networks"]["testnet"]["whitelist"]
    require(config["defaultNetwork"] == "testnet" and whitelist["enabled"] is True
            and set(whitelist["secp256k1"]) == set(PUBLIC_KEYS.values()), "approved whitelist mismatch")
    files = dict(inputs)
    for role, template in worker_configs(topology).items():
        files[role + ".json"] = encode(template)
        files[unit_name(role)] = worker_unit(role)
    files["psy-core-worker-r3.slice"] = b"[Unit]\nDescription=Psy core workers\n[Slice]\nMemoryHigh=26G\nMemoryMax=28G\n"
    return files


def write_new(path, raw, mode, uid, gid):
    parent = directory(path.parent)
    temporary = ".worker-" + os.urandom(12).hex()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            if (uid, gid) != (os.getuid(), os.getgid()):
                os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def prepare_package(release_dir, network_config, topology, output, build_attestation):
    inputs = {name: read_file(path)[0] for name, path in {
        "psy_worker_cli": release_dir / "psy_worker_cli", "build.json": release_dir / "manifest.json",
        "network.json": network_config, "topology.json": topology,
        "attestation.json": build_attestation,
    }.items()}
    files = payloads(inputs)
    files["prepare_workers.py"] = read_file(Path(__file__).absolute())[0]
    parent = directory(output.parent)
    try:
        os.mkdir(output.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    for name, raw in files.items():
        write_new(output / name, raw, 0o600, os.getuid(), os.getgid())
    return {"mode": "prepared", "services": len(THREADS), "contains_credentials": False, "started": False}


def read_package(package, *, activation=False):
    fd = directory(package)
    try:
        owner = os.fstat(fd)
        require(stat.S_IMODE(owner.st_mode) == 0o700, "package must be mode 0700")
        names = set(os.listdir(fd))
    finally:
        os.close(fd)
    inputs = {}
    for name in ("psy_worker_cli", "build.json", "network.json", "topology.json", "attestation.json"):
        inputs[name] = read_file(package / name)[0]
    expected = payloads(inputs)
    if activation:
        installer = read_file(package / "prepare_workers.py")[0]
        require(digest(installer) in (ACTIVATION_INSTALLER_SHA256, digest(read_file(Path(__file__).absolute())[0])),
                "installed package helper hash mismatch")
        expected["prepare_workers.py"] = installer
    else:
        expected["prepare_workers.py"] = read_file(Path(__file__).absolute())[0]
    require(names == set(expected), "package inventory mismatch")
    for name, raw in expected.items():
        actual, info = read_file(package / name)
        require(actual == raw and info.st_uid == owner.st_uid and stat.S_IMODE(info.st_mode) == 0o600,
                "package bytes or permissions mismatch")
    return expected


def command(argv):
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        raise WorkerError("host command failed") from None


def check_worker_activity(allowed=()):
    for pattern in ("parth-c4d-worker@*.service", "psy-core-worker*.service"):
        units = command(["systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager", pattern])
        for line in units.splitlines():
            fields = line.split()
            require(len(fields) >= 4 and (fields[0] in allowed
                    or fields[2:4] in (["inactive", "dead"], ["failed", "failed"])),
                    "worker is active or transitioning")
    jobs = command(["systemctl", "list-jobs", "--no-legend", "--no-pager"])
    require(not any(len(parts) > 1 and parts[1].startswith(("psy-core-worker", "parth-c4d-worker@"))
                    for parts in map(str.split, jobs.splitlines())), "worker has queued systemd job")


def check_host():
    require(os.geteuid() == 0, "sudo required for host credential verification")
    require(command(["hostname", "-s"]).strip() == "test-c4d", "wrong worker host")
    require(command(["uname", "-m"]).strip() == "x86_64", "worker architecture mismatch")
    check_worker_activity()
    account = pwd.getpwnam("parth")
    require(account.pw_uid != 0 and account.pw_gid != 0, "non-root parth account required")
    return account.pw_uid, account.pw_gid


def read_credentials(gid):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    keys = {}
    for role, path in SOURCES.items():
        raw, info = read_file(path)
        require(info.st_uid == ROOT_UID and info.st_gid == gid
                and stat.S_IMODE(info.st_mode) in (0o600, 0o640), "unsafe source credential permissions")
        key = decode(raw).get("private_key")
        require(isinstance(key, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", key), "invalid secp credential")
        public = ec.derive_private_key(int(key.removeprefix("0x"), 16), ec.SECP256K1()).public_key()
        encoded = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()
        require(encoded == PUBLIC_KEYS[role], "source identity is not the approved worker")
        keys[role] = key
    return keys


def install_paths(files, keys, user):
    uid, gid = user
    targets = {
        RELEASE / "psy_worker_cli": (files["psy_worker_cli"], 0o755, ROOT_UID, ROOT_GID),
        CONFIG / "network.json": (files["network.json"], 0o640, ROOT_UID, gid),
        CONFIG / "build.json": (files["build.json"], 0o640, ROOT_UID, gid),
        CONFIG / "attestation.json": (files["attestation.json"], 0o640, ROOT_UID, gid),
        CONFIG / "topology.json": (files["topology.json"], 0o640, ROOT_UID, gid),
    }
    directories = {RELEASE: (0o755, ROOT_UID, ROOT_GID), CONFIG: (0o750, ROOT_UID, gid),
                   STATE: (0o750, ROOT_UID, gid), UNITS: (0o755, ROOT_UID, ROOT_GID)}
    for role in THREADS:
        config = decode(files[role + ".json"])
        config["private_key"] = keys[role]
        targets[CONFIG / (role + ".json")] = (encode(config), 0o640, ROOT_UID, gid)
        directories[STATE / role] = (0o700, uid, gid)
        targets[UNITS / unit_name(role)] = (files[unit_name(role)], 0o644, ROOT_UID, ROOT_GID)
    targets[UNITS / "psy-core-worker-r3.slice"] = (files["psy-core-worker-r3.slice"], 0o644, ROOT_UID, ROOT_GID)
    for path in list(directories):
        for parent in path.parents:
            if parent != Path("/"):
                directories.setdefault(parent, (0o755, ROOT_UID, ROOT_GID))
    return targets, directories


def check_destinations(targets, directories):
    for root in (RELEASE, CONFIG, STATE):
        require(not os.path.lexists(root), "worker release/config/state already exists; inspection required")
    for name in [*(unit_name(role) for role in THREADS), "psy-core-worker-r3.slice",
                 "psy-core-worker-r3-realm-.service", "psy-core-worker-r3-.service",
                 "psy-core-worker-.service", "psy-core-.service", "psy-.service", "service"]:
        for root in UNIT_SEARCH:
            require(not os.path.lexists(root / name) and not os.path.lexists(root / (name + ".d")),
                    "existing worker unit or override")
    for path in [*directories, *(p.parent for p in targets)]:
        try:
            fd = directory(path)
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(fd)
            require(info.st_uid == ROOT_UID and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                    "unsafe destination ancestor")
        finally:
            os.close(fd)


def create_directory(path, mode, uid, gid):
    parent = directory(path.parent)
    try:
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
        except FileExistsError:
            fd = directory(path)
            try:
                info = os.fstat(fd)
                require(info.st_uid == ROOT_UID and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                        "unsafe destination ancestor")
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


def install_workers(package, check_only=True):
    files = read_package(package)
    user = check_host()
    keys = read_credentials(user[1])
    targets, directories = install_paths(files, keys, user)
    check_destinations(targets, directories)
    if not check_only:
        check_host()
        check_destinations(targets, directories)
        for path, attributes in sorted(directories.items(), key=lambda item: len(item[0].parts)):
            create_directory(path, *attributes)
        for path, attributes in targets.items():
            write_new(path, *attributes)
        command(["systemctl", "daemon-reload"])
    return {"mode": "checked" if check_only else "installed", "services": 3,
            "approved_identities": True, "reward_users": [0, 0, 1048576], "started": False, "enabled": False}


def unit_state(name):
    raw = command(["systemctl", "show", "--no-pager",
                   "--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload",
                   name])
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def verify_worker_process(name):
    pid = None
    for attempt in range(20):
        state = unit_state(name)
        require(state["ActiveState"] == "active" and state["SubState"] == "running"
                and state["UnitFileState"] == "enabled", "worker is not running/enabled")
        current = int(state["MainPID"])
        require(current > 0 and (pid is None or current == pid), "worker PID changed or disappeared")
        pid = current
        with open(f"/proc/{pid}/exe", "rb") as stream:
            actual = os.fstat(stream.fileno())
            expected = os.stat(RELEASE / "psy_worker_cli")
            if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
                require(hashlib.file_digest(stream, "sha256").hexdigest() == WORKER_SHA256,
                        "running worker hash mismatch")
                require(unit_state(name)["MainPID"] == str(pid), "worker PID changed during verification")
                return pid
            # Type=simple may report the systemd executor before execve completes.
            executors = set()
            for path in ("/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-executor"):
                try:
                    executor = os.stat(path)
                except FileNotFoundError:
                    continue
                executors.add((executor.st_dev, executor.st_ino))
            require((actual.st_dev, actual.st_ino) in executors,
                    "wrong running worker executable")
        time.sleep(0.25)
    raise WorkerError("worker exec did not complete within startup grace")


def activate_workers(package):
    require(os.geteuid() == 0, "sudo required for worker activation")
    require(command(["hostname", "-s"]).strip() == "test-c4d", "wrong worker host")
    require(command(["uname", "-m"]).strip() == "x86_64", "worker architecture mismatch")
    files = read_package(package, activation=True)
    account = pwd.getpwnam("parth")
    require(account.pw_uid != 0 and account.pw_gid != 0, "non-root parth account required")
    keys = read_credentials(account.pw_gid)
    targets, _ = install_paths(files, keys, (account.pw_uid, account.pw_gid))
    for path, (expected, mode, uid, gid) in targets.items():
        actual, info = read_file(path)
        require(actual == expected and stat.S_IMODE(info.st_mode) == mode
                and (info.st_uid, info.st_gid) == (uid, gid), "installed worker files differ")
    names = [unit_name(role) for role in THREADS]
    for role in THREADS:
        old = unit_state("psy-core-worker-r2-" + role + ".service")
        require(old["ActiveState"] == "inactive" and old["SubState"] == "dead"
                and old["MainPID"] == "0" and old["UnitFileState"] == "disabled",
                "old r2 worker must be inactive/PID0/disabled")
    for name in [*names, "psy-core-worker-r3.slice"]:
        state = unit_state(name)
        require(state["LoadState"] == "loaded" and state["FragmentPath"] == str(UNITS / name)
                and not state["DropInPaths"] and state["NeedDaemonReload"] == "no",
                "effective worker unit differs or needs reload")
    check_worker_activity(allowed=names)
    command(["systemctl", "enable", "--now", *names])
    pids = {name: verify_worker_process(name) for name in names}
    return {"mode": "activated", "services": 3, "enabled": True, "started": True,
            "worker_sha256": WORKER_SHA256, "pids": pids}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="action", required=True)
    prepare = commands.add_parser("package")
    prepare.add_argument("--release-dir", type=Path, required=True)
    prepare.add_argument("--network-config", type=Path, required=True)
    prepare.add_argument("--build-attestation", type=Path, required=True)
    prepare.add_argument("--topology", type=Path, default=HERE / "topology.json")
    prepare.add_argument("--output", type=Path, required=True)
    for name in ("check-host", "install", "activate"):
        host = commands.add_parser(name)
        host.add_argument("--package", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "package":
            report = prepare_package(args.release_dir, args.network_config, args.topology, args.output,
                                     args.build_attestation)
        elif args.action == "activate":
            report = activate_workers(args.package)
        else:
            report = install_workers(args.package, args.action == "check-host")
    except WorkerError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, ImportError):
        print('{"error":"worker preparation failed; input, identity or host safety gate rejected; no secret values logged"}', file=sys.stderr)
        return 1
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
