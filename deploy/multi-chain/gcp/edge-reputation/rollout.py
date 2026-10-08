#!/usr/bin/env python3
"""Guarded, one-Edge-at-a-time update. Never restart a Processor or reset state."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import time
import urllib.parse
import urllib.request

UNITS = {
    "realm-0": ("parth-realm-edge@0.service", "realm-edge", 1338),
    "realm-1": ("parth-realm-edge@1.service", "realm-edge", 1339),
    "coordinator": ("parth-coordinator-edge@0.service", "coordinator-edge", 1337),
}
OLD_HASHES = {
    "realm-0": "9d29dafa9e998b400e74ad966b953121c5f9e6b8b592adef183f92d3f93ffd8a",
    "realm-1": "9d29dafa9e998b400e74ad966b953121c5f9e6b8b592adef183f92d3f93ffd8a",
    "coordinator": "bda82589c26bd914ead5bd77b8e6de136e0703797d0135fcddf3c2ff8dd8bb03",
}
GENESIS = "569e58c901cdf7bd9edfc25bab70c4b0aafe0f5d2ec782781290d963ae63b710"
DROP_NAME = "99-worker-reputation-20261008.conf"
PACKAGE = Path(__file__).resolve().parent
PATH_ANCHORS = (Path("/opt"), Path("/etc"), Path("/run"))
OWNER_UID = 0


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=90).strip()


def sha(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def props(unit):
    return dict(line.split("=", 1) for line in run(
        "systemctl", "show", unit, "-p", "MainPID", "-p", "ActiveState", "-p", "NRestarts",
        "-p", "FragmentPath", "-p", "DropInPaths",
        "-p", "EnvironmentFiles",
    ).splitlines())


def executable(unit):
    p = props(unit)
    require(p["ActiveState"] == "active" and p["MainPID"] != "0", f"{unit} not active")
    proc = Path("/proc") / p["MainPID"] / "exe"
    return {"path": str(proc.resolve()), "sha256": sha(proc), "pid": p["MainPID"]}


def runtime(unit):
    pid = props(unit)["MainPID"]
    args = (Path("/proc") / pid / "cmdline").read_bytes().decode().split("\0")
    env = dict(v.split("=", 1) for v in (Path("/proc") / pid / "environ").read_bytes().decode().split("\0") if "=" in v)
    url = args[args.index("--redis-url") + 1]
    namespace = args[args.index("--db-namespace") + 1]
    require(int(env.get("NATS_WORKER_ACK_WAIT_MS", "30000")) == 30_000, "unexpected Edge ACK wait")
    return url, namespace


def checkpoint(name):
    req = urllib.request.Request(f"http://127.0.0.1:{UNITS[name][2]}/", headers={"Content-Type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "psy_get_latest_checkpoint_id", "params": []}).encode())
    with urllib.request.urlopen(req, timeout=5) as response:
        data = json.load(response)
    require(type(data.get("result")) is int and data["result"] > 0 and "error" not in data, "checkpoint RPC failed")
    return data["result"]


def other_pids():
    lines = run("systemctl", "list-units", "--all", "--type=service", "--plain", "--no-legend", "--no-pager").splitlines()
    edges = {v[0] for v in UNITS.values()}
    units = [line.split()[0] for line in lines if line.split() and line.split()[0].startswith("parth-")]
    return {u: props(u)["MainPID"] for u in units if u not in edges}


def disk_unit_files():
    # Inspect unloaded overrides too; systemctl's DropInPaths is only the loaded view.
    directories = [Path(p) for p in run("systemctl", "show", "-p", "UnitPath", "--value").split()]
    require(bool(directories) and all(p.is_absolute() for p in directories), "invalid systemd unit search path")
    files = set()
    for name, (unit, _, _) in UNITS.items():
        stem, suffix = unit.rsplit(".", 1)
        names = {unit, stem.split("@", 1)[0] + "@." + suffix}
        drop_dirs = {"service.d", *(n + ".d" for n in names)}
        drop_dirs.update(stem[:i + 1] + "." + suffix + ".d" for i, char in enumerate(stem) if char == "-")
        for directory in directories:
            files.update(directory / n for n in names if (directory / n).exists() or (directory / n).is_symlink())
            for drop_dir in drop_dirs:
                files.update(p for p in (directory / drop_dir).glob("*.conf") if p != drop_path(name))
    return {"search_path": [str(p) for p in directories], "files": {
        str(p): {"sha256": sha(p), "symlink": os.readlink(p) if p.is_symlink() else None}
        for p in sorted(files)}}


def protected():
    home = Path("/opt/parth/current")
    files = [home / "genesis.json", home / "deploy/bin/run-parth-service"]
    files += [p for p in Path("/etc/parth").rglob("*") if p.is_file()]
    drops = {}
    for name, (unit, _, _) in UNITS.items():
        p = props(unit)
        paths = [Path(p["FragmentPath"])] + [Path(s) for s in p["DropInPaths"].split() if Path(s) != drop_path(name)]
        paths += [Path(s) for s, _ in re.findall(r"(\S+) \(ignore_errors=(yes|no)\)", p["EnvironmentFiles"]) if Path(s).is_file()]
        files += paths
        drops[name] = sorted(str(p) for p in paths)
    return {"current": str(home.resolve()), "files": {str(p): sha(p) for p in sorted(set(files))},
        "unit_files": drops, "disk_units": disk_unit_files()}


def snapshot():
    require(sha("/opt/parth/current/genesis.json") == GENESIS, "Genesis differs")
    require(run("timedatectl", "show", "-p", "NTPSynchronized", "--value") == "yes", "host clock is not synchronized")
    urls = [runtime(v[0])[0] for v in UNITS.values()]
    require(len(set(urls)) == 1, "all Edges must use the same Redis database")
    return {"protected": protected(), "other_pids": other_pids(),
        "edges": {k: executable(v[0]) for k, v in UNITS.items()},
        "checkpoints": {k: checkpoint(k) for k in UNITS}, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


class RedisReadOnly:
    def __init__(self, url):
        u = urllib.parse.urlsplit(url)
        require(u.scheme == "redis", "unsupported Redis transport for snapshot")
        self.sock = socket.create_connection((u.hostname, u.port or 6379), timeout=10)
        self.stream = self.sock.makefile("rb")
        if u.password is not None:
            self.command("AUTH", *([urllib.parse.unquote(u.username)] if u.username else []), urllib.parse.unquote(u.password))
        if u.path not in ("", "/", "/0"):
            self.command("SELECT", int(u.path[1:]))

    def read(self):
        line = self.stream.readline()
        require(line.endswith(b"\r\n"), "truncated Redis response")
        kind, body = line[:1], line[1:-2]
        if kind == b"-":
            raise RuntimeError("Redis snapshot command failed")
        if kind == b"+":
            return body
        if kind == b":":
            return int(body)
        if kind == b"$":
            n = int(body)
            if n < 0:
                return None
            data = self.stream.read(n)
            require(len(data) == n and self.stream.read(2) == b"\r\n", "truncated Redis bulk reply")
            return data
        if kind == b"*":
            return [self.read() for _ in range(int(body))]
        raise RuntimeError("unsupported Redis response")

    def command(self, *parts):
        require(parts[0] in ("AUTH", "SELECT", "SCAN", "HSCAN"), "non-read-only Redis operation refused")
        items = [p if isinstance(p, bytes) else str(p).encode() for p in parts]
        self.sock.sendall(b"*" + str(len(items)).encode() + b"\r\n" + b"".join(
            b"$" + str(len(p)).encode() + b"\r\n" + p + b"\r\n" for p in items))
        return self.read()

    def close(self):
        self.stream.close()
        self.sock.close()


def reputation_snapshot(unit):
    url, namespace = runtime(unit)
    client = RedisReadOnly(url)
    deadline = time.monotonic() + 120
    result = {}
    try:
        cursor = b"0"
        while True:
            require(time.monotonic() < deadline, "reputation snapshot exceeded deadline")
            cursor, keys = client.command("SCAN", cursor, "MATCH", f"TKVSV1-{namespace}-*", "COUNT", 1000)
            for key in keys:
                hcursor = b"0"
                rows = {}
                while True:
                    require(time.monotonic() < deadline, "reputation snapshot exceeded deadline")
                    hcursor, pairs = client.command("HSCAN", key, hcursor, "MATCH", b"??????WR*", "COUNT", 1000)
                    for field, value in zip(pairs[0::2], pairs[1::2]):
                        if len(field) == 41 and field[6:8] == b"WR":
                            rows[field.hex()] = value.hex()
                    if hcursor == b"0":
                        break
                result[key.decode()] = rows
            if cursor == b"0":
                return result
    finally:
        client.close()


def trusted_path(path, directory=False, missing_ok=False):
    require(path.is_absolute() and ".." not in path.parts, "unsafe path")
    anchors = [p for p in PATH_ANCHORS if path == p or p in path.parents]
    require(bool(anchors), f"path outside trusted roots: {path}")
    anchor = max(anchors, key=lambda p: len(p.parts))
    chain = [anchor]
    for part in path.relative_to(anchor).parts:
        chain.append(chain[-1] / part)
    for entry in chain:
        try:
            info = entry.lstat()
        except FileNotFoundError:
            require(missing_ok, f"missing trusted path: {entry}")
            return False
        is_dir = entry != path or directory
        require(stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode),
            f"symlink or unexpected file type: {entry}")
        require(info.st_uid == OWNER_UID and not info.st_mode & 0o022,
            f"untrusted owner or writable path: {entry}")
        require(is_dir or info.st_nlink == 1, f"hard-linked file refused: {entry}")
    return True


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def secure_dir(path, mode=0o755):
    if trusted_path(path, directory=True, missing_ok=True):
        return
    secure_dir(path.parent, mode)
    path.mkdir(mode=mode)
    path.chmod(mode)
    sync_dir(path.parent)


def copy_exclusive(source, path, mode):
    trusted_path(path, missing_ok=True)
    with open(source, "rb") as src, open(path, "xb") as dst:
        shutil.copyfileobj(src, dst)
        dst.flush()
        os.fchmod(dst.fileno(), mode)
        os.fsync(dst.fileno())
    sync_dir(path.parent)


def atomic(path, data, mode=0o600):
    secure_dir(path.parent)
    trusted_path(path, missing_ok=True)
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    with open(tmp, "xb") as f:
        os.fchmod(f.fileno(), mode)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    sync_dir(path.parent)


def drop_path(name):
    return Path("/etc/systemd/system") / (UNITS[name][0] + ".d") / DROP_NAME


def drop_bytes(name, root):
    return ("[Service]\nExecStart=\nExecStart=/usr/bin/env PARTH_TARGET_DIR=" + str(root / "target") +
        " /usr/bin/bash -lc 'cd \"$PARTH_HOME\" && exec bash deploy/bin/run-parth-service " + UNITS[name][1] + "'\n").encode()


def ready(name, expected):
    deadline = time.monotonic() + 120
    stable = 0
    last = None
    while time.monotonic() < deadline:
        try:
            exe = executable(UNITS[name][0])
            require(exe["sha256"] == expected, "running executable hash mismatch")
            cp = checkpoint(name)
            stable = stable + 1 if exe["pid"] == last else 1
            last = exe["pid"]
            if stable >= 3:
                return {"pid": last, "sha256": expected, "checkpoint": cp}
        except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
            stable = 0
        time.sleep(2)
    raise RuntimeError(f"{name} failed readiness")


def package():
    m = json.loads((PACKAGE / "manifest.json").read_text())
    require(len(m["source_commit"]) == 40 and all(c in "0123456789abcdef" for c in m["source_commit"]), "invalid source commit")
    require(sha(PACKAGE / "psy_node_cli") == m["binary_sha256"], "package binary hash mismatch")
    require(sha(__file__) == m["installer_sha256"], "installer hash mismatch")
    root = Path("/opt/parth-edge-reputation") / ("20261008-" + m["source_commit"][:12])
    return m, root


def preflight(m, root):
    trusted_path(root, directory=True, missing_ok=True)
    require(protected() == m["baseline"]["protected"], "protected config changed since capture")
    for name, (unit, _, _) in UNITS.items():
        require(executable(unit)["sha256"] in (OLD_HASHES[name], m["binary_sha256"]), f"unknown binary for {name}")
        drop = drop_path(name)
        if trusted_path(drop, missing_ok=True):
            require(drop.read_bytes() == drop_bytes(name, root), f"foreign override for {name}")
    require(other_pids() == m["baseline"]["other_pids"], "unrelated service PID changed since capture")
    require("not found" not in run("ldd", str(PACKAGE / "psy_node_cli")), "missing library")
    snapshot()


def recovery_owner(name, m, root):
    baseline = json.dumps(m["baseline"], sort_keys=True, separators=(",", ":")).encode()
    return {"schema": 1, "unit": UNITS[name][0], "root": str(root),
        "binary_sha256": m["binary_sha256"], "installer_sha256": m["installer_sha256"],
        "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
        "drop_sha256": hashlib.sha256(drop_bytes(name, root)).hexdigest()}


def recovery_path(name, root):
    return root / "rollback" / name / "recovery.json"


def rollback_guard(name, m):
    # Deliberately avoid snapshot(): the target Edge may be stopped or crashing.
    require(protected() == m["baseline"]["protected"], "rollback refused: protected config changed")
    require(other_pids() == m["baseline"]["other_pids"], "rollback refused: unrelated service PID changed")
    old = m["baseline"]["edges"][name]
    require(sha(old["path"]) == OLD_HASHES[name], "original rollback binary changed or missing")


def rollback(name, m, root):
    state_path = recovery_path(name, root)
    trusted_path(state_path)
    state = json.loads(state_path.read_text())
    require(state.get("owner") == recovery_owner(name, m, root), "rollback refused: recovery ownership differs")
    require(state.get("phase") in ("owned", "rollback_pending", "rolled_back"), "invalid recovery phase")
    drop = drop_path(name)
    present = trusted_path(drop, missing_ok=True)
    if present:
        require(state["phase"] != "rolled_back" and drop.read_bytes() == drop_bytes(name, root),
            "rollback refused: override changed")
    else:
        require(state["phase"] in ("rollback_pending", "rolled_back"),
            "rollback refused: missing override without pending recovery")
    rollback_guard(name, m)
    if state["phase"] == "rolled_back":
        return ready(name, OLD_HASHES[name])
    # Persist intent before unlink so interruptions after removal remain recoverable.
    state["phase"] = "rollback_pending"
    atomic(state_path, json.dumps(state, indent=2).encode())
    if present:
        drop.unlink()
        sync_dir(drop.parent)
    run("systemctl", "daemon-reload")
    rollback_guard(name, m)
    run("systemctl", "restart", UNITS[name][0])
    result = ready(name, OLD_HASHES[name])
    rollback_guard(name, m)
    state["phase"] = "rolled_back"
    atomic(state_path, json.dumps(state, indent=2).encode())
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("capture", "check", "apply", "rollback"))
    parser.add_argument("--unit", choices=UNITS)
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    os.umask(0o077)
    lock_path = Path("/run/parth-edge-reputation-20261008.lock")
    trusted_path(lock_path, missing_ok=True)
    with open(lock_path, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "capture":
            state = snapshot()
            for name in UNITS:
                require(state["edges"][name]["sha256"] == OLD_HASHES[name], "unexpected baseline binary")
            print(json.dumps(state, indent=2))
            return
        m, root = package()
        if args.action == "rollback":
            require(args.unit is not None, "--unit required")
            print(json.dumps(rollback(args.unit, m, root)))
            return
        preflight(m, root)
        if args.action == "check":
            print(json.dumps({"preflight": "passed", "checkpoints": {k: checkpoint(k) for k in UNITS}}))
            return
        require(args.unit is not None, "--unit required")
        name = args.unit
        require(not trusted_path(drop_path(name), missing_ok=True), "already applied; inspect before retry")
        secure_dir(root)
        binary = root / "target/release/psy_node_cli"
        secure_dir(binary.parent)
        for directory in (root.parent, root, root / "target", binary.parent):
            require(directory.stat().st_mode & 0o555 == 0o555, f"release directory not traversable: {directory}")
        if trusted_path(binary, missing_ok=True):
            require(sha(binary) == m["binary_sha256"], "immutable release differs")
            require(binary.stat().st_mode & 0o555 == 0o555, "release binary is not executable/readable")
        else:
            copy_exclusive(PACKAGE / "psy_node_cli", binary, 0o755)
        require(sha(binary) == m["binary_sha256"], "installed binary hash mismatch")
        backup = root / "rollback" / name
        require(not trusted_path(backup, directory=True, missing_ok=True), "existing backup: inspect before retry")
        secure_dir(backup, mode=0o700)
        atomic(backup / "reputation.json", json.dumps(reputation_snapshot(UNITS[name][0]), indent=2).encode())
        atomic(backup / "before.json", json.dumps(snapshot(), indent=2).encode())
        copy_exclusive(m["baseline"]["edges"][name]["path"], backup / "psy_node_cli", 0o600)
        atomic(root / "manifest.json", json.dumps(m, indent=2).encode())
        require(sha(backup / "psy_node_cli") == OLD_HASHES[name], "rollback copy hash mismatch")
        preflight(m, root)
        atomic(recovery_path(name, root), json.dumps({"owner": recovery_owner(name, m, root),
            "phase": "owned"}, indent=2).encode())
        try:
            atomic(drop_path(name), drop_bytes(name, root), mode=0o644)
            run("systemctl", "daemon-reload")
            run("systemctl", "restart", UNITS[name][0])
            result = ready(name, m["binary_sha256"])
            require(protected() == m["baseline"]["protected"], "protected configuration changed")
            require(other_pids() == m["baseline"]["other_pids"], "unrelated service PID changed")
            atomic(backup / "result.json", json.dumps(result, indent=2).encode())
            print(json.dumps({"updated": name, **result}))
        except BaseException:
            try:
                rollback(name, m, root)
                print(json.dumps({"rolled_back": name}), flush=True)
            except BaseException:
                print(json.dumps({"rollback_failed": name, "operator_required": True}), flush=True)
            raise


if __name__ == "__main__":
    main()
