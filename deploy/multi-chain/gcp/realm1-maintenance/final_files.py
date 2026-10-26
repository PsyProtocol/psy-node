#!/usr/bin/env python3
"""Fenced Realm1 file transfer. No service start/stop and no data deletion."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shlex
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("presync", HERE / "presync.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
MIGRATE = Path("/usr/local/lib/parth-realm-migration/migrate.py")
SOURCE_HELPER = "2fa4d51e076cbdc2efeeca46c3a4bc59abf10d9ff3fed25dd9d3923eca52a673"
AUDIT = Path("/var/lib/parth/realm1-final-files-20261013")


def source_fenced():
    p.host(p.SOURCE)
    if p.sha(MIGRATE) != SOURCE_HELPER:
        raise RuntimeError("Source lifecycle helper changed")
    p.run("python3", "-I", str(MIGRATE), "source-fenced", "1")
    props = dict(line.split("=", 1) for line in p.run(
        "systemctl", "show", p.UNIT, "-p", "ActiveState", "-p", "MainPID",
        "-p", "UnitFileState", "-p", "ControlGroup").splitlines())
    if any(props[k] != v for k, v in
           {"ActiveState": "inactive", "MainPID": "0", "UnitFileState": "disabled"}.items()):
        raise RuntimeError("Source is not inactive and disabled")
    group = props.get("ControlGroup")
    if group:
        root = Path("/sys/fs/cgroup") / group.lstrip("/")
        if root.exists() and any(f.read_text().strip() for f in root.rglob("cgroup.procs")):
            raise RuntimeError("Source cgroup still contains processes")


def inventory(root, check_owner=False):
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Unexpected data root")
    owner = pwd.getpwnam("parth") if check_owner else None
    digest = hashlib.sha256()
    files = directories = total = 0
    def fail_walk(error):
        raise error

    for current, dirs, names in os.walk(root, followlinks=False, onerror=fail_walk):
        dirs.sort()
        for name in sorted(dirs + names):
            path = Path(current) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                record = [relative, "directory"]
                directories += 1
                required = 0o750
            elif stat.S_ISREG(info.st_mode):
                record = [relative, "file", info.st_size, p.sha(path)]
                files += 1
                total += info.st_size
                required = 0o640
                after = path.stat()
                if (info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                    raise RuntimeError("Data changed while hashing")
            else:
                raise RuntimeError("Symlink or special file in checkpoint directory")
            if owner and (info.st_uid != owner.pw_uid or info.st_gid != owner.pw_gid
                          or stat.S_IMODE(info.st_mode) != required):
                raise RuntimeError("Target checkpoint permissions differ")
            digest.update(json.dumps(record, separators=(",", ":")).encode() + b"\n")
    return dict(sha256=digest.hexdigest(), files=files, directories=directories, bytes=total)


def ensure_audit():
    AUDIT.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = AUDIT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError("Unsafe audit directory")


def save(kind, record):
    ensure_audit()
    path = AUDIT / f"{kind}-{time.time_ns()}.json"
    p.write_new(path, json.dumps(record, indent=2))
    print(json.dumps({"audit": str(path), **record}), flush=True)


def copy():
    p.target_check()
    ensure_audit()
    with (p.STATE / "sync.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        p.target_check()
        backup = AUDIT / f"overwritten-target-{time.time_ns()}"
        backup.mkdir(mode=0o700)
        transport = shlex.join(["ssh", "-i", str(p.KEY), "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={p.STATE}/known_hosts", "-o", "ConnectTimeout=10"])
        command = ["rsync", "-rtp", "--checksum", "--stats", "--timeout=120",
            "--backup", f"--backup-dir={backup}", "--chown=parth:parth", "--chmod=D750,F640",
            "-e", transport, f"root@{p.SOURCE}:./", str(p.DATA) + "/"]
        started = time.time()
        result = subprocess.run(command, capture_output=True, text=True, timeout=3600)
        p.write_new(AUDIT / f"rsync-{time.time_ns()}.json", json.dumps(dict(
            started=started, finished=time.time(), returncode=result.returncode,
            stdout=result.stdout, stderr=result.stderr, backup=str(backup))))
        if result.returncode != 0:
            raise RuntimeError("Final rsync must return exactly zero; target remains fenced")
        p.target_check()
        save("copy", dict(rsync_exit=0, backup=str(backup), seconds=round(time.time()-started, 2),
                          safe_to_start=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["source-inventory", "target-inventory", "copy", "source-fenced"])
    args = parser.parse_args()
    if args.action == "copy":
        copy()
    elif args.action == "source-fenced":
        source_fenced()
        print("FENCED")
    elif args.action == "source-inventory":
        source_fenced()
        p.run("sync", timeout=120)
        data = inventory(p.DATA)
        if data["files"] < 580000 or data["bytes"] < 1000000000:
            raise RuntimeError("Source file inventory unexpectedly small")
        source_fenced()
        save("source", dict(inventory=data, sampled_at=time.time(), source_fenced=True))
    else:
        p.target_check()
        with (p.STATE / "sync.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            p.run("sync", timeout=120)
            data = inventory(p.DATA, check_owner=True)
            if data["files"] < 580000 or data["bytes"] < 1000000000:
                raise RuntimeError("Target file inventory unexpectedly small")
            p.target_check()
            save("target", dict(inventory=data, sampled_at=time.time(), target_fenced=True))


if __name__ == "__main__":
    main()
