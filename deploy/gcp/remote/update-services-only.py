#!/usr/bin/env python3
"""Guarded Services-only binary rollout. Preserve all data and other processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import urllib.request

UNIT = "parth-psy-services.service"
CURRENT = Path("/opt/parth/psy-services/current")
ENV = Path("/etc/parth/psy-services.env")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed; inspect on host (output protected)")
    return result.stdout.strip()


def state(unit):
    return dict(line.split("=", 1) for line in run([
        "systemctl", "show", unit, "-p", "MainPID", "-p", "ActiveState"
    ]).splitlines())


def other_units():
    units = json.loads(run(["systemctl", "list-units", "--all", "--no-pager",
                           "--output=json", "parth-*.service"]))
    return {item["unit"]: state(item["unit"]) for item in units if item["unit"] != UNIT}


def atomic(path, content, mode, uid=0, gid=0):
    temp = path.with_name(path.name + ".services-next")
    with temp.open("xb") as stream:
        stream.write(content)
    temp.chmod(mode)
    os.chown(temp, uid, gid)
    temp.replace(path)


def link(home):
    temp = CURRENT.with_name("current.services-next")
    temp.symlink_to(home)
    temp.replace(CURRENT)


def ready(expected_sha, require_cache):
    endpoint = "health/ready" if require_cache else "health"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            process = state(UNIT)
            exe = Path("/proc") / process["MainPID"] / "exe"
            if process["ActiveState"] == "active" and digest(exe) == expected_sha:
                with urllib.request.urlopen(f"http://127.0.0.1:3000/{endpoint}", timeout=4) as response:
                    body = json.load(response)
                    if response.status == 200 and (not require_cache or body["status"] == "ready"):
                        return process
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(2)
    raise RuntimeError("Services executable/readiness verification timed out")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args()
    spec = json.loads(args.manifest.read_text())
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != "cp-ce":
        raise RuntimeError("Run as root on cp-ce only")
    for key in ("base_commit", "commit"):
        if not re.fullmatch(r"[0-9a-f]{40}", spec[key]):
            raise RuntimeError("Expected full commit")
    for key in ("base_sha256", "sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", spec[key]):
            raise RuntimeError("Expected SHA256")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", spec["release_id"]):
        raise RuntimeError("Invalid release ID")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", spec["branch"]):
        raise RuntimeError("Invalid source branch")
    old = Path(spec["base_release"])
    root = Path("/opt/parth/psy-services/releases")
    if old.parent != root or old.resolve() != old or CURRENT.resolve() != old:
        raise RuntimeError("Unexpected current release")
    new = root / spec["release_id"]
    audit = Path("/var/lib/parth-services-maintenance") / spec["release_id"]
    if new.exists() or audit.exists():
        raise RuntimeError("Previous attempt exists; inspect before retry")
    baseline = state(UNIT)
    if baseline["ActiveState"] != "active" or digest(Path("/proc") / baseline["MainPID"] / "exe") != spec["base_sha256"]:
        raise RuntimeError("Running baseline mismatch")
    if digest(old / "target/release/psy-services") != spec["base_sha256"]:
        raise RuntimeError("Rollback binary mismatch")
    if digest(args.binary) != spec["sha256"]:
        raise RuntimeError("Candidate binary mismatch")
    manifest = dict(line.split("=", 1) for line in (old / "BUILD-MANIFEST.env").read_text().splitlines()
                    if line and not line.startswith("#") and "=" in line)
    if manifest.get("PSY_SERVICES_COMMIT") != spec["base_commit"]:
        raise RuntimeError("Baseline source manifest mismatch")
    env_bytes = ENV.read_bytes()
    old_line = f"PSY_SERVICES_HOME={old}\n".encode()
    if env_bytes.count(old_line) != 1:
        raise RuntimeError("Unexpected Services home configuration")
    env_stat = ENV.stat()
    protected = {str(p): digest(p) for p in Path("/etc/parth").glob("*.env") if p != ENV}
    node_home = str(Path("/opt/parth/current").resolve())
    units_before = other_units()
    if not args.activate:
        print(json.dumps({"preflight": "passed", "base": str(old), "candidate": str(new),
                          "other_services": len(units_before), "activated": False}))
        return
    os.umask(0o077)
    audit.mkdir(parents=True)
    (audit / "services.env.before").write_bytes(env_bytes)
    (audit / "manifest.json").write_text(json.dumps(spec, indent=2))
    (audit / "before.json").write_text(json.dumps({"units": units_before, "protected": protected,
        "node_home": node_home, "service": baseline, "time_unix": time.time()}, indent=2))
    shutil.copytree(old, new, symlinks=True)
    for source in [old, *old.rglob("*")]:
        original = source.lstat()
        os.chown(new / source.relative_to(old), original.st_uid, original.st_gid, follow_symlinks=False)
    (new / ".bundle.sha256").unlink(missing_ok=True)
    binary = new / "target/release/psy-services"
    original = binary.stat()
    atomic(binary, args.binary.read_bytes(), 0o755, original.st_uid, original.st_gid)
    if digest(binary) != spec["sha256"]:
        raise RuntimeError("Installed binary mismatch")
    manifest.update(PSY_SERVICES_COMMIT=spec["commit"], PSY_SERVICES_BRANCH=spec["branch"],
                    PSY_SERVICES_BINARY_SHA256=spec["sha256"],
                    PSY_SERVICES_PARENT_COMMIT=spec["base_commit"], RELEASE_KIND="services-only-bb8-fix")
    manifest.pop("SOURCE_COMMIT_TIMESTAMP", None)
    # PSY_INDEXER_COMMIT and every other artifact/config are deliberately retained.
    atomic(new / "BUILD-MANIFEST.env", "".join(f"{k}={v}\n" for k, v in manifest.items()).encode(), 0o644)
    user = run(["systemctl", "show", UNIT, "-p", "User", "--value"])
    run(["runuser", "-u", user, "--", str(binary), "--help"])
    for source in old.rglob("*"):
        relative = source.relative_to(old)
        if relative.as_posix() in ("target/release/psy-services", "BUILD-MANIFEST.env", ".bundle.sha256"):
            continue
        if source.is_file() and digest(source) != digest(new / relative):
            raise RuntimeError("Unrelated release file changed")
    if ENV.read_bytes() != env_bytes or other_units() != units_before or state(UNIT) != baseline:
        raise RuntimeError("Concurrent configuration/process change before activation")
    new_env = env_bytes.replace(old_line, f"PSY_SERVICES_HOME={new}\n".encode())
    changed = False
    try:
        atomic(ENV, new_env, env_stat.st_mode & 0o777, env_stat.st_uid, env_stat.st_gid)
        changed = True
        link(new)
        (audit / "activation-time.txt").write_text(str(time.time()))
        run(["systemctl", "restart", UNIT])
        process = ready(spec["sha256"], True)
        if any(digest(Path(p)) != value for p, value in protected.items()):
            raise RuntimeError("Unrelated environment changed")
        if other_units() != units_before or str(Path("/opt/parth/current").resolve()) != node_home:
            raise RuntimeError("Other processes or node release changed")
        result = {"commit": spec["commit"], "binary_sha256": spec["sha256"], "release": str(new),
                  "service": process, "other_units_unchanged": True, "rollback_release": str(old),
                  "time_unix": time.time(), "readiness": "ready"}
        (audit / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
    except Exception:
        rollback = "not_needed"
        if changed:
            try:
                if ENV.read_bytes() != new_env or CURRENT.resolve() not in (new, old):
                    raise RuntimeError("Concurrent change; manual recovery required")
                atomic(ENV, env_bytes, env_stat.st_mode & 0o777, env_stat.st_uid, env_stat.st_gid)
                link(old)
                run(["systemctl", "restart", UNIT])
                ready(spec["base_sha256"], False)
                rollback = "restored_previous_binary"
            except Exception:
                rollback = "blocked_or_failed_manual_inspection_required"
        (audit / "failure.json").write_text(json.dumps({"rollback": rollback, "time_unix": time.time()}))
        raise RuntimeError(f"Rollout failed; rollback={rollback}; inspect protected evidence") from None


if __name__ == "__main__":
    main()
