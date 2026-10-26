#!/usr/bin/env python3
"""Services cache hotfix only; preserve configuration, state and indexers."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

UNIT = "parth-psy-services.service"
BASE = Path("/opt/parth-services/31f7eb8dfbbb")
OLD_BIN = Path("/opt/parth-services/f4d6ee8a4f55/psy-services")
COMMIT = "a43632d6d899c49cbeca3786dba42b337489bb3e"
OLD = "9e8effe10057c2444df5618b8a2aa5a9b8a810b2f257213897059c1803b1631d"
NEW = "a6a5abfaa76068c9bf59d4bbc51e5e2553c6f746a0bda0ff51237fe9ddb88179"
RELEASE = Path("/opt/parth-services") / COMMIT[:12]
PREVIOUS_DROP = Path(f"/etc/systemd/system/{UNIT}.d/99-response-deadline-20261012.conf")
DROP = Path(f"/etc/systemd/system/{UNIT}.d/99-z-claimable-cache-20261014.conf")
STATE = Path("/var/lib/parth/services-claimable-cache-20261014")
HEALTH = "http://10.148.0.38:3000/health/ready"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=180).strip()


def sha(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prop(name):
    return run("systemctl", "show", UNIT, "-p", name, "--value")


def live():
    pid = prop("MainPID")
    require(pid != "0", "No running Services PID")
    exe = Path(f"/proc/{pid}/exe")
    result = {"pid": pid, "exe": str(exe.resolve()), "sha256": sha(exe)}
    require(prop("MainPID") == pid, "PID changed while inspecting")
    return result


def config_hash(pid):
    values = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    values = sorted(v for v in values if v.startswith((b"PSY_", b"DATABASE_", b"REDIS_", b"RUST_")))
    return hashlib.sha256(b"\0".join(values)).hexdigest()


def protected():
    files = [Path(prop("FragmentPath")), PREVIOUS_DROP, BASE / "service.env", BASE / "genesis_contracts.index.json"]
    files += [p for p in (BASE / "genesis_abi").rglob("*") if p.is_file()]
    return {str(p): sha(p) for p in files}


def unchanged(state, check_loaded=True):
    require(all(sha(p) == h for p, h in state["protected"].items()), "Protected files changed")
    require(prop("WorkingDirectory") == str(BASE), "Working directory changed")
    require(prop("MemoryHigh") == "5368709120" and prop("MemoryMax") == "6442450944", "Memory limits changed")
    require(prop("User") == "parth" and prop("Group") == "parth", "Service identity changed")
    require('--run-migrations=false' in prop("ExecStart"), "Migration policy changed")
    if check_loaded:
        expected = [str(PREVIOUS_DROP)] + ([str(DROP)] if DROP.exists() else [])
        require(prop("DropInPaths").split() == expected, "Unexpected drop-ins")


def ready(expected, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            current = live()
            require(current["sha256"] == expected, "Running hash mismatch")
            with urllib.request.urlopen(HEALTH, timeout=3) as response:
                body = json.load(response)
            require(body["status"] == "ready", "Services not ready")
            require(all(body["details"][key]["status"] == "healthy" for key in ("database", "cache")), "Dependency unhealthy")
            if expected == NEW:
                require(body["details"]["private_claimable_cache"]["enabled"], "New cache is not enabled")
            return current
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
            time.sleep(2)
    raise RuntimeError("Readiness deadline exceeded")


def save(state):
    temporary = STATE / "state.next"
    with temporary.open("w") as stream:
        json.dump(state, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(STATE / "state.json")


def audit_best_effort(state):
    try:
        save(state)
        return True
    except OSError:
        return False


def emit(value):
    # Lost SSH stdout must not interfere with local recovery.
    try:
        print(json.dumps(value), flush=True)
    except OSError:
        pass


def preflight(binary):
    current = live()
    require(current["sha256"] == OLD and current["exe"] == str(OLD_BIN), "Live baseline differs")
    require(not STATE.exists() and not RELEASE.exists() and not DROP.exists(), "Existing rollout; inspect before proceeding")
    require(prop("DropInPaths") == str(PREVIOUS_DROP), "Unexpected baseline overrides")
    require(sha(binary) == NEW and sha(OLD_BIN) == OLD, "Artifact mismatch")
    require(f"{BASE}/service.env" in prop("EnvironmentFiles"), "Unexpected environment file")
    require(shutil.disk_usage(BASE).free > 512 * 1024**2, "Insufficient disk headroom")
    require("not found" not in run("ldd", str(binary)), "Missing dynamic dependency")
    expected = f"ExecStart={OLD_BIN} --disable-auth --verbose --run-migrations=false --migrations-path {BASE}/migrations"
    require(expected in PREVIOUS_DROP.read_text(), "Previous invocation differs")
    state = {"old": current, "protected": protected(), "config_hash": config_hash(current["pid"]), "source_commit": COMMIT}
    unchanged(state)
    ready(OLD, 12)
    return state


def rollback(state):
    # The override may already have been removed by an interrupted rollback.
    unchanged(state, check_loaded=False)
    require(set(prop("DropInPaths").split()) <= {str(PREVIOUS_DROP), str(DROP)}, "Unexpected loaded overrides")
    require(sha(OLD_BIN) == OLD, "Rollback binary changed")
    if DROP.exists():
        require(sha(DROP) == state["drop_sha256"], "Rollback override changed")
    if prop("MainPID") != "0":
        require(live()["sha256"] in (OLD, NEW), "Unexpected executable")
    if DROP.exists():
        DROP.unlink()
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", UNIT)
    restored = ready(OLD)
    unchanged(state)
    require(config_hash(restored["pid"]) == state["config_hash"], "Rollback configuration differs")
    state.update(phase="rolled_back", restored=restored)
    audit_best_effort(state)
    emit({"phase": "rolled_back", **restored})


def activate(binary):
    state = preflight(binary)
    STATE.mkdir(mode=0o700)
    for index, path in enumerate(state["protected"]):
        shutil.copy2(path, STATE / f"protected-{index}")
    RELEASE.mkdir(mode=0o755)
    RELEASE.chmod(0o755)
    shutil.copyfile(binary, RELEASE / "psy-services")
    (RELEASE / "psy-services").chmod(0o755)
    require(sha(RELEASE / "psy-services") == NEW, "Installed artifact differs")
    (RELEASE / "manifest.json").write_text(json.dumps({"repository": "PsyProtocol/psy-services", "commit": COMMIT, "binary_sha256": NEW, "base_commit": "f4d6ee8a4f55a69586e4ed8d5a3f0a9bc4422ded", "config_home": str(BASE), "indexers_updated": False}, indent=2) + "\n")
    unchanged(state)
    require(live() == state["old"], "Baseline process changed")
    drop_text = f"[Service]\nExecStart=\nExecStart={RELEASE}/psy-services --disable-auth --verbose --run-migrations=false --migrations-path {BASE}/migrations\n"
    staged_drop = STATE / "candidate.conf"
    with staged_drop.open("x") as stream:
        stream.write(drop_text)
        stream.flush()
        os.fsync(stream.fileno())
    staged_drop.chmod(0o644)
    state.update(phase="prepared", drop_sha256=sha(staged_drop), activated_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    # Persist enough information for rollback BEFORE any active override exists.
    save(state)
    try:
        os.link(staged_drop, DROP)
        run("systemctl", "daemon-reload")
        unchanged(state)
        state["phase"] = "restarting"
        save(state)
        run("systemctl", "restart", UNIT)
        observed = ready(NEW)
        unchanged(state)
        require(config_hash(observed["pid"]) == state["config_hash"], "Process configuration changed")
        state.update(phase="ready", observed=observed)
        save(state)
        emit({"phase": "ready", **observed, "audit": str(STATE)})
    except Exception:
        state["phase"] = "activation_failed"
        audit_best_effort(state)
        try:
            rollback(state)
        except Exception:
            state["phase"] = "rollback_failed_requires_operator"
            audit_best_effort(state)
            raise RuntimeError("Rollback failed; inspect protected audit") from None
        raise RuntimeError("Activation failed; old Services restored") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "activate", "rollback"))
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "Root required")
    os.umask(0o077)
    with open("/run/psy-services-response-rollout.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "rollback":
            rollback(json.loads((STATE / "state.json").read_text()))
        else:
            require(args.binary is not None, "Binary required")
            if args.action == "preflight":
                state = preflight(args.binary)
                emit({"preflight": "pass", "old": state["old"], "candidate_sha256": NEW})
            else:
                activate(args.binary)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit({"status": "stopped", "error_type": type(error).__name__, "reason": str(error) if isinstance(error, RuntimeError) else "Inspect protected state"})
        raise SystemExit(1)
