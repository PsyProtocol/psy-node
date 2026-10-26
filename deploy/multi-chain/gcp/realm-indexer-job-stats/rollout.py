#!/usr/bin/env python3
"""Sequential Realm Indexer hotfix. Never rewind cursors or touch processors."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.request

OLD_HOME = Path("/opt/parth-indexers/7c1e1f616739")
OLD_HASH = "611f5975dd9291c6e8253491689f018b3935a4e70ec5fd6d8a7044fdddf8e770"
COORDINATOR = "http://10.148.0.25:1337"
ROOT = Path("/var/lib/parth/realm-indexer-job-stats-20261014")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def emit(value):
    try:
        print(json.dumps(value), flush=True)
    except OSError:
        pass


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=100).strip()


def sha(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prop(unit, name):
    return run("systemctl", "show", unit, "-p", name, "--value")


def live(unit):
    pid = prop(unit, "MainPID")
    require(pid != "0", "Missing running Indexer PID")
    executable = Path(f"/proc/{pid}/exe")
    result = {"pid": pid, "exe": str(executable.resolve()), "sha256": sha(executable)}
    require(prop(unit, "MainPID") == pid, "PID changed during check")
    return result


def env(unit):
    pid = prop(unit, "MainPID")
    return dict(v.split(b"=", 1) for v in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0") if b"=" in v)


def env_hash(unit):
    values = env(unit)
    return hashlib.sha256(b"\0".join(k + b"=" + values[k] for k in sorted(values) if k.startswith((b"PSY_", b"RUST_", b"DATABASE_", b"REDIS_")) and k != b"PSY_COORDINATOR_EDGE_RPC_URL")).hexdigest()


def paths(realm):
    unit = f"parth-psy-indexer@realm-{realm}.service"
    drop = Path(f"/etc/systemd/system/{unit}.d/99-z-job-stats-20261014.conf")
    cursor = Path(f"/var/lib/parth/checkpoints/indexer_state/realm_{realm}_1.json")
    return unit, drop, cursor, ROOT / str(realm)


def read_cursor(path):
    for _ in range(5):
        try:
            value = json.loads(path.read_text())["last_checkpoint_id"]
            require(type(value) is int and value >= 0, "Invalid cursor")
            return value
        except (OSError, ValueError, KeyError):
            time.sleep(0.1)
    raise RuntimeError("Cannot read cursor")


def rpc(method, params):
    request = urllib.request.Request(COORDINATOR, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.load(response)
    require("error" not in body, "Coordinator RPC failed")
    return body["result"]


def save(directory, state):
    temporary = directory / "state.next"
    with temporary.open("w") as stream:
        json.dump(state, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(directory / "state.json")


def audit(directory, state):
    try:
        save(directory, state)
    except OSError:
        pass


def unchanged(state, check_processors=True):
    require(all(sha(p) == h for p, h in state["protected"].items()), "Original configuration changed")
    if check_processors:
        for unit, pid in state["processor_pids"].items():
            require(prop(unit, "MainPID") == pid and prop(unit, "ActiveState") == "active", "Processor state changed")
    require(prop(state["unit"], "WorkingDirectory") == str(OLD_HOME), "Working directory changed")


def healthy(state, digest, new, seconds=180):
    unit, _, cursor, _ = paths(state["realm"])
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        unchanged(state, check_processors=new)
        if prop(unit, "MainPID") != "0" and prop(unit, "ActiveState") == "active":
            current = live(unit)
            require(current["sha256"] == digest, "Unexpected running executable")
            require(env_hash(unit) == state["env_hash"], "Original environment changed")
            expected = COORDINATOR.encode() if new else state["old_coordinator"].encode()
            require(env(unit).get(b"PSY_COORDINATOR_EDGE_RPC_URL", b"") == expected, "Coordinator configuration differs")
            position = read_cursor(cursor)
            require(position >= state["cursor_before"], "Cursor moved backwards")
            if position >= state["cursor_at_start"] + 3:
                return {**current, "cursor": position}
        time.sleep(3)
    raise RuntimeError("Indexer did not advance three checkpoints before deadline")


def preflight(realm, binary, manifest):
    unit, drop, cursor, directory = paths(realm)
    require(not directory.exists() and not drop.exists(), "Existing rollout; inspect first")
    current = live(unit)
    require(current["sha256"] == OLD_HASH and current["exe"] == str(OLD_HOME / "psy-indexer"), "Baseline differs")
    require(sha(binary) == manifest["binary_sha256"], "Candidate hash differs")
    require("not found" not in run("ldd", str(binary)), "Missing shared library")
    expected_drop = f"/etc/systemd/system/{unit}.d/99-services-relocation.conf" if realm == 0 else ""
    require(prop(unit, "DropInPaths") == expected_drop, "Unexpected baseline overrides")
    require(prop(unit, "User") == "parth" and prop(unit, "Group") == "parth", "Service identity differs")
    require(f"--realm-id {realm} --realm-sub-id 1" in prop(unit, "ExecStart"), "Invocation differs")
    config = Path("/etc/parth/services-relocation-indexer.env") if realm == 0 else Path("/etc/parth/realm1-indexer-20261014.env")
    configs = [OLD_HOME / "indexer.env", config] if realm == 0 else [config]
    require(prop(unit, "EnvironmentFiles").splitlines() == [f"{p} (ignore_errors=no)" for p in configs], "Unexpected configuration source")
    values = env(unit)
    require(values.get(b"PSY_BACKUP_DIR") == b"/var/lib/parth/checkpoints", "Backup path differs")
    files = [Path(prop(unit, "FragmentPath")), *configs] + ([Path(expected_drop)] if expected_drop else [])
    checkpoint = read_cursor(cursor)
    require(int(rpc("psy_get_latest_checkpoint_id", [])) >= checkpoint, "Coordinator behind cursor")
    historical = rpc("psy_get_realm_root_and_last_modified_checkpoint", [checkpoint, realm])
    require(int(historical["checkpoint_id"]) <= checkpoint and len(bytes.fromhex(historical["value"].removeprefix("0x"))) == 32, "Invalid historical classification RPC")
    state = {"realm": realm, "unit": unit, "old": current, "old_coordinator": values.get(b"PSY_COORDINATOR_EDGE_RPC_URL", b"").decode(), "old_dropins": prop(unit, "DropInPaths").split(), "env_hash": env_hash(unit), "protected": {str(p): sha(p) for p in files}, "cursor_before": checkpoint, "manifest": manifest, "processor_pids": {u: prop(u, "MainPID") for u in ("parth-realm-processor@0.service", "parth-realm-processor@1.service")}}
    unchanged(state)
    require(all(pid != "0" for pid in state["processor_pids"].values()), "Processor not running")
    return state


def rollback(state):
    unit, drop, cursor, directory = paths(state["realm"])
    unchanged(state, check_processors=False)
    require(sha(OLD_HOME / "psy-indexer") == OLD_HASH, "Rollback binary differs")
    require(set(prop(unit, "DropInPaths").split()) <= set(state["old_dropins"] + [str(drop)]), "Unexpected overrides")
    if prop(unit, "MainPID") != "0":
        require(live(unit)["sha256"] in (OLD_HASH, state["manifest"]["binary_sha256"]), "Unexpected running binary")
    if drop.exists():
        require(sha(drop) == state["drop_sha256"], "Override differs")
        drop.unlink()
    run("systemctl", "daemon-reload")
    start_from_stopped_cursor(state)
    state.update(phase="rolled_back", observed=healthy(state, OLD_HASH, False))
    audit(directory, state)
    emit({"phase": state["phase"], "realm": state["realm"], **state["observed"]})


def start_from_stopped_cursor(state):
    unit, _, cursor, directory = paths(state["realm"])
    run("systemctl", "stop", unit)
    require(prop(unit, "MainPID") == "0", "Old Indexer is still running")
    # Old-process shutdown can persist progress. Only count progress after it exits.
    state["cursor_at_start"] = read_cursor(cursor)
    require(state["cursor_at_start"] >= state["cursor_before"], "Cursor moved backwards")
    audit(directory, state)
    run("systemctl", "start", unit)


def activate(realm, binary, manifest):
    state = preflight(realm, binary, manifest)
    unit, drop, cursor, directory = paths(realm)
    directory.mkdir(parents=True, mode=0o700)
    for index, path in enumerate(state["protected"]):
        shutil.copy2(path, directory / f"original-{index}")
    release = Path("/opt/parth-indexers") / manifest["source_commit"][:12]
    if not release.exists():
        release.mkdir(mode=0o755)
        release.chmod(0o755)
        shutil.copyfile(binary, release / "psy-indexer")
        (release / "psy-indexer").chmod(0o755)
        (release / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    require(sha(release / "psy-indexer") == manifest["binary_sha256"], "Installed artifact differs")
    drop.parent.mkdir(exist_ok=True, mode=0o755)
    drop.parent.chmod(0o755)
    staged = directory / "candidate.conf"
    with staged.open("x") as stream:
        stream.write(f"[Service]\nEnvironment=PSY_COORDINATOR_EDGE_RPC_URL={COORDINATOR}\nExecStart=\nExecStart={release}/psy-indexer realm --realm-id {realm} --realm-sub-id 1\n")
        stream.flush()
        os.fsync(stream.fileno())
    staged.chmod(0o644)
    state.update(phase="prepared", drop_sha256=sha(staged), activated_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    save(directory, state)
    require(live(unit) == state["old"], "Process changed before activation")
    try:
        os.link(staged, drop)
        run("systemctl", "daemon-reload")
        unchanged(state)
        require(prop(unit, "DropInPaths").split() == state["old_dropins"] + [str(drop)], "Unexpected loaded override")
        start_from_stopped_cursor(state)
        state.update(phase="ready", observed=healthy(state, manifest["binary_sha256"], True))
        save(directory, state)
        emit({"phase": state["phase"], "realm": realm, **state["observed"], "audit": str(directory)})
    except Exception:
        state["phase"] = "activation_failed"
        audit(directory, state)
        try:
            rollback(state)
        except Exception:
            state["phase"] = "rollback_failed_requires_operator"
            audit(directory, state)
            raise RuntimeError("Rollback failed; inspect protected audit") from None
        raise RuntimeError("Activation failed; old Indexer restored") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "activate", "rollback"))
    parser.add_argument("--realm", type=int, choices=(0, 1), required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "Root required")
    os.umask(0o077)
    with open("/run/parth-realm-indexer-rollout.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "rollback":
            rollback(json.loads((paths(args.realm)[3] / "state.json").read_text()))
            return
        require(args.binary and args.manifest, "Binary and manifest required")
        manifest = json.loads(args.manifest.read_text())
        require(re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]) and re.fullmatch(r"[0-9a-f]{64}", manifest["binary_sha256"]), "Invalid provenance")
        if args.action == "preflight":
            state = preflight(args.realm, args.binary, manifest)
            emit({"preflight": "pass", "realm": args.realm, "old": state["old"], "cursor": state["cursor_before"]})
        else:
            activate(args.realm, args.binary, manifest)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit({"status": "stopped", "error_type": type(error).__name__, "reason": str(error) if isinstance(error, RuntimeError) else "Inspect protected state"})
        raise SystemExit(1)
