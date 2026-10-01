#!/usr/bin/env python3
"""Faucet-only immutable binary rollout. Never change keys, config or chain data."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request

UNIT = "parth-faucet-server.service"
RELAYER = "parth-relayer.service"
OLD_SHA = "1b87493f71125294ce9451e1022a90e8445532bb19b5daa264186e57e6b945fa"
DROPIN = Path("/etc/systemd/system") / f"{UNIT}.d/95-faucet-cancel-safe.conf"
PROTECTED = [
    Path("/opt/parth/current/genesis.json"),
    Path("/opt/parth/current/client_prover/config.json"),
    Path("/etc/parth/common.env"),
    Path("/etc/parth/faucet-server.env"),
]


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def pid(unit):
    return int(run("systemctl", "show", unit, "-p", "MainPID", "--value"))


def public_config():
    request = urllib.request.Request(
        "http://127.0.0.1:9998/",
        data=b'{"jsonrpc":"2.0","id":1,"method":"psy_get_psy_faucet_config","params":[]}',
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.load(response)["result"]
    assert result["enabled"] and len(result["operator_user_ids"]) == 10
    return result


def wait_ready(expected_sha, config, seconds=600):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            current = pid(UNIT)
            if current and sha(f"/proc/{current}/exe") == expected_sha and public_config() == config:
                return current
        except (OSError, ValueError, KeyError, AssertionError, subprocess.CalledProcessError):
            pass
        time.sleep(3)
    raise RuntimeError("Faucet executable/readiness did not pass before deadline")


def protected_hashes():
    return {str(path): sha(path) for path in PROTECTED}


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo; do not print environment files")
    package = Path(sys.argv[1]).resolve()
    manifest = json.loads((package / "manifest.json").read_text())
    commit = manifest["source_commit"]
    assert len(commit) == 40 and all(c in "0123456789abcdef" for c in commit)
    expected = manifest["binary_sha256"]
    assert sha(package / "psy_user_cli") == expected
    assert manifest["base_commit"] == "32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6"
    assert manifest["service"] == UNIT and manifest["magic"] == "0x1337CF514544CF69"
    assert not DROPIN.exists(), "Existing override: inspect before re-running"
    old_pid = pid(UNIT)
    assert old_pid and sha(f"/proc/{old_pid}/exe") == OLD_SHA, "Unexpected live Faucet binary"
    old_exe = str(Path(f"/proc/{old_pid}/exe").resolve())
    old_argv = Path(f"/proc/{old_pid}/cmdline").read_bytes().split(b"\0")
    assert old_argv[1:-1] == [b"faucet-server", b"--listen-addr", b"0.0.0.0:9998",
                              b"--rpc-config", b"/opt/parth/current/client_prover/config.json"]
    config = public_config()
    hashes = protected_hashes()
    relayer_pid = pid(RELAYER)
    assert relayer_pid > 0
    relayer_sha = sha(f"/proc/{relayer_pid}/exe")
    release = Path("/opt/parth/faucet/releases") / f"20261001-{commit[:12]}"
    release.mkdir(parents=True, exist_ok=False, mode=0o755)
    shutil.copyfile(package / "psy_user_cli", release / "psy_user_cli")
    os.chmod(release / "psy_user_cli", 0o755)
    shutil.copyfile(package / "manifest.json", release / "manifest.json")
    (release / "logging.env").write_text("RUST_LOG=warn,psy_prover::local::native::faucet=info\n")
    assert sha(release / "psy_user_cli") == expected
    state = {"old_pid": old_pid, "old_executable": old_exe, "old_sha256": OLD_SHA,
             "relayer_pid": relayer_pid, "protected_hashes": hashes, "config": config}
    state_path = release / "rollout-state.json"
    state_path.touch(mode=0o600)
    state_path.write_text(json.dumps(state, indent=2) + "\n")
    content = ("[Service]\nWorkingDirectory=/opt/parth/current\nExecStart=\n"
               f"ExecStart={release}/psy_user_cli faucet-server --listen-addr 0.0.0.0:9998 "
               "--rpc-config /opt/parth/current/client_prover/config.json\n"
               f"EnvironmentFile={release}/logging.env\n")
    DROPIN.parent.mkdir(parents=True, exist_ok=True)
    assert pid(UNIT) == old_pid and protected_hashes() == hashes
    with DROPIN.open("x") as stream:
        stream.write(content)
    try:
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", UNIT)
        new_pid = wait_ready(expected, config)
        assert protected_hashes() == hashes, "Protected configuration changed"
        assert pid(RELAYER) == relayer_pid and sha(f"/proc/{relayer_pid}/exe") == relayer_sha
        state.update(phase="verified", new_pid=new_pid, binary_sha256=expected)
        state_path.write_text(json.dumps(state, indent=2) + "\n")
        print(json.dumps({"phase": "verified", "pid": new_pid, "sha256": expected,
                          "operator_count": 10, "relayer_unchanged": True}), flush=True)
    except Exception:
        if DROPIN.read_text() != content or protected_hashes() != hashes:
            raise RuntimeError("Rollback blocked: unexpected config change; operator inspection required")
        DROPIN.unlink()
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", UNIT)
        wait_ready(OLD_SHA, config)
        state.update(phase="rolled_back")
        state_path.write_text(json.dumps(state, indent=2) + "\n")
        raise RuntimeError("Candidate failed; old Faucet restored") from None


if __name__ == "__main__":
    main()
