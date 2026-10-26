#!/usr/bin/env python3
"""Private, online Realm1 pre-copy only. No service lifecycle operations."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

SOURCE = "10.148.0.25"
TARGET = "10.148.0.37"
TAG = "realm1-presync-20261013"
STATE = Path("/var/lib/parth") / TAG
KEY = STATE / "read-only-key"
DATA = Path("/var/lib/parth/checkpoints/realm_1_1")
RELEASE = Path("/opt/parth-realm-processors/72da74e3")
PERMIT = Path("/var/lib/parth/realm-migration-20261010/realm-1.permit")
UNIT = "parth-realm-processor@1.service"
EXPECTED_BINARY = "bda82589c26bd914ead5bd77b8e6de136e0703797d0135fcddf3c2ff8dd8bb03"
EXPECTED_GENESIS = "569e58c901cdf7bd9edfc25bab70c4b0aafe0f5d2ec782781290d963ae63b710"
EXPECTED_WRAPPER = "192b22fe65fd9f49c2bde75e16fd81293edaf8cff03f9c68aedd324c96dde568"
SOURCE_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJstOeTBzGI7x1kTNmXCjmBdPlt9fYRYj02jCYadYR8S"
EXPIRY = "20261015000000Z"


def run(*args, timeout=60):
    return subprocess.check_output(args, text=True, timeout=timeout).strip()


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def write_new(path, text, mode=0o600):
    with path.open("x") as f:
        os.fchmod(f.fileno(), mode)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def host(address):
    if os.geteuid() != 0:
        raise RuntimeError("sudo required")
    addresses = json.loads(run("ip", "-j", "-4", "addr"))
    if not any(a.get("local") == address for i in addresses for a in i["addr_info"]):
        raise RuntimeError("Wrong host")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise RuntimeError("State directory must be root-owned and private")


def state():
    props = run("systemctl", "show", UNIT, "-p", "MainPID", "-p", "ActiveState", "-p", "UnitFileState")
    return dict(line.split("=", 1) for line in props.splitlines())


def require_target_fenced(props, permit_exists):
    if (props.get("MainPID") != "0" or props.get("ActiveState") != "inactive"
            or props.get("UnitFileState") != "disabled" or permit_exists):
        raise RuntimeError("Target must remain inactive, disabled and without a startup permit")


def target_check():
    host(TARGET)
    require_target_fenced(state(), PERMIT.exists())
    for path, expected in ((RELEASE / "target/release/psy_node_cli", EXPECTED_BINARY),
                           (RELEASE / "genesis.json", EXPECTED_GENESIS),
                           (RELEASE / "deploy/bin/run-parth-service", EXPECTED_WRAPPER)):
        if sha(path) != expected:
            raise RuntimeError("Target artifact mismatch: " + str(path))
    if DATA.is_symlink() or not DATA.is_dir():
        raise RuntimeError("Unexpected target checkpoint directory")


def prepare_key():
    target_check()
    if not KEY.exists():
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", TAG, "-f", str(KEY))
    known = STATE / "known_hosts"
    content = f"{SOURCE} {SOURCE_HOST_KEY}\n"
    if not known.exists():
        write_new(known, content)
    elif known.read_text() != content:
        raise RuntimeError("Source host key file drift")
    print(KEY.with_suffix(".pub").read_text().strip())


def authorized_entry(public):
    fields = public.strip().split()
    if len(fields) != 3 or fields[0] != "ssh-ed25519" or fields[2] != TAG:
        raise ValueError("Unexpected public key")
    import base64
    decoded = base64.b64decode(fields[1], validate=True)
    if len(decoded) != 51 or not decoded.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"):
        raise ValueError("Invalid Ed25519 key structure")
    return (f'from="{TARGET}",restrict,expiry-time="{EXPIRY}",'
            f'command="/usr/bin/rrsync -ro {DATA}" ' + " ".join(fields))


def authorize(public):
    host(SOURCE)
    props = state()
    p = int(props.get("MainPID", 0))
    if props.get("ActiveState") != "active" or not p or sha(f"/proc/{p}/exe") != EXPECTED_BINARY:
        raise RuntimeError("Original Realm1 must still run approved binary")
    if datetime.datetime.now(datetime.timezone.utc) >= datetime.datetime.strptime(EXPIRY, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc):
        raise RuntimeError("Key expiry passed")
    entry = authorized_entry(public)
    auth = Path("/root/.ssh/authorized_keys")
    if auth.is_symlink() or not auth.exists():
        raise RuntimeError("Unexpected root authorized_keys")
    with (STATE / "auth.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = auth.read_text()
        existing = [line for line in before.splitlines() if TAG in line]
        if existing:
            if existing != [entry]:
                raise RuntimeError("Existing key entry differs; inspect manually")
        else:
            write_new(STATE / f"authorized_keys.before-{time.time_ns()}", before)
            # Append only; unrelated keys and original inode/permissions remain intact.
            with auth.open("a") as f:
                f.write(("\n" if before and not before.endswith("\n") else "") + entry + "\n")
                f.flush()
                os.fsync(f.fileno())
    print(json.dumps({"authorized": True, "source_pid_unchanged": int(state()["MainPID"]) == p,
                      "read_only_directory": str(DATA), "expires": EXPIRY}))


def copy():
    target_check()
    with (STATE / "sync.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        target_check()
        ssh = shlex.join(["ssh", "-i", str(KEY), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                          "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={STATE}/known_hosts",
                          "-o", "ConnectTimeout=10"])
        started = time.time()
        # No --delete or --inplace. Changing source files are replaced atomically on target.
        command = ["rsync", "-rtp", "--checksum", "--stats", "--timeout=120",
                   "--chown=parth:parth", "--chmod=D750,F640", "-e", ssh,
                   f"root@{SOURCE}:./", str(DATA) + "/"]
        result = subprocess.run(command, text=True, capture_output=True, timeout=3600)
        record = {"started_unix": started, "finished_unix": time.time(), "exit_code": result.returncode,
                  "kind": "live_presync_not_consistent_snapshot", "stdout": result.stdout,
                  "stderr": result.stderr, "target_state_after": state()}
        write_new(STATE / f"presync-{time.time_ns()}.json", json.dumps(record, indent=2))
        print(result.stdout)
        if result.returncode not in (0, 24):
            raise RuntimeError("rsync failed; consult protected record")
        target_check()
        print(json.dumps({"precopy_completed": True, "exit_code": result.returncode,
                          "seconds": round(time.time() - started, 2), "safe_to_start": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare-key", "authorize-key", "copy", "check"])
    parser.add_argument("public_key", nargs="?")
    args = parser.parse_args()
    if args.action == "prepare-key":
        prepare_key()
    elif args.action == "authorize-key":
        authorize(args.public_key or "")
    elif args.action == "copy":
        copy()
    else:
        target_check()
        print(json.dumps({"target_fenced": True, "artifacts_match": True}))


if __name__ == "__main__":
    main()
