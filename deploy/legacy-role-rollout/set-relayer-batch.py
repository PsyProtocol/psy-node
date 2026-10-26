#!/usr/bin/env python3
"""Change only a deployed relayer's batch size, preserving pending bridge work."""
import argparse
import copy
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import tomllib


def updated_config(original, batch):
    parsed = tomllib.loads(original)
    expected = copy.deepcopy(parsed)
    expected["max_checkpoint_batch"] = batch
    updated, count = re.subn(
        r"(?m)^(max_checkpoint_batch\s*=\s*)[0-9]+(?=\s*(?:#.*)?$)",
        lambda match: match[1] + str(batch), original,
    )
    if count != 1 or tomllib.loads(updated) != expected:
        raise ValueError("Expected one existing batch setting and no other semantic changes")
    return parsed, updated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch", type=int, choices=(8, 16, 32, 64))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run with sudo on the relayer host")
    unit = "parth-relayer.service"
    path = Path("/etc/parth/bridge-relayer.toml")
    with open("/run/lock/parth-relayer-batch.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = path.read_text()
        parsed, updated = updated_config(original, args.batch)
        if updated == original:
            print("Already configured; no restart performed")
            return
        subprocess.run(["systemctl", "is-active", "--quiet", unit], check=True)
        stat = path.stat()
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(path.name + ".before-batch-change." + stamp)
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(original)

        def replace(content):
            fd, name = tempfile.mkstemp(prefix=".relayer-batch-", dir=path.parent)
            try:
                with os.fdopen(fd, "w") as handle:
                    os.fchmod(handle.fileno(), stat.st_mode & 0o777)
                    os.fchown(handle.fileno(), stat.st_uid, stat.st_gid)
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(name, path)
            finally:
                if os.path.exists(name):
                    os.unlink(name)

        subprocess.run(["systemctl", "stop", unit], check=True)
        try:
            if path.read_text() != original:
                raise RuntimeError("Configuration changed concurrently; refusing overwrite")
            replace(updated)
            subprocess.run(["systemctl", "start", unit], check=True)
            pid = subprocess.check_output(["systemctl", "show", unit, "-p", "MainPID", "--value"])
            time.sleep(10)
            subprocess.run(["systemctl", "is-active", "--quiet", unit], check=True)
            if subprocess.check_output(["systemctl", "show", unit, "-p", "MainPID", "--value"]) != pid:
                raise RuntimeError("Relayer restarted during startup")
        except Exception:
            if path.read_text() == updated:
                subprocess.run(["systemctl", "stop", unit], check=True)
                replace(original)
            subprocess.run(["systemctl", "start", unit], check=False)
            raise
        print(json.dumps({"old_batch": parsed["max_checkpoint_batch"], "new_batch": args.batch,
                          "backup": str(backup), "note": "Verify completed batches separately"}))
        subprocess.run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "MainPID", "-p", "InvocationID"])


if __name__ == "__main__":
    main()
