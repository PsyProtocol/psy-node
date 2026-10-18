#!/usr/bin/env python3
"""Operator-run temporary stop of the dedicated lab hosts' native Psy services."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time


UNITS = {
    "x3": (
        "parth-prove-capture.service",
        "parth-prove-observer-allocator.service",
        "parth-prove-observer-base.service",
        "parth-sentinel-collector.service",
        "parth-prove-proxy@system.service",
        "parth-prove-proxy@user.service",
    ),
    "x4": ("parth-prove-proxy@user.service",),
}


def state(unit):
    result = subprocess.run(
        ["systemctl", "show", unit, "--no-pager",
         "--property=LoadState,ActiveState,SubState,UnitFileState,TriggeredBy"],
        check=True, capture_output=True, text=True, timeout=15,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=UNITS)
    parser.add_argument("--apply", action="store_true", help="requires operator sudo")
    args = parser.parse_args()
    expected = "arc99" + args.host
    if Path("/proc/sys/kernel/hostname").read_text().strip() != expected:
        raise SystemExit("Wrong physical host; expected " + expected)
    if args.apply and os.geteuid() != 0:
        raise SystemExit("Run --apply using sudo from the host console/SSH session")
    before = {unit: state(unit) for unit in UNITS[args.host]}
    print(json.dumps({"host": expected, "before": before}, indent=2), flush=True)
    if not args.apply:
        print("Plan only. Add --apply with sudo to stop these native services.")
        return
    os.umask(0o077)
    saved = Path(tempfile.mkdtemp(prefix="psy-pause-" + args.host + "-", dir="/var/tmp"))
    (saved / "before.json").write_text(json.dumps({
        "host": expected, "time_unix": time.time(), "units": before,
    }, indent=2) + "\n")
    running = [unit for unit, row in before.items()
               if row.get("ActiveState") in {"active", "activating", "reloading"}]
    restore = "#!/bin/sh\nset -eu\n"
    restore += '[ "$(cat /proc/sys/kernel/hostname)" = ' + shlex.quote(expected) + ' ]\n'
    if running:
        restore += "systemctl start " + " ".join(shlex.quote(unit) for unit in running) + "\n"
    (saved / "resume-native-services.sh").write_text(restore)
    print("Saved previous state and operator resume script: " + str(saved), flush=True)
    loaded = [unit for unit, row in before.items() if row.get("LoadState") != "not-found"]
    if loaded:
        # Explicit stop suppresses systemd Restart=; enabled state is retained.
        subprocess.run(["systemctl", "stop", *loaded], check=True, timeout=300)
    after = {unit: state(unit) for unit in UNITS[args.host]}
    (saved / "after.json").write_text(json.dumps(after, indent=2) + "\n")
    print(json.dumps({"after": after}, indent=2), flush=True)
    if any(row.get("ActiveState") not in {"inactive", "failed"} for row in after.values()):
        raise SystemExit("Some services are still active; inspect after.json")
    print("Native Psy services stopped. Disk data and enabled settings retained.")
    subprocess.run(["free", "-h"], check=True)


if __name__ == "__main__":
    main()
