#!/usr/bin/env python3
"""Activate only installed R3 processors or edges. No SSH, DB reset or rollback.

Without --apply this is root-only read-only preflight. Successful activation is
process/executable evidence only, never checkpoint or network readiness.
Keep the exact reviewed install_host.py sibling beside this file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import types

HELPER_SHA256 = "0c2b63f996fd1be7eb4909cb2a5b15c88b377405833cc8a15fd532951264a164"
_path = Path(__file__).with_name("install_host.py")
_raw = _path.read_bytes()
if hashlib.sha256(_raw).hexdigest() != HELPER_SHA256:
    raise SystemExit("install_host.py hash mismatch")
h = types.ModuleType("approved_install_host")
h.__file__ = str(_path)
exec(compile(_raw, str(_path), "exec"), h.__dict__)


def show(name):
    raw = h.command(["systemctl", "show", name, "--property=Id,LoadState,ActiveState,MainPID,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload"])
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def process(name, expected):
    value = show(name)
    h.require(value.get("ActiveState") == "active" and value.get("MainPID", "0").isdigit()
              and int(value["MainPID"]) > 0, "unit not active with PID: " + name)
    path = Path("/proc") / value["MainPID"] / "exe"
    h.require(os.readlink(path) == str(h.RELEASE / "bin/psy_node_cli"), "unexpected running executable")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    h.require(digest == expected, "running executable hash mismatch")
    again = show(name)
    h.require(again.get("MainPID") == value["MainPID"] and again.get("ActiveState") == "active", "process changed during check")
    return {"unit": name, "pid": int(value["MainPID"]), "exe_sha256": digest}


def installed(payloads):
    user = h.get_runtime_user()
    h.require(user is not None, "installed runtime account missing")
    files, directories = h.build_paths(payloads, user)
    h.check_paths(files, directories)
    for path, (raw, mode, uid, gid) in files.items():
        parent = h.directory(path.parent)
        try:
            actual, info = h.read_file(parent, path.name)
        finally:
            os.close(parent)
        h.require(actual == raw and (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid),
                  "installed artifact differs: " + str(path))


def preflight(manifest, units, expected):
    addresses = json.loads(h.command(["ip", "-j", "-4", "address", "show"]))
    h.require(manifest["private_ip"] == h.HOSTS[manifest["host"]] and any(
        a.get("local") == manifest["private_ip"] for i in addresses for a in i.get("addr_info", [])), "target IP mismatch")
    listed = h.command(["systemctl", "list-units", "--all", "--type=service", "--no-legend", "--plain", "--no-pager",
                        *(p + "*" for p in h.STOPPED_UNIT_PREFIXES)])
    for line in listed.splitlines():
        row = line.split()
        h.require(len(row) >= 4 and row[0].startswith(h.STOPPED_UNIT_PREFIXES), "unexpected unit listing")
        if row[0] not in units:
            value = show(row[0])
            h.require(value.get("ActiveState") == "inactive" and value.get("MainPID") == "0", "legacy/foreign core not inactive")
    jobs = h.command(["systemctl", "list-jobs", "--no-legend", "--no-pager"])
    h.require(not any(len(r) > 1 and r[1].startswith(h.STOPPED_UNIT_PREFIXES)
                      for r in map(str.split, jobs.splitlines())), "core job queued")
    for name in sorted(units):
        value = show(name)
        h.require(value.get("Id") == name and value.get("LoadState") == "loaded"
                  and value.get("FragmentPath") == str(h.UNITS / name) and value.get("DropInPaths") == ""
                  and value.get("NeedDaemonReload") == "no", "unit source/override/reload mismatch")
        if value.get("ActiveState") == "active":
            process(name, expected)
        else:
            h.require(value.get("ActiveState") == "inactive" and value.get("MainPID") == "0", "R3 unit transitioning or failed")


def activate(package, phase, apply=False):
    h.require(os.geteuid() == 0, "root required")
    h.require(phase in ("processors", "edges"), "invalid phase")
    manifest, payloads = h.read_package(package)
    units, _ = h.host_inventory(manifest["host"])
    selected = sorted(n for n in units if n.endswith("processor.service") == (phase == "processors"))
    h.require(selected, "host has no units for requested phase")
    installed(payloads)
    expected = manifest["files"]["bin/psy_node_cli"]
    preflight(manifest, units, expected)
    results = []
    if apply:
        for name in selected:
            preflight(manifest, units, expected)
            active = show(name).get("ActiveState") == "active"
            h.command(["systemctl", "enable", *([] if active else ["--now"]), name])
            deadline = time.monotonic() + 15
            # Type=simple can report active before the executor reaches execve.
            while True:
                try:
                    result = process(name, expected)
                    break
                except (h.InstallError, FileNotFoundError, ProcessLookupError):
                    if (active or time.monotonic() >= deadline or
                            show(name).get("ActiveState") not in ("active", "activating")):
                        raise
                    time.sleep(0.25)
            h.require(show(name).get("UnitFileState") == "enabled", "unit not enabled")
            results.append({**result, "already_active": active})
    return {"host": manifest["host"], "phase": phase, "units": selected, "started": apply,
            "mode": "started" if apply else "checked_not_started", "processes": results,
            "checkpoint_progress_verified": False, "deployment_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--phase", choices=("processors", "edges"), required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(activate(args.package, args.phase, args.apply), sort_keys=True))
    except Exception as error:
        detail = str(error) if isinstance(error, h.InstallError) else type(error).__name__
        raise SystemExit("Activation failed: " + detail + "; no rollback attempted; inspect selected units") from None


if __name__ == "__main__":
    main()
