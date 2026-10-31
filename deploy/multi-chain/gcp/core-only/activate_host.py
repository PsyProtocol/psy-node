#!/usr/bin/env python3
"""Activate only installed release processors or edges. No SSH, DB reset or rollback.

Without --apply this is root-only read-only preflight. Successful activation is
process/executable evidence only, never checkpoint or network readiness.
Keep the exact install_host.py sibling named by the release lock beside this file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import types

h = None


def read_release_lock(path, expected_sha256):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SystemExit("release lock hash mismatch")
    return json.loads(raw)


def load_helper(lock):
    path = Path(__file__).with_name("install_host.py")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock["tool_sha256"]["install_host.py"]:
        raise SystemExit("install_host.py hash mismatch")
    module = types.ModuleType("approved_install_host")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def show(name):
    raw = h.command(["systemctl", "show", name, "--property=Id,LoadState,ActiveState,MainPID,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload"])
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def process(name, expected, release):
    value = show(name)
    h.require(value.get("ActiveState") == "active" and value.get("MainPID", "0").isdigit()
              and int(value["MainPID"]) > 0, "unit not active with PID: " + name)
    path = Path("/proc") / value["MainPID"] / "exe"
    h.require(os.readlink(path) == str(release.release_dir / "bin/psy_node_cli"), "unexpected running executable")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    h.require(digest == expected, "running executable hash mismatch")
    again = show(name)
    h.require(again.get("MainPID") == value["MainPID"] and again.get("ActiveState") == "active", "process changed during check")
    return {"unit": name, "pid": int(value["MainPID"]), "exe_sha256": digest}


def installed(payloads, release):
    user = h.get_runtime_user()
    h.require(user is not None, "installed runtime account missing")
    files, directories = h.build_paths(payloads, user, release)
    h.check_paths(files, directories, release)
    for path, (raw, mode, uid, gid) in files.items():
        parent = h.directory(path.parent)
        try:
            actual, info = h.read_file(parent, path.name)
        finally:
            os.close(parent)
        h.require(actual == raw and (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (mode, uid, gid),
                  "installed artifact differs: " + str(path))


def preflight(manifest, units, expected, release):
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
            process(name, expected, release)
        else:
            h.require(value.get("ActiveState") == "inactive" and value.get("MainPID") == "0", "release unit transitioning or failed")


def activate(package, phase, release, apply):
    h.require(os.geteuid() == 0, "root required")
    h.require(phase in ("processors", "edges"), "invalid phase")
    manifest, payloads = h.read_package(package, release)
    units, _ = h.host_inventory(manifest["host"], release)
    selected = sorted(n for n in units if n.endswith("processor.service") == (phase == "processors"))
    h.require(selected, "host has no units for requested phase")
    installed(payloads, release)
    expected = manifest["files"]["bin/psy_node_cli"]
    preflight(manifest, units, expected, release)
    results = []
    if apply:
        for name in selected:
            preflight(manifest, units, expected, release)
            active = show(name).get("ActiveState") == "active"
            h.command(["systemctl", "enable", *([] if active else ["--now"]), name])
            deadline = time.monotonic() + 15
            # Type=simple can report active before the executor reaches execve.
            while True:
                try:
                    result = process(name, expected, release)
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
    global h
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--release-lock-sha256", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--phase", choices=("processors", "edges"), required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    lock = read_release_lock(args.release_lock, args.release_lock_sha256)
    h = load_helper(lock)
    try:
        print(json.dumps(activate(args.package, args.phase, h.load_core_release(lock), args.apply), sort_keys=True))
    except Exception as error:
        detail = str(error) if isinstance(error, h.InstallError) else type(error).__name__
        raise SystemExit("Activation failed: " + detail + "; no rollback attempted; inspect selected units") from None


if __name__ == "__main__":
    main()
