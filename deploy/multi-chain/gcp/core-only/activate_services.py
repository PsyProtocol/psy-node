#!/usr/bin/env python3
"""Activate only a reviewed installed R3 Services/indexer group; never stop or repair."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import types
import urllib.request


def load_installer(expected):
    path = Path(__file__).with_name("install_services.py")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("installer hash mismatch")
    helper = types.ModuleType("reviewed_services_installer")
    helper.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), helper.__dict__)
    return helper


def http_health(url):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=10) as response:
        if response.status != 200:
            raise ValueError("private dependency health check failed")


def preflight(helper, root, manifest, topology):
    helper.require(os.geteuid() == 0 and manifest["l1_ready"], "root and fresh L1 documents required")
    helper.require(str(root) == helper.RELEASE, "installed r3 release required")
    group = topology["groups"][manifest["group"]]
    addresses = subprocess.check_output(["hostname", "-I"], text=True).split()
    helper.require(group["host"] in addresses, "wrong host")
    helper.trusted_parents(root)
    for path in (root, *root.rglob("*")):
        helper.no_links(path)
        info = path.stat()
        helper.require(info.st_uid == 0 and not info.st_mode & 0o022, "installed file permissions")
    names = [helper.unit_name(role) for role in group["roles"]]
    helper.fence_services(names)
    role = "services" if manifest["group"] == "services" else "indexer"
    helper.read_credentials(Path(topology["credentials"]) / (role + ".env"), role, topology)
    for name in names:
        value = helper.unit_status(name)
        helper.require(value.get("Id") == name and value.get("DropInPaths") == ""
                       and value.get("NeedDaemonReload") == "no"
                       and value.get("FragmentPath") == "/etc/systemd/system/" + name,
                       "unit source/drop-in/reload conflict")
        actual = Path(value["FragmentPath"])
        helper.require(actual.read_bytes() == (root / "units" / name).read_bytes(), "installed unit bytes differ")
        helper.require(value.get("ActiveState") in ("inactive", "active"), "unit failed or transitioning; inspect without retry")
        if value["ActiveState"] == "inactive":
            helper.require(value.get("MainPID") == "0", "inactive unit still has PID")
    if role == "services":
        helper.require(topology["hasura_url"] == "http://10.148.0.24:38081/v1/graphql", "fresh Hasura required")
        http_health("http://10.148.0.24:38081/healthz")
    else:
        http_health(topology["services_url"] + "/health")
        for name in group["roles"]:
            item = topology["indexers"][name]
            subprocess.run(["systemctl", "is-active", "--quiet", item["core_unit"]], check=True)
            if name.startswith("realm"):
                realm = int(name[-1])
                sources = json.loads((root / (name + ".json")).read_bytes())
                directories = [Path(sources["coordinator_backup_base_dir"]) / "coordinator_0_0/guta_updates_backup"]
                directories += [Path(row["backup_base_dir"]) / f"realm_{realm}_{row['realm_sub_id']}/guta_updates_backup"
                                for row in sources["validators"]]
                for directory in directories:
                    helper.no_links(directory)
                    helper.require(directory.is_dir() and any(directory.glob("*.backup")), "fresh committed backup source missing")
    return names


def process(helper, name, binary):
    value = helper.unit_status(name)
    helper.require(value.get("ActiveState") == "active" and value.get("MainPID", "0").isdigit()
                   and int(value["MainPID"]) > 0, "unit not active; inspect without restart")
    path = Path("/proc") / value["MainPID"] / "exe"
    helper.require(os.readlink(path) == helper.RELEASE + "/" + binary, "unexpected running executable")
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    helper.require(sha == helper.BINARIES[binary], "running binary mismatch")
    again = helper.unit_status(name)
    helper.require(again.get("MainPID") == value["MainPID"] and again.get("ActiveState") == "active", "process changed")
    return {"unit": name, "pid": int(value["MainPID"]), "exe_sha256": sha}


def wait_process(helper, name, binary):
    deadline = time.monotonic() + 15
    observed_pid = None
    while True:
        value = helper.unit_status(name)
        helper.require(value.get("ActiveState") in ("active", "activating"), "unit failed during initial exec")
        pid = value.get("MainPID", "0")
        helper.require(pid.isdigit(), "invalid process id")
        if int(pid) > 0:
            helper.require(observed_pid in (None, pid), "process restarted during initial exec")
            observed_pid = pid
            try:
                executable = os.readlink(Path("/proc") / pid / "exe")
            except (FileNotFoundError, ProcessLookupError):
                executable = None
            if executable == helper.RELEASE + "/" + binary:
                return process(helper, name, binary)
            # Type=simple may become active before the systemd executor's execve.
            helper.require(executable in (None, "/usr/lib/systemd/systemd", "/lib/systemd/systemd",
                                          "/usr/lib/systemd/systemd-executor", "/lib/systemd/systemd-executor"),
                           "unexpected executor; refusing retry")
        helper.require(time.monotonic() < deadline, "initial exec deadline exceeded; inspect without restart")
        time.sleep(0.25)


def activate(args):
    helper = load_installer(args.installer_sha256)
    manifest, topology = helper.load_package(args.package, args.manifest_sha256)
    helper.require(helper.digest(Path(helper.__file__)) == manifest["files"]["install_services.py"], "helper/package mismatch")
    names = preflight(helper, args.package, manifest, topology)
    binary = "psy-services" if manifest["group"] == "services" else "psy-indexer"
    results = []
    if args.apply:
        for name in names:
            preflight(helper, args.package, manifest, topology)
            already_active = helper.unit_status(name).get("ActiveState") == "active"
            if already_active:
                process(helper, name, binary)
            subprocess.run(["systemctl", "enable", *([] if already_active else ["--now"]), name], check=True)
            results.append(process(helper, name, binary) if already_active else wait_process(helper, name, binary))
    return {"group": manifest["group"], "started": args.apply, "processes": results,
            "database_acceptance_verified": False, "indexer_progress_verified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--installer-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    try:
        print(json.dumps(activate(parser.parse_args()), sort_keys=True))
    except Exception as error:
        raise SystemExit("Services activation refused: " + type(error).__name__ + "; preserve state, no automatic retry") from None
