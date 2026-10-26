#!/usr/bin/env python3
"""Read-only, secret-free systemd artifact inventory. Never executes a rollout."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys


HOSTS = {
    "gcp-cp-ce": [
        "parth-coordinator-processor.service",
        "parth-realm-processor@0.service", "parth-realm-processor@1.service",
        "parth-coordinator-edge@0.service",
        "parth-realm-edge@0.service", "parth-realm-edge@1.service",
        "parth-psy-services.service", "parth-psy-indexer@coordinator.service",
        "parth-psy-indexer@realm-0.service", "parth-psy-indexer@realm-1.service",
    ],
    "gcp-faucet": ["parth-relayer.service", "parth-faucet-server.service"],
    "gcp-coordinator-worker": ["parth-faucet-server.service"],
    "gcp-postgres": ["parth-envio.service"],
    "arc99x1": ["parth-prove-proxy@user.service", "parth-prove-proxy@system.service",
                "parth-user-proxy-lb.service"],
    "arc99x3": ["parth-prove-proxy@user.service", "parth-prove-proxy@system.service"],
    "arc99x4": ["parth-prove-proxy@user.service"],
    "arc99x2": [f"parth-offsite-worker@{role}.service"
                for role in ("coordinator", "realm-0", "realm-1")],
}
FILES = {
    "gcp-cp-ce": ["/opt/parth/current/genesis.json"],
    "gcp-faucet": ["/etc/parth/bridge-relayer.toml"],
    "gcp-postgres": [
        "/opt/parth/envio/current/schema.graphql",
        "/opt/parth/envio/current/package.json",
        "/opt/parth/envio/current/node_modules/envio/src/db/EntityHistory.res.js",
        "/opt/parth/envio/current/node_modules/envio/src/sources/RpcSource.res.js",
    ],
    "arc99x1": ["/etc/parth/user-proxy-lb.conf"],
}
PROPERTIES = ["Id", "LoadState", "ActiveState", "SubState", "UnitFileState",
              "MainPID", "ExecMainStartTimestampMonotonic", "NRestarts", "DropInPaths"]


def digest(path):
    with open(path, "rb") as source:
        return digest_stream(source)


def digest_stream(source):
    value = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        value.update(chunk)
    return value.hexdigest()


def properties(unit):
    result = subprocess.run(
        ["systemctl", "show", unit, "--no-pager", "--property=" + ",".join(PROPERTIES)],
        capture_output=True, text=True, timeout=15, check=True,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def sample(unit):
    before = properties(unit)
    result = {"unit": unit, "systemd": before, "executable": None,
              "sha256": None, "identity_verified": False}
    if before.get("MainPID", "0") != "0":
        path = "/proc/" + before["MainPID"] + "/exe"
        try:
            result["executable"] = os.readlink(path)
            # Bind metadata and hash to one descriptor; never share hashes
            # across samples that may overlap exec/restart transitions.
            with open(path, "rb") as source:
                stat = os.fstat(source.fileno())
                result["sha256"] = digest_stream(source)
            after = properties(unit)
            current_stat = os.stat(path)
            result["identity_verified"] = (
                before.get("MainPID") == after.get("MainPID")
                and before.get("ExecMainStartTimestampMonotonic") ==
                after.get("ExecMainStartTimestampMonotonic")
                and os.readlink(path) == result["executable"]
                and (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns) ==
                (current_stat.st_dev, current_stat.st_ino, current_stat.st_size,
                 current_stat.st_mtime_ns)
            )
            if not result["identity_verified"]:
                result["error"] = "process_changed_during_sample"
        except (OSError, subprocess.SubprocessError) as error:
            result["error"] = type(error).__name__
    return result


def collect(host):
    result = {"host": host, "actual_hostname": socket.gethostname(), "observed_at_utc": datetime.datetime.now(
        datetime.timezone.utc).isoformat(), "units": [], "files": []}
    for unit in HOSTS[host]:
        try:
            result["units"].append(sample(unit))
        except (OSError, subprocess.SubprocessError) as error:
            result["units"].append({"unit": unit, "error": type(error).__name__})
    for path in FILES.get(host, []):
        record = {"path": path}
        try:
            record.update(resolved_path=str(Path(path).resolve(strict=True)), sha256=digest(path))
        except OSError as error:
            record["error"] = type(error).__name__
        result["files"].append(record)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", choices=HOSTS)
    parser.add_argument("--local", action="store_true", help="Collect on this host, without SSH")
    parser.add_argument("--sudo", action="store_true", help="Use noninteractive sudo on the SSH host")
    args = parser.parse_args()
    if args.local:
        result = collect(args.host)
    else:
        remote = "sudo -n python3 -" if args.sudo else "python3 -"
        command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                   args.host, remote + " " + args.host + " --local"]
        try:
            completed = subprocess.run(command, input=Path(__file__).read_text(),
                                       capture_output=True, text=True, timeout=180, check=True)
            result = json.loads(completed.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            # Do not forward SSH banners, command output or protected file contents.
            result = {"host": args.host, "error": type(error).__name__}
    print(json.dumps(result, indent=2))
    return 1 if "error" in result else 0


if __name__ == "__main__":
    sys.exit(main())
