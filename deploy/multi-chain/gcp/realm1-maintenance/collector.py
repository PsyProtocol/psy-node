#!/usr/bin/env python3
"""Move only Realm1 Processor monitoring after migration acceptance."""
import argparse
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import tomllib

UNIT = "parth-realm-processor@1.service"
CONFIG = Path("/etc/parth-sentinel/collector.toml")
SERVICE = {"id": "processor", "unit": UNIT, "logs": {"source": "journald", "unit": UNIT}}
BLOCK = '''[[targets.services]]
id = "processor"
unit = "parth-realm-processor@1.service"
[targets.services.logs]
source = "journald"
unit = "parth-realm-processor@1.service"

'''
TARGET = '''\n[[targets]]
id = "realm-1"
kind = "realm"
labels = { realm_id = "1" }

''' + BLOCK


def transform(text, role):
    original = tomllib.loads(text)
    expected = copy.deepcopy(original)
    realms = [x for x in expected["targets"] if x["id"] == "realm-1"]
    if role == "source":
        if len(realms) != 1 or realms[0]["services"].count(SERVICE) != 1 or text.count(BLOCK) != 1:
            raise ValueError("Original source monitoring differs")
        realms[0]["services"].remove(SERVICE)
        changed = text.replace(BLOCK, "", 1)
    else:
        if realms:
            raise ValueError("Target Realm1 monitoring already exists")
        expected["targets"].append({"id": "realm-1", "kind": "realm", "labels": {"realm_id": "1"},
                                    "services": [SERVICE]})
        changed = text + TARGET
        changed = changed.replace(
            "# Only Processor 0 moved. Realm 0 Edge/checkpoint/indexer and Realm 1 stay on cp-ce.",
            "# Both Realm Processors and Realm0 indexer relocated; Edges remain on their hosts.")
    if tomllib.loads(changed) != expected:
        raise ValueError("Unexpected monitoring change")
    return changed


def run(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["source", "target"])
    role = parser.parse_args().role
    if os.geteuid() != 0:
        raise RuntimeError("sudo required")
    expected_ip = "10.148.0.25" if role == "source" else "10.148.0.37"
    addresses = json.loads(run("ip", "-j", "-4", "addr"))
    if not any(x.get("local") == expected_ip for interface in addresses for x in interface["addr_info"]):
        raise RuntimeError("Wrong host")
    expected_state = "inactive" if role == "source" else "active"
    if run("systemctl", "show", UNIT, "-p", "ActiveState", "--value") != expected_state:
        raise RuntimeError("Processor is not in its expected post-migration state")
    if CONFIG.is_symlink():
        raise RuntimeError("Unexpected config symlink")
    original = CONFIG.read_text()
    changed = transform(original, role)
    info = CONFIG.stat()
    audit = Path("/var/lib/parth/realm1-collector-20261013")
    audit.mkdir(mode=0o700, parents=True, exist_ok=True)
    if audit.is_symlink() or audit.stat().st_uid != 0 or audit.stat().st_mode & 0o077:
        raise RuntimeError("Unsafe audit directory")
    backup = audit / f"collector-before-{time.time_ns()}.toml"
    with backup.open("x") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(original)
        f.flush()
        os.fsync(f.fileno())
    candidate = CONFIG.with_name(f"collector-realm1-{time.time_ns()}.toml")
    with candidate.open("x") as f:
        os.fchmod(f.fileno(), stat.S_IMODE(info.st_mode))
        os.fchown(f.fileno(), info.st_uid, info.st_gid)
        f.write(changed)
        f.flush()
        os.fsync(f.fileno())
    print(run("/usr/local/bin/psy-notifier-collector", "config", "validate", "--config", str(candidate)))
    if CONFIG.read_text() != original:
        raise RuntimeError("Concurrent config edit; candidate not activated")
    os.replace(candidate, CONFIG)
    descriptor = os.open(CONFIG.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    run("systemctl", "restart", "parth-sentinel-collector.service")
    if run("systemctl", "is-active", "parth-sentinel-collector.service") != "active":
        raise RuntimeError("Collector did not recover; inspect backup")
    print(json.dumps({"role": role, "realm1_processor_monitoring": "removed" if role == "source" else "added",
                      "backup": str(backup)}))


if __name__ == "__main__":
    main()
