#!/usr/bin/env python3
"""Validate observation coverage; never selects or deploys a build."""
import argparse
import json
from pathlib import Path


def check(mapping, snapshot):
    errors, unverified = [], []
    known = {}
    for component in mapping["components"]:
        for unit in component["units"]:
            key = (component["host"], unit)
            if key in known:
                errors.append("duplicate mapping: " + str(key))
            known[key] = component
    seen = set()
    seen_hosts = set()
    for host in snapshot["hosts"]:
        if host["host"] in seen_hosts:
            errors.append("duplicate host observation: " + host["host"])
        seen_hosts.add(host["host"])
        if "error" in host:
            errors.append("host collection failed: " + host["host"])
        for unit in host.get("units", []):
            key = (host["host"], unit["unit"])
            if key in seen:
                errors.append("duplicate service observation: " + str(key))
            seen.add(key)
            if "systemd" not in unit:
                errors.append("missing service observation: " + str(key))
                continue
            if unit["systemd"].get("MainPID", "0") == "0":
                if key in known:
                    errors.append("expected running service has no PID: " + str(key))
                continue
            component = known.get(key)
            if component is None:
                errors.append("unmapped running service: " + str(key))
                continue
            expected = component["expected_binary_sha256"]
            if expected:
                if not unit.get("identity_verified") or not unit.get("sha256"):
                    unverified.append(str(key))
                elif unit["sha256"] != expected:
                    errors.append("running artifact mismatch: " + str(key))
    for key in known.keys() - seen:
        errors.append("missing observation: " + str(key))
    return errors, unverified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-verified", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    mapping = json.loads((root / "components.json").read_text())
    snapshot = json.loads((root / mapping["snapshot"]).read_text())
    errors, unverified = check(mapping, snapshot)
    print(json.dumps({"errors": errors, "unverified_application_binaries": unverified,
                      "source_consolidation_complete": mapping["complete"],
                      "deployable_release": False}, indent=2))
    return int(bool(errors or (args.require_verified and unverified)))


if __name__ == "__main__":
    raise SystemExit(main())
