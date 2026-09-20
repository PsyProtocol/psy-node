#!/usr/bin/env python3
"""Enforce a separate production source line-coverage floor for each DB crate."""
import argparse
import json
from pathlib import Path

CRATES = ("psy_node_scylla", "psy_node_nats", "psy_node_redis")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--minimum", type=float, default=80.0)
    parser.add_argument("--crate", choices=CRATES, help="Check only the separately tested crate")
    args = parser.parse_args()
    if not 0 <= args.minimum <= 100:
        parser.error("minimum must be between 0 and 100")
    data = json.loads(args.report.read_text())
    files = [f for group in data["data"] for f in group["files"]]
    failed = False
    print("| Crate | Covered lines | Total lines | Line coverage | Gate |")
    print("|---|---:|---:|---:|---|")
    for crate in ((args.crate,) if args.crate else CRATES):
        source = {f["filename"]: f for f in files if f"/{crate}/src/" in f["filename"]}
        total = sum(f["summary"]["lines"]["count"] for f in source.values())
        covered = sum(f["summary"]["lines"]["covered"] for f in source.values())
        passed = bool(total) and covered * 100 >= total * args.minimum
        failed |= not passed
        percent = f"{covered / total * 100:.2f}%" if total else "MISSING"
        print(f"| {crate} | {covered} | {total} | {percent} | {'PASS' if passed else 'FAIL'} |")
    raise SystemExit(int(failed))


if __name__ == "__main__":
    main()
