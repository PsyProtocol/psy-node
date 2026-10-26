#!/usr/bin/env python3
"""Operator-controlled activation after three identical fenced inventories."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("presync", HERE / "presync.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
file_spec = importlib.util.spec_from_file_location("final_files", HERE / "final_files.py")
files = importlib.util.module_from_spec(file_spec)
file_spec.loader.exec_module(files)
REMOTE = "/home/ubuntu/realm1-maintenance-20261013"
AUDIT = Path("/var/lib/parth/realm1-final-files-20261013")
ENV_SHA = "99128d6359f6da09da3f3192601449b625d2dd897e297df98f150502d5de82eb"


def remote(host, *args):
    return subprocess.check_output(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        host, shlex.join(args)], text=True, timeout=600).strip()


def audit_path(raw, kind):
    path = Path(raw)
    if path.parent != AUDIT or not path.name.startswith(kind + "-") or path.suffix != ".json":
        raise ValueError("Unexpected audit path")
    return path


def consistent(before, after, target):
    if not before.get("source_fenced") or not after.get("source_fenced") or not target.get("target_fenced"):
        raise ValueError("Inventories were not fenced")
    if before["inventory"] != after["inventory"] or before["inventory"] != target["inventory"]:
        raise ValueError("Source before/after and target inventories differ")
    if (target["inventory"]["files"] < 580000 or target["inventory"]["bytes"] < 1000000000
            or after["sampled_at"] < before["sampled_at"]
            or target["sampled_at"] < before["sampled_at"]):
        raise ValueError("Incomplete or out-of-order inventory")


def start_target(receipt):
    p.target_check()
    with (p.STATE / "sync.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = audit_path(receipt["target_audit"], "target")
        if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
            raise RuntimeError("Target audit is not protected")
        target = json.loads(path.read_text())
        consistent(receipt["source_before"], receipt["source_after"], target)
        now = time.time()
        if not 0 <= now - receipt["source_fenced_at"] <= 30 or not 0 <= now - target["sampled_at"] <= 300:
            raise RuntimeError("Fence or target inventory is stale")
        if p.sha(p.RELEASE / "realm-processor-1.env") != ENV_SHA:
            raise RuntimeError("Target Realm1 environment changed")
        # A new presync after the accepted inventory would invalidate the receipt.
        for record in p.STATE.glob("presync-*.json"):
            if record.stat().st_mtime > target["sampled_at"]:
                raise RuntimeError("Presync ran after the accepted inventory")
        # Hold the transfer lock across rehash and start, including copies that
        # failed before writing an audit record. A stale receipt cannot authorize
        # changed files, regardless of which transfer entry point was used.
        p.run("sync", timeout=120)
        if files.inventory(p.DATA, check_owner=True) != target["inventory"]:
            raise RuntimeError("Target data changed after inventory")
        p.target_check()
        now = time.time()
        p.write_new(AUDIT / f"activation-{time.time_ns()}.json", json.dumps(receipt, indent=2))
        p.write_new(p.PERMIT, json.dumps({"inventory": target["inventory"], "activated_at": now}) + "\n")
        directory = os.open(p.PERMIT.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        p.run("systemctl", "start", p.UNIT, timeout=90)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = p.state()
            pid = int(current.get("MainPID", 0))
            try:
                if pid and p.sha(f"/proc/{pid}/exe") == p.EXPECTED_BINARY:
                    print(json.dumps({"target_started": True, "pid": pid, "inventory": target["inventory"],
                                      "source_must_remain_fenced": True}))
                    return
            except FileNotFoundError:
                pass
            time.sleep(0.25)
        raise RuntimeError("Startup not verified; inspect target; NEVER automatically restart source")


def controller(before_path, after_path, target_path):
    before = json.loads(remote("gcp-cp-ce", "sudo", "-n", "cat", str(audit_path(before_path, "source"))))
    after = json.loads(remote("gcp-cp-ce", "sudo", "-n", "cat", str(audit_path(after_path, "source"))))
    target_path = audit_path(target_path, "target")
    target = json.loads(remote("gcp-realm-processor", "sudo", "-n", "cat", str(target_path)))
    consistent(before, after, target)
    # An execution approval may arrive long after preparation. Refresh evidence
    # within the authorized operation, never loosen the activation age checks.
    if time.time() - target["sampled_at"] > 240:
        fresh = json.loads(remote("gcp-realm-processor", "sudo", "-n", "python3", "-I",
                                  REMOTE + "/final_files.py", "target-inventory"))
        consistent(before, after, fresh)
        target_path = audit_path(fresh["audit"], "target")
        target = fresh
    gate = json.loads(remote("gcp-nostr", "sudo", "-n", "curl", "-fsS", "--max-time", "10",
        "--unix-socket", "/run/parth-realm1-admission/admin.sock", "http://localhost/status"))
    if (gate.get("mode") != "closed" or gate.get("active_submissions") != 0
            or gate.get("pending_or_ambiguous") != 0 or gate.get("persistence_uncertain") is not False):
        raise RuntimeError("Gate is not closed and clear")
    remote("gcp-realm-processor", "sudo", "-n", "python3", "-I", REMOTE + "/presync.py", "check")
    remote("gcp-cp-ce", "sudo", "-n", "python3", "-I", REMOTE + "/final_files.py", "source-fenced")
    receipt = dict(source_before=before, source_after=after, target_audit=str(target_path),
                   source_fenced_at=time.time(), gate=gate)
    print(remote("gcp-realm-processor", "sudo", "-n", "python3", "-I", REMOTE + "/activate_target.py",
                 "target", json.dumps(receipt)), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["controller", "target"])
    parser.add_argument("evidence", nargs="+")
    args = parser.parse_args()
    if args.mode == "target" and len(args.evidence) == 1:
        start_target(json.loads(args.evidence[0]))
    elif args.mode == "controller" and len(args.evidence) == 3:
        controller(*args.evidence)
    else:
        parser.error("controller requires source-before, source-after, target audit paths")


if __name__ == "__main__":
    main()
