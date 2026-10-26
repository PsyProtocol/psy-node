#!/usr/bin/env python3
"""Main-only clean=true runner. Default is public check; never auto-broadcast/retry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import types

HERE = Path(__file__).resolve().parent
QUARANTINE_SHA = "24dc8ddae4a7807d4335dd8b943c9774385198b21ded3111de0a9cdf4df3915b"
RESET_JS_SHA = "b4a1e1e8e02e70ba0eddb624f2e33e7c52bcda2a4a93bed27a920d2e02f3c114"
ATTEMPT = Path("/var/lib/psy-l1-clean-20261027")
RESET_COMPLETE = Path("/var/lib/psy-l1-reset-20261027/complete.json")
NETWORKS = {"sepolia", "bscTestnet", "baseSepolia"}
RESET_PATHS = {"bundle", "evidence", "plan", "snapshot", "fence", "quarantine_plan", "baseline_snapshot", "collector", "budgets"}


def load_helper(path, pin, execute):
    for current in (path, *path.parents):
        info = current.lstat()
        owned = info.st_uid == 0 if execute else info.st_uid in (0, os.getuid())
        allowed_mode = not info.st_mode & 0o022 or (not execute and current == Path("/tmp") and info.st_mode & stat.S_ISVTX)
        if stat.S_ISLNK(info.st_mode) or not owned or not allowed_mode:
            raise ValueError("untrusted helper path")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError("helper hash mismatch")
    module = types.ModuleType("clean_" + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def validate_inputs(q, value, execute):
    q.require(set(value) == {"reset", "post_snapshot", "post_snapshot_sha256", "fork_tool", "fork_tool_sha256",
                            "proof", "attestation", "attestation_sha256", "fork_reports"})
    q.require(set(value["reset"]) == RESET_PATHS | {"plan_sha256", "snapshot_sha256", "fence_sha256"})
    q.require(set(value["fork_reports"]) == NETWORKS)
    for name in RESET_PATHS:
        q.trusted(value["reset"][name], execute)
    for name in ("post_snapshot", "fork_tool", "proof", "attestation"):
        q.trusted(value[name], execute)
    for entry in value["fork_reports"].values():
        q.require(set(entry) == {"path", "sha256"})
        q.trusted(entry["path"], execute)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("helpers", "node", "inputs", "inputs-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--rpc-config", default="/etc/parth/bridge-relayer.toml")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    helpers = Path(os.path.abspath(args.helpers))
    q = load_helper(helpers / "run_l1_quarantine.py", QUARANTINE_SHA, args.execute)
    q.require(not args.execute or os.geteuid() == 0)
    for file in (HERE / "run_l1_clean.py", HERE / "run_l1_clean.cjs", helpers / "run_l1_reset.cjs",
                 helpers / "run_l1_quarantine.cjs", helpers / "fresh_l1.cjs", helpers / "prepare_l1_reset.cjs"):
        q.trusted(file, args.execute)
    q.require(q.sha(helpers / "run_l1_reset.cjs") == RESET_JS_SHA)
    fresh = load_helper(helpers / "fresh_l1.py", q.HELPER_SHA, args.execute)
    q.trusted(args.inputs, args.execute)
    q.require(q.sha(args.inputs) == args.inputs_sha256)
    inputs = fresh.read_json(args.inputs)
    validate_inputs(q, inputs, args.execute)
    q.trusted(args.node, args.execute)
    q.require(q.sha(args.node) == q.NODE_SHA)
    bundle = fresh.verify_bundle(inputs["reset"]["bundle"], q.BUNDLE_SHA)
    if args.execute:
        for parent, dirs, files in os.walk(bundle, followlinks=False):
            for name in dirs + files:
                info = (Path(parent) / name).stat()
                q.require(info.st_uid == 0 and not info.st_mode & 0o022)
        q.trusted(RESET_COMPLETE, True)
        completed = fresh.read_json(RESET_COMPLETE)
        q.require(completed["execute"] is True and completed["phase"] == "reset" and completed["transactions_completed"] == 6
                  and completed["plan_sha256"] == inputs["reset"]["plan_sha256"] and completed["runner_sha256"] == RESET_JS_SHA)
    output = Path(os.path.abspath(args.output))
    q.trusted(output.parent, args.execute)
    output.mkdir(mode=0o700)
    request = {"helpers": str(helpers), "inputs": str(Path(args.inputs).absolute()), "inputs_sha256": args.inputs_sha256,
               "output": str(output), "execute": False,
               "rpcs": {name: fresh.own_rpc(args.rpc_config, name) for name in fresh.NETWORKS}}

    def child(value):
        result = subprocess.run([args.node, str(HERE / "run_l1_clean.cjs")], input=json.dumps(value), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "HOME": str(output)}, check=False)
        q.require(result.returncode == 0)
        report = json.loads(result.stdout)
        q.require(report.get("ok") is True and report.get("phase") == "clean")
        return report

    checked = child(request)
    if not args.execute:
        return checked
    q.trusted(ATTEMPT.parent, True)
    ATTEMPT.mkdir(mode=0o700)
    fd = os.open(ATTEMPT.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    with (ATTEMPT / "attempt.json").open("x") as stream:
        json.dump({"inputs_sha256": args.inputs_sha256, "output": str(output), "status": "claimed-no-retry",
                   "runner_python_sha256": q.sha(__file__), "runner_js_sha256": q.sha(HERE / "run_l1_clean.cjs"),
                   "proof_sha256": checked["proof_sha256"], "snapshot_sha256": checked["snapshot_sha256"]}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(ATTEMPT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    info = q.KEY.lstat()
    q.require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o027 and q.sha(q.KEY) == q.KEY_SHA)
    secrets = fresh.secret_env([q.PASSWORD_ENV])
    q.require(bool(secrets.get("WALLET_PASSWORD")))
    request.update(execute=True, password=secrets["WALLET_PASSWORD"], keystore=str(q.KEY))
    return child(request)


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception:
        print('{"ok":false,"error":"clean gate failed; preserve attempt and audit; never retry execution"}')
        raise SystemExit(1)
