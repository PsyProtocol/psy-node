#!/usr/bin/env python3
"""Main-only reset runner. Check is default; execution requires real quarantine evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import subprocess

HERE = Path(__file__).resolve().parent
QUARANTINE_PY_SHA = "24dc8ddae4a7807d4335dd8b943c9774385198b21ded3111de0a9cdf4df3915b"
QUARANTINE_JS_SHA = "51e94ca832838bba79ace121d59fa723a0f2a2445b9fee6ac9df3c0a2169858f"
ATTEMPT = Path("/var/lib/psy-l1-reset-20261027")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "node", "evidence", "plan", "plan-sha256", "snapshot", "snapshot-sha256",
                 "fence", "fence-sha256", "quarantine-plan", "baseline-snapshot", "collector", "budgets", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--rpc-config", default="/etc/parth/bridge-relayer.toml")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    helper = HERE / "run_l1_quarantine.py"
    for path in (helper, *helper.parents):
        s = path.lstat()
        owned = s.st_uid == 0 if args.execute else s.st_uid in (0, os.getuid())
        mode = not s.st_mode & 0o022 or (not args.execute and path == Path("/tmp") and s.st_mode & stat.S_ISVTX)
        if stat.S_ISLNK(s.st_mode) or not owned or not mode:
            raise ValueError("untrusted frozen helper path")
    if hashlib.sha256(helper.read_bytes()).hexdigest() != QUARANTINE_PY_SHA:
        raise ValueError("frozen helper hash mismatch")
    spec = importlib.util.spec_from_file_location("reset_quarantine", helper)
    q = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(q)
    q.require(not args.execute or os.geteuid() == 0)
    for name in ("run_l1_reset.py", "run_l1_reset.cjs", "run_l1_quarantine.py", "run_l1_quarantine.cjs", "fresh_l1.py", "fresh_l1.cjs", "prepare_l1_reset.cjs"):
        q.trusted(HERE / name, args.execute)
    q.require(q.sha(HERE / "run_l1_quarantine.cjs") == QUARANTINE_JS_SHA)
    q.require(q.sha(HERE / "fresh_l1.py") == q.HELPER_SHA)
    spec = importlib.util.spec_from_file_location("reset_fresh", HERE / "fresh_l1.py")
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    paths = ("bundle", "node", "evidence", "plan", "snapshot", "fence", "quarantine_plan", "baseline_snapshot", "collector", "budgets")
    for name in paths:
        q.trusted(getattr(args, name), args.execute)
    q.require(q.sha(args.node) == q.NODE_SHA)
    bundle = fresh.verify_bundle(args.bundle, q.BUNDLE_SHA)
    if args.execute:
        for parent, dirs, files in os.walk(bundle, followlinks=False):
            for name in dirs + files:
                s = (Path(parent) / name).stat()
                q.require(s.st_uid == 0 and not s.st_mode & 0o022)
        completed = q.ATTEMPT / "complete.json"
        q.trusted(completed, True)
        report = fresh.read_json(completed)
        q.require(report["execute"] is True and report["transactions_completed"] == 6
                  and report["plan_sha256"] == "cb29a265a72c7c0ae320119e2c652ca3ee86aceca8536117ce42eb3114771598")
    output = Path(os.path.abspath(args.output))
    q.trusted(output.parent, args.execute)
    output.mkdir(mode=0o700)
    request = {name: str(Path(getattr(args, name)).absolute()) for name in paths if name != "node"}
    request.update({name: getattr(args, name) for name in ("plan_sha256", "snapshot_sha256", "fence_sha256")})
    request.update(output=str(output), execute=False, rpcs={n: fresh.own_rpc(args.rpc_config, n) for n in fresh.NETWORKS})

    def child(value):
        result = subprocess.run([args.node, str(HERE / "run_l1_reset.cjs")], input=json.dumps(value), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "HOME": str(output)}, check=False)
        q.require(result.returncode == 0)
        report = json.loads(result.stdout)
        q.require(report.get("ok") is True)
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
        json.dump({"plan_sha256": args.plan_sha256, "snapshot_sha256": args.snapshot_sha256,
                   "fence_sha256": args.fence_sha256, "output": str(output), "status": "claimed-no-retry",
                   "runner_python_sha256": q.sha(__file__), "runner_js_sha256": q.sha(HERE / "run_l1_reset.cjs"),
                   "collector_sha256": checked["collector_sha256"]}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(ATTEMPT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    s = q.KEY.lstat()
    q.require(stat.S_ISREG(s.st_mode) and not s.st_mode & 0o027 and q.sha(q.KEY) == q.KEY_SHA)
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
        print('{"ok":false,"error":"reset gate failed; inspect public audit; never remove attempt or retry execution"}')
        raise SystemExit(1)
