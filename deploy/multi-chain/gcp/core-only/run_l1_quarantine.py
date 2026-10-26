#!/usr/bin/env python3
"""Main-operated, fixed quarantine only. Default check never opens signer custody.

Run on the retained signer host. No SSH, installation, service changes or retry.
All input paths are operator supplied except the original custody and durable
attempt directory. --execute is the only signing/broadcast mode. The fixed
attempt directory must NEVER be removed to retry; partial failure needs review.
"""
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
HELPER_SHA = "258fef747d790b6c7537a428716d95b2090625c1738790cd6106c9b335bd97c9"
BUNDLE_SHA = "9b85d37a199fd385e8196973b40ffe06834bb25d05894c9555806637c7000b6f"
NODE_SHA = "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
KEY_SHA = "2a100a28748685bcba8a9abf8dd6c4e15361d6e5ec306b72b6a32e45d838c184"
KEY = Path("/var/lib/parth/.psy/keystore/bridge-relayer-dev")
PASSWORD_ENV = Path("/etc/parth/relayer.env")
ATTEMPT = Path("/var/lib/psy-l1-quarantine-20261026")


def require(value):
    if not value:
        raise ValueError("quarantine gate failed")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def trusted(path, execute=False):
    path = Path(os.path.abspath(path))
    for p in (path, *path.parents):
        s = p.lstat()
        require(not stat.S_ISLNK(s.st_mode))
        require(s.st_uid == 0 if execute else s.st_uid in (0, os.getuid()))
        # Sticky /tmp is acceptable for read-only checks, never execution.
        require(not s.st_mode & 0o022 or (not execute and p == Path("/tmp") and s.st_mode & stat.S_ISVTX))
    return path


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "node", "evidence", "plan", "snapshot", "collector", "budgets", "output"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--rpc-config", default="/etc/parth/bridge-relayer.toml")
    p.add_argument("--execute", action="store_true")
    args = p.parse_args(argv)
    require(not args.execute or os.geteuid() == 0)
    helper = trusted(HERE / "fresh_l1.py", args.execute)
    require(sha(helper) == HELPER_SHA)
    spec = importlib.util.spec_from_file_location("quarantine_fresh_l1", helper)
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    for file in ("run_l1_quarantine.py", "run_l1_quarantine.cjs", "prepare_l1_reset.cjs", "fresh_l1.cjs"):
        trusted(HERE / file, args.execute)
    for name in ("node", "bundle", "evidence", "plan", "snapshot", "collector", "budgets"):
        trusted(getattr(args, name), args.execute)
    require(sha(args.node) == NODE_SHA)
    bundle = fresh.verify_bundle(args.bundle, BUNDLE_SHA)
    if args.execute:
        # Dependencies may contain pnpm links, but all resolved bytes must be
        # root-owned and unwritable to non-root during custody use.
        for parent, dirs, files in os.walk(bundle, followlinks=False):
            for name in dirs + files:
                s = (Path(parent) / name).stat()
                require(s.st_uid == 0 and not s.st_mode & 0o022)
    output = Path(os.path.abspath(args.output))
    trusted(output.parent, args.execute)
    output.mkdir(mode=0o700)
    request = {name: str(Path(getattr(args, name)).absolute()) for name in
               ("bundle", "evidence", "plan", "snapshot", "collector", "budgets")}
    request.update(output=str(output), execute=False,
                   rpcs={n: fresh.own_rpc(args.rpc_config, n) for n in fresh.NETWORKS})
    env = {"PATH": "/usr/bin:/bin", "HOME": str(output)}

    def child(value):
        result = subprocess.run([args.node, str(HERE / "run_l1_quarantine.cjs")],
                                input=json.dumps(value), text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, check=False)
        require(result.returncode == 0)
        report = json.loads(result.stdout)
        require(report.get("ok") is True)
        return report

    checked = child(request)
    if not args.execute:
        return checked
    trusted(ATTEMPT.parent, True)
    # mkdir is the non-repeatable attempt claim, independent of output path.
    ATTEMPT.mkdir(mode=0o700)
    fd = os.open(ATTEMPT.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    with (ATTEMPT / "attempt.json").open("x") as stream:
        json.dump({"plan_sha256": checked["plan_sha256"], "output": str(output),
                   "runner_python_sha256": sha(__file__), "runner_js_sha256": sha(HERE / "run_l1_quarantine.cjs"),
                   "collector_sha256": checked["collector_sha256"], "status": "claimed-no-retry"}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(ATTEMPT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    # Retained custody is only opened after all-chain public preflight and the
    # durable attempt claim. Never copy it into staging or print child errors.
    s = KEY.lstat()
    require(stat.S_ISREG(s.st_mode) and not s.st_mode & 0o027)
    require(sha(KEY) == KEY_SHA)
    secrets = fresh.secret_env([PASSWORD_ENV])
    require(bool(secrets.get("WALLET_PASSWORD")))
    request.update(execute=True, password=secrets["WALLET_PASSWORD"], keystore=str(KEY))
    return child(request)


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception:
        print('{"ok":false,"error":"quarantine gate failed; inspect public audit; never retry an execution attempt"}')
        raise SystemExit(1)
