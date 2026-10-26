#!/usr/bin/env python3
"""Guarded Services-only binary/config update, with hash-checked rollback.

Does not change shared environment files, current links, Indexers or database.
Rollback retains only migration-disable in the added unit-specific environment.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request

UNIT = "parth-psy-services.service"
DROP = Path(f"/etc/systemd/system/{UNIT}.d/99-l1-rpc-failover-20261009.conf")
ENV = Path("/etc/parth/psy-services-rpc-20261009.env")
LOCK = "/run/psy-services-rpc-rollout.lock"
OLD_HASH = "95a29f85d00ac92ca58db471e8686112bfb29a764d1af9858f11bac8e84e362a"
INDEXERS = [f"parth-psy-indexer@{r}.service" for r in ("coordinator", "realm-0", "realm-1")]


def sha(path):
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()


def pid(unit=UNIT):
    return run("systemctl", "show", unit, "-p", "MainPID", "--value")


def live():
    current = pid()
    assert current != "0", "service has no PID"
    executable = Path(f"/proc/{current}/exe")
    result = {"pid": current, "exe": str(executable.resolve()), "binary_sha256": sha(executable)}
    assert pid() == current, "process changed during snapshot"
    return result


def read_environment(current):
    return dict(item.split("=", 1) for item in Path(f"/proc/{current}/environ").read_bytes().decode().split("\0") if "=" in item)


def env_text(values):
    # systemd EnvironmentFile double quoting, not shell substitution.
    return "".join(f"{key}={json.dumps(value, ensure_ascii=True)}\n" for key, value in values.items())


def new_chains(original, profiles):
    chains = json.loads(json.dumps(original))
    assert sorted(c["chain_index"] for c in chains) == [0, 1, 2]
    assert set(profiles) == {"0", "1", "2"}
    for chain in chains:
        index = chain["chain_index"]
        assert chain["chain_id"] == {0: 11155111, 1: 97, 2: 84532}[index]
        providers = profiles[str(index)]
        assert len(providers) == (3 if index < 2 else 2)
        assert len({p["name"] for p in providers}) == len(providers)
        for provider in providers:
            assert set(provider) == {"name", "url", "operator", "quota_group"}
            assert all(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", provider[k]) for k in ("name", "operator", "quota_group"))
            assert "\n" not in provider["url"] and "\r" not in provider["url"]
        if index < 2:
            assert providers[0]["url"] == f"http://10.148.0.32:{28545 if index == 0 else 28645}"
        for provider in providers[1:] if index < 2 else providers:
            from urllib.parse import urlsplit
            url = urlsplit(provider["url"])
            assert url.scheme == "https" and url.hostname == {0: "eth-sepolia.g.alchemy.com", 1: "bnb-testnet.g.alchemy.com", 2: "base-sepolia.g.alchemy.com"}[index]
            assert not url.username and not url.password and not url.fragment
        chain["rpc_providers"] = providers
        chain["rpc_policy"] = dict(connect_timeout_ms=1000, attempt_timeout_ms=2000,
            operation_timeout_ms=6000, max_attempts=3, cooldown_ms=30000,
            missing_ttl_ms=15000, freshness_cache_ms=5000,
            max_head_age_secs=120 if index == 0 else 30)
    return chains


def unchanged(hashes):
    assert all(sha(path) == digest for path, digest in hashes.items()), "protected file changed"


def ready(expected_hash, seconds=90):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            observed = live()
            assert observed["binary_sha256"] == expected_hash
            with urllib.request.urlopen("http://127.0.0.1:3000/health", timeout=3) as response:
                assert response.status == 200
            return observed
        except (AssertionError, OSError, subprocess.SubprocessError):
            time.sleep(2)
    raise RuntimeError("readiness or running hash check failed")


def rollback(state):
    unchanged(state["protected"])
    assert sha(DROP) == state["drop_sha256"] and sha(ENV) == state["env_sha256"], "rollout files changed; operator recovery required"
    if pid() != "0":
        current = live()
        assert current["binary_sha256"] in (state["new_hash"], OLD_HASH), "unexpected third-party binary"
    assert sha(state["old"]["exe"]) == OLD_HASH
    # Restore the old binary/provider settings from the original environment,
    # but never let the launcher's default re-enable migrations on rollback.
    with tempfile.NamedTemporaryFile(mode="w", dir=ENV.parent, delete=False) as file:
        file.write("PSY_SERVICES_RUN_MIGRATIONS=false\n")
        file.flush()
        os.fsync(file.fileno())
        replacement = Path(file.name)
    replacement.chmod(0o600)
    replacement.replace(ENV)
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", UNIT)
    return ready(OLD_HASH)


def activate(args):
    baseline = json.loads(Path(args.baseline).read_text())
    old = live()
    assert old["binary_sha256"] == OLD_HASH == baseline["binary_sha256"]
    assert old["pid"] == baseline["MainPID"] and old["exe"] == baseline["exe"], "baseline changed"
    protected = baseline["protected_file_sha256"]
    unchanged(protected)
    assert run("systemctl", "show", UNIT, "-p", "DropInPaths", "--value") == baseline["DropInPaths"], "unit overrides changed"
    assert not DROP.exists() and not ENV.exists(), "rollout already exists; inspect before reapply"
    manifest = json.loads(Path(args.manifest).read_text())
    for key in ("source_commit", "pool_commit"):
        assert re.fullmatch(r"[0-9a-f]{40}", manifest[key])
    new_hash = manifest["binary_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", new_hash) and sha(args.binary) == new_hash
    assert manifest["protocol_node_commit"] == "e68ccc034f4cdd3580913bd2245456ecbdc711a4"
    assert manifest["local_overrides"] is False
    env = read_environment(old["pid"])
    chains = new_chains(json.loads(env["PSY_L1_CHAINS"]), json.loads(Path(args.providers).read_text()))
    others = {unit: pid(unit) for unit in INDEXERS}
    assert all(value != "0" for value in others.values()), "indexer not running before rollout"
    root = Path("/opt/parth/psy-services/releases") / f"20261009-rpc-{manifest['source_commit'][:12]}-{new_hash[:12]}"
    assert not root.exists(), "release exists; inspect instead of overwriting"
    root.mkdir(mode=0o755)
    (root / "target/release").mkdir(parents=True)
    for directory in (root, root / "target", root / "target/release"):
        directory.chmod(0o755)
    shutil.copyfile(args.binary, root / "target/release/psy-services")
    (root / "target/release/psy-services").chmod(0o755)
    assert sha(root / "target/release/psy-services") == new_hash
    old_home = Path(old["exe"]).parents[2]
    for directory in ("migrations", "genesis_contracts"):
        if (old_home / directory).is_dir():
            shutil.copytree(old_home / directory, root / directory)
    (root / "BUILD-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    backup = Path("/var/lib/parth/services-rpc-rollout") / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup.mkdir(parents=True, mode=0o700)
    backup.chmod(0o700)
    for index, path in enumerate(protected):
        shutil.copy2(path, backup / f"protected-{index}")
    (backup / "unit.txt").write_text(run("systemctl", "cat", UNIT))
    candidate = env_text({"PSY_L1_CHAINS": json.dumps(chains, separators=(",", ":")),
        "PSY_SERVICES_HOME": str(root), "PSY_SERVICES_TARGET_DIR": str(root / "target"),
        "PSY_SERVICES_MIGRATIONS_PATH": str(root / "migrations"), "PSY_SERVICES_RUN_MIGRATIONS": "false"})
    drop = f"[Service]\nEnvironmentFile={ENV}\n"
    unchanged(protected)
    assert live() == old, "running service changed before activation"
    assert run("systemctl", "show", UNIT, "-p", "DropInPaths", "--value") == baseline["DropInPaths"]
    with ENV.open("x") as file:
        file.write(candidate)
    ENV.chmod(0o600)
    DROP.parent.mkdir(exist_ok=True)
    with DROP.open("x") as file:
        file.write(drop)
    DROP.chmod(0o644)
    state = dict(old=old, new_hash=new_hash, protected=protected, indexer_pids=others,
                 drop_sha256=sha(DROP), env_sha256=sha(ENV))
    state_path = backup / "state.json"
    state_path.write_text(json.dumps(state, indent=2) + "\n")
    try:
        run("systemctl", "daemon-reload")
        assert set(run("systemctl", "show", UNIT, "-p", "DropInPaths", "--value").split()) == set(baseline["DropInPaths"].split()) | {str(DROP)}
        run("systemctl", "restart", UNIT)
        observed = ready(new_hash)
        assert json.loads(read_environment(observed["pid"])["PSY_L1_CHAINS"]) == chains
        assert {unit: pid(unit) for unit in INDEXERS} == others, "indexer PID changed"
        unchanged(protected)
        print(json.dumps(dict(status="ready", **observed, rollback_state=str(state_path))))
    except Exception:
        print(json.dumps(dict(status="activation_failed", rollback_state=str(state_path))), flush=True)
        restored = rollback(state)
        print(json.dumps(dict(status="rolled_back", **restored)), flush=True)
        raise RuntimeError("activation failed; rolled back") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    activate_parser = sub.add_parser("activate")
    for name in ("baseline", "manifest", "binary", "providers"):
        activate_parser.add_argument("--" + name, required=True)
    revert = sub.add_parser("rollback")
    revert.add_argument("state")
    args = parser.parse_args()
    assert os.geteuid() == 0, "root required"
    os.umask(0o077)
    with open(LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "activate":
            activate(args)
        else:
            print(json.dumps(rollback(json.loads(Path(args.state).read_text()))))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Avoid leaking configuration or subprocess stderr containing credentials.
        print(json.dumps(dict(status="stopped", failure_class=type(error).__name__)))
        raise SystemExit(1)
