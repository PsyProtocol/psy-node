#!/usr/bin/env python3
"""Root-local signer activation using the exact installed operator spec.

--release-lock FILE --release-lock-sha256 SHA --role guardian|relayer --spec FILE --spec-sha256 SHA [--apply]
--release-lock FILE --release-lock-sha256 SHA --role guardian-readiness --rpc-config FILE --rpc-config-sha256 SHA
Without --apply, validate only. Start Guardians first; Relayer additionally
requires all three Guardian readiness responses and Services /health/ready.
guardian-readiness only asks the three Guardians; run it on the Relayer host to prove they are reachable
from there. The sibling installers are executed only when their bytes match the lock's tool_sha256.
No SSH, reset-failed, DB changes, key generation or automatic rollback. Starting
Relayer authorizes its normal daemon work, including L1 broadcasts; --apply must
therefore be an explicit operator decision, not part of L1 preparation.
Health checks do not attest peer artifact identity or checkpoint progress.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import time
import types
import urllib.request


g = types.ModuleType("install_guardian")
r = types.ModuleType("install_relayer")


def helper(name, digest):
    path = Path(__file__).with_name(name + ".py")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise SystemExit("reviewed signer installer hash mismatch")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def read_release_lock(path, expected_sha256):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise SystemExit("release lock hash mismatch")
    return json.loads(raw)


def load_helpers(lock):
    """Bind the sibling installers (g, r) once their bytes match the lock; r shares g's checked helpers."""
    global g, r
    g = helper("install_guardian", lock["tool_sha256"]["install_guardian.py"])
    r = helper("install_relayer", lock["tool_sha256"]["install_relayer.py"])
    r.g = g


def show(name):
    raw = g.command(["systemctl", "show", name,
                     "--property=Id,LoadState,ActiveState,MainPID,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,Job"])
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def process(name, binary, digest):
    before = show(name)
    pid = before.get("MainPID", "0")
    g.require(before.get("ActiveState") == "active" and pid.isdigit() and int(pid) > 0, "signer not active with PID")
    exe = Path("/proc") / pid / "exe"
    g.require(os.readlink(exe) == str(binary), "unexpected signer executable")
    with exe.open("rb") as stream:
        g.require(hashlib.file_digest(stream, "sha256").hexdigest() == digest, "signer executable hash mismatch")
    after = show(name)
    g.require(after.get("MainPID") == pid and after.get("ActiveState") == "active", "signer PID changed during check")
    return int(pid)


def context(role, spec_path, spec_hash, lock):
    g.require(os.geteuid() == 0 and role in ("guardian", "relayer"), "root and explicit signer role required")
    signer = (g if role == "guardian" else r).load_release(lock)
    loaded = (g if role == "guardian" else r).load_plan(spec_path, spec_hash, signer)
    spec, files = loaded[:2]
    g.require(spec["l1_documents"], "fresh three-chain L1 documents pending")
    network = g.decode(files["rpc.json"])["networks"]["testnet"]
    if role == "guardian":
        ident = spec["guardian_id"]
        release, state = signer.releases / f"guardian-{ident}", signer.states / f"guardian-{ident}"
        unit = signer.unit_name(ident)
        old = g.guardian_unit_names()
        required, static = set(), {f"psy-guardian-{i}.service" for i in (1, 2, 3)}
    else:
        release, state, unit = signer.release, signer.state, signer.unit
        old = r.relayer_unit_names()
        required, static = set(), set()
    return spec, files, network, release, state, unit, [n for n in old if n != unit], required, static, signer


def preflight(role, data):
    spec, files, network, release, state, unit, old, required, static, signer = data
    g.require(socket.gethostname() == spec["hostname"] and os.uname().machine == "x86_64", "wrong signer host")
    addresses = json.loads(g.command(["ip", "-j", "-4", "address", "show"]))
    g.require(any(a.get("local") == spec["address"] for i in addresses for a in i.get("addr_info", [])), "signer address mismatch")
    g.inactive_units(old, required, static)
    account = pwd.getpwnam(spec["service_user"])
    g.require(account.pw_uid > 0 and account.pw_gid > 0, "non-root signer account required")
    for path in (release, state, *release.parents, *state.parents):
        g.trusted_directory(path)
    for name, expected in files.items():
        path = release / name
        for parent in path.parents:
            g.trusted_directory(parent)
        g.require(g.read(path, private=name == "operator.json", uid=0, limit=max(len(expected), 1)) == expected,
                  "installed signer artifact mismatch")
        info = path.stat()
        g.require(info.st_uid == 0 and not info.st_mode & 0o022, "installed artifact writable or non-root")
    installer = g if role == "guardian" else r
    unit_path = installer.UNITS / unit
    g.trusted_directory(unit_path.parent)
    g.require(g.read(unit_path) == installer.unit(spec, signer), "installed signer unit mismatch")
    info = unit_path.stat()
    g.require(info.st_uid == 0 and not info.st_mode & 0o022, "unsafe signer unit ownership/mode")
    value = show(unit)
    g.require(value.get("Id") == unit and value.get("LoadState") == "loaded" and value.get("Job") == ""
              and value.get("FragmentPath") == str(unit_path) and value.get("DropInPaths") == ""
              and value.get("NeedDaemonReload") == "no", "signer unit override, reload or job conflict")
    key = release / "home/.psy/keystore" / (f"guardian-{spec['guardian_id']}.keystore.json" if role == "guardian" else "bridge-relayer.keystore.json")
    expected_key = spec["custody_keystore_sha256"] if role == "guardian" else spec["l1_keystore"]["sha256"]
    g.require(g.digest(g.read(key, private=True, uid=account.pw_uid, limit=65536)) == expected_key, "installed encrypted keystore mismatch")
    if role == "guardian":
        custody = signer.custody / f"guardian-{spec['guardian_id']}"
        public = g.decode(g.read(custody / "public.json", private=True, uid=0))
        g.require(public["node_source"] == signer.key_source and public["guardian_id"] == spec["guardian_id"]
                  and g.commitment(public["public_key_hash"]) == g.commitment(network["guardian_initial_member_hashes"][spec["guardian_id"] - 1]), "retained Guardian identity mismatch")
        g.read(custody / f"psy-guardian-{spec['guardian_id']}-password.cred", private=True, uid=0, limit=65536)
    else:
        credential = g.read(signer.credentials / "l1-password.cred", private=True, uid=0, limit=65536)
        g.require(g.digest(credential) == spec["password_credential"]["sha256"], "installed encrypted credential mismatch")
    active = value.get("ActiveState") == "active"
    if active:
        process(unit, release / "psy_relayer_cli", spec["binary"]["sha256"])
    else:
        g.require(value.get("ActiveState") == "inactive" and value.get("MainPID") == "0", "signer not stopped or already active")
    return active


def get_json(origin, path):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    url = origin.rstrip("/") + path
    with opener.open(url, timeout=10) as response:
        g.require(response.status == 200 and response.url == url, "dependency HTTP status/redirect mismatch")
        raw = response.read(65537)
    g.require(len(raw) <= 65536, "dependency response too large")
    return g.decode(raw)


def guardians_ready(network):
    for guardian in network["guardian_configs"]:
        origin = guardian.get("rpc_url") or "http://" + guardian["listen_address"]
        value = get_json(origin, "/v1/ready")
        magic = value.get("network_magic")
        g.require(type(magic) is int or (type(magic) is str and re.fullmatch(r"[0-9]{1,20}", magic)),
                  "Guardian network magic must be an integer or ASCII decimal string")
        g.require(value.get("schema_version") == 3 and value.get("user_id") == 524288
                  and int(magic) == int(network["magic"], 16)
                  and value.get("runtime_initialized") is True and value.get("halted") is False, "Guardian not ready for configured bridge account")


def services_ready(files, signer):
    daemon = r.validate_daemon(files["daemon.toml"], signer)
    value = get_json(daemon["services_url"], "/health/ready")
    g.require(value.get("status") == "ready" and all(value.get("details", {}).get(k, {}).get("status") == "healthy"
                                                     for k in ("database", "cache")), "Services dependencies not ready")


def dependencies(data):
    files, network, signer = data[1], data[2], data[9]
    guardians_ready(network)
    services_ready(files, signer)


def readiness(rpc_path, rpc_sha256):
    """Ask the three Guardians from this host; the RPC config is the one the Guardians were installed with."""
    raw = g.read(g.path_value(str(rpc_path)))
    g.require(g.digest(raw) == g.pin(rpc_sha256), "rpc config hash mismatch")
    network = g.decode(raw)["networks"]["testnet"]
    guardians_ready(network)
    return {"role": "guardian-readiness", "guardians_ready": len(network["guardian_configs"])}


def activate(role, spec_path, spec_hash, lock, apply=False):
    data = context(role, spec_path, spec_hash, lock)
    spec, _, _, release, _, unit, *_ = data
    active = preflight(role, data)
    if role == "relayer":
        dependencies(data)
    pid = None
    if apply:
        active = preflight(role, data)
        g.command(["systemctl", "enable", *([] if active else ["--now"]), unit])
        deadline = time.monotonic() + 15
        while True:
            try:
                pid = process(unit, release / "psy_relayer_cli", spec["binary"]["sha256"])
                break
            except (ValueError, FileNotFoundError, ProcessLookupError):
                if active or time.monotonic() >= deadline or show(unit).get("ActiveState") not in ("active", "activating"):
                    raise
                time.sleep(0.25)
        g.require(show(unit).get("UnitFileState") == "enabled", "signer not enabled")
    return {"role": role, "unit": unit, "started": apply, "already_active": active, "pid": pid,
            "mode": "started" if apply else "checked_not_started", "checkpoint_progress_verified": False,
            "l1_finalization_verified": False, "deployment_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--release-lock-sha256", required=True)
    parser.add_argument("--role", choices=("guardian", "relayer", "guardian-readiness"), required=True)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--spec-sha256")
    parser.add_argument("--rpc-config", type=Path)
    parser.add_argument("--rpc-config-sha256")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        lock = read_release_lock(args.release_lock, args.release_lock_sha256)
        load_helpers(lock)
        if args.role == "guardian-readiness":
            g.require(args.rpc_config and args.rpc_config_sha256 and not (args.spec or args.spec_sha256 or args.apply),
                      "readiness takes the RPC config and its hash only")
            print(json.dumps(readiness(args.rpc_config, args.rpc_config_sha256), sort_keys=True))
            return
        g.require(args.spec and args.spec_sha256 and not (args.rpc_config or args.rpc_config_sha256),
                  "signer activation takes the spec and its hash only")
        print(json.dumps(activate(args.role, args.spec, args.spec_sha256, lock, args.apply), sort_keys=True))
    except Exception as error:
        detail = str(error) if type(error) is ValueError else type(error).__name__
        raise SystemExit("Bridge activation failed: " + detail + "; no rollback; inspect selected unit") from None


if __name__ == "__main__":
    main()
