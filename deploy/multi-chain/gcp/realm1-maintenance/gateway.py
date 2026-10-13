#!/usr/bin/env python3
"""Route only the existing Realm1 WireGuard relay through the admission gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

UNIT = "parth-offsite-prove-rpc-realm1.service"
SOCKET = "parth-offsite-prove-rpc-realm1.socket"
ROOT = Path("/var/lib/parth-realm1-gateway-20261013")
DROP = Path("/etc/systemd/system") / (UNIT + ".d") / "90-admission-20261013.conf"
OLD = "/lib/systemd/systemd-socket-proxyd 10.148.0.25:1339"
NEW = "/lib/systemd/systemd-socket-proxyd 10.148.0.29:21340"
CONTENT = "[Service]\nExecStart=\nExecStart=" + NEW + "\n"


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=45).strip()


def gate_check(url="http://10.148.0.29:21340/"):
    payload = [{"jsonrpc": "2.0", "id": 1, "method": "psy_get_latest_checkpoint_id", "params": []},
               {"jsonrpc": "2.0", "id": 2, "method": "psy_submit_user_end_cap", "params": []},
               {"jsonrpc": "2.0", "id": 3, "method": "psy_submit_user_end_cap_batch", "params": []}]
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=15) as response:
        result = json.load(response)
    if not isinstance(result, list) or len(result) != 3:
        raise RuntimeError("unexpected gate response")
    replies = {r["id"]: r for r in result}
    if type(replies.get(1, {}).get("result")) is not int or any(
            replies.get(n, {}).get("error", {}).get("code") != -32098 for n in (2, 3)):
        raise RuntimeError("gate must allow reads and deny both submission methods")


def identity():
    if os.geteuid() != 0:
        raise RuntimeError("sudo required")
    addresses = json.loads(run("ip", "-j", "-4", "addr"))
    if not any(a.get("local") == "10.148.0.32" for i in addresses for a in i["addr_info"]):
        raise RuntimeError("only gcp-gateway")
    if run("systemctl", "is-active", SOCKET) != "active":
        raise RuntimeError("existing socket is not active")
    socket_text = run("systemctl", "cat", SOCKET)
    if "ListenStream=10.250.0.1:11339" not in socket_text:
        raise RuntimeError("unexpected existing socket")
    return socket_text


def save_new(path, value):
    with path.open("x") as file:
        os.fchmod(file.fileno(), 0o600)
        json.dump(value, file, indent=2)
        file.flush()
        os.fsync(file.fileno())


def prepare():
    socket_text = identity()
    if ROOT.exists() or DROP.exists():
        raise RuntimeError("preparation exists; inspect, do not overwrite")
    before = run("systemctl", "cat", UNIT)
    if run("systemctl", "show", UNIT, "-p", "DropInPaths", "--value") or "ExecStart=" + OLD not in before:
        raise RuntimeError("unexpected original relay configuration")
    gate_check()
    ROOT.mkdir(mode=0o700)
    save_new(ROOT / "prepared.json", dict(service=before, socket=socket_text, proposed=CONTENT,
                                         existing_pid=run("systemctl", "show", UNIT, "-p", "MainPID", "--value")))
    print(json.dumps(dict(prepared=True, live_changed=False, connection_reconnect_required=True)))


def activate():
    socket_text = identity()
    if DROP.exists() or (ROOT / "activated.json").exists():
        raise RuntimeError("activation already attempted; inspect instead of repeating")
    before = json.loads((ROOT / "prepared.json").read_text())
    if before["service"] != run("systemctl", "cat", UNIT) or before["socket"] != socket_text or before["proposed"] != CONTENT:
        raise RuntimeError("configuration changed since preparation")
    gate_check()
    DROP.parent.mkdir(mode=0o755, exist_ok=True)
    fd, candidate = tempfile.mkstemp(prefix=".admission-", dir=DROP.parent)
    try:
        with os.fdopen(fd, "w") as file:
            os.fchmod(file.fileno(), 0o644)
            file.write(CONTENT)
            file.flush()
            os.fsync(file.fileno())
        os.replace(candidate, DROP)
        directory = os.open(DROP.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(candidate).unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", UNIT)
    if run("systemctl", "is-active", UNIT) != "active":
        raise RuntimeError("relay did not become active; inspect, no automatic bypass")
    pid = run("systemctl", "show", UNIT, "-p", "MainPID", "--value")
    argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    if argv[:2] != [b"/lib/systemd/systemd-socket-proxyd", b"10.148.0.29:21340"]:
        raise RuntimeError("running relay destination mismatch")
    gate_check("http://10.250.0.1:11339/")
    save_new(ROOT / "activated.json", dict(time=time.time(), pid=pid, dropin_sha256=hashlib.sha256(DROP.read_bytes()).hexdigest()))
    print(json.dumps(dict(wireguard_realm1_gated=True, socket_unchanged=True, pid=pid, safe_to_stop_processor=False)))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "activate"])
    args = parser.parse_args()
    globals()[args.action]()


if __name__ == "__main__":
    main()
