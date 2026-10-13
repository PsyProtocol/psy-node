#!/usr/bin/env python3
"""Prepare a closed gate without changing public ingress; activate separately."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import subprocess
import time
import urllib.request

SHA = "d2739378a269547ad2ef9eb3ba1baa68d8115fef09c3f80d6e7b0494576bc83a"
ROOT = Path("/opt/parth/realm1-maintenance-20261013")
AUDIT = Path("/var/lib/parth-realm1-maintenance-audit")
CADDYFILE = Path("/opt/nostr-relay/Caddyfile")
SHARED = Path("/opt/nostr-relay/caddy_config/realm1-maintenance-20261013")
GATE = "parth-realm1-admission.service"
POOL = "parth-realm1-edge-pool.service"
SOCKET = "/run/parth-realm1-admission/admin.sock"
HOSTS = {"realm1-stg.psy-protocol.xyz", "realm1.psy-protocol.xyz"}
UPSTREAMS = ["10.148.0.25:1339", "10.148.0.36:1339", "10.148.0.35:1339"]


def run(*args, input=None, timeout=30):
    return subprocess.check_output(args, input=input, text=True, stderr=subprocess.PIPE, timeout=timeout).strip()


def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def save(path, value, mode=0o600):
    data = value if isinstance(value, str) else json.dumps(value, indent=2) + "\n"
    if path.is_symlink():
        raise RuntimeError("refusing symlink destination")
    original = path.stat() if path.exists() else None
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            if original is not None:
                os.fchown(f.fileno(), original.st_uid, original.st_gid)
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def live():
    return json.loads(run("docker", "exec", "nostr-caddy", "wget", "-qO-", "http://127.0.0.1:2019/config/"))


def proxies(value):
    if isinstance(value, dict):
        if value.get("handler") == "reverse_proxy":
            yield value
        for item in value.values():
            yield from proxies(item)
    elif isinstance(value, list):
        for item in value:
            yield from proxies(item)


def realm_routes(config):
    found = set()
    routes = []
    for server in config["apps"]["http"]["servers"].values():
        for route in server.get("routes", []):
            hosts = {h for m in route.get("match", []) for h in m.get("host", [])}
            if hosts & HOSTS:
                if not hosts <= HOSTS or found & hosts:
                    raise RuntimeError("ambiguous Realm1 route")
                found |= hosts
                routes.append(route)
    if found != HOSTS:
        raise RuntimeError("both Realm1 aliases must exist")
    return routes


def render(config):
    candidate = copy.deepcopy(config)
    pool = None
    for route in realm_routes(candidate):
        handlers = list(proxies(route))
        if len(handlers) != 1 or [u["dial"] for u in handlers[0]["upstreams"]] != UPSTREAMS:
            raise RuntimeError("unexpected original Realm1 pool")
        p = handlers[0]
        if pool is not None and pool != p:
            raise RuntimeError("Realm1 alias pools differ")
        pool = copy.deepcopy(p)
        p["upstreams"] = [{"dial": "10.148.0.29:21340"}]
    backend = {"admin": {"disabled": True}, "apps": {"http": {"servers": {
        "realm1_private": {"listen": ["127.0.0.1:21342"], "routes": [{"handle": [pool]}]}
    }}}}
    return candidate, backend


def normalize(config):
    result = copy.deepcopy(config)
    def visit(v):
        if isinstance(v, dict):
            if v.get("handler") == "file_server":
                hides = v.get("hide", [])
                allowed = {"./-", "/dev/stdin", "/etc/caddy/Caddyfile",
                           "/config/realm1-maintenance-20261013/Caddyfile"}
                v["hide"] = ["AUTO_CONFIG_PATH" if h in allowed else h for h in hides]
            for child in v.values():
                visit(child)
        elif isinstance(v, list):
            for child in v:
                visit(child)
    visit(result)
    return result


def adapt(text):
    return json.loads(run("docker", "exec", "-i", "nostr-caddy", "caddy", "adapt",
                          "--config", "/dev/stdin", "--adapter", "caddyfile", input=text))


def rpc(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=15) as response:
        return json.load(response)


def query():
    return {"jsonrpc": "2.0", "id": 1, "method": "psy_get_latest_checkpoint_id", "params": []}


def status():
    return json.loads(run("curl", "--fail", "--silent", "--max-time", "10", "--unix-socket", SOCKET, "http://localhost/status"))


def unit(binary, args, private_pool=False):
    name = "parth-realm1-edge-pool" if private_pool else "parth-realm1-admission"
    allowed = ["localhost", "10.148.0.25/32", "10.148.0.35/32", "10.148.0.36/32"] if private_pool else ["localhost", "10.148.0.29/32", "10.148.0.32/32", "172.18.0.0/16"]
    return f"""[Unit]
Description=Realm1 maintenance {'private Edge pool' if private_pool else 'admission'} 20261013
After=network-online.target
Wants=network-online.target
[Service]
Type=exec
DynamicUser=yes
StateDirectory={name}
StateDirectoryMode=0700
RuntimeDirectory={name}
RuntimeDirectoryMode=0700
Environment=HOME=/run/{name}
Environment=GOMEMLIMIT={'192MiB' if private_pool else '768MiB'}
ExecStart={binary} {args}
Restart=on-failure
RestartSec=3
TimeoutStopSec=210
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax={'256M' if private_pool else '1G'}
CPUQuota=100%
IPAddressDeny=any
""" + "".join(f"IPAddressAllow={x}\n" for x in allowed) + "[Install]\nWantedBy=multi-user.target\n"


def prepare(binary):
    if ROOT.exists() or AUDIT.exists() or SHARED.exists():
        raise RuntimeError("preparation exists; inspect instead of overwriting")
    for service in (GATE, POOL):
        if run("systemctl", "show", service, "-p", "LoadState", "--value") != "not-found":
            raise RuntimeError("unit already exists")
    if sha(binary) != SHA:
        raise RuntimeError("binary hash mismatch")
    before = live()
    original = CADDYFILE.read_text()
    if normalize(adapt(original)) != normalize(before):
        raise RuntimeError("host Caddyfile differs from live config; do not overwrite")
    candidate, backend = render(before)
    needle = "reverse_proxy " + " ".join(UPSTREAMS)
    if original.count(needle) != 2:
        raise RuntimeError("unexpected Caddyfile Realm1 pool count")
    candidate_text = original.replace(needle, "reverse_proxy 10.148.0.29:21340")
    if normalize(adapt(candidate_text)) != normalize(candidate):
        raise RuntimeError("candidate changes unrelated routes")
    ROOT.mkdir(mode=0o755)
    AUDIT.mkdir(mode=0o700)
    SHARED.mkdir(mode=0o700)
    save(AUDIT / "original.json", before)
    save(AUDIT / "original.Caddyfile", original)
    save(AUDIT / "candidate.json", candidate)
    save(AUDIT / "candidate.Caddyfile", candidate_text)
    save(SHARED / "candidate.json", candidate)
    save(ROOT / "backend.json", backend, 0o644)
    shutil.copyfile(binary, ROOT / "admission")
    (ROOT / "admission").chmod(0o755)
    run("docker", "cp", "nostr-caddy:/usr/bin/caddy", str(ROOT / "caddy"))
    (ROOT / "caddy").chmod(0o755)
    run(str(ROOT / "caddy"), "validate", "--config", str(ROOT / "backend.json"))
    run("docker", "exec", "nostr-caddy", "caddy", "validate", "--config", "/config/realm1-maintenance-20261013/candidate.json")
    save(Path("/etc/systemd/system") / POOL, unit(ROOT / "caddy", f"run --config {ROOT}/backend.json", True), 0o644)
    args = "--listen=10.148.0.29:21340 --upstream=http://127.0.0.1:21342/ --state-dir=/var/lib/parth-realm1-admission --admin-socket=" + SOCKET
    save(Path("/etc/systemd/system") / GATE, unit(ROOT / "admission", args), 0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", POOL, GATE)
    for attempt in range(30):
        try:
            s = status()
            if s["mode"] != "closed" or s["active_submissions"] or s["pending_or_ambiguous"]:
                raise RuntimeError("gate not clean and closed")
            payload = [query(), {"jsonrpc": "2.0", "id": 2, "method": "psy_submit_user_end_cap", "params": []}]
            values = rpc("http://10.148.0.29:21340/", payload)
            if type(values[0].get("result")) is not int or values[1].get("error", {}).get("code") != -32098:
                raise RuntimeError("mixed batch failed")
            break
        except Exception:
            if attempt == 29:
                raise
            time.sleep(1)
    pid = int(run("systemctl", "show", GATE, "-p", "MainPID", "--value"))
    if sha(f"/proc/{pid}/exe") != SHA or live() != before:
        raise RuntimeError("runtime or unchanged public config check failed")
    save(AUDIT / "prepared.json", {"binary_sha256": SHA, "pid": pid, "checkpoint": values[0]["result"], "public_changed": False})
    print(json.dumps({"prepared": True, "gate_pid": pid, "closed_private_smoke": True, "public_changed": False}))


def activate():
    if not (AUDIT / "prepared.json").exists() or (AUDIT / "activated.json").exists():
        raise RuntimeError("requires fresh verified preparation")
    before = json.loads((AUDIT / "original.json").read_text())
    if live() != before or CADDYFILE.read_text() != (AUDIT / "original.Caddyfile").read_text():
        raise RuntimeError("Caddy changed since preparation")
    s = status()
    if s["mode"] != "closed" or s["active_submissions"] or s["pending_or_ambiguous"] or s.get("persistence_uncertain"):
        raise RuntimeError("gate is not clean and closed")
    pid = int(run("systemctl", "show", GATE, "-p", "MainPID", "--value"))
    if sha(f"/proc/{pid}/exe") != SHA:
        raise RuntimeError("running gate changed")
    # Persist the restart source before reloading. Never automatically reopen on error.
    save(CADDYFILE, (AUDIT / "candidate.Caddyfile").read_text(), 0o644)
    run("docker", "exec", "nostr-caddy", "caddy", "reload", "--config", "/config/realm1-maintenance-20261013/candidate.json")
    candidate = json.loads((AUDIT / "candidate.json").read_text())
    if live() != candidate:
        raise RuntimeError("live Caddy candidate mismatch; leave gate closed and inspect")
    save(AUDIT / "activated.json", {"utc_unix": time.time(), "mode": "closed", "processor_stopped": False})
    print(json.dumps({"public_realm1_admission": "closed", "queries_enabled": True, "processor_stopped": False,
                      "wireguard_not_yet_gated": True, "safe_to_stop_processor": False}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["prepare", "activate", "status"])
    p.add_argument("--binary", type=Path)
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error("sudo required")
    addresses = json.loads(run("ip", "-j", "-4", "addr"))
    if not any(a.get("local") == "10.148.0.29" for i in addresses for a in i["addr_info"]):
        p.error("only gcp-nostr is allowed")
    if args.action == "prepare":
        if not args.binary:
            p.error("--binary required")
        prepare(args.binary)
    elif args.action == "activate":
        activate()
    else:
        print(json.dumps(status()))


if __name__ == "__main__":
    main()
