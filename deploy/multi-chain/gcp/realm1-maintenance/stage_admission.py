#!/usr/bin/env python3
"""Run an isolated, localhost-only candidate. Never edits Caddy or node units."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

EXPECTED = "f900490c353dcff2bd09b502971d5bb49034c9728c0cb29f72a1835f9aaf03b7"
UNIT = "parth-realm1-admission-candidate-v2.service"
STATE = "parth-realm1-admission-candidate-v2"
PORT = 21341
SOCKET = f"/run/{STATE}/admin.sock"


def run(*args, timeout=30):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=timeout).strip()


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def rpc(payload):
    request = urllib.request.Request(f"http://127.0.0.1:{PORT}/", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=15) as response:
        return json.load(response)


def start_candidate(binary):
    # Transient, not enabled at boot; RuntimeDirectory removes stale control sockets.
    run("systemd-run", "--unit=" + UNIT, "--service-type=exec",
        "--description=Realm1 isolated admission candidate " + EXPECTED,
        "--property=DynamicUser=yes", "--property=StateDirectory=" + STATE,
        "--property=StateDirectoryMode=0700", "--property=RuntimeDirectory=" + STATE,
        "--property=RuntimeDirectoryMode=0700", "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
        "--property=MemoryMax=1G", "--property=CPUQuota=100%", "--property=TimeoutStopSec=210s",
        "--property=IPAddressDeny=any", "--property=IPAddressAllow=localhost",
        "--property=IPAddressAllow=10.148.0.25/32", "--property=Restart=no",
        str(binary), f"--listen=127.0.0.1:{PORT}", "--upstream=http://10.148.0.25:1339/",
        f"--state-dir=/var/lib/{STATE}", "--admin-socket=" + SOCKET)


def stop_owned_candidate(binary):
    try:
        description = run("systemctl", "show", UNIT, "-p", "Description", "--value")
        command = run("systemctl", "show", UNIT, "-p", "ExecStart", "--value")
        paths = re.findall(r"(?:^|\{)\s*path=([^ ;]+)\s*;", command)
        if description != "Realm1 isolated admission candidate " + EXPECTED or paths != [str(binary)]:
            print("Candidate ownership not confirmed; cleanup requires inspection")
            return
        run("systemctl", "stop", UNIT)
    except Exception:
        print("Candidate cleanup failed; inspect this candidate unit only")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    args = p.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("sudo required")
    addresses = json.loads(run("ip", "-j", "-4", "addr"))
    if not any(a.get("local") == "10.148.0.29" for i in addresses for a in i["addr_info"]):
        raise RuntimeError("Only gcp-nostr is allowed")
    if digest(args.binary) != EXPECTED:
        raise RuntimeError("Candidate binary hash mismatch")
    if run("systemctl", "show", UNIT, "-p", "LoadState", "--value") != "not-found":
        raise RuntimeError("Candidate unit already exists; inspect rather than overwrite")
    if Path(f"/var/lib/{STATE}").exists() or Path(f"/var/lib/private/{STATE}").exists():
        raise RuntimeError("Candidate state already exists; inspect before reusing")
    release = Path("/opt/parth/realm-rpc-admission-candidates") / EXPECTED
    release.mkdir(mode=0o755, parents=True, exist_ok=False)
    binary = release / "admission"
    shutil.copyfile(args.binary, binary)
    binary.chmod(0o755)
    if digest(binary) != EXPECTED:
        raise RuntimeError("Installed binary differs")
    try:
        start_candidate(binary)
        deadline = time.monotonic() + 15
        while not Path(SOCKET).exists() and time.monotonic() < deadline:
            time.sleep(0.25)
        status = json.loads(run("curl", "--fail", "--silent", "--max-time", "5",
                                "--unix-socket", SOCKET, "http://localhost/status"))
        if status["mode"] != "closed" or status["pending_or_ambiguous"] != 0:
            raise RuntimeError("Candidate is not clean and closed")
        query = {"jsonrpc": "2.0", "id": 1, "method": "psy_get_latest_checkpoint_id", "params": []}
        blocked = {"jsonrpc": "2.0", "id": 2, "method": "psy_submit_user_end_cap", "params": []}
        response = rpc([query, blocked])
        if (len(response) != 2 or type(response[0].get("result")) is not int
                or response[1].get("error", {}).get("code") != -32098):
            raise RuntimeError("Mixed batch verification failed")
        pid = int(run("systemctl", "show", UNIT, "-p", "MainPID", "--value"))
        if not pid or digest(f"/proc/{pid}/exe") != EXPECTED:
            raise RuntimeError("Running candidate executable mismatch")
        print(json.dumps({"isolated_candidate_ready": True, "pid": pid, "sha256": EXPECTED,
                          "checkpoint": response[0]["result"], "submission_rejected": True,
                          "caddy_changed": False, "processor_changed": False,
                          "safe_to_stop_processor": False}))
    except Exception:
        stop_owned_candidate(binary)
        raise


if __name__ == "__main__":
    main()
