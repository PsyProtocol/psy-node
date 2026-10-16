#!/usr/bin/env python3
"""Explicit opt-in role probe; one request at a time, no retries or proof requests."""
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


def probe(url):
    # Private bounded response capture; no body, URL, headers or errors enter the log.
    with tempfile.TemporaryDirectory(prefix="prove-role-") as d:
        body, headers = Path(d)/"body", Path(d)/"headers"
        result = subprocess.run([
            "curl", "--silent", "--max-time", "3", "--connect-timeout", "2",
            "--max-filesize", "65536", "--output", str(body), "--dump-header", str(headers),
            "--header", "Content-Type: application/json", "--header", "X-Psy-Probe: role-readiness",
            "--data", '{"jsonrpc":"2.0","id":1,"method":"psy_get_prove_proxy_role","params":[]}',
            "--write-out", "%{json}", url], capture_output=True, text=True, timeout=4)
        try:
            timings = json.loads(result.stdout)
        except ValueError:
            timings = {}
        out = {k: timings.get(k) for k in ("http_code", "remote_ip", "time_namelookup", "time_connect",
                                          "time_appconnect", "time_starttransfer", "time_total", "size_download")}
        out["curl_exit"] = result.returncode
        out["rpc_success"] = False
        try:
            data = json.loads(body.read_text())
            out["rpc_success"] = (data.get("jsonrpc") == "2.0" and data.get("id") == 1
                                   and isinstance(data.get("result"), dict)
                                   and data["result"].get("role") in ("user", "system", "all") and "error" not in data)
        except (OSError, ValueError, AttributeError):
            pass
        try:
            ids = re.findall(r"(?im)^x-request-id:\s*([A-Za-z0-9_.:-]{1,96})\s*$", headers.read_text())
            out["request_id"] = ids[-1] if ids else None
        except OSError:
            out["request_id"] = None
        return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--url", required=True)
    p.add_argument("--label", required=True, help="public, wireguard, or backend name; no credentials")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--samples", type=int, default=6)
    p.add_argument("--interval", type=float, default=10)
    a = p.parse_args()
    u = urlsplit(a.url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
        p.error("use an HTTP(S) endpoint without credentials, query, or fragment")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", a.label) or not 1 <= a.samples <= 8640 or not 10 <= a.interval <= 300:
        p.error("safe label, 1..8640 samples, 10..300 second interval required")
    os.umask(0o077)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("role-probe");log.setLevel(logging.INFO)
    log.addHandler(RotatingFileHandler(a.output, maxBytes=1024*1024, backupCount=3))
    failures = 0
    for n in range(a.samples):
        start = time.monotonic()
        try:
            result = probe(a.url)
        except (OSError, subprocess.TimeoutExpired):
            result = {"probe_error": True, "rpc_success": False}
        ok = result.get("http_code") == 200 and result.get("rpc_success")
        failures = 0 if ok else failures + 1
        result.update(label=a.label, epoch_s=time.time(), mono_s=start, consecutive_failures=failures,
                      alert=failures >= 3)
        log.info(json.dumps(result, separators=(",", ":")))
        if n + 1 < a.samples:
            time.sleep(max(0, a.interval - (time.monotonic() - start)))


if __name__ == "__main__":
    main()
