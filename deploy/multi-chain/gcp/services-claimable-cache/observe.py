#!/usr/bin/env python3
"""Read-only public API observation; use synthetic, unassigned claimable scope."""
import argparse
import datetime
import hashlib
import json
import statistics
import time
import urllib.error
import urllib.request
from pathlib import Path


def request(url, payload=None):
    started = time.monotonic()
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = response.read()
            return response.status, time.monotonic() - started, body
    except urllib.error.HTTPError as error:
        return error.code, time.monotonic() - started, b""
    except (OSError, TimeoutError):
        return 0, time.monotonic() - started, b""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--count", type=int, default=5)
    args = parser.parse_args()
    base = "https://services-stg.psy-protocol.xyz"
    result = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "synthetic_only": True}
    code, seconds, body = request(base + "/health/ready")
    result["health_before"] = {"status": code, "seconds": seconds, "body": json.loads(body) if body else None}
    result["routes"] = {}
    for route in ("/api/v1/wallet/private-claimable", "/api/v1/wallet/private-claimable/page"):
        samples = []
        for _ in range(args.count):
            status, duration, body = request(base + route, {"nostr_pubkeys": ["deployment-cache-observation-20261014"], "token_contract_ids": [0], "shield_addresses": [], "limit": 1})
            parsed = json.loads(body) if body else {}
            samples.append({"status": status, "seconds": duration, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "success": parsed.get("success"), "items": len(parsed.get("data", {}).get("items", []))})
        result["routes"][route] = {"samples": samples, "median_seconds": statistics.median(x["seconds"] for x in samples)}
    code, seconds, body = request(base + "/health/ready")
    result["health_after"] = {"status": code, "seconds": seconds, "body": json.loads(body) if body else None}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
