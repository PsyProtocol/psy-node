#!/usr/bin/env python3
"""Read-only local Envio metrics samples; no credentials or event payloads."""
import argparse
import datetime
import json
from pathlib import Path
import re
import time
import urllib.request

METRICS = {"envio_source_get_height_duration_count", "envio_source_height",
           "chain_block_height_fully_fetched", "envio_progress_block_number",
           "envio_progress_events_count", "envio_progress_latency"}


def sample():
    with urllib.request.urlopen("http://127.0.0.1:9898/metrics", timeout=10) as r:
        text = r.read().decode()
    rows = {}
    for line in text.splitlines():
        m = re.fullmatch(r'([a-z_]+)\{([^}]*)\} ([0-9.eE+-]+)', line)
        if not m or m[1] not in METRICS:
            continue
        chain = re.search(r'chainId="(\d+)"', m[2])
        if chain:
            values = rows.setdefault(chain[1], {})
            values[m[1]] = values.get(m[1], 0) + float(m[3])
    return {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "chains": rows}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--seconds", type=int, default=120)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    first = sample()
    start = time.monotonic()
    time.sleep(a.seconds)
    last = sample()
    elapsed = time.monotonic() - start
    rates = {}
    for chain, values in first["chains"].items():
        delta = last["chains"][chain]["envio_source_get_height_duration_count"] - values["envio_source_get_height_duration_count"]
        if delta < 0:
            raise RuntimeError("Indexer restarted during sample; rerun")
        rates[chain] = {"height_requests": delta, "requests_per_minute": delta / elapsed * 60}
    result = {"elapsed_s": elapsed, "first": first, "last": last, "rates": rates}
    if a.output:
        a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
