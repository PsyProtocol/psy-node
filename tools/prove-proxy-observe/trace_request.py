#!/usr/bin/env python3
"""Extract an allowlisted request timeline from the diagnostic JSONL files (offline)."""
import argparse
import json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("files", nargs="+")
    p.add_argument("--request-id", required=True)
    a = p.parse_args()
    rows = []
    for path in a.files:
        with open(path) as f:
            for raw in f:
                if len(raw) > 1024*1024:
                    continue
                try:
                    entry = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                if entry.get("request_id") == a.request_id:
                    row = {k: entry.get(k) for k in ("instance", "mono_ms", "event", "id", "parent_id", "kind", "method")}
                    row["detail"] = {k: entry.get("detail", {}).get(k) for k in (
                        "stage", "cache_key", "queue_ms", "elapsed_ms", "outcome", "response_bytes", "success")
                        if k in entry.get("detail", {})}
                    rows.append(row)
                if entry.get("event") == "watchdog":
                    for item in entry.get("active", []):
                        if item.get("request_id") == a.request_id:
                            row = {k: item.get(k) for k in ("id", "parent_id", "kind", "method", "stage",
                                "cache_key", "stage_ms", "age_ms", "rpc_waiter_gone")}
                            row.update(event="watchdog_active", instance=entry.get("instance"), mono_ms=entry.get("mono_ms"))
                            rows.append(row)
    for row in sorted(rows, key=lambda r: (r.get("instance") or "", r.get("mono_ms") or 0)):
        print(json.dumps(row, ensure_ascii=False))


if __name__ == "__main__":
    main()
