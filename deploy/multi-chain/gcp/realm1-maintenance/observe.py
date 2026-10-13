#!/usr/bin/env python3
"""Read-only migration observations. Never authorizes stopping a Processor."""
import argparse
from datetime import datetime, timezone
import json
import shlex
import subprocess
import time


def remote(host, *args):
    return subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host,
         shlex.join(args)], text=True, timeout=30)


def heights():
    result = {}
    for name, port in [("coordinator", 1337), ("realm0", 1338), ("realm1", 1339)]:
        try:
            body = json.loads(remote("gcp-cp-ce", "curl", "--silent", "--show-error",
                "--fail", "--max-time", "10", f"http://127.0.0.1:{port}/",
                "-H", "Content-Type: application/json", "--data",
                json.dumps({"jsonrpc": "2.0", "id": 1,
                            "method": "psy_get_latest_checkpoint_id", "params": []})))
            if type(body.get("result")) is not int:
                raise ValueError("invalid checkpoint response")
            result[name] = body["result"]
        except (OSError, ValueError, subprocess.SubprocessError):
            result[name] = None
    return {"utc": datetime.now(timezone.utc).isoformat(), "checkpoints": result}


def queue_state():
    prefix = ("nats", "--server", "nats://127.0.0.1:4222")
    stream = json.loads(remote("gcp-nats", *prefix, "stream", "info", "realm_1_stream", "--json"))
    names = json.loads(remote("gcp-nats", *prefix, "consumer", "list", "realm_1_stream", "--json"))
    consumers = []
    for name in names:
        try:
            info = json.loads(remote("gcp-nats", *prefix, "consumer", "info", "realm_1_stream", name, "--json"))
            consumers.append({"name": name, "subject": info.get("config", {}).get("filter_subject"),
                              **{key: info.get(key) for key in
                                 ("num_pending", "num_ack_pending", "num_redelivered", "ack_floor")}})
        except (OSError, ValueError, subprocess.SubprocessError):
            consumers.append({"name": name, "observation": "unavailable_or_rotated_not_zero"})
    return {"sample_is_atomic": False,
            "stream": {k: stream.get("state", {}).get(k) for k in
                       ("messages", "first_seq", "last_seq", "last_ts", "consumer_count")},
            "consumers": consumers,
            "old_subjects_not_covered_by_live_consumers": True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--interval", type=int, default=30)
    args = p.parse_args()
    if not 5 <= args.interval <= 120:
        p.error("interval must be 5..120 seconds")
    first = heights()
    queues = queue_state()
    time.sleep(args.interval)
    second = heights()
    delta = {k: second["checkpoints"][k] - v
             if v is not None and second["checkpoints"][k] is not None else None
             for k, v in first["checkpoints"].items()}
    print(json.dumps({"first": first, "second": second, "checkpoint_delta": delta,
                      "realm1_queue_observation": queues,
                      "safe_to_stop_processor": False,
                      "missing_stop_evidence": [
                          "all_admission_paths_fenced_including_existing_sessions",
                          "pre_gate_and_ambiguous_handlers_reconciled",
                          "all_relevant_queue_generations_and_user_updates_committed",
                          "coordinator_root_and_realm_durable_state_reconciled"
                      ]}, indent=2))


if __name__ == "__main__":
    main()
