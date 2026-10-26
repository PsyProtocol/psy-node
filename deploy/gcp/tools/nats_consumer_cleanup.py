#!/usr/bin/env python3
"""Dry-run and guarded cleanup for leaked Parth JetStream consumers.

The default mode is read-only. Use --execute only after reviewing the report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any
from uuid import UUID


QUEUE_NAME_RE = re.compile(
    r"^(?P<namespace>coordinator|realm_[0-9]+)_pq_"
    r"r(?P<realm_id>[0-9a-f]+)_"
    r"rs(?P<realm_sub_id>[0-9a-f]+)_"
    r"u(?P<unique_id>[0-9a-f]+)_"
    r"qt(?P<topic_id>[0-9a-f]+)_"
    r"g(?P<task_group>[0-9a-f]+)$"
)


@dataclass
class Candidate:
    stream: str
    name: str
    namespace: str
    topic_id: str
    unique_id: str
    created: str | None
    age_minutes: float | None
    num_pending: int
    num_ack_pending: int
    num_redelivered: int
    delivered_stream_seq: int
    ack_floor_stream_seq: int
    reason: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nats-monitor-url", default="http://10.148.0.20:8222")
    parser.add_argument("--nats-host", default="10.148.0.20")
    parser.add_argument("--nats-port", type=int, default=4222)
    parser.add_argument(
        "--streams",
        default="coordinator_stream,realm_0_stream,realm_1_stream",
        help="comma-separated stream allowlist",
    )
    parser.add_argument(
        "--topics",
        default="1,2,3,20,40,41",
        help="comma-separated hex topic ids to consider",
    )
    parser.add_argument("--min-age-minutes", type=float, default=60.0)
    parser.add_argument("--keep-checkpoints", type=int, default=100)
    parser.add_argument(
        "--keep-pending-ids",
        type=int,
        default=140,
        help="also protect this many newest pending ids per keyspace",
    )
    parser.add_argument(
        "--keyspaces",
        default="coordinator,realm_0,realm_1",
        help="comma-separated Scylla keyspaces used for recent checkpoint protection",
    )
    parser.add_argument(
        "--cqlsh-command",
        default="sudo docker exec scylla-server cqlsh",
        help="command used on a Scylla VM to run cqlsh; set empty to disable DB protection",
    )
    parser.add_argument(
        "--allow-without-db-protection",
        action="store_true",
        help="allow candidate selection if Scylla protection cannot be loaded",
    )
    parser.add_argument("--limit", type=int, default=0, help="max consumers to delete in --execute mode")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--report-json", default="")
    parser.add_argument(
        "--delete-concurrency",
        type=int,
        default=1,
        help="parallel NATS API delete connections in --execute mode; default is conservative serial delete",
    )
    parser.add_argument("--delete-sleep-ms", type=float, default=0.0)
    return parser.parse_args()


def split_csv(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_rfc3339(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        if "." in value:
            base, suffix = value.split(".", 1)
            tz = "+00:00" if suffix.endswith("+00:00") else ""
            frac = suffix.removesuffix("+00:00")[:6]
            return dt.datetime.fromisoformat(f"{base}.{frac}{tz}")
        return None


def get_int(data: dict[str, Any], key: str) -> int:
    value = data.get(key, 0)
    return int(value or 0)


def run_cql(cqlsh_command: str, query: str) -> str:
    cmd = shlex.split(cqlsh_command) + ["-e", query]
    completed = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return completed.stdout


def parse_cql_two_column_table(output: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "|" not in line:
            continue
        left, right, *_ = [part.strip() for part in line.split("|")]
        if not left or left == "obj_id" or set(left) == {"-"}:
            continue
        if not re.fullmatch(r"-?\d+", left):
            continue
        rows.append((left, right))
    return rows


def load_protected_unique_ids(args: argparse.Namespace) -> tuple[set[str], dict[str, Any]]:
    if not args.cqlsh_command.strip():
        if args.allow_without_db_protection:
            return set(), {"enabled": False, "reason": "disabled"}
        raise RuntimeError("Scylla protection disabled; pass --allow-without-db-protection to override")

    protected: set[str] = set()
    details: dict[str, Any] = {"enabled": True, "keyspaces": {}}
    for keyspace in sorted(split_csv(args.keyspaces)):
        checkpoint_rows = parse_cql_two_column_table(
            run_cql(args.cqlsh_command, f"SELECT obj_id, value FROM {keyspace}.checkpoint_id_to_pending_id_table;")
        )
        pending_rows = parse_cql_two_column_table(
            run_cql(args.cqlsh_command, f"SELECT obj_id, value FROM {keyspace}.pending_id_to_pending_proc_id_table_u64_to_u128;")
        )
        checkpoint_to_pending: dict[int, int] = {
            int(checkpoint_id): int(pending_id) for checkpoint_id, pending_id in checkpoint_rows
        }
        pending_to_unique: dict[int, str] = {}
        for pending_id, uuid_text in pending_rows:
            try:
                pending_to_unique[int(pending_id)] = format(UUID(uuid_text).int, "x")
            except ValueError:
                continue

        max_checkpoint = max(checkpoint_to_pending.keys(), default=-1)
        max_pending = max(pending_to_unique.keys(), default=-1)
        checkpoint_floor = max(0, max_checkpoint - args.keep_checkpoints + 1)
        pending_floor = max(0, max_pending - args.keep_pending_ids + 1)

        checkpoint_protected = 0
        for checkpoint_id, pending_id in checkpoint_to_pending.items():
            if checkpoint_id >= checkpoint_floor:
                unique_id = pending_to_unique.get(pending_id)
                if unique_id:
                    protected.add(unique_id)
                    checkpoint_protected += 1

        pending_protected = 0
        for pending_id, unique_id in pending_to_unique.items():
            if pending_id >= pending_floor:
                protected.add(unique_id)
                pending_protected += 1

        details["keyspaces"][keyspace] = {
            "max_checkpoint": max_checkpoint,
            "checkpoint_floor": checkpoint_floor,
            "max_pending_id": max_pending,
            "pending_floor": pending_floor,
            "checkpoint_rows": len(checkpoint_rows),
            "pending_rows": len(pending_rows),
            "checkpoint_protected": checkpoint_protected,
            "pending_protected": pending_protected,
        }

    details["protected_unique_ids"] = len(protected)
    return protected, details


def fetch_jsz(monitor_url: str) -> dict[str, Any]:
    url = monitor_url.rstrip("/") + "/jsz?streams=true&consumers=true"
    with urllib.request.urlopen(url, timeout=120) as response:
        return json.load(response)


def iter_consumers(jsz: dict[str, Any]) -> list[dict[str, Any]]:
    consumers: list[dict[str, Any]] = []
    for account in jsz.get("account_details", []):
        for stream in account.get("stream_detail", []):
            for consumer in stream.get("consumer_detail", []):
                consumers.append(consumer)
    return consumers


def candidate_for_consumer(
    consumer: dict[str, Any],
    *,
    streams: set[str],
    topics: set[str],
    protected_unique_ids: set[str],
    min_age_minutes: float,
    now: dt.datetime,
) -> Candidate | None:
    stream = str(consumer.get("stream_name", ""))
    name = str(consumer.get("name", ""))
    if stream not in streams:
        return None
    match = QUEUE_NAME_RE.match(name)
    if not match:
        return None

    topic_id = match.group("topic_id")
    unique_id = match.group("unique_id")
    if topic_id not in topics:
        return None
    if unique_id in protected_unique_ids:
        return None

    created_raw = consumer.get("created")
    created_at = parse_rfc3339(created_raw)
    age_minutes = None
    if created_at is not None:
        age_minutes = (now - created_at).total_seconds() / 60.0
        if age_minutes < min_age_minutes:
            return None
    else:
        return None

    delivered = consumer.get("delivered", {}) or {}
    ack_floor = consumer.get("ack_floor", {}) or {}
    delivered_stream_seq = get_int(delivered, "stream_seq")
    ack_floor_stream_seq = get_int(ack_floor, "stream_seq")
    num_pending = get_int(consumer, "num_pending")
    num_ack_pending = get_int(consumer, "num_ack_pending")
    num_redelivered = get_int(consumer, "num_redelivered")

    if num_pending != 0 or num_ack_pending != 0 or num_redelivered != 0:
        return None
    if ack_floor_stream_seq != delivered_stream_seq:
        return None

    return Candidate(
        stream=stream,
        name=name,
        namespace=match.group("namespace"),
        topic_id=topic_id,
        unique_id=unique_id,
        created=created_raw,
        age_minutes=round(age_minutes, 2),
        num_pending=num_pending,
        num_ack_pending=num_ack_pending,
        num_redelivered=num_redelivered,
        delivered_stream_seq=delivered_stream_seq,
        ack_floor_stream_seq=ack_floor_stream_seq,
        reason="empty consumer, no ack pending, no redelivery, ack floor caught up, old and outside protected checkpoint window",
    )


def find_candidates(args: argparse.Namespace, protected_unique_ids: set[str]) -> tuple[list[Candidate], dict[str, Any]]:
    jsz = fetch_jsz(args.nats_monitor_url)
    consumers = iter_consumers(jsz)
    streams = split_csv(args.streams)
    topics = split_csv(args.topics)
    now = utc_now()
    candidates: list[Candidate] = []
    for consumer in consumers:
        candidate = candidate_for_consumer(
            consumer,
            streams=streams,
            topics=topics,
            protected_unique_ids=protected_unique_ids,
            min_age_minutes=args.min_age_minutes,
            now=now,
        )
        if candidate:
            candidates.append(candidate)

    metadata = {
        "server_time_utc": now.isoformat(),
        "total_consumers_seen": len(consumers),
        "server": {
            "server_id": jsz.get("server_id"),
            "now": jsz.get("now"),
            "messages": jsz.get("messages"),
            "bytes": jsz.get("bytes"),
        },
    }
    return candidates, metadata


def summarize(candidates: list[Candidate]) -> dict[str, Any]:
    by_stream: dict[str, int] = {}
    by_topic: dict[str, int] = {}
    for candidate in candidates:
        by_stream[candidate.stream] = by_stream.get(candidate.stream, 0) + 1
        key = f"{candidate.stream}:qt{candidate.topic_id}"
        by_topic[key] = by_topic.get(key, 0) + 1
    return {
        "candidate_count": len(candidates),
        "by_stream": dict(sorted(by_stream.items())),
        "by_stream_topic": dict(sorted(by_topic.items())),
        "sample": [asdict(candidate) for candidate in candidates[:20]],
    }


class NatsApiClient:
    def __init__(self, host: str, port: int) -> None:
        self.sock = socket.create_connection((host, port), timeout=30)
        self.file = self.sock.makefile("rwb", buffering=0)
        self.sid = 0
        self._read_info()
        self._send_line(b'CONNECT {"verbose":false,"pedantic":false,"lang":"python","version":"parth-cleanup"}')
        self._send_line(b"PING")
        self._read_until_pong()

    def close(self) -> None:
        try:
            self.file.close()
        finally:
            self.sock.close()

    def _send_line(self, line: bytes) -> None:
        self.file.write(line + b"\r\n")

    def _read_line(self) -> bytes:
        line = self.file.readline()
        if not line:
            raise RuntimeError("NATS connection closed")
        return line.rstrip(b"\r\n")

    def _read_info(self) -> None:
        line = self._read_line()
        if not line.startswith(b"INFO "):
            raise RuntimeError(f"expected INFO from NATS, got {line!r}")

    def _read_until_pong(self) -> None:
        while True:
            line = self._read_line()
            if line == b"PONG":
                return
            if line == b"PING":
                self._send_line(b"PONG")
            elif line.startswith(b"-ERR"):
                raise RuntimeError(line.decode("utf-8", "replace"))

    def request_json(self, subject: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.sid += 1
        sid = self.sid
        inbox = f"_INBOX.parth_cleanup.{os.getpid()}.{int(time.time() * 1000)}.{sid}"
        self._send_line(f"SUB {inbox} {sid}".encode())
        data = json.dumps(payload, separators=(",", ":")).encode()
        self._send_line(f"PUB {subject} {inbox} {len(data)}".encode())
        self.file.write(data + b"\r\n")

        while True:
            line = self._read_line()
            if line == b"PING":
                self._send_line(b"PONG")
                continue
            if line.startswith(b"-ERR"):
                raise RuntimeError(line.decode("utf-8", "replace"))
            if not line.startswith(b"MSG "):
                continue
            parts = line.split()
            if len(parts) < 4:
                raise RuntimeError(f"malformed NATS MSG line: {line!r}")
            size = int(parts[-1])
            body = self.file.read(size)
            self.file.read(2)
            self._send_line(f"UNSUB {sid}".encode())
            return json.loads(body.decode())


def execute_deletes(args: argparse.Namespace, candidates: list[Candidate]) -> dict[str, Any]:
    to_delete = candidates[: args.limit] if args.limit > 0 else candidates
    concurrency = max(1, int(args.delete_concurrency))
    if concurrency > 1:
        return execute_deletes_concurrently(args, to_delete, concurrency)

    client = NatsApiClient(args.nats_host, args.nats_port)
    deleted = 0
    errors: list[dict[str, str]] = []
    try:
        for candidate in to_delete:
            subject = f"$JS.API.CONSUMER.DELETE.{candidate.stream}.{candidate.name}"
            try:
                response = client.request_json(subject, {})
                if response.get("success") is True:
                    deleted += 1
                else:
                    errors.append({"stream": candidate.stream, "name": candidate.name, "response": json.dumps(response)})
            except Exception as exc:  # noqa: BLE001
                errors.append({"stream": candidate.stream, "name": candidate.name, "error": str(exc)})
            if args.delete_sleep_ms > 0:
                time.sleep(args.delete_sleep_ms / 1000.0)
    finally:
        client.close()
    return {"requested": len(to_delete), "deleted": deleted, "errors": errors[:50], "error_count": len(errors)}


def delete_candidate_batch(args: argparse.Namespace, candidates: list[Candidate]) -> dict[str, Any]:
    client = NatsApiClient(args.nats_host, args.nats_port)
    deleted = 0
    errors: list[dict[str, str]] = []
    try:
        for candidate in candidates:
            subject = f"$JS.API.CONSUMER.DELETE.{candidate.stream}.{candidate.name}"
            try:
                response = client.request_json(subject, {})
                if response.get("success") is True:
                    deleted += 1
                else:
                    errors.append({"stream": candidate.stream, "name": candidate.name, "response": json.dumps(response)})
            except Exception as exc:  # noqa: BLE001
                errors.append({"stream": candidate.stream, "name": candidate.name, "error": str(exc)})
            if args.delete_sleep_ms > 0:
                time.sleep(args.delete_sleep_ms / 1000.0)
    finally:
        client.close()
    return {"requested": len(candidates), "deleted": deleted, "errors": errors, "error_count": len(errors)}


def split_batches(candidates: list[Candidate], batch_count: int) -> list[list[Candidate]]:
    batches: list[list[Candidate]] = [[] for _ in range(batch_count)]
    for index, candidate in enumerate(candidates):
        batches[index % batch_count].append(candidate)
    return [batch for batch in batches if batch]


def execute_deletes_concurrently(
    args: argparse.Namespace,
    candidates: list[Candidate],
    concurrency: int,
) -> dict[str, Any]:
    if not candidates:
        return {"requested": 0, "deleted": 0, "errors": [], "error_count": 0}

    batches = split_batches(candidates, min(concurrency, len(candidates)))
    deleted = 0
    errors: list[dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(batches)) as executor:
        futures = [executor.submit(delete_candidate_batch, args, batch) for batch in batches]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            deleted += int(result["deleted"])
            errors.extend(result["errors"])

    return {"requested": len(candidates), "deleted": deleted, "errors": errors[:50], "error_count": len(errors)}


def main() -> int:
    args = parse_args()
    try:
        protected_unique_ids, protection_details = load_protected_unique_ids(args)
        candidates, metadata = find_candidates(args, protected_unique_ids)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    summary = summarize(candidates)
    report: dict[str, Any] = {
        "mode": "execute" if args.execute else "dry-run",
        "args": {
            "nats_monitor_url": args.nats_monitor_url,
            "streams": sorted(split_csv(args.streams)),
            "topics": sorted(split_csv(args.topics)),
            "min_age_minutes": args.min_age_minutes,
            "keep_checkpoints": args.keep_checkpoints,
            "keep_pending_ids": args.keep_pending_ids,
            "keyspaces": sorted(split_csv(args.keyspaces)),
            "limit": args.limit,
            "delete_concurrency": args.delete_concurrency,
        },
        "metadata": metadata,
        "protection": protection_details,
        "summary": summary,
        "candidates": [asdict(candidate) for candidate in candidates],
    }

    if args.execute:
        protected_unique_ids, protection_details = load_protected_unique_ids(args)
        candidates, metadata = find_candidates(args, protected_unique_ids)
        report["metadata"] = metadata
        report["protection"] = protection_details
        report["summary"] = summarize(candidates)
        report["candidates"] = [asdict(candidate) for candidate in candidates]
        report["delete_result"] = execute_deletes(args, candidates)

    report_path = args.report_json
    if not report_path:
        suffix = "execute" if args.execute else "dry_run"
        report_path = f"/tmp/nats_consumer_cleanup_{suffix}_{int(time.time())}.json"
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)

    print(json.dumps({k: report[k] for k in ("mode", "protection", "summary")}, indent=2, sort_keys=True))
    print(f"report_json={report_path}")
    if args.execute:
        print(json.dumps(report["delete_result"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
