#!/usr/bin/env python3
"""Read archived Realm1 updates, then verify exact historical inclusion. No ACKs."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import time
import urllib.request
import uuid

STREAM = "realm_1_stream"
FILTER = "realm_1.pq.r1.rs1.*.qt20.g0"
SUBJECT = re.compile(r"realm_1\.pq\.r1\.rs1\.u[0-9a-f]+\.qt20\.g0\Z")
ROOT = Path("/var/lib/parth/realm1-maintenance-reconciliation")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class ReadOnlyNats:
    def __init__(self):
        self.sock = socket.create_connection(("10.148.0.20", 4222), timeout=15)
        self.f = self.sock.makefile("rb")
        if not self.f.readline(65536).startswith(b"INFO "):
            raise RuntimeError("invalid NATS greeting")
        self.sock.sendall(b'CONNECT {"verbose":false,"pedantic":true,"protocol":1}\r\n')

    def request(self, api, body):
        if api not in (f"$JS.API.STREAM.INFO.{STREAM}", f"$JS.API.STREAM.MSG.GET.{STREAM}"):
            raise ValueError("only read-only stream metadata and archived-message reads allowed")
        inbox = "_INBOX.realm1_audit_" + uuid.uuid4().hex
        data = json.dumps(body).encode()
        self.sock.sendall(f"SUB {inbox} 1\r\nUNSUB 1 1\r\nPUB {api} {inbox} {len(data)}\r\n".encode() + data + b"\r\n")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            line = self.f.readline(65536)
            if line == b"PING\r\n":
                self.sock.sendall(b"PONG\r\n")
                continue
            parts = line.split()
            if parts and parts[0] == b"MSG" and parts[1] == inbox.encode():
                size = int(parts[-1])
                if not 0 <= size <= 8 * 1024 * 1024:
                    raise RuntimeError("oversized message")
                raw = self.f.read(size)
                if len(raw) != size or self.f.read(2) != b"\r\n":
                    raise RuntimeError("truncated NATS message")
                return json.loads(raw)
            if not line or line.startswith(b"-ERR"):
                raise RuntimeError("NATS read failed")
        raise TimeoutError("NATS deadline")

    def close(self):
        self.f.close()
        self.sock.close()


def rpc(method, params, port=1339):
    if port not in (1337, 1339) or (port == 1337 and method != "psy_get_latest_checkpoint_id"):
        raise ValueError("unexpected RPC target")
    if method not in {"psy_get_checkpoint_id_for_unique_pending_id", "psy_get_user_tree_leaf_hash", "psy_get_latest_checkpoint_id"}:
        raise ValueError("read-only RPC allowlist")
    body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
    req = urllib.request.Request(f"http://10.148.0.25:{port}/", data=body, headers={"Content-Type": "application/json"})
    with OPENER.open(req, timeout=20) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError("RPC query failed: " + str(result["error"]))
    return result["result"]


def pending_state():
    # One atomic HMGET of the existing processing/gathering identifiers only.
    fields = [struct.pack("<IH", 1, 1) + name for name in (b"PI", b"GP")]
    args = [b"HMGET", b"TKVSV1-realm_1-1-1", *fields]
    wire = b"*4\r\n" + b"".join(b"$%d\r\n" % len(a) + a + b"\r\n" for a in args)
    result = {}
    with socket.create_connection(("10.148.0.12", 6379), timeout=10) as sock:
        with sock.makefile("rb") as reader:
            sock.sendall(wire)
            if reader.readline(128) != b"*2\r\n":
                raise RuntimeError("unexpected pending state reply")
            for kind in ("processing", "gathering"):
                if reader.readline(128) != b"$24\r\n":
                    raise RuntimeError("missing or malformed pending state")
                value = reader.read(24)
                if len(value) != 24 or reader.read(2) != b"\r\n":
                    raise RuntimeError("truncated pending state")
                pending = int.from_bytes(value[:8], "little")
                proc = int.from_bytes(value[8:], "little")
                result[kind] = dict(pending=pending, proc_id=str(proc),
                                    subject=f"realm_1.pq.r1.rs1.u{proc:x}.qt20.g0")
    return result


def decode(message):
    if not SUBJECT.fullmatch(message["subject"]):
        raise ValueError("unexpected subject")
    raw = base64.b64decode(message["data"], validate=True)
    if len(raw) < 244:
        raise ValueError("truncated update")
    job = struct.unpack_from("<BQBIIIBB", raw)
    user = struct.unpack_from("<Q", raw, 192)[0]
    if job[0] != 0 or job[2:5] != (6, 32, 0) or job[5] != user or job[6:] != (0, 0):
        raise ValueError("unexpected update job layout")
    return dict(seq=message["seq"], subject=message["subject"], time=message["time"],
                # QHashOut JSON reverses the canonical little-endian wire bytes.
                pending=job[1], user_id=user, new_hash=raw[64:96][::-1].hex(),
                sha256=hashlib.sha256(raw).hexdigest())


def retained_without_holes(state, first):
    return (type(state.get("first_seq")) is int and type(state.get("last_seq")) is int
            and state["first_seq"] <= first <= state["last_seq"]
            and state.get("messages") == state["last_seq"] - state["first_seq"] + 1)


def committed(checkpoint, realm_head, coordinator_head):
    return (type(checkpoint) is int and type(realm_head) is int and type(coordinator_head) is int
            and 0 <= checkpoint <= min(realm_head, coordinator_head))


def collect(first, maximum):
    client = ReadOnlyNats()
    try:
        pending_before = pending_state()
        initial = client.request(f"$JS.API.STREAM.INFO.{STREAM}", {})
        state = initial["state"]
        if first < state["first_seq"] or first > state["last_seq"]:
            raise ValueError("range outside retained stream")
        dest = ROOT / f"snapshot-{time.time_ns()}"
        dest.mkdir(mode=0o700, parents=True)
        (dest / "stream.json").write_text(json.dumps(initial))
        rows, sequence = [], first
        while sequence <= state["last_seq"]:
            value = client.request(f"$JS.API.STREAM.MSG.GET.{STREAM}", {"seq": sequence, "next_by_subj": FILTER})
            if "error" in value:
                if value["error"].get("err_code") == 10037:
                    break
                raise RuntimeError(str(value["error"]))
            message = value["message"]
            if not sequence <= message["seq"]:
                raise RuntimeError("sequence moved backwards")
            if message["seq"] > state["last_seq"]:
                break
            rows.append(decode(message))
            (dest / f"message-{message['seq']}.json").write_text(json.dumps(value))
            if len(rows) > maximum:
                raise RuntimeError("row limit exceeded; partial snapshot is not a pass")
            sequence = message["seq"] + 1
        after = client.request(f"$JS.API.STREAM.INFO.{STREAM}", {})
        (dest / "stream-after.json").write_text(json.dumps(after))
        result = dict(first_seq=first, last_seq=state["last_seq"], filter=FILTER, rows=rows,
                      pending_before=pending_before, pending_after=pending_state(),
                      scan_completed=True, earlier_history_not_audited=True,
                      retained_without_holes_at_samples=(retained_without_holes(state, first)
                          and retained_without_holes(after["state"], first)),
                      all_relevant_generations_covered=False,
                      safe_to_stop_processor=False)
        (dest / "manifest.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(dict(snapshot=str(dest), rows=len(rows), first_seq=first, last_seq=state["last_seq"], safe_to_stop_processor=False)))
    finally:
        client.close()


def verify(directory):
    directory = directory.resolve()
    if directory.parent != ROOT or not directory.name.startswith("snapshot-"):
        raise ValueError("unexpected snapshot directory")
    source = json.loads((directory / "manifest.json").read_text())
    if not source.get("scan_completed") or source.get("filter") != FILTER:
        raise ValueError("incomplete snapshot")
    results, checkpoints = [], {}
    realm_head = rpc("psy_get_latest_checkpoint_id", [])
    coordinator_head = rpc("psy_get_latest_checkpoint_id", [], 1337)
    for expected in source["rows"]:
        message = json.loads((directory / f"message-{expected['seq']}.json").read_text())["message"]
        if decode(message) != expected:
            raise ValueError("snapshot message mismatch")
        pending = expected["pending"]
        if pending not in checkpoints:
            checkpoints[pending] = rpc("psy_get_checkpoint_id_for_unique_pending_id", [pending])
        checkpoint = checkpoints[pending]
        observed = rpc("psy_get_user_tree_leaf_hash", [checkpoint, expected["user_id"]]) if type(checkpoint) is int else None
        results.append({**expected, "checkpoint": checkpoint,
                        "exact_inclusion": observed == expected["new_hash"] and committed(checkpoint, realm_head, coordinator_head)})
        time.sleep(0.02)
    unresolved = [r for r in results if not r["exact_inclusion"]]
    report = dict(rows=results, unresolved=len(unresolved), safe_to_stop_processor=False,
                  first_seq=source["first_seq"], last_seq=source["last_seq"],
                  filter=source["filter"], scan_completed=True,
                  retained_without_holes_at_samples=source["retained_without_holes_at_samples"],
                  earlier_history_not_audited=True, all_relevant_generations_covered=False,
                  committed_bounds=dict(realm=realm_head, coordinator=coordinator_head),
                  checkpoint=rpc("psy_get_latest_checkpoint_id", []))
    output = directory / f"verification-{time.time_ns()}.json"
    output.write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(report=str(output), rows=len(results), unresolved=len(unresolved),
                          pending_without_checkpoint=sum(r["checkpoint"] is None for r in unresolved),
                          safe_to_stop_processor=False)))


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit("sudo required for private evidence")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["collect", "verify", "pending"])
    parser.add_argument("--first-seq", type=int)
    parser.add_argument("--max-rows", type=int, default=10000)
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    if args.action == "collect":
        if args.first_seq is None or args.first_seq < 1 or not 1 <= args.max_rows <= 10000:
            parser.error("bounded starting sequence required")
        collect(args.first_seq, args.max_rows)
    elif args.action == "verify":
        if args.directory is None:
            parser.error("snapshot directory required")
        verify(args.directory)
    else:
        print(json.dumps(pending_state()))


if __name__ == "__main__":
    main()
