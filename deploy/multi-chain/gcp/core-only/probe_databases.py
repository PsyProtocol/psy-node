#!/usr/bin/env python3
"""Root tool: write and read back through one rebuilt database container; standard library only.

Usage: python3 -I -B - <valkey|nats|postgres|scylla|nostr>   (script on stdin). It prints one JSON object.
"""
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

COMMAND_TIMEOUT_SECONDS = 60
WAIT_SECONDS = 240
POLL_SECONDS = 5
NATS_PORT, NATS_MONITOR_PORT, NOSTR_PORT = 4222, 8222, 8080
FIELD, ORDER = 2**256 - 2**32 - 977, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


class ProbeFailed(Exception):
    """The component did not pass; the message names what failed, never a secret."""


def command(argv, timeout=COMMAND_TIMEOUT_SECONDS):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if done.returncode != 0:
        raise ProbeFailed(f"{argv[0].rsplit('/', 1)[-1]} {argv[1]} failed")
    return done.stdout


def wait_for(attempt, label):
    deadline = time.monotonic() + WAIT_SECONDS
    while True:
        try:
            return attempt()
        except (ProbeFailed, OSError, subprocess.SubprocessError, ValueError) as error:
            if time.monotonic() >= deadline:
                raise ProbeFailed(f"{label} not ready after {WAIT_SECONDS}s: {error}") from None
            time.sleep(POLL_SECONDS)


def probe_valkey(run=command):
    def attempt():
        policy = run(["/usr/bin/docker", "exec", "valkey-server", "valkey-cli", "CONFIG", "GET", "maxmemory-policy"]).split()
        if policy[:1] != ["maxmemory-policy"] or len(policy) != 2:
            raise ProbeFailed("CONFIG GET returned an unexpected answer")
        size = int(run(["/usr/bin/docker", "exec", "valkey-server", "valkey-cli", "DBSIZE"]).strip())
        key, value = "psy_deploy_verify", f"v-{os.getpid()}-{time.time_ns()}"
        run(["/usr/bin/docker", "exec", "valkey-server", "valkey-cli", "SET", key, value])
        readback = run(["/usr/bin/docker", "exec", "valkey-server", "valkey-cli", "GET", key]).strip()
        run(["/usr/bin/docker", "exec", "valkey-server", "valkey-cli", "DEL", key])
        return policy[1], readback == value, size
    policy, matched, size = wait_for(attempt, "valkey")
    if policy != "noeviction":
        raise ProbeFailed(f"maxmemory-policy is {policy}, not noeviction")
    if size != 0:
        raise ProbeFailed(f"valkey is not empty after the wipe ({size} keys)")
    if not matched:
        raise ProbeFailed("valkey read-back differs from the write")
    return {"component": "valkey", "maxmemory_policy": policy, "read_write": True, "keys_before": size}


class NatsClient:
    """Raw NATS protocol over a file-like object; an end of file is an error, never a wait."""

    def __init__(self, stream):
        self.stream = stream
        self.line()
        stream.write(b'CONNECT {"verbose":false,"pedantic":false}\r\nPING\r\n')
        while self.line() != b"PONG":
            pass

    def line(self):
        data = self.stream.readline()
        if not data:
            raise ProbeFailed("nats closed the connection")
        return data.strip()

    def message(self, subscription):
        for _ in range(20):
            head = self.line()
            if head.startswith(b"MSG "):
                fields = head.split()
                if fields[2] == str(subscription).encode():
                    return self.line() if int(fields[-1]) else b""
                self.line()
        raise ProbeFailed("nats did not deliver the message")

    def request(self, subject, payload):
        inbox = f"_INBOX.psy{time.time_ns()}"
        self.stream.write(f"SUB {inbox} 9\r\n".encode())
        self.stream.write(f"PUB {subject} {inbox} {len(payload)}\r\n".encode() + payload + b"\r\n")
        reply = json.loads(self.message(9))
        self.stream.write(b"UNSUB 9\r\n")
        return reply

    def page(self, subject, key):
        """Every row under one key of a paged JetStream listing; an API error is a failure, not an empty list."""
        rows, offset = [], 0
        while True:
            reply = self.request(subject, json.dumps({"offset": offset}).encode())
            if "error" in reply:
                raise ProbeFailed(f"JetStream refused {subject.split('.')[2].lower()} listing")
            found = reply.get(key) or []
            rows += found
            offset += len(found)
            if not found or offset >= reply.get("total", 0):
                return rows

    def list_consumers(self):
        """Every consumer that is not an ack-all consumer, with the configuration the server reports (ack_wait in ns)."""
        rows = []
        for stream in self.page("$JS.API.STREAM.NAMES", "streams"):
            for consumer in self.page(f"$JS.API.CONSUMER.LIST.{stream}", "consumers"):
                config = consumer.get("config", {})
                if config.get("ack_policy") != "all":
                    rows.append({"stream": stream, "ack_policy": config.get("ack_policy"),
                                 "ack_wait": config.get("ack_wait"), "max_deliver": config.get("max_deliver")})
        return rows

    def roundtrip(self, subject, payload):
        self.stream.write(f"SUB {subject} 8\r\n".encode())
        self.stream.write(f"PUB {subject} {len(payload)}\r\n".encode() + payload + b"\r\n")
        return self.message(8) == payload


class SocketStream:
    """Buffered reads, unbuffered writes: a large listing must not cost one system call per byte."""

    def __init__(self, sock):
        self.sock, self.reader = sock, sock.makefile("rb")

    def readline(self):
        return self.reader.readline()

    def write(self, data):
        self.sock.sendall(data)


def connect_nats(port=NATS_PORT):
    return NatsClient(SocketStream(socket.create_connection(("127.0.0.1", port), timeout=10)))


def nats_roundtrip():
    return connect_nats().roundtrip(f"_psy.verify.{os.getpid()}", f"ok-{time.time_ns()}".encode())


def nats_jetstream_write():
    """Create a stream on the fresh store, publish, read it back, delete it, and list what streams remain."""
    client, name = connect_nats(), "PSY_DEPLOY_VERIFY"
    subject = "psy.deploy.verify"
    spec = {"name": name, "subjects": [subject], "storage": "file", "retention": "limits", "num_replicas": 1}
    if "error" in client.request("$JS.API.STREAM.CREATE." + name, json.dumps(spec).encode()):
        raise ProbeFailed("JetStream refused to create the verification stream")
    if "seq" not in client.request(subject, f"js-{time.time_ns()}".encode()):
        raise ProbeFailed("JetStream did not acknowledge the write")
    messages = client.request("$JS.API.STREAM.INFO." + name, b"").get("state", {}).get("messages", 0)
    client.request("$JS.API.STREAM.DELETE." + name, b"")
    return {"messages": messages, "streams_left": client.request("$JS.API.STREAM.NAMES", b"{}").get("streams") or []}


def probe_nats(roundtrip=nats_roundtrip, fetch=lambda url: urllib.request.urlopen(url, timeout=5).read(),
               write=nats_jetstream_write):
    if not wait_for(roundtrip, "nats"):
        raise ProbeFailed("nats pub/sub read-back differs from the write")
    state = json.loads(fetch(f"http://127.0.0.1:{NATS_MONITOR_PORT}/jsz"))
    if not isinstance(state.get("config"), dict):
        raise ProbeFailed("nats JetStream is not enabled")
    stored = wait_for(write, "nats JetStream")
    if stored["messages"] < 1:
        raise ProbeFailed("JetStream did not store the written message")
    if stored["streams_left"]:
        raise ProbeFailed("old streams are still present: " + ", ".join(stored["streams_left"]))
    return {"component": "nats", "read_write": True, "jetstream": True, "jetstream_write": True}


def nats_consumers():
    return {"component": "nats", "consumers": connect_nats().list_consumers()}


def probe_postgres(run=command):
    psql = ["/usr/bin/docker", "exec", "parth-postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"]
    value = f"pg-{time.time_ns()}"

    def attempt():
        run([*psql, "-c", "CREATE TABLE IF NOT EXISTS psy_deploy_verify (k text PRIMARY KEY, v text NOT NULL)"])
        run([*psql, "-c", f"INSERT INTO psy_deploy_verify VALUES ('last', '{value}') "
                           "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"])
        return run([*psql, "-tAc", "SELECT v FROM psy_deploy_verify WHERE k = 'last'"]).strip()
    readback = wait_for(attempt, "postgres")
    run([*psql, "-c", "DROP TABLE psy_deploy_verify"])
    if readback != value:
        raise ProbeFailed("postgres read-back differs from the write")
    return {"component": "postgres", "read_write": True}


def scylla_cql(query, run=command):
    script = ('set -eu; cqlsh_path="$(command -v cqlsh || command -v cqlsh.py)"; '
              'host="$(hostname -i | awk \'{print $1}\')"; exec "$cqlsh_path" "$host" 9042 -e "$1"')
    return run(["/usr/bin/docker", "exec", "scylla-server", "sh", "-c", script, "sh", query])


def probe_scylla(run=command):
    value = f"scylla-{time.time_ns()}"

    def attempt():
        scylla_cql("CREATE KEYSPACE IF NOT EXISTS psy_deploy_verify WITH replication = "
                   "{'class': 'SimpleStrategy', 'replication_factor': 1}", run)
        scylla_cql("CREATE TABLE IF NOT EXISTS psy_deploy_verify.t (k text PRIMARY KEY, v text)", run)
        scylla_cql(f"INSERT INTO psy_deploy_verify.t (k, v) VALUES ('last', '{value}')", run)
        return scylla_cql("SELECT v FROM psy_deploy_verify.t WHERE k = 'last'", run)
    readback = wait_for(attempt, "scylla")
    scylla_cql("DROP KEYSPACE psy_deploy_verify", run)
    if value not in readback:
        raise ProbeFailed("scylla read-back differs from the write")
    user = sorted(name for name in scylla_cql("DESCRIBE KEYSPACES", run).split() if not name.startswith("system"))
    if user:
        raise ProbeFailed("old keyspaces are still present: " + ", ".join(user))
    return {"component": "scylla", "read_write": True, "user_keyspaces": user}


def point_add(first, second):
    if first is None or second is None:
        return first or second
    if first[0] == second[0] and (first[1] + second[1]) % FIELD == 0:
        return None
    if first == second:
        slope = 3 * first[0] * first[0] * pow(2 * first[1], -1, FIELD) % FIELD
    else:
        slope = (second[1] - first[1]) * pow(second[0] - first[0], -1, FIELD) % FIELD
    x = (slope * slope - first[0] - second[0]) % FIELD
    return x, (slope * (first[0] - x) - first[1]) % FIELD


def point_mul(point, scalar):
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point, scalar = point_add(point, point), scalar >> 1
    return result


def tagged_hash(tag, data):
    prefix = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(prefix + prefix + data).digest()


def schnorr_sign(message, secret, aux=bytes(32)):
    """BIP-340 signature of a 32-byte message."""
    d0 = int.from_bytes(secret, "big")
    public = point_mul(GENERATOR, d0)
    d = d0 if public[1] % 2 == 0 else ORDER - d0
    px = public[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px + message), "big") % ORDER
    nonce = point_mul(GENERATOR, k0)
    k = k0 if nonce[1] % 2 == 0 else ORDER - k0
    rx = nonce[0].to_bytes(32, "big")
    e = int.from_bytes(tagged_hash("BIP0340/challenge", rx + px + message), "big") % ORDER
    return rx + ((k + e * d) % ORDER).to_bytes(32, "big")


def schnorr_public(secret):
    return point_mul(GENERATOR, int.from_bytes(secret, "big"))[0].to_bytes(32, "big")


def build_event(secret, now):
    """A signed kind 1059 event, the only kind the relay accepts."""
    pub = schnorr_public(secret).hex()
    fields = [0, pub, now, 1059, [], "psy-deploy-verify"]
    event_id = hashlib.sha256(json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode()).digest()
    return {"id": event_id.hex(), "pubkey": pub, "created_at": now, "kind": 1059, "tags": [],
            "content": "psy-deploy-verify", "sig": schnorr_sign(event_id, secret).hex()}


class Socket:
    """Just enough of a WebSocket client for one text round trip."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            block = self.sock.recv(1)
            if not block:
                raise ProbeFailed("relay closed the connection")
            head += block
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ProbeFailed("relay refused the WebSocket upgrade")

    def send(self, text):
        data, mask = text.encode(), os.urandom(4)
        header = bytes([0x81]) + (bytes([0x80 | len(data)]) if len(data) < 126 else bytes([0x80 | 126]) + len(data).to_bytes(2, "big"))
        self.sock.sendall(header + mask + bytes(byte ^ mask[i % 4] for i, byte in enumerate(data)))

    def receive(self):
        def exact(count):
            data = b""
            while len(data) < count:
                block = self.sock.recv(count - len(data))
                if not block:
                    raise ProbeFailed("relay closed the connection")
                data += block
            return data
        first, second = exact(2)
        length = second & 0x7F
        length = int.from_bytes(exact(2), "big") if length == 126 else int.from_bytes(exact(8), "big") if length == 127 else length
        payload = exact(length)
        return payload.decode() if first & 0x0F == 1 else self.receive()


def relay_address(container, run):
    template = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    address = run(["/usr/bin/docker", "inspect", "-f", template, container]).strip()
    if not address:
        raise ProbeFailed("relay container has no address")
    return address


def read_event(link, event_id):
    link.send(json.dumps(["REQ", "verify", {"ids": [event_id]}]))
    for _ in range(5):
        frame = json.loads(link.receive())
        if frame[0] == "EVENT" and frame[2].get("id") == event_id:
            return True
        if frame[0] == "EOSE":
            break
    return False


def probe_nostr(run=command, connect=Socket, container="nostr-relay", event_id=None):
    """Write a signed event and read it back, or, given an event id, only read that event back."""
    event = None if event_id else build_event(os.urandom(32), int(time.time()))

    def attempt():
        link = connect(relay_address(container, run), NOSTR_PORT)
        if event is not None:
            link.send(json.dumps(["EVENT", event]))
            if json.loads(link.receive())[:3] != ["OK", event["id"], True]:
                raise ProbeFailed("relay did not accept the event")
        return read_event(link, event_id or event["id"])
    if not wait_for(attempt, "nostr"):
        raise ProbeFailed("nostr read-back did not return the written event")
    return {"component": "nostr", "read_write": True, "event_id": event_id or event["id"]}


PROBES = {"valkey": probe_valkey, "nats": probe_nats, "postgres": probe_postgres, "scylla": probe_scylla,
          "nostr": probe_nostr}
COMMANDS = {**PROBES, "nats-consumers": nats_consumers}
USAGE = "usage: probe_databases.py " + "|".join(sorted(PROBES)) + " | nostr-read <event id> | nats-consumers"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    read_back = len(argv) == 2 and argv[0] == "nostr-read" and len(argv[1]) == 64 and set(argv[1]) <= set("0123456789abcdef")
    if not read_back and (len(argv) != 1 or argv[0] not in COMMANDS):
        print(json.dumps({"ok": False, "error": USAGE}))
        return 2
    try:
        report = {"ok": True, **(probe_nostr(event_id=argv[1]) if read_back else COMMANDS[argv[0]]())}
    except ProbeFailed as error:
        report = {"ok": False, "component": argv[0], "error": str(error)}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
