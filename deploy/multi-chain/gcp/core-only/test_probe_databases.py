"""probe_databases tests: every container command is faked; the Schnorr code is checked against BIP-340."""
import hashlib
import json
import unittest
from unittest.mock import patch

import probe_databases as probe


class Recorder:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, argv, timeout=60):
        self.calls.append(list(argv))
        for needle, answer in self.answers:
            if needle in argv:
                return answer() if callable(answer) else answer
        return ""


class ProbeTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(probe.time, "sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_valkey_reads_the_live_policy_with_config_get(self):
        store = {}

        def run(argv, timeout=60):
            verb = argv[4]
            if verb == "DBSIZE":
                return "0\n"
            if verb == "CONFIG":
                return "maxmemory-policy\nnoeviction\n"
            if verb == "SET":
                store[argv[5]] = argv[6]
            return store.get(argv[5], "") + "\n" if verb == "GET" else ""

        result = probe.probe_valkey(run)
        self.assertEqual(result, {"component": "valkey", "maxmemory_policy": "noeviction", "read_write": True,
                                  "keys_before": 0})

    def test_valkey_refuses_any_policy_but_noeviction(self):
        calls = []

        def run(argv, timeout=60):
            calls.append(argv)
            return "maxmemory-policy\nallkeys-lru\n" if argv[4] == "CONFIG" else "0\n" if argv[4] == "DBSIZE" else ""

        with self.assertRaisesRegex(probe.ProbeFailed, "allkeys-lru"):
            probe.probe_valkey(run)
        self.assertTrue(all(call[0] == "/usr/bin/docker" for call in calls), "no config file may be read")

    def test_valkey_refuses_a_read_back_that_differs(self):
        def run(argv, timeout=60):
            return "maxmemory-policy\nnoeviction\n" if argv[4] == "CONFIG" else "0\n" if argv[4] == "DBSIZE" else "stale\n"

        with self.assertRaisesRegex(probe.ProbeFailed, "read-back"):
            probe.probe_valkey(run)

    def test_postgres_writes_reads_and_drops_its_table(self):
        written = {}

        def run(argv, timeout=60):
            statement = argv[-1]
            if statement.startswith("INSERT"):
                written["v"] = statement.split("'last', '")[1].split("'")[0]
            return written.get("v", "") + "\n" if statement.startswith("SELECT") else ""

        self.assertEqual(probe.probe_postgres(run), {"component": "postgres", "read_write": True})

    def test_postgres_refuses_a_wrong_read_back(self):
        with self.assertRaisesRegex(probe.ProbeFailed, "read-back"):
            probe.probe_postgres(lambda argv, timeout=60: "wrong\n" if argv[-1].startswith("SELECT") else "")

    def test_scylla_writes_reads_and_drops_its_keyspace(self):
        written = {}

        def run(argv, timeout=60):
            query = argv[-1]
            if query.startswith("INSERT"):
                written["v"] = query.split("'last', '")[1].split("'")[0]
            return f" v\n---\n {written.get('v')}\n" if query.startswith("SELECT") else ""

        self.assertEqual(probe.probe_scylla(run), {"component": "scylla", "read_write": True, "user_keyspaces": []})

    def test_nats_needs_pub_sub_and_a_jetstream_write_to_the_wiped_store(self):
        fetch = lambda url: json.dumps({"config": {"max_memory": 1}}).encode()
        write = lambda: {"messages": 1, "streams_left": []}
        self.assertEqual(probe.probe_nats(lambda: True, fetch, write)["jetstream_write"], True)
        with self.assertRaisesRegex(probe.ProbeFailed, "JetStream"):
            probe.probe_nats(lambda: True, lambda url: b"{}", write)
        with self.assertRaisesRegex(probe.ProbeFailed, "pub/sub"):
            probe.probe_nats(lambda: False, fetch, write)
        with self.assertRaisesRegex(probe.ProbeFailed, "did not store"):
            probe.probe_nats(lambda: True, fetch, lambda: {"messages": 0, "streams_left": []})
        with self.assertRaisesRegex(probe.ProbeFailed, "old streams"):
            probe.probe_nats(lambda: True, fetch, lambda: {"messages": 1, "streams_left": ["OLD_STREAM"]})

    def test_nats_client_reads_replies_and_never_spins_on_end_of_file(self):
        import io

        class Wire:
            def __init__(self, data):
                self.incoming = io.BytesIO(data)

            def readline(self):
                return self.incoming.readline()

            def write(self, data):
                pass

        reply = json.dumps({"seq": 1})
        wire = (b'INFO {"server_id":"x"}\r\nPONG\r\n' + f"MSG _INBOX.abc 9 {len(reply)}\r\n{reply}\r\n".encode())
        self.assertEqual(probe.NatsClient(Wire(wire)).request("$JS.API.X", b"{}"), {"seq": 1})
        with self.assertRaisesRegex(probe.ProbeFailed, "closed"):
            probe.NatsClient(Wire(b""))
        with self.assertRaisesRegex(probe.ProbeFailed, "closed"):
            probe.NatsClient(Wire(b'INFO {}\r\nPONG\r\n')).request("$JS.API.X", b"{}")

    def test_the_websocket_handshake_does_not_spin_on_end_of_file(self):
        class Closed:
            def sendall(self, data):
                pass

            def recv(self, count):
                return b""

        with patch.object(probe.socket, "create_connection", return_value=Closed()):
            with self.assertRaisesRegex(probe.ProbeFailed, "closed"):
                probe.Socket("127.0.0.1", 8080)

    def test_valkey_must_be_empty_after_the_wipe(self):
        def run(argv, timeout=60):
            return {"CONFIG": "maxmemory-policy\nnoeviction\n", "DBSIZE": "7\n"}.get(argv[4], "")

        with self.assertRaisesRegex(probe.ProbeFailed, "not empty"):
            probe.probe_valkey(run)

    def test_scylla_must_hold_no_old_keyspace_after_the_wipe(self):
        written = {}

        def run(argv, timeout=60):
            query = argv[-1]
            if query.startswith("INSERT"):
                written["v"] = query.split("'last', '")[1].split("'")[0]
            if query.startswith("SELECT"):
                return f" v\n---\n {written.get('v')}\n"
            if query.startswith("DESCRIBE"):
                return "system  system_schema  fresh_old_r3_coordinator\n"
            return ""

        with self.assertRaisesRegex(probe.ProbeFailed, "old keyspaces.*fresh_old_r3_coordinator"):
            probe.probe_scylla(run)

    def test_nostr_read_back_mode_reads_a_recorded_event_without_writing(self):
        sent = []

        class Link:
            def __init__(self, host, port):
                self.queue = []

            def send(self, text):
                sent.append(json.loads(text)[0])
                self.queue = [json.dumps(["EVENT", "verify", {"id": "abc"}]), json.dumps(["EOSE", "verify"])]

            def receive(self):
                return self.queue.pop(0)

        result = probe.probe_nostr(lambda argv, timeout=60: "172.18.0.2\n", Link, event_id="abc")
        self.assertEqual(sent, ["REQ"])
        self.assertEqual(result["event_id"], "abc")

    def test_nostr_write_mode_reports_the_event_id(self):
        class Link:
            def __init__(self, host, port):
                self.queue = []

            def send(self, text):
                message = json.loads(text)
                if message[0] == "EVENT":
                    self.event = message[1]
                    self.queue = [json.dumps(["OK", message[1]["id"], True, ""])]
                else:
                    self.queue = [json.dumps(["EVENT", "verify", self.event]), json.dumps(["EOSE", "verify"])]

            def receive(self):
                return self.queue.pop(0)

        result = probe.probe_nostr(lambda argv, timeout=60: "172.18.0.2\n", Link)
        self.assertEqual(len(result["event_id"]), 64)

    def test_main_accepts_the_read_back_form_with_an_event_id(self):
        self.assertEqual(probe.main(["nostr-read"]), 2)
        self.assertEqual(probe.main(["nostr-read", "not-hex"]), 2)

    def test_schnorr_matches_the_bip340_vector(self):
        secret = bytes(31) + bytes([3])
        self.assertEqual(probe.schnorr_public(secret).hex(),
                         "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
        self.assertEqual(probe.schnorr_sign(bytes(32), secret).hex(),
                         "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
                         "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0")

    def test_event_id_commits_to_its_fields(self):
        event = probe.build_event(bytes([7]) * 32, 1700000000)
        fields = [0, event["pubkey"], 1700000000, 1059, [], "psy-deploy-verify"]
        self.assertEqual(event["id"], hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest())
        self.assertEqual(event["kind"], 1059)

    def test_nostr_publishes_then_reads_the_event_back(self):
        sent = []

        class Link:
            def __init__(self, host, port):
                self.queue = []

            def send(self, text):
                message = json.loads(text)
                sent.append(message[0])
                if message[0] == "EVENT":
                    self.event = message[1]
                    self.queue = [json.dumps(["OK", message[1]["id"], True, ""])]
                else:
                    self.queue = [json.dumps(["EVENT", "verify", self.event]), json.dumps(["EOSE", "verify"])]

            def receive(self):
                return self.queue.pop(0)

        run = lambda argv, timeout=60: "172.18.0.2\n"
        result = probe.probe_nostr(run, Link)
        self.assertEqual((result["component"], result["read_write"]), ("nostr", True))
        self.assertEqual(sent, ["EVENT", "REQ"])

    def test_nostr_refuses_a_rejected_event(self):
        class Link:
            def __init__(self, host, port):
                pass

            def send(self, text):
                pass

            def receive(self):
                return json.dumps(["OK", "x", False, "blocked"])

        with patch.object(probe, "WAIT_SECONDS", 0), self.assertRaises(probe.ProbeFailed):
            probe.probe_nostr(lambda argv, timeout=60: "172.18.0.2\n", Link)

    def test_unknown_component_is_a_usage_error(self):
        self.assertEqual(probe.main(["mysql"]), 2)

    def test_standard_library_only(self):
        import re
        from pathlib import Path
        imports = set(re.findall(r"^(?:import|from) (\w+)", Path(probe.__file__).read_text(), re.MULTILINE))
        self.assertTrue(imports <= {"base64", "hashlib", "json", "os", "socket", "subprocess", "sys", "time", "urllib"})


if __name__ == "__main__":
    unittest.main()
