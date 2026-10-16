import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

import observe_resources
import probe_role


class Tests(unittest.TestCase):
    def test_transport_failure_is_unhealthy_even_with_valid_rpc(self):
        self.assertFalse(probe_role.healthy({"curl_exit":18,"http_code":200,"rpc_success":True}))
        self.assertTrue(probe_role.healthy({"curl_exit":0,"http_code":200,"rpc_success":True}))

    def test_sampler_tracks_own_pid_and_bounds_disk(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d)/"resources.jsonl"
            subprocess.run([sys.executable, str(Path(__file__).with_name("observe_resources.py")),
                "--pid", str(os.getpid()), "--samples", "2", "--interval", "1", "--output", str(output)], check=True)
            records = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["start_ticks"], records[1]["start_ticks"])
            self.assertIn("cpu_cores", records[1]["rates"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("cmdline", output.read_text())
            self.assertTrue(observe_resources.sample(2147483647)["process_missing"])

    def test_role_probe_and_privacy(self):
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                seen.append((self.headers.get("X-Psy-Probe"),json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                data = json.dumps({"jsonrpc":"2.0", "id":1, "result":{"role":"user","user_methods":True,"system_methods":False}, "ignored":"SECRET"}).encode()
                self.send_response(200)
                self.send_header("X-Request-ID", "abcdef0123456789abcdef0123456789")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers();self.wfile.write(data)
        with http.server.HTTPServer(("127.0.0.1",0), Handler) as server:
            t = threading.Thread(target=server.serve_forever);t.start()
            try:
                result=probe_role.probe(f"http://127.0.0.1:{server.server_port}")
                self.assertTrue(result["rpc_success"])
                self.assertEqual(result["http_code"],200)
                self.assertEqual(result["request_id"],"abcdef0123456789abcdef0123456789")
                self.assertNotIn("SECRET",json.dumps(result))
                self.assertEqual(seen[0][0],"role-readiness")
                self.assertEqual(seen[0][1]["method"],"psy_get_prove_proxy_role")
            finally:
                server.shutdown();t.join()

    def test_offline_trace_filters_payloads_and_ids(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/"events.jsonl"
            file.write_text(json.dumps({"request_id":"mine","event":"stage_end","detail":{"elapsed_ms":10,"params":"SECRET"}})+"\n"+
                json.dumps({"request_id":"other","event":"SECRET"})+"\n")
            run = subprocess.run([sys.executable, str(Path(__file__).with_name("trace_request.py")),
                "--request-id","mine",str(file)],capture_output=True,text=True,check=True)
            self.assertNotIn("SECRET",run.stdout)
            self.assertEqual(json.loads(run.stdout)["detail"],{"elapsed_ms":10})


if __name__ == "__main__": unittest.main()
