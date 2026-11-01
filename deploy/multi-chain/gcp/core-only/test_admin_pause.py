"""The signer-host pause tool: request validation, secret handling and exit behaviour, with a stub node binary."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import admin_pause as m

HERE = Path(__file__).resolve().parent
ADDRESS = "0x" + "ab" * 20


def request(**changes):
    value = {"chain": "sepolia", "target": 0, "execute": False, "signer": ADDRESS, "chain_id": 11155111, "port": 18545,
             "bridge": ADDRESS, "acl": ADDRESS, "tokens": [ADDRESS] * 3, "keystore": "/k/keystore", "env_file": "/k/env",
             "node": "/n/node", "ethers": "/n/ethers", "max_gas": 300000, "max_fee_gwei": 5}
    value.update(changes)
    return value


def encode(value):
    raw = json.dumps(value).encode()
    return base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest()


class ValidationTests(unittest.TestCase):
    def test_a_valid_request_round_trips_and_a_wrong_hash_is_refused(self):
        encoded, digest = encode(request())
        self.assertEqual(m.read_request(encoded, digest), request())
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            m.read_request(encoded, "0" * 64)

    def test_every_malformed_request_is_refused(self):
        for label, bad in (("extra", dict(request(), extra=1)), ("chain", request(chain="mainnet")),
                           ("chain id", request(chain_id=1)), ("target", request(target=2)), ("target type", request(target=True)),
                           ("execute", request(execute="yes")), ("signer", request(signer="0x12")),
                           ("tokens", request(tokens=[ADDRESS])), ("port", request(port=80)), ("gas", request(max_gas=0)),
                           ("relative path", request(node="node")), ("dotdot", request(ethers="/a/../b"))):
            encoded, digest = encode(bad)
            with self.subTest(label), self.assertRaises(ValueError):
                m.read_request(encoded, digest)

    def test_the_tool_has_no_fixed_gas_cap_and_no_release_address(self):
        text = (HERE / "admin_pause.py").read_text()
        self.assertNotIn("300000", text)
        self.assertNotIn("500000", text)
        self.assertNotIn("2000000", text)
        self.assertNotRegex(text, r"0x[0-9a-fA-F]{40}\b")


class RunTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.node = self.root / "node"
        self.node.write_text("#!" + sys.executable + "\n" + (
            "import json, sys\n"
            "payload = json.loads(sys.stdin.read())\n"
            "print(json.dumps({'ok': True, 'saw_secret': 'password' in payload, 'saw_keystore': 'encrypted' in payload,\n"
            "                  'target': payload['target'], 'execute': payload['execute']}))\n"
            "sys.exit(1 if __import__('os').path.exists(sys.argv[0] + '.fail') else 0)\n"))
        self.node.chmod(0o700)
        self.env = self.root / "env"
        self.env.write_text("export WALLET_PASSWORD='s3cret value'\n")
        self.keystore = self.root / "keystore"
        self.keystore.write_text("{}")

    def run_tool(self, euid=0, **changes):
        base = request(node=str(self.node), env_file=str(self.env), keystore=str(self.keystore), **changes)
        encoded, digest = encode(base)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = m.main(["--request-base64", encoded, "--request-sha256", digest], geteuid=lambda: euid)
        return code, json.loads(out.getvalue().strip().splitlines()[-1])

    def test_a_dry_run_reads_neither_keystore_nor_secret(self):
        self.env.unlink()
        self.keystore.unlink()
        code, report = self.run_tool(execute=False)
        self.assertEqual((code, report["saw_secret"], report["saw_keystore"]), (0, False, False))

    def test_an_executing_run_hands_the_node_the_keystore_and_secret_but_prints_neither(self):
        code, report = self.run_tool(execute=True, target=1)
        self.assertEqual((code, report["saw_secret"], report["saw_keystore"], report["target"]), (0, True, True, 1))
        self.assertNotIn("s3cret", json.dumps(report))

    def test_a_missing_secret_is_a_clean_failure(self):
        self.env.write_text("export OTHER=1\n")
        code, report = self.run_tool(execute=True)
        self.assertEqual((code, report["ok"], report["stage"]), (1, False, "request"))

    def test_a_node_failure_exit_is_passed_on(self):
        Path(str(self.node) + ".fail").write_text("")
        code, _ = self.run_tool()
        self.assertEqual(code, 1)

    def test_a_non_root_caller_is_refused_before_anything_is_read(self):
        code, report = self.run_tool(euid=1000, execute=True)
        self.assertEqual((code, report["ok"]), (1, False))

    def test_the_command_line_entry_runs_under_isolated_python(self):
        encoded, digest = encode(request(node=str(self.node)))
        done = subprocess.run([sys.executable, "-I", "-B", str(HERE / "admin_pause.py"), "--request-base64", encoded,
                               "--request-sha256", digest], capture_output=True, text=True)
        self.assertEqual(json.loads(done.stdout)["ok"], False)  # not root here: refused cleanly, no traceback
        self.assertNotIn("Traceback", done.stderr)


if __name__ == "__main__":
    unittest.main()
