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
import unittest.mock

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


FAKE_ETHERS = r"""
class N { constructor(v) { this.v = BigInt(v); }
  mul(x) { return new N(this.v * BigInt(x.v ?? x)); } add(x) { return new N(this.v + BigInt(x.v ?? x)); }
  div(x) { return new N(this.v / BigInt(x.v ?? x)); } gt(x) { return this.v > BigInt(x.v ?? x); }
  lt(x) { return this.v < BigInt(x.v ?? x); } toString() { return this.v.toString(); } }
const state = JSON.parse(process.env.FAKE_CHAIN);
exports.utils = {
  Interface: class { encodeFunctionData(name, args) { return name + ':' + JSON.stringify(args); }
    decodeFunctionResult(name, data) { return JSON.parse(data); } },
  parseUnits: (v, unit) => new N(BigInt(v) * 10n ** 9n), keccak256: (raw) => '0xhash',
};
exports.providers = { JsonRpcProvider: class {
  async send() { return '0x' + state.chainId.toString(16); }
  async call(tx) { if (tx.data.startsWith('getPauseFlags')) return JSON.stringify(state.flags[0]); if (tx.data.startsWith('isBridgeAdmin')) return JSON.stringify([true]); return '[]'; }
  async estimateGas() { return new N(state.gas); } async getGasPrice() { return new N(state.price); }
  async getTransactionCount() { return 1; } async getBalance() { return new N(state.balance); }
  async sendTransaction(raw) { const target = JSON.parse(raw).target; state.flags = state.flags.map(() => [target, 0, target]); }
  async waitForTransaction() { return { status: 1, blockNumber: 7, gasUsed: new N(50000), effectiveGasPrice: new N(state.price) }; } } };
exports.Wallet = { fromEncryptedJson: async () => ({ address: state.signer,
  signTransaction: async (tx) => JSON.stringify({ target: Number(process.env.FAKE_TARGET) }) }) };
"""


@unittest.skipUnless(__import__("shutil").which("node"), "node is needed to run the embedded script")
class EmbeddedScriptTests(unittest.TestCase):
    """The embedded node script against a fake ethers module: fee cap and balance margin apply to opening only."""

    def run_tool(self, target, price, balance):
        import os
        import shutil
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "ethers.js").write_text(FAKE_ETHERS)
        (root / "env").write_text("export WALLET_PASSWORD=pw\n")
        (root / "keystore").write_text("{}")
        flags = [[1, 0, 1]] * 3 if target == 0 else [[0, 0, 0]] * 3
        chain = {"chainId": 11155111, "flags": flags, "gas": 55000, "price": price, "balance": balance, "signer": ADDRESS}
        os.environ["FAKE_CHAIN"], os.environ["FAKE_TARGET"] = json.dumps(chain), str(target)
        self.addCleanup(os.environ.pop, "FAKE_CHAIN")
        self.addCleanup(os.environ.pop, "FAKE_TARGET")
        original_environ = m.subprocess.Popen

        def popen(argv, **kwargs):
            kwargs["env"] = {**kwargs["env"], "FAKE_CHAIN": os.environ["FAKE_CHAIN"], "FAKE_TARGET": os.environ["FAKE_TARGET"]}
            return original_environ(argv, **kwargs)
        req = request(execute=True, target=target, node=shutil.which("node"), ethers=str(root / "ethers.js"),
                      env_file=str(root / "env"), keystore=str(root / "keystore"))
        encoded, digest = encode(req)
        out = io.StringIO()
        with unittest.mock.patch.object(m.subprocess, "Popen", popen), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            code = m.main(["--request-base64", encoded, "--request-sha256", digest], geteuid=lambda: 0)
        return code, json.loads(out.getvalue().strip().splitlines()[-1])

    HIGH_PRICE, LOW_BALANCE = 100 * 10 ** 9, 55000 * 2 * 100 * 10 ** 9 * 2

    def test_opening_is_refused_above_the_fee_cap(self):
        code, report = self.run_tool(0, self.HIGH_PRICE, 10 ** 30)
        self.assertEqual((code, report["ok"]), (1, False))
        self.assertIn("fee above the cap", report["msg"])

    def test_a_repause_goes_out_above_the_fee_cap_and_with_a_thin_balance(self):
        code, report = self.run_tool(1, self.HIGH_PRICE, self.LOW_BALANCE)
        self.assertEqual((code, report["ok"], report["broadcast"]), (0, True, True))
        self.assertEqual(report["flags"], [[1, 0, 1]] * 3)

    def test_opening_needs_the_three_times_balance_margin_but_a_repause_does_not(self):
        code, report = self.run_tool(0, 10 ** 9, 55000 * 2 * 10 ** 9 * 2)
        self.assertEqual(code, 1)
        self.assertIn("balance is low", report["msg"])


if __name__ == "__main__":
    unittest.main()
