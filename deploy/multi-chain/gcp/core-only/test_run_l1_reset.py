import importlib.util
import json
from pathlib import Path
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack

spec = importlib.util.spec_from_file_location("reset_runner", Path(__file__).with_name("run_l1_reset.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ResetTests(unittest.TestCase):
    def fixture(self, root, execute=False):
        root = Path(root)
        key = root / "fixture-ciphertext"
        key.write_text("public-test-placeholder-not-a-key")
        key.chmod(0o600)
        prior = root / "quarantine"
        prior.mkdir()
        (prior / "complete.json").write_text(json.dumps({"execute": True, "transactions_completed": 6,
            "plan_sha256": "cb29a265a72c7c0ae320119e2c652ca3ee86aceca8536117ce42eb3114771598"}))

        def require(value):
            if not value:
                raise ValueError("test gate")

        hashes = {str(runner.HERE / "run_l1_quarantine.cjs"): runner.QUARANTINE_JS_SHA,
                  str(runner.HERE / "fresh_l1.py"): "helper", str(root / "node"): "node", str(key): "ciphertext"}
        q = SimpleNamespace(require=require, trusted=Mock(side_effect=lambda p, *args: Path(p)),
            sha=lambda p: hashes.get(str(p), "f" * 64), HELPER_SHA="helper", NODE_SHA="node", BUNDLE_SHA="bundle",
            KEY_SHA="ciphertext", KEY=key, PASSWORD_ENV=root / "fixture-password-env", ATTEMPT=prior)
        fresh = SimpleNamespace(NETWORKS={"sepolia": (), "bscTestnet": (), "baseSepolia": ()},
            verify_bundle=Mock(return_value=root / "bundle"), own_rpc=Mock(return_value="http://127.0.0.1:1"),
            secret_env=Mock(return_value={"WALLET_PASSWORD": "test-only"}), read_json=lambda p: json.loads(Path(p).read_text()))
        requests = []

        def child(*args, **kwargs):
            value = json.loads(kwargs["input"])
            requests.append(value)
            if value["execute"]:
                self.assertTrue((root / "attempt/attempt.json").is_file())
                claim = json.loads((root / "attempt/attempt.json").read_text())
                self.assertEqual(claim["plan_sha256"], "a" * 64)
            return SimpleNamespace(returncode=0, stdout=json.dumps({"ok": True, "collector_sha256": "b" * 64}))

        argv = []
        for name in ("bundle", "node", "evidence", "plan", "snapshot", "fence", "quarantine-plan", "baseline-snapshot", "collector", "budgets", "output"):
            argv += ["--" + name, str(root / name)]
        for name in ("plan-sha256", "snapshot-sha256", "fence-sha256"):
            argv += ["--" + name, "a" * 64]
        if execute:
            argv += ["--execute"]
        original_lstat = Path.lstat

        def root_lstat(path, *a, **kw):
            values = list(original_lstat(path, *a, **kw))
            values[4] = 0  # Simulated root-owned fixture, no real ownership changes.
            return os.stat_result(values)

        patches = [patch.object(runner.importlib.util, "spec_from_file_location", return_value=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))),
            patch.object(runner.importlib.util, "module_from_spec", side_effect=[q, fresh, q, fresh]),
            patch.object(runner.subprocess, "run", side_effect=child), patch.object(runner, "ATTEMPT", root / "attempt"),
            patch.object(Path, "lstat", root_lstat), patch.object(runner.os, "geteuid", return_value=0)]
        return argv, patches, fresh, requests

    def invoke(self, argv, patches):
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return runner.main(argv)

    def test_default_check_passes_pins_but_no_custody_or_attempt(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, requests = self.fixture(root)
            self.assertTrue(self.invoke(argv, patches)["ok"])
            fresh.secret_env.assert_not_called()
            self.assertEqual(requests[0]["plan_sha256"], "a" * 64)
            self.assertNotIn("password", requests[0])
            self.assertFalse((Path(root) / "attempt").exists())

    def test_execute_requires_complete_quarantine_before_password(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, requests = self.fixture(root, True)
            (Path(root) / "quarantine/complete.json").write_text('{"execute":true,"transactions_completed":5}')
            with self.assertRaises(ValueError):
                self.invoke(argv, patches)
            fresh.secret_env.assert_not_called()
            self.assertEqual(requests, [])

    def test_claim_precedes_custody_and_output_change_cannot_repeat(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, requests = self.fixture(root, True)
            self.assertTrue(self.invoke(argv, patches)["ok"])
            self.assertEqual([r["execute"] for r in requests], [False, True])
            argv[argv.index("--output") + 1] = str(Path(root) / "second-output")
            with self.assertRaises(FileExistsError):
                self.invoke(argv, patches)
            self.assertEqual(fresh.secret_env.call_count, 1)
            self.assertTrue((Path(root) / "attempt/attempt.json").exists())

    def test_failed_unlock_preparation_retains_attempt(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, requests = self.fixture(root, True)
            fresh.secret_env.side_effect = ValueError("test-only unavailable password")
            with self.assertRaises(ValueError):
                self.invoke(argv, patches)
            self.assertTrue((Path(root) / "attempt/attempt.json").exists())
            self.assertEqual([r["execute"] for r in requests], [False])


if __name__ == "__main__":
    unittest.main()
