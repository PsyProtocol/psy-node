import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack

SPEC = importlib.util.spec_from_file_location("clean_runner", Path(__file__).with_name("run_l1_clean.py"))
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)


class CleanTests(unittest.TestCase):
    def fixture(self, root, execute=False):
        root = Path(root)
        inputs = {"reset": {name: str(root / name) for name in c.RESET_PATHS},
                  "post_snapshot": str(root / "post.json"), "post_snapshot_sha256": "a" * 64,
                  "fork_tool": str(root / "fork.cjs"), "fork_tool_sha256": "b" * 64,
                  "proof": str(root / "proof.json"), "attestation": str(root / "attestation.json"),
                  "attestation_sha256": "c" * 64,
                  "fork_reports": {n: {"path": str(root / (n + ".json")), "sha256": "d" * 64} for n in c.NETWORKS}}
        inputs["reset"].update(plan_sha256="e" * 64, snapshot_sha256="f" * 64, fence_sha256="a" * 64)
        input_file = root / "inputs.json"
        input_file.write_text(json.dumps(inputs))
        complete = root / "complete.json"
        complete.write_text(json.dumps({"execute": True, "phase": "reset", "transactions_completed": 6,
            "plan_sha256": "e" * 64, "runner_sha256": c.RESET_JS_SHA}))
        key = root / "fixture-ciphertext"
        key.write_bytes(b"public-test-data")
        key.chmod(0o600)
        def require(ok):
            if not ok:
                raise ValueError("test gate failed")
        def sha(path):
            return {"run_l1_reset.cjs": c.RESET_JS_SHA, "inputs.json": "1" * 64,
                    "node": "node-pin", "fixture-ciphertext": "key-pin"}.get(Path(path).name, "2" * 64)
        q = SimpleNamespace(require=require, trusted=Mock(side_effect=lambda p, *args: Path(p)), sha=sha,
            HELPER_SHA="helper-pin", NODE_SHA="node-pin", BUNDLE_SHA="bundle-pin", KEY=key, KEY_SHA="key-pin", PASSWORD_ENV=root / "fixture-env")
        fresh = SimpleNamespace(read_json=lambda p: json.loads(Path(p).read_text()),
            verify_bundle=Mock(return_value=root / "bundle"), NETWORKS=c.NETWORKS,
            own_rpc=Mock(return_value="http://127.0.0.1:1"), secret_env=Mock(return_value={"WALLET_PASSWORD": "test-only"}))
        calls = []
        def child(*args, **kwargs):
            request = json.loads(kwargs["input"])
            calls.append(request)
            self.assertNotIn("test-only", " ".join(args[0]))
            self.assertNotIn("WALLET_PASSWORD", kwargs["env"])
            if request["execute"]:
                self.assertTrue((root / "attempt/attempt.json").is_file())
            return SimpleNamespace(returncode=0, stdout=json.dumps({"ok": True, "phase": "clean",
                "proof_sha256": "3" * 64, "snapshot_sha256": "a" * 64}))
        argv = ["--helpers", str(root), "--node", str(root / "node"), "--inputs", str(input_file),
                "--inputs-sha256", "1" * 64, "--output", str(root / "output")]
        if execute:
            argv.append("--execute")
        patches = [patch.object(c, "load_helper", side_effect=[q, fresh, q, fresh]),
                   patch.object(c, "ATTEMPT", root / "attempt"), patch.object(c, "RESET_COMPLETE", complete),
                   patch.object(c.os, "geteuid", return_value=0), patch.object(c.subprocess, "run", side_effect=child)]
        return argv, patches, fresh, calls, complete, input_file

    def invoke(self, argv, patches):
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            return c.main(argv)

    def test_default_is_check_and_never_opens_custody(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, calls, _, _ = self.fixture(root)
            self.invoke(argv, patches)
            self.assertEqual([v["execute"] for v in calls], [False])
            self.assertNotIn("password", calls[0])
            fresh.secret_env.assert_not_called()
            self.assertFalse((Path(root) / "attempt").exists())

    def test_complete_reset_required_before_any_custody(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, calls, complete, _ = self.fixture(root, True)
            value = json.loads(complete.read_text())
            value["transactions_completed"] = 5
            complete.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                self.invoke(argv, patches)
            fresh.secret_env.assert_not_called()
            self.assertEqual(calls, [])

    def test_missing_chain_fork_report_rejects_before_child_or_custody(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, calls, _, file = self.fixture(root)
            value = json.loads(file.read_text())
            del value["fork_reports"]["sepolia"]
            file.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                self.invoke(argv, patches)
            self.assertEqual(calls, [])
            fresh.secret_env.assert_not_called()

    def test_attempt_claim_precedes_custody_and_blocks_retry_with_new_output(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, calls, _, _ = self.fixture(root, True)
            self.invoke(argv, patches)
            self.assertEqual([v["execute"] for v in calls], [False, True])
            argv[argv.index("--output") + 1] = str(Path(root) / "second-output")
            with self.assertRaises(FileExistsError):
                self.invoke(argv, patches)
            self.assertEqual(fresh.secret_env.call_count, 1)

    def test_failed_custody_preserves_claim_no_execute(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, calls, _, _ = self.fixture(root, True)
            fresh.secret_env.side_effect = ValueError("unavailable fixture")
            with self.assertRaises(ValueError):
                self.invoke(argv, patches)
            self.assertTrue((Path(root) / "attempt/attempt.json").is_file())
            self.assertEqual([v["execute"] for v in calls], [False])


if __name__ == "__main__":
    unittest.main()
