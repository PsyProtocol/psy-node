import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location("quarantine", Path(__file__).with_name("run_l1_quarantine.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class QuarantineTests(unittest.TestCase):
    def test_trusted_rejects_links_and_writable_input(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "input"
            p.write_text("public")
            p.chmod(0o600)
            q.trusted(p)
            link = Path(root) / "link"
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                q.trusted(link)
            p.chmod(0o666)
            with self.assertRaises(ValueError):
                q.trusted(p)

    def fixture(self, root, execute=False, fail=False):
        root = Path(root)
        key = root / "fixture-ciphertext"
        key.write_text("public-test-placeholder-not-a-key")
        key.chmod(0o600)
        fresh = SimpleNamespace(NETWORKS={"sepolia": (), "bscTestnet": (), "baseSepolia": ()},
            verify_bundle=Mock(return_value=root / "bundle"), own_rpc=Mock(return_value="http://127.0.0.1:1"),
            secret_env=Mock(return_value={"WALLET_PASSWORD": "test-only"}))
        requests = []

        def child(*args, **kwargs):
            request = json.loads(kwargs["input"])
            requests.append(request)
            if request["execute"]:
                self.assertTrue((root / "attempt/attempt.json").is_file())
                self.assertEqual((root / "attempt").stat().st_mode & 0o777, 0o700)
            return SimpleNamespace(returncode=1 if fail else 0,
                stdout=json.dumps({"ok": True, "plan_sha256": "a" * 64, "collector_sha256": "b" * 64}))

        argv = []
        for name in ("bundle", "node", "evidence", "plan", "snapshot", "collector", "budgets", "output"):
            argv += ["--" + name, str(root / name)]
        if execute:
            argv += ["--execute"]
        hashes = {str(q.HERE / "fresh_l1.py"): q.HELPER_SHA, str(root / "node"): q.NODE_SHA, str(key): q.KEY_SHA}
        patches = [patch.object(q, "trusted", side_effect=lambda p, *a: Path(p)),
            patch.object(q, "sha", side_effect=lambda p: hashes.get(str(p), "c" * 64)),
            patch.object(q.importlib.util, "spec_from_file_location", return_value=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))),
            patch.object(q.importlib.util, "module_from_spec", return_value=fresh),
            patch.object(q.subprocess, "run", side_effect=child), patch.object(q, "KEY", key),
            patch.object(q, "ATTEMPT", root / "attempt"), patch.object(q.os, "geteuid", return_value=0)]
        return argv, patches, fresh, requests

    def invoke(self, argv, patches):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return q.main(argv)

    def test_check_never_opens_custody(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, requests = self.fixture(root)
            self.assertTrue(self.invoke(argv, patches)["ok"])
            fresh.secret_env.assert_not_called()
            self.assertEqual(len(requests), 1)
            self.assertNotIn("password", requests[0])
            self.assertFalse((Path(root) / "attempt").exists())

    def test_failed_public_check_never_claims_attempt_or_reads_password(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, requests = self.fixture(root, execute=True, fail=True)
            with self.assertRaises(ValueError):
                self.invoke(argv, patches)
            fresh.secret_env.assert_not_called()
            self.assertFalse((Path(root) / "attempt").exists())

    def test_execution_claim_is_durable_before_password_and_cannot_repeat(self):
        with tempfile.TemporaryDirectory() as root:
            argv, patches, fresh, requests = self.fixture(root, execute=True)
            self.assertTrue(self.invoke(argv, patches)["ok"])
            self.assertEqual([r["execute"] for r in requests], [False, True])
            self.assertEqual(fresh.secret_env.call_count, 1)
            argv[argv.index("--output") + 1] = str(Path(root) / "new-output")
            with self.assertRaises(FileExistsError):
                self.invoke(argv, patches)
            self.assertEqual(fresh.secret_env.call_count, 1)
            self.assertTrue((Path(root) / "attempt/attempt.json").exists())


if __name__ == "__main__":
    unittest.main()
