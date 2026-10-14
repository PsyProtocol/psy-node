"""Offline failure injection; no systemd, network or production paths accessed."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class RolloutTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("rollout", Path(__file__).with_name("rollout.py"))
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name, value in {
            "BASE": root / "base", "OLD_BIN": root / "old", "RELEASE": root / "new",
            "DROP": root / "override.conf", "STATE": root / "audit",
        }.items():
            setattr(self.m, name, value)
        self.m.OLD_BIN.write_bytes(b"old")
        self.m.OLD = hashlib.sha256(b"old").hexdigest()
        self.binary = root / "candidate"
        self.binary.write_bytes(b"new")
        self.m.NEW = hashlib.sha256(b"new").hexdigest()
        self.old = {"pid": "1", "sha256": self.m.OLD}
        self.state = {"old": self.old, "protected": {}, "config_hash": "same"}
        self.real_unchanged = self.m.unchanged
        self.stack = []
        for name, kwargs in {
            "preflight": {"return_value": self.state},
            "unchanged": {}, "live": {"return_value": self.old},
            "config_hash": {"return_value": "same"},
            "ready": {"return_value": self.old},
            "prop": {"side_effect": lambda key: "0" if key == "MainPID" else ""},
        }.items():
            mock = patch.object(self.m, name, **kwargs)
            mock.start()
            self.addCleanup(mock.stop)

    def test_initial_audit_failure_does_not_install_override(self):
        with patch.object(self.m, "save", side_effect=OSError("disk full")), patch.object(self.m, "run") as run:
            with self.assertRaises(OSError):
                self.m.activate(self.binary)
            self.assertFalse(self.m.DROP.exists())
            run.assert_not_called()

    def test_failed_audit_after_activation_does_not_block_rollback(self):
        save = self.m.save
        calls = 0

        def flaky_save(state):
            nonlocal calls
            calls += 1
            if calls == 1:
                return save(state)
            raise OSError("disk full")

        with patch.object(self.m, "save", side_effect=flaky_save), patch.object(self.m, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "old Services restored"):
                self.m.activate(self.binary)
            self.assertFalse(self.m.DROP.exists())
            self.m.ready.assert_called_with(self.m.OLD)
            run.assert_any_call("systemctl", "restart", self.m.UNIT)

    def test_rollback_resumes_after_override_was_removed(self):
        self.m.STATE.mkdir()
        self.state["drop_sha256"] = "already removed"
        with patch.object(self.m, "run") as run:
            self.m.rollback(self.state)
            run.assert_any_call("systemctl", "daemon-reload")
            self.m.ready.assert_called_with(self.m.OLD)
            self.assertEqual(self.state["phase"], "rolled_back")

    def test_candidate_readiness_failure_recovers_despite_disk_and_stdout_failure(self):
        save = self.m.save
        calls = 0
        order = []

        def flaky_save(state):
            nonlocal calls
            calls += 1
            if calls <= 2:
                return save(state)
            raise OSError("disk full")

        def readiness(expected):
            order.append(("ready", expected))
            if expected == self.m.NEW:
                raise RuntimeError("candidate not ready")
            return self.old

        with patch.object(self.m, "save", side_effect=flaky_save), patch.object(self.m, "run", side_effect=lambda *args: order.append(args)), patch.object(self.m, "ready", side_effect=readiness), patch("builtins.print", side_effect=BrokenPipeError()):
            with self.assertRaisesRegex(RuntimeError, "old Services restored"):
                self.m.activate(self.binary)
        restarts = [i for i, item in enumerate(order) if item == ("systemctl", "restart", self.m.UNIT)]
        self.assertEqual(len(restarts), 2)
        self.assertLess(restarts[0], order.index(("ready", self.m.NEW)))
        self.assertLess(order.index(("ready", self.m.NEW)), restarts[1])
        self.assertLess(restarts[1], order.index(("ready", self.m.OLD)))
        self.assertFalse(self.m.DROP.exists())

    def test_absent_override_with_stale_systemd_loaded_paths_recovers(self):
        self.m.STATE.mkdir()
        self.state["drop_sha256"] = "already removed"
        loaded = [str(self.m.PREVIOUS_DROP), str(self.m.DROP)]

        def property_value(key):
            return {
                "WorkingDirectory": str(self.m.BASE), "MemoryHigh": "5368709120",
                "MemoryMax": "6442450944", "User": "parth", "Group": "parth",
                "ExecStart": "--run-migrations=false", "MainPID": "0",
                "DropInPaths": " ".join(loaded),
            }[key]

        def command(*args):
            if args == ("systemctl", "daemon-reload"):
                loaded[:] = [str(self.m.PREVIOUS_DROP)]

        with patch.object(self.m, "unchanged", side_effect=self.real_unchanged), patch.object(self.m, "prop", side_effect=property_value), patch.object(self.m, "run", side_effect=command):
            self.m.rollback(self.state)
        self.assertEqual(self.state["phase"], "rolled_back")


if __name__ == "__main__":
    unittest.main()
