import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("rollout", Path(__file__).with_name("rollout.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RolloutTests(unittest.TestCase):
    def test_shutdown_progress_is_not_counted_as_candidate_progress(self):
        state = {"realm": 0, "cursor_before": 100}
        calls = []
        with patch.object(m, "run", side_effect=lambda *args: calls.append(args)), \
             patch.object(m, "prop", return_value="0"), \
             patch.object(m, "read_cursor", side_effect=lambda _: (calls.append("cursor") or 108)), \
             patch.object(m, "audit"):
            m.start_from_stopped_cursor(state)
        self.assertEqual(state["cursor_at_start"], 108)
        self.assertEqual(calls, [("systemctl", "stop", "parth-psy-indexer@realm-0.service"),
                                 "cursor", ("systemctl", "start", "parth-psy-indexer@realm-0.service")])

    def test_running_old_process_blocks_start(self):
        with patch.object(m, "run") as run, patch.object(m, "prop", return_value="123"):
            with self.assertRaisesRegex(RuntimeError, "still running"):
                m.start_from_stopped_cursor({"realm": 0, "cursor_before": 100})
        self.assertEqual(run.call_count, 1)

    def test_health_requires_three_new_checkpoints(self):
        state = {"realm": 0, "unit": "indexer", "cursor_before": 100,
                 "cursor_at_start": 108, "env_hash": "env"}
        with patch.object(m, "unchanged"), \
             patch.object(m, "prop", side_effect=lambda _, key: "active" if key == "ActiveState" else "123"), \
             patch.object(m, "live", return_value={"sha256": "binary"}), \
             patch.object(m, "env_hash", return_value="env"), \
             patch.object(m, "env", return_value={b"PSY_COORDINATOR_EDGE_RPC_URL": m.COORDINATOR.encode()}), \
             patch.object(m, "read_cursor", return_value=110), \
             patch.object(m.time, "monotonic", side_effect=[0, 0, 2]), \
             patch.object(m.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "did not advance"):
                m.healthy(state, "binary", True, seconds=1)

    def test_rollback_does_not_depend_on_processor_pid(self):
        state = {"realm": 0, "unit": "indexer", "old_dropins": [],
                 "manifest": {"binary_sha256": "candidate"}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(m, "paths", return_value=("indexer", root / "absent", root / "cursor", root)), \
                 patch.object(m, "unchanged") as unchanged, \
                 patch.object(m, "sha", return_value=m.OLD_HASH), \
                 patch.object(m, "prop", side_effect=lambda _, key: "0" if key == "MainPID" else ""), \
                 patch.object(m, "run"), patch.object(m, "start_from_stopped_cursor") as start, \
                 patch.object(m, "healthy", return_value={}), patch.object(m, "audit"), patch.object(m, "emit"):
                m.rollback(state)
            unchanged.assert_called_once_with(state, check_processors=False)
            start.assert_called_once_with(state)
        self.assertEqual(state["phase"], "rolled_back")


if __name__ == "__main__":
    unittest.main()
