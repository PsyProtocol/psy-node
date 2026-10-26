import json
import subprocess
import unittest
from unittest.mock import patch
import observe as o


class ObserveTests(unittest.TestCase):
    def test_error_is_unknown_not_zero(self):
        with patch.object(o, "remote", side_effect=[json.dumps({"error": {"code": -32001}}),
                         json.dumps({"result": 10}), json.dumps({"result": 11})]):
            self.assertEqual(o.heights()["checkpoints"],
                             {"coordinator": None, "realm0": 10, "realm1": 11})

    def test_rotating_consumer_not_reported_as_empty(self):
        with patch.object(o, "remote", side_effect=[json.dumps({"state": {"last_seq": 100}}),
                         json.dumps(["old"]), subprocess.CalledProcessError(1, "nats")]):
            result = o.queue_state()
        self.assertFalse(result["sample_is_atomic"])
        self.assertEqual(result["consumers"][0]["observation"], "unavailable_or_rotated_not_zero")
        self.assertNotIn("num_pending", result["consumers"][0])

    def test_empty_live_consumers_do_not_cover_old_subjects(self):
        with patch.object(o, "remote", side_effect=["{}", "[]"]):
            result = o.queue_state()
        self.assertTrue(result["old_subjects_not_covered_by_live_consumers"])
        self.assertEqual(result["consumers"], [])


if __name__ == "__main__":
    unittest.main()
