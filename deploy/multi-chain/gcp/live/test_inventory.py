import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check
import collect


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.mapping = {"components": [{"host": "host", "units": ["unit"],
                                       "expected_binary_sha256": "abc"}]}
        self.unit = {"unit": "unit", "systemd": {"MainPID": "123"},
                     "identity_verified": True, "sha256": "abc"}
        self.snapshot = {"hosts": [{"host": "host", "units": [self.unit]}]}

    def test_matching_running_artifact(self):
        self.assertEqual(check.check(self.mapping, self.snapshot), ([], []))

    def test_permission_error_never_counts_as_verified(self):
        self.unit.update(identity_verified=False, sha256=None, error="PermissionError")
        errors, unverified = check.check(self.mapping, self.snapshot)
        self.assertEqual(errors, [])
        self.assertEqual(len(unverified), 1)

    def test_mismatch_is_an_error(self):
        self.unit["sha256"] = "other"
        self.assertIn("mismatch", check.check(self.mapping, self.snapshot)[0][0])

    def test_missing_host_is_an_error(self):
        self.snapshot["hosts"] = []
        self.assertIn("missing observation", check.check(self.mapping, self.snapshot)[0][0])

    def test_unmapped_active_service_is_an_error(self):
        extra = copy.deepcopy(self.unit)
        extra["unit"] = "unexpected"
        self.snapshot["hosts"][0]["units"].append(extra)
        self.assertIn("unmapped", check.check(self.mapping, self.snapshot)[0][0])

    def test_expected_service_stopped_is_an_error(self):
        self.unit["systemd"]["MainPID"] = "0"
        self.assertIn("no PID", check.check(self.mapping, self.snapshot)[0][0])

    def test_duplicate_mapping_is_an_error(self):
        self.mapping["components"].append(copy.deepcopy(self.mapping["components"][0]))
        self.assertIn("duplicate", check.check(self.mapping, self.snapshot)[0][0])

    def test_duplicate_host_observation_is_an_error(self):
        self.snapshot["hosts"].append(copy.deepcopy(self.snapshot["hosts"][0]))
        self.assertIn("duplicate host", check.check(self.mapping, self.snapshot)[0][0])

    def test_duplicate_service_observation_is_an_error(self):
        self.snapshot["hosts"][0]["units"].append(copy.deepcopy(self.unit))
        self.assertIn("duplicate service", check.check(self.mapping, self.snapshot)[0][0])

    def test_unpinned_interpreter_does_not_attest_application(self):
        self.mapping["components"][0]["expected_binary_sha256"] = None
        self.unit.update(identity_verified=False, sha256=None)
        self.assertEqual(check.check(self.mapping, self.snapshot), ([], []))

    def test_pid_change_invalidates_hash(self):
        before = {"MainPID": "123", "ExecMainStartTimestampMonotonic": "10"}
        after = {"MainPID": "124", "ExecMainStartTimestampMonotonic": "20"}
        with tempfile.NamedTemporaryFile() as file:
            stat = Path(file.name).stat()
            with patch.object(collect, "properties", side_effect=[before, after]), \
                 patch.object(collect.os, "readlink", return_value="/safe/binary"), \
                 patch.object(collect.os, "stat", return_value=stat), \
                 patch.object(collect, "open", return_value=open(file.name, "rb"), create=True):
                result = collect.sample("unit")
        self.assertFalse(result["identity_verified"])
        self.assertEqual(result["error"], "process_changed_during_sample")

    def test_failed_exec_sample_cannot_contaminate_another_service(self):
        props = {"MainPID": "123", "ExecMainStartTimestampMonotonic": "10"}
        with tempfile.NamedTemporaryFile() as a, tempfile.NamedTemporaryFile() as b:
            a.write(b"binary-a")
            b.write(b"binary-b")
            a.flush()
            b.flush()
            with patch.object(collect, "properties", return_value=props), \
                 patch.object(collect.os, "readlink", side_effect=["/a", "/b", "/a", "/a"]), \
                 patch.object(collect.os, "stat", side_effect=[Path(b.name).stat(), Path(a.name).stat()]), \
                 patch.object(collect, "open", side_effect=[open(b.name, "rb"), open(a.name, "rb")], create=True):
                rejected = collect.sample("first")
                accepted = collect.sample("second")
        self.assertFalse(rejected["identity_verified"])
        self.assertTrue(accepted["identity_verified"])
        self.assertEqual(accepted["sha256"], hashlib.sha256(b"binary-a").hexdigest())

    def test_digest(self):
        with tempfile.NamedTemporaryFile() as file:
            file.write(b"inventory-test")
            file.flush()
            self.assertEqual(collect.digest(file.name), hashlib.sha256(b"inventory-test").hexdigest())

    def test_recorded_snapshot_consistency(self):
        root = Path(__file__).resolve().parent
        mapping = json.loads((root / "components.json").read_text())
        snapshot = json.loads((root / mapping["snapshot"]).read_text())
        self.assertEqual(check.check(mapping, snapshot), ([], []))
        self.assertFalse(mapping["complete"])


if __name__ == "__main__":
    unittest.main()
