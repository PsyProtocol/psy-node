import unittest
from unittest.mock import patch
import rollout


class ReadinessTests(unittest.TestCase):
    def test_waits_through_launcher_pid_before_hashing_real_binary(self):
        with patch.object(rollout, "pid", side_effect=[10, 11]), \
             patch.object(rollout, "sha", side_effect=["launcher", "candidate"]), \
             patch.object(rollout, "public_config", return_value={"enabled": True}), \
             patch.object(rollout.time, "sleep"):
            self.assertEqual(rollout.wait_ready("candidate", {"enabled": True}), 11)

    def test_wrong_account_configuration_does_not_pass_readiness(self):
        with patch.object(rollout, "pid", return_value=12), \
             patch.object(rollout, "sha", return_value="candidate"), \
             patch.object(rollout, "public_config", side_effect=[{"operators": [1]}, {"operators": [2]}]), \
             patch.object(rollout.time, "sleep"):
            self.assertEqual(rollout.wait_ready("candidate", {"operators": [2]}), 12)

    def test_timeout_is_not_success(self):
        with patch.object(rollout.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                rollout.wait_ready("candidate", {}, seconds=1)


if __name__ == "__main__":
    unittest.main()
