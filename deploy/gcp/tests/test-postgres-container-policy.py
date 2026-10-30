#!/usr/bin/env python3
"""Check the fresh PostgreSQL installer without executing it or touching Docker."""
from pathlib import Path
import shlex
import unittest


SCRIPT = (Path(__file__).resolve().parents[1] / "remote/install-postgres.sh").read_text()
RUN = shlex.split(SCRIPT.split("docker run -d", 1)[1].replace("\\\n", " ").split('"postgres:', 1)[0])


class PostgresContainerPolicyTests(unittest.TestCase):
    def test_shared_memory_is_persistent_container_configuration(self):
        self.assertIn("--shm-size=2g", RUN)

    def test_logs_have_bounded_compressed_rotation(self):
        for option in ("--log-driver=json-file", "--log-opt=max-size=100m",
                       "--log-opt=max-file=100", "--log-opt=compress=true"):
            self.assertIn(option, RUN)

    def test_created_container_policy_is_checked_before_readiness(self):
        inspect = SCRIPT.index("{{.HostConfig.ShmSize}}")
        self.assertGreater(inspect, SCRIPT.index("docker run -d"))
        self.assertLess(inspect, SCRIPT.index("pg_isready"))
        self.assertIn("2147483648 json-file 100m 100 true", SCRIPT[inspect:])
        self.assertIn("PostgreSQL container policy not applied", SCRIPT[inspect:])
        failure = SCRIPT.split('if [ "$policy" !=', 1)[1].split("\nfi", 1)[0]
        self.assertLess(failure.index("docker stop --time 30 parth-postgres"), failure.index("exit 1"))

    def test_existing_data_volume_and_restart_policy_are_preserved(self):
        self.assertIn("/var/lib/parth/postgres:/var/lib/postgresql/data", RUN)
        self.assertEqual(RUN[RUN.index("--restart") + 1], "unless-stopped")


if __name__ == "__main__":
    unittest.main()
