import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch
import stage_admission as s


class CleanupTests(unittest.TestCase):
    def test_stops_only_owned_candidate(self):
        with patch.object(s, "run", side_effect=["Realm1 isolated admission candidate " + s.EXPECTED,
                                                "{ path=/pinned/admission ; argv[]=/pinned/admission; }", ""]) as run:
            s.stop_owned_candidate(Path("/pinned/admission"))
            run.assert_called_with("systemctl", "stop", s.UNIT)

    def test_does_not_stop_other_unit_configuration(self):
        with patch.object(s, "run", side_effect=["other", "/pinned/admission"]) as run:
            s.stop_owned_candidate(Path("/pinned/admission"))
            self.assertEqual(run.call_count, 2)

    def test_rejects_prefix_and_argument_matches(self):
        for command in ["{ path=/pinned/admission-other ; argv[]=/pinned/admission-other; }",
                        "{ path=/other ; argv[]=/other /pinned/admission; }"]:
            with self.subTest(command=command), patch.object(s, "run", side_effect=[
                    "Realm1 isolated admission candidate " + s.EXPECTED, command]) as run:
                s.stop_owned_candidate(Path("/pinned/admission"))
                self.assertEqual(run.call_count, 2)

    def test_cleanup_failure_does_not_replace_launch_exception(self):
        with patch.object(s, "run", side_effect=subprocess.TimeoutExpired("systemctl", 30)):
            s.stop_owned_candidate(Path("/pinned/admission"))


if __name__ == "__main__":
    unittest.main()
