#!/usr/bin/env python3
"""Regression tests for a fail-closed per-crate coverage gate."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CRATES = ("psy_node_scylla", "psy_node_nats", "psy_node_redis")


class CoverageGateTest(unittest.TestCase):
    def run_gate(self, counts, *args):
        files = [{"filename": f"/repo/{c}/src/lib.rs", "summary": {"lines": {"count": n, "covered": hit}}}
                 for c, n, hit in counts]
        # Fully covered tests and dependencies must not inflate source coverage.
        for name in ("psy_node_scylla/tests/integration.rs", "other/src/lib.rs"):
            files.append({"filename": f"/repo/{name}", "summary": {"lines": {"count": 99999, "covered": 99999}}})
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "coverage.json"
            report.write_text(json.dumps({"data": [{"files": files}]}))
            return subprocess.run([sys.executable, str(Path(__file__).with_name("check-db-coverage.py")), str(report), *args], capture_output=True, text=True)

    def test_each_crate_must_pass_even_when_average_passes(self):
        self.assertEqual(self.run_gate([(c, 100, hit) for c, hit in zip(CRATES, (79, 100, 100))]).returncode, 1)

    def test_missing_and_zero_line_crates_fail(self):
        self.assertEqual(self.run_gate([(c, 100, 100) for c in CRATES[:2]]).returncode, 1)
        self.assertEqual(self.run_gate([(c, 0, 0) for c in CRATES]).returncode, 1)

    def test_single_crate_requires_its_own_coverage(self):
        self.assertEqual(self.run_gate([(CRATES[0], 100, 91)], "--crate", CRATES[0]).returncode, 0)
        self.assertEqual(self.run_gate([(CRATES[0], 100, 89)], "--crate", CRATES[0]).returncode, 1)
        self.assertEqual(self.run_gate([(CRATES[1], 100, 100)], "--crate", CRATES[0]).returncode, 1)

    def test_threshold_uses_unrounded_ratio(self):
        self.assertEqual(self.run_gate([(c, 100000, 79999) for c in CRATES], "--minimum", "80").returncode, 1)
        self.assertEqual(self.run_gate([(c, 100000, 80000) for c in CRATES], "--minimum", "80").returncode, 0)

    def test_distinct_default_floors(self):
        floors = (90, 92, 95)
        exact = [(c, 100, floor) for c, floor in zip(CRATES, floors)]
        self.assertEqual(self.run_gate(exact).returncode, 0)
        for crate, floor in zip(CRATES, floors):
            with self.subTest(crate=crate):
                below = [(c, 100, floor - 1 if c == crate else 100) for c in CRATES]
                self.assertEqual(self.run_gate(below).returncode, 1)


if __name__ == "__main__":
    unittest.main()
