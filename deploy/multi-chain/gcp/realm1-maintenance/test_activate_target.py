import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("activate", Path(__file__).with_name("activate_target.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ActivationTests(unittest.TestCase):
    def records(self):
        inv = dict(sha256="a" * 64, files=588608, directories=1, bytes=1637895789)
        return (dict(inventory=inv.copy(), source_fenced=True, sampled_at=10),
                dict(inventory=inv.copy(), source_fenced=True, sampled_at=20),
                dict(inventory=inv.copy(), target_fenced=True, sampled_at=21))

    def test_three_equal(self):
        m.consistent(*self.records())

    def test_mismatch_stops(self):
        records = self.records()
        records[2]["inventory"]["sha256"] = "b" * 64
        with self.assertRaises(ValueError):
            m.consistent(*records)

    def test_missing_fence_stops(self):
        records = self.records()
        records[0]["source_fenced"] = False
        with self.assertRaises(ValueError):
            m.consistent(*records)

    def test_outside_audit_directory_stops(self):
        with self.assertRaises(ValueError):
            m.audit_path("/tmp/source-1.json", "source")


if __name__ == "__main__":
    unittest.main()
