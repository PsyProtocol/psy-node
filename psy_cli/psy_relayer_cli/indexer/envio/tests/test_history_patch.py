"""Run after applying the patch; fixtures never modify installed dependencies."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HOME = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("history_patch", HOME / "scripts/patch-history-backfill.py")
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


class PatchTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.package = self.home / "node_modules/envio"
        (self.package / "src/db").mkdir(parents=True)
        (self.package / "package.json").write_text(json.dumps({"version": "2.32.10"}))
        for name in ("EntityHistory.res", "EntityHistory.res.js"):
            source = HOME / "node_modules/envio/src/db" / name
            (self.package / "src/db" / name).write_bytes(source.read_bytes())

    def test_apply_and_check_are_idempotent_even_after_rescript_build(self):
        before = patcher.patch(self.home, check=True)
        self.assertEqual(before, patcher.patch(self.home))
        self.assertEqual(before, patcher.patch(self.home, check=True))

    def test_unsupported_version_refused_without_writes(self):
        (self.package / "package.json").write_text('{"version":"2.33.0"}')
        before = (self.package / "src/db/EntityHistory.res").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "Unsupported"):
            patcher.patch(self.home)
        self.assertEqual(before, (self.package / "src/db/EntityHistory.res").read_bytes())

    def test_modified_query_refused(self):
        for kind in ("res", "js"):
            text = patcher.replacement(kind).replace("jsonb_populate_record", "wrong_function")
            with self.assertRaises(RuntimeError):
                patcher.transform(text, kind)

    def test_unknown_unpatched_source_refused(self):
        for kind in ("res", "js"):
            with self.assertRaisesRegex(RuntimeError, "Unknown"):
                patcher.transform("unexpected dependency contents", kind)

    def test_missing_dependency_refused(self):
        with self.assertRaisesRegex(RuntimeError, "missing"):
            patcher.patch(self.home / "missing")

    def test_shared_generated_package_checked_once(self):
        (self.home / "generated/node_modules").mkdir(parents=True)
        (self.home / "generated/node_modules/envio").symlink_to(self.package)
        self.assertEqual(len(patcher.patch(self.home, check=True)), 2)


if __name__ == "__main__":
    unittest.main()
