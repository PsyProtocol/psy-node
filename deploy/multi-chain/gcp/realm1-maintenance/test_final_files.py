import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("final_files", Path(__file__).with_name("final_files.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InventoryTests(unittest.TestCase):
    def test_activation_between_precheck_and_lock_prevents_final_copy(self):
        active = False

        def check():
            if active:
                raise RuntimeError("target became active")

        def acquire(*args):
            nonlocal active
            active = True

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(m.p, "STATE", Path(tmp)), \
                 mock.patch.object(m.p, "target_check", side_effect=check) as guard, \
                 mock.patch.object(m, "ensure_audit"), \
                 mock.patch.object(m.fcntl, "flock", side_effect=acquire), \
                 mock.patch.object(m.subprocess, "run") as copy:
                with self.assertRaisesRegex(RuntimeError, "target became active"):
                    m.copy()
                self.assertEqual(guard.call_count, 2)
                copy.assert_not_called()

    def test_equal_copies_ignore_timestamps(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            for root in (a, b):
                root.mkdir()
                (root / "nested").mkdir()
                (root / "nested" / "state").write_bytes(b"checkpoint")
            self.assertEqual(m.inventory(a), m.inventory(b))
            (b / "nested" / "state").write_bytes(b"checkpoinu")
            self.assertNotEqual(m.inventory(a), m.inventory(b))

    def test_extra_files_and_directories_change_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = m.inventory(root)
            (root / "extra").mkdir()
            self.assertNotEqual(before, m.inventory(root))
            before = m.inventory(root)
            (root / "extra" / "empty").touch()
            self.assertNotEqual(before, m.inventory(root))

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "external").symlink_to("/etc")
            with self.assertRaises(RuntimeError):
                m.inventory(root)

    def test_walk_failure_is_not_empty_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(m.os, "scandir", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    m.inventory(Path(tmp))

    def test_child_walk_failure_is_not_partial_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "child").mkdir()
            original = m.os.scandir
            def scan(path):
                if Path(path).name == "child":
                    raise PermissionError("denied child")
                return original(path)
            with mock.patch.object(m.os, "scandir", side_effect=scan):
                with self.assertRaises(PermissionError):
                    m.inventory(root)


if __name__ == "__main__":
    unittest.main()
