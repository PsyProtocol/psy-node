"""Offline rollback fault injection; never contacts systemd, Redis, or an RPC."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("edge_rollout", Path(__file__).with_name("rollout.py"))
rollout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rollout)


class RollbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="edge-rollout-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "parth-edge-reputation" / "20261008-abcdef012345"
        self.name = "realm-0"
        self.unit = rollout.UNITS[self.name][0]
        self.drop = self.base / "systemd" / (self.unit + ".d") / rollout.DROP_NAME
        self.old = self.base / "original"
        self.old.write_bytes(b"original executable fixture")
        self.old_hash = hashlib.sha256(self.old.read_bytes()).hexdigest()
        self.baseline = {"protected": {"current": "/original-release", "files": {"genesis": "fixed"}},
            "other_pids": {"parth-coordinator-processor.service": "111"},
            "edges": {self.name: {"path": str(self.old), "sha256": self.old_hash}}}
        self.manifest = {"baseline": self.baseline, "binary_sha256": "new-hash", "installer_sha256": "installer-hash"}
        self.run = Mock()
        self.ready = Mock(return_value={"pid": "222", "sha256": self.old_hash, "checkpoint": 123})
        self.protected = Mock(return_value=self.baseline["protected"])
        mocks = {
            "PATH_ANCHORS": (self.base,), "OWNER_UID": os.geteuid(),
            "OLD_HASHES": {self.name: self.old_hash},
            "drop_path": Mock(return_value=self.drop), "run": self.run, "ready": self.ready,
            "protected": self.protected,
            "other_pids": Mock(return_value=self.baseline["other_pids"]),
            "snapshot": Mock(side_effect=AssertionError("must not snapshot a failed Edge")),
            "executable": Mock(side_effect=AssertionError("must not require an active Edge")),
        }
        for name, value in mocks.items():
            p = patch.object(rollout, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.state_path = rollout.recovery_path(self.name, self.root)
        rollout.secure_dir(self.state_path.parent, 0o700)
        self.write_state("owned")
        rollout.atomic(self.drop, rollout.drop_bytes(self.name, self.root), 0o644)

    def write_state(self, phase):
        rollout.atomic(self.state_path, json.dumps({
            "owner": rollout.recovery_owner(self.name, self.manifest, self.root), "phase": phase,
        }).encode())

    def phase(self):
        return json.loads(self.state_path.read_text())["phase"]

    def rollback(self):
        return rollout.rollback(self.name, self.manifest, self.root)

    def assert_no_restart(self):
        self.assertNotIn(("systemctl", "restart", self.unit), [c.args for c in self.run.call_args_list])

    def test_failed_edge_rollback_and_completed_retry(self):
        sibling = self.drop.with_name("95-existing.conf")
        sibling.write_bytes(b"existing config")
        self.assertEqual(self.rollback(), self.ready.return_value)
        self.assertFalse(self.drop.exists())
        self.assertEqual(sibling.read_bytes(), b"existing config")
        self.assertEqual(self.phase(), "rolled_back")
        self.assertEqual([c.args for c in self.run.call_args_list], [
            ("systemctl", "daemon-reload"), ("systemctl", "restart", self.unit)])
        self.ready.assert_called_with(self.name, self.old_hash)
        self.run.reset_mock()
        self.rollback()
        self.run.assert_not_called()

    def test_original_runtime_need_not_be_inside_root_owned_release(self):
        with patch.object(rollout, "PATH_ANCHORS", (self.root.parent, self.base / "systemd")):
            self.rollback()
        self.assertEqual(self.phase(), "rolled_back")
        self.assertEqual(self.old.read_bytes(), b"original executable fixture")

    def test_protected_drift_refuses_before_unlink(self):
        self.protected.return_value = {"current": "/changed"}
        with self.assertRaisesRegex(RuntimeError, "protected config changed"):
            self.rollback()
        self.assertTrue(self.drop.exists())
        self.assertEqual(self.phase(), "owned")
        self.run.assert_not_called()

    def test_unloaded_disk_drop_in_blocks_rollback(self):
        unit_dir = self.base / "systemd"
        self.run.return_value = str(unit_dir)
        self.baseline["protected"] = {"disk_units": rollout.disk_unit_files()}
        self.protected.side_effect = lambda: {"disk_units": rollout.disk_unit_files()}
        self.write_state("owned")
        foreign = self.drop.with_name("98-unloaded.conf")
        foreign.write_bytes(b"[Service]\nEnvironment=UNEXPECTED=1\n")
        self.run.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "protected config changed"):
            self.rollback()
        self.assertTrue(self.drop.exists())
        self.assertEqual(self.phase(), "owned")
        self.assertTrue(all(c.args == ("systemctl", "show", "-p", "UnitPath", "--value")
            for c in self.run.call_args_list))

    def test_drift_loaded_by_reload_refuses_before_restart(self):
        self.protected.side_effect = [self.baseline["protected"], {"current": "/changed"}]
        with self.assertRaisesRegex(RuntimeError, "protected config changed"):
            self.rollback()
        self.assertFalse(self.drop.exists())
        self.assertEqual(self.phase(), "rollback_pending")
        self.assert_no_restart()
        self.protected.side_effect = None
        self.rollback()
        self.assertEqual(self.phase(), "rolled_back")

    def test_unrelated_pid_drift_refuses(self):
        rollout.other_pids.return_value = {"parth-coordinator-processor.service": "999"}
        with self.assertRaisesRegex(RuntimeError, "unrelated service PID changed"):
            self.rollback()
        self.assertTrue(self.drop.exists())
        self.run.assert_not_called()

    def test_original_binary_drift_refuses(self):
        self.old.write_bytes(b"unexpected executable")
        with self.assertRaisesRegex(RuntimeError, "original rollback binary changed"):
            self.rollback()
        self.assertTrue(self.drop.exists())
        self.run.assert_not_called()

    def test_missing_drop_without_pending_state_refuses(self):
        self.drop.unlink()
        with self.assertRaisesRegex(RuntimeError, "without pending recovery"):
            self.rollback()
        self.run.assert_not_called()

    def test_missing_ownership_state_refuses(self):
        self.state_path.unlink()
        with self.assertRaisesRegex(RuntimeError, "missing trusted path"):
            self.rollback()
        self.assertTrue(self.drop.exists())
        self.run.assert_not_called()

    def test_record_bound_to_manifest_and_baseline(self):
        for field in ("binary_sha256", "installer_sha256", "baseline"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.manifest)
                if field == "baseline":
                    changed[field]["other_pids"] = {}
                else:
                    changed[field] = "foreign"
                with self.assertRaisesRegex(RuntimeError, "recovery ownership differs"):
                    rollout.rollback(self.name, changed, self.root)
                self.assertTrue(self.drop.exists())
        self.run.assert_not_called()

    def test_foreign_drop_refused_during_pending_retry(self):
        self.write_state("rollback_pending")
        self.drop.write_bytes(b"foreign override")
        with self.assertRaisesRegex(RuntimeError, "override changed"):
            self.rollback()
        self.assertEqual(self.drop.read_bytes(), b"foreign override")
        self.run.assert_not_called()

    def test_reappeared_drop_after_completion_refuses(self):
        self.write_state("rolled_back")
        with self.assertRaisesRegex(RuntimeError, "override changed"):
            self.rollback()
        self.assertTrue(self.drop.exists())
        self.run.assert_not_called()

    def test_symlink_drop_and_state_refused(self):
        for path in (self.drop, self.state_path):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.unlink()
                path.symlink_to(self.base / "missing-target")
                with self.assertRaisesRegex(RuntimeError, "symlink"):
                    self.rollback()
                self.assertTrue(path.is_symlink())
                path.unlink()
                path.write_bytes(original)
        self.run.assert_not_called()

    def test_interrupt_before_unlink_has_durable_pending_state(self):
        with patch.object(Path, "unlink", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.rollback()
        self.assertTrue(self.drop.exists())
        self.assertEqual(self.phase(), "rollback_pending")
        self.run.assert_not_called()
        self.rollback()
        self.assertEqual(self.phase(), "rolled_back")

    def test_directory_sync_failure_after_unlink_is_recoverable(self):
        original = rollout.sync_dir

        def fail_drop_sync(path):
            if path == self.drop.parent:
                raise OSError("injected directory fsync failure")
            original(path)

        with patch.object(rollout, "sync_dir", side_effect=fail_drop_sync):
            with self.assertRaisesRegex(OSError, "injected"):
                self.rollback()
        self.assertFalse(self.drop.exists())
        self.assertEqual(self.phase(), "rollback_pending")
        self.run.assert_not_called()
        self.rollback()
        self.assertEqual(self.phase(), "rolled_back")

    def test_reload_failure_allows_missing_drop_retry(self):
        self.run.side_effect = RuntimeError("injected reload failure")
        with self.assertRaisesRegex(RuntimeError, "injected"):
            self.rollback()
        self.assertFalse(self.drop.exists())
        self.assertEqual(self.phase(), "rollback_pending")
        self.assert_no_restart()
        self.run.side_effect = None
        self.rollback()
        self.assertEqual(self.phase(), "rolled_back")

    def test_restart_failure_allows_missing_drop_retry(self):
        self.run.side_effect = [None, RuntimeError("injected restart failure")]
        with self.assertRaisesRegex(RuntimeError, "injected"):
            self.rollback()
        self.assertFalse(self.drop.exists())
        self.assertEqual(self.phase(), "rollback_pending")
        self.run.side_effect = None
        self.rollback()
        self.assertEqual(self.phase(), "rolled_back")

    def test_readiness_failure_allows_missing_drop_retry(self):
        self.ready.side_effect = RuntimeError("injected readiness failure")
        with self.assertRaisesRegex(RuntimeError, "injected"):
            self.rollback()
        self.assertEqual(self.phase(), "rollback_pending")
        self.ready.side_effect = None
        self.rollback()
        self.assertEqual(self.phase(), "rolled_back")

    def test_completion_write_failure_allows_retry(self):
        original = rollout.atomic

        def fail_completion(path, data, mode=0o600):
            if json.loads(data).get("phase") == "rolled_back":
                raise OSError("injected completion write failure")
            original(path, data, mode)

        with patch.object(rollout, "atomic", side_effect=fail_completion):
            with self.assertRaisesRegex(OSError, "injected"):
                self.rollback()
        self.assertEqual(self.phase(), "rollback_pending")
        self.rollback()
        self.assertEqual(self.phase(), "rolled_back")

    def test_pending_write_failure_keeps_drop(self):
        with patch.object(rollout, "atomic", side_effect=OSError("injected state write failure")):
            with self.assertRaisesRegex(OSError, "injected"):
                self.rollback()
        self.assertTrue(self.drop.exists())
        self.assertEqual(self.phase(), "owned")
        self.run.assert_not_called()


class PathSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="edge-path-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        for name, value in {"PATH_ANCHORS": (self.base,), "OWNER_UID": os.geteuid()}.items():
            p = patch.object(rollout, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_umask_modes_and_private_backups(self):
        previous = os.umask(0o077)
        try:
            directory = self.base / "parth-edge-reputation" / "20261008-abcdef012345" / "target" / "release"
            rollout.secure_dir(directory)
            for path in (directory, directory.parent, directory.parent.parent, directory.parent.parent.parent):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
            source = self.base / "source"
            source.write_bytes(b"binary")
            rollout.copy_exclusive(source, directory / "binary", 0o755)
            self.assertEqual(stat.S_IMODE((directory / "binary").stat().st_mode), 0o755)
            private = self.base / "rollback" / "realm-0"
            rollout.secure_dir(private, 0o700)
            rollout.atomic(private / "state", b"private")
            self.assertEqual(stat.S_IMODE(private.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((private / "state").stat().st_mode), 0o600)
            drop = self.base / "systemd" / "drop.conf"
            rollout.atomic(drop, b"drop", 0o644)
            self.assertEqual(stat.S_IMODE(drop.stat().st_mode), 0o644)
        finally:
            os.umask(previous)

    def test_symlink_parent_rejected_without_writing_target(self):
        real = self.base / "real"
        real.mkdir()
        link = self.base / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            rollout.atomic(link / "file", b"must not write")
        self.assertFalse((real / "file").exists())

    def test_writable_existing_directory_rejected_without_chmod(self):
        directory = self.base / "unsafe"
        directory.mkdir()
        directory.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, "writable path"):
            rollout.secure_dir(directory)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)

    def test_untrusted_owner_rejected(self):
        with patch.object(rollout, "OWNER_UID", os.geteuid() + 1):
            with self.assertRaisesRegex(RuntimeError, "untrusted owner"):
                rollout.trusted_path(self.base, directory=True)

    def test_writable_existing_file_rejected(self):
        path = self.base / "unsafe"
        path.write_bytes(b"original")
        path.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "writable path"):
            rollout.atomic(path, b"replacement")
        self.assertEqual(path.read_bytes(), b"original")

    def test_hardlinked_existing_file_rejected(self):
        path = self.base / "original"
        path.write_bytes(b"original")
        link = self.base / "alias"
        os.link(path, link)
        with self.assertRaisesRegex(RuntimeError, "hard-linked"):
            rollout.atomic(link, b"replacement")
        self.assertEqual(path.read_bytes(), b"original")

    def test_copy_does_not_overwrite_existing_binary(self):
        source = self.base / "source"
        target = self.base / "target"
        source.write_bytes(b"new")
        target.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            rollout.copy_exclusive(source, target, 0o755)
        self.assertEqual(target.read_bytes(), b"existing")

    def test_atomic_syncs_parent_after_replacement(self):
        target = self.base / "state"
        observations = []
        with patch.object(rollout, "sync_dir", side_effect=lambda p: observations.append((p, target.read_bytes()))):
            rollout.atomic(target, b"durable")
        self.assertEqual(observations, [(self.base, b"durable")])

    def test_package_uses_dedicated_root_without_changing_old_paths(self):
        manifest = {"source_commit": "a" * 40, "binary_sha256": "binary", "installer_sha256": "installer",
            "baseline": {"edges": {"realm-0": {"path": "/opt/parth/edge-hotfix/original/psy_node_cli"}}}}
        with patch.object(Path, "read_text", return_value=json.dumps(manifest)), \
                patch.object(rollout, "sha", side_effect=["binary", "installer"]):
            actual, root = rollout.package()
        self.assertEqual(root, Path("/opt/parth-edge-reputation/20261008-aaaaaaaaaaaa"))
        self.assertEqual(actual, manifest)


class DiskUnitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="edge-unit-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        p = patch.object(rollout, "run", return_value=str(self.base))
        self.run = p.start()
        self.addCleanup(p.stop)
        p = patch.object(rollout, "drop_path", side_effect=lambda name:
            self.base / (rollout.UNITS[name][0] + ".d") / rollout.DROP_NAME)
        p.start()
        self.addCleanup(p.stop)

    def test_unloaded_instance_template_prefix_and_type_overrides(self):
        baseline = rollout.disk_unit_files()
        for directory in ("parth-realm-edge@0.service.d", "parth-realm-edge@.service.d",
                "parth-realm-.service.d", "parth-.service.d", "service.d"):
            with self.subTest(directory=directory):
                path = self.base / directory / "new.conf"
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(b"[Service]\nEnvironment=DRIFT=1\n")
                self.assertNotEqual(rollout.disk_unit_files(), baseline)
                self.assertIn(str(path), rollout.disk_unit_files()["files"])
                path.unlink()
                self.assertEqual(rollout.disk_unit_files(), baseline)

    def test_only_exact_owned_instance_drop_is_excluded(self):
        baseline = rollout.disk_unit_files()
        for name in rollout.UNITS:
            path = rollout.drop_path(name)
            path.parent.mkdir()
            path.write_bytes(rollout.drop_bytes(name, Path("/release")))
        self.assertEqual(rollout.disk_unit_files(), baseline)
        foreign = self.base / "service.d" / rollout.DROP_NAME
        foreign.parent.mkdir()
        foreign.write_bytes(b"foreign")
        self.assertIn(str(foreign), rollout.disk_unit_files()["files"])

    def test_unloaded_fragment_changes_and_masks_detected(self):
        path = self.base / "parth-realm-edge@.service"
        path.write_bytes(b"original")
        baseline = rollout.disk_unit_files()
        path.write_bytes(b"changed")
        self.assertNotEqual(rollout.disk_unit_files(), baseline)
        path.unlink()
        path.symlink_to("/dev/null")
        masked = rollout.disk_unit_files()
        self.assertNotEqual(masked, baseline)
        self.assertEqual(masked["files"][str(path)]["symlink"], "/dev/null")

    def test_all_manager_search_paths_are_checked(self):
        vendor = self.base / "vendor"
        runtime = self.base / "runtime"
        vendor.mkdir()
        runtime.mkdir()
        self.run.return_value = f"{runtime} {vendor}"
        baseline = rollout.disk_unit_files()
        path = vendor / "parth-coordinator-edge@.service"
        path.write_bytes(b"vendor unit")
        self.assertNotEqual(rollout.disk_unit_files(), baseline)
        self.assertIn(str(path), rollout.disk_unit_files()["files"])

    def test_invalid_search_path_fails_closed(self):
        for value in ("", "relative/path"):
            with self.subTest(value=value):
                self.run.return_value = value
                with self.assertRaisesRegex(RuntimeError, "invalid systemd unit search path"):
                    rollout.disk_unit_files()


if __name__ == "__main__":
    unittest.main()
