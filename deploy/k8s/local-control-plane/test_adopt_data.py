#!/usr/bin/env python3
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import test_four_node as shared

adopt = shared.load("adopt_data", Path(__file__).parent / "adopt-data.py")


class AdoptDataTests(unittest.TestCase):
    def test_data_uuid_serial_and_paths_are_bound(self):
        cfg = shared.lab.validate(shared.inventory())
        self.assertEqual(cfg["hosts"]["x4"]["data_pool"], "/data/psy-k8s-lab/vm-data")
        for field, value in (("data_uuid", "another-uuid"), ("data_serial", "another-ssd"), ("data_pool", "/data"), ("data_mount", "/mnt/disk4t")):
            cfg = shared.inventory()
            cfg["hosts"]["x4"][field] = value
            with self.assertRaises(ValueError):
                shared.lab.validate(cfg)
        cfg = shared.inventory()
        cfg["hosts"]["x4"].update(data_mount="/mnt/psy-k8s-lab", data_pool="/mnt/psy-k8s-lab/vm-data")
        cfg["hosts"]["x4"].pop("data_uuid")
        cfg["hosts"]["x4"].pop("data_serial")
        shared.lab.validate(cfg)

    def test_plan_never_calls_prepare(self):
        with patch("sys.argv", ["adopt-data.py"]), patch.object(adopt, "inspect", return_value={"uuid": adopt.UUID}), patch.object(adopt.shutil, "disk_usage", return_value=types.SimpleNamespace(free=288 * 2**30)), patch.object(adopt, "prepare") as prepare, contextlib.redirect_stdout(io.StringIO()) as output:
            adopt.main()
        prepare.assert_not_called()
        self.assertFalse(json.loads(output.getvalue())["applied"])

    def test_root_is_rejected_before_disk_commands(self):
        with patch.object(adopt.setup, "identity", return_value={"user": "psy"}), patch.object(adopt.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=1000)), patch.object(adopt.os, "geteuid", return_value=0), patch.object(adopt.setup, "run") as run, self.assertRaises(ValueError):
            adopt.inspect()
        run.assert_not_called()

    def test_wrong_uuid_is_rejected_before_other_disk_checks(self):
        with patch.object(adopt.setup, "identity", return_value={"user": "psy"}), patch.object(adopt.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=os.geteuid())), patch.object(Path, "is_symlink", return_value=False), patch.object(Path, "is_mount", return_value=True), patch.object(adopt.setup, "run", return_value="wrong-uuid") as run, self.assertRaisesRegex(ValueError, "UUID"):
            adopt.inspect()
        self.assertEqual(run.call_count, 1)

    def test_new_pool_only_sets_acls_on_new_paths_and_preserves_existing_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            mount = Path(tmp)
            existing = mount / "existing-data"
            existing.write_text("preserve this")
            root, pool = mount / "psy-k8s-lab", mount / "psy-k8s-lab/vm-data"
            receipt = {"uuid": adopt.UUID, "qemu_uid": 999}
            with patch.object(adopt, "MOUNT", mount), patch.object(adopt, "ROOT", root), patch.object(adopt, "POOL", pool), patch.object(adopt.subprocess, "run") as run, patch.object(adopt, "verify_existing") as verify:
                adopt.prepare(receipt)
                verify.assert_called_once_with(receipt)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertEqual(calls, [["setfacl", "-b", "-k", str(root), str(pool)], ["setfacl", "-m", "u:999:--x", str(root)], ["setfacl", "-m", "u:999:r-x", str(pool)]])
            self.assertEqual(existing.read_text(), "preserve this")
            self.assertEqual(json.loads((root / "pool-receipt.json").read_text()), receipt)

    def test_existing_unknown_or_symlink_directory_is_not_modified(self):
        for symlink in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                mount = Path(tmp)
                real = mount / "existing"
                real.mkdir()
                (real / "valuable").write_text("keep")
                root = mount / "psy-k8s-lab"
                if symlink:
                    root.symlink_to(real, target_is_directory=True)
                else:
                    root.mkdir()
                with patch.object(adopt, "MOUNT", mount), patch.object(adopt, "ROOT", root), patch.object(adopt, "POOL", root / "vm-data"), patch.object(subprocess, "run") as run, self.assertRaises(ValueError):
                    adopt.prepare({"qemu_uid": 999})
                run.assert_not_called()
                self.assertEqual((real / "valuable").read_text(), "keep")


if __name__ == "__main__":
    unittest.main(verbosity=2)
