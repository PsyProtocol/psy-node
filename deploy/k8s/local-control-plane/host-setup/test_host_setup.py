#!/usr/bin/env python3
import contextlib
import copy
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import host_setup as host


class HostSetupTests(unittest.TestCase):
    def test_x1_and_unknown_hosts_are_not_targets(self):
        self.assertEqual(set(host.HOSTS), {"local", "x2", "x3", "x4"})
        with patch("sys.argv", ["host_setup.py", "x1", "install", "--apply"]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            host.main()

    def test_wrong_physical_host_refused(self):
        with patch.object(Path, "read_text", return_value="arc99x1\n"), self.assertRaises(ValueError):
            host.identity("x2")

    def test_no_apply_is_a_plan_with_zero_mutations(self):
        with patch("sys.argv", ["host_setup.py", "x2", "install"]), patch.object(host, "identity", return_value=host.HOSTS["x2"]), patch.object(host, "install") as install, patch.object(host.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(host.main(), 0)
        self.assertFalse(json.loads(output.getvalue())["mutations"])
        install.assert_not_called()
        run.assert_not_called()

    def test_mutation_requires_root(self):
        with patch("sys.argv", ["host_setup.py", "x3", "install", "--apply"]), patch.object(host, "identity", return_value=host.HOSTS["x3"]), patch.object(host.os, "geteuid", return_value=1000), patch.object(host, "install") as install, self.assertRaises(ValueError):
            host.main()
        install.assert_not_called()

    def test_network_requires_console_and_ip_acknowledgement(self):
        for flags in ([], ["--console-confirmed"]):
            with patch("sys.argv", ["host_setup.py", "x2", "bridge", "--apply", *flags]), patch.object(host, "identity", return_value=host.HOSTS["x2"]), patch.object(host.os, "geteuid", return_value=0), patch.object(host.os, "umask"), patch.object(host, "bridge") as bridge, self.assertRaises(ValueError):
                host.main()
            bridge.assert_not_called()

    def test_owned_file_never_overwrites_other_work(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "config"
            p.write_text("existing config")
            with self.assertRaises(ValueError):
                host.owned_file(p, "replacement")
            self.assertEqual(p.read_text(), "existing config")
            link = Path(directory) / "link"
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                host.owned_file(link, "replacement")

    def test_missing_svm_stops_before_install_or_modprobe(self):
        with patch.object(host.subprocess, "run", return_value=SimpleNamespace(returncode=3)) as run, patch.object(Path, "read_text", return_value="flags : avx2\n"), self.assertRaises(ValueError):
            host.install(host.HOSTS["local"])
        self.assertTrue(all(call.args[0][0] == "systemctl" for call in run.call_args_list))

    def test_pool_ancestor_symlink_rejected_before_mkdir(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "real").mkdir()
            (base / "link").symlink_to(base / "real", target_is_directory=True)
            with patch.object(host.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)), self.assertRaises(ValueError):
                host.prepare_pool(str(base / "link/newpool"), "psy", "libvirt-qemu")
            self.assertFalse((base / "real/newpool").exists())

    def test_network_templates_keep_other_interfaces_and_original_files(self):
        texts = host.network_texts(host.HOSTS["x3"])
        self.assertIn("Address=192.168.5.41/24", texts[1])
        self.assertIn("Name=enp3s0", texts[2])
        self.assertIn("Bridge=br0", texts[2])
        self.assertTrue(all("wg0" not in text and "tailscale" not in text for text in texts))
        self.assertTrue(all(p.name.startswith("00-psy-k8s-") for p in host.NETWORK_FILES))

    def disk(self, edit=None, signatures="", disks=None):
        info = {"name": "sdb", "type": "disk", "size": 2 * 1024**4, "serial": "NEW_DISK_123", "mountpoints": [None]}
        if edit:
            edit(info)
        target = SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=stat.S_IFBLK))
        with patch.object(Path, "resolve", return_value=target), patch.object(host, "backing_disks", return_value=disks or {"sda"}), patch.object(host, "run", side_effect=[json.dumps({"blockdevices": [info]}), signatures]):
            return host.validate_blank_disk(host.HOSTS["x4"], "/dev/disk/by-id/NEW_DISK", "NEW_DISK_123")

    def test_blank_new_disk_is_accepted_for_initialization(self):
        self.assertIsNotNone(self.disk())

    def test_existing_disk_or_wrong_serial_is_refused(self):
        for edit in (
            lambda d: d.update(children=[{"name": "sdb1"}]),
            lambda d: d.update(serial="WRONG_DISK"),
            lambda d: d.update(size=200 * 2**30),
            lambda d: d.update(mountpoints=["/home"]),
            lambda d: d.update(name="sda"),
        ):
            with self.assertRaises(ValueError):
                self.disk(edit)
        with self.assertRaises(ValueError):
            self.disk(signatures="ext4")

    def test_initialization_only_on_x4_and_stable_id(self):
        with self.assertRaises(ValueError):
            host.validate_blank_disk(host.HOSTS["x3"], "/dev/disk/by-id/NEW", "SERIAL")
        with self.assertRaises(ValueError):
            host.validate_blank_disk(host.HOSTS["x4"], "/dev/sdb", "SERIAL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
