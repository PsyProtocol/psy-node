"""Offline synthetic-fixture tests; no credentials, network or systemd changes."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_faucet as faucet


class FaucetTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for name in ("RELEASE", "CUSTODY", "STATE", "UNITS", "OLD_CUSTODY"):
            self.stack.enter_context(patch.object(faucet, name, self.root / name))
        faucet.UNITS.mkdir()
        self.host = self.root / "host.json"
        self.host.write_bytes(faucet.encode({"hostname": "fixture-host", "listen_addr": "192.0.2.10:29998"}))
        self.binary = self.root / "binary"
        self.canonical = self.root / "canonical"
        self.rpc = self.root / "rpc"
        for path, pin in ((self.binary, "BINARY_SHA256"), (self.canonical, "CANONICAL_SHA256"),
                          (self.rpc, "RPC_SHA256")):
            path.write_bytes(b"synthetic-" + path.name.encode())
            self.stack.enter_context(patch.object(faucet, pin, faucet.digest(path.read_bytes())))
        self.package = self.root / "package"
        self.args = SimpleNamespace(binary=self.binary, canonical=self.canonical, rpc=self.rpc,
            host_spec=self.host, spec_sha256=faucet.digest(self.host.read_bytes()), output=self.package)
        self.stack.enter_context(patch.object(faucet, "safe_parents"))

    def prepare(self):
        result = faucet.prepare(self.args)
        return SimpleNamespace(package=self.package, manifest_sha256=result["manifest_sha256"],
                               start_private=False, public_ingress_closed=False)

    def test_prepare_secret_free_fresh_paths_and_resource_limits(self):
        args = self.prepare()
        manifest, files = faucet.read_package(args.package, args.manifest_sha256)
        self.assertFalse(manifest["public_switch_allowed"])
        self.assertEqual(manifest["operator_count"], 100)
        self.assertNotIn("operators.cred", files)
        unit = files[faucet.UNIT].decode()
        for value in ("MemoryMax=20G", "MemorySwapMax=0", "Restart=on-failure",
                      "User=psy-faucet-r2", "LoadCredentialEncrypted=operators.json:",
                      str(faucet.STATE), "--spec-sha256 " + self.args.spec_sha256):
            self.assertIn(value, unit)
        self.assertNotIn("MemoryHigh=", unit)
        self.assertEqual(stat.S_IMODE(args.package.stat().st_mode), 0o700)
        with self.assertRaises(FileExistsError):
            faucet.prepare(self.args)

    def test_pins_tampering_inventory_and_symlinks_fail(self):
        args = self.prepare()
        for name in ("psy_user_cli", "host.json", faucet.UNIT, "prepare_faucet.py"):
            path = self.package / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaises(ValueError): faucet.read_package(self.package, args.manifest_sha256)
            path.write_bytes(original)
        extra = self.package / "unexpected"
        extra.write_bytes(b"synthetic")
        with self.assertRaises(ValueError): faucet.read_package(self.package, args.manifest_sha256)
        extra.unlink()
        link = self.root / "link"
        link.symlink_to(self.binary)
        with self.assertRaises(OSError): faucet.read_file(link)
        with self.assertRaises(ValueError): faucet.read_package(self.package, "0" * 64)

    def test_private_listener_and_exact_spec_only(self):
        for addr in ("0.0.0.0:29998", "8.8.8.8:29998", "127.0.0.1:29998", "192.0.2.10:9999"):
            with self.assertRaises(ValueError):
                faucet.validate_spec(faucet.encode({"hostname": "fixture-host", "listen_addr": addr}))
        with self.assertRaises(ValueError):
            faucet.validate_spec(faucet.encode({"hostname": "bad\nhost", "listen_addr": "192.0.2.10:29998"}))

    def test_old_active_enabled_pid_or_queued_job_rejected(self):
        stopped = {"LoadState": "loaded", "ActiveState": "inactive", "MainPID": "0",
                   "UnitFileState": "disabled", "Job": ""}
        with patch.object(Path, "iterdir", return_value=[]):
            with patch.object(faucet, "unit_state", return_value=stopped): faucet.check_stopped()
            for field, value in (("ActiveState", "active"), ("MainPID", "123"),
                                 ("UnitFileState", "enabled"), ("Job", "1")):
                with patch.object(faucet, "unit_state", return_value=dict(stopped, **{field: value})):
                    with self.assertRaises(ValueError): faucet.check_stopped()

    def test_previous_faucet_units_must_be_stopped(self):
        stopped = {"LoadState": "loaded", "ActiveState": "inactive", "MainPID": "0",
                   "UnitFileState": "disabled", "Job": ""}
        with patch.object(Path, "iterdir", return_value=[]), \
                patch.object(faucet, "unit_state", return_value=stopped) as state:
            faucet.check_stopped()
        checked = [c.args[0] for c in state.call_args_list]
        for name in ("psy-faucet-r3.service", "psy-faucet-r3-memprobe.service",
                     "psy-faucet-r3-batch.service", faucet.UNIT):
            self.assertIn(name, checked)

    def test_wrong_host_rejected_before_credentials(self):
        with patch.object(faucet.os, "geteuid", return_value=0), \
                patch.object(faucet.os, "uname", return_value=SimpleNamespace(machine="x86_64")), \
                patch.object(faucet.socket, "gethostname", return_value="other-host"):
            with self.assertRaisesRegex(ValueError, "wrong hostname"):
                faucet.check_host({"hostname": "fixture-host"})

    def test_credential_reuses_ciphertext_and_checks_plaintext_in_memory(self):
        plain = faucet.encode({"operators": ["synthetic"] * 100})
        encrypted = b"synthetic-host-bound-ciphertext"
        with patch.object(faucet, "OPERATORS_SHA256", faucet.digest(plain)):
            audit = faucet.encode({"credential_sha256": faucet.digest(encrypted),
                                  "operators_sha256": faucet.OPERATORS_SHA256, "operators": 100})
            with patch.object(faucet, "read_file", side_effect=[encrypted, audit]), \
                    patch.object(faucet, "run", return_value=plain) as run, \
                    patch.object(faucet, "write_new") as write:
                self.assertEqual(faucet.credential(), encrypted)
                run.assert_called_once_with("systemd-creds", "--name=operators.json", "decrypt", "-", "-", data=encrypted)
                write.assert_not_called()
            with patch.object(faucet, "read_file", side_effect=[encrypted, audit]), \
                    patch.object(faucet, "run", return_value=b"changed"):
                with self.assertRaisesRegex(ValueError, "identity hash"): faucet.credential()

    def test_bootstrap_install_only_and_optional_private_start_never_enable(self):
        args = self.prepare()
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with patch.object(faucet, "check_host", return_value=account), \
                patch.object(faucet, "check_stopped"), patch.object(faucet.os, "chown"), \
                patch.object(faucet, "credential", return_value=b"synthetic-encrypted"), \
                patch.object(faucet, "run", return_value=b"") as run, \
                patch.object(faucet, "read_file", wraps=faucet.read_file) as read:
            real_read = read._mock_wraps
            read.side_effect = lambda path, owner=None, private=False: real_read(path, None, private)
            result = faucet.bootstrap(args)
        self.assertFalse(result["started"])
        self.assertFalse(result["enabled"])
        self.assertFalse(result["public_switch"])
        self.assertEqual((faucet.CUSTODY / "operators.cred").read_bytes(), b"synthetic-encrypted")
        self.assertEqual(list(faucet.STATE.iterdir()), [])
        self.assertFalse(any(c.args[:2] in (("systemctl", "start"), ("systemctl", "enable")) for c in run.call_args_list))

    def test_private_start_requires_explicit_closed_ingress_before_install(self):
        args = SimpleNamespace(start_private=True, public_ingress_closed=False)
        with patch.object(faucet, "read_package") as read:
            with self.assertRaisesRegex(ValueError, "closed public ingress"): faucet.bootstrap(args)
            read.assert_not_called()

    def test_private_start_only_starts_new_unit_not_old_or_enable(self):
        args = self.prepare()
        args.start_private = args.public_ingress_closed = True
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with patch.object(faucet, "check_host", return_value=account), \
                patch.object(faucet, "check_stopped"), patch.object(faucet.os, "chown"), \
                patch.object(faucet, "credential", return_value=b"synthetic-encrypted"), \
                patch.object(faucet, "run", return_value=b"") as run, \
                patch.object(faucet, "unit_state", return_value={"UnitFileState": "disabled"}), \
                patch.object(faucet, "read_file", wraps=faucet.read_file) as read:
            real_read = read._mock_wraps
            read.side_effect = lambda path, owner=None, private=False: real_read(path, None, private)
            result = faucet.bootstrap(args)
        self.assertTrue(result["started"])
        self.assertEqual([c.args for c in run.call_args_list if c.args[:2] == ("systemctl", "start")],
                         [("systemctl", "start", faucet.UNIT)])
        self.assertFalse(any(c.args[:2] == ("systemctl", "enable") for c in run.call_args_list))

    def test_credentials_fail_before_new_release_or_state(self):
        args = self.prepare()
        with patch.object(faucet, "check_host"), patch.object(faucet, "credential", side_effect=ValueError("fixture")):
            with self.assertRaises(ValueError): faucet.bootstrap(args)
        self.assertFalse(faucet.RELEASE.exists())
        self.assertFalse(faucet.STATE.exists())


if __name__ == "__main__":
    unittest.main()
