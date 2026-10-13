import unittest
from pathlib import Path
import tempfile
from unittest import mock
import presync as p


class PresyncTests(unittest.TestCase):
    def test_activation_between_precheck_and_lock_prevents_copy(self):
        active = False

        def check():
            if active:
                raise RuntimeError("target became active")

        def acquire(*args):
            nonlocal active
            active = True

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(p, "STATE", Path(tmp)), \
                 mock.patch.object(p, "target_check", side_effect=check) as guard, \
                 mock.patch.object(p.fcntl, "flock", side_effect=acquire), \
                 mock.patch.object(p.subprocess, "run") as copy:
                with self.assertRaisesRegex(RuntimeError, "target became active"):
                    p.copy()
                self.assertEqual(guard.call_count, 2)
                copy.assert_not_called()

    def test_only_inactive_disabled_permitless_target(self):
        good = {"MainPID": "0", "ActiveState": "inactive", "UnitFileState": "disabled"}
        p.require_target_fenced(good, False)
        for key, value in [("MainPID", "42"), ("ActiveState", "activating"),
                           ("ActiveState", "failed"), ("UnitFileState", "enabled")]:
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                p.require_target_fenced({**good, key: value}, False)
        with self.assertRaises(RuntimeError):
            p.require_target_fenced(good, True)

    def test_restrict_key_to_directory_and_private_host(self):
        public = p.SOURCE_HOST_KEY + " " + p.TAG
        entry = p.authorized_entry(public)
        self.assertIn('from="10.148.0.37",restrict,expiry-time=', entry)
        self.assertIn('command="/usr/bin/rrsync -ro /var/lib/parth/checkpoints/realm_1_1"', entry)

    def test_reject_key_injection_or_wrong_format(self):
        for key in ["", "ssh-rsa AAA x", p.SOURCE_HOST_KEY + " other",
                    p.SOURCE_HOST_KEY + " " + p.TAG + "\nextra",
                    "ssh-ed25519 AAAA " + p.TAG]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.authorized_entry(key)


if __name__ == "__main__":
    unittest.main()
