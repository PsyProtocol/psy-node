import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import provision_guardians as provision


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "user_cli"
        self.binary.write_bytes(b"synthetic cli")
        self.lock = self.root / "lock.json"
        self.lock.write_text(json.dumps({"sources": {"guardian_key": "4" * 40}}))

    def digest(self, path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def test_wrong_cli_hash_is_refused_before_the_custody_directory_exists(self):
        custody = self.root / "custody"
        with self.assertRaisesRegex(RuntimeError, "unexpected User CLI"):
            provision.provision(self.binary, custody, "4" * 40, "0" * 64)
        self.assertFalse(custody.exists())

    def test_existing_custody_is_never_overwritten(self):
        custody = self.root / "custody"
        custody.mkdir()
        with self.assertRaisesRegex(RuntimeError, "refusing overwrite"):
            provision.provision(self.binary, custody, "4" * 40, self.digest(self.binary))

    def test_release_lock_is_hash_checked_before_it_is_parsed(self):
        with self.assertRaisesRegex(RuntimeError, "release lock hash mismatch"):
            provision.read_release_lock(self.lock, "0" * 64)
        self.assertEqual(provision.read_release_lock(self.lock, self.digest(self.lock))["sources"]["guardian_key"], "4" * 40)

    def test_command_line_requires_the_lock_and_the_cli_hash(self):
        with patch("sys.argv", ["provision", "--binary", str(self.binary), "--root", str(self.root / "c")]):
            with self.assertRaises(SystemExit):
                provision.main()
        self.assertFalse((self.root / "c").exists())

    def test_the_lock_source_reaches_the_custody_summary(self):
        seen = {}
        def fail_after_source(binary, root, source, user_cli_sha256):
            seen.update(source=source, cli=user_cli_sha256)
        argv = ["provision", "--release-lock", str(self.lock), "--release-lock-sha256", self.digest(self.lock),
                "--user-cli-sha256", "a" * 64, "--binary", str(self.binary), "--root", str(self.root / "c")]
        with patch("sys.argv", argv), patch.object(provision, "provision", side_effect=fail_after_source):
            provision.main()
        self.assertEqual(seen, {"source": "4" * 40, "cli": "a" * 64})


if __name__ == "__main__":
    unittest.main()
