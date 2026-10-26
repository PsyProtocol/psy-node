import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("backup_guardians", HERE / "backup_guardians.py")
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)
PASSWORD = b"test-only-password-not-for-custody"


def write_private(path, value):
    path.write_bytes(value)
    path.chmod(0o600)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        keys = self.source
        for part in ("home", ".psy", "keystore"):
            keys = keys / part
            keys.mkdir(mode=0o700)
        self.keys = keys
        commitments = [f"{number:064x}" for number in (1, 2, 3)]
        write_private(self.source / "public-commitments.json", json.dumps({
            "node_source": backup.SOURCE, "user_cli_sha256": backup.USER_CLI_SHA256,
            "guardian_initial_member_hashes": commitments,
        }).encode())
        for guardian_id in backup.HOSTS:
            write_private(self.source / f"guardian-{guardian_id}-public.json",
                          json.dumps({"public_key_hash": commitments[guardian_id - 1]}).encode())
            write_private(keys / f"guardian-{guardian_id}.keystore.json", json.dumps({
                "version": 3, "crypto": {"ciphertext": f"fixture-{guardian_id}"},
            }).encode())
            write_private(self.source / f"psy-guardian-{guardian_id}-password.cred",
                          f"local-encrypted-{guardian_id}".encode())
        self.remote = self.root / "remote"
        self.calls = []

    def client_command(self, argv, payload=None, timeout=60):
        self.calls.append((argv, payload))
        if argv[0] == "systemd-creds":
            self.assertIn("--user", argv)
            self.assertEqual(argv[-3:], ["decrypt", "-", "-"])
            return PASSWORD
        self.assertEqual(argv[0], "ssh")
        message = json.loads(payload)
        return json.dumps(backup.acknowledgement(
            message["guardian_id"], message["public_key_hash"], message["keystore_sha256"])).encode()

    def envelope(self, guardian_id=1):
        with patch.object(backup, "command", side_effect=self.client_command):
            backup.backup(self.source, guardian_id, Path("/test/identity"), "# public helper")
        return self.calls[-1][1]

    def remote_command(self, argv, payload=None, timeout=60):
        self.calls.append((argv, payload))
        self.assertEqual(argv[0], "systemd-creds")
        self.assertNotIn("--user", argv)
        self.assertNotIn(PASSWORD.decode(), " ".join(argv))
        if "encrypt" in argv:
            self.assertIn("--with-key=host", argv)
            self.assertEqual(payload, PASSWORD)
            return b"remote-host-encrypted-credential"
        self.assertEqual(payload, b"remote-host-encrypted-credential")
        return PASSWORD

    def receive(self, raw, guardian_id=1):
        with patch.object(backup, "REMOTE_ROOT", self.remote), \
                patch.object(backup, "require_remote_host") as host, \
                patch.object(backup, "command", side_effect=self.remote_command):
            result = backup.receive(raw, guardian_id)
        host.assert_called_once_with(guardian_id)
        return result

    def test_only_assigned_guardian_crosses_ssh_stdin(self):
        for guardian_id, host in backup.HOSTS.items():
            self.calls.clear()
            raw = self.envelope(guardian_id)
            self.assertEqual(len(self.calls), 2)
            decrypt, credential = self.calls[0]
            self.assertIn(f"--name=psy-guardian-{guardian_id}-password", decrypt)
            self.assertEqual(credential, f"local-encrypted-{guardian_id}".encode())
            ssh, sent = self.calls[1]
            self.assertIn(f"ubuntu@{host}", ssh)
            self.assertEqual(ssh[ssh.index("-J") + 1], "gcp-gateway")
            self.assertIn("StrictHostKeyChecking=yes", ssh)
            self.assertIn("sudo -n -- /usr/bin/python3 -I -c", ssh[-1])
            self.assertNotIn(PASSWORD.decode(), " ".join(ssh))
            self.assertNotIn(base64.b64encode(PASSWORD).decode(), " ".join(ssh))
            self.assertEqual(raw, sent)
            message = json.loads(raw)
            self.assertEqual(base64.b64decode(message["password"]), PASSWORD)
            self.assertEqual(base64.b64decode(message["keystore"]),
                             (self.keys / f"guardian-{guardian_id}.keystore.json").read_bytes())
            self.assertNotIn("credential", message)

    def test_receiver_reencrypts_checks_hash_and_writes_only_protected_backup(self):
        result = self.receive(self.envelope())
        target = self.remote / "guardian-1"
        self.assertEqual(result["public_key_hash"], f"{1:064x}")
        self.assertEqual(stat.S_IMODE(self.remote.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.assertEqual({p.name for p in target.iterdir()}, {
            "guardian-1.keystore.json", "psy-guardian-1-password.cred", "public.json"})
        for path in target.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(PASSWORD, path.read_bytes())
            self.assertNotIn(base64.b64encode(PASSWORD), path.read_bytes())
        self.assertEqual((target / "guardian-1.keystore.json").read_bytes(),
                         (self.keys / "guardian-1.keystore.json").read_bytes())
        self.assertEqual((target / "psy-guardian-1-password.cred").read_bytes(),
                         b"remote-host-encrypted-credential")
        self.assertFalse((self.remote / "guardian-2").exists())
        self.assertFalse((self.remote / "guardian-3").exists())

    def test_existing_or_partial_backup_is_never_overwritten(self):
        raw = self.envelope()
        self.receive(raw)
        target = self.remote / "guardian-1"
        before = {p.name: p.read_bytes() for p in target.iterdir()}
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.receive(raw)
        self.assertEqual(before, {p.name: p.read_bytes() for p in target.iterdir()})
        for path in target.iterdir():
            path.unlink()
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.receive(raw)
        self.assertEqual(list(target.iterdir()), [])

    def test_receiver_rejects_wrong_id_host_hash_or_secret_field(self):
        original = json.loads(self.envelope())
        for field, value in (("guardian_id", 2), ("host", backup.HOSTS[2]),
                             ("keystore_sha256", "0" * 64), ("extra_password", "not-allowed"),
                             ("public_key_hash", "0" * 64)):
            with self.subTest(field=field):
                modified = dict(original, **{field: value})
                with self.assertRaises(RuntimeError):
                    self.receive(json.dumps(modified).encode())
                self.assertFalse(self.remote.exists())

    def test_wrong_physical_host_rejected(self):
        with patch.object(backup.os, "geteuid", return_value=0), \
                patch.object(backup, "command", return_value=b'[{"addr_info":[{"local":"10.148.0.40"}]}]'):
            with self.assertRaisesRegex(RuntimeError, "wrong Guardian"):
                backup.require_remote_host(1)
            backup.require_remote_host(2)
        with patch.object(backup.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "root"):
                backup.require_remote_host(1)

    def test_bad_remote_round_trip_does_not_create_guardian_directory(self):
        raw = self.envelope()
        with patch.object(backup, "REMOTE_ROOT", self.remote), \
                patch.object(backup, "require_remote_host"), \
                patch.object(backup, "command", side_effect=[b"encrypted", b"wrong"]):
            with self.assertRaisesRegex(RuntimeError, "round-trip"):
                backup.receive(raw, 1)
        self.assertFalse((self.remote / "guardian-1").exists())

    def test_interrupted_write_retains_partial_backup_and_refuses_retry(self):
        raw = self.envelope()
        write = backup.write_file

        def interrupt(descriptor, name, value):
            if name.endswith(".cred"):
                raise OSError("injected write failure")
            write(descriptor, name, value)

        with patch.object(backup, "write_file", side_effect=interrupt):
            with self.assertRaises(OSError):
                self.receive(raw)
        target = self.remote / "guardian-1"
        self.assertEqual({p.name for p in target.iterdir()}, {"guardian-1.keystore.json"})
        original = (target / "guardian-1.keystore.json").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.receive(raw)
        self.assertEqual((target / "guardian-1.keystore.json").read_bytes(), original)

    def test_source_commitment_mismatch_fails_before_decrypt_or_ssh(self):
        write_private(self.source / "guardian-1-public.json", b'{"public_key_hash":"4"}')
        with patch.object(backup, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "commitment mismatch"):
                backup.backup(self.source, 1, Path("/test/key"), "helper")
            command.assert_not_called()

    def test_source_symlink_hardlink_and_public_modes_rejected(self):
        path = self.keys / "guardian-1.keystore.json"
        original = path.read_bytes()
        path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "unsafe custody"):
            backup.read_source(self.source)
        path.chmod(0o600)
        link = self.root / "hardlink"
        os.link(path, link)
        with self.assertRaisesRegex(RuntimeError, "unsafe custody"):
            backup.read_source(self.source)
        link.unlink()
        path.unlink()
        write_private(link, original)
        path.symlink_to(link)
        with self.assertRaises(OSError):
            backup.read_source(self.source)

    def test_destination_symlink_is_not_followed(self):
        raw = self.envelope()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        self.remote.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(OSError):
            self.receive(raw)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_remote_receipt_mismatch_is_not_reported_as_success(self):
        with patch.object(backup, "command", side_effect=[PASSWORD, b'{}']):
            with self.assertRaisesRegex(RuntimeError, "acknowledgement mismatch"):
                backup.backup(self.source, 1, Path("/test/key"), "helper")

    def test_subprocess_failure_never_exposes_input_or_stderr(self):
        for failure in (subprocess.CalledProcessError(1, ["tool"], stderr=PASSWORD),
                        subprocess.TimeoutExpired(["tool"], 1, output=PASSWORD)):
            with patch.object(backup.subprocess, "run", side_effect=failure):
                with self.assertRaises(RuntimeError) as caught:
                    backup.command(["tool"], PASSWORD)
            self.assertNotIn(PASSWORD.decode(), str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)

    def test_subprocess_preserves_user_credential_environment_not_password_environment(self):
        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1234",
                                    "GUARDIAN_1_KEYSTORE_PASSWORD": PASSWORD.decode()}), \
                patch.object(backup.subprocess, "run",
                             return_value=subprocess.CompletedProcess(["tool"], 0, b"ok")) as run:
            self.assertEqual(backup.command(["tool"], b"input"), b"ok")
        self.assertEqual(run.call_args.kwargs["env"]["XDG_RUNTIME_DIR"], "/run/user/1234")
        self.assertNotIn("GUARDIAN_1_KEYSTORE_PASSWORD", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_invalid_guardian_and_invalid_commitment_rejected(self):
        for guardian_id in (0, 4, True, "1"):
            with self.assertRaises(RuntimeError):
                backup.guardian_name(guardian_id)
        for commitment in ("0", "1" * 65, "z", None):
            with self.assertRaises(RuntimeError):
                backup.public_commitment(commitment)

    def test_duplicate_json_fields_and_oversized_input_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            backup.decode_json(b'{"password":"a","password":"b"}')
        with self.assertRaisesRegex(RuntimeError, "too large"):
            self.receive(b"x" * (backup.MAX_MESSAGE + 1))


if __name__ == "__main__":
    unittest.main()
