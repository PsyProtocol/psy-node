import dataclasses
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install_bridge_reader as reader
import install_services
from test_release_lock import build_test_lock
from test_services_packages import TOPOLOGY


LOGIN = "fixture-reader-login-" + "a" * 30
TOKEN = "b" * 64


class InstallBridgeReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = b"\x7fELF fixture reader"
        self.tool = Path(reader.__file__).read_bytes()
        self.lock = build_test_lock()
        self.lock["hosts"]["gcp-postgres"] = "10.0.0.24"
        self.lock["binaries"]["psy-bridge-reader"] = reader.sha(self.binary)
        self.lock["tool_sha256"]["install_bridge_reader.py"] = reader.sha(self.tool)
        self.release = dataclasses.replace(reader.load_release(self.lock), release=self.root / "opt/release",
                                           config=self.root / "etc/reader", client_token=self.root / "etc/client/token",
                                           unit=self.root / "units/reader.service")
        self.secrets = {"postgres_password": LOGIN, "token": TOKEN}
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_shell="/usr/sbin/nologin")

    def test_constants_come_from_the_lock(self):
        release = reader.load_release(self.lock)
        locked = self.lock["bridge_reader"]
        self.assertEqual((str(release.release), str(release.config), str(release.client_token)),
                         (locked["release"], locked["config"], locked["client_token_file"]))
        self.assertEqual((release.listen, release.role, release.database), (locked["listen"], locked["database_role"],
                                                                            self.lock["envio"]["database"]))
        self.assertEqual(release.unit.name, self.lock["units"]["bridge_reader"])
        self.assertEqual(release.services_host, self.lock["services"]["listen"].rpartition(":")[0])
        self.assertEqual(release.postgres_host, "10.0.0.24")

    def test_services_account_matches_the_services_placement(self):
        lock = dict(self.lock, hosts={"gcp-postgres": "10.0.0.24", "gcp-svc": "10.0.0.38"})
        group = install_services.placement(lock, TOPOLOGY)["groups"]["gcp-svc"]
        self.assertEqual(group["user"], reader.SERVICES_USER)

    def test_environment_reads_the_envio_database_as_the_read_only_role_on_loopback(self):
        text = reader.environment_text(self.release, self.secrets).decode()
        values = {line.split("=", 1)[0]: json.loads(line.split("=", 1)[1]) for line in text.splitlines()}
        self.assertEqual(values["PSY_BRIDGE_READER_LISTEN"], "127.0.0.1:8740")
        self.assertEqual(values["PSY_BRIDGE_READER_DATABASE_URL"],
                         f"postgresql://{self.release.role}:{LOGIN}@10.0.0.24:5432/{self.release.database}")
        self.assertEqual(values["PSY_BRIDGE_READER_DB_SCHEMA"], "envio")
        self.assertEqual(values["PSY_BRIDGE_READER_TOKEN_FILE"], str(self.release.config / "token"))
        unit = reader.unit_text(self.release).decode()
        self.assertIn("User=psy-bridge-reader\n", unit)
        self.assertIn("IPAddressDeny=any\n", unit)
        self.assertIn("IPAddressAllow=10.0.0.24/32\n", unit)
        self.assertIn(f"ExecStart={self.release.release}/psy-bridge-reader\n", unit)

    def test_secrets_have_a_fixed_shape(self):
        self.assertEqual(reader.read_secrets(json.dumps(self.secrets)), self.secrets)
        for bad in ({"postgres_password": LOGIN}, {**self.secrets, "extra": "x"}, {**self.secrets, "token": "short"},
                    {**self.secrets, "postgres_password": "quote'" + "a" * 30}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                reader.read_secrets(json.dumps(bad))

    def test_install_writes_private_files_and_never_starts(self):
        commands = []
        self.release.unit.parent.mkdir()
        with patch.object(reader, "host_checks", return_value=(self.account, self.account)), \
                patch.object(reader.os, "chown"), patch.object(reader.os, "fchown"), \
                patch.object(reader, "run", side_effect=lambda argv, timeout=60: commands.append(argv) or ""):
            reader.install(self.release, self.binary, self.tool, b"{}", self.secrets)
        self.assertEqual(commands, [["systemctl", "daemon-reload"]])
        mode = lambda path: stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(mode(self.release.release / "psy-bridge-reader"), 0o755)
        self.assertEqual((self.release.release / "install_bridge_reader.py").read_bytes(), self.tool)
        self.assertEqual(mode(self.release.config), 0o750)
        for path in (self.release.config / "token", self.release.config / "reader.env", self.release.client_token):
            self.assertEqual(mode(path), 0o600, path)
        self.assertEqual((self.release.config / "token").read_text(), TOKEN + "\n")
        self.assertEqual(self.release.client_token.read_text(), TOKEN + "\n")
        self.assertEqual(self.release.unit.read_bytes(), reader.unit_text(self.release))
        with patch.object(reader, "host_checks", return_value=(self.account, self.account)), \
                patch.object(reader.os, "chown"), patch.object(reader.os, "fchown"), patch.object(reader, "run", return_value=""):
            with self.assertRaises(FileExistsError):
                reader.install(self.release, self.binary, self.tool, b"{}", self.secrets)
            with self.assertRaisesRegex(ValueError, "installer differs"):
                reader.install(self.release, self.binary, b"changed tool", b"{}", self.secrets)

    def host_command(self, argv, timeout=60):
        if argv[0] == "hostname":
            return "10.0.0.38 172.17.0.1"
        if argv[0] == "systemctl":
            return "not-found"
        return "LISTEN 0 128 127.0.0.1:3001 0.0.0.0:*"

    def test_host_checks_refuse_wrong_host_binary_port_and_existing_destinations(self):
        patches = (patch.object(reader.os, "geteuid", return_value=0), patch.object(reader.pwd, "getpwnam", return_value=self.account),
                   patch.object(reader.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=self.account.pw_gid)),
                   patch.object(reader, "trusted"))
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        with patch.object(reader, "run", side_effect=self.host_command):
            self.assertEqual(reader.host_checks(self.release, self.binary), (self.account, self.account))
            with self.assertRaisesRegex(ValueError, "differs from the lock"):
                reader.host_checks(self.release, b"other binary")
        with patch.object(reader, "run", side_effect=lambda argv, timeout=60: "10.0.0.99" if argv[0] == "hostname"
                          else self.host_command(argv)):
            with self.assertRaisesRegex(ValueError, "Services host"):
                reader.host_checks(self.release, self.binary)
        with patch.object(reader, "run", side_effect=lambda argv, timeout=60: "LISTEN 0 128 127.0.0.1:8740 0.0.0.0:*"
                          if argv[0] == "ss" else self.host_command(argv)):
            with self.assertRaisesRegex(ValueError, "port already in use"):
                reader.host_checks(self.release, self.binary)
        self.release.client_token.parent.mkdir(parents=True)
        with patch.object(reader, "run", side_effect=self.host_command):
            with self.assertRaisesRegex(ValueError, f"destination already exists: {self.release.client_token.parent}"):
                reader.host_checks(self.release, self.binary)

    def status(self, **changes):
        chains = [{"chain_index": index, "chain_id": chain_id, "ready": True, "not_ready_reason": None, "deposit_count": 3,
                   "committed_count": 3, "envio_tree_count": 3, "envio_tree_root": "0xab", "tree_root": "0xab",
                   "last_verified_unix_ms": 1} for index, chain_id in enumerate(reader.CHAIN_IDS)]
        envio = [{"chain_id": chain_id, "progress_block": 9, "max_reorg_depth": 8, "safe_block": 1, "committed_safe_block": 1,
                  "ready": True} for chain_id in reader.CHAIN_IDS]
        return {"revision": {}, "ready": True, "chains": chains, "envio_chains": envio, **changes}

    def test_readiness_needs_all_three_envio_chains_and_matching_roots(self):
        self.assertTrue(reader.is_ready(reader.summarize(self.status())))
        self.assertTrue(reader.is_ready(reader.summarize(self.status(chains=[]))), "a fresh chain without deposits is ready")
        broken = self.status()
        broken["chains"][1]["tree_root"] = "0xcd"
        self.assertFalse(reader.is_ready(reader.summarize(broken)))
        self.assertFalse(reader.is_ready(reader.summarize(self.status(ready=False))))
        self.assertFalse(reader.is_ready(reader.summarize(self.status(envio_chains=self.status()["envio_chains"][:2]))))
        summary = reader.summarize(self.status())
        self.assertNotIn("0xab", json.dumps(summary))

    def test_report_sends_the_token_only_to_the_loopback_status_route(self):
        self.release.config.mkdir(parents=True)
        (self.release.config / "token").write_text(TOKEN + "\n")
        calls = []

        def fetch(url, headers=None):
            calls.append((url, headers))
            return (200, b"ok") if url.endswith("/health/ready") else (200, json.dumps(self.status()).encode())
        with patch.object(reader, "fetch", side_effect=fetch):
            result = reader.report(self.release)
        self.assertTrue(result["reader_ready"] and result["health_ready"])
        self.assertEqual(calls[0], ("http://127.0.0.1:8740/health/ready", None))
        self.assertEqual(calls[1], ("http://127.0.0.1:8740/v1/status",
                                    {"Authorization": "Bearer " + TOKEN, "x-psy-lane": "background"}))
        self.assertNotIn(TOKEN, json.dumps(result))
        with patch.object(reader, "fetch", return_value=(503, b"")):
            self.assertFalse(reader.report(self.release)["reader_ready"])
        with patch.object(reader, "fetch", side_effect=lambda url, headers=None: (200, b'{"ready": true, "chains": [{}]}')):
            self.assertFalse(reader.report(self.release)["reader_ready"], "a partial status body is not ready")

    def test_activate_enables_and_waits_until_ready_or_failed(self):
        reports = iter([{"reader_ready": False}, {"reader_ready": True}, {"reader_ready": True}])
        with patch.object(reader, "check_installed"), patch.object(reader, "run", return_value="") as run, \
                patch.object(reader, "report", side_effect=lambda release: next(reports)), \
                patch.object(reader, "unit_properties", return_value={"ActiveState": "active"}), \
                patch.object(reader.time, "sleep"):
            self.assertTrue(reader.activate(self.release, True)["reader_ready"])
        run.assert_called_once_with(["systemctl", "enable", "--now", self.release.unit.name])
        with patch.object(reader, "check_installed"), patch.object(reader, "run", return_value=""), \
                patch.object(reader, "report", return_value={"reader_ready": False}), \
                patch.object(reader, "unit_properties", return_value={"ActiveState": "failed"}), patch.object(reader.time, "sleep"):
            with self.assertRaisesRegex(ValueError, "failed"):
                reader.activate(self.release, True)
        with patch.object(reader, "check_installed"), patch.object(reader, "run") as run, \
                patch.object(reader, "report", return_value={"reader_ready": False}):
            reader.activate(self.release, False)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
