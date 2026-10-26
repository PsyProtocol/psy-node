import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_workers as workers


class WorkerPreparationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.release = self.root / "release"
        self.release.mkdir()
        self.package = self.root / "package"
        self.network = self.root / "network.json"
        self.topology = Path(__file__).with_name("topology.json")
        self.topology_bytes = self.topology.read_bytes()
        self.binary = b"test-only-worker-binary"
        self.config = workers.encode({"defaultNetwork": "testnet", "networks": {"testnet": {
            "whitelist": {"enabled": True, "secp256k1": list(set(workers.PUBLIC_KEYS.values()))}}}})
        self.stack.enter_context(patch.object(workers, "WORKER_SHA256", workers.digest(self.binary)))
        self.stack.enter_context(patch.object(workers, "CONFIG_SHA256", workers.digest(self.config)))
        self.build = {"source_commit": workers.SOURCE, "network": "testnet", "cli_network": "psy-public-testnet",
                      "backend": "plonky2-poseidon-goldilocks", "config_sha256": workers.CONFIG_SHA256,
                      "binaries": {"psy_worker_cli": workers.WORKER_SHA256}}
        (self.release / "psy_worker_cli").write_bytes(self.binary)
        (self.release / "manifest.json").write_bytes(workers.encode(self.build))
        self.network.write_bytes(self.config)

    def prepare(self):
        return workers.prepare_package(self.release, self.network, self.topology, self.package)

    def map_host(self):
        for name in ("RELEASE", "CONFIG", "STATE", "UNITS"):
            self.stack.enter_context(patch.object(workers, name, self.root / "host" / name.lower()))
        self.stack.enter_context(patch.object(workers, "UNIT_SEARCH", (workers.UNITS, self.root / "run-units")))
        self.stack.enter_context(patch.object(workers, "ROOT_UID", os.getuid()))
        self.stack.enter_context(patch.object(workers, "ROOT_GID", os.getgid()))
        real_fstat = os.fstat
        root_uid = os.stat("/").st_uid
        def host_stat(fd):
            info = real_fstat(fd)
            if info.st_uid == root_uid and root_uid != os.getuid():
                values = list(info)
                values[4] = os.getuid()
                return os.stat_result(values)
            return info
        self.stack.enter_context(patch.object(workers.os, "fstat", side_effect=host_stat))
        self.stack.enter_context(patch.object(workers, "check_host", return_value=(os.getuid(), os.getgid())))
        self.stack.enter_context(patch.object(workers, "read_credentials", return_value={r: "test-secret" for r in workers.THREADS}))
        self.commands = self.stack.enter_context(patch.object(workers, "command", return_value=""))

    def test_package_is_secret_free_and_has_exact_mapping(self):
        result = self.prepare()
        self.assertFalse(result["started"])
        self.assertFalse(result["contains_credentials"])
        files = workers.read_package(self.package)
        for role in workers.THREADS:
            config = workers.decode(files[role + ".json"])
            self.assertNotIn("private_key", config)
            self.assertEqual(config["user"], 1048576 if role == "realm-1" else 0)
            self.assertEqual(config["network"], "psy-public-testnet")
            self.assertEqual(config["url_rotation_strategy"], "round-robin")
            urls = config["realm_api_urls"] + config["coordinator_api_urls"]
            self.assertEqual(len(urls), 3)
            ports = [int(url.rsplit(":", 1)[1]) for url in urls]
            self.assertEqual(ports, {"coordinator": [15370, 15371, 15372],
                                     "realm-0": [15380, 15381, 15382], "realm-1": [15383, 15384, 15385]}[role])
            self.assertEqual(config["completed_jobs_log_file"], str(workers.STATE / role / "completed.backup"))
            unit = files[workers.unit_name(role)].decode()
            self.assertIn("[Install]\nWantedBy=multi-user.target", unit)
            self.assertIn("--batch-size 1", unit)
            self.assertIn("--url-rotation-strategy round-robin", unit)
            self.assertIn("RAYON_NUM_THREADS=" + str(workers.THREADS[role]), unit)
            self.assertNotIn("--private-key", unit)
            self.assertNotIn("PRIVATE_KEY=", unit)
        self.assertEqual(stat.S_IMODE(self.package.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.package.iterdir()))

    def test_invalid_release_inputs_write_nothing(self):
        for name, value in (("source_commit", "0" * 40), ("network", "localhost"),
                            ("cli_network", "local-devnet"), ("backend", "jtmb-poseidon-goldilocks")):
            with self.subTest(name=name):
                (self.release / "manifest.json").write_bytes(workers.encode(dict(self.build, **{name: value})))
                with self.assertRaises(workers.WorkerError):
                    self.prepare()
                self.assertFalse(self.package.exists())

    def test_binary_config_and_topology_hashes_are_enforced(self):
        for path in (self.release / "psy_worker_cli", self.network):
            original = path.read_bytes()
            path.write_bytes(b"changed")
            with self.assertRaises(workers.WorkerError):
                self.prepare()
            self.assertFalse(self.package.exists())
            path.write_bytes(original)
        changed = self.root / "topology.json"
        changed.write_bytes(self.topology_bytes + b"\n")
        with self.assertRaises(workers.WorkerError):
            workers.prepare_package(self.release, self.network, changed, self.package)

    def test_package_refuses_overwrite(self):
        self.prepare()
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.package.iterdir()}
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.package.iterdir()})

    def test_package_rejects_tampered_unit_or_config(self):
        self.prepare()
        for name in (workers.unit_name("coordinator"), "realm-1.json"):
            path = self.package / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaises(workers.WorkerError):
                workers.read_package(self.package)
            path.write_bytes(original)

    def test_package_rejects_unlisted_files_and_permissions(self):
        self.prepare()
        extra = self.package / "extra"
        extra.write_bytes(b"unexpected")
        with self.assertRaises(workers.WorkerError):
            workers.read_package(self.package)
        extra.unlink()
        (self.package / "realm-0.json").chmod(0o644)
        with self.assertRaises(workers.WorkerError):
            workers.read_package(self.package)

    def test_source_links_and_special_files_rejected(self):
        path = self.root / "input"
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    path.symlink_to(self.network)
                elif kind == "hardlink":
                    os.link(self.network, path)
                else:
                    os.mkfifo(path, 0o600)
                with self.assertRaises((OSError, workers.WorkerError)):
                    workers.read_file(path)
                path.unlink()
        alias = self.root / "alias"
        alias.symlink_to(self.release, target_is_directory=True)
        with self.assertRaises(OSError):
            workers.read_file(alias / "psy_worker_cli")

    def test_readonly_check_never_creates_files_or_reloads(self):
        self.map_host()
        self.prepare()
        result = workers.install_workers(self.package)
        self.assertEqual(result["mode"], "checked")
        self.assertFalse((self.root / "host").exists())
        self.commands.assert_not_called()

    def test_install_modes_new_state_no_start_and_old_backups_untouched(self):
        self.map_host()
        self.prepare()
        old = self.root / "old-completed.backup"
        old.write_bytes(b"retain-history")
        before = old.stat().st_mtime_ns
        result = workers.install_workers(self.package, check_only=False)
        self.assertFalse(result["started"])
        self.assertFalse(result["enabled"])
        self.commands.assert_called_once_with(["systemctl", "daemon-reload"])
        for role in workers.THREADS:
            path = workers.CONFIG / (role + ".json")
            self.assertEqual(workers.decode(path.read_bytes())["private_key"], "test-secret")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE((workers.STATE / role).stat().st_mode), 0o700)
            self.assertFalse((workers.STATE / role / "completed.backup").exists())
        self.assertEqual(old.read_bytes(), b"retain-history")
        self.assertEqual(old.stat().st_mtime_ns, before)
        with self.assertRaises(workers.WorkerError):
            workers.install_workers(self.package, check_only=False)

    def test_existing_state_units_and_symlinks_block_install(self):
        self.map_host()
        self.prepare()
        for target in (workers.STATE, workers.UNITS / workers.unit_name("realm-0"),
                       workers.UNITS / (workers.unit_name("realm-1") + ".d")):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(self.root / "missing")
            with self.assertRaises(workers.WorkerError):
                workers.install_workers(self.package, check_only=False)
            target.unlink()
        self.commands.assert_not_called()

    def test_cli_sanitizes_json_and_crypto_errors(self):
        for error in (ValueError("test-private-key"), KeyError("test-private-key"), OSError("test-private-key")):
            output = io.StringIO()
            with patch.object(workers, "install_workers", side_effect=error), redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(workers.main(["check-host", "--package", str(self.package)]), 1)
            self.assertNotIn("test-private-key", output.getvalue())

    def test_credential_identity_verified_without_printing_or_modifying(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        key = "0" * 63 + "1"
        public = ec.derive_private_key(1, ec.SECP256K1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()
        path = self.root / "credential.json"
        path.write_bytes(workers.encode({"private_key": key, "user": 999, "network": "local-devnet"}))
        path.chmod(0o640)
        before = path.stat().st_mtime_ns
        with patch.object(workers, "SOURCES", {"coordinator": path}), patch.object(workers, "ROOT_UID", os.getuid()):
            with self.assertRaises(workers.WorkerError):
                workers.read_credentials(os.getgid())
            with patch.object(workers, "PUBLIC_KEYS", {"coordinator": public}):
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(workers.read_credentials(os.getgid()), {"coordinator": key})
                self.assertEqual(output.getvalue(), "")
                path.chmod(0o644)
                with self.assertRaises(workers.WorkerError):
                    workers.read_credentials(os.getgid())
        self.assertEqual(path.stat().st_mtime_ns, before)


class WorkerHostChecks(unittest.TestCase):
    def test_host_activity_and_queued_jobs_rejected(self):
        account = SimpleNamespace(pw_uid=999, pw_gid=999)
        with patch.object(workers.os, "geteuid", return_value=0), patch.object(workers.pwd, "getpwnam", return_value=account):
            for answers in (["wrong-host"], ["test-c4d", "aarch64"],
                            ["test-c4d", "x86_64", "parth-c4d-worker@realm-0-0.service loaded active running"],
                            ["test-c4d", "x86_64", "", "psy-core-worker-realm-0.service loaded activating start"],
                            ["test-c4d", "x86_64", "", "", "12 psy-core-worker-realm-0.service start waiting"]):
                with patch.object(workers, "command", side_effect=answers):
                    with self.assertRaises(workers.WorkerError):
                        workers.check_host()
            with patch.object(workers, "command", side_effect=["test-c4d", "x86_64", "", "", ""]):
                self.assertEqual(workers.check_host(), (999, 999))

    def test_commands_bounded_and_errors_sanitized(self):
        with patch.object(workers.subprocess, "run", return_value=SimpleNamespace(stdout="ok")) as run:
            self.assertEqual(workers.command(["hostname", "-s"]), "ok")
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(set(run.call_args.kwargs["env"]), {"PATH", "LC_ALL"})
        with patch.object(workers.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "test", stderr="secret")):
            with self.assertRaises(workers.WorkerError) as error:
                workers.command(["hostname", "-s"])
        self.assertNotIn("secret", str(error.exception))


if __name__ == "__main__":
    unittest.main()
