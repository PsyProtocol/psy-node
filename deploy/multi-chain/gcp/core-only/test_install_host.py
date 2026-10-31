"""Unprivileged filesystem tests; all host commands and account changes mocked."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install_host as installer
import plan
import prepare_host_packages as packages
from test_plan import fixture, profile_for
from test_release_lock import build_test_lock


class InstallHostTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        real_fstat = os.fstat
        mapped_root_uid = os.stat("/").st_uid
        def host_stat(fd):
            info = real_fstat(fd)
            if mapped_root_uid != os.getuid() and info.st_uid == mapped_root_uid:
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)
            return info
        self.stack.enter_context(patch.object(installer.os, "fstat", side_effect=host_stat))
        self.package = self.root / "package"
        self.package.mkdir(mode=0o700)
        self.stack.enter_context(patch.object(installer, "UNITS", self.root / "host/etc/systemd/system"))
        self.stack.enter_context(patch.object(installer, "ROOT_UID", os.getuid()))
        self.stack.enter_context(patch.object(installer, "ROOT_GID", os.getgid()))
        self.stack.enter_context(patch.object(installer.os, "geteuid", return_value=0))
        self.stack.enter_context(patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}))
        self.artifacts = {
            "bin/psy_node_cli": b"test executable bytes",
            "config.json": b'{"defaultNetwork":"testnet","networks":{"testnet":{}}}',
            "genesis.json": b"opaque Genesis bytes; validated by package builder",
        }
        self.lock = build_test_lock()
        self.original_core = dict(self.lock["paths"]["core"])
        self.lock["paths"]["core"] = {name: str(self.root / "host" / Path(path).relative_to("/"))
                                      for name, path in self.original_core.items()}
        self.lock["binaries"]["psy_node_cli"] = hashlib.sha256(self.artifacts["bin/psy_node_cli"]).hexdigest()
        self.lock["inputs"]["runtime_config"] = hashlib.sha256(self.artifacts["config.json"]).hexdigest()
        self.lock["inputs"]["genesis"] = hashlib.sha256(self.artifacts["genesis.json"]).hexdigest()
        self.release = installer.load_core_release(self.lock)
        self.account = self.stack.enter_context(patch.object(installer, "get_runtime_user", return_value=(os.getuid(), os.getgid())))
        self.commands = self.stack.enter_context(patch.object(installer, "command", side_effect=self.command))
        self.host = "gcp-realm-processor"
        self.create_package()

    def command(self, argv):
        if argv[0] == "ip":
            return json.dumps([{"addr_info": [{"local": installer.HOSTS[self.host]}]}])
        return ""

    def write(self, relative, raw):
        path = self.package / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)

    def create_package(self):
        for name, raw in self.artifacts.items():
            self.write(name, raw)
        topology = fixture(self.lock)[0]
        for service in plan.services(topology):
            if service["host"] != self.host:
                continue
            text = packages.unit_text(service, self.release.release_id)
            for name, path in self.original_core.items():
                text = text.replace(path, str(getattr(self.release, name + "_dir")))
            self.write("units/" + service["unit"], text.encode())
        _, keys = installer.host_inventory(self.host, self.release)
        for key in keys:
            self.write(key, ("test-only-" + key).encode())
        self.manifest = {"schema_version": 1, "release_id": self.release.release_id,
                         "source_commit": self.release.source_commit, "network": "testnet",
                         "host": self.host, "private_ip": installer.HOSTS[self.host], "files": {}}
        self.save_manifest()

    def save_manifest(self, rehash=True):
        if rehash:
            self.manifest["files"] = {str(path.relative_to(self.package)): hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in self.package.rglob("*") if path.is_file() and path.name != "manifest.json"}
        self.write("manifest.json", json.dumps(self.manifest).encode())

    def install(self, check_only=False, package=None):
        return installer.install_host(self.package if package is None else package, check_only, self.release)

    def assert_rejected(self):
        with self.assertRaises((installer.InstallError, OSError)):
            self.install()
        self.assertFalse((self.root / "host").exists())
        self.assertFalse(any(call.args[0][0] == "useradd" or call.args[0][-1] == "daemon-reload"
                             for call in self.commands.call_args_list))

    def test_all_six_host_packages_accept_builder_units(self):
        for host in installer.HOSTS:
            with self.subTest(host=host):
                self.package = self.root / host
                self.package.mkdir(mode=0o700)
                self.host = host
                self.create_package()
                result = self.install(True)
                self.assertEqual(result["host"], host)
        self.assertFalse((self.root / "host").exists())

    def test_check_only_never_writes_or_creates_account(self):
        self.account.return_value = None
        with patch.object(installer, "create_directory") as mkdir, patch.object(installer, "install_file") as install:
            self.assertEqual(self.install(True)["mode"], "check-only")
        mkdir.assert_not_called()
        install.assert_not_called()
        self.assertFalse((self.root / "host").exists())
        self.assertEqual({call.args[0][0] for call in self.commands.call_args_list}, {"ip", "systemctl"})
        self.assertFalse(any(call.args[0][-1] == "daemon-reload" for call in self.commands.call_args_list))

    def test_install_exact_modes_no_start_and_idempotent(self):
        result = self.install()
        self.assertFalse(result["started"])
        targets, directories = installer.build_paths(installer.read_package(self.package, self.release)[1], self.account.return_value, self.release)
        for path, (raw, mode, uid, gid) in targets.items():
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.stat().st_uid, path.stat().st_gid), (mode, uid, gid))
        for path, (mode, _, _) in directories.items():
            if self.release.config_dir in path.parents or path == self.release.state_dir or self.release.state_dir in path.parents:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        before = {path: (path.stat().st_ino, path.stat().st_mtime_ns) for path in targets}
        self.install()
        self.assertEqual(before, {path: (path.stat().st_ino, path.stat().st_mtime_ns) for path in targets})
        self.assertEqual(self.commands.call_args.args[0], ["systemctl", "daemon-reload"])
        self.assertFalse(any(set(call.args[0]) & {"start", "enable", "restart", "stop"} for call in self.commands.call_args_list))

    def test_hash_mismatch_before_host_commands(self):
        self.write("genesis.json", b"tampered")
        self.assert_rejected()
        self.commands.assert_not_called()

    def test_unfrozen_binary_blocks_both_modes_before_host_commands(self):
        self.lock["binaries"]["psy_node_cli"] = ""
        self.release = installer.load_core_release(self.lock)
        for check_only in (True, False):
            with self.subTest(check_only=check_only), self.assertRaisesRegex(
                    installer.InstallError, "release artifact pins not frozen"):
                self.install(check_only)
        self.commands.assert_not_called()
        self.assertFalse((self.root / "host").exists())

    def test_rehashed_artifact_tampering_rejected_by_release_pins(self):
        for name, raw in self.artifacts.items():
            with self.subTest(payload=name):
                self.write(name, raw + b" ")
                self.save_manifest()
                for check_only in (True, False):
                    with self.assertRaisesRegex(installer.InstallError, "release artifact pin mismatch"):
                        self.install(check_only)
                self.commands.assert_not_called()
                self.assertFalse((self.root / "host").exists())
                self.write(name, raw)
        self.save_manifest()
        self.assertEqual(self.install(True)["mode"], "check-only")

    def test_endpoint_mutations_rejected_for_all_builder_units(self):
        for host in installer.HOSTS:
            self.host = host
            self.package = self.root / host
            self.package.mkdir(mode=0o700)
            self.create_package()
            for unit in (self.package / "units").iterdir():
                original = unit.read_text()
                line = next(line for line in original.splitlines() if line.startswith("ExecStart="))
                argv = shlex.split(line.removeprefix("ExecStart="))
                changes = []
                for option in ("--listen", "--port", "--p2p-listen", "--coordinator-api-urls"):
                    if option not in argv:
                        changes.append(argv + [option, "0"])
                        continue
                    index = argv.index(option) + 1
                    value = argv[index]
                    alternatives = {
                        "--listen": ["0.0.0.0", "127.0.0.1", "10.148.0.99"],
                        "--port": ["80", "15370", "15385"],
                        "--p2p-listen": ["/ip4/0.0.0.0/tcp/41001", "/ip4/10.148.0.99/tcp/41001", value + "0"],
                        "--coordinator-api-urls": ["http://10.148.0.99:15370", "http://10.148.0.25:80",
                                                    "http://10.148.0.25:15371", "http://user:password@10.148.0.25:15370"],
                    }
                    for replacement in alternatives[option]:
                        if replacement != value:
                            changes.append(argv[:index] + [replacement] + argv[index + 1:])
                    changes.append(argv[:index - 1] + argv[index + (3 if option == "--coordinator-api-urls" else 1):])
                for changed in changes:
                    with self.subTest(host=host, unit=unit.name, argv=changed[1:]):
                        updated = "ExecStart=" + " ".join(json.dumps(value) for value in changed)
                        unit.write_text(original.replace(line, updated))
                        self.save_manifest()
                        with self.assertRaisesRegex(installer.InstallError, "unit endpoints"):
                            self.install(True)
                unit.write_text(original)
                self.save_manifest()
        self.commands.assert_not_called()
        self.assertFalse((self.root / "host").exists())

    def test_schema_pin_and_host_rejections(self):
        original = dict(self.manifest)
        for field, value in (("source_commit", "f" * 40), ("network", "mainnet"),
                             ("release_id", "../parth"), ("schema_version", True),
                             ("private_ip", "10.148.0.25"), ("host", "unknown")):
            with self.subTest(field=field):
                self.manifest = dict(original, **{field: value})
                self.save_manifest(False)
                self.assert_rejected()

    def test_manifest_traversal_and_unlisted_payload_rejected(self):
        for path in ("../escape", "/etc/passwd", "keys/../escape", "bin//psy_node_cli"):
            with self.subTest(path=path):
                self.manifest["files"][path] = "a" * 64
                self.save_manifest(False)
                self.assert_rejected()
                del self.manifest["files"][path]
        self.save_manifest(False)
        self.write("unlisted", b"unlisted")
        self.assert_rejected()

    def test_unauthorized_host_key_rejected_even_with_hash(self):
        self.write("keys/realm-0-v2/zk.key", b"test-other-validator")
        self.save_manifest()
        self.assert_rejected()

    def test_source_links_and_special_files_rejected(self):
        target = self.package / "genesis.json"
        original = target.read_bytes()
        outside = self.root / "outside"
        outside.write_bytes(original)
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                target.unlink()
                if kind == "symlink":
                    target.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, target)
                else:
                    os.mkfifo(target, 0o600)
                self.assert_rejected()
                target.unlink()
                self.write("genesis.json", original)

    def test_source_directory_symlink_and_private_modes(self):
        alias = self.root / "alias"
        alias.symlink_to(self.package, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install(package=alias)
        self.package.chmod(0o755)
        self.assert_rejected()
        self.package.chmod(0o700)
        key = next((self.package / "keys").rglob("*.key"))
        key.chmod(0o644)
        self.assert_rejected()

    def test_wrong_host_running_transitioning_and_queued_units(self):
        names = ("psy-core-r2-realm-1-v1-processor.service", "psy-core-r3-coordinator-processor.service",
                 "psy-core-realm-processor.service", "parth-realm-processor@1.service",
                 "parth-coordinator-processor.service", "psy-realm-processor.service",
                 "psy-coordinator-edge.service")
        for name in names:
            for state in ("active running", "activating auto-restart", "deactivating stop-sigterm"):
                with self.subTest(name=name, state=state):
                    self.commands.side_effect = [self.command(["ip"]), f"{name} loaded {state} test\n"]
                    self.assert_rejected()
            self.commands.side_effect = [self.command(["ip"]), "", f"123 {name} start waiting\n"]
            self.assert_rejected()
        self.commands.side_effect = ["[]"]
        self.assert_rejected()

    def test_stopped_legacy_units_are_scanned_without_stop_or_overwrite(self):
        output = "psy-core-r2-realm-1-v1-processor.service loaded inactive dead old\n"
        output += "parth-realm-processor@1.service loaded failed failed old\n"
        self.commands.side_effect = [self.command(["ip"]), output, ""]
        self.assertEqual(self.install(True)["mode"], "check-only")
        scan = self.commands.call_args_list[1].args[0]
        for pattern in ("psy-core-*", "parth-coordinator-*", "parth-realm-*", "psy-realm-*", "psy-coordinator-*"):
            self.assertIn(pattern, scan)
        self.assertFalse(any(set(call.args[0]) & {"start", "enable", "restart", "stop"}
                             for call in self.commands.call_args_list))
        self.assertFalse((self.root / "host").exists())

    def test_active_non_node_services_do_not_block_host_check(self):
        names = ("parth-performance-monitor.service", "parth-forwarder.service",
                 "parth-notifier.service", "parth-worker.service")

        def command(argv):
            if argv[:2] == ["systemctl", "list-units"]:
                patterns = [arg for arg in argv if arg.endswith("*")]
                self.assertEqual(set(patterns), {"psy-core-*", "parth-coordinator-*",
                                                "parth-realm-*", "psy-realm-*", "psy-coordinator-*"})
                return "".join(f"{name} loaded active running unrelated\n" for name in names
                               if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns))
            if argv[:2] == ["systemctl", "list-jobs"]:
                return "".join(f"{index} {name} start running\n" for index, name in enumerate(names, 1))
            return self.command(argv)

        self.commands.side_effect = command
        self.assertEqual(self.install(True)["mode"], "check-only")
        self.assertFalse((self.root / "host").exists())

    def test_release_dropins_remain_conflicts(self):
        self.install()
        name = next(iter(installer.host_inventory(self.host, self.release)[0]))
        dropin = installer.UNITS / (name + ".d")
        dropin.mkdir()
        sentinel = dropin / "90-hold.conf"
        sentinel.write_bytes(b"[Unit]\nConditionPathExists=/missing-approval\n")
        with self.assertRaisesRegex(installer.InstallError, "unit drop-in conflict"):
            self.install(True)
        self.assertEqual(sentinel.read_bytes(), b"[Unit]\nConditionPathExists=/missing-approval\n")

    def test_existing_file_and_mode_conflicts_are_not_repaired(self):
        self.install()
        target = self.release.config_dir / "config.json"
        target.write_bytes(b"existing config")
        before = target.read_bytes()
        with self.assertRaisesRegex(installer.InstallError, "conflict"):
            self.install()
        self.assertEqual(target.read_bytes(), before)
        target.write_bytes((self.package / "config.json").read_bytes())
        target.chmod(0o666)
        with self.assertRaisesRegex(installer.InstallError, "conflict"):
            self.install(True)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o666)

    def test_destination_symlink_and_unexpected_release_file(self):
        self.release.config_dir.parent.mkdir(parents=True)
        outside = self.root / "parth"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"untouched")
        self.release.config_dir.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install()
        self.assertEqual((outside / "sentinel").read_bytes(), b"untouched")
        self.release.config_dir.unlink()
        self.install()
        (self.release.config_dir / "unexpected").write_bytes(b"retain")
        with self.assertRaisesRegex(installer.InstallError, "unexpected existing"):
            self.install()

    def test_unit_secret_environment_and_unsafe_directives(self):
        unit = next((self.package / "units").iterdir())
        original = unit.read_bytes()
        for replacement in (b"Environment=PRIVATE_KEY=test-secret\n", b"ExecStartPre=/bin/true\n",
                            b"Environment=RUST_LOG=debug\n", b"ProtectHome=false\n"):
            with self.subTest(replacement=replacement):
                unit.write_bytes(original.replace(b"[Service]\n", b"[Service]\n" + replacement))
                self.save_manifest()
                self.assert_rejected()

    def test_unit_old_paths_and_wrong_keys_rejected(self):
        unit = next((self.package / "units").iterdir())
        original = unit.read_bytes()
        for before, after in ((self.release.namespace_prefix.encode() + b"_r", b"fresh20261026r2_r"), (b"processor_identity.key", b"edge_identity.key"),
                              (b"psy-public-testnet", b"psy-mainnet"), (b"/checkpoints", b"/old-checkpoints")):
            with self.subTest(after=after):
                unit.write_bytes(original.replace(before, after))
                self.save_manifest()
                self.assert_rejected()

    def test_duplicate_json_rejected_and_genesis_not_parsed(self):
        self.write("manifest.json", b'{"schema_version":1,"schema_version":1}')
        self.assert_rejected()
        self.save_manifest()
        self.assertEqual(self.install(True)["mode"], "check-only")

    def test_missing_account_is_created_only_after_preflight(self):
        self.account.side_effect = [None, (os.getuid(), os.getgid())]
        self.install()
        calls = [call.args[0] for call in self.commands.call_args_list]
        self.assertEqual(sum(argv[0] == "useradd" for argv in calls), 1)
        self.assertIn("--system", next(argv for argv in calls if argv[0] == "useradd"))

    def test_partial_install_failure_does_not_reload_and_can_retry(self):
        original = installer.install_file
        count = 0
        def interrupted(*args):
            nonlocal count
            count += 1
            if count == 3:
                raise OSError("injected failure")
            return original(*args)
        with patch.object(installer, "install_file", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.install()
        self.assertFalse(any(call.args[0][-1] == "daemon-reload" for call in self.commands.call_args_list))
        self.install()

    def test_cli_failure_is_nonzero_and_does_not_print_payloads(self):
        self.write("genesis.json", b"test-private-input-never-print")
        raw = json.dumps(self.lock).encode()
        lock_path = self.root / "release-lock.json"
        lock_path.write_bytes(raw)
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = installer.main(["--release-lock", str(lock_path), "--release-lock-sha256",
                                   hashlib.sha256(raw).hexdigest(), "--package", str(self.package), "--check-only"])
        self.assertEqual(code, 1)
        self.assertNotIn("test-private-input", output.getvalue())

    def test_unit_without_queue_lease_is_rejected(self):
        unit = next((self.package / "units").iterdir())
        unit.write_bytes(unit.read_bytes().replace(
            ("Environment=\"NATS_WORKER_ACK_WAIT_MS=%d\"\n" % self.release.worker_queue_ack_wait_ms).encode(), b""))
        self.save_manifest()
        with self.assertRaisesRegex(installer.InstallError, "unit environment"):
            self.install(True)

    def test_root_required(self):
        with patch.object(installer.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(installer.InstallError, "sudo/root"):
                self.install(True)


class HostCommandTests(unittest.TestCase):
    def test_load_core_release_reads_lock_fields(self):
        lock = build_test_lock()
        release = installer.load_core_release(lock)
        topology = fixture(lock)[0]
        core = lock["paths"]["core"]
        self.assertEqual(dict(release.pins), {"bin/psy_node_cli": lock["binaries"]["psy_node_cli"],
                                              "config.json": lock["inputs"]["runtime_config"],
                                              "genesis.json": lock["inputs"]["genesis"]})
        self.assertEqual(release.release_id, lock["release_id"])
        self.assertEqual(release.source_commit, lock["sources"]["runtime"])
        self.assertEqual(release.unit_prefix, lock["units"]["core_prefix"])
        self.assertEqual(release.namespace_prefix, lock["units"]["core_namespace_prefix"])
        self.assertEqual(release.worker_queue_ack_wait_ms, lock["gates"]["worker_queue_ack_wait_ms"])
        self.assertEqual((release.release_dir, release.config_dir, release.state_dir),
                         (Path(core["release"]), Path(core["config"]), Path(core["state"])))
        self.assertEqual(release.profile_sha256, lock["inputs"]["release_profile"])
        self.assertEqual(release.release_id, topology["release_id"])
        self.assertEqual(release.source_commit, topology["runtime_commit"])
        self.assertEqual(release.namespace_prefix, topology["namespace_prefix"])
        self.assertEqual(release.worker_queue_ack_wait_ms, topology["worker_queue_ack_wait_ms"])
        self.assertEqual(release.worker_queue_ack_wait_ms, profile_for(lock)["worker_queue_ack_wait_ms"])
        self.assertEqual(installer.HOSTS, topology["hosts"])
        with self.assertRaises(AttributeError):
            installer.get_release
        for name in ("SOURCE_COMMIT", "PINNED_SHA256", "RELEASE_ID", "RELEASE", "CONFIG", "STATE"):
            self.assertFalse(hasattr(installer, name), name)

    def test_non_integer_queue_lease_is_rejected_at_load(self):
        for value in (None, True, "30000", 30000.0):
            with self.subTest(value=value):
                lock = build_test_lock()
                lock["gates"]["worker_queue_ack_wait_ms"] = value
                with self.assertRaisesRegex(installer.InstallError, "worker_queue_ack_wait_ms must be an integer"):
                    installer.load_core_release(lock)

    def test_install_requires_release_lock_argument(self):
        lock_raw = json.dumps(build_test_lock()).encode()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-lock.json"
            path.write_bytes(lock_raw)
            with redirect_stderr(io.StringIO()):
                for argv in (["--package", temporary], ["--package", temporary, "--release-lock", str(path)],
                             ["--package", temporary, "--release-lock-sha256", "0" * 64]):
                    with self.assertRaises(SystemExit) as error:
                        installer.main(argv)
                    self.assertEqual(error.exception.code, 2)
                errors = io.StringIO()
                with redirect_stderr(errors):
                    self.assertEqual(installer.main(["--package", temporary, "--release-lock", str(path),
                                                     "--release-lock-sha256", "0" * 64]), 1)
                self.assertIn("release lock hash mismatch", errors.getvalue())
                with patch.object(installer, "install_host", return_value={"mode": "check-only"}) as run, \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(installer.main(["--package", temporary, "--release-lock", str(path),
                                                     "--release-lock-sha256", hashlib.sha256(lock_raw).hexdigest(),
                                                     "--check-only"]), 0)
                self.assertEqual(run.call_args.args[2], installer.load_core_release(json.loads(lock_raw)))

    def test_package_owner_is_root_sudo_user_or_local_reader_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            for euid, sudo_uid, owner, accepted in (
                (0, None, 0, True), (0, "1000", 1000, True), (0, "1000", 2000, False),
                (0, None, 1000, False), (1000, None, 1000, True), (1000, None, 2000, False),
            ):
                with self.subTest(euid=euid, sudo_uid=sudo_uid, owner=owner), \
                        patch.object(installer.os, "geteuid", return_value=euid), \
                        patch.object(installer.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=owner)), \
                        patch.dict(os.environ, {} if sudo_uid is None else {"SUDO_UID": sudo_uid}, clear=True):
                    with self.assertRaisesRegex(installer.InstallError, "manifest missing" if accepted else "package owner"):
                        installer.read_package(temporary, installer.load_core_release(build_test_lock()))
            for sudo_uid in ("", "-1", "not-a-uid", "4294967295"):
                with self.subTest(sudo_uid=sudo_uid), patch.dict(os.environ, {"SUDO_UID": sudo_uid}):
                    with self.assertRaisesRegex(installer.InstallError, "invalid SUDO_UID"):
                        installer.read_package(temporary, installer.load_core_release(build_test_lock()))

    def test_command_failure_sanitized_and_environment_not_inherited(self):
        with patch.object(installer.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["ip"], stderr="secret")):
            with self.assertRaises(installer.InstallError) as error:
                installer.command(["ip"])
        self.assertNotIn("secret", str(error.exception))
        with patch.object(installer.subprocess, "run", return_value=SimpleNamespace(stdout="[]")) as run:
            self.assertEqual(installer.command(["ip"]), "[]")
        self.assertEqual(set(run.call_args.kwargs["env"]), {"PATH", "LC_ALL"})

    def test_account_rejects_login_user_or_root(self):
        for uid, shell in ((0, "/usr/sbin/nologin"), (1001, "/usr/sbin/nologin"), (999, "/bin/bash")):
            user = SimpleNamespace(pw_uid=uid, pw_gid=999, pw_dir="/nonexistent", pw_shell=shell)
            with patch.object(installer.pwd, "getpwnam", return_value=user), \
                    patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=999)):
                with self.assertRaises(installer.InstallError):
                    installer.get_runtime_user()


if __name__ == "__main__":
    unittest.main()
