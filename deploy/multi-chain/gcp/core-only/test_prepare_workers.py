import copy
from dataclasses import replace
import hashlib
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
from test_release_lock import build_test_lock

HERE = Path(__file__).resolve().parent
FRESH_TOPOLOGY = HERE.parent / "fresh-192-20261030" / "topology.json"
SOURCE = "1" * 40


class WorkerPreparationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.release = self.root / "release"
        self.release.mkdir()
        self.package = self.root / "package"
        self.network = self.root / "network.json"
        self.topology = self.root / "topology.json"
        self.lock = build_test_lock()
        topology = dict(json.loads(FRESH_TOPOLOGY.read_bytes()), release_id=self.lock["release_id"],
                        runtime_commit=SOURCE)
        self.topology_bytes = workers.encode(topology)
        self.topology.write_bytes(self.topology_bytes)
        self.binary = b"test-only-worker-binary"
        self.config = workers.encode({"defaultNetwork": "testnet", "networks": {"testnet": {
            "whitelist": {"enabled": True, "secp256k1": list(set(workers.PUBLIC_KEYS.values()))}}}})
        self.lock["binaries"]["psy_worker_cli"] = workers.digest(self.binary)
        self.lock["inputs"]["runtime_config"] = workers.digest(self.config)
        self.lock["inputs"]["topology"] = workers.digest(self.topology_bytes)
        self.rel = workers.load_worker_release(self.lock)
        self.lock_path = self.root / "release-lock.json"
        self.lock_path.write_bytes(json.dumps(self.lock).encode())
        self.lock_sha256 = hashlib.sha256(self.lock_path.read_bytes()).hexdigest()
        self.build = {"source_commit": self.rel.source_commit, "network": "testnet",
                      "network_magic": self.rel.network_magic, "config_sha256": self.rel.config_sha256,
                      "binaries": {"psy_worker_cli": self.rel.worker_sha256}}
        (self.release / "psy_worker_cli").write_bytes(self.binary)
        (self.release / "manifest.json").write_bytes(workers.encode(self.build))
        self.network.write_bytes(self.config)

    def prepare(self):
        return workers.prepare_package(self.rel, self.release, self.network, self.topology, self.package)

    def test_release_units_state_and_slice_come_from_the_lock(self):
        rid = self.lock["release_id"]
        self.assertEqual(self.rel.source_commit, self.lock["sources"]["runtime"])
        self.assertEqual(self.rel.release_id, rid)
        for path in (self.rel.release_dir, self.rel.config_dir, self.rel.state_dir):
            self.assertEqual(path.name, rid)
        self.prepare()
        files = workers.read_package(self.package, self.rel)
        slice_name = self.lock["units"]["worker_prefix"].rstrip("-") + ".slice"
        self.assertEqual(workers.slice_name(self.rel), slice_name)
        self.assertIn(slice_name, files)
        self.assertFalse(any("r2" in name or "r3" in name for name in files))
        for role in workers.THREADS:
            name = self.lock["units"]["worker_prefix"] + role + ".service"
            self.assertEqual(workers.unit_name(self.rel, role), name)
            unit = files[name].decode()
            self.assertIn("Slice=" + slice_name, unit)
            self.assertIn("ReadWritePaths=" + str(self.rel.state_dir / role), unit)
            self.assertEqual(unit.count("Environment=PSY_WORKER_TASK_PROTOCOL=v2\n"), 1)
        targets, _ = workers.install_paths(files, {r: "test-secret" for r in workers.THREADS}, (999, 999), self.rel)
        self.assertIn(workers.UNITS / slice_name, targets)

    def test_unfrozen_artifact_pins_reject_before_parsing(self):
        for name in ("worker_sha256", "config_sha256", "topology_sha256"):
            unfrozen = replace(self.rel, **{name: None})
            with self.subTest(name=name):
                with self.assertRaisesRegex(workers.WorkerError, "pins not frozen"):
                    workers.payloads({}, unfrozen)
                with self.assertRaises(workers.WorkerError):
                    workers.prepare_package(unfrozen, self.release, self.network, self.topology, self.package)
                self.assertFalse(self.package.exists())

    def map_host(self):
        self.rel = replace(self.rel, release_dir=self.root / "host" / "release", config_dir=self.root / "host" / "config",
                           state_dir=self.root / "host" / "state")
        self.stack.enter_context(patch.object(workers, "UNITS", self.root / "host" / "units"))
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
        files = workers.read_package(self.package, self.rel)
        self.assertEqual(files["build.json"], workers.encode(self.build))
        self.assertNotIn("cli_network", workers.decode(files["build.json"]))
        for role in workers.THREADS:
            config = workers.decode(files[role + ".json"])
            self.assertNotIn("private_key", config)
            self.assertEqual(config["user"], 1048576 if role == "realm-1" else 0)
            self.assertEqual(config["network"], "psy-public-testnet")
            self.assertEqual(config["url_rotation_strategy"], "round-robin")
            urls = config["realm_api_urls"] + config["coordinator_api_urls"]
            ports = [int(url.rsplit(":", 1)[1]) for url in urls]
            self.assertEqual(ports, {"coordinator": [15369],
                                     "realm-0": [15380, 15381, 15382], "realm-1": [15383, 15384, 15385]}[role])
            self.assertEqual(config["completed_jobs_log_file"], str(self.rel.state_dir / role / "completed.backup"))
            unit = files[workers.unit_name(self.rel, role)].decode()
            self.assertIn("[Install]\nWantedBy=multi-user.target", unit)
            self.assertIn("--batch-size 1", unit)
            self.assertIn("--network psy-public-testnet --proving-backend plonky2-poseidon-goldilocks", unit)
            self.assertIn("--url-rotation-strategy round-robin", unit)
            self.assertIn("RAYON_NUM_THREADS=" + str(workers.THREADS[role]), unit)
            self.assertNotIn("--private-key", unit)
            self.assertNotIn("PRIVATE_KEY=", unit)
        self.assertEqual(stat.S_IMODE(self.package.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.package.iterdir()))

    def test_invalid_release_inputs_write_nothing(self):
        for name, value in (("source_commit", "0" * 40), ("network", "localhost")):
            with self.subTest(name=name):
                (self.release / "manifest.json").write_bytes(workers.encode(dict(self.build, **{name: value})))
                with self.assertRaises(workers.WorkerError):
                    self.prepare()
                self.assertFalse(self.package.exists())
        (self.release / "manifest.json").write_bytes(workers.encode(self.build))
        for name, value in (("network", "local-devnet"), ("proving_backend", "jtmb-poseidon-goldilocks")):
            with self.subTest(name=name):
                raw = workers.encode(dict(json.loads(self.topology_bytes), **{name: value}))
                self.topology.write_bytes(raw)
                bad = replace(self.rel, topology_sha256=workers.digest(raw))
                with self.assertRaises(workers.WorkerError):
                    workers.prepare_package(bad, self.release, self.network, self.topology, self.package)
                self.assertFalse(self.package.exists())

    def test_binary_config_and_topology_hashes_are_enforced(self):
        for path in (self.release / "psy_worker_cli", self.network):
            original = path.read_bytes()
            path.write_bytes(b"changed")
            with self.assertRaises(workers.WorkerError):
                self.prepare()
            self.assertFalse(self.package.exists())
            path.write_bytes(original)
        changed = self.root / "changed-topology.json"
        changed.write_bytes(self.topology_bytes + b"\n")
        with self.assertRaises(workers.WorkerError):
            workers.prepare_package(self.rel, self.release, self.network, changed, self.package)

    def test_build_manifest_binding_to_the_lock_fails_closed(self):
        for field, value in (("source_commit", "a" * 40), ("config_sha256", "b" * 64),
                             ("network", "localhost"), ("network_magic", "0x1"), ("binaries", {})):
            raw = workers.encode(dict(self.build, **{field: value}))
            (self.release / "manifest.json").write_bytes(raw)
            with self.subTest(field=field):
                with self.assertRaises((workers.WorkerError, KeyError)):
                    self.prepare()
                self.assertFalse(self.package.exists())

    def test_every_binary_of_the_build_must_equal_the_lock(self):
        worker = self.rel.worker_sha256
        for extra in ({"psy_node_cli": "f" * 64}, {"psy_unknown_cli": worker}):
            with self.subTest(extra=extra):
                raw = workers.encode(dict(self.build, binaries={"psy_worker_cli": worker, **extra}))
                (self.release / "manifest.json").write_bytes(raw)
                with self.assertRaisesRegex(workers.WorkerError, "build binaries differ from the lock"):
                    self.prepare()
                self.assertFalse(self.package.exists())
        matching = {"psy_worker_cli": worker, "psy_node_cli": self.lock["binaries"]["psy_node_cli"]}
        (self.release / "manifest.json").write_bytes(workers.encode(dict(self.build, binaries=matching)))
        self.prepare()

    def test_package_refuses_overwrite(self):
        self.prepare()
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.package.iterdir()}
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.package.iterdir()})

    def test_activation_package_accepts_current_source_helper(self):
        self.prepare()
        files = workers.read_package(self.package, self.rel, activation=True)
        self.assertEqual(files["prepare_workers.py"], Path(workers.__file__).read_bytes())
        self.assertNotEqual(workers.digest(files["prepare_workers.py"]), self.rel.helper_sha256)

    def test_activation_package_accepts_only_lock_pinned_or_current_helper(self):
        self.prepare()
        path = self.package / "prepare_workers.py"
        old_helper = b"test-only-pinned-old-helper"
        path.write_bytes(old_helper)
        pinned = replace(self.rel, helper_sha256=workers.digest(old_helper))
        self.assertEqual(workers.read_package(self.package, pinned, activation=True)[path.name], old_helper)
        with self.assertRaises(workers.WorkerError):
            workers.read_package(self.package, pinned)
        path.write_bytes(old_helper + b"\n")
        with self.assertRaisesRegex(workers.WorkerError, "helper hash"):
            workers.read_package(self.package, pinned, activation=True)

    def test_package_rejects_tampered_unit_or_config(self):
        self.prepare()
        for name in (workers.unit_name(self.rel, "coordinator"), "realm-1.json"):
            path = self.package / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaises(workers.WorkerError):
                workers.read_package(self.package, self.rel)
            path.write_bytes(original)

    def test_package_rejects_unlisted_files_and_permissions(self):
        self.prepare()
        extra = self.package / "extra"
        extra.write_bytes(b"unexpected")
        with self.assertRaises(workers.WorkerError):
            workers.read_package(self.package, self.rel)
        extra.unlink()
        (self.package / "realm-0.json").chmod(0o644)
        with self.assertRaises(workers.WorkerError):
            workers.read_package(self.package, self.rel)

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
        result = workers.install_workers(self.package, self.rel)
        self.assertEqual(result["mode"], "checked")
        self.assertFalse((self.root / "host").exists())
        self.commands.assert_not_called()

    def test_install_modes_new_state_no_start_and_old_backups_untouched(self):
        self.map_host()
        self.prepare()
        old = self.root / "old-completed.backup"
        old.write_bytes(b"retain-history")
        before = old.stat().st_mtime_ns
        result = workers.install_workers(self.package, self.rel, check_only=False)
        self.assertFalse(result["started"])
        self.assertFalse(result["enabled"])
        self.commands.assert_called_once_with(["systemctl", "daemon-reload"])
        for role in workers.THREADS:
            path = self.rel.config_dir / (role + ".json")
            self.assertEqual(workers.decode(path.read_bytes())["private_key"], "test-secret")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE((self.rel.state_dir / role).stat().st_mode), 0o700)
            self.assertFalse((self.rel.state_dir / role / "completed.backup").exists())
        self.assertEqual(old.read_bytes(), b"retain-history")
        self.assertEqual(old.stat().st_mtime_ns, before)
        with self.assertRaises(workers.WorkerError):
            workers.install_workers(self.package, self.rel, check_only=False)

    def test_existing_state_units_and_symlinks_block_install(self):
        self.map_host()
        self.prepare()
        for target in (self.rel.state_dir, workers.UNITS / workers.unit_name(self.rel, "realm-0"),
                       workers.UNITS / (workers.unit_name(self.rel, "realm-1") + ".d")):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(self.root / "missing")
            with self.assertRaises(workers.WorkerError):
                workers.install_workers(self.package, self.rel, check_only=False)
            target.unlink()
        self.commands.assert_not_called()

    def test_cli_sanitizes_json_and_crypto_errors(self):
        for error in (ValueError("test-private-key"), KeyError("test-private-key"), OSError("test-private-key")):
            output = io.StringIO()
            with patch.object(workers, "install_workers", side_effect=error), redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(workers.main(["check-host", "--package", str(self.package),
                                               "--release-lock", str(self.lock_path),
                                               "--release-lock-sha256", self.lock_sha256]), 1)
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

    def activation_fixture(self):
        self.map_host()
        self.prepare()
        workers.install_workers(self.package, self.rel, check_only=False)
        self.commands.reset_mock()
        self.commands.side_effect = lambda argv: {"hostname": "test-c4d", "uname": "x86_64"}.get(argv[0], "")
        self.stack.enter_context(patch.object(workers.os, "geteuid", return_value=0))
        self.stack.enter_context(patch.object(workers.pwd, "getpwnam",
                                             return_value=SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())))
        def state(name):
            return {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead",
                    "MainPID": "0", "UnitFileState": "disabled", "DropInPaths": "",
                    "NeedDaemonReload": "no", "FragmentPath": str(workers.UNITS / name)}
        self.activation_state = state
        self.states = self.stack.enter_context(patch.object(workers, "unit_state", side_effect=state))
        self.processes = self.stack.enter_context(patch.object(workers, "verify_worker_process", return_value=123))

    def test_activate_enables_only_the_three_lock_units(self):
        self.activation_fixture()
        result = workers.activate_workers(self.package, self.rel)
        self.assertEqual(result["mode"], "activated")
        mutations = [call.args[0] for call in self.commands.call_args_list
                     if call.args[0][0] == "systemctl" and call.args[0][1] not in ("list-units", "list-jobs")]
        self.assertEqual(mutations, [["systemctl", "enable", "--now",
                                     *(workers.unit_name(self.rel, r) for r in workers.THREADS)]])
        self.assertEqual(self.processes.call_count, 3)

    def test_activate_rejects_old_running_or_enabled_workers(self):
        self.activation_fixture()
        old_worker = "psy-core-worker-old-realm-0.service"
        def list_old(argv):
            if argv[0] == "hostname": return "test-c4d"
            if argv[0] == "uname": return "x86_64"
            if argv[1] == "list-units" and argv[-1] == "psy-core-worker*.service":
                return old_worker + " loaded inactive dead Old worker"
            return ""
        self.commands.side_effect = list_old
        for field, value in (("ActiveState", "active"), ("MainPID", "42"), ("UnitFileState", "enabled")):
            self.states.side_effect = lambda name: dict(self.activation_state(name), **({field: value} if name == old_worker else {}))
            with self.assertRaises(workers.WorkerError): workers.activate_workers(self.package, self.rel)
        self.assertFalse(any(c.args[0][0] == "systemctl" and c.args[0][1] not in ("list-units", "list-jobs")
                             for c in self.commands.call_args_list))
        self.states.side_effect = self.activation_state
        for blocked in ("list-units", "list-jobs"):
            def response(argv):
                if argv[0] == "hostname": return "test-c4d"
                if argv[0] == "uname": return "x86_64"
                if argv[1] == blocked:
                    return ("parth-c4d-worker@realm-0-0.service loaded active running" if blocked == "list-units"
                            else "1 parth-c4d-worker@realm-0-0.service start waiting")
                return ""
            self.commands.side_effect = response
            with self.assertRaises(workers.WorkerError): workers.activate_workers(self.package, self.rel)
        self.assertFalse(any(c.args[0][:2] == ["systemctl", "enable"] for c in self.commands.call_args_list))

    def test_activate_rejects_changed_installed_config_and_dropin(self):
        self.activation_fixture()
        path = self.rel.config_dir / "realm-0.json"
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with self.assertRaises(workers.WorkerError): workers.activate_workers(self.package, self.rel)
        path.write_bytes(original)
        self.states.side_effect = lambda name: dict(self.activation_state(name), DropInPaths="unexpected.conf")
        with self.assertRaises(workers.WorkerError): workers.activate_workers(self.package, self.rel)
        self.assertFalse(any(c.args[0][0] == "systemctl" and c.args[0][1] not in ("list-units", "list-jobs")
                             for c in self.commands.call_args_list))

    def test_activate_rejects_changed_frozen_package_helper(self):
        self.activation_fixture()
        path = self.package / "prepare_workers.py"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(workers.WorkerError, "helper hash"):
            workers.activate_workers(self.package, self.rel)
        self.processes.assert_not_called()

    def test_distinct_systemd_executor_inode_then_exact_worker(self):
        state = {"ActiveState": "active", "SubState": "running", "UnitFileState": "enabled", "MainPID": "123"}
        systemd_info = SimpleNamespace(st_dev=66305, st_ino=5138)
        executor_info = SimpleNamespace(st_dev=66305, st_ino=5144)
        binary_info = SimpleNamespace(st_dev=66305, st_ino=9000)
        identities = {"/usr/lib/systemd/systemd": systemd_info,
                      "/usr/lib/systemd/systemd-executor": executor_info,
                      str(self.rel.release_dir / "psy_worker_cli"): binary_info}
        with tempfile.TemporaryFile() as executor, tempfile.TemporaryFile() as binary:
            binary.write(self.binary)
            binary.seek(0)
            with patch.object(workers, "unit_state", return_value=state), \
                    patch("builtins.open", side_effect=[executor, binary]), \
                    patch.object(workers.os, "fstat", side_effect=[executor_info, binary_info]), \
                    patch.object(workers.os, "stat", side_effect=lambda p: identities[str(p)]), \
                    patch.object(workers.time, "sleep") as sleep:
                self.assertEqual(workers.verify_worker_process("worker", self.rel), 123)
                sleep.assert_called_once_with(0.25)

    def test_running_executable_hash_checked_after_known_executor_grace(self):
        state = {"ActiveState": "active", "SubState": "running", "UnitFileState": "enabled", "MainPID": "123"}
        with tempfile.TemporaryFile() as executor, tempfile.TemporaryFile() as binary:
            binary.write(self.binary)
            binary.seek(0)
            executor_info, binary_info = os.fstat(executor.fileno()), os.fstat(binary.fileno())
            with patch.object(workers, "unit_state", return_value=state), \
                    patch("builtins.open", side_effect=[executor, binary]), \
                    patch.object(workers.os, "stat", side_effect=lambda p: executor_info if str(p).endswith("systemd") else binary_info), \
                    patch.object(workers.time, "sleep") as sleep:
                self.assertEqual(workers.verify_worker_process("worker", self.rel), 123)
                sleep.assert_called_once_with(0.25)
        with tempfile.TemporaryFile() as binary:
            binary.write(b"wrong-binary")
            binary.seek(0)
            with patch.object(workers, "unit_state", return_value=state), \
                    patch("builtins.open", return_value=binary), \
                    patch.object(workers.os, "stat", return_value=os.fstat(binary.fileno())):
                with self.assertRaisesRegex(workers.WorkerError, "hash mismatch"):
                    workers.verify_worker_process("worker", self.rel)


class WorkerHostChecks(unittest.TestCase):
    def test_host_activity_and_queued_jobs_rejected(self):
        account = SimpleNamespace(pw_uid=999, pw_gid=999)
        with patch.object(workers.os, "geteuid", return_value=0), patch.object(workers.pwd, "getpwnam", return_value=account):
            for answers in (["wrong-host"], ["test-c4d", "aarch64"],
                            ["test-c4d", "x86_64", "parth-c4d-worker@realm-0-0.service loaded active running"],
                            ["test-c4d", "x86_64", "", "psy-core-worker-old-realm-0.service loaded active running"],
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
