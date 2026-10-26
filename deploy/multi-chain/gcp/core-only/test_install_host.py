"""Unprivileged filesystem tests; all host commands and account changes mocked."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
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
from test_plan import fixture


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
        self.original_paths = {name: getattr(installer, name) for name in ("RELEASE", "CONFIG", "STATE", "UNITS")}
        for name, path in self.original_paths.items():
            self.stack.enter_context(patch.object(installer, name, self.root / "host" / path.relative_to("/")))
        self.stack.enter_context(patch.object(installer, "ROOT_UID", os.getuid()))
        self.stack.enter_context(patch.object(installer, "ROOT_GID", os.getgid()))
        self.stack.enter_context(patch.object(installer.os, "geteuid", return_value=0))
        self.stack.enter_context(patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}))
        self.artifacts = {
            "bin/psy_node_cli": b"test executable bytes",
            "config.json": b'{"defaultNetwork":"testnet","networks":{"testnet":{}}}',
            "genesis.json": b"opaque Genesis bytes; validated by package builder",
        }
        self.stack.enter_context(patch.object(installer, "PINNED_SHA256", {
            name: hashlib.sha256(raw).hexdigest() for name, raw in self.artifacts.items()
        }))
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
        topology = fixture()[0]
        for service in plan.services(topology):
            if service["host"] != self.host:
                continue
            text = packages.unit_text(service, installer.RELEASE_ID)
            for name, path in self.original_paths.items():
                text = text.replace(str(path), str(getattr(installer, name)))
            self.write("units/" + service["unit"], text.encode())
        _, keys = installer.host_inventory(self.host)
        for key in keys:
            self.write(key, ("test-only-" + key).encode())
        self.manifest = {"schema_version": 1, "release_id": installer.RELEASE_ID,
                         "source_commit": installer.SOURCE_COMMIT, "network": "testnet",
                         "host": self.host, "private_ip": installer.HOSTS[self.host], "files": {}}
        self.save_manifest()

    def save_manifest(self, rehash=True):
        if rehash:
            self.manifest["files"] = {str(path.relative_to(self.package)): hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in self.package.rglob("*") if path.is_file() and path.name != "manifest.json"}
        self.write("manifest.json", json.dumps(self.manifest).encode())

    def assert_rejected(self):
        with self.assertRaises((installer.InstallError, OSError)):
            installer.install_host(self.package)
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
                result = installer.install_host(self.package, check_only=True)
                self.assertEqual(result["host"], host)
        self.assertFalse((self.root / "host").exists())

    def test_check_only_never_writes_or_creates_account(self):
        self.account.return_value = None
        with patch.object(installer, "create_directory") as mkdir, patch.object(installer, "install_file") as install:
            self.assertEqual(installer.install_host(self.package, True)["mode"], "check-only")
        mkdir.assert_not_called()
        install.assert_not_called()
        self.assertFalse((self.root / "host").exists())
        self.assertEqual({call.args[0][0] for call in self.commands.call_args_list}, {"ip", "systemctl"})
        self.assertFalse(any(call.args[0][-1] == "daemon-reload" for call in self.commands.call_args_list))

    def test_install_exact_modes_no_start_and_idempotent(self):
        result = installer.install_host(self.package)
        self.assertFalse(result["started"])
        targets, directories = installer.build_paths(installer.read_package(self.package)[1], self.account.return_value)
        for path, (raw, mode, uid, gid) in targets.items():
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.stat().st_uid, path.stat().st_gid), (mode, uid, gid))
        for path, (mode, _, _) in directories.items():
            if installer.CONFIG in path.parents or path == installer.STATE or installer.STATE in path.parents:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        before = {path: (path.stat().st_ino, path.stat().st_mtime_ns) for path in targets}
        installer.install_host(self.package)
        self.assertEqual(before, {path: (path.stat().st_ino, path.stat().st_mtime_ns) for path in targets})
        self.assertEqual(self.commands.call_args.args[0], ["systemctl", "daemon-reload"])
        self.assertFalse(any(set(call.args[0]) & {"start", "enable", "restart", "stop"} for call in self.commands.call_args_list))

    def test_hash_mismatch_before_host_commands(self):
        self.write("genesis.json", b"tampered")
        self.assert_rejected()
        self.commands.assert_not_called()

    def test_rehashed_artifact_tampering_rejected_by_release_pins(self):
        for name, raw in self.artifacts.items():
            with self.subTest(payload=name):
                self.write(name, raw + b" ")
                self.save_manifest()
                for check_only in (True, False):
                    with self.assertRaisesRegex(installer.InstallError, "release artifact pin mismatch"):
                        installer.install_host(self.package, check_only)
                self.commands.assert_not_called()
                self.assertFalse((self.root / "host").exists())
                self.write(name, raw)
        self.save_manifest()
        self.assertEqual(installer.install_host(self.package, True)["mode"], "check-only")

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
                            installer.install_host(self.package, True)
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
            installer.install_host(alias)
        self.package.chmod(0o755)
        self.assert_rejected()
        self.package.chmod(0o700)
        key = next((self.package / "keys").rglob("*.key"))
        key.chmod(0o644)
        self.assert_rejected()

    def test_wrong_host_running_transitioning_and_queued_units(self):
        for output in ("psy-core-x.service loaded active running test\n",
                       "psy-core-x.service loaded activating auto-restart test\n"):
            self.commands.side_effect = [self.command(["ip"]), output]
            self.assert_rejected()
        self.commands.side_effect = ["[]"]
        self.assert_rejected()
        self.commands.side_effect = [self.command(["ip"]), "", "123 psy-core-x.service start waiting\n"]
        self.assert_rejected()

    def test_existing_file_and_mode_conflicts_are_not_repaired(self):
        installer.install_host(self.package)
        target = installer.CONFIG / "config.json"
        target.write_bytes(b"existing config")
        before = target.read_bytes()
        with self.assertRaisesRegex(installer.InstallError, "conflict"):
            installer.install_host(self.package)
        self.assertEqual(target.read_bytes(), before)
        target.write_bytes((self.package / "config.json").read_bytes())
        target.chmod(0o666)
        with self.assertRaisesRegex(installer.InstallError, "conflict"):
            installer.install_host(self.package, True)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o666)

    def test_destination_symlink_and_unexpected_release_file(self):
        installer.CONFIG.parent.mkdir(parents=True)
        outside = self.root / "parth"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"untouched")
        installer.CONFIG.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            installer.install_host(self.package)
        self.assertEqual((outside / "sentinel").read_bytes(), b"untouched")
        installer.CONFIG.unlink()
        installer.install_host(self.package)
        (installer.CONFIG / "unexpected").write_bytes(b"retain")
        with self.assertRaisesRegex(installer.InstallError, "unexpected existing"):
            installer.install_host(self.package)

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
        for before, after in ((b"fresh20261026r2_r", b"parth_r"), (b"processor_identity.key", b"edge_identity.key"),
                              (b"psy-public-testnet", b"psy-mainnet"), (b"/checkpoints", b"/old-checkpoints")):
            with self.subTest(after=after):
                unit.write_bytes(original.replace(before, after))
                self.save_manifest()
                self.assert_rejected()

    def test_duplicate_json_rejected_and_genesis_not_parsed(self):
        self.write("manifest.json", b'{"schema_version":1,"schema_version":1}')
        self.assert_rejected()
        self.save_manifest()
        self.assertEqual(installer.install_host(self.package, True)["mode"], "check-only")

    def test_missing_account_is_created_only_after_preflight(self):
        self.account.side_effect = [None, (os.getuid(), os.getgid())]
        installer.install_host(self.package)
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
                installer.install_host(self.package)
        self.assertFalse(any(call.args[0][-1] == "daemon-reload" for call in self.commands.call_args_list))
        installer.install_host(self.package)

    def test_cli_failure_is_nonzero_and_does_not_print_payloads(self):
        self.write("genesis.json", b"test-private-input-never-print")
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            code = installer.main(["--package", str(self.package), "--check-only"])
        self.assertEqual(code, 1)
        self.assertNotIn("test-private-input", output.getvalue())

    def test_root_required(self):
        with patch.object(installer.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(installer.InstallError, "sudo/root"):
                installer.install_host(self.package, True)


class HostCommandTests(unittest.TestCase):
    def test_production_pins_match_release_and_builder_plan(self):
        topology = fixture()[0]
        self.assertEqual(installer.PINNED_SHA256, {
            "bin/psy_node_cli": None,
            "config.json": "c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0",
            "genesis.json": None,
        })
        self.assertEqual(installer.PINNED_SHA256["bin/psy_node_cli"], packages.NODE_SHA256)
        self.assertEqual(installer.PINNED_SHA256["config.json"], packages.CONFIG_SHA256)
        self.assertEqual(installer.SOURCE_COMMIT, "5d38eefc07b0925ed9875b74805d9c3fea73d998")
        self.assertEqual(installer.SOURCE_COMMIT, plan.RUNTIME_COMMIT)
        self.assertEqual(installer.SOURCE_COMMIT, topology["runtime_commit"])
        self.assertEqual(installer.HOSTS, topology["hosts"])

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
                        installer.read_package(temporary)
            for sudo_uid in ("", "-1", "not-a-uid", "4294967295"):
                with self.subTest(sudo_uid=sudo_uid), patch.dict(os.environ, {"SUDO_UID": sudo_uid}):
                    with self.assertRaisesRegex(installer.InstallError, "invalid SUDO_UID"):
                        installer.read_package(temporary)

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
