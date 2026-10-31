"""Offline SD192 packaging policy, independent of live service operations."""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import install_host as installer
import plan
import prepare_host_packages as packages
import test_prepare_host_packages as package_fixtures


HERE = Path(__file__).resolve().parent


class FreshReleaseTests(unittest.TestCase):
    def test_fresh_release_matches_verified_receipt(self):
        receipt = json.loads((HERE.parent / "fresh-192-20261030/artifacts.json").read_bytes())
        profile = json.loads((HERE.parent / "fresh-192-20261030/release.json").read_bytes())
        release = installer.get_release("sd192")
        self.assertEqual(release.release_id, receipt["release_id"])
        self.assertEqual(release.source_commit, receipt["source_commit"])
        self.assertEqual(release.pins, {"bin/psy_node_cli": receipt["binaries"]["psy_node_cli"],
                                      "config.json": receipt["runtime_config_sha256"],
                                      "genesis.json": receipt["genesis_sha256"]})
        self.assertEqual(release.namespace_prefix, profile["namespace_prefix"])
        self.assertEqual(release.worker_queue_ack_wait_ms, 30000)
        self.assertEqual(release.unit_prefix, "psy-core-fresh20261030sd192-")
        self.assertFalse(receipt["deployment_ready"])

    def test_legacy_default_and_fresh_selection_are_distinct(self):
        old = installer.get_release()
        new = installer.get_release("sd192")
        self.assertEqual(old.release_id, installer.RELEASE_ID)
        self.assertEqual(old.pins, installer.PINNED_SHA256)
        self.assertEqual(old.unit_prefix, "psy-core-r3-")
        self.assertIsNone(old.worker_queue_ack_wait_ms)
        self.assertNotEqual(old.release_dir, new.release_dir)
        self.assertNotEqual(old.config_dir, new.config_dir)
        self.assertNotEqual(old.state_dir, new.state_dir)

    def test_unknown_release_is_not_inferred_from_a_package(self):
        with self.assertRaises(installer.InstallError):
            installer.get_release("latest")


class FreshPackageTests(unittest.TestCase):
    def setUp(self):
        self.base = package_fixtures.PrepareTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.args = self.base.args
        self.args.cohort = "sd192"
        self.topology = json.loads((HERE.parent / "fresh-192-20261030/topology.json").read_bytes())
        self.args.topology.write_text(json.dumps(self.topology))
        config = json.loads(self.args.config.read_bytes())
        config["networks"]["testnet"]["p2p"]["checkpoints_per_epoch"] = 32
        self.args.config.write_text(json.dumps(config))
        self.base.hashes["config.json"] = packages.digest(self.args.config)
        self.profile = json.loads((HERE.parent / "fresh-192-20261030/release.json").read_bytes())
        self.profile["runtime_config_sha256"] = self.base.hashes["config.json"]
        self.args.release_profile = self.base.root / "profile.json"
        self.args.release_profile.write_text(json.dumps(self.profile))
        self.release = replace(installer.get_release("sd192"), pins=self.base.hashes,
                               profile_sha256=packages.digest(self.args.release_profile))
        self.select = self.enterContext(patch.object(installer, "get_release", return_value=self.release))

    def test_all_six_fresh_packages_pass_installer_validation(self):
        packages.prepare(self.args)
        total = 0
        for host in self.topology["hosts"]:
            manifest, payloads = installer.read_package(self.args.output / host, self.release)
            self.assertEqual(manifest["release_id"], self.release.release_id)
            self.assertEqual(manifest["source_commit"], self.release.source_commit)
            self.assertNotIn("faucetOperators.json", payloads)
            self.assertNotIn("private_keys.json", payloads)
            units = {name: raw for name, raw in payloads.items() if name.startswith("units/")}
            total += len(units)
            for name, raw in units.items():
                self.assertTrue(name.startswith("units/" + self.release.unit_prefix))
                self.assertIn(b"NATS_WORKER_ACK_WAIT_MS=30000", raw)
                self.assertNotIn(b"fresh20261027r3", raw)
        self.assertEqual(total, 16)

    def test_missing_profile_stops_before_private_input_reads(self):
        self.args.release_profile = None
        with self.assertRaisesRegex(ValueError, "pinned release profile"):
            packages.prepare(self.args)
        self.base.assert_no_output()

    def test_changed_profile_hash_is_not_accepted(self):
        self.args.release_profile.write_text(json.dumps({**self.profile, "checkpoints_per_epoch": 10}))
        with self.assertRaisesRegex(ValueError, "profile hash mismatch"):
            packages.prepare(self.args)
        self.base.assert_no_output()

    def test_profile_config_pin_cannot_differ_from_release(self):
        self.profile["runtime_config_sha256"] = "0" * 64
        self.args.release_profile.write_text(json.dumps(self.profile))
        self.select.return_value = replace(self.release, profile_sha256=packages.digest(self.args.release_profile))
        with self.assertRaisesRegex(ValueError, "release config pin mismatch"):
            packages.prepare(self.args)
        self.base.assert_no_output()

    def test_wrong_binary_and_genesis_are_refused(self):
        for field in ("node_binary", "genesis"):
            with self.subTest(field=field):
                file = getattr(self.args, field)
                before = file.read_bytes()
                file.write_bytes(b"{}" if field == "genesis" else b"other cohort executable")
                with self.assertRaises(ValueError):
                    packages.prepare(self.args)
                file.write_bytes(before)
                self.base.assert_no_output()


class FreshInstallerTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        raw_fstat, mapped_uid = os.fstat, os.stat("/").st_uid
        def normalized_root(fd):
            info = raw_fstat(fd)
            if mapped_uid != os.getuid() and info.st_uid == mapped_uid:
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)
            return info
        self.stack.enter_context(patch.object(installer.os, "fstat", side_effect=normalized_root))
        original = installer.get_release("sd192")
        self.artifacts = {"bin/psy_node_cli": b"synthetic SD192 executable",
                          "config.json": b'{"defaultNetwork":"testnet","networks":{"testnet":{}}}',
                          "genesis.json": b"synthetic Genesis"}
        self.release = replace(original, pins={name: hashlib.sha256(raw).hexdigest() for name, raw in self.artifacts.items()},
                               release_dir=self.root / "host/opt" / original.release_id,
                               config_dir=self.root / "host/etc" / original.release_id,
                               state_dir=self.root / "host/var" / original.release_id)
        self.stack.enter_context(patch.object(installer, "UNITS", self.root / "host/systemd"))
        self.stack.enter_context(patch.object(installer, "ROOT_UID", os.getuid()))
        self.stack.enter_context(patch.object(installer, "ROOT_GID", os.getgid()))
        self.stack.enter_context(patch.object(installer.os, "geteuid", return_value=0))
        self.stack.enter_context(patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}))
        self.stack.enter_context(patch.object(installer, "get_runtime_user", return_value=(os.getuid(), os.getgid())))
        self.commands = self.stack.enter_context(patch.object(installer, "command", side_effect=self.command))
        self.host = "gcp-realm-processor"
        self.package = self.root / "package"
        self.package.mkdir(mode=0o700)
        self.create_package(original)

    def command(self, argv):
        if argv[0] == "ip":
            return json.dumps([{"addr_info": [{"local": installer.HOSTS[self.host]}]}])
        return ""

    def write(self, name, raw):
        file = self.package / name
        file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        file.write_bytes(raw)
        file.chmod(0o600)

    def save_manifest(self):
        self.manifest["files"] = {str(file.relative_to(self.package)): packages.digest(file)
                                  for file in self.package.rglob("*") if file.is_file() and file.name != "manifest.json"}
        self.write("manifest.json", json.dumps(self.manifest).encode())

    def create_package(self, original):
        for name, raw in self.artifacts.items():
            self.write(name, raw)
        topology = json.loads((HERE.parent / "fresh-192-20261030/topology.json").read_bytes())
        for service in plan.services(topology):
            if service["host"] == self.host:
                text = packages.unit_text(service, self.release.release_id)
                for name in ("release_dir", "config_dir", "state_dir"):
                    text = text.replace(str(getattr(original, name)), str(getattr(self.release, name)))
                self.write("units/" + service["unit"], text.encode())
        for name in installer.host_inventory(self.host, self.release)[1]:
            self.write(name, ("test-only-" + name).encode())
        self.manifest = {"schema_version": 1, "release_id": self.release.release_id,
                         "source_commit": self.release.source_commit, "network": "testnet",
                         "host": self.host, "private_ip": installer.HOSTS[self.host], "files": {}}
        self.save_manifest()

    def test_fresh_install_is_idempotent_and_never_starts(self):
        result = installer.install_host(self.package, release=self.release)
        self.assertFalse(result["started"])
        installer.install_host(self.package, release=self.release)
        self.assertFalse(any(set(call.args[0]) & {"start", "stop", "enable", "restart"}
                             for call in self.commands.call_args_list))

    def test_check_only_does_not_write(self):
        self.assertEqual(installer.install_host(self.package, True, self.release)["mode"], "check-only")
        self.assertFalse((self.root / "host").exists())

    def test_missing_or_wrong_queue_lease_is_refused(self):
        unit = next((self.package / "units").iterdir())
        original = unit.read_bytes()
        for raw in (original.replace(b"NATS_WORKER_ACK_WAIT_MS=30000", b"NATS_WORKER_ACK_WAIT_MS=30001"),
                    original.replace(b'Environment="NATS_WORKER_ACK_WAIT_MS=30000"\n', b"")):
            unit.write_bytes(raw)
            self.save_manifest()
            with self.assertRaises(installer.InstallError):
                installer.install_host(self.package, release=self.release)
            self.assertFalse((self.root / "host").exists())
        self.commands.assert_not_called()

    def test_cross_cohort_manifest_and_namespace_are_refused(self):
        self.manifest["release_id"] = installer.RELEASE_ID
        self.save_manifest()
        with self.assertRaises(installer.InstallError):
            installer.install_host(self.package, release=self.release)
        self.manifest["release_id"] = self.release.release_id
        unit = next((self.package / "units").iterdir())
        unit.write_bytes(unit.read_bytes().replace(b"fresh20261030sd192_r", b"fresh20261027r3_r"))
        self.save_manifest()
        with self.assertRaises(installer.InstallError):
            installer.install_host(self.package, release=self.release)
        self.commands.assert_not_called()

    def test_old_active_r3_unit_still_blocks_fresh_installation(self):
        original = self.command
        def active_old(argv):
            if argv[:2] == ["systemctl", "list-units"]:
                return "psy-core-r3-realm-0-v1-processor.service loaded active running old\n"
            return original(argv)
        self.commands.side_effect = active_old
        with self.assertRaisesRegex(installer.InstallError, "running or transitioning"):
            installer.install_host(self.package, release=self.release)
        self.assertFalse((self.root / "host").exists())


if __name__ == "__main__":
    unittest.main()
