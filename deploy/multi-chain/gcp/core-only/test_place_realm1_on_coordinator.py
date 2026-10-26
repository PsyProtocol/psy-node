"""Synthetic placement tests; no real packages, accounts or host commands."""

from contextlib import ExitStack, redirect_stderr
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import install_host as install
import place_realm1_on_coordinator as placement
import plan
import prepare_host_packages as packages
from test_plan import fixture


class PlacementTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.original_paths = {name: getattr(install, name) for name in ("RELEASE", "CONFIG", "STATE", "UNITS")}
        for name, path in self.original_paths.items():
            self.stack.enter_context(patch.object(install, name, self.root / "host" / path.relative_to("/")))
        self.stack.enter_context(patch.object(install, "ROOT_UID", os.getuid()))
        self.stack.enter_context(patch.object(install, "ROOT_GID", os.getgid()))
        self.stack.enter_context(patch.object(install.os, "geteuid", return_value=0))
        self.stack.enter_context(patch.object(install, "get_runtime_user", return_value=(os.getuid(), os.getgid())))
        real_fstat = os.fstat
        root_uid = os.stat("/").st_uid

        def host_stat(fd):
            info = real_fstat(fd)
            if root_uid != os.getuid() and info.st_uid == root_uid:
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)
            return info

        self.stack.enter_context(patch.object(install.os, "fstat", side_effect=host_stat))
        topology, self.config, genesis, _ = fixture()
        self.artifacts = {"bin/psy_node_cli": b"synthetic node", "config.json": json.dumps(self.config).encode(),
                          "genesis.json": json.dumps(genesis).encode()}
        self.stack.enter_context(patch.object(install, "PINNED_SHA256", {
            name: hashlib.sha256(raw).hexdigest() for name, raw in self.artifacts.items()}))
        self.sources = self.root / "original"
        for host in install.HOSTS:
            payloads = dict(self.artifacts)
            for service in plan.services(topology):
                if service["host"] == host:
                    text = packages.unit_text(service, install.RELEASE_ID)
                    for name, old in self.original_paths.items():
                        text = text.replace(str(old), str(getattr(install, name)))
                    payloads["units/" + service["unit"]] = text.encode()
            for key in install.host_inventory(host)[1]:
                payloads[key] = ("synthetic-only-" + key).encode()
            manifest = {"host": host, "private_ip": install.HOSTS[host], "source_commit": install.SOURCE_COMMIT,
                        "release_id": install.RELEASE_ID, "network": "testnet",
                        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()}}
            payloads["manifest.json"] = json.dumps(manifest).encode()
            for name, raw in payloads.items():
                packages.write_new(self.sources / host / name, raw)
        self.output = self.root / "placement"
        self.host = "gcp-cp-ce"
        self.commands = self.stack.enter_context(patch.object(install, "command", side_effect=self.command))

    def command(self, argv):
        if argv[0] == "ip":
            return json.dumps([{"addr_info": [{"local": install.HOSTS[self.host]}]}])
        return ""

    def prepare(self):
        placement.prepare(self.sources, self.output)
        return self.output / self.host

    def installed(self):
        for name, raw in self.artifacts.items():
            path = install.RELEASE / name if name.startswith("bin/") else install.CONFIG / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o755 if name.startswith("bin/") else 0o644)
        install.UNITS.mkdir(parents=True, exist_ok=True)
        if self.host == "gcp-edge-2":
            for position in range(1, 4):
                name = placement.unit_name(position, "edge")
                (install.UNITS / name).write_bytes((self.sources / self.host / "units" / name).read_bytes())
        self.sentinel = install.UNITS / "psy-core-coordinator-processor.service"
        self.sentinel.write_bytes(b"existing CP remains untouched")

    def test_prepare_exact_routes_keys_units_and_private_modes(self):
        self.prepare()
        expected = copy.deepcopy(self.config)
        for member in expected["networks"]["testnet"]["realm_configs"][1]["validators"]:
            parts = member["processor_addresses"][0].split("/")
            parts[2] = install.HOSTS["gcp-cp-ce"]
            member["processor_addresses"] = ["/".join(parts)]
        for host in placement.HOSTS:
            actual_host, payloads = placement.read_package(self.output / host)
            self.assertEqual(actual_host, host)
            self.assertEqual(json.loads(payloads[placement.CONFIG_NAME]), expected)
            keys = {name for name in payloads if name.startswith("keys/")}
            self.assertEqual(len(keys), 9 if host == "gcp-cp-ce" else 0)
            self.assertTrue(all(name.startswith("keys/realm-1-") for name in keys))
            for name in keys:
                position = int(name.split("/")[1][-1])
                self.assertEqual(payloads[name], (self.sources / install.PROCESSORS[position - 1] / name).read_bytes())
            for position in range(1, 4):
                if host == "gcp-cp-ce":
                    unit = payloads["units/" + placement.unit_name(position, "processor")].decode()
                    self.assertIn("Slice=" + placement.SLICE, unit)
                    self.assertIn(f'"fresh20261026r2_r1_v{position}"', unit)
                    self.assertIn("/core-testnet-20261026-r2/checkpoints", unit)
                    self.assertIn(f"/ip4/10.148.0.25/tcp/{41020 + position}", unit)
                    self.assertIn(str(install.CONFIG / placement.CONFIG_NAME), unit)
                else:
                    name = f"units/{placement.unit_name(position, 'edge')}.d/{placement.DROPIN}"
                    self.assertEqual(payloads[name], f'[Service]\nEnvironment="PSY_CONFIG_PATH={install.CONFIG / placement.CONFIG_NAME}"\n'.encode())
        for path in [self.output, *self.output.rglob("*")]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.commands.assert_not_called()

    def test_prepare_refuses_existing_and_cleans_only_owned_temp(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_bytes(b"keep")
        with self.assertRaises(install.InstallError):
            placement.prepare(self.sources, self.output)
        self.assertEqual(marker.read_bytes(), b"keep")
        with patch.object(placement, "build_payloads", side_effect=install.InstallError("test failure")):
            with self.assertRaises(install.InstallError):
                placement.prepare(self.sources, self.root / "failed")
        self.assertFalse((self.root / "failed").exists())
        self.assertFalse(list(self.root.glob(".realm1-placement-*")))

    def test_source_hash_and_private_directory_fail_closed(self):
        key = self.sources / install.PROCESSORS[0] / "keys/realm-1-v1/bls.key"
        original = key.read_bytes()
        key.write_bytes(b"changed")
        with self.assertRaisesRegex(install.InstallError, "hash mismatch"):
            self.prepare()
        key.write_bytes(original)
        key.parent.parent.chmod(0o755)
        with self.assertRaisesRegex(install.InstallError, "directories must be private"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_rehashed_derived_payload_tampering_rejected(self):
        package = self.prepare()
        config = package / placement.CONFIG_NAME
        config.write_bytes(config.read_bytes() + b" ")
        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][placement.CONFIG_NAME] = hashlib.sha256(config.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(install.InstallError, "payload mismatch"):
            placement.read_package(package)

    def test_source_symlink_hardlink_and_public_file_rejected(self):
        key = self.sources / install.PROCESSORS[0] / "keys/realm-1-v1/bls.key"
        outside = self.root / "outside"
        outside.write_bytes(key.read_bytes())
        outside.chmod(0o600)
        for kind in ("symlink", "hardlink", "public"):
            with self.subTest(kind=kind):
                key.unlink()
                if kind == "symlink":
                    key.symlink_to(outside)
                elif kind == "hardlink":
                    os.link(outside, key)
                else:
                    key.write_bytes(outside.read_bytes())
                    key.chmod(0o644)
                with self.assertRaises((install.InstallError, OSError)):
                    self.prepare()
                self.assertFalse(self.output.exists())

    def test_apply_check_install_idempotence_rollback_preserves_keys_and_originals(self):
        package = self.prepare()
        self.installed()
        original_config = (install.CONFIG / "config.json").read_bytes()
        with patch.object(install, "install_file") as write, patch.object(install, "create_directory") as mkdir:
            placement.apply(package, check_only=True)
            write.assert_not_called()
            mkdir.assert_not_called()
        placement.apply(package)
        key = install.CONFIG / "keys/realm-1-v1/bls.key"
        identity = (key.stat().st_ino, key.read_bytes())
        placement.apply(package)
        self.assertEqual((key.stat().st_ino, key.read_bytes()), identity)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(key.parent.stat().st_mode), 0o700)
        placement.apply(package, rollback=True)
        self.assertEqual((key.stat().st_ino, key.read_bytes()), identity)
        self.assertFalse((install.CONFIG / placement.CONFIG_NAME).exists())
        self.assertFalse((install.UNITS / placement.SLICE).exists())
        self.assertEqual((install.CONFIG / "config.json").read_bytes(), original_config)
        self.assertEqual(self.sentinel.read_bytes(), b"existing CP remains untouched")
        self.assertFalse(any(set(call.args[0]) & {"start", "restart", "stop", "enable", "mask"}
                             for call in self.commands.call_args_list))

    def test_edge_apply_and_rollback_preserve_original_units(self):
        self.host = "gcp-edge-2"
        package = self.prepare()
        self.installed()
        originals = {p: p.read_bytes() for p in install.UNITS.iterdir()}
        placement.apply(package)
        self.assertFalse((install.CONFIG / "keys").exists())
        placement.apply(package, rollback=True)
        for path, raw in originals.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_wrong_ip_active_unit_and_queued_job_rejected(self):
        package = self.prepare()
        self.installed()
        for bad in ("ip", "list-units", "list-jobs"):
            def command(argv):
                if bad in argv:
                    return {"ip": "[]", "list-units": placement.unit_name(1, "processor") + " loaded active running",
                            "list-jobs": "1 " + placement.unit_name(1, "processor") + " start waiting"}[bad]
                return self.command(argv)
            with self.subTest(bad=bad), patch.object(install, "command", side_effect=command):
                with self.assertRaises(install.InstallError):
                    placement.apply(package)
                self.assertFalse((install.CONFIG / placement.CONFIG_NAME).exists())

    def test_installed_pin_conflict_and_destination_conflict_prevent_writes(self):
        package = self.prepare()
        self.installed()
        genesis = install.CONFIG / "genesis.json"
        genesis.write_bytes(b"wrong genesis")
        with self.assertRaisesRegex(install.InstallError, "pin mismatch"):
            placement.apply(package)
        genesis.write_bytes(self.artifacts["genesis.json"])
        target = install.UNITS / placement.unit_name(3, "processor")
        target.write_bytes(b"existing conflicting unit")
        with self.assertRaisesRegex(install.InstallError, "content conflict"):
            placement.apply(package)
        self.assertFalse((install.CONFIG / placement.CONFIG_NAME).exists())

    def test_diagnostics_include_path_not_contents(self):
        package = self.prepare()
        self.installed()
        install.CONFIG.chmod(0o700)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(placement.main(["apply", "--package", str(package)]), 1)
        self.assertIn(str(install.CONFIG), stderr.getvalue())
        self.assertIn("expected 0755", stderr.getvalue())
        self.assertNotIn("synthetic-only", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
