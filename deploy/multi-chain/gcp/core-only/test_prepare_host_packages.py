import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import plan
import prepare_host_packages as package
from test_plan import fixture


class PackageTests(unittest.TestCase):
    def test_unit_uses_pinned_commands_and_private_network(self):
        topology = fixture()[0]
        services = plan.services(topology)
        self.assertEqual(len(services), 16)
        for service in services:
            unit = package.unit_text(service, topology["release_id"])
            self.assertIn('"PSY_NETWORK=testnet"', unit)
            self.assertIn('"--network" "psy-public-testnet"', unit)
            self.assertIn('"--proving-backend" "plonky2-poseidon-goldilocks"', unit)
            self.assertIn('"10.148.0.23:9042"', unit)
            self.assertIn('"redis://10.148.0.12:6379"', unit)
            self.assertIn('"nats://10.148.0.20:4222"', unit)
            self.assertIn("ProtectSystem=strict", unit)
            self.assertIn("LimitCORE=0", unit)
            self.assertNotIn("PRIVATE_KEY=", unit)
            self.assertNotIn("local-devnet", unit)
            self.assertNotIn("jtmb", unit)

    def test_write_new_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys" / "key"
            package.write_new(path, b"original")
            with self.assertRaises(FileExistsError):
                package.write_new(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_private_input_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "key"
            package.write_new(path, b"example")
            self.assertEqual(package.regular(path, True), path)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                package.regular(path, True)
            link = root / "alias"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                package.regular(link)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.topology, config, genesis, whitelist = fixture()
        self.args = SimpleNamespace(**{name: self.root / (name + ".json") for name in
                                      ("topology", "config", "genesis", "whitelist", "private_keys", "faucet_operators")},
                                    node_binary=self.root / "node", p2p_keys=self.root / "p2p",
                                    output=self.root / "packages")
        self.private_keys = [None if i == 2 else f"{i + 1:064x}" for i in range(107)]
        operators = {"operators": [
            {"userId": str(((i & 1) << 20) | int(f"{i >> 1:020b}"[::-1], 2)),
             "privateKey": self.private_keys[i],
             "fingerprint": genesis["users"][i]["public_key_info"]["fingerprint"]}
            for i in range(7, 107)]}
        for name, document in (("topology", self.topology), ("config", config), ("genesis", genesis),
                               ("whitelist", whitelist), ("private_keys", self.private_keys),
                               ("faucet_operators", operators)):
            package.write_new(getattr(self.args, name), json.dumps(document).encode())
        package.write_new(self.args.node_binary, b"synthetic node binary")
        for rid, position, _ in plan.validators(self.topology):
            for name in ("processor_identity.key", "edge_identity.key", "bls.key"):
                package.write_new(self.args.p2p_keys / f"realm_{rid}_sub_{position}_{name}",
                                  f"synthetic-{rid}-{position}-{name}".encode())
        self.hashes = {name: package.digest(path) for name, path in (
            ("bin/psy_node_cli", self.args.node_binary), ("config.json", self.args.config),
            ("genesis.json", self.args.genesis))}
        for constant, name in (("NODE_SHA256", "bin/psy_node_cli"), ("CONFIG_SHA256", "config.json"),
                               ("GENESIS_SHA256", "genesis.json")):
            self.enterContext(patch.object(package, constant, self.hashes[name], create=True))
        self.output = self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def assert_no_output(self):
        self.assertFalse(os.path.lexists(self.args.output))
        self.assertEqual(list(self.root.glob(".psy-core-packages-*")), [])

    def test_prepare_all_six_hosts_hashes_modes_and_key_scope(self):
        previous = os.umask(0o022)
        try:
            package.prepare(self.args)
        finally:
            os.umask(previous)
        self.assertEqual({p.name for p in self.args.output.iterdir()}, set(self.topology["hosts"]))
        self.assertEqual(json.loads(self.output.getvalue()), {
            "packages": 6, "services": 16, "faucet_operators": 100, "installed": False, "started": False})
        for host, ip in self.topology["hosts"].items():
            root = self.args.output / host
            manifest = json.loads((root / "manifest.json").read_bytes())
            expected = {name: getattr(self.args, field).read_bytes() for name, field in (
                ("bin/psy_node_cli", "node_binary"), ("config.json", "config"), ("genesis.json", "genesis"))}
            for service in plan.services(self.topology):
                if service["host"] == host:
                    expected["units/" + service["unit"]] = package.unit_text(service, self.topology["release_id"]).encode()
            for rid, position, validator in plan.validators(self.topology):
                prefix = f"keys/realm-{rid}-v{position}/"
                names = []
                if validator["processor_host"] == host:
                    names += ["processor_identity.key", "bls.key"]
                    expected[prefix + "zk.key"] = (self.private_keys[validator["registration_id"]] + "\n").encode()
                if validator["edge_host"] == host:
                    names.append("edge_identity.key")
                for name in names:
                    expected[prefix + name] = (self.args.p2p_keys / f"realm_{rid}_sub_{position}_{name}").read_bytes()
            self.assertEqual(manifest, {
                "schema_version": 1, "release_id": self.topology["release_id"],
                "source_commit": "5d38eefc07b0925ed9875b74805d9c3fea73d998", "network": "testnet",
                "host": host, "private_ip": ip,
                "files": {name: hashlib.sha256(content).hexdigest() for name, content in expected.items()}})
            self.assertEqual({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()},
                             set(expected) | {"manifest.json"})
            for name, content in expected.items():
                self.assertTrue((root / name).read_bytes() == content, "package bytes mismatch")
                self.assertEqual((root / name).stat().st_mode & 0o777, 0o700 if name.startswith("bin/") else 0o600)
            self.assertEqual((root / "manifest.json").stat().st_mode & 0o777, 0o600)
        for path in (self.args.output, *self.args.output.rglob("*")):
            if path.is_dir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o700, str(path))
        for secret in self.private_keys:
            if secret:
                self.assertTrue(secret not in self.output.getvalue(), "secret leaked to stdout")

    def test_payload_pins_reject_before_creating_output(self):
        for constant in ("NODE_SHA256", "CONFIG_SHA256", "GENESIS_SHA256"):
            with self.subTest(constant=constant), patch.object(package, constant, "00" * 32):
                with self.assertRaises(ValueError):
                    package.prepare(self.args)
                self.assert_no_output()

    def test_each_copied_payload_is_checked_against_validated_bytes(self):
        copyfile = package.shutil.copyfile
        for source in (self.args.node_binary, self.args.config, self.args.genesis):
            original = source.read_bytes()
            def changed_copy(src, dst):
                if src == source:
                    source.write_bytes(b"changed after validation")
                return copyfile(src, dst)
            with self.subTest(source=source.name), patch.object(package.shutil, "copyfile", side_effect=changed_copy):
                try:
                    with self.assertRaisesRegex(ValueError, "copied .* hash mismatch"):
                        package.prepare(self.args)
                    self.assert_no_output()
                finally:
                    source.write_bytes(original)

    def test_failure_cleans_only_owned_temporary_directory(self):
        unrelated = self.root / ".psy-core-packages-unrelated"
        unrelated.mkdir()
        sentinel = unrelated / "retain"
        sentinel.write_bytes(b"retain")
        with patch.object(package, "unit_text", side_effect=OSError("simulated build failure")):
            with self.assertRaises(OSError):
                package.prepare(self.args)
        self.assertFalse(self.args.output.exists())
        self.assertEqual(list(self.root.glob(".psy-core-packages-*")), [unrelated])
        self.assertEqual(sentinel.read_bytes(), b"retain")

    def test_existing_output_is_never_replaced(self):
        self.args.output.mkdir()
        with self.assertRaisesRegex(ValueError, "output already exists"):
            package.prepare(self.args)
        self.assertEqual(list(self.args.output.iterdir()), [])
        self.assertEqual(list(self.root.glob(".psy-core-packages-*")), [])

    def test_publication_refuses_concurrently_created_empty_directory(self):
        publish = package.publish_packages
        def race(source, destination):
            self.assertFalse(destination.exists())
            destination.mkdir()
            self.inode = destination.stat().st_ino
            publish(source, destination)
        with patch.object(package, "publish_packages", side_effect=race):
            with self.assertRaises(FileExistsError):
                package.prepare(self.args)
        self.assertEqual(self.args.output.stat().st_ino, self.inode)
        self.assertEqual(list(self.args.output.iterdir()), [])
        self.assertEqual(list(self.root.glob(".psy-core-packages-*")), [])

    def test_publication_failure_leaves_no_final_or_temporary_output(self):
        with patch.object(package, "publish_packages", side_effect=OSError("simulated rename failure")):
            with self.assertRaises(OSError):
                package.prepare(self.args)
        self.assert_no_output()


if __name__ == "__main__":
    unittest.main()
