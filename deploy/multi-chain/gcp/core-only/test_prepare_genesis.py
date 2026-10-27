"""Adapter tests with mocked children; not circuit/Genesis acceptance evidence."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import prepare_genesis as prepare
from test_prepare_network import fixture


class GenesisPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "output"
        canonical, p2p, commitments, topology, whitelist, self.genesis = fixture()
        self.config = prepare.network.assemble_config(canonical, p2p, commitments, topology, whitelist)
        self.genesis["contracts"] = [{"test": i} for i in range(6)]
        self.secret = self.encode(["SECRET-SENTINEL-never-output"] * 107)
        self.keys = self.root / "retained-keys.json"
        self.keys.write_bytes(self.secret)
        self.keys.chmod(0o600)
        self.inputs = {}
        for name, raw in (("binary", b"mock-generator"), ("validator", b"mock-validator"),
                          ("config", self.encode(self.config)), ("bundle", b"full-public-bundle"),
                          ("bundle_stamp", b"{}")):
            self.inputs[name] = self.input(name, raw)
        for name in ("binary", "validator"):
            Path(self.inputs[name]["path"]).chmod(0o700)
        self.identity = {"schema_version": 1, "source_commit": "a" * 40,
                         "psy_network": "testnet", "cli_network": "psy-public-testnet",
                         "proving_backend": "plonky2-poseidon-goldilocks", "private_keys_mode": "import-only",
                         "binary_sha256": self.inputs["binary"]["sha256"],
                         "config_sha256": self.inputs["config"]["sha256"]}
        self.inputs["build_identity"] = self.input("build_identity", self.encode(self.identity))
        self.measurements = {"schema_version": 1, "network": "testnet", "node_source_commit": "a" * 40,
                             "config_sha256": self.inputs["config"]["sha256"],
                             "deposit_inclusion_fingerprint": [1, 2, 3, 4],
                             "private_note_inclusion_fingerprint": [5, 6, 7, 8]}
        self.inputs["measurements"] = self.input("measurements", self.encode(self.measurements))
        prior = prepare.network.inject_genesis(self.genesis, self.config)
        # The retained account baseline deliberately has no new contract layout.
        prior["contracts"] = [{"legacy_contract_without_layout": i} for i in range(6)]
        self.inputs["prior_genesis"] = self.input("prior_genesis", self.encode(prior))
        self.spec = {"schema_version": 1, "block_time": 1793070000, "inputs": self.inputs,
                     "compiler_artifacts": {name: self.input("compiler_" + name, self.encode({"name": name}))
                                            for name in prepare.CONTRACTS}}
        self.spec_path = self.root / "spec.json"
        self.save_spec()

    @staticmethod
    def encode(value):
        return (json.dumps(value) + "\n").encode()

    def input(self, name, raw):
        path = self.root / (name + ".json")
        path.write_bytes(raw)
        return {"path": str(path), "sha256": prepare.sha256(raw)}

    def save_spec(self):
        self.spec_path.write_bytes(self.encode(self.spec))

    def load(self):
        return prepare.load(self.spec_path, self.keys, prepare.sha256(self.secret), self.output)

    def invoke(self, mode):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = prepare.main([mode, "--spec", str(self.spec_path), "--private-keys-in", str(self.keys),
                                 "--private-keys-sha256", prepare.sha256(self.secret), "--output", str(self.output)])
        self.assertNotIn("SECRET-SENTINEL", stdout.getvalue() + stderr.getvalue())
        return code, json.loads(stdout.getvalue())

    def child(self, argv, **kwargs):
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(stat.S_IMODE(os.fstat(kwargs["stdout"].fileno()).st_mode), 0o600)
        self.assertEqual(kwargs["stderr"], subprocess.STDOUT)
        kwargs["stdout"].write(b"SECRET-SENTINEL-child-output\n")
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["timeout"], prepare.TIMEOUT)
        self.assertNotIn("PRIVATE_ENV_SENTINEL", kwargs["env"])
        self.assertNotIn("LD_PRELOAD", kwargs["env"])
        self.assertEqual(kwargs["env"]["PSY_NETWORK"], "testnet")
        self.assertEqual((Path(kwargs["cwd"]) / ".env").read_bytes(), b"")
        if argv[1] == "generate-genesis-data":
            self.assertNotIn("--random-private-keys", argv)
            self.assertEqual(argv[argv.index("--private-keys-in") + 1], str(self.keys))
            self.assertEqual(argv[argv.index("--private-keys-sha256") + 1], prepare.sha256(self.secret))
            prior = self.inputs["prior_genesis"]
            self.assertEqual(argv[argv.index("--accounts-genesis-in") + 1], prior["path"])
            self.assertEqual(argv[argv.index("--accounts-genesis-sha256") + 1], prior["sha256"])
            self.assertNotEqual(prior["path"], str(self.keys))
            self.assertNotIn(self.output, Path(prior["path"]).parents)
            self.assertNotEqual(prior["path"], argv[argv.index("--genesis-out") + 1])
            self.assertEqual(argv.count("--validator-slot"), 6)
            self.assertEqual(argv[argv.index("--faucet-operator-count") + 1], "100")
            repo = Path(argv[argv.index("--repo-root") + 1])
            self.assertEqual((repo / "psy-genesis/config.json").read_bytes(), self.encode(self.config))
            for name in prepare.CONTRACTS:
                self.assertTrue((repo.parent / "psy-compiler/psy-precompiles" / name / "target" / (name + ".json")).is_file())
            prepare.write_json(self.output / "generated-genesis.json", self.genesis)
            prepare.write_new(self.output / "private_keys.json", self.secret)
            prepare.write_json(self.output / "faucetOperators.json", {
                "operators": [{"userId": str(i), "privateKey": "SECRET-SENTINEL"} for i in range(100)]})
        else:
            self.assertEqual(argv[0], self.inputs["validator"]["path"])
            final = json.loads((self.output / "genesis.json").read_text())
            self.assertEqual(len(final["validators"]), 6)
            self.assertEqual(len(final["users"]), 107)
        return subprocess.CompletedProcess(argv, 0)

    def test_plan_has_no_child_or_output(self):
        with patch.object(prepare.subprocess, "run") as run:
            code, summary = self.invoke("plan")
        self.assertEqual(code, 0)
        self.assertFalse(summary["ready_static"])
        self.assertFalse(summary["deployment_ready"])
        run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_serial_generate_inject_validate_and_protected_outputs(self):
        before = self.keys.read_bytes()
        with patch.dict(os.environ, {"PRIVATE_ENV_SENTINEL": "secret", "LD_PRELOAD": "untrusted"}), \
             patch.object(prepare.subprocess, "run", side_effect=self.child) as run:
            code, summary = self.invoke("generate")
        self.assertEqual(code, 0)
        self.assertTrue(summary["ready_static"])
        self.assertFalse(summary["deployment_ready"])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(self.keys.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.output / "private_keys.json").stat().st_mode), 0o600)
        for stage in ("generate-genesis-data", "typed-cbor-validation"):
            log_path = self.output / (stage + ".private.log")
            self.assertEqual(summary["child_logs"][stage], str(log_path))
            self.assertTrue(log_path.is_file())
            self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)
        self.assertFalse((self.output / "FAILED").exists())

    def test_generator_failure_keeps_partial_and_does_not_validate(self):
        def fail(argv, **kwargs):
            prepare.write_new(self.output / "partial", b"retained")
            kwargs["stdout"].write(b"SECRET-SENTINEL-failure-evidence\n")
            raise subprocess.CalledProcessError(1, ["SECRET-SENTINEL"], output="SECRET-SENTINEL")
        with patch.object(prepare.subprocess, "run", side_effect=fail) as run:
            code, summary = self.invoke("generate")
        self.assertEqual(code, 1)
        self.assertFalse(summary["ready_static"])
        self.assertEqual(run.call_count, 1)
        self.assertTrue((self.output / "partial").exists())
        self.assertEqual(json.loads((self.output / "FAILED").read_text())["failed_stage"], "generate-genesis-data")
        self.assertEqual(summary["failed_stage"], "generate-genesis-data")
        log_path = Path(summary["child_logs"]["generate-genesis-data"])
        self.assertTrue(log_path.is_file())
        self.assertGreater(log_path.stat().st_size, 0)
        self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)
        self.assertFalse((self.output / "typed-cbor-validation.private.log").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_validator_rejection_cannot_publish_ready(self):
        def reject(argv, **kwargs):
            result = self.child(argv, **kwargs)
            if argv[1] != "generate-genesis-data":
                raise subprocess.CalledProcessError(1, argv)
            return result
        with patch.object(prepare.subprocess, "run", side_effect=reject):
            code, summary = self.invoke("generate")
        self.assertEqual(code, 1)
        self.assertEqual(summary["failed_stage"], "typed-cbor-validation")
        self.assertTrue(Path(summary["child_logs"]["typed-cbor-validation"]).is_file())
        self.assertTrue((self.output / "genesis.json").exists())
        self.assertTrue((self.output / "FAILED").exists())
        self.assertFalse((self.output / "result.json").exists())

    def test_timeout_keeps_failed_marker(self):
        with patch.object(prepare.subprocess, "run", side_effect=subprocess.TimeoutExpired("secret", 1)):
            self.assertEqual(self.invoke("generate")[0], 1)
        self.assertTrue((self.output / "FAILED").exists())

    def test_existing_output_never_modified(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("unchanged")
        with patch.object(prepare.subprocess, "run") as run:
            self.assertEqual(self.invoke("generate")[0], 1)
        run.assert_not_called()
        self.assertEqual(list(self.output.iterdir()), [marker])

    def test_bad_pin_rejected_before_generation(self):
        self.spec["inputs"]["bundle"]["sha256"] = "0" * 64
        self.save_spec()
        with patch.object(prepare.subprocess, "run") as run:
            self.assertEqual(self.invoke("generate")[0], 1)
        run.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_wrong_key_sha_rejected(self):
        with self.assertRaises(ValueError):
            prepare.load(self.spec_path, self.keys, "0" * 64, self.output)

    def test_prior_genesis_required_and_hash_pinned(self):
        original = copy.deepcopy(self.spec)
        for invalid in (None, {"path": self.inputs["prior_genesis"]["path"], "sha256": "0" * 64}):
            with self.subTest(prior=invalid is not None):
                self.spec = copy.deepcopy(original)
                if invalid is None:
                    del self.spec["inputs"]["prior_genesis"]
                else:
                    self.spec["inputs"]["prior_genesis"] = invalid
                self.save_spec()
                with patch.object(prepare.subprocess, "run") as run:
                    self.assertEqual(self.invoke("generate")[0], 1)
                run.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_prior_genesis_cannot_be_new_output_or_keys(self):
        for path, checksum in ((self.output / "genesis.json", "0" * 64),
                               (self.keys, prepare.sha256(self.secret))):
            with self.subTest(path=path.name):
                self.spec["inputs"]["prior_genesis"] = {"path": str(path), "sha256": checksum}
                self.save_spec()
                with patch.object(prepare.subprocess, "run") as run:
                    self.assertEqual(self.invoke("generate")[0], 1)
                run.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_private_mode_rejected(self):
        self.keys.chmod(0o644)
        with self.assertRaises(ValueError):
            self.load()

    def test_path_alias_and_symlinks_rejected(self):
        original = copy.deepcopy(self.spec)
        self.spec["inputs"]["bundle_stamp"] = dict(self.spec["inputs"]["bundle"])
        self.save_spec()
        with self.assertRaises(ValueError):
            self.load()
        self.spec = original
        self.save_spec()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.spec["inputs"]["config"]["path"] = str(alias / "config.json")
        self.save_spec()
        with self.assertRaises(ValueError):
            self.load()

    def test_wrong_network_backend_or_rng_identity_rejected(self):
        for name, value in (("psy_network", "localhost"), ("cli_network", "local-devnet"),
                            ("proving_backend", "jtmb-poseidon-goldilocks"), ("private_keys_mode", "random")):
            with self.subTest(field=name):
                changed = dict(self.identity, **{name: value})
                self.spec["inputs"]["build_identity"] = self.input("build_identity", self.encode(changed))
                self.save_spec()
                with self.assertRaises(ValueError):
                    self.load()

    def test_wrong_measurement_source_rejected(self):
        self.measurements["node_source_commit"] = "b" * 40
        self.spec["inputs"]["measurements"] = self.input("measurements", self.encode(self.measurements))
        self.save_spec()
        with self.assertRaises(ValueError):
            self.load()

    def test_changed_input_during_child_fails_closed(self):
        def changed(argv, **kwargs):
            result = self.child(argv, **kwargs)
            Path(self.inputs["bundle"]["path"]).write_bytes(b"changed")
            return result
        with patch.object(prepare.subprocess, "run", side_effect=changed) as run:
            self.assertEqual(self.invoke("generate")[0], 1)
        self.assertEqual(run.call_count, 1)
        self.assertTrue((self.output / "FAILED").exists())

    def test_wrong_user_count_fails_before_validator(self):
        self.genesis["users"].pop()
        with patch.object(prepare.subprocess, "run", side_effect=self.child) as run:
            self.assertEqual(self.invoke("generate")[0], 1)
        self.assertEqual(run.call_count, 1)

    def test_changed_keys_or_short_operator_inventory_rejected(self):
        for file, value in (("private_keys.json", ["DIFFERENT"] * 107),
                            ("faucetOperators.json", {"operators": []})):
            with self.subTest(file=file):
                self.output = self.root / file.replace(".json", "-failed")
                def changed(argv, **kwargs):
                    result = self.child(argv, **kwargs)
                    (self.output / file).write_bytes(self.encode(value))
                    return result
                with patch.object(prepare.subprocess, "run", side_effect=changed) as run:
                    self.assertEqual(self.invoke("generate")[0], 1)
                self.assertEqual(run.call_count, 1)
                self.assertTrue((self.output / "FAILED").exists())

    def test_membership_injection_uses_existing_module(self):
        with patch.object(prepare.network, "inject_genesis", wraps=prepare.network.inject_genesis) as inject, \
             patch.object(prepare.subprocess, "run", side_effect=self.child):
            self.assertEqual(self.invoke("generate")[0], 0)
        inject.assert_called_once()


if __name__ == "__main__":
    unittest.main()
