"""Config candidate tests; no private keys, native acceptance or deployment."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prepare_config as prepare
import test_preflight


class ConfigPreparationTests(unittest.TestCase):
    def setUp(self):
        fixture = test_preflight.Fresh192PreflightTests()
        fixture.setUp()
        self.release = fixture.release
        self.retained = fixture.config
        self.retained["networks"]["testnet"].update(guardian_configs=copy.deepcopy(self.release["guardian_configs"]), guardian_history=[])
        for realm in self.retained["networks"]["testnet"]["realm_configs"]:
            realm["rpc_url"] = [f"https://realm{index}.invalid/" for index in range(3)]
        self.canonical = copy.deepcopy(self.retained)
        self.canonical["defaultNetwork"] = "localhost"
        self.canonical["networks"]["testnet"]["guardian_configs"] = []
        self.retained["networks"]["testnet"]["p2p"]["checkpoints_per_epoch"] = 10
        self.retained["networks"]["testnet"]["unexpected_private_field"] = "NEVER-COPY"

    def test_only_identity_fields_are_retained_and_inputs_stay_unchanged(self):
        original = copy.deepcopy(self.retained)
        config = prepare.build_config(self.canonical, self.retained, self.release)
        self.assertEqual(config["defaultNetwork"], "testnet")
        self.assertEqual(config["networks"]["testnet"]["p2p"]["checkpoints_per_epoch"], 32)
        self.assertNotIn("unexpected_private_field", config["networks"]["testnet"])
        self.assertEqual(original, self.retained)
        self.assertEqual(self.canonical["defaultNetwork"], "localhost")
        self.assertEqual(config["networks"]["testnet"]["guardian_configs"], self.release["guardian_configs"])

    def test_wrong_consensus_or_missing_membership_rejects(self):
        for key in ("magic", "realm_configs", "whitelist"):
            retained = copy.deepcopy(self.retained)
            retained["networks"]["testnet"].pop(key)
            with self.assertRaises((ValueError, KeyError)):
                prepare.build_config(self.canonical, retained, self.release)
        canonical = copy.deepcopy(self.canonical)
        canonical["networks"]["testnet"]["p2p"]["checkpoints_per_epoch"] = 10
        with self.assertRaises(ValueError):
            prepare.build_config(canonical, self.retained, self.release)

    def test_pinned_inputs_and_create_only_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = []
            for name, value in (("canonical", self.canonical), ("retained", self.retained)):
                raw = json.dumps(value).encode()
                path = root / (name + ".json")
                path.write_bytes(raw)
                args += ["--" + name, str(path), "--" + name + "-sha256", hashlib.sha256(raw).hexdigest()]
                self.release["canonical_config_sha256" if name == "canonical" else "retained_public_config_sha256"] = hashlib.sha256(raw).hexdigest()
            args += ["--output", str(root / "candidate")]
            with patch.object(prepare.preflight, "document", return_value=self.release), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(prepare.main(args), 0)
                self.assertEqual(prepare.main(args), 2)
            report = json.loads((root / "candidate/manifest.json").read_text())
            self.assertFalse(report["deployment_ready"])
            self.assertFalse(report["activation_authorized"])
            self.assertFalse(report["private_key_files_opened"])
            self.assertEqual((root / "candidate").stat().st_mode & 0o777, 0o700)
            for name in ("config.json", "manifest.json"):
                self.assertEqual((root / "candidate" / name).stat().st_mode & 0o777, 0o600)

    def test_wrong_hash_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "public.json"
            path.write_text("{}")
            with self.assertRaises(ValueError):
                prepare.read_pinned(path, "0" * 64)

    def test_missing_optional_guardian_history_does_not_copy_template_history(self):
        self.retained["networks"]["testnet"].pop("guardian_history")
        self.canonical["networks"]["testnet"]["guardian_history"] = ["template-not-retained"]
        config = prepare.build_config(self.canonical, self.retained, self.release)
        self.assertNotIn("guardian_history", config["networks"]["testnet"])

    def test_nonempty_history_unknown_nested_fields_or_wrong_guardians_reject(self):
        for mutate in (
            lambda n: n.update(guardian_history=[{"old": "state"}]),
            lambda n: n["guardian_configs"][0].update(password="NEVER-COPY"),
            lambda n: n["guardian_configs"].reverse(),
            lambda n: n["realm_configs"][0]["validators"][0].update(secret="NEVER-COPY"),
            lambda n: n["realm_configs"][0]["validators"][0]["edge_nodes"][0].update(secret="NEVER-COPY"),
            lambda n: n["realm_configs"][0]["rpc_url"].__setitem__(0, "https://user:secret@realm.invalid/"),
        ):
            retained = copy.deepcopy(self.retained)
            mutate(retained["networks"]["testnet"])
            with self.assertRaises(ValueError):
                prepare.build_config(self.canonical, retained, self.release)

    def test_symlink_and_nonregular_inputs_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / "public.json"
            file.write_text("{}")
            link = root / "link.json"
            link.symlink_to(file)
            for path in (root, link):
                with self.assertRaises((OSError, ValueError)):
                    prepare.read_pinned(path, hashlib.sha256(b"{}").hexdigest())

    def test_self_consistent_but_unapproved_input_hashes_reject_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = []
            for name, value in (("canonical", self.canonical), ("retained", self.retained)):
                raw = json.dumps(value).encode()
                file = root / (name + ".json")
                file.write_bytes(raw)
                args += ["--" + name, str(file), "--" + name + "-sha256", hashlib.sha256(raw).hexdigest()]
            args += ["--output", str(root / "candidate")]
            with patch.object(prepare, "read_pinned") as read, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(prepare.main(args), 2)
            read.assert_not_called()
            self.assertFalse((root / "candidate").exists())


if __name__ == "__main__":
    unittest.main()
