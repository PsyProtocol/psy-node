"""Synthetic read-only preflight tests; no cloud, Docker, keys or broadcasts."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import preflight


class Fresh192PreflightTests(unittest.TestCase):
    def setUp(self):
        self.release = preflight.document(preflight.HERE / "release.json")
        self.config = {"defaultNetwork": "testnet", "networks": {"testnet": {
            "magic": self.release["network_magic"], "p2p": {"checkpoints_per_epoch": 32},
            "whitelist": {"enabled": True, "secp256k1": ["02" + "1" * 64]},
            "guardian_initial_member_hashes": ["1", "02", "003"],
            "realm_configs": [{"id": i, "validators": [{
                "validator_user_id": (i << 20) + position,
                "processor_node_id": "002408011220" + f"{i * 6 + position * 2 + 1:064x}",
                "bls_public_key": f"{i * 3 + position + 1:096x}",
                "processor_addresses": ["/ip4/10.148.0.42/tcp/41001"],
                "edge_nodes": [{"node_id": "002408011220" + f"{i * 6 + position * 2 + 2:064x}",
                                "addresses": ["/ip4/10.148.0.36/tcp/41101"]}],
            } for position in range(3)]} for i in (0, 1)],
        }}}

    def test_release_keeps_required_cohort_choices(self):
        for key, expected in {"sd_key_max_calldata_words": 192, "max_introspectable_transactions": 64,
                              "checkpoints_per_epoch": 32, "faucet_operator_count": 100,
                              "native_deposits_allowed": False, "public_deposits_after_deploy": False,
                              "bridge_reader_included": False}.items():
            self.assertEqual(self.release[key], expected)
        self.assertEqual(self.release["deposit_tokens"], {"PSY": 0, "pUSDT": 4})
        self.assertEqual(self.release["withdrawal_append_supported_batch_sizes"], [1, 2, 5])
        self.assertEqual(self.release["withdrawal_append_max_batch_size"], 5)
        self.assertEqual([chain["chain_id"] for chain in self.release["chains"]], [11155111, 97, 84532])

    def test_valid_config_format_is_not_runtime_acceptance(self):
        preflight.config_checks(self.config, self.release)

    def test_old_epoch_disabled_whitelist_and_wrong_network_reject(self):
        for mutation in (lambda c: c.update(defaultNetwork="localhost"),
                         lambda c: c["networks"]["testnet"]["p2p"].update(checkpoints_per_epoch=10),
                         lambda c: c["networks"]["testnet"]["whitelist"].update(enabled=False),
                         lambda c: c["networks"]["testnet"]["whitelist"].update(secp256k1=[]),
                         lambda c: c["networks"]["testnet"]["realm_configs"][1].update(id=True)):
            config = copy.deepcopy(self.config)
            mutation(config)
            with self.assertRaises(ValueError):
                preflight.config_checks(config, self.release)

    def test_guardian_alias_duplicates_and_missing_members_reject(self):
        for members in (["1", "01", "2"], ["0", "1", "2"], ["1", "2"]):
            self.config["networks"]["testnet"]["guardian_initial_member_hashes"] = members
            with self.assertRaises(ValueError):
                preflight.config_checks(self.config, self.release)

    def test_source_checks_exact_published_commit_clean_tree_and_both_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            code = source / "client_prover/psy_core/psy_data/src/dpn/sd_key.rs"
            code.parent.mkdir(parents=True)
            code.write_text("pub const SDKEY_MAX_CALLDATA_WORDS: u32 = 192;\n"
                            "pub const MAX_INTROSPECTABLE_TRANSACTIONS: u32 = 64;\n")
            with patch.object(preflight.subprocess, "check_output", side_effect=[self.release["runtime_candidate_commit"], ""]) as git:
                preflight.source_checks(source, self.release)
                self.assertEqual(git.call_count, 2)
                self.assertTrue(all(call.args[0][0] == "git" for call in git.call_args_list))
                self.assertTrue(all("GIT_DIR" not in call.kwargs["env"] for call in git.call_args_list))
            for responses in (["3d317587" + "0" * 32], [self.release["runtime_candidate_commit"], " M source"]):
                with patch.object(preflight.subprocess, "check_output", side_effect=responses), self.assertRaises(ValueError):
                    preflight.source_checks(source, self.release)
            code.write_text(code.read_text().replace("192", "128"))
            with patch.object(preflight.subprocess, "check_output", side_effect=[self.release["runtime_candidate_commit"], ""]), self.assertRaises(ValueError):
                preflight.source_checks(source, self.release)

    def test_missing_inputs_only_reports_preparation_without_commands(self):
        output = io.StringIO()
        with patch.object(preflight.subprocess, "check_output") as git, contextlib.redirect_stdout(output):
            self.assertEqual(preflight.main([]), 2)
        git.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertFalse(report["deployment_ready"])
        self.assertFalse(report["activation_authorized"])
        self.assertEqual(len(report["blockers"]), 2)
        self.assertTrue(report["required_next_actions"])

    def test_passed_limited_checks_never_approve_deployment(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(json.dumps(self.config))
            with patch.object(preflight, "source_checks"), contextlib.redirect_stdout(output):
                self.assertEqual(preflight.main(["--source", tmp, "--config", str(config)]), 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["source_preflight_passed"])
        self.assertTrue(report["config_preflight_passed"])
        self.assertFalse(report["deployment_ready"])

    def test_bad_config_does_not_echo_secret_values(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text('{"password":"SENTINEL-DO-NOT-LOG"}')
            with contextlib.redirect_stdout(output):
                self.assertEqual(preflight.main(["--config", str(config)]), 2)
        self.assertNotIn("SENTINEL", output.getvalue())

    def test_duplicate_json_fields_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"defaultNetwork":"localhost","defaultNetwork":"testnet"}')
            with self.assertRaises(ValueError):
                preflight.document(path)

    def test_incomplete_or_duplicate_validator_membership_rejects(self):
        original = copy.deepcopy(self.config)
        for members in ([{}, {}, {}], "abc", [original["networks"]["testnet"]["realm_configs"][0]["validators"][0]] * 3):
            config = copy.deepcopy(original)
            config["networks"]["testnet"]["realm_configs"][0]["validators"] = members
            with self.assertRaises(ValueError):
                preflight.config_checks(config, self.release)
        config = copy.deepcopy(original)
        config["networks"]["testnet"]["realm_configs"][1]["validators"][0]["processor_node_id"] = config["networks"]["testnet"]["realm_configs"][0]["validators"][0]["processor_node_id"]
        with self.assertRaisesRegex(ValueError, "duplicate.*NodeId"):
            preflight.config_checks(config, self.release)

    def test_nonregular_public_inputs_reject_without_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "config.json"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular public input"):
                preflight.document(fifo)


if __name__ == "__main__":
    unittest.main()
