"""Offline Relayer generator/writer tests. No deployment or private config inputs."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "deploy/gcp/lib/multichain.sh"
WRITER = ROOT / "deploy/gcp/remote/write-relayer-config.sh"
SECRET = "SYNTHETIC_RPC_CREDENTIAL"


class RelayerRpcConfigTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="relayer-rpc-config-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.runtime = self.directory / "runtime.json"
        self.output = self.directory / "relayer.toml"
        chains = []
        for index, (network, chain_id, host) in enumerate((
                ("sepolia", 11155111, "eth-sepolia"),
                ("bscTestnet", 97, "bnb-testnet"),
                ("baseSepolia", 84532, "base-sepolia"))):
            chains.append({
                "name": network, "network": network, "chain_id": chain_id, "chain_index": index,
                "start_block": 100 + index, "rpc_url": f"https://{host}.g.alchemy.com/v2/Z_PRIMARY",
                "public_rpc_domain": f"rpc-{index}.example.invalid", "explorer_url": "https://explorer.example.invalid",
                "contracts": {"Bridge": f"0x{index + 1:040x}", "StateManager": f"0x{index + 16:040x}"},
                "protocol": {"chain": {"bridgeChain": network, "name": network, "shortName": network,
                    "nativeCurrency": {"name": "Test", "symbol": "TEST", "decimals": 18}}, "tokens": {}},
            })
        chains[0]["rpc_fallback_url"] = "https://eth-sepolia.g.alchemy.com/v2/A_BACKUP"
        chains[1]["rpc_fallback_url"] = chains[1]["rpc_url"]
        self.runtime.write_text(json.dumps({"schema_version": 1, "chains": chains}))
        self.env = {
            "PATH": os.environ["PATH"], "HOME": str(self.directory), "REPO_ROOT": str(ROOT),
            "MULTICHAIN_L1_ENABLED": "1", "MULTICHAIN_L1_RPC_PROVIDER": "alchemy",
            "MULTICHAIN_L1_RUNTIME_FILE": str(self.runtime), "MULTICHAIN_L1_CHAINS_JSON": json.dumps(chains),
            "INDEXER_GRAPHQL_URL": "http://indexer.example.invalid/graphql",
            "RELAYER_CONFIG": str(self.output), "RELAYER_PROOF_DIR": str(self.directory / "proofs"),
            "RELAYER_SERVICES_URL": "http://services.example.invalid",
            "RELAYER_L2_PRIVATE_KEY": "SYNTHETIC_L2_KEY",
            "RELAYER_FINALIZE_KEYSTORE_PATH": "/fixture/keystore/l1",
        }
        generated = self.helper()
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.legacy = json.loads(generated.stdout)

    def helper(self, function="multichain_relayer_chains_json", override=None):
        env = dict(self.env)
        if override is not None:
            env["RELAYER_CHAINS_JSON"] = override if isinstance(override, str) else json.dumps(override)
        return subprocess.run(["bash", "-c", 'source "$1"; "$2"', "test", str(HELPER), function],
            env=env, capture_output=True, text=True, timeout=20)

    def writer(self, chains, validate_only=False):
        env = dict(self.env, RELAYER_CHAINS_JSON=chains if isinstance(chains, str) else json.dumps(chains))
        args = ["bash", str(WRITER)] + (["--validate-chains"] if validate_only else [])
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)

    def providers(self):
        chains = copy.deepcopy(self.legacy)
        for index, chain in enumerate(chains):
            chain.pop("rpc_urls")
            chain["rpc_providers"] = [
                {"name": "colleague", "url": f"https://z-colleague.example.invalid/{SECRET}/{index}",
                    "operator": "alchemy", "quota_group": "colleague-subscription"},
                {"name": "peter", "url": f"https://a-peter.example.invalid/{SECRET}/{index}",
                    "operator": "alchemy", "quota_group": "peter-subscription"},
            ]
        chains[0]["rpc_providers"].insert(0, {
            "name": "local-http", "url": "http://127.0.0.1:18545", "operator": "local", "quota_group": "local"})
        return chains

    def assert_rejected_without_secrets(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(SECRET, result.stderr)

    def test_legacy_order_and_first_duplicate_preserved(self):
        self.assertEqual(self.legacy[0]["rpc_urls"], [
            "https://eth-sepolia.g.alchemy.com/v2/Z_PRIMARY", "https://eth-sepolia.g.alchemy.com/v2/A_BACKUP"])
        self.assertEqual(len(self.legacy[1]["rpc_urls"]), 1)
        self.assertEqual(len(self.legacy[2]["rpc_urls"]), 1)
        result = self.writer(self.legacy)
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = tomllib.loads(self.output.read_text())
        self.assertEqual([c["rpc_urls"] for c in parsed["chains"]], [c["rpc_urls"] for c in self.legacy])

    def test_explicit_named_pool_order_and_metadata_roundtrip(self):
        providers = self.providers()
        providers[0]["rpc_providers"][1]["name"] = 'colleague "quoted" \\ account'
        providers[0]["rpc_providers"][1]["priority_weight"] = 11
        providers[2]["rpc_providers"][1]["weight"] = 9
        generated = self.helper(override=providers)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.assertEqual(json.loads(generated.stdout), providers)
        result = self.writer(generated.stdout)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        config = tomllib.loads(self.output.read_text())
        self.assertEqual([len(c["rpc_providers"]) for c in config["chains"]], [3, 2, 2])
        for actual, expected in zip(config["chains"], providers):
            self.assertEqual(actual["rpc_providers"], expected["rpc_providers"])
            self.assertNotIn("rpc_urls", actual)
            self.assertEqual(actual["keystore_path"], "/fixture/keystore/l1")
            self.assertEqual(actual["bridge_address"], expected["bridge_address"])

    def test_non_rpc_config_unchanged(self):
        self.assertEqual(self.writer(self.legacy).returncode, 0)
        before = tomllib.loads(self.output.read_text())
        self.assertEqual(self.writer(self.providers()).returncode, 0)
        after = tomllib.loads(self.output.read_text())
        for config in (before, after):
            for chain in config["chains"]:
                chain.pop("rpc_urls", None)
                chain.pop("rpc_providers", None)
        self.assertEqual(before, after)

    def test_named_providers_take_precedence_over_legacy_urls(self):
        chains = self.providers()
        for chain in chains:
            chain["rpc_urls"] = ["https://ignored.example.invalid"]
        self.assertEqual(self.writer(chains).returncode, 0)
        parsed = tomllib.loads(self.output.read_text())
        self.assertTrue(all("rpc_urls" not in chain for chain in parsed["chains"]))
        self.assertEqual(parsed["chains"][0]["rpc_providers"], chains[0]["rpc_providers"])

    def test_empty_provider_list_falls_back_and_mixed_chains_work(self):
        chains = self.providers()
        chains[1] = copy.deepcopy(self.legacy[1])
        chains[1]["rpc_providers"] = []
        self.assertEqual(self.writer(chains).returncode, 0)
        parsed = tomllib.loads(self.output.read_text())
        self.assertEqual(parsed["chains"][1]["rpc_urls"], self.legacy[1]["rpc_urls"])
        self.assertNotIn("rpc_providers", parsed["chains"][1])

    def test_legacy_explicit_three_urls_keep_order(self):
        chains = copy.deepcopy(self.legacy)
        chains[0]["rpc_urls"] = ["http://127.0.0.1:18545", "https://z.example.invalid", "https://a.example.invalid"]
        generated = self.helper(override=chains)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.assertEqual(self.writer(generated.stdout).returncode, 0)
        self.assertEqual(tomllib.loads(self.output.read_text())["chains"][0]["rpc_urls"], chains[0]["rpc_urls"])

    def test_validation_mode_has_no_filesystem_side_effects(self):
        env = {"PATH": os.environ["PATH"], "RELAYER_CHAINS_JSON": json.dumps(self.providers()),
            "RELAYER_CONFIG": str(self.output), "RELAYER_PROOF_DIR": str(self.directory / "proofs")}
        result = subprocess.run(["bash", str(WRITER), "--validate-chains"], env=env,
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertFalse(self.output.exists())
        self.assertFalse((self.directory / "proofs").exists())

    def test_registry_and_contract_changes_rejected(self):
        for key, value in (("chain_index", 200), ("network_id", SECRET), ("deployments_network", SECRET),
                ("bridge_address", "0x" + "f" * 40), ("state_manager", "0x" + "e" * 40)):
            with self.subTest(key=key):
                chains = self.providers()
                chains[0][key] = value
                self.assert_rejected_without_secrets(self.helper(override=chains))
        chains = self.providers()
        self.assert_rejected_without_secrets(self.helper(override=chains[:2]))
        chains[0]["unexpected"] = SECRET
        self.assert_rejected_without_secrets(self.helper(override=chains))

    def test_chain_list_reordering_allowed_provider_order_preserved(self):
        chains = list(reversed(self.providers()))
        generated = self.helper(override=chains)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.assertEqual(json.loads(generated.stdout), chains)
        self.assertEqual(self.writer(generated.stdout).returncode, 0)
        parsed = tomllib.loads(self.output.read_text())
        self.assertEqual([c["chain_index"] for c in parsed["chains"]], [0, 1, 2])
        self.assertEqual(parsed["chains"][0]["rpc_providers"], chains[2]["rpc_providers"])

    def test_invalid_provider_input_is_redacted_and_preserves_output(self):
        original = b"existing config must not change"
        self.output.write_bytes(original)
        for field, value in (("url", "wss://host.invalid/" + SECRET), ("url", ""),
                ("url", "https://host.invalid/" + SECRET + "\n"), ("name", None),
                ("name", SECRET + "\n"), ("operator", 4), ("quota_group", []),
                ("weight", 1.5), ("weight", True), ("priority_weight", 2147483648),
                ("unknown", SECRET)):
            with self.subTest(field=field, value=value):
                chains = self.providers()
                chains[0]["rpc_providers"][0][field] = value
                self.assert_rejected_without_secrets(self.writer(chains))
                self.assertEqual(self.output.read_bytes(), original)
        chains = self.providers()
        chains[0]["rpc_providers"][0].update(weight=1, priority_weight=2)
        self.assert_rejected_without_secrets(self.writer(chains))
        self.assertFalse((self.directory / "proofs").exists())

    def test_malformed_or_multiple_json_values_are_redacted(self):
        for malformed in ('[{"rpc_providers":"' + SECRET, json.dumps(self.providers()) + "\n[]"):
            with self.subTest(malformed=malformed):
                self.assert_rejected_without_secrets(self.helper(override=malformed))
                self.assert_rejected_without_secrets(self.writer(malformed, validate_only=True))

    def test_invalid_chain_or_empty_rpc_list_rejected(self):
        for field, value in (("rpc_providers", []), ("rpc_providers", None),
                ("rpc_providers", {}), ("chain_index", 1), ("family", "other")):
            with self.subTest(field=field, value=value):
                chains = self.providers()
                chains[0][field] = value
                self.assert_rejected_without_secrets(self.writer(chains, validate_only=True))

    def test_explicit_relayer_pools_do_not_change_shared_or_public_outputs(self):
        original_runtime = self.runtime.read_bytes()
        for function in ("multichain_envio_chains_json", "multichain_services_l1_json",
                "multichain_public_rpc_routes_json", "multichain_public_l1_config_json"):
            with self.subTest(function=function):
                before = self.helper(function)
                after = self.helper(function, override=self.providers())
                self.assertEqual(before.returncode, 0, before.stderr)
                self.assertEqual(after.returncode, 0, after.stderr)
                self.assertEqual(before.stdout, after.stdout)
                self.assertNotIn(SECRET, after.stdout + after.stderr)
        self.assertEqual(self.runtime.read_bytes(), original_runtime)

    def test_shared_alchemy_policy_is_not_relaxed(self):
        runtime = json.loads(self.runtime.read_text())
        runtime["chains"][0]["rpc_url"] = "http://127.0.0.1:18545"
        self.runtime.write_text(json.dumps(runtime))
        self.assert_rejected_without_secrets(self.helper(override=self.providers()))


if __name__ == "__main__":
    unittest.main()
