import importlib.util
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rollout = load("rollout", "rollout.py")
config = load("rpc_config", "rpc-config.py")
gateway = load("gateway", "install-gateway.py")


class RolloutTests(unittest.TestCase):
    def setUp(self):
        self.chains = [dict(chain_index=i, chain_id=cid, state_manager=f"0x{i}",
                            graphql_url="http://private.example", hasura_admin_secret="test-only")
                       for i, cid in enumerate([11155111, 97, 84532])]
        self.profiles = config.providers_from_relayer({"chains": [dict(chain_index=i,
            rpc_providers=[dict(name="alchemy-" + who, operator="alchemy", quota_group=who,
                url=f"https://{network}.g.alchemy.com/v2/test-only-{who}") for who in ("team", "peter")])
            for i, network in enumerate(["eth-sepolia", "bnb-testnet", "base-sepolia"])]})

    def test_preserves_existing_chain_fields_and_legacy_config(self):
        before = json.dumps(self.chains)
        updated = rollout.new_chains(self.chains, self.profiles)
        self.assertEqual(json.dumps(self.chains), before)
        for old, new in zip(self.chains, updated):
            self.assertEqual({k: v for k, v in new.items() if k not in ("rpc_providers", "rpc_policy")}, old)

    def test_quote_roundtrip_without_shell_expansion(self):
        value = json.dumps(rollout.new_chains(self.chains, self.profiles))
        output = rollout.env_text({"PSY_L1_CHAINS": value})
        self.assertEqual(shlex.split(output)[0].split("=", 1)[1], value)

    def test_wrong_network_rejected(self):
        self.chains[1]["chain_id"] = 56
        with self.assertRaises(AssertionError):
            rollout.new_chains(self.chains, self.profiles)

    def test_wrong_provider_host_rejected(self):
        self.profiles["2"][0]["url"] = "https://example.org/v2/test-only"
        with self.assertRaises(AssertionError):
            rollout.new_chains(self.chains, self.profiles)

    def test_gateway_has_exact_source_acl_and_private_binding(self):
        unit = gateway.unit_text("sepolia", 28545, 8545)
        self.assertIn("bind=10.148.0.32", unit)
        self.assertIn("range=10.148.0.25/32", unit)
        self.assertNotIn("18545", unit)
        self.assertIn("ProtectSystem=strict", unit)

    def test_protected_file_drift_rejected(self):
        with tempfile.NamedTemporaryFile() as file:
            with self.assertRaises(AssertionError):
                rollout.unchanged({file.name: "wrong"})

    def test_rollback_allows_crashed_candidate(self):
        with tempfile.TemporaryDirectory() as root:
            drop = Path(root) / "drop"
            env = Path(root) / "env"
            exe = Path(root) / "old"
            for file in (drop, env, exe):
                file.write_text("test")
            state = dict(protected={}, drop_sha256=rollout.sha(drop), env_sha256=rollout.sha(env),
                         old={"exe": str(exe)}, new_hash="new")
            with patch.object(rollout, "DROP", drop), patch.object(rollout, "ENV", env), \
                 patch.object(rollout, "OLD_HASH", rollout.sha(exe)), patch.object(rollout, "pid", return_value="0"), \
                 patch.object(rollout, "run") as run, patch.object(rollout, "ready", return_value={"restored": True}):
                self.assertEqual(rollout.rollback(state), {"restored": True})
                run.assert_any_call("systemctl", "restart", rollout.UNIT)
            self.assertTrue(drop.exists())
            self.assertEqual(env.read_text(), "PSY_SERVICES_RUN_MIGRATIONS=false\n")
            self.assertEqual(env.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
