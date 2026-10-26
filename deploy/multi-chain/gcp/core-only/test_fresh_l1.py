"""Offline filesystem, policy, RPC and secret-transport tests. Never broadcasts."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fresh_l1", HERE / "fresh_l1.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def policy():
    cfg = {"minDepositAmount": "1", "depositCap": str(10**19),
           "smallWithdrawalMax": "10", "mediumWithdrawalMax": "20", "totalWithdrawalCap": "30",
           "smallWithdrawalDelay": "0", "mediumWithdrawalDelay": "60", "largeWithdrawalDelay": "120",
           "configured": True}
    return {"version": 1, "deposit_rate_limit": "legacy-amount-bucket-absent-deposits-paused", "pause_deposits": True,
            "governance": "deployer-admin-proxy-timelock",
            "networks": {n: {t: copy.deepcopy(cfg) for t in ("native", "PSY", "pUSDT")} for n in m.NETWORKS}}


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        path.chmod(0o600)
        return path

    def bundle(self):
        root = self.root / "bundle"
        root.mkdir(mode=0o700)
        self.write(root / "fresh_l1.cjs", "public fixture")
        manifest = {"version": 1, "contracts_base": m.BASE, "contracts_commit": m.SOURCE, "signer": m.SIGNER,
                    "verifiers": {}, "files": m.inventory(root)}
        m.write_json(root / "manifest.json", manifest)
        return root, m.digest(root / "manifest.json")

    def test_policy_requires_explicit_bucket_decision(self):
        p = policy()
        m.validate_policy(p)
        for decision in (None, "10/minute", "pending"):
            p["deposit_rate_limit"] = decision
            with self.assertRaises(m.GateError): m.validate_policy(p)

    def test_policy_no_defaults_or_wrong_networks(self):
        p = policy()
        del p["networks"]["baseSepolia"]["PSY"]["largeWithdrawalDelay"]
        with self.assertRaises(m.GateError): m.validate_policy(p)
        p = policy()
        p["networks"]["ethereum"] = p["networks"].pop("sepolia")
        with self.assertRaises(m.GateError): m.validate_policy(p)

    def test_policy_widths_inventory_and_order(self):
        for field, value in (("depositCap", str(10**18)), ("minDepositAmount", "0"),
                             ("largeWithdrawalDelay", str(2**32)), ("depositCap", str(2**128)),
                             ("smallWithdrawalDelay", "121"), ("mediumWithdrawalMax", "1")):
            p = policy()
            p["networks"]["sepolia"]["PSY"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(m.GateError): m.validate_policy(p)

    def test_output_conflict_symlink_and_old_path(self):
        with self.assertRaises(m.GateError): m.safe_root(self.root, new=True)
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(m.GateError): m.safe_root(link / "fresh", new=True)
        with self.assertRaises(m.GateError): m.safe_root(self.root / "parth-old", new=True)

    def test_node_modules_links_only_within_module_tree(self):
        root = self.root / "bundle"
        modules = root / "contracts/node_modules"
        modules.mkdir(parents=True)
        self.write(modules / ".pnpm/pkg/index.js", "module.exports = 1;")
        (modules / "pkg").symlink_to(".pnpm/pkg", target_is_directory=True)
        self.assertIn("contracts/node_modules/pkg", m.inventory(root))
        (modules / "escape").symlink_to(self.root)
        with self.assertRaises(m.GateError): m.inventory(root)

    def test_extra_files_tamper_and_wrong_manifest_hash(self):
        root, pin = self.bundle()
        with patch.object(m, "validate_build"):
            m.verify_bundle(root, pin)
            with self.assertRaises(m.GateError): m.verify_bundle(root, "0" * 64)
            self.write(root / "extra", "unexpected")
            with self.assertRaises(m.GateError): m.verify_bundle(root, pin)
            (root / "extra").unlink()
            self.write(root / "fresh_l1.cjs", "tampered")
            with self.assertRaises(m.GateError): m.verify_bundle(root, pin)

    def test_duplicate_json(self):
        p = self.write(self.root / "p.json", '{"x":1,"x":2}')
        with self.assertRaises(m.GateError): m.read_json(p)

    def test_prepare_and_check_never_call_child_or_network(self):
        root, pin = self.bundle()
        with patch.object(m, "validate_build"), patch.object(m, "child") as child, patch.object(m, "rpc") as rpc:
            m.main(["check", "--bundle", str(root), "--manifest-sha256", pin])
            m.main(["prepare", "--bundle", str(root), "--manifest-sha256", pin, "--output", str(self.root / "fresh")])
            child.assert_not_called()
            rpc.assert_not_called()

    def test_no_execute_or_unapproved_policy_stops_before_rpc(self):
        with patch.object(m, "rpc") as rpc:
            with self.assertRaises(m.GateError): m.deploy(SimpleNamespace(execute=False))
            p = policy()
            p["deposit_rate_limit"] = "pending"
            target = self.write(self.root / "policy.json", json.dumps(p))
            with self.assertRaises(m.GateError):
                m.deploy(SimpleNamespace(execute=True, policy=target, policy_sha256=m.digest(target)))
            rpc.assert_not_called()

    def test_existing_attempt_never_retried(self):
        output = self.root / "out"
        output.mkdir()
        m.write_json(output / "prepared.json", {"manifest_sha256": "approved"})
        m.write_json(output / "attempt-sepolia.json", {})
        p = self.write(self.root / "policy.json", json.dumps(policy()))
        args = SimpleNamespace(execute=True, policy=p, policy_sha256=m.digest(p), bundle=self.root,
                               manifest_sha256="approved", output=output, network="sepolia")
        budget = self.write(self.root / "gas.json", json.dumps({"maxGasPriceWei":"1", "maxGasPerTransaction":"1",
            "maxTotalGas":"1", "maxNativeSpendWei":"1", "l1FeeReserveWeiPerTransaction":"0"}))
        args.gas_budget, args.gas_budget_sha256 = budget, m.digest(budget)
        with patch.object(m, "verify_bundle", return_value=self.root), patch.object(m, "child") as child:
            with self.assertRaises(m.GateError): m.deploy(args)
            child.assert_not_called()

    def test_protected_env_does_not_evaluate_shell(self):
        p = self.write(self.root / "secret.env", "WALLET_PASSWORD='$(touch never); secret'\nPRIVATE_KEY=ignored\n")
        self.assertEqual(m.secret_env([p]), {"WALLET_PASSWORD": "$(touch never); secret"})
        self.assertFalse((self.root / "never").exists())
        p.chmod(0o644)
        with self.assertRaises(m.GateError): m.secret_env([p])

    def test_private_rpc_ports_and_allowlist(self):
        p = self.write(self.root / "r.toml", '[[chains]]\nnetwork_id="sepolia"\n'
                       'rpc_providers=[{operator="local-reth",url="http://192.0.2.1:18545"}]\n')
        documentation_network = m.ipaddress.ip_network("192.0.2.0/24")
        with patch.object(m.ipaddress, "ip_network", return_value=documentation_network):
            self.assertEqual(m.own_rpc(p, "baseSepolia"), "http://192.0.2.1:18945")
        with self.assertRaises(m.GateError): m.own_rpc(p, "ethereum")

    def test_rpc_rejects_broadcast_methods(self):
        with self.assertRaises(m.GateError): m.rpc("http://unused", "eth_sendRawTransaction", [])

    def test_status_own_first_and_secret_backup_not_in_output(self):
        calls = []
        def fake(url, method, params):
            calls.append((url, method))
            if url == "own": raise ValueError("never expose https://token@backup")
            return {"eth_chainId": hex(11155111), "eth_getBlockByNumber": {"timestamp": hex(1000), "number": "0x2"},
                    "eth_syncing": False, "eth_getBalance": "0x3", "eth_gasPrice": "0x4"}[method]
        with patch.object(m, "rpc", side_effect=fake), patch.object(m.time, "time", return_value=1001):
            report, selected = m.status("sepolia", "own", "https://token@backup")
        self.assertEqual(calls[0][0], "own")
        self.assertEqual(selected, "https://token@backup")
        self.assertNotIn("token", json.dumps(report))

    def test_stale_or_wrong_chain_fails_closed(self):
        with patch.object(m, "rpc", return_value="0x1"):
            with self.assertRaises(m.GateError): m.status("sepolia", "own")

    def test_child_secrets_only_stdin_and_errors_suppressed(self):
        request = {"password": "SENSITIVE", "rpc": "https://secret@rpc"}
        response = SimpleNamespace(returncode=0, stdout=json.dumps({"ok": True, "address": m.SIGNER, "network": "sepolia"}))
        with patch.object(m.subprocess, "run", return_value=response) as run:
            m.child("/node", self.root, self.root, "sepolia", request)
        args, kwargs = run.call_args
        self.assertNotIn("SENSITIVE", repr(args))
        self.assertNotIn("secret@rpc", repr(kwargs["env"]))
        self.assertIn("SENSITIVE", kwargs["input"])
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
