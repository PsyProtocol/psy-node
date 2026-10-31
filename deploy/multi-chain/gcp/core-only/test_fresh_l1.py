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
        manifest = {"version": 1, "contracts_base": m.BASE, "contracts_commit": "b" * 40, "signer": m.SIGNER,
                    "verifiers": {}, "files": m.inventory(root)}
        m.write_json(root / "manifest.json", manifest)
        return root, m.digest(root / "manifest.json")

    def test_admission_fixed_base_is_required(self):
        self.assertEqual(m.BASE, "394153fa7b4eb1b5f041131d15036a38321620f0")

    def test_pack_requires_operator_pinned_contracts_revision(self):
        with patch.object(m.subprocess, "run") as child, self.assertRaises(SystemExit):
            m.main(["pack", "--contracts", str(self.root), "--verifiers", "unused",
                    "--verifiers-sha256", "0" * 64, "--output", str(self.root / "out")])
        child.assert_not_called()

    def test_pack_rejects_non_descendant_and_extra_contract_changes_before_reading_exports(self):
        commit = "b" * 40
        args = SimpleNamespace(contracts=str(self.root), contracts_commit=commit,
                               verifiers="unused", verifiers_sha256="0" * 64,
                               output=str(self.root / "out"))
        approved = "\n".join(sorted(m.VERIFIERS)) + "\n"
        for ancestor, changed, reason in (
                (False, approved.encode(), "contracts Git verification failed"),
                (True, (approved + "contracts/Router.sol\n").encode(), "candidate changes more than four exported verifiers")):
            def git(argv, **kwargs):
                command = argv[3]
                if command == "rev-parse":
                    return subprocess.CompletedProcess(argv, 0, (commit + "\n").encode())
                if command == "status":
                    return subprocess.CompletedProcess(argv, 0, b"")
                if command == "merge-base":
                    return subprocess.CompletedProcess(argv, 0 if ancestor else 1, b"")
                if command == "diff":
                    return subprocess.CompletedProcess(argv, 0, changed)
                raise AssertionError(command)
            with self.subTest(ancestor=ancestor), patch.object(m.subprocess, "run", side_effect=git), \
                    patch.object(m, "read_json") as exports, self.assertRaisesRegex(m.GateError, reason):
                m.pack(args)
            exports.assert_not_called()
            self.assertFalse(Path(args.output).exists())

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

    def test_explicit_backup_only_and_sanitized_report(self):
        values = {"eth_chainId": hex(11155111),
                  "eth_getBlockByNumber": {"timestamp": hex(1000), "number": "0x2"},
                  "eth_syncing": False, "eth_getBalance": "0x3", "eth_gasPrice": "0x4"}
        with patch.object(m, "rpc", side_effect=lambda url, method, params: values[method]) as rpc, \
                patch.object(m.time, "time", return_value=1001):
            report, endpoint = m.status("sepolia", "own", "https://backup.invalid/token",
                                        "protected-env-backup")
        self.assertEqual(endpoint, "https://backup.invalid/token")
        self.assertEqual(report["provider"], "protected-env-backup")
        self.assertNotIn("token", json.dumps(report))
        self.assertTrue(all(call.args[0] == endpoint for call in rpc.call_args_list))

    def test_explicit_backup_missing_or_unhealthy_never_uses_own(self):
        for endpoint in (None, "", "https://backup.invalid/token"):
            with self.subTest(endpoint=bool(endpoint)), \
                    patch.object(m, "rpc", side_effect=ValueError("secret URL")) as rpc:
                with self.assertRaises(m.GateError) as error:
                    m.status("sepolia", "own", endpoint, "protected-env-backup")
                self.assertNotIn("secret URL", str(error.exception))
                self.assertTrue(all(call.args[0] == endpoint for call in rpc.call_args_list))
                if not endpoint:
                    rpc.assert_not_called()

    def test_status_cli_preference_default_and_explicit(self):
        for preference in ("own-node", "protected-env-backup"):
            argv = ["status"]
            if preference != "own-node":
                argv += ["--rpc-preference", preference]
            with patch.object(m, "secret_env", return_value={}), \
                    patch.object(m, "own_rpc", return_value="own"), \
                    patch.object(m, "status", return_value=({}, "selected")) as status:
                m.main(argv)
            self.assertEqual(status.call_count, 3)
            self.assertTrue(all(call.args[3] == preference for call in status.call_args_list))

    def test_deploy_backup_keeps_own_public_metadata(self):
        output = self.root / "out"
        output.mkdir()
        m.write_json(output / "prepared.json", {"manifest_sha256": "approved"})
        p = self.write(self.root / "policy.json", json.dumps(policy()))
        budget = self.write(self.root / "gas.json", json.dumps({"maxGasPriceWei": "4",
            "maxGasPerTransaction": "1", "maxTotalGas": "1", "maxNativeSpendWei": "1",
            "l1FeeReserveWeiPerTransaction": "0"}))
        key = self.write(self.root / "key.json", "synthetic")
        requests = []
        with patch.object(m, "verify_bundle", return_value=self.root), \
                patch.object(m, "secret_env", return_value={"WALLET_PASSWORD": "synthetic",
                    m.NETWORKS["sepolia"][3] + "_RPC_FALLBACK_URL": "backup"}), \
                patch.object(m, "own_rpc", return_value="own"), \
                patch.object(m, "status", return_value=({"balance_wei": "3", "gas_price_wei": "4"}, "backup")) as status, \
                patch.object(m, "child", side_effect=lambda *args: requests.append(copy.deepcopy(args[-1]))):
            m.main(["deploy", "--execute", "--bundle", str(self.root), "--manifest-sha256", "approved",
                    "--output", str(output), "--network", "sepolia", "--policy", str(p),
                    "--policy-sha256", m.digest(p), "--gas-budget", str(budget),
                    "--gas-budget-sha256", m.digest(budget), "--keystore", str(key), "--node", "/node",
                    "--rpc-preference", "protected-env-backup"])
        status.assert_called_once_with("sepolia", "own", "backup", "protected-env-backup")
        self.assertEqual([r["execute"] for r in requests], [False, True])
        self.assertTrue(all(r["rpc"] == "backup" and r["public_rpc"] == "own" for r in requests))

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
