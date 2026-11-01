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
COMMIT = "b" * 40
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
        manifest = {"version": 1, "contracts_commit": COMMIT, "signer": m.SIGNER,
                    "verifiers": {}, "files": m.inventory(root)}
        m.write_json(root / "manifest.json", manifest)
        return root, m.digest(root / "manifest.json")

    def test_no_fixed_base_commit_remains(self):
        self.assertFalse(hasattr(m, "BASE"))

    def test_pack_requires_operator_pinned_contracts_revision(self):
        with patch.object(m.subprocess, "run") as child, self.assertRaises(SystemExit):
            m.main(["pack", "--contracts", str(self.root), "--verifiers", "unused",
                    "--verifiers-sha256", "0" * 64, "--output", str(self.root / "out")])
        child.assert_not_called()

    def test_pack_rejects_wrong_head_and_dirty_tree_before_reading_exports(self):
        args = SimpleNamespace(contracts=str(self.root), contracts_commit=COMMIT,
                               verifiers="unused", verifiers_sha256="0" * 64,
                               output=str(self.root / "out"))
        for head, dirty, reason in (("c" * 40, b"", "wrong contracts commit"),
                                    (COMMIT, b" M src/Bridge.sol\n", "tracked worktree must be clean")):
            def git(argv, **kwargs):
                command = argv[3]
                if command == "rev-parse":
                    return subprocess.CompletedProcess(argv, 0, (head + "\n").encode())
                if command == "status":
                    return subprocess.CompletedProcess(argv, 0, dirty)
                raise AssertionError(command)
            with self.subTest(reason=reason), patch.object(m.subprocess, "run", side_effect=git), \
                    patch.object(m, "read_json") as exports, self.assertRaisesRegex(m.GateError, reason):
                m.pack(args)
            exports.assert_not_called()
            self.assertFalse(Path(args.output).exists())

    def test_pack_rejects_source_that_differs_from_the_pinned_commit(self):
        source = self.root / "contracts"
        for name in ("package.json", "pnpm-lock.yaml", "tsconfig.json", "hardhat.config.ts",
                     "helper-hardhat-config.ts"):
            self.write(source / name, "x")
        self.write(source / "src/Bridge.sol", "edited")
        self.write(self.root / "verifiers.json", json.dumps({name: "0" * 64 for name in m.VERIFIERS}))
        tracked = "\0".join(["package.json", "pnpm-lock.yaml", "tsconfig.json", "hardhat.config.ts",
                             "helper-hardhat-config.ts", "src/Bridge.sol"]) + "\0"
        def git(argv, **kwargs):
            command = argv[3]
            outputs = {"rev-parse": COMMIT + "\n", "status": "", "ls-files": tracked}
            if command == "show":
                return subprocess.CompletedProcess(argv, 0, b"x" if argv[4] != f"{COMMIT}:src/Bridge.sol" else b"committed")
            return subprocess.CompletedProcess(argv, 0, outputs[command].encode())
        args = SimpleNamespace(contracts=str(source), contracts_commit=COMMIT,
                               verifiers=str(self.root / "verifiers.json"),
                               verifiers_sha256=m.digest(self.root / "verifiers.json"), output=str(self.root / "out"))
        with patch.object(m.subprocess, "run", side_effect=git), \
                self.assertRaisesRegex(m.GateError, "source differs from the pinned commit"):
            m.pack(args)
        self.assertFalse((self.root / "out").exists())

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
            m.verify_bundle(root, pin, COMMIT)
            with self.assertRaises(m.GateError): m.verify_bundle(root, "0" * 64, COMMIT)
            self.write(root / "extra", "unexpected")
            with self.assertRaises(m.GateError): m.verify_bundle(root, pin, COMMIT)
            (root / "extra").unlink()
            self.write(root / "fresh_l1.cjs", "tampered")
            with self.assertRaises(m.GateError): m.verify_bundle(root, pin, COMMIT)

    def test_bundle_rejects_contracts_commit_differing_from_lock(self):
        root, pin = self.bundle()
        with patch.object(m, "validate_build"):
            for other in ("c" * 40, "", None, "B" * 40, COMMIT[:39]):
                with self.subTest(commit=other), self.assertRaises(m.GateError):
                    m.verify_bundle(root, pin, other)
            m.verify_bundle(root, pin, COMMIT)

    def test_duplicate_json(self):
        p = self.write(self.root / "p.json", '{"x":1,"x":2}')
        with self.assertRaises(m.GateError): m.read_json(p)

    def test_prepare_and_check_never_call_child_or_network(self):
        root, pin = self.bundle()
        with patch.object(m, "validate_build"), patch.object(m, "child") as child, patch.object(m, "rpc") as rpc:
            m.main(["check", "--bundle", str(root), "--manifest-sha256", pin, "--contracts-commit", COMMIT])
            m.main(["prepare", "--bundle", str(root), "--manifest-sha256", pin, "--contracts-commit", COMMIT,
                    "--output", str(self.root / "fresh")])
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
                               manifest_sha256="approved", output=output, network="sepolia", contracts_commit=COMMIT)
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
                    "eth_syncing": False, "eth_getBalance": "0x3", "eth_gasPrice": "0x4",
                    "eth_getTransactionCount": "0x5"}[method]
        with patch.object(m, "rpc", side_effect=fake), patch.object(m.time, "time", return_value=1001):
            report, selected = m.status("sepolia", "own", "https://token@backup")
        self.assertEqual(calls[0][0], "own")
        self.assertEqual(selected, "https://token@backup")
        self.assertNotIn("token", json.dumps(report))


    def test_status_reports_signer_and_latest_and_pending_nonce(self):
        seen = []
        def fake(url, method, params):
            seen.append((method, params))
            return {"eth_chainId": hex(11155111), "eth_getBlockByNumber": {"timestamp": hex(1000), "number": "0x2"},
                    "eth_syncing": False, "eth_getBalance": "0x3", "eth_gasPrice": "0x4",
                    "eth_getTransactionCount": "0x7" if (params or [None])[-1] == "latest" else "0x9"}[method]
        with patch.object(m, "rpc", side_effect=fake), patch.object(m.time, "time", return_value=1001):
            report, _ = m.status("sepolia", "own")
        self.assertEqual(report["signer"], m.SIGNER)
        self.assertEqual((report["nonce_latest"], report["nonce_pending"]), (7, 9))
        self.assertIn(("eth_getTransactionCount", [m.SIGNER, "pending"]), seen)

    def test_nonce_read_is_an_allowed_read_only_method(self):
        with patch.object(m.urllib.request, "build_opener", side_effect=RuntimeError("reached transport")):
            with self.assertRaises(RuntimeError):
                m.rpc("http://unused", "eth_getTransactionCount", [m.SIGNER, "latest"])

    def test_validate_budget_is_the_one_check_for_all_networks(self):
        good = {"maxGasPriceWei": "1", "maxGasPerTransaction": "2", "maxTotalGas": "3", "maxNativeSpendWei": "4",
                "l1FeeReserveWeiPerTransaction": "0"}
        m.validate_budget(good, "sepolia")
        for bad in ({**good, "maxTotalGas": "0"}, {**good, "maxTotalGas": 3}, {**good, "extra": "1"},
                    {key: value for key, value in good.items() if key != "maxTotalGas"}):
            with self.assertRaises(m.GateError):
                m.validate_budget(bad, "sepolia")
        with self.assertRaisesRegex(m.GateError, "Base L1 data-fee reserve required"):
            m.validate_budget(good, "baseSepolia")
        m.validate_budget({**good, "l1FeeReserveWeiPerTransaction": "1"}, "baseSepolia")

    def test_stale_or_wrong_chain_fails_closed(self):
        with patch.object(m, "rpc", return_value="0x1"):
            with self.assertRaises(m.GateError): m.status("sepolia", "own")

    def test_explicit_backup_only_and_sanitized_report(self):
        values = {"eth_chainId": hex(11155111),
                  "eth_getBlockByNumber": {"timestamp": hex(1000), "number": "0x2"},
                  "eth_syncing": False, "eth_getBalance": "0x3", "eth_gasPrice": "0x4",
                  "eth_getTransactionCount": "0x5"}
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

    def deploy_fixture(self, name="case"):
        base = self.root / name
        output = base / "out"
        output.mkdir(parents=True)
        m.write_json(output / "prepared.json", {"manifest_sha256": "approved"})
        p = self.write(base / "policy.json", json.dumps(policy()))
        budget = self.write(base / "gas.json", json.dumps({"maxGasPriceWei": "4",
            "maxGasPerTransaction": "50000000", "maxTotalGas": "1", "maxNativeSpendWei": "3",
            "l1FeeReserveWeiPerTransaction": "0"}))
        key = self.write(base / "key.json", "synthetic")
        argv = ["deploy", "--execute", "--bundle", str(self.root), "--manifest-sha256", "approved",
                "--contracts-commit", COMMIT, "--output", str(output), "--network", "sepolia", "--policy", str(p),
                "--policy-sha256", m.digest(p), "--gas-budget", str(budget),
                "--gas-budget-sha256", m.digest(budget), "--keystore", str(key), "--node", "/node",
                "--rpc-preference", "protected-env-backup"]
        return output, argv

    def run_deploy(self, argv, reports, estimate_within=True):
        requests = []
        with patch.object(m, "verify_bundle", return_value=self.root) as verify, \
                patch.object(m, "secret_env", return_value={"WALLET_PASSWORD": "synthetic",
                    m.NETWORKS["sepolia"][3] + "_RPC_FALLBACK_URL": "backup"}), \
                patch.object(m, "own_rpc", return_value="own"), \
                patch.object(m, "estimate_creation", return_value={"within_budget": estimate_within}) as estimate, \
                patch.object(m, "status", side_effect=[(report, "backup") for report in reports]) as status, \
                patch.object(m, "child", side_effect=lambda *args: requests.append(copy.deepcopy(args[-1]))):
            try:
                m.main(argv)
            finally:
                self.calls = (verify, estimate, status, requests)
        return requests

    def report(self, latest=5, pending=5):
        return {"balance_wei": "3", "gas_price_wei": "3", "nonce_latest": latest, "nonce_pending": pending}

    def test_whole_stack_cost_must_fit_the_spend_ceiling_before_any_child(self):
        budget = {"maxGasPriceWei": "4", "maxGasPerTransaction": "50000000", "maxTotalGas": "1", "maxNativeSpendWei": "1",
                  "l1FeeReserveWeiPerTransaction": "0"}
        self.assertFalse(m.stack_within_spend(budget, 2))
        self.assertTrue(m.stack_within_spend({**budget, "maxNativeSpendWei": "2"}, 2))
        self.assertFalse(m.stack_within_spend({**budget, "maxNativeSpendWei": "100", "l1FeeReserveWeiPerTransaction": "3"}, 0))
        self.assertTrue(m.stack_within_spend({**budget, "maxNativeSpendWei": "123", "l1FeeReserveWeiPerTransaction": "3"}, 0))
        output, argv = self.deploy_fixture("spend")
        gas = Path(argv[argv.index("--gas-budget") + 1])
        gas.write_text(json.dumps({**budget, "maxGasPriceWei": "4", "maxTotalGas": "100"}))
        argv[argv.index("--gas-budget-sha256") + 1] = m.digest(gas)
        with self.assertRaisesRegex(m.GateError, "whole-stack cost"):
            self.run_deploy(argv, [self.report()])
        self.assertEqual(self.calls[3], [])

    def test_deploy_backup_keeps_own_public_metadata(self):
        output, argv = self.deploy_fixture()
        requests = self.run_deploy(argv, [self.report(), self.report()])
        verify, estimate, status, _ = self.calls
        verify.assert_called_once_with(str(self.root), "approved", COMMIT)
        self.assertEqual(status.call_args_list[0].args, ("sepolia", "own", "backup", "protected-env-backup"))
        self.assertEqual([r["execute"] for r in requests], [False, True])
        self.assertTrue(all(r["rpc"] == "backup" and r["public_rpc"] == "own" for r in requests))

    def test_nonce_mismatch_blocks_deploy(self):
        for label, reports in (("pending-before-preflight", [self.report(5, 6)]),
                               ("pending-before-broadcast", [self.report(), self.report(5, 6)]),
                               ("moved-before-broadcast", [self.report(), self.report(6, 6)])):
            output, argv = self.deploy_fixture(label)
            with self.subTest(label), self.assertRaisesRegex(m.GateError, "nonce|pending transactions"):
                self.run_deploy(argv, reports)
            self.assertEqual([r["execute"] for r in self.calls[3]], [] if len(reports) == 1 else [False])
            self.assertFalse((output / "attempt-sepolia.json").exists())

    def test_nonce_is_reread_after_the_wallet_check_and_before_the_attempt_record(self):
        output, argv = self.deploy_fixture()
        order = []
        with patch.object(m, "verify_bundle", return_value=self.root), \
                patch.object(m, "secret_env", return_value={"WALLET_PASSWORD": "synthetic"}), \
                patch.object(m, "own_rpc", return_value="own"), \
                patch.object(m, "estimate_creation", return_value={"within_budget": True}), \
                patch.object(m, "status", side_effect=lambda *a: order.append("status") or (self.report(), "own")), \
                patch.object(m, "child", side_effect=lambda *a: order.append(f"child-{a[-1]['execute']}")):
            argv = [a for a in argv if a != "protected-env-backup"] + ["own-node"]
            m.main(argv)
        self.assertEqual(order, ["status", "child-False", "status", "child-True"])

    def test_estimate_over_budget_blocks_deploy_before_any_child(self):
        output, argv = self.deploy_fixture()
        with self.assertRaisesRegex(m.GateError, "estimate exceeds"):
            self.run_deploy(argv, [self.report()], estimate_within=False)
        self.assertEqual(self.calls[3], [])

    def test_estimate_uses_live_rpc_with_margin_and_the_largest_bytecode(self):
        codes = {"Bridge": "0x" + "60" * 4, "GnarkGroth16Verifier": "0x60"}
        seen = []
        def fake(url, method, params):
            seen.append((url, method, params[0]["from"]))
            return hex({"0x" + "60" * 4: 36613401, "0x60": 100}[params[0]["data"]])
        budget = {"maxGasPerTransaction": "50000000"}
        with patch.object(m, "creation_bytecodes", return_value=codes), patch.object(m, "rpc", side_effect=fake):
            report = m.estimate_creation("sepolia", "endpoint", self.root, budget)
        self.assertEqual(report["estimates"], {"Bridge": 36613401, "GnarkGroth16Verifier": 100})
        self.assertEqual(report["required_with_margin"], 36613401 * 120 // 100)
        self.assertTrue(report["within_budget"])
        self.assertTrue(all(row == ("endpoint", "eth_estimateGas", m.SIGNER) for row in seen))
        for limit, within in (("43936080", False), ("43936081", True), ("12000000", False)):
            with patch.object(m, "creation_bytecodes", return_value=codes), patch.object(m, "rpc", side_effect=fake):
                self.assertEqual(m.estimate_creation("sepolia", "e", self.root,
                                                     {"maxGasPerTransaction": limit})["within_budget"], within, limit)

    def test_creation_bytecodes_cover_bridge_and_four_verifiers_and_refuse_constructor_arguments(self):
        root = self.root / "bundle/contracts/artifacts/hardhat"
        def artifact(path, code, inputs=()):
            self.write(path, json.dumps({"bytecode": code, "abi": [{"type": "constructor", "inputs": list(inputs)}]}))
        artifact(root / "src/Bridge.sol/Bridge.json", "0x6001")
        for name in sorted(m.VERIFIERS):
            artifact(root / name / "Verifier.json", "0x6002")
        codes = m.creation_bytecodes(self.root / "bundle")
        self.assertEqual(sorted(codes), ["Bridge", "DepositBatchVerifier", "GnarkGroth16Verifier",
                                         "RewardClaimVerifier", "WithdrawalClaimVerifier"])
        for bad, reason in (("0x", "unusable"), ("0x60__$abc$__60", "unusable")):
            artifact(root / "src/Bridge.sol/Bridge.json", bad)
            Path(root / "src/Bridge.sol/Bridge.json").chmod(0o600)
            with self.assertRaisesRegex(m.GateError, reason):
                m.creation_bytecodes(self.root / "bundle")
        artifact(root / "src/Bridge.sol/Bridge.json", "0x6001", [{"type": "address"}])
        with self.assertRaisesRegex(m.GateError, "constructor arguments"):
            m.creation_bytecodes(self.root / "bundle")

    def test_estimate_is_an_allowed_read_only_method(self):
        with patch.object(m.urllib.request, "build_opener", side_effect=RuntimeError("reached transport")):
            with self.assertRaises(RuntimeError):
                m.rpc("http://unused", "eth_estimateGas", [{"from": m.SIGNER, "data": "0x"}])

    def make_attempt(self, number, chains, bundle="approved", prepared=True):
        attempt = self.root / "root" / f"attempt-{number}"
        attempt.mkdir(parents=True, exist_ok=True)
        if prepared:
            m.write_json(attempt / "prepared.json", {"manifest_sha256": bundle})
        for network, state in chains.items():
            if state == "untouched":
                continue
            if state in ("partial", "attempted-only"):
                m.write_json(attempt / f"attempt-{network}.json", {})
                continue
            for name in (f"readback-{network}.json", f"deployments/{network}/deployed-contracts.json",
                         f"deployments/{network}/Bridge_Proxy.json"):
                (attempt / name).parent.mkdir(parents=True, exist_ok=True)
                m.write_json(attempt / name, {})
            if state == "completed":
                m.write_json(attempt / f"completed-{network}.json", {"manifest_sha256": bundle, "policy_sha256": "p" * 64})
            elif state == "marker-without-evidence":
                (attempt / f"readback-{network}.json").unlink()
                m.write_json(attempt / f"completed-{network}.json", {"manifest_sha256": bundle, "policy_sha256": "p" * 64})
        return attempt

    def attempts(self):
        (self.root / "root").chmod(0o700)
        with patch.object(m, "active_deploys", return_value=0):
            return m.attempts(SimpleNamespace(root=str(self.root / "root"), manifest_sha256="a" * 64))

    def test_attempts_report_completed_partial_and_untouched_per_network(self):
        self.make_attempt(1, {"sepolia": "completed", "bscTestnet": "partial", "baseSepolia": "untouched"}, bundle="a" * 64)
        self.make_attempt(2, {"sepolia": "marker-without-evidence"}, bundle="a" * 64)
        self.make_attempt(3, {}, bundle="b" * 64)
        report = self.attempts()
        rows = {row["number"]: row for row in report["attempts"]}
        self.assertEqual({k: v["state"] for k, v in rows[1]["networks"].items()},
                         {"sepolia": "completed", "bscTestnet": "partial", "baseSepolia": "untouched"})
        self.assertEqual(rows[1]["networks"]["sepolia"]["policy_sha256"], "p" * 64)
        self.assertEqual(rows[2]["networks"]["sepolia"]["state"], "partial")
        self.assertTrue(rows[1]["prepared_for_bundle"])
        self.assertFalse(rows[3]["prepared_for_bundle"])
        self.assertEqual(list(rows), [1, 2, 3])

    def test_attempts_without_root_is_empty_and_symlinked_attempt_is_refused(self):
        self.assertEqual(m.attempts(SimpleNamespace(root=str(self.root / "none"), manifest_sha256="a" * 64)),
                         {"attempts": [], "active_deploys": 0})
        (self.root / "root").mkdir(mode=0o700)
        (self.root / "root/attempt-1").symlink_to(self.root, target_is_directory=True)
        with patch.object(m, "active_deploys", return_value=0), self.assertRaises(m.GateError):
            m.attempts(SimpleNamespace(root=str(self.root / "root"), manifest_sha256="a" * 64))

    def test_active_deploys_counts_only_deploys_writing_under_the_root(self):
        proc = self.root / "proc"
        for pid, argv in (("11", ["python3", "/dev/stdin", "deploy", "--output", "/var/x/attempt-1"]),
                          ("12", ["python3", "/dev/stdin", "deploy", "--output", "/var/other/attempt-1"]),
                          ("13", ["python3", "/dev/stdin", "attempts", "--root", "/var/x"]),
                          ("15", ["/opt/node", "/opt/b/fresh_l1.cjs", "/opt/b/contracts", "/var/x/attempt-2", "sepolia"]),
                          ("16", ["/opt/node", "/opt/b/fresh_l1.cjs", "/opt/b/contracts", "/var/other/attempt-2", "sepolia"]),
                          ("self", ["python3"])):
            (proc / pid).mkdir(parents=True)
            (proc / pid / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (proc / "14").mkdir()
        with patch.object(m, "PROCESS_ROOT", proc):
            self.assertEqual(m.active_deploys(Path("/var/x")), 2)

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
