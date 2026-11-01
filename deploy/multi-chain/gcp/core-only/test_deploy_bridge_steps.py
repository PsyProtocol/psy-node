import copy
import hashlib
import json
from pathlib import Path
import re
import unittest
import unittest.mock

import deploy_bridge_steps as bridge
import deploy_prepare_steps as prepare
import fresh_l1
import release_lock
import test_fresh_l1
from deploy_remote import RemoteError, find_secret
from test_deploy_prepare_steps import CHAINS, PrepareTestCase, sha

HOST = "gcp-test-services"
RELAYER_HOST = "gcp-test-relayer"
GUARDIAN_HOSTS = {"guardian-test-1": 1, "guardian-test-2": 2, "guardian-test-3": 3}
CHAIN_IDS = {"sepolia": 11155111, "bscTestnet": 97, "baseSepolia": 84532}
BUDGET = {"maxGasPriceWei": "10", "maxGasPerTransaction": "500", "maxTotalGas": "1000", "maxNativeSpendWei": "5000",
          "l1FeeReserveWeiPerTransaction": "1"}


def address(seed):
    return "0x" + f"{seed:040x}"


def chain_documents(chain, signer, policy):
    index = fresh_l1.NETWORKS[chain][1]
    bridge_address, manager = address(100 + index), address(200 + index)
    summary = {"network": chain, "chainId": str(CHAIN_IDS[chain]), "core": {"Bridge": bridge_address, "StateManager": manager},
               "protocol": {"chain": {"l1ChainIndex": index}}}
    receipt = {"address": bridge_address, "transactionHash": "0x" + f"{index + 1:064x}",
               "receipt": {"status": 1, "blockNumber": 1000 + index}}
    readback = {"signer": signer, "proposer": True, "bridge_admin": True, "l1_acl_guardian": False,
                "deposits_paused": True, "withdrawal_registration_paused": False, "pending_claims_paused": False,
                "deposit_mapping": {"block_number": 5, "native_allowed": False, "tokens": {
                    "PSY": {"l1_address": address(300 + index), "l2_contract_id": bridge.HASH_ZERO},
                    "pUSDT": {"l1_address": address(400 + index), "l2_contract_id": bridge.PUSDT_L2_ID}}},
                "tokens": {name: {"address": address(500), "config": policy["networks"][chain][name], "global_flags": 1,
                                  "token_flags": 0, "effective_flags": 1} for name in ("native", "PSY", "pUSDT")}}
    readback["verifiers"] = {name: {"address": address(600 + 10 * index + number), "code_sha256": f"{number:064x}",
                                    "artifact": "src/X.sol:Verifier"} for number, name in enumerate(bridge.VERIFIER_NAMES)}
    return summary, receipt, readback


class FakeRemote:
    """A signer host with one output root, plus the three Guardian hosts and the Relayer host."""

    def __init__(self, ws, policy):
        self.ws, self.policy = ws, policy
        self.calls, self.files, self.units, self.copies = [], {}, {}, []
        self.bundle_present = True
        self.attempts = []
        self.active = 0
        self.status_nonces = {chain: (5, 5) for chain in CHAINS}
        self.estimate_within = {chain: True for chain in CHAINS}
        self.env_counts = {name: 1 for name in (bridge.WALLET_NAME, *bridge.FALLBACK_NAMES)}
        self.env_mode = "root 640"
        self.node_version = "v22.23.4"
        self.fail_deploy = {}
        self.checkpoints = []
        self.activation_error = None
        self.readiness_failures = 0

    def sudo_mode(self, host):
        return "passwordless"

    def missing_aliases(self, aliases):
        return []

    def tool_calls(self, name):
        return [call for call in self.calls if call[0] == "tool" and call[2] == name]

    def deploy_networks(self):
        return [call[3]["--network"] for call in self.tool_calls("deploy")]

    def option(self, argv, name):
        return argv[argv.index(name) + 1] if name in argv else None

    def run_root_text(self, host, argv, timeout_seconds, *, stdin_text=None, show_stderr=False):
        if argv[:4] == [bridge.PYTHON, "-I", "-B", "/dev/stdin"]:
            return self.tool(host, argv[4], argv[5:], stdin_text)
        if argv[0].endswith("/activate_bridge.py") or (len(argv) > 3 and argv[3].endswith("/activate_bridge.py")):
            return self.activation(host, argv)
        if len(argv) > 3 and argv[3].endswith(("/install_guardian.py", "/install_relayer.py")):
            self.calls.append(("install", host, argv[3].rsplit("/", 1)[1], argv[4], "--apply" in argv))
            return json.dumps({"mode": argv[4]})
        if argv[0] == "/usr/bin/cat":
            self.calls.append(("cat", host, argv[-1]))
            return self.files[argv[-1]].decode()
        if argv[0] == "/usr/bin/sha256sum":
            return f"{hashlib.sha256(self.files[argv[-1]]).hexdigest()}  {argv[-1]}\n"
        if argv[0] == "/usr/bin/bash":
            return self.script(host, stdin_text)
        raise AssertionError(f"unexpected root command: {argv}")

    def script(self, host, text):
        self.calls.append(("root-script", host, text))
        if "grep -c" in text:
            lines = []
            for path, names in ((fresh_l1.WALLET_ENV, (bridge.WALLET_NAME,)), (fresh_l1.FALLBACK_ENV, bridge.FALLBACK_NAMES)):
                lines.append(f"file {path} {self.env_mode}")
                lines += [f"name {path} {name} {self.env_counts[name]}" for name in names]
            return "\n".join(lines) + "\n"
        if "--version" in text:
            return self.node_version + "\n"
        return ""

    def tool(self, host, name, argv, source):
        options = {argv[i]: argv[i + 1] for i in range(0, len(argv) - 1) if argv[i].startswith("--")}
        self.calls.append(("tool", host, name, options, argv))
        if name == "status":
            return json.dumps([{"network": chain, "provider": "protected-env-backup", "chain_id": CHAIN_IDS[chain], "block": 9,
                                "block_age_seconds": 2, "balance_wei": "100000", "gas_price_wei": "1",
                                "signer": self.ws.lock["l1"]["signer"], "nonce_latest": self.status_nonces[chain][0],
                                "nonce_pending": self.status_nonces[chain][1]} for chain in CHAINS])
        if name == "check":
            return json.dumps({"verified": True, "broadcast": False})
        if name == "attempts":
            return json.dumps({"attempts": copy.deepcopy(self.attempts), "active_deploys": self.active})
        if name == "estimate":
            chain = options["--network"]
            return json.dumps({"network": chain, "required_with_margin": 400 if self.estimate_within[chain] else 600,
                               "max_gas_per_transaction": 500, "within_budget": self.estimate_within[chain]})
        if name == "prepare":
            number = int(options["--output"].rsplit("-", 1)[1])
            self.attempts.append(self.new_row(number))
            return json.dumps({"verified": True, "broadcast": False})
        if name == "deploy":
            return self.deploy(options)
        raise AssertionError(name)

    def new_row(self, number, states=None, prepared=True):
        states = states or {}
        return {"number": number, "path": f"/x/attempt-{number}", "prepared_for_bundle": prepared,
                "networks": {chain: {"state": states.get(chain, "untouched"),
                                     "policy_sha256": self.ws.lock["l1"]["policy_sha256"] if states.get(chain) == "completed" else None}
                             for chain in CHAINS}}

    def deploy(self, options):
        number = int(options["--output"].rsplit("-", 1)[1])
        chain = options["--network"]
        row = next(row for row in self.attempts if row["number"] == number)
        if chain in self.fail_deploy:
            row["networks"][chain] = {"state": "partial", "policy_sha256": None}
            raise self.fail_deploy[chain]
        row["networks"][chain] = {"state": "completed", "policy_sha256": self.ws.lock["l1"]["policy_sha256"]}
        root = options["--output"]
        summary, receipt, readback = chain_documents(chain, self.ws.lock["l1"]["signer"], self.policy)
        for path, value in ((f"{root}/deployments/{chain}/deployed-contracts.json", summary),
                            (f"{root}/deployments/{chain}/Bridge_Proxy.json", receipt), (f"{root}/readback-{chain}.json", readback)):
            self.files[path] = (json.dumps(value, indent=2) + "\n").encode()
        return json.dumps({"network": chain, "completed": True})

    def run_script(self, host, script, timeout_seconds):
        self.calls.append(("script", host, script))
        if script.startswith("test -e"):
            return "present\n" if self.bundle_present else "absent\n"
        match = re.search(r"systemctl show (\S+) ", script)
        if match:
            state = self.units.get(match.group(1), {"LoadState": "not-found"})
            return "".join(f"{key}={value}\n" for key, value in state.items())
        if "PSY_CHECKPOINT_END" in script:
            values = self.checkpoints.pop(0) if len(self.checkpoints) > 1 else self.checkpoints[0]
            return json.dumps(values) + "\n"
        return ""

    def copy_files(self, host, sources, destination, *, timeout_seconds=600):
        self.calls.append(("copy", host, [Path(source).name for source in sources], destination))
        self.copies.append((host, [Path(source) for source in sources], destination))

    def activation(self, host, argv):
        role = argv[argv.index("--role") + 1]
        self.calls.append(("activate", host, role, "--apply" in argv))
        if role == "relayer" and self.activation_error:
            raise self.activation_error
        if role == "guardian-readiness":
            if self.readiness_failures:
                self.readiness_failures -= 1
                raise RemoteError(f"{host}: exit 1: Bridge activation failed: connection refused", host=host)
            return json.dumps({"role": role, "guardians_ready": 3})
        return json.dumps({"role": role, "started": True})


def running_unit():
    return {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled", "MainPID": "42", "NRestarts": "0"}


class BridgeTestCase(PrepareTestCase):
    def setUp(self):
        super().setUp()
        ws = self.ws
        lock = ws.lock
        lock["l1"]["signer"] = fresh_l1.SIGNER
        lock["l1"]["signer_host"] = HOST
        lock["hosts"].update({HOST: "10.0.0.50", RELAYER_HOST: "10.0.0.51"})
        lock["sources"]["contracts"] = "5" * 40
        self.policy = test_fresh_l1.policy()
        bundle = ws.root / "bundle"
        bundle.mkdir()
        for tool in ("fresh_l1.py", "fresh_l1.cjs"):
            (bundle / tool).write_bytes((ws.tools_dir / tool).read_bytes())
        (bundle / "manifest.json").write_text("{}\n")
        ws.put_file("l1_policy", (json.dumps(self.policy) + "\n").encode(), pin=lambda h: lock["l1"].update(policy_sha256=h))
        ws.local["files"]["l1_bundle_manifest"] = str(bundle / "manifest.json")
        lock["l1"]["bundle_sha256"] = sha("bundle manifest")
        for chain in CHAINS:
            path = ws.release_dir / f"fresh_l1_gas_budget.{chain}.json"
            path.write_text(json.dumps(BUDGET))
            lock["l1"]["gas_budget_sha256"][chain] = sha(path.read_bytes())
        ws.write_local()
        patcher = unittest.mock.patch.object(bridge.fresh_l1, "verify_bundle")
        self.verify_bundle = patcher.start()
        self.addCleanup(patcher.stop)
        self.remote = FakeRemote(ws, self.policy)
        sleeper = unittest.mock.patch("deploy_remote.time.sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def ctx(self):
        return self.ws.context(self.remote)

    def run_step(self, name="deploy_l1"):
        step, ctx = bridge.BRIDGE_STEPS[name], self.ctx()
        step.check(ctx)
        step.apply(ctx)
        return step.verify(ctx)


class DeployL1Tests(BridgeTestCase):
    def test_steps_are_registered_as_cutover_steps(self):
        self.assertEqual(sorted(bridge.BRIDGE_STEPS), ["deploy_l1", "start_guardians", "start_relayer"])
        self.assertTrue(all(step.cutover and step.requires_complete for step in bridge.BRIDGE_STEPS.values()))

    def test_deploy_order_is_sepolia_bsc_base(self):
        result = self.run_step()
        self.assertEqual(self.remote.deploy_networks(), ["sepolia", "bscTestnet", "baseSepolia"])
        self.assertEqual(list(bridge.CHAIN_ORDER), ["sepolia", "bscTestnet", "baseSepolia"])
        self.assertEqual([call[3]["--output"] for call in self.remote.tool_calls("prepare")],
                         ["/var/lib/psy-fresh-test/attempt-1"])
        self.assertEqual(result["attempt"], 1)
        self.assertIsNone(find_secret(result))

    def test_deploy_commands_use_the_protected_route_and_hashes_from_the_lock(self):
        self.run_step()
        for call in self.remote.tool_calls("deploy"):
            options, argv = call[3], call[4]
            self.assertEqual(options["--rpc-preference"], "protected-env-backup")
            self.assertEqual([argv[i + 1] for i, word in enumerate(argv) if word == "--secret-env"],
                             [fresh_l1.WALLET_ENV, fresh_l1.FALLBACK_ENV])
            self.assertEqual(options["--manifest-sha256"], self.ws.lock["l1"]["bundle_sha256"])
            self.assertEqual(options["--contracts-commit"], self.ws.lock["sources"]["contracts"])
            self.assertEqual(options["--policy-sha256"], self.ws.lock["l1"]["policy_sha256"])
            self.assertEqual(options["--gas-budget-sha256"], self.ws.lock["l1"]["gas_budget_sha256"][options["--network"]])
            self.assertEqual(options["--node"], bridge.NODE_PATH)
            self.assertIn("--execute", argv)
            self.assertNotIn("protected-env", argv)
            self.assertFalse(any("http" in word for word in argv))

    def put_completed_documents(self, chain, number=1):
        summary, receipt, readback = chain_documents(chain, fresh_l1.SIGNER, self.policy)
        root = f"/var/lib/psy-fresh-test/attempt-{number}"
        for path, value in ((f"{root}/deployments/{chain}/deployed-contracts.json", summary),
                            (f"{root}/deployments/{chain}/Bridge_Proxy.json", receipt), (f"{root}/readback-{chain}.json", readback)):
            self.remote.files[path] = (json.dumps(value, indent=2) + "\n").encode()

    def test_completed_chain_is_verified_not_redeployed(self):
        self.remote.attempts = [self.remote.new_row(1, {"sepolia": "completed"})]
        self.put_completed_documents("sepolia")
        self.run_step()
        self.assertEqual(self.remote.deploy_networks(), ["bscTestnet", "baseSepolia"])
        self.assertEqual(self.remote.tool_calls("prepare"), [])

    def test_resume_from_69_after_full_completion_never_broadcasts(self):
        self.run_step()
        first = (self.ws.state_dir / "deploy_l1.json").read_bytes()
        broadcasts = len(self.remote.tool_calls("deploy"))
        result = self.run_step()
        self.assertEqual(len(self.remote.tool_calls("deploy")), broadcasts)
        self.assertEqual(len(self.remote.tool_calls("prepare")), 1)
        self.assertEqual((self.ws.state_dir / "deploy_l1.json").read_bytes(), first)
        self.assertEqual(result["attempt"], 1)

    def test_partial_attempt_is_refused_without_new_attempt(self):
        self.remote.attempts = [self.remote.new_row(1, {"sepolia": "completed", "bscTestnet": "partial"})]
        with self.assertRaises(bridge.AttemptBlocked) as error:
            self.run_step()
        message = str(error.exception)
        self.assertIn("attempt 1", message)
        self.assertIn("fresh_l1.py prepare", message)
        self.assertIn("/var/lib/psy-fresh-test/attempt-2", message)
        self.assertIn("--from 69", message)
        self.assertEqual(self.remote.deploy_networks(), [])
        self.assertEqual(self.remote.tool_calls("prepare"), [])
        self.assertNotRegex(message, r"(?i)secret|passw|token|credential")

    def test_a_hand_made_next_attempt_is_used_and_old_evidence_is_kept(self):
        self.remote.attempts = [self.remote.new_row(1, {"bscTestnet": "partial"}), self.remote.new_row(2)]
        result = self.run_step()
        self.assertEqual(self.remote.deploy_networks(), ["sepolia", "bscTestnet", "baseSepolia"])
        self.assertTrue(all(call[3]["--output"].endswith("attempt-2") for call in self.remote.tool_calls("deploy")))
        self.assertEqual(result["attempt"], 2)
        self.assertEqual([row["number"] for row in self.remote.attempts], [1, 2])

    def test_attempts_of_another_bundle_and_running_deploys_block(self):
        self.remote.attempts = [self.remote.new_row(1, prepared=False)]
        with self.assertRaisesRegex(bridge.AttemptBlocked, "another bundle"):
            self.run_step()
        self.remote.attempts = []
        self.remote.active = 1
        with self.assertRaisesRegex(bridge.AttemptBlocked, "still running"):
            self.run_step()
        self.assertEqual(self.remote.deploy_networks(), [])

    def test_chain_completed_out_of_order_or_with_another_policy_blocks(self):
        self.remote.attempts = [self.remote.new_row(1, {"baseSepolia": "completed"})]
        with self.assertRaisesRegex(bridge.AttemptBlocked, "out of order"):
            self.run_step()
        row = self.remote.new_row(1, {"sepolia": "completed"})
        row["networks"]["sepolia"]["policy_sha256"] = "f" * 64
        self.remote.attempts = [row]
        with self.assertRaisesRegex(bridge.AttemptBlocked, "partial or foreign"):
            self.run_step()

    def test_failed_deploy_leaves_a_partial_attempt_and_names_the_next_command(self):
        self.remote.fail_deploy["bscTestnet"] = RemoteError("gcp-test-services: exit 1: L1 helper failed at stage bridge", host=HOST)
        with self.assertRaisesRegex(RuntimeError, "attempt 1 is now partial.*prepare.*attempt-2"):
            self.run_step()
        self.assertEqual(self.remote.deploy_networks(), ["sepolia", "bscTestnet"])
        with self.assertRaises(bridge.AttemptBlocked):
            self.run_step()
        self.assertEqual(self.remote.deploy_networks(), ["sepolia", "bscTestnet"])

    def test_a_lost_connection_is_reported_as_running_untouched_or_partial(self):
        lost = RemoteError("gcp-test-services: ssh dropped", host=HOST)
        original = self.remote.deploy
        def drop(options, state, running):
            chain = options["--network"]
            row = next(r for r in self.remote.attempts if r["number"] == 1)
            row["networks"][chain] = {"state": state, "policy_sha256": None}
            self.remote.active = running
            raise lost
        cases = (("partial", 1, "still running.*wait|Wait for it.*--from 69; do not create a new attempt"),
                 ("untouched", 0, "nothing was written for sepolia in attempt 1.*--from 69 is safe"),
                 ("partial", 0, "attempt 1 is now partial.*prepare.*attempt-2"))
        for state, running, pattern in cases:
            self.remote.attempts, self.remote.active = [self.remote.new_row(1)], 0
            self.remote.deploy = lambda options, state=state, running=running: drop(options, state, running)
            with self.subTest(state=state, running=running), self.assertRaisesRegex(RuntimeError, pattern):
                bridge.deploy_apply(self.ctx())
        self.remote.deploy = original

    def test_nonce_mismatch_blocks_deploy(self):
        self.remote.status_nonces["bscTestnet"] = (5, 6)
        with self.assertRaisesRegex(ValueError, "bscTestnet: pending nonce 6 differs from latest 5"):
            self.run_step()
        self.assertEqual(self.remote.deploy_networks(), [])

    def test_estimate_over_budget_blocks_before_any_broadcast(self):
        self.remote.estimate_within["sepolia"] = False
        with self.assertRaisesRegex(ValueError, "sepolia: creation gas estimate 600 exceeds the per-transaction budget 500"):
            self.run_step()
        self.assertEqual(self.remote.deploy_networks(), [])
        estimates = self.remote.tool_calls("estimate")
        self.assertEqual({call[3]["--rpc-preference"] for call in estimates}, {"protected-env-backup"})
        self.assertEqual(sorted(call[3]["--network"] for call in estimates), sorted(CHAINS))

    def test_live_gates_cover_only_the_chains_that_are_still_to_deploy(self):
        self.remote.attempts = [self.remote.new_row(1, {"sepolia": "completed"})]
        self.remote.status_nonces["sepolia"] = (5, 9)
        self.remote.estimate_within["sepolia"] = False
        self.put_completed_documents("sepolia")
        self.run_step()
        self.assertEqual(sorted(call[3]["--network"] for call in self.remote.tool_calls("estimate")), ["baseSepolia", "bscTestnet"])

    def test_gas_budget_required_for_each_network(self):
        for chain in CHAINS:
            with self.subTest(chain=chain):
                saved = self.ws.lock["l1"]["gas_budget_sha256"][chain]
                self.ws.lock["l1"]["gas_budget_sha256"][chain] = ""
                with self.assertRaisesRegex(ValueError, f"gas budget {chain} is not pinned"):
                    bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())
                self.ws.lock["l1"]["gas_budget_sha256"][chain] = saved
                (self.ws.release_dir / f"fresh_l1_gas_budget.{chain}.json").write_text("{}\n")
                with self.assertRaises(ValueError):
                    bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())
                (self.ws.release_dir / f"fresh_l1_gas_budget.{chain}.json").write_text(json.dumps(BUDGET))
        self.assertEqual(self.remote.deploy_networks(), [])

    def test_bundle_is_checked_against_the_contracts_commit_of_the_lock(self):
        bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())
        self.verify_bundle.assert_called_with(self.ws.root / "bundle", self.ws.lock["l1"]["bundle_sha256"],
                                              self.ws.lock["sources"]["contracts"])
        self.verify_bundle.side_effect = fresh_l1.GateError("bundle identity mismatch")
        with self.assertRaisesRegex(fresh_l1.GateError, "bundle identity mismatch"):
            bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())
        self.verify_bundle.side_effect = None
        self.ws.lock["sources"]["contracts"] = ""
        with self.assertRaisesRegex(ValueError, "sources.contracts is not pinned"):
            bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())

    def test_tools_in_the_bundle_must_be_the_tools_of_the_lock(self):
        (self.ws.root / "bundle" / "fresh_l1.cjs").write_text("// edited\n")
        with self.assertRaisesRegex(ValueError, "bundle copy of fresh_l1.cjs differs from the lock"):
            bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())
        (self.ws.tools_dir / "fresh_l1.py").write_text("# edited\n")
        with self.assertRaisesRegex(ValueError, "tool hash differs: fresh_l1.py"):
            bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())

    def test_signer_env_is_probed_by_name_and_mode_only(self):
        self.run_step()
        scripts = [call[2] for call in self.remote.calls if call[0] == "root-script" and "grep -c" in call[2]]
        self.assertTrue(scripts)
        for path in (fresh_l1.WALLET_ENV, fresh_l1.FALLBACK_ENV):
            self.assertFalse(any(call[0] == "cat" and call[2] == path for call in self.remote.calls))
        self.assertNotIn("cut -d", scripts[0])
        self.remote.env_counts["BSC_TESTNET_RPC_FALLBACK_URL"] = 0
        with self.assertRaisesRegex(ValueError, "lacks exactly one entry for: BSC_TESTNET_RPC_FALLBACK_URL"):
            bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())
        self.remote.env_counts["BSC_TESTNET_RPC_FALLBACK_URL"] = 1
        self.remote.env_counts[bridge.WALLET_NAME] = 0
        with self.assertRaisesRegex(ValueError, "lacks exactly one entry for: wallet entry"):
            bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())
        self.remote.env_counts[bridge.WALLET_NAME] = 1
        for mode in ("ubuntu 640", "root 660", "root 604"):
            self.remote.env_mode = mode
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "root-owned and not group-writable"):
                bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())

    def test_node_version_is_required_on_the_signer_host(self):
        for version in ("v16.20.0", "node", ""):
            self.remote.node_version = version
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "Node 18\\+ required"):
                bridge.BRIDGE_STEPS["deploy_l1"].check(self.ctx())

    def test_absent_bundle_is_uploaded_verified_and_only_then_published(self):
        self.remote.bundle_present = False
        with unittest.mock.patch.object(bridge, "pack_bundle", side_effect=lambda source, target: Path(target).write_bytes(b"tar")) as pack:
            self.run_step()
        pack.assert_called_once()
        sequence = [call for call in self.remote.calls if call[0] in ("copy", "root-script", "tool")]
        kinds = []
        for call in sequence:
            text = call[2] if call[0] == "root-script" else ""
            if call[0] == "copy" and call[3] == bridge.STAGE_ROOT + "/":
                kinds.append("upload")
            elif "tar -xzf" in text:
                kinds.append("extract")
            elif call[0] == "tool" and call[2] == "check" and call[3]["--bundle"].endswith(".partial"):
                kinds.append("check-partial")
            elif "mv -T" in text:
                kinds.append("publish")
        self.assertEqual(kinds, ["upload", "extract", "check-partial", "publish"])

    def test_present_bundle_is_verified_in_place_and_never_uploaded(self):
        self.run_step()
        self.assertFalse(any(call[0] == "copy" and call[3] == bridge.STAGE_ROOT + "/" for call in self.remote.calls))
        checks = self.remote.tool_calls("check")
        self.assertTrue(checks and all(call[3]["--bundle"] == bridge.bundle_dir(self.ctx()) for call in checks))

    def test_failed_partial_check_removes_the_partial_directory(self):
        self.remote.bundle_present = False
        original = self.remote.tool
        def refuse(host, name, argv, source):
            if name == "check" and "--bundle" in argv and argv[argv.index("--bundle") + 1].endswith(".partial"):
                return json.dumps({"verified": False})
            return original(host, name, argv, source)
        self.remote.tool = refuse
        with unittest.mock.patch.object(bridge, "pack_bundle", side_effect=lambda s, t: Path(t).write_bytes(b"x")):
            with self.assertRaisesRegex(ValueError, "did not verify"):
                self.run_step()
        scripts = [call[2] for call in self.remote.calls if call[0] == "root-script"]
        self.assertTrue(any("rm -rf" in text and ".partial" in text and "mv -T" not in text for text in scripts[-1:]))
        self.assertFalse(any("mv -T" in text for text in scripts))

    def test_tarball_is_root_owned_without_group_or_other_write(self):
        import tarfile
        source = self.ws.root / "tree"
        (source / "a").mkdir(parents=True)
        (source / "a" / "file").write_text("x")
        (source / "a" / "file").chmod(0o664)
        (source / "a" / "link").symlink_to("file")
        target = self.ws.root / "bundle.tar.gz"
        bridge.pack_bundle(source, target)
        with tarfile.open(target) as archive:
            members = {member.name: member for member in archive.getmembers()}
        self.assertTrue(all(member.uid == 0 and member.gid == 0 and not member.mode & 0o022 for member in members.values()))
        self.assertTrue(members["./a/link"].issym())

    def test_documents_are_recorded_for_step_70_with_hashes_and_addresses(self):
        self.run_step()
        document = release_lock.read_document(self.ws.state_dir / "deploy_l1.json")
        self.assertEqual(set(document), {"schema_version", "lock_sha256", "release_id", "attempt", "output_dir", "signer_host",
                                         "bundle_sha256", "policy_sha256", "contracts_commit", "chains"})
        self.assertEqual(document["lock_sha256"], self.ctx().lock_sha256)
        self.assertEqual(sorted(document["chains"]), sorted(CHAINS))
        for chain, row in document["chains"].items():
            self.assertEqual(set(row), {"summary", "receipt", "readback", "chain_id", "bridge", "state_manager", "block_number",
                                        "deployment_tx"})
            for name in ("summary", "receipt", "readback"):
                path = Path(row[name]["path"])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row[name]["sha256"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(Path(row["summary"]["path"]).name, "deployed-contracts.json")
            self.assertEqual(Path(row["receipt"]["path"]).name, "Bridge_Proxy.json")
        self.assertEqual((self.ws.state_dir / "deploy_l1.json").stat().st_mode & 0o777, 0o600)

    def test_conflicting_local_document_is_never_overwritten(self):
        self.run_step()
        victim = Path(release_lock.read_document(self.ws.state_dir / "deploy_l1.json")["chains"]["sepolia"]["summary"]["path"])
        victim.chmod(0o600)
        victim.write_text("tampered")
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            bridge.BRIDGE_STEPS["deploy_l1"].apply(self.ctx())
        self.assertEqual(victim.read_text(), "tampered")

    def test_download_must_equal_the_host_copy(self):
        self.run_step()
        original = self.remote.run_root_text
        def lossy(host, argv, timeout, **kwargs):
            if argv[0] == "/usr/bin/sha256sum":
                return "0" * 64 + "  file\n"
            return original(host, argv, timeout, **kwargs)
        self.remote.run_root_text = lossy
        with self.assertRaisesRegex(ValueError, "differs from the host copy"):
            bridge.BRIDGE_STEPS["deploy_l1"].apply(self.ctx())

    def test_readback_requires_paused_proposer_admin_and_router_pairs(self):
        signer = fresh_l1.SIGNER
        _, _, good = chain_documents("sepolia", signer, self.policy)
        bridge.validate_readback(good, "sepolia", self.policy, signer)
        mutations = {
            "unpaused": lambda r: r.update(deposits_paused=False),
            "registration paused": lambda r: r.update(withdrawal_registration_paused=True),
            "claims paused": lambda r: r.update(pending_claims_paused=True),
            "not proposer": lambda r: r.update(proposer=False),
            "not admin": lambda r: r.update(bridge_admin=False),
            "other signer": lambda r: r.update(signer="0x" + "1" * 40),
            "native allowed": lambda r: r["deposit_mapping"].update(native_allowed=True),
            "missing pair": lambda r: r["deposit_mapping"]["tokens"].pop("pUSDT"),
            "wrong psy id": lambda r: r["deposit_mapping"]["tokens"]["PSY"].update(l2_contract_id="0x" + "0" * 63 + "1"),
            "wrong pusdt id": lambda r: r["deposit_mapping"]["tokens"]["pUSDT"].update(l2_contract_id=bridge.HASH_ZERO),
            "colliding l1": lambda r: r["deposit_mapping"]["tokens"]["PSY"].update(
                l1_address=r["deposit_mapping"]["tokens"]["pUSDT"]["l1_address"]),
            "token not paused": lambda r: r["tokens"]["PSY"].update(effective_flags=0),
            "other limits": lambda r: r["tokens"]["pUSDT"]["config"].update(depositCap="1"),
            "extra field": lambda r: r.update(extra=True),
            "no verifier evidence": lambda r: r.pop("verifiers"),
            "missing verifier": lambda r: r["verifiers"].pop("RewardClaimVerifier"),
            "bad code hash": lambda r: r["verifiers"]["ZKVerifier"].update(code_sha256="xyz"),
            "verifier address collision": lambda r: r["verifiers"]["ZKVerifier"].update(
                address=r["verifiers"]["RewardClaimVerifier"]["address"]),
        }
        for label, mutate in mutations.items():
            broken = copy.deepcopy(good)
            mutate(broken)
            with self.subTest(label), self.assertRaises(ValueError):
                bridge.validate_readback(broken, "sepolia", self.policy, signer)

    def test_receipt_and_identity_must_match_the_chain(self):
        summary, receipt, _ = chain_documents("bscTestnet", fresh_l1.SIGNER, self.policy)
        bridge.validate_documents("bscTestnet", summary, receipt)
        for label, mutate in {"chain id": lambda s, r: s.update(chainId="1"),
                              "network": lambda s, r: s.update(network="sepolia"),
                              "index": lambda s, r: s["protocol"]["chain"].update(l1ChainIndex=0),
                              "receipt address": lambda s, r: r.update(address=address(7)),
                              "failed": lambda s, r: r["receipt"].update(status=0),
                              "no block": lambda s, r: r["receipt"].update(blockNumber=0),
                              "hash": lambda s, r: r.update(transactionHash="0x12")}.items():
            s, r = copy.deepcopy(summary), copy.deepcopy(receipt)
            mutate(s, r)
            with self.subTest(label), self.assertRaises(ValueError):
                bridge.validate_documents("bscTestnet", s, r)

    def test_verify_requires_the_recorded_lock_and_unchanged_documents(self):
        self.run_step()
        ctx = self.ctx()
        path = self.ws.state_dir / "deploy_l1.json"
        document = json.loads(path.read_text())
        path.write_text(json.dumps({**document, "lock_sha256": "f" * 64}))
        with self.assertRaisesRegex(ValueError, "another release lock"):
            bridge.BRIDGE_STEPS["deploy_l1"].verify(ctx)
        path.write_text(json.dumps(document))
        Path(document["chains"]["baseSepolia"]["readback"]["path"]).write_text("changed")
        with self.assertRaisesRegex(ValueError, "baseSepolia: recorded readback document changed"):
            bridge.BRIDGE_STEPS["deploy_l1"].verify(ctx)

    def test_verify_rereads_the_host_and_never_trusts_the_state_file_alone(self):
        self.run_step()
        self.remote.attempts[0]["networks"]["bscTestnet"]["state"] = "partial"
        with self.assertRaisesRegex(ValueError, "bscTestnet: not completed in attempt 1"):
            bridge.BRIDGE_STEPS["deploy_l1"].verify(self.ctx())


def build_package(ws, name, role, host, tools, *, guardian_id=None, documents_hash=None, spec_extra=b""):
    root = ws.root / "bridge-packages" / role / host
    root.mkdir(parents=True, exist_ok=True)
    files = {}
    for tool in tools:
        (root / tool).write_bytes((ws.tools_dir / tool).read_bytes())
        files[tool] = sha((root / tool).read_bytes())
    for filename, content in (("spec.json", b'{"spec": true}\n' + spec_extra), ("rpc.json", b'{"rpc": true}\n')):
        (root / filename).write_bytes(content)
        files[filename] = sha(content)
    document = {"role": role, "host": host, "spec": "spec.json", "spec_sha256": files["spec.json"],
                "stage_dir": f"/var/tmp/psy-bridge-{name}", "rpc_config": "rpc.json", "files": files}
    if guardian_id:
        document["guardian_id"] = guardian_id
    (root / "package.json").write_text(json.dumps(document))
    return root


class PackageTestCase(BridgeTestCase):
    def setUp(self):
        super().setUp()
        self.remote.attempts = []
        self.run_step()
        self.documents_sha = prepare.file_sha256(self.ws.state_dir / "deploy_l1.json")
        self.write_packages()

    def write_packages(self, **options):
        ws = self.ws
        guardians = {host: str(build_package(ws, f"guardian-{i}", "guardian", host, bridge.GUARDIAN_TOOLS, guardian_id=i))
                     for host, i in GUARDIAN_HOSTS.items()}
        relayer = {RELAYER_HOST: str(build_package(ws, "relayer", "relayer", RELAYER_HOST, bridge.RELAYER_TOOLS))}
        prepare.write_state(ws.context(None), "prepare_bridge_packages",
                            {"lock_sha256": self.ctx().lock_sha256, "l1_documents_sha256": options.get("documents", self.documents_sha),
                             "guardian": guardians, "relayer": relayer})

    def commands(self, kind):
        return [call for call in self.remote.calls if call[0] == kind]

    def unit(self, index):
        return f"{self.ws.lock['units']['guardian_prefix']}{index}.service"


class GuardianStepTests(PackageTestCase):
    def test_guardians_are_installed_then_activated_in_id_order_and_readiness_comes_from_the_relayer_host(self):
        self.remote.calls.clear()
        bridge.BRIDGE_STEPS["start_guardians"].check(self.ctx())
        bridge.BRIDGE_STEPS["start_guardians"].apply(self.ctx())
        hosts = [call[1] for call in self.remote.calls if call[0] == "install" and call[3] == "install"]
        self.assertEqual(hosts, ["guardian-test-1", "guardian-test-2", "guardian-test-3"])
        for host in GUARDIAN_HOSTS:
            order = [(call[0], call[3] if call[0] == "install" else call[2]) for call in self.remote.calls
                     if call[0] in ("install", "activate") and call[1] == host]
            self.assertEqual(order, [("install", "check-host"), ("install", "install"), ("activate", "guardian")])
        readiness = [call for call in self.commands("activate") if call[2] == "guardian-readiness"]
        self.assertEqual([call[1] for call in readiness], [RELAYER_HOST])
        self.assertTrue(self.remote.calls.index(readiness[0]) > max(i for i, call in enumerate(self.remote.calls)
                                                                    if call[0] == "activate" and call[2] == "guardian"))

    def test_guardian_readiness_is_polled_every_30_seconds_up_to_300_seconds(self):
        self.assertEqual((bridge.POLL_SECONDS, bridge.READY_SECONDS), (30, 300))
        self.remote.readiness_failures = 2
        bridge.BRIDGE_STEPS["start_guardians"].apply(self.ctx())
        readiness = [call for call in self.commands("activate") if call[2] == "guardian-readiness"]
        self.assertEqual(len(readiness), 3)
        scripts = [call[2] for call in self.remote.calls if call[0] == "root-script" and call[1] == RELAYER_HOST]
        self.assertTrue(scripts and scripts[-1].endswith("psy-guardian-readiness-" + self.ws.lock["release_id"] + "\n"))

    def test_guardian_readiness_that_never_comes_times_out_and_removes_the_stage(self):
        self.remote.readiness_failures = 10 ** 6
        with unittest.mock.patch.object(bridge, "READY_SECONDS", 0), self.assertRaisesRegex(TimeoutError, "Guardian readiness"):
            bridge.BRIDGE_STEPS["start_guardians"].apply(self.ctx())
        scripts = [call[2] for call in self.remote.calls if call[0] == "root-script" and call[1] == RELAYER_HOST]
        self.assertIn("rm -rf", scripts[-1])

    def test_stage_is_removed_as_root_before_it_is_recreated(self):
        self.remote.calls.clear()
        bridge.BRIDGE_STEPS["start_guardians"].apply(self.ctx())
        for host in GUARDIAN_HOSTS:
            kinds = [call[0] + ":" + ("rm" if "rm -rf" in call[2] else "mkdir" if "mkdir" in call[2] else "other")
                     for call in self.remote.calls if call[0] in ("root-script", "script") and call[1] == host
                     and ("rm -rf" in call[2] or "mkdir" in call[2])]
            self.assertEqual(kinds[:2], ["root-script:rm", "script:mkdir"])
            self.assertNotIn("rm -rf", "".join(call[2] for call in self.remote.calls if call[0] == "script"))

    def test_a_running_guardian_is_verified_and_never_restarted_or_reinstalled(self):
        for index in (1, 2, 3):
            self.remote.units[self.unit(index)] = running_unit()
        self.remote.calls.clear()
        bridge.BRIDGE_STEPS["start_guardians"].apply(self.ctx())
        self.assertEqual(self.commands("install"), [])
        self.assertEqual([call for call in self.commands("activate") if call[2] == "guardian"], [])
        self.assertEqual([call for call in self.commands("copy") if call[1] in GUARDIAN_HOSTS], [])

    def test_an_installed_stopped_guardian_is_only_activated(self):
        self.remote.units[self.unit(2)] = {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled",
                                           "MainPID": "0", "NRestarts": "0"}
        for index in (1, 3):
            self.remote.units[self.unit(index)] = running_unit()
        self.remote.calls.clear()
        bridge.BRIDGE_STEPS["start_guardians"].apply(self.ctx())
        self.assertEqual(self.commands("install"), [])
        self.assertEqual([(call[1], call[3]) for call in self.commands("activate") if call[2] == "guardian"],
                         [("guardian-test-2", True)])

    def test_the_stage_directory_is_removed_even_when_activation_fails(self):
        original = self.remote.activation
        attempted = []
        def fail(host, argv):
            if argv[argv.index("--role") + 1] == "guardian":
                attempted.append(host)
                raise RemoteError(f"{host}: exit 1: Bridge activation failed")
            return original(host, argv)
        self.remote.activation = fail
        with self.assertRaises(RemoteError):
            bridge.BRIDGE_STEPS["start_guardians"].apply(self.ctx())
        scripts = [call[2] for call in self.remote.calls if call[0] == "root-script" and call[1] == "guardian-test-1"]
        self.assertTrue(any(text.startswith("set -euo pipefail\nrm -rf -- /var/tmp/psy-bridge-guardian-1") for text in scripts))
        self.assertEqual(attempted, ["guardian-test-1"])

    def test_packages_must_match_the_lock_tools_and_the_recorded_documents(self):
        ctx = self.ctx()
        self.write_packages(documents="f" * 64)
        with self.assertRaisesRegex(ValueError, "different L1 documents"):
            bridge.BRIDGE_STEPS["start_guardians"].check(ctx)
        self.write_packages()
        package = Path(prepare.read_state(ctx, "prepare_bridge_packages")["guardian"]["guardian-test-1"])
        (package / "install_guardian.py").write_text("# edited\n")
        with self.assertRaisesRegex(ValueError, "package file hash differs: install_guardian.py"):
            bridge.BRIDGE_STEPS["start_guardians"].check(ctx)
        self.write_packages()
        info = json.loads((package / "package.json").read_text())
        info["files"]["guardian_exec.py"] = "f" * 64
        (package / "package.json").write_text(json.dumps(info))
        with self.assertRaisesRegex(ValueError, "package file hash differs: guardian_exec.py"):
            bridge.BRIDGE_STEPS["start_guardians"].check(ctx)

    def test_package_copy_of_a_tool_must_be_the_tool_of_the_lock(self):
        self.ws.lock["tool_sha256"]["activate_bridge.py"] = "f" * 64
        with self.assertRaises(ValueError):
            bridge.BRIDGE_STEPS["start_guardians"].check(self.ctx())

    def test_verify_requires_running_enabled_units_without_restarts_and_readiness(self):
        for index in (1, 2, 3):
            self.remote.units[self.unit(index)] = running_unit()
        result = bridge.BRIDGE_STEPS["start_guardians"].verify(self.ctx())
        self.assertEqual(result["ready_from_relayer_host"], 3)
        self.assertEqual(sorted(row["guardian_id"] for row in result["guardians"].values()), [1, 2, 3])
        self.assertIsNone(find_secret(result))
        self.remote.units[self.unit(3)]["NRestarts"] = "1"
        with self.assertRaisesRegex(ValueError, "guardian-test-3: Guardian is not running without restarts"):
            bridge.BRIDGE_STEPS["start_guardians"].verify(self.ctx())

    def test_guardian_step_needs_the_recorded_l1_documents(self):
        (self.ws.state_dir / "deploy_l1.json").unlink()
        with self.assertRaisesRegex(ValueError, "no recorded state for deploy_l1"):
            bridge.BRIDGE_STEPS["start_guardians"].check(self.ctx())


class RelayerStepTests(PackageTestCase):
    def setUp(self):
        super().setUp()
        self.remote.checkpoints = [{"sepolia": 256, "bscTestnet": 256, "baseSepolia": 256}]
        self.relayer_unit = self.ws.lock["units"]["relayer"]

    def apply(self):
        bridge.BRIDGE_STEPS["start_relayer"].check(self.ctx())
        bridge.BRIDGE_STEPS["start_relayer"].apply(self.ctx())

    def test_relayer_is_installed_checked_activated_and_then_watched(self):
        self.remote.calls.clear()
        state = {"seen": False}
        original = self.remote.run_script
        def scripted(host, script, timeout):
            if f"systemctl show {self.relayer_unit}" in script and state["seen"]:
                return "".join(f"{k}={v}\n" for k, v in running_unit().items())
            return original(host, script, timeout)
        def activation(host, argv):
            state["seen"] = True
            return json.dumps({"role": "relayer", "started": True})
        self.remote.run_script, self.remote.activation = scripted, activation
        self.apply()
        order = [(call[0], call[3] if call[0] == "install" else None) for call in self.remote.calls if call[0] == "install"]
        self.assertEqual(order, [("install", "check-host"), ("install", "install")])

    def test_relayer_start_refused_until_guardians_and_services_ready(self):
        self.remote.activation_error = RemoteError(f"{RELAYER_HOST}: exit 1: Bridge activation failed: Guardian not ready")
        with self.assertRaisesRegex(RemoteError, "Guardian not ready"):
            self.apply()
        self.assertTrue(any(call[0] == "activate" and call[2] == "relayer" for call in self.remote.calls))
        self.assertFalse(any("PSY_CHECKPOINT_END" in call[2] for call in self.remote.calls if call[0] == "script"))

    def test_a_running_relayer_is_not_reinstalled_or_restarted(self):
        self.remote.units[self.relayer_unit] = running_unit()
        self.remote.calls.clear()
        self.apply()
        self.assertEqual(self.commands("install"), [])
        self.assertEqual(self.commands("activate"), [])
        self.assertEqual([call for call in self.commands("copy")], [])

    def test_first_settlement_requires_all_three_chains_to_advance(self):
        self.remote.units[self.relayer_unit] = running_unit()
        self.remote.checkpoints = [{"sepolia": 256, "bscTestnet": 256, "baseSepolia": 0}]
        with unittest.mock.patch.object(bridge, "SETTLEMENT_SECONDS", 0), self.assertRaisesRegex(TimeoutError, "first settlement"):
            self.apply()
        self.remote.checkpoints = [{"sepolia": 0, "bscTestnet": 0, "baseSepolia": 0}, {"sepolia": 192, "bscTestnet": 0, "baseSepolia": 0},
                                   {"sepolia": 192, "bscTestnet": 192, "baseSepolia": None},
                                   {"sepolia": 256, "bscTestnet": 256, "baseSepolia": 256}]
        self.apply()
        self.assertEqual(self.remote.checkpoints, [{"sepolia": 256, "bscTestnet": 256, "baseSepolia": 256}])

    def test_checkpoint_read_uses_the_state_managers_and_private_routes_of_the_lock(self):
        self.remote.units[self.relayer_unit] = running_unit()
        self.apply()
        script = next(call[2] for call in self.remote.calls if call[0] == "script" and "PSY_CHECKPOINT_END" in call[2])
        recorded = prepare.read_state(self.ctx(), "deploy_l1")
        for chain in CHAINS:
            self.assertIn(recorded["chains"][chain]["state_manager"], script)
            self.assertIn(self.ws.lock["envio"]["rpc_routes"][chain], script)
        self.assertIn(bridge.LAST_FINALIZED_SELECTOR, script)
        self.assertEqual(bridge.LAST_FINALIZED_SELECTOR, "0x3590a6a3")

    def test_a_restart_while_waiting_fails_instead_of_waiting_out_the_limit(self):
        self.remote.units[self.relayer_unit] = {**running_unit(), "NRestarts": "1"}
        self.remote.checkpoints = [{"sepolia": 0, "bscTestnet": 0, "baseSepolia": 0}]
        with self.assertRaisesRegex(RuntimeError, "Relayer is active with 1 restarts"):
            self.apply()

    def test_verify_reports_checkpoints_and_refuses_an_unsettled_chain(self):
        self.remote.units[self.relayer_unit] = running_unit()
        result = bridge.BRIDGE_STEPS["start_relayer"].verify(self.ctx())
        self.assertEqual(result["checkpoints"], {"sepolia": 256, "bscTestnet": 256, "baseSepolia": 256})
        self.assertIsNone(find_secret(result))
        self.remote.checkpoints = [{"sepolia": 256, "bscTestnet": 0, "baseSepolia": 256}]
        with self.assertRaisesRegex(ValueError, "has not settled"):
            bridge.BRIDGE_STEPS["start_relayer"].verify(self.ctx())

    def test_relayer_needs_exactly_one_package_with_lock_pinned_tools(self):
        state = prepare.read_state(self.ctx(), "prepare_bridge_packages")
        prepare.write_state(self.ctx(), "prepare_bridge_packages", {**state, "relayer": {}})
        with self.assertRaisesRegex(ValueError, "no relayer package recorded"):
            bridge.BRIDGE_STEPS["start_relayer"].check(self.ctx())


class RegistryTests(unittest.TestCase):
    def test_the_module_is_registered_with_the_orchestrator(self):
        import deploy
        self.assertIn("deploy_bridge_steps", deploy.STEP_MODULES)
        registry = deploy.build_registry()
        for name in ("deploy_l1", "start_guardians", "start_relayer"):
            self.assertTrue(registry[name].cutover)

    def test_steps_table_marks_the_three_steps_as_cutover(self):
        table = (Path(__file__).resolve().parents[1] / "fresh-192-20261030" / "steps.tsv").read_text()
        for step_id, name in (("69", "deploy_l1"), ("71", "start_guardians"), ("74", "start_relayer")):
            self.assertRegex(table, rf"(?m)^{step_id}\tpy-cutover:{name}\t")


if __name__ == "__main__":
    unittest.main()
