"""Acceptance steps with fake hosts and chains; the drivers run in a real bash against stub CLIs."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import unittest.mock
from types import SimpleNamespace

import accept_common as ac
import deploy
import deploy_accept_steps as steps
import release_lock
from deploy_remote import OperatorPending, RemoteError, find_secret

HERE = Path(__file__).resolve().parent
REAL_TABLE = HERE.parent / "fresh-192-20261030" / "steps.tsv"
CHAINS = release_lock.CHAINS
ADDRESS = "0x" + "e" * 40


def documents():
    return {chain: {"core": {"Bridge": "0x" + "b" * 40, "Router": "0x" + "c" * 40, "USDTToken": "0x" + "d" * 40,
                             "PsyToken": "0x" + "9" * 40, "TokenFaucetManager": "0x" + "f" * 40, "ERC20Gateway": "0x" + "a" * 40}}
            for chain in CHAINS}


class World(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state, self.release, self.work = self.root / "state", self.root / "release", self.root / "work"
        for path in (self.state, self.release):
            path.mkdir()
        (self.release / "release.json").write_text(json.dumps({"core_placement": {"relayer": "relayer-host"}}))
        self.remote = FakeRemote()
        self.ctx = SimpleNamespace(state_dir=self.state, release_dir=self.release, lock_sha256="a" * 64, remote=self.remote,
                                   lock={"units": {"core_prefix": "psy-core-x-", "relayer": "relayer.service", "faucet": "faucet.service"},
                                         "l1": {"signer_host": "signer"}, "hosts": {}})
        ac.OPEN_CHAINS.clear()
        self.addCleanup(ac.OPEN_CHAINS.clear)
        self.events = []
        self.work.mkdir()
        patcher = unittest.mock.patch.object(steps, "work_dir", lambda ctx: self.work)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put_state(self, name, **fields):
        (self.state / f"{name}.json").write_text(json.dumps({"lock_sha256": "a" * 64, **fields}))

    def patch(self, **replacements):
        for name, value in replacements.items():
            patcher = unittest.mock.patch.object(steps, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)


class FakeRemote:
    def __init__(self):
        self.scripts, self.journals, self.roots = [], {}, []

    def run_root_text(self, host, argv, timeout, **options):
        self.roots.append((host, argv))
        if "journalctl" in argv[0]:
            unit, pattern = argv[argv.index("-u") + 1], argv[argv.index("-g") + 1]
            return self.journals.get((unit, pattern), "")
        return ""

    def run_script(self, host, script, timeout):
        self.scripts.append((host, script))
        return "1000\n2000\n9000\n" if "MemoryCurrent" in script and "seq" in script else "21474836480\n"


class RegistrationTests(unittest.TestCase):
    def test_the_whole_real_table_is_registered_with_matching_cutover_flags(self):
        registry = deploy.build_registry()
        self.assertEqual(deploy.unregistered_steps(REAL_TABLE, registry), [])
        self.assertEqual(deploy.mismatched_cutover_steps(REAL_TABLE, registry), [])
        for name in steps.ACCEPT_STEPS:
            self.assertIs(registry[name], steps.ACCEPT_STEPS[name])

    def test_acceptance_steps_are_listed_in_the_order_of_the_brief(self):
        rows = [line.split("\t")[1] for line in REAL_TABLE.read_text().splitlines() if line and line[0].isdigit()]
        wanted = ["py:accept_entrypoints", "py:accept_p2p_rotation", "py:accept_faucet_batch", "py:accept_five_withdrawals",
                  "py:accept_three_chains", "py:deploy_monitoring", "py:accept_psy_withdrawal", "py:open_deposits"]
        self.assertEqual([row for row in rows if row in wanted], wanted)

    def test_metamask_is_skipped_by_name_and_the_reward_claim_stays_unverified(self):
        self.assertIn("metamask", steps.SKIPPED)
        self.assertTrue(steps.UNVERIFIED["reward_claim"].startswith("unverified"))


class EntrypointTests(World):
    PUBLIC = {"chains": {chain: {"rpc_url": f"https://rpc-{chain}.example/"} for chain in CHAINS},
              "trust_setup": {"base_url": "https://nostr.example/trust-setup", "archive": "a.tar.gz"},
              "services": {"coordinator_rpc": "https://c.example", "realm_rpcs": ["https://r0.example", "https://r1.example"],
                           "prove_proxy": "https://p.example", "faucet_rpc": "https://f.example", "psy_services": "https://s.example"},
              "frontends": {"app": "https://app.example/"}}

    def test_entrypoint_deferred_items_are_listed_in_the_result(self):
        passed, deferred = steps.parse_entrypoint_lines("[ok] nostr\n[ok] coordinator\n[DEFERRED] public trust setup archive (x)\n")
        self.assertEqual((passed, deferred), (["nostr", "coordinator"], ["public trust setup archive (x)"]))

    def test_the_check_runs_standalone_and_defers_the_trust_setup_until_it_is_published(self):
        env = steps.entrypoint_env(self.ctx, self.PUBLIC, False)
        self.assertEqual((env["CHECK_PUBLIC_STANDALONE"], env["CHECK_PUBLIC_TRUST_SETUP"]), ("1", "0"))
        self.assertEqual(steps.entrypoint_env(self.ctx, self.PUBLIC, True)["CHECK_PUBLIC_TRUST_SETUP"], "1")
        self.assertEqual(env["PUBLIC_TRUST_SETUP_PATH"], "/trust-setup")
        self.assertEqual({row["name"] for row in json.loads(env["PUBLIC_L1_RPC_ROUTES_JSON"])}, {"sepolia", "bsc", "base"})
        self.assertIsNone(find_secret({"env": {k: v for k, v in env.items() if k.startswith("PUBLIC_")}}))
        self.assertNotIn("PUBLIC_INDEXER_DOMAIN", env)

    def test_a_stale_public_route_fails_with_its_age(self):
        now = 10_000
        fresh = lambda url, method, params: ({"timestamp": hex(now - 5)}, None)
        self.assertEqual(set(steps.head_ages(self.PUBLIC, now, fresh).values()), {5})
        stale = lambda url, method, params: ({"timestamp": hex(now - 3 * 86400)}, None)
        with self.assertRaisesRegex(ValueError, "behind; its node is stale"):
            steps.head_ages(self.PUBLIC, now, stale)

    def test_the_script_standalone_mode_needs_no_deployment_config(self):
        text = (steps.CHECK_SCRIPT).read_text()
        self.assertIn("CHECK_PUBLIC_STANDALONE", text)
        self.assertIn("[DEFERRED]", text)
        done = subprocess.run(["bash", "-n", str(steps.CHECK_SCRIPT)], capture_output=True)
        self.assertEqual(done.returncode, 0)
        refused = subprocess.run(["bash", str(steps.CHECK_SCRIPT)], env={"PATH": os.environ["PATH"], "CHECK_PUBLIC_STANDALONE": "1"},
                                 capture_output=True, text=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("PUBLIC_NOSTR_DOMAIN", refused.stderr)


class P2pTests(World):
    def setUp(self):
        super().setUp()
        validators = lambda realm, base: [{"processor_host": f"h{realm}{n}"} for n in range(3)]
        (self.release / "topology.json").write_text(json.dumps({"realms": [{"id": 0, "validators": validators(0, 0)},
                                                                            {"id": 1, "validators": validators(1, 0)}]}))
        self.patch(base_check=lambda ctx: None)

    def line(self, realm, sub, epoch):
        return f"2026 INFO x: realm P2P proposal published proposal=ab realm={realm} sub_id={sub} epoch={epoch} target=5\n"

    def feed(self, subs_by_realm):
        for realm, subs in subs_by_realm.items():
            for sub in subs:
                unit = f"psy-core-x-realm-{realm}-v{sub}-processor.service"
                self.remote.journals[(unit, "realm P2P proposal published")] = self.line(realm, sub, 16 + sub)

    def test_p2p_rotation_requires_each_validator_to_propose(self):
        self.feed({0: (1, 2, 3), 1: (1, 2)})
        seen = steps.proposals(self.ctx, "24 hours ago")
        with self.assertRaisesRegex(ValueError, "realm 1 validator 3"):
            steps.require_rotation(seen, (0, 1), (1, 2, 3))
        self.feed({1: (1, 2, 3)})
        report = steps.require_rotation(steps.proposals(self.ctx, "24 hours ago"), (0, 1), (1, 2, 3))
        self.assertEqual(report["realm0"]["v2"], [18])

    def test_p2p_recovery_restarts_one_processor_per_realm_and_never_the_current_proposer(self):
        self.feed({0: (1, 2, 3), 1: (1, 2, 3)})
        quiet = unittest.mock.patch.object(steps, "quiet_unit", return_value=True)
        quiet.start()
        self.addCleanup(quiet.stop)
        wait = unittest.mock.patch.object(steps, "wait_until", side_effect=lambda ready, failure, *a: self.assertTrue(ready()))
        wait.start()
        self.addCleanup(wait.stop)
        steps.p2p_apply(self.ctx)
        restarts = [argv for host, argv in self.remote.roots if "systemctl" in argv[0]]
        self.assertEqual(len(restarts), 2)
        self.assertEqual({argv[2].split("-realm-")[1][0] for argv in restarts}, {"0", "1"})
        steps.p2p_apply(self.ctx)
        self.assertEqual(len([argv for host, argv in self.remote.roots if "systemctl" in argv[0]]), 2, "a rerun restarts nothing")
        self.assertEqual(sorted(steps.p2p_verify(self.ctx)["restarted"]), ["0", "1"])

    def test_a_realm_whose_every_validator_is_proposing_is_not_restarted(self):
        with self.assertRaisesRegex(ValueError, "nothing safe to restart"):
            steps.restart_one(self.ctx, 0, steps.processors(self.ctx), {0: {1, 2, 3}})


class FaucetTests(World):
    def test_faucet_batch_records_peak_resources_and_each_burst_recipient(self):
        users = {name: {"name": name, "id": index, "key": Path("/k") / name} for index, name in enumerate(("u00", *steps.BURST_USERS))}
        grants = iter(range(100))
        self.patch(user_check=lambda ctx: None, driver_env=lambda ctx, documents: {"E2E_WORK_DIR": str(self.work)},
                   l1_documents=lambda ctx: documents(), public_of=lambda ctx: {"services": {"faucet_rpc": "https://f.example"}},
                   ensure_user=lambda ctx, env, name: users[name],
                   faucet_claim=lambda public, user_id: {"tx_hash": "t1", "operator_user_id": 500 + next(grants)},
                   l2_claim=lambda env, user, operator: self.events.append(("claim", user["name"])))
        self.patch(prepare=SimpleNamespace(faucet_host=lambda ctx: "faucet-host", local_inputs=None))
        steps.faucet_apply(self.ctx)
        state = steps.faucet_verify(self.ctx)
        self.assertEqual(state["burst"]["recipients"], 10)
        self.assertEqual(state["burst"]["batches"], 1)
        self.assertEqual((state["memory"]["peak_bytes"], state["memory"]["idle_bytes"], state["memory"]["limit_bytes"]), (9000, 1000, 21474836480))
        self.assertEqual(len([event for event in self.events if event[0] == "claim"]), 11)
        steps.faucet_apply(self.ctx)
        self.assertEqual(len([event for event in self.events if event[0] == "claim"]), 11, "a finished burst is never repeated")

    def test_a_faucet_at_its_memory_limit_fails_the_step(self):
        self.remote.run_script = lambda host, script, timeout: "9999\n" if "MemoryCurrent" in script and "seq" in script else "5000\n"
        self.patch(prepare=SimpleNamespace(faucet_host=lambda ctx: "faucet-host"), burst=lambda public, users: [])
        with self.assertRaisesRegex(ValueError, "memory limit"):
            steps.faucet_apply_burst(self.ctx, {}, {}, [])


class ThreeChainTests(World):
    def setUp(self):
        super().setUp()
        self.docs = documents()
        self.put_state("accept_faucet_batch", burst={})
        self.patch(user_check=lambda ctx: None, l1_documents=lambda ctx: self.docs, public_of=lambda ctx: {},
                   driver_env=lambda ctx, docs: {"E2E_WALLET_ADDRESS": ADDRESS, "E2E_WORK_DIR": str(self.work)},
                   ensure_user=lambda ctx, env, name: {"name": name, "id": 7, "key": Path("/k")},
                   prepare_wallet=lambda env, docs, chain, amount: self.events.append(("prepare", chain)),
                   deposit_once=lambda *args: self.events.append(("deposit", args[3])) or Path("/r"),
                   wait_proved=lambda chain, bridge, index: self.events.append(("proved", chain, index)),
                   claim_one=lambda *args: self.events.append(("claim", args[2])),
                   withdraw_one=lambda *args, **kw: self.events.append(("withdraw", args[3])),
                   wait_balance=lambda *args: self.events.append(("settled", args[0])))
        for name, value in (("read_count", lambda chain, bridge, selector: 3), ("read_balance", lambda *a: 0)):
            patcher = unittest.mock.patch.object(ac, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        tunnel = unittest.mock.patch.object(ac, "gateway_tunnel", unittest.mock.MagicMock())
        tunnel.start()
        self.addCleanup(tunnel.stop)
        self.windows = []

        def run_window(ctx, chain, docs, wallet, deposit, admin=None):
            self.windows.append(chain)
            self.assertEqual(ac.OPEN_CHAINS, [], "no chain is open between windows")
            return deposit()
        patcher = unittest.mock.patch.object(ac, "run_window", run_window)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_three_chains_go_one_at_a_time_and_each_settles(self):
        steps.three_chains_apply(self.ctx)
        self.assertEqual(self.windows, list(CHAINS))
        kinds = [event[0] for event in self.events]
        self.assertEqual(kinds, ["prepare", "deposit", "proved", "claim", "withdraw", "settled"] * 3)
        state = json.loads((self.state / "accept_three_chains.json").read_text())
        self.assertEqual(sorted(state["chains"]), sorted(CHAINS))
        self.assertIn("metamask", state["skipped"])
        self.assertTrue(state["unverified"]["reward_claim"].startswith("unverified"))
        self.assertIsNone(find_secret(state))

    def test_a_rerun_after_a_settle_timeout_withdraws_nothing_again(self):
        sent = []
        self.patch(withdraw_one=lambda *a, **k: sent.append((a[3], k["nonce"])))
        outcomes = iter([TimeoutError("not settled")] + [None] * 10)

        def wait_balance(*args):
            outcome = next(outcomes)
            if outcome is not None:
                raise outcome
        self.patch(wait_balance=wait_balance)
        with self.assertRaises(TimeoutError):
            steps.three_chains_apply(self.ctx)
        first = list(sent)
        self.assertEqual([chain for chain, _ in first], ["sepolia"])
        steps.three_chains_apply(self.ctx)
        self.assertEqual(sent[0], first[0], "the recorded withdrawal is not sent again")
        self.assertEqual([chain for chain, _ in sent], list(CHAINS))
        claims = [event for event in self.events if event[0] == "claim"]
        self.assertEqual(len(claims), 3, "a claimed deposit is not claimed again")

    def test_a_rerun_after_a_finished_chain_does_not_deposit_again(self):
        steps.three_chains_apply(self.ctx)
        self.events.clear()
        steps.three_chains_apply(self.ctx)
        self.assertEqual(self.events, [])
        self.assertEqual(self.windows, list(CHAINS))

    def test_a_window_that_did_not_finish_is_never_repeated_blindly(self):
        self.put_state("accept_three_chains", chains={"sepolia": {"deposit_index": 3, "window": "opened"}})
        with self.assertRaisesRegex(ValueError, "did not finish; read the pending deposit count"):
            steps.three_chains_apply(self.ctx)
        self.assertEqual(self.windows, [])

    def test_verify_needs_a_settled_leg_per_chain_and_a_paused_fleet(self):
        steps.three_chains_apply(self.ctx)
        with unittest.mock.patch.object(ac, "unpaused_chains", return_value=[]):
            self.assertEqual(sorted(steps.three_chains_verify(self.ctx)["chains"]), sorted(CHAINS))
        with unittest.mock.patch.object(ac, "unpaused_chains", return_value=["bscTestnet"]):
            with self.assertRaisesRegex(ValueError, "deposits are open on bscTestnet"):
                steps.three_chains_verify(self.ctx)


class FiveWithdrawalTests(World):
    def setUp(self):
        super().setUp()
        self.put_state("accept_faucet_batch", burst={})
        self.docs = documents()
        self.patch(user_check=lambda ctx: None, l1_documents=lambda ctx: self.docs,
                   driver_env=lambda ctx, docs: {"E2E_WALLET_ADDRESS": ADDRESS, "E2E_WORK_DIR": str(self.work)},
                   ensure_user=lambda ctx, env, name: {"name": name, "id": 1, "key": Path("/k")},
                   prepare_wallet=lambda *a: None, deposit_once=lambda *a: self.events.append(("deposit", a[5])),
                   wait_proved=lambda *a: self.events.append(("proved", a[2])), claim_one=lambda *a: self.events.append(("claim", a[3])),
                   withdraw_one=lambda *a, **k: self.events.append(("withdraw", a[4])), wait_balance=lambda *a: None)
        for name, value in (("read_count", lambda *a: 10), ("read_balance", lambda *a: 0)):
            patcher = unittest.mock.patch.object(ac, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, value in (("gateway_tunnel", unittest.mock.MagicMock()), ("run_window", lambda ctx, chain, docs, wallet, deposit, admin=None: deposit())):
            patcher = unittest.mock.patch.object(ac, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_five_withdrawals_requires_batch_size_5_on_chain(self):
        with self.assertRaisesRegex(ValueError, "never resolved batch_append_withdrawals_5"):
            steps.five_apply(self.ctx)
        self.assertEqual([event for event in self.events if event[0] == "deposit"], [("deposit", f"five-{name}") for name in steps.FIVE_USERS])
        self.remote.journals[("relayer.service", "batch_append_withdrawals_5")] = "resolve method batch_append_withdrawals_5 of contract 3\n"
        self.events.clear()
        steps.five_apply(self.ctx)
        self.assertEqual(self.events and [e for e in self.events if e[0] == "deposit"], [], "the five deposits are not repeated")
        self.assertEqual(steps.five_verify(self.ctx)["batch_5_lines"], 1)

    def test_any_quarantine_line_fails_the_five_withdrawals_and_the_record_never_passes(self):
        self.remote.journals[("relayer.service", "batch_append_withdrawals_5")] = "x\n"
        self.remote.journals[("relayer.service", "quarantining withdrawal")] = "quarantining withdrawal event 9\n"
        with self.assertRaisesRegex(ValueError, "1 quarantining withdrawal line"):
            steps.five_apply(self.ctx)
        self.assertNotIn("settled", json.loads((self.state / "accept_five_withdrawals.json").read_text()))
        self.put_state("accept_five_withdrawals", settled={"batch_5_lines": 1, "quarantine_lines": 3})
        with self.assertRaisesRegex(ValueError, "quarantine line was recorded"):
            steps.five_verify(self.ctx)

    def test_a_rerun_after_a_settle_timeout_reuses_the_recorded_withdrawals_and_baseline(self):
        self.remote.journals[("relayer.service", "batch_append_withdrawals_5")] = "x\n"
        sent, balances = [], iter([1000, 9999, 9999, 9999])
        self.patch(withdraw_one=lambda *a, **k: sent.append((a[5], k["nonce"])))
        waits = iter([TimeoutError("not settled"), None])
        self.patch(wait_balance=lambda *a: self.wait_or_raise(waits, a))
        with unittest.mock.patch.object(ac, "read_balance", lambda *a: next(balances)):
            with self.assertRaises(TimeoutError):
                steps.five_apply(self.ctx)
            first = list(sent)
            steps.five_apply(self.ctx)
        self.assertEqual(sent, first, "no second withdrawal and no fresh nonce")
        state = json.loads((self.state / "accept_five_withdrawals.json").read_text())
        self.assertEqual(state["withdrawal"]["baseline"], 1000)
        self.assertEqual(len(first), 5)
        self.assertEqual(len({nonce for _, nonce in first}), 5)

    def test_a_failed_withdrawal_is_resent_with_its_own_nonce_and_the_others_are_not(self):
        self.remote.journals[("relayer.service", "batch_append_withdrawals_5")] = "x\n"
        sent, fail = [], {"five-u03"}

        def withdraw(*a, **k):
            if a[5] in fail:
                raise RuntimeError("cli failed")
            sent.append((a[5], k["nonce"]))
        self.patch(withdraw_one=withdraw)
        with self.assertRaisesRegex(RuntimeError, "cli failed"):
            steps.five_apply(self.ctx)
        nonce = json.loads((self.state / "accept_five_withdrawals.json").read_text())["withdrawal"]["nonces"]["u03"]
        fail.clear()
        steps.five_apply(self.ctx)
        self.assertEqual(len(sent), 5)
        self.assertEqual([n for label, n in sent if label == "five-u03"], [nonce])

    @staticmethod
    def wait_or_raise(waits, args):
        outcome = next(waits)
        if outcome is not None:
            raise outcome

    def test_the_five_users_are_claimed_at_consecutive_deposit_indexes(self):
        self.remote.journals[("relayer.service", "batch_append_withdrawals_5")] = "x\n"
        steps.five_apply(self.ctx)
        self.assertEqual([event for event in self.events if event[0] == "proved"], [("proved", 14)])
        self.assertEqual(len([event for event in self.events if event[0] == "withdraw"]), 5)


class PsyWithdrawalTests(World):
    def test_a_settled_psy_withdrawal_is_recorded_with_the_address_from_the_documents(self):
        docs = documents()
        self.put_state("accept_faucet_batch", burst={})
        self.patch(user_check=lambda ctx: None, l1_documents=lambda ctx: docs,
                   driver_env=lambda ctx, d: {"E2E_WALLET_ADDRESS": ADDRESS, "E2E_WORK_DIR": str(self.work)},
                   ensure_user=lambda ctx, env, name: {"name": name, "id": 1, "key": Path("/k")},
                   withdraw_one=lambda *a, **k: self.events.append(("withdraw", a[7], k.get("contract_id"))),
                   wait_balance=lambda *a: self.events.append(("wait", a[3])))
        for name, value in (("read_balance", lambda *a: 5), ("gateway_tunnel", unittest.mock.MagicMock())):
            patcher = unittest.mock.patch.object(ac, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        steps.psy_apply(self.ctx)
        self.assertIn(("withdraw", steps.PSY_WITHDRAW_AMOUNT, 0), self.events)
        self.assertIn(("wait", 5 + steps.PSY_WITHDRAW_AMOUNT), self.events)
        report = steps.psy_verify(self.ctx)
        self.assertEqual(report["address_from_documents"], "0x" + "9" * 40)


class PsyQuarantineTests(World):
    def setUp(self):
        super().setUp()
        self.docs = documents()
        self.put_state("accept_faucet_batch", burst={})
        self.patch(user_check=lambda ctx: None, l1_documents=lambda ctx: self.docs,
                   driver_env=lambda ctx, d: {"E2E_WALLET_ADDRESS": ADDRESS, "E2E_WORK_DIR": str(self.work)},
                   ensure_user=lambda ctx, env, name: {"name": name, "id": 1, "key": Path("/k")},
                   withdraw_one=lambda *a, **k: self.events.append(("withdraw", k["nonce"])), wait_balance=lambda *a: None)
        for name, value in (("read_balance", lambda *a: 5), ("gateway_tunnel", unittest.mock.MagicMock())):
            patcher = unittest.mock.patch.object(ac, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_three_quarantine_lines_fail_the_psy_withdrawal(self):
        self.remote.journals[("relayer.service", "quarantining withdrawal")] = "q 1\nq 2\nq 3\n"
        with self.assertRaisesRegex(ValueError, "3 quarantining withdrawal line"):
            steps.psy_apply(self.ctx)
        self.assertNotIn("settled", json.loads((self.state / "accept_psy_withdrawal.json").read_text()))
        self.put_state("accept_psy_withdrawal", settled={"quarantine_lines": 3})
        with self.assertRaisesRegex(ValueError, "quarantine line was recorded"):
            steps.psy_verify(self.ctx)

    def test_a_rerun_after_the_quarantine_failure_does_not_withdraw_again(self):
        self.remote.journals[("relayer.service", "quarantining withdrawal")] = "q\n"
        with self.assertRaises(ValueError):
            steps.psy_apply(self.ctx)
        with self.assertRaises(ValueError):
            steps.psy_apply(self.ctx)
        self.assertEqual(len([event for event in self.events if event[0] == "withdraw"]), 1)


class OpenDepositTests(World):
    def write_acceptance_records(self, **overrides):
        records = {
            "accept_entrypoints": {"checks": 25, "deferred": [], "head_age_seconds": {}},
            "accept_p2p_rotation": {"restarted": {"0": {}, "1": {}}, "rotation": {}},
            "accept_faucet_batch": {"burst": {"recipients": 10, "batches": 1}, "memory": {}},
            "accept_five_withdrawals": {"settled": {"batch_5_lines": 1, "quarantine_lines": 0}},
            "accept_three_chains": {"chains": {chain: {"settled": {"returned": 1}} for chain in CHAINS}},
            "accept_psy_withdrawal": {"settled": {"quarantine_lines": 0}}}
        records.update(overrides)
        for name, fields in records.items():
            self.put_state(name, **fields)

    def setUp(self):
        super().setUp()
        self.write_acceptance_records()
        self.open = set()

        def admin(ctx, chain, target, execute):
            if execute:
                self.events.append((chain, target))
                (self.open.add if target == 0 else self.open.discard)(chain)
            return {"ok": True, "flags": [[0, 0, 0] if chain in self.open else [1, 0, 1]] * 3, "hash": "0xh", "gasUsed": "55000",
                    "flagsBefore": [[0, 0, 0] if chain in self.open else [1, 0, 1]] * 3}
        for name, value in (("run_admin", admin),):
            patcher = unittest.mock.patch.object(ac, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_without_the_confirm_variable_the_step_is_pending_and_opens_nothing(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(steps.CONFIRM_VARIABLE, None)
            with self.assertRaises(OperatorPending) as pending:
                steps.open_apply(self.ctx)
        self.assertIn(f"{steps.CONFIRM_VARIABLE}=1", pending.exception.command)
        self.assertEqual(self.events, [])

    def test_with_the_variable_each_chain_opens_with_a_read_back_and_a_rerun_skips_open_chains(self):
        with unittest.mock.patch.dict(os.environ, {steps.CONFIRM_VARIABLE: "1"}):
            steps.open_apply(self.ctx)
            self.assertEqual(self.events, [(chain, 0) for chain in CHAINS])
            steps.open_apply(self.ctx)
        self.assertEqual(len(self.events), 3)
        self.assertEqual(sorted(steps.open_verify(self.ctx)["chains"]), sorted(CHAINS))

    def test_open_requires_every_acceptance_record(self):
        (self.state / "accept_five_withdrawals.json").unlink()
        self.patch(require_frontends_current=lambda ctx: None, prepare=SimpleNamespace(check_tool_hash=lambda ctx, name: None))
        with self.assertRaisesRegex(ValueError, "no recorded state for accept_five_withdrawals"):
            steps.open_check(self.ctx)

    def test_open_runs_the_verify_of_each_step_so_partial_progress_does_not_pass(self):
        self.patch(require_frontends_current=lambda ctx: None, prepare=SimpleNamespace(check_tool_hash=lambda ctx, name: None))
        steps.open_check(self.ctx)
        partial = {chain: ({"settled": {"returned": 1}} if chain == "sepolia" else {"deposit_index": 3, "window": "closed"}) for chain in CHAINS}
        self.write_acceptance_records(accept_three_chains={"chains": partial})
        with self.assertRaisesRegex(ValueError, "every chain must have settled"):
            steps.open_check(self.ctx)
        self.write_acceptance_records(accept_five_withdrawals={"first_index": 3, "window": "closed"})
        with self.assertRaises(ValueError):
            steps.open_check(self.ctx)
        self.write_acceptance_records(accept_psy_withdrawal={"started": "now"})
        with self.assertRaisesRegex(ValueError, "did not settle"):
            steps.open_check(self.ctx)

    def test_open_stays_possible_to_rerun_once_chains_are_open(self):
        self.patch(require_frontends_current=lambda ctx: None, prepare=SimpleNamespace(check_tool_hash=lambda ctx, name: None))
        self.open.update(CHAINS)
        steps.open_check(self.ctx)

    def test_a_failed_readback_does_not_record_the_chain_as_open(self):
        bad = lambda ctx, chain, target, execute: {"ok": True, "flags": [[1, 0, 1]] * 3, "flagsBefore": [[1, 0, 1]] * 3}
        with unittest.mock.patch.object(ac, "run_admin", bad), unittest.mock.patch.dict(os.environ, {steps.CONFIRM_VARIABLE: "1"}):
            with self.assertRaisesRegex(ValueError, "not read back as open"):
                steps.open_apply(self.ctx)
        self.assertFalse((self.state / "open_deposits.json").exists())


class GateTests(World):
    def test_acceptance_stops_when_the_frontends_are_not_current_or_a_chain_is_left_open(self):
        with unittest.mock.patch.object(steps, "require_frontends_current", side_effect=ValueError("another config")):
            with self.assertRaisesRegex(ValueError, "another config"):
                steps.base_check(self.ctx)
        self.patch(require_frontends_current=lambda ctx: None)
        with unittest.mock.patch.object(ac, "unpaused_chains", return_value=["baseSepolia"]):
            with self.assertRaisesRegex(ValueError, "deposits are open on baseSepolia"):
                steps.base_check(self.ctx)


class DriverTests(unittest.TestCase):
    """The bash drivers against stub CLIs: argument shapes, no key in any output, no machine path in the sources."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("psy_user_cli", "cast"):
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$0 $*\" >> \"$STUB_LOG\"\nprintf 'key=%s\\n' \"${PRIVATE_KEY:+set}${L1_PRIVATE_KEY:+set}\" >> \"$STUB_LOG\"\nexit 0\n")
            path.chmod(0o755)
        docs = self.root / "docs" / "sepolia"
        docs.mkdir(parents=True)
        (docs / "deployed-contracts.json").write_text(json.dumps({"protocol": {"tokens": {"USDT": {"l1Address": "0x" + "d" * 40}}},
                                                                    "proxies": {"Router_Proxy": "0x" + "c" * 40}}))
        self.key, self.wallet = self.root / "user.key", self.root / "wallet.key"
        self.key.write_text("USERSECRETKEYVALUE\n")
        self.wallet.write_text("WALLETSECRETKEYVALUE\n")
        self.secrets = self.root / "secrets.env"
        self.secrets.write_text("R0=1\nR1=2\nNOTE_SECRET=3\nNULLIFIER_SECRET=4\n")
        self.log = self.root / "log"
        self.env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_LOG": str(self.log), "E2E_USER_CLI": str(self.bin / "psy_user_cli"),
                    "E2E_RUNTIME_CONFIG": "/cfg.json", "E2E_USER_RPC_CONFIG": "/rpc.json", "E2E_DEPLOYMENTS_DIR": str(self.root / "docs"),
                    "E2E_WALLET_KEY_FILE": str(self.wallet), "E2E_WALLET_ADDRESS": ADDRESS, "E2E_RPC_SEPOLIA": "http://127.0.0.1:1"}

    def run_driver(self, name, *args):
        done = subprocess.run(["bash", str(steps.DRIVERS / name), *map(str, args)], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        for stream in (done.stdout, done.stderr):
            self.assertNotIn("SECRETKEYVALUE", stream)
        return self.log.read_text()

    def test_deposit_driver_passes_the_documented_flags_and_hands_the_wallet_key_by_environment(self):
        log = self.run_driver("deposit.sh", "sepolia", 0, 42, self.secrets, self.root / "r.json", 1000000)
        for flag in ("deposit", "--router-address 0x" + "c" * 40, "--token 0x" + "d" * 40, "--amount 1000000", "--user-id 42",
                     "--source-chain-index 0", "--l2-token-contract-id 4", "--l1-rpc-url http://127.0.0.1:1"):
            self.assertIn(flag, log)
        self.assertIn("key=set", log)
        self.assertNotIn("WALLETSECRET", log)

    def test_withdraw_driver_uses_the_chain_index_and_passes_the_contract_id_only_when_given(self):
        log = self.run_driver("withdraw.sh", "sepolia", 0, self.key, "0x" + "9" * 40, 1000000, ADDRESS, "0x" + "1" * 64, self.root / "w.json", 0)
        self.assertIn("withdraw --sign-type zk", log)
        self.assertIn("--destination-chain-index 0", log)
        self.assertIn("--contract-id 0", log)
        self.log.unlink()
        self.assertNotIn("--contract-id", self.run_driver("withdraw.sh", "sepolia", 0, self.key, "0x" + "9" * 40, 5, ADDRESS, "0x" + "1" * 64, self.root / "w.json"))

    def test_the_evm_driver_signs_with_the_wallet_file_and_never_prints_it(self):
        log = self.run_driver("evm.sh", "send", "0xto", "claim(address)", "0xtoken", "--rpc-url", "http://127.0.0.1:1")
        self.assertIn("send 0xto claim(address)", log)

    def test_a_missing_variable_is_named_and_stops_the_driver(self):
        del self.env["E2E_WALLET_KEY_FILE"]
        done = subprocess.run(["bash", str(steps.DRIVERS / "deposit.sh"), "sepolia", "0", "1", str(self.secrets), "r", "1"], env=self.env,
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertIn("E2E_WALLET_KEY_FILE", done.stderr)

    def test_no_driver_names_a_machine_path_a_release_constant_or_a_key(self):
        for path in steps.DRIVERS.iterdir():
            text = path.read_text()
            self.assertNotIn("/home/", text)
            self.assertNotIn("/tmp/", text)
            self.assertNotRegex(text, r"0x[0-9a-fA-F]{40}\b", path.name)
            self.assertNotRegex(text, r"r3|R3", path.name)


if __name__ == "__main__":
    unittest.main()
