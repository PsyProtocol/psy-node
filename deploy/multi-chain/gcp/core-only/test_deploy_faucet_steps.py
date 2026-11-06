import json
from pathlib import Path
import unittest
import unittest.mock

import deploy_faucet_steps as faucet
import test_deploy_prepare_steps as base
from deploy_remote import OperatorPending, RemoteError, find_secret

HOST = "arc99x2"
ADDRESS = "10.250.0.14:29998"
STEP = faucet.FAUCET_STEPS["start_faucet"]


class FakeRemote:
    """Records stage, report and RPC traffic; the unit state and the faucet answers are set by the test."""

    def __init__(self, ws, ids):
        self.ws, self.ids = ws, ids
        self.report, self.copies, self.scripts, self.claims = None, [], [], []
        self.pid, self.state, self.binary_hash = 0, "active", ws.lock["binaries"]["psy_user_cli"]
        self.restarts = 3
        self.claim_answer, self.inclusion_failure, self.inclusion_calls = None, None, []

    def missing_aliases(self, aliases):
        return []

    sudo = "operator"

    def sudo_mode(self, host):
        return self.sudo

    on_activate = None

    def run_script(self, host, script, timeout):
        self.scripts.append((host, script))
        assert host == HOST
        if " activate " in script and "sha256sum -c -" in script:
            self.activations = getattr(self, "activations", 0) + 1
            if self.on_activate:
                self.on_activate()
            return ""
        if script.startswith("systemctl show"):
            return f"ActiveState={self.state}\nMainPID={self.pid}\nNRestarts={self.restarts}\n"
        if "echo missing" in script:
            if self.report is None:
                return "missing\n"
            return "present\n" + (self.report if isinstance(self.report, str) else json.dumps(self.report))
        if "sha256sum --" in script:
            return self.binary_hash + "  /installed\n"
        if " tx get-status " in script:
            self.inclusion_calls.append(script)
            if self.inclusion_failure:
                raise self.inclusion_failure
            return ""
        if "curl" in script:
            body = json.loads(script.split("<<'PSY_FAUCET_BODY_END'\n", 1)[1].rsplit("\nPSY_FAUCET_BODY_END", 1)[0])
            if body["method"] == "psy_get_psy_faucet_config":
                return json.dumps({"result": {"enabled": True, "operator_user_ids": self.ids}})
            self.claims.append(body["params"])
            return json.dumps(self.claim_answer(body))
        return ""

    def copy_files(self, host, sources, destination, *, timeout_seconds=0):
        self.copies.append((host, sorted(Path(source).name for source in sources), destination))


class FaucetStepTests(base.PrepareTestCase):
    def setUp(self):
        super().setUp()
        ws = self.ws
        ws.lock["hosts"][HOST] = "10.250.0.14"
        (ws.release_dir / "release.json").write_text(json.dumps({"core_placement": {"faucet": HOST}}))
        self.ids = list(range(7, 107))
        operators = json.dumps({"operators": [{"userId": str(i), "privateKey": "k"} for i in self.ids]}).encode()
        ws.lock["faucet"]["operators_sha256"] = base.sha(operators)
        self.package = ws.root / "faucet-out"
        self.package.mkdir()
        (self.package / "operators.json").write_bytes(operators)
        (self.package / "host.json").write_text(json.dumps({"hostname": HOST, "listen_addr": ADDRESS}))
        (self.package / "manifest.json").write_text(json.dumps({
            "release_lock_sha256": "a" * 64, "files": {"prepare_faucet.py": ws.lock["tool_sha256"]["prepare_faucet.py"]}}))
        (ws.state_dir / "prepare_packages.json").write_text(json.dumps({"faucet": str(self.package)}))
        ws.write_local()
        self.remote = FakeRemote(ws, self.ids)
        self.remote.claim_answer = lambda body: {"result": {
            "tx_hash": "0xabc", "operator_user_id": self.ids[0], "amount": "1", "checkpoint_id": 5, "window_id": 0,
            "already_submitted": False}}
        self.ctx = ws.context(self.remote)
        self.ingress = unittest.mock.Mock()
        self.ingress.open_faucet.return_value = {"faucet_host_count": 2}
        for patcher in (unittest.mock.patch.object(faucet, "ingress_module", return_value=self.ingress),
                        unittest.mock.patch.object(faucet, "wait_until", side_effect=lambda ready, failure, *a: (
                            self.assertIsNone(failure()), self.assertTrue(ready())))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def request(self):
        nonce = json.loads((self.ws.state_dir / "start_faucet.json").read_text())["request"]["nonce"]
        return faucet.request_digest(self.ctx, nonce)

    def good_report(self, **changes):
        document = {"lock_sha256": "a" * 64, "request_sha256": self.request(), "unit": self.ws.lock["units"]["faucet"],
                    "pid": 4321, "binary_sha256": self.ws.lock["binaries"]["psy_user_cli"],
                    "operators_sha256": self.ws.lock["faucet"]["operators_sha256"]}
        document.update(changes)
        self.remote.pid = 4321
        return document

    def pending(self):
        with self.assertRaises(OperatorPending) as raised:
            STEP.apply(self.ctx)
        return raised.exception

    def finish(self):
        self.pending()
        self.remote.report = self.good_report()
        STEP.apply(self.ctx)

    def progress(self):
        return json.loads((self.ws.state_dir / "start_faucet.json").read_text())

    def test_passwordless_host_runs_the_command_through_the_remote_instead_of_pending(self):
        self.remote.sudo = "passwordless"
        self.remote.on_activate = lambda: setattr(self.remote, "report", self.good_report())
        STEP.check(self.ctx)
        STEP.apply(self.ctx)
        self.assertEqual(self.remote.activations, 1)
        self.assertEqual(self.progress()["validated"]["pid"], 4321)
        STEP.apply(self.ctx)
        self.assertEqual(self.remote.activations, 1)

    def test_passwordless_host_whose_command_leaves_no_report_fails_loudly(self):
        self.remote.sudo = "passwordless"
        with self.assertRaisesRegex(RuntimeError, "ran but its result is not valid"):
            STEP.apply(self.ctx)

    def test_pending_until_operator_result(self):
        STEP.check(self.ctx)
        pending = self.pending()
        self.assertEqual(pending.host, HOST)
        self.assertIn("a" * 64, pending.command)
        self.assertIn(" activate ", pending.command)
        self.assertIn(self.request(), pending.command)
        self.assertEqual(pending.result_path, faucet.report_path(self.ctx))
        self.assertIn(" && sudo /usr/bin/python3 -I -B ", pending.command)
        self.assertIsNone(find_secret({"command": pending.command}))
        self.assertEqual(self.remote.copies[0][:2], (HOST, ["host.json", "manifest.json", "operators.json"]))
        copies = len(self.remote.copies)
        again = self.pending()
        self.assertEqual((again.host, again.command), (pending.host, pending.command))
        self.assertEqual(len(self.remote.copies), copies)
        self.assertEqual((self.remote.claims, self.ingress.open_faucet.call_count), ([], 0))

    def test_stale_or_foreign_results_show_the_command_again(self):
        first = self.pending()
        for field, value in (("request_sha256", "0" * 64), ("lock_sha256", "b" * 64), ("unit", "other.service"),
                             ("binary_sha256", "c" * 64), ("operators_sha256", "d" * 64), ("pid", 0), ("pid", "7")):
            self.remote.report = self.good_report(**{field: value})
            with self.subTest(field=field, value=value):
                self.assertEqual(self.pending().command, first.command)
        for broken in ({**self.good_report(), "extra": 1}, "not json"):
            self.remote.report = broken
            self.assertEqual(self.pending().command, first.command)
        self.remote.report = self.good_report()
        self.remote.state = "failed"
        self.assertEqual(self.pending().command, first.command)
        self.remote.state, self.remote.binary_hash = "active", "e" * 64
        self.assertEqual(self.pending().command, first.command)
        self.assertIsNone(self.progress()["validated"])
        self.assertEqual(self.ingress.open_faucet.call_count, 0)

    def test_report_of_an_earlier_request_cannot_satisfy_a_new_one(self):
        self.pending()
        old = self.good_report()
        (self.ws.state_dir / "start_faucet.json").unlink()
        fresh = self.pending()
        self.remote.report = old
        self.assertEqual(self.pending().command, fresh.command)

    def test_faucet_fence_removed_only_after_grant(self):
        self.pending()
        self.remote.report = self.good_report()
        self.remote.claim_answer = lambda body: {"error": {"code": -32000, "message": "busy"}}
        with self.assertRaisesRegex(ValueError, "did not authorize the grant"):
            STEP.apply(self.ctx)
        self.assertEqual(self.ingress.open_faucet.call_count, 0)
        self.assertIsNone(self.progress()["fence_removed"])
        self.remote.claim_answer = lambda body: {"result": {
            "tx_hash": "0xabc", "operator_user_id": self.ids[3], "amount": "1", "checkpoint_id": 9, "window_id": 0,
            "already_submitted": False}}
        STEP.apply(self.ctx)
        self.assertEqual(self.remote.claims, [[{"recipient_user_id": 262144}]] * 2)
        self.ingress.open_faucet.assert_called_once_with(self.ctx)
        self.assertEqual(self.progress()["fence_removed"], {"faucet_host_count": 2})

    def test_grant_from_an_operator_outside_the_set_is_refused(self):
        self.pending()
        self.remote.report = self.good_report()
        self.remote.claim_answer = lambda body: {"result": {
            "tx_hash": "0xabc", "operator_user_id": 999, "amount": "1", "checkpoint_id": 9, "window_id": 0,
            "already_submitted": False}}
        with self.assertRaisesRegex(ValueError, "did not authorize"):
            STEP.apply(self.ctx)
        self.assertEqual(self.ingress.open_faucet.call_count, 0)

    def test_operator_set_mismatch_blocks_grant_and_fence(self):
        self.pending()
        self.remote.report = self.good_report()
        self.remote.ids = self.ids[:-1] + [4242]
        with self.assertRaisesRegex(ValueError, "operator set differs"):
            STEP.apply(self.ctx)
        self.assertEqual((self.remote.claims, self.ingress.open_faucet.call_count), ([], 0))

    def test_rerun_after_the_fence_is_removed_changes_nothing(self):
        self.finish()
        copies, claims, opened = len(self.remote.copies), len(self.remote.claims), self.ingress.open_faucet.call_count
        scripts = len(self.remote.scripts)
        STEP.apply(self.ctx)
        self.assertEqual((len(self.remote.copies), len(self.remote.claims), self.ingress.open_faucet.call_count),
                         (copies, claims, opened))
        self.assertEqual(opened, 1)
        self.assertTrue(all("enable" not in s and "restart" not in s and "echo missing" not in s
                            for _, s in self.remote.scripts[scripts:]))

    def test_a_restart_does_not_wedge_the_step(self):
        self.finish()
        scripts = len(self.remote.scripts)
        self.remote.state = "activating"
        STEP.apply(self.ctx)
        STEP.verify(self.ctx)
        self.assertTrue(all("enable" not in s and "restart" not in s for _, s in self.remote.scripts[scripts:]))
        for state in ("failed", "inactive"):
            self.remote.state = state
            with self.assertRaisesRegex(ValueError, "not running.*nothing was restarted"):
                STEP.apply(self.ctx)
        self.remote.state, self.remote.binary_hash = "active", "e" * 64
        with self.assertRaisesRegex(ValueError, "binary differs"):
            STEP.apply(self.ctx)

    def test_activating_unit_is_waited_for_and_failed_unit_stops_the_wait(self):
        with unittest.mock.patch.object(faucet, "wait_until") as waited:
            self.remote.state = "activating"
            faucet.wait_for_faucet(self.ctx)
            failure = waited.call_args.args[1]
            self.assertIsNone(failure())
            self.remote.state = "failed"
            self.assertIn("failed or stopped", failure())
            self.remote.state = "inactive"
            self.assertIn("failed or stopped", failure())

    def test_a_crash_loop_stops_the_wait(self):
        with unittest.mock.patch.object(faucet, "wait_until") as waited:
            self.remote.state = "activating"
            faucet.wait_for_faucet(self.ctx)
            failure = waited.call_args.args[1]
            self.assertIsNone(failure())
            self.remote.restarts = 4
            self.assertIn("restarted while starting", failure())

    def test_inclusion_gates_the_fence_and_a_rerun_never_reclaims(self):
        self.pending()
        self.remote.report = self.good_report()
        self.remote.inclusion_failure = RemoteError("host: exit 1: not included", host=HOST)
        with self.assertRaises(RemoteError):
            STEP.apply(self.ctx)
        self.assertEqual(self.ingress.open_faucet.call_count, 0)
        self.assertIsNone(self.progress()["inclusion"])
        self.assertIsNotNone(self.progress()["grant"])
        self.remote.inclusion_failure = None
        STEP.apply(self.ctx)
        self.assertEqual(len(self.remote.claims), 1)
        self.assertEqual(len(self.remote.inclusion_calls), 2)
        call = self.remote.inclusion_calls[-1]
        for part in ("tx get-status", "--start-checkpoint-id 5", f"--user-id {self.ids[0]}",
                     "--end-user-leaf-hash 0xabc", "PSY_NETWORK=testnet", "/rpc.json", "/canonical.json"):
            self.assertIn(part, call)
        self.assertEqual(self.ingress.open_faucet.call_count, 1)
        STEP.apply(self.ctx)
        self.assertEqual((len(self.remote.inclusion_calls), self.ingress.open_faucet.call_count), (2, 1))

    def test_grant_recipient_defaults_to_a_validator_and_never_an_operator(self):
        self.assertEqual(faucet.grant_recipient(self.ctx), 262144)
        self.ws.local["faucet_grant"] = {"recipient_user_id": self.ids[5]}
        self.ws.write_local()
        with self.assertRaisesRegex(ValueError, "must not be a faucet operator"):
            STEP.check(self.ctx)

    def test_verify_requires_one_authorized_grant(self):
        self.finish()
        report = STEP.verify(self.ctx)
        self.assertEqual(report["faucet"]["operator_count"], 100)
        self.assertEqual(report["faucet"]["grant"]["count"], 1)
        self.assertIsNone(find_secret(report))
        path = self.ws.state_dir / "start_faucet.json"
        original = path.read_text()
        for grant, message in ((None, "exactly one authorized grant"),
                               ({"count": 2, "tx_hash": "0xabc", "operator_user_id": self.ids[0]}, "exactly one"),
                               ({"count": 1, "tx_hash": "", "operator_user_id": self.ids[0]}, "exactly one"),
                               ({"count": 1, "tx_hash": "0xabc", "operator_user_id": 999}, "outside the set")):
            document = json.loads(original)
            document["grant"] = grant
            path.write_text(json.dumps(document))
            with self.subTest(grant=grant), self.assertRaisesRegex(ValueError, message):
                STEP.verify(self.ctx)
        document = json.loads(original)
        document["inclusion"] = None
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "not confirmed on chain"):
            STEP.verify(self.ctx)
        document = json.loads(original)
        document["fence_removed"] = None
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "fence is still in place"):
            STEP.verify(self.ctx)

    def test_check_refuses_a_package_for_another_lock_or_listener(self):
        manifest = self.package / "manifest.json"
        document = json.loads(manifest.read_text())
        manifest.write_text(json.dumps({**document, "release_lock_sha256": "b" * 64}))
        with self.assertRaisesRegex(ValueError, "another release lock"):
            STEP.check(self.ctx)
        manifest.write_text(json.dumps(document))
        (self.package / "host.json").write_text(json.dumps({"hostname": HOST, "listen_addr": "10.250.0.99:29998"}))
        with self.assertRaisesRegex(ValueError, "not the faucet host"):
            STEP.check(self.ctx)


class FaucetPackageBuilderTests(base.PrepareTestCase):
    def setUp(self):
        super().setUp()
        ws = self.ws
        ws.lock["ingress"]["fenced_hosts"] = ["coordinator.x", "coordinator-stg.x", "realm0-stg.x", "realm1-stg.x",
                                              "prove-stg.x", "prove.x"]
        (ws.release_dir / "release.json").write_text(json.dumps({"core_placement": {"faucet": HOST}}))
        binary = b"user-binary"
        self.build = ws.root / "build"
        self.build.mkdir()
        (self.build / "psy_user_cli").write_bytes(binary)
        ws.set_binaries({"psy_user_cli": binary})
        (ws.state_dir / "rebuild_binaries.json").write_text(json.dumps({"build_dir": str(self.build)}))
        ws.put_file("canonical_config", b"canonical", pin=lambda h: ws.lock["inputs"].update(canonical_config=h))
        config = {"defaultNetwork": "testnet", "networks": {"testnet": {
            "magic": "0x1", "coordinator_configs": [{"id": 0, "rpc_url": ["http://10.0.0.1:1"] * 3}],
            "realm_configs": [{"id": 0, "rpc_url": ["http://10.0.0.2:1"], "validators": []},
                              {"id": 1, "rpc_url": ["http://10.0.0.3:1"], "validators": []}],
            "prove_proxy_url": ["https://old"], "system_prove_proxy_url": ["https://kept"],
            "faucet_rpc_url": ["https://kept-faucet"]}}}
        self.config_path = ws.put_file("config", json.dumps(config).encode(),
                                       pin=lambda h: ws.lock["inputs"].update(runtime_config=h))
        self.output = ws.root / "faucet-package"
        ws.local["packages"] = {"faucet": {"faucet_operators": "/ops.json", "output": str(self.output)}}
        ws.write_local()
        self.builder = next(b for b in base.steps.PACKAGE_BUILDERS if b.name == "faucet")

    def test_rpc_config_is_derived_from_files_config_with_public_hosts(self):
        document = json.loads(base.steps.faucet_rpc_bytes(self.ws.context()))["networks"]["testnet"]
        self.assertEqual(document["coordinator_configs"][0]["rpc_url"], ["https://coordinator-stg.x/"])
        self.assertEqual([row["rpc_url"] for row in document["realm_configs"]],
                         [["https://realm0-stg.x/"], ["https://realm1-stg.x/"]])
        self.assertEqual(document["prove_proxy_url"], ["https://prove-stg.x/"])
        self.assertEqual((document["system_prove_proxy_url"], document["faucet_rpc_url"]),
                         (["https://kept"], ["https://kept-faucet"]))
        self.ws.lock["ingress"]["fenced_hosts"].append("prove-stg.y")
        with self.assertRaisesRegex(ValueError, "exactly one prove-stg host"):
            base.steps.faucet_rpc_bytes(self.ws.context())

    def test_builder_passes_derived_hash_and_publishes_atomically(self):
        ws = self.ws
        inputs = ws.local["packages"]["faucet"]

        def fake_run(argv, timeout=None):
            Path(argv[argv.index("--output") + 1]).mkdir()
            return base.done(0)
        with unittest.mock.patch.object(base.steps, "run_local", side_effect=fake_run) as run:
            self.assertEqual(self.builder.build(ws.context(), inputs), self.output)
        argv = run.call_args.args[0]
        derived = base.steps.faucet_rpc_bytes(ws.context())
        self.assertEqual(argv[argv.index("--rpc-sha256") + 1], base.sha(derived))
        self.assertEqual(Path(argv[argv.index("--rpc") + 1]).read_bytes(), derived)
        self.assertEqual(argv[argv.index("--host") + 1], HOST)
        self.assertEqual(argv[argv.index("--release-lock-sha256") + 1], "a" * 64)
        self.assertTrue(self.output.is_dir() and not self.output.with_name("faucet-package.partial").exists())
        ws.lock["binaries"]["psy_user_cli"] = "0" * 64
        self.output.rmdir()
        with self.assertRaisesRegex(ValueError, "differs from the lock"):
            self.builder.build(ws.context(), inputs)


if __name__ == "__main__":
    unittest.main()
