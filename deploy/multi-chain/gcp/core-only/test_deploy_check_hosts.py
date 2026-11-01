import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
import unittest.mock

import deploy_prepare_steps as steps
from deploy_remote import RemoteError, find_secret
from test_deploy_prepare_steps import CHAINS, GIB, PrepareTestCase, run_all, sha


class FakeRemote:
    """Answers the host probe and the root status read from tables; records both kinds of call."""

    def __init__(self, sudo, *, avail=None, states=None, denied=(), l1=None):
        self.sudo, self.avail, self.states, self.denied = sudo, avail or {}, states or {}, set(denied)
        self.l1 = l1
        self.scripts, self.root_calls = [], []

    def sudo_mode(self, host):
        return self.sudo[host]

    def missing_aliases(self, aliases):
        return []

    def run_root_text(self, host, argv, timeout_seconds, *, stdin_text=None, show_stderr=False):
        self.root_calls.append((host, argv, stdin_text))
        self.show_stderr = show_stderr
        return json.dumps(self.l1)

    def run_script(self, host, script, timeout_seconds):
        self.scripts.append((host, script))
        lines = [f"avail={self.avail.get(host, 50 * GIB)}"]
        if self.sudo[host] == "passwordless":
            lines.append("sudo=denied" if host in self.denied else "sudo=ok")
        for match in re.finditer(r"^check (\d+) (.+)$", script, re.MULTILINE):
            path = shlex.split(match.group(2))[0]
            lines.append(f"{match.group(1)} {self.states.get((host, path), 'present')}")
        return "\n".join(lines) + "\n"


class CheckHostsTests(PrepareTestCase):
    CP, SERVICES, OPERATOR = "gcp-test-cp", "gcp-test-services", "arc-test-operator"
    KEYSTORE = "/var/lib/parth/.psy/keystore"

    def setUp(self):
        super().setUp()
        ws = self.ws
        ws.lock["hosts"]["arc-test-operator"] = "10.0.0.50"
        ws.lock["l1"]["signer_host"] = self.SERVICES
        paths = [{"host": self.CP, "path": "/var/lib/test/sealed", "kind": "secret"},
                 {"host": self.CP, "path": "/etc/test-infra", "kind": "infrastructure"},
                 {"host": self.SERVICES, "path": "/etc/parth", "kind": "secret"},
                 {"host": self.SERVICES, "path": self.KEYSTORE, "kind": "secret"},
                 {"host": self.SERVICES, "path": steps.SIGNER_KEYSTORE_FILE, "kind": "secret"},
                 {"host": self.OPERATOR, "path": "/var/lib/parth/.psy", "kind": "secret"},
                 {"host": "local", "path": str(ws.root), "kind": "secret"}]
        (ws.private_dir / "retained-paths.json").write_text(json.dumps({"paths": paths}))
        ws.lock["inputs"]["retained_paths"] = sha((ws.private_dir / "retained-paths.json").read_bytes())
        for chain in CHAINS:
            budget = {"maxGasPriceWei": "10", "maxGasPerTransaction": "500", "maxTotalGas": "1000",
                      "maxNativeSpendWei": "5000", "l1FeeReserveWeiPerTransaction": "1"}
            path = ws.release_dir / f"fresh_l1_gas_budget.{chain}.json"
            path.write_text(json.dumps(budget))
            ws.lock["l1"]["gas_budget_sha256"][chain] = sha(path.read_bytes())
        self.chain_ids = {"sepolia": 11155111, "bscTestnet": 97, "baseSepolia": 84532}
        import deploy_clear_steps
        self.fleet = unittest.mock.patch.object(deploy_clear_steps, "dry_run_fleet", return_value={"hosts": 3})
        self.fleet_mock = self.fleet.start()
        self.addCleanup(self.fleet.stop)

    def reports(self, **changes):
        result = []
        for chain in CHAINS:
            report = {"network": chain, "provider": "own-node", "chain_id": self.chain_ids[chain], "block": 9,
                      "block_age_seconds": 3, "balance_wei": "10000", "gas_price_wei": "7",
                      "signer": self.ws.lock["l1"]["signer"], "nonce_latest": 5, "nonce_pending": 5}
            report.update(changes.get(chain, {}))
            result.append(report)
        return result

    def remote(self, **options):
        sudo = {self.CP: "passwordless", self.SERVICES: "passwordless", self.OPERATOR: "operator"}
        options.setdefault("l1", self.reports())
        return FakeRemote(sudo, **options)

    def run_step(self, remote):
        return run_all(steps.PREPARE_STEPS["check_hosts"], self.ws.context(remote))

    def test_check_hosts_runs_the_clearing_dry_run_over_the_fleet_as_a_gate(self):
        result = self.run_step(self.remote())
        self.fleet_mock.assert_called_once()
        self.assertEqual(result["clear_dry_run"], {"hosts": 3})

    def test_a_fleet_refusal_fails_check_hosts_together_with_the_other_findings(self):
        self.fleet_mock.side_effect = ValueError("gcp-edge-1: 1 refusal(s)\n  key-like name under a clear target: /x/operators.json")
        remote = self.remote(l1=self.reports(baseSepolia={"balance_wei": "9999"}))
        with self.assertRaises(ValueError) as raised:
            self.run_step(remote)
        self.assertIn("operators.json", str(raised.exception))
        self.assertIn("baseSepolia: balance 9999 below required", str(raised.exception))

    def test_the_fleet_gate_never_ends_in_pending(self):
        self.fleet_mock.side_effect = ValueError("refused")
        with self.assertRaises(ValueError):
            self.run_step(self.remote())

    def test_check_hosts_reports_operator_hosts_without_sudo(self):
        remote = self.remote()
        result = self.run_step(remote)
        self.assertEqual(result["operator_hosts"], [self.OPERATOR])
        self.assertEqual(result["hosts"][self.OPERATOR]["sudo"], "operator")
        self.assertEqual(result["hosts"][self.SERVICES]["sudo"], "passwordless")
        operator_scripts = [script for host, script in remote.scripts if host == self.OPERATOR]
        self.assertTrue(operator_scripts)
        self.assertFalse(any("sudo" in script for script in operator_scripts))

    def test_check_hosts_rejects_missing_keystore(self):
        remote = self.remote(states={(self.SERVICES, self.KEYSTORE): "missing"})
        with self.assertRaisesRegex(ValueError, r"retained path #\d+ missing"):
            self.run_step(remote)

    def test_check_hosts_rejects_balance_below_gas_budget(self):
        remote = self.remote(l1=self.reports(baseSepolia={"balance_wei": "9999"}))
        with self.assertRaisesRegex(ValueError, "baseSepolia: balance 9999 below required 10000"):
            self.run_step(remote)

    def test_check_hosts_rejects_pending_nonce_differing_from_latest(self):
        remote = self.remote(l1=self.reports(bscTestnet={"nonce_pending": 6}))
        with self.assertRaisesRegex(ValueError, "bscTestnet: pending nonce 6 differs from latest 5"):
            self.run_step(remote)

    def test_required_balance_is_total_gas_times_the_price_cap_per_chain(self):
        budget = json.loads((self.ws.release_dir / "fresh_l1_gas_budget.sepolia.json").read_text())
        budget["maxTotalGas"], budget["maxGasPriceWei"] = "178000000", "3"
        path = self.ws.release_dir / "fresh_l1_gas_budget.sepolia.json"
        path.write_text(json.dumps(budget))
        self.ws.lock["l1"]["gas_budget_sha256"]["sepolia"] = sha(path.read_bytes())
        remote = self.remote(l1=self.reports(sepolia={"balance_wei": "533999999", "gas_price_wei": "3"}))
        with self.assertRaisesRegex(ValueError, "sepolia: balance 533999999 below required 534000000"):
            self.run_step(remote)
        result = self.run_step(self.remote(l1=self.reports(sepolia={"balance_wei": "534000000", "gas_price_wei": "3"})))
        self.assertEqual(result["l1"]["sepolia"]["required_wei"], "534000000")

    def test_balance_must_also_cover_the_budget_native_spend_limit(self):
        path = self.ws.release_dir / "fresh_l1_gas_budget.sepolia.json"
        budget = json.loads(path.read_text())
        budget["maxNativeSpendWei"] = "20000"
        path.write_text(json.dumps(budget))
        self.ws.lock["l1"]["gas_budget_sha256"]["sepolia"] = sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, "sepolia: balance 10000 below required 20000"):
            self.run_step(self.remote())

    def test_missing_gas_budget_file_fails_check(self):
        (self.ws.release_dir / "fresh_l1_gas_budget.sepolia.json").unlink()
        with self.assertRaisesRegex(ValueError, "gas budget file missing: sepolia"):
            steps.PREPARE_STEPS["check_hosts"].check(self.ws.context(self.remote()))

    def test_gas_budget_file_differing_from_the_lock_fails_check(self):
        (self.ws.release_dir / "fresh_l1_gas_budget.sepolia.json").write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "gas budget sepolia hash differs from the lock"):
            steps.PREPARE_STEPS["check_hosts"].check(self.ws.context(self.remote()))

    def test_current_gas_price_above_the_cap_fails(self):
        remote = self.remote(l1=self.reports(sepolia={"gas_price_wei": "11"}))
        with self.assertRaisesRegex(ValueError, "sepolia: gas price 11 above the approved cap 10"):
            self.run_step(remote)

    def test_report_for_another_signer_or_chain_id_fails(self):
        with self.assertRaisesRegex(ValueError, "sepolia: signer differs from the lock"):
            self.run_step(self.remote(l1=self.reports(sepolia={"signer": "0x" + "1" * 40})))
        with self.assertRaisesRegex(ValueError, "bscTestnet: chain id 1 differs"):
            self.run_step(self.remote(l1=self.reports(bscTestnet={"chain_id": 1})))

    def test_report_missing_a_chain_fails(self):
        with self.assertRaisesRegex(ValueError, "L1 status chains differ"):
            self.run_step(self.remote(l1=self.reports()[:2]))

    def test_l1_status_runs_the_pinned_tool_from_stdin_on_the_signer_host_only_with_the_protected_route(self):
        remote = self.remote()
        self.run_step(remote)
        self.assertEqual([call[0] for call in remote.root_calls], [self.SERVICES])
        _, argv, stdin_text = remote.root_calls[0]
        self.assertEqual(stdin_text, "# fixture fresh_l1.py\n")
        self.assertEqual(argv, steps.STATUS_ARGV)
        self.assertEqual(argv[-2:], ["--rpc-preference", "protected-env-backup"])
        self.assertTrue(remote.show_stderr)

    def test_tool_changed_between_check_and_send_is_refused_by_hashing_the_sent_bytes(self):
        step = steps.PREPARE_STEPS["check_hosts"]
        ctx = self.ws.context(self.remote())
        step.check(ctx)
        (self.ws.tools_dir / "fresh_l1.py").write_text("# swapped\n")
        with self.assertRaisesRegex(ValueError, "tool hash differs: fresh_l1.py"):
            step.verify(ctx)

    def test_changed_helper_fails_check_before_it_is_sent(self):
        (self.ws.tools_dir / "fresh_l1.py").write_text("# edited\n")
        remote = self.remote()
        with self.assertRaisesRegex(ValueError, "tool hash differs: fresh_l1.py"):
            self.run_step(remote)
        self.assertEqual(remote.root_calls, [])

    def test_result_never_carries_urls_or_secret_looking_text(self):
        result = self.run_step(self.remote())
        self.assertIsNone(find_secret(result))
        self.assertNotIn("http", json.dumps(result))
        self.assertEqual(set(result["l1"]), set(CHAINS))
        self.assertEqual(result["l1"]["sepolia"]["nonce"], 5)

    def test_unreadable_status_output_names_the_failure_without_the_output(self):
        remote = self.remote(l1="not json")
        with self.assertRaisesRegex(ValueError, "L1 status output is not a JSON list"):
            self.run_step(remote)

    def test_low_disk_fails_naming_the_host(self):
        remote = self.remote(avail={self.CP: steps.MIN_HOST_FREE_BYTES - 1})
        with self.assertRaisesRegex(ValueError, f"{self.CP}: free disk"):
            self.run_step(remote)

    def test_host_without_no_prompt_sudo_fails(self):
        with self.assertRaisesRegex(ValueError, f"{self.CP}: no-prompt sudo denied"):
            self.run_step(self.remote(denied=[self.CP]))

    def test_denied_stat_on_an_operator_host_is_unverified_not_a_failure(self):
        remote = self.remote(states={(self.OPERATOR, "/var/lib/parth/.psy"): "denied"})
        result = self.run_step(remote)
        self.assertEqual(result["hosts"][self.OPERATOR]["unverified_paths"], 1)

    def test_denied_stat_on_a_no_prompt_host_fails(self):
        remote = self.remote(states={(self.CP, "/var/lib/test/sealed"): "denied"})
        with self.assertRaisesRegex(ValueError, "cannot stat retained path #"):
            self.run_step(remote)

    def test_missing_operator_host_path_fails(self):
        remote = self.remote(states={(self.OPERATOR, "/var/lib/parth/.psy"): "missing"})
        with self.assertRaisesRegex(ValueError, r"retained path #\d+ missing"):
            self.run_step(remote)

    def test_only_secret_kind_paths_are_statted_and_stat_is_used_never_a_read(self):
        remote = self.remote()
        self.run_step(remote)
        scripts = "\n".join(script for host, script in remote.scripts)
        self.assertIn("/var/lib/test/sealed", scripts)
        self.assertNotIn("/etc/test-infra", scripts)
        self.assertRegex(scripts, r"stat -c %F --")
        for forbidden in ("cat ", "head ", "tail ", "base64", "xxd", "< /"):
            self.assertNotIn(forbidden, scripts)

    def test_local_retained_path_is_checked_without_reading(self):
        retained = json.loads((self.ws.private_dir / "retained-paths.json").read_text())
        retained["paths"][-1]["path"] = str(self.ws.root / "absent")
        (self.ws.private_dir / "retained-paths.json").write_text(json.dumps(retained))
        self.ws.lock["inputs"]["retained_paths"] = sha((self.ws.private_dir / "retained-paths.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "local retained path #0 missing"):
            self.run_step(self.remote())

    def test_retained_paths_differing_from_the_lock_hash_are_refused(self):
        self.ws.lock["inputs"]["retained_paths"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "retained-paths.json differs from the lock"):
            steps.PREPARE_STEPS["check_hosts"].check(self.ws.context(self.remote()))

    def test_signer_host_is_the_single_host_retaining_the_rpc_config_and_the_keystore(self):
        retained = json.loads((self.ws.private_dir / "retained-paths.json").read_text())
        retained["paths"].append({"host": self.CP, "path": "/etc/parth", "kind": "secret"})
        retained["paths"].append({"host": self.CP, "path": self.KEYSTORE, "kind": "secret"})
        (self.ws.private_dir / "retained-paths.json").write_text(json.dumps(retained))
        self.ws.lock["inputs"]["retained_paths"] = sha((self.ws.private_dir / "retained-paths.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "differs from the retained paths"):
            self.run_step(self.remote())

    def test_signer_host_without_no_prompt_sudo_fails_clearly(self):
        remote = self.remote()
        remote.sudo[self.SERVICES] = "operator"
        with self.assertRaisesRegex(ValueError, "signer host needs no-prompt sudo"):
            self.run_step(remote)

    def test_every_host_of_the_release_is_probed_once(self):
        remote = self.remote()
        self.run_step(remote)
        probed = sorted(host for host, script in remote.scripts)
        self.assertEqual(probed, sorted([self.CP, self.SERVICES, self.OPERATOR]))

    def test_pending_nonce_failure_names_the_likely_cause(self):
        remote = self.remote(l1=self.reports(sepolia={"nonce_pending": 6}))
        with self.assertRaisesRegex(ValueError, "old Relayer may still be broadcasting"):
            self.run_step(remote)

    def test_budget_deploy_would_refuse_is_refused_by_check_hosts(self):
        for chain, change, message in (("baseSepolia", {"l1FeeReserveWeiPerTransaction": "0"}, "Base L1 data-fee"),
                                       ("sepolia", {"maxGasPerTransaction": "0"}, "invalid gas budget"),
                                       ("bscTestnet", {"surplus": "1"}, "gas budget required")):
            path = self.ws.release_dir / f"fresh_l1_gas_budget.{chain}.json"
            original = path.read_text()
            path.write_text(json.dumps({**json.loads(original), **change}))
            self.ws.lock["l1"]["gas_budget_sha256"][chain] = sha(path.read_bytes())
            with self.subTest(chain=chain), self.assertRaisesRegex(ValueError, message):
                steps.PREPARE_STEPS["check_hosts"].check(self.ws.context(self.remote()))
            path.write_text(original)
            self.ws.lock["l1"]["gas_budget_sha256"][chain] = sha(original.encode())

    def test_signer_host_must_match_the_lock_and_retain_the_keystore_file(self):
        self.ws.lock["l1"]["signer_host"] = self.CP
        with self.assertRaisesRegex(ValueError, f"signer host {self.CP} differs from the retained paths"):
            steps.PREPARE_STEPS["check_hosts"].check(self.ws.context(self.remote()))
        self.ws.lock["l1"]["signer_host"] = self.SERVICES
        retained = json.loads((self.ws.private_dir / "retained-paths.json").read_text())
        retained["paths"] = [item for item in retained["paths"] if item["path"] != steps.SIGNER_KEYSTORE_FILE]
        (self.ws.private_dir / "retained-paths.json").write_text(json.dumps(retained))
        self.ws.lock["inputs"]["retained_paths"] = sha((self.ws.private_dir / "retained-paths.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "does not retain the signer keystore file"):
            steps.PREPARE_STEPS["check_hosts"].check(self.ws.context(self.remote()))

    def test_every_failure_is_collected_before_the_step_fails(self):
        remote = self.remote(
            avail={self.CP: 1}, denied=[self.SERVICES], states={(self.OPERATOR, "/var/lib/parth/.psy"): "missing"},
            l1=self.reports(sepolia={"balance_wei": "1"}, bscTestnet={"nonce_pending": 9}))
        with self.assertRaises(ValueError) as caught:
            self.run_step(remote)
        lines = str(caught.exception).splitlines()
        self.assertTrue(any("free disk" in line for line in lines) and any("no-prompt sudo denied" in line for line in lines))
        self.assertTrue(any("retained path #0 missing" in line for line in lines))
        self.assertTrue(any("sepolia: balance" in line for line in lines) and any("bscTestnet: pending" in line for line in lines))

    def test_a_failing_host_does_not_stop_the_other_checks(self):
        remote = self.remote()
        original = remote.run_script
        def flaky(host, script, timeout_seconds):
            if host == self.CP:
                raise RemoteError(f"{host}: exit 255: unreachable", host=host)
            return original(host, script, timeout_seconds)
        remote.run_script = flaky
        with self.assertRaises(ValueError) as caught:
            self.run_step(remote)
        self.assertIn("gcp-test-cp: exit 255", str(caught.exception))
        self.assertEqual(len(remote.root_calls), 1)

    def test_every_failure_message_survives_the_operator_output_filter(self):
        from deploy_remote import redact_tail
        states = {(self.OPERATOR, "/var/lib/parth/.psy"): "missing", (self.CP, "/var/lib/test/sealed"): "denied"}
        remote = self.remote(avail={self.CP: 1}, denied=[self.SERVICES], states=states,
                             l1=self.reports(sepolia={"nonce_pending": 9}))
        with self.assertRaises(ValueError) as caught:
            self.run_step(remote)
        self.assertNotIn("[redacted line]", redact_tail(str(caught.exception), 4000))

    def test_failure_reaches_the_operator_through_deploy_main_unredacted(self):
        import contextlib, io
        import deploy
        import test_deploy
        from deploy_remote import Step
        workspace = test_deploy.build_workspace(Path(tempfile.mkdtemp(dir=self.ws.root)))
        release_dir, private_dir, access_file, run_dir, steps_file = workspace
        remote = self.remote(states={(self.SERVICES, "/etc/parth"): "missing"}, denied=[self.CP])
        def fail(ctx):
            failures = []
            steps.probe_host(ctx, self.SERVICES, ["/etc/parth"], failures)
            steps.probe_host(ctx, self.CP, [], failures)
            raise ValueError("\n".join(failures))
        registry = {"alpha": Step("alpha", fail, lambda ctx: None, lambda ctx: {})}
        steps_file.write_text("50\tpy:alpha\tplain\n")
        argv = ["alpha", "--release-dir", str(release_dir), "--access", str(access_file), "--run-dir", str(run_dir),
                "--private-dir", str(private_dir), "--steps-file", str(steps_file)]
        err = io.StringIO()
        with unittest.mock.patch.object(deploy, "Remote", return_value=remote), contextlib.redirect_stderr(err):
            code = deploy.main(argv, registry=registry)
        self.assertEqual(code, 1)
        self.assertIn("retained path #0 missing", err.getvalue())
        self.assertIn("no-prompt sudo denied", err.getvalue())
        self.assertNotIn("[redacted line]", err.getvalue())

    def test_probe_script_runs_in_real_bash_and_reports_present_missing_and_denied(self):
        base = Path(tempfile.mkdtemp(dir=self.ws.root))
        (base / "here").write_text("x")
        locked = base / "locked"
        locked.mkdir()
        (locked / "inner").write_text("x")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        paths = [str(base / "here"), str(base / "absent"), str(locked / "inner")]
        done = subprocess.run(["/usr/bin/bash", "-s"], input=steps.probe_script("operator", paths).encode(),
                              capture_output=True, timeout=30)
        values, states = steps.parse_probe("local", done.stdout.decode(), 3)
        self.assertGreater(int(values["avail"]), 0)
        self.assertEqual((states["0"], states["1"]), ("present", "missing"))
        self.assertEqual(states["2"], "present" if os.geteuid() == 0 else "denied")
        self.assertNotIn("sudo", steps.probe_script("operator", paths))


if __name__ == "__main__":
    unittest.main()
