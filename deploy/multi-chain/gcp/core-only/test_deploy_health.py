"""Tests of the L2 stability evaluation and the chain sample reader; no host is touched."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import deploy_health as health
from deploy_health import ChainSample, evaluate_l2_stability
from deploy_remote import RemoteConnectionError, RemoteError

EDGES = [f"edge-{index}" for index in range(9)]
UNITS = ("unit-a", "unit-b")


def sample(height=1000, *, lag=None, silent=(), restarts=0, panics=(), uploads=None, pids=None):
    """One sample: every edge at `height`, except `lag` edges behind and `silent` edges with no answer.

    Proof uploads grow with the height unless fixed.
    """
    lag = lag or {}
    heights = {name: (None if name in silent else height - lag.get(name, 0)) for name in EDGES}
    count = (height - 1000) // 2 if uploads is None else uploads
    return ChainSample(heights, {unit: restarts for unit in UNITS}, tuple(panics), count, pids or {})


def run(heights, **options):
    return [sample(height, **options) for height in heights]


class EvaluateStabilityTests(unittest.TestCase):
    def test_unfinished_run_returns_none(self):
        self.assertIsNone(evaluate_l2_stability(run([1000, 1010, 1050]), 100))
        self.assertIsNone(evaluate_l2_stability(run([1000]), 100))

    def test_stability_passes_at_100_checkpoints(self):
        self.assertEqual(evaluate_l2_stability(run([1000, 1050, 1100]), 100), "passed")
        self.assertIsNone(evaluate_l2_stability(run([1000, 1050, 1099]), 100))

    def test_stability_fails_on_checkpoint_regression(self):
        samples = run([1000, 1020, 1010])
        with self.assertRaisesRegex(ValueError, "regress"):
            evaluate_l2_stability(samples, 100)

    def test_regression_of_one_edge_is_caught_even_when_others_advance(self):
        samples = run([1000, 1020, 1040])
        samples[2] = ChainSample({**samples[2].edge_checkpoint_ids, "edge-3": 1005}, samples[2].unit_restart_counts, (), 5)
        with self.assertRaisesRegex(ValueError, "edge-3"):
            evaluate_l2_stability(samples, 100)

    def test_stability_fails_on_any_restart(self):
        for count in (1, 3):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "restart"):
                evaluate_l2_stability([sample(1000, restarts=count), sample(1010)], 100)

    def test_restart_between_samples_is_caught_through_the_counter(self):
        with self.assertRaisesRegex(ValueError, "unit-a"):
            evaluate_l2_stability([sample(1000), ChainSample({n: 1010 for n in EDGES}, {"unit-a": 1, "unit-b": 0}, (), 5)], 100)

    def test_a_unit_missing_from_a_later_sample_is_not_a_restart(self):
        first = ChainSample({n: 1000 for n in EDGES}, {"unit-a": 0}, (), 5)
        second = ChainSample({n: 1010 for n in EDGES}, {"unit-a": 0}, (), 5)
        third = ChainSample({n: 1020 for n in EDGES}, {}, (), 5)
        self.assertIsNone(evaluate_l2_stability([first, second, third], 100))

    def test_stability_fails_on_panic_line(self):
        with self.assertRaisesRegex(ValueError, "panic"):
            evaluate_l2_stability([sample(1000), sample(1010, panics=("unit-a: thread main panicked at x.rs:1",))], 100)

    def test_stability_tolerates_single_rpc_timeout(self):
        samples = run([1000, 1010, 1020], silent=())
        samples[1] = sample(1010, silent=("edge-4",))
        self.assertIsNone(evaluate_l2_stability(samples, 100))
        samples += run([1060, 1100])
        self.assertEqual(evaluate_l2_stability(samples, 100), "passed")

    def test_timeouts_that_are_not_consecutive_are_tolerated(self):
        samples = [sample(1000 + 10 * index, silent=("edge-4",) if index % 3 != 2 else ()) for index in range(12)]
        self.assertEqual(evaluate_l2_stability(samples, 100), "passed")

    def test_stability_fails_after_three_consecutive_timeouts(self):
        samples = [sample(1000), *[sample(1010 + 10 * index, silent=("edge-4",)) for index in range(3)]]
        with self.assertRaisesRegex(ValueError, "edge-4"):
            evaluate_l2_stability(samples, 100)
        two = samples[:3]
        self.assertIsNone(evaluate_l2_stability(two, 100))

    def test_stability_tolerates_one_sample_lag_between_edges(self):
        samples = [sample(1000), sample(1050, lag={"edge-2": 30}), sample(1100)]
        self.assertEqual(evaluate_l2_stability(samples, 100), "passed")

    def test_read_skew_of_one_checkpoint_is_not_divergence(self):
        samples = [sample(1000 + 25 * index, lag={"edge-2": 1}) for index in range(5)]
        self.assertEqual(evaluate_l2_stability(samples, 100), "passed")

    def test_stability_fails_on_lasting_edge_divergence(self):
        samples = [sample(1000), sample(1050, lag={"edge-2": 30}), sample(1100, lag={"edge-2": 60})]
        with self.assertRaisesRegex(ValueError, "edge-2"):
            evaluate_l2_stability(samples, 100)

    def test_lagging_final_sample_waits_instead_of_passing(self):
        samples = [sample(1000), sample(1100, lag={"edge-2": 30})]
        self.assertIsNone(evaluate_l2_stability(samples, 100))

    def test_final_sample_with_a_silent_edge_waits_instead_of_passing(self):
        samples = [sample(1000), sample(1100, silent=("edge-5",))]
        self.assertIsNone(evaluate_l2_stability(samples, 100))

    def test_stability_requires_real_proof_uploads(self):
        samples = run([1000, 1100], uploads=0)
        self.assertIsNone(evaluate_l2_stability(samples, 100))
        samples[1] = sample(1100, uploads=1)
        self.assertIsNone(evaluate_l2_stability(samples, 100))
        samples[1] = sample(1100, uploads=100 // health.CHECKPOINTS_PER_UPLOAD)
        self.assertEqual(evaluate_l2_stability(samples, 100), "passed")

    def test_uploads_are_judged_by_growth_in_the_run_not_by_the_total(self):
        samples = run([1000, 1100], uploads=900)
        self.assertIsNone(evaluate_l2_stability(samples, 100))

    def test_an_unread_worker_host_does_not_fake_growth_or_hide_it(self):
        samples = [sample(1000, uploads=40), sample(1050, uploads=-1), sample(1100, uploads=90)]
        self.assertEqual(evaluate_l2_stability(samples, 100), "passed")
        samples = [sample(1000, uploads=-1), sample(1100, uploads=-1)]
        self.assertIsNone(evaluate_l2_stability(samples, 100))

    def test_a_chain_that_stops_advancing_fails_after_six_samples(self):
        self.assertIsNone(evaluate_l2_stability(run([1000] * 6), 100))
        with self.assertRaisesRegex(ValueError, "did not advance in 6 samples"):
            evaluate_l2_stability(run([1000] * 7), 100)
        self.assertIsNone(evaluate_l2_stability(run([1000] * 4 + [1001] + [1001] * 4), 100))

    def test_a_changed_main_process_is_a_restart_even_with_a_zero_counter(self):
        samples = [sample(1000, pids={"unit-a": 10}), sample(1010, pids={"unit-a": 11})]
        with self.assertRaisesRegex(ValueError, "unit-a changed its main process"):
            evaluate_l2_stability(samples, 100)
        self.assertIsNone(evaluate_l2_stability([sample(1000, pids={"unit-a": 10}), sample(1010, pids={"unit-a": 10})], 100))

    def test_lag_carries_across_a_silent_sample(self):
        samples = [sample(1000, lag={"edge-2": 30}), sample(1010, silent=("edge-2",)), sample(1020, lag={"edge-2": 30})]
        with self.assertRaisesRegex(ValueError, "edge-2"):
            evaluate_l2_stability(samples, 100)
        caught_up = [sample(1000, lag={"edge-2": 30}), sample(1010), sample(1020, silent=("edge-2",)), sample(1030, lag={"edge-2": 5})]
        self.assertIsNone(evaluate_l2_stability(caught_up, 100))

    def test_the_gate_ceiling_is_required_times_11_seconds_twice(self):
        self.assertEqual(health.gate_limit_seconds(100), 2200)


TOPOLOGY = {"hosts": {"host-cp": "10.0.0.25", "host-e1": "10.0.0.36", "host-e2": "10.0.0.35"},
            "coordinator": {"host": "host-cp", "edge_ports": [15370, 15371, 15372], "ingress_port": 15369},
            "realms": [{"id": 0, "validators": [{"edge_host": "host-e1", "http_port": 15380 + i} for i in range(3)]},
                       {"id": 1, "validators": [{"edge_host": "host-e2", "http_port": 15383 + i} for i in range(3)]}]}


class EdgeTargetTests(unittest.TestCase):
    def test_running_coordinator_edges_the_ingress_and_six_realm_edges(self):
        targets = health.edge_targets(TOPOLOGY, 3)
        self.assertEqual(len(targets), 10)
        self.assertEqual([t.name for t in targets[:5]],
                         ["coordinator-0", "coordinator-1", "coordinator-2", "coordinator-ingress", "realm-0-v1"])
        self.assertEqual((targets[0].host, targets[0].address, targets[0].port), ("host-cp", "10.0.0.25", 15370))
        self.assertEqual((targets[3].host, targets[3].address, targets[3].port), ("host-cp", "10.0.0.25", 15369))
        self.assertEqual((targets[9].host, targets[9].address, targets[9].port), ("host-e2", "10.0.0.35", 15385))
        starting = [t.name for t in health.edge_targets(TOPOLOGY, 1)]
        self.assertEqual(starting[:3], ["coordinator-0", "coordinator-ingress", "realm-0-v1"])
        self.assertEqual(len(starting), 8)


class ParseHostReportTests(unittest.TestCase):
    def test_edge_values_timeouts_and_garbage(self):
        output = "\n".join(['edge a {"jsonrpc":"2.0","id":1,"result":42}', "edge b timeout", 'edge c {"error":{"code":-1}}',
                            "edge d not json", 'edge e {"result":-3}', 'edge f {"result":true}'])
        report = health.parse_host_report(output)
        self.assertEqual(report.edges, {"a": 42, "b": None, "c": None, "d": None, "e": None, "f": None})

    def test_units_panics_and_uploads(self):
        output = "\n".join(["unit u1 LoadState=loaded ActiveState=active MainPID=11 NRestarts=0 ",
                            "unit u2 LoadState=loaded ActiveState=active MainPID=12 NRestarts=2 ",
                            "panic u1 thread 'x' panicked at src/lib.rs:1", "uploads 17"])
        report = health.parse_host_report(output)
        self.assertEqual(report.restarts, {"u1": 0, "u2": 2})
        self.assertEqual(report.pids, {"u1": 11, "u2": 12})
        self.assertEqual(report.panics, ("u1: thread 'x' panicked at src/lib.rs:1",))
        self.assertEqual(report.uploads, 17)
        self.assertEqual(health.parse_host_report("").uploads, -1)

    def test_a_unit_that_is_not_loaded_and_active_is_a_failure(self):
        for state in ("LoadState=not-found ActiveState=inactive", "LoadState=loaded ActiveState=failed",
                      "LoadState=loaded ActiveState=activating"):
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, "u9"):
                health.parse_host_report(f"unit u9 {state} MainPID=0 NRestarts=0 ")

    def test_a_unit_without_a_main_process_or_counter_is_a_failure(self):
        with self.assertRaisesRegex(ValueError, "u9"):
            health.parse_host_report("unit u9 LoadState=loaded ActiveState=active MainPID=0 NRestarts=0 ")
        with self.assertRaisesRegex(ValueError, "u9"):
            health.parse_host_report("unit u9 LoadState=loaded ActiveState=active MainPID=5 NRestarts= ")

    def test_a_unit_without_a_log_line_proves_nothing_and_fails(self):
        with self.assertRaisesRegex(ValueError, "u9 has no log lines"):
            health.parse_host_report("unit u9 LoadState=loaded ActiveState=active MainPID=5 NRestarts=0 \nnolog u9")

    def test_garbage_lines_are_a_failure(self):
        with self.assertRaises(ValueError):
            health.parse_host_report("edge only-two")


class BashRemote:
    """Runs the generated scripts in a real bash with fake systemctl, journalctl and curl: exit statuses are real."""

    def __init__(self, directory, *, panic="", log=True, edge_answer=True):
        self.directory, self.calls = Path(directory), []
        self.env = {"PATH": f"{self.directory}:/usr/bin:/bin", "FAKE_PANIC": panic, "FAKE_LOG": "yes" if log else "none",
                    "FAKE_CURL": "ok" if edge_answer else "fail"}
        self.write("systemctl", 'case "$*" in\n *ActiveEnterTimestamp*) echo "Tue 2026-10-27 10:06:29 UTC";;\n'
                   ' *) printf "LoadState=loaded\\nActiveState=active\\nMainPID=42\\nNRestarts=0\\n";;\nesac\n')
        self.write("journalctl", 'case "$*" in\n *"-n 1"*) [ "$FAKE_LOG" = none ] || echo "a log line";;\n'
                   ' *"-g"*) if [ -n "$FAKE_PANIC" ]; then echo "$FAKE_PANIC"; exit 0; fi; exit 1;;\nesac\n')
        self.write("curl", '[ "$FAKE_CURL" = ok ] || exit 28\necho \'{"jsonrpc":"2.0","id":1,"result":123}\'\n')

    def write(self, name, body):
        path = self.directory / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def run(self, host, script):
        script = script.replace("/usr/bin/curl", str(self.directory / "curl"))
        self.calls.append(host)
        done = subprocess.run(["/usr/bin/bash", "-s"], input=script.encode(), capture_output=True, env=self.env, timeout=60)
        if done.returncode != 0:
            raise RemoteError(f"{host}: exit {done.returncode}", host=host, exit_code=done.returncode)
        return done.stdout.decode()

    def run_script(self, host, script, timeout_seconds):
        return self.run(host, script)

    def run_root_text(self, host, argv, timeout, *, stdin_text=None, show_stderr=False):
        return self.run(host, stdin_text)


class ReadChainSampleTests(unittest.TestCase):
    def setUp(self):
        import test_deploy_core_steps as fixtures
        self.fixtures = fixtures
        self.fixture = fixtures.CoreFixture()
        self.addCleanup(self.fixture.close)
        self.tools = tempfile.TemporaryDirectory()
        self.addCleanup(self.tools.cleanup)

    def sample_with(self, remote):
        return health.read_chain_sample(self.fixture.context(remote), 1)

    def test_the_scripts_exit_zero_when_the_journal_search_finds_nothing(self):
        # journalctl --grep exits 1 on no match; the sample must still be taken.
        sample_value = self.sample_with(BashRemote(self.tools.name))
        self.assertEqual(sample_value.panic_lines, ())
        self.assertEqual(len(sample_value.unit_restart_counts), 17)
        self.assertEqual(set(sample_value.unit_main_pids.values()), {42})
        self.assertEqual(set(sample_value.edge_checkpoint_ids.values()), {123})
        self.assertEqual(sample_value.proof_upload_count, 0)

    def test_panic_lines_are_collected_and_a_unit_without_logs_fails_the_sample(self):
        sample_value = self.sample_with(BashRemote(self.tools.name, panic="thread x panicked at y.rs:1"))
        self.assertEqual(len(sample_value.panic_lines), 17)
        with self.assertRaisesRegex(ValueError, "has no log lines"):
            self.sample_with(BashRemote(self.tools.name, log=False))

    def test_edges_are_read_in_one_pass_from_one_host_before_the_unit_pass(self):
        remote = BashRemote(self.tools.name)
        self.sample_with(remote)
        self.assertEqual(remote.calls[0], health.EDGE_READER_HOST)
        self.assertEqual(len(remote.calls), 1 + 7)
        script = health.edge_script(health.edge_targets(self.fixture.topology, 1))
        self.assertEqual(script.count("&\n"), 8)
        self.assertIn("\nwait\n", script)

    def test_an_edge_that_does_not_answer_is_none_not_a_failure(self):
        sample_value = self.sample_with(BashRemote(self.tools.name, edge_answer=False))
        self.assertEqual(set(sample_value.edge_checkpoint_ids.values()), {None})

    def test_unreachable_edge_reader_gives_silent_edges_and_a_real_failure_raises(self):
        remote = self.fixtures.FakeRemote(self.fixture, active=True)
        remote.broken[health.EDGE_READER_HOST] = [RemoteConnectionError("x: exit 255", host="x", exit_code=255)]
        value = health.read_chain_sample(self.fixture.context(remote), 1)
        self.assertEqual(set(value.edge_checkpoint_ids.values()), {None})
        self.assertEqual(len(value.unit_restart_counts), 17)
        remote.broken[health.EDGE_READER_HOST] = [RemoteError("x: exit 1: boom", host="x", exit_code=1)]
        with self.assertRaises(RemoteError):
            health.read_chain_sample(self.fixture.context(remote), 1)

    def test_a_silent_unit_host_omits_its_units_only(self):
        remote = self.fixtures.FakeRemote(self.fixture, active=True)
        remote.broken["gcp-edge-1"] = [RemoteConnectionError("x: exit 255", host="x", exit_code=255)]
        value = health.read_chain_sample(self.fixture.context(remote), 1)
        self.assertEqual(len(value.unit_restart_counts), 14)
        self.assertEqual(set(value.edge_checkpoint_ids.values()), {1000})

    def test_a_unit_that_is_not_active_is_a_failure_not_a_silent_host(self):
        remote = self.fixtures.FakeRemote(self.fixture, active=True)
        host = "gcp-edge-2"
        remote.set_state(host, self.fixture.unit_sets()[host].units[:1], active="failed")
        with self.assertRaisesRegex(ValueError, "not loaded and active"):
            health.read_chain_sample(self.fixture.context(remote), 1)

    def test_restart_counts_come_from_the_listed_units_only(self):
        remote = self.fixtures.FakeRemote(self.fixture, active=True)
        value = health.read_chain_sample(self.fixture.context(remote), 1)
        self.assertEqual(len(value.unit_restart_counts), 14 + 3)
        self.assertEqual(len(value.edge_checkpoint_ids), 8)
        self.assertEqual(value.proof_upload_count, 7)
        scripts = [health.unit_script(units, None) for units in health.core_units(self.fixture.context(remote), 1).values()]
        for script in scripts:
            self.assertNotIn("psy-core-*", script)
            self.assertIn("NRestarts", script)
            self.assertIn("-n 1 -o cat", script)
            self.assertIn('--since "$since"', script)
            self.assertIn("return 0", script)


class UnreachableRuleTests(unittest.TestCase):
    def test_only_connection_loss_and_time_limits_count_as_silent(self):
        self.assertTrue(health.is_unreachable(RemoteConnectionError("c", host="h", exit_code=255)))
        self.assertTrue(health.is_unreachable(RemoteError("h: timed out after 120s", host="h")))
        for code in (124, 137):
            self.assertTrue(health.is_unreachable(RemoteError("h: timed out on the remote", host="h", exit_code=code)))
        self.assertFalse(health.is_unreachable(RemoteError("h: exit 1: boom", host="h", exit_code=1)))
        self.assertFalse(health.is_unreachable(RemoteError("h: not in the access file", host="h")))


if __name__ == "__main__":
    unittest.main()
