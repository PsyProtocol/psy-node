"""Tests of steps 61-64 with a fake Remote; nothing here touches a host."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import clear_host_state
import deploy
import deploy_clear_steps as steps
import release_lock
import test_release_lock
from deploy_remote import DeployContext, OperatorPending, RemoteError
from test_deploy_prepare_steps import Workspace, sha

GCP = Path(__file__).resolve().parents[3] / "gcp"
OPERATOR_HOSTS = ("arc99x1", "arc99x2", "arc99x3")
CONTAINERS = {"scylla-server": "scylla", "valkey-server": "valkey", "nats-server": "nats", "parth-postgres": "postgres",
              "nostr-relay": "nostr"}


class FakeRemote:
    HOME = "/home/op"

    def __init__(self, lock, operator_hosts=OPERATOR_HOSTS):
        self.lock, self.operator, self.calls, self.files = lock, set(operator_hosts), [], {}
        self.images = dict(lock["images"])
        self.overrides, self.apply_overrides, self.cleared, self.valkey_policy = {}, {}, set(), "noeviction"
        self.copies, self.scripts, self.fail_install = [], [], None
        self.owner_problem, self.live_active, self.live_present = False, set(), set()
        self.core_active = []

    def sudo_mode(self, host):
        return "operator" if host in self.operator else "passwordless"

    def tool_calls(self, apply=None):
        found = [call for call in self.calls if call[1][:4] == steps.ROOT_PYTHON and call[1][4].startswith("--")]
        if apply is not None:
            found = [call for call in found if ("--apply" in call[1]) is apply]
        return found

    def run_root_text(self, host, argv, timeout, *, stdin_text=None, show_stderr=False):
        self.calls.append((host, list(argv), stdin_text))
        if argv[:4] == steps.ROOT_PYTHON and argv[4].startswith("--"):
            return json.dumps(self.tool_report(host, argv[4:]))
        if argv[:4] == steps.ROOT_PYTHON:
            report = {"ok": True, "component": argv[4], "read_write": True}
            if argv[4] == "valkey":
                report["maxmemory_policy"] = self.valkey_policy
            if argv[4] == "nostr":
                report["event_id"] = "e" * 64
            if argv[4] == "nostr-read":
                report["event_id"] = argv[5]
            return json.dumps(report)
        if argv[0] == steps.DOCKER:
            return self.images[CONTAINERS[argv[-1]]] + "\n"
        if argv[0] == "/usr/bin/systemctl":
            return "".join(f"{unit} loaded active running x\n" for unit in self.core_active)
        if argv[0] == "/usr/bin/env" and self.fail_install == host:
            raise RemoteError(f"{host}: exit 1: install failed", host=host, exit_code=1)
        return ""

    def tool_report(self, host, flags):
        args = clear_host_state.parse_args(flags)
        apply = args.apply
        clear = json.loads(args.clear_paths)
        plan = {"clear": clear, "allow": json.loads(args.clear_allow), "stop": json.loads(args.stop_units),
                "keep": json.loads(args.keep_units), "containers": json.loads(args.containers)}
        existing = [] if host in self.cleared else clear
        if apply:
            self.cleared.add(host)
        rows = [] if args.skip_retained_hash else [
            {"path": "/fixture/keep", "kind": "file", "class": "secret", "sha256": "ab" * 32, "sha256_after": None}]
        report = {"host": host, "applied": apply, "cleared": existing, "absent": [], "refused": [],
                  "stopped": plan["stop"] if apply else [], "disabled": plan["stop"] if apply else [],
                  "containers_removed": plan["containers"] if apply else [],
                  "active_listed": [] if apply or host in self.cleared else plan["stop"], "unlisted_active": [],
                  "active_kept": [], "retained": rows, "retained_unchanged": True if apply else None, "error": None,
                  "request_sha256": clear_host_state.request_digest(host, plan, args.retained_paths_sha256,
                                                                   args.release_lock_sha256),
                  "lock_sha256": args.release_lock_sha256, "address": args.address}
        report.update(self.overrides.get(host, {}))
        if apply:
            report.update(self.apply_overrides.get(host, {}))
        return report

    def operator_file_text(self, script):
        match = re.search(r"(/\S*-result\.json)", script)
        return self.files.get(match.group(1)) if match else None

    def run_script(self, host, script, timeout_seconds):
        self.scripts.append((host, script))
        if 'printf %s "$HOME"' in script:
            return self.HOME
        if "<<'" in script and "--skip-retained-hash" in script:
            line = script.split("<<'")[0].strip().splitlines()[-1]
            return json.dumps(self.tool_report(host, shlex.split(line)[4:]))
        if "rm -f" in script:
            for key in [key for key in self.files if key.endswith("-result.json") and key.startswith(self.HOME)]:
                del self.files[key]
            return ""
        if "cat --" in script:
            if self.owner_problem:
                raise RemoteError(f"{host}: exit 4: owner", host=host, exit_code=4)
            text = self.operator_file_text(script)
            if text is None:
                raise RemoteError(f"{host}: exit 3: missing", host=host, exit_code=3)
            return text
        if "is-active" in script:
            lines = []
            for index, unit in re.findall(r"^unit (\d+) (\S+)$", script, re.MULTILINE):
                lines.append(f"unit {index} {'active' if unit in self.live_active else 'inactive'}")
            for index, rest in re.findall(r"^path (\d+) (.+)$", script, re.MULTILINE):
                lines.append(f"path {index} {'present' if shlex.split(rest)[0] in self.live_present else 'absent'}")
            return "\n".join(lines) + "\n"
        return ""

    def read_text(self, host, path):
        raise AssertionError("operator results are read through run_script with an owner check")

    def copy_files(self, host, sources, destination, **options):
        self.copies.append((host, [Path(source).name for source in sources], destination))


class ClearStepTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ws = Workspace(temp.name)
        self.ws.lock["hosts"].update({"gcp-scylla": "10.0.0.23", "gcp-redis": "10.0.0.12", "gcp-nats": "10.0.0.20",
                                      "gcp-postgres": "10.0.0.24", "gcp-nostr": "10.0.0.29"})
        (self.ws.release_dir / "topology.json").write_text(json.dumps({
            "hosts": {"gcp-test-cp": "10.0.0.25"},
            "infrastructure": {"scylla_db_url": "10.0.0.23:9042", "redis_url": "redis://10.0.0.12:6379",
                               "nats_jetstream_url": "nats://10.0.0.20:4222"}}))
        self.write_retirement()
        self.remote = FakeRemote(self.ws.lock)
        patcher = patch.object(steps, "TOOLS_DIR", self.ws.tools_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.password_file = Path(temp.name) / "pg-password"
        self.password_file.write_text("hunter2-secret\n")
        (self.ws.private_dir / "local-inputs.json").write_text(json.dumps(
            {"databases": {"postgres_password_file": str(self.password_file)}}))
        self.ws.lock["images"]["nostr"] = "scsibug/nostr-rs-relay@sha256:" + "f" * 64
        self.ws.lock["nostr"] = {"home": "/opt/nostr-relay-test", "network": "nostr-test_net"}

    def write_retirement(self, mutate=None):
        retired, retained = test_release_lock.build_test_retirement()
        for alias, entry in retired["hosts"].items():
            entry["stop"], entry["containers"], entry["clear"] = [f"psy-old-{alias}.service"], [], [f"/opt/psy-old/{alias}"]
        for engine in steps.ENGINES:
            retired["hosts"][engine.host]["containers"] = [engine.container, "extra-old-container"]
        if mutate:
            mutate(retired, retained)
        (self.ws.private_dir / "retired-state.json").write_text(json.dumps(retired))
        (self.ws.private_dir / "retained-paths.json").write_text(json.dumps(retained))
        for name, key in (("retired-state.json", "retired_state"), ("retained-paths.json", "retained_paths")):
            self.ws.lock["inputs"][key] = sha((self.ws.private_dir / name).read_bytes())
        self.retired, self.retained = retired, retained

    def ctx(self):
        raw = json.dumps(self.ws.lock).encode()
        (self.ws.release_dir / "release-lock.json").write_bytes(raw)
        return DeployContext(lock=self.ws.lock, lock_sha256=hashlib.sha256(raw).hexdigest(),
                             release_dir=self.ws.release_dir, run_dir=self.ws.run_dir, remote=self.remote,
                             private_dir=self.ws.private_dir, state_dir=self.ws.state_dir)

    # --- registry
    def test_steps_are_registered_cutover_and_named_like_the_table(self):
        self.assertEqual(set(steps.CLEAR_STEPS), {"stop_services", "stop_operator_hosts", "clear_node_state",
                                                  "rebuild_databases"})
        for name, step in steps.CLEAR_STEPS.items():
            self.assertTrue(step.cutover and step.name == name)
        registry = deploy.build_registry(deploy.STEP_MODULES)
        table = Path(__file__).resolve().parents[1] / "fresh-192-20261030" / "steps.tsv"
        self.assertEqual([name for name in deploy.unregistered_steps(table, registry) if name in steps.CLEAR_STEPS], [])
        self.assertEqual(deploy.mismatched_cutover_steps(table, registry), [])

    # --- step 61
    def test_stop_uses_only_listed_units(self):
        steps.CLEAR_STEPS["stop_services"].apply(self.ctx())
        hosts = sorted(set(self.retired["hosts"]) - set(OPERATOR_HOSTS))
        self.assertEqual(sorted(call[0] for call in self.remote.tool_calls(apply=True)), hosts)
        for host, argv, _ in self.remote.tool_calls(apply=True):
            args = clear_host_state.parse_args(argv[4:])
            self.assertEqual(json.loads(args.stop_units), self.retired["hosts"][host]["stop"])
            self.assertEqual(json.loads(args.clear_paths), [], "stopping must not clear")
            self.assertEqual(json.loads(args.containers), [])

    def test_stop_never_touches_retained_units(self):
        def retain_a_forwarder(retired, retained):
            entry = retired["hosts"]["gcp-gateway"]
            unit = "/etc/systemd/system/psy-forward.service"
            entry["retain"] = sorted(entry["retain"] + [unit])
            retained["paths"].append({"host": "gcp-gateway", "path": unit, "kind": "secret"})
        self.write_retirement(retain_a_forwarder)
        steps.CLEAR_STEPS["stop_services"].apply(self.ctx())
        call = next(call for call in self.remote.tool_calls(apply=True) if call[0] == "gcp-gateway")
        args = clear_host_state.parse_args(call[1][4:])
        self.assertIn("psy-forward.service", json.loads(args.keep_units))
        self.assertNotIn("psy-forward.service", json.loads(args.stop_units))

    def test_stop_refuses_a_list_that_stops_a_retained_unit(self):
        def stop_the_forwarder(retired, retained):
            entry = retired["hosts"]["gcp-gateway"]
            entry["stop"] = ["psy-forward.service"]
            entry["retain"] = sorted(entry["retain"] + ["/etc/systemd/system/psy-forward.service"])
            retained["paths"].append({"host": "gcp-gateway", "path": "/etc/systemd/system/psy-forward.service",
                                      "kind": "secret"})
        self.write_retirement(stop_the_forwarder)
        with self.assertRaisesRegex(ValueError, "stops a retained unit"):
            steps.CLEAR_STEPS["stop_services"].apply(self.ctx())
        self.assertFalse(self.remote.calls)

    def test_stop_verify_fails_on_unlisted_business_unit(self):
        self.remote.overrides["gcp-edge-1"] = {"unlisted_active": ["parth-surprise.service"]}
        with self.assertRaisesRegex(ValueError, "gcp-edge-1.*parth-surprise.service"):
            steps.CLEAR_STEPS["stop_services"].verify(self.ctx())

    def test_stop_verify_fails_when_a_listed_unit_is_still_active(self):
        self.remote.overrides["gcp-edge-1"] = {"active_listed": ["psy-old-gcp-edge-1.service"]}
        with self.assertRaisesRegex(ValueError, "still active"):
            steps.CLEAR_STEPS["stop_services"].verify(self.ctx())

    def test_stop_verify_passes_and_run_dir_result_has_counts_only(self):
        steps.CLEAR_STEPS["stop_services"].apply(self.ctx())
        result = steps.CLEAR_STEPS["stop_services"].verify(self.ctx())
        self.assertNotIn("gcp-test-cp", result["hosts"])
        self.assertEqual(result["hosts"]["gcp-edge-1"], {"listed_units": 1, "still_active": 0, "retained_units_active": 0})

    def test_stop_rerun_with_everything_stopped_is_a_no_op_success(self):
        step = steps.CLEAR_STEPS["stop_services"]
        step.apply(self.ctx())
        step.apply(self.ctx())
        step.verify(self.ctx())

    def test_tool_arguments_are_accepted_by_the_tool_and_carry_the_hashes(self):
        steps.CLEAR_STEPS["stop_services"].apply(self.ctx())
        host, argv, stdin = self.remote.tool_calls(apply=True)[0]
        args = clear_host_state.parse_args(argv[4:])
        self.assertEqual(args.release_lock_sha256, self.ctx().lock_sha256)
        self.assertEqual(hashlib.sha256(args.retained_paths[len("inline:"):].encode()).hexdigest(),
                         args.retained_paths_sha256)
        self.assertEqual(stdin, (self.ws.tools_dir / steps.TOOL).read_text())
        self.assertIn("--exit-zero-with-report", argv)

    def test_a_tool_that_differs_from_the_lock_is_not_sent(self):
        (self.ws.tools_dir / steps.TOOL).write_text("# tampered\n")
        with self.assertRaisesRegex(ValueError, "tool hash differs"):
            steps.CLEAR_STEPS["stop_services"].apply(self.ctx())
        self.assertFalse(self.remote.calls)

    # --- step 62
    def test_operator_stop_is_pending_until_result_exists(self):
        ctx = self.ctx()
        with self.assertRaises(OperatorPending) as raised:
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(ctx)
        pending = raised.exception
        self.assertEqual(pending.host, "arc99x1")
        self.assertIn(ctx.lock_sha256, pending.command)
        self.assertIn(self.ws.lock["tool_sha256"][steps.TOOL], pending.command)
        self.assertIn("--apply", pending.command)
        self.assertEqual(pending.result_path, steps.operator_result_path(ctx, "arc99x1"))
        self.assertEqual([copy[1] for copy in self.remote.copies], [[steps.TOOL, "release-lock.json"],
                                                                    ["operator-arc99x1-retained.json"]])
        self.assertFalse(self.remote.tool_calls(), "an operator host is never reached with sudo")

    def operator_result(self, host, **changes):
        retired, retained = steps.retirement(self.ctx())
        request = steps.make_request(retired, retained, host)
        report = {"host": host, "applied": True, "cleared": request.clear, "absent": [], "stopped": request.stop,
                  "containers_removed": [], "unlisted_active": [], "retained_unchanged": True, "error": None,
                  "retained": [{"path": "/fixture/keep", "kind": "file", "class": "secret", "sha256": "ab" * 32,
                                "sha256_after": "ab" * 32}],
                  "request_sha256": request.digest(self.ctx().lock_sha256), "lock_sha256": self.ctx().lock_sha256}
        report.update(changes)
        self.remote.files[steps.operator_result_path(self.ctx(), host)] = json.dumps(report)

    def test_operator_rerun_with_valid_results_continues(self):
        for host in OPERATOR_HOSTS:
            self.operator_result(host)
        step = steps.CLEAR_STEPS["stop_operator_hosts"]
        step.apply(self.ctx())
        result = step.verify(self.ctx())
        self.assertEqual(sorted(result["hosts"]), list(OPERATOR_HOSTS))
        self.assertFalse(self.remote.copies, "nothing is staged again")

    def test_operator_second_host_is_next_in_line(self):
        self.operator_result("arc99x1")
        with self.assertRaises(OperatorPending) as raised:
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())
        self.assertEqual(raised.exception.host, "arc99x2")

    def test_operator_result_for_another_request_is_stale_and_replaced(self):
        self.operator_result("arc99x1", request_sha256="0" * 64)
        with self.assertRaises(OperatorPending):
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())
        self.assertTrue(any("rm -f" in script for _, script in self.remote.scripts))

    def test_operator_result_for_another_lock_is_stale(self):
        self.operator_result("arc99x1", lock_sha256="1" * 64)
        with self.assertRaises(OperatorPending):
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())

    def test_operator_failed_result_raises_and_is_removed_so_the_next_run_stages_again(self):
        self.operator_result("arc99x1", error="1 refusal(s); nothing was changed")
        with self.assertRaisesRegex(ValueError, "operator run failed"):
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())
        with self.assertRaises(OperatorPending):
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())

    def test_operator_changed_secret_is_a_failure(self):
        self.operator_result("arc99x1", retained_unchanged=False)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())

    def test_operator_verify_needs_every_result(self):
        self.operator_result("arc99x1")
        with self.assertRaisesRegex(ValueError, "arc99x2.*no valid operator result"):
            steps.CLEAR_STEPS["stop_operator_hosts"].verify(self.ctx())

    # --- step 63
    def test_clear_touches_only_cloud_non_database_hosts(self):
        step = steps.CLEAR_STEPS["clear_node_state"]
        step.check(self.ctx())
        step.apply(self.ctx())
        hosts = {call[0] for call in self.remote.tool_calls(apply=True)}
        self.assertTrue(hosts and not hosts & (set(OPERATOR_HOSTS) | steps.DATABASE_HOSTS))
        for host, argv, _ in self.remote.tool_calls(apply=True):
            args = clear_host_state.parse_args(argv[4:])
            self.assertEqual(json.loads(args.clear_paths), self.retired["hosts"][host]["clear"])
            self.assertEqual(json.loads(args.stop_units), [])

    def test_clear_check_is_read_only_and_refuses_the_whole_step_on_one_refusal(self):
        self.remote.overrides["gcp-edge-2"] = {"refused": ["key-like name under a clear target: /opt/x/operators.json"],
                                               "error": "1 refusal(s); nothing was changed"}
        with self.assertRaisesRegex(ValueError, "(?s)gcp-edge-2.*operators.json"):
            steps.CLEAR_STEPS["clear_node_state"].check(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))

    def test_clear_check_reports_every_refusing_host(self):
        for host in ("gcp-edge-1", "gcp-edge-2"):
            self.remote.overrides[host] = {"refused": ["nope"], "error": "refused"}
        with self.assertRaises(ValueError) as raised:
            steps.CLEAR_STEPS["clear_node_state"].check(self.ctx())
        self.assertIn("gcp-edge-1", str(raised.exception))
        self.assertIn("gcp-edge-2", str(raised.exception))

    def test_clear_apply_stops_at_the_first_failure_and_records_nothing(self):
        self.remote.overrides["gcp-edge-1"] = {"error": "a retained secret changed during the clear"}
        with self.assertRaisesRegex(ValueError, "retained secret changed"):
            steps.CLEAR_STEPS["clear_node_state"].apply(self.ctx())
        self.assertFalse((self.ws.state_dir / "clear_node_state.json").exists())

    def test_clear_verify_requires_clear_done_and_operator_results(self):
        step = steps.CLEAR_STEPS["clear_node_state"]
        step.apply(self.ctx())
        with self.assertRaisesRegex(ValueError, "no valid operator result"):
            step.verify(self.ctx())
        for host in OPERATOR_HOSTS:
            self.operator_result(host)
        result = step.verify(self.ctx())
        self.assertEqual(sorted(result["operator_hosts"]), list(OPERATOR_HOSTS))
        self.assertNotIn("/", json.dumps(result), "no path may reach the run directory")

    def test_clear_verify_fails_when_listed_paths_remain(self):
        step = steps.CLEAR_STEPS["clear_node_state"]
        step.apply(self.ctx())
        self.remote.overrides["gcp-edge-1"] = {"cleared": ["/opt/psy-old/gcp-edge-1"]}
        for host in OPERATOR_HOSTS:
            self.operator_result(host)
        with self.assertRaisesRegex(ValueError, "still exist"):
            step.verify(self.ctx())

    def test_clear_verify_fails_when_retained_digest_moved(self):
        step = steps.CLEAR_STEPS["clear_node_state"]
        step.apply(self.ctx())
        self.remote.overrides["gcp-edge-1"] = {"retained": [{"path": "/fixture/keep", "kind": "file",
                                                             "sha256": "cd" * 32, "sha256_after": None}]}
        for host in OPERATOR_HOSTS:
            self.operator_result(host)
        with self.assertRaisesRegex(ValueError, "differs from the baseline"):
            step.verify(self.ctx())

    # --- step 64
    def test_rebuild_rejects_mutable_image(self):
        for key in ("scylla", "valkey", "nats", "postgres", "nostr"):
            with self.subTest(key=key):
                lock = json.loads(json.dumps(self.ws.lock))
                lock["images"][key] = "scylladb/scylla:latest"
                self.ws.lock["images"], saved = lock["images"], self.ws.lock["images"]
                with self.assertRaisesRegex(ValueError, "pinned by digest"):
                    steps.check_images(self.ctx())
                self.ws.lock["images"] = saved

    def test_rebuild_check_confirms_database_hosts_equal_the_topology(self):
        steps.CLEAR_STEPS["rebuild_databases"].check(self.ctx())
        self.ws.lock["hosts"]["gcp-redis"] = "10.0.0.99"
        with self.assertRaisesRegex(ValueError, "gcp-redis.*topology"):
            steps.CLEAR_STEPS["rebuild_databases"].check(self.ctx())

    def test_rebuild_check_needs_a_real_password(self):
        self.password_file.write_text("change-me\n")
        with self.assertRaisesRegex(ValueError, "placeholder"):
            steps.CLEAR_STEPS["rebuild_databases"].check(self.ctx())

    def test_rebuild_check_is_read_only(self):
        steps.CLEAR_STEPS["rebuild_databases"].check(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))
        self.assertFalse([call for call in self.calls_of("/usr/bin/env")])
        self.assertFalse(self.remote.copies)

    def calls_of(self, program):
        return [call for call in self.remote.calls if call[1][0] == program]

    def test_rebuild_installs_every_engine_from_the_lock_image(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        step.apply(self.ctx())
        installs = {call[0]: call[1] for call in self.calls_of("/usr/bin/env")}
        self.assertEqual(sorted(installs), sorted(engine.host for engine in steps.ENGINES))
        for engine in steps.ENGINES:
            self.assertIn(f"{engine.image_var}={self.ws.lock['images'][engine.image_key]}", installs[engine.host])
        self.assertIn(f"NOSTR_RELAY_HOME={self.ws.lock['nostr']['home']}", installs["gcp-nostr"])
        self.assertIn(f"NOSTR_RELAY_NETWORK={self.ws.lock['nostr']['network']}", installs["gcp-nostr"])
        applied = {call[0]: clear_host_state.parse_args(call[1][4:]) for call in self.remote.tool_calls(apply=True)}
        for engine in steps.ENGINES:
            self.assertEqual(json.loads(applied[engine.host].containers), self.retired["hosts"][engine.host]["containers"])
            self.assertEqual(json.loads(applied[engine.host].clear_paths), self.retired["hosts"][engine.host]["clear"])

    def test_postgres_password_travels_on_stdin_never_in_arguments(self):
        steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        call = next(call for call in self.calls_of("/usr/bin/env") if call[0] == "gcp-postgres")
        self.assertEqual(call[2], "hunter2-secret")
        self.assertNotIn("hunter2-secret", " ".join(call[1]))
        for other in self.remote.calls:
            self.assertNotIn("hunter2-secret", " ".join(other[1]))

    def test_installer_files_are_hash_checked_on_the_host_before_running(self):
        steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        order = [call[1][0] for call in self.remote.calls if call[0] == "gcp-redis"]
        self.assertLess(order.index("/usr/bin/sha256sum"), order.index("/usr/bin/env"))
        listing = next(call[2] for call in self.remote.calls if call[0] == "gcp-redis" and call[1][0] == "/usr/bin/sha256sum")
        script = GCP / "remote" / "install-valkey.sh"
        self.assertIn(f"{hashlib.sha256(script.read_bytes()).hexdigest()}  /tmp/install-valkey.sh", listing)

    def test_rebuild_rerun_does_not_wipe_a_verified_database_again(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        step.apply(self.ctx())
        wipes, installs = len(self.remote.tool_calls(apply=True)), len(self.calls_of("/usr/bin/env"))
        step.apply(self.ctx())
        self.assertEqual((len(self.remote.tool_calls(apply=True)), len(self.calls_of("/usr/bin/env"))), (wipes, installs))
        step.verify(self.ctx())

    def test_rebuild_failure_midway_keeps_finished_hosts_and_redoes_only_the_failed_one(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        self.remote.fail_install = "gcp-nats"
        with self.assertRaises(RemoteError):
            step.apply(self.ctx())
        record = json.loads((self.ws.state_dir / "rebuild_databases.json").read_text())["hosts"]
        self.assertEqual(sorted(record), ["gcp-redis", "gcp-scylla"])
        self.remote.fail_install = None
        before = len(self.remote.tool_calls(apply=True))
        step.apply(self.ctx())
        redone = [call[0] for call in self.remote.tool_calls(apply=True)][before:]
        self.assertEqual(redone, ["gcp-nats", "gcp-postgres", "gcp-nostr"])

    def test_rebuild_does_not_record_a_host_that_failed_its_probe(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        self.remote.valkey_policy = "allkeys-lru"
        with self.assertRaisesRegex(ValueError, "noeviction"):
            step.apply(self.ctx())
        record = json.loads((self.ws.state_dir / "rebuild_databases.json").read_text())["hosts"]
        self.assertEqual(sorted(record), ["gcp-scylla"])

    def test_rebuild_verify_checks_noeviction_live(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        step.apply(self.ctx())
        self.assertEqual(step.verify(self.ctx())["hosts"]["gcp-redis"]["maxmemory_policy"], "noeviction")
        self.remote.valkey_policy = "volatile-lru"
        with self.assertRaisesRegex(ValueError, "noeviction"):
            step.verify(self.ctx())
        probes = [call for call in self.remote.calls if call[1][:4] == steps.ROOT_PYTHON and call[1][4] == "valkey"]
        self.assertTrue(probes and all("probe_databases" not in " ".join(call[1]) for call in probes))

    def test_rebuild_verify_refuses_a_container_that_runs_another_image(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        step.apply(self.ctx())
        self.remote.images["nats"] = "nats@sha256:" + "9" * 64
        with self.assertRaisesRegex(ValueError, "locked image"):
            step.verify(self.ctx())

    def test_rebuild_verify_needs_a_record_for_every_host(self):
        with self.assertRaisesRegex(ValueError, "no rebuild record"):
            steps.CLEAR_STEPS["rebuild_databases"].verify(self.ctx())


    # ---- fix round 1
    def all_hosts(self):
        return sorted(self.retired["hosts"])

    def test_dry_run_fleet_runs_the_full_request_everywhere_without_apply(self):
        result = steps.dry_run_fleet(self.ctx())
        cloud = sorted(set(self.all_hosts()) - set(OPERATOR_HOSTS))
        self.assertEqual(sorted(call[0] for call in self.remote.tool_calls()), cloud)
        for host, argv, _ in self.remote.tool_calls():
            self.assertNotIn("--apply", argv)
            args = clear_host_state.parse_args(argv[4:])
            entry = self.retired["hosts"][host]
            self.assertEqual((json.loads(args.stop_units), json.loads(args.clear_paths), json.loads(args.containers)),
                             (entry["stop"], entry["clear"], entry["containers"]))
        operator_scripts = [script for host, script in self.remote.scripts if "--skip-retained-hash" in script]
        self.assertEqual(len(operator_scripts), len(OPERATOR_HOSTS))
        for script in operator_scripts:
            self.assertNotIn("sudo", script)
            self.assertNotIn("--apply", script)
        self.assertEqual(result["hosts"], len(self.all_hosts()))

    def test_dry_run_fleet_names_every_refusing_host_and_changes_nothing(self):
        self.remote.overrides["gcp-edge-1"] = {"refused": ["key-like name under a clear target: /opt/x/operators.json"],
                                               "error": "1 refusal(s); nothing was changed"}
        self.remote.overrides["arc99x2"] = {"refused": ["cannot scan /opt/psy-faucet/x: Permission denied"],
                                            "error": "1 refusal(s); nothing was changed"}
        with self.assertRaisesRegex(ValueError, "(?s)arc99x2.*Permission denied.*gcp-edge-1.*operators.json"):
            steps.dry_run_fleet(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))

    def test_dry_run_fleet_fails_on_an_unlisted_active_unit_even_when_nothing_is_cleared(self):
        self.remote.overrides["gcp-gateway"] = {"unlisted_active": ["psy-surprise.timer"]}
        with self.assertRaisesRegex(ValueError, "gcp-gateway.*psy-surprise.timer"):
            steps.dry_run_fleet(self.ctx())

    def test_dry_run_fleet_checks_the_postgres_password_file(self):
        self.password_file.write_text("change-me\n")
        with self.assertRaisesRegex(ValueError, "placeholder"):
            steps.dry_run_fleet(self.ctx())
        self.assertFalse(self.remote.calls)

    def test_dry_run_fleet_passes_the_address_the_lock_holds(self):
        steps.dry_run_fleet(self.ctx())
        by_host = {call[0]: clear_host_state.parse_args(call[1][4:]) for call in self.remote.tool_calls()}
        self.assertEqual(by_host["gcp-scylla"].address, "10.0.0.23")
        self.assertIsNone(by_host["gcp-edge-1"].address, "no address is held for this host")

    def test_stop_check_repeats_the_fleet_dry_run(self):
        steps.CLEAR_STEPS["stop_services"].check(self.ctx())
        self.assertEqual(len(self.remote.tool_calls()), len(self.all_hosts()) - len(OPERATOR_HOSTS))
        self.remote.overrides["gcp-edge-2"] = {"refused": ["nope"], "error": "refused"}
        with self.assertRaisesRegex(ValueError, "gcp-edge-2"):
            steps.CLEAR_STEPS["stop_services"].check(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))

    def test_a_timer_in_a_stop_list_passes_the_validator_and_the_tool_arguments(self):
        def add_timer(retired, retained):
            retired["hosts"]["gcp-realm-processor"]["stop"] = ["psy-indexer-r3-mirror.timer", "psy-x.service"]
        self.write_retirement(add_timer)
        steps.dry_run_fleet(self.ctx())

    # --- baseline
    def baseline_path(self):
        return self.ws.state_dir / "retained_baseline.json"

    def test_clear_records_a_once_only_baseline_before_the_first_delete(self):
        steps.CLEAR_STEPS["clear_node_state"].apply(self.ctx())
        host = steps.node_hosts(self.ctx(), self.retired["hosts"])[0]
        calls = [call for call in self.remote.calls if call[0] == host and call[1][:4] == steps.ROOT_PYTHON]
        self.assertEqual(["--apply" in call[1] for call in calls], [False, True], "a read-only pass comes first")
        baseline = json.loads(self.baseline_path().read_text())
        self.assertEqual(baseline["lock_sha256"], self.ctx().lock_sha256)
        self.assertEqual(baseline["hosts"][host]["/fixture/keep"], {"kind": "file", "sha256": "ab" * 32})

    def test_a_retained_change_is_not_forgotten_by_a_rerun(self):
        step = steps.CLEAR_STEPS["clear_node_state"]
        self.remote.apply_overrides["gcp-edge-1"] = {"retained_unchanged": False,
                                                    "error": "a retained secret changed during the clear"}
        with self.assertRaisesRegex(ValueError, "retained secret changed"):
            step.apply(self.ctx())
        self.remote.apply_overrides.clear()
        recorded = self.baseline_path().read_text()
        self.remote.overrides["gcp-edge-1"] = {"retained": [{"path": "/fixture/keep", "kind": "file", "class": "secret",
                                                             "sha256": "cd" * 32, "sha256_after": "cd" * 32}]}
        with self.assertRaisesRegex(ValueError, "differs from the baseline"):
            step.apply(self.ctx())
        self.assertEqual(self.baseline_path().read_text(), recorded, "a baseline is written once")

    def test_a_missing_retained_secret_fails_before_any_delete(self):
        self.remote.overrides["gcp-edge-1"] = {"retained": [{"path": "/fixture/keep", "kind": "missing", "class": "secret",
                                                             "sha256": None, "sha256_after": None}]}
        with self.assertRaisesRegex(ValueError, "missing"):
            steps.CLEAR_STEPS["clear_node_state"].apply(self.ctx())
        self.assertFalse([call for call in self.remote.tool_calls(apply=True) if call[0] == "gcp-edge-1"])

    def test_the_baseline_is_bound_to_the_lock(self):
        self.baseline_path().write_text(json.dumps({"lock_sha256": "9" * 64, "hosts": {}}))
        with self.assertRaisesRegex(ValueError, "another release lock"):
            steps.CLEAR_STEPS["clear_node_state"].apply(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))

    def test_operator_results_are_recorded_and_compared_with_the_baseline(self):
        self.operator_result("arc99x1")
        step = steps.CLEAR_STEPS["stop_operator_hosts"]
        with self.assertRaises(OperatorPending):
            step.apply(self.ctx())
        baseline = json.loads(self.baseline_path().read_text())
        self.assertIn("arc99x1", baseline["hosts"])
        self.operator_result("arc99x1", retained=[{"path": "/fixture/keep", "kind": "file", "class": "secret",
                                                   "sha256": "cd" * 32, "sha256_after": "cd" * 32}])
        with self.assertRaisesRegex(ValueError, "differs from the baseline"):
            step.apply(self.ctx())

    def test_rebuild_compares_with_the_baseline_before_wiping(self):
        self.baseline_path().write_text(json.dumps({"lock_sha256": self.ctx().lock_sha256, "hosts": {
            "gcp-scylla": {"/fixture/keep": {"kind": "file", "sha256": "00" * 32}}}}))
        with self.assertRaisesRegex(ValueError, "differs from the baseline"):
            steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))

    # --- operators
    def test_operator_files_live_in_a_private_directory_below_the_home(self):
        with self.assertRaises(OperatorPending) as raised:
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())
        self.assertIn(f"{FakeRemote.HOME}/.psy-release-", raised.exception.command)
        self.assertNotIn("/tmp/", raised.exception.command)
        self.assertTrue(raised.exception.result_path.startswith(FakeRemote.HOME + "/.psy-release-"))
        stage = next(script for host, script in self.remote.scripts if "install -d" in script)
        self.assertIn("-m 0700", stage)

    def test_an_operator_result_with_the_wrong_owner_or_mode_is_refused(self):
        self.operator_result("arc99x1")
        self.remote.owner_problem = True
        with self.assertRaisesRegex(ValueError, "owner or mode"):
            steps.CLEAR_STEPS["stop_operator_hosts"].apply(self.ctx())

    def test_operator_verify_checks_the_live_state_unprivileged(self):
        for host in OPERATOR_HOSTS:
            self.operator_result(host)
        step = steps.CLEAR_STEPS["stop_operator_hosts"]
        step.verify(self.ctx())
        self.remote.live_active = {"psy-old-arc99x2.service"}
        with self.assertRaisesRegex(ValueError, "arc99x2.*still active"):
            step.verify(self.ctx())
        self.remote.live_active = set()
        self.remote.live_present = {"/opt/psy-old/arc99x3"}
        with self.assertRaisesRegex(ValueError, "arc99x3.*still exist"):
            step.verify(self.ctx())
        probes = [script for _, script in self.remote.scripts if "is-active" in script]
        self.assertTrue(probes and all("sudo" not in script for script in probes))

    def test_clear_verify_checks_the_operator_hosts_live_as_well(self):
        step = steps.CLEAR_STEPS["clear_node_state"]
        step.apply(self.ctx())
        for host in OPERATOR_HOSTS:
            self.operator_result(host)
        self.remote.live_present = {"/opt/psy-old/arc99x1"}
        with self.assertRaisesRegex(ValueError, "arc99x1.*still exist"):
            step.verify(self.ctx())

    # --- step 64 marker
    def test_the_rebuild_record_is_bound_to_the_lock_and_the_request(self):
        steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        record = json.loads((self.ws.state_dir / "rebuild_databases.json").read_text())
        self.assertEqual(record["lock_sha256"], self.ctx().lock_sha256)
        for host, row in record["hosts"].items():
            self.assertEqual(len(row["request_sha256"]), 64)
        self.ws.lock["images"]["nats"] = "nats@sha256:" + "9" * 64
        wipes = len(self.remote.tool_calls(apply=True))
        with self.assertRaisesRegex(ValueError, "another lock|another image|request"):
            steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        self.assertEqual(len(self.remote.tool_calls(apply=True)), wipes, "never wiped again")

    def test_a_changed_request_never_wipes_a_recorded_host_again(self):
        steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        wipes = len(self.remote.tool_calls(apply=True))

        def other_clear(retired, retained):
            retired["hosts"]["gcp-redis"]["clear"] = ["/var/lib/parth/redis", "/var/lib/parth/extra"]
        self.write_retirement(other_clear)
        record = json.loads((self.ws.state_dir / "rebuild_databases.json").read_text())
        (self.ws.state_dir / "rebuild_databases.json").write_text(json.dumps(
            {**record, "lock_sha256": self.ctx().lock_sha256}))
        with self.assertRaisesRegex(ValueError, "request differs"):
            steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        self.assertEqual(len(self.remote.tool_calls(apply=True)), wipes)

    def test_an_unreadable_rebuild_record_is_a_failure_not_nothing_recorded(self):
        (self.ws.state_dir / "rebuild_databases.json").write_text("{not json")
        with self.assertRaises(ValueError):
            steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))
        self.assertFalse(self.calls_of("/usr/bin/env"))

    def test_rebuild_refuses_while_a_core_unit_is_active_on_the_coordinator_host(self):
        self.remote.core_active = [self.ws.lock["units"]["core_prefix"] + "coordinator-processor.service"]
        with self.assertRaisesRegex(ValueError, "core unit.*active.*gcp-cp-ce"):
            steps.CLEAR_STEPS["rebuild_databases"].apply(self.ctx())
        self.assertFalse(self.remote.tool_calls(apply=True))
        self.assertFalse(self.calls_of("/usr/bin/env"))

    def test_a_core_unit_check_runs_even_when_the_records_are_lost(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        step.apply(self.ctx())
        (self.ws.state_dir / "rebuild_databases.json").unlink()
        self.remote.core_active = [self.ws.lock["units"]["core_prefix"] + "x.service"]
        wipes = len(self.remote.tool_calls(apply=True))
        with self.assertRaisesRegex(ValueError, "core unit"):
            step.apply(self.ctx())
        self.assertEqual(len(self.remote.tool_calls(apply=True)), wipes)

    def test_the_nostr_write_probe_runs_once_per_run_and_verify_reads_that_event_back(self):
        step = steps.CLEAR_STEPS["rebuild_databases"]
        step.apply(self.ctx())
        step.verify(self.ctx())
        writes = [call for call in self.remote.calls if call[1][:4] == steps.ROOT_PYTHON and call[1][4] == "nostr"]
        reads = [call for call in self.remote.calls if call[1][:4] == steps.ROOT_PYTHON and call[1][4] == "nostr-read"]
        self.assertEqual((len(writes), len(reads)), (1, 1))
        self.assertEqual(reads[0][1][5], "e" * 64)

    def test_stop_verify_reports_retained_units_separately(self):
        steps.CLEAR_STEPS["stop_services"].apply(self.ctx())
        self.remote.overrides["gcp-gateway"] = {"active_kept": ["psy-forward.service"]}
        result = steps.CLEAR_STEPS["stop_services"].verify(self.ctx())
        self.assertEqual(result["hosts"]["gcp-gateway"]["retained_units_active"], 1)
        self.assertEqual(result["hosts"]["gcp-edge-1"]["retained_units_active"], 0)

    # --- shell guards
    def guard_environment(self, config_text="", stubs=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "config.env").write_text(config_text)
        path = "/usr/bin:/bin"
        if stubs:
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name in ("ssh", "sleep"):
                (bin_dir / name).write_text("#!/bin/sh\nexit %d\n" % (97 if name == "ssh" else 0))
                (bin_dir / name).chmod(0o755)
            path = f"{bin_dir}:{path}"
        return {"PATH": path, "HOME": str(root), "GCP_DEPLOY_CONFIG": str(root / "config.env"),
                "DEPLOY_SOURCE_VERSIONS_FILE": str(GCP.parent / "multi-chain" / "gcp" / "source-versions.env")}

    def run_guard(self, script, config_text="", stubs=False, **env):
        environment = {**self.guard_environment(config_text, stubs), **env}
        return subprocess.run(["/usr/bin/bash", str(GCP / script)], capture_output=True, text=True, env=environment)

    SCRIPT_IMAGES = (("create-scylla.sh", "SCYLLA_IMAGE"), ("create-redis.sh", "VALKEY_IMAGE"),
                     ("create-nats.sh", "NATS_IMAGE"), ("create-postgres.sh", "POSTGRES_IMAGE"),
                     ("create-nostr.sh", "NOSTR_RELAY_IMAGE"))

    def test_create_scripts_refuse_a_mutable_or_missing_image_before_doing_anything(self):
        digest = "@sha256:" + "a" * 64
        for script, var in self.SCRIPT_IMAGES:
            for value in (None, "x/y:latest", "x/y", "x/y@sha256:abc", "X/Y" + digest, "x/y" + digest + " "):
                env = {} if value is None else {var: value}
                with self.subTest(script=script, value=value):
                    done = self.run_guard(script, stubs=True, POSTGRES_PASSWORD="p", NOSTR_RELAY_URL="u", NOSTR_DOMAIN="d", **env)
                    self.assertNotEqual(done.returncode, 0)
                    self.assertIn(f"{var} must be set to an image pinned by digest", done.stderr)
                    self.assertNotIn("waiting for SSH", done.stdout, "nothing may run before the guard")

    def test_a_pin_in_config_env_is_accepted_and_the_script_goes_on(self):
        digest = "x/y@sha256:" + "a" * 64
        for script, var in self.SCRIPT_IMAGES:
            with self.subTest(script=script):
                done = self.run_guard(script, config_text=f'{var}="{digest}"\nPOSTGRES_PASSWORD=p\nNOSTR_RELAY_URL=u\n'
                                      'NOSTR_DOMAIN=d\n', stubs=True)
                self.assertNotIn("pinned by digest", done.stderr)
                self.assertNotEqual(done.returncode, 0, "the stubbed ssh makes the next step fail")
                if script != "create-nostr.sh":  # that script resolves host names before it waits for ssh
                    self.assertIn("timed out waiting for SSH", done.stderr)

    def test_a_mutable_pin_in_config_env_is_refused(self):
        done = self.run_guard("create-scylla.sh", config_text='SCYLLA_IMAGE="scylladb/scylla:latest"\n', stubs=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("SCYLLA_IMAGE must be set to an image pinned by digest", done.stderr)

    def test_pinned_image_guard_accepts_a_digest(self):
        guard = GCP / "lib" / "require-pinned-image.sh"
        done = subprocess.run(["/usr/bin/bash", "-c", f'source {guard}; require_pinned_image IMG'], capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "IMG": "scylladb/scylla@sha256:" + "a" * 64})
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_install_scripts_have_no_mutable_image_default(self):
        for name in ("install-scylla.sh", "install-valkey.sh", "install-nats.sh", "install-postgres.sh",
                     "install-nostr.sh", "install-nostr-relay.sh"):
            text = (GCP / "remote" / name).read_text()
            with self.subTest(name=name):
                self.assertIn("require_pinned_image", text)
                for mutable in (":latest", "nats:2", "postgres:${", "caddy:2"):
                    if name != "install-nostr.sh" or mutable != "caddy:2":
                        self.assertNotIn(mutable, text)

    def test_install_scripts_refuse_a_mutable_image_when_run(self):
        for name, var in (("install-scylla.sh", "SCYLLA_IMAGE"), ("install-valkey.sh", "VALKEY_IMAGE"),
                          ("install-nats.sh", "NATS_IMAGE"), ("install-postgres.sh", "POSTGRES_IMAGE"),
                          ("install-nostr-relay.sh", "NOSTR_RELAY_IMAGE")):
            with self.subTest(name=name):
                done = subprocess.run(["/usr/bin/bash", str(GCP / "remote" / name)], capture_output=True, text=True,
                                      env={"PATH": "/usr/bin:/bin", var: "x:latest", "POSTGRES_PASSWORD": "p"})
                self.assertNotEqual(done.returncode, 0)

    def test_postgres_password_never_reaches_a_docker_command_line(self):
        text = (GCP / "remote" / "install-postgres.sh").read_text()
        self.assertNotRegex(text, r"-e (POSTGRES_PASSWORD|PGPASSWORD)=")
        self.assertIn("-e POSTGRES_PASSWORD \\", text)
        self.assertIn("export PGPASSWORD", text)

    def test_valkey_installer_does_not_hide_package_errors(self):
        text = (GCP / "remote" / "install-valkey.sh").read_text()
        self.assertNotIn("2>/dev/null || true", text)
        self.assertIn("apt-get install -y docker.io", text)

    def test_nostr_relay_script_keeps_caddy_alone(self):
        text = (GCP / "remote" / "install-nostr-relay.sh").read_text()
        self.assertNotIn("caddy", text.lower().replace("caddy proxies", "").replace("caddy, its", ""))
        self.assertIn("--network-alias nostr-relay", text)

    def test_sdk_has_no_other_clear_path_than_the_private_list(self):
        source = Path(steps.__file__).read_text()
        for forbidden in ("02_clear_parth_state", "03_clear_database_state", "rm -rf", "/var/lib/parth/*"):
            self.assertNotIn(forbidden, source)

    def test_lock_images_include_nostr(self):
        self.assertIn("nostr", release_lock.IMAGES)


if __name__ == "__main__":
    unittest.main()
