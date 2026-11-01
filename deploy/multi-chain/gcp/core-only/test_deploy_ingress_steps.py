"""Ingress steps against a scripted remote and scripted public responses; no SSH, no network."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import caddy_ingress
import deploy_ingress_steps as steps
from deploy_remote import DeployContext, RemoteError

FENCED = ["coordinator.example.test", "services.example.test"]
FAUCET = ["faucet.example.test"]
FORWARDER_SHA = "7" * 64
EDGES = {"coordinator": "10.0.0.25", "realm0": "10.0.0.36", "realm1": "10.0.0.35"}
PROXIES = {"system": "10.1.0.13", "user": "10.1.0.12"}
RELEASE_TOPOLOGY = {"hosts": {"cp": "10.0.0.25", "e1": "10.0.0.36", "e2": "10.0.0.35"}, "coordinator": {"host": "cp"},
                    "realms": [{"id": 0, "validators": [{"edge_host": "e1"}, {"edge_host": "e1"}]},
                               {"id": 1, "validators": [{"edge_host": "e2"}]}]}


def digest(path):
    return hashlib.sha256((steps.HERE / path).read_bytes()).hexdigest()


class ScriptedRemote:
    def __init__(self, sudo="passwordless"):
        self.sudo, self.calls, self.fenced, self.edit = sudo, [], set(FENCED + FAUCET), ""
        self.forwarders = [{"name": f"route-{n}", "ready": True} for n in range(steps.FORWARDER_ROUTE_COUNT)]
        self.edges, self.proxies = dict(EDGES), dict(PROXIES)

    def file_hash(self, fenced, edit=""):
        return hashlib.sha256((",".join(sorted(fenced)) + edit).encode()).hexdigest()

    def sudo_mode(self, host):
        return self.sudo

    def run_root_text(self, host, argv, timeout_seconds, *, stdin_text=None, show_stderr=False):
        self.calls.append((host, argv, stdin_text))
        if "check-backends" in argv:
            units = [{"name": f["name"], "socket_active": f.get("socket_active", True),
                      "service_failed": f.get("service_failed", False)} for f in self.forwarders]
            return json.dumps({"units": units, "backends": self.forwarders, "edges": self.edges,
                               "proxies": self.proxies}) + "\n"
        command = argv[argv.index("stage") if "stage" in argv else argv.index("check")]
        if command == "stage":
            phase = argv[argv.index("--phase") + 1]
            files = {"original.Caddyfile": self.file_hash(self.fenced, self.edit),
                     "candidate.Caddyfile": self.file_hash(self.after(phase))}
            return json.dumps({"phase": phase, "is_unchanged": self.is_unchanged(phase), "report_sha256": "a" * 64,
                               "files": files})
        phase = argv[argv.index("--stage") + 1].rsplit("/", 1)[1].rsplit("-", 1)[0]
        was_unchanged = self.is_unchanged(phase)
        self.fenced = self.after(phase)
        return json.dumps({"result": "ALREADY_IN_STATE" if was_unchanged else "APPLIED"})

    def after(self, phase):
        return {"fence": set(FENCED + FAUCET), "open": self.fenced - set(FENCED),
                "open-faucet": self.fenced - set(FAUCET)}[phase]

    def is_unchanged(self, phase):
        return self.fenced == self.after(phase)

    def tool_calls(self):
        return [argv for _, argv, _ in self.calls if argv[0] == "/usr/bin/python3"]


class StepTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        text = json.dumps({"release": "test"}) + "\n"
        (root / "release-lock.json").write_text(text)
        topology = json.dumps(RELEASE_TOPOLOGY)
        (root / "topology.json").write_text(topology)
        lock = {"hosts": {steps.CADDY_HOST: "10.0.0.1", steps.GATEWAY_HOST: "10.0.0.2", "arc99x1": "10.1.0.13",
                          "arc99x3": "10.1.0.12"},
                "ingress": {"fenced_hosts": FENCED, "faucet_hosts": FAUCET, "maintenance_tag": "tag",
                            "forwarder_topology_sha256": FORWARDER_SHA},
                "inputs": {"topology": hashlib.sha256(topology.encode()).hexdigest()},
                "tool_sha256": {steps.CADDY_TOOL: digest(steps.CADDY_TOOL), steps.FORWARDER_TOOL: digest(steps.FORWARDER_TOOL)}}
        self.remote = ScriptedRemote()
        self.ctx = DeployContext(lock=lock, lock_sha256=hashlib.sha256(text.encode()).hexdigest(), release_dir=root,
                                 run_dir=root, remote=self.remote, private_dir=root, state_dir=root / "state")
        self.public = {host: (200, '{"result": 7}') for host in FENCED}
        self.public.update({host: (503, caddy_ingress.BODY) for host in FAUCET})
        self.enterContext(patch.object(steps, "fetch_response", side_effect=lambda host, is_rpc: self.public[host]))
        self.enterContext(patch.object(steps, "OPEN_WAIT_SECONDS", 1))
        self.enterContext(patch.object(steps, "POLL_SECONDS", 1))
        self.remote.fenced = set()

    def fence_hosts(self):
        self.remote.fenced = set(FENCED + FAUCET)
        self.public.update({host: (503, caddy_ingress.BODY) for host in FENCED + FAUCET})

    def test_steps_are_cutover_steps_with_the_table_names(self):
        self.assertEqual(sorted(steps.INGRESS_STEPS), ["fence_ingress", "open_ingress"])
        for name, step in steps.INGRESS_STEPS.items():
            self.assertEqual(step.name, name)
            self.assertTrue(step.cutover)

    def test_fence_runs_stage_then_check_apply_with_the_lock_and_tool_hash(self):
        steps.INGRESS_STEPS["fence_ingress"].apply(self.ctx)
        stage, check = self.remote.tool_calls()
        self.assertEqual(stage[stage.index("--release-lock-sha256") + 1], self.ctx.lock_sha256)
        lock_bytes = base64.b64decode(stage[stage.index("--release-lock-base64") + 1])
        self.assertEqual(hashlib.sha256(lock_bytes).hexdigest(), self.ctx.lock_sha256)
        self.assertEqual(stage[stage.index("--phase") + 1], "fence")
        self.assertTrue(stage[stage.index("--output") + 1].startswith(steps.STAGE_ROOT + "/fence-"))
        self.assertIn("--apply", check)
        tool_sources = {text for _, argv, text in self.remote.calls if argv[0] == "/usr/bin/python3"}
        self.assertEqual(tool_sources, {(steps.HERE / "caddy_ingress.py").read_text()})
        self.assertTrue((self.ctx.state_dir / "ingress-fence.json").is_file())

    def test_rerun_of_fence_and_open_is_accepted_when_already_in_place(self):
        for name in ("fence_ingress", "open_ingress"):
            step = steps.INGRESS_STEPS[name]
            step.apply(self.ctx)
            step.apply(self.ctx)
        saved = json.loads((self.ctx.state_dir / "ingress-open.json").read_text())
        self.assertEqual(saved["result"], "ALREADY_IN_STATE")

    def test_check_refuses_a_tool_that_differs_from_the_lock(self):
        self.ctx.lock["tool_sha256"][steps.CADDY_TOOL] = "0" * 64
        with self.assertRaisesRegex(ValueError, "tool hash differs"):
            steps.INGRESS_STEPS["fence_ingress"].check(self.ctx)
        self.assertEqual(self.remote.tool_calls(), [])

    def test_check_refuses_a_host_without_no_prompt_sudo(self):
        self.remote.sudo = "operator"
        with self.assertRaisesRegex(ValueError, "no-prompt sudo"):
            steps.INGRESS_STEPS["open_ingress"].check(self.ctx)

    def test_check_never_applies(self):
        steps.INGRESS_STEPS["open_ingress"].check(self.ctx)
        self.assertTrue(all("--apply" not in argv for argv in self.remote.tool_calls()))

    def test_fence_verify_needs_every_listed_host_to_return_503(self):
        self.fence_hosts()
        self.assertEqual(steps.INGRESS_STEPS["fence_ingress"].verify(self.ctx), {"fenced_host_count": 3})
        self.public[FENCED[1]] = (200, "backend")
        with self.assertRaisesRegex(ValueError, FENCED[1]):
            steps.INGRESS_STEPS["fence_ingress"].verify(self.ctx)

    def test_open_verify_checks_each_route_keeps_faucet_503_and_runs_the_forwarder_check(self):
        self.remote.fenced = set(FAUCET)
        report = steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)
        self.assertEqual(report, {"opened_host_count": 2, "faucet_host_count": 1, "forwarder_route_count": 11})
        host, argv, text = self.remote.calls[-1]
        self.assertEqual(host, steps.GATEWAY_HOST)
        self.assertIn("check-backends", argv)
        self.assertNotIn("check-host", argv)
        self.assertEqual(argv[argv.index("--topology-sha256") + 1], FORWARDER_SHA)
        self.assertEqual(text, (steps.HERE / "prepare_bridge_forwarders.py").read_text())

    def test_open_verify_refuses_a_faucet_host_that_is_already_open(self):
        self.remote.fenced = set(FAUCET)
        self.public[FAUCET[0]] = (200, "backend")
        with self.assertRaisesRegex(ValueError, FAUCET[0]):
            steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)

    def test_open_verify_refuses_a_route_still_in_maintenance_or_broken(self):
        self.remote.fenced = set(FAUCET)
        for response in ((503, caddy_ingress.BODY), (502, "bad gateway"), (200, '{"error": 1}')):
            self.public[FENCED[0]] = response
            with self.subTest(response=response), self.assertRaises(TimeoutError):
                steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)

    def test_open_verify_refuses_when_the_caddyfile_is_not_in_the_open_state(self):
        self.fence_hosts()
        with self.assertRaisesRegex(ValueError, "not in the open state"):
            steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)

    def test_forwarder_check_must_report_eleven_active_ready_routes(self):
        self.remote.fenced = set(FAUCET)
        for forwarders in (self.remote.forwarders[:10], [dict(f, ready=False) for f in self.remote.forwarders],
                           [dict(f, socket_active=False) for f in self.remote.forwarders],
                           [dict(f, service_failed=True) for f in self.remote.forwarders]):
            self.remote.forwarders = forwarders
            with self.subTest(count=len(forwarders)), self.assertRaisesRegex(ValueError, "11 live sockets"):
                steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)

    def test_open_faucet_removes_only_the_faucet_fence_and_checks_only_faucet_hosts(self):
        self.remote.fenced = set(FENCED + FAUCET)
        self.public.update({host: (200, "backend") for host in FAUCET})
        self.assertEqual(steps.open_faucet(self.ctx), {"faucet_host_count": 1})
        phases = [argv[argv.index("--phase") + 1] for argv in self.remote.tool_calls() if "--phase" in argv]
        self.assertEqual(set(phases), {"open-faucet"})
        self.assertEqual(self.remote.fenced, set(FENCED))
        self.assertTrue(all(host != steps.GATEWAY_HOST for host, _, _ in self.remote.calls))

    def test_remote_failure_is_not_swallowed(self):
        def fail(*args, **kwargs):
            raise RemoteError("caddy host: exit 1", host=steps.CADDY_HOST, exit_code=1)
        with patch.object(self.remote, "run_root_text", side_effect=fail), self.assertRaises(RemoteError):
            steps.INGRESS_STEPS["fence_ingress"].apply(self.ctx)

    def test_lock_file_must_match_the_loaded_lock(self):
        (self.ctx.release_dir / "release-lock.json").write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "differs from the loaded lock"):
            steps.INGRESS_STEPS["fence_ingress"].apply(self.ctx)
        self.assertEqual(self.remote.calls, [])

    def test_check_never_writes_to_the_host(self):
        for name in ("fence_ingress", "open_ingress"):
            self.remote.fenced = set(FAUCET)
            steps.INGRESS_STEPS[name].check(self.ctx)
        self.assertTrue(all(argv[0] == "/usr/bin/python3" for _, argv, _ in self.remote.calls))
        self.assertTrue(all("--output" not in argv and "--apply" not in argv for _, argv, _ in self.remote.calls))

    def test_open_check_runs_the_forwarder_check_first_and_needs_gateway_sudo(self):
        self.remote.fenced = set(FAUCET)
        steps.INGRESS_STEPS["open_ingress"].check(self.ctx)
        self.assertEqual(self.remote.calls[-1][0], steps.GATEWAY_HOST)
        self.remote.forwarders = self.remote.forwarders[:3]
        with self.assertRaisesRegex(ValueError, "11 live sockets"):
            steps.INGRESS_STEPS["open_ingress"].check(self.ctx)
        self.ctx.lock["tool_sha256"][steps.FORWARDER_TOOL] = "0" * 64
        with self.assertRaisesRegex(ValueError, "tool hash differs"):
            steps.INGRESS_STEPS["open_ingress"].check(self.ctx)

    def test_forwarder_backends_must_equal_the_release_topology(self):
        self.remote.fenced = set(FAUCET)
        for field, value in (("edges", dict(EDGES, realm1="10.9.9.9")), ("proxies", dict(PROXIES, user="10.9.9.9")),
                             ("edges", {"coordinator": EDGES["coordinator"]})):
            setattr(self.remote, field, value)
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "differ from the release topology"):
                steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)
            self.remote.edges, self.remote.proxies = dict(EDGES), dict(PROXIES)

    def test_open_verify_can_be_rerun_after_the_faucet_was_opened(self):
        self.remote.fenced = set()
        self.public.update({host: (200, "backend") for host in FAUCET})
        report = steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)
        self.assertEqual(report["faucet_host_count"], 1)
        self.public[FAUCET[0]] = (503, caddy_ingress.BODY)
        with self.assertRaises(TimeoutError):
            steps.INGRESS_STEPS["open_ingress"].verify(self.ctx)

    def test_next_phase_refuses_a_caddyfile_edited_since_the_last_phase(self):
        steps.INGRESS_STEPS["fence_ingress"].apply(self.ctx)
        steps.INGRESS_STEPS["open_ingress"].check(self.ctx)
        self.remote.edit = "reload-after-ordinary-edit"
        with self.assertRaisesRegex(ValueError, "changed since the last ingress phase"):
            steps.INGRESS_STEPS["open_ingress"].apply(self.ctx)
        self.assertEqual(len([argv for argv in self.remote.tool_calls() if "--apply" in argv]), 1)

    def test_fence_starts_a_new_chain_and_ignores_earlier_state(self):
        steps.INGRESS_STEPS["fence_ingress"].apply(self.ctx)
        self.remote.edit = "legitimate-change-between-deployments"
        steps.INGRESS_STEPS["fence_ingress"].apply(self.ctx)

    def test_state_file_records_the_candidate_hash(self):
        steps.INGRESS_STEPS["fence_ingress"].apply(self.ctx)
        saved = json.loads((self.ctx.state_dir / "ingress-fence.json").read_text())
        self.assertEqual(saved["candidate_sha256"], self.remote.file_hash(set(FENCED + FAUCET)))

    def test_probe_treats_http_protocol_errors_as_not_ready(self):
        import http.client
        with patch.object(steps, "fetch_response", side_effect=http.client.RemoteDisconnected("closed")):
            self.assertIsNone(steps.probe("coordinator.example.test"))


if __name__ == "__main__":
    unittest.main()
