import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("topology_steps", HERE / "steps.py")
steps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(steps)


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.t = json.loads((HERE / "topology.json").read_text())

    def test_live_layout(self):
        steps.validate(self.t)
        ops = steps.operations(self.t)
        self.assertEqual(len(ops["12-coordinator-edges"]), 3)
        self.assertEqual(len(ops["12-realm0-edges"]), 3)
        self.assertEqual(len(ops["12-realm1-edges"]), 3)
        self.assertEqual(ops["12-realm0-processor"][0]["host"], "gcp-realm-processor")
        self.assertEqual(ops["12-realm1-processor"][0]["host"], "gcp-cp-ce")
        self.assertEqual(ops["12-services"][0]["host"], "gcp-psy-service")
        self.assertEqual({op["host"] for op in ops["14-workers"]}, {"gcp-c4d-1"})
        self.assertEqual(len(ops["14-workers"]), 5)
        self.assertEqual(ops["13-faucet"][0]["host"], "gcp-coordinator-worker")
        self.assertEqual(ops["16-relayer"][0]["env"]["RELAYER_MAX_CHECKPOINT_BATCH"], "64")

    def test_replica_number_is_not_protocol_sub_id(self):
        for op in steps.operations(self.t)["12-coordinator-edges"]:
            self.assertEqual(op["env"]["COORDINATOR_SUB_ID"], "0")
            self.assertEqual(op["env"]["COORDINATOR_ID"], "0")

    def test_edge_healthchecks_use_the_bind_address(self):
        ops = steps.operations(self.t)
        for step, key, port in [("12-coordinator-edges", "COORDINATOR", "COORDINATOR_EDGE_PORT"),
                                ("12-realm0-edges", "REALM", "REALM_EDGE_PORT"),
                                ("12-realm1-edges", "REALM", "REALM_EDGE_PORT")]:
            for op in ops[step]:
                env = op["env"]
                self.assertEqual(env[key + "_EDGE_HEALTHCHECK_JSONRPC_URL"],
                                 f'http://{env["LISTEN_ADDR"]}:{env[port]}')

    def test_explicit_shared_worker_keys_are_allowed(self):
        instances = [op["env"]["DEPLOY_INSTANCE"] for op in steps.operations(self.t)["14-workers"]]
        self.t["workers"]["key_indexes"] = {instance: 3 for instance in instances}
        steps.validate(self.t)
        for op in steps.operations(self.t)["14-workers"]:
            self.assertEqual(op["env"]["WORKER_KEY_INDEX"], "3")
        self.t["workers"]["key_indexes"].pop(instances[0])
        with self.assertRaises(ValueError):
            steps.validate(self.t)

    def test_caddy_step_recreates_nostr_after_reset(self):
        self.assertEqual(steps.operations(self.t)["17-caddy"][0]["script"], "create-nostr.sh")

    def test_move_coordinator_edge_propagates_without_moving_processor(self):
        self.t["hosts"]["future-edge"] = {"ip": "10.148.0.40", "location": "gcp"}
        self.t["coordinator"]["edges"][0]["host"] = "future-edge"
        steps.validate(self.t)
        ops = steps.operations(self.t)
        self.assertIn("10.148.0.40:1337", ops["17-caddy"][0]["env"]["PUBLIC_COORDINATOR_UPSTREAM"])
        self.assertIn("10.148.0.40:1337", ops["12-realm0-processor"][0]["env"]["COORDINATOR_API_URLS"])
        self.assertIn("10.148.0.40:1337", ops["14-workers"][0]["env"]["COORDINATOR_API_URLS"])
        self.assertEqual(ops["12-services"][0]["env"]["PSY_NODE_URL"], "http://10.148.0.40:1337")
        self.assertEqual(ops["12-coordinator-processor"][0]["host"], "gcp-cp-ce")

    def test_indexers_explicitly_target_service_host(self):
        for op in steps.operations(self.t)["12-indexers"]:
            self.assertEqual(op["env"]["PSY_SERVICES_URL"], "http://10.148.0.38:3000")
            self.assertIn("PSY_EDGE_RPC_URL", op["env"])

    def test_private_infra_overrides(self):
        for ops in steps.operations(self.t).values():
            for op in ops:
                self.assertEqual(op["env"]["SCYLLA_DB_URL"], "10.148.0.23:9042")
                self.assertEqual(op["env"]["NATS_JETSTREAM_URL"], "nats://10.148.0.20:4222")
                self.assertEqual(op["env"]["POSTGRES_HOST"], "10.148.0.24")

    def test_reject_public_db_host(self):
        self.t["hosts"]["gcp-scylla"]["ip"] = "8.8.8.8"
        with self.assertRaises(ValueError):
            steps.validate(self.t)

    def test_effective_config_rejects_public_or_dns_db_override_without_leaking_key(self):
        for host in ("8.8.8.8", "public-db.example.test", "localhost"):
            with self.assertRaises(ValueError) as caught:
                steps.check_private_config({"PSY_SERVICES_DATABASE_URL": f"postgres://user:do-not-print@{host}/db"})
            self.assertNotIn("do-not-print", str(caught.exception))
        steps.check_private_config({"PSY_SERVICES_DATABASE_URL": "postgres://user:secret@10.148.0.24/db"})

    def test_reject_duplicate_listen_and_instance(self):
        for field, value in [("port", 1337), ("instance", "0")]:
            t = copy.deepcopy(self.t)
            t["coordinator"]["edges"][1][field] = value
            with self.assertRaises(ValueError):
                steps.validate(t)

    def test_reject_chain_index_drift(self):
        self.t["chains"][1]["index"] = 2
        with self.assertRaises(ValueError):
            steps.validate(self.t)

    def test_reject_invalid_weight_or_count(self):
        self.t["proxies"]["user_weights"]["arc99x2"] = 10
        with self.assertRaises(ValueError):
            steps.validate(self.t)
        self.setUp()
        self.t["workers"]["coordinator"] = 0
        with self.assertRaises(ValueError):
            steps.validate(self.t)

    def test_inactive_x2_is_not_added_to_route(self):
        self.assertEqual(self.t["proxies"]["user_weights"]["arc99x2"], 0)
        caddy = steps.operations(self.t)["17-caddy"][0]["env"]
        self.assertEqual(caddy["PUBLIC_PROVE_PROXY_UPSTREAM"], "10.148.0.32:19999")

    def test_overlay_survives_config_resourcing_and_quotes_paths(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / "config with ' quote.env"
            original.write_text("NODE_VM_NAME=old-host\nPSY_SERVICES_URL=http://old:3000\n")
            overlay = Path(d) / "overlay.env"
            overlay.write_text(steps.overlay(original, {"NODE_VM_NAME": "gcp-psy-service",
                                                       "PSY_SERVICES_URL": "http://10.148.0.38:3000"}))
            result = subprocess.check_output(["bash", "-c", 'source "$1"; source "$1"; printf "%s %s" "$NODE_VM_NAME" "$PSY_SERVICES_URL"', "test", str(overlay)], text=True)
            self.assertEqual(result, "gcp-psy-service http://10.148.0.38:3000")

    def test_plan_has_no_subprocess_or_config_sourcing(self):
        with patch.object(sys, "argv", ["steps.py", "plan", "--config", "/does/not/exist"]), \
                patch.object(steps.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(steps.main(), 0)
            run.assert_not_called()

    def test_unready_apply_stops_before_network(self):
        with patch.object(sys, "argv", ["steps.py", "12-services", "--apply"]), \
                patch.object(steps.subprocess, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                steps.main()
            run.assert_not_called()

    def test_readiness_is_not_success(self):
        with patch.object(sys, "argv", ["steps.py", "readiness"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(steps.main(), 2)

    def test_script_paths_exist(self):
        for ops in steps.operations(self.t).values():
            for op in ops:
                self.assertTrue((steps.ROOT / "deploy/gcp" / op["script"]).is_file())

    def test_apply_dispatch_and_private_overlay_with_fake_installer(self):
        self.t["release_blockers"] = []
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            topology = directory / "topology.json"
            topology.write_text(json.dumps(self.t))
            config, versions = directory / "private.env", directory / "versions.env"
            config.touch()
            versions.touch()
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command[-1])
                if command[-1].endswith("deploy-coordinator-edge.sh"):
                    path = Path(kwargs["env"]["GCP_DEPLOY_CONFIG"])
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertIn("COORDINATOR_SUB_ID=0", path.read_text())
                    self.assertIn("NODE_VM_NAME=gcp-cp-ce", path.read_text())
                    self.assertEqual(kwargs["env"]["DEPLOY_SOURCE_VERSIONS_FILE"], str(versions))
                    self.assertEqual(kwargs["env"]["DEPLOY_INSTANCE"], str(len(calls) // 2 - 1))

            argv = ["steps.py", "12-coordinator-edges", "--topology", str(topology),
                    "--config", str(config), "--versions", str(versions), "--apply"]
            with patch.object(sys, "argv", argv), patch.dict(os.environ, CONFIRM_FULL_FRESH_DEPLOY="1", DEPLOY_INSTANCE="ambient-wrong"), \
                    patch.object(steps.subprocess, "run", side_effect=fake_run), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(steps.main(), 0)
            self.assertEqual(Path(calls[0]).name, "preflight.sh")
            self.assertEqual([Path(c).name for c in calls[1:]], ["steps.py", "deploy-coordinator-edge.sh"] * 3)

    def test_split_total_plan_and_range(self):
        env = dict(os.environ, GCP_DEPLOY_CONFIG=str(steps.PROFILE / "config.split.example.env"))
        runner = str(steps.PROFILE / "deploy_all.sh")
        result = subprocess.check_output(["bash", runner, "--plan"], env=env, text=True)
        rows = [line[:2] for line in result.splitlines() if len(line) > 3 and line[:2].isdigit() and line[2:4] == "  "]
        self.assertEqual(rows[:4], ["04", "01", "02", "03"])
        self.assertEqual(rows[-1], "32")
        self.assertIn("Five c4d Workers", result)
        self.assertNotIn("11 collectors", result)
        result = subprocess.check_output(["bash", runner, "--plan", "--only", "43"], env=env, text=True)
        self.assertIn("gcp-realm-processor -> deploy-realm-processor.sh", result)
        self.assertNotIn("gcp-c4d-1 ->", result)

    def test_full_runner_blocked_before_stop(self):
        env = dict(os.environ, GCP_DEPLOY_CONFIG=str(steps.PROFILE / "config.split.example.env"),
                   CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING="1", CONFIRM_FULL_FRESH_DEPLOY="1")
        result = subprocess.run(["bash", str(steps.PROFILE / "deploy_all.sh"), "--only", "01"],
                                env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("step 01 is not implemented", result.stderr)
        self.assertNotIn("START 01", result.stdout)

    def test_blocked_description_survives_empty_blocker_list(self):
        self.t["release_blockers"] = []
        with tempfile.TemporaryDirectory() as d:
            topology = Path(d) / "topology.json"
            topology.write_text(json.dumps(self.t))
            config = Path(d) / "config.env"
            config.write_text(steps.overlay(steps.PROFILE / "config.split.example.env",
                                           {"DEPLOY_TOPOLOGY_FILE": str(topology)}))
            env = dict(os.environ, GCP_DEPLOY_CONFIG=str(config), CONFIRM_FULL_FRESH_DEPLOY="1",
                       CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING="1")
            result = subprocess.run(["bash", str(steps.PROFILE / "deploy_all.sh"), "--only", "03"],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("step 03 is not implemented", result.stderr)
            self.assertNotIn("START 03", result.stdout)

    def test_modified_shell_syntax(self):
        paths = ["deploy/gcp/fresh-staging/12_deploy_cp_ce_stack.sh",
                 "deploy/gcp/fresh-staging/14_deploy_workers.sh",
                 "deploy/gcp/fresh-staging/16_deploy_relayer.sh",
                 "deploy/gcp/fresh-staging/17_deploy_caddy_entrypoints.sh",
                 "deploy/gcp/remote/update-caddy-entrypoints.sh",
                 "deploy/multi-chain/gcp/deploy_all.sh",
                 "deploy/multi-chain/gcp/config.split.example.env",
                 "deploy/multi-chain/gcp/fresh-topology/run-step.sh"]
        for path in paths:
            subprocess.run(["bash", "-n", str(steps.ROOT / path)], check=True)


if __name__ == "__main__":
    unittest.main()
