import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

import bridge_packages as bridge
import deploy_services_steps as steps
import prepare_envio
import release_lock
from test_services_packages import ServicesWorld, sha


REAL_READ_CURSOR = steps.read_cursor


class BridgeWorld(ServicesWorld):
    """Adds the Guardian, Relayer and Envio operator inputs to a Services world."""

    def __init__(self, root):
        super().__init__(root)
        self.run_dir, self.state_dir = self.root / "run", self.private_dir / "state"
        self.run_dir.mkdir()
        self.state_dir.mkdir()
        self.relayer_binary = b"\x7fELF fixture relayer"
        self.lock["binaries"]["psy_relayer_cli"] = sha(self.relayer_binary)
        self.config = self.root / "files-config.json"
        self.config.write_text('{"network": "testnet"}')
        self.lock["inputs"]["runtime_config"] = sha(self.config.read_bytes())
        self.patches = self.root / "patches"
        self.patches.mkdir()
        for name in release_lock.ENVIO_PATCHES:
            (self.patches / name).write_bytes(("fixture:" + name).encode())
            self.lock["envio"]["patch_sha256"][name] = sha(("fixture:" + name).encode())
        self.package_json = {"devDependencies": {"envio": "2.32.10"}, "dependencies": {"poseidon-goldilocks-lite": "^0.2.3"}}
        pnpm = {"lockfileVersion": "9.0", "importers": {".": {kind: {key: {"specifier": value, "version": value} for key, value in values.items()}
                                                              for kind, values in self.package_json.items()}}}
        self.pnpm = self.root / "pnpm-lock.yaml"
        self.pnpm.write_text(yaml.safe_dump(pnpm))
        self.sources = {name: (name + " pinned\n").encode() for name in prepare_envio.SOURCE_FILES}
        self.sources["package.json"] = prepare_envio.encode(self.package_json)
        self.sources["config.template.yaml"] = yaml.safe_dump({"name": "x", "contracts": [], "networks": []}).encode()
        self.write_placement()
        self.rewrite_lock()
        self.write_local_inputs()
        self.write_build_state()

    def rewrite_lock(self):
        raw = json.dumps(self.lock, indent=2).encode()
        (self.release_dir / "release-lock.json").write_bytes(raw)
        self.lock_sha256 = sha(raw)

    def write_placement(self):
        rows = [{"guardian_id": index, "hostname": f"guardian-{index}.internal", "address": f"10.0.0.{38 + index}",
                 "guardian_history": {"listen_address": "10.0.0.33:15450", "rpc_url": "http://10.0.0.33:15450"},
                 "proof_origins": {"prove_proxy_url": ["http://127.0.0.1:19999"], "system_prove_proxy_url": ["http://10.0.0.32:19998"]},
                 "service_user": f"psy-guardian-{index}", "memory_high_gib": 2, "memory_max_gib": 3, "custody_keystore_sha256": "a" * 64}
                for index in (1, 2, 3)]
        for row in rows:
            self.lock["hosts"][f"guardian-next-{row['guardian_id']}"] = row["address"]
        self.lock["hosts"]["gcp-relayer"] = "10.0.0.31"
        self.operator = self.root / "operator"
        self.operator.mkdir()
        (self.operator / "placement.json").write_text(json.dumps({"version": 1, "guardians": rows}))
        (self.operator / "rpc.json").write_text('{"rpc": true}')
        (self.operator / "daemon.toml").write_text("poll = 1\n")
        (self.operator / "relayer.json").write_text(json.dumps({
            "hostname": "relayer.internal", "address": "10.0.0.31",
            "guardian_history": {"listen_address": "10.0.0.33:15450", "rpc_url": "http://10.0.0.33:15450"},
            "service_user": "psy-core-relayer", "memory_high_gib": 2, "memory_max_gib": 3, "keystore_owner": "psy-core",
            "l1_keystore": {"path": "/var/lib/keys/relayer", "sha256": "b" * 64},
            "password_credential": {"path": "/var/lib/keys/cred", "sha256": "c" * 64}}))

    def write_local_inputs(self):
        node = self.root / "node"
        node.mkdir()
        local = {"build": {"source": str(node)},
                 "files": {"config": str(self.config), "psy_services": str(self.inputs_dir / "psy-services"),
                           "psy_indexer": str(self.inputs_dir / "psy-indexer"), "genesis": str(self.inputs_dir / "genesis.json.zst")},
                 "databases": {"postgres_password_file": str(self.root / "pg-login")},
                 "packages": {"bridge": {"output_root": str(self.root / "out"), "guardian_placement": str(self.operator / "placement.json"),
                                         "guardian_rpc_config": str(self.operator / "rpc.json"), "relayer_spec": str(self.operator / "relayer.json"),
                                         "relayer_rpc_config": str(self.operator / "rpc.json"),
                                         "relayer_daemon_config": str(self.operator / "daemon.toml")},
                              "services": {"services_source": str(node), "indexer_source": str(node), "genesis_source": str(node),
                                           "mirror_host_keys": {"10.0.0.25": "k1", "10.0.0.42": "k2", "10.0.0.43": "k3"}},
                              "envio": {"patches_dir": str(self.patches), "dependency_lock": str(self.pnpm),
                                        "build_script": str(self.root / "build-envio")}}}
        (self.private_dir / "local-inputs.json").write_text(json.dumps(local))
        (self.root / "pg-login").write_text("fixture-login-" + "a" * 30 + "\n")

    def write_build_state(self):
        build = self.root / "build"
        build.mkdir()
        (build / "manifest.json").write_text(json.dumps({"source_commit": self.lock["sources"]["runtime"],
                                                         "config_sha256": self.lock["inputs"]["runtime_config"]}))
        (build / "psy_relayer_cli").write_bytes(self.relayer_binary)
        (self.state_dir / "rebuild_binaries.json").write_text(json.dumps({"build_dir": str(build)}))

    def ctx(self):
        return SimpleNamespace(lock=self.lock, lock_sha256=self.lock_sha256, release_dir=self.release_dir, run_dir=self.run_dir,
                               remote=None, private_dir=self.private_dir, state_dir=self.state_dir)

    def prepare_inputs(self, arguments, lock):
        shutil.copytree(self.inputs_dir, arguments.output)
        return {"manifest_sha256": self.manifest_sha256}


class PackageSetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.world = BridgeWorld(self.temp.name)
        self.ctx = self.world.ctx()
        for target, value in (("prepare_envio.source_files", self.world.sources),):
            patcher = patch.object(prepare_envio, "source_files", return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(bridge.prepare_services_inputs, "prepare", side_effect=self.world.prepare_inputs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def build_pending(self):
        with patch.object(bridge, "plan_locally") as plan:
            output = bridge.build_bridge_packages(self.ctx, None)
        return output, plan

    def test_pending_mode_validates_all_inputs_except_l1_documents(self):
        output, plan = self.build_pending()
        summary = bridge.read_summary(self.ctx, output)
        self.assertIs(summary["pending"], True)
        self.assertEqual(plan.call_count, 4)
        for call in plan.call_args_list:
            self.assertEqual(call.args[2]["l1_documents"], {})
            self.assertEqual(call.args[2]["version"], 3)
        self.assertNotIn("built", summary["envio"])
        self.assertFalse((Path(summary["envio"]["source"]) / "config.yaml").exists())
        config = json.loads((output / "services/gcp-svc/services.json").read_bytes())
        self.assertEqual(config["l1_chains"], [])
        steps.verify_set(self.ctx, output, True)
        for host, directory in summary["guardian"].items():
            package = json.loads((Path(directory) / "package.json").read_bytes())
            self.assertEqual((package["role"], package["host"]), ("guardian", host))
            self.assertEqual(package["spec"], "operator.json")
            self.assertEqual(package["files"]["install_guardian.py"], self.world.lock["tool_sha256"]["install_guardian.py"])
            self.assertTrue(package["stage_dir"].startswith("/var/tmp/psy-guardian-"))
        # An input that is not about L1 still stops a pending build.
        self.world.patches.joinpath("history.py").write_bytes(b"tampered patch")
        with patch.object(bridge, "plan_locally"), self.assertRaises(ValueError):
            bridge.build_bridge_packages(self.ctx, None)
        self.world.patches.joinpath("history.py").write_bytes(b"fixture:history.py")
        (self.world.root / "build" / "psy_relayer_cli").write_bytes(b"another binary")
        with patch.object(bridge, "plan_locally"), self.assertRaisesRegex(ValueError, "relayer binary differs"):
            bridge.build_bridge_packages(self.ctx, None)

    def test_pending_set_is_replaced_but_a_foreign_directory_is_not(self):
        output, _ = self.build_pending()
        self.build_pending()
        shutil.rmtree(output)
        output.mkdir()
        with self.assertRaisesRegex(ValueError, "not a pending package set"):
            self.build_pending()

    def documents(self):
        directory = self.world.root / "documents"
        documents = {}
        for chain in release_lock.CHAINS:
            row = {}
            for name in ("summary", "bridge_receipt", "state_manager_receipt"):
                path = directory / chain / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(json.dumps({"core": {"StateManager": "0x" + "1" * 40}}).encode() if name == "summary"
                                 else (chain + name).encode())
                row[name] = {"path": str(path), "sha256": sha(path.read_bytes())}
            documents[chain] = row
        return documents

    def test_real_mode_rejects_document_hash_differing_from_deploy_l1(self):
        documents = self.documents()
        self.assertEqual(set(bridge.l1_files(documents)), {f"{chain}/{name}" for chain in release_lock.CHAINS
                                                           for name in ("deployed-contracts.json", "Bridge_Proxy.json")})
        Path(documents["bscTestnet"]["summary"]["path"]).write_bytes(b"replaced after the deployment")
        with self.assertRaisesRegex(ValueError, "differs from its recorded hash"):
            bridge.l1_files(documents)
        with self.assertRaisesRegex(ValueError, "all three chains"):
            bridge.build_bridge_packages(self.ctx, {"sepolia": documents["sepolia"]})
        deploy = self.world.state_dir / "deploy_l1.json"
        deploy.write_text(json.dumps({"lock_sha256": self.world.lock_sha256}))
        record = {"schema_version": 1, "lock_sha256": self.world.lock_sha256, "l1_documents_sha256": sha(deploy.read_bytes())}
        (self.world.state_dir / "prepare_bridge_packages.json").write_text(json.dumps(record))
        self.assertEqual(steps.bridge_state(self.ctx)["l1_documents_sha256"], record["l1_documents_sha256"])
        deploy.write_text(json.dumps({"lock_sha256": self.world.lock_sha256, "attempt": 2}))
        with self.assertRaisesRegex(ValueError, "different L1 documents"):
            steps.bridge_state(self.ctx)
        record["lock_sha256"] = "0" * 64
        (self.world.state_dir / "prepare_bridge_packages.json").write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "another release lock"):
            steps.bridge_state(self.ctx)

    def test_failed_final_build_is_removed_on_rerun_but_a_finished_set_is_kept(self):
        documents = self.documents()
        output = bridge.output_directory(self.ctx, documents)
        with patch.object(bridge, "plan_locally"), patch.object(bridge, "build_envio", side_effect=RuntimeError("envio build failed")):
            with self.assertRaisesRegex(RuntimeError, "envio build failed"):
                bridge.build_bridge_packages(self.ctx, documents)
        self.assertTrue(output.exists() and not (output / "summary.json").exists())
        with patch.object(bridge, "plan_locally"), patch.object(bridge, "build_envio", return_value={"source": "x"}):
            self.assertEqual(bridge.build_bridge_packages(self.ctx, documents), output)
            self.assertTrue((output / "summary.json").is_file())
            with self.assertRaisesRegex(ValueError, "exists"):
                bridge.build_bridge_packages(self.ctx, documents)

    def test_deployment_state_must_cover_three_chains_of_this_lock(self):
        state = {"lock_sha256": self.world.lock_sha256, "chains": {"sepolia": {}}}
        (self.world.state_dir / "deploy_l1.json").write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, "three chains"):
            steps.deploy_state(self.ctx)
        state["lock_sha256"] = "1" * 64
        (self.world.state_dir / "deploy_l1.json").write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, "another release lock"):
            steps.deploy_state(self.ctx)

    def test_envio_source_points_at_the_lock(self):
        spec = bridge.envio_spec(self.ctx, None)
        lock = self.world.lock
        self.assertEqual(spec["placement"]["postgres_user"], lock["envio"]["database"])
        self.assertEqual(spec["placement"]["postgres_host"], lock["hosts"]["gcp-postgres"])
        self.assertEqual([route["urls"] for route in spec["rpc_routes"].values()], [[url] for url in lock["envio"]["rpc_routes"].values()])
        self.assertEqual(spec["l1_documents"], {})

    def test_envio_build_must_carry_verified_evidence(self):
        built = self.world.root / "built"
        built.mkdir()
        (built / "node").write_bytes(b"node")
        evidence = {"source_commit": self.world.lock["sources"]["runtime"], "node_sha256": self.world.lock["envio"]["node_sha256"],
                    "frozen_install_verified": True, "patches_verified": True, "native_help_verified": True,
                    "generated_config_verified": True}
        import install_envio
        evidence["files"] = install_envio.inventory(built)
        (built / "build.json").write_text(json.dumps(evidence))
        self.assertEqual(bridge.check_envio_build(built, self.world.lock), sha((built / "build.json").read_bytes()))
        for key in ("frozen_install_verified", "patches_verified", "native_help_verified", "generated_config_verified"):
            broken = copy.deepcopy(evidence)
            broken[key] = False
            (built / "build.json").write_text(json.dumps(broken))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "not verified"):
                bridge.check_envio_build(built, self.world.lock)
        (built / "build.json").write_text(json.dumps(evidence))
        (built / "extra").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            bridge.check_envio_build(built, self.world.lock)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.world = BridgeWorld(self.temp.name)
        self.ctx = self.world.ctx()
        sleeper = patch("deploy_remote.time.sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)
        for name, value in (("READY_SECONDS", 0.2), ("POLL_SECONDS", 1)):
            patcher = patch.object(steps, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.cursors = {"coordinator": [10, 12], "realm0": [4, 6]}
        self.rows = {"0": 0, "1": 0, "2": 0}
        self.status = 200
        for name, replacement in (
                ("unit_state", lambda ctx, host, unit: {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled",
                                                        "MainPID": "9", "NRestarts": "0"}),
                ("http_status", lambda ctx, host, url: self.status),
                ("read_cursor", self.read_cursor),
                ("deposit_root_rows", lambda ctx: dict(self.rows))):
            patcher = patch.object(steps, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def read_cursor(self, ctx, placement, role):
        values = self.cursors[role]
        return values.pop(0) if len(values) > 1 else values[0]

    def test_verify_requires_ready_and_advancing_watermark(self):
        result = steps.services_verify(self.ctx)
        self.assertTrue(result["services_ready"])
        self.assertEqual(set(result["watermarks"]), {"coordinator", "realm0"})
        self.assertEqual(result["watermarks"]["realm0"], 6)
        self.cursors = {"coordinator": [10, 12], "realm0": [4, 6]}
        self.status = 503
        with self.assertRaisesRegex(ValueError, "health/ready"):
            steps.services_verify(self.ctx)
        self.status = 200
        self.cursors = {"coordinator": [10, 12], "realm0": [4, 4]}
        with self.assertRaisesRegex(ValueError, "CGB2"):
            steps.services_verify(self.ctx)
        self.cursors = {"coordinator": [10, 10], "realm0": [4, 6]}
        with self.assertRaisesRegex(ValueError, "Coordinator indexer watermark"):
            steps.services_verify(self.ctx)
        self.cursors = {"coordinator": [None], "realm0": [4, 6]}
        with self.assertRaisesRegex(ValueError, "Coordinator indexer watermark"):
            steps.services_verify(self.ctx)
        self.cursors = {"coordinator": [None, None, 10, 12], "realm0": [None, 4, 6]}
        self.assertEqual(steps.services_verify(self.ctx)["watermarks"], {"coordinator": 12, "realm0": 6})

    def test_read_cursor_parses_the_pretty_json_the_indexer_writes(self):
        placement = steps.read_placement(self.ctx)
        for text, expected in (('{\n  "last_checkpoint_id": 42\n}\n', 42), ('{}', None), ('', None),
                               ('{\n  "last_check', None), ('{"last_checkpoint_id": "7"}', None)):
            with self.subTest(text=text), patch.object(steps, "root_script", return_value=text):
                self.assertEqual(REAL_READ_CURSOR(self.ctx, placement, "realm0"), expected)

    def test_verify_requires_running_units_without_restarts(self):
        with patch.object(steps, "unit_state", return_value={"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled",
                                                              "MainPID": "9", "NRestarts": "2"}):
            with self.assertRaisesRegex(ValueError, "without restarts"):
                steps.services_verify(self.ctx)

    def test_verify_requires_empty_deposit_root_query_on_three_chains(self):
        self.assertEqual(steps.services_verify(self.ctx)["deposit_root_rows"], {"0": 0, "1": 0, "2": 0})
        for bad in ({"0": 0, "1": None, "2": 0}, {"0": 0, "1": 0}):
            self.cursors = {"coordinator": [10, 12], "realm0": [4, 6]}
            self.rows = bad
            with self.subTest(rows=bad), self.assertRaisesRegex(ValueError, "deposit root query"):
                steps.services_verify(self.ctx)
        self.cursors = {"coordinator": [10, 12], "realm0": [4, 6]}
        self.rows = {"0": 0, "1": 0, "2": 3}
        self.assertEqual(steps.services_verify(self.ctx)["deposit_root_rows"]["2"], 3)

    def test_envio_verify_needs_polling_that_advances_on_all_three_chains(self):
        chains = prepare_envio.CHAINS
        depths = {chain_id: depth for _, chain_id, depth in chains.values()}
        sequences = [{chain: (100 + 5 * step, depth) for chain, depth in depths.items()} for step in range(3)]
        with patch.object(steps, "envio_rows", side_effect=sequences), patch.object(steps, "hasura_status", return_value=200):
            self.assertEqual(steps.envio_verify(self.ctx)["chains"], sorted(depths))
        stuck = {chain: (100, depth) for chain, depth in depths.items()}
        with patch.object(steps, "envio_rows", return_value=stuck), patch.object(steps, "hasura_status", return_value=200):
            with self.assertRaises(TimeoutError):
                steps.envio_verify(self.ctx)
        wrong_depth = {chain: (100, 1) for chain in depths}
        with patch.object(steps, "envio_rows", return_value=wrong_depth), patch.object(steps, "hasura_status", return_value=200):
            with self.assertRaisesRegex(ValueError, "reorg window"):
                steps.envio_verify(self.ctx)
        with patch.object(steps, "envio_rows", return_value={}), patch.object(steps, "hasura_status", return_value=503):
            with self.assertRaisesRegex(ValueError, "Hasura is not healthy"):
                steps.envio_verify(self.ctx)

    def test_database_login_must_have_the_installer_shape(self):
        self.assertTrue(steps.database_login(self.ctx).startswith("fixture-login-"))
        (self.world.root / "pg-login").write_text("short\n")
        with self.assertRaisesRegex(ValueError, "login file"):
            steps.database_login(self.ctx)
        (self.world.root / "pg-login").write_text("quote'in-" + "a" * 30 + "\n")
        with self.assertRaisesRegex(ValueError, "login file"):
            steps.database_login(self.ctx)

    def test_service_values_are_generated_once_and_kept_private(self):
        first = steps.service_values(self.ctx)
        self.assertEqual(steps.service_values(self.ctx), first)
        path = self.world.state_dir / "service-credentials.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertGreaterEqual(len(first["hasura_admin_secret"]), 32)
        self.assertRegex(first["jwt_secret"], r"[0-9a-f]{64}")

    def test_steps_are_registered_with_the_right_cutover_flags(self):
        self.assertEqual({name: step.cutover for name, step in steps.SERVICES_STEPS.items()},
                         {"plan_bridge_packages": False, "prepare_bridge_packages": True, "start_envio": True, "start_services": True})
        for name, step in steps.SERVICES_STEPS.items():
            self.assertEqual(step.name, name)


if __name__ == "__main__":
    unittest.main()
