import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
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
REAL_READER_ROLE_SQL = steps.reader_role_sql
REAL_SERVICES_READER_STATE = steps.services_reader_state


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
        self.assertEqual(spec["placement"], {"postgres_host": lock["hosts"]["gcp-postgres"], "postgres_port": 5432,
                                             "postgres_user": lock["envio"]["database"], "indexer_port": lock["envio"]["indexer_port"]})

    def test_envio_build_must_carry_verified_evidence(self):
        built = self.world.root / "built"
        built.mkdir()
        (built / "node").write_bytes(b"node")
        evidence = {"source_commit": self.world.lock["sources"]["bridge_reader"], "node_sha256": self.world.lock["envio"]["node_sha256"],
                    "frozen_install_verified": True, "patches_verified": True, "native_help_verified": True,
                    "generated_config_verified": True}
        import install_envio
        evidence["files"] = install_envio.inventory(built)
        (built / "build.json").write_text(json.dumps(evidence))
        self.assertEqual(bridge.check_envio_build(built, self.world.lock), sha((built / "build.json").read_bytes()))
        runtime_build = dict(evidence, source_commit=self.world.lock["sources"]["runtime"])
        (built / "build.json").write_text(json.dumps(runtime_build))
        with self.assertRaisesRegex(ValueError, "not verified"):
            bridge.check_envio_build(built, self.world.lock)
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


class MirrorHostKeyTests(unittest.TestCase):
    BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAI" + "A" * 43

    def test_blob_and_typed_forms_both_become_the_blob(self):
        self.assertEqual(steps.host_key_blob(self.BLOB), self.BLOB)
        self.assertEqual(steps.host_key_blob("ssh-ed25519 " + self.BLOB + "\n"), self.BLOB)

    def test_other_shapes_are_refused(self):
        for value in ("k1", "", "ssh-rsa " + self.BLOB, "ssh-ed25519 ssh-ed25519 " + self.BLOB, self.BLOB + " comment", 7):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "host key"):
                steps.host_key_blob(value)

    def test_known_hosts_line_does_not_double_the_type(self):
        sources = {"a": {"host": "10.0.0.25", "roles": ["coordinator"]}}
        keys = {"10.0.0.25": "ssh-ed25519 " + self.BLOB}
        row = steps.mirror_sources(sources, keys)["a"]
        self.assertEqual(f"{row['host']} ssh-ed25519 {row['host_key']}", f"10.0.0.25 ssh-ed25519 {self.BLOB}")


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
        self.reader = {"reader_ready": True, "envio_chain_ids": [97, 84532, 11155111], "chains": []}
        self.services_reader = True
        self.status = 200
        for name, replacement in (
                ("unit_state", lambda ctx, host, unit: {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled",
                                                        "MainPID": "9", "NRestarts": "0"}),
                ("http_status", lambda ctx, host, url: self.status),
                ("read_cursor", self.read_cursor),
                ("reader_report", lambda ctx, alias: dict(self.reader)),
                ("services_reader_state", lambda ctx, placement: self.services_reader)):
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

    def test_verify_reads_deposits_through_services_and_the_reader_not_hasura(self):
        self.assertEqual(steps.services_verify(self.ctx)["deposits"], {})
        self.cursors = {"coordinator": [10, 12], "realm0": [4, 6]}
        self.reader["chains"] = [{"chain_index": 2, "deposit_count": 3}]
        self.assertEqual(steps.services_verify(self.ctx)["deposits"], {"2": 3})
        self.cursors = {"coordinator": [10, 12], "realm0": [4, 6]}
        self.services_reader = False
        with self.assertRaisesRegex(ValueError, "Services does not report a ready Bridge Reader"):
            steps.services_verify(self.ctx)
        self.cursors = {"coordinator": [10, 12], "realm0": [4, 6]}
        self.services_reader, self.reader["reader_ready"] = True, False
        with self.assertRaisesRegex(ValueError, "not ready on all three chains"):
            steps.services_verify(self.ctx)

    def test_services_reader_state_reads_the_health_details(self):
        placement = steps.read_placement(self.ctx)
        for output, expected in (("true\n", True), ("false\n", False), ("", False)):
            remote = SimpleNamespace(run_script=lambda host, script, timeout: output)
            with self.subTest(output=output):
                self.assertIs(REAL_SERVICES_READER_STATE(SimpleNamespace(**{**vars(self.ctx), "remote": remote}), placement), expected)

    def test_services_check_needs_a_ready_reader(self):
        with patch.object(steps, "bridge_state", return_value={"services": {"gcp-svc": {}}}), \
                patch.object(steps.prepare, "check_tool_hash"), patch.object(steps, "mirror_sources"), \
                patch.object(steps, "database_login"), \
                patch.object(steps.prepare, "local_value", return_value={"mirror_host_keys": {"10.0.0.25": "k", "10.0.0.42": "k",
                                                                                              "10.0.0.43": "k"}}), \
                patch.object(steps, "read_placement", return_value={"groups": {"gcp-svc": {"roles": ["services"]}},
                                                                    "mirror_sources": {}}):
            steps.services_check(self.ctx)
            self.reader["reader_ready"] = False
            with self.assertRaisesRegex(ValueError, "Bridge Reader is not ready"):
                steps.services_check(self.ctx)

    def test_envio_verify_needs_polling_that_advances_on_all_three_chains(self):
        chains = prepare_envio.CHAINS
        depths = {chain_id: depth for _, chain_id, depth in chains.values()}
        sequences = [{chain: (100 + 5 * step, depth) for chain, depth in depths.items()} for step in range(3)]
        with patch.object(steps, "envio_rows", side_effect=sequences):
            self.assertEqual(steps.envio_verify(self.ctx), {"unit": self.world.lock["units"]["envio"], "restarts": 0,
                                                            "chains": sorted(depths)})
        stuck = {chain: (100, depth) for chain, depth in depths.items()}
        with patch.object(steps, "envio_rows", return_value=stuck):
            with self.assertRaises(TimeoutError):
                steps.envio_verify(self.ctx)
        wrong_depth = {chain: (100, 1) for chain in depths}
        with patch.object(steps, "envio_rows", return_value=wrong_depth):
            with self.assertRaisesRegex(ValueError, "reorg window"):
                steps.envio_verify(self.ctx)
        with patch.object(steps, "envio_rows", return_value={}):
            with self.assertRaisesRegex(ValueError, "all three chains"):
                steps.envio_verify(self.ctx)

    def test_envio_apply_sends_only_the_database_login(self):
        recorded = {}

        def stage(ctx, summary, secrets_raw):
            recorded["secrets"] = json.loads(secrets_raw)
            return "f" * 64
        scripts = []
        with patch.object(steps, "read_envio_summary", return_value={"built": "/x", "build_sha256": "a" * 64}), \
                patch.object(steps, "unit_state", return_value={"LoadState": "not-found"}), \
                patch.object(steps, "root_script", side_effect=lambda ctx, host, script, timeout=0: scripts.append(script) or ""), \
                patch.object(steps, "postgres_script"), patch.object(steps, "stage_envio", side_effect=stage), \
                patch.object(steps, "run_envio_tool", return_value="") as tool:
            steps.envio_apply(self.ctx)
        self.assertEqual(recorded["secrets"], {"postgres_password": steps.database_login(self.ctx)})
        self.assertEqual([call.args[1] for call in tool.call_args_list], ["check-host", "install", "activate"])
        self.assertFalse(any("docker pull" in script or "graphql-engine" in script for script in scripts))

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
        self.assertRegex(first["jwt_secret"], r"[0-9a-f]{64}")
        self.assertRegex(first["bridge_reader_token"], r"^[0-9a-f]{64}$")
        self.assertRegex(first["bridge_reader_login"], r"^[A-Za-z0-9_-]{64}$")
        self.assertNotEqual(first["bridge_reader_login"], steps.database_login(self.ctx))
        path.write_text(json.dumps(dict(first, bridge_reader_login="quote'" + "a" * 30)))
        with self.assertRaisesRegex(ValueError, "Bridge Reader credentials"):
            steps.service_values(self.ctx)

    def test_steps_are_registered_with_the_right_cutover_flags(self):
        self.assertEqual({name: step.cutover for name, step in steps.SERVICES_STEPS.items()},
                         {"plan_bridge_packages": False, "prepare_bridge_packages": True, "start_envio": True,
                          "start_bridge_reader": True, "start_services": True})
        for name, step in steps.SERVICES_STEPS.items():
            self.assertEqual(step.name, name)



class ReaderStepTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.world = BridgeWorld(self.temp.name)
        self.binary = self.world.root / "psy-bridge-reader"
        self.binary.write_bytes(b"\x7fELF reader")
        self.world.lock["binaries"]["psy-bridge-reader"] = sha(self.binary.read_bytes())
        local = json.loads((self.world.private_dir / "local-inputs.json").read_bytes())
        local["files"]["psy_bridge_reader"] = str(self.binary)
        (self.world.private_dir / "local-inputs.json").write_text(json.dumps(local))
        self.world.rewrite_lock()
        self.remote = SimpleNamespace(copies=[], tools=[])
        self.remote.copy_files = lambda host, sources, destination, timeout_seconds=0: self.remote.copies.append((host, sources, destination))
        self.remote.run_root_text = self.run_root_text
        self.ctx = SimpleNamespace(**{**vars(self.world.ctx()), "remote": self.remote})
        self.report = {"reader_ready": True, "envio_chain_ids": [97, 84532, 11155111], "chains": []}
        self.sql = []
        self.scripts = []
        for name, replacement in (
                ("reader_role_sql", lambda ctx: "GRANT SELECT ON :\"envio_schema\".\"Deposit\" TO :\"reader_role\";\n"),
                ("postgres_script", lambda ctx, sql, timeout=0, database="postgres": self.sql.append((database, sql))),
                ("root_script", lambda ctx, host, script, timeout=0: self.scripts.append((host, script)) or "")):
            patcher = patch.object(steps, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_root_text(self, host, argv, timeout, stdin_text=None, show_stderr=True):
        self.remote.tools.append((host, argv, stdin_text))
        return json.dumps(self.report) + "\n"

    def test_apply_creates_the_role_grants_installs_and_activates(self):
        with patch.object(steps, "unit_state", return_value={"LoadState": "not-found"}):
            steps.reader_apply(self.ctx)
        role, database = self.world.lock["bridge_reader"]["database_role"], self.world.lock["envio"]["database"]
        values = steps.service_values(self.ctx)
        (_, role_sql), (grant_database, grant_sql) = self.sql
        self.assertIn(f'ALTER ROLE "{role}" LOGIN PASSWORD \'{values["bridge_reader_login"]}\'', role_sql)
        self.assertIn("CONNECTION LIMIT 8", role_sql)
        self.assertIn("default_transaction_read_only = on", role_sql)
        self.assertEqual(grant_database, database)
        self.assertTrue(grant_sql.startswith(f"\\set reader_role {role}\n\\set envio_schema envio\n"))
        self.assertIn(f'GRANT CONNECT ON DATABASE "{database}" TO "{role}";', grant_sql)
        self.assertNotIn("INSERT", grant_sql.upper().replace("GRANT SELECT", ""))
        modes = [argv[4] for _, argv, _ in self.remote.tools]
        self.assertEqual(modes, ["check-host", "install", "activate"])
        stage = steps.reader_stage(self.ctx)
        self.assertEqual(self.remote.copies[0][1][0], self.binary)
        _, install_argv, stdin = self.remote.tools[1]
        self.assertEqual(install_argv[install_argv.index("--binary") + 1], f"{stage}/psy-bridge-reader")
        self.assertEqual(json.loads(stdin), {"postgres_password": values["bridge_reader_login"], "token": values["bridge_reader_token"]})
        self.assertFalse(any(values["bridge_reader_token"] in " ".join(argv) for _, argv, _ in self.remote.tools))
        activate = self.remote.tools[2][1]
        self.assertEqual(activate[3], self.world.lock["bridge_reader"]["release"] + "/install_bridge_reader.py")
        self.assertIn("--apply", activate)
        self.assertIn(f"rm -rf -- {stage}\n", [script for _, script in self.scripts][-1])

    def test_apply_on_a_running_ready_reader_only_reapplies_the_grants(self):
        running = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled", "MainPID": "9", "NRestarts": "0"}
        with patch.object(steps, "unit_state", return_value=running):
            steps.reader_apply(self.ctx)
        self.assertEqual([argv[4] for _, argv, _ in self.remote.tools], ["status"])
        self.assertEqual(len(self.sql), 2)

    def test_apply_on_an_installed_stopped_reader_activates_without_reinstalling(self):
        with patch.object(steps, "unit_state", return_value={"LoadState": "loaded", "ActiveState": "inactive"}):
            steps.reader_apply(self.ctx)
        self.assertEqual([argv[4] for _, argv, _ in self.remote.tools], ["activate"])
        self.assertEqual(self.remote.copies, [])

    def test_verify_needs_a_running_ready_reader(self):
        running = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled", "MainPID": "9", "NRestarts": "0"}
        with patch.object(steps, "unit_state", return_value=running):
            self.assertEqual(steps.reader_verify(self.ctx)["unit"], self.world.lock["units"]["bridge_reader"])
            self.report = dict(self.report, reader_ready=False)
            with self.assertRaisesRegex(ValueError, "not ready"):
                steps.reader_verify(self.ctx)
        with patch.object(steps, "unit_state", return_value=dict(running, NRestarts="1")):
            with self.assertRaisesRegex(ValueError, "without restarts"):
                steps.reader_verify(self.ctx)

    def test_grant_script_is_read_from_the_pinned_reader_commit(self):
        repo = self.world.root / "node"
        sql = repo / "psy_bridge_reader_api/sql/reader-role.sql"
        sql.parent.mkdir(parents=True)
        git = lambda *args: subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q")
        sql.write_text("GRANT SELECT ON pinned TO reader;\n")
        git("add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "pinned")
        pinned = git("rev-parse", "HEAD")
        sql.write_text("GRANT ALL ON later TO reader;\n")
        self.world.lock["sources"]["bridge_reader"] = pinned
        self.assertEqual(REAL_READER_ROLE_SQL(self.ctx), "GRANT SELECT ON pinned TO reader;\n")
        self.world.lock["sources"]["bridge_reader"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "grant script is missing"):
            REAL_READER_ROLE_SQL(self.ctx)

    def test_check_refuses_a_binary_that_differs_from_the_lock(self):
        with patch.object(steps, "envio_rows_ready", return_value=True), patch.object(steps.prepare, "check_tool_hash"):
            steps.reader_check(self.ctx)
            self.binary.write_bytes(b"other")
            with self.assertRaisesRegex(ValueError, "Reader binary differs"):
                steps.reader_check(self.ctx)


if __name__ == "__main__":
    unittest.main()
