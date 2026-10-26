import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("core_plan", HERE / "plan.py")
plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plan)
WORKER_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def fixture():
    topology, _ = plan.read_json(HERE / "topology.json")
    policy = {"enabled": True, "secp256k1": [WORKER_KEY]}
    whitelist = {"networks": {"testnet": {"whitelist": copy.deepcopy(policy)}}}
    selected = copy.deepcopy(plan.CONSENSUS)
    selected.update(whitelist=policy, fees={"register_user_fee": 0, "deploy_contract_fee": 0,
                                          "guta_fee": 1000000000, "da_fee": 1000},
                    guardian_initial_member_hashes=[f"{i:064x}" for i in (1, 2, 3)])
    c = topology["coordinator"]
    selected["coordinator_configs"] = [{"id": 0, "rpc_url": [
        f'http://{topology["hosts"][c["host"]]}:{port}' for port in c["edge_ports"]]}]
    selected["realm_configs"] = []
    genesis = {"validators": [], "users": [{
        "public_key_info": {"fingerprint": "01" * 32, "public_key_param": "02" * 32},
        "balance": 1000000000, "nonce": 0, "last_checkpoint_id": 0, "event_index": 0,
        "constract_state_tree_records": [],
    } for _ in range(107)]}
    for rid, realm in enumerate(topology["realms"]):
        public = {"id": rid, "rpc_url": [], "validators": []}
        for index, v in enumerate(realm["validators"]):
            serial = rid * 3 + index + 1
            node = "002408011220" + f"{serial:064x}"
            edge = "002408011220" + f"{serial + 10:064x}"
            bls = f"{serial:096x}"
            public["rpc_url"].append(f'http://{topology["hosts"][v["edge_host"]]}:{v["http_port"]}')
            public["validators"].append({
                "validator_user_id": v["validator_user_id"], "processor_node_id": node,
                "bls_public_key": bls,
                "processor_addresses": [f'/ip4/{topology["hosts"][v["processor_host"]]}/tcp/{v["processor_port"]}/p2p/{plan.peer_id(node)}'],
                "edge_nodes": [{"node_id": edge, "addresses": [
                    f'/ip4/{topology["hosts"][v["edge_host"]]}/tcp/{v["edge_port"]}/p2p/{plan.peer_id(edge)}']}],
            })
            genesis["validators"].append({"realm_id": rid, "validator_user_id": v["validator_user_id"],
                                          "node_id": node, "bls_public_key": bls})
        selected["realm_configs"].append(public)
    config = {"defaultNetwork": "testnet", "networks": {"testnet": selected}}
    return topology, config, genesis, whitelist


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.t, self.c, self.g, self.w = fixture()

    def report(self):
        return plan.make_plan(self.t, self.c, self.g, self.w)

    def edit_networks(self, edit):
        for network in self.c["networks"].values():
            edit(network)

    def reject(self, message):
        with self.assertRaisesRegex(plan.PlanError, message):
            self.report()

    def test_default_plan_is_blocked_but_has_six_pairs_and_four_coordinator_services(self):
        report = plan.make_plan(self.t)
        self.assertFalse(report["input_consistency_passed"])
        self.assertFalse(report["deployment_ready"])
        self.assertEqual(len(report["services"]), 16)
        self.assertEqual(len(report["blockers"]), 2)

    def test_matching_inputs_do_not_approve_unpublished_runtime_candidate(self):
        report = self.report()
        self.assertTrue(report["input_consistency_passed"])
        self.assertEqual(report["blockers"], [plan.RUNTIME_BLOCKER])
        self.assertIn("not published", report["blockers"][0])
        self.assertIsNone(report["runtime_commit"])
        self.assertEqual(report["runtime_source_base"], plan.RUNTIME_SOURCE_BASE)
        self.assertEqual(report["runtime_patch_sha256"], plan.RUNTIME_PATCH_SHA256)
        self.assertFalse(report["deployment_ready"])
        self.assertFalse(report["release_approved"])
        self.assertTrue(all(not service["deployment_ready"] for service in report["services"]))

    def test_faucet_account_generation_is_explicit(self):
        account_plan = self.report()["genesis_account_plan"]
        self.assertEqual(account_plan["faucet_operator_count"], 100)
        self.assertEqual(account_plan["total_user_count"], 107)
        self.assertEqual(account_plan["faucet_registration_range"], [7, 106])
        self.assertFalse(account_plan["operator_inventory_verified"])
        args = account_plan["required_generator_account_args"]
        self.assertEqual(args[:2], ["--faucet-operator-count", "100"])
        self.assertEqual([args[i + 1] for i, arg in enumerate(args) if arg == "--validator-slot"],
                         ["0,1,0", "1,1,1", "1,2,3", "0,2,4", "1,3,5", "0,3,6"])

    def test_wrong_faucet_count_is_rejected(self):
        for count in (10, 99, 101, True, "100"):
            with self.subTest(count=count):
                self.t["faucet_operator_count"] = count
                self.reject("faucet operator count")

    def test_old_ten_operator_genesis_is_rejected(self):
        self.g["users"] = self.g["users"][:17]
        self.reject("107 users")

    def test_testnet_config_does_not_require_a_localhost_mirror(self):
        self.assertEqual(set(self.c["networks"]), {"testnet"})
        self.assertTrue(self.report()["input_consistency_passed"])
        self.c["networks"]["localhost"] = {"whitelist": {"enabled": False}}
        self.assertTrue(self.report()["input_consistency_passed"])

    def test_network_selection_matches_all_sixteen_services(self):
        for report in (plan.make_plan(self.t), self.report()):
            with self.subTest(inputs_valid=report["input_consistency_passed"]):
                selection = report["network_selection"]
                self.assertEqual(selection, {
                    "build_stage": "testnet", "runtime_stage": "testnet",
                    "cli_network": "psy-public-testnet",
                    "proving_backend": "plonky2-poseidon-goldilocks",
                    "config_selector": "networks.testnet",
                })
                self.assertEqual(len(report["services"]), 16)
                for service in report["services"]:
                    argv = service["argv"]
                    self.assertEqual(service["environment"]["PSY_NETWORK"], selection["runtime_stage"])
                    self.assertEqual(argv[argv.index("--network") + 1], selection["cli_network"])
                    self.assertEqual(argv[argv.index("--proving-backend") + 1], selection["proving_backend"])

    def test_localhost_config_cannot_replace_testnet(self):
        self.c["networks"]["localhost"] = self.c["networks"].pop("testnet")
        self.reject("testnet config required")

    def test_default_network_must_be_testnet(self):
        self.c["defaultNetwork"] = "localhost"
        self.reject("defaultNetwork must be testnet")

    def test_namespace_shared_only_with_owning_edge(self):
        services = self.report()["services"]
        namespaces = {}
        for service in services:
            namespaces.setdefault(service["namespace"], []).append(service)
        self.assertEqual(sorted(map(len, namespaces.values())), [2, 2, 2, 2, 2, 2, 4])
        for name, pair in namespaces.items():
            if len(pair) == 2:
                self.assertIn("start-realm-processor", pair[0]["argv"])
                self.assertIn("start-realm-edge", pair[1]["argv"])
                self.assertEqual(pair[0]["argv"][pair[0]["argv"].index("--db-namespace") + 1], name)

    def test_argv_and_systemd_match_existing_cli_without_realm_subid(self):
        services = self.report()["services"]
        for s in services:
            argv = s["argv"]
            self.assertNotIn("--realm-sub-id", argv)
            self.assertNotIn("--dbsubid", argv)
            self.assertEqual(s["environment"]["PSY_NETWORK"], "testnet")
            self.assertIn('Environment="PSY_NETWORK=testnet"', s["systemd_preview"])
            self.assertEqual(argv[argv.index("--network") + 1], "psy-public-testnet")
            self.assertEqual(argv[argv.index("--proving-backend") + 1], "plonky2-poseidon-goldilocks")
            self.assertIn('"--network" "psy-public-testnet"', s["systemd_preview"])
            self.assertNotIn("localhost", s["systemd_preview"])
            self.assertIn("OFFLINE PREVIEW", s["systemd_preview"])
            self.assertNotIn("[Install]", s["systemd_preview"])
            if "start-realm-processor" in argv:
                for flag in ("--p2p-identity-key", "--p2p-bls-key", "--p2p-zk-key",
                             "--p2p-listen", "--checkpoint-backup-path"):
                    self.assertIn(flag, argv)
                start = argv.index("--coordinator-api-urls") + 1
                self.assertEqual(argv[start:start + 3], [f"http://10.148.0.25:{p}" for p in (15370, 15371, 15372)])
            if "edge" in argv[1]:
                self.assertIn("--worker-whitelist-config", argv)
                self.assertEqual(argv[argv.index("--worker-whitelist-config") + 1],
                                 s["environment"]["PSY_CONFIG_PATH"])
                self.assertTrue(s["environment"]["PSY_CONFIG_PATH"].endswith("/config.json"))
            else:
                self.assertNotIn("--worker-whitelist-config", argv)
        self.assertEqual(sum("--worker-whitelist-config" in s["argv"] for s in services), 9)

    def test_exact_reserved_slots_and_host_counts(self):
        self.assertEqual([(r, p, v["registration_id"], v["validator_user_id"])
                          for r, p, v in plan.validators(self.t)],
                         [(0, 1, 0, 0), (0, 2, 4, 262144), (0, 3, 6, 786432),
                          (1, 1, 1, 1048576), (1, 2, 3, 1572864), (1, 3, 5, 1310720)])
        hosts = [s["host"] for s in self.report()["services"]]
        for host in plan.PROCESSORS:
            self.assertEqual(hosts.count(host), 2)
        for host in plan.EDGES:
            self.assertEqual(hosts.count(host), 3)

    def test_namespace_collision_rejected(self):
        self.t["realms"][1]["validators"][0]["namespace"] = self.t["realms"][0]["validators"][0]["namespace"]
        self.reject("shared namespace")

    def test_coordinator_namespace_collision_rejected(self):
        self.t["realms"][0]["validators"][0]["namespace"] = self.t["coordinator"]["namespace"]
        self.reject("shared namespace")

    def test_namespace_normalization_alias_and_injection_rejected(self):
        for value in ("fresh20261026.r0.v1", "realm_0", "fresh20261026_r0;id", "fresh20261026_%i"):
            with self.subTest(value=value):
                self.t["realms"][0]["validators"][0]["namespace"] = value
                self.reject("invalid fresh namespace")

    def test_port_collision_between_edge_http_and_p2p_rejected(self):
        v = self.t["realms"][0]["validators"][0]
        v["http_port"] = v["edge_port"]
        self.reject("duplicate host/listener")

    def test_legacy_port_rejected(self):
        self.t["realms"][0]["validators"][0]["http_port"] = 1338
        self.reject("listener port")

    def test_duplicate_processor_socket_rejected(self):
        self.t["realms"][1]["validators"][0]["processor_port"] = 41001
        self.reject("duplicate host/listener")

    def test_public_host_and_credentials_rejected(self):
        for value in ("nats://8.8.8.8:4222", "nats://user:password@10.148.0.20:4222"):
            with self.subTest(value=value):
                self.t["infrastructure"]["nats_jetstream_url"] = value
                self.reject("RFC1918|credentials")

    def test_infrastructure_url_cannot_inject_systemd_environment_or_arguments(self):
        for value in ("nats://10.148.0.20:4222\n", "nats://10.148.0.20:04222",
                      "nats://10.148.0.20:4222/#%i", "nats://10.148.0.20:4222\t"):
            with self.subTest(value=value):
                self.t["infrastructure"]["nats_jetstream_url"] = value
                with self.assertRaises(plan.PlanError):
                    self.report()

    def test_frozen_revision_network_backend_rejected_on_change(self):
        for field, value in (("runtime_commit", "0" * 40),
                             ("runtime_commit", plan.RUNTIME_SOURCE_BASE),
                             ("runtime_source_base", "0" * 40),
                             ("runtime_patch_sha256", "0" * 64),
                             ("psy_network", "localhost"), ("network", "local-devnet"),
                             ("proving_backend", "jtmb-poseidon-goldilocks")):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.t)
                candidate[field] = value
                with self.assertRaises(plan.PlanError):
                    plan.make_plan(candidate)

    def test_runtime_provenance_fields_are_required(self):
        for field in ("runtime_commit", "runtime_source_base", "runtime_patch_sha256"):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.t)
                del candidate[field]
                with self.assertRaisesRegex(plan.PlanError, "missing fields"):
                    plan.make_plan(candidate)

    def test_registration_order_and_bool_ids_rejected(self):
        v = self.t["realms"][1]["validators"][1]
        v["registration_id"] = 5
        self.reject("approved slots")
        v["registration_id"] = True
        self.reject("registration ID")

    def test_config_magic_tree_height_epoch_and_type_mismatch_rejected(self):
        for field, value in (("magic", "0x1"), ("realm_user_tree_height", 19),
                             ("p2p", {"checkpoints_per_epoch": 1}), ("group_realm_height", True)):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.c)
                candidate["networks"]["testnet"][field] = value
                with self.assertRaisesRegex(plan.PlanError, "consensus mismatch"):
                    plan.make_plan(self.t, candidate, self.g, self.w)

    def test_genesis_missing_and_tampered_membership_rejected(self):
        self.g["validators"].pop()
        self.reject("six validators")
        _, _, self.g, _ = fixture()
        self.g["validators"][0]["bls_public_key"] = "09" * 48
        self.reject("Genesis validator membership")

    def test_genesis_registration_requires_actual_public_key_fields(self):
        self.g["users"][6]["public_key_info"] = {"placeholder": True}
        self.reject("Genesis public key info")

    def test_genesis_membership_order_is_not_a_separate_subid(self):
        self.g["validators"].reverse()
        self.assertTrue(self.report()["input_consistency_passed"])

    def test_public_validator_order_rejected(self):
        self.edit_networks(lambda n: n["realm_configs"][0]["validators"].reverse())
        self.reject("public validator order")

    def test_wrong_advertised_ip_or_peerid_rejected(self):
        self.edit_networks(lambda n: n["realm_configs"][0]["validators"][0].update(
            processor_addresses=["/ip4/127.0.0.1/tcp/41001/p2p/bad"]))
        self.reject("P2P address/PeerId")

    def test_duplicate_identity_and_bls_rejected(self):
        self.edit_networks(lambda n: n["realm_configs"][0]["validators"][1].update(
            bls_public_key=n["realm_configs"][0]["validators"][0]["bls_public_key"]))
        self.reject("duplicate BLS")
        _, self.c, _, _ = fixture()
        self.edit_networks(lambda n: n["realm_configs"][0]["validators"][0]["edge_nodes"][0].update(
            node_id=n["realm_configs"][0]["validators"][0]["processor_node_id"]))
        self.reject("duplicate processor/edge")

    def test_empty_disabled_missing_wrong_network_whitelist_rejected(self):
        policies = ({"enabled": True, "secp256k1": []}, {"enabled": False, "secp256k1": [WORKER_KEY]},
                    {"secp256k1": [WORKER_KEY]}, {"enabled": True, "secp256k1": [WORKER_KEY, WORKER_KEY]})
        for policy in policies:
            with self.subTest(policy=policy):
                self.w["networks"]["testnet"]["whitelist"] = policy
                with self.assertRaises(plan.PlanError):
                    self.report()
        self.w = {"networks": {"localhost": {"whitelist": {"enabled": True, "secp256k1": [WORKER_KEY]}}}}
        self.reject("runtime worker whitelist networks")

    def test_embedded_and_dedicated_testnet_policies_must_match(self):
        for policy in (None, {"enabled": False, "secp256k1": [WORKER_KEY]},
                       {"enabled": True, "secp256k1": []},
                       {"enabled": True, "secp256k1": ["03" + WORKER_KEY[2:]]}):
            with self.subTest(policy=policy):
                self.c["networks"]["testnet"]["whitelist"] = policy
                self.reject("testnet whitelist differs from dedicated policy")

    def test_guardian_commitments_not_fabricated(self):
        self.edit_networks(lambda n: n.update(guardian_initial_member_hashes=[]))
        self.reject("three Guardian")

    def test_cli_is_readonly_no_network_subprocess_or_install(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for name, obj in (("config", self.c), ("genesis", self.g), ("whitelist", self.w)):
                path = Path(directory) / (name + ".json")
                path.write_text(json.dumps(obj))
                paths.extend(["--" + name, str(path)])
            before = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
            output = io.StringIO()
            with patch("subprocess.Popen", side_effect=AssertionError("subprocess forbidden")), \
                 patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                 patch.object(Path, "write_text", side_effect=AssertionError("write forbidden")), \
                 patch.object(Path, "write_bytes", side_effect=AssertionError("write forbidden")), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(plan.main(paths), 2)
            report = json.loads(output.getvalue())
            self.assertFalse(report["deployment_ready"])
            self.assertEqual(set(report["input_sha256"]), {"topology", "config", "genesis", "whitelist"})
            self.assertEqual(before, {p.name: p.read_bytes() for p in Path(directory).iterdir()})

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(plan.PlanError, "duplicate JSON"):
                plan.read_json(path)

    def test_malformed_input_has_no_traceback_or_executable_preview(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for value in ("{bad", "[]", '{"hosts":null}'):
                path.write_text(value)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(plan.main(["--topology", str(path)]), 2)
                result = json.loads(output.getvalue())
                self.assertEqual(result["services"], [])
                self.assertFalse(result["deployment_ready"])

    def test_invalid_supplied_config_never_prints_a_service_preview(self):
        with tempfile.TemporaryDirectory() as directory:
            self.g["validators"][0]["validator_user_id"] = 1
            args = []
            for name, data in (("config", self.c), ("genesis", self.g), ("whitelist", self.w)):
                path = Path(directory) / name
                path.write_text(json.dumps(data))
                args.extend(["--" + name, str(path)])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(plan.main(args), 2)
            report = json.loads(output.getvalue())
            self.assertEqual(report["services"], [])
            self.assertIn("Genesis validator membership", report["blockers"][0])

    def test_apply_flag_does_not_exist(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            plan.main(["--apply"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
