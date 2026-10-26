import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("prepare_network", HERE / "prepare_network.py")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
WORKER_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def fixture():
    topology = json.loads((HERE / "topology.json").read_text())
    network = copy.deepcopy(prepare.CONSENSUS)
    network.update(
        realm_configs=[{"id": rid, "rpc_url": ["https://old.example"], "validators": []}
                       for rid in (0, 1)],
        coordinator_configs=[{"id": 0, "rpc_url": ["https://old.example"]}],
        fees={"register_user_fee": 0, "deploy_contract_fee": 0, "guta_fee": 1000000000, "da_fee": 1000},
        whitelist={"enabled": False, "secp256k1": []},
        native_currency="0", native_currency_symbol="PSY", nostr_relay_url="wss://old.example",
        l1_config_url="https://old.example/config.json",
        guardian_history={"listen_address": "127.0.0.1:15450"})
    for name in prepare.PERIPHERAL_LISTS:
        network[name] = ["https://old.example"]
    canonical = {"defaultNetwork": "localhost", "networks": {
        "localhost": copy.deepcopy(network), "testnet": copy.deepcopy(network),
        "mainnet": {"unchanged": True}}}
    p2p = copy.deepcopy(canonical)
    p2p["defaultNetwork"] = "testnet"
    for rid, realm in enumerate(p2p["networks"]["testnet"]["realm_configs"]):
        for index, (_, uid) in enumerate(prepare.SLOTS[rid]):
            serial = rid * 3 + index + 1
            # Public encoding fixtures only, not generated keys or curve validation.
            node = "002408011220" + f"{serial:064x}"
            edge = "002408011220" + f"{serial + 10:064x}"
            realm["validators"].append({
                "validator_user_id": uid, "processor_node_id": node,
                "bls_public_key": f"{serial:096x}",
                "processor_addresses": [f"/ip4/127.0.0.1/tcp/41001/p2p/{prepare.peer_id(node)}"],
                "edge_nodes": [{"node_id": edge, "addresses": [
                    f"/ip4/127.0.0.1/tcp/41101/p2p/{prepare.peer_id(edge)}"]}],
            })
    commitments = {"node_source": prepare.SOURCE_BASE, "user_cli_sha256": "ab" * 32,
                   "guardian_initial_member_hashes": [f"{i:064x}" for i in (1, 2, 3)],
                   "password_storage": "systemd user-scoped host-bound encrypted credentials"}
    genesis = {"contracts": [{"unchanged": "contract bytes"}],
               "users": [{"public_key_info": {"fingerprint": "01" * 32, "public_key_param": "02" * 32},
                          "constract_state_tree_records": [{"untouched": index}]} for index in range(107)],
               "checkpoint_stats": {"block_time": 1764248609},
               "deposit_tree_root": "03" * 32, "withdrawal_tree_root": "04" * 32,
               "validators": []}
    whitelist = {"networks": {"testnet": {"whitelist": {
        "enabled": True, "secp256k1": [WORKER_KEY]}}}}
    return canonical, p2p, commitments, topology, whitelist, genesis


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.canonical, self.p2p, self.commitments, self.topology, self.whitelist, self.genesis = fixture()

    def assemble(self):
        return prepare.assemble_config(self.canonical, self.p2p, self.commitments, self.topology, self.whitelist)

    def members(self):
        return self.p2p["networks"]["testnet"]["realm_configs"][0]["validators"]

    def test_addresses_and_membership_preserve_all_identities(self):
        original = copy.deepcopy((self.canonical, self.p2p, self.commitments, self.topology, self.whitelist))
        result = self.assemble()
        self.assertEqual((self.canonical, self.p2p, self.commitments, self.topology, self.whitelist), original)
        self.assertEqual(result["defaultNetwork"], "testnet")
        self.assertEqual(result["networks"]["mainnet"], self.canonical["networks"]["mainnet"])
        self.assertEqual(result["networks"]["localhost"], self.canonical["networks"]["localhost"])
        for name in ("testnet",):
            network = result["networks"][name]
            self.assertEqual(network["guardian_initial_member_hashes"], self.commitments["guardian_initial_member_hashes"])
            self.assertEqual(network["guardian_configs"], prepare.GUARDIANS)
            self.assertEqual(network["fees"], self.canonical["networks"][name]["fees"])
            self.assertEqual(network["whitelist"], self.whitelist["networks"]["testnet"]["whitelist"])
            for field, value in prepare.CONSENSUS.items():
                self.assertEqual(network[field], value)
            self.assertEqual(network["coordinator_configs"], [{"id": 0, "rpc_url": [
                f"http://10.148.0.25:{port}" for port in (15370, 15371, 15372)]}])
            for rid, realm in enumerate(network["realm_configs"]):
                expected_rpc = []
                for index, member in enumerate(realm["validators"]):
                    source = self.p2p["networks"]["testnet"]["realm_configs"][rid]["validators"][index]
                    slot = self.topology["realms"][rid]["validators"][index]
                    for field in ("validator_user_id", "processor_node_id", "bls_public_key"):
                        self.assertEqual(member[field], source[field])
                    self.assertEqual(member["edge_nodes"][0]["node_id"], source["edge_nodes"][0]["node_id"])
                    for node, addresses, host, port in (
                        (member["processor_node_id"], member["processor_addresses"], slot["processor_host"], slot["processor_port"]),
                        (member["edge_nodes"][0]["node_id"], member["edge_nodes"][0]["addresses"], slot["edge_host"], slot["edge_port"]),
                    ):
                        self.assertEqual(addresses, [f'/ip4/{self.topology["hosts"][host]}/tcp/{port}/p2p/{prepare.peer_id(node)}'])
                    expected_rpc.append(f'http://{self.topology["hosts"][slot["edge_host"]]}:{slot["http_port"]}')
                self.assertEqual(realm["rpc_url"], expected_rpc)
            for field in prepare.PERIPHERAL_LISTS:
                self.assertEqual(network[field], [])
            self.assertEqual(network["nostr_relay_url"], "")
            self.assertNotIn("l1_config_url", network)
            self.assertNotIn("guardian_history", network)

    def test_only_testnet_source_is_supported(self):
        self.assertEqual(self.assemble()["defaultNetwork"], "testnet")
        self.p2p["defaultNetwork"] = "localhost"
        with self.assertRaisesRegex(prepare.PrepareError, "P2P source defaultNetwork"):
            self.assemble()

    def test_canonical_localhost_is_not_required_or_used(self):
        self.canonical["networks"].pop("localhost")
        self.p2p["networks"]["localhost"] = {"not_selected": True}
        result = self.assemble()
        self.assertNotIn("localhost", result["networks"])
        self.assertEqual(len(result["networks"]["testnet"]["realm_configs"][0]["validators"]), 3)

    def test_runtime_patch_provenance_is_separate_from_retained_guardian_identity(self):
        before = copy.deepcopy(self.commitments)
        first = self.assemble()
        self.assertIsNone(self.topology["runtime_commit"])
        self.assertEqual(self.topology["runtime_source_base"], prepare.SOURCE_BASE)
        self.assertEqual(len(self.topology["runtime_patch_sha256"]), 64)
        self.assertEqual(self.assemble(), first)
        self.assertEqual(self.commitments, before)
        self.assertEqual(self.commitments["node_source"], prepare.SOURCE_BASE)
        for field, value in (("runtime_commit", prepare.SOURCE_BASE),
                             ("runtime_commit", "cd" * 20),
                             ("runtime_commit", "invalid"),
                             ("runtime_source_base", "cd" * 20),
                             ("runtime_patch_sha256", None), ("runtime_patch_sha256", "00" * 32),
                             ("runtime_patch_sha256", "invalid")):
            with self.subTest(field=field, value=value):
                saved = self.topology[field]
                self.topology[field] = value
                with self.assertRaises(prepare.PrepareError):
                    self.assemble()
                self.topology[field] = saved

    def test_whitelist_must_be_enabled_nonempty_and_testnet_only(self):
        invalid = [
            {}, {"networks": {}},
            {"networks": {"localhost": self.whitelist["networks"]["testnet"]}},
            {"networks": {"testnet": self.whitelist["networks"]["testnet"], "localhost": {}}},
        ]
        for policy in ({"enabled": False, "secp256k1": [WORKER_KEY]},
                       {"enabled": 1, "secp256k1": [WORKER_KEY]},
                       {"enabled": True, "secp256k1": []},
                       {"enabled": True, "secp256k1": WORKER_KEY}):
            invalid.append({"networks": {"testnet": {"whitelist": policy}}})
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(prepare.PrepareError):
                prepare.validate_whitelist(document)

    def test_topology_rejects_legacy_patch_field(self):
        self.topology["patch_sha256"] = self.topology.pop("runtime_patch_sha256")
        with self.assertRaisesRegex(prepare.PrepareError, "topology: unexpected or missing fields"):
            self.assemble()

    def test_whitelist_rejects_bad_encodings_points_and_duplicate_keys(self):
        prime = (1 << 256) - (1 << 32) - 977
        nonresidue_x = next(x for x in range(100)
                            if pow((pow(x, 3, prime) + 7) % prime, (prime - 1) // 2, prime) == prime - 1)
        invalid_keys = [[WORKER_KEY, "0X" + WORKER_KEY.upper()], ["04" + WORKER_KEY[2:]],
                        ["02" + "ff" * 32], ["02" + f"{nonresidue_x:064x}"],
                        ["02" + f"{prime:064x}"], ["bad"], [None]]
        for keys in invalid_keys:
            with self.subTest(keys=keys):
                self.whitelist["networks"]["testnet"]["whitelist"]["secp256k1"] = keys
                with self.assertRaises(prepare.PrepareError):
                    self.assemble()

    def test_whitelist_valid_compressed_encodings_preserve_order(self):
        keys = ["0X" + WORKER_KEY.upper(), "03" + WORKER_KEY[2:]]
        self.whitelist["networks"]["testnet"]["whitelist"]["secp256k1"] = keys
        result = self.assemble()
        self.assertEqual(result["networks"]["testnet"]["whitelist"]["secp256k1"], keys)

    def test_guardian_order_preserved_and_invalid_commitments_rejected(self):
        self.commitments["guardian_initial_member_hashes"].reverse()
        self.assertEqual(self.assemble()["networks"]["testnet"]["guardian_initial_member_hashes"],
                         self.commitments["guardian_initial_member_hashes"])
        for invalid in (["01" * 32] * 3, ["00" * 32, "01" * 32, "02" * 32], ["01" * 32],
                        ["bad", "01" * 32, "02" * 32]):
            with self.subTest(invalid=invalid):
                self.commitments["guardian_initial_member_hashes"] = invalid
                with self.assertRaises(prepare.PrepareError):
                    self.assemble()

    def test_rejects_peer_mismatch_and_duplicate_identities(self):
        member = self.members()[0]
        member["processor_addresses"][0] += "1"
        with self.assertRaisesRegex(prepare.PrepareError, "PeerId"):
            self.assemble()
        member["processor_addresses"][0] = member["processor_addresses"][0][:-1]
        self.members()[1]["processor_node_id"] = member["processor_node_id"]
        with self.assertRaisesRegex(prepare.PrepareError, "duplicate processor/edge"):
            self.assemble()

    def test_rejects_duplicate_bls_and_unknown_validator_fields(self):
        self.members()[1]["bls_public_key"] = self.members()[0]["bls_public_key"]
        with self.assertRaisesRegex(prepare.PrepareError, "duplicate BLS"):
            self.assemble()
        self.members()[0]["secret"] = "not a real secret"
        with self.assertRaisesRegex(prepare.PrepareError, "unexpected or missing"):
            self.assemble()

    def test_rejects_slot_reordering_and_missing_edge(self):
        self.members().reverse()
        with self.assertRaisesRegex(prepare.PrepareError, "validator order"):
            self.assemble()
        self.members().reverse()
        self.members()[0]["edge_nodes"] = []
        with self.assertRaisesRegex(prepare.PrepareError, "one edge"):
            self.assemble()

    def test_rejects_consensus_and_topology_drift(self):
        changes = [
            lambda: self.canonical["networks"]["testnet"].update(magic="0x123"),
            lambda: self.p2p["networks"]["testnet"]["p2p"].update(checkpoints_per_epoch=True),
            lambda: self.topology["hosts"].update({"gcp-edge-1": "8.8.8.8"}),
            lambda: self.topology["coordinator"].update(edge_ports=[15370, 15371, 443]),
            lambda: self.topology["realms"][0]["validators"][0].update(registration_id=True),
            lambda: self.topology["realms"][0]["validators"][0].update(http_port=41101),
            lambda: self.commitments.update(node_source="a" * 40),
            lambda: self.topology.update(psy_network="localhost"),
            lambda: self.topology.update(network="local-devnet"),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.setUp()
                change()
                with self.assertRaises(prepare.PrepareError):
                    self.assemble()

    def test_genesis_exact_shape_and_no_nonmembership_changes(self):
        config = self.assemble()
        original = copy.deepcopy(self.genesis)
        result = prepare.inject_genesis(self.genesis, config)
        self.assertEqual(self.genesis, original)
        self.assertEqual({k: v for k, v in result.items() if k != "validators"},
                         {k: v for k, v in original.items() if k != "validators"})
        self.assertEqual(len(result["validators"]), 6)
        for rid, realm in enumerate(config["networks"]["testnet"]["realm_configs"]):
            for index, member in enumerate(realm["validators"]):
                self.assertEqual(result["validators"][rid * 3 + index], {
                    "realm_id": rid, "validator_user_id": member["validator_user_id"],
                    "node_id": member["processor_node_id"], "bls_public_key": member["bls_public_key"]})
        result["validators"].reverse()
        self.assertEqual(prepare.inject_genesis(result, config), result)

    def test_genesis_conflict_missing_users_and_malformed_members_fail(self):
        config = self.assemble()
        bad = prepare.inject_genesis(self.genesis, config)
        bad["validators"][0]["bls_public_key"] = "ff" * 48
        with self.assertRaisesRegex(prepare.PrepareError, "conflicts"):
            prepare.inject_genesis(bad, config)
        for bad in (dict(self.genesis, validators=None), dict(self.genesis, users=[]),
                    dict(self.genesis, validators=[{"realm_id": 0}])):
            with self.subTest(bad=bad), self.assertRaises(prepare.PrepareError):
                prepare.inject_genesis(bad, config)

    def test_old_faucet_pool_cannot_pass_assembly(self):
        config = self.assemble()
        for total in (7, 17, 106, 108):
            bad = dict(self.genesis, users=[self.genesis["users"][0]] * total)
            with self.subTest(total=total), self.assertRaisesRegex(prepare.PrepareError, "107 users"):
                prepare.inject_genesis(bad, config)

    def test_topology_requires_one_hundred_operators(self):
        for count in (10, 99, 101, True, "100"):
            self.topology["faucet_operator_count"] = count
            with self.subTest(count=count), self.assertRaisesRegex(prepare.PrepareError, "faucet operator count"):
                self.assemble()


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="prepare-network-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.documents = fixture()
        names = ("canonical", "p2p", "commitments", "topology", "whitelist", "genesis")
        for name, document in zip(names, self.documents):
            (self.root / f"{name}.json").write_text(json.dumps(document))
        self.args = []
        for flag, name in zip(("canonical-config", "p2p-config", "guardian-commitments", "topology", "whitelist"), names):
            self.args += ["--" + flag, str(self.root / f"{name}.json")]

    def run_cli(self, *extra):
        errors = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
            result = prepare.main(self.args + list(map(str, extra)))
        self.last_error = errors.getvalue()
        return result

    def test_two_stage_cli_does_not_change_inputs(self):
        before = {path: path.read_bytes() for path in self.root.iterdir()}
        self.assertEqual(self.run_cli("--config-out", self.root / "config.json"), 0, self.last_error)
        config_bytes = (self.root / "config.json").read_bytes()
        self.assertEqual(self.run_cli("--genesis-in", self.root / "genesis.json",
                                     "--genesis-out", self.root / "injected.json"), 0)
        self.assertEqual(len(json.loads((self.root / "injected.json").read_text())["validators"]), 6)
        self.assertEqual((self.root / "config.json").read_bytes(), config_bytes)
        config = json.loads(config_bytes)
        self.assertEqual(config["networks"]["testnet"]["whitelist"],
                         self.documents[4]["networks"]["testnet"]["whitelist"])
        self.assertEqual(config["networks"]["localhost"], self.documents[0]["networks"]["localhost"])
        for path, payload in before.items():
            self.assertEqual(path.read_bytes(), payload)

    def test_no_overwrite_including_input_alias_and_dangling_symlink(self):
        target = self.root / "exists.json"
        target.write_bytes(b"preserve")
        self.assertEqual(self.run_cli("--config-out", target), 1)
        self.assertEqual(target.read_bytes(), b"preserve")
        self.assertEqual(self.run_cli("--config-out", self.root / "canonical.json"), 1)
        alias = self.root / "alias.json"
        alias.symlink_to(self.root / "missing.json")
        self.assertEqual(self.run_cli("--config-out", alias), 1)
        self.assertTrue(alias.is_symlink())
        self.assertFalse((self.root / "missing.json").exists())

    def test_rejects_symlinked_output_parent_and_git_checkout(self):
        directory = self.root / "directory"
        directory.mkdir()
        link = self.root / "link"
        link.symlink_to(directory, target_is_directory=True)
        self.assertEqual(self.run_cli("--config-out", link / "config.json"), 1)
        (directory / ".git").write_text("gitdir: elsewhere")
        self.assertEqual(self.run_cli("--config-out", directory / "config.json"), 1)
        self.assertFalse((directory / "config.json").exists())

    def test_failure_on_second_output_removes_only_own_first_output(self):
        target = self.root / "injected.json"
        target.write_bytes(b"retain")
        self.assertEqual(self.run_cli("--config-out", self.root / "config.json",
                                     "--genesis-in", self.root / "genesis.json",
                                     "--genesis-out", target), 1)
        self.assertFalse((self.root / "config.json").exists())
        self.assertEqual(target.read_bytes(), b"retain")

    def test_io_failure_removes_new_outputs(self):
        with patch.object(prepare.os, "fsync", side_effect=OSError("simulated failure")):
            self.assertEqual(self.run_cli("--config-out", self.root / "config.json"), 1)
        self.assertFalse((self.root / "config.json").exists())

    def test_duplicate_json_fields_symlink_fifo_and_nonfinite_rejected(self):
        path = self.root / "input.json"
        for payload in ('{"a":1,"a":2}', '{"a":NaN}', '[]'):
            path.write_text(payload)
            with self.subTest(payload=payload), self.assertRaises(prepare.PrepareError):
                prepare.read_public_json(path)
        link = self.root / "public-link.json"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            prepare.read_public_json(link)
        fifo = self.root / "fifo.json"
        os.mkfifo(fifo)
        with self.assertRaises(prepare.PrepareError):
            prepare.read_public_json(fifo)

    def test_invalid_arguments_and_same_outputs_leave_no_files(self):
        target = self.root / "output.json"
        cases = [(), ("--genesis-in", self.root / "genesis.json"),
                 ("--config-out", target, "--genesis-in", self.root / "genesis.json",
                  "--genesis-out", target)]
        for extra in cases:
            with self.subTest(extra=extra):
                self.assertEqual(self.run_cli(*extra), 1)
                self.assertFalse(target.exists())

    def test_invalid_public_input_fails_before_outputs(self):
        self.documents[1]["networks"]["testnet"]["realm_configs"][0]["validators"] = []
        (self.root / "p2p.json").write_text(json.dumps(self.documents[1]))
        self.assertEqual(self.run_cli("--config-out", self.root / "output.json"), 1)
        self.assertFalse((self.root / "output.json").exists())

    def test_whitelist_argument_is_mandatory(self):
        self.args = self.args[:-2]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            prepare.main(self.args + ["--config-out", str(self.root / "output.json")])
        self.assertEqual(error.exception.code, 2)
        self.assertFalse((self.root / "output.json").exists())

    def test_disabled_whitelist_fails_before_outputs(self):
        self.documents[4]["networks"]["testnet"]["whitelist"]["enabled"] = False
        (self.root / "whitelist.json").write_text(json.dumps(self.documents[4]))
        self.assertEqual(self.run_cli("--config-out", self.root / "output.json"), 1)
        self.assertFalse((self.root / "output.json").exists())


if __name__ == "__main__":
    unittest.main()
