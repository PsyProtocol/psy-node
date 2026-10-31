import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import release_lock as lock_module


HERE = Path(__file__).resolve().parent
RELEASE_DIR = HERE.parent / "fresh-192-20261030"
COMMITTED = RELEASE_DIR / "release-lock.json"
CHAINS = ("sepolia", "bscTestnet", "baseSepolia")


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def build_test_retirement():
    """Return synthetic (retired, retained) lists that satisfy every required retain needle."""
    hosts, paths = {}, []
    for alias in lock_module.ALL_HOSTS:
        retain = sorted({n if n.startswith("/") else "/fixture/" + n for n in lock_module.REQUIRED_RETAIN[alias]})
        hosts[alias] = {"stop": ["old.service"], "containers": ["old-container"], "retain": retain,
                        "clear": ["/opt/old-release"]}
        paths += [{"host": alias, "path": p, "kind": "secret"} for p in retain]
    paths.append({"host": "local", "path": "/fixture/.private", "kind": "secret"})
    return {"hosts": hosts}, {"paths": paths}


def build_test_lock(release_dir=None, private_dir=None, *, topology_text=None, runtime_config_sha256=None,
                    genesis_sha256=None, node_sha256=None):
    """Return a schema-valid synthetic lock; directories, when given, receive matching input files."""
    digest = lambda label: sha256(label.encode())
    release = {"schema_version": 1, "release_id": "core-testnet-20260101-sd192", "network": "testnet",
               "network_magic": "0x1337CF514544CF69", "namespace_prefix": "fresh20260101sd192", "worker_queue_ack_wait_ms": 30000,
               "runtime_candidate_commit": "1" * 40, "checkpoints_per_epoch": 32,
               "proving_backend": "plonky2-poseidon-goldilocks",
               "runtime_config_sha256": digest("runtime") if runtime_config_sha256 is None else runtime_config_sha256,
               "canonical_config_sha256": digest("canonical")}
    binaries = {name: digest(name) for name in lock_module.CLI_BINARIES}
    binaries["psy_node_cli"] = binaries["psy_node_cli"] if node_sha256 is None else node_sha256
    artifacts = {"genesis_sha256": digest("genesis") if genesis_sha256 is None else genesis_sha256, "binaries": binaries,
                 "preparation_commits": {"compiler": "2" * 40, "genesis": "3" * 40}}
    texts = {"release.json": json.dumps(release), "topology.json": topology_text or '{"hosts": {"gcp-test-cp": "10.0.0.25"}}', "artifacts.json": json.dumps(artifacts),
             "risk-acceptance.md": "risk\n", "worker-whitelist.json": "{}\n"}
    retired, retained = build_test_retirement()
    private = {"retired-state.json": json.dumps(retired), "retained-paths.json": json.dumps(retained)}
    if private_dir is not None:
        for name, text in private.items():
            (Path(private_dir) / name).write_text(text)
    if release_dir is not None:
        for name, text in texts.items():
            target = Path(release_dir) / name
            if name == "worker-whitelist.json":
                target = Path(release_dir).parent / "core-only" / name
                target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
    namespace = release["namespace_prefix"]
    rid = release["release_id"]
    paths = {role: {"release": f"/opt/{role}/{rid}", "config": f"/etc/{role}/{rid}", "state": f"/var/lib/{role}/{rid}"}
             for role in lock_module.PATH_ROLES}
    paths["core"] = {"release": f"/opt/psy-core/releases/{rid}", "config": f"/etc/psy-core/{rid}",
                     "state": f"/var/lib/psy-core/{rid}"}
    return {
        "schema_version": 1, "release_id": rid, "network": "testnet", "network_magic": release["network_magic"],
        "inputs": {"release_profile": sha256(texts["release.json"].encode()),
                   "topology": sha256(texts["topology.json"].encode()),
                   "artifacts": sha256(texts["artifacts.json"].encode()),
                   "runtime_config": release["runtime_config_sha256"],
                   "canonical_config": release["canonical_config_sha256"], "genesis": artifacts["genesis_sha256"],
                   "worker_whitelist": sha256(texts["worker-whitelist.json"].encode()),
                   "risk_acceptance": sha256(texts["risk-acceptance.md"].encode()),
                   "retired_state": sha256(private["retired-state.json"].encode()),
                   "retained_paths": sha256(private["retained-paths.json"].encode())},
        "sources": {"runtime": "1" * 40, "guardian_key": "4" * 40, "compiler": "2" * 40, "genesis": "3" * 40,
                    "contracts": "5" * 40, "services": "6" * 40, "indexer": "7" * 40},
        "binaries": {**binaries, "psy-services": digest("psy-services"), "psy-indexer": digest("psy-indexer")},
        "paths": paths,
        "units": {"core_prefix": f"psy-core-{namespace}-", "core_namespace_prefix": namespace,
                  "guardian_prefix": f"psy-guardian-{namespace}-",
                  "relayer": f"psy-core-relayer-{namespace}.service", "worker_prefix": f"psy-core-worker-{namespace}-",
                  "proxy_prefix": f"psy-core-prove-proxy-{namespace}-", "faucet": f"psy-faucet-{namespace}.service",
                  "services": f"psy-services-{namespace}.service", "indexer_prefix": f"psy-indexer-{namespace}-",
                  "envio": f"psy-envio-{namespace}.service"},
        "hosts": {"gcp-test-services": "10.0.0.38"},
        "services": {"database": "services_db", "owner": "services_owner", "redis_db": 14,
                     "key_prefix": "svc:", "listen": "10.0.0.38:3001", "backups": f"/var/lib/psy-core/{rid}/checkpoints",
                     "mirror": "/var/lib/psy-indexer-mirror"},
        "envio": {"database": "envio_db", "project": "envio-project",
                  "image": "hasura/graphql-engine@sha256:" + "a" * 64, "graphql_port": 29899, "hasura_port": 38081,
                  "rpc_routes": {chain: f"http://10.0.0.32:{18545 + index}" for index, chain in enumerate(CHAINS)}},
        "faucet": {"account": "faucet-account", "listen_port": 29998, "operators_sha256": digest("operators")},
        "images": {"scylla": "scylladb/scylla@sha256:" + "b" * 64, "valkey": "valkey/valkey@sha256:" + "c" * 64,
                   "nats": "nats@sha256:" + "d" * 64, "postgres": "postgres@sha256:" + "e" * 64,
                   "nostr": "scsibug/nostr-rs-relay@sha256:" + "f" * 64},
        "groth16": {"setup_manifest_sha256": digest("setup"),
                    "verifiers": {name: digest(name) for name in lock_module.GROTH16_VERIFIERS}},
        "l1": {"signer": "0x" + "9" * 40, "output_root": "/var/lib/psy-fresh-test",
               "bundle_sha256": digest("bundle"), "policy_sha256": digest("policy"),
               "gas_budget_sha256": {chain: digest("gas" + chain) for chain in CHAINS}},
        "ingress": {"fenced_hosts": ["fenced.example.test"], "faucet_hosts": ["faucet.example.test"],
                    "maintenance_tag": "maintenance-test"},
        "gates": {"l2_stability_checkpoint_count": 100, "worker_queue_ack_wait_ms": 30000},
        "tool_sha256": {name: digest(name) for name in lock_module.TOOL_NAMES},
    }


class ReleaseLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.release_dir = Path(self.temp.name) / "release"
        self.release_dir.mkdir()
        self.private_dir = Path(self.temp.name) / "private"
        self.private_dir.mkdir()
        self.lock = build_test_lock(self.release_dir, self.private_dir)

    def validate(self, lock=None, complete=True, private=True):
        lock_module.validate_release_lock(self.lock if lock is None else lock, self.release_dir, complete,
                                          self.private_dir if private else None)

    def test_fixture_is_valid_and_complete(self):
        self.validate()

    def test_load_rejects_hash_mismatch(self):
        path = Path(self.temp.name) / "lock.json"
        raw = json.dumps(self.lock).encode()
        path.write_bytes(raw)
        self.assertEqual(lock_module.load_release_lock(path, sha256(raw)), self.lock)
        with self.assertRaisesRegex(ValueError, "release lock hash mismatch"):
            lock_module.load_release_lock(path, "0" * 64)

    def test_load_rejects_duplicate_keys(self):
        path = Path(self.temp.name) / "lock.json"
        raw = b'{"schema_version": 1, "schema_version": 1}'
        path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            lock_module.load_release_lock(path, sha256(raw))

    def test_validate_rejects_unknown_top_level_key(self):
        lock = {**self.lock, "extra": {}}
        with self.assertRaisesRegex(ValueError, "release lock fields"):
            self.validate(lock)

    def test_validate_rejects_missing_top_level_key(self):
        lock = copy.deepcopy(self.lock)
        del lock["gates"]
        with self.assertRaisesRegex(ValueError, "release lock fields"):
            self.validate(lock)

    def test_validate_rejects_release_id_differing_from_profile(self):
        lock = {**self.lock, "release_id": "core-testnet-20260102-sd192"}
        with self.assertRaisesRegex(ValueError, "release_id differs from the release profile"):
            self.validate(lock)

    def test_validate_rejects_network_magic_differing_from_profile(self):
        lock = {**self.lock, "network_magic": "0x1"}
        with self.assertRaisesRegex(ValueError, "network_magic differs from the release profile"):
            self.validate(lock)

    def test_validate_rejects_input_hash_differing_from_file(self):
        (self.release_dir / "risk-acceptance.md").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "input hash differs from file: risk_acceptance"):
            self.validate()

    def test_validate_rejects_genesis_differing_from_artifacts(self):
        lock = copy.deepcopy(self.lock)
        lock["inputs"]["genesis"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "genesis hash differs from artifacts"):
            self.validate(lock)

    def test_validate_rejects_mutable_image_tag(self):
        for reference in ("scylladb/scylla:latest", "nats:2.11-alpine", "postgres@sha256:short"):
            lock = copy.deepcopy(self.lock)
            lock["images"]["scylla"] = reference
            with self.assertRaisesRegex(ValueError, "image must be pinned by digest"):
                self.validate(lock)

    def test_validate_rejects_wrong_gate(self):
        for value in (99, True, "100"):
            lock = copy.deepcopy(self.lock)
            lock["gates"]["l2_stability_checkpoint_count"] = value
            with self.assertRaisesRegex(ValueError, "l2_stability_checkpoint_count"):
                self.validate(lock)

    def test_validate_rejects_core_namespace_differing_from_profile(self):
        lock = copy.deepcopy(self.lock)
        lock["units"]["core_namespace_prefix"] = "fresh20260102sd192"
        with self.assertRaisesRegex(ValueError, "core_namespace_prefix differs from the release profile"):
            self.validate(lock)

    def test_validate_rejects_worker_ack_wait_differing_from_profile(self):
        for value in (1, 30000.0, True, 0, "30000"):
            lock = copy.deepcopy(self.lock)
            lock["gates"]["worker_queue_ack_wait_ms"] = value
            with self.assertRaisesRegex(ValueError, "worker_queue_ack_wait_ms"):
                self.validate(lock)

    def test_load_checked_release_lock_validates_the_lock_directory(self):
        path = self.release_dir / "release-lock.json"
        raw = json.dumps(self.lock).encode()
        path.write_bytes(raw)
        self.assertEqual(lock_module.load_checked_release_lock(path, sha256(raw)), self.lock)
        (self.release_dir / "risk-acceptance.md").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "input hash differs from file: risk_acceptance"):
            lock_module.load_checked_release_lock(path, sha256(raw))

    def test_validate_rejects_unit_prefix_without_namespace(self):
        lock = copy.deepcopy(self.lock)
        lock["units"]["core_prefix"] = "psy-core-r3-"
        with self.assertRaisesRegex(ValueError, "unit name must carry the namespace"):
            self.validate(lock)

    def test_validate_rejects_path_outside_release(self):
        lock = copy.deepcopy(self.lock)
        lock["paths"]["core"]["state"] = "/var/lib/psy-core/core-testnet-20261027-r3"
        with self.assertRaisesRegex(ValueError, "path must carry the release id or namespace"):
            self.validate(lock)

    def test_require_complete_rejects_empty_contracts_commit(self):
        lock = copy.deepcopy(self.lock)
        lock["sources"]["contracts"] = ""
        with self.assertRaisesRegex(ValueError, "release lock incomplete: sources.contracts"):
            self.validate(lock, complete=True)
        self.validate(lock, complete=False)

    def test_pending_values_must_still_be_well_formed(self):
        lock = copy.deepcopy(self.lock)
        lock["sources"]["contracts"] = "not-a-commit"
        with self.assertRaisesRegex(ValueError, "sources.contracts"):
            self.validate(lock, complete=False)

    def test_require_complete_rejects_empty_gas_budget(self):
        lock = copy.deepcopy(self.lock)
        lock["l1"]["gas_budget_sha256"]["bscTestnet"] = ""
        with self.assertRaisesRegex(ValueError, "release lock incomplete: l1.gas_budget_sha256.bscTestnet"):
            self.validate(lock, complete=True)

    def test_complete_check_requires_the_private_directory(self):
        with self.assertRaisesRegex(ValueError, "complete check requires the private directory"):
            self.validate(complete=True, private=False)
        self.validate(complete=False, private=False)

    def test_private_inputs_are_checked_only_when_the_directory_is_given(self):
        (self.private_dir / "retired-state.json").write_text("{}")
        self.validate(complete=False, private=False)
        with self.assertRaisesRegex(ValueError, "input hash differs from file: retired_state"):
            self.validate(complete=False)

    def test_update_inputs_refreshes_every_input_from_the_files(self):
        path = Path(self.temp.name) / "lock.json"
        lock = copy.deepcopy(self.lock)
        lock["inputs"]["risk_acceptance"] = "0" * 64
        lock["inputs"]["retired_state"] = "0" * 64
        path.write_text(json.dumps(lock))
        lock_module.write_inputs(path, self.release_dir, self.private_dir)
        self.assertEqual(json.loads(path.read_text()), self.lock)
        lock["inputs"]["risk_acceptance"] = "0" * 64
        lock["inputs"]["retired_state"] = "1" * 64
        path.write_text(json.dumps(lock))
        lock_module.write_inputs(path, self.release_dir)
        refreshed = json.loads(path.read_text())["inputs"]
        self.assertEqual(refreshed["risk_acceptance"], self.lock["inputs"]["risk_acceptance"])
        self.assertEqual(refreshed["retired_state"], "1" * 64)

    def test_update_inputs_command_line(self):
        path = self.release_dir / "lock.json"
        lock = copy.deepcopy(self.lock)
        lock["inputs"]["topology"] = "0" * 64
        path.write_text(json.dumps(lock))
        lock_module.main(["update-inputs", "--lock", str(path), "--private-dir", str(self.private_dir)])
        self.assertEqual(json.loads(path.read_text())["inputs"], self.lock["inputs"])

    def test_validate_checks_the_retirement_lists_in_the_private_directory(self):
        retired, retained = build_test_retirement()
        retired["hosts"]["gcp-gateway"]["retain"] = ["/etc/ssh"]
        (self.private_dir / "retired-state.json").write_text(json.dumps(retired))
        lock = copy.deepcopy(self.lock)
        lock["inputs"]["retired_state"] = sha256((self.private_dir / "retired-state.json").read_bytes())
        with self.assertRaisesRegex(ValueError, "gcp-gateway must retain /etc/wireguard"):
            self.validate(lock, complete=False)

    def test_write_tool_hashes_updates_only_tool_section(self):
        path = Path(self.temp.name) / "lock.json"
        path.write_text(json.dumps(self.lock))
        tools = Path(self.temp.name) / "tools"
        tools.mkdir()
        for name in lock_module.TOOL_NAMES:
            (tools / name).write_bytes(name.encode())
        lock_module.write_tool_hashes(path, tools)
        updated = json.loads(path.read_text())
        self.assertEqual(updated["tool_sha256"], {name: sha256(name.encode()) for name in lock_module.TOOL_NAMES})
        self.assertEqual({k: v for k, v in updated.items() if k != "tool_sha256"},
                         {k: v for k, v in self.lock.items() if k != "tool_sha256"})
        lock_module.check_tool_hashes(updated, tools)
        (tools / lock_module.TOOL_NAMES[0]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "tool hash differs: " + lock_module.TOOL_NAMES[0]):
            lock_module.check_tool_hashes(updated, tools)


class CommittedLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = lock_module.read_release_lock(COMMITTED)

    def test_committed_lock_validates_while_pending_values_are_empty(self):
        lock_module.validate_release_lock(self.lock, RELEASE_DIR, False)

    def test_committed_lock_still_has_pending_values_and_a_known_key_source(self):
        self.assertEqual(self.lock["sources"]["contracts"], "")
        self.assertEqual(self.lock["sources"]["guardian_key"], "de539f565ec1a92f91bb4e9686e1442e89ba8639")

    def test_committed_lock_matches_current_tools(self):
        lock_module.check_tool_hashes(self.lock, HERE)
        self.assertEqual(set(self.lock["tool_sha256"]), set(lock_module.TOOL_NAMES))

    def test_committed_lock_images_are_digests_of_the_inspected_infrastructure(self):
        self.assertEqual(set(self.lock["images"]), {"scylla", "valkey", "nats", "postgres", "nostr"})
        for reference in self.lock["images"].values():
            self.assertRegex(reference, r"^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")


class RetirementListTests(unittest.TestCase):
    def setUp(self):
        self.retired, self.retained = build_test_retirement()

    def check(self):
        lock_module.validate_retirement(self.retired, self.retained)

    def test_fixture_is_valid(self):
        self.check()

    def test_removing_any_required_needle_fails(self):
        for alias, wanted in lock_module.REQUIRED_RETAIN.items():
            for needle in wanted:
                retired, retained = build_test_retirement()
                retired["hosts"][alias]["retain"] = [p for p in retired["hosts"][alias]["retain"] if needle not in p]
                retained["paths"] = [i for i in retained["paths"] if not (i["host"] == alias and needle in i["path"])]
                with self.assertRaisesRegex(ValueError, f"{alias} must retain {needle}"):
                    lock_module.validate_retirement(retired, retained)

    def test_required_table_covers_forwarders_l1_nodes_wireguard_and_ssh(self):
        table = lock_module.REQUIRED_RETAIN
        for alias in lock_module.ALL_HOSTS:
            self.assertIn("/etc/ssh", table[alias])
        for alias in ("gcp-gateway", "gcp-nostr", "arc99x1", "arc99x2", "arc99x3"):
            self.assertIn("/etc/wireguard", table[alias])
        for alias in ("guardian-next-1", "guardian-next-2", "guardian-next-3", "gcp-coordinator-worker", "gcp-faucet"):
            self.assertIn("psy-core-client-18545.service", table[alias])
        for name in ("psy-bridge-private-edge-15370.service", "psy-faucet-x2-ingress.service",
                     "psy-relayer-selfhosted-sepolia-r3.service", "bsc-rpc-forward.service", "sepolia-rpc-forward.service"):
            self.assertIn(name, table["gcp-gateway"])
        for name in ("base-sepolia-execution.service", "bsc-testnet.service", "sepolia-reth.service",
                     "sepolia-lighthouse.service"):
            self.assertIn(name, table["arc99x1"])

    def test_stopping_a_retained_forwarder_or_l1_node_is_rejected(self):
        for alias, unit in (("gcp-gateway", "psy-bridge-private-edge-15370.service"),
                            ("arc99x1", "sepolia-reth.service"), ("gcp-faucet", "psy-core-client-18545.service"),
                            ("guardian-next-1", "psy-core-client-18945.service"),
                            ("gcp-gateway", "psy-faucet-x2-ingress.service"), ("arc99x1", "bsc-testnet.service")):
            retired, retained = build_test_retirement()
            entry = retired["hosts"][alias]
            entry["retain"].append("/etc/systemd/system/" + unit)
            retained["paths"].append({"host": alias, "path": "/etc/systemd/system/" + unit, "kind": "infrastructure"})
            entry["stop"].append(unit)
            with self.assertRaisesRegex(ValueError, f"{alias} stops a retained unit: {unit}"):
                lock_module.validate_retirement(retired, retained)

    def test_duplicate_retain_unknown_host_and_overlapping_names_are_rejected(self):
        self.retired["hosts"]["gcp-scylla"]["retain"].append("/etc/ssh")
        with self.assertRaisesRegex(ValueError, "gcp-scylla retain lists a path twice"):
            self.check()
        self.retired["hosts"]["gcp-scylla"]["retain"].pop()
        self.retired["hosts"]["gcp-scylla"]["containers"] = ["x"]
        self.retired["hosts"]["gcp-scylla"]["stop"] = ["x"]
        with self.assertRaisesRegex(ValueError, "stop and containers"):
            self.check()
        self.retired["hosts"]["gcp-scylla"]["stop"] = ["old.service"]
        self.retained["paths"].append({"host": "gcp-elsewhere", "path": "/x", "kind": "secret"})
        with self.assertRaisesRegex(ValueError, "unknown host: gcp-elsewhere"):
            self.check()

    def test_infrastructure_kind_on_a_secret_path_is_rejected(self):
        self.retained["paths"][0]["kind"] = "infrastructure"
        with self.assertRaisesRegex(ValueError, "infrastructure kind on secret path"):
            self.check()

    def test_host_entry_has_exactly_stop_containers_retain_clear(self):
        for extra in ("confirm", "docker"):
            self.retired["hosts"]["gcp-scylla"][extra] = []
            with self.assertRaisesRegex(ValueError, "retired state gcp-scylla fields"):
                self.check()
            del self.retired["hosts"]["gcp-scylla"][extra]
        del self.retired["hosts"]["gcp-scylla"]["containers"]
        with self.assertRaisesRegex(ValueError, "retired state gcp-scylla fields"):
            self.check()

    def test_containers_and_units_are_names_not_paths(self):
        for key, value in (("stop", "docker:scylla"), ("containers", "docker:scylla"), ("stop", "/etc/x.service")):
            self.retired["hosts"]["gcp-scylla"][key] = [value]
            with self.assertRaisesRegex(ValueError, "names, not paths"):
                self.check()
            self.retired["hosts"]["gcp-scylla"][key] = ["old"]

    def test_clear_never_touches_retain(self):
        for clear in ("/fixture", "/fixture/psy-guardian-custody", "/fixture/psy-guardian-custody/sub"):
            self.retired["hosts"]["guardian-next-1"]["clear"] = [clear]
            with self.assertRaisesRegex(ValueError, "clear touches retain"):
                self.check()

    def test_clear_names_no_key_material(self):
        for clear in ("/opt/x/keystore", "/etc/psy-core/r/keys", "/opt/x/operator.json", "/opt/x/operators.json", "/var/lib/systemd/credential.secret"):
            self.retired["hosts"]["gcp-scylla"]["clear"] = [clear]
            with self.assertRaisesRegex(ValueError, "clear names key material"):
                self.check()

    def test_paths_must_be_absolute_normal_and_unique(self):
        for clear in (["relative/path"], ["/opt/../etc"], ["/opt/dir/"], ["/opt/a", "/opt/a"]):
            self.retired["hosts"]["gcp-scylla"]["clear"] = clear
            with self.assertRaises(ValueError):
                self.check()

    def test_retained_paths_must_equal_retain_lists_and_carry_a_kind(self):
        self.retained["paths"][0]["kind"] = "other"
        with self.assertRaisesRegex(ValueError, "retained path kind"):
            self.check()
        self.retained["paths"][0]["kind"] = "secret"
        self.retained["paths"].pop(1)
        with self.assertRaisesRegex(ValueError, "retained paths differ from retain list"):
            self.check()

    def test_local_private_material_must_be_retained(self):
        self.retained["paths"] = [i for i in self.retained["paths"] if i["host"] != "local"]
        with self.assertRaisesRegex(ValueError, "local .private material"):
            self.check()

    def test_host_set_is_closed(self):
        self.retired["hosts"]["gcp-unknown"] = {"stop": [], "containers": [], "retain": [], "clear": []}
        with self.assertRaisesRegex(ValueError, "retired state host set"):
            self.check()


if __name__ == "__main__":
    unittest.main()
