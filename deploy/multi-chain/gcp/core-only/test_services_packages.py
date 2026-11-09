import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import activate_services
import indexer_backup_mirror
import install_services as installer
import prepare_services_inputs as inputs
import prepare_services_packages as packages
from test_release_lock import build_test_lock

HERE = Path(__file__).resolve().parent
INDEXER_BYTES = b"fixture indexer with authorization_header inside"
TOPOLOGY = {
    "hosts": {"gcp-cp": "10.0.0.25", "gcp-realm-a": "10.0.0.37", "gcp-realm-b": "10.0.0.42", "gcp-realm-c": "10.0.0.43",
              "gcp-edge-1": "10.0.0.36", "gcp-edge-2": "10.0.0.35"},
    "infrastructure": {"redis_url": "redis://10.0.0.12:6379"},
    "coordinator": {"host": "gcp-cp", "edge_ports": [15370, 15371, 15372], "ingress_port": 15369},
    "realms": [{"id": realm, "validators": [
        {"processor_host": host, "edge_host": f"gcp-edge-{realm + 1}", "http_port": 15380 + realm * 3 + index}
        for index, host in enumerate(("gcp-realm-a", "gcp-realm-b", "gcp-realm-c"))]} for realm in (0, 1)]}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class ServicesWorld:
    """A lock, a release directory and an offline inputs directory that agree with each other."""

    def __init__(self, root, indexer_bytes=INDEXER_BYTES):
        self.root = Path(root)
        self.release_dir, self.private_dir = self.root / "release", self.root / "private"
        for directory in (self.release_dir, self.private_dir):
            directory.mkdir()
        self.lock = build_test_lock(self.release_dir, self.private_dir, topology_text=json.dumps(TOPOLOGY))
        self.lock["hosts"] = {"gcp-svc": "10.0.0.38", "gcp-postgres": "10.0.0.24"}
        for name in self.lock["tool_sha256"]:
            if (HERE / name).is_file():
                self.lock["tool_sha256"][name] = sha((HERE / name).read_bytes())
        self.inputs_dir = self.root / "inputs"
        genesis = b"fixture genesis"
        self.write_inputs(genesis, indexer_bytes)
        self.lock["inputs"]["genesis"] = sha(genesis)
        self.lock["binaries"]["psy-services"], self.lock["binaries"]["psy-indexer"] = sha(b"fixture services"), sha(indexer_bytes)
        self.write_manifest(genesis)
        raw = json.dumps(self.lock, indent=2).encode()
        (self.release_dir / "release-lock.json").write_bytes(raw)
        self.lock_sha256 = sha(raw)

    def write(self, name, value):
        path = self.inputs_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())

    def write_inputs(self, genesis, indexer_bytes):
        rows = []
        for index, name in enumerate(inputs.ABI_NAMES):
            methods = [{"name": f"method{i}", "method_id": i} for i in range(inputs.METHOD_COUNTS[index])]
            if index in (0, 4):
                methods[0]["name"], methods[1]["name"] = "mint", "burn"
            if index == 3:
                methods[-1] = {"name": "set_chain_root", "method_id": 4192350829, "input_felt_count": 10, "output_felt_count": 0}
            self.write(f"genesis_abi/{name}.json", {"contract": {"name": name, "state_tree_height": inputs.HEIGHTS[index],
                                                                "state_layout": {"field_count": 1}, "methods": methods}})
            rows.append({"contract_id": index, "abi_path": name + ".json", "state_tree_height": inputs.HEIGHTS[index]})
        self.write("genesis_abi/abi_list.json", {"users": [], "contracts": [], "precompiles": rows})
        self.write("psy-services", b"fixture services")
        self.write("psy-indexer", indexer_bytes)
        self.write("genesis.json.zst", b"fixture compressed genesis")
        self.write("migrations/001.sql", b"select 1;")

    def write_manifest(self, genesis):
        files = {str(p.relative_to(self.inputs_dir)): sha(p.read_bytes()) for p in sorted(self.inputs_dir.rglob("*")) if p.is_file()}
        manifest = {"genesis_sha256": sha(genesis), "services_commit": self.lock["sources"]["services"],
                    "indexer_commit": self.lock["sources"]["indexer"], "files": files}
        self.write("input-manifest.json", manifest)
        self.manifest_sha256 = sha((self.inputs_dir / "input-manifest.json").read_bytes())

    def build(self, name, documents=None):
        output = self.root / name
        delivery = packages.build_service_packages(self.lock, self.lock_sha256, self.release_dir, self.inputs_dir,
                                                   self.manifest_sha256, output, documents)
        return output, delivery

    def summaries(self):
        return {chain: json.dumps({"core": {"StateManager": "0x" + "1" * 40}}).encode() for chain in ("sepolia", "bscTestnet", "baseSepolia")}

    def placement(self):
        return installer.placement(self.lock, TOPOLOGY)


class ServicesPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.world = ServicesWorld(self.temp.name)
        self.lock = self.world.lock

    def test_services_package_uses_lock_database_and_owner(self):
        output, delivery = self.world.build("pending")
        placement = self.world.placement()
        services = self.lock["services"]
        self.assertEqual((placement["database"], placement["database_owner"], placement["redis_prefix"], placement["backup_dir"],
                          placement["mirror_dir"]), (services["database"], services["owner"], services["key_prefix"],
                                                     services["backups"], services["mirror"]))
        self.assertEqual(placement["redis_url"], "redis://10.0.0.12:6379/14")
        self.assertEqual(placement["release"], self.lock["paths"]["services"]["release"])
        self.assertEqual(placement["credentials"], self.lock["paths"]["services"]["config"])
        self.assertEqual(json.loads((output / "gcp-svc/topology.json").read_bytes()), placement)
        self.assertEqual(set(delivery), {"gcp-svc", "gcp-cp", "gcp-realm-a"})
        unit = (output / "gcp-svc/units" / self.lock["units"]["services"]).read_text()
        self.assertIn("--release-lock-sha256 " + self.world.lock_sha256, unit)
        self.assertNotIn("20261026", unit)

    def test_core_unit_names_use_lock_prefix(self):
        placement = self.world.placement()
        prefix = self.lock["units"]["core_prefix"]
        self.assertEqual(placement["indexers"]["coordinator"]["core_unit"], prefix + "coordinator-processor.service")
        self.assertEqual(placement["indexers"]["realm1"]["core_unit"], prefix + "realm-1-v1-processor.service")
        self.assertEqual(installer.unit_name(self.lock, "realm0"), self.lock["units"]["indexer_prefix"] + "realm0.service")
        self.assertEqual(installer.unit_name(self.lock, "services"), self.lock["units"]["services"])
        self.assertEqual(placement["groups"]["gcp-realm-a"]["roles"], ["realm0", "realm1"])
        self.assertEqual(placement["indexers"]["realm1"]["edge_url"], "http://10.0.0.35:15383")

    def test_realm_sources_cover_all_validators_from_the_mirror(self):
        sources = self.world.placement()["realm_sources"]
        mirror, backups = self.lock["services"]["mirror"], self.lock["services"]["backups"]
        for role, row in sources.items():
            self.assertEqual(row["coordinator_backup_base_dir"], mirror + "/cp/checkpoints")
            self.assertEqual([v["realm_sub_id"] for v in row["validators"]], [1, 2, 3])
            self.assertEqual(row["validators"][0]["backup_base_dir"], backups)
            self.assertEqual(row["validators"][2]["backup_base_dir"], mirror + "/v3/checkpoints")
        self.assertEqual(self.world.placement()["mirror_sources"]["v2"], {"host": "10.0.0.42", "roles": ["realm_0_2", "realm_1_2"]})

    def test_nostr_enabled_in_initial_package(self):
        output, _ = self.world.build("pending")
        config = json.loads((output / "gcp-svc/services.json").read_bytes())
        self.assertIs(config["nostr"]["enabled"], True)
        self.assertEqual(config["nostr"]["lookback_seconds"], 172800)
        self.assertEqual(config["l1_chains"], [])
        output, _ = self.world.build("final", self.world.summaries())
        config = json.loads((output / "gcp-svc/services.json").read_bytes())
        self.assertEqual([row["eth_rpc_url"] for row in config["l1_chains"]], list(self.lock["envio"]["rpc_routes"].values()))
        self.assertTrue(all(row["state_manager"] == "0x" + "1" * 40 for row in config["l1_chains"]))
        self.assertEqual([row["role"] for row in config["rpc"]["endpoints"]],
                         [{"type": "Coordinator", "id": 0}, {"type": "Realm", "id": 0}, {"type": "Realm", "id": 1}])

    def test_realm_indexer_fresh_bootstrap_flag_set(self):
        output, _ = self.world.build("pending")
        realm = (output / "gcp-realm-a/units" / installer.unit_name(self.lock, "realm0")).read_text()
        coordinator = (output / "gcp-cp/units" / installer.unit_name(self.lock, "coordinator")).read_text()
        cursor = self.lock["services"]["backups"] + "/indexer_state/realm_0_1.json"
        self.assertIn(f"if [ -e {cursor} ]", realm)
        self.assertIn("PSY_INDEXER_START_CHECKPOINT=0", realm)
        self.assertIn("ExecStartPre=+/usr/bin/bash -c", realm)
        self.assertNotIn("--start-checkpoint", realm)
        self.assertIn("--committed-realm-sources", realm)
        self.assertIn("\nRestart=on-failure\n", realm)
        self.assertNotIn("START_CHECKPOINT", coordinator)

    def test_jwt_renewal_setting_present(self):
        with self.assertRaisesRegex(ValueError, "per-request JWT"):
            packages.check_jwt_renewal(b"an indexer from before the fix")
        packages.check_jwt_renewal(INDEXER_BYTES)
        stale_root = Path(self.temp.name) / "stale"
        stale_root.mkdir()
        stale = ServicesWorld(stale_root, b"an indexer from before the fix")
        with self.assertRaisesRegex(ValueError, "per-request JWT"):
            stale.build("pending")
        output, _ = self.world.build("pending")
        for alias in ("gcp-svc", "gcp-cp", "gcp-realm-a"):
            for unit in (output / alias / "units").iterdir():
                self.assertNotIn("hotfix", unit.read_text())
                self.assertEqual(unit.read_text().count("ExecStart="), 1)
        config = json.loads((output / "gcp-svc/services.json").read_bytes())
        self.assertEqual(config["redis"]["pool_size"], packages.REDIS_POOL_SIZE)

    def test_package_rejects_tampering_and_foreign_lock(self):
        output, delivery = self.world.build("pending")
        directory = output / "gcp-cp"
        with self.assertRaisesRegex(installer.ValidationError, "release lock differs"):
            installer.load_package(directory, delivery["gcp-cp"], self.lock, "0" * 64)
        (directory / "topology.json").write_text("{}")
        with self.assertRaises(installer.ValidationError):
            installer.load_package(directory, delivery["gcp-cp"], self.lock, self.world.lock_sha256)

    def test_pending_install_refused_before_commands_or_files(self):
        with patch.object(installer.os, "geteuid", return_value=0), patch.object(installer.subprocess, "run") as run:
            with self.assertRaisesRegex(installer.ValidationError, "documents"):
                installer.check_host(Path("/not-created"), {"l1_ready": False}, {}, self.lock)
            with self.assertRaisesRegex(installer.ValidationError, "documents"):
                installer.install(Path("/not-created"), {"l1_ready": False}, {}, None, self.lock)
            run.assert_not_called()

    def test_pending_activation_refused_before_commands(self):
        with patch.object(activate_services.os, "geteuid", return_value=0), patch.object(activate_services.subprocess, "check_output") as run:
            with self.assertRaisesRegex(installer.ValidationError, "fresh L1"):
                activate_services.preflight(installer, Path("/not-created"), {"l1_ready": False}, {"release": "/not-created"}, self.lock)
            run.assert_not_called()

    def test_old_service_fence_refuses_active_without_stopping(self):
        row = "psy-services-fresh-20261026-r2.service loaded active running Old\n"
        with patch.object(installer.subprocess, "check_output", return_value=row), patch.object(installer, "unit_status",
                return_value={"MainPID": "123", "ActiveState": "active"}), patch.object(installer.subprocess, "run") as run:
            with self.assertRaisesRegex(installer.ValidationError, "still running"):
                installer.fence_services()
            run.assert_not_called()

    def test_mirror_names_and_paths_come_from_the_lock(self):
        config = {"reader": "10.0.0.37", "sources": {"cp": {"host": "10.0.0.25", "host_key": "key", "roles": ["coordinator_0_0"]}}}
        lock_path, config_path = Path(self.temp.name) / "lock.json", Path(self.temp.name) / "mirror.json"
        lock_path.write_text(json.dumps(self.lock))
        config_path.write_text(json.dumps(config))
        mirror = indexer_backup_mirror.load_mirror(lock_path, sha(lock_path.read_bytes()), config_path, sha(config_path.read_bytes()))
        self.assertEqual(str(mirror.state), self.lock["services"]["mirror"])
        self.assertEqual(mirror.backups, self.lock["services"]["backups"])
        self.assertEqual(str(mirror.program), "/usr/local/libexec/" + Path(self.lock["services"]["mirror"]).name + ".py")
        line = indexer_backup_mirror.authorize_line("ssh-ed25519 AAAA", "cp", mirror).decode()
        self.assertIn('from="10.0.0.37",restrict,command="sudo -n', line)
        self.assertIn("--address 10.0.0.25 --backups " + self.lock["services"]["backups"] + " --role coordinator_0_0", line)
        with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
            indexer_backup_mirror.load_mirror(lock_path, "0" * 64, config_path, sha(config_path.read_bytes()))

    def test_activation_waits_for_executor_without_restarting(self):
        release = "/opt/release"
        values = [{"ActiveState": "active", "MainPID": "20"}] * 2
        with patch.object(installer, "unit_status", side_effect=values), patch.object(activate_services.os, "readlink",
                side_effect=["/usr/lib/systemd/systemd-executor", release + "/psy-services"]), \
                patch.object(activate_services, "process", return_value={"pid": 20}) as process, \
                patch.object(activate_services.time, "sleep") as sleep:
            self.assertEqual(activate_services.wait_process(installer, "new.service", "psy-services", release, self.lock), {"pid": 20})
            sleep.assert_called_once_with(0.25)
            process.assert_called_once()

    def test_activation_rejects_wrong_exe_or_restarted_pid(self):
        release = "/opt/release"
        with patch.object(installer, "unit_status", return_value={"ActiveState": "active", "MainPID": "20"}), \
                patch.object(activate_services.os, "readlink", return_value="/usr/bin/other"), \
                patch.object(activate_services.time, "sleep") as sleep:
            with self.assertRaisesRegex(installer.ValidationError, "unexpected executor"):
                activate_services.wait_process(installer, "new.service", "psy-services", release, self.lock)
            sleep.assert_not_called()
        with patch.object(installer, "unit_status", side_effect=[
                {"ActiveState": "active", "MainPID": "20"}, {"ActiveState": "active", "MainPID": "21"}]), \
                patch.object(activate_services.os, "readlink", return_value="/usr/lib/systemd/systemd"), \
                patch.object(activate_services.time, "sleep"):
            with self.assertRaisesRegex(installer.ValidationError, "restarted"):
                activate_services.wait_process(installer, "new.service", "psy-services", release, self.lock)

    def test_activation_failed_or_deadline_does_not_retry_start(self):
        release = "/opt/release"
        with patch.object(installer, "unit_status", return_value={"ActiveState": "failed", "MainPID": "0"}), \
                patch.object(activate_services.subprocess, "run") as run:
            with self.assertRaisesRegex(installer.ValidationError, "failed during"):
                activate_services.wait_process(installer, "new.service", "psy-services", release, self.lock)
            run.assert_not_called()
        with patch.object(installer, "unit_status", return_value={"ActiveState": "active", "MainPID": "0"}), \
                patch.object(activate_services.time, "monotonic", side_effect=[0, 16]):
            with self.assertRaisesRegex(installer.ValidationError, "deadline"):
                activate_services.wait_process(installer, "new.service", "psy-services", release, self.lock)


if __name__ == "__main__":
    unittest.main()
