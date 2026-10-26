import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

import prepare_envio as envio


class PrepareEnvioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = {"devDependencies": {"envio": "2.32.10", "typescript": "5.6.3"},
                        "dependencies": {"poseidon-goldilocks-lite": "^0.2.3"}}
        self.template = {"name": "psy-relayer-indexer", "field_selection": {"transaction_fields": ["hash"]},
                         "contracts": [{"name": "Bridge", "handler": "./handlers.ts",
                                        "events": [{"event": "WithdrawalClaimed(bytes32 indexed nullifier)"}]}],
                         "networks": []}
        self.sources = {name: (name + " pinned\n").encode() for name in envio.SOURCE_FILES}
        self.sources["package.json"] = envio.encode(self.package)
        self.sources["config.template.yaml"] = yaml.safe_dump(self.template).encode()
        self.spec = {"version": 1, "patches": {}, "dependency_lock": None, "placement": None,
                     "rpc_routes": {}, "l1_documents": {}}
        self.pins = {}
        for name in envio.PATCHES:
            self.spec["patches"][name] = self.artifact(name, ("fixture:" + name).encode())
            self.pins[name] = self.spec["patches"][name]["sha256"]
        self.source_mock = patch.object(envio, "source_files", return_value=self.sources)
        self.source_mock.start()
        self.addCleanup(self.source_mock.stop)
        pins = patch.object(envio, "PATCHES", self.pins)
        pins.start()
        self.addCleanup(pins.stop)

    def artifact(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}

    def complete(self):
        address = str(ipaddress.IPv4Address(0xAC100102))
        self.spec["placement"] = {"postgres_host": address, "postgres_port": 5432,
                                  "postgres_user": "envio_fresh", "hasura_bind": address,
                                  "hasura_port": 28080, "indexer_port": 19898}
        for name, (index, chain_id, depth) in envio.CHAINS.items():
            self.spec["rpc_routes"][name] = {"urls": [f"http://{address}:{12000 + index}"],
                                             "confirmed_block_threshold": depth}
            bridge, manager = "0x" + "1" * 40, "0x" + "2" * 40
            summary = {"network": name, "chainId": chain_id, "deploymentBlock": 120,
                       "protocol": {"chain": {"l1ChainId": str(chain_id), "l1ChainIndex": index}},
                       "core": {"Bridge": bridge, "StateManager": manager},
                       "contracts": {"Bridge": bridge, "StateManager": manager},
                       "proxies": {"Bridge_Proxy": bridge, "StateManager_Proxy": manager}}
            docs = {"summary": self.artifact(name + "/summary", envio.encode(summary))}
            for key, value, block in (("bridge_receipt", bridge, 120), ("state_manager_receipt", manager, 100)):
                receipt = {"address": value, "transactionHash": "0x" + "a" * 64,
                           "receipt": {"status": 1, "blockNumber": block, "contractAddress": value, "to": None,
                                                         "transactionHash": "0x" + "a" * 64}}
                docs[key] = self.artifact(name + "/" + key, envio.encode(receipt))
            self.spec["l1_documents"][name] = docs
        lock = {"lockfileVersion": "9.0", "importers": {".": {
            kind: {key: {"specifier": value, "version": value} for key, value in values.items()}
            for kind, values in self.package.items()}}}
        self.spec["dependency_lock"] = self.artifact("lock.yaml", yaml.safe_dump(lock).encode())

    def build(self):
        return envio.build_files(self.spec, self.root)

    def test_pending_has_no_runnable_config_or_claims(self):
        files, report = self.build()
        self.assertNotIn("config.yaml", files)
        self.assertNotIn("compose.hasura.json", files)
        self.assertTrue(report["l1_documents_pending"])
        for key in ("dependencies_built", "patches_applied", "database_created", "installed", "started",
                    "deployment_ready", "release_approved"):
            self.assertIs(report[key], False)

    def test_complete_preserves_handler_events_and_earliest_deployment(self):
        self.complete()
        files, report = self.build()
        config = yaml.safe_load(files["config.yaml"])
        self.assertEqual(config["contracts"], self.template["contracts"])
        self.assertEqual(config["field_selection"], self.template["field_selection"])
        self.assertEqual(files["handlers.ts"], self.sources["handlers.ts"])
        self.assertEqual(files["schema.graphql"], self.sources["schema.graphql"])
        self.assertEqual([network["start_block"] for network in config["networks"]], [100] * 3)
        self.assertEqual([n["confirmed_block_threshold"] for n in config["networks"]], [8, 200, 64])
        self.assertFalse(report["l1_documents_pending"] or report["deployment_ready"])

    def test_hasura_is_separate_private_and_cannot_target_old_database(self):
        self.complete()
        files, _ = self.build()
        compose = json.loads(files["compose.hasura.json"])
        self.assertEqual(compose["name"], envio.PROJECT)
        self.assertEqual(set(compose["services"]), {"graphql-engine"})
        self.assertNotIn("volumes", compose)
        service = compose["services"]["graphql-engine"]
        self.assertEqual(service["restart"], "no")
        self.assertEqual(service["ports"][0]["host_ip"], self.spec["placement"]["hasura_bind"])
        for key in ("HASURA_GRAPHQL_DATABASE_URL", "HASURA_GRAPHQL_METADATA_DATABASE_URL"):
            self.assertTrue(service["environment"][key].endswith("/" + envio.DATABASE))
            self.assertNotIn("${ENVIO_DATABASE_URL", service["environment"][key])
        runtime = json.loads(files["runtime-env.json"])
        self.assertEqual(runtime["ENVIO_PG_DATABASE"], envio.DATABASE)
        self.assertEqual(runtime["ENVIO_RPC_POLLING_INTERVAL_MILLIS"], "12000")
        self.assertEqual(runtime["HASURA_GRAPHQL_ENDPOINT"],
                         f'http://{self.spec["placement"]["hasura_bind"]}:28080/v1/metadata')

    def test_ordered_fallback_preserves_supplied_order(self):
        self.complete()
        route = self.spec["rpc_routes"]["sepolia"]
        route["urls"].append(route["urls"][0] + "/fallback")
        files, _ = self.build()
        rpc = yaml.safe_load(files["config.yaml"])["networks"][0]["rpc"]
        self.assertEqual([r["url"] for r in rpc], route["urls"])
        self.assertEqual([r["for"] for r in rpc], ["sync", "fallback"])
        self.assertEqual(json.loads(files["runtime-env.json"])["PSY_ENVIO_ORDERED_FAILOVER"], "1")

    def test_incomplete_or_failed_or_wrong_chain_documents_rejected(self):
        self.complete()
        original = copy.deepcopy(self.spec)
        for kind in ("missing", "chain", "failed", "address", "unmined"):
            with self.subTest(kind=kind):
                self.spec = copy.deepcopy(original)
                docs = self.spec["l1_documents"]["sepolia"]
                if kind == "missing":
                    del docs["state_manager_receipt"]
                else:
                    key = "summary" if kind == "chain" else "bridge_receipt"
                    value = json.loads(Path(docs[key]["path"]).read_bytes())
                    if kind == "chain":
                        value["chainId"] = 1
                    elif kind == "address":
                        value["address"] = "0x" + "3" * 40
                    else:
                        value["receipt"]["status" if kind == "failed" else "blockNumber"] = 0
                    docs[key] = self.artifact(kind + ".json", envio.encode(value))
                with self.assertRaises(ValueError):
                    self.build()

    def test_public_hosts_old_ports_superuser_and_small_windows_rejected(self):
        self.complete()
        original = copy.deepcopy(self.spec)
        changes = [("postgres_host", "8.8.8.8"), ("hasura_bind", "0.0.0.0"),
                   ("hasura_port", 18080), ("indexer_port", 9898), ("postgres_user", "postgres")]
        for key, value in changes:
            self.spec = copy.deepcopy(original)
            self.spec["placement"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.build()
        self.spec = copy.deepcopy(original)
        self.spec["rpc_routes"]["bscTestnet"]["confirmed_block_threshold"] = 8
        with self.assertRaises(ValueError):
            self.build()

    def test_receipts_are_proxy_creations_bound_to_exporter(self):
        self.complete()
        original = copy.deepcopy(self.spec)
        for kind in ("proxy", "deployment_block", "contract_address", "missing_address", "transaction"):
            self.spec = copy.deepcopy(original)
            docs = self.spec["l1_documents"]["sepolia"]
            key = "summary" if kind in ("proxy", "deployment_block") else "bridge_receipt"
            value = json.loads(Path(docs[key]["path"]).read_bytes())
            if kind == "proxy":
                value["proxies"]["Bridge_Proxy"] = "0x" + "3" * 40
            elif kind == "deployment_block":
                value["deploymentBlock"] = 121
            elif kind == "missing_address":
                del value["receipt"]["contractAddress"]
            elif kind == "transaction":
                value["transactionHash"] = "0x" + "b" * 64
            else:
                value["receipt"]["contractAddress"] = "0x" + "3" * 40
            docs[key] = self.artifact(kind + ".json", envio.encode(value))
            with self.subTest(kind=kind), self.assertRaises((ValueError, KeyError)):
                self.build()

    def test_rpc_credentials_public_hosts_and_partial_routes_rejected(self):
        self.complete()
        original = copy.deepcopy(self.spec)
        for url in ("https://example.com/rpc", "http://user:password@example.com", "http://127.0.0.1:8545"):
            self.spec = copy.deepcopy(original)
            self.spec["rpc_routes"]["sepolia"]["urls"] = [url]
            with self.assertRaises(ValueError):
                self.build()
        self.spec = copy.deepcopy(original)
        del self.spec["rpc_routes"]["bscTestnet"]
        with self.assertRaises(ValueError):
            self.build()

    def test_patch_hash_is_independent_of_operator_supplied_pin(self):
        self.spec["patches"]["history.py"] = self.artifact("changed.py", b"different patch")
        with self.assertRaises(ValueError):
            self.build()

    def test_lock_importer_must_match_current_source(self):
        self.complete()
        descriptor = self.spec["dependency_lock"]
        lock = yaml.safe_load(Path(descriptor["path"]).read_bytes())
        lock["importers"]["."]["devDependencies"]["envio"]["specifier"] = "2.0.0"
        self.spec["dependency_lock"] = self.artifact("bad-lock", yaml.safe_dump(lock).encode())
        with self.assertRaises(ValueError):
            self.build()

    def test_prepare_is_private_atomic_and_never_executes_patch_or_network(self):
        self.complete()
        spec = self.artifact("spec.json", envio.encode(self.spec))
        args = SimpleNamespace(spec=Path(spec["path"]), spec_sha256=spec["sha256"],
                               source_repo=self.root, output=self.root / "package")
        with patch.object(envio.subprocess, "run", side_effect=AssertionError("unexpected command")):
            envio.prepare(args)
        for path in args.output.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        manifest = json.loads((args.output / "manifest.json").read_bytes())
        for name, expected in manifest["files"].items():
            self.assertEqual(hashlib.sha256((args.output / name).read_bytes()).hexdigest(), expected)
        with self.assertRaises(ValueError):
            envio.prepare(args)
        self.assertEqual(list(self.root.glob(".envio-prepare-*")), [])

    def test_failure_cleans_only_owned_temporary_output(self):
        spec = self.artifact("spec.json", envio.encode(self.spec))
        args = SimpleNamespace(spec=Path(spec["path"]), spec_sha256=spec["sha256"],
                               source_repo=self.root, output=self.root / "package")
        with patch.object(envio, "write_new", side_effect=OSError("disk full")), self.assertRaises(OSError):
            envio.prepare(args)
        self.assertFalse(args.output.exists())
        self.assertEqual(list(self.root.glob(".envio-prepare-*")), [])
        self.assertTrue(args.spec.exists())

    def test_symlink_inputs_and_git_outputs_rejected(self):
        descriptor = self.spec["patches"]["history.py"]
        link = self.root / "link"
        link.symlink_to(descriptor["path"])
        with self.assertRaises(ValueError):
            envio.read(link)
        spec = self.artifact("spec.json", envio.encode(self.spec))
        (self.root / ".git").mkdir()
        (self.root / ".git/HEAD").write_text("ref: refs/heads/main\n")
        args = SimpleNamespace(spec=Path(spec["path"]), spec_sha256=spec["sha256"],
                               source_repo=self.root, output=self.root / "package")
        with self.assertRaises(ValueError):
            envio.prepare(args)

    def test_git_reader_uses_commit_objects_not_dirty_worktree(self):
        self.source_mock.stop()
        repo = self.root / "source"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for name, raw in self.sources.items():
            path = repo / envio.SOURCE_DIR / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        subprocess.run(["git", "-C", str(repo), "add", envio.SOURCE_DIR], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
        commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        (repo / envio.SOURCE_DIR / "handlers.ts").write_text("unowned dirty bytes")
        with patch.object(envio, "SOURCE", commit):
            self.assertEqual(envio.source_files(repo)["handlers.ts"], self.sources["handlers.ts"])
        old = subprocess.check_output(["git", "-C", str(repo), "rev-parse", f"{commit}:{envio.SOURCE_DIR}/handlers.ts"], text=True).strip()
        new = subprocess.check_output(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=b"replaced object").decode().strip()
        subprocess.run(["git", "-C", str(repo), "replace", old, new], check=True)
        with patch.object(envio, "SOURCE", commit):
            self.assertEqual(envio.source_files(repo)["handlers.ts"], self.sources["handlers.ts"])
            with patch.dict(os.environ, {"GIT_DIR": str(self.root / "missing.git")}):
                self.assertEqual(envio.source_files(repo)["handlers.ts"], self.sources["handlers.ts"])


if __name__ == "__main__":
    unittest.main()
