import copy
import errno
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load("install_guardian")
wrapper = load("guardian_exec")
ADDRESS = str(ipaddress.IPv4Address((10 << 24) + 41))
PROXY = str(ipaddress.IPv4Address((10 << 24) + 42))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.network = {"magic": installer.MAGIC, "membership": ["unchanged"],
                        "guardian_initial_member_hashes": [f"{i:064x}" for i in (1, 2, 3)],
                        "guardian_configs": [{"id": i, "listen_address": f"{ADDRESS}:{9700+i}"} for i in (1, 2, 3)],
                        "coordinator_configs": [{"id": 0, "rpc_url": ["http://old.example:1"]}],
                        "realm_configs": [{"id": i, "rpc_url": ["http://old.example:2"]} for i in (0, 1)],
                        "prove_proxy_url": ["http://old.example:3"], "system_prove_proxy_url": ["http://old.example:4"]}
        self.canonical = {"defaultNetwork": "testnet", "networks": {"testnet": self.network, "localhost": {"keep": True}}}
        self.rpc = copy.deepcopy(self.canonical)
        for field in ("coordinator_configs", "realm_configs"):
            for row in self.rpc["networks"]["testnet"][field]:
                row["rpc_url"] = [f"http://{ADDRESS}:15370"]
        self.rpc["networks"]["testnet"]["prove_proxy_url"] = [f"https://{PROXY}:19999"]
        self.rpc["networks"]["testnet"]["system_prove_proxy_url"] = [f"http://{PROXY}:19998"]
        self.history = {"listen_address": f"{PROXY}:9700", "rpc_url": f"http://{PROXY}:9700"}
        self.rpc["networks"]["testnet"]["guardian_history"] = copy.deepcopy(self.history)
        self.key = b'{"version":3,"crypto":{"ciphertext":"synthetic-only"}}'
        binary = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00" + b"synthetic"
        canonical = self.input("canonical.json", self.canonical)
        build = {"source_commit": installer.RUNTIME_SOURCE, "network": "testnet",
                 "config_sha256": canonical["sha256"], "binaries": {"psy_relayer_cli": installer.digest(binary)}}
        self.spec = {"version": 3, "guardian_id": 1, "hostname": "guardian.example", "address": ADDRESS,
                     "guardian_history": copy.deepcopy(self.history),
                     "proof_origins": {field: copy.deepcopy(self.rpc["networks"]["testnet"][field])
                                       for field in ("prove_proxy_url", "system_prove_proxy_url")},
                     "service_user": "psy-guardian-1", "memory_high_gib": 4, "memory_max_gib": 6,
                     "custody_keystore_sha256": installer.digest(self.key), "build": self.input("build.json", build),
                     "binary": self.input("binary", binary), "canonical_config": canonical,
                     "rpc_config": self.input("rpc.json", self.rpc),
                     "wrapper": self.input("wrapper.py", (HERE / "guardian_exec.py").read_bytes()), "l1_documents": {}}
        self.addCleanup(patch.stopall)
        patch.object(installer, "BUILD_HASH", self.spec["build"]["sha256"]).start()
        self.spec_path = self.root / "spec.json"

    def input(self, name, value):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return {"path": str(path), "sha256": installer.digest(raw)}

    def save(self):
        return self.input("spec.json", self.spec)["sha256"]

    def documents(self):
        for name, (index, chain_id) in installer.CHAINS.items():
            bridge = "0x" + f"{index+1:040x}"
            summary = {"network": name, "chainId": str(chain_id), "core": {"Bridge": bridge},
                       "protocol": {"chain": {"l1ChainIndex": index, "l1ChainId": chain_id,
                                               "defaultRpcUrl": f"https://{PROXY}:8545"}}}
            receipt = {"address": bridge, "receipt": {"blockNumber": 123}}
            self.spec["l1_documents"][name] = {"summary": self.input(name + ".json", summary),
                                              "receipt": self.input(name + "-receipt.json", receipt)}

    def test_pending_plan_is_readonly_and_never_ready(self):
        with patch.object(installer, "host_checks") as host, patch.object(installer, "write") as write:
            result = installer.run("plan", self.spec_path, self.save())
        host.assert_not_called()
        write.assert_not_called()
        self.assertTrue(result["l1_documents_pending"])
        self.assertFalse(result["deployment_ready"] or result["release_approved"] or result["started"] or result["enabled"])
        self.assertEqual(result["runtime_source"], installer.RUNTIME_SOURCE)
        self.assertEqual(result["key_source"], installer.KEY_SOURCE)

    def test_install_requires_apply_and_real_documents(self):
        for mode, apply in (("install", False), ("plan", True), ("install", True), ("check-host", False)):
            with self.subTest(mode=mode, apply=apply), patch.object(installer, "host_checks") as host:
                with self.assertRaises(ValueError):
                    installer.run(mode, self.spec_path, self.save(), apply)
                host.assert_not_called()

    def test_spec_permissions_hash_and_duplicate_fields(self):
        sha = self.save()
        self.spec_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private file"):
            installer.load_plan(self.spec_path, sha)
        self.save()
        with self.assertRaisesRegex(ValueError, "spec hash"):
            installer.load_plan(self.spec_path, "f" * 64)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            installer.decode(b'{"version":1,"version":1}')

    def test_non_url_config_changes_fail(self):
        for mutate in (lambda x: x["networks"]["testnet"].update(membership=[]),
                       lambda x: x["networks"]["localhost"].update(keep=False),
                       lambda x: x.update(defaultNetwork="localhost")):
            rpc = copy.deepcopy(self.rpc)
            mutate(rpc)
            self.spec["rpc_config"] = self.input("rpc.json", rpc)
            with self.assertRaises(ValueError):
                installer.load_plan(self.spec_path, self.save())

    def test_history_is_explicit_without_mutating_canonical(self):
        original = Path(self.spec["canonical_config"]["path"]).read_bytes()
        _, files, network, _ = installer.load_plan(self.spec_path, self.save())
        self.assertEqual(network["guardian_history"], self.history)
        self.assertEqual(files["canonical.json"], original)
        self.assertEqual(Path(self.spec["canonical_config"]["path"]).read_bytes(), original)
        self.assertNotIn("guardian_history", self.canonical["networks"]["testnet"])
        for history in (None, self.history):
            canonical = copy.deepcopy(self.canonical)
            canonical["networks"]["testnet"]["guardian_history"] = copy.deepcopy(history)
            frozen = copy.deepcopy(canonical)
            installer.validate_rpc(canonical, self.rpc, self.spec)
            self.assertEqual(canonical, frozen)

    def test_missing_history_and_old_spec_are_rejected(self):
        self.spec["version"] = 1
        with self.assertRaisesRegex(ValueError, "version"):
            installer.load_plan(self.spec_path, self.save())
        self.spec["version"] = 3
        del self.spec["guardian_history"]
        with self.assertRaisesRegex(ValueError, "fields"):
            installer.load_plan(self.spec_path, self.save())
        self.spec["guardian_history"] = self.history
        for value in (None, {}, {"listen_address": self.history["listen_address"]}):
            rpc = copy.deepcopy(self.rpc)
            rpc["networks"]["testnet"]["guardian_history"] = value
            with self.assertRaisesRegex(ValueError, "history"):
                installer.validate_rpc(self.canonical, rpc, self.spec)

    def test_history_must_match_approval_and_existing_canonical(self):
        changed = {"listen_address": f"{PROXY}:9701", "rpc_url": f"http://{PROXY}:9701"}
        rpc = copy.deepcopy(self.rpc)
        rpc["networks"]["testnet"]["guardian_history"] = changed
        with self.assertRaisesRegex(ValueError, "approval"):
            installer.validate_rpc(self.canonical, rpc, self.spec)
        canonical = copy.deepcopy(self.canonical)
        canonical["networks"]["testnet"]["guardian_history"] = changed
        with self.assertRaisesRegex(ValueError, "canonical history"):
            installer.validate_rpc(canonical, self.rpc, self.spec)
        rpc = copy.deepcopy(self.rpc)
        rpc["networks"]["testnet"]["guardian_initial_member_hashes"][0] = "f" * 64
        with self.assertRaisesRegex(ValueError, "non-URL"):
            installer.validate_rpc(self.canonical, rpc, self.spec)

    def test_history_origin_is_private_http_and_matches_listen(self):
        variants = [
            {"listen_address": f"{PROXY}:0", "rpc_url": f"http://{PROXY}:0"},
            {"listen_address": "127.0.0.1:9700", "rpc_url": "http://127.0.0.1:9700"},
            {"listen_address": "history.example:9700", "rpc_url": "http://history.example:9700"},
            {"listen_address": f"{PROXY}:9700/path", "rpc_url": f"http://{PROXY}:9700/path"},
            {"listen_address": f"user@{PROXY}:9700", "rpc_url": f"http://user@{PROXY}:9700"},
            {**self.history, "rpc_url": f"https://{PROXY}:9700"},
            {**self.history, "rpc_url": f"http://{PROXY}:9701"},
            {**self.history, "rpc_url": f"http://{PROXY}:9700?token=x"},
        ]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                rpc, spec = copy.deepcopy(self.rpc), copy.deepcopy(self.spec)
                rpc["networks"]["testnet"]["guardian_history"] = value
                spec["guardian_history"] = value
                installer.validate_rpc(self.canonical, rpc, spec)

    def test_host_bind_and_private_proof_urls_required(self):
        for value in ("http://rpc.example:9999", f"http://user:pass@{PROXY}:9999", f"http://{PROXY}:9999/?token=x"):
            with self.assertRaises(ValueError):
                installer.origins([value])
        self.spec["address"] = PROXY
        with self.assertRaisesRegex(ValueError, "bind mismatch"):
            installer.load_plan(self.spec_path, self.save())

    def test_explicit_loopback_proof_origins_and_private_edges(self):
        for field, port in (("prove_proxy_url", 19999), ("system_prove_proxy_url", 19998)):
            values = [f"http://127.0.0.1:{port}"]
            self.rpc["networks"]["testnet"][field] = values
            self.spec["proof_origins"][field] = values
        self.spec["rpc_config"] = self.input("rpc.json", self.rpc)
        installer.load_plan(self.spec_path, self.save())
        for field in ("coordinator_configs", "realm_configs"):
            rpc = copy.deepcopy(self.rpc)
            rpc["networks"]["testnet"][field][0]["rpc_url"] = ["http://127.0.0.1:15370"]
            with self.assertRaisesRegex(ValueError, "private IPv4"):
                installer.validate_rpc(self.canonical, rpc, self.spec)

    def test_proof_loopback_requires_exact_explicit_approval(self):
        rpc = copy.deepcopy(self.rpc)
        rpc["networks"]["testnet"]["prove_proxy_url"] = ["http://127.0.0.1:19999"]
        with self.assertRaisesRegex(ValueError, "operator approval"):
            installer.validate_rpc(self.canonical, rpc, self.spec)
        self.spec["proof_origins"] = {}
        with self.assertRaisesRegex(ValueError, "explicit proof"):
            installer.validate_rpc(self.canonical, rpc, self.spec)
        del self.spec["proof_origins"]
        with self.assertRaisesRegex(ValueError, "fields"):
            installer.load_plan(self.spec_path, self.save())

    def test_user_proof_rejects_native_incompatible_or_public_transport(self):
        values = [f"http://{PROXY}:9999", "https://rpc.example:9999", "http://127.0.0.1:0",
                  "http://127.0.0.1:65536", "http://[::1]:9999", "https://8.8.8.8:9999",
                  "http://user:pass@127.0.0.1:9999", "http://127.0.0.1:9999?token=x"]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                rpc, spec = copy.deepcopy(self.rpc), copy.deepcopy(self.spec)
                rpc["networks"]["testnet"]["prove_proxy_url"] = [value]
                spec["proof_origins"]["prove_proxy_url"] = [value]
                installer.validate_rpc(self.canonical, rpc, spec)

    def test_l1_document_transport_matches_native_guardian_boundary(self):
        self.documents()
        field = self.spec["l1_documents"]["sepolia"]
        document = json.loads(Path(field["summary"]["path"]).read_bytes())
        for value, valid in (("http://127.0.0.1:18545", True), (f"https://{PROXY}:18545", True),
                             (f"http://{PROXY}:18545", False), ("https://rpc.example", False)):
            document["protocol"]["chain"]["defaultRpcUrl"] = value
            field["summary"] = self.input("sepolia.json", document)
            with self.subTest(value=value):
                if valid:
                    self.assertEqual(len(installer.l1_files(self.spec["l1_documents"])), 6)
                else:
                    with self.assertRaises(ValueError):
                        installer.l1_files(self.spec["l1_documents"])

    def test_artifact_tampering_and_wrapper_substitution_fail(self):
        original = self.spec["wrapper"]
        self.spec["wrapper"] = self.input("different-wrapper.py", b"unreviewed")
        with self.assertRaisesRegex(ValueError, "sibling wrapper"):
            installer.load_plan(self.spec_path, self.save())
        self.spec["wrapper"] = original
        Path(self.spec["binary"]["path"]).write_bytes(b"altered")
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            installer.load_plan(self.spec_path, self.save())
        self.spec["binary"] = self.input("binary", b"wrong ELF")
        with self.assertRaisesRegex(ValueError, "reviewed x86"):
            installer.load_plan(self.spec_path, self.save())

    def test_l1_documents_must_match_testnet_and_receipt(self):
        self.documents()
        self.assertEqual(len(installer.l1_files(self.spec["l1_documents"])), 6)
        fields = self.spec["l1_documents"]["sepolia"]
        fields["receipt"] = self.input("bad-receipt.json", {"address": "0x" + "9" * 40, "receipt": {"blockNumber": 123}})
        with self.assertRaisesRegex(ValueError, "receipt mismatch"):
            installer.l1_files(self.spec["l1_documents"])
        self.documents()
        doc = json.loads(Path(fields["summary"]["path"]).read_text())
        doc["chainId"] = "1"
        self.spec["l1_documents"]["sepolia"]["summary"] = self.input("wrong-chain.json", doc)
        with self.assertRaisesRegex(ValueError, "testnet identity"):
            installer.l1_files(self.spec["l1_documents"])

    def test_input_symlinks_hardlinks_and_parent_symlinks_rejected(self):
        target = Path(self.spec["canonical_config"]["path"])
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            installer.read(link)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            installer.read(alias / target.name)
        hardlink = self.root / "hardlink"
        os.link(target, hardlink)
        with self.assertRaisesRegex(ValueError, "single-link"):
            installer.read(hardlink)

    def test_real_root_directory_is_valid_for_ancestor_checks(self):
        fd = installer.directory(Path("/"))
        try:
            self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
        finally:
            os.close(fd)
        installer.trusted_directory(Path("/"))
        for path in Path("/var/lib").parents:
            installer.trusted_directory(path)

    def test_units_scope_credentials_and_write_access_for_all_ids(self):
        for guardian_id in (1, 2, 3):
            self.spec.update(guardian_id=guardian_id, service_user=f"psy-guardian-{guardian_id}")
            text = installer.unit(self.spec).decode()
            self.assertIn(f"LoadCredentialEncrypted=psy-guardian-{guardian_id}-password:", text)
            self.assertIn(f"/guardian-{guardian_id}/psy-guardian-{guardian_id}-password.cred", text)
            self.assertIn(f"ReadWritePaths={installer.STATES}/guardian-{guardian_id}/db\n", text)
            self.assertIn("ProtectSystem=strict", text)
            self.assertIn("WantedBy=multi-user.target", text)
            self.assertNotIn("KEYSTORE_PASSWORD=", text)

    def test_install_uses_frozen_bytes_and_copies_only_assigned_key(self):
        self.documents()
        for name in ("RELEASES", "STATES", "UNITS"):
            path = self.root / name.lower()
            path.mkdir()
            patch.object(installer, name, path).start()
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        expected_binary = Path(self.spec["binary"]["path"]).read_bytes()

        def checked(*args):
            Path(self.spec["binary"]["path"]).write_bytes(b"changed-after-validation")
            return account, self.key

        old_unit = installer.UNITS / "psy-guardian-1.service"
        old_unit.write_bytes(b"retained old unit")
        r2_unit = installer.UNITS / "psy-guardian-r2-1.service"
        r2_unit.write_bytes(b"retained R2 unit")
        with patch.object(installer, "host_checks", side_effect=checked), \
                patch.object(installer.os, "fchown"), patch.object(installer, "command") as command:
            result = installer.run("install", self.spec_path, self.save(), apply=True)
        command.assert_called_once_with(["systemctl", "daemon-reload"])
        release = installer.RELEASES / "guardian-1"
        self.assertEqual((release / "psy_relayer_cli").read_bytes(), expected_binary)
        keys = release / "home/.psy/keystore"
        self.assertEqual([p.name for p in keys.iterdir()], ["guardian-1.keystore.json"])
        self.assertEqual((keys / "guardian-1.keystore.json").read_bytes(), self.key)
        for path in (release / "home", release / "home/.psy", keys, installer.STATES / "guardian-1/db"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((keys / "guardian-1.keystore.json").stat().st_mode), 0o600)
        self.assertFalse(result["started"] or result["enabled"])
        self.assertEqual(old_unit.read_bytes(), b"retained old unit")
        self.assertEqual(r2_unit.read_bytes(), b"retained R2 unit")
        self.assertEqual((installer.UNITS / "psy-guardian-r3-1.service").read_bytes(), installer.unit(self.spec))

    def test_atomic_write_refuses_existing_target_and_cleans_owned_temporary(self):
        target = self.root / "existing"
        target.write_bytes(b"preserved")
        with patch.object(installer.os, "fchown"):
            with self.assertRaises(FileExistsError):
                installer.write(target, b"replacement")
        self.assertEqual(target.read_bytes(), b"preserved")
        self.assertEqual(list(self.root.glob(".guardian-*")), [])
        target = self.root / "failed"
        with patch.object(installer.os, "fchown", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                installer.write(target, b"incomplete")
        self.assertFalse(target.exists())
        self.assertEqual(list(self.root.glob(".guardian-*")), [])

    def test_host_checks_custody_binding_and_conflicts(self):
        self.documents()
        self.root.chmod(0o755)
        for name in ("RELEASES", "STATES", "UNITS", "CUSTODY"):
            path = self.root / name.lower()
            path.mkdir()
            patch.object(installer, name, path).start()
        custody = installer.CUSTODY / "guardian-1"
        public = {"guardian_id": 1, "node_source": installer.KEY_SOURCE, "host": ADDRESS,
                  "destination": str(custody), "public_key_hash": self.network["guardian_initial_member_hashes"][0],
                  "keystore_sha256": installer.digest(self.key)}
        outputs = {"ip": json.dumps([{"addr_info": [{"local": ADDRESS}]}]),
                   "ss": "", "systemd-analyze": str(installer.UNITS)}
        state = {"show": "LoadState=not-found\n", "jobs": ""}
        overrides = {}

        def command(argv):
            if argv[0] == "systemctl":
                if argv[1] == "--version":
                    return "systemd 252"
                if argv[1] == "show" and argv[2] in overrides:
                    return overrides[argv[2]]
                if argv[1] == "show" and argv[2] == "psy-guardian-r2-1.service" and state["show"] == "LoadState=not-found\n":
                    return "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\n"
                return state["show" if argv[1] == "show" else "jobs"]
            return outputs[argv[0]]

        def read(path, **kwargs):
            self.assertTrue(kwargs["private"])
            self.assertEqual(kwargs["uid"], 0)
            return {"public.json": json.dumps(public).encode(), "guardian-1.keystore.json": self.key,
                    "psy-guardian-1-password.cred": b"host-bound-encrypted-fixture"}[path.name]

        patch.object(installer.os, "geteuid", return_value=0).start()
        patch.object(installer.socket, "gethostname", return_value=self.spec["hostname"]).start()
        patch.object(installer.os, "uname", return_value=SimpleNamespace(machine="x86_64")).start()
        patch.object(installer.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1234, pw_gid=1234)).start()
        patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=1234)).start()
        patch.object(installer, "trusted_directory").start()
        patch.object(installer, "command", side_effect=command).start()
        patch.object(installer, "read", side_effect=read).start()
        _, key = installer.host_checks(self.spec, self.network, 9701)
        self.assertEqual(key, self.key)
        good = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\n"
        for generation in ("", "r2-", "r3-"):
            for guardian_id in (1, 2, 3):
                name = f"psy-guardian-{generation}{guardian_id}.service"
                overrides[name] = good.replace("inactive", "active")
                with self.subTest(unit=name), self.assertRaisesRegex(ValueError, "active or enabled"):
                    installer.host_checks(self.spec, self.network, 9701)
                overrides.clear()
        for output in ("LoadState=not-found\n", good.replace("disabled", "static"),
                       good.replace("disabled", "enabled"), good.replace("MainPID=0", "MainPID=42")):
            overrides["psy-guardian-r2-1.service"] = output
            with self.subTest(r2=output), self.assertRaisesRegex(ValueError, "active or enabled"):
                installer.host_checks(self.spec, self.network, 9701)
        overrides.clear()
        for field, value in (("node_source", installer.RUNTIME_SOURCE), ("public_key_hash", "f" * 64),
                             ("keystore_sha256", "f" * 64), ("guardian_id", 2), ("host", PROXY)):
            original = public[field]
            public[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                installer.host_checks(self.spec, self.network, 9701)
            public[field] = original
        state["show"] = "LoadState=loaded\nActiveState=active\nMainPID=42\nUnitFileState=enabled\n"
        with self.assertRaisesRegex(ValueError, "active or enabled"):
            installer.host_checks(self.spec, self.network, 9701)
        state["show"] = "LoadState=not-found\n"
        state["jobs"] = "1 psy-guardian-1.service start waiting"
        with self.assertRaisesRegex(ValueError, "job queued"):
            installer.host_checks(self.spec, self.network, 9701)
        state["jobs"] = ""
        outputs["ss"] = f"LISTEN 0 10 {ADDRESS}:9701 0.0.0.0:*"
        with self.assertRaisesRegex(ValueError, "port occupied"):
            installer.host_checks(self.spec, self.network, 9701)
        outputs["ss"] = ""
        (installer.RELEASES / "guardian-1").mkdir()
        with self.assertRaisesRegex(ValueError, "destination exists"):
            installer.host_checks(self.spec, self.network, 9701)

    def test_check_host_mode_never_writes_or_reloads(self):
        self.documents()
        with patch.object(installer, "host_checks", return_value=(None, None)) as host, \
                patch.object(installer, "write") as write, patch.object(installer, "command") as command:
            installer.run("check-host", self.spec_path, self.save())
        host.assert_called_once()
        write.assert_not_called()
        command.assert_not_called()

    def test_r3_rejects_old_schema_and_uses_fresh_state(self):
        self.spec["version"] = 2
        with self.assertRaisesRegex(ValueError, "version"):
            installer.load_plan(self.spec_path, self.save())
        self.assertTrue(str(installer.RELEASES).endswith("core-testnet-20261027-r3"))
        self.assertTrue(str(installer.STATES).endswith("core-testnet-20261027-r3"))
        self.assertEqual(installer.KEY_SOURCE, "de539f565ec1a92f91bb4e9686e1442e89ba8639")
        self.assertEqual(installer.RUNTIME_SOURCE, "3d31758738f833a7eea6f9ff7fd680a69a0d9a44")

    def test_unfrozen_or_old_build_manifest_fails_closed(self):
        for build_hash in (None, "da174adeccef81c312e1f2eb1e6a136b53fb8a68f6e9f5b39510c6c1305133bf"):
            with self.subTest(pin=build_hash), patch.object(installer, "BUILD_HASH", build_hash):
                with self.assertRaisesRegex(ValueError, "reviewed build manifest"):
                    installer.load_plan(self.spec_path, self.save())

    def test_retained_unit_must_be_loaded_inactive_disabled_without_jobs(self):
        names = ("old.service", "new.service")
        good = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\n"
        for output in ("LoadState=not-found\n", good.replace("disabled", "enabled"),
                       good.replace("disabled", "masked"), good.replace("disabled", "static"),
                       good.replace("inactive", "active"), good.replace("MainPID=0", "MainPID=42"),
                       good.replace("LoadState=loaded", "LoadState=error")):
            with self.subTest(output=output), patch.object(installer, "command", return_value=output):
                with self.assertRaises(ValueError):
                    installer.inactive_units(names, {"old.service"})
        def command(argv):
            if argv[1] == "show":
                return good if argv[2] == "old.service" else "LoadState=not-found\n"
            return ""
        with patch.object(installer, "command", side_effect=command):
            installer.inactive_units(names, {"old.service"})
        for name in names:
            with patch.object(installer, "command", side_effect=[good, "LoadState=not-found\n", f"1 {name} start waiting"]):
                with self.assertRaisesRegex(ValueError, "job queued"):
                    installer.inactive_units(names, {"old.service"})

    def test_static_guardian_requires_listed_scope_and_no_enablement(self):
        name = "psy-guardian-1.service"
        good = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=static\n"
        with patch.object(installer, "command", side_effect=[good, ""]), \
                patch.object(installer, "static_guardian_unlinked") as check:
            installer.inactive_units([name], {name}, {name})
            check.assert_called_once_with(name)
        with patch.object(installer, "command", return_value=good), \
                patch.object(installer, "static_guardian_unlinked") as check:
            with self.assertRaises(ValueError):
                installer.inactive_units([name], {name})
            check.assert_not_called()
        with self.assertRaises(ValueError):
            installer.static_guardian_unlinked("psy-core-relayer.service")
        unit_root = self.root / "units"
        unit_root.mkdir()
        (unit_root / name).write_bytes(b"[Service]\nExecStart=/bin/true\n")
        wanted = unit_root / "multi-user.target.wants"
        wanted.mkdir()
        details = f"FragmentPath={unit_root / name}\nDropInPaths=\nNames={name}\n"
        def command(argv):
            return details if argv[0] == "systemctl" else str(unit_root)
        with patch.object(installer, "UNITS", unit_root), patch.object(installer, "command", side_effect=command):
            installer.static_guardian_unlinked(name)
            for link in (wanted / name, unit_root / "alias.service"):
                link.symlink_to(unit_root / name)
                with self.assertRaisesRegex(ValueError, "enablement or alias"):
                    installer.static_guardian_unlinked(name)
                link.unlink()
            for changed in (details.replace("DropInPaths=", "DropInPaths=/unapproved.conf"),
                            details.replace(f"Names={name}", f"Names={name} alias.service"),
                            details.replace(f"FragmentPath={unit_root / name}", "FragmentPath=/wrong.service")):
                with patch.object(installer, "command", return_value=changed), self.assertRaises(ValueError):
                    installer.static_guardian_unlinked(name)
        with patch.object(installer, "command", side_effect=[good, f"1 {name} start waiting"]), \
                patch.object(installer, "static_guardian_unlinked"):
            with self.assertRaisesRegex(ValueError, "job queued"):
                installer.inactive_units([name], {name}, {name})


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(self.root.chmod, 0o700)

    def credential(self, guardian_id, value):
        self.root.chmod(0o700)
        path = self.root / f"psy-guardian-{guardian_id}-password"
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(value)
        path.chmod(0o400)
        self.root.chmod(0o500)
        return path

    @staticmethod
    def acl(permission, uid=999):
        return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in (
            (1, permission, 0xffffffff), (2, permission, uid), (4, 0, 0xffffffff),
            (16, permission, 0xffffffff), (32, 0, 0xffffffff)))

    def test_systemd_root_acl_file_and_directory_launch(self):
        self.credential(1, b"synthetic-only")
        real_fstat = os.fstat

        def metadata(fd):
            directory = stat.S_ISDIR(real_fstat(fd).st_mode)
            return SimpleNamespace(st_uid=0, st_gid=0,
                                   st_mode=(stat.S_IFDIR | 0o550) if directory else (stat.S_IFREG | 0o440))

        def acl(fd, name):
            self.assertEqual(name, "system.posix_acl_access")
            return self.acl(5 if stat.S_ISDIR(real_fstat(fd).st_mode) else 4)

        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root)}, clear=True), \
                patch.object(wrapper.resource, "setrlimit"), patch.object(wrapper.os, "geteuid", return_value=999), \
                patch.object(wrapper.os, "fstat", side_effect=metadata), \
                patch.object(wrapper.os, "getxattr", side_effect=acl), \
                patch.object(wrapper.os, "execve") as execute:
            wrapper.launch(1)
        self.assertEqual(execute.call_args.args[2]["GUARDIAN_1_KEYSTORE_PASSWORD"], "synthetic-only")

    def test_root_acl_rejects_nonexact_metadata_and_permissions(self):
        for directory in (False, True):
            permission = 5 if directory else 4
            mode = (stat.S_IFDIR if directory else stat.S_IFREG) | (0o550 if directory else 0o440)
            expected = self.acl(permission)
            altered_acls = [None, b"", expected[:-1], expected + b"\0", self.acl(permission, 998),
                            struct.pack("<I", 3) + expected[4:],
                            expected + struct.pack("<HHI", 8, permission, 988)]
            for offset, value in ((6, permission | 2), (14, permission | 2),
                                  (22, permission), (30, permission | 2), (38, permission)):
                altered = bytearray(expected)
                struct.pack_into("<H", altered, offset, value)
                altered_acls.append(bytes(altered))
            cases = [(0, 0, mode, acl) for acl in altered_acls]
            cases.extend((uid, gid, changed, expected) for uid, gid, changed in (
                (998, 0, mode), (0, 988, mode), (0, 0, mode | 0o200),
                (0, 0, mode | 0o020), (0, 0, mode | 0o004), (0, 0, mode | 0o4000),
                (0, 0, stat.S_IFLNK | 0o550)))
            for uid, gid, changed, acl in cases:
                with self.subTest(directory=directory, uid=uid, gid=gid, mode=changed, acl=acl), \
                        patch.object(wrapper.os, "geteuid", return_value=999), \
                        patch.object(wrapper.os, "fstat", return_value=SimpleNamespace(
                            st_uid=uid, st_gid=gid, st_mode=changed)), \
                        patch.object(wrapper.os, "getxattr", return_value=acl):
                    with self.assertRaises(ValueError):
                        wrapper.check_credential_access(123, directory=directory)

    def test_uid_owned_readonly_credentials_and_xattr_errors(self):
        for directory in (False, True):
            mode = (stat.S_IFDIR | 0o500) if directory else (stat.S_IFREG | 0o400)
            with patch.object(wrapper.os, "geteuid", return_value=999), \
                    patch.object(wrapper.os, "fstat", return_value=SimpleNamespace(st_uid=999, st_gid=988, st_mode=mode)):
                for error in (errno.ENODATA, errno.EOPNOTSUPP):
                    with patch.object(wrapper.os, "getxattr", side_effect=OSError(error, "synthetic")):
                        wrapper.check_credential_access(123, directory=directory)
                with patch.object(wrapper.os, "getxattr", side_effect=OSError(errno.EACCES, "synthetic")):
                    with self.assertRaises(OSError):
                        wrapper.check_credential_access(123, directory=directory)
                with patch.object(wrapper.os, "getxattr", return_value=self.acl(5 if directory else 4)):
                    with self.assertRaises(ValueError):
                        wrapper.check_credential_access(123, directory=directory)

    def test_only_selected_password_in_exec_environment_not_argv(self):
        for guardian_id in (1, 2, 3):
            self.credential(guardian_id, b"synthetic-only")
            with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root),
                                         "GUARDIAN_2_KEYSTORE_PASSWORD": "other"}, clear=True), \
                    patch.object(wrapper.resource, "setrlimit"), patch.object(wrapper.os, "execve") as execute:
                wrapper.launch(guardian_id)
            binary, argv, env = execute.call_args.args
            self.assertTrue(binary.endswith("/psy_relayer_cli"))
            self.assertNotIn("synthetic-only", " ".join(argv))
            self.assertEqual({k: v for k, v in env.items() if k.startswith("GUARDIAN_")},
                             {f"GUARDIAN_{guardian_id}_KEYSTORE_PASSWORD": "synthetic-only"})
            self.assertEqual(argv.count("--l1-config"), 3)
            self.assertEqual(argv[argv.index("--guardian-root") + 1],
                             str(installer.STATES / f"guardian-{guardian_id}"))
            self.assertIn("guardian-service", argv)

    def test_invalid_credentials_never_exec(self):
        for value in (b"", b"x\n", b"x\r", b"x\0", b"x" * 4097, b"\xff", b"\xef\xbb\xbfsecret"):
            self.credential(1, value)
            with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root)}), \
                    patch.object(wrapper.resource, "setrlimit"), patch.object(wrapper.os, "execve") as execute:
                with self.assertRaises((ValueError, UnicodeError)):
                    wrapper.launch(1)
                execute.assert_not_called()

    def test_credential_mode_and_symlink_fail(self):
        path = self.credential(1, b"synthetic")
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root)}), \
                patch.object(wrapper.resource, "setrlimit"), patch.object(wrapper.os, "execve") as execute:
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                wrapper.launch(1)
            self.root.chmod(0o700)
            path.unlink()
            other = self.credential(2, b"other")
            self.root.chmod(0o700)
            path.symlink_to(other)
            self.root.chmod(0o500)
            with self.assertRaises(OSError):
                wrapper.launch(1)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
