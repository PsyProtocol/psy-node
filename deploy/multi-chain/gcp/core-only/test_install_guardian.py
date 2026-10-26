import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
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
                        "guardian_history": {"listen_address": f"{ADDRESS}:9700"},
                        "coordinator_configs": [{"id": 0, "rpc_url": ["http://old.example:1"]}],
                        "realm_configs": [{"id": i, "rpc_url": ["http://old.example:2"]} for i in (0, 1)],
                        "prove_proxy_url": ["http://old.example:3"], "system_prove_proxy_url": ["http://old.example:4"]}
        self.canonical = {"defaultNetwork": "testnet", "networks": {"testnet": self.network, "localhost": {"keep": True}}}
        self.rpc = copy.deepcopy(self.canonical)
        for field in ("coordinator_configs", "realm_configs"):
            for row in self.rpc["networks"]["testnet"][field]:
                row["rpc_url"] = [f"http://{ADDRESS}:15370"]
        self.rpc["networks"]["testnet"]["prove_proxy_url"] = [f"http://{PROXY}:19999"]
        self.rpc["networks"]["testnet"]["system_prove_proxy_url"] = [f"http://{PROXY}:19998"]
        self.key = b'{"version":3,"crypto":{"ciphertext":"synthetic-only"}}'
        binary = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00" + b"synthetic"
        canonical = self.input("canonical.json", self.canonical)
        build = {"source_commit": installer.RUNTIME_SOURCE, "network": "testnet",
                 "config_sha256": canonical["sha256"], "binaries": {"psy_relayer_cli": installer.digest(binary)}}
        self.spec = {"version": 1, "guardian_id": 1, "hostname": "guardian.example", "address": ADDRESS,
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
                                               "defaultRpcUrl": "https://rpc.example"}}}
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

    def test_host_bind_and_private_proof_urls_required(self):
        for value in ("http://rpc.example:9999", f"http://user:pass@{PROXY}:9999", f"http://{PROXY}:9999/?token=x"):
            with self.assertRaises(ValueError):
                installer.origins([value])
        self.spec["address"] = PROXY
        with self.assertRaisesRegex(ValueError, "bind mismatch"):
            installer.load_plan(self.spec_path, self.save())

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
            self.assertNotIn("WantedBy=", text)
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

        def command(argv):
            if argv[0] == "systemctl":
                if argv[1] == "--version":
                    return "systemd 252"
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


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def credential(self, guardian_id, value):
        path = self.root / f"psy-guardian-{guardian_id}-password"
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(value)
        path.chmod(0o400)
        return path

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
            path.unlink()
            path.symlink_to(self.credential(2, b"other"))
            with self.assertRaises(OSError):
                wrapper.launch(1)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
