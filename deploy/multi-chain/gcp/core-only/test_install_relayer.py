import copy
import contextlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
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


installer = load("install_relayer")
wrapper = load("relayer_exec")
credential_helper = load("prepare_relayer_credential")
ADDRESS = str(ipaddress.IPv4Address((172 << 24) + (30 << 16) + 1))
OTHER = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(ADDRESS)) + 1))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for constant in ("RELEASE", "STATE", "CREDENTIALS", "UNITS"):
            path = self.root / constant.lower()
            if constant == "UNITS":
                path.mkdir()
            patcher = patch.object(installer, constant, path)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.network = {"magic": installer.g.MAGIC, "membership": ["retained"],
                        "guardian_initial_member_hashes": [f"{i:064x}" for i in (1, 2, 3)],
                        "guardian_configs": [{"id": i, "listen_address": f"{ADDRESS}:{9700+i}"} for i in (1, 2, 3)],
                        "guardian_history": {"listen_address": f"{ADDRESS}:9700", "rpc_url": f"http://{ADDRESS}:9700"},
                        "coordinator_configs": [{"id": 0, "rpc_url": [f"http://{ADDRESS}:15370"]}],
                        "realm_configs": [{"id": i, "rpc_url": [f"http://{ADDRESS}:{15380+i}"]} for i in (0, 1)],
                        "prove_proxy_url": ["http://127.0.0.1:19999"], "system_prove_proxy_url": [f"http://{ADDRESS}:19998"]}
        self.canonical = {"defaultNetwork": "testnet", "networks": {"testnet": self.network, "localhost": {"keep": True}}}
        self.rpc = copy.deepcopy(self.canonical)
        self.rpc["networks"]["testnet"]["coordinator_configs"][0]["rpc_url"] = [f"http://{OTHER}:15370"]
        canonical = self.input("canonical.json", self.canonical)
        binary = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00" + b"synthetic"
        build = {"source_commit": installer.g.RUNTIME_SOURCE, "network": "testnet",
                 "config_sha256": canonical["sha256"], "binaries": {"psy_relayer_cli": installer.g.digest(binary)}}
        self.spec = {"version": 3, "hostname": "relayer.example", "address": ADDRESS,
                     "guardian_history": copy.deepcopy(self.network["guardian_history"]),
                     "service_user": installer.USER, "memory_high_gib": 4, "memory_max_gib": 6,
                     "keystore_owner": "custodian", "build": self.input("build.json", build),
                     "binary": self.input("binary", binary), "canonical_config": canonical,
                     "rpc_config": self.input("rpc.json", self.rpc),
                     "wrapper": self.input("wrapper.py", (HERE / "relayer_exec.py").read_bytes()),
                     "l1_keystore": {"path": str(self.root / "unread-key"), "sha256": "a" * 64},
                     "password_credential": {"path": str(self.root / "unread-credential"), "sha256": "b" * 64},
                     "l1_documents": {}}
        patcher = patch.object(installer.g, "BUILD_HASH", self.spec["build"]["sha256"])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.spec_path = self.root / "spec.json"
        self.daemon = self.daemon_text()
        self.spec["daemon_config"] = self.input("daemon.toml", self.daemon.encode())

    def input(self, name, value):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return {"path": str(path), "sha256": installer.g.digest(raw)}

    def save(self):
        return self.input("spec.json", self.spec)["sha256"]

    def daemon_text(self):
        values = {"rpc_config": str(installer.RELEASE / "rpc.json"), "guardian_root": str(installer.STATE),
                  "proof_dir": str(installer.STATE / "proofs"), "services_url": f"http://{ADDRESS}:3000",
                  "withdraw_method_id": 3055054724, "max_concurrent_l2_batches": 1}
        text = "".join(f"{key} = {json.dumps(value)}\n" for key, value in values.items())
        for name, (index, _) in installer.g.CHAINS.items():
            row = {"family": "evm", "network_id": name, "deployments_network": name, "chain_index": index,
                   "rpc_urls": [f"http://{ADDRESS}:{18545+index}"],
                   "keystore_path": str(installer.RELEASE / "home/.psy/keystore/bridge-relayer.keystore.json"),
                   "password_env": installer.PASSWORD_ENV}
            text += "\n[[chains]]\n" + "".join(f"{key} = {json.dumps(value)}\n" for key, value in row.items())
        return text

    def documents(self):
        for name, (index, chain_id) in installer.g.CHAINS.items():
            addresses = {contract: "0x" + f"{index*10+n:040x}" for n, contract in enumerate(("Bridge", "StateManager", "Multicall3"), 1)}
            summary = {"network": name, "chainId": str(chain_id), "core": addresses, "contracts": addresses,
                       "protocol": {"chain": {"l1ChainIndex": index, "l1ChainId": chain_id,
                                               "defaultRpcUrl": f"https://{ADDRESS}:18545"}}}
            transaction = "0x" + f"{index+1:064x}"
            receipt = {"address": addresses["Bridge"], "transactionHash": transaction,
                       "receipt": {"blockNumber": 123, "status": 1, "transactionHash": transaction,
                                   "contractAddress": addresses["Bridge"]}}
            self.spec["l1_documents"][name] = {"summary": self.input(name + ".json", summary),
                                              "receipt": self.input(name + "-receipt.json", receipt)}

    def test_pending_plan_parses_toml_without_custody_or_host_access(self):
        with patch.object(installer, "host_checks") as host, patch.object(installer.g, "write") as write:
            result = installer.run("plan", self.spec_path, self.save())
        host.assert_not_called()
        write.assert_not_called()
        self.assertTrue(result["offline_config_validated"] and result["l1_documents_pending"])
        self.assertFalse(result["native_config_parse_verified"] or result["deployment_ready"] or result["started"] or result["enabled"])

    def test_offline_cli_plan_dispatch_and_structured_result(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["install_relayer.py", "plan", "--spec", str(self.spec_path),
                                       "--spec-sha256", self.save()]), patch.object(installer.os, "umask"), \
                contextlib.redirect_stdout(output):
            installer.main()
        self.assertTrue(json.loads(output.getvalue())["offline_config_validated"])

    def test_mode_authorization_and_pending_documents_fail_before_host_checks(self):
        for mode, apply in (("install", False), ("install", True), ("check-host", False), ("plan", True)):
            with self.subTest(mode=mode, apply=apply), patch.object(installer, "host_checks") as host:
                with self.assertRaises(ValueError):
                    installer.run(mode, self.spec_path, self.save(), apply)
                host.assert_not_called()

    def test_toml_rejects_private_keys_unknown_fields_duplicates_and_bad_types(self):
        for text in (self.daemon + '\nprivate_key = "synthetic"\n',
                     'private_key = "synthetic"\n' + self.daemon,
                     '[wallet]\nprivate_key = "synthetic"\n' + self.daemon,
                     self.daemon.replace('max_concurrent_l2_batches = 1', 'max_concurrent_l2_batches = 2'),
                     self.daemon.replace('max_concurrent_l2_batches = 1', 'max_concurrent_l2_batches = true'),
                     self.daemon.replace('withdraw_method_id = 3055054724', 'withdraw_method_id = 0'),
                     self.daemon.replace('withdraw_method_id = 3055054724', 'withdraw_method_id = 4294967296'),
                     'guardian_root = "old"\n' + self.daemon,
                     self.daemon.replace(str(installer.STATE), '/var/lib/old-relayer')):
            with self.subTest(text=text[:70]), self.assertRaises(ValueError):
                installer.validate_daemon(text.encode())

    def test_toml_requires_private_services_and_rpc_origins_without_secrets(self):
        for endpoint in ('https://public.example:3000', f'http://user:secret@{ADDRESS}:3000',
                         f'http://{ADDRESS}:3000/?token=secret', f'http://{ADDRESS}:3000/secret', 'http://127.0.0.1:3000'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                installer.validate_daemon(self.daemon.replace(f'http://{ADDRESS}:3000', endpoint).encode())
        with self.assertRaises(ValueError):
            installer.validate_daemon(self.daemon.replace(f'http://{ADDRESS}:18545', 'https://rpc.example:443').encode())

    def test_chain_schema_rejects_wrong_identity_duplicate_and_credential_override(self):
        original = installer.validate_daemon(self.daemon.encode())["chains"][0]
        for field, value in (("chain_index", 1), ("chain_index", False), ("network_id", "mainnet"),
                             ("deployments_network", "old"), ("family", "other"), ("password_env", "WALLET_PASSWORD"),
                             ("keystore_path", "/old/key"), ("private_key", "synthetic"), ("bridge_address", "0x" + "1" * 40)):
            chain = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                installer.validate_chain(chain)
        with self.assertRaises(ValueError):
            installer.validate_daemon(self.daemon.replace('network_id = "baseSepolia"', 'network_id = "sepolia"').encode())

    def test_rpc_providers_and_bsc_fee_policy(self):
        chain = installer.validate_daemon(self.daemon.encode())["chains"][1]
        url = chain.pop("rpc_urls")[0]
        chain["rpc_providers"] = [{"name": "primary", "url": url, "priority_weight": 10, "operator": "self", "quota_group": "primary"}]
        chain["fee_policy"] = {"expected_chain_id": 97, "min_priority_fee_wei": 1,
                               "max_priority_fee_wei": 2, "max_fee_per_gas_wei": 3}
        installer.validate_chain(chain)
        for mutate in (lambda c: c.update(rpc_urls=[url]), lambda c: c["rpc_providers"][0].update(token="synthetic"),
                       lambda c: c["rpc_providers"][0].update(priority_weight=0),
                       lambda c: c["fee_policy"].update(expected_chain_id=56),
                       lambda c: c["fee_policy"].update(min_priority_fee_wei=4)):
            altered = copy.deepcopy(chain)
            mutate(altered)
            with self.assertRaises(ValueError):
                installer.validate_chain(altered)

    def test_canonical_membership_history_magic_and_other_network_preserved(self):
        for mutate in (lambda d: d["networks"]["testnet"].update(membership=[]),
                       lambda d: d["networks"]["testnet"]["guardian_history"].update(listen_address=f"{OTHER}:9700"),
                       lambda d: d["networks"]["testnet"].update(guardian_initial_member_hashes=["1"]*3),
                       lambda d: d["networks"]["testnet"].update(magic="0x1"),
                       lambda d: d["networks"]["localhost"].update(keep=False)):
            altered = copy.deepcopy(self.rpc)
            mutate(altered)
            with self.assertRaises(ValueError):
                installer.validate_rpc(self.canonical, altered, self.spec)
        self.spec["address"] = OTHER
        with self.assertRaisesRegex(ValueError, "history bind"):
            installer.load_plan(self.spec_path, self.save())

    def test_manifest_binary_launcher_and_artifact_pins(self):
        self.save()
        with self.assertRaises(ValueError):
            installer.load_plan(self.spec_path, "f" * 64)
        self.spec["wrapper"] = self.input("wrong-wrapper", b"unapproved")
        with self.assertRaisesRegex(ValueError, "sibling launcher"):
            installer.load_plan(self.spec_path, self.save())
        self.spec["wrapper"] = self.input("wrapper.py", (HERE / "relayer_exec.py").read_bytes())
        Path(self.spec["binary"]["path"]).write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            installer.load_plan(self.spec_path, self.save())

    def test_absent_history_can_only_be_filled_from_approved_spec(self):
        for null in (False, True):
            canonical = copy.deepcopy(self.canonical)
            if null:
                canonical["networks"]["testnet"]["guardian_history"] = None
            else:
                del canonical["networks"]["testnet"]["guardian_history"]
            self.assertEqual(installer.validate_rpc(canonical, self.rpc, self.spec), 9700)
            for mutate in (lambda d: d["networks"]["testnet"]["guardian_history"].update(rpc_url=f"http://{OTHER}:9700"),
                           lambda d: d["networks"]["testnet"].update(guardian_initial_member_hashes=["1"]*3)):
                changed = copy.deepcopy(self.rpc)
                mutate(changed)
                with self.assertRaises(ValueError):
                    installer.validate_rpc(canonical, changed, self.spec)
        self.spec["version"] = 1
        with self.assertRaises(ValueError):
            installer.load_plan(self.spec_path, self.save())
        self.spec["version"] = 3
        del self.spec["guardian_history"]
        with self.assertRaises(ValueError):
            installer.load_plan(self.spec_path, self.save())

    def test_guardian_l1_transport_matches_native_validation(self):
        for origin in (f"https://{ADDRESS}:18545", "http://127.0.0.1:18545"):
            installer.validate_guardian_rpc(origin)
        for origin in (f"http://{ADDRESS}:18545", "https://public.example:443", "http://0.0.0.0:18545",
                       "http://user:secret@127.0.0.1:18545", "http://127.0.0.1:18545/?token=secret"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                installer.validate_guardian_rpc(origin)
        canonical = copy.deepcopy(self.canonical)
        canonical["networks"]["testnet"]["guardian_configs"][0]["rpc_url"] = f"https://{ADDRESS}:9701"
        with self.assertRaisesRegex(ValueError, "origins must use HTTP"):
            installer.validate_rpc(canonical, canonical, self.spec)

    def test_user_proxy_transport_and_system_private_or_loopback(self):
        for origin in (f"https://{ADDRESS}:19999", "http://127.0.0.1:19999"):
            rpc = copy.deepcopy(self.rpc)
            rpc["networks"]["testnet"]["prove_proxy_url"] = [origin]
            rpc["networks"]["testnet"]["system_prove_proxy_url"] = ["http://127.0.0.1:19998"]
            installer.validate_rpc(self.canonical, rpc, self.spec)
        for origin in (f"http://{ADDRESS}:19999", "https://public.example:443", "http://127.0.0.1:19999/?secret=x"):
            rpc = copy.deepcopy(self.rpc)
            rpc["networks"]["testnet"]["prove_proxy_url"] = [origin]
            with self.assertRaises(ValueError):
                installer.validate_rpc(self.canonical, rpc, self.spec)

    def test_operator_permissions_root_identity_and_unsafe_paths(self):
        sha = self.save()
        self.spec_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private file"):
            installer.load_plan(self.spec_path, sha)
        self.spec["service_user"] = "root"
        with self.assertRaisesRegex(ValueError, "non-root"):
            installer.load_plan(self.spec_path, self.save())
        self.spec["service_user"] = installer.USER
        self.spec["password_credential"]["path"] = "/tmp/../key"
        with self.assertRaises(ValueError):
            installer.load_plan(self.spec_path, self.save())

    def test_l1_documents_complete_and_consistent(self):
        self.documents()
        _, files, _ = installer.load_plan(self.spec_path, self.save())
        self.assertEqual(len([name for name in files if name.startswith("deployments/")]), 6)
        del self.spec["l1_documents"]["baseSepolia"]
        with self.assertRaises(ValueError):
            installer.load_plan(self.spec_path, self.save())

    def test_l1_receipt_must_show_success_and_matching_transaction(self):
        self.documents()
        fields = self.spec["l1_documents"]["sepolia"]
        original = json.loads(Path(fields["receipt"]["path"]).read_text())
        for mutate in (lambda d: d["receipt"].update(status=0), lambda d: d["receipt"].update(status=True),
                       lambda d: d["receipt"].update(transactionHash="0x" + "9"*64),
                       lambda d: d["receipt"].update(contractAddress="0x" + "9"*40),
                       lambda d: d["receipt"].update(blockNumber=0)):
            altered = copy.deepcopy(original)
            mutate(altered)
            fields["receipt"] = self.input("receipt-invalid.json", altered)
            with self.assertRaises(ValueError):
                installer.load_plan(self.spec_path, self.save())
    def test_l1_deployment_fields_reject_wrong_network_and_contracts(self):
        self.documents()
        fields = self.spec["l1_documents"]["sepolia"]
        doc = json.loads(Path(fields["summary"]["path"]).read_text())
        for mutate in (lambda d: d.update(chainId="1"), lambda d: d.update(network="old"),
                       lambda d: d["protocol"]["chain"].update(defaultRpcUrl="https://public.example"),
                       lambda d: d["protocol"]["chain"].update(defaultRpcUrl=f"http://{ADDRESS}:18545"),
                       lambda d: d.pop("contracts"), lambda d: d["contracts"].update(Extra=123),
                       lambda d: d["contracts"].update(StateManager="0x" + "9" * 40),
                       lambda d: (d["core"].pop("Multicall3"), d["contracts"].pop("Multicall3"))):
            altered = copy.deepcopy(doc)
            mutate(altered)
            fields["summary"] = self.input("bad-summary.json", altered)
            with self.assertRaises(ValueError):
                installer.load_plan(self.spec_path, self.save())
        self.documents()
        self.spec["l1_documents"]["sepolia"]["receipt"] = self.input("bad-receipt.json", {"address": "0x" + "f"*40, "receipt": {"blockNumber": 123}})
        with self.assertRaises(ValueError):
            installer.load_plan(self.spec_path, self.save())

    def test_install_frozen_bytes_private_state_preserves_custody_and_never_starts(self):
        self.documents()
        key = b'{"version":3,"crypto":{"ciphertext":"synthetic"}}'
        credential = b"synthetic-encrypted-credential"
        source_key = self.input("retained-key", key)
        source_credential = self.input("retained-credential", credential)
        self.spec.update(l1_keystore=source_key, password_credential=source_credential)
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        expected = Path(self.spec["binary"]["path"]).read_bytes()

        def checked(*args):
            Path(self.spec["binary"]["path"]).write_bytes(b"changed-after-plan")
            return account, key, credential

        old_unit = installer.UNITS / "psy-core-relayer.service"
        old_unit.write_bytes(b"retained old Relayer unit")
        with patch.object(installer, "host_checks", side_effect=checked), patch.object(installer.g.os, "fchown"), \
                patch.object(installer.g, "command") as command:
            result = installer.run("install", self.spec_path, self.save(), True)
        command.assert_called_once_with(["systemctl", "daemon-reload"])
        self.assertEqual((installer.RELEASE / "psy_relayer_cli").read_bytes(), expected)
        self.assertEqual(Path(source_key["path"]).read_bytes(), key)
        self.assertEqual(Path(source_credential["path"]).read_bytes(), credential)
        for path in (installer.STATE / "db", installer.STATE / "proofs", installer.CREDENTIALS, installer.RELEASE / "home/.psy/keystore"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in (installer.CREDENTIALS / "l1-password.cred", installer.RELEASE / "home/.psy/keystore/bridge-relayer.keystore.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse((installer.STATE / "db/relayer.redb").exists())
        self.assertFalse(result["started"] or result["enabled"])
        self.assertEqual(old_unit.read_bytes(), b"retained old Relayer unit")
        with patch.object(installer.g.os, "fchown"), self.assertRaises(FileExistsError):
            installer.g.write(installer.UNITS / installer.UNIT, b"replacement")

    def test_unit_has_no_secrets_and_scopes_credential_state_and_enable_target(self):
        unit = installer.unit(self.spec).decode()
        self.assertIn("User=psy-core-relayer\n", unit)
        self.assertIn("LoadCredentialEncrypted=psy-core-relayer-l1-password:", unit)
        self.assertIn(f"ReadWritePaths={installer.STATE}/db {installer.STATE}/proofs\n", unit)
        self.assertNotIn("Environment=", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertIn("StartLimitBurst=3", unit)
        self.assertNotIn("EnvironmentFile=", unit)
        self.assertNotIn("PRIVATE_KEY", unit)
        self.assertNotIn(installer.PASSWORD_ENV + "=", unit)

    def test_host_checks_actual_history_interface_and_port_before_custody(self):
        account = SimpleNamespace(pw_uid=4321, pw_gid=4321)

        def command(argv):
            if argv[:2] == ["ip", "-j"]:
                return json.dumps([{"addr_info": [{"local": ADDRESS}]}])
            if argv == ["systemctl", "--version"]:
                return "systemd 255"
            if argv[:2] == ["systemctl", "show"]:
                if argv[2] == "psy-core-relayer-r2.service":
                    return "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\n"
                return "LoadState=not-found\n"
            if argv[:2] == ["systemctl", "list-jobs"]:
                return ""
            if argv[0] == "ss":
                return f"LISTEN 0 128 {ADDRESS}:9700 0.0.0.0:*\n"
            raise AssertionError(argv)

        with patch.object(installer.os, "geteuid", return_value=0), \
                patch.object(installer.socket, "gethostname", return_value=self.spec["hostname"]), \
                patch.object(installer.pwd, "getpwnam", return_value=account), \
                patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=4321)), \
                patch.object(installer.g, "command", side_effect=command):
            with self.assertRaisesRegex(ValueError, "history port occupied"):
                installer.host_checks(self.spec, 9700)
            altered = {**self.spec, "address": OTHER}
            with self.assertRaisesRegex(ValueError, "address not assigned"):
                installer.host_checks(altered, 9700)

    def test_offline_cli_suppresses_unapproved_spec_diagnostics(self):
        self.spec["daemon_config"] = self.input("daemon.toml", b'private_key = "DO_NOT_PRINT_SECRET"\n')
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "install_relayer.py"), "plan",
                                 "--spec", str(self.spec_path), "--spec-sha256", self.save()],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DO_NOT_PRINT_SECRET", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_host_custody_pins_permissions_and_no_overwrite(self):
        self.documents()
        key = b'{"version":3,"crypto":{"ciphertext":"synthetic"}}'
        credential = b"synthetic-encrypted-password"
        self.spec["l1_keystore"] = self.input("retained-key", key)
        self.spec["password_credential"] = self.input("retained-password", credential)
        service = SimpleNamespace(pw_uid=4321, pw_gid=4321)
        custody = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        read = installer.g.read
        host_state = {"unit": "LoadState=not-found\n\n", "jobs": ""}
        overrides = {}

        def root_read(path, private=False, uid=None, limit=8*1024*1024):
            return read(path, private=private, uid=os.getuid() if uid == 0 else uid, limit=limit)

        def command(argv):
            if argv[:2] == ["ip", "-j"]:
                return json.dumps([{"addr_info": [{"local": ADDRESS}]}])
            if argv == ["systemctl", "--version"]:
                return "systemd 255"
            if argv[:2] == ["systemctl", "show"]:
                if argv[2] in overrides:
                    return overrides[argv[2]]
                if argv[2] == "psy-core-relayer-r2.service" and host_state["unit"].strip() == "LoadState=not-found":
                    return "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\n"
                return host_state["unit"]
            if argv[:2] == ["systemctl", "list-jobs"]:
                return host_state["jobs"]
            if argv[0] == "ss":
                return ""
            if argv == ["systemd-analyze", "unit-paths"]:
                return str(installer.UNITS) + "\n"
            raise AssertionError(argv)

        with patch.object(installer.os, "geteuid", return_value=0), \
                patch.object(installer.socket, "gethostname", return_value=self.spec["hostname"]), \
                patch.object(installer.pwd, "getpwnam", side_effect=lambda name: service if name == installer.USER else custody), \
                patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=4321)), \
                patch.object(installer.g, "command", side_effect=command), \
                patch.object(installer.g, "trusted_directory"), patch.object(installer.g, "read", side_effect=root_read):
            self.root.chmod(0o755)
            actual, actual_key, actual_credential = installer.host_checks(self.spec, 9700)
            self.assertEqual((actual, actual_key, actual_credential), (service, key, credential))
            credential_parent = self.root / "root-only-credentials"
            credential_parent.mkdir(mode=0o700)
            with patch.object(installer, "CREDENTIALS", credential_parent / "fresh"):
                self.assertEqual(installer.host_checks(self.spec, 9700)[2], credential)
            self.root.chmod(0o700)
            with self.assertRaisesRegex(ValueError, "service ancestor blocks traversal"):
                installer.host_checks(self.spec, 9700)
            self.root.chmod(0o755)
            good = "LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\n"
            for name in ("psy-core-relayer.service", "psy-core-relayer-r2.service", installer.UNIT):
                overrides[name] = good.replace("inactive", "active")
                with self.subTest(unit=name), self.assertRaisesRegex(ValueError, "unit active or enabled"):
                    installer.host_checks(self.spec, 9700)
                overrides.clear()
            for output in ("LoadState=not-found\n", good.replace("disabled", "static"),
                           good.replace("disabled", "enabled"), good.replace("MainPID=0", "MainPID=42")):
                overrides["psy-core-relayer-r2.service"] = output
                with self.subTest(r2=output), self.assertRaisesRegex(ValueError, "unit active or enabled"):
                    installer.host_checks(self.spec, 9700)
            overrides.clear()
            for active, enabled in (("active", "disabled"), ("inactive", "enabled"), ("inactive", "masked"), ("inactive", "static")):
                host_state["unit"] = f"LoadState=loaded\nActiveState={active}\nUnitFileState={enabled}\nMainPID=0\n"
                with self.assertRaisesRegex(ValueError, "unit active or enabled"):
                    installer.host_checks(self.spec, 9700)
            host_state["unit"] = "LoadState=not-found\n"
            host_state["jobs"] = "42 parth-bridge-relayer.service start waiting\n"
            with self.assertRaisesRegex(ValueError, "job queued"):
                installer.host_checks(self.spec, 9700)
            host_state["jobs"] = ""
            installer.STATE.mkdir()
            with self.assertRaisesRegex(ValueError, "destination exists"):
                installer.host_checks(self.spec, 9700)
            installer.STATE.rmdir()
            dropin = installer.UNITS / "psy-.service.d"
            dropin.mkdir()
            with self.assertRaisesRegex(ValueError, "inherited drop-in"):
                installer.host_checks(self.spec, 9700)
            dropin.rmdir()
            key_path = Path(self.spec["l1_keystore"]["path"])
            key_path.chmod(0o640)
            self.assertEqual(installer.host_checks(self.spec, 9700)[1], key)
            custody.pw_uid = os.getuid() + 1
            with self.assertRaisesRegex(ValueError, "owner/mode"):
                installer.host_checks(self.spec, 9700)
            custody.pw_uid = os.getuid()
            key_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "owner/mode"):
                installer.host_checks(self.spec, 9700)
            key_path.chmod(0o600)
            self.spec["l1_keystore"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "keystore hash"):
                installer.host_checks(self.spec, 9700)
            self.spec["l1_keystore"]["sha256"] = installer.g.digest(key)
            bad_key = b'{"version":3,"crypto":{"ciphertext":"synthetic"},"private_key":"synthetic"}'
            key_path.write_bytes(bad_key)
            self.spec["l1_keystore"]["sha256"] = installer.g.digest(bad_key)
            with self.assertRaisesRegex(ValueError, "encrypted V3"):
                installer.host_checks(self.spec, 9700)
            key_path.write_bytes(key)
            self.spec["l1_keystore"]["sha256"] = installer.g.digest(key)
            self.spec["password_credential"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "credential hash"):
                installer.host_checks(self.spec, 9700)
            self.spec["password_credential"]["sha256"] = installer.g.digest(credential)
            Path(self.spec["password_credential"]["path"]).chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private file"):
                installer.host_checks(self.spec, 9700)

    def test_r3_paths_and_unfrozen_build_fail_closed(self):
        self.assertEqual(installer.UNIT, "psy-core-relayer-r3.service")
        actual = load("install_relayer")
        for path in (actual.RELEASE, actual.STATE, actual.CREDENTIALS):
            self.assertTrue(str(path).endswith("core-testnet-20261027-r3"))
        with patch.object(installer.g, "BUILD_HASH", None):
            with self.assertRaisesRegex(ValueError, "approved build manifest"):
                installer.load_plan(self.spec_path, self.save())

    def test_rejects_changed_helper_before_executing_it(self):
        script = self.root / "install_relayer.py"
        script.write_bytes((HERE / "install_relayer.py").read_bytes())
        (self.root / "install_guardian.py").write_text('raise RuntimeError("DO_NOT_EXECUTE")\n')
        result = subprocess.run([sys.executable, "-I", "-B", str(script), "--help"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sibling hash mismatch", result.stderr)
        self.assertNotIn("DO_NOT_EXECUTE", result.stdout + result.stderr)


class CredentialPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env_file = self.root / "retained.env"
        self.env_file.write_bytes(b"OTHER=unused\nWALLET_PASSWORD='synthetic $literal #value'\n")
        self.env_file.chmod(0o600)
        fstat = os.fstat

        def root_stat(fd):
            info = fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink, st_uid=0)

        patcher = patch.object(credential_helper.os, "fstat", side_effect=root_stat)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_literal_assignments_and_special_characters(self):
        for text, expected in (("'synthetic $literal #value'", b"synthetic $literal #value"),
                               ('"synthetic literal"', b"synthetic literal"),
                               ("'synthetic\u2028literal'", "synthetic\u2028literal".encode()),
                               ('synthetic_@%+=:.,/-', b'synthetic_@%+=:.,/-')):
            self.env_file.write_text("export WALLET_PASSWORD=" + text + "\n")
            self.assertEqual(credential_helper.password_from_env(self.env_file, "WALLET_PASSWORD"), expected)
        self.env_file.chmod(0o640)
        self.assertEqual(credential_helper.password_from_env(self.env_file, "WALLET_PASSWORD"), expected)

    def test_missing_duplicate_expansion_escape_and_invalid_values_rejected(self):
        for text in ("OTHER=only\n", "WALLET_PASSWORD=a\nWALLET_PASSWORD=b\n",
                     'WALLET_PASSWORD=abc # ambiguous-comment\n',
                     'WALLET_PASSWORD="$OTHER"\n', 'WALLET_PASSWORD=$(id)\n',
                     'WALLET_PASSWORD="`id`"\n', 'WALLET_PASSWORD="a\\nb"\n',
                     "WALLET_PASSWORD=''\n", "WALLET_PASSWORD='a\0b'\n",
                     "WALLET_PASSWORD='\ufeffvalue'\n", "WALLET_PASSWORD='a\nb'\n",
                     "WALLET_PASSWORD=" + "a" * 4097 + "\n"):
            self.env_file.write_text(text)
            with self.subTest(length=len(text)), self.assertRaises(ValueError):
                credential_helper.password_from_env(self.env_file, "WALLET_PASSWORD")

    def test_source_permissions_links_and_owner_rejected(self):
        self.env_file.chmod(0o644)
        with self.assertRaises(ValueError):
            credential_helper.password_from_env(self.env_file, "WALLET_PASSWORD")
        self.env_file.chmod(0o600)
        with patch.object(credential_helper.os, "fstat", return_value=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600, st_uid=1234, st_nlink=1)), self.assertRaises(ValueError):
            credential_helper.password_from_env(self.env_file, "WALLET_PASSWORD")
        linked = self.root / "linked.env"
        linked.symlink_to(self.env_file)
        with self.assertRaises(OSError):
            credential_helper.password_from_env(linked, "WALLET_PASSWORD")
        linked.unlink()
        os.link(self.env_file, linked)
        with self.assertRaises(ValueError):
            credential_helper.password_from_env(self.env_file, "WALLET_PASSWORD")

    def test_encrypt_stdin_only_ciphertext_written_and_source_unchanged(self):
        host_key = self.root / "host-key"
        executable = self.root / "systemd-creds"
        output = self.root / "new-custody/password.cred"
        original = self.env_file.read_bytes()
        ciphertext = b"synthetic-ciphertext-only"
        path_stat = Path.stat
        key_mode = 0o400

        def file_info(path, **kwargs):
            if path == host_key:
                return SimpleNamespace(st_mode=stat.S_IFREG | key_mode, st_uid=0)
            if path == executable:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
            return path_stat(path, **kwargs)

        with patch.object(credential_helper, "HOST_KEY", host_key), \
                patch.object(credential_helper, "ENCRYPT", executable), \
                patch.object(Path, "stat", file_info), \
                patch.object(credential_helper.os, "geteuid", return_value=0), \
                patch.object(credential_helper.resource, "setrlimit"), \
                patch.object(credential_helper.r.g, "trusted_directory"), \
                patch.object(credential_helper.r.g.os, "fchown"), \
                patch.object(credential_helper.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=ciphertext, stderr=b"")) as encrypt:
            with self.assertRaisesRegex(ValueError, "--apply"):
                credential_helper.prepare(self.env_file, "WALLET_PASSWORD", output)
            encrypt.assert_not_called()
            result = credential_helper.prepare(self.env_file, "WALLET_PASSWORD", output, True)
            argv = encrypt.call_args.args[0]
            self.assertEqual(argv, [str(executable), "encrypt", "--with-key=host",
                                    "--name=psy-core-relayer-l1-password", "-", "-"])
            self.assertEqual(encrypt.call_args.kwargs["input"], b"synthetic $literal #value")
            self.assertNotIn("synthetic", " ".join(argv))
            self.assertEqual(output.read_bytes(), ciphertext)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o700)
            self.assertEqual(self.env_file.read_bytes(), original)
            self.assertEqual(result["credential_sha256"], installer.g.digest(ciphertext))
            self.assertNotIn("synthetic", json.dumps(result))
            self.assertFalse(result["source_modified"] or result["started"])
            with self.assertRaisesRegex(ValueError, "never overwrite"):
                credential_helper.prepare(self.env_file, "WALLET_PASSWORD", output, True)
            encrypt.assert_called_once()
            encrypt.return_value = SimpleNamespace(returncode=1, stdout=b"", stderr=b"DO_NOT_PRINT_SECRET")
            failed = self.root / "failed/password.cred"
            with self.assertRaisesRegex(ValueError, "encryption failed"):
                credential_helper.prepare(self.env_file, "WALLET_PASSWORD", failed, True)
            self.assertFalse(failed.parent.exists())
            key_mode = 0o600
            with self.assertRaisesRegex(ValueError, "encryption failed"):
                credential_helper.prepare(self.env_file, "WALLET_PASSWORD", failed, True)
            key_mode = 0o640
            with self.assertRaisesRegex(ValueError, "existing root-owned systemd host key"):
                credential_helper.prepare(self.env_file, "WALLET_PASSWORD", failed, True)
            with patch.object(Path, "stat", side_effect=FileNotFoundError("host key absent")), self.assertRaises(OSError):
                credential_helper.prepare(self.env_file, "WALLET_PASSWORD", failed, True)

    def test_cli_withholds_secret_diagnostics(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["prepare_relayer_credential.py", "--env-file", str(self.env_file),
                                       "--output", str(self.root / "new.cred"), "--apply"]), \
                patch.object(credential_helper.os, "umask"), \
                patch.object(credential_helper, "prepare", side_effect=ValueError("DO_NOT_PRINT_SECRET")), \
                contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as error:
                credential_helper.main()
        self.assertNotIn("DO_NOT_PRINT_SECRET", str(error.exception) + output.getvalue())


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.credential = self.directory / "psy-core-relayer-l1-password"
        self.credential.write_bytes(b"synthetic-test-password")
        self.credential.chmod(0o400)
        self.directory.chmod(0o500)
        self.addCleanup(self.directory.chmod, 0o700)

    def invoke(self):
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.directory),
                                     "PRIVATE_KEY": "old-unused", "GUARDIAN_1_KEYSTORE_PASSWORD": "old-unused",
                                     "PSY_NETWORK": "localhost", "WALLET_PASSWORD": "old-unused"}, clear=True), \
                patch.object(sys, "argv", ["relayer_exec.py"]), patch.object(wrapper.resource, "setrlimit"), \
                patch.object(wrapper.os, "execve") as execute:
            wrapper.launch()
        return execute.call_args.args

    def test_password_only_in_exec_environment_and_no_inherited_secrets(self):
        executable, argv, environment = self.invoke()
        self.assertTrue(executable.endswith("/psy_relayer_cli"))
        self.assertEqual(argv[1], "--config")
        self.assertEqual(argv.count("--l1-config"), 3)
        self.assertNotIn("synthetic-test-password", " ".join(argv))
        self.assertEqual(environment["PSY_CORE_RELAYER_L1_PASSWORD"], "synthetic-test-password")
        self.assertEqual(environment["PSY_NETWORK"], "testnet")
        self.assertFalse({"PRIVATE_KEY", "WALLET_PASSWORD", "GUARDIAN_1_KEYSTORE_PASSWORD"} & set(environment))
        self.assertTrue(environment["PSY_DEPLOYMENTS_DIR"].endswith("/deployments"))

    def test_rejects_empty_oversized_newline_bom_and_invalid_utf8_credentials(self):
        for raw in (b"", b"x"*4097, b"secret\n", b"secret\r", b"secret\0", b"\xef\xbb\xbfsecret", b"\xff"):
            self.credential.chmod(0o600)
            self.credential.write_bytes(raw)
            self.credential.chmod(0o400)
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                self.invoke()

    def test_rejects_world_readable_and_symlink_credentials(self):
        self.credential.chmod(0o644)
        with self.assertRaises(ValueError):
            self.invoke()
        self.directory.chmod(0o700)
        self.credential.unlink()
        self.credential.symlink_to(self.directory / "other")
        self.directory.chmod(0o500)
        with self.assertRaises(OSError):
            self.invoke()

    @staticmethod
    def credential_acl(permissions, uid=999):
        entries = [(1, permissions, 0xffffffff), (2, permissions, uid), (4, 0, 0xffffffff),
                   (16, permissions, 0xffffffff), (32, 0, 0xffffffff)]
        return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *row) for row in entries)

    def invoke_root_acl(self, file_acl=None, directory_acl=None, file_mode=0o440, directory_mode=0o550,
                        file_uid=0, directory_uid=0, gid=0):
        fstat = os.fstat

        def info(fd):
            is_directory = stat.S_ISDIR(fstat(fd).st_mode)
            return SimpleNamespace(st_mode=(stat.S_IFDIR | directory_mode) if is_directory else (stat.S_IFREG | file_mode),
                                   st_uid=directory_uid if is_directory else file_uid, st_gid=gid)

        def access_acl(fd, name):
            self.assertEqual(name, "system.posix_acl_access")
            if stat.S_ISDIR(fstat(fd).st_mode):
                return self.credential_acl(5) if directory_acl is None else directory_acl
            return self.credential_acl(4) if file_acl is None else file_acl

        with patch.object(wrapper.os, "geteuid", return_value=999), patch.object(wrapper.os, "fstat", side_effect=info), \
                patch.object(wrapper.os, "getxattr", side_effect=access_acl):
            return self.invoke()

    def test_root_owned_systemd_named_user_acl_accepts_file_and_directory(self):
        _, argv, environment = self.invoke_root_acl()
        self.assertEqual(environment["PSY_CORE_RELAYER_L1_PASSWORD"], "synthetic-test-password")
        self.assertNotIn("synthetic-test-password", " ".join(argv))

    def test_root_acl_rejects_wrong_uid_extra_grants_missing_and_malformed_acl(self):
        for permissions, field in ((4, "file_acl"), (5, "directory_acl")):
            original = self.credential_acl(permissions)
            rows = [(1, permissions, 0xffffffff), (2, permissions, 999), (4, 0, 0xffffffff),
                    (16, permissions, 0xffffffff), (32, 0, 0xffffffff)]
            bad = [b"", original[:-1], struct.pack("<I", 3) + original[4:], self.credential_acl(permissions, 998)]
            for index, replacement in ((1, (2, 7, 999)), (2, (4, 4, 0xffffffff)),
                                       (3, (16, 7, 0xffffffff)), (4, (32, 4, 0xffffffff))):
                altered = rows.copy()
                altered[index] = replacement
                bad.append(struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *row) for row in altered))
            bad.append(original + struct.pack("<HHI", 2, permissions, 1001))
            for acl in bad:
                with self.subTest(field=field, size=len(acl)), self.assertRaises((ValueError, OSError)):
                    self.invoke_root_acl(**{field: acl})

    def test_root_acl_rejects_other_owners_groups_and_writable_modes(self):
        for field, values in (("file_mode", (0o640, 0o444, 0o660, 0o450)),
                              ("directory_mode", (0o750, 0o555, 0o770)),
                              ("file_uid", (998, 999)), ("directory_uid", (998, 999)), ("gid", (999,))):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.invoke_root_acl(**{field: value})

    def test_real_posix_acl_bytes_are_read_from_open_descriptors(self):
        os.setxattr(self.directory, "system.posix_acl_access", self.credential_acl(5))
        self.addCleanup(self.directory.chmod, 0o700)
        os.setxattr(self.credential, "system.posix_acl_access", self.credential_acl(4))
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o550)
        self.assertEqual(stat.S_IMODE(self.credential.stat().st_mode), 0o440)
        fstat = os.fstat

        def root_owner(fd):
            info = fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0)

        with patch.object(wrapper.os, "geteuid", return_value=999), \
                patch.object(wrapper.os, "fstat", side_effect=root_owner):
            self.assertEqual(self.invoke()[2]["PSY_CORE_RELAYER_L1_PASSWORD"], "synthetic-test-password")

    def test_missing_acl_and_unexpected_xattr_error_fail_closed(self):
        import errno
        for error in (errno.ENODATA, errno.EOPNOTSUPP, errno.EIO):
            root = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_uid=0, st_gid=0)
            with self.subTest(error=error), patch.object(wrapper.os, "geteuid", return_value=999), \
                    patch.object(wrapper.os, "fstat", return_value=root), \
                    patch.object(wrapper.os, "getxattr", side_effect=OSError(error, "xattr failed")), \
                    self.assertRaises((ValueError, OSError)):
                wrapper.check_credential_access(42)

    def test_service_owned_writable_permissions_and_extra_acl_rejected(self):
        self.credential.chmod(0o600)
        with self.assertRaises(ValueError):
            self.invoke()
        self.credential.chmod(0o400)
        self.directory.chmod(0o700)
        with self.assertRaises(ValueError):
            self.invoke()
        self.directory.chmod(0o500)
        with patch.object(wrapper.os, "getxattr", return_value=self.credential_acl(5)), \
                self.assertRaises(ValueError):
            self.invoke()


if __name__ == "__main__":
    unittest.main()
