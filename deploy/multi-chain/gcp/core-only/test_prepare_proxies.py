import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("prepare_proxies", Path(__file__).with_name("prepare_proxies.py"))
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
SOURCE = "5d38eefc07b0925ed9875b74805d9c3fea73d998"


class ProxyPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.network = {"defaultNetwork": "testnet", "networks": {"testnet": {
            "magic": p.MAGIC,
            "p2p": {"protocol": "retained-test-protocol"},
            "guardian_initial_member_hashes": ["public-1", "public-2", "public-3"],
            "coordinator_configs": [{"id": 0, "rpc_url": [f"http://192.0.2.25:{port}"
                                                        for port in (15370, 15371, 15372)]}],
            "realm_configs": [{"id": i, "rpc_url": [f"http://{host}:{port}" for port in ports]}
                              for i, host, ports in ((0, "192.0.2.36", (15380, 15381, 15382)),
                                                     (1, "192.0.2.35", (15383, 15384, 15385)))],
        }}}
        self.binary = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00" + b"test-only binary"
        (self.root / "psy_user_cli").write_bytes(self.binary)
        self.build = {"source_commit": SOURCE, "network": "testnet",
                      "config_sha256": p.digest(p.encode(self.network)),
                      "local_circuits_sha256": "1" * 64,
                      "binaries": {"psy_user_cli": p.digest(self.binary), "psy_relayer_cli": "3" * 64}}
        self.endpoints = {"coordinator": {"0": [f"http://198.51.100.1:{port}" for port in (15370, 15371, 15372)]},
            "realms": {str(i): [f"http://198.51.100.1:{port}" for port in ports]
                       for i, ports in ((0, (15380, 15381, 15382)), (1, (15383, 15384, 15385)))},
            "prove_proxy_url": ["http://198.51.100.12:9999"],
            "system_prove_proxy_url": ["http://198.51.100.13:9998"],
            "placement": {"system": {"host": "system.example", "listen_addr": "198.51.100.13:9998"},
                          "user": {"host": "user.example", "listen_addr": "198.51.100.12:9999"}}}
        provenance = {"source_commit": SOURCE, "config_sha256": self.build["config_sha256"],
                      "local_circuits_sha256": self.build["local_circuits_sha256"]}
        self.setup = {"version": 1, "network": "testnet", "magic": p.MAGIC,
                      "consumer": {**provenance, "binary_sha256": p.digest(self.binary)},
                      "generator": {**provenance, "binary_sha256": "3" * 64},
                      "verifier_solidity_sha256": {}, "files": {}}
        (self.root / "verifiers").mkdir()
        for cohort, name in p.VERIFIERS.items():
            path = self.root / "verifiers" / name
            path.write_bytes(("test-only verifier " + name).encode())
            self.setup["verifier_solidity_sha256"][cohort] = p.file_hash(path)["sha256"]
        for name in p.SETUP_NAMES:
            path = self.root / "setup" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("test-only setup " + name).encode())
            self.setup["files"][name] = p.file_hash(path)
        self.args = argparse.Namespace(role="user", source_commit=SOURCE, binary=self.root / "psy_user_cli",
            binary_manifest=self.root / "build.json", binary_manifest_sha256=None,
            network_config=self.root / "network.json", output=self.root / "package",
            rpc_endpoints=self.root / "rpc-endpoints.json", rpc_endpoints_sha256=None,
            memory_high_gib=None, memory_max_gib=None,
            setup_dir=None, verifier_dir=None, setup_manifest=None, setup_manifest_sha256=None)
        self.save_inputs()

    def save_inputs(self):
        (self.root / "network.json").write_bytes(p.encode(self.network))
        self.args.binary_manifest.write_bytes(p.encode(self.build))
        self.args.binary_manifest_sha256 = p.digest(p.encode(self.build))
        (self.root / "setup.json").write_bytes(p.encode(self.setup))
        self.args.rpc_endpoints.write_bytes(p.encode(self.endpoints))
        self.args.rpc_endpoints_sha256 = p.digest(p.encode(self.endpoints))
        if self.args.role == "system":
            self.args.setup_dir = self.root / "setup"
            self.args.verifier_dir = self.root / "verifiers"
            self.args.setup_manifest = self.root / "setup.json"
            self.args.setup_manifest_sha256 = p.digest(p.encode(self.setup))

    def package(self, role="user"):
        self.args.role = role
        self.save_inputs()
        return p.prepare_package(self.args)

    def test_user_package_and_exact_runtime_contract(self):
        report = self.package()
        role, files = p.read_package(self.args.output, report["package_sha256"])
        self.assertEqual(role, "user")
        self.assertFalse(report["claim_ready"])
        self.assertFalse(any("setup" in name or "keystore" in name or "verifiers" in name for name in files))
        unit = (self.args.output / p.unit_name(role)).read_text()
        self.assertIn("ConditionHost=user.example", unit)
        self.assertIn("/psy_user_cli prove-proxy --role user --listen-addr 198.51.100.12:9999", unit)
        self.assertIn("[Install]\nWantedBy=multi-user.target", unit)
        self.assertNotIn("EnvironmentFile", unit)
        self.assertNotIn("/opt/parth", unit)
        self.assertIn("MemoryHigh=40G\nMemoryMax=48G", unit)
        rpc = json.loads((self.args.output / "rpc.json").read_text())["networks"]["testnet"]
        self.assertEqual(rpc["system_prove_proxy_url"], ["http://198.51.100.13:9998"])
        self.assertEqual(rpc["prove_proxy_url"], ["http://198.51.100.12:9999"])
        self.assertEqual(rpc["coordinator_configs"][0]["rpc_url"], self.endpoints["coordinator"]["0"])
        for realm in rpc["realm_configs"]:
            self.assertEqual(realm["rpc_url"], self.endpoints["realms"][str(realm["id"])])
        original = self.network["networks"]["testnet"]
        self.assertEqual(rpc["p2p"], original["p2p"])
        self.assertEqual(rpc["guardian_initial_member_hashes"], original["guardian_initial_member_hashes"])
        self.assertEqual((self.args.output / "network.json").read_bytes(), p.encode(self.network))
        self.assertFalse(report["rpc_reachability_verified"])
        self.assertFalse(report["memory_fit_verified"])
        self.assertEqual(stat.S_IMODE(self.args.output.stat().st_mode), 0o700)

    def test_system_package_has_exactly_four_cohorts(self):
        report = self.package("system")
        role, files = p.read_package(self.args.output, report["package_sha256"])
        self.assertEqual(role, "system")
        self.assertEqual({name for name in files if name.startswith("keystore/")},
                         {"keystore/" + name for name in p.SETUP_NAMES})
        unit = p.proxy_unit(role, self.endpoints).decode()
        self.assertIn("ConditionHost=system.example", unit)
        self.assertIn("MemoryHigh=36G\nMemoryMax=44G", unit)
        self.assertIn("StartLimitBurst=3", unit)
        self.assertIn("--role system --listen-addr 198.51.100.13:9998", unit)
        self.assertIn("Environment=HOME=/opt/psy-core-prove-proxy/releases/" + p.RELEASE_ID + "-system/home", unit)

    def test_binary_build_and_network_mismatches_fail_before_output(self):
        for field, value in (("source_commit", "a" * 40), ("network", "localhost"),
                             ("config_sha256", "a" * 64), ("local_circuits_sha256", "unknown")):
            with self.subTest(field=field):
                original = copy.deepcopy(self.build)
                self.build[field] = value
                self.save_inputs()
                with self.assertRaises(p.ProxyError):
                    p.prepare_package(self.args)
                self.assertFalse(self.args.output.exists())
                self.build = original
        self.save_inputs()
        self.args.binary_manifest_sha256 = "2" * 64
        with self.assertRaises(p.ProxyError):
            p.prepare_package(self.args)

    def test_memory_overrides_are_pinned_and_cannot_exceed_host_caps(self):
        for high, maximum in ((0, 44), (44, 44), (40, 49), (True, 44), (20, -1)):
            with self.assertRaises(p.ProxyError):
                p.memory_limits("system", high, maximum)
        self.args.memory_high_gib = 24
        self.args.memory_max_gib = 32
        report = self.package()
        p.read_package(self.args.output, report["package_sha256"])
        self.assertIn("MemoryHigh=24G\nMemoryMax=32G", (self.args.output / p.unit_name("user")).read_text())

    def test_only_pinned_source_is_accepted_even_with_matching_manifest(self):
        for source in ("main", "dcc11465", "0" * 40, "a" * 40):
            self.args.source_commit = source
            with self.assertRaises(p.ProxyError):
                p.prepare_package(self.args)
            self.assertFalse(self.args.output.exists())
        self.build["source_commit"] = "a" * 40
        self.args.source_commit = "a" * 40
        with self.assertRaises(p.ProxyError):
            self.package()
        self.assertFalse(self.args.output.exists())

    def test_wrong_testnet_magic_and_realm_ids_rejected(self):
        for mutation in (lambda n: n.update(magic="0x1"),
                         lambda n: n["realm_configs"][0].update(id=99)):
            network = copy.deepcopy(self.network)
            mutation(network["networks"]["testnet"])
            with self.assertRaises(p.ProxyError):
                p.rpc_config(p.encode(network), self.endpoints)

    def test_endpoint_map_is_required_pinned_and_array_typed(self):
        for field in self.endpoints:
            endpoints = copy.deepcopy(self.endpoints)
            del endpoints[field]
            with self.assertRaises(p.ProxyError):
                p.rpc_config(p.encode(self.network), endpoints)
        for field in ("prove_proxy_url", "system_prove_proxy_url"):
            endpoints = copy.deepcopy(self.endpoints)
            endpoints[field] = "http://198.51.100.12:9999"
            with self.assertRaises(p.ProxyError):
                p.rpc_config(p.encode(self.network), endpoints)
        for urls in ([], ["http://198.51.100.1:15370"] * 3, ["http://user:secret@198.51.100.1:15370"]):
            endpoints = copy.deepcopy(self.endpoints)
            endpoints["coordinator"]["0"] = urls
            with self.assertRaises(p.ProxyError):
                p.rpc_config(p.encode(self.network), endpoints)
        self.args.rpc_endpoints_sha256 = "a" * 64
        with self.assertRaises(p.ProxyError):
            p.prepare_package(self.args)
        self.assertFalse(self.args.output.exists())

    def test_placement_is_complete_and_rejects_unit_injection(self):
        for placement in (None, {}, {"user": self.endpoints["placement"]["user"]}):
            endpoints = copy.deepcopy(self.endpoints)
            endpoints["placement"] = placement
            with self.assertRaises(p.ProxyError):
                p.validate_placement(endpoints)
        for field, value in (("host", ""), ("host", "*.example"), ("host", "%H"),
                             ("host", "user.example\nWants=other.service"), ("host", "-user.example"),
                             ("listen_addr", ""), ("listen_addr", "host.example:9999"),
                             ("listen_addr", "198.51.100.12:0"), ("listen_addr", "198.51.100.12:65536"),
                             ("listen_addr", "0.0.0.0:9999"), ("listen_addr", "[ff02::1]:9999"),
                             ("listen_addr", "198.51.100.12:9999 --role all")):
            endpoints = copy.deepcopy(self.endpoints)
            endpoints["placement"]["user"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                p.validate_placement(endpoints)
        endpoints = copy.deepcopy(self.endpoints)
        endpoints["placement"]["user"]["listen_addr"] = "[2001:db8::12]:29999"
        self.assertIn("--listen-addr [2001:db8::12]:29999", p.proxy_unit("user", endpoints).decode())

    def test_package_version_one_and_missing_placement_are_rejected(self):
        endpoints = self.endpoints.pop("placement")
        self.save_inputs()
        with self.assertRaises(p.ProxyError):
            p.prepare_package(self.args)
        self.assertFalse(self.args.output.exists())
        self.endpoints["placement"] = endpoints
        self.package()
        path = self.args.output / "package.json"
        approval = p.decode(path.read_bytes())
        self.assertEqual(approval["version"], 2)
        approval["version"] = 1
        raw = p.encode(approval)
        path.write_bytes(raw)
        with self.assertRaisesRegex(p.ProxyError, "package schema mismatch"):
            p.read_package(self.args.output, p.digest(raw))

    def test_placement_changes_are_pinned_and_drive_host_port_checks(self):
        self.endpoints["placement"]["user"] = {"host": "relocated.example", "listen_addr": "198.51.100.99:29999"}
        report = self.package()
        unit = (self.args.output / p.unit_name("user")).read_text()
        self.assertIn("ConditionHost=relocated.example", unit)
        self.assertIn("--listen-addr 198.51.100.99:29999", unit)
        with patch.object(p.socket, "gethostname", return_value="relocated.example"), \
                patch.object(p, "command", self.host_command):
            p.check_host("user", self.endpoints)
            with patch.object(p, "command", side_effect=lambda argv:
                              "LISTEN 0 4096 [2001:db8::1]:29999 [::]:*" if argv[0] == "ss" else self.host_command(argv)):
                with self.assertRaisesRegex(p.ProxyError, "port occupied"):
                    p.check_host("user", self.endpoints)
        self.endpoints["placement"]["user"]["host"] = "tampered.example"
        (self.args.output / "rpc-endpoints.json").write_bytes(p.encode(self.endpoints))
        with self.assertRaisesRegex(p.ProxyError, "RPC endpoint approval pin mismatch"):
            p.read_package(self.args.output, report["package_sha256"])

    def test_user_rejects_every_setup_input(self):
        for field, value in (("setup_dir", self.root / "setup"), ("verifier_dir", self.root / "verifiers"),
                             ("setup_manifest", self.root / "setup.json"),
                             ("setup_manifest_sha256", "a" * 64)):
            with self.subTest(field=field):
                args = copy.copy(self.args)
                setattr(args, field, value)
                with self.assertRaises(p.ProxyError):
                    p.prepare_package(args)

    def test_system_requires_setup_and_all_cohorts(self):
        self.args.role = "system"
        with self.assertRaises(p.ProxyError):
            p.prepare_package(self.args)
        for name in p.SETUP_NAMES:
            setup = copy.deepcopy(self.setup)
            del setup["files"][name]
            with self.subTest(name=name), self.assertRaises(p.ProxyError):
                p.validate_setup(setup, self.build)
        for cohort in p.COHORTS:
            setup = copy.deepcopy(self.setup)
            del setup["verifier_solidity_sha256"][cohort]
            with self.assertRaises(p.ProxyError):
                p.validate_setup(setup, self.build)

    def test_setup_binding_verifier_hashes_and_paths_fail_closed(self):
        for field in ("binary_sha256", "config_sha256", "local_circuits_sha256", "source_commit"):
            setup = copy.deepcopy(self.setup)
            setup["consumer"][field] = "a" * 64
            with self.subTest(field=field), self.assertRaises(p.ProxyError):
                p.validate_setup(setup, self.build)
        for sha256 in ("unknown", "0" * 64, True):
            setup = copy.deepcopy(self.setup)
            setup["verifier_solidity_sha256"]["bridge_agg"] = sha256
            with self.assertRaises(p.ProxyError):
                p.validate_setup(setup, self.build)
        setup = copy.deepcopy(self.setup)
        setup["files"]["../wallet.json"] = setup["files"].pop("circuit_groth16.bin")
        with self.assertRaises(p.ProxyError):
            p.validate_setup(setup, self.build)

    def test_distinct_generator_and_consumer_binaries_require_same_candidate(self):
        setup = copy.deepcopy(self.setup)
        p.validate_setup(setup, self.build)
        self.assertNotEqual(setup["generator"]["binary_sha256"],
                            setup["consumer"]["binary_sha256"])
        for field, value in (("binary_sha256", setup["consumer"]["binary_sha256"]),
                             ("source_commit", "b" * 40), ("config_sha256", "a" * 64),
                             ("local_circuits_sha256", "b" * 64)):
            broken = copy.deepcopy(setup)
            broken["generator"][field] = value
            with self.assertRaises(p.ProxyError):
                p.validate_setup(broken, self.build)
        build = copy.deepcopy(self.build)
        build["binaries"]["psy_relayer_cli"] = build["binaries"]["psy_user_cli"]
        setup["generator"]["binary_sha256"] = setup["consumer"]["binary_sha256"]
        with self.assertRaises(p.ProxyError):
            p.validate_setup(setup, build)

    def test_exported_verifier_hash_mismatch_rejected_before_output(self):
        self.args.role = "system"
        self.save_inputs()
        (self.args.verifier_dir / "RewardClaimVerifier.sol").write_text("wrong verifier")
        with self.assertRaises(p.ProxyError):
            p.prepare_package(self.args)
        self.assertFalse(self.args.output.exists())

    def test_setup_bytes_and_empty_file_rejected(self):
        self.args.role = "system"
        self.save_inputs()
        for raw in (b"", b"wrong setup"):
            (self.args.setup_dir / "pk_groth16.bin").write_bytes(raw)
            with self.assertRaises(p.ProxyError):
                p.prepare_package(self.args)
            self.assertFalse(self.args.output.exists())

    def test_secrets_and_duplicate_fields_rejected_without_echo(self):
        for key in ("private_key", "privateKey", "password", "mnemonic", "api_key", "authorization", "token", "seed"):
            with self.subTest(key=key), self.assertRaises(p.ProxyError):
                p.validate_public({"nested": [{key: "secret-test-sentinel"}]})
        for url in ("http://name:secret@host", "https://host/?token=secret", "https://host/#secret"):
            with self.assertRaises(p.ProxyError):
                p.validate_public({"rpc_url": url})
        with self.assertRaises(p.ProxyError):
            p.decode(b'{"role":"user","role":"system"}')
        self.network["networks"]["testnet"]["private_key"] = "secret-test-sentinel"
        self.build["config_sha256"] = p.digest(p.encode(self.network))
        self.save_inputs()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = p.main(["package", "--role", "user", "--source-commit", SOURCE, "--binary", str(self.args.binary),
                             "--binary-manifest", str(self.args.binary_manifest),
                             "--binary-manifest-sha256", self.args.binary_manifest_sha256,
                             "--rpc-endpoints", str(self.args.rpc_endpoints),
                             "--rpc-endpoints-sha256", self.args.rpc_endpoints_sha256,
                             "--network-config", str(self.args.network_config), "--output", str(self.args.output)])
        self.assertEqual(result, 1)
        self.assertNotIn("secret-test-sentinel", stderr.getvalue())

    def test_symlink_hardlink_parent_and_non_elf_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.args.binary)
        with self.assertRaises(OSError):
            p.file_hash(link)
        link.unlink()
        os.link(self.args.binary, link)
        with self.assertRaises(p.ProxyError):
            p.file_hash(link)
        link.unlink()
        link.symlink_to(self.root / "setup", target_is_directory=True)
        with self.assertRaises(OSError):
            p.file_hash(link / "pk_groth16.bin")
        self.args.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.build["binaries"]["psy_user_cli"] = p.file_hash(self.args.binary)["sha256"]
        self.save_inputs()
        with self.assertRaises(p.ProxyError):
            p.prepare_package(self.args)

    def test_tamper_extra_files_approval_and_existing_output_rejected(self):
        report = self.package()
        with self.assertRaises(p.ProxyError):
            p.read_package(self.args.output, "a" * 64)
        with self.assertRaises(p.ProxyError):
            p.prepare_package(self.args)
        extra = self.args.output / "wallet.json"
        extra.write_text("{}")
        with self.assertRaises(p.ProxyError):
            p.read_package(self.args.output, report["package_sha256"])
        extra.unlink()
        (self.args.output / "rpc.json").write_text("{}")
        with self.assertRaises(p.ProxyError):
            p.read_package(self.args.output, report["package_sha256"])

    def test_running_installer_must_match_package_approval(self):
        report = self.package()
        other_script = self.root / "other-installer.py"
        other_script.write_bytes(b"different reviewed revision")
        with patch.object(p, "__file__", str(other_script)), self.assertRaises(p.ProxyError):
            p.read_package(self.args.output, report["package_sha256"])

    def test_copy_does_not_overwrite_or_publish_changed_bytes(self):
        destination = self.root / "destination"
        destination.write_bytes(b"retained")
        with self.assertRaises(FileExistsError):
            p.write_new(destination, io.BytesIO(b"new"), p.digest(b"new"), 0o644)
        self.assertEqual(destination.read_bytes(), b"retained")
        with self.assertRaises(p.ProxyError):
            p.write_new(self.root / "new", io.BytesIO(b"changed"), p.digest(b"approved"), 0o644)
        self.assertFalse((self.root / "new").exists())
        self.assertFalse(list(self.root.glob(".proxy-*")))

    def test_created_directory_modes_ignore_restrictive_umask_without_changing_existing(self):
        previous = os.umask(0o077)
        try:
            release = self.root / "release"
            p.create_directory(release, 0o755, fresh=True)
            self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o755)
            release.chmod(0o700)
            p.create_directory(release, 0o755)
            self.assertEqual(stat.S_IMODE(release.stat().st_mode), 0o700)
            with self.assertRaises(p.ProxyError):
                p.create_directory(release, fresh=True)
        finally:
            os.umask(previous)

    def host_command(self, argv):
        if argv[:2] == ["systemctl", "show"]:
            return "LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nMainPID=0\n"
        return ""

    def test_wrong_host_active_enabled_jobs_and_ports_rejected(self):
        with patch.object(p.socket, "gethostname", return_value="user.example"), patch.object(p, "command", self.host_command):
            with self.assertRaises(p.ProxyError):
                p.check_host("system", self.endpoints)
            p.check_host("user", self.endpoints)
            for output in ("LoadState=loaded\nActiveState=active\nUnitFileState=disabled\nMainPID=1\n",
                           "LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled\nMainPID=0\n"):
                with patch.object(p, "command", return_value=output), self.assertRaises(p.ProxyError):
                    p.check_host("user", self.endpoints)
            for prefix, output in ((["systemctl", "list-jobs"], "1 parth-prove-proxy@system.service start waiting"),
                                   (["ss", "-H"], "LISTEN 0 4096 0.0.0.0:9998 0.0.0.0:*")):
                with patch.object(p, "command", side_effect=lambda argv: output if argv[:2] == prefix else self.host_command(argv)):
                    with self.assertRaises(p.ProxyError):
                        p.check_host("user", self.endpoints)

    def test_install_layout_modes_no_enable_start_and_preserve_old(self):
        report = self.package("system")
        old = self.root / "old-backup"
        old.write_bytes(b"old setup and state remain unchanged")
        unit_root = self.root / "units"
        unit_root.mkdir()
        with patch.multiple(p, RELEASE_ROOT=self.root / "release", CONFIG_ROOT=self.root / "config",
                            STATE_ROOT=self.root / "state", UNITS=unit_root), \
                patch.object(p, "check_host") as host, patch.object(p, "check_destinations"), \
                patch.object(p.os, "geteuid", return_value=0), patch.object(p, "command") as command:
            # Regenerate units for redirected test destinations; production verifies these exact bytes.
            unit_raw = p.proxy_unit("system", self.endpoints)
            (self.args.output / p.unit_name("system")).write_bytes(unit_raw)
            real_mkdir = p.create_directory
            def mkdir(path, mode=0o755, fresh=False):
                if path in self.root.parents or path == self.root:
                    return
                with patch.object(p.os, "geteuid", return_value=os.getuid()):
                    real_mkdir(path, mode, fresh)
            with patch.object(p, "create_directory", side_effect=mkdir):
                checked = p.install_proxy(self.args.output, report["package_sha256"], check_only=True)
                self.assertEqual(checked["mode"], "checked")
                self.assertFalse((self.root / "release").exists())
                installed = p.install_proxy(self.args.output, report["package_sha256"], check_only=False)
            release, config, state = p.paths("system")
            self.assertFalse(state.exists())
            self.assertIn("StateDirectory=psy-core-prove-proxy/" + state.name, unit_raw.decode())
            self.assertEqual((config / "network.json").read_bytes(), p.encode(self.network))
            for name in p.SETUP_NAMES:
                target = release / "home/.psy/keystore" / name
                self.assertEqual(p.file_hash(target), self.setup["files"][name])
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((release / "psy_user_cli").stat().st_mode), 0o755)
            self.assertEqual((unit_root / p.unit_name("system")).read_bytes(), unit_raw)
            command.assert_called_once_with(["systemctl", "daemon-reload"])
            self.assertEqual(host.call_count, 2)
            self.assertFalse(installed["started"])
            self.assertFalse(installed["enabled"])
        self.assertEqual(old.read_bytes(), b"old setup and state remain unchanged")

    def test_destination_and_generic_dropin_conflicts(self):
        with patch.object(p, "paths", return_value=(self.root / "existing", self.root / "c", self.root / "s")):
            (self.root / "existing").mkdir()
            with self.assertRaises(p.ProxyError):
                p.check_destinations("user")
        unit_root = self.root / "unit-search"
        unit_root.mkdir()
        (unit_root / "psy-core-.service.d").mkdir()
        with patch.object(p, "UNITS", unit_root), patch.object(p, "command", return_value=str(unit_root) + "\n"):
            with self.assertRaisesRegex(p.ProxyError, "inherited override"):
                p.check_destinations("user")

    def test_release_ancestor_must_allow_dynamic_user_traversal(self):
        locked = self.root / "locked"
        locked.mkdir(mode=0o750)
        units = self.root / "units"
        units.mkdir()
        fstat = os.fstat
        def root_stat(fd):
            return SimpleNamespace(st_uid=0, st_mode=fstat(fd).st_mode)
        with patch.object(p, "paths", return_value=(locked / "release", self.root / "config", self.root / "state")), \
                patch.object(p, "UNITS", units), patch.object(p, "command", return_value=str(units) + "\n"), \
                patch.object(p.os, "fstat", side_effect=root_stat):
            with self.assertRaisesRegex(p.ProxyError, "blocks service traversal"):
                p.check_destinations("user")


if __name__ == "__main__":
    unittest.main()
