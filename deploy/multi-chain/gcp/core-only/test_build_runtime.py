#!/usr/bin/env python3
"""Synthetic inputs and mock Docker only; never compile or contact a daemon."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_runtime as build


class RuntimeBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.git_dir = self.root / "git-metadata"
        self.git_dir.mkdir()
        for name in build.SOURCE_FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture\n')
        (self.source / "rust-toolchain.toml").write_text('[toolchain]\nchannel="nightly-2025-09-20"\n')
        nested = self.source / "psy-genesis"
        nested.mkdir()
        self.genesis = self.root / "external-genesis"
        self.genesis.mkdir()
        (self.genesis / "config.json").write_text('{}')
        config = {"networks": {"testnet": {"magic": "0x1337CF514544CF69",
                                         "p2p": {"checkpoints_per_epoch": 10}}}}
        self.inputs = {}
        for name, data in (("config", json.dumps(config)), ("bundle", '[{"fixture":true}]')):
            path = self.root / "config.json" if name == "config" else self.genesis / "genesis_contracts.json"
            path.write_text(data)
            self.inputs[name] = {"path": str(path), "sha256": build.digest(path)}
        stamp = self.genesis / "stamp.json"
        stamp.write_text(json.dumps({"artifactSha256": self.inputs["bundle"]["sha256"],
                                     "artifactByteSize": Path(self.inputs["bundle"]["path"]).stat().st_size,
                                     "compilerRevision": "b" * 40}))
        self.inputs["bundle_stamp"] = {"path": str(stamp), "sha256": build.digest(stamp)}
        caches = {}
        for name in build.CACHE_NAMES:
            path = self.root / name
            path.mkdir()
            caches[name] = str(path)
        self.spec = {"schema_version": 1, "source": {"path": str(self.source), "commit": "a" * 40},
                     "inputs": self.inputs, "builder_image": "sha256:" + "c" * 64,
                     "caches": caches, "output": str(self.root / "release"), "jobs": 2}
        self.spec_path = self.root / "spec.json"
        self.save_spec()
        self.commands = []
        self.git_dirty = False
        self.glibc = "2.36"
        self.fail_help = False
        self.change_input = False
        self.fail_clean = False
        self.omit_library_records = False
        self.actual_commit = self.spec["source"]["commit"]

    def save_spec(self):
        self.spec_path.write_text(json.dumps(self.spec))

    def fake_command(self, argv, **kwargs):
        self.commands.append(argv)
        if kwargs.get("log"):
            with kwargs["log"].open("x") as stream:
                stream.write("mock command output\n")
        if argv[0] == "git":
            if "status" in argv:
                return " M changed.rs" if self.git_dirty else ""
            if "--git-common-dir" in argv or "--absolute-git-dir" in argv:
                return str(self.git_dir)
            if "HEAD^{tree}" in argv:
                return "d" * 40
            if "submodule" in argv:
                return ""
            return self.actual_commit
        if argv[:3] == ["docker", "image", "inspect"]:
            return self.spec["builder_image"] + " linux/amd64"
        if argv[:2] == ["docker", "run"]:
            if "cargo" in argv and "metadata" in argv:
                return json.dumps({"packages": [{"id": "node", "name": "psy_node_cli", "version": "0.1.0", "source": None},
                    {"id": "relayer", "name": "psy_relayer_cli", "version": "0.1.0", "source": None},
                    {"id": "external", "name": "local_dependency", "version": "0.2.0", "source": None},
                    {"id": "registry", "name": "registry_dependency", "version": "1.0.0", "source": "registry+fixture"}],
                    "workspace_members": ["node", "relayer"]})
            if "cargo" in argv and "clean" in argv and self.fail_clean:
                raise RuntimeError("mock workspace clean failed")
            if "cargo" in argv and "build" in argv:
                release = Path(self.spec["caches"]["target"]) / "release"
                release.mkdir()
                for binary in build.BINS:
                    (release / binary).write_bytes(b"\x7fELFsynthetic-" + binary.encode())
                if self.change_input:
                    Path(self.inputs["bundle"]["path"]).write_text("changed")
                dependencies = release / "deps"
                dependencies.mkdir()
                library = dependencies / "libfixture-a.rlib"
                library.write_bytes(b"synthetic library")
                if not self.omit_library_records:
                    kwargs["log"].write_text(json.dumps({"reason": "compiler-artifact",
                        "target": {"name": "fixture", "kind": ["lib"]},
                        "profile": {"test": False, "opt_level": "3", "debug_assertions": False},
                        "filenames": [str(library)]}) + "\n")
            if "objdump" in argv:
                return "0000 (GLIBC_" + self.glibc + ") fixture\n"
            if "--help" in argv and self.fail_help:
                raise RuntimeError("mock help failure")
            return "mock command passed\n"
        raise AssertionError("unexpected command: " + repr(argv))

    def run_build(self):
        with patch.object(build, "command", side_effect=self.fake_command), \
                patch.object(build, "check_cache_writers"):
            return build.build_runtime(self.spec_path)

    def test_complete_mock_build_records_only_build_acceptance(self):
        self.run_build()
        out = Path(self.spec["output"])
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertFalse(manifest["deployment_ready"])
        self.assertFalse(manifest["runtime_approved"])
        self.assertEqual(set(manifest["binaries"]), set(build.BINS))
        self.assertEqual(manifest["verification"]["cli_help_passed"], 5)
        self.assertEqual(manifest["verification"]["genesis_acceptance"], "pending")
        library = Path(self.spec["caches"]["target"]) / "release/deps/libfixture-a.rlib"
        self.assertEqual(manifest["release_libraries"], {str(library): build.digest(library)})
        self.assertEqual(manifest["config_sha256"], self.inputs["config"]["sha256"])
        self.assertEqual(manifest["genesis_contracts_sha256"], self.inputs["bundle"]["sha256"])
        for key, path in (
            ("local_circuits_sha256", "client_prover/psy_prover/src/wallet/local_circuits.json"),
            ("cached_circuit_library_sha256", "psy_plonky2_circuits/src/generated/cached_circuit_library.rs"),
            ("cached_common_data_sha256", "psy_plonky2_circuits/src/generated/cached_common_data.rs"),
        ):
            self.assertEqual(manifest[key], build.digest(self.source / path))
            self.assertEqual(manifest[key], manifest["source_files"][path])
        self.assertEqual(manifest["network_magic"], "0x1337CF514544CF69")
        self.assertEqual(manifest["external_genesis_directory"], str(self.genesis))
        self.assertNotIn("psy_genesis_commit", manifest)
        self.assertEqual(list((self.source / "psy-genesis").iterdir()), [])
        self.assertEqual((out.stat().st_mode & 0o777), 0o700)
        for binary, digest in manifest["binaries"].items():
            self.assertEqual(build.digest(out / binary), digest)
        runs = [c for c in self.commands if c[:2] == ["docker", "run"]]
        self.assertTrue(runs)
        for argv in runs:
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertEqual(argv[argv.index("--pull") + 1], "never")
            self.assertEqual(argv[argv.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
            mounts = [argv[i + 1] for i, x in enumerate(argv) if x == "--mount"]
            for path in (self.source, Path(self.inputs["config"]["path"]), self.genesis):
                self.assertTrue(any(f"src={path}," in m and m.endswith(",readonly") for m in mounts))
            genesis_mount = f"type=bind,src={self.genesis},dst=/psy-node/psy-genesis,readonly"
            config_mount = f"type=bind,src={self.inputs['config']['path']},dst=/psy-node/psy-genesis/config.json,readonly"
            self.assertLess(mounts.index(genesis_mount), mounts.index(config_mount))
            self.assertIn("PSY_CONFIG_PATH=/psy-node/psy-genesis/config.json", argv)
            self.assertIn(f"type=bind,src={self.git_dir},dst={self.git_dir},readonly", mounts)
            writable = [m for m in mounts if not m.endswith(",readonly")]
            self.assertEqual(len(writable), 4)
            self.assertNotIn("psy-services", " ".join(argv))
            self.assertNotIn("SSH_AUTH_SOCK", " ".join(argv))
        cargo = next(c for c in runs if "cargo" in c and "build" in c)
        self.assertIn("--offline", cargo)
        self.assertIn("--locked", cargo)
        self.assertIn("--message-format=json-render-diagnostics", cargo)
        self.assertEqual(sum(x == "--bin" for x in cargo), 5)

    def test_reject_existing_output_without_running_docker(self):
        Path(self.spec["output"]).mkdir()
        with self.assertRaises(ValueError):
            self.run_build()
        self.assertFalse(self.commands)

    def test_workspace_outputs_are_cleaned_before_building_another_source(self):
        self.run_build()
        runs = [argv for argv in self.commands if argv[:2] == ["docker", "run"]]
        clean = next((i for i, argv in enumerate(runs) if "cargo" in argv and "clean" in argv), None)
        compile_index = next(i for i, argv in enumerate(runs) if "cargo" in argv and "build" in argv)
        self.assertIsNotNone(clean, "same /psy-node mount can reuse stale workspace objects from another worktree")
        self.assertLess(clean, compile_index)
        self.assertIn("psy_node_cli@0.1.0", runs[clean])
        self.assertIn("psy_relayer_cli@0.1.0", runs[clean])

    def test_clean_includes_local_path_dependencies_outside_workspace(self):
        self.run_build()
        clean = next(argv for argv in self.commands if "cargo" in argv and "clean" in argv)
        self.assertIn("local_dependency@0.2.0", clean)
        self.assertNotIn("registry_dependency@1.0.0", clean)
        self.assertIn("--offline", clean)
        self.assertIn("--locked", clean)
        metadata = next(argv for argv in self.commands if "cargo" in argv and "metadata" in argv)
        self.assertNotIn("--no-deps", metadata)
        self.assertIn("--offline", metadata)
        self.assertIn("--locked", metadata)

    def test_clean_failure_never_builds_or_publishes_manifest(self):
        self.fail_clean = True
        with self.assertRaisesRegex(RuntimeError, "workspace clean"):
            self.run_build()
        self.assertFalse(any("cargo" in argv and "build" in argv for argv in self.commands))
        self.assertFalse((Path(self.spec["output"])/"manifest.json").exists())

    def test_bad_pin_or_unknown_spec_field_rejected(self):
        for change in ("sha", "image", "extra", "network"):
            with self.subTest(change=change):
                spec = copy.deepcopy(self.spec)
                if change == "sha": spec["inputs"]["config"]["sha256"] = "0" * 64
                if change == "image": spec["builder_image"] = "builder:latest"
                if change == "extra": spec["command"] = ["unexpected"]
                if change == "network": spec["network"] = "localhost"
                self.spec_path.write_text(json.dumps(spec))
                with self.assertRaises(ValueError):
                    self.run_build()
        self.assertFalse(self.commands)

    def test_dirty_source_rejected_before_output(self):
        self.git_dirty = True
        with self.assertRaises(ValueError):
            self.run_build()
        self.assertFalse(Path(self.spec["output"]).exists())

    def test_fresh_build_binds_epoch_source_and_config_to_release_profile(self):
        config_path = Path(self.inputs["config"]["path"])
        config = json.loads(config_path.read_text())
        config["defaultNetwork"] = "testnet"
        config["networks"]["testnet"]["p2p"]["checkpoints_per_epoch"] = 32
        config_path.write_text(json.dumps(config))
        self.inputs["config"]["sha256"] = build.digest(config_path)
        profile = {"network": "testnet", "runtime_candidate_commit": self.actual_commit,
                   "runtime_inputs_frozen": True,
                   "network_magic": "0x1337CF514544CF69", "checkpoints_per_epoch": 32,
                   "proving_backend": "plonky2-poseidon-goldilocks",
                   "runtime_config_sha256": self.inputs["config"]["sha256"]}
        profile_path = self.root / "release-profile.json"
        profile_path.write_text(json.dumps(profile))
        self.spec["schema_version"] = 2
        self.inputs["release_profile"] = {"path": str(profile_path), "sha256": build.digest(profile_path)}
        self.save_spec()
        build.load_spec(self.spec_path)
        for field, wrong in (("checkpoints_per_epoch", 10), ("runtime_candidate_commit", "f" * 40),
                             ("runtime_config_sha256", "0" * 64), ("proving_backend", "jtmb"),
                             ("runtime_inputs_frozen", False)):
            broken = {**profile, field: wrong}
            profile_path.write_text(json.dumps(broken))
            self.inputs["release_profile"]["sha256"] = build.digest(profile_path)
            self.save_spec()
            with self.subTest(field=field), self.assertRaises(ValueError):
                build.load_spec(self.spec_path)

    def test_wrong_source_commit_rejected(self):
        self.actual_commit = "f" * 40
        with self.assertRaisesRegex(ValueError, "source commit"):
            self.run_build()
        self.assertFalse(Path(self.spec["output"]).exists())

    def test_wrong_network_or_stamp_binding_rejected(self):
        for name in ("config", "bundle_stamp"):
            path = Path(self.inputs[name]["path"])
            original = path.read_bytes()
            value = json.loads(original)
            if name == "config": value["networks"]["testnet"]["magic"] = "0x1"
            else: value["artifactSha256"] = "0" * 64
            path.write_text(json.dumps(value))
            self.inputs[name]["sha256"] = build.digest(path)
            self.save_spec()
            with self.assertRaises(ValueError): self.run_build()
            path.write_bytes(original)
            self.inputs[name]["sha256"] = build.digest(path)
        self.assertFalse(self.commands)

    def test_external_genesis_needs_existing_config_mount_target(self):
        (self.genesis / "config.json").unlink()
        with self.assertRaises(OSError): self.run_build()
        self.assertFalse(self.commands)

    def test_duplicate_json_fields_rejected(self):
        self.spec_path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_build()

    def test_symlink_and_cache_overlap_rejected(self):
        link = self.root / "linked"
        link.symlink_to(self.source, target_is_directory=True)
        self.spec["source"]["path"] = str(link)
        self.save_spec()
        with self.assertRaises(ValueError): self.run_build()
        self.spec["source"]["path"] = str(self.source)
        self.spec["caches"]["target"] = str(self.source)
        self.save_spec()
        with self.assertRaises(ValueError): self.run_build()

    def test_input_changed_during_build_keeps_failure_without_manifest(self):
        self.change_input = True
        with self.assertRaises(ValueError): self.run_build()
        self.assertTrue((Path(self.spec["output"]) / "release-build.log").exists())
        self.assertFalse((Path(self.spec["output"]) / "manifest.json").exists())

    def test_missing_release_library_records_never_publish_manifest(self):
        self.omit_library_records = True
        with self.assertRaisesRegex(ValueError, "no release library artifacts"):
            self.run_build()
        self.assertFalse((Path(self.spec["output"]) / "manifest.json").exists())

    def test_glibc_and_help_failure_never_publish_manifest(self):
        for failure in ("glibc", "help"):
            with self.subTest(failure=failure):
                self.spec["output"] = str(self.root / ("release-" + failure))
                self.spec["caches"]["target"] = str(self.root / ("target-" + failure))
                Path(self.spec["caches"]["target"]).mkdir()
                self.save_spec()
                self.glibc = "2.37" if failure == "glibc" else "2.36"
                self.fail_help = failure == "help"
                with self.assertRaises((ValueError, RuntimeError)): self.run_build()
                self.assertFalse((Path(self.spec["output"]) / "manifest.json").exists())

    def test_cache_lock_conflict(self):
        import fcntl
        path = Path(self.spec["caches"]["target"]) / build.LOCK_NAME
        with path.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): self.run_build()
        self.assertFalse(Path(self.spec["output"]).exists())

    def test_running_container_writable_overlap_rejected(self):
        responses = ["container-id", json.dumps([{"RW": True, "Source": str(self.root)}])]
        with patch.object(build, "check_process_writers"), patch.object(build, "command", side_effect=responses):
            with self.assertRaises(ValueError): build.check_cache_writers(self.spec)

    def test_running_container_readonly_overlap_permitted(self):
        responses = ["container-id", json.dumps([{"RW": False, "Source": str(self.root)}])]
        with patch.object(build, "check_process_writers"), patch.object(build, "command", side_effect=responses):
            build.check_cache_writers(self.spec)

    def test_glibc_missing_symbols_rejected(self):
        self.glibc = "unknown"
        with self.assertRaisesRegex(ValueError, "GLIBC"):
            self.run_build()
        self.assertFalse((Path(self.spec["output"]) / "manifest.json").exists())

    def test_shell_dispatch_precedes_legacy_source_requirements(self):
        entry = Path(__file__).resolve().parents[3] / "scripts/build-linux-artifacts-bookworm.sh"
        result = subprocess.run(["bash", str(entry), "--pinned-node-spec", str(self.root / "missing")],
                                env={**os.environ, "PARTH_DIR": str(self.root / "missing-source")},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pinned-node-build failed", result.stderr)
        self.assertNotIn("rust-toolchain.toml", result.stderr)


if __name__ == "__main__":
    unittest.main()
