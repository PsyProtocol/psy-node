import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_genesis_tools as tools
import build_runtime as runtime


class GenesisToolsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.dependencies = self.target / "release/deps"
        self.dependencies.mkdir(parents=True)
        self.log = self.root / "release-build.log"
        self.entries = []
        for name in sorted({name for names in tools.TOOLS.values() for name in names} | set(tools.STANDARD_LIBRARIES)):
            self.entries.append(self.artifact(name, "a", "3"))
        self.write_log()

    def artifact(self, name, suffix, level):
        path = self.dependencies / ("lib" + name + "-" + suffix + ".rlib")
        path.write_bytes(b"synthetic library")
        return {"reason": "compiler-artifact", "target": {"name": name, "kind": ["lib"]},
                "profile": {"opt_level": level, "test": False, "debug_assertions": False},
                "filenames": [str(path), str(path.with_suffix(".rmeta"))]}

    def write_log(self):
        self.log.write_text("a rendered diagnostic\n" + "\n".join(json.dumps(entry) for entry in self.entries) + "\n")

    def test_uses_only_recorded_release_libraries_not_host_or_cache_candidates(self):
        self.entries.append(self.artifact("serde_json", "b", "0"))
        (self.dependencies / "libserde_json-deadbeef.rlib").write_bytes(b"unrecorded stale library")
        self.write_log()
        selected = tools.dependencies(self.log, self.target)
        self.assertEqual(selected["serde_json"].name, "libserde_json-a.rlib")

    def test_missing_record_cannot_fall_back_to_existing_cache_file(self):
        self.entries = [entry for entry in self.entries if entry["target"]["name"] != "psy_config"]
        self.write_log()
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            tools.dependencies(self.log, self.target)

    def test_ambiguous_record_is_rejected(self):
        self.entries.append(self.artifact("psy_config", "b", "3"))
        self.write_log()
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            tools.dependencies(self.log, self.target)

    def test_recorded_rebuilt_standard_library_is_required(self):
        entry = next(entry for entry in self.entries if entry["target"]["name"] == "std")
        entry["target"]["kind"] = ["rlib"]
        self.write_log()
        self.assertEqual(tools.dependencies(self.log, self.target)["std"].name, "libstd-a.rlib")
        self.entries.remove(entry)
        self.write_log()
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            tools.dependencies(self.log, self.target)

    def test_library_outside_recorded_target_is_rejected(self):
        path = self.root / "libanyhow-b.rlib"
        path.write_bytes(b"outside target")
        self.entries[0]["filenames"] = [str(path)]
        self.write_log()
        with self.assertRaisesRegex(ValueError, "library path differs"):
            tools.dependencies(self.log, self.target)

    def test_debug_or_test_artifacts_do_not_satisfy_missing_release_input(self):
        for key, value in (("test", True), ("debug_assertions", True), ("opt_level", "2")):
            original = dict(self.entries[0]["profile"])
            self.entries[0]["profile"][key] = value
            self.write_log()
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                tools.dependencies(self.log, self.target)
            self.entries[0]["profile"] = original

    def test_duplicate_json_fields_are_rejected(self):
        self.log.write_text('{"reason":"compiler-artifact","reason":"other"}\n')
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            tools.dependencies(self.log, self.target)

    def test_wrong_manifest_hash_rejects_before_docker_or_output(self):
        manifest = self.root / "manifest.json"
        manifest.write_text("{}")
        output = self.root / "tools"
        with patch.object(tools.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "manifest hash mismatch"):
                tools.build_tools(manifest, "0" * 64, output)
            run.assert_not_called()
        self.assertFalse(output.exists())

    def runtime_manifest(self):
        release = self.root / "runtime"
        release.mkdir()
        (release / self.log.name).write_bytes(self.log.read_bytes())
        config = self.root / "config.json"
        config.write_text("{}")
        binaries = {}
        for name in runtime.BINS:
            path = release / name
            path.write_bytes(b"synthetic binary")
            binaries[name] = runtime.digest(path)
        manifest = {"schema_version": 1, "build_spec_version": 2, "network": "testnet",
                    "network_magic": "0x1337CF514544CF69", "checkpoints_per_epoch": 32,
                    "source_clean_before_and_after_build": True, "verification": {"cli_help_passed": 5},
                    "source_commit": "a" * 40, "config_sha256": runtime.digest(config),
                    "builder_image": "sha256:" + "c" * 64, "rust_toolchain": "nightly-2025-09-20",
                    "inputs": {"config": {"path": str(config), "sha256": runtime.digest(config)}},
                    "binaries": binaries, "logs": {self.log.name: runtime.digest(self.log)},
                    "environment": {"CARGO_TARGET_DIR": str(self.target)},
                    "release_libraries": {str(path): runtime.digest(path) for path in
                                          tools.dependencies(self.log, self.target).values()}}
        path = release / "manifest.json"
        path.write_text(json.dumps(manifest))
        return path, manifest

    def test_changed_library_at_same_recorded_path_is_rejected(self):
        path, _ = self.runtime_manifest()
        library = tools.dependencies(self.log, self.target)["psy_config"]
        library.write_bytes(b"a different build at exactly the same filename")
        with self.assertRaisesRegex(ValueError, "library differs from runtime build"):
            tools.load(path, runtime.digest(path))

    def test_missing_producer_library_receipt_is_not_reconstructed_from_cache(self):
        path, manifest = self.runtime_manifest()
        del manifest["release_libraries"]
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "runtime build lacks library hashes"):
            tools.load(path, runtime.digest(path))

    def test_nonregular_cache_lock_rejects_before_docker_or_output(self):
        path, manifest = self.runtime_manifest()
        for key, name in (("CARGO_HOME", "cargo"), ("GOPATH", "go"), ("GOCACHE", "go-build")):
            cache = self.root / name
            cache.mkdir()
            manifest["environment"][key] = str(cache)
        path.write_text(json.dumps(manifest))
        os.mkfifo(Path(manifest["environment"]["CARGO_HOME"]) / runtime.LOCK_NAME)
        output = self.root / "tools"
        with patch.object(tools.subprocess, "run") as run, patch.object(runtime, "check_cache_writers"):
            with self.assertRaisesRegex(ValueError, "cache lock is not regular"):
                tools.build_tools(path, runtime.digest(path), output)
            run.assert_not_called()
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
