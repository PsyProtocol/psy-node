import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import unittest.mock

import deploy_prepare_steps as steps
import release_lock
import test_release_lock
from deploy_remote import DeployContext, find_secret

GIB = 1024 ** 3
CHAINS = ("sepolia", "bscTestnet", "baseSepolia")
CLI_NAMES = ("psy_dev_cli", "psy_node_cli", "psy_relayer_cli", "psy_user_cli", "psy_worker_cli")
FILE_NAMES = ("config", "canonical_config", "genesis", "genesis_contracts", "compiler_stamp",
              "groth16_setup_manifest", "gnark_groth16_verifier", "deposit_batch_verifier",
              "withdrawal_claim_verifier", "psy_services", "psy_indexer", "l1_bundle_manifest", "l1_policy")


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def done(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class Workspace:
    """A synthetic release and private directory; the lock dict is edited in step with the files."""

    def __init__(self, root):
        self.root = Path(root)
        self.release_dir, self.private_dir = self.root / "release", self.root / "private"
        self.run_dir, self.state_dir = self.root / "run", self.private_dir / "state"
        for path in (self.release_dir, self.private_dir, self.run_dir):
            path.mkdir()
        self.state_dir.mkdir(mode=0o700)
        self.lock = test_release_lock.build_test_lock(self.release_dir, self.private_dir)
        self.tools_dir = self.root / "tools"
        self.tools_dir.mkdir()
        for name in release_lock.TOOL_NAMES:
            (self.tools_dir / name).write_text(f"# fixture {name}\n")
        self.lock["tool_sha256"] = {name: sha((self.tools_dir / name).read_bytes()) for name in release_lock.TOOL_NAMES}
        self.set_artifacts()
        (self.root / "notifier").mkdir()
        self.local = {"build": {}, "files": {}, "packages": {}, "notifier": {"checkout": str(self.root / "notifier")}}

    def context(self, remote=None):
        return DeployContext(lock=self.lock, lock_sha256="a" * 64, release_dir=self.release_dir, run_dir=self.run_dir,
                             remote=remote, private_dir=self.private_dir, state_dir=self.state_dir)

    def set_artifacts(self, **extra):
        path = self.release_dir / "artifacts.json"
        data = json.loads(path.read_text())
        data.update(extra)
        path.write_text(json.dumps(data))
        self.lock["inputs"]["artifacts"] = sha(path.read_bytes())

    def write_local(self):
        path = self.private_dir / "local-inputs.json"
        path.write_text(json.dumps(self.local))
        path.chmod(0o600)

    def put_file(self, name, content, *, pin, filename=None):
        path = self.root / "files" / (filename or name)
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
        self.local["files"][name] = str(path)
        pin(sha(content))
        return path

    def set_binaries(self, contents):
        hashes = {name: sha(data) for name, data in contents.items()}
        self.lock["binaries"].update(hashes)
        self.set_artifacts(binaries=hashes)
        return hashes


def run_all(step, ctx):
    step.check(ctx)
    step.apply(ctx)
    return step.verify(ctx)


class PrepareTestCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.ws = Workspace(temp.name)
        patcher = unittest.mock.patch.object(steps, "TOOLS_DIR", self.ws.tools_dir)
        patcher.start()
        self.addCleanup(patcher.stop)


class VerifyReleaseTests(PrepareTestCase):
    def setUp(self):
        super().setUp()
        self.ws.local["build"]["source"] = str(self.ws.root / "source")
        self.ws.local["files"]["config"] = str(self.ws.root / "config.json")
        self.ws.write_local()
        self.report = {"source_preflight_passed": True, "config_preflight_passed": True, "blockers": []}

    def run_step(self, returncode=0, report=None):
        output = json.dumps(self.report if report is None else report)
        with unittest.mock.patch.object(steps, "run_local", return_value=done(returncode, output)) as run:
            result = run_all(steps.PREPARE_STEPS["verify_release"], self.ws.context())
        return result, run

    def test_verify_release_runs_preflight_and_lock_check(self):
        result, run = self.run_step()
        argv = run.call_args.args[0]
        self.assertEqual(Path(argv[argv.index("--source") - 1]).name, "preflight.py")
        self.assertEqual(argv[argv.index("--source") + 1], str(self.ws.root / "source"))
        self.assertEqual(argv[argv.index("--config") + 1], str(self.ws.root / "config.json"))
        self.assertEqual(result["source_preflight_passed"], True)
        self.assertEqual(result["release_id"], self.ws.lock["release_id"])
        self.assertIsNone(find_secret(result))

    def test_incomplete_lock_fails_before_preflight(self):
        self.ws.lock["sources"]["services"] = ""
        with unittest.mock.patch.object(steps, "run_local") as run:
            with self.assertRaisesRegex(ValueError, "incomplete: sources.services"):
                steps.PREPARE_STEPS["verify_release"].check(self.ws.context())
        run.assert_not_called()

    def test_changed_tool_fails_the_lock_check(self):
        (self.ws.tools_dir / "fresh_l1.py").write_text("# edited\n")
        with self.assertRaisesRegex(ValueError, "tool hash differs: fresh_l1.py"):
            steps.PREPARE_STEPS["verify_release"].check(self.ws.context())

    def test_failed_preflight_fails_the_step(self):
        with self.assertRaisesRegex(RuntimeError, "preflight"):
            self.run_step(returncode=2, report={"blockers": ["source input failed validation"]})

    def test_preflight_report_without_both_passes_fails(self):
        with self.assertRaisesRegex(RuntimeError, "preflight"):
            self.run_step(report={"source_preflight_passed": True, "config_preflight_passed": False})

    def test_step_requires_a_complete_lock(self):
        step = steps.PREPARE_STEPS["verify_release"]
        self.assertTrue(step.requires_complete)
        self.assertFalse(step.cutover)


class RebuildBinariesTests(PrepareTestCase):
    CONTENTS = {name: f"ELF {name}".encode() for name in CLI_NAMES}

    def setUp(self):
        super().setUp()
        ws = self.ws
        self.hashes = ws.set_binaries(self.CONTENTS)
        ws.put_file("config", b"config", pin=lambda h: ws.lock["inputs"].update(runtime_config=h))
        ws.put_file("genesis_contracts", b"bundle", pin=lambda h: ws.set_artifacts(genesis_contracts_sha256=h))
        ws.put_file("compiler_stamp", b"stamp", pin=lambda h: ws.set_artifacts(compiler_stamp_sha256=h))
        self.caches = {name: ws.root / "cache" / name for name in ("cargo", "target", "go", "go_build")}
        for path in self.caches.values():
            path.mkdir(parents=True)
        self.out_root = ws.root / "builds"
        self.out_root.mkdir()
        ws.local["build"] = {"source": str(ws.root / "source"), "builder_image": "sha256:" + "b" * 64,
                             "caches": {name: str(path) for name, path in self.caches.items()},
                             "output_root": str(self.out_root), "jobs": 4}
        ws.write_local()
        patcher = unittest.mock.patch.object(steps, "disk_free", return_value=100 * GIB)
        self.disk = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(steps, "BUILD_SCRIPT", ws.root / "build.sh")
        patcher.start()
        self.addCleanup(patcher.stop)
        (ws.root / "build.sh").write_text("#!/bin/sh\n")

    def make_build(self, directory, *, contents=None, manifest_extra=None, with_manifest=True):
        directory.mkdir()
        contents = self.CONTENTS if contents is None else contents
        for name, data in contents.items():
            (directory / name).write_bytes(data)
        if with_manifest:
            manifest = {"binaries": {name: sha(data) for name, data in contents.items()},
                        "source_commit": self.ws.lock["sources"]["runtime"],
                        "config_sha256": self.ws.lock["inputs"]["runtime_config"],
                        "genesis_contracts_sha256": sha(b"bundle")}
            manifest.update(manifest_extra or {})
            (directory / "manifest.json").write_text(json.dumps(manifest))

    def fake_build(self, contents=None):
        def run(argv, timeout=None):
            spec = json.loads(Path(argv[-1]).read_text())
            self.make_build(Path(spec["output"]), contents=contents)
            return done(0, json.dumps({"manifest": "x"}))
        return run

    def build_dir(self, number=1):
        return self.out_root / f"{self.ws.lock['release_id']}-{self.ws.lock['sources']['runtime'][:12]}-build-{number}"

    def test_rebuild_calls_the_pinned_script_with_a_spec_under_the_private_dir(self):
        calls = []
        fake = self.fake_build()
        with unittest.mock.patch.object(steps, "run_local", side_effect=lambda argv, timeout=None: (calls.append(argv), fake(argv))[1]):
            result = run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())
        argv = calls[0]
        self.assertEqual(argv[:3], ["bash", str(self.ws.root / "build.sh"), "--pinned-node-spec"])
        spec_path = Path(argv[3])
        self.assertEqual(spec_path.parent, self.ws.private_dir)
        spec = json.loads(spec_path.read_text())
        self.assertEqual(set(spec), {"schema_version", "source", "inputs", "builder_image", "caches", "output", "jobs"})
        self.assertEqual(spec["schema_version"], 2)
        self.assertEqual(spec["source"], {"path": str(self.ws.root / "source"), "commit": self.ws.lock["sources"]["runtime"]})
        self.assertEqual(spec["inputs"]["release_profile"],
                         {"path": str(self.ws.release_dir / "release.json"), "sha256": self.ws.lock["inputs"]["release_profile"]})
        self.assertEqual(spec["inputs"]["config"]["sha256"], self.ws.lock["inputs"]["runtime_config"])
        self.assertEqual(spec["output"], str(self.build_dir()))
        self.assertEqual(spec_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["binaries"], self.hashes)
        self.assertIsNone(find_secret(result))

    def test_rebuild_binaries_rejects_hash_differing_from_artifacts(self):
        other = {**self.CONTENTS, "psy_node_cli": b"a different build"}
        with unittest.mock.patch.object(steps, "run_local", side_effect=self.fake_build(other)):
            with self.assertRaisesRegex(ValueError, "psy_node_cli hash differs from artifacts"):
                run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())

    def test_manifest_naming_other_hashes_than_the_files_is_rejected(self):
        self.make_build(self.build_dir(), manifest_extra={"binaries": {name: "0" * 64 for name in CLI_NAMES}})
        with self.assertRaisesRegex(ValueError, "manifest binary hash differs"):
            steps.PREPARE_STEPS["rebuild_binaries"].verify(self.ws.context())

    def test_manifest_for_another_source_commit_is_rejected(self):
        self.make_build(self.build_dir(), manifest_extra={"source_commit": "9" * 40})
        with self.assertRaisesRegex(ValueError, "source commit differs"):
            steps.PREPARE_STEPS["rebuild_binaries"].verify(self.ws.context())

    def test_completed_build_is_verified_not_rebuilt(self):
        self.make_build(self.build_dir())
        with unittest.mock.patch.object(steps, "run_local") as run:
            result = run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())
        run.assert_not_called()
        self.assertEqual(result["binaries"], self.hashes)

    def test_failed_attempt_is_kept_and_the_next_attempt_gets_a_new_directory(self):
        self.make_build(self.build_dir(1), with_manifest=False)
        marker = (self.build_dir(1) / "psy_node_cli").read_bytes()
        with unittest.mock.patch.object(steps, "run_local", side_effect=self.fake_build()):
            run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())
        self.assertEqual((self.build_dir(1) / "psy_node_cli").read_bytes(), marker)
        self.assertTrue((self.build_dir(2) / "manifest.json").is_file())

    def test_failed_build_script_names_the_failure_without_output_values(self):
        with unittest.mock.patch.object(steps, "run_local", return_value=done(1, "", "pinned-node-build failed")):
            with self.assertRaisesRegex(RuntimeError, "build script failed"):
                run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())

    def test_check_fails_clearly_when_free_disk_is_below_the_threshold(self):
        self.disk.return_value = steps.MIN_BUILD_FREE_BYTES - 1
        with self.assertRaisesRegex(ValueError, "free disk .* below"):
            steps.PREPARE_STEPS["rebuild_binaries"].check(self.ws.context())

    def test_completed_build_of_another_commit_does_not_block_a_new_build(self):
        other = self.out_root / f"{self.ws.lock['release_id']}-{'a' * 12}-build-1"
        self.make_build(other, manifest_extra={"source_commit": "a" * 40})
        with unittest.mock.patch.object(steps, "run_local", side_effect=self.fake_build()):
            result = run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())
        self.assertEqual(result["binaries"], self.hashes)
        self.assertTrue((self.build_dir(1) / "manifest.json").is_file())

    def test_same_commit_build_with_a_wrong_hash_still_stops_the_step(self):
        self.make_build(self.build_dir(1), contents={**self.CONTENTS, "psy_node_cli": b"drift"})
        with unittest.mock.patch.object(steps, "run_local") as run:
            with self.assertRaisesRegex(ValueError, "hash differs"):
                run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())
        run.assert_not_called()

    def test_finished_build_is_rechecked_even_when_disk_is_low(self):
        self.make_build(self.build_dir())
        self.disk.return_value = 0
        with unittest.mock.patch.object(steps, "run_local") as run:
            result = run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())
        run.assert_not_called()
        self.assertEqual(result["binaries"], self.hashes)

    def test_threshold_covers_the_measured_full_target_cache(self):
        # A full release target cache of the pinned workspace measured 21 GB; output and logs add 0.4 GB.
        self.assertGreaterEqual(steps.MIN_BUILD_FREE_BYTES, 22 * GIB)

    def test_every_device_that_holds_a_cache_or_the_output_is_measured(self):
        seen = []
        self.disk.side_effect = lambda path: (seen.append(Path(path)), 100 * GIB)[1]
        steps.PREPARE_STEPS["rebuild_binaries"].check(self.ws.context())
        self.assertEqual(set(seen), {*self.caches.values(), self.out_root})

    def test_config_differing_from_the_lock_is_rejected_in_check(self):
        Path(self.ws.local["files"]["config"]).write_bytes(b"edited")
        with self.assertRaisesRegex(ValueError, "config hash differs from the lock"):
            steps.PREPARE_STEPS["rebuild_binaries"].check(self.ws.context())

    def test_missing_script_fails_check(self):
        (self.ws.root / "build.sh").unlink()
        with self.assertRaisesRegex(ValueError, "build script not found"):
            steps.PREPARE_STEPS["rebuild_binaries"].check(self.ws.context())

    def test_result_is_stored_in_the_state_dir_for_later_steps(self):
        self.make_build(self.build_dir())
        run_all(steps.PREPARE_STEPS["rebuild_binaries"], self.ws.context())
        state = json.loads((self.ws.state_dir / "rebuild_binaries.json").read_text())
        self.assertEqual(state, {"build_dir": str(self.build_dir())})


class VerifyArtifactsTests(PrepareTestCase):
    def setUp(self):
        super().setUp()
        ws = self.ws
        lock = ws.lock
        pins = {
            "config": lambda h: lock["inputs"].update(runtime_config=h),
            "canonical_config": lambda h: lock["inputs"].update(canonical_config=h),
            "genesis": lambda h: lock["inputs"].update(genesis=h),
            "genesis_contracts": lambda h: ws.set_artifacts(genesis_contracts_sha256=h),
            "compiler_stamp": lambda h: ws.set_artifacts(compiler_stamp_sha256=h),
            "groth16_setup_manifest": lambda h: lock["groth16"].update(setup_manifest_sha256=h),
            "gnark_groth16_verifier": lambda h: lock["groth16"]["verifiers"].update(gnark_groth16_verifier=h),
            "deposit_batch_verifier": lambda h: lock["groth16"]["verifiers"].update(deposit_batch_verifier=h),
            "withdrawal_claim_verifier": lambda h: lock["groth16"]["verifiers"].update(withdrawal_claim_verifier=h),
            "psy_services": lambda h: lock["binaries"].update({"psy-services": h}),
            "psy_indexer": lambda h: lock["binaries"].update({"psy-indexer": h}),
            "l1_bundle_manifest": lambda h: lock["l1"].update(bundle_sha256=h),
            "l1_policy": lambda h: lock["l1"].update(policy_sha256=h),
        }
        self.paths = {name: ws.put_file(name, f"content {name}".encode(), pin=pin,
                                        filename="manifest.json" if name == "l1_bundle_manifest" else None)
                      for name, pin in pins.items()}
        patcher = unittest.mock.patch.object(steps.fresh_l1, "verify_bundle")
        self.verify_bundle = patcher.start()
        self.addCleanup(patcher.stop)
        for chain in CHAINS:
            path = ws.release_dir / f"fresh_l1_gas_budget.{chain}.json"
            path.write_text("{}\n")
            lock["l1"]["gas_budget_sha256"][chain] = sha(path.read_bytes())
        ws.write_local()

    def test_verify_artifacts_never_invokes_genesis_generation(self):
        with unittest.mock.patch.object(steps, "run_local", side_effect=AssertionError("ran a command")) as run, \
                unittest.mock.patch("subprocess.run", side_effect=AssertionError("ran a process")) as process:
            result = run_all(steps.PREPARE_STEPS["verify_artifacts"], self.ws.context())
        run.assert_not_called()
        process.assert_not_called()
        self.assertEqual(set(result["verified"]) >= set(FILE_NAMES), True)

    def test_l1_bundle_is_deeply_verified_against_the_locked_hash_before_any_wipe(self):
        run_all(steps.PREPARE_STEPS["verify_artifacts"], self.ws.context())
        self.verify_bundle.assert_called_once_with(self.paths["l1_bundle_manifest"].parent,
                                                   self.ws.lock["l1"]["bundle_sha256"])
        self.verify_bundle.side_effect = steps.fresh_l1.GateError("bundle contents/hash mismatch")
        with self.assertRaisesRegex(ValueError, "bundle contents/hash mismatch"):
            steps.PREPARE_STEPS["verify_artifacts"].verify(self.ws.context())

    def test_bundle_manifest_must_be_named_manifest_json(self):
        misnamed = self.paths["l1_bundle_manifest"].with_name("other.json")
        self.paths["l1_bundle_manifest"].rename(misnamed)
        self.ws.local["files"]["l1_bundle_manifest"] = str(misnamed)
        self.ws.write_local()
        with self.assertRaisesRegex(ValueError, "must be the manifest.json of the bundle"):
            steps.PREPARE_STEPS["verify_artifacts"].verify(self.ws.context())

    def test_result_has_hashes_only_and_passes_the_result_filter(self):
        result = run_all(steps.PREPARE_STEPS["verify_artifacts"], self.ws.context())
        self.assertEqual(result["verified"]["psy_indexer"], sha(b"content psy_indexer"))
        self.assertIsNone(find_secret(result))
        self.assertNotIn(str(self.ws.root), json.dumps(result))

    def test_services_binary_hash_mismatch_is_rejected_by_name(self):
        self.paths["psy_services"].write_bytes(b"swapped")
        with self.assertRaisesRegex(ValueError, "psy_services hash differs from the lock"):
            run_all(steps.PREPARE_STEPS["verify_artifacts"], self.ws.context())

    def test_groth16_verifier_mismatch_is_rejected_by_name(self):
        self.paths["deposit_batch_verifier"].write_bytes(b"swapped")
        with self.assertRaisesRegex(ValueError, "deposit_batch_verifier hash differs from the lock"):
            run_all(steps.PREPARE_STEPS["verify_artifacts"], self.ws.context())

    def test_genesis_and_contract_bundle_mismatches_are_rejected(self):
        for name in ("genesis", "genesis_contracts", "compiler_stamp", "config"):
            with self.subTest(name=name):
                original = self.paths[name].read_bytes()
                self.paths[name].write_bytes(b"swapped")
                with self.assertRaisesRegex(ValueError, f"{name} hash differs"):
                    steps.PREPARE_STEPS["verify_artifacts"].verify(self.ws.context())
                self.paths[name].write_bytes(original)

    def test_empty_pin_is_refused_even_when_called_directly(self):
        self.ws.lock["binaries"]["psy-services"] = ""
        with self.assertRaisesRegex(ValueError, "psy_services is not pinned in the lock"):
            steps.PREPARE_STEPS["verify_artifacts"].check(self.ws.context())
        self.ws.lock["binaries"]["psy-services"] = sha(b"content psy_services")
        self.ws.lock["groth16"]["setup_manifest_sha256"] = ""
        with self.assertRaisesRegex(ValueError, "groth16_setup_manifest is not pinned"):
            steps.PREPARE_STEPS["verify_artifacts"].check(self.ws.context())

    def test_gas_budget_file_hash_is_checked_per_chain(self):
        (self.ws.release_dir / "fresh_l1_gas_budget.baseSepolia.json").write_text('{"x": 1}\n')
        with self.assertRaisesRegex(ValueError, "gas budget baseSepolia hash differs"):
            steps.PREPARE_STEPS["verify_artifacts"].verify(self.ws.context())

    def test_missing_gas_budget_file_is_refused(self):
        (self.ws.release_dir / "fresh_l1_gas_budget.bscTestnet.json").unlink()
        with self.assertRaisesRegex(ValueError, "gas budget file missing: bscTestnet"):
            steps.PREPARE_STEPS["verify_artifacts"].check(self.ws.context())

    def test_missing_file_is_refused_in_check(self):
        self.paths["l1_policy"].unlink()
        with self.assertRaisesRegex(ValueError, "l1_policy: file not found"):
            steps.PREPARE_STEPS["verify_artifacts"].check(self.ws.context())


class PackageBuilderTests(PrepareTestCase):
    def fake_builders(self, order):
        def builder(name):
            def build(ctx, inputs):
                order.append(("build", name, inputs))
                return Path(f"/out/{name}")
            def verify(ctx, inputs, output):
                order.append(("verify", name, str(output)))
                return {"packages": 1}
            return steps.PackageBuilder(name, (), build, verify)
        return [builder("alpha"), builder("beta")]

    def test_every_builder_in_the_list_runs_in_order_and_is_reported(self):
        order = []
        self.ws.local["packages"] = {"alpha": {"k": "1"}, "beta": {"k": "2"}}
        self.ws.write_local()
        with unittest.mock.patch.object(steps, "PACKAGE_BUILDERS", self.fake_builders(order)):
            result = run_all(steps.PREPARE_STEPS["prepare_packages"], self.ws.context())
        self.assertEqual([call[:2] for call in order], [("build", "alpha"), ("build", "beta"),
                                                          ("verify", "alpha"), ("verify", "beta")])
        self.assertEqual(order[0][2], {"k": "1"})
        self.assertEqual(result, {"packages": {"alpha": {"packages": 1}, "beta": {"packages": 1}}})

    def test_adding_a_builder_is_one_list_entry(self):
        order = []
        extra = steps.PackageBuilder("gamma", (), lambda ctx, inputs: Path("/out/gamma"),
                                     lambda ctx, inputs, output: {"packages": 3})
        self.ws.local["packages"] = {"alpha": {}, "beta": {}, "gamma": {}}
        self.ws.write_local()
        with unittest.mock.patch.object(steps, "PACKAGE_BUILDERS", [*self.fake_builders(order), extra]):
            result = run_all(steps.PREPARE_STEPS["prepare_packages"], self.ws.context())
        self.assertEqual(list(result["packages"]), ["alpha", "beta", "gamma"])

    def test_the_shipped_list_holds_the_core_and_proxy_builders(self):
        self.assertEqual([builder.name for builder in steps.PACKAGE_BUILDERS], ["core", "proxy"])

    def test_duplicate_builder_names_are_refused(self):
        order = []
        builders = self.fake_builders(order)
        with unittest.mock.patch.object(steps, "PACKAGE_BUILDERS", [builders[0], builders[0]]):
            with self.assertRaisesRegex(ValueError, "duplicate package builder: alpha"):
                steps.PREPARE_STEPS["prepare_packages"].check(self.ws.context())

    def test_builder_without_local_inputs_is_refused_in_check(self):
        self.ws.write_local()
        with unittest.mock.patch.object(steps, "PACKAGE_BUILDERS", self.fake_builders([])):
            with self.assertRaisesRegex(ValueError, "local-inputs.json lacks packages.alpha"):
                steps.PREPARE_STEPS["prepare_packages"].check(self.ws.context())

    def test_declared_inputs_must_exist_and_be_absolute_paths_in_check(self):
        builder = steps.PackageBuilder("alpha", ("keys", "output"), lambda ctx, inputs: Path("/o"),
                                       lambda ctx, inputs, output: {})
        for inputs, message in (({"output": "/o"}, "lacks packages.alpha.keys"),
                                ({"keys": "/k", "output": "relative/out"}, "packages.alpha.output must be an absolute path"),
                                ({"keys": "/k/../x", "output": "/o"}, "packages.alpha.keys must be an absolute path"),
                                ({"keys": "/k", "output": 5}, "packages.alpha.output must be an absolute path")):
            self.ws.local["packages"] = {"alpha": inputs}
            self.ws.write_local()
            with self.subTest(inputs=inputs), unittest.mock.patch.object(steps, "PACKAGE_BUILDERS", [builder]):
                with self.assertRaisesRegex(ValueError, message):
                    steps.PREPARE_STEPS["prepare_packages"].check(self.ws.context())

    def test_output_paths_go_to_the_state_dir_not_the_result(self):
        self.ws.local["packages"] = {"alpha": {}, "beta": {}}
        self.ws.write_local()
        with unittest.mock.patch.object(steps, "PACKAGE_BUILDERS", self.fake_builders([])):
            result = run_all(steps.PREPARE_STEPS["prepare_packages"], self.ws.context())
        self.assertEqual(json.loads((self.ws.state_dir / "prepare_packages.json").read_text()),
                         {"alpha": "/out/alpha", "beta": "/out/beta"})
        self.assertNotIn("/out/", json.dumps(result))


class CorePackageTests(PrepareTestCase):
    HOST = "gcp-test-cp"

    def setUp(self):
        super().setUp()
        ws = self.ws
        self.node = b"ELF node"
        ws.set_binaries({"psy_node_cli": self.node})
        self.build_dir = ws.root / "build"
        self.build_dir.mkdir()
        (self.build_dir / "psy_node_cli").write_bytes(self.node)
        (ws.state_dir / "rebuild_binaries.json").write_text(json.dumps({"build_dir": str(self.build_dir)}))
        ws.put_file("config", b"config", pin=lambda h: ws.lock["inputs"].update(runtime_config=h))
        ws.put_file("genesis", b"genesis", pin=lambda h: ws.lock["inputs"].update(genesis=h))
        only_core = [builder for builder in steps.PACKAGE_BUILDERS if builder.name == "core"]
        patcher = unittest.mock.patch.object(steps, "PACKAGE_BUILDERS", only_core)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.output = ws.root / "packages"
        ws.local["packages"] = {"core": {"registration_keys": str(ws.root / "keys.json"),
                                         "faucet_operators": str(ws.root / "operators.json"),
                                         "p2p_keys": str(ws.root / "p2p"), "output": str(self.output)}}
        ws.write_local()

    def make_packages(self, *, tamper=None, extra_file=False, manifest_hash=True):
        root = self.output / self.HOST
        (root / "bin").mkdir(parents=True)
        (root / "keys").mkdir()
        files = {"bin/psy_node_cli": self.node, "config.json": b"config", "genesis.json": b"genesis",
                 "keys/realm-0-v1/zk.key": b"key"}
        for name, data in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        manifest = {"schema_version": 1, "host": self.HOST, "files": {name: sha(data) for name, data in files.items()}}
        if tamper:
            (root / tamper).write_bytes(b"tampered")
        if extra_file:
            (root / "stray.txt").write_text("x")
        text = json.dumps(manifest, indent=2)
        (root / "manifest.json").write_text(text)
        self.ws.set_artifacts(core_host_packages={"manifest_sha256": {self.HOST: sha(text) if manifest_hash else "0" * 64}})

    def run_step(self):
        return run_all(steps.PREPARE_STEPS["prepare_packages"], self.ws.context())

    def test_core_builder_calls_prepare_host_packages_with_the_lock_hash_and_rebuilt_node(self):
        calls = []
        def fake(argv, timeout=None):
            calls.append(argv)
            self.make_packages()
            return done()
        with unittest.mock.patch.object(steps, "run_local", side_effect=fake):
            result = self.run_step()
        argv = calls[0]
        self.assertEqual(Path(argv[argv.index("--release-lock") - 1]).name, "prepare_host_packages.py")
        self.assertEqual(argv[argv.index("--release-lock") + 1], str(self.ws.release_dir / "release-lock.json"))
        self.assertEqual(argv[argv.index("--release-lock-sha256") + 1], "a" * 64)
        self.assertEqual(argv[argv.index("--node-binary") + 1], str(self.build_dir / "psy_node_cli"))
        self.assertEqual(argv[argv.index("--output") + 1], str(self.output))
        self.assertEqual(result["packages"]["core"]["hosts"], 1)
        self.assertIsNone(find_secret(result))

    def test_missing_core_input_fails_in_check_not_as_a_key_error_in_apply(self):
        del self.ws.local["packages"]["core"]["p2p_keys"]
        self.ws.write_local()
        with unittest.mock.patch.object(steps, "run_local") as run:
            with self.assertRaisesRegex(ValueError, "lacks packages.core.p2p_keys"):
                steps.PREPARE_STEPS["prepare_packages"].check(self.ws.context())
        run.assert_not_called()

    def test_existing_output_is_verified_not_rebuilt(self):
        self.make_packages()
        with unittest.mock.patch.object(steps, "run_local") as run:
            self.run_step()
        run.assert_not_called()

    def test_package_manifest_hash_differing_from_artifacts_is_rejected(self):
        self.make_packages(manifest_hash=False)
        with self.assertRaisesRegex(ValueError, "manifest hash differs from artifacts"):
            self.run_step()

    def test_tampered_package_file_is_rejected(self):
        self.make_packages(tamper="keys/realm-0-v1/zk.key")
        with self.assertRaisesRegex(ValueError, "package file hash differs"):
            self.run_step()

    def test_payload_differing_from_the_lock_is_rejected(self):
        self.make_packages()
        self.ws.lock["inputs"]["genesis"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "genesis.json differs from the lock"):
            self.run_step()

    def test_file_missing_from_the_package_manifest_is_rejected(self):
        self.make_packages(extra_file=True)
        with self.assertRaisesRegex(ValueError, "files differ from the manifest"):
            self.run_step()

    def test_node_binary_differing_from_the_lock_is_refused_before_building(self):
        (self.build_dir / "psy_node_cli").write_bytes(b"other")
        with unittest.mock.patch.object(steps, "run_local") as run:
            with self.assertRaisesRegex(ValueError, "node binary differs from the lock"):
                self.run_step()
        run.assert_not_called()

    def test_failed_script_is_reported_without_its_output(self):
        with unittest.mock.patch.object(steps, "run_local", return_value=done(1, "", "boom")):
            with self.assertRaisesRegex(RuntimeError, "prepare_host_packages failed"):
                self.run_step()


class RegistrationTests(unittest.TestCase):
    def test_every_step_name_is_a_python_row_of_the_release_step_table(self):
        table = (Path(__file__).resolve().parent.parent / "fresh-192-20261030" / "steps.tsv").read_text()
        names = {line.split("\t")[1].split(":", 1)[1] for line in table.splitlines()
                 if not line.startswith("#") and line.split("\t")[1].startswith("py:")}
        self.assertTrue(set(steps.PREPARE_STEPS) <= names)
        self.assertEqual(len(steps.PREPARE_STEPS), 5)

    def test_steps_are_not_cutover_and_require_a_complete_lock(self):
        for name, step in steps.PREPARE_STEPS.items():
            with self.subTest(step=name):
                self.assertEqual(step.name, name)
                self.assertFalse(step.cutover)
                self.assertTrue(step.requires_complete)

    def test_module_is_registered_and_imports_only_from_deploy_remote(self):
        import deploy
        self.assertIn("deploy_prepare_steps", deploy.STEP_MODULES)
        self.assertTrue(set(steps.PREPARE_STEPS) <= set(deploy.build_registry()))
        source = Path(steps.__file__).read_text()
        self.assertNotRegex(source, r"(?m)^(import deploy|from deploy) ")

    def test_standard_library_and_release_modules_only(self):
        source = Path(steps.__file__).read_text()
        imported = set(re.findall(r"(?m)^(?:import|from) ([a-z_0-9]+)", source))
        local = {"deploy_remote", "release_lock", "build_runtime", "fresh_l1", "deploy_monitoring_steps"}
        import sys
        self.assertEqual({name for name in imported if name not in sys.stdlib_module_names}, local & imported)


if __name__ == "__main__":
    unittest.main()
