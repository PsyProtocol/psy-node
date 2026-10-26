#!/usr/bin/env python3
"""Behavioral checks using disposable Git worktrees; no builds or services."""

from contextlib import redirect_stdout
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("fresh", Path(__file__).with_name("fresh.py"))
fresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fresh)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, stderr=subprocess.PIPE).strip()


class CohortTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        disk = patch.object(fresh, "disk_free", return_value=200)
        disk.start()
        self.addCleanup(disk.stop)
        self.root = self.workspace / "isolated"
        self.sources = {"schema_version": 1, "network": "localhost", "repositories": {}}
        for name in fresh.REPOSITORIES:
            repo = self.workspace / (name + "-source")
            repo.mkdir()
            git(repo, "init", "-q")
            git(repo, "config", "user.name", "Local fixture")
            git(repo, "config", "user.email", "fixture@invalid")
            git(repo, "remote", "add", "origin", f"https://github.com/PsyProtocol/{name}.git")
            (repo / "Cargo.toml").write_text('[workspace]\n[workspace.dependencies]\npsy_data = { git = "https://github.com/PsyProtocol/psy-node.git", rev = "' + "0" * 40 + '" }\n')
            (repo / "lib.rs").write_text("// immutable fixture\n")
            git(repo, "add", "Cargo.toml", "lib.rs")
            git(repo, "commit", "-qm", "Frozen fixture")
            self.sources["repositories"][name] = {"checkout": repo.name, "commit": git(repo, "rev-parse", "HEAD")}
        self.source_file = self.workspace / "sources.json"
        self.source_file.write_text(json.dumps(self.sources))
        self.source_hash = fresh.digest(self.source_file)

    def prepare(self):
        return fresh.prepare(self.root, self.workspace, self.sources, self.source_hash, "fixture", True)

    def invoke(self, *args):
        with redirect_stdout(io.StringIO()) as output:
            result = fresh.main(["--workspace", str(self.workspace), "--root", str(self.root),
                                 "--sources", str(self.source_file), *args])
        return result, json.loads(output.getvalue())

    def test_preview_has_no_directories_or_branches(self):
        before = {name: git(self.workspace / entry["checkout"], "show-ref")
                  for name, entry in self.sources["repositories"].items()}
        result = fresh.prepare(self.root, self.workspace, self.sources, self.source_hash, "fixture", False)
        self.assertFalse(result["apply"])
        self.assertFalse(self.root.exists())
        for name, entry in self.sources["repositories"].items():
            self.assertEqual(git(self.workspace / entry["checkout"], "show-ref"), before[name])

    def test_real_worktrees_use_frozen_commits_and_preserve_dirty_sources(self):
        entry = self.sources["repositories"]["psy-services"]
        source = self.workspace / entry["checkout"]
        (source / "lib.rs").write_text("// later committed fixture\n")
        git(source, "add", "lib.rs")
        git(source, "commit", "-qm", "Later source")
        (source / "lib.rs").write_text("// contributor's uncommitted work\n")
        before = git(source, "status", "--porcelain")
        self.prepare()
        for name, item in self.sources["repositories"].items():
            checkout = self.root / "projects" / name
            self.assertEqual(git(checkout, "rev-parse", "HEAD"), item["commit"])
            self.assertEqual(git(checkout, "branch", "--show-current"), "local/fixture")
        self.assertEqual(git(source, "status", "--porcelain"), before)
        self.assertEqual((source / "lib.rs").read_text(), "// contributor's uncommitted work\n")
        self.assertEqual((self.root / "projects/psy-services/lib.rs").read_text(), "// immutable fixture\n")
        fresh.validate_cohort(self.root, self.source_hash, self.sources)

    def test_existing_destination_and_partial_prepare_are_retained(self):
        self.root.mkdir()
        marker = self.root / "retain"
        marker.write_text("existing state")
        with self.assertRaisesRegex(fresh.PreparationError, "already exists"):
            self.prepare()
        self.assertEqual(marker.read_text(), "existing state")

    def test_noncanonical_compiler_origin_rejected_before_writes(self):
        source = self.workspace / self.sources["repositories"]["psy-compiler"]["checkout"]
        git(source, "remote", "set-url", "origin", "git@github.com:QEDProtocol/psy-compiler.git")
        with self.assertRaisesRegex(fresh.PreparationError, "canonical"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_low_disk_rejected_before_any_worktree(self):
        with patch.object(fresh, "disk_free", return_value=33):
            with self.assertRaisesRegex(fresh.PreparationError, "150 GiB"):
                self.prepare()
        self.assertFalse(self.root.exists())

    def test_changed_source_manifest_is_not_adopted(self):
        self.prepare()
        with self.assertRaisesRegex(fresh.PreparationError, "manifest"):
            fresh.validate_cohort(self.root, "changed", self.sources)

    def test_build_preview_does_not_execute_compilation(self):
        self.prepare()
        with patch.object(fresh, "execute_build", side_effect=AssertionError("preview built code")):
            code, result = self.invoke("build", "--stage", "node")
        self.assertEqual(code, 0)
        self.assertFalse(result["apply"])
        command = result["commands"][0]["argv"]
        self.assertIn("--locked", command)
        self.assertIn("psy_relayer_cli", command)
        self.assertFalse((self.root / "operation.lock").exists())

    def test_divergent_node_switch_requires_explicit_preview_flag(self):
        self.prepare()
        _, ordinary = self.invoke("deps", "--mode", "node")
        _, reviewed = self.invoke("deps", "--mode", "node", "--allow-history-switch")
        self.assertNotIn("--allow-history-switch", ordinary["commands"][0]["argv"])
        self.assertIn("--allow-history-switch", reviewed["commands"][0]["argv"])
        with self.assertRaisesRegex(fresh.PreparationError, "requires deps --mode node"):
            self.invoke("deps", "--mode", "local", "--allow-history-switch")
        self.assertFalse((self.root / "operation.lock").exists())

    def test_submodule_plan_registers_before_ephemeral_url_override(self):
        self.prepare()
        projects = self.root / "projects"
        commands = fresh.submodule_commands(projects)
        for name in fresh.REPOSITORIES:
            selected = [command for cwd, command in commands if cwd == projects / name]
            self.assertEqual(selected[0], ["git", "submodule", "init"])
            self.assertIn("submodule.psy-genesis.url=https://github.com/PsyProtocol/psy-genesis.git", selected[1])
            self.assertNotIn("--remote", selected[1])
        dapp = [command for cwd, command in commands if cwd == projects / "psy-node/psy-dapp"]
        self.assertEqual(dapp[0], ["git", "submodule", "init"])
        self.assertEqual(dapp[1][-4:], ["submodule", "update", "--init", "--recursive"])

    def test_parallel_mutator_is_refused_before_submodules(self):
        self.prepare()
        with (self.root / "operation.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(fresh.PreparationError, "Another cohort"):
                self.invoke("submodules", "--apply")

    def test_untracked_source_edits_invalidate_binary_identity(self):
        self.prepare()
        projects = self.root / "projects"
        before = fresh.input_identity(projects)
        new_source = projects / "psy-node/new.rs"
        new_source.write_text("// source one\n")
        one = fresh.input_identity(projects)
        new_source.write_text("// source two\n")
        two = fresh.input_identity(projects)
        self.assertNotEqual(before, one)
        self.assertNotEqual(one, two)

    def test_foreign_local_node_crate_is_rejected_by_resolved_graph(self):
        self.prepare()
        projects = self.root / "projects"
        node = projects / "psy-node"
        crate = node / "owned/Cargo.toml"
        crate.parent.mkdir()
        crate.write_text('[package]\nname = "psy_client_data"\nversion = "0.0.0"\n')
        git(node, "add", "owned/Cargo.toml")
        git(node, "commit", "-qm", "Fixture crate")
        original_run = fresh.run
        def resolved(argv, cwd=None, env=None, capture=True):
            if argv[0] == "cargo":
                self.assertIn("--locked", argv)
                return json.dumps({"packages": [{"name": "psy_client_data", "source": None,
                                                  "manifest_path": "/foreign/psy-node/owned/Cargo.toml"}]})
            return original_run(argv, cwd, env, capture)
        with patch.object(fresh, "run", side_effect=resolved):
            with self.assertRaisesRegex(fresh.PreparationError, "outside the owned cohort"):
                fresh.verify_node_dependencies(projects, {}, self.sources["repositories"]["psy-node"]["commit"])

    def test_source_change_during_compilation_retains_failed_evidence(self):
        self.prepare()
        projects = self.root / "projects"
        original_run = fresh.run
        def compile_with_change(argv, cwd=None, env=None, capture=True):
            if argv[0] == "cargo":
                (projects / "psy-node/lib.rs").write_text("// concurrent source change\n")
                return ""
            return original_run(argv, cwd, env, capture)
        with patch.object(fresh, "run", side_effect=compile_with_change), \
                patch.object(fresh, "tool_failures", return_value=[]), \
                patch.object(fresh, "verify_node_dependencies"):
            with self.assertRaisesRegex(fresh.PreparationError, "changed during compilation"):
                fresh.execute_build(self.root, projects, "node")
        evidence = list((self.root / "evidence").glob("build-node-*.json"))
        self.assertEqual(len(evidence), 1)
        self.assertFalse(json.loads(evidence[0].read_text())["passed"])
        self.assertIn("concurrent source change", (projects / "psy-node/lib.rs").read_text())

    def generated_abi_fixture(self):
        self.prepare()
        projects = self.root / "projects"
        outputs = {}
        for path in fresh.genesis_outputs(projects):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"fixture": "' + path.name + '"}\n')
            outputs[str(path.relative_to(projects))] = fresh.digest(path)
        record = {"passed": True, "compiler_identity": fresh.compiler_identity(projects / "psy-compiler"),
                  "outputs": outputs}
        (self.root / "evidence/build-genesis-artifacts-1.json").write_text(json.dumps(record))
        return projects

    def test_generated_abis_are_verified_and_materialized_for_services(self):
        projects = self.generated_abi_fixture()
        fresh.materialize_services_abis(self.root, projects)
        fresh.materialize_services_abis(self.root, projects)
        for name in fresh.PRECOMPILES:
            if name == "multisig_policy":
                continue
            compiler = projects / "psy-compiler"
            self.assertEqual((compiler / f"target/genesis_abi/{name}.abi.json").read_bytes(),
                             (compiler / f"psy-precompiles/{name}/target/{name}.abi.json").read_bytes())

    def test_changed_generated_abi_is_rejected_before_alias_creation(self):
        projects = self.generated_abi_fixture()
        compiler = projects / "psy-compiler"
        (compiler / "target/genesis_abi/token.abi.json").write_text("{}\n")
        with self.assertRaisesRegex(fresh.PreparationError, "artifacts changed"):
            fresh.materialize_services_abis(self.root, projects)
        self.assertFalse((compiler / "psy-precompiles/token/target/token.abi.json").exists())

    def test_different_existing_abi_alias_is_preserved_before_any_copy(self):
        projects = self.generated_abi_fixture()
        compiler = projects / "psy-compiler"
        target = compiler / "psy-precompiles/faucet/target/faucet.abi.json"
        target.write_text("existing unrelated ABI\n")
        with self.assertRaisesRegex(fresh.PreparationError, "alias differs"):
            fresh.materialize_services_abis(self.root, projects)
        self.assertEqual(target.read_text(), "existing unrelated ABI\n")
        self.assertFalse((compiler / "psy-precompiles/token/target/token.abi.json").exists())

    def test_real_provenance_detects_modified_payload(self):
        self.prepare()
        projects = self.root / "projects"
        expected = fresh.compiler_identity(projects / "psy-compiler")
        genesis = projects / "psy-node/psy-genesis"
        genesis.mkdir()
        stamp = dict(expected)
        for filename, key, size in (
            ("genesis_contracts.json", "artifactSha256", "artifactByteSize"),
            ("token.json", "tokenArtifactSha256", "tokenArtifactByteSize"),
            ("token.update.json", "tokenUpdateArtifactSha256", "tokenUpdateArtifactByteSize"),
        ):
            payload = genesis / filename
            payload.write_text("[]\n")
            stamp[key] = fresh.digest(payload)
            stamp[size] = payload.stat().st_size
        (genesis / ".genesis_contracts.compiler-artifact.json").write_text(json.dumps(stamp))
        sdk = projects / "psy-sdk/psy-ts-sdk/packages/psy-sdk"
        sdk.mkdir(parents=True)
        (sdk / ".compiler-artifact.json").write_text(json.dumps(expected))
        self.assertEqual(fresh.artifact_failures(projects), [])
        (genesis / "token.json").write_text("[1]\n")
        self.assertIn("Genesis: missing or modified token.json", fresh.artifact_failures(projects))

    def test_stale_pin_never_reports_ready_without_builds(self):
        self.prepare()
        with patch.object(fresh, "tool_failures", return_value=[]):
            code, result = self.invoke("preflight")
        self.assertEqual(code, 2)
        self.assertFalse(result["build_checks_passed"])
        self.assertFalse(result["runtime_ready"])
        self.assertTrue(any("Node Cargo pins" in finding for finding in result["failures"]))
        self.assertTrue(any("no recorded release build" in finding for finding in result["failures"]))

    def test_manifest_rejects_branch_names_and_path_escape(self):
        for field, value in (("commit", "testnet-dev"), ("checkout", "../other")):
            entry = self.sources["repositories"]["psy-node"]
            original = entry[field]
            entry[field] = value
            self.source_file.write_text(json.dumps(self.sources))
            with self.assertRaises(fresh.PreparationError):
                fresh.read_sources(self.source_file)
            entry[field] = original

    def test_root_cannot_reuse_source_or_symlink_parent(self):
        source = self.workspace / "psy-node-source"
        with self.assertRaises(fresh.PreparationError):
            fresh.validate_root(source / "runtime", self.workspace, self.sources)
        link = self.workspace / "linked"
        link.symlink_to(source, target_is_directory=True)
        with self.assertRaises(fresh.PreparationError):
            fresh.validate_root(link / "runtime", self.workspace, self.sources)


class BoundaryTests(unittest.TestCase):
    def test_make_uses_owned_cwd_instead_of_inherited_pwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Makefile").write_text("all:\n\t@printf '%s' '$(PWD)'\n")
            env = dict(os.environ, PWD="/foreign/compiler")
            self.assertEqual(fresh.run(["make"], cwd=root, env=env), str(root))
            self.assertEqual(env["PWD"], "/foreign/compiler")
            with patch.dict(os.environ, {"PWD": "/another/compiler"}):
                self.assertEqual(fresh.run(["make"], cwd=root), str(root))

    def test_sdk_build_produces_both_local_dependency_packages(self):
        commands = fresh.build_commands(Path("/cohort/projects"), "sdk")
        packages = [command[command.index("--filter") + 1] for _, command in commands if "--filter" in command]
        self.assertEqual(packages, ["@psy-protocol/utils", "@psy-protocol/psy-sdk", "@psy-protocol/evm-wallet"])

    def test_legacy_lifecycle_and_e2e_refuse_guardian_before_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "node/psy_cli/guardian_common/src/runtime.rs"
            marker.parent.mkdir(parents=True)
            marker.write_text("// new Guardian source fixture\n")
            env = dict(os.environ, PSY_NODE_DIR=str(root / "node"),
                       LOCAL_MULTICHAIN_ENV_FILE="/dev/null", LOCAL_DEPLOY_STATE_DIR=str(root / "state"))
            for script in ("start.sh", "stop.sh", "e2e.sh"):
                result = subprocess.run(["bash", str(fresh.DIRECTORY / script)], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertNotEqual(result.returncode, 0, script)
                self.assertIn("cannot operate the Guardian runtime", result.stderr, script)
                self.assertFalse((root / "state").exists(), script)

    def test_port_conflict_is_reported_without_terminating_listener(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            with patch.object(fresh, "PORTS", {"fixture": port}):
                failures = fresh.port_failures()
            self.assertTrue(any(str(port) in finding for finding in failures))
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass

    def test_build_environment_removes_wallet_and_guardian_secrets(self):
        with patch.dict(os.environ, {"PRIVATE_KEY": "must-not-copy", "GUARDIAN_1_KEYSTORE_PASSWORD": "must-not-copy",
                                     "CARGO_ENCODED_RUSTFLAGS": "AVX512", "GIT_DIR": "/foreign"}):
            env = fresh.build_environment(Path("/cohort/projects"))
        self.assertNotIn("PRIVATE_KEY", env)
        self.assertNotIn("GUARDIAN_1_KEYSTORE_PASSWORD", env)
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", env)
        self.assertNotIn("GIT_DIR", env)
        self.assertEqual(env["PSY_NETWORK"], "localhost")
        self.assertNotIn("avx512", env["RUSTFLAGS"].lower())
        self.assertEqual(env["CARGO_CACHE_AUTO_CLEAN_FREQUENCY"], "never")

    def test_private_tools_override_path_and_keep_cache_inside_cohort(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools/bin").mkdir(parents=True)
            with patch.dict(os.environ, {"PATH": "/global/bin", "COREPACK_HOME": "/foreign/cache"}):
                env = fresh.build_environment(root / "projects")
            self.assertEqual(env["PATH"].split(os.pathsep)[0], str(root / "tools/bin"))
            self.assertEqual(env["COREPACK_HOME"], str(root / "tools/corepack-cache"))


if __name__ == "__main__":
    unittest.main()
