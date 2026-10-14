#!/usr/bin/env python3
"""Policy/receipt failure tests, plus an optional real Docker/Rust fixture smoke."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("build", HERE / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
BASE = json.loads((HERE / "versions.json").read_text())


class BuildPolicyTests(unittest.TestCase):
    def rejected(self, change):
        data = copy.deepcopy(BASE)
        change(data)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "versions.json"
            build.write_json(path, data)
            with self.assertRaises(ValueError):
                build.policy(path)

    def test_refuses_floating_base(self):
        self.rejected(lambda p: p["toolchain"].update(runtime_base="debian:bookworm-slim"))

    def test_refuses_production_stage(self):
        self.rejected(lambda p: p.update(stage="testnet"))

    def test_refuses_branch_instead_of_commit(self):
        self.rejected(lambda p: p["sources"]["node"].update(commit="release/testnet-stable"))

    def test_refuses_native_cpu(self):
        self.rejected(lambda p: p["toolchain"].update(rustflags="-C target-cpu=native"))

    def test_refuses_unsafe_binary(self):
        self.rejected(lambda p: p["components"]["node"].update(binary="../../escape"))

    def test_receipt_rejects_tampered_binary_and_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path = root / "versions.json"
            build.write_json(policy_path, BASE)
            args = argparse.Namespace(versions=policy_path)
            binary = root / "artifacts/node/psy_node_cli"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"fixture-only")
            receipt = {"component": "node", "binary": "psy_node_cli", "binary_sha256": build.sha(binary),
                       "source": BASE["sources"]["node"], "policy_sha256": build.sha(policy_path),
                       "stage": BASE["stage"], "genesis": BASE["sources"]["genesis"],
                       "toolchain": BASE["toolchain"], "builder_image_id": "sha256:" + "1" * 64}
            path = binary.parent / "artifact.json"
            build.write_json(path, receipt)
            build.write_json(root / "builder.json", {"image_id": receipt["builder_image_id"], "policy_sha256": build.sha(policy_path)})
            build.artifact_check(root, "node", args, BASE)
            binary.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "binary hash/type mismatch"):
                build.artifact_check(root, "node", args, BASE)
            binary.write_bytes(b"fixture-only")
            receipt["source"] = BASE["sources"]["node"]
            receipt["builder_image_id"] = "sha256:" + "2" * 64
            build.write_json(path, receipt)
            with self.assertRaisesRegex(ValueError, "different builder"):
                build.artifact_check(root, "node", args, BASE)
            receipt["builder_image_id"] = "sha256:" + "1" * 64
            receipt["source"] = dict(receipt["source"], commit="0" * 40)
            build.write_json(path, receipt)
            with self.assertRaisesRegex(ValueError, "field mismatch: source"):
                build.artifact_check(root, "node", args, BASE)

    def test_existing_preparation_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "unowned.txt"
            sentinel.write_text("keep")
            with self.assertRaises(ValueError):
                build.prepare(argparse.Namespace(output=root), BASE)
            self.assertEqual(sentinel.read_text(), "keep")

    def test_container_identity_adds_missing_uid_without_removing_existing_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(build, "run", side_effect=["root:x:0:0:root:/root:/bin/bash", "root:x:0:"]):
                build.container_identity(root, "fixture-image", 1000, 1000)
            self.assertIn("root:x:0:0:", (root / "passwd").read_text())
            self.assertIn("psy-build-1000:x:1000:1000:", (root / "passwd").read_text())
            self.assertIn("psy-build-1000:x:1000:", (root / "group").read_text())

    def test_container_identity_does_not_duplicate_an_existing_uid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = "builder:x:1000:1000:builder:/builder:/bin/bash"
            with patch.object(build, "run", side_effect=[original, "builder:x:1000:"]):
                build.container_identity(root, "fixture-image", 1000, 1000)
            self.assertEqual((root / "passwd").read_text(), original + "\n")


def fixture_repo(path, repository):
    path.mkdir(parents=True)
    build.run(["git", "init", "-q", path])
    build.git(path, "config", "user.email", "fixture@example.invalid")
    build.git(path, "config", "user.name", "Build harness fixture")
    build.git(path, "remote", "add", "origin", "https://github.com/" + repository + ".git")


def fixture_commit(path):
    # Synthetic temporary repositories only; no project branch is committed.
    build.git(path, "add", "--all")
    build.git(path, "commit", "-q", "-m", "Synthetic build harness input")
    return build.git(path, "rev-parse", "HEAD")


def docker_smoke(output, builder_image):
    if output.exists():
        raise ValueError("Smoke output must be a new directory")
    output.mkdir(parents=True)
    fixtures = output / "fixtures"
    genesis, source = fixtures / "genesis", fixtures / "node"
    fixture_repo(genesis, "PsyProtocol/psy-genesis")
    (genesis / "config.json").write_text('{"fixture":true}\n')
    (genesis / "genesis_contracts.json").write_text('{"fixture":true}\n')
    genesis_commit = fixture_commit(genesis)
    fixture_repo(source, "PsyProtocol/psy-node")
    (source / "src").mkdir()
    (source / "src/main.rs").write_text('fn main() { println!("BUILD HARNESS FIXTURE ONLY"); }\n')
    bins = [item["binary"] for item in BASE["components"].values()]
    (source / "Cargo.toml").write_text('[package]\nname="build_harness_fixture"\nversion="0.0.0"\nedition="2021"\n' +
        ''.join('\n[[bin]]\nname="' + name + '"\npath="src/main.rs"\n' for name in bins))
    (source / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "build_harness_fixture"\nversion = "0.0.0"\n')
    (source / "rust-toolchain.toml").write_text('[toolchain]\nchannel="nightly-2025-09-20"\n')
    (source / ".gitignore").write_text('.env\n')
    (source / "migrations").mkdir()
    (source / "migrations/001.sql").write_text('-- fixture only\n')
    source_commit = fixture_commit(source)
    build.git(source, "update-index", "--add", "--cacheinfo", "160000," + genesis_commit + ",psy-genesis")
    build.git(source, "commit", "-q", "-m", "Synthetic pinned Genesis gitlink")
    node_commit = build.git(source, "rev-parse", "HEAD")
    services = fixtures / "services"
    build.run(["git", "clone", "--shared", "--no-checkout", source, services])
    build.git(services, "remote", "set-url", "origin", "https://github.com/PsyProtocol/psy-services.git")
    build.git(services, "checkout", "--detach", source_commit)
    config = copy.deepcopy(BASE)
    config["scope"] = "synthetic-build-harness-fixture-not-psy-release"
    config["build_limits"]["minimum_free_gib"] = 1
    for name in ("node", "services", "indexer"):
        config["sources"][name]["commit"] = node_commit if name == "node" else source_commit
        config["sources"][name]["lock_sha256"] = build.sha(source / "Cargo.lock")
        config["sources"][name]["basis"] = "Synthetic fixture only"
    config["sources"]["genesis"].update(commit=genesis_commit, config_sha256=build.sha(genesis / "config.json"),
                                         contracts_sha256=build.sha(genesis / "genesis_contracts.json"))
    versions = output / "fixture-versions.json"
    build.write_json(versions, config)
    common = ["python3", HERE / "build.py"]
    args = ["--versions", versions, "--output", output / "build", "--component", "all"]
    build.run(common + ["prepare", *args, "--node-repo", source, "--services-repo", services, "--genesis-repo", genesis])
    # An ignored secret-like file must not enter the allowlisted image resources.
    (output / "build/sources/services/.env").write_text("FIXTURE_SECRET_DO_NOT_PACKAGE=true\n")
    build.run(common + ["builder", *args, "--use-builder", builder_image])
    build.run(common + ["compile", *args, "--offline"])
    build.run(common + ["verify", *args])
    build.run(common + ["images", *args, "--image-prefix", "psy-build-fixture"])
    images = json.loads((output / "build/images.json").read_text())["images"]
    for item in images.values():
        settings = build.inspect_image(item["image_id"])["Config"]
        if settings["User"] != "10001:10001":
            raise ValueError("Runtime image does not run as the planned non-root user")
        build.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "/bin/sh",
                   item["image_id"], "-c", "test ! -e /app/.env && test ! -e /app/Cargo.toml && test ! -e /app/.git"])
    build.write_json(output / "SMOKE-RESULT.json", {"status": "passed", "images": len(images),
                     "scope": "synthetic Rust compile and Docker build harness; not Psy binary/proof/E2E validation",
                     "created_utc": build.utc()})
    print(output / "SMOKE-RESULT.json")


def identity_smoke(output, builder_image):
    output.mkdir(parents=True, exist_ok=False)
    uid, gid = os.getuid(), os.getgid()
    mounts = build.container_identity(output, builder_image, uid, gid)
    command = ["docker", "run", "--rm", "--network", "none", "--read-only",
               "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *mounts,
               "--entrypoint", "/bin/sh", builder_image, "-c",
               'getent passwd "$(id -u)" >/dev/null && ssh -G -F /dev/null -o StrictHostKeyChecking=yes git@github.com >/dev/null']
    build.run(command)
    build.write_json(output / "IDENTITY-RESULT.json", {"status": "passed", "uid": uid, "gid": gid,
                     "scope": "network-disabled SSH config resolution as exact build UID; no Git connection",
                     "created_utc": build.utc()})
    print(output / "IDENTITY-RESULT.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-smoke", type=Path)
    parser.add_argument("--identity-smoke", type=Path)
    parser.add_argument("--builder", default="psy-bookworm-builder:nightly-2025-09-20")
    args = parser.parse_args()
    if args.identity_smoke:
        identity_smoke(args.identity_smoke.resolve(), args.builder)
    elif args.docker_smoke:
        docker_smoke(args.docker_smoke.resolve(), args.builder)
    else:
        unittest.main(argv=[__file__], verbosity=2)
