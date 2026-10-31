#!/usr/bin/env python3
"""Compile offline Genesis tools and reject invalid args; no measurement or Genesis reads."""
import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
import build_runtime as runtime


HERE = Path(__file__).resolve().parent
TOOLS = {
    "verify_genesis": ("anyhow", "serde_json", "zstd", "psy_vm", "psy_client_data", "parth_core",
                       "psy_data", "guardian_common", "psy_config", "sha2"),
    "measure_genesis_fingerprints": ("anyhow", "serde_json", "plonky2", "psy_config",
                                      "psy_client_data", "psy_common_circuit", "psy_dpn_circuit"),
}
STANDARD_LIBRARIES = ("std", "core", "alloc", "compiler_builtins", "panic_unwind")
require = runtime.require


def dependencies(log, target):
    needed = {name for names in TOOLS.values() for name in names} | set(STANDARD_LIBRARIES)
    found = {name: set() for name in needed}
    total = 0
    with log.open() as stream:
        for line in stream:
            total += len(line)
            require(total <= 256 * 1024 * 1024, "runtime build log exceeds bound")
            if not line.startswith("{"):
                continue
            entry = json.loads(line, object_pairs_hook=runtime.unique_object)
            if entry.get("reason") != "compiler-artifact":
                continue
            name = entry["target"]["name"]
            profile = entry["profile"]
            if name not in needed or entry["target"]["kind"] not in (["lib"], ["rlib"]) or profile.get("test") is not False:
                continue
            # Build dependencies use opt-level 0; these tools consume the CLI's release libraries.
            if profile.get("opt_level") != "3" or profile.get("debug_assertions") is not False:
                continue
            for filename in entry["filenames"]:
                if not filename.endswith(".rlib"):
                    continue
                path = runtime.absolute_path(filename)
                require(path.parent == target / "release/deps"
                        and re.fullmatch(r"lib" + re.escape(name) + r"-[0-9a-f]+\.rlib", path.name),
                        "library path differs from the recorded target")
                found[name].add(path)
    require(all(len(paths) == 1 for paths in found.values()), "missing or ambiguous release library record")
    return {name: paths.pop() for name, paths in found.items()}


def load(build_path, build_sha):
    require(runtime.digest(build_path) == build_sha, "runtime manifest hash mismatch")
    require(build_path.stat().st_size <= 4 * 1024 * 1024, "runtime manifest exceeds bound")
    manifest = runtime.document(build_path)
    require(manifest["schema_version"] == 1 and manifest["build_spec_version"] == 2
            and manifest["network"] == "testnet" and manifest["checkpoints_per_epoch"] == 32
            and manifest["network_magic"] == "0x1337CF514544CF69"
            and manifest["source_clean_before_and_after_build"] is True
            and manifest["verification"]["cli_help_passed"] == 5, "unsupported runtime build")
    require(re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"])
            and re.fullmatch(r"[0-9a-f]{64}", manifest["config_sha256"]), "invalid runtime provenance")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", manifest["builder_image"])
            and re.fullmatch(r"nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}", manifest["rust_toolchain"]),
            "immutable image and dated toolchain required")
    for entry in manifest["inputs"].values():
        require(runtime.digest(entry["path"]) == entry["sha256"], "runtime input changed")
    for binary, digest in manifest["binaries"].items():
        require(binary in runtime.BINS and runtime.digest(build_path.parent / binary) == digest,
                "runtime binary changed")
    require(set(manifest["binaries"]) == set(runtime.BINS), "incomplete runtime binaries")
    log = build_path.parent / "release-build.log"
    require(runtime.digest(log) == manifest["logs"][log.name], "runtime build log changed")
    target = runtime.absolute_path(manifest["environment"]["CARGO_TARGET_DIR"])
    libraries = dependencies(log, target)
    recorded = manifest.get("release_libraries")
    require(isinstance(recorded, dict) and recorded, "runtime build lacks library hashes")
    for path in libraries.values():
        require(recorded.get(str(path)) == runtime.digest(path), "library differs from runtime build")
    return manifest, target, libraries


def build_tools(build_path, build_sha, output):
    manifest, target, libraries = load(build_path, build_sha)
    output = runtime.absolute_path(output, missing=True)
    require(output.parent.stat().st_uid == os.getuid() and not output.parent.stat().st_mode & 0o022,
            "output parent must be owned and protected")
    require(not any(runtime.overlaps(output, path) for path in (target, build_path.parent, HERE)),
            "output overlaps build inputs")
    prefix = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
              "--user", f"{os.getuid()}:{os.getgid()}",
              "-e", "RUSTUP_HOME=/usr/local/rustup", "-e", "RUSTUP_TOOLCHAIN=" + manifest["rust_toolchain"],
              "-e", "HOME=/tmp", "-e", "TS_RS_EXPORT_DIR=/tmp", "-e", "PSY_NETWORK=testnet",
              "--mount", f"type=bind,src={target},dst={target},readonly",
              "--mount", f"type=bind,src={HERE},dst=/tool-sources,readonly",
              "--mount", f"type=bind,src={output},dst=/tools", "-w", "/tmp", manifest["builder_image"]]
    commands = []
    old_umask = os.umask(0o077)
    stack = ExitStack()
    try:
        caches = {name: runtime.absolute_path(manifest["environment"][key]) for name, key in
                  (("cargo", "CARGO_HOME"), ("target", "CARGO_TARGET_DIR"), ("go", "GOPATH"), ("go_build", "GOCACHE"))}
        require(len(set(caches.values())) == 4, "runtime caches alias one another")
        for cache in sorted(caches.values()):
            descriptor = os.open(cache / runtime.LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                raise ValueError("cache lock is not regular")
            lock = stack.enter_context(os.fdopen(descriptor, "a+"))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        runtime.check_cache_writers({"caches": caches})
        require(load(build_path, build_sha)[2] == libraries, "runtime library records changed")
        hashes = {name: runtime.digest(path) for name, path in libraries.items()}
        sources = {name: runtime.digest(HERE / (name + ".rs")) for name in TOOLS}
        output.mkdir(mode=0o700)
        for name, names in TOOLS.items():
            argv = ["rustc", "--edition=2021", "--crate-name", name, "-C", "opt-level=3",
                    "-L", "dependency=" + str(target / "release/deps")]
            for dependency in (*names, *STANDARD_LIBRARIES):
                argv += ["--extern", dependency + "=" + str(libraries[dependency])]
            argv += ["/tool-sources/" + name + ".rs", "-o", "/tools/" + name]
            with (output / (name + ".build.log")).open("x") as log:
                subprocess.run(prefix + argv, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
            commands.append(argv)
            # Deliberately invalid arguments must fail before reading files or constructing circuits.
            result = subprocess.run(prefix + ["/tools/" + name, "--unexpected"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            require(result.returncode == 1, "tool did not reject invalid arguments")
            if name == "verify_genesis":
                failure = json.loads(result.stdout, object_pairs_hook=runtime.unique_object)
                require(failure.get("ok") is False and failure.get("error", "").startswith("expected --bundle"),
                        "verifier failed for an unrelated reason")
            else:
                require(result.stdout.startswith("fingerprint measurement failed: expected --node-source-commit"),
                        "measurement tool failed for an unrelated reason")
            with (output / (name + ".invalid-args.log")).open("x") as log:
                log.write(result.stdout)
        require(runtime.digest(build_path) == build_sha, "runtime manifest changed while linking")
        for name, path in libraries.items():
            require(runtime.digest(path) == hashes[name], "library changed while linking")
        for name, digest in sources.items():
            require(runtime.digest(HERE / (name + ".rs")) == digest, "tool source changed while linking")
        report = {"schema_version": 1, "runtime_manifest_sha256": build_sha,
                  "source_commit": manifest["source_commit"], "config_sha256": manifest["config_sha256"],
                  "builder_image": manifest["builder_image"], "rust_toolchain": manifest["rust_toolchain"],
                  "tool_sources_sha256": sources, "libraries": {
                      name: {"path": str(libraries[name]), "sha256": digest} for name, digest in hashes.items()},
                  "commands": commands, "binaries": {name: runtime.digest(output / name) for name in TOOLS},
                  "logs": {path.name: runtime.digest(path) for path in output.glob("*.log")},
                  "invalid_argument_checks_passed": 2, "rust_unit_tests_run": False,
                  "fingerprints_measured": False, "genesis_verified": False, "deployment_ready": False}
        with (output / "manifest.json").open("x") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return output / "manifest.json"
    finally:
        stack.close()
        os.umask(old_umask)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-manifest", required=True, type=Path)
    parser.add_argument("--runtime-manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = build_tools(runtime.absolute_path(args.runtime_manifest), args.runtime_manifest_sha256, args.output)
    print(json.dumps({"manifest": str(result), "manifest_sha256": runtime.digest(result), "deployment_ready": False}))


if __name__ == "__main__":
    main()
