#!/usr/bin/env python3
"""Pinned, offline Node release build. No Services, generation or deployment."""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tomllib


BINS = ("psy_dev_cli", "psy_relayer_cli", "psy_user_cli", "psy_node_cli", "psy_worker_cli")
CACHE_NAMES = ("cargo", "target", "go", "go_build")
LOCK_NAME = ".psy-runtime-build.lock"
SOURCE_FILES = ("Cargo.lock", "rust-toolchain.toml",
                "client_prover/psy_prover/src/wallet/local_circuits.json",
                "psy_plonky2_circuits/src/generated/cached_circuit_library.rs",
                "psy_plonky2_circuits/src/generated/cached_common_data.rs")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), "unexpected spec fields")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def document(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique_object)


def absolute_path(value, *, missing=False):
    require(isinstance(value, (str, Path)), "invalid path")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and not any(c in str(path) for c in ",\n\r"),
            "absolute, mount-safe path required")
    for parent in reversed((path, *path.parents)):
        if missing and parent == path:
            require(not os.path.lexists(path), "output already exists")
            continue
        require(not stat.S_ISLNK(parent.lstat().st_mode), "symlink path rejected")
        if parent != path:
            require(parent.is_dir(), "non-directory ancestor")
    return path


def digest(path):
    path = absolute_path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular file required")
        return hashlib.file_digest(stream, "sha256").hexdigest()


def overlaps(a, b):
    return a == b or a in b.parents or b in a.parents


def load_spec(path):
    spec = document(absolute_path(path))
    fields(spec, ("schema_version", "source", "inputs", "builder_image", "caches", "output", "jobs"))
    require(type(spec["schema_version"]) is int and spec["schema_version"] in (1, 2), "unsupported spec")
    fields(spec["source"], ("path", "commit"))
    require(isinstance(spec["source"]["commit"], str) and re.fullmatch(r"[0-9a-f]{40}", spec["source"]["commit"]),
            "full source commit required")
    require(isinstance(spec["builder_image"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", spec["builder_image"]),
            "immutable local image ID required")
    require(type(spec["jobs"]) is int and 1 <= spec["jobs"] <= 256, "invalid jobs")
    input_names = ("config", "bundle", "bundle_stamp")
    if spec["schema_version"] == 2:
        input_names += ("release_profile",)
    fields(spec["inputs"], input_names)
    for entry in spec["inputs"].values():
        fields(entry, ("path", "sha256"))
        require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "invalid SHA256")
        require(digest(entry["path"]) == entry["sha256"], "input SHA256 mismatch")
    source = absolute_path(spec["source"]["path"])
    require(source.is_dir() and (source / "psy-genesis").is_dir(), "source needs existing nested Genesis directory")
    genesis = Path(spec["inputs"]["bundle"]["path"]).parent
    require(Path(spec["inputs"]["bundle"]["path"]).name == "genesis_contracts.json", "canonical bundle filename required")
    require(Path(spec["inputs"]["bundle_stamp"]["path"]).parent == genesis, "stamp must accompany external bundle")
    require(not overlaps(source, genesis), "external Genesis must be separate from source")
    # Both mount targets must already exist; Docker must not create files in source.
    digest(genesis / "config.json")
    absolute_path(source / "psy-genesis")
    fields(spec["caches"], CACHE_NAMES)
    caches = [absolute_path(spec["caches"][name]) for name in CACHE_NAMES]
    require(all(p.is_dir() for p in caches), "existing cache directories required")
    out = absolute_path(spec["output"], missing=True)
    parent = out.parent.stat()
    require(parent.st_uid == os.getuid() and not parent.st_mode & 0o022, "output parent must be owned and not group/world writable")
    protected = [source, genesis, absolute_path(path), *(Path(e["path"]) for e in spec["inputs"].values())]
    writable = [*caches, out]
    require(all(not overlaps(a, b) for i, a in enumerate(writable) for b in writable[i + 1:]), "writable paths overlap")
    require(all(not overlaps(a, b) for a in writable for b in protected), "writable path overlaps input")
    config = document(Path(spec["inputs"]["config"]["path"]))
    network = config["networks"]["testnet"]
    require(int(network["magic"], 0) == 0x1337CF514544CF69, "testnet magic mismatch")
    period = network["p2p"]["checkpoints_per_epoch"]
    require(type(period) is int and period > 0, "invalid testnet checkpoint period")
    if spec["schema_version"] == 2:
        profile = document(Path(spec["inputs"]["release_profile"]["path"]))
        require(profile.get("runtime_inputs_frozen") is True, "fresh runtime inputs are not frozen")
        require(profile["network"] == "testnet" and config.get("defaultNetwork") == "testnet",
                "fresh build must select testnet")
        require(profile["runtime_candidate_commit"] == spec["source"]["commit"], "release source mismatch")
        require(profile["runtime_config_sha256"] == spec["inputs"]["config"]["sha256"], "release config hash mismatch")
        require(profile["network_magic"] == network["magic"] and
                type(profile["checkpoints_per_epoch"]) is int and profile["checkpoints_per_epoch"] == period == 32,
                "fresh build requires release-bound epoch 32")
        require(profile["proving_backend"] == "plonky2-poseidon-goldilocks", "fresh build requires Plonky2")
    else:
        require(period == 10, "non-R3 builds require a version-2 release-bound spec")
    stamp = document(Path(spec["inputs"]["bundle_stamp"]["path"]))
    require(stamp["artifactSha256"] == spec["inputs"]["bundle"]["sha256"] and
            stamp["artifactByteSize"] == Path(spec["inputs"]["bundle"]["path"]).stat().st_size,
            "compiler stamp does not bind bundle")
    require(isinstance(stamp["compilerRevision"], str) and re.fullmatch(r"[0-9a-f]{40}", stamp["compilerRevision"]),
            "invalid compiler revision")
    return spec


def command(argv, *, log=None):
    if log is not None:
        with log.open("x") as stream:
            subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=True)
        return log.read_text()
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE).strip()


def check_source(spec):
    source = Path(spec["source"]["path"])
    def git(*args):
        return command(["git", "--no-optional-locks", "-C", str(source), *args])
    require(git("rev-parse", "HEAD") == spec["source"]["commit"], "source commit mismatch")
    require(not git("status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"), "source is not clean")
    metadata = {"source_tree": git("rev-parse", "HEAD^{tree}"),
                "source_submodules": git("submodule", "status", "--recursive"),
                "source_files": {name: digest(source / name) for name in SOURCE_FILES},
                "git_common_dir": str(absolute_path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))),
                "git_dir": str(absolute_path(git("rev-parse", "--absolute-git-dir")))}
    for entry in spec["inputs"].values():
        require(digest(entry["path"]) == entry["sha256"], "input SHA256 mismatch")
    metadata["rust_toolchain"] = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    require(re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", metadata["rust_toolchain"]), "dated nightly required")
    for key in ("git_common_dir", "git_dir"):
        require(all(not overlaps(Path(metadata[key]), Path(spec["caches"][name])) for name in CACHE_NAMES),
                "cache overlaps Git metadata")
        require(not overlaps(Path(metadata[key]), Path(spec["output"])), "output overlaps Git metadata")
    return metadata


def check_process_writers():
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text().strip()
        except FileNotFoundError:
            continue
        require(name not in {"cargo", "rustc", "rust-lld", "ld.lld", "collect2", "go", "cgo"},
                "existing build process; cache ownership refused")


def check_cache_writers(spec):
    check_process_writers()
    for cid in command(["docker", "ps", "-q"]).split():
        mounts = json.loads(command(["docker", "inspect", "--format", "{{json .Mounts}}", cid]))
        for mount in mounts:
            if mount.get("RW"):
                path = Path(mount["Source"]).resolve()
                require(all(not overlaps(path, Path(cache)) for cache in spec["caches"].values()),
                        "container has writable build-cache mount")


def container(spec, metadata):
    source = spec["source"]["path"]
    caches = spec["caches"]
    environment = {
        "PATH": "/usr/local/cargo/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "RUSTUP_HOME": "/usr/local/rustup", "RUSTUP_TOOLCHAIN": metadata["rust_toolchain"],
        "CARGO_HOME": caches["cargo"], "CARGO_TARGET_DIR": caches["target"],
        "CARGO_BUILD_JOBS": str(spec["jobs"]), "CARGO_INCREMENTAL": "0", "CARGO_TERM_COLOR": "never",
        "CARGO_NET_OFFLINE": "true", "RAYON_NUM_THREADS": str(spec["jobs"]), "HOME": "/tmp",
        "GOPATH": caches["go"], "GOCACHE": caches["go_build"], "GOPROXY": "off", "GOSUMDB": "off",
        "PSY_NETWORK": "testnet", "PSY_CONFIG_PATH": "/psy-node/psy-genesis/config.json",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
    }
    argv = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}"]
    for key, value in environment.items():
        argv += ["-e", key + "=" + value]
    def mount(src, dst, readonly=True):
        argv.extend(["--mount", f"type=bind,src={src},dst={dst}" + (",readonly" if readonly else "")])
    mount(source, "/psy-node")
    # Worktree .git files refer to host-absolute Git metadata/worktree locations.
    mount(source, source)
    mount(metadata["git_common_dir"], metadata["git_common_dir"])
    if not Path(metadata["git_dir"]).is_relative_to(metadata["git_common_dir"]):
        mount(metadata["git_dir"], metadata["git_dir"])
    genesis = Path(spec["inputs"]["bundle"]["path"]).parent
    for root in ("/psy-node", source):
        mount(genesis, root + "/psy-genesis")
        mount(spec["inputs"]["config"]["path"], root + "/psy-genesis/config.json")
    for cache in caches.values():
        mount(cache, cache, readonly=False)
    mount(spec["output"], spec["output"])
    argv += ["-w", "/psy-node", spec["builder_image"]]
    return argv, environment


def build_runtime(spec_path):
    spec_path = absolute_path(spec_path)
    spec_sha = digest(spec_path)
    spec = load_spec(spec_path)
    before = check_source(spec)
    image = command(["docker", "image", "inspect", spec["builder_image"], "--format", "{{.Id}} {{.Os}}/{{.Architecture}}"])
    require(image == spec["builder_image"] + " linux/amd64", "builder image/platform mismatch")
    out = Path(spec["output"])
    def phase_gate():
        require(digest(spec_path) == spec_sha, "spec changed")
        require(check_source(spec) == before, "source inputs changed")
        check_cache_writers(spec)
    with ExitStack() as stack:
        for cache in sorted(spec["caches"].values()):
            fd = os.open(Path(cache) / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            lock = stack.enter_context(os.fdopen(fd, "a+"))
            require(stat.S_ISREG(os.fstat(fd).st_mode), "cache lock is not regular")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        phase_gate()
        out.mkdir(mode=0o700)
        prefix, environment = container(spec, before)
        def logged(args, name):
            phase_gate()
            result = command(prefix + args, log=out / name)
            phase_gate()
            return result
        versions = logged(["rustc", "--version", "--verbose"], "rustc.log")
        go_version = logged(["go", "version"], "go.log")
        # Every worktree is mounted at /psy-node. Cargo's source mtimes alone
        # cannot distinguish an older checkout from newer cached local objects.
        workspace = json.loads(logged(["cargo", "metadata", "--offline", "--locked",
            "--format-version", "1", "--quiet"], "cargo-metadata.log"))
        packages = {package["id"]: package for package in workspace["packages"]}
        package_specs = []
        require(all(packages[member].get("source") is None for member in workspace["workspace_members"]),
                "workspace package must be local")
        for package in packages.values():
            if package.get("source") is not None:
                continue
            require(re.fullmatch(r"[A-Za-z0-9_-]+", package["name"]) and
                    re.fullmatch(r"[A-Za-z0-9.+-]+", package["version"]), "invalid workspace package")
            package_specs.append(package["name"] + "@" + package["version"])
        require(package_specs, "empty workspace package set")
        package_specs = sorted(set(package_specs))
        clean = ["cargo", "clean", "--offline", "--locked", "--release"]
        for package in package_specs:
            clean += ["-p", package]
        logged(clean, "workspace-clean.log")
        build = ["cargo", "build", "--offline", "--locked", "--release", "--message-format=json-render-diagnostics"]
        for binary in BINS:
            build += ["--bin", binary]
        logged(build, "release-build.log")
        hashes, glibc = {}, {}
        for binary in BINS:
            src = absolute_path(Path(spec["caches"]["target"]) / "release" / binary)
            source_sha = digest(src)
            dst = out / binary
            with src.open("rb") as stream, dst.open("xb") as target:
                require(stream.read(4) == b"\x7fELF", "output is not ELF")
                stream.seek(0)
                shutil.copyfileobj(stream, target)
            dst.chmod(0o755)
            require(digest(dst) == source_sha, "binary changed while copying")
            hashes[binary] = source_sha
            symbols = logged(["objdump", "-T", str(dst)], binary + "-glibc.log")
            require("GLIBC_PRIVATE" not in symbols and "GLIBC_ABI_" not in symbols, "unsupported GLIBC requirement")
            versions_found = [tuple(map(int, v.split("."))) for v in re.findall(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", symbols)]
            require(versions_found and max(versions_found) <= (2, 36), "GLIBC requirement missing or above 2.36")
            glibc[binary] = ".".join(map(str, max(versions_found)))
            logged([str(dst), "--help"], binary + "-help.log")
            require(digest(dst) == source_sha, "packaged binary changed during verification")
        phase_gate()
        manifest = {
            "schema_version": 1, "build_spec_version": spec["schema_version"], "source_commit": spec["source"]["commit"], **before,
            "source_directory": spec["source"]["path"], "source_clean_before_and_after_build": True,
            "source_mount_read_only": True, "external_genesis_directory": str(Path(spec["inputs"]["bundle"]["path"]).parent),
            "inputs": spec["inputs"], "genesis_contracts_sha256": spec["inputs"]["bundle"]["sha256"],
            "config_sha256": spec["inputs"]["config"]["sha256"], "builder_image": spec["builder_image"],
            "cargo_lock_sha256": before["source_files"]["Cargo.lock"], "network": "testnet",
            "local_circuits_sha256": before["source_files"]["client_prover/psy_prover/src/wallet/local_circuits.json"],
            "cached_circuit_library_sha256": before["source_files"]["psy_plonky2_circuits/src/generated/cached_circuit_library.rs"],
            "cached_common_data_sha256": before["source_files"]["psy_plonky2_circuits/src/generated/cached_common_data.rs"],
            "network_magic": "0x1337CF514544CF69",
            "checkpoints_per_epoch": document(Path(spec["inputs"]["config"]["path"]))["networks"]["testnet"]["p2p"]["checkpoints_per_epoch"],
            "build_network": "none", "environment": environment, "build_command": build,
            "local_clean_command": clean, "local_package_specs": package_specs,
            "compiler_revision": document(Path(spec["inputs"]["bundle_stamp"]["path"]))["compilerRevision"],
            "rustc_version": versions.strip(), "go_version": go_version.strip(), "binaries": hashes,
            "glibc_maximums": glibc, "spec_sha256": spec_sha, "recipe_sha256": digest(Path(__file__).resolve()),
            "logs": {p.name: digest(p) for p in out.glob("*.log")},
            "verification": {"cli_help_passed": 5, "exact_tests_passed": 0, "genesis_acceptance": "pending"},
            "runtime_approved": False, "deployment_ready": False,
            "not_performed": ["Services build", "Genesis acceptance", "Genesis/key/setup generation", "remote operations"],
        }
        with (out / "manifest.json").open("x") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
    return out / "manifest.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        manifest = build_runtime(args.spec)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("pinned-node-build failed; retain partial output and inspect its private logs", file=sys.stderr)
        return 1
    print(json.dumps({"manifest": str(manifest), "manifest_sha256": digest(manifest), "deployment_ready": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
