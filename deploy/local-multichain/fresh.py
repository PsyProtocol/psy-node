#!/usr/bin/env python3
"""Prepare and build an isolated, pinned localhost cohort; never start services."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import tomllib


DIRECTORY = Path(__file__).resolve().parent
SOURCE_FILE = DIRECTORY / "fresh-sources.json"
REPOSITORIES = (
    "psy-node", "psy-compiler", "psy-genesis", "psy-contracts",
    "psy-sdk", "psy-services", "psy-dapp", "psy-wallet",
)
BINARIES = {
    "node": ("psy_node_cli", "psy_worker_cli", "psy_dev_cli", "psy_relayer_cli", "psy_user_cli"),
    "compiler": ("dargo",),
    "services": ("psy-services", "psy-indexer"),
}
PRECOMPILES = ("token", "multisig_policy", "deposit_tree", "withdrawal_tree", "usdt_token", "faucet")
PORTS = {
    "coordinator": 1337, "realm0-sub1": 13380, "realm0-sub2": 13381,
    "realm1-sub1": 13390, "realm1-sub2": 13391,
    "processor-r0-sub1": 41001, "processor-r0-sub2": 41002,
    "processor-r1-sub1": 41021, "processor-r1-sub2": 41022,
    "edge-r0-sub1": 41101, "edge-r0-sub2": 41102,
    "edge-r1-sub1": 41121, "edge-r1-sub2": 41122,
    "scylla": 9042, "nats": 4222, "redis": 6379, "nostr": 8081,
    "postgres": 15433, "hasura": 9080, "envio": 9898,
    "services": 3000, "prove-proxy": 9999, "faucet": 9998,
    "ethereum": 8545, "bsc": 9545, "base": 10545,
    "guardian1": 15441, "guardian2": 15442, "guardian3": 15443,
    "guardian-history": 15450,
    "account": 5179, "ide": 5176, "bridge": 5177, "explorer": 5178,
}
SECRET_KEYS = {
    "PRIVATE_KEY", "KEYSTORE_PATH", "PSY_BRIDGE_RELAYER_KEYSTORE_PATH",
    "BRIDGE_RELAYER_KEYSTORE_PATH", "BRIDGE_RELAYER_L2_PRIVATE_KEY", "WALLET_PASSWORD",
    "PSY_RELAYER_MULTISIG_ACCOUNT", "PSY_MULTISIG_POLICY_ARTIFACT",
}
ENVIRONMENT_KEYS = {
    "PSY_NETWORK", "PSY_CONFIG_PATH", "PSY_PROJECTS_DIR", "DARGO_STD_PATH",
    "RUSTFLAGS", "CARGO_BUILD_JOBS", "RAYON_NUM_THREADS", "CARGO_NET_GIT_FETCH_WITH_CLI",
    "VITE_NETWORK", "VITE_PSY_STAGE", "PSY_SKIP_CONFIG_SYNC", "HUSKY",
    "PSY_COMPILER_DIR", "PSY_GENESIS", "GENESIS_CONTRACTS_DIR",
    "PSY_COMPILER_DARGO_BIN", "PSY_COMPILER_DARGO_STD_PATH",
    "CARGO_CACHE_AUTO_CLEAN_FREQUENCY", "COREPACK_HOME",
}
RUNTIME_GATES = [
    "Apply and review the current-source port overlay: all PostgreSQL clients and Compose must use 15433; Hasura must use 9080.",
    "Provision three local-only Guardian keystores and ordered public member commitments; retain schema-3 journal checks.",
    "Prepare fresh local Groth16 setup and matching exported Solidity verifiers, including every enabled proof family.",
    "Prepare frozen Envio dependencies and Guardian daemon config; validate Guardian History availability.",
    "Provision local Worker identities, fresh-Genesis reward mappings and Edge whitelists; verify allow/reject behavior.",
    "Align generated Genesis/ABI/SDK artifacts in every consumed gitlink; do not delete or edit provenance stamps.",
    "Use the native foreground lifecycle for 2 Realms x 2 validators, three Anvil chains and Guardians; old start.sh is incompatible.",
]


class PreparationError(Exception):
    pass


def run(argv, cwd=None, env=None, capture=True):
    child_env = dict(os.environ if env is None else env)
    # subprocess changes cwd, but inherited PWD otherwise still names the
    # caller. The compiler Makefile derives all generated paths from $(PWD).
    child_env["PWD"] = str(Path.cwd() if cwd is None else Path(cwd).resolve())
    result = subprocess.run(
        [str(value) for value in argv], cwd=cwd, env=child_env,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None, text=True,
    )
    if result.returncode:
        # Resolver/build output can contain credentials. Preserve its exit code,
        # but never include captured stderr, inherited environment or argv secrets.
        raise PreparationError(f"{Path(str(argv[0])).name} failed (exit {result.returncode}) in {cwd}")
    return result.stdout.strip() if capture else ""


def git(repo, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    return run(["git", "-C", repo, *args], env=env)


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def read_sources(path):
    document = json.loads(path.read_text())
    if document.get("schema_version") != 1 or document.get("network") != "localhost":
        raise PreparationError("Source manifest must use schema 1 and network localhost")
    repositories = document.get("repositories", {})
    if set(repositories) != set(REPOSITORIES):
        raise PreparationError("Source manifest must name exactly the eight cohort repositories")
    for name, entry in repositories.items():
        if not re.fullmatch(r"[0-9a-f]{40}", entry.get("commit", "")):
            raise PreparationError(f"{name}: expected a full immutable commit")
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", entry.get("checkout", "")):
            raise PreparationError(f"{name}: checkout must be a workspace child basename")
    return document


def canonical_origin(name, value):
    return value.removesuffix(".git") in {
        f"git@github.com:PsyProtocol/{name}", f"https://github.com/PsyProtocol/{name}",
        f"ssh://git@github.com/PsyProtocol/{name}",
    }


def validate_root(root, workspace, sources):
    # Inspect before resolve(), so a symlink cannot silently select another home.
    for candidate in (root, *root.parents):
        if candidate.is_symlink():
            raise PreparationError("Runtime root must not contain symlink ancestors")
    if root == workspace or root == Path(root.anchor):
        raise PreparationError("Runtime root must be a dedicated directory")
    for entry in sources["repositories"].values():
        source = (workspace / entry["checkout"]).resolve()
        if root == source or source in root.parents or root in source.parents:
            raise PreparationError("Runtime root must not contain or be inside a source checkout")


def disk_free(root):
    parent = root
    while not parent.exists():
        parent = parent.parent
    return shutil.disk_usage(parent).free / 1024 ** 3


def require_disk(root, minimum):
    available = disk_free(root)
    if available < minimum:
        raise PreparationError(f"Need {minimum} GiB free before writes/builds; found {available:.1f} GiB")


def save_new(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def source_report(workspace, sources):
    report = {}
    for name, entry in sources["repositories"].items():
        repo = workspace / entry["checkout"]
        if Path(git(repo, "rev-parse", "--show-toplevel")).resolve() != repo.resolve():
            raise PreparationError(f"{name}: checkout is not a repository root")
        if not canonical_origin(name, git(repo, "remote", "get-url", "origin")):
            raise PreparationError(f"{name}: origin is not the canonical PsyProtocol repository")
        git(repo, "cat-file", "-e", entry["commit"] + "^{commit}")
        report[name] = {
            "commit": entry["commit"], "checkout_head": git(repo, "rev-parse", "HEAD"),
            "dirty": bool(git(repo, "status", "--porcelain")),
            "source_directory": str(repo),
        }
    return report


def tool_failures(env=None):
    environment = dict(os.environ if env is None else env)
    failures = [f"Missing tool: {name}" for name in ("git", "cargo", "bun", "pnpm", "node", "make")
                if shutil.which(name, path=environment.get("PATH")) is None]
    if shutil.which("bun", path=environment.get("PATH")):
        version = run(["bun", "--version"], env=environment)
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
        if not match or tuple(map(int, match.groups())) < (1, 3, 14):
            failures.append(f"Bun {version}: workspace dependency workflow requires >= 1.3.14")
    return failures


def prepare(root, workspace, sources, source_hash, namespace, apply):
    report = source_report(workspace, sources)
    branch = f"local/{namespace}"
    if root.exists():
        raise PreparationError("Destination already exists; partial preparations are retained, never overwritten")
    for name, entry in sources["repositories"].items():
        branches = git(workspace / entry["checkout"], "for-each-ref", "--format=%(refname)", f"refs/heads/{branch}")
        if branches:
            raise PreparationError(f"{name}: branch {branch} already exists")
    plan = {"root": str(root), "branch": branch, "namespace": namespace, "sources": report}
    if not apply:
        return {"apply": False, **plan}
    require_disk(root, 150)
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    (root / "projects").mkdir()
    (root / "evidence").mkdir()
    save_new(root / "cohort.json", {"schema_version": 1, "source_manifest_sha256": source_hash, **plan})
    for name, entry in sources["repositories"].items():
        run(["git", "-C", workspace / entry["checkout"], "worktree", "add", "-b", branch,
             root / "projects" / name, entry["commit"]], capture=False)
    return {"prepared": True, **plan}


def validate_cohort(root, source_hash, sources):
    record = json.loads((root / "cohort.json").read_text())
    if record.get("root") != str(root) or record.get("source_manifest_sha256") != source_hash:
        raise PreparationError("Cohort ownership/source manifest does not match this invocation")
    for name, entry in sources["repositories"].items():
        repo = root / "projects" / name
        if repo.is_symlink() or Path(git(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
            raise PreparationError(f"{name}: expected the owned cohort worktree")
        if git(repo, "branch", "--show-current") != record["branch"]:
            raise PreparationError(f"{name}: cohort branch changed")
        git(repo, "merge-base", "--is-ancestor", entry["commit"], "HEAD")
    return record


def submodule_commands(projects):
    # Linked worktrees share local submodule URL overrides with their source.
    # Override only this invocation, without rewriting shared .git/config.
    command = ["git"]
    for name in ("psy-genesis", "psy-contracts", "psy-dapp"):
        command.extend(["-c", f"submodule.{name}.url=https://github.com/PsyProtocol/{name}.git"])
    commands = [entry for name in REPOSITORIES for entry in (
        (projects / name, ["git", "submodule", "init"]),
        (projects / name, [*command, "submodule", "update", "--init", "--recursive"]),
    )]
    commands.extend([
        (projects / "psy-node", [*command, "submodule", "update", "--init", "--checkout", "--", "psy-dapp"]),
        (projects / "psy-node/psy-dapp", ["git", "submodule", "init"]),
        (projects / "psy-node/psy-dapp", [*command, "submodule", "update", "--init", "--recursive"]),
    ])
    return commands


def build_environment(projects):
    env = {key: value for key, value in os.environ.items()
           if key not in SECRET_KEYS and not key.startswith("GUARDIAN_")
           and not key.startswith(("GIT_", "PSY_", "GENESIS_", "VITE_", "SKIP_"))
           and key not in {"CARGO_TARGET_DIR", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN"}}
    env.update({
        "PSY_NETWORK": "localhost", "PSY_CONFIG_PATH": str(projects / "psy-node/psy-genesis/config.json"),
        "PSY_PROJECTS_DIR": str(projects), "DARGO_STD_PATH": str(projects / "psy-compiler/psy-std/std.psy"),
        "RUSTFLAGS": "-C target-cpu=x86-64-v3 -C debuginfo=0", "CARGO_BUILD_JOBS": "4",
        "RAYON_NUM_THREADS": "4", "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
        "CARGO_CACHE_AUTO_CLEAN_FREQUENCY": "never",
        "VITE_NETWORK": "localhost", "VITE_PSY_STAGE": "localhost",
        "PSY_SKIP_CONFIG_SYNC": "1", "HUSKY": "0",
        "PSY_COMPILER_DIR": str(projects / "psy-compiler"),
        "PSY_GENESIS": str(projects / "psy-node/psy-genesis"),
        "GENESIS_CONTRACTS_DIR": str(projects / "psy-services/genesis_contracts"),
        "PSY_COMPILER_DARGO_BIN": str(projects / "psy-compiler/target/release/dargo"),
        "PSY_COMPILER_DARGO_STD_PATH": str(projects / "psy-compiler/psy-std/std.psy"),
    })
    tools = projects.parent / "tools/bin"
    if tools.is_dir():
        env["PATH"] = str(tools) + os.pathsep + env.get("PATH", os.defpath)
        env["COREPACK_HOME"] = str(projects.parent / "tools/corepack-cache")
        env["COREPACK_ENABLE_DOWNLOAD_PROMPT"] = "0"
    return env


def build_commands(projects, stage):
    node = projects / "psy-node"
    compiler = projects / "psy-compiler"
    sdk = projects / "psy-sdk/psy-ts-sdk"
    services = projects / "psy-services"
    contracts = projects / "psy-contracts"
    dapp = projects / "psy-dapp"
    wallet = projects / "psy-wallet"
    commands = {
        "compiler": [(compiler, ["cargo", "build", "--release", "--locked", "--bin", "dargo"])],
        "genesis-artifacts": [(compiler, ["make", "gen-deploy-json"])],
        "node": [(node, ["cargo", "build", "--release", "--locked",
                           *[value for binary in BINARIES["node"] for value in ("--bin", binary)]])],
        "sdk": [(sdk, ["pnpm", "install", "--frozen-lockfile"]),
                (sdk, ["pnpm", "--filter", "@psy-protocol/utils", "run", "build"]),
                (sdk, ["pnpm", "--filter", "@psy-protocol/psy-sdk", "run", "build"]),
                (sdk, ["pnpm", "--filter", "@psy-protocol/evm-wallet", "run", "build"])],
        "services": [(services, ["make", "sync-genesis-contract-abis"]),
                     (services, ["cargo", "build", "--release", "--locked", "--bin", "psy-services", "--bin", "psy-indexer"])],
        "contracts": [(contracts, ["pnpm", "install", "--frozen-lockfile"]), (contracts, ["pnpm", "run", "build"])],
        "clients": [(dapp, ["pnpm", "install", "--frozen-lockfile"]),
                    *[(dapp, ["pnpm", "run", f"build:{app}"]) for app in ("bridge", "explorer", "ide", "account")],
                    (wallet, ["pnpm", "install", "--frozen-lockfile"]), (wallet, ["pnpm", "run", "build:dev"])],
    }
    return commands[stage]


def describe_commands(commands):
    return [{"cwd": str(cwd), "argv": [str(value) for value in argv]} for cwd, argv in commands]


def input_identity(projects):
    # Hash tracked differences, not raw private state or inherited environment.
    record = {}
    for name in REPOSITORIES:
        repo = projects / name
        record[name] = {
            "head": git(repo, "rev-parse", "HEAD"),
            "diff_sha256": hashlib.sha256(git(repo, "diff", "HEAD", "--binary").encode()).hexdigest(),
            "submodules": git(repo, "submodule", "status", "--recursive"),
            "files_sha256": worktree_digest(repo),
        }
    return record


def worktree_digest(repo):
    checksum = hashlib.sha256()
    paths = git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")
    for relative in sorted(set(paths)):
        if not relative:
            continue
        path = repo / relative
        checksum.update(relative.encode() + b"\0")
        if path.is_symlink():
            checksum.update(os.readlink(path).encode())
        elif path.is_file():
            checksum.update(digest(path).encode())
        elif path.is_dir() and (path / ".git").exists():
            checksum.update(worktree_digest(path).encode())
        else:
            checksum.update(b"absent")
        checksum.update(b"\0")
    return checksum.hexdigest()


def check_submodules(projects):
    failures = []
    for name in REPOSITORIES:
        rows = git(projects / name, "submodule", "status", "--recursive").splitlines()
        failures.extend(f"{name}: initialize/align recorded submodule {row[1:].split()[1]}"
                        for row in rows if row and row[0] in "-+U")
    return failures


def verify_node_dependencies(projects, env, revision):
    owned = {}
    for relative in git(projects / "psy-node", "ls-files", "-z").split("\0"):
        if relative and Path(relative).name == "Cargo.toml":
            path = projects / "psy-node" / relative
            document = tomllib.loads(path.read_text())
            name = document.get("package", {}).get("name")
            if isinstance(name, str):
                owned[name] = path.resolve()
    # Cargo, rather than manifest spelling, determines the consumed source.
    for name in ("psy-compiler", "psy-sdk", "psy-services"):
        metadata = json.loads(run(["cargo", "metadata", "--locked", "--format-version", "1"], projects / name, env))
        packages = metadata["packages"]
        matched = 0
        for package in packages:
            source = package.get("source") or ""
            if "github.com/PsyProtocol/psy-node" in source and source.rsplit("#", 1)[-1] != revision:
                raise PreparationError(f"{name}: Cargo resolved another psy-node revision")
            if package["name"] in owned:
                matched += 1
                if not source and Path(package["manifest_path"]).resolve() != owned[package["name"]]:
                    raise PreparationError(f"{name}: Cargo resolved a Node crate outside the owned cohort")
                if source and ("github.com/PsyProtocol/psy-node" not in source or source.rsplit("#", 1)[-1] != revision):
                    raise PreparationError(f"{name}: Node crate resolved from another source")
        manifest = (projects / name / "Cargo.toml").read_text()
        if not matched or ("github.com/PsyProtocol/psy-node" not in manifest and "../psy-node/" not in manifest):
            raise PreparationError(f"{name}: no recognized psy-node dependency declarations")


def compiler_identity(compiler):
    revision = git(compiler, "rev-parse", "HEAD")
    entries = []
    for row in git(compiler, "ls-tree", "-r", "--full-tree", revision).splitlines():
        metadata, relative = row.split("\t", 1)
        _, kind, oid = metadata.split()
        path = Path(relative)
        eligible = relative != ".compiler-artifact.json" and (
            relative in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "Makefile"}
            or path.name in {"build.rs", "precompiles.json", "package.json"}
            or path.suffix.lower() in {".rs", ".psy", ".toml", ".lock"}
        )
        if kind == "blob" and eligible:
            entries.append((relative, oid))
    entries.sort(key=lambda entry: entry[0].encode())
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    raw = subprocess.run(["git", "-C", str(compiler), "cat-file", "--batch"],
                         input="".join(oid + "\n" for _, oid in entries).encode(),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=True).stdout
    checksum = hashlib.sha256()
    offset = 0
    for relative, oid in entries:
        end = raw.index(b"\n", offset)
        actual, kind, size = raw[offset:end].decode().split()
        if actual != oid or kind != "blob":
            raise PreparationError("Unexpected compiler Git blob response")
        start = end + 1
        checksum.update(relative.encode() + b"\0" + raw[start:start + int(size)] + b"\0")
        offset = start + int(size) + 1
    return {"compilerRevision": revision, "compilerSourcesHash": checksum.hexdigest()}


def artifact_failures(projects):
    failures = []
    compiler = projects / "psy-compiler"
    if git(compiler, "status", "--porcelain", "--untracked-files=all"):
        failures.append("compiler: commit reviewed source/dependency changes before generation")
    expected = compiler_identity(compiler)
    genesis = projects / "psy-node/psy-genesis"
    for label, path in (
        ("Genesis", genesis / ".genesis_contracts.compiler-artifact.json"),
        ("SDK", projects / "psy-sdk/psy-ts-sdk/packages/psy-sdk/.compiler-artifact.json"),
    ):
        if not path.is_file():
            failures.append(f"{label}: missing compiler provenance stamp")
            continue
        stamp = json.loads(path.read_text())
        if any(stamp.get(key) != value for key, value in expected.items()):
            failures.append(f"{label}: compiler revision/source hash mismatch; rebuild artifacts")
        if label == "Genesis":
            for filename, sha_key, size_key in (
                ("genesis_contracts.json", "artifactSha256", "artifactByteSize"),
                ("token.json", "tokenArtifactSha256", "tokenArtifactByteSize"),
                ("token.update.json", "tokenUpdateArtifactSha256", "tokenUpdateArtifactByteSize"),
            ):
                payload = genesis / filename
                if not payload.is_file() or digest(payload) != stamp.get(sha_key) or payload.stat().st_size != stamp.get(size_key):
                    failures.append(f"Genesis: missing or modified {filename}")
    return failures


def genesis_outputs(projects):
    compiler = projects / "psy-compiler"
    genesis = projects / "psy-node/psy-genesis"
    return [genesis / name for name in (
        "genesis_contracts.json", "token.json", "token.update.json", ".genesis_contracts.compiler-artifact.json",
    )] + [path for name in PRECOMPILES for path in (
        compiler / f"psy-precompiles/{name}/target/{name}.json",
        compiler / f"target/genesis_abi/{name}.abi.json",
    )]


def materialize_services_abis(root, projects):
    records = sorted((root / "evidence").glob("build-genesis-artifacts-*.json"))
    if not records:
        raise PreparationError("Run the recorded genesis-artifacts build before Services ABI synchronization")
    record = json.loads(records[-1].read_text())
    compiler = projects / "psy-compiler"
    if not record.get("passed") or record.get("compiler_identity") != compiler_identity(compiler):
        raise PreparationError("Latest Genesis artifact generation failed or compiler identity changed")
    for path in genesis_outputs(projects):
        if not path.resolve().is_relative_to(projects) or not path.is_file():
            raise PreparationError("A generated Genesis/ABI artifact is missing or outside the cohort")
        if record.get("outputs", {}).get(str(path.relative_to(projects))) != digest(path):
            raise PreparationError("Generated Genesis/ABI artifacts changed; regenerate the complete set")
    copies = []
    for name in PRECOMPILES:
        # Frozen Services already consumes multisig_policy from this directory.
        if name == "multisig_policy":
            continue
        source = compiler / f"target/genesis_abi/{name}.abi.json"
        target = compiler / f"psy-precompiles/{name}/target/{name}.abi.json"
        if not target.resolve().is_relative_to(compiler):
            raise PreparationError("Services ABI target is outside the owned compiler checkout")
        data = source.read_bytes()
        if target.is_symlink() or (target.exists() and target.read_bytes() != data):
            raise PreparationError("Existing Services ABI alias differs; retain it and review before regeneration")
        copies.append((target, data))
    # Validate the entire set before creating the first compatibility alias.
    for target, data in copies:
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(data)


def execute_build(root, projects, stage):
    failures = tool_failures(build_environment(projects)) + check_submodules(projects)
    if failures:
        raise PreparationError("; ".join(failures))
    require_disk(root, 100)
    if sys.platform != "linux" or "avx2" not in Path("/proc/cpuinfo").read_text().lower():
        raise PreparationError("This build profile requires Linux with AVX2; never reuse an AVX-512 binary")
    compiler = projects / "psy-compiler"
    if stage in {"genesis-artifacts", "sdk", "services"} and git(compiler, "status", "--porcelain", "--untracked-files=all"):
        raise PreparationError("Review and commit isolated compiler dependency edits before artifact generation")
    env = build_environment(projects)
    revision = json.loads((root / "cohort.json").read_text())["sources"]["psy-node"]["commit"]
    verify_node_dependencies(projects, env, revision)
    if stage == "services":
        # Consume the already generated ABI cohort. Recompiling here can overwrite
        # compiler targets independently of the retained Genesis provenance stamp.
        env.update({"SKIP_COMPILE": "1", "SKIP_DARGO_BUILD": "1"})
        materialize_services_abis(root, projects)
    commands = build_commands(projects, stage)
    locks = {str(path): digest(path) for name in REPOSITORIES
             for path in (projects / name / "Cargo.lock",) if path.is_file()}
    record = {
        "stage": stage, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commands": describe_commands(commands),
        "environment": {key: env[key] for key in sorted(ENVIRONMENT_KEYS | {"SKIP_COMPILE", "SKIP_DARGO_BUILD"}) if key in env},
        "inputs_before": input_identity(projects), "passed": False,
    }
    evidence = root / "evidence" / f"build-{stage}-{time.time_ns()}.json"
    try:
        for cwd, argv in commands:
            require_disk(root, 100)
            inputs = input_identity(projects) if stage in BINARIES and argv[0] == "cargo" else None
            run(argv, cwd, env, capture=False)
            if inputs is not None and inputs != input_identity(projects):
                raise PreparationError("Cohort source inputs changed during compilation; rebuild after review")
        for path, expected in locks.items():
            if digest(path) != expected:
                raise PreparationError("Build changed a Cargo lock; review retained output before proceeding")
        record["outputs"] = {}
        if stage == "genesis-artifacts":
            record["compiler_identity"] = compiler_identity(compiler)
            for path in genesis_outputs(projects):
                if not path.is_file() or path.stat().st_size == 0:
                    raise PreparationError("Genesis generation did not produce the complete ABI/artifact set")
                record["outputs"][str(path.relative_to(projects))] = digest(path)
        for binary in BINARIES.get(stage, ()):
            path = projects / f"psy-{stage}" / "target/release" / binary
            if not path.is_file() or not os.access(path, os.X_OK):
                raise PreparationError(f"Build did not produce executable {binary}")
            record["outputs"][str(path.relative_to(projects))] = digest(path)
        record["inputs_after"] = input_identity(projects)
        record["passed"] = True
    finally:
        save_new(evidence, record)
    return {"passed": True, "stage": stage, "evidence": str(evidence)}


def port_failures():
    failures = []
    for label, port in PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("0.0.0.0", port))
        except OSError as error:
            failures.append(f"{label}: cannot reserve TCP {port} ({error.strerror})")
    return failures


def preflight(root, projects, check_ports):
    failures = tool_failures(build_environment(projects)) + check_submodules(projects)
    failures.extend(artifact_failures(projects))
    revision = json.loads((root / "cohort.json").read_text())["sources"]["psy-node"]["commit"]
    for name in ("psy-compiler", "psy-sdk", "psy-services"):
        text = (projects / name / "Cargo.toml").read_text()
        pins = re.findall(r'github\.com/PsyProtocol/psy-node[^\n]*?rev\s*=\s*"([0-9a-f]+)"', text)
        if pins and set(pins) != {revision}:
            failures.append(f"{name}: Node Cargo pins still differ from this cohort")
    identity = input_identity(projects)
    for stage in ("node", "services"):
        records = sorted((root / "evidence").glob(f"build-{stage}-*.json"))
        if not records:
            failures.append(f"{stage}: no recorded release build")
            continue
        record = json.loads(records[-1].read_text())
        if not record.get("passed") or record.get("inputs_after") != identity:
            failures.append(f"{stage}: latest build failed or cohort inputs changed; rebuild after review")
        if not record.get("outputs"):
            failures.append(f"{stage}: build record has no output hashes")
        for relative, expected in record.get("outputs", {}).items():
            path = projects / relative
            if not path.is_file() or digest(path) != expected:
                failures.append(f"{stage}: binary missing or changed: {relative}")
    if disk_free(root) < 100:
        failures.append("Less than the 100-GiB build reserve remains")
    if check_ports:
        failures.extend(port_failures())
    return {"build_checks_passed": not failures, "runtime_ready": False,
            "failures": failures, "runtime_gates_pending": RUNTIME_GATES,
            "note": "Build checks are not artifact, Guardian quorum, P2P rotation or three-chain E2E acceptance."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=DIRECTORY.parents[2])
    parser.add_argument("--root", type=Path, required=True, help="New dedicated cohort root; never an existing deployment")
    parser.add_argument("--sources", type=Path, default=SOURCE_FILE)
    parser.add_argument("--namespace", default="psy-fresh-local-20261023")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    for command in ("prepare", "submodules", "deps", "build"):
        child = sub.add_parser(command)
        child.add_argument("--apply", action="store_true", help="Execute the displayed mutation/build")
        if command == "deps":
            child.add_argument("--mode", choices=("show", "node", "local"), default="show")
            child.add_argument("--allow-history-switch", action="store_true",
                               help="Explicitly adopt the frozen Node source after reviewing divergent consumed changes")
        if command == "build":
            child.add_argument("--stage", choices=("compiler", "genesis-artifacts", "sdk", "node", "services", "contracts", "clients"), required=True)
    check = sub.add_parser("preflight")
    check.add_argument("--ports", action="store_true", help="Also bind-check proposed ports; run on the host")
    args = parser.parse_args(argv)
    root = Path(os.path.abspath(args.root))
    workspace = args.workspace.resolve()
    sources = read_sources(args.sources)
    source_hash = digest(args.sources)
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", args.namespace):
        raise PreparationError("Namespace must be 1..32 lowercase letters/digits/hyphens")
    validate_root(root, workspace, sources)
    if args.command == "plan":
        result = {"sources": source_report(workspace, sources), "root": str(root),
                  "free_gib": round(disk_free(root), 1), "ports": PORTS,
                  "tool_failures": tool_failures(build_environment(root / "projects")),
                  "runtime_ready": False, "runtime_gates_pending": RUNTIME_GATES}
    elif args.command == "prepare":
        result = prepare(root, workspace, sources, source_hash, args.namespace, args.apply)
    else:
        validate_cohort(root, source_hash, sources)
        projects = root / "projects"
        if args.command == "preflight":
            result = preflight(root, projects, args.ports)
            print(json.dumps(result, indent=2))
            return 0 if result["build_checks_passed"] else 2
        if args.command == "submodules":
            commands = submodule_commands(projects)
        elif args.command == "deps":
            if args.allow_history_switch and args.mode != "node":
                raise PreparationError("--allow-history-switch requires deps --mode node")
            if args.apply:
                failures = tool_failures(build_environment(projects))
                if failures:
                    raise PreparationError("; ".join(failures))
            helper = projects / "psy-node/scripts/workspace.ts"
            mode = {"show": "show", "node": "use-node-commit", "local": "use-local"}[args.mode]
            command = ["bun", helper, "deps", mode, "--source", projects]
            if args.mode == "node":
                command.extend(["--rev", sources["repositories"]["psy-node"]["commit"]])
                if args.allow_history_switch:
                    command.append("--allow-history-switch")
            if args.apply:
                if args.mode == "show":
                    raise PreparationError("deps --mode show is read-only; omit --apply")
                command.append("--apply")
            commands = [(projects, command)]
        else:
            commands = build_commands(projects, args.stage)
        result = {"apply": args.apply, "commands": describe_commands(commands)}
        if args.command == "deps" and args.mode == "show":
            if args.apply:
                raise PreparationError("deps --mode show is read-only; omit --apply")
            for cwd, command in commands:
                run(command, cwd, build_environment(projects), capture=False)
        elif args.apply:
            # One preparation/build mutator per cohort. No stale-lock deletion.
            with (root / "operation.lock").open("a") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise PreparationError("Another cohort preparation/build operation is running")
                require_disk(root, 100)
                if args.command == "build":
                    result = execute_build(root, projects, args.stage)
                else:
                    for cwd, command in commands:
                        run(command, cwd, build_environment(projects), capture=False)
                    if args.command == "submodules":
                        failures = check_submodules(projects)
                        if failures:
                            raise PreparationError("; ".join(failures))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PreparationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error), "runtime_ready": False}), file=sys.stderr)
        sys.exit(2)
