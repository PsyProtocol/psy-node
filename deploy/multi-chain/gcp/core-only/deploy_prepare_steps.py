#!/usr/bin/env python3
"""Prepare-stage deploy steps: they hash, build locally and probe hosts, and never change a host."""
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys

import fresh_l1
import release_lock
from deploy_remote import DeployContext, RemoteError, Step, redact_tail


HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE
BUILD_SCRIPT = HERE.parents[2] / "scripts" / "build-linux-artifacts-bookworm.sh"
GIB = 1024 ** 3
# A full release target cache of the pinned workspace measured 21 GB; the output and logs add 0.4 GB.
MIN_BUILD_FREE_BYTES = 30 * GIB
# A host receives one package of a few hundred MB plus logs; database hosts are rebuilt whole.
MIN_HOST_FREE_BYTES = 5 * GIB
MAX_BUILD_ATTEMPTS = 20
PREFLIGHT_TIMEOUT_SECONDS = 600
BUILD_TIMEOUT_SECONDS = 3 * 3600
PACKAGE_TIMEOUT_SECONDS = 1800
HOST_TIMEOUT_SECONDS = 120
L1_LIMIT_SECONDS = 200
GAS_BUDGET_FIELDS = ("maxGasPriceWei", "maxTotalGas", "maxNativeSpendWei")
# fresh_l1.py reads its RPC config and env under /etc/parth and signs with the default keystore file.
SIGNER_CONFIG_PATH = "/etc/parth"
SIGNER_KEYSTORE_PATH = "/var/lib/parth/.psy/keystore"
SIGNER_KEYSTORE_FILE = SIGNER_KEYSTORE_PATH + "/bridge-relayer-dev"
STATUS_ARGV = ["/usr/bin/python3", "-I", "-B", "/dev/stdin", "status", "--rpc-preference", "protected-env-backup"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_sha256(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular file required")
        return hashlib.file_digest(stream, "sha256").hexdigest()


def disk_free(path):
    filesystem = os.statvfs(path)
    return filesystem.f_bavail * filesystem.f_frsize


def run_local(argv, timeout=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"local command timed out after {timeout}s") from None


def write_private_json(path, document):
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def write_state(ctx, name, document):
    write_private_json(ctx.state_dir / f"{name}.json", document)


def read_state(ctx, name):
    path = ctx.state_dir / f"{name}.json"
    require(path.is_file(), f"no recorded state for {name}; run its apply first")
    return release_lock.read_document(path)


def read_artifacts(ctx):
    return release_lock.read_document(ctx.release_dir / "artifacts.json")


def local_inputs(ctx):
    path = ctx.private_dir / "local-inputs.json"
    require(path.is_file(), "local-inputs.json not found in the operator-only directory")
    return release_lock.read_document(path)


def local_value(ctx, section, name):
    group = local_inputs(ctx).get(section)
    require(isinstance(group, dict) and name in group, f"local-inputs.json lacks {section}.{name}")
    return group[name]


def local_path(ctx, section, name):
    value = local_value(ctx, section, name)
    require(isinstance(value, str) and value.startswith("/") and ".." not in value.split("/"),
            f"local-inputs.json {section}.{name} must be an absolute path")
    return Path(value)


def check_tool_hash(ctx, name):
    require(ctx.lock["tool_sha256"].get(name) == file_sha256(TOOLS_DIR / name), f"tool hash differs: {name}")


def command_failure(command_name, result):
    return f"{command_name} failed (exit {result.returncode}): {redact_tail(result.stderr)}"


def verify_release_check(ctx):
    release_lock.validate_release_lock(ctx.lock, ctx.release_dir, True, ctx.private_dir)
    release_lock.check_tool_hashes(ctx.lock, TOOLS_DIR)


def verify_release_verify(ctx):
    argv = [sys.executable, "-B", str(ctx.release_dir / "preflight.py"),
            "--source", str(local_path(ctx, "build", "source")), "--config", str(local_path(ctx, "files", "config"))]
    result = run_local(argv, PREFLIGHT_TIMEOUT_SECONDS)
    try:
        report = json.loads(result.stdout)
    except ValueError:
        report = {}
    passed = (result.returncode == 0 and isinstance(report, dict) and report.get("blockers") == []
              and report.get("source_preflight_passed") is True and report.get("config_preflight_passed") is True)
    if not passed:
        blockers = report.get("blockers") if isinstance(report, dict) else None
        raise RuntimeError(f"preflight did not pass (exit {result.returncode}, blockers: {blockers})")
    return {"release_id": ctx.lock["release_id"], "lock_sha256": ctx.lock_sha256,
            "tools_checked": len(release_lock.TOOL_NAMES), "source_preflight_passed": True,
            "config_preflight_passed": True}


def build_settings(ctx):
    build = local_inputs(ctx).get("build")
    names = ("source", "builder_image", "caches", "output_root", "jobs")
    require(isinstance(build, dict) and all(name in build for name in names), "local-inputs.json build is incomplete")
    caches = build["caches"]
    require(isinstance(caches, dict) and set(caches) == {"cargo", "target", "go", "go_build"},
            "local-inputs.json build.caches needs cargo, target, go and go_build")
    for value in (build["source"], build["output_root"], *caches.values()):
        require(isinstance(value, str) and value.startswith("/") and ".." not in value.split("/"),
                "local-inputs.json build paths must be absolute")
    return build


def check_build_inputs(ctx):
    lock, artifacts = ctx.lock, read_artifacts(ctx)
    pins = (("config", local_path(ctx, "files", "config"), lock["inputs"]["runtime_config"], "the lock"),
            ("genesis_contracts", local_path(ctx, "files", "genesis_contracts"),
             artifacts.get("genesis_contracts_sha256"), "artifacts"),
            ("compiler_stamp", local_path(ctx, "files", "compiler_stamp"), artifacts.get("compiler_stamp_sha256"),
             "artifacts"),
            ("release_profile", ctx.release_dir / "release.json", lock["inputs"]["release_profile"], "the lock"))
    for label, path, expected, source in pins:
        require(expected, f"{label} is not pinned in {source}")
        require(file_sha256(path) == expected, f"{label} hash differs from {source}")


def check_disk(settings):
    places = [(f"cache {name}", Path(path)) for name, path in settings["caches"].items()]
    places.append(("output", Path(settings["output_root"])))
    for label, path in places:
        free = disk_free(path)
        require(free >= MIN_BUILD_FREE_BYTES, f"free disk {free // GIB} GiB below the "
                f"{MIN_BUILD_FREE_BYTES // GIB} GiB the build needs at {label}")


def rebuild_check(ctx):
    settings = build_settings(ctx)
    require(BUILD_SCRIPT.is_file(), "build script not found")
    check_build_inputs(ctx)
    if find_build(ctx, settings)[0] is None:
        check_disk(settings)


def attempt_dir(ctx, settings, number):
    return Path(settings["output_root"]) / f"{ctx.lock['release_id']}-{ctx.lock['sources']['runtime'][:12]}-build-{number}"


def find_build(ctx, settings):
    """Return (first completed build directory or None, number of the first unused attempt)."""
    for number in range(1, MAX_BUILD_ATTEMPTS + 1):
        directory = attempt_dir(ctx, settings, number)
        if not os.path.lexists(directory):
            return None, number
        if (directory / "manifest.json").is_file():
            return directory, number
    raise ValueError(f"{MAX_BUILD_ATTEMPTS} build attempts exist; review the failed ones first")


def build_spec(ctx, settings, output):
    lock = ctx.lock
    def pinned_file(path, digest):
        return {"path": str(path), "sha256": digest}
    return {"schema_version": 2, "source": {"path": settings["source"], "commit": lock["sources"]["runtime"]},
            "inputs": {"config": pinned_file(local_path(ctx, "files", "config"), lock["inputs"]["runtime_config"]),
                       "bundle": pinned_file(local_path(ctx, "files", "genesis_contracts"),
                                       read_artifacts(ctx)["genesis_contracts_sha256"]),
                       "bundle_stamp": pinned_file(local_path(ctx, "files", "compiler_stamp"),
                                             read_artifacts(ctx)["compiler_stamp_sha256"]),
                       "release_profile": pinned_file(ctx.release_dir / "release.json", lock["inputs"]["release_profile"])},
            "builder_image": settings["builder_image"], "caches": dict(settings["caches"]), "output": str(output),
            "jobs": settings["jobs"]}


def rebuild_apply(ctx):
    settings = build_settings(ctx)
    completed, number = find_build(ctx, settings)
    if completed is not None:
        check_build_output(ctx, completed)
        return
    output = attempt_dir(ctx, settings, number)
    spec_path = ctx.private_dir / f"{output.name}-spec.json"
    write_private_json(spec_path, build_spec(ctx, settings, output))
    result = run_local(["bash", str(BUILD_SCRIPT), "--pinned-node-spec", str(spec_path)], BUILD_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise RuntimeError(command_failure("build script", result))


def check_build_output(ctx, directory):
    manifest_path = directory / "manifest.json"
    manifest = release_lock.read_document(manifest_path)
    artifacts = read_artifacts(ctx)
    require(manifest.get("source_commit") == ctx.lock["sources"]["runtime"], "source commit differs from the lock")
    require(manifest.get("config_sha256") == ctx.lock["inputs"]["runtime_config"], "config hash differs from the lock")
    require(manifest.get("genesis_contracts_sha256") == artifacts.get("genesis_contracts_sha256"),
            "genesis_contracts hash differs from artifacts")
    hashes = {}
    for name in release_lock.CLI_BINARIES:
        actual = file_sha256(directory / name)
        require(manifest.get("binaries", {}).get(name) == actual, f"manifest binary hash differs from the file: {name}")
        require(artifacts.get("binaries", {}).get(name) == actual, f"{name} hash differs from artifacts")
        require(ctx.lock["binaries"][name] == actual, f"{name} hash differs from the lock")
        hashes[name] = actual
    return {"build": directory.name, "binaries": hashes, "manifest_sha256": file_sha256(manifest_path)}


def rebuild_verify(ctx):
    settings = build_settings(ctx)
    completed, _ = find_build(ctx, settings)
    require(completed is not None, "no completed build found")
    result = check_build_output(ctx, completed)
    write_state(ctx, "rebuild_binaries", {"build_dir": str(completed)})
    return result


def rebuilt_binary(ctx, name):
    path = Path(read_state(ctx, "rebuild_binaries")["build_dir"]) / name
    require(path.is_file(), f"rebuilt binary not found: {name}")
    return path


def artifact_pins(ctx):
    lock, artifacts = ctx.lock, read_artifacts(ctx)
    groth16 = lock["groth16"]
    return [("genesis", lock["inputs"]["genesis"]), ("config", lock["inputs"]["runtime_config"]),
            ("canonical_config", lock["inputs"]["canonical_config"]),
            ("genesis_contracts", artifacts.get("genesis_contracts_sha256")),
            ("compiler_stamp", artifacts.get("compiler_stamp_sha256")),
            ("psy_services", lock["binaries"]["psy-services"]), ("psy_indexer", lock["binaries"]["psy-indexer"]),
            ("groth16_setup_manifest", groth16["setup_manifest_sha256"]),
            *[(name, groth16["verifiers"][name]) for name in release_lock.GROTH16_VERIFIERS],
            ("l1_bundle_manifest", lock["l1"]["bundle_sha256"]), ("l1_policy", lock["l1"]["policy_sha256"])]


def gas_budget(ctx, chain):
    """Return (parsed budget, sha256) of the release's gas budget for one chain, checked against the lock."""
    expected = ctx.lock["l1"]["gas_budget_sha256"][chain]
    require(expected, f"gas budget {chain} is not pinned in the lock")
    path = ctx.release_dir / f"fresh_l1_gas_budget.{chain}.json"
    require(path.is_file(), f"gas budget file missing: {chain}")
    digest = file_sha256(path)
    require(digest == expected, f"gas budget {chain} hash differs from the lock")
    return release_lock.read_document(path), digest


def artifacts_check(ctx):
    for label, expected in artifact_pins(ctx):
        require(expected, f"{label} is not pinned in the lock")
        require(local_path(ctx, "files", label).is_file(), f"{label}: file not found")
    for chain in release_lock.CHAINS:
        gas_budget(ctx, chain)


def artifacts_verify(ctx):
    verified = {}
    for label, expected in artifact_pins(ctx):
        require(expected, f"{label} is not pinned in the lock")
        actual = file_sha256(local_path(ctx, "files", label))
        require(actual == expected, f"{label} hash differs from the lock")
        verified[label] = actual
    bundle_manifest = local_path(ctx, "files", "l1_bundle_manifest")
    require(bundle_manifest.name == "manifest.json", "l1_bundle_manifest must be the manifest.json of the bundle")
    fresh_l1.verify_bundle(bundle_manifest.parent, ctx.lock["l1"]["bundle_sha256"])
    return {"verified": verified, "gas_budgets": {chain: gas_budget(ctx, chain)[1] for chain in release_lock.CHAINS}}


@dataclass(frozen=True)
class PackageBuilder:
    """One package family: build prepares (or finds) its output and returns the path; verify reads it back."""
    name: str
    inputs: tuple
    build: Callable[[DeployContext, dict], Path]
    verify: Callable[[DeployContext, dict, Path], dict]
    check: Callable[[DeployContext, dict], None] = None


def core_build(ctx, inputs):
    output = Path(inputs["output"])
    if output.exists():
        return output  # prepare_host_packages publishes atomically; verification judges the content
    node = rebuilt_binary(ctx, "psy_node_cli")
    require(file_sha256(node) == ctx.lock["binaries"]["psy_node_cli"], "node binary differs from the lock")
    argv = [sys.executable, "-B", str(HERE / "prepare_host_packages.py"),
            "--release-lock", str(ctx.release_dir / "release-lock.json"), "--release-lock-sha256", ctx.lock_sha256,
            "--config", str(local_path(ctx, "files", "config")), "--genesis", str(local_path(ctx, "files", "genesis")),
            "--node-binary", str(node), "--private-keys", inputs["registration_keys"],
            "--faucet-operators", inputs["faucet_operators"], "--p2p-keys", inputs["p2p_keys"],
            "--output", str(output)]
    result = run_local(argv, PACKAGE_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise RuntimeError(command_failure("prepare_host_packages", result))
    return output


def check_host_package(ctx, host, root, expected_manifest):
    manifest_path = root / "manifest.json"
    require(manifest_path.is_file() and file_sha256(manifest_path) == expected_manifest,
            f"{host}: package manifest hash differs from artifacts")
    files = release_lock.read_document(manifest_path)["files"]
    on_disk = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()} - {"manifest.json"}
    require(on_disk == set(files), f"{host}: package files differ from the manifest")
    for name, digest in files.items():
        require(file_sha256(root / name) == digest, f"{host}: package file hash differs: {name}")
    lock = ctx.lock
    pinned = {"bin/psy_node_cli": lock["binaries"]["psy_node_cli"], "config.json": lock["inputs"]["runtime_config"],
              "genesis.json": lock["inputs"]["genesis"]}
    for name, expected in pinned.items():
        require(files.get(name) == expected, f"{host}: {name} differs from the lock")


def core_verify(ctx, inputs, output):
    expected = read_artifacts(ctx).get("core_host_packages", {}).get("manifest_sha256")
    hosts = sorted(release_lock.read_document(ctx.release_dir / "topology.json")["hosts"])
    require(isinstance(expected, dict) and sorted(expected) == hosts, "artifacts core_host_packages differ from the topology")
    require(output.is_dir() and sorted(p.name for p in output.iterdir()) == hosts,
            "package hosts differ from the topology")
    for host in hosts:
        check_host_package(ctx, host, output / host, expected[host])
    return {"hosts": len(hosts), "manifest_sha256": dict(expected)}


PROXY_ROLES = ("system", "user")


def proxy_pin(ctx, name):
    pinned = read_artifacts(ctx).get("proxy_packages", {}).get(name)
    require(pinned, f"artifacts proxy_packages.{name} is not pinned")
    return pinned


def proxy_tool_argv(ctx, action, *arguments):
    check_tool_hash(ctx, "prepare_proxies.py")
    return [sys.executable, "-B", str(HERE / "prepare_proxies.py"), action,
            "--release-lock", str(ctx.release_dir / "release-lock.json"), "--release-lock-sha256", ctx.lock_sha256,
            *arguments]


BUILD_FIELDS = ("source_commit", "network", "config_sha256", "local_circuits_sha256")
BUILD_BINARIES = ("psy_user_cli", "psy_relayer_cli")


def narrow_build_document(build):
    """The fields the proxy tool reads; the full build record holds hundreds of local library paths."""
    for name in BUILD_FIELDS:
        require(isinstance(build.get(name), str) and build[name], f"build record lacks {name}")
    binaries = build.get("binaries")
    require(isinstance(binaries, dict) and all(isinstance(binaries.get(name), str) for name in BUILD_BINARIES),
            "build record lacks the user and relayer binary hashes")
    return {**{name: build[name] for name in BUILD_FIELDS}, "binaries": {name: binaries[name] for name in BUILD_BINARIES}}


def proxy_check(ctx, inputs):
    check_tool_hash(ctx, "prepare_proxies.py")
    proxy_pin(ctx, "rpc_endpoints_sha256")


def proxy_role_arguments(ctx, inputs, role, binary, build_file, output):
    arguments = ["--role", role, "--source-commit", ctx.lock["sources"]["runtime"], "--binary", str(binary),
                 "--binary-manifest", str(build_file), "--binary-manifest-sha256", file_sha256(build_file),
                 "--network-config", str(local_path(ctx, "files", "config")),
                 "--rpc-endpoints", inputs["rpc_endpoints"], "--rpc-endpoints-sha256", proxy_pin(ctx, "rpc_endpoints_sha256"),
                 "--output", str(output / role)]
    if role == "system":
        setup_hash = ctx.lock["groth16"]["setup_manifest_sha256"]
        require(setup_hash, "groth16.setup_manifest_sha256 is not pinned in the lock")
        arguments += ["--setup-dir", inputs["setup_dir"], "--verifier-dir", inputs["verifier_dir"],
                      "--setup-manifest", str(local_path(ctx, "files", "groth16_setup_manifest")),
                      "--setup-manifest-sha256", setup_hash]
    return arguments


def proxy_build(ctx, inputs):
    output = Path(inputs["output"])
    if output.exists():
        return output  # verification judges what is there
    binary = rebuilt_binary(ctx, "psy_user_cli")
    require(file_sha256(binary) == ctx.lock["binaries"]["psy_user_cli"], "user binary differs from the lock")
    narrow = narrow_build_document(release_lock.read_document(binary.parent / "manifest.json"))
    build_file = ctx.state_dir / "proxy-build-input.json"
    write_private_json(build_file, narrow)
    partial = output.with_name(output.name + ".partial")
    require(not partial.exists(), "a partial proxy package output exists; inspect it first")
    argvs = [proxy_tool_argv(ctx, "package", *proxy_role_arguments(ctx, inputs, role, binary, build_file, partial))
             for role in PROXY_ROLES]
    partial.mkdir(mode=0o700)
    for role, argv in zip(PROXY_ROLES, argvs):
        outcome = run_local(argv, PACKAGE_TIMEOUT_SECONDS)
        if outcome.returncode != 0:
            raise RuntimeError(command_failure(f"prepare_proxies package {role}", outcome))
    partial.rename(output)
    return output


def proxy_verify(ctx, inputs, output):
    require(output.is_dir() and sorted(path.name for path in output.iterdir()) == sorted(PROXY_ROLES),
            "proxy package roles differ from system and user")
    reports = {}
    for role in PROXY_ROLES:
        package = output / role
        package_sha256 = file_sha256(package / "package.json")
        argv = proxy_tool_argv(ctx, "verify", "--package", str(package), "--package-sha256", package_sha256)
        outcome = run_local(argv, PACKAGE_TIMEOUT_SECONDS)
        if outcome.returncode != 0:
            raise RuntimeError(command_failure(f"prepare_proxies verify {role}", outcome))
        approval = release_lock.read_document(package / "package.json")
        require(approval["installer_sha256"] == ctx.lock["tool_sha256"]["prepare_proxies.py"],
                f"{role} package installer differs from the reviewed tool")
        reports[role] = {"package_sha256": package_sha256}
    return reports


# Adding a package family (Worker, Faucet) is one line here plus its packages.<name> input.
PACKAGE_BUILDERS = [PackageBuilder("core", ("registration_keys", "faucet_operators", "p2p_keys", "output"), core_build,
                                  core_verify),
                    PackageBuilder("proxy", ("rpc_endpoints", "setup_dir", "verifier_dir", "output"), proxy_build,
                                  proxy_verify, proxy_check)]


def packages_check(ctx):
    names = [builder.name for builder in PACKAGE_BUILDERS]
    for name in names:
        require(names.count(name) == 1, f"duplicate package builder: {name}")
    for builder in PACKAGE_BUILDERS:
        values = local_value(ctx, "packages", builder.name)
        require(isinstance(values, dict), f"local-inputs.json packages.{builder.name} must be an object")
        for name in builder.inputs:
            require(name in values, f"local-inputs.json lacks packages.{builder.name}.{name}")
            require(isinstance(values[name], str) and values[name].startswith("/") and ".." not in values[name].split("/"),
                    f"local-inputs.json packages.{builder.name}.{name} must be an absolute path")
        if builder.check is not None:
            builder.check(ctx, values)


def packages_apply(ctx):
    outputs = {builder.name: str(builder.build(ctx, local_value(ctx, "packages", builder.name)))
               for builder in PACKAGE_BUILDERS}
    write_state(ctx, "prepare_packages", outputs)


def packages_verify(ctx):
    outputs = read_state(ctx, "prepare_packages")
    results = {}
    for builder in PACKAGE_BUILDERS:
        require(builder.name in outputs, f"no recorded output for package builder {builder.name}")
        results[builder.name] = builder.verify(ctx, local_value(ctx, "packages", builder.name),
                                               Path(outputs[builder.name]))
    return {"packages": results}


def release_hosts(ctx):
    topology = release_lock.read_document(ctx.release_dir / "topology.json")["hosts"]
    return sorted(set(topology) | set(ctx.lock["hosts"]))


def retained_secret_paths(ctx):
    """Return ({host: [paths]}, [local paths]) of the retained paths with kind secret."""
    path = ctx.private_dir / "retained-paths.json"
    require(path.is_file() and file_sha256(path) == ctx.lock["inputs"]["retained_paths"],
            "retained-paths.json differs from the lock")
    remote, local = {}, []
    for retained_path in release_lock.read_document(path)["paths"]:
        if retained_path["kind"] != "secret":
            continue
        if retained_path["host"] == "local":
            local.append(retained_path["path"])
        else:
            remote.setdefault(retained_path["host"], []).append(retained_path["path"])
    outside = sorted(set(remote) - set(release_hosts(ctx)))
    require(not outside, f"retained path for a host outside the release: {outside[0] if outside else ''}")
    return remote, local


def probe_script(mode, paths):
    lines = ["set -uo pipefail", "echo \"avail=$(df -B1 --output=avail / | awk 'NR==2 {print $1}')\""]
    prefix = "LC_ALL=C "
    if mode == "passwordless":
        prefix = "sudo -n -- env LC_ALL=C "
        lines.append("if sudo -n -- true 2>/dev/null; then echo sudo=ok; else echo sudo=denied; fi")
    lines += ["check() {", f'  if out=$({prefix}stat -c %F -- "$2" 2>&1); then echo "$1 present"',
              '  elif [[ "$out" == *"No such file"* ]]; then echo "$1 missing"',
              '  else echo "$1 denied"; fi', "}"]
    lines += [f"check {index} {shlex.quote(path)}" for index, path in enumerate(paths)]
    return "\n".join(lines) + "\n"


def parse_probe(host, output, count):
    values = dict(line.split("=", 1) for line in output.splitlines() if re.fullmatch(r"(avail|sudo)=\S+", line))
    states = dict(line.split(" ", 1) for line in output.splitlines()
                  if re.fullmatch(r"\d+ (present|missing|denied)", line))
    require("avail" in values and len(states) == count, f"{host}: probe output incomplete")
    return values, states


def probe_host(ctx, host, paths, failures):
    mode = ctx.remote.sudo_mode(host)
    values, states = parse_probe(host, ctx.remote.run_script(host, probe_script(mode, paths), HOST_TIMEOUT_SECONDS),
                                 len(paths))
    free = int(values["avail"])
    if free < MIN_HOST_FREE_BYTES:
        failures.append(f"{host}: free disk {free // GIB} GiB below {MIN_HOST_FREE_BYTES // GIB} GiB")
    if mode == "passwordless" and values.get("sudo") != "ok":
        failures.append(f"{host}: no-prompt sudo denied")
    unverified = 0
    for index in range(len(paths)):
        state = states[str(index)]
        if state == "missing":
            failures.append(f"{host}: retained path #{index} missing (position among this host's retained sensitive paths)")
        elif state == "denied" and mode == "operator":
            unverified += 1
        elif state == "denied":
            failures.append(f"{host}: cannot stat retained path #{index} (position among this host's retained sensitive paths)")
    return {"sudo": mode, "free_gib": free // GIB, "unverified_paths": unverified}


def get_signer_host(ctx, remote_paths):
    named = ctx.lock["l1"]["signer_host"]
    derived = sorted(host for host, paths in remote_paths.items()
                     if SIGNER_CONFIG_PATH in paths and SIGNER_KEYSTORE_PATH in paths)
    require(derived == [named], f"signer host {named} differs from the retained paths, which name {derived}")
    require(SIGNER_KEYSTORE_FILE in remote_paths[named], f"signer host {named} does not retain the signer keystore file")
    return named


def read_status_source(ctx):
    raw = (TOOLS_DIR / "fresh_l1.py").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ctx.lock["tool_sha256"]["fresh_l1.py"], "tool hash differs: fresh_l1.py")
    return raw.decode()


def read_l1_reports(ctx, host):
    require(ctx.remote.sudo_mode(host) == "passwordless", "signer host needs no-prompt sudo for the L1 status read")
    output = ctx.remote.run_root_text(host, STATUS_ARGV, L1_LIMIT_SECONDS, stdin_text=read_status_source(ctx),
                                       show_stderr=True)
    try:
        reports = json.loads(output)
    except ValueError:
        reports = None
    require(isinstance(reports, list) and all(isinstance(report, dict) for report in reports),
            "L1 status output is not a JSON list of reports")
    by_chain = {report.get("network"): report for report in reports}
    require(len(reports) == len(by_chain) and set(by_chain) == set(release_lock.CHAINS),
            "L1 status chains differ from the release chains")
    return by_chain


def decimal(value, label):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value), f"{label} must be an unsigned decimal")
    return int(value)


def budget_numbers(ctx, chain):
    budget, _ = gas_budget(ctx, chain)
    fresh_l1.validate_budget(budget, chain)
    numbers = {field: int(budget[field]) for field in GAS_BUDGET_FIELDS}
    return numbers["maxTotalGas"] * numbers["maxGasPriceWei"], numbers


def check_chain(ctx, chain, report, failures):
    required, numbers = budget_numbers(ctx, chain)
    expected_id = fresh_l1.NETWORKS[chain][0]
    if report.get("chain_id") != expected_id:
        failures.append(f"{chain}: chain id {report.get('chain_id')} differs from {expected_id}")
    if str(report.get("signer", "")).lower() != ctx.lock["l1"]["signer"].lower():
        failures.append(f"{chain}: signer differs from the lock")
    latest, pending = report.get("nonce_latest"), report.get("nonce_pending")
    if type(latest) is not int or latest != pending:
        failures.append(f"{chain}: pending nonce {pending} differs from latest {latest}; the old Relayer may still "
                        "be broadcasting from this wallet until it is stopped")
    required = max(required, numbers["maxNativeSpendWei"])
    balance, price = decimal(report.get("balance_wei"), "balance"), decimal(report.get("gas_price_wei"), "gas price")
    if balance < required:
        failures.append(f"{chain}: balance {balance} below required {required}")
    if price > numbers["maxGasPriceWei"]:
        failures.append(f"{chain}: gas price {price} above the approved cap {numbers['maxGasPriceWei']}")
    return {"balance_wei": str(balance), "required_wei": str(required), "gas_price_wei": str(price),
            "gas_price_cap_wei": str(numbers["maxGasPriceWei"]), "nonce": latest}


def collect(failures, action):
    """Run one check; a failure is recorded and the remaining checks still run."""
    try:
        return action()
    except (ValueError, RemoteError) as error:
        failures.append(str(error))
        return None


def hosts_check(ctx):
    check_tool_hash(ctx, "fresh_l1.py")
    remote_paths, _ = retained_secret_paths(ctx)
    get_signer_host(ctx, remote_paths)
    for chain in release_lock.CHAINS:
        budget_numbers(ctx, chain)


def hosts_verify(ctx):
    remote_paths, local_paths = retained_secret_paths(ctx)
    failures, hosts, l1 = [], {}, {}
    for host in release_hosts(ctx):
        found = collect(failures, lambda: probe_host(ctx, host, remote_paths.get(host, []), failures))
        if found is not None:
            hosts[host] = found
    for index, path in enumerate(local_paths):
        if not os.path.lexists(path):
            failures.append(f"local retained path #{index} missing")
    signer = collect(failures, lambda: get_signer_host(ctx, remote_paths))
    reports = signer and collect(failures, lambda: read_l1_reports(ctx, signer))
    for chain in release_lock.CHAINS if reports else ():
        l1[chain] = collect(failures, lambda: check_chain(ctx, chain, reports[chain], failures))
    import deploy_clear_steps  # imported here: that module imports this one
    fleet = collect(failures, lambda: deploy_clear_steps.dry_run_fleet(ctx))
    if failures:
        raise ValueError("\n".join(failures))
    return {"hosts": hosts, "operator_hosts": sorted(host for host, found in hosts.items() if found["sudo"] == "operator"),
            "local_paths": len(local_paths), "l1": l1, "clear_dry_run": fleet}


def nothing(ctx):
    return None


PREPARE_STEPS = {
    "verify_release": Step("verify_release", verify_release_check, nothing, verify_release_verify),
    "rebuild_binaries": Step("rebuild_binaries", rebuild_check, rebuild_apply, rebuild_verify),
    "verify_artifacts": Step("verify_artifacts", artifacts_check, nothing, artifacts_verify),
    "prepare_packages": Step("prepare_packages", packages_check, packages_apply, packages_verify),
    "check_hosts": Step("check_hosts", hosts_check, nothing, hosts_verify),
}
