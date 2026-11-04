#!/usr/bin/env python3
"""Build the Guardian, Relayer, Services and Envio packages of one release; local only, never touches a host.

Step 54 calls build_bridge_packages(ctx, None): every input except the L1 documents is validated and the packages are
planned. Step 70 calls it with the real documents of the deployed contracts and the packages become installable.

Operator inputs live in local-inputs.json under packages.bridge, packages.services and packages.envio; see the
release README. Guardian and Relayer packages follow the package.json contract that deploy_bridge_steps reads.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import deploy_prepare_steps as prepare
import install_envio
import prepare_envio
import prepare_services_inputs
import prepare_services_packages
import release_lock

GUARDIAN_TOOLS = ("install_guardian.py", "guardian_exec.py", "activate_bridge.py", "install_relayer.py")
RELAYER_TOOLS = ("install_relayer.py", "relayer_exec.py", "install_guardian.py", "activate_bridge.py")
GUARDIAN_FIELDS = ("guardian_id", "hostname", "address", "guardian_history", "proof_origins", "service_user",
                   "memory_high_gib", "memory_max_gib", "custody_keystore_sha256")
RELAYER_FIELDS = ("hostname", "address", "guardian_history", "service_user", "memory_high_gib", "memory_max_gib",
                  "keystore_owner", "l1_keystore", "password_credential")
PENDING_MARKER = ".bridge-packages-pending"
PLAN_TIMEOUT_SECONDS = 300
BUILD_TIMEOUT_SECONDS = 3 * 3600
POSTGRES_ALIAS = "gcp-postgres"
POSTGRES_PORT = 5432


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write_new(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def bridge_inputs(ctx):
    values = prepare.local_value(ctx, "packages", "bridge")
    names = ("output_root", "guardian_placement", "guardian_rpc_config", "relayer_spec", "relayer_rpc_config",
             "relayer_daemon_config")
    prepare.require(isinstance(values, dict) and all(isinstance(values.get(name), str) and values[name].startswith("/")
                                                     for name in names), "local-inputs packages.bridge is incomplete")
    return values


def deployment_address(ctx, address):
    aliases = [alias for alias, value in ctx.lock["hosts"].items() if value == address]
    prepare.require(len(aliases) == 1, f"address {address} must belong to exactly one release host")
    return aliases[0]


def output_directory(ctx, l1_documents):
    root = Path(bridge_inputs(ctx)["output_root"])
    if l1_documents is None:
        return root / "pending"
    pins = sorted((chain, name, row[name]["sha256"]) for chain, row in l1_documents.items() for name in row)
    return root / ("final-" + sha256_bytes(json.dumps(pins).encode())[:12])


def clear_pending(directory):
    """A pending set is scratch: it is replaced, but only when it carries this module's marker."""
    if not directory.exists():
        return
    prepare.require((directory / PENDING_MARKER).is_file(), f"{directory.name} exists and is not a pending package set")
    shutil.rmtree(directory)


def build_document(ctx):
    lock = ctx.lock
    build_dir = Path(prepare.read_state(ctx, "rebuild_binaries")["build_dir"])
    manifest = release_lock.read_document(build_dir / "manifest.json")
    prepare.require(manifest.get("source_commit") == lock["sources"]["runtime"], "build source differs from the lock")
    prepare.require(manifest.get("config_sha256") == lock["inputs"]["runtime_config"], "build config differs from the lock")
    return {"source_commit": lock["sources"]["runtime"], "network": lock["network"],
            "config_sha256": lock["inputs"]["runtime_config"], "binaries": {"psy_relayer_cli": lock["binaries"]["psy_relayer_cli"]}}


def l1_files(l1_documents):
    """Map package file names to local document paths; Guardian and Relayer read the summary and the Bridge receipt."""
    files = {}
    for chain, row in (l1_documents or {}).items():
        for name, filename in (("summary", "deployed-contracts.json"), ("bridge_receipt", "Bridge_Proxy.json")):
            path = Path(row[name]["path"])
            prepare.require(prepare.file_sha256(path) == row[name]["sha256"], f"{chain}: {name} differs from its recorded hash")
            files[f"{chain}/{filename}"] = path
    return files


def artifact(directory, base, name):
    return {"path": f"{base}/{name}", "sha256": prepare.file_sha256(directory / name)}


def operator_spec(role, fields, directory, base, document_names, wrapper):
    """The installer's operator spec; base is the directory the installer will read, local for plan, stage for the host."""
    spec = {"version": 3, **fields, "build": artifact(directory, base, "build.json"),
            "binary": artifact(directory, base, "psy_relayer_cli"), "canonical_config": artifact(directory, base, "canonical.json"),
            "rpc_config": artifact(directory, base, "rpc.json"), "wrapper": artifact(directory, base, wrapper)}
    if role == "relayer":
        spec["daemon_config"] = artifact(directory, base, "daemon.toml")
    documents = {}
    for name in document_names:
        chain, filename = name.split("/")
        documents.setdefault(chain, {})["summary" if filename == "deployed-contracts.json" else "receipt"] = artifact(directory, base, name)
    spec["l1_documents"] = documents
    return spec


def plan_locally(ctx, tool, spec, directory):
    """Run the lock-pinned installer's plan mode on a local copy of the spec; the remote spec points at the stage."""
    path = directory / "plan-spec.json"
    write_new(path, encode(spec))
    argv = [sys.executable, "-B", str(prepare.TOOLS_DIR / tool), "plan", "--release-lock", str(ctx.release_dir / "release-lock.json"),
            "--release-lock-sha256", ctx.lock_sha256, "--spec", str(path), "--spec-sha256", prepare.file_sha256(path)]
    result = prepare.run_local(argv, PLAN_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise RuntimeError(prepare.command_failure(f"{tool} plan", result))


def write_component(ctx, role, host, directory, fields, rpc_config, documents, label, guardian_id=None):
    """Write one Guardian or Relayer package (files, remote spec, package.json) after a local plan run."""
    lock = ctx.lock
    tools = GUARDIAN_TOOLS if role == "guardian" else RELAYER_TOOLS
    wrapper = "guardian_exec.py" if role == "guardian" else "relayer_exec.py"
    for tool in tools:
        prepare.check_tool_hash(ctx, tool)
        write_new(directory / tool, (prepare.TOOLS_DIR / tool).read_bytes())
    config = prepare.local_path(ctx, "files", "config")
    prepare.require(prepare.file_sha256(config) == lock["inputs"]["runtime_config"], "runtime config differs from the lock")
    binary = prepare.rebuilt_binary(ctx, "psy_relayer_cli")
    prepare.require(prepare.file_sha256(binary) == lock["binaries"]["psy_relayer_cli"], "relayer binary differs from the lock")
    write_new(directory / "build.json", encode(build_document(ctx)))
    write_new(directory / "canonical.json", config.read_bytes())
    write_new(directory / "rpc.json", Path(rpc_config).read_bytes())
    write_new(directory / "psy_relayer_cli", binary.read_bytes(), 0o700)
    if role == "relayer":
        write_new(directory / "daemon.toml", Path(bridge_inputs(ctx)["relayer_daemon_config"]).read_bytes())
    document_files = l1_files(documents)
    for name, path in document_files.items():
        write_new(directory / name, path.read_bytes())
    plan_locally(ctx, f"install_{role}.py", operator_spec(role, fields, directory, str(directory), list(document_files), wrapper), directory)
    stage_dir = f"/var/tmp/psy-{role}-{lock['units']['core_namespace_prefix']}-{label}"
    write_new(directory / "operator.json", encode(operator_spec(role, fields, directory, stage_dir, list(document_files), wrapper)))
    files = {str(path.relative_to(directory)): prepare.file_sha256(path) for path in sorted(directory.rglob("*"))
             if path.is_file() and path.name not in ("package.json", "plan-spec.json")}
    package = {"role": role, "host": host, "spec": "operator.json", "spec_sha256": files["operator.json"],
               "stage_dir": stage_dir, "rpc_config": "rpc.json", "files": files}
    if guardian_id is not None:
        package["guardian_id"] = guardian_id
    write_new(directory / "package.json", encode(package))
    return str(directory)


def build_guardians(ctx, output, documents):
    inputs = bridge_inputs(ctx)
    placement = release_lock.read_document(Path(inputs["guardian_placement"]))
    rows = placement.get("guardians")
    prepare.require(placement.get("version") == 1 and isinstance(rows, list)
                    and sorted(row.get("guardian_id") for row in rows) == [1, 2, 3], "guardian placement must list ids 1, 2 and 3")
    result = {}
    for row in rows:
        prepare.require(set(row) == set(GUARDIAN_FIELDS), f"guardian {row.get('guardian_id')}: placement fields differ")
        host = deployment_address(ctx, row["address"])
        result[host] = write_component(ctx, "guardian", host, output / "guardian" / host, row, inputs["guardian_rpc_config"],
                                       documents, str(row["guardian_id"]), row["guardian_id"])
    return result


def build_relayer(ctx, output, documents):
    inputs = bridge_inputs(ctx)
    fields = release_lock.read_document(Path(inputs["relayer_spec"]))
    prepare.require(set(fields) == set(RELAYER_FIELDS), "relayer spec fields differ")
    host = deployment_address(ctx, fields["address"])
    return {host: write_component(ctx, "relayer", host, output / "relayer" / host, fields, inputs["relayer_rpc_config"],
                                  documents, "relayer")}


def services_inputs(ctx):
    values = prepare.local_value(ctx, "packages", "services")
    names = ("services_source", "indexer_source", "genesis_source")
    prepare.require(isinstance(values, dict) and all(isinstance(values.get(name), str) and values[name].startswith("/")
                                                     for name in names), "local-inputs packages.services is incomplete")
    return values


def build_services(ctx, output, documents):
    values = services_inputs(ctx)
    inputs_dir = output / "services-inputs"
    arguments = SimpleNamespace(
        services_source=Path(values["services_source"]), indexer_source=Path(values["indexer_source"]),
        genesis_source=Path(values["genesis_source"]), services_binary=prepare.local_path(ctx, "files", "psy_services"),
        indexer_binary=prepare.local_path(ctx, "files", "psy_indexer"), genesis=prepare.local_path(ctx, "files", "genesis"),
        output=inputs_dir)
    receipt = prepare_services_inputs.prepare(arguments, ctx.lock)
    summaries = None
    if documents is not None:
        summaries = {chain: Path(row["summary"]["path"]).read_bytes() for chain, row in documents.items()}
    delivery = prepare_services_packages.build_service_packages(
        ctx.lock, ctx.lock_sha256, ctx.release_dir, inputs_dir, receipt["manifest_sha256"], output / "services", summaries)
    return {host: {"directory": str(output / "services" / host), "manifest_sha256": pin} for host, pin in delivery.items()}


def envio_inputs(ctx):
    values = prepare.local_value(ctx, "packages", "envio")
    names = ("patches_dir", "dependency_lock", "build_script")
    prepare.require(isinstance(values, dict) and all(isinstance(values.get(name), str) and values[name].startswith("/")
                                                     for name in names), "local-inputs packages.envio is incomplete")
    return values


def envio_spec(ctx, documents):
    lock, values = ctx.lock, envio_inputs(ctx)
    patches = {}
    for name in release_lock.ENVIO_PATCHES:
        path = Path(values["patches_dir"]) / name
        patches[name] = {"path": str(path), "sha256": prepare.file_sha256(path)}
    address = ctx.lock["hosts"][POSTGRES_ALIAS]
    placement = {"postgres_host": address, "postgres_port": POSTGRES_PORT, "postgres_user": lock["envio"]["database"],
                 "indexer_port": lock["envio"]["indexer_port"]}
    routes = {name: {"urls": [lock["envio"]["rpc_routes"][name]], "confirmed_block_threshold": depth}
              for name, (_, _, depth) in prepare_envio.CHAINS.items()}
    dependency_lock = Path(values["dependency_lock"])
    return {"version": 1, "patches": patches, "dependency_lock": {"path": str(dependency_lock), "sha256": prepare.file_sha256(dependency_lock)},
            "placement": placement, "rpc_routes": routes, "l1_documents": dict(documents or {})}


def check_envio_build(built, lock):
    """The build script's output must carry its own verified evidence; the installer repeats this on the host."""
    build_path = built / "build.json"
    prepare.require(build_path.is_file(), "the Envio build produced no build.json")
    build = release_lock.parse(build_path.read_bytes())  # lists every file, so it exceeds the document size cap
    flags = ("frozen_install_verified", "patches_verified", "native_help_verified", "generated_config_verified")
    prepare.require(build.get("source_commit") == lock["sources"]["bridge_reader"] and build.get("node_sha256") == lock["envio"]["node_sha256"]
                    and all(build.get(flag) is True for flag in flags), "the Envio build is not verified against the lock")
    prepare.require(install_envio.inventory(built) == build["files"], "the Envio build inventory differs from build.json")
    return prepare.file_sha256(build_path)


def build_envio(ctx, output, documents):
    values = envio_inputs(ctx)
    spec_raw = encode(envio_spec(ctx, documents))
    spec_path = output / "envio-spec.json"
    write_new(spec_path, spec_raw)
    package = output / "envio-source"
    arguments = SimpleNamespace(spec=spec_path, spec_sha256=sha256_bytes(spec_raw),
                                source_repo=prepare.local_path(ctx, "build", "source"), output=package)
    prepare_envio.prepare(arguments, ctx.lock)
    if documents is None:
        return {"source": str(package)}
    built = output / "envio-built"
    result = prepare.run_local([values["build_script"], str(package), str(built)], BUILD_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise RuntimeError(prepare.command_failure("Envio build script", result))
    return {"source": str(package), "built": str(built), "build_sha256": check_envio_build(built, ctx.lock)}


def build_bridge_packages(ctx, l1_documents):
    """Build all four component families under the operator output root and return the directory.

    l1_documents is None (pending) or {chain: {summary, bridge_receipt, state_manager_receipt}}, each {path, sha256}.
    """
    output = output_directory(ctx, l1_documents)
    if l1_documents is None:
        clear_pending(output)
    else:
        prepare.require(not (output / "summary.json").exists(), "this package set exists; verify it instead of rebuilding")
        if output.exists():
            # A set without summary.json is the leftover of a failed build; the summary is written last.
            prepare.require(output.name.startswith("final-"), "refusing to remove a directory this module did not name")
            shutil.rmtree(output)
        prepare.require(set(l1_documents) == set(release_lock.CHAINS), "documents are needed for all three chains")
    output.mkdir(parents=True, mode=0o700)
    if l1_documents is None:
        write_new(output / PENDING_MARKER, b"pending package set; safe to replace\n")
    summary = {"schema_version": 1, "lock_sha256": ctx.lock_sha256, "pending": l1_documents is None,
               "guardian": build_guardians(ctx, output, l1_documents), "relayer": build_relayer(ctx, output, l1_documents),
               "services": build_services(ctx, output, l1_documents), "envio": build_envio(ctx, output, l1_documents)}
    write_new(output / "summary.json", encode(summary))
    return output


def read_summary(ctx, output):
    summary = release_lock.read_document(Path(output) / "summary.json")
    prepare.require(summary.get("lock_sha256") == ctx.lock_sha256, "the package set belongs to another release lock")
    return summary
