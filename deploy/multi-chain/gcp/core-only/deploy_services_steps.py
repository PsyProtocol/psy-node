#!/usr/bin/env python3
"""Steps 54, 70, 72, 88 and 73: plan and prepare the bridge packages, start Envio, the Bridge Reader, Services and the indexers.

Step 54 runs with no L1 documents and changes nothing on a host. Steps 70, 72, 88 and 73 are cutover steps. Every apply
looks at the host first: an installed unit is not installed again and a running unit is left alone, so a rerun after a
failure or after later steps repeats nothing that already holds. Credentials travel on stdin and are never in a
command line or a result; the generated values are kept once in the operator state directory.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import tarfile
from urllib.parse import quote

import bridge_packages as bridge
import deploy_prepare_steps as prepare
import install_services
import prepare_envio
import release_lock
from deploy_remote import Step, wait_until

PYTHON = "/usr/bin/python3"
STAGE_ROOT = "/var/tmp"
POSTGRES_ALIAS = "gcp-postgres"
POSTGRES_CONTAINER = "parth-postgres"
ENVIO_ACCOUNT = "psy-envio-fresh"
READER_ACCOUNT = "psy-bridge-reader"
READER_ROLE_SQL = "psy_bridge_reader_api/sql/reader-role.sql"
READER_CONNECTION_LIMIT = 8
LOGIN_PATTERN = re.compile(r"[A-Za-z0-9_+/=-]{24,256}")
ROLE_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}")
SHORT_SECONDS = 120
INSTALL_SECONDS = 900
ACTIVATE_SECONDS = 1200
UPLOAD_SECONDS = 3600
READY_SECONDS = 600
SYNC_SECONDS = 180
POLL_SECONDS = 10
UNIT_PROPERTIES = "LoadState,ActiveState,UnitFileState,MainPID,NRestarts"
BRIDGE_TOOLS = ("install_envio.py", "install_bridge_reader.py", "install_services.py", "activate_services.py", "indexer_backup_mirror.py",
                "install_guardian.py", "guardian_exec.py", "activate_bridge.py", "install_relayer.py", "relayer_exec.py")
REALM_STALL_MESSAGE = ("the Realm indexer watermark is not advancing; the committed-realm backup parser (CGB2) was only "
                       "tested on derived fixtures, so read the Realm indexer log for a parser error before anything else")


def quote_word(value):
    return shlex.quote(str(value))


def root_script(ctx, host, script, timeout=SHORT_SECONDS):
    return ctx.remote.run_root_text(host, ["/usr/bin/bash", "-s"], timeout, stdin_text="set -euo pipefail\n" + script)


def unit_state(ctx, host, unit):
    output = ctx.remote.run_script(host, f"systemctl show {quote_word(unit)} --property={UNIT_PROPERTIES}\n", SHORT_SECONDS)
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def is_running(state):
    return (state.get("LoadState") == "loaded" and state.get("ActiveState") == "active" and state.get("UnitFileState") == "enabled"
            and state.get("MainPID", "0").isdigit() and int(state["MainPID"]) > 0)


def namespace(ctx):
    return ctx.lock["units"]["core_namespace_prefix"]


# ---- steps 54 and 70: packages -------------------------------------------------------------------------------------

def package_check(ctx):
    for tool in BRIDGE_TOOLS:
        prepare.check_tool_hash(ctx, tool)
    for label in ("services", "indexer", "genesis"):
        prepare.require(ctx.lock["sources"][label], f"sources.{label} is not pinned in the lock")
    for name in ("psy-services", "psy-indexer"):
        prepare.require(ctx.lock["binaries"][name], f"binaries.{name} is not pinned in the lock")
    bridge.bridge_inputs(ctx)
    bridge.services_inputs(ctx)
    bridge.envio_inputs(ctx)


def check_component(ctx, role, host, directory):
    package = release_lock.read_document(Path(directory) / "package.json")
    prepare.require(package["role"] == role and package["host"] == host, f"{host}: package.json differs")
    for name, expected in package["files"].items():
        prepare.require(prepare.file_sha256(Path(directory) / name) == expected, f"{host}: package file hash differs: {name}")
    for tool in (bridge.GUARDIAN_TOOLS if role == "guardian" else bridge.RELAYER_TOOLS):
        prepare.require(package["files"].get(tool) == ctx.lock["tool_sha256"][tool], f"{host}: package copy of {tool} differs from the lock")


def check_envio_source(directory):
    manifest = release_lock.read_document(Path(directory) / "manifest.json")
    for name, expected in manifest["files"].items():
        prepare.require(prepare.file_sha256(Path(directory) / name) == expected, f"Envio source file hash differs: {name}")


def verify_set(ctx, output, is_pending):
    summary = bridge.read_summary(ctx, output)
    prepare.require(summary["pending"] is is_pending, "the package set has the wrong mode")
    for role in ("guardian", "relayer"):
        for host, directory in summary[role].items():
            check_component(ctx, role, host, directory)
    for host, row in summary["services"].items():
        install_services.load_package(Path(row["directory"]), row["manifest_sha256"], ctx.lock, ctx.lock_sha256)
    check_envio_source(summary["envio"]["source"])
    if not is_pending:
        prepare.require(bridge.check_envio_build(Path(summary["envio"]["built"]), ctx.lock) == summary["envio"]["build_sha256"],
                        "the Envio build differs from the recorded one")
    return summary


def plan_apply(ctx):
    output = bridge.build_bridge_packages(ctx, None)
    prepare.write_state(ctx, "plan_bridge_packages", {"schema_version": 1, "lock_sha256": ctx.lock_sha256, "output": str(output)})


def plan_verify(ctx):
    state = prepare.read_state(ctx, "plan_bridge_packages")
    prepare.require(state.get("lock_sha256") == ctx.lock_sha256, "the planned packages belong to another release lock")
    summary = verify_set(ctx, state["output"], True)
    return {"pending": True, "guardians": sorted(summary["guardian"]), "relayers": sorted(summary["relayer"]),
            "services_groups": sorted(summary["services"]), "l1_documents_bound": False}


def fetch_remote_document(ctx, host, path):
    text = ctx.remote.run_root_text(host, ["/usr/bin/cat", "--", path], SHORT_SECONDS)
    remote_sum = ctx.remote.run_root_text(host, ["/usr/bin/sha256sum", "--", path], SHORT_SECONDS).split()[0]
    raw = text.encode()
    prepare.require(hashlib.sha256(raw).hexdigest() == remote_sum, "downloaded document differs from the host copy")
    return raw


def deploy_state(ctx):
    state = prepare.read_state(ctx, "deploy_l1")
    prepare.require(state.get("lock_sha256") == ctx.lock_sha256, "recorded L1 documents belong to another release lock")
    prepare.require(set(state.get("chains", {})) == set(release_lock.CHAINS), "recorded L1 documents do not cover three chains")
    return state


def state_manager_receipt(ctx, state, chain, row):
    """The deployment state keeps the summary and the Bridge receipt; Envio also needs the StateManager creation receipt."""
    target = Path(row["summary"]["path"]).parent / "StateManager_Proxy.json"
    if not target.exists():
        raw = fetch_remote_document(ctx, state["signer_host"], f"{state['output_dir']}/deployments/{chain}/StateManager_Proxy.json")
        bridge.write_new(target, raw)
    return {"path": str(target), "sha256": prepare.file_sha256(target)}


def l1_documents(ctx):
    state = deploy_state(ctx)
    return {chain: {"summary": row["summary"], "bridge_receipt": row["receipt"],
                    "state_manager_receipt": state_manager_receipt(ctx, state, chain, row)}
            for chain, row in state["chains"].items()}


def prepare_apply(ctx):
    documents = l1_documents(ctx)
    output = bridge.output_directory(ctx, documents)
    if not (output / "summary.json").exists():
        output = bridge.build_bridge_packages(ctx, documents)
    summary = verify_set(ctx, output, False)
    prepare.write_state(ctx, "prepare_bridge_packages", {
        "schema_version": 1, "lock_sha256": ctx.lock_sha256,
        "l1_documents_sha256": prepare.file_sha256(ctx.state_dir / "deploy_l1.json"), "output": str(output),
        "guardian": summary["guardian"], "relayer": summary["relayer"], "services": summary["services"], "envio": summary["envio"]})


def bridge_state(ctx):
    """The step 70 record; it must still match the recorded L1 deployment, so later steps and reruns stay honest."""
    state = prepare.read_state(ctx, "prepare_bridge_packages")
    prepare.require(state.get("lock_sha256") == ctx.lock_sha256, "recorded bridge packages belong to another release lock")
    deploy_file = ctx.state_dir / "deploy_l1.json"
    prepare.require(deploy_file.is_file() and state.get("l1_documents_sha256") == prepare.file_sha256(deploy_file),
                    "bridge packages were built from different L1 documents than the recorded deployment")
    return state


def prepare_check(ctx):
    package_check(ctx)
    deploy_state(ctx)


def prepare_verify(ctx):
    state = bridge_state(ctx)
    summary = verify_set(ctx, state["output"], False)
    return {"pending": False, "guardians": sorted(summary["guardian"]), "relayers": sorted(summary["relayer"]),
            "services_groups": sorted(summary["services"]), "l1_documents_sha256": state["l1_documents_sha256"],
            "envio_build_sha256": summary["envio"]["build_sha256"]}


# ---- shared credentials and Postgres -------------------------------------------------------------------------------

def database_login(ctx):
    """The one login value of the database roles; it is the file the database host was rebuilt from."""
    value = prepare.local_path(ctx, "databases", "postgres_password_file").read_text().strip("\n")
    prepare.require(LOGIN_PATTERN.fullmatch(value) is not None,
                    "the database login file must hold 24 to 256 letters, digits, underscore, plus, slash, equals or hyphen")
    return value


def service_values(ctx):
    """Generated once, kept in the operator state directory, shared by the Bridge Reader, Services and the indexers."""
    path = ctx.state_dir / "service-credentials.json"
    if not path.exists():
        values = {"jwt_secret": secrets.token_hex(32), "bridge_reader_login": secrets.token_urlsafe(48),
                  "bridge_reader_token": secrets.token_hex(32)}
        bridge.write_new(path, bridge.encode(values))
    values = release_lock.read_document(path)
    prepare.require(set(values) == {"jwt_secret", "bridge_reader_login", "bridge_reader_token"},
                    "recorded service values differ in shape")
    prepare.require(LOGIN_PATTERN.fullmatch(values["bridge_reader_login"]) is not None
                    and re.fullmatch(r"[0-9a-f]{64}", values["bridge_reader_token"]) is not None,
                    "recorded Bridge Reader credentials differ in shape")
    return values


def postgres_script(ctx, sql, timeout=SHORT_SECONDS, database="postgres"):
    script = (f"docker exec -i --user postgres {POSTGRES_CONTAINER} psql -XqAt -v ON_ERROR_STOP=1 -U postgres -d {quote_word(database)} "
              f"<<'PSY_SQL_END'\n{sql}PSY_SQL_END\n")
    return root_script(ctx, POSTGRES_ALIAS, script, timeout)


def ensure_roles(ctx):
    login = database_login(ctx)
    sql = ""
    for name in (ctx.lock["envio"]["database"], ctx.lock["services"]["owner"]):
        prepare.require(ROLE_PATTERN.fullmatch(name) is not None, "database role names must be plain lowercase identifiers")
        sql += (f"SELECT 'CREATE ROLE \"{name}\" LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{name}') \\gexec\n"
                f"ALTER ROLE \"{name}\" LOGIN PASSWORD '{login}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n")
    postgres_script(ctx, sql)


def ensure_services_database(ctx):
    database, owner = ctx.lock["services"]["database"], ctx.lock["services"]["owner"]
    postgres_script(ctx, f"SELECT 'CREATE DATABASE \"{database}\" OWNER \"{owner}\" TEMPLATE template0' WHERE NOT EXISTS "
                         f"(SELECT FROM pg_database WHERE datname='{database}') \\gexec\n")


# ---- step 72: Envio ------------------------------------------------------------------------------------------------

def envio_unit(ctx):
    return ctx.lock["units"]["envio"]


def envio_stage(ctx):
    return f"{STAGE_ROOT}/psy-envio-{namespace(ctx)}-stage"


def read_envio_summary(ctx):
    summary = bridge_state(ctx)["envio"]
    prepare.require(summary.get("built") and summary.get("build_sha256"), "no Envio build is recorded")
    return summary


def envio_check(ctx):
    prepare.check_tool_hash(ctx, "install_envio.py")
    read_envio_summary(ctx)
    database_login(ctx)
    prepare.require(ctx.remote.sudo_mode(POSTGRES_ALIAS) == "passwordless", "the database host needs no-prompt sudo")


def pack_envio(built, target):
    def normalise(info):
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mode &= ~0o022
        return info
    with tarfile.open(target, "w:gz", compresslevel=3) as archive:
        archive.add(built, arcname=".", filter=normalise)


def stage_envio(ctx, summary, secrets_raw):
    """Copy the build, the installer and the lock to the database host; the secrets file is written from stdin."""
    stage, built = envio_stage(ctx), Path(summary["built"])
    tarball = ctx.run_dir / f"envio-{namespace(ctx)}.tar.gz"
    pack_envio(built, tarball)
    try:
        root_script(ctx, POSTGRES_ALIAS, f"rm -rf -- {quote_word(stage)}\ninstall -d -m 0755 -o \"$SUDO_USER\" -- {quote_word(stage)}\n")
        ctx.remote.copy_files(POSTGRES_ALIAS, [tarball, prepare.TOOLS_DIR / "install_envio.py", ctx.release_dir / "release-lock.json"],
                              stage + "/", timeout_seconds=UPLOAD_SECONDS)
    finally:
        tarball.unlink(missing_ok=True)
    root_script(ctx, POSTGRES_ALIAS, f"cd {quote_word(stage)}\ninstall -d -m 0755 -o root -g root package\n"
                f"tar -xzf {quote_word(tarball.name)} -C package --no-same-owner\nrm -f -- {quote_word(tarball.name)}\n"
                "chown -R root:root .\nchmod go-w install_envio.py release-lock.json\n", UPLOAD_SECONDS)
    container = root_script(ctx, POSTGRES_ALIAS, f"docker inspect --format '{{{{.Id}}}}' {POSTGRES_CONTAINER}\n").strip()
    hostname = root_script(ctx, POSTGRES_ALIAS, "hostname\n").strip()
    prepare.require(re.fullmatch(r"[a-f0-9]{64}", container) is not None, "the Postgres container id could not be read")
    address = ctx.lock["hosts"][POSTGRES_ALIAS]
    secrets_sha = hashlib.sha256(secrets_raw).hexdigest()
    spec = {"version": 1, "hostname": hostname, "address": address, "postgres_container_id": container,
            "package": f"{stage}/package", "build_sha256": summary["build_sha256"],
            "secrets": {"path": f"{stage}/secrets.json", "sha256": secrets_sha}}
    spec_raw = bridge.encode(spec)
    write = (f"umask 077\ncat > {quote_word(stage + '/secrets.json')} <<'PSY_SECRET_END'\n{secrets_raw.decode()}PSY_SECRET_END\n"
             f"cat > {quote_word(stage + '/spec.json')} <<'PSY_SPEC_END'\n{spec_raw.decode()}PSY_SPEC_END\n"
             f"chmod 0600 -- {quote_word(stage + '/secrets.json')} {quote_word(stage + '/spec.json')}\n")
    root_script(ctx, POSTGRES_ALIAS, write)
    return hashlib.sha256(spec_raw).hexdigest()


def run_envio_tool(ctx, mode, spec_sha, apply, timeout):
    stage = envio_stage(ctx)
    argv = [PYTHON, "-I", "-B", f"{stage}/install_envio.py", mode, "--release-lock", f"{stage}/release-lock.json",
            "--release-lock-sha256", ctx.lock_sha256, "--spec", f"{stage}/spec.json", "--spec-sha256", spec_sha]
    return ctx.remote.run_root_text(POSTGRES_ALIAS, argv + (["--apply"] if apply else []), timeout, show_stderr=True)


def prepare_envio_host(ctx):
    root_script(ctx, POSTGRES_ALIAS,
                f"id {ENVIO_ACCOUNT} >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir /nonexistent "
                f"--shell /usr/sbin/nologin {ENVIO_ACCOUNT}\n", INSTALL_SECONDS)


def envio_apply(ctx):
    summary = read_envio_summary(ctx)
    state = unit_state(ctx, POSTGRES_ALIAS, envio_unit(ctx))
    prepare_envio_host(ctx)
    ensure_roles(ctx)
    if is_running(state) and envio_rows_ready(ctx):
        return
    secrets_raw = bridge.encode({"postgres_password": database_login(ctx)})
    try:
        spec_sha = stage_envio(ctx, summary, secrets_raw)
        if state.get("LoadState") != "loaded":
            run_envio_tool(ctx, "check-host", spec_sha, False, INSTALL_SECONDS)
            run_envio_tool(ctx, "install", spec_sha, True, INSTALL_SECONDS)
        run_envio_tool(ctx, "activate", spec_sha, True, ACTIVATE_SECONDS)
    finally:
        root_script(ctx, POSTGRES_ALIAS, f"rm -rf -- {quote_word(envio_stage(ctx))}\n")


def envio_rows(ctx):
    """{chain id: (source_block, max_reorg_depth)} from the Envio database; empty before the schema exists."""
    sql = "SELECT id, source_block, max_reorg_depth FROM envio.envio_chains ORDER BY id;"
    script = (f"docker exec -i --user postgres {POSTGRES_CONTAINER} psql -XqAt -U postgres -d {ctx.lock['envio']['database']} "
              f"<<'PSY_SQL_END' 2>/dev/null || true\nSET default_transaction_read_only=on;\n{sql}\nPSY_SQL_END\n")
    rows = {}
    for line in root_script(ctx, POSTGRES_ALIAS, script).splitlines():
        fields = line.split("|")
        if len(fields) == 3 and all(field.lstrip("-").isdigit() for field in fields):
            rows[int(fields[0])] = (int(fields[1]), int(fields[2]))
    return rows


def expected_chains():
    return {chain_id: depth for _, chain_id, depth in prepare_envio.CHAINS.values()}


def envio_rows_ready(ctx):
    rows = envio_rows(ctx)
    return set(rows) == set(expected_chains()) and all(block > 0 for block, _ in rows.values())


def http_status(ctx, host, url):
    script = ("python3 -I - <<'PSY_HTTP_END'\nimport urllib.request\ntry:\n    print(urllib.request.urlopen(%r, timeout=10).status)\n"
              "except Exception:\n    print(0)\nPSY_HTTP_END\n") % url
    output = ctx.remote.run_script(host, script, SHORT_SECONDS).strip().splitlines()
    return int(output[-1]) if output and output[-1].isdigit() else 0


def envio_verify(ctx):
    state = unit_state(ctx, POSTGRES_ALIAS, envio_unit(ctx))
    prepare.require(is_running(state) and state.get("NRestarts") == "0", "Envio is not running without restarts")
    first = envio_rows(ctx)
    prepare.require(set(first) == set(expected_chains()), "Envio does not report all three chains")
    for chain_id, depth in expected_chains().items():
        prepare.require(first[chain_id][1] == depth, f"chain {chain_id}: reorg window differs from the reviewed minimum")

    def advanced():
        rows = envio_rows(ctx)
        return set(rows) == set(first) and all(rows[chain][0] > first[chain][0] > 0 for chain in first)

    wait_until(advanced, lambda: None, POLL_SECONDS, READY_SECONDS, "Envio polling on three chains")
    return {"unit": envio_unit(ctx), "restarts": 0, "chains": sorted(first)}


# ---- step 88: Bridge Reader ----------------------------------------------------------------------------------------

def reader_unit(ctx):
    return ctx.lock["units"]["bridge_reader"]


def reader_alias(ctx):
    return services_alias(read_placement(ctx))


def reader_stage(ctx):
    return f"{STAGE_ROOT}/psy-bridge-reader-{namespace(ctx)}-stage"


def reader_binary(ctx):
    path = prepare.local_path(ctx, "files", "psy_bridge_reader")
    prepare.require(prepare.file_sha256(path) == ctx.lock["binaries"][release_lock.READER_BINARY], "the Reader binary differs from the lock")
    return path


def reader_role_sql(ctx):
    """The grant script of the pinned Reader source; it grants SELECT on the Reader's six tables and nothing else."""
    repo = prepare.local_path(ctx, "build", "source")
    result = prepare.run_local(["git", "--no-replace-objects", "-C", str(repo), "show",
                                f"{ctx.lock['sources']['bridge_reader']}:{READER_ROLE_SQL}"], SHORT_SECONDS)
    prepare.require(result.returncode == 0 and "GRANT SELECT" in result.stdout,
                    "the Reader grant script is missing from the build source at sources.bridge_reader")
    return result.stdout


def reader_role(ctx):
    role = ctx.lock["bridge_reader"]["database_role"]
    prepare.require(ROLE_PATTERN.fullmatch(role) is not None, "database role names must be plain lowercase identifiers")
    return role


def ensure_reader_role(ctx):
    """A read-only login role of its own, so the Reader never holds the Envio owner's login."""
    role, login = reader_role(ctx), service_values(ctx)["bridge_reader_login"]
    postgres_script(ctx, f"SELECT 'CREATE ROLE \"{role}\" LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') \\gexec\n"
                         f"ALTER ROLE \"{role}\" LOGIN PASSWORD '{login}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
                         f"NOBYPASSRLS CONNECTION LIMIT {READER_CONNECTION_LIMIT};\n"
                         f"ALTER ROLE \"{role}\" SET default_transaction_read_only = on;\n")


def grant_reader(ctx):
    """Re-applied on every run, since an Envio schema re-initialisation drops the grants; PUBLIC also loses CREATE on public."""
    role, database = reader_role(ctx), ctx.lock["envio"]["database"]
    sql = (f"\\set reader_role {role}\n\\set envio_schema envio\nREVOKE CREATE ON SCHEMA public FROM PUBLIC;\n"
           f"GRANT CONNECT ON DATABASE \"{database}\" TO \"{role}\";\n" + reader_role_sql(ctx))
    postgres_script(ctx, sql, database=database)


def run_reader_tool(ctx, alias, directory, mode, extra=(), stdin_text=None, timeout=INSTALL_SECONDS):
    argv = [PYTHON, "-I", "-B", f"{directory}/install_bridge_reader.py", mode, "--release-lock", f"{directory}/release-lock.json",
            "--release-lock-sha256", ctx.lock_sha256, *extra]
    return ctx.remote.run_root_text(alias, argv, timeout, stdin_text=stdin_text, show_stderr=True)


def reader_report(ctx, alias):
    """The installed tool's status report; it carries readiness only, never the token."""
    output = run_reader_tool(ctx, alias, ctx.lock["bridge_reader"]["release"], "status", timeout=SHORT_SECONDS)
    return json.loads(output.strip().splitlines()[-1])


def reader_check(ctx):
    prepare.check_tool_hash(ctx, "install_bridge_reader.py")
    reader_binary(ctx)
    reader_role_sql(ctx)
    prepare.require(envio_rows_ready(ctx), "Envio is not polling all three chains; start Envio first")


def install_reader(ctx, alias, binary):
    stage = reader_stage(ctx)
    values = service_values(ctx)
    secrets_raw = bridge.encode({"postgres_password": values["bridge_reader_login"], "token": values["bridge_reader_token"]})
    try:
        root_script(ctx, alias, f"rm -rf -- {quote_word(stage)}\ninstall -d -m 0755 -o \"$SUDO_USER\" -- {quote_word(stage)}\n")
        ctx.remote.copy_files(alias, [binary, prepare.TOOLS_DIR / "install_bridge_reader.py", ctx.release_dir / "release-lock.json"],
                              stage + "/", timeout_seconds=UPLOAD_SECONDS)
        root_script(ctx, alias, f"chown -R root:root -- {quote_word(stage)}\nchmod -R go-w -- {quote_word(stage)}\n")
        extra = ["--binary", f"{stage}/{binary.name}"]
        run_reader_tool(ctx, alias, stage, "check-host", extra)
        run_reader_tool(ctx, alias, stage, "install", [*extra, "--apply"], stdin_text=secrets_raw.decode())
    finally:
        root_script(ctx, alias, f"rm -rf -- {quote_word(stage)}\n")


def reader_apply(ctx):
    alias, binary = reader_alias(ctx), reader_binary(ctx)
    state = unit_state(ctx, alias, reader_unit(ctx))
    ensure_reader_role(ctx)
    grant_reader(ctx)
    if is_running(state) and reader_report(ctx, alias)["reader_ready"]:
        return
    root_script(ctx, alias, f"id {READER_ACCOUNT} >/dev/null 2>&1 || useradd --system --user-group --no-create-home "
                            f"--home-dir /nonexistent --shell /usr/sbin/nologin {READER_ACCOUNT}\n")
    if state.get("LoadState") != "loaded":
        install_reader(ctx, alias, binary)
    run_reader_tool(ctx, alias, ctx.lock["bridge_reader"]["release"], "activate", ["--apply"], timeout=ACTIVATE_SECONDS)


def reader_verify(ctx):
    alias = reader_alias(ctx)
    state = unit_state(ctx, alias, reader_unit(ctx))
    prepare.require(is_running(state) and state.get("NRestarts") == "0", "the Bridge Reader is not running without restarts")
    report = reader_report(ctx, alias)
    prepare.require(report["reader_ready"], "the Bridge Reader is not ready on all three chains")
    return {"unit": reader_unit(ctx), "restarts": 0, "envio_chain_ids": report["envio_chain_ids"],
            "deposits": {str(row["chain_index"]): row["deposit_count"] for row in report["chains"]}}


# ---- step 73: Services and indexers --------------------------------------------------------------------------------

def read_placement(ctx):
    raw = (ctx.release_dir / "topology.json").read_bytes()
    prepare.require(hashlib.sha256(raw).hexdigest() == ctx.lock["inputs"]["topology"], "release topology differs from the lock")
    return install_services.placement(ctx.lock, json.loads(raw))


def services_alias(placement):
    return next(alias for alias, group in placement["groups"].items() if "services" in group["roles"])


ED25519_BLOB = re.compile(r"AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}")


def host_key_blob(value):
    """The base64 blob of an ssh-ed25519 host key; the indexer mirror writes the type itself, so a typed value is unwrapped."""
    words = value.split() if isinstance(value, str) else []
    if len(words) == 2 and words[0] == "ssh-ed25519":
        words = words[1:]
    if len(words) != 1 or not ED25519_BLOB.fullmatch(words[0]):
        raise ValueError("mirror host key must be an ssh-ed25519 key, either the base64 blob or 'ssh-ed25519 <blob>'")
    return words[0]


def mirror_sources(sources, keys):
    return {name: {"host": row["host"], "host_key": host_key_blob(keys[row["host"]]), "roles": row["roles"]}
            for name, row in sources.items()}


def services_check(ctx):
    for tool in ("install_services.py", "activate_services.py", "indexer_backup_mirror.py"):
        prepare.check_tool_hash(ctx, tool)
    state = bridge_state(ctx)
    prepare.require(set(state["services"]) == set(read_placement(ctx)["groups"]), "Services packages differ from the placement")
    keys = prepare.local_value(ctx, "packages", "services").get("mirror_host_keys")
    sources = read_placement(ctx)["mirror_sources"]
    prepare.require(isinstance(keys, dict) and all(isinstance(keys.get(row["host"]), str) for row in sources.values()),
                    "local-inputs packages.services.mirror_host_keys must hold a host key for every mirror source")
    mirror_sources(sources, keys)
    database_login(ctx)
    prepare.require(reader_report(ctx, services_alias(read_placement(ctx)))["reader_ready"],
                    "the Bridge Reader is not ready; start it first")


def write_env_file(ctx, host, path, lines):
    parent = str(Path(path).parent)
    body = "".join(line + "\n" for line in lines)
    script = (f"install -d -m 0700 -o root -g root -- {quote_word(parent)}\numask 077\n"
              f"cat > {quote_word(path + '.new')} <<'PSY_ENV_END'\n{body}PSY_ENV_END\n"
              f"chown root:root -- {quote_word(path + '.new')}\nchmod 0600 -- {quote_word(path + '.new')}\n"
              f"mv -f -- {quote_word(path + '.new')} {quote_word(path)}\n")
    root_script(ctx, host, script)


def write_credentials(ctx, placement):
    values = service_values(ctx)
    login = quote(database_login(ctx), safe="")
    url = (f"postgresql://{ctx.lock['services']['owner']}:{login}@{placement['postgres_host']}:{bridge.POSTGRES_PORT}"
           f"/{ctx.lock['services']['database']}")
    for alias, group in placement["groups"].items():
        if "services" in group["roles"]:
            write_env_file(ctx, alias, placement["credentials"] + "/services.env",
                           [f"DATABASE_URL={url}", f"PSY_JWT_SECRET={values['jwt_secret']}"])
        else:
            write_env_file(ctx, alias, placement["credentials"] + "/indexer.env", [f"PSY_JWT_SECRET={values['jwt_secret']}"])


def package_stage(ctx, alias):
    return f"{STAGE_ROOT}/psy-services-{namespace(ctx)}-{alias}-stage"


def stage_services_package(ctx, alias, row):
    """Copy one Services or indexer package to its host and hand it to root; the stage is replaced, never merged."""
    stage, directory = package_stage(ctx, alias), Path(row["directory"])
    names = sorted(str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file())
    by_directory = {}
    for name in names:
        by_directory.setdefault(str(Path(name).parent), []).append(directory / name)
    targets = {parent: stage if parent == "." else f"{stage}/{parent}" for parent in by_directory}
    root_script(ctx, alias, f"rm -rf -- {quote_word(stage)}\numask 022\nmkdir -p -- " + " ".join(quote_word(t) for t in targets.values())
                + f"\nchown -R \"$SUDO_USER\" -- {quote_word(stage)}\n")
    for parent, paths in by_directory.items():
        ctx.remote.copy_files(alias, paths, targets[parent], timeout_seconds=UPLOAD_SECONDS)
    root_script(ctx, alias, f"chown -R root:root -- {quote_word(stage)}\nchmod -R go-w -- {quote_word(stage)}\n")
    return stage


def run_services_tool(ctx, alias, tool_path, mode_args, timeout):
    argv = [PYTHON, "-I", "-B", tool_path, *mode_args]
    return ctx.remote.run_root_text(alias, argv, timeout, show_stderr=True)


def install_package(ctx, alias, row):
    """Install when no unit of this group is loaded yet, then activate from the installed release."""
    placement = read_placement(ctx)
    group = placement["groups"][alias]
    names = [install_services.unit_name(ctx.lock, name) for name in group["roles"]]
    loaded = [unit_state(ctx, alias, name).get("LoadState") == "loaded" for name in names]
    if not any(loaded):
        stage = stage_services_package(ctx, alias, row)
        try:
            common = ["--package", stage, "--manifest-sha256", row["manifest_sha256"], "--release-lock", f"{stage}/release-lock.json",
                      "--release-lock-sha256", ctx.lock_sha256]
            run_services_tool(ctx, alias, f"{stage}/install_services.py", ["check-host", *common], INSTALL_SECONDS)
            run_services_tool(ctx, alias, f"{stage}/install_services.py", ["install", *common, "--apply"], INSTALL_SECONDS)
        finally:
            root_script(ctx, alias, f"rm -rf -- {quote_word(stage)}\n")
    release = placement["release"]
    run_services_tool(ctx, alias, f"{release}/activate_services.py",
                      ["--package", release, "--manifest-sha256", row["manifest_sha256"], "--release-lock", f"{release}/release-lock.json",
                       "--release-lock-sha256", ctx.lock_sha256, "--apply"], ACTIVATE_SECONDS)


def mirror_name(ctx):
    return Path(ctx.lock["services"]["mirror"]).name


def mirror_config(ctx, placement):
    keys = prepare.local_value(ctx, "packages", "services")["mirror_host_keys"]
    reader = next(group["host"] for group in placement["groups"].values() if any(role.startswith("realm") for role in group["roles"]))
    return reader, bridge.encode({"reader": reader, "sources": mirror_sources(placement["mirror_sources"], keys)})


def stage_mirror(ctx, alias, config_raw):
    stage = f"{STAGE_ROOT}/psy-mirror-{namespace(ctx)}-stage"
    config_file = ctx.run_dir / "mirror.json"
    config_file.write_bytes(config_raw)
    root_script(ctx, alias, f"rm -rf -- {quote_word(stage)}\ninstall -d -m 0755 -o \"$SUDO_USER\" -- {quote_word(stage)}\n")
    ctx.remote.copy_files(alias, [prepare.TOOLS_DIR / "indexer_backup_mirror.py", ctx.release_dir / "release-lock.json", config_file], stage + "/")
    config_file.unlink(missing_ok=True)
    root_script(ctx, alias, f"chown -R root:root -- {quote_word(stage)}\nchmod -R go-w -- {quote_word(stage)}\n")
    return stage


def run_mirror(ctx, alias, stage, action, config_raw, extra=()):
    argv = [PYTHON, "-I", "-B", f"{stage}/indexer_backup_mirror.py", action, "--release-lock", f"{stage}/release-lock.json",
            "--release-lock-sha256", ctx.lock_sha256, "--mirror-config", f"{stage}/mirror.json",
            "--mirror-config-sha256", hashlib.sha256(config_raw).hexdigest(), *extra]
    return ctx.remote.run_root_text(alias, argv, SHORT_SECONDS * 3, show_stderr=True)


def remote_exists(ctx, alias, path, directory=False):
    flag = "-d" if directory else "-e"
    return ctx.remote.run_script(alias, f"test {flag} {quote_word(path)} && echo yes || echo no\n", SHORT_SECONDS).strip() == "yes"


def reader_public_key(ctx, alias, stage, config_raw, config_dir):
    if not remote_exists(ctx, alias, config_dir, directory=True):
        return run_mirror(ctx, alias, stage, "prepare-key", config_raw).strip().splitlines()[-1]
    text = root_script(ctx, alias, f"cat -- {quote_word(config_dir + '/id_ed25519.pub')}\n").strip()
    return " ".join(text.split()[:2])


def grant_source_access(ctx, placement, reader, config_raw, public_key):
    program = f"/usr/local/libexec/{mirror_name(ctx)}.py"
    by_address = {alias: group["host"] for alias, group in placement["groups"].items()}
    for name, row in placement["mirror_sources"].items():
        alias = next(alias for alias, address in {**by_address, **ctx.lock["hosts"], **read_topology_hosts(ctx)}.items() if address == row["host"])
        if remote_exists(ctx, alias, program):
            continue
        stage = stage_mirror(ctx, alias, config_raw)
        key_dir = f"/root/psy-mirror-{namespace(ctx)}-reader"
        try:
            # The tool accepts a key file only below root-owned, non-writable directories; /var/tmp is not one.
            root_script(ctx, alias, f"rm -rf -- {quote_word(key_dir)}\ninstall -d -m 0700 -o root -g root -- {quote_word(key_dir)}\n"
                        f"umask 077\nprintf '%s\\n' {quote_word(public_key)} > {quote_word(key_dir + '/reader.pub')}\n")
            run_mirror(ctx, alias, stage, "source-access", config_raw, ["--source", name, "--public-key", f"{key_dir}/reader.pub"])
        finally:
            root_script(ctx, alias, f"rm -rf -- {quote_word(stage)} {quote_word(key_dir)}\n")


def read_topology_hosts(ctx):
    return release_lock.read_document(ctx.release_dir / "topology.json")["hosts"]


def mirror_ready(ctx, alias, placement):
    state = ctx.lock["services"]["mirror"]
    pattern = " ".join(f"{state}/{name}/checkpoints/{role}/guta_updates_backup" for name, row in placement["mirror_sources"].items()
                       for role in row["roles"])
    script = f"for d in {pattern}; do compgen -G \"$d/*.backup\" >/dev/null || {{ echo no; exit 0; }}; done; echo yes\n"
    return root_script(ctx, alias, script).strip() == "yes"


def start_mirror(ctx, placement):
    reader, config_raw = mirror_config(ctx, placement)
    alias = next(alias for alias, group in placement["groups"].items() if group["host"] == reader)
    name = mirror_name(ctx)
    if not remote_exists(ctx, alias, f"/etc/systemd/system/{name}.timer"):
        stage = stage_mirror(ctx, alias, config_raw)
        try:
            public_key = reader_public_key(ctx, alias, stage, config_raw, f"/etc/{name}")
            grant_source_access(ctx, placement, reader, config_raw, public_key)
            run_mirror(ctx, alias, stage, "install", config_raw)
        finally:
            root_script(ctx, alias, f"rm -rf -- {quote_word(stage)}\n")
        root_script(ctx, alias, "systemctl daemon-reload\n")
    root_script(ctx, alias, f"systemctl enable --now {quote_word(name + '.timer')}\n")
    wait_until(lambda: mirror_ready(ctx, alias, placement), lambda: None, POLL_SECONDS, SYNC_SECONDS, "first backup mirror sync")


def services_http(ctx, placement, path):
    return http_status(ctx, services_alias(placement), placement["services_url"] + path)


def services_apply(ctx):
    state, placement = bridge_state(ctx), read_placement(ctx)
    ensure_roles(ctx)
    ensure_services_database(ctx)
    write_credentials(ctx, placement)
    alias = services_alias(placement)
    install_package(ctx, alias, state["services"][alias])
    wait_until(lambda: services_http(ctx, placement, "/health/ready") == 200, lambda: services_failure(ctx, placement, alias),
               POLL_SECONDS, READY_SECONDS, "Services readiness")
    start_mirror(ctx, placement)
    for group_alias, group in placement["groups"].items():
        if group_alias != alias:
            install_package(ctx, group_alias, state["services"][group_alias])


def services_failure(ctx, placement, alias):
    unit = unit_state(ctx, alias, ctx.lock["units"]["services"])
    if unit.get("ActiveState") == "failed" or unit.get("NRestarts", "0") != "0":
        return f"Services is {unit.get('ActiveState')} with {unit.get('NRestarts')} restarts"
    return None


def read_cursor(ctx, placement, role):
    group_alias = next(alias for alias, group in placement["groups"].items() if role in group["roles"])
    name = "coordinator.json" if role == "coordinator" else f"realm_{role[len('realm'):]}_1.json"
    path = f"{placement['backup_dir']}/indexer_state/{name}"
    text = root_script(ctx, group_alias, f"cat -- {quote_word(path)} 2>/dev/null || echo '{{}}'\n")
    try:
        value = json.loads(text.strip() or "{}")
    except ValueError:
        return None  # the indexer's write is not atomic; a torn file is read again on the next poll
    return value.get("last_checkpoint_id") if type(value.get("last_checkpoint_id")) is int else None


def watermark_advancing(ctx, placement, role, message):
    baseline = []

    def advanced():
        current = read_cursor(ctx, placement, role)
        if current is None:
            return False
        if not baseline:
            baseline.append(current)
            return False
        return current > baseline[0]
    try:
        wait_until(advanced, lambda: None, POLL_SECONDS, READY_SECONDS, f"{role} watermark")
    except TimeoutError:
        raise ValueError(message) from None
    return read_cursor(ctx, placement, role)


def services_reader_state(ctx, placement):
    """details.bridge_reader of Services' /health/ready: whether Services itself reaches a ready Bridge Reader."""
    script = ("python3 -I - <<'PSY_HTTP_END'\nimport json, urllib.request\ntry:\n"
              "    body = json.loads(urllib.request.urlopen(%r, timeout=10).read())\n"
              "    print(json.dumps(body.get('details', {}).get('bridge_reader', {}).get('ready') is True))\n"
              "except Exception:\n    print('false')\nPSY_HTTP_END\n") % (placement["services_url"] + "/health/ready")
    output = ctx.remote.run_script(services_alias(placement), script, SHORT_SECONDS).strip().splitlines()
    return bool(output) and output[-1] == "true"


def services_verify(ctx):
    placement = read_placement(ctx)
    alias = services_alias(placement)
    units = {}
    for group_alias, group in placement["groups"].items():
        for role in group["roles"]:
            name = install_services.unit_name(ctx.lock, role)
            state = unit_state(ctx, group_alias, name)
            prepare.require(is_running(state) and state.get("NRestarts") == "0", f"{role}: unit is not running without restarts")
            units[role] = 0
    prepare.require(services_http(ctx, placement, "/health/ready") == 200, "Services /health/ready is not 200")
    watermarks = {"coordinator": watermark_advancing(ctx, placement, "coordinator",
                                                       "the Coordinator indexer watermark is not advancing")}
    realm = sorted(role for role in placement["indexers"] if role.startswith("realm"))[0]
    watermarks[realm] = watermark_advancing(ctx, placement, realm, REALM_STALL_MESSAGE)
    prepare.require(services_reader_state(ctx, placement), "Services does not report a ready Bridge Reader")
    report = reader_report(ctx, alias)
    prepare.require(report["reader_ready"], "the Bridge Reader is not ready on all three chains")
    return {"services_ready": True, "units": sorted(units), "watermarks": watermarks, "reader_ready": True,
            "deposits": {str(row["chain_index"]): row["deposit_count"] for row in report["chains"]}, "services_host": alias}


SERVICES_STEPS = {
    "plan_bridge_packages": Step("plan_bridge_packages", package_check, plan_apply, plan_verify),
    "prepare_bridge_packages": Step("prepare_bridge_packages", prepare_check, prepare_apply, prepare_verify, cutover=True),
    "start_envio": Step("start_envio", envio_check, envio_apply, envio_verify, cutover=True),
    "start_bridge_reader": Step("start_bridge_reader", reader_check, reader_apply, reader_verify, cutover=True),
    "start_services": Step("start_services", services_check, services_apply, services_verify, cutover=True),
}
