#!/usr/bin/env python3
"""One-rollout install-only helper. Database creation and activation are operator-owned."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit

POSTGRES_ALIAS = "gcp-postgres"
# The class roles scripts/envio-reader-roles.sql of psy-services creates for the pg fallback, keyed by the URL that names each.
FALLBACK_URLS = {"ENVIO_DATABASE_URL": "envio_bridge_reader", "ENVIO_DATABASE_URL_INTERACTIVE": "envio_interactive_reader",
                 "ENVIO_DATABASE_URL_BACKGROUND": "envio_background_reader"}
READ_PATH_KEYS = {"PSY_ENVIO_READ_PATH", "PSY_ENVIO_DB_SCHEMA", *FALLBACK_URLS}
ENVIO_SCHEMA = "envio"
SERVICE_PATTERNS = ("psy-services-fresh*", "psy-indexer-fresh*", "parth-psy-services.service", "parth-psy-indexer@*")


class ValidationError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ValidationError(message)


def read_release_lock(path, expected_sha256):
    raw = Path(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "release lock hash mismatch")
    return json.loads(raw)


def unit_name(lock, role):
    return lock["units"]["services"] if role == "services" else f"{lock['units']['indexer_prefix']}{role}.service"


def placement(lock, release_topology):
    """The Services and indexer placement, derived only from the release lock and the release topology."""
    services, envio, reader = lock["services"], lock["envio"], lock["bridge_reader"]
    addresses = {**release_topology["hosts"], **lock["hosts"]}
    postgres_host = addresses[POSTGRES_ALIAS]
    listen_host, _, listen_port = services["listen"].rpartition(":")
    owners = [alias for alias, address in addresses.items() if address == listen_host]
    require(len(owners) == 1, "the Services listen address must belong to exactly one host")
    core_prefix, backups, mirror = lock["units"]["core_prefix"], services["backups"], services["mirror"]
    groups = {owners[0]: {"host": listen_host, "roles": ["services"], "user": "parth"}}

    def add_role(alias, role):
        groups.setdefault(alias, {"host": addresses[alias], "roles": [], "user": "psy-core"})["roles"].append(role)

    coordinator = release_topology["coordinator"]
    add_role(coordinator["host"], "coordinator")
    indexers = {"coordinator": {"args": "coordinator", "backup_subdir": "coordinator_0_0",
                                "core_unit": f"{core_prefix}coordinator-processor.service",
                                "edge_url": f"http://{addresses[coordinator['host']]}:{coordinator['edge_ports'][0]}"}}
    sources = {}
    for realm in release_topology["realms"]:
        realm_id, first = realm["id"], realm["validators"][0]
        role = f"realm{realm_id}"
        add_role(first["processor_host"], role)
        indexers[role] = {"args": f"realm --realm-id {realm_id} --realm-sub-id 1", "backup_subdir": f"realm_{realm_id}_1",
                          "core_unit": f"{core_prefix}realm-{realm_id}-v1-processor.service",
                          "edge_url": f"http://{addresses[first['edge_host']]}:{first['http_port']}"}
        sources[role] = {"coordinator_rpc_url": indexers["coordinator"]["edge_url"],
                         "coordinator_backup_base_dir": mirror + "/cp/checkpoints",
                         "validators": [{"realm_sub_id": position,
                                         "edge_rpc_url": f"http://{addresses[v['edge_host']]}:{v['http_port']}",
                                         "backup_base_dir": backups if position == 1 else f"{mirror}/v{position}/checkpoints"}
                                        for position, v in enumerate(realm["validators"], 1)]}
    mirror_sources = {"cp": {"host": addresses[coordinator["host"]], "roles": ["coordinator_0_0"]}}
    for position in range(2, len(release_topology["realms"][0]["validators"]) + 1):
        hosts = {realm["validators"][position - 1]["processor_host"] for realm in release_topology["realms"]}
        require(len(hosts) == 1, f"validator {position} must run on one processor host")
        mirror_sources[f"v{position}"] = {"host": addresses[hosts.pop()],
                                          "roles": [f"realm_{realm['id']}_{position}" for realm in release_topology["realms"]]}
    return {"release": lock["paths"]["services"]["release"], "credentials": lock["paths"]["services"]["config"],
            "database": services["database"], "database_owner": services["owner"], "postgres_host": postgres_host,
            "redis_url": f"{release_topology['infrastructure']['redis_url']}/{services['redis_db']}",
            "redis_prefix": services["key_prefix"], "backup_dir": backups, "cursor_dir": backups + "/indexer_state",
            "mirror_dir": mirror, "nostr_state": lock["paths"]["services"]["state"],
            "services_url": "http://" + services["listen"], "services_host": listen_host, "services_port": int(listen_port),
            "bridge_reader_url": "http://" + reader["listen"], "bridge_reader_token_file": reader["client_token_file"],
            "bridge_reader_unit": lock["units"]["bridge_reader"], "envio_database": envio["database"],
            "read_path_file": lock["paths"]["services"]["config"] + "/envio-read-path.env",
            "groups": groups, "indexers": indexers, "realm_sources": sources, "mirror_sources": mirror_sources}


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def write_new(path, content, mode=0o600):
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        os.fchmod(handle.fileno(), mode)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def publish_packages(source, destination):
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        raise OSError(ctypes.get_errno(), "package publication failed; destination not replaced")
    fd = os.open(destination.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def no_links(path):
    for part in (path, *path.parents):
        require(not part.is_symlink(), "symlink path rejected")


def trusted_parents(path):
    no_links(path)
    for parent in path.parents:
        if parent.exists():
            st = parent.stat()
            require(st.st_uid == 0 and not st.st_mode & 0o022,
                    "destination/credential ancestors must be root-owned and not writable by others")


def load_package(root, expected, lock, lock_sha256):
    no_links(root)
    require(digest(root / "manifest.json") == expected, "manifest hash mismatch")
    manifest = json.loads((root / "manifest.json").read_bytes())
    inventory = manifest["files"]
    actual = set()
    for path in root.rglob("*"):
        require(not path.is_symlink(), "package symlink rejected")
        if path.is_file() and path != root / "manifest.json":
            actual.add(str(path.relative_to(root)))
    require(actual == set(inventory), "package file inventory mismatch")
    for name, expected_hash in inventory.items():
        path = root / name
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,
                "invalid package path")
        require(digest(path) == expected_hash, "package file hash mismatch: " + name)
    require(inventory.get("release-lock.json") == lock_sha256, "package release lock differs from the lock in use")
    release_topology_raw = (root / "release-topology.json").read_bytes()
    require(hashlib.sha256(release_topology_raw).hexdigest() == lock["inputs"]["topology"], "release topology differs from the lock")
    topology = json.loads((root / "topology.json").read_bytes())
    require(topology == placement(lock, json.loads(release_topology_raw)), "package topology differs from the release placement")
    require(manifest["group"] in topology["groups"] and type(manifest.get("l1_ready")) is bool, "unknown package group/readiness")
    require(manifest["rpc_policy"] == "protected-alchemy-only-no-fallback", "RPC policy mismatch")
    require(manifest["runtime_node_commit"] == lock["sources"]["runtime"]
            and manifest["genesis_sha256"] == lock["inputs"]["genesis"], "runtime/Genesis mismatch")
    binary = "psy-services" if "services" in topology["groups"][manifest["group"]]["roles"] else "psy-indexer"
    require(inventory.get(binary) == lock["binaries"][binary], "binary pin mismatch")
    for tool in ("install_services.py", "activate_services.py"):
        require(inventory.get(tool) == lock["tool_sha256"][tool], f"package copy of {tool} differs from the lock")
    expected_units = {"units/" + unit_name(lock, role) for role in topology["groups"][manifest["group"]]["roles"]}
    require({name for name in inventory if name.startswith("units/")} == expected_units, "unit scope mismatch")
    for role in topology["groups"][manifest["group"]]["roles"]:
        if role in topology["realm_sources"]:
            require(json.loads((root / (role + ".json")).read_bytes()) == topology["realm_sources"][role],
                    f"committed realm sources differ from the placement: {role}")
    return manifest, topology


def unit_status(name):
    raw = subprocess.check_output(["systemctl", "show", name,
        "--property=Id,MainPID,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload"], text=True)
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def fence_services(allowed=()):
    import fnmatch
    raw = subprocess.check_output(["systemctl", "list-units", "--all", "--type=service",
        "--no-legend", "--plain", "--no-pager", *SERVICE_PATTERNS], text=True)
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) >= 4 and any(fnmatch.fnmatchcase(fields[0], p) for p in SERVICE_PATTERNS),
                "unexpected service listing")
        if fields[0] not in allowed:
            value = unit_status(fields[0])
            require(value.get("MainPID") == "0" and value.get("ActiveState") == "inactive",
                    "old/foreign Services or indexer still running")
    jobs = subprocess.check_output(["systemctl", "list-jobs", "--no-legend", "--no-pager"], text=True)
    require(not any(len(row) > 1 and any(fnmatch.fnmatchcase(row[1], p) for p in SERVICE_PATTERNS)
                    for row in map(str.split, jobs.splitlines())), "Services/indexer job queued")


def validate_environment(env, role, topology):
    require(re.fullmatch(r"[0-9a-fA-F]{64,128}", env.get("PSY_JWT_SECRET", "")),
            "JWT must be a fresh 32-64 byte hex secret")
    if role == "services":
        db = urlsplit(env.get("DATABASE_URL", ""))
        require(db.scheme == "postgresql" and db.hostname == topology["postgres_host"]
                and db.port == 5432 and db.username == topology["database_owner"]
                and db.path == "/" + topology["database"] and bool(db.password)
                and not db.query and not db.fragment, "fresh database URL required")


def validate_read_path(env, topology):
    """Services reads Envio through the Bridge Reader or, after an operator switch, the read-only pg fallback; never GraphQL."""
    require(env.get("PSY_ENVIO_READ_PATH") in ("reader", "pg"), "PSY_ENVIO_READ_PATH must be reader or pg")
    require(env.get("PSY_ENVIO_DB_SCHEMA") == ENVIO_SCHEMA, "the pg fallback must read the Envio schema")
    for key, role in FALLBACK_URLS.items():
        url = urlsplit(env.get(key, ""))
        require(url.scheme == "postgresql" and url.hostname == topology["postgres_host"] and url.port == 5432
                and url.username == role and bool(url.password) and url.path == "/" + topology["envio_database"]
                and not url.query and not url.fragment, f"{key} must name the read-only fallback role on the Envio database")
    require(env.get("PSY_BRIDGE_READER_URL") == topology["bridge_reader_url"]
            and env.get("PSY_BRIDGE_READER_TOKEN_FILE") == topology["bridge_reader_token_file"],
            "Bridge Reader endpoint differs from frozen topology")
    require(not any(key in env for key in ("INDEXER_GRAPHQL_URL", "ENVIO_GRAPHQL_URL", "HASURA_GRAPHQL_ADMIN_SECRET")),
            "a GraphQL endpoint or Hasura secret reaches Services")


def check_reader_token(topology, account):
    path = Path(topology["bridge_reader_token_file"])
    trusted_parents(path)
    require(path.exists(), "the Bridge Reader token is missing; install the Reader first")
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == account.pw_uid and stat.S_IMODE(st.st_mode) == 0o600,
            "the Bridge Reader token must be a mode 0600 file of the Services account; install the Reader first")


def read_env_file(path, allowed):
    trusted_parents(path)
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
            "credentials must be root-owned regular mode 0600")
    values = {}
    for line in path.read_text().splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in allowed and key not in values and value
                and re.fullmatch(r"[A-Za-z0-9_:/@.%+?=&-]+", value),
                "credentials require only exact unquoted environment keys and URL-safe values")
        values[key] = value
    require(set(values) == allowed, "credential keys missing")
    return values


def read_credentials(path, role, topology):
    values = read_env_file(path, {"PSY_JWT_SECRET", "DATABASE_URL"} if role == "services" else {"PSY_JWT_SECRET"})
    validate_environment(values, role, topology)
    return values


def read_read_path(topology):
    """The operator-switchable file: PSY_ENVIO_READ_PATH plus the pre-provisioned fallback URLs, nothing else."""
    values = read_env_file(Path(topology["read_path_file"]), READ_PATH_KEYS)
    validate_read_path({**values, "PSY_BRIDGE_READER_URL": topology["bridge_reader_url"],
                        "PSY_BRIDGE_READER_TOKEN_FILE": topology["bridge_reader_token_file"]}, topology)
    return values


def check_host(root, manifest, topology, lock):
    require(os.geteuid() == 0, "root required for host preflight")
    require(manifest["l1_ready"], "fresh three-chain documents not bound; install blocked")
    fence_services()
    for path in (root, *root.rglob("*")):
        st = path.stat()
        require(st.st_uid == 0 and not st.st_mode & 0o022, "stage must be root-owned, not group/world writable")
    group = topology["groups"][manifest["group"]]
    addresses = subprocess.check_output(["hostname", "-I"], text=True).split()
    require(group["host"] in addresses, "wrong host")
    account = pwd.getpwnam(group["user"])
    require(account.pw_uid != 0, "runtime user must not be root")
    release = Path(topology["release"])
    trusted_parents(release)
    require(not release.exists(), "release already exists; do not overwrite or reinstall")
    credential_role = "services" if "services" in group["roles"] else "indexer"
    read_credentials(Path(topology["credentials"]) / (credential_role + ".env"), credential_role, topology)
    for role in group["roles"]:
        unit = unit_name(lock, role)
        for base in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
            require(not os.path.lexists(Path(base) / unit), "unit already exists")
            require(not os.path.lexists(Path(base) / (unit + ".d")), "unit drop-in exists")
        loaded = subprocess.run(["systemctl", "show", unit, "-p", "LoadState", "--value"], capture_output=True, text=True)
        require(loaded.stdout.strip() == "not-found", "unit is already loaded")
        if role != "services":
            item = topology["indexers"][role]
            backup = Path(topology["backup_dir"])
            no_links(backup)
            require((backup / item["backup_subdir"]).is_dir(), "fresh backup subtree missing")
            subprocess.run(["systemctl", "is-active", "--quiet", item["core_unit"]], check=True)
    if "services" in group["roles"]:
        check_reader_token(topology, account)
        read_read_path(topology)
        require(not os.path.lexists(topology["nostr_state"]), "fresh Nostr state already exists")
        with socket.socket() as sock:
            sock.bind((topology["services_host"], topology["services_port"]))
    else:
        cursor = Path(topology["backup_dir"]) / "indexer_state"
        require(not os.path.lexists(cursor), "fresh cursor directory already exists; operator review required")
    return account


def install(root, manifest, topology, account, lock):
    require(manifest["l1_ready"], "fresh three-chain documents not bound; install blocked")
    fence_services()
    os.umask(0o022)
    destination = Path(topology["release"])
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = Path(tempfile.mkdtemp(prefix=".services-new-", dir=destination.parent))
    try:
        for src in root.rglob("*"):
            target = temporary / src.relative_to(root)
            if src.is_dir():
                target.mkdir(exist_ok=True, parents=True, mode=0o755)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                mode = 0o755 if src.name in ("psy-services", "psy-indexer") else 0o644
                write_new(target, src.read_bytes(), mode)
        temporary.chmod(0o755)
        publish_packages(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    # All destinations were checked before the first write; no existing bytes are replaced.
    if "services" not in topology["groups"][manifest["group"]]["roles"]:
        cursor = Path(topology["backup_dir"]) / "indexer_state"
        cursor.mkdir(mode=0o750)
        os.chown(cursor, account.pw_uid, account.pw_gid)
    for role in topology["groups"][manifest["group"]]["roles"]:
        name = unit_name(lock, role)
        write_new(Path("/etc/systemd/system") / name, (root / "units" / name).read_bytes(), 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("INSTALL PASS; no start/enable or database operation performed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["verify", "check-host", "install", "guard"])
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--release-lock-sha256", required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--role")
    args = parser.parse_args()
    require(args.package.is_absolute(), "absolute package path required")
    expected = args.manifest_sha256
    if args.mode == "guard":
        trusted_parents(args.package)
        for path in (args.package, *args.package.rglob("*")):
            no_links(path)
            st = path.stat()
            require(st.st_uid == 0 and not st.st_mode & 0o022, "installed package permissions invalid")
        expected = digest(args.package / "manifest.json")
    require(expected is not None, "manifest hash required")
    lock = read_release_lock(args.release_lock, args.release_lock_sha256)
    manifest, topology = load_package(args.package, expected, lock, args.release_lock_sha256)
    if args.mode == "guard":
        require(manifest["l1_ready"], "fresh L1 documents missing")
        require(args.role in topology["groups"][manifest["group"]]["roles"], "role mismatch")
        validate_environment(os.environ, args.role, topology)
        if args.role == "services":
            validate_read_path(os.environ, topology)
    elif args.mode in ("check-host", "install"):
        account = check_host(args.package, manifest, topology, lock)
        if args.mode == "install":
            require(args.apply, "install needs --apply")
            install(args.package, manifest, topology, account, lock)
    print(args.mode.upper() + " PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Do not echo credential values, subprocess output or URL parsing exceptions.
        print("FAILED: " + (str(exc) if isinstance(exc, ValidationError) else type(exc).__name__))
        raise SystemExit(1)
