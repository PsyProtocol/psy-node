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

RELEASE = "/opt/psy-services/releases/core-testnet-20261027-dfd4e483-r3"
BACKUPS = "/var/lib/psy-core/core-testnet-20261027-r3/checkpoints"
HOSTS = {"services": ("10.148.0.38", ["services"]), "cp": ("10.148.0.25", ["coordinator"]),
         "realm0": ("10.148.0.37", ["realm0", "realm1"])}
BINARIES = {"psy-services": "27071ac53edf861e33a3c59d2ffce819bd6b84a9bf3cc85627b960cda6c6699e",
            "psy-indexer": "d2a1cd3c2ddaac55b7dc5d87471ea5aafe89d44448c732a1ab7ade5986d18a53"}
SERVICE_PATTERNS = ("psy-services-fresh-*", "psy-indexer-fresh-*", "parth-psy-services.service", "parth-psy-indexer@*")


class ValidationError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ValidationError(message)


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


def load_package(root, expected):
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
    topology = json.loads((root / "topology.json").read_bytes())
    require(manifest["group"] in HOSTS and type(manifest.get("l1_ready")) is bool, "unknown package group/readiness")
    require(topology["release"] == RELEASE and topology["backup_dir"] == BACKUPS
            and topology["database"] == "psy_services_fresh_20261027_r3"
            and topology["database_owner"] == "psy_services_fresh_20261026"
            and topology["credentials"] == "/etc/psy-services-fresh-20261027-r3"
            and topology["redis_prefix"] == "psy_svc_fresh_20261027_r3:"
            and topology["hasura_url"] == "http://10.148.0.24:38081/v1/graphql"
            and topology["envio_database"] == "envio_bridge_fresh_20261027_r3", "fresh r3 paths required")
    require(manifest["l1_document_cohort"] == "psy-fresh20261027r3b"
            and manifest["rpc_policy"] == "protected-alchemy-only-no-fallback", "L1 cohort/policy mismatch")
    require(manifest["runtime_node_commit"] == "3d31758738f833a7eea6f9ff7fd680a69a0d9a44"
            and manifest["genesis_sha256"] == "f839b453ab130c29998620c4c5d4bf9a30ce341a2e7c480aa9dbd8ed10902173",
            "runtime/Genesis mismatch")
    for group, (ip, roles) in HOSTS.items():
        require(topology["groups"][group]["host"] == ip and topology["groups"][group]["roles"] == roles,
                "host placement mismatch")
    binary = "psy-services" if manifest["group"] == "services" else "psy-indexer"
    require(inventory.get(binary) == BINARIES[binary], "binary pin mismatch")
    expected_units = {"units/" + unit_name(role) for role in HOSTS[manifest["group"]][1]}
    require({name for name in inventory if name.startswith("units/")} == expected_units, "unit scope mismatch")
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
        require(env.get("INDEXER_GRAPHQL_URL") == topology["hasura_url"], "Hasura URL differs from frozen topology")
        graphql = urlsplit(env.get("INDEXER_GRAPHQL_URL", ""))
        require(graphql.scheme == "http" and graphql.hostname == topology["postgres_host"]
                and graphql.port is not None and 1024 < graphql.port < 65536
                and graphql.port not in (8080, 18080, 9898)
                and graphql.path == "/v1/graphql" and not graphql.username
                and not graphql.query and not graphql.fragment, "fresh private Hasura URL required")
        require(len(env.get("HASURA_GRAPHQL_ADMIN_SECRET", "")) >= 32,
                "fresh Hasura secret required")


def read_credentials(path, role, topology):
    trusted_parents(path)
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
            "credentials must be root-owned regular mode 0600")
    allowed = {"PSY_JWT_SECRET"}
    if role == "services":
        allowed |= {"DATABASE_URL", "INDEXER_GRAPHQL_URL", "HASURA_GRAPHQL_ADMIN_SECRET"}
    values = {}
    for line in path.read_text().splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in allowed and key not in values and value
                and re.fullmatch(r"[A-Za-z0-9_:/@.%+?=&-]+", value),
                "credentials require only exact unquoted environment keys and URL-safe values")
        values[key] = value
    require(set(values) == allowed, "credential keys missing")
    validate_environment(values, role, topology)
    return values


def check_host(root, manifest, topology):
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
    credential_role = "services" if manifest["group"] == "services" else "indexer"
    read_credentials(Path(topology["credentials"]) / (credential_role + ".env"), credential_role, topology)
    for role in group["roles"]:
        unit = unit_name(role)
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
    if manifest["group"] == "services":
        require(not os.path.lexists(topology["nostr_state"]), "fresh Nostr state already exists")
        with socket.socket() as sock:
            sock.bind((topology["services_host"], topology["services_port"]))
    else:
        cursor = Path(topology["backup_dir"]) / "indexer_state"
        require(not os.path.lexists(cursor), "fresh cursor directory already exists; operator review required")
    return account


def unit_name(role):
    return ("psy-services-fresh-20261027-r3" if role == "services" else
            "psy-indexer-fresh-20261027-r3-" + role) + ".service"


def install(root, manifest, topology, account):
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
    if manifest["group"] != "services":
        cursor = Path(topology["backup_dir"]) / "indexer_state"
        cursor.mkdir(mode=0o750)
        os.chown(cursor, account.pw_uid, account.pw_gid)
    for role in topology["groups"][manifest["group"]]["roles"]:
        name = unit_name(role)
        write_new(Path("/etc/systemd/system") / name, (root / "units" / name).read_bytes(), 0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("INSTALL PASS; no start/enable or database operation performed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["verify", "check-host", "install", "guard"])
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--role", choices=["services", "coordinator", "realm0", "realm1"])
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
    manifest, topology = load_package(args.package, expected)
    if args.mode == "guard":
        require(manifest["l1_ready"], "fresh L1 documents missing")
        require(args.role in topology["groups"][manifest["group"]]["roles"], "role mismatch")
        validate_environment(os.environ, args.role, topology)
    elif args.mode in ("check-host", "install"):
        account = check_host(args.package, manifest, topology)
        if args.mode == "install":
            require(args.apply, "install needs explicit --apply")
            install(args.package, manifest, topology, account)
    print(args.mode.upper() + " PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Do not echo credential values, subprocess output or URL parsing exceptions.
        print("FAILED: " + (str(exc) if isinstance(exc, ValidationError) else type(exc).__name__))
        raise SystemExit(1)
