#!/usr/bin/env python3
"""Local plan/check-host/install for one fresh Envio release; never start or restart services."""
import argparse
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
from urllib.parse import quote


SOURCE = "da6391549e44d49c07e856eaeb5d0b8d7902ef17"
NODE_HASH = "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
DATABASE = "envio_bridge_fresh_20261026"
PROJECT = "psy-envio-fresh-20261026"
RELEASE = Path("/opt/psy-envio/releases/core-testnet-20261026")
STATE = Path("/var/lib/psy-envio/core-testnet-20261026")
CONFIG = Path("/etc/psy-envio/core-testnet-20261026")
UNIT = Path("/etc/systemd/system") / (PROJECT + ".service")
USER = "psy-envio-fresh"


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute path required")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink input rejected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 512 * 1024 * 1024, "invalid input file")
        if private:
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, "private input ownership/mode mismatch")
        return stream.read()


def inventory(root):
    root = root.absolute()
    require(not root.is_symlink(), "package root cannot be a symlink")
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            if relative == "build.json":
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                require(not os.path.isabs(target) and path.resolve(strict=False).is_relative_to(root), "external dependency link")
                result[relative] = {"link": target}
            elif stat.S_ISREG(info.st_mode):
                require(path.name != ".env", "plaintext environment file forbidden in package")
                result[relative] = {"sha256": sha(read(path)), "executable": bool(info.st_mode & 0o111)}
            else:
                require(stat.S_ISDIR(info.st_mode), "special package file rejected")
                result[relative] = {"directory": True}
    return result


def load_plan(spec_path, spec_hash):
    raw = read(spec_path, private=True)
    require(sha(raw) == spec_hash, "spec pin mismatch")
    spec = json.loads(raw)
    require(set(spec) == {"version", "hostname", "address", "postgres_container_id", "package", "build_sha256", "secrets"}
            and type(spec["version"]) is int and spec["version"] == 1, "spec fields mismatch")
    require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", spec["hostname"]), "invalid hostname")
    address = ipaddress.IPv4Address(spec["address"])
    require(any(address in ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")), "private host required")
    require(re.fullmatch(r"[a-f0-9]{64}", spec["postgres_container_id"]), "exact existing PG container ID required")
    root = Path(spec["package"])
    build_raw = read(root / "build.json")
    require(sha(build_raw) == spec["build_sha256"], "build pin mismatch")
    build = json.loads(build_raw)
    require(build["source_commit"] == SOURCE and build["node_sha256"] == NODE_HASH
            and all(build[key] is True for key in ("frozen_install_verified", "patches_verified", "native_help_verified", "generated_config_verified")),
            "verified build required")
    require(inventory(root) == build["files"], "package inventory mismatch")
    require(sha(read(root / "node/bin/node")) == NODE_HASH, "bundled Node mismatch")
    runtime = json.loads(read(root / "runtime-env.json"))
    require(set(runtime) == {"ENVIO_PG_HOST", "ENVIO_PG_PORT", "ENVIO_PG_USER", "ENVIO_PG_DATABASE",
                            "ENVIO_PG_PUBLIC_SCHEMA", "ENVIO_PG_SSL_MODE", "ENVIO_HASURA", "ENVIO_INDEXER_PORT",
                            "TUI_OFF", "HASURA_GRAPHQL_ENDPOINT", "ENVIO_RPC_POLLING_INTERVAL_MILLIS",
                            "PSY_ENVIO_FRESH_REORG_PARENT", "PSY_ENVIO_ORDERED_FAILOVER"}, "runtime environment fields mismatch")
    require(runtime["ENVIO_PG_DATABASE"] == DATABASE and runtime["ENVIO_PG_PUBLIC_SCHEMA"] == "envio"
            and runtime["ENVIO_PG_HOST"] == spec["address"] and runtime["ENVIO_PG_USER"] == DATABASE,
            "isolated database identity mismatch")
    require(runtime["ENVIO_RPC_POLLING_INTERVAL_MILLIS"] == "12000" and runtime["PSY_ENVIO_FRESH_REORG_PARENT"] == "1"
            and runtime["ENVIO_HASURA"] == "true" and runtime["PSY_ENVIO_ORDERED_FAILOVER"] in ("0", "1"), "runtime policy mismatch")
    compose = json.loads(read(root / "compose.hasura.json"))
    require(compose["name"] == PROJECT and set(compose["services"]) == {"graphql-engine"}
            and set(compose) == {"name", "services"}, "Hasura-only compose required")
    service = compose["services"]["graphql-engine"]
    require(set(service) == {"image", "user", "restart", "ports", "ulimits", "logging", "environment"}, "unexpected Compose capability")
    listener, = service["ports"]
    hasura_port = int(listener["published"])
    indexer_port = int(runtime["ENVIO_INDEXER_PORT"])
    require(listener["host_ip"] == spec["address"] and listener["target"] == 8080
            and service["restart"] == "no" and service["image"] == "hasura/graphql-engine:v2.43.0", "Hasura isolation mismatch")
    require(runtime["HASURA_GRAPHQL_ENDPOINT"] == f'http://{spec["address"]}:{hasura_port}/v1/metadata'
            and len({hasura_port, indexer_port, int(runtime["ENVIO_PG_PORT"])}) == 3
            and all(1024 <= p <= 65535 and p not in (8080, 18080, 9898) for p in (hasura_port, indexer_port)), "port identity mismatch")
    database_url = (f'postgresql://{DATABASE}:'
                    '${ENVIO_POSTGRES_PASSWORD_ENCODED:?URL-encoded private password required}'
                    f'@{spec["address"]}:{runtime["ENVIO_PG_PORT"]}/{DATABASE}')
    require(all(service["environment"][key] == database_url for key in
                ("HASURA_GRAPHQL_DATABASE_URL", "HASURA_GRAPHQL_METADATA_DATABASE_URL")), "Hasura must use only the new database")
    descriptor = spec["secrets"]
    require(set(descriptor) == {"path", "sha256"}, "secret descriptor mismatch")
    secret_raw = read(Path(descriptor["path"]), private=True)
    require(sha(secret_raw) == descriptor["sha256"], "secret file pin mismatch")
    secrets = json.loads(secret_raw)
    require(set(secrets) == {"postgres_password", "hasura_admin_secret"}
            and all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_+/=-]{24,256}", v) for v in secrets.values()), "invalid dedicated credentials")
    return spec, root, build_raw, build, runtime, secrets, (hasura_port, indexer_port)


def run(args, input=None):
    result = subprocess.run([str(arg) for arg in args], input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    require(result.returncode == 0, "host command failed; diagnostics suppressed")
    return result.stdout.strip()


def pg(spec, sql):
    return run(["docker", "exec", "-i", "--user", "postgres", spec["postgres_container_id"],
                "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"], sql)


def trusted(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "untrusted directory")


def host_checks(plan):
    spec, root, _, _, runtime, _, ports = plan
    require(os.geteuid() == 0 and socket.gethostname() == spec["hostname"] and os.uname().machine == "x86_64", "wrong host or user")
    addresses = json.loads(run(["ip", "-j", "-4", "address", "show"]))
    require(any(a.get("local") == spec["address"] for link in addresses for a in link.get("addr_info", [])), "host IP mismatch")
    account = pwd.getpwnam(USER)
    require(account.pw_uid > 0 and account.pw_gid == grp.getgrnam(USER).gr_gid > 0
            and account.pw_shell == "/usr/sbin/nologin", "dedicated non-root account required")
    for directory in (root, *root.parents):
        trusted(directory)
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            info = (Path(directory) / name).lstat()
            require(info.st_uid == 0 and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022), "untrusted package ownership/mode")
    for target in (RELEASE, STATE, CONFIG, UNIT, UNIT.with_name(UNIT.name + ".d")):
        require(not os.path.lexists(target), "destination already exists")
        for parent in target.parents:
            if os.path.lexists(parent):
                trusted(parent)
    require(not run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + PROJECT]), "Compose project already exists")
    info = json.loads(run(["docker", "inspect", "--format", "{{json .Id}}", spec["postgres_container_id"]]))
    require(info == spec["postgres_container_id"] and run(["docker", "inspect", "--format", "{{.State.Running}}", info]) == "true", "PG identity/state mismatch")
    role = runtime["ENVIO_PG_USER"]
    sql = ("SET default_transaction_read_only=on;\n"
           f"SELECT count(*) FROM pg_database WHERE datname='{DATABASE}';\n"
           f"SELECT count(*) FROM pg_roles WHERE rolname='{role}' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls;\n"
           f"SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='{role}');\n")
    require(pg(spec, sql).splitlines() == ["0", "1", "0"], "new DB must be absent; isolated login role must already exist")
    listeners = run(["ss", "-H", "-lnt"])
    require(not any(int(line.split()[3].rsplit(":", 1)[1]) in ports for line in listeners.splitlines()), "new port already in use")
    require(run(["systemctl", "show", UNIT.name, "--property=LoadState", "--value"]) == "not-found", "unit already loaded")
    run(["docker", "image", "inspect", "--format", "{{.Id}}", "hasura/graphql-engine:v2.43.0"])
    run(["docker", "compose", "version"])
    return account


def mkdir(path, mode=0o750, uid=0, gid=0):
    if not path.parent.exists():
        mkdir(path.parent, 0o755)
    os.mkdir(path, mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def write(path, raw, mode=0o640, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        os.fchown(stream.fileno(), 0, gid)
        os.fchmod(stream.fileno(), mode)
        stream.flush()
        os.fsync(stream.fileno())


def unit():
    node = str(RELEASE / "node/bin/node")
    return "\n".join([
        "[Unit]", "Description=Fresh testnet Envio indexer", "After=network-online.target docker.service",
        "[Service]", "Type=simple", "User=" + USER, "Group=" + USER, "UMask=0077",
        "WorkingDirectory=" + str(RELEASE / "generated"), "EnvironmentFile=" + str(CONFIG / "runtime.env"),
        f"ExecStartPre={node} -e 'require(\"./src/db/Migrations.res.js\").runUpMigrations(true,false)'",
        f"ExecStart={node} node_modules/ts-node/dist/bin.js src/Index.res.js", "Restart=on-failure", "RestartSec=10",
        "TimeoutStopSec=90", "KillSignal=SIGINT", "MemoryMax=1G", "LimitNOFILE=65536", "LimitCORE=0",
        "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true", "ProtectSystem=strict",
        "ReadWritePaths=" + str(STATE), "RestrictAddressFamilies=AF_UNIX AF_INET", "IPAddressDeny=any",
        "IPAddressAllow=localhost", "IPAddressAllow=10.0.0.0/8", "IPAddressAllow=172.16.0.0/12", "IPAddressAllow=192.168.0.0/16",
        "[Install]", "WantedBy=multi-user.target", "",
    ]).encode()


def install(plan):
    account = host_checks(plan)
    spec, root, build_raw, build, runtime, secrets, _ = plan
    mkdir(RELEASE, gid=account.pw_gid)
    for name, info in sorted(build["files"].items(), key=lambda pair: (pair[0].count("/"), pair[0])):
        target = RELEASE / name
        if "directory" in info:
            mkdir(target, gid=account.pw_gid)
        elif "sha256" in info:
            raw = read(root / name)
            require(sha(raw) == info["sha256"], "input changed during copy")
            write(target, raw, 0o750 if info["executable"] else 0o640, account.pw_gid)
    for name, info in build["files"].items():
        if "link" in info:
            os.symlink(info["link"], RELEASE / name)
    write(RELEASE / "build.json", build_raw, gid=account.pw_gid)
    require(inventory(RELEASE) == build["files"], "installed inventory mismatch")
    mkdir(STATE, 0o700, account.pw_uid, account.pw_gid)
    mkdir(CONFIG, 0o700)
    environment = dict(runtime, ENVIO_PG_PASSWORD=secrets["postgres_password"],
                       HASURA_GRAPHQL_ADMIN_SECRET=secrets["hasura_admin_secret"],
                       LOG_FILE=str(STATE / "envio.log"), FILE_LOG_LEVEL="info",
                       PATH=str(RELEASE / "node/bin") + ":/usr/bin:/bin",
                       TS_NODE_COMPILER_OPTIONS='{"module":"CommonJS","moduleResolution":"node","noImplicitAny":false}')
    line = lambda key, value: key + "=" + json.dumps(str(value)) + "\n"
    write(CONFIG / "runtime.env", "".join(line(k, v) for k, v in environment.items()).encode(), 0o600)
    compose_env = {"ENVIO_POSTGRES_PASSWORD_ENCODED": quote(secrets["postgres_password"], safe=""),
                   "HASURA_GRAPHQL_ADMIN_SECRET": secrets["hasura_admin_secret"]}
    write(CONFIG / "hasura.env", "".join(line(k, v) for k, v in compose_env.items()).encode(), 0o600)
    pg(spec, f'CREATE DATABASE "{DATABASE}" OWNER "{runtime["ENVIO_PG_USER"]}" TEMPLATE template0;\n'
             f'REVOKE CONNECT ON DATABASE "{DATABASE}" FROM PUBLIC;\n')
    write(UNIT, unit(), 0o644)
    run(["systemctl", "daemon-reload"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "check-host", "install"))
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        plan = load_plan(args.spec, args.spec_sha256)
        require(not args.apply or args.mode == "install", "apply only belongs to install")
        if args.mode == "install":
            require(args.apply, "install requires --apply")
            install(plan)
        elif args.mode == "check-host":
            host_checks(plan)
        print(json.dumps({"mode": args.mode, "installed": args.mode == "install", "database_created": args.mode == "install",
                          "started": False, "enabled": False, "postgres_restarted": False,
                          "deployment_ready": False, "release_approved": False}, sort_keys=True))
    except Exception:
        raise SystemExit("Envio refused; partial owned output retained, never overwrite; diagnostics suppressed") from None


if __name__ == "__main__":
    main()
