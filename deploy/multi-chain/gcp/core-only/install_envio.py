#!/usr/bin/env python3
"""Plan, check-host, install and activate one fresh Envio release from the release lock.

install never starts services. activate without --apply only reports; with --apply it starts this release's
Envio unit, waits for polling on all three chains and builds the Deposit query indexes. Envio runs with
ENVIO_HASURA=false; no Hasura is installed.
"""
import argparse
from dataclasses import dataclass
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
import time


USER = "psy-envio-fresh"
CHAIN_IDS = (11155111, 97, 84532)
UNIT_DIRECTORY = Path("/etc/systemd/system")
ACTIVATE_LIMIT_SECONDS = 600
POLL_SECONDS = 10
PATCH_TIMEOUT_SECONDS = 1800


@dataclass(frozen=True)
class EnvioRelease:
    source: str
    node_sha256: str
    database: str
    release: Path
    state: Path
    config: Path
    unit: Path
    indexer_port: int


def read_release_lock(path, expected_sha256):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("release lock hash mismatch")
    return json.loads(raw)


def load_release(lock):
    envio, paths = lock["envio"], lock["paths"]["envio"]
    return EnvioRelease(
        source=lock["sources"]["bridge_reader"], node_sha256=envio["node_sha256"], database=envio["database"],
        release=Path(paths["release"]), state=Path(paths["state"]),
        config=Path(paths["config"]), unit=UNIT_DIRECTORY / lock["units"]["envio"], indexer_port=envio["indexer_port"])


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


def load_plan(spec_path, spec_hash, release):
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
    require(build["source_commit"] == release.source and build["node_sha256"] == release.node_sha256
            and all(build[key] is True for key in ("frozen_install_verified", "patches_verified", "native_help_verified", "generated_config_verified")),
            "verified build required")
    require(inventory(root) == build["files"], "package inventory mismatch")
    require(sha(read(root / "node/bin/node")) == release.node_sha256, "bundled Node mismatch")
    runtime = json.loads(read(root / "runtime-env.json"))
    require(set(runtime) == {"ENVIO_PG_HOST", "ENVIO_PG_PORT", "ENVIO_PG_USER", "ENVIO_PG_DATABASE",
                            "ENVIO_PG_PUBLIC_SCHEMA", "ENVIO_PG_SSL_MODE", "ENVIO_HASURA", "ENVIO_INDEXER_PORT",
                            "TUI_OFF", "ENVIO_RPC_POLLING_INTERVAL_MILLIS",
                            "PSY_ENVIO_FRESH_REORG_PARENT", "PSY_ENVIO_ORDERED_FAILOVER"}, "runtime environment fields mismatch")
    require(runtime["ENVIO_PG_DATABASE"] == release.database and runtime["ENVIO_PG_PUBLIC_SCHEMA"] == "envio"
            and runtime["ENVIO_PG_HOST"] == spec["address"] and runtime["ENVIO_PG_USER"] == release.database,
            "isolated database identity mismatch")
    require(runtime["ENVIO_RPC_POLLING_INTERVAL_MILLIS"] == "12000" and runtime["PSY_ENVIO_FRESH_REORG_PARENT"] == "1"
            and runtime["ENVIO_HASURA"] == "false" and runtime["PSY_ENVIO_ORDERED_FAILOVER"] in ("0", "1"), "runtime policy mismatch")
    indexer_port = int(runtime["ENVIO_INDEXER_PORT"])
    require(indexer_port != int(runtime["ENVIO_PG_PORT"]) and indexer_port == release.indexer_port, "port identity mismatch")
    descriptor = spec["secrets"]
    require(set(descriptor) == {"path", "sha256"}, "secret descriptor mismatch")
    secret_raw = read(Path(descriptor["path"]), private=True)
    require(sha(secret_raw) == descriptor["sha256"], "secret file pin mismatch")
    secrets = json.loads(secret_raw)
    require(set(secrets) == {"postgres_password"}
            and all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_+/=-]{24,256}", v) for v in secrets.values()), "invalid dedicated credentials")
    return spec, root, build_raw, build, runtime, secrets, indexer_port


def run(args, input=None, timeout=120):
    result = subprocess.run([str(arg) for arg in args], input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, "host command failed; diagnostics suppressed")
    return result.stdout.strip()


def pg(spec, sql, database="postgres"):
    return run(["docker", "exec", "-i", "--user", "postgres", spec["postgres_container_id"],
                "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], sql)


def trusted(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "untrusted directory")


def host_checks(plan, release):
    spec, root, _, _, runtime, _, indexer_port = plan
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
    unit_path = release.unit
    for target in (release.release, release.state, release.config, unit_path, unit_path.with_name(unit_path.name + ".d")):
        require(not os.path.lexists(target), "destination already exists")
        for parent in target.parents:
            if os.path.lexists(parent):
                trusted(parent)
    info = json.loads(run(["docker", "inspect", "--format", "{{json .Id}}", spec["postgres_container_id"]]))
    require(info == spec["postgres_container_id"] and run(["docker", "inspect", "--format", "{{.State.Running}}", info]) == "true", "PG identity/state mismatch")
    role = runtime["ENVIO_PG_USER"]
    sql = ("SET default_transaction_read_only=on;\n"
           f"SELECT count(*) FROM pg_database WHERE datname='{release.database}';\n"
           f"SELECT count(*) FROM pg_roles WHERE rolname='{role}' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls;\n"
           f"SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='{role}');\n")
    require(pg(spec, sql).splitlines() == ["0", "1", "0"], "new DB must be absent; isolated login role must already exist")
    listeners = run(["ss", "-H", "-lnt"])
    require(not any(int(line.split()[3].rsplit(":", 1)[1]) == indexer_port for line in listeners.splitlines()), "new port already in use")
    require(run(["systemctl", "show", unit_path.name, "--property=LoadState", "--value"]) == "not-found", "unit already loaded")
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


def unit(release):
    node = str(release.release / "node/bin/node")
    return "\n".join([
        "[Unit]", "Description=Fresh testnet Envio indexer", "After=network-online.target docker.service",
        "[Service]", "Type=simple", "User=" + USER, "Group=" + USER, "UMask=0077",
        "WorkingDirectory=" + str(release.release / "generated"), "EnvironmentFile=" + str(release.config / "runtime.env"),
        f"ExecStartPre={node} -e 'require(\"./src/db/Migrations.res.js\").runUpMigrations(true,false)'",
        f"ExecStart={node} node_modules/ts-node/dist/bin.js src/Index.res.js", "Restart=on-failure", "RestartSec=10",
        "TimeoutStopSec=90", "KillSignal=SIGINT", "MemoryMax=1G", "LimitNOFILE=65536", "LimitCORE=0",
        "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true", "ProtectSystem=strict",
        "ReadWritePaths=" + str(release.state), "RestrictAddressFamilies=AF_UNIX AF_INET", "IPAddressDeny=any",
        "IPAddressAllow=localhost", "IPAddressAllow=10.0.0.0/8", "IPAddressAllow=172.16.0.0/12", "IPAddressAllow=192.168.0.0/16",
        "[Install]", "WantedBy=multi-user.target", "",
    ]).encode()


def install(plan, release):
    account = host_checks(plan, release)
    spec, root, build_raw, build, runtime, secrets, _ = plan
    mkdir(release.release, gid=account.pw_gid)
    for name, info in sorted(build["files"].items(), key=lambda pair: (pair[0].count("/"), pair[0])):
        target = release.release / name
        if "directory" in info:
            mkdir(target, gid=account.pw_gid)
        elif "sha256" in info:
            raw = read(root / name)
            require(sha(raw) == info["sha256"], "input changed during copy")
            write(target, raw, 0o750 if info["executable"] else 0o640, account.pw_gid)
    for name, info in build["files"].items():
        if "link" in info:
            os.symlink(info["link"], release.release / name)
    write(release.release / "build.json", build_raw, gid=account.pw_gid)
    require(inventory(release.release) == build["files"], "installed inventory mismatch")
    mkdir(release.state, 0o700, account.pw_uid, account.pw_gid)
    mkdir(release.config, 0o700)
    environment = dict(runtime, ENVIO_PG_PASSWORD=secrets["postgres_password"], LOG_FILE=str(release.state / "envio.log"), FILE_LOG_LEVEL="info",
                       PATH=str(release.release / "node/bin") + ":/usr/bin:/bin",
                       TS_NODE_COMPILER_OPTIONS='{"module":"CommonJS","moduleResolution":"node","noImplicitAny":false}')
    line = lambda key, value: key + "=" + json.dumps(str(value)) + "\n"
    write(release.config / "runtime.env", "".join(line(k, v) for k, v in environment.items()).encode(), 0o600)
    pg(spec, f'CREATE DATABASE "{release.database}" OWNER "{runtime["ENVIO_PG_USER"]}" TEMPLATE template0;\n'
             f'REVOKE CONNECT ON DATABASE "{release.database}" FROM PUBLIC;\n')
    write(release.unit, unit(release), 0o644)
    run(["systemctl", "daemon-reload"])


def unit_properties(release):
    text = run(["systemctl", "show", release.unit.name, "--property=LoadState,ActiveState,MainPID,NRestarts,UnitFileState"])
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def chain_rows(plan, release):
    spec = plan[0]
    sql = "SET default_transaction_read_only=on;\nSELECT id, source_block, max_reorg_depth FROM envio.envio_chains ORDER BY id;\n"
    rows = [line.split("|") for line in pg(spec, sql, release.database).splitlines() if "|" in line]
    return {int(row[0]): {"source_block": int(row[1] or 0), "max_reorg_depth": int(row[2] or 0)} for row in rows}


def polling_is_live(rows):
    return set(rows) == set(CHAIN_IDS) and all(row["source_block"] > 0 for row in rows.values())


def report(plan, release):
    properties = unit_properties(release)
    rows = chain_rows(plan, release) if properties.get("ActiveState") == "active" else {}
    return {"unit_active": properties.get("ActiveState") == "active" and int(properties.get("MainPID", "0")) > 0,
            "unit_restarts": int(properties.get("NRestarts", "0") or 0),
            "chains": {str(chain): row for chain, row in sorted(rows.items())}, "polling_live": polling_is_live(rows)}


def wait_until_ready(condition, release, label):
    deadline = time.monotonic() + ACTIVATE_LIMIT_SECONDS
    while not condition():
        require(unit_properties(release).get("ActiveState") != "failed", f"{label}: unit failed while waiting")
        require(time.monotonic() < deadline, f"{label}: not ready within {ACTIVATE_LIMIT_SECONDS}s")
        time.sleep(POLL_SECONDS)


def check_installed(plan, release):
    spec, root, build_raw, build, runtime, secrets, _ = plan
    require(os.geteuid() == 0, "root required")
    require(inventory(release.release) == build["files"] and read(release.release / "build.json") == build_raw, "installed release differs from the build")
    require(read(release.unit) == unit(release), "installed unit differs from the release")
    require(unit_properties(release).get("LoadState") == "loaded", "unit is not loaded")
    require(read(release.config / "runtime.env", private=True), "protected environment file missing")


def apply_indexes(plan, release):
    spec = plan[0]
    psql = f"docker exec -i --user postgres {spec['postgres_container_id']} psql -U postgres -d {release.database}"
    result = subprocess.run(["/usr/bin/python3", "-I", "-B", str(release.release / "patches/deposit-indexes.py"),
                             "--psql", psql, "--schema", "envio", "--mode", "apply"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=PATCH_TIMEOUT_SECONDS)
    require(result.returncode == 0, "Deposit query indexes did not build; rerun is safe")


def activate(plan, release, is_apply):
    check_installed(plan, release)
    if not is_apply:
        return report(plan, release)
    run(["systemctl", "enable", "--now", release.unit.name], timeout=ACTIVATE_LIMIT_SECONDS)
    wait_until_ready(lambda: unit_properties(release).get("ActiveState") == "active"
                     and int(unit_properties(release).get("MainPID", "0")) > 0, release, "Envio unit")
    wait_until_ready(lambda: polling_is_live(chain_rows(plan, release)), release, "Envio polling on three chains")
    apply_indexes(plan, release)
    return report(plan, release)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "check-host", "install", "activate"))
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--release-lock-sha256", required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        release = load_release(read_release_lock(args.release_lock, args.release_lock_sha256))
        plan = load_plan(args.spec, args.spec_sha256, release)
        require(not args.apply or args.mode in ("install", "activate"), "apply only belongs to install and activate")
        if args.mode == "install":
            require(args.apply, "install requires --apply")
            install(plan, release)
        elif args.mode == "check-host":
            host_checks(plan, release)
        elif args.mode == "activate":
            print(json.dumps(dict(activate(plan, release, args.apply), mode="activate", applied=args.apply), sort_keys=True))
            return
        print(json.dumps({"mode": args.mode, "installed": args.mode == "install", "database_created": args.mode == "install",
                          "started": False, "enabled": False, "postgres_restarted": False,
                          "deployment_ready": False, "release_approved": False}, sort_keys=True))
    except Exception:
        raise SystemExit("Envio refused; partial owned output retained, never overwrite; diagnostics suppressed") from None


if __name__ == "__main__":
    main()
