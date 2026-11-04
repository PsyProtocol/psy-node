#!/usr/bin/env python3
"""Check-host, install, activate and report the Bridge Reader of one release from the release lock.

The Reader runs on the Services host, listens on loopback only and reads the Envio database through its read-only
role. install never starts anything; activate --apply enables the unit and waits until the Reader reports ready on
all three chains. The database login and the bearer token arrive on stdin and are written only to mode 0600 files.
"""
import argparse
from dataclasses import dataclass
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import urllib.request
from urllib.parse import quote


USER = "psy-bridge-reader"
SERVICES_USER = "parth"
BINARY = "psy-bridge-reader"
TOOL = "install_bridge_reader.py"
POSTGRES_ALIAS = "gcp-postgres"
POSTGRES_PORT = 5432
ENVIO_SCHEMA = "envio"
MEMORY_BUDGET_BYTES = 2 * 1024 ** 3
CHAIN_IDS = (11155111, 97, 84532)
UNIT_DIRECTORY = Path("/etc/systemd/system")
ACTIVATE_LIMIT_SECONDS = 120
POLL_SECONDS = 2
LOGIN = re.compile(r"[A-Za-z0-9_+/=-]{24,256}")
TOKEN = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ReaderRelease:
    binary_sha256: str
    tool_sha256: str
    release: Path
    config: Path
    client_token: Path
    unit: Path
    listen: str
    services_host: str
    postgres_host: str
    database: str
    role: str


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_release_lock(path, expected_sha256):
    raw = Path(path).read_bytes()
    require(sha(raw) == expected_sha256, "release lock hash mismatch")
    return raw, json.loads(raw)


def load_release(lock):
    reader = lock["bridge_reader"]
    return ReaderRelease(
        binary_sha256=lock["binaries"][BINARY], tool_sha256=lock["tool_sha256"][TOOL], release=Path(reader["release"]),
        config=Path(reader["config"]), client_token=Path(reader["client_token_file"]),
        unit=UNIT_DIRECTORY / lock["units"]["bridge_reader"], listen=reader["listen"],
        services_host=lock["services"]["listen"].rpartition(":")[0], postgres_host=lock["hosts"][POSTGRES_ALIAS],
        database=lock["envio"]["database"], role=reader["database_role"])


def read_secrets(raw):
    secrets = json.loads(raw)
    require(isinstance(secrets, dict) and set(secrets) == {"postgres_password", "token"}, "secret fields mismatch")
    require(isinstance(secrets["postgres_password"], str) and LOGIN.fullmatch(secrets["postgres_password"]),
            "invalid Reader database login")
    require(isinstance(secrets["token"], str) and TOKEN.fullmatch(secrets["token"]), "invalid Reader token")
    return secrets


def unit_text(release):
    return "\n".join([
        "[Unit]", "Description=psy-bridge-reader", "Wants=network-online.target", "After=network-online.target", "",
        "[Service]", "Type=simple", "User=" + USER, "Group=" + USER, "EnvironmentFile=" + str(release.config / "reader.env"),
        "ExecStart=" + str(release.release / BINARY), "Restart=always", "RestartSec=2", "TimeoutStopSec=15",
        "MemoryMax=3G", "LimitNOFILE=65536", "LimitCORE=0", "NoNewPrivileges=true", "PrivateTmp=true",
        "ProtectSystem=strict", "ProtectHome=true", "RestrictAddressFamilies=AF_UNIX AF_INET", "IPAddressDeny=any",
        "IPAddressAllow=localhost", f"IPAddressAllow={release.postgres_host}/32", "UMask=0077", "",
        "[Install]", "WantedBy=multi-user.target", ""]).encode()


def environment_text(release, secrets):
    url = (f"postgresql://{release.role}:{quote(secrets['postgres_password'], safe='')}@{release.postgres_host}:"
           f"{POSTGRES_PORT}/{release.database}")
    values = {"PSY_BRIDGE_READER_LISTEN": release.listen, "PSY_BRIDGE_READER_TOKEN_FILE": str(release.config / "token"),
              "PSY_BRIDGE_READER_DATABASE_URL": url, "PSY_BRIDGE_READER_DB_SCHEMA": ENVIO_SCHEMA,
              "PSY_BRIDGE_READER_MEMORY_BUDGET_BYTES": str(MEMORY_BUDGET_BYTES), "RUST_LOG": "info"}
    return "".join(key + "=" + json.dumps(value) + "\n" for key, value in values.items()).encode()


def run(argv, timeout=60):
    result = subprocess.run([str(arg) for arg in argv], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, "host command failed; diagnostics suppressed")
    return result.stdout.strip()


def trusted(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "untrusted directory")


def destinations(release):
    return (release.release, release.config, release.client_token.parent, release.unit, release.unit.with_name(release.unit.name + ".d"))


def host_checks(release, binary_raw):
    require(os.geteuid() == 0, "root required")
    require(release.services_host in run(["hostname", "-I"]).split(), "the Reader belongs on the Services host")
    require(sha(binary_raw) == release.binary_sha256, "Reader binary differs from the lock")
    account = pwd.getpwnam(USER)
    require(account.pw_uid > 0 and account.pw_gid == grp.getgrnam(USER).gr_gid > 0
            and account.pw_shell == "/usr/sbin/nologin", "dedicated non-root Reader account required")
    client = pwd.getpwnam(SERVICES_USER)
    require(client.pw_uid > 0, "the Services account must not be root")
    for target in destinations(release):
        require(not os.path.lexists(target), f"destination already exists: {target}; remove a partial Reader install by hand")
        for parent in target.parents:
            if os.path.lexists(parent):
                trusted(parent)
    require(run(["systemctl", "show", release.unit.name, "--property=LoadState", "--value"]) == "not-found", "unit already loaded")
    port = release.listen.rpartition(":")[2]
    require(not any(line.split()[3].rpartition(":")[2] == port for line in run(["ss", "-H", "-lnt"]).splitlines()),
            "Reader port already in use")
    return account, client


def mkdir(path, mode, uid=0, gid=0):
    if not path.parent.exists():
        mkdir(path.parent, 0o755)
    os.mkdir(path, mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def write(path, raw, mode, uid=0, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        stream.flush()
        os.fsync(stream.fileno())


def install(release, binary_raw, tool_raw, lock_raw, secrets):
    account, client = host_checks(release, binary_raw)
    require(sha(tool_raw) == release.tool_sha256, "installer differs from the lock")
    token = (secrets["token"] + "\n").encode()
    mkdir(release.release, 0o755)
    write(release.release / BINARY, binary_raw, 0o755)
    write(release.release / TOOL, tool_raw, 0o644)
    write(release.release / "release-lock.json", lock_raw, 0o644)
    mkdir(release.config, 0o750, gid=account.pw_gid)
    write(release.config / "token", token, 0o600, account.pw_uid, account.pw_gid)
    write(release.config / "reader.env", environment_text(release, secrets), 0o600)
    mkdir(release.client_token.parent, 0o755)
    write(release.client_token, token, 0o600, client.pw_uid, client.pw_gid)
    write(release.unit, unit_text(release), 0o644)
    run(["systemctl", "daemon-reload"])


def private_file(path, uid):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o600,
            "protected Reader file missing or exposed")


def check_installed(release):
    require(os.geteuid() == 0, "root required")
    require(sha((release.release / BINARY).read_bytes()) == release.binary_sha256, "installed Reader binary differs from the lock")
    require(release.unit.read_bytes() == unit_text(release), "installed unit differs from the release")
    private_file(release.config / "reader.env", 0)
    private_file(release.config / "token", pwd.getpwnam(USER).pw_uid)
    private_file(release.client_token, pwd.getpwnam(SERVICES_USER).pw_uid)
    require(run(["systemctl", "show", release.unit.name, "--property=LoadState", "--value"]) == "loaded", "unit is not loaded")


def fetch(url, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers=headers or {}), timeout=10) as response:
            return response.status, response.read()
    except OSError:
        return 0, b""


def summarize(status):
    """The parts of /v1/status that decide readiness; no tree roots or counts beyond what the decision needs."""
    return {"ready": status.get("ready") is True,
            "envio_chain_ids": sorted(row["chain_id"] for row in status.get("envio_chains", [])),
            "chains": [{"chain_index": row["chain_index"], "chain_id": row["chain_id"], "ready": row["ready"] is True,
                        "root_matches": row["tree_root"] == row["envio_tree_root"], "deposit_count": row["deposit_count"]}
                       for row in status.get("chains", [])]}


def is_ready(summary):
    return (summary["ready"] and summary["envio_chain_ids"] == sorted(CHAIN_IDS)
            and all(row["ready"] and row["root_matches"] and row["chain_id"] in CHAIN_IDS for row in summary["chains"]))


def report(release):
    code, _ = fetch(f"http://{release.listen}/health/ready")
    summary = {"ready": False, "envio_chain_ids": [], "chains": []}
    if code == 200:
        token = (release.config / "token").read_text().strip()
        status_code, body = fetch(f"http://{release.listen}/v1/status",
                                  {"Authorization": "Bearer " + token, "x-psy-lane": "background"})
        if status_code == 200:
            try:
                summary = summarize(json.loads(body))
            except (KeyError, TypeError, ValueError):
                pass
    return dict(summary, health_ready=code == 200, reader_ready=code == 200 and is_ready(summary))


def unit_properties(release):
    text = run(["systemctl", "show", release.unit.name, "--property=ActiveState,MainPID,NRestarts"])
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def activate(release, is_apply):
    check_installed(release)
    if is_apply:
        run(["systemctl", "enable", "--now", release.unit.name])
        deadline = time.monotonic() + ACTIVATE_LIMIT_SECONDS
        while not report(release)["reader_ready"]:
            require(unit_properties(release).get("ActiveState") != "failed", "Reader unit failed while waiting")
            require(time.monotonic() < deadline, f"Reader not ready within {ACTIVATE_LIMIT_SECONDS}s")
            time.sleep(POLL_SECONDS)
    return report(release)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check-host", "install", "activate", "status"))
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--release-lock-sha256", required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        lock_raw, lock = read_release_lock(args.release_lock, args.release_lock_sha256)
        release = load_release(lock)
        require(not args.apply or args.mode in ("install", "activate"), "apply only belongs to install and activate")
        require((args.binary is not None) == (args.mode in ("check-host", "install")), "--binary belongs to check-host and install")
        if args.mode == "check-host":
            host_checks(release, args.binary.read_bytes())
            result = {"installed": False}
        elif args.mode == "install":
            require(args.apply, "install requires --apply")
            install(release, args.binary.read_bytes(), Path(__file__).read_bytes(), lock_raw, read_secrets(sys.stdin.read(4096)))
            result = {"installed": True, "started": False}
        elif args.mode == "activate":
            result = dict(activate(release, args.apply), applied=args.apply)
        else:
            check_installed(release)
            result = report(release)
        print(json.dumps(dict(result, mode=args.mode), sort_keys=True))
    except ValueError as error:
        raise SystemExit(f"Bridge Reader refused: {error}; partial owned output retained, never overwrite") from None
    except Exception as error:
        raise SystemExit(f"Bridge Reader refused: {type(error).__name__}; partial owned output retained, never overwrite") from None


if __name__ == "__main__":
    main()
