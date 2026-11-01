#!/usr/bin/env python3
"""Package, install and activate the batched Faucet of the release named by the release lock.

Every action takes --release-lock FILE --release-lock-sha256 HASH. The runtime binary, config, operator set,
account, listen port, unit name and install paths come from the lock; nothing release-specific is built in.
package builds a package that holds the Genesis operator file (mode 0600) and nothing from earlier releases.
activate installs when nothing is installed (the operator file is sealed to the host and the staged copy is
deleted), enables and starts the unit, waits until it stays active, and writes a report with lock_sha256,
request_sha256, unit, pid, binary_sha256 and operators_sha256.
operators-sha256 --operators FILE prints the hash and count of an operator file and never its content.
"""
import argparse
import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import resource
import socket
import stat
import subprocess
import time

UNITS = Path("/etc/systemd/system")
VAR_LIB = Path("/var/lib")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}
OPERATOR_COUNT = 100
STABLE_SECONDS = 20
POLL_SECONDS = 2
PACKAGE_FILES = ("psy_user_cli", "canonical.json", "rpc.json", "host.json", "prepare_faucet.py", "release-lock.json")
OPERATORS_FILE = "operators.json"
MANIFEST_FIELDS = {"version", "release_lock_sha256", "source", "operators_sha256", "operator_count", "rpc_sha256",
                   "public_switch_allowed", "files"}


@dataclass(frozen=True)
class FaucetRelease:
    release_id: str
    source: str
    magic: str
    binary_sha256: str
    canonical_sha256: str
    operators_sha256: str
    tool_sha256: str
    account: str
    port: int
    unit: str
    release: Path
    custody: Path
    state: Path
    hosts: dict
    lock_sha256: str


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def read_file(path, owner=None, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size < 160 * 1024**2, "unsafe file")
        require(owner is None or info.st_uid == owner, "wrong file owner")
        require(not private or stat.S_IMODE(info.st_mode) == 0o600, "private file must be0600")
        return stream.read()


def safe_parents(path, owner=0):
    for parent in path.parents:
        info = parent.lstat()
        # A sticky shared directory (/var/tmp) is safe: entries can only be replaced by their owner.
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, owner)
                and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "unsafe parent")


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def run(*args, data=None):
    return subprocess.check_output(args, input=data, stderr=subprocess.PIPE, timeout=45, env=ENV)


def validate_spec(release, raw):
    spec = json.loads(raw)
    require(set(spec) == {"hostname", "listen_addr"}, "unexpected host spec fields")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", spec["hostname"]), "invalid hostname")
    host, port = spec["listen_addr"].rsplit(":", 1)
    address = ipaddress.ip_address(host)
    require(address.version == 4 and address.is_private and not address.is_loopback
            and not address.is_unspecified and not address.is_multicast and port == str(release.port),
            "private listen required")
    require(release.hosts.get(spec["hostname"]) == host, "host spec differs from the release hosts")
    return spec


def operator_ids(raw):
    """Validate an operator file in memory and return its user IDs; no value is ever printed."""
    operators = json.loads(raw).get("operators")
    require(isinstance(operators, list) and len(operators) == OPERATOR_COUNT, "operator count mismatch")
    ids = [int(row["userId"]) for row in operators]
    require(len(set(ids)) == OPERATOR_COUNT, "operator user IDs must be unique")
    require(all(row.get("privateKey") and row.get("fingerprint") and row.get("address") for row in operators),
            "operator entry incomplete")
    return ids


def unit_text(release, spec_sha):
    state_name = release.state.relative_to(VAR_LIB)
    return f"""[Unit]
Description=Psy Faucet batched claims (10 per End Cap)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
User={release.account}
WorkingDirectory={release.state}
StateDirectory={state_name}
StateDirectoryMode=0700
LoadCredentialEncrypted=operators.json:{release.custody}/operators.cred
Environment=PSY_NETWORK=testnet
Environment=PSY_CONFIG_PATH={release.release}/canonical.json
Environment=HOME={release.state}
Environment=RUST_LOG=info,psy_provider=warn
Environment=RAYON_NUM_THREADS=4
Environment=MALLOC_CONF=narenas:16,dirty_decay_ms:1000,muzzy_decay_ms:1000
Environment=PSY_FAUCET_REQUIRE_TURNSTILE=0
Environment=PSY_FAUCET_WINDOW_CHECKPOINTS=120
ExecStart=/usr/bin/python3 -I -B {release.release}/prepare_faucet.py run --release-lock {release.release}/release-lock.json --release-lock-sha256 {release.lock_sha256} --spec-sha256 {spec_sha}
Restart=on-failure
RestartSec=10
TimeoutStopSec=180
KillSignal=SIGINT
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths={release.state}
CapabilityBoundingSet=
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitCORE=0
LimitNOFILE=65536
MemoryMax=20G
MemorySwapMax=0

[Install]
WantedBy=multi-user.target
""".encode()


def validate_payload(release, files, rpc_sha256):
    names = set(PACKAGE_FILES) | {release.unit}
    require(set(files) - {OPERATORS_FILE} == names, "package inventory mismatch")
    for name, expected in (("psy_user_cli", release.binary_sha256), ("canonical.json", release.canonical_sha256),
                           ("rpc.json", rpc_sha256), ("release-lock.json", release.lock_sha256),
                           ("prepare_faucet.py", release.tool_sha256)):
        require(digest(files[name]) == expected, "public artifact hash mismatch")
    network = json.loads(files["rpc.json"])
    require(network.get("defaultNetwork") == "testnet" and network["networks"]["testnet"]["magic"] == release.magic,
            "rpc config is not the release network")
    validate_spec(release, files["host.json"])
    require(files[release.unit] == unit_text(release, digest(files["host.json"])), "unit mismatch")
    require(files["prepare_faucet.py"] == read_file(Path(__file__).absolute()), "installer mismatch")
    if OPERATORS_FILE in files:
        require(digest(files[OPERATORS_FILE]) == release.operators_sha256, "operator set hash differs from the lock")
        operator_ids(files[OPERATORS_FILE])


def prepare(release, args):
    require(args.host in release.hosts, "faucet host is not a release host")
    spec_raw = encode({"hostname": args.host, "listen_addr": f"{release.hosts[args.host]}:{release.port}"})
    files = {"psy_user_cli": read_file(args.binary), "canonical.json": read_file(args.canonical),
             "rpc.json": read_file(args.rpc), "host.json": spec_raw,
             "prepare_faucet.py": read_file(Path(__file__).absolute()),
             "release-lock.json": read_file(args.release_lock), release.unit: unit_text(release, digest(spec_raw)),
             OPERATORS_FILE: read_file(args.operators, private=True)}
    validate_payload(release, files, args.rpc_sha256)
    manifest = {"version": 2, "release_lock_sha256": release.lock_sha256, "source": release.source,
                "operators_sha256": release.operators_sha256, "operator_count": OPERATOR_COUNT,
                "rpc_sha256": args.rpc_sha256, "public_switch_allowed": False,
                "files": {name: digest(raw) for name, raw in files.items()}}
    args.output.mkdir(mode=0o700)
    for name, raw in dict(files, **{"manifest.json": encode(manifest)}).items():
        write_new(args.output / name, raw)
    return {"prepared": True, "manifest_sha256": digest(encode(manifest)), "operator_file_copied": True}


def read_package(release, package, expected_sha, need_operators):
    owner = package.lstat()
    require(stat.S_ISDIR(owner.st_mode) and not owner.st_mode & 0o022, "unsafe package directory")
    safe_parents(package, owner.st_uid)
    raw = read_file(package / "manifest.json", owner.st_uid)
    require(digest(raw) == expected_sha, "manifest pin mismatch")
    manifest = json.loads(raw)
    require(set(manifest) == MANIFEST_FIELDS and manifest["version"] == 2 and manifest["source"] == release.source
            and manifest["release_lock_sha256"] == release.lock_sha256
            and manifest["operators_sha256"] == release.operators_sha256
            and manifest["operator_count"] == OPERATOR_COUNT and manifest["public_switch_allowed"] is False,
            "manifest identity mismatch")
    names = set(PACKAGE_FILES) | {release.unit, OPERATORS_FILE}
    present = {p.name for p in package.iterdir()} - {"manifest.json"}
    require(set(manifest["files"]) == names and present <= names and (present == names or not need_operators)
            and names - {OPERATORS_FILE} <= present, "package inventory mismatch")
    files = {name: read_file(package / name, owner.st_uid, private=name == OPERATORS_FILE) for name in present}
    require(all(digest(raw) == manifest["files"][name] for name, raw in files.items()), "package hash mismatch")
    validate_payload(release, files, manifest["rpc_sha256"])
    return manifest, files


def unit_state(name):
    result = subprocess.run(["systemctl", "show", name, "-p",
                             "LoadState,ActiveState,SubState,MainPID,UnitFileState,Job,NRestarts"],
                            capture_output=True, text=True, timeout=20, env=ENV)
    require(result.returncode in (0, 1), "unit query failed")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def faucet_unit_names(release):
    names = {release.unit}
    for command in (["list-units", "--all"], ["list-unit-files"]):
        listing = subprocess.run(["systemctl", *command, "--plain", "--no-legend", "--no-pager",
                                  "psy-faucet-*", "parth-faucet-*"], capture_output=True, text=True, timeout=20, env=ENV)
        require(listing.returncode == 0, "unit listing failed")
        names |= {line.split()[0] for line in listing.stdout.splitlines() if line.split()}
    return sorted(names)


def check_stopped(release):
    for name in faucet_unit_names(release):
        state = unit_state(name)
        require(state.get("ActiveState") == "inactive" and state.get("MainPID") == "0"
                and state.get("Job", "") in ("", "0"), "Faucet must be inactive without queued jobs")
        require(state.get("LoadState") == "not-found" or state.get("UnitFileState") in ("disabled", "masked"),
                "old Faucet must be disabled")
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            exe = Path(os.readlink(proc / "exe").removesuffix(" (deleted)")).name
        except FileNotFoundError:
            continue
        require(exe != "psy_user_cli", "existing psy_user_cli process")


def seal_operators(plain):
    return run("systemd-creds", "--name=operators.json", "encrypt", "-", "-", data=plain)


def check_sealed(release, ciphertext):
    plain = run("systemd-creds", "--name=operators.json", "decrypt", "-", "-", data=ciphertext)
    require(digest(plain) == release.operators_sha256, "sealed operator set differs from the lock")


def check_host(release, spec):
    require(os.geteuid() == 0 and os.uname().machine == "x86_64", "root x86_64 required")
    require(socket.gethostname() == spec["hostname"], "wrong hostname")
    account = pwd.getpwnam(release.account)
    require(account.pw_uid != 0 and account.pw_gid != 0, "existing nonroot account required")
    addresses = json.loads(run("ip", "-j", "address", "show"))
    host = spec["listen_addr"].rsplit(":", 1)[0]
    require(any(row.get("ifname", "").startswith("wg") and any(a.get("local") == host
                for a in row.get("addr_info", [])) for row in addresses), "WG listener address missing")
    check_stopped(release)
    with socket.socket() as probe:
        probe.bind((host, release.port))
    for path in (release.release, release.custody, release.state, UNITS / release.unit):
        require(not os.path.lexists(path), "destination exists; preserve partial state")
        safe_parents(path)
    for root in (UNITS, Path("/run/systemd/system"), Path("/etc/systemd/system.control"),
                 Path("/run/systemd/system.control"), Path("/usr/lib/systemd/system")):
        require(not os.path.lexists(root / release.unit) and not os.path.lexists(root / (release.unit + ".d")),
                "unit collision")
    return account


def install(release, manifest, files, manifest_sha256):
    spec = validate_spec(release, files["host.json"])
    account = check_host(release, spec)
    encrypted = seal_operators(files[OPERATORS_FILE])
    check_sealed(release, encrypted)
    release.release.mkdir(mode=0o755)
    release.release.chmod(0o755)
    for name, raw in dict({n: r for n, r in files.items() if n != OPERATORS_FILE},
                          **{"manifest.json": encode(manifest)}).items():
        write_new(release.release / name, raw, 0o755 if name == "psy_user_cli" else 0o644)
    release.custody.mkdir(mode=0o700)
    write_new(release.custody / "operators.cred", encrypted)
    release.state.mkdir(mode=0o700)
    os.chown(release.state, account.pw_uid, account.pw_gid)
    write_new(UNITS / release.unit, files[release.unit], 0o644)
    run("systemd-analyze", "verify", str(UNITS / release.unit))
    run("systemctl", "daemon-reload")
    check_stopped(release)
    audit = {"installed": True, "operators": OPERATOR_COUNT, "operators_sha256": release.operators_sha256,
             "sealed_sha256": digest(encrypted), "manifest_sha256": manifest_sha256,
             "operator_plaintext_written": False, "new_state": str(release.state)}
    write_new(release.custody / "installed.json", encode(audit))


def check_installed(release, manifest, files):
    for name, raw in files.items():
        if name != OPERATORS_FILE:
            require(file_hash(release.release / name) == digest(raw), "installed file differs from the package")
    require(file_hash(UNITS / release.unit) == digest(files[release.unit]), "installed unit differs from the package")
    check_sealed(release, read_file(release.custody / "operators.cred", 0, private=True))


def file_hash(path):
    return digest(read_file(path, 0))


def wait_stable(release):
    deadline = time.monotonic() + STABLE_SECONDS
    first = None
    while True:
        state = unit_state(release.unit)
        pid = int(state.get("MainPID", "0"))
        require(state.get("ActiveState") == "active" and pid > 0, "Faucet unit did not stay active")
        require(first in (None, pid), "Faucet main process changed")
        first = pid
        if time.monotonic() >= deadline:
            return pid
        time.sleep(POLL_SECONDS)


def running_binary_sha256(pid):
    with open("/proc/%d/exe" % pid, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_report(path, document):
    temporary = path.parent / (".report-" + os.urandom(8).hex())
    write_new(temporary, encode(document), 0o644)
    os.replace(temporary, path)


def activate(release, args):
    """Install when nothing is installed, enable and start the unit, then record unit, pid and binary hash."""
    require(os.geteuid() == 0, "activation requires root")
    require(re.fullmatch(r"[0-9a-f]{64}", args.request_sha256) and args.report_path.is_absolute(), "invalid request")
    targets = (release.release, release.custody, release.state, UNITS / release.unit)
    present = [os.path.lexists(path) for path in targets]
    if not any(present):
        manifest, files = read_package(release, args.package, args.package_sha256, True)
        install(release, manifest, files, args.package_sha256)
    else:
        require(all(present), "partial installation; inspect before retry")
        manifest, files = read_package(release, args.package, args.package_sha256, False)
        check_installed(release, manifest, files)
    staged = args.package / OPERATORS_FILE
    if os.path.lexists(staged):
        os.unlink(staged)
    run("systemctl", "enable", "--now", release.unit)
    pid = wait_stable(release)
    running = running_binary_sha256(pid)
    require(running == release.binary_sha256, "running binary differs from the lock")
    write_report(args.report_path, {"lock_sha256": release.lock_sha256, "request_sha256": args.request_sha256,
                                    "unit": release.unit, "pid": pid, "binary_sha256": running,
                                    "operators_sha256": release.operators_sha256})
    return {"mode": "activated", "unit": release.unit, "pid": pid}


def run_faucet(release, args):
    require(os.geteuid() == pwd.getpwnam(release.account).pw_uid != 0, "service account required")
    spec_raw = read_file(release.release / "host.json", 0)
    require(digest(spec_raw) == args.spec_sha256, "host spec pin mismatch")
    spec = validate_spec(release, spec_raw)
    require(socket.gethostname() == spec["hostname"], "wrong hostname")
    raw = (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "operators.json").read_bytes()
    require(digest(raw) == release.operators_sha256, "operator set hash differs from the lock")
    env = {name: os.environ[name] for name in ("PSY_NETWORK", "PSY_CONFIG_PATH", "HOME", "RUST_LOG",
        "RAYON_NUM_THREADS", "MALLOC_CONF", "PSY_FAUCET_REQUIRE_TURNSTILE", "PSY_FAUCET_WINDOW_CHECKPOINTS",
        "PSY_FAUCET_BATCH_MAX_IN_FLIGHT") if name in os.environ}
    env["PATH"] = "/usr/bin:/bin"
    env["PSY_FAUCET_OPERATORS_JSON_B64"] = base64.b64encode(raw).decode("ascii")
    os.execve(str(release.release / "psy_user_cli"), ["psy_user_cli", "faucet-server", "--listen-addr",
              spec["listen_addr"], "--rpc-config", str(release.release / "rpc.json")], env)


def read_release_lock(path, expected_sha256):
    raw = read_file(Path(path).absolute())
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) and digest(raw) == expected_sha256,
            "release lock hash mismatch")
    lock = json.loads(raw)
    faucet, paths = lock["faucet"], lock["paths"]["faucet"]
    release = FaucetRelease(lock["release_id"], lock["sources"]["runtime"], lock["network_magic"],
                            lock["binaries"]["psy_user_cli"], lock["inputs"]["canonical_config"],
                            faucet["operators_sha256"], lock["tool_sha256"]["prepare_faucet.py"], faucet["account"],
                            faucet["listen_port"], lock["units"]["faucet"], Path(paths["release"]),
                            Path(paths["config"]), Path(paths["state"]), lock["hosts"], expected_sha256)
    require(re.fullmatch(r"[0-9a-f]{64}", release.operators_sha256), "operator set is not pinned in the lock")
    require(release.state.parent == VAR_LIB or VAR_LIB in release.state.parents, "state path must be under /var/lib")
    return release


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sealed = commands.add_parser("operators-sha256")
    sealed.add_argument("--operators", type=Path, required=True)
    p = commands.add_parser("package")
    for name in ("binary", "canonical", "rpc", "operators", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--rpc-sha256", required=True)
    p.add_argument("--host", required=True)
    for name in ("verify", "activate", "run"):
        p = commands.add_parser(name)
        if name == "run":
            p.add_argument("--spec-sha256", required=True)
        else:
            p.add_argument("--package", type=Path, required=True)
            p.add_argument("--package-sha256", required=True)
        if name == "activate":
            p.add_argument("--request-sha256", required=True)
            p.add_argument("--report-path", type=Path, required=True)
    for name in ("package", "verify", "activate", "run"):
        commands.choices[name].add_argument("--release-lock", type=Path, required=True)
        commands.choices[name].add_argument("--release-lock-sha256", required=True)
    args = parser.parse_args(argv)
    if args.command == "operators-sha256":
        raw = read_file(args.operators, private=True)
        return {"operators_sha256": digest(raw), "operators": len(operator_ids(raw))}
    release = read_release_lock(args.release_lock, args.release_lock_sha256)
    if args.command == "package":
        return prepare(release, args)
    if args.command == "verify":
        read_package(release, args.package, args.package_sha256, True)
        return {"verified": True, "operators": OPERATOR_COUNT}
    return (activate if args.command == "activate" else run_faucet)(release, args)


if __name__ == "__main__":
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception as error:
        raise SystemExit("Faucet failed: " + type(error).__name__ + "; details suppressed; preserve partial artifacts.") from None
