#!/usr/bin/env python3
"""Prepare and bootstrap a private Faucet using retained host-bound credentials."""
import argparse
import base64
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

SOURCE = "3d31758738f833a7eea6f9ff7fd680a69a0d9a44"
GENESIS_SHA256 = "f839b453ab130c29998620c4c5d4bf9a30ce341a2e7c480aa9dbd8ed10902173"
BINARY_SHA256 = "601af4fe4c642680720526da1a9dd5b0d75b764a6a9e3916cec07859adca4135"
CANONICAL_SHA256 = "c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0"
RPC_SHA256 = "362be1695045cabc4f2df3353f499cabbac1cd70116df742eef3bbc1455ed3a5"
OPERATORS_SHA256 = "18911c1ed70c5be25af168979499f75a1cb9ea4b91923fbf4743653caaa644df"
ACCOUNT = "psy-faucet-r2"
OLD_CUSTODY = Path("/etc/psy-faucet/core-testnet-20261026-r2-x2")
RELEASE = Path("/opt/psy-faucet/releases/core-testnet-20261027-r3-x2")
CUSTODY = Path("/etc/psy-faucet/core-testnet-20261027-r3-x2")
STATE = Path("/var/lib/psy-faucet-r3-x2")
UNITS = Path("/etc/systemd/system")
UNIT = "psy-faucet-r3.service"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "LANG": "C"}


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
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, owner)
                and not info.st_mode & 0o022, "unsafe parent")


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def run(*args, data=None):
    return subprocess.check_output(args, input=data, stderr=subprocess.PIPE, timeout=45, env=ENV)


def validate_spec(raw):
    spec = json.loads(raw)
    require(set(spec) == {"hostname", "listen_addr"}, "unexpected host spec fields")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", spec["hostname"]), "invalid hostname")
    host, port = spec["listen_addr"].rsplit(":", 1)
    address = ipaddress.ip_address(host)
    require(address.version == 4 and address.is_private and not address.is_loopback
            and not address.is_unspecified and not address.is_multicast and port == "29998", "private listen required")
    return spec


def unit(spec_sha):
    return f"""[Unit]
Description=Psy Faucet r3 private acceptance
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
User={ACCOUNT}
WorkingDirectory={STATE}
StateDirectory={STATE.name}
StateDirectoryMode=0700
LoadCredentialEncrypted=operators.json:{CUSTODY}/operators.cred
Environment=PSY_NETWORK=testnet
Environment=PSY_CONFIG_PATH={RELEASE}/canonical.json
Environment=HOME={STATE}
Environment=RUST_LOG=info,psy_provider=warn
Environment=RAYON_NUM_THREADS=4
Environment=MALLOC_CONF=narenas:16,dirty_decay_ms:1000,muzzy_decay_ms:1000
Environment=PSY_FAUCET_REQUIRE_TURNSTILE=0
Environment=PSY_FAUCET_WINDOW_CHECKPOINTS=120
ExecStart=/usr/bin/python3 -I -B {RELEASE}/prepare_faucet.py run --spec-sha256 {spec_sha}
Restart=on-failure
RestartSec=10
TimeoutStopSec=180
KillSignal=SIGINT
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths={STATE}
CapabilityBoundingSet=
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitCORE=0
LimitNOFILE=65536
MemoryHigh=22G
MemoryMax=26G
MemorySwapMax=12G

[Install]
WantedBy=multi-user.target
""".encode()


def validate_payload(files):
    require(set(files) == {"psy_user_cli", "canonical.json", "rpc.json", "host.json", "prepare_faucet.py", UNIT},
            "package inventory mismatch")
    for name, expected in (("psy_user_cli", BINARY_SHA256), ("canonical.json", CANONICAL_SHA256),
                           ("rpc.json", RPC_SHA256)):
        require(digest(files[name]) == expected, "public artifact hash mismatch")
    validate_spec(files["host.json"])
    require(files[UNIT] == unit(digest(files["host.json"])), "unit mismatch")
    require(files["prepare_faucet.py"] == read_file(Path(__file__).absolute()), "helper mismatch")


def prepare(args):
    spec_raw = read_file(args.host_spec)
    require(digest(spec_raw) == args.spec_sha256, "host spec pin mismatch")
    files = {"psy_user_cli": read_file(args.binary), "canonical.json": read_file(args.canonical),
             "rpc.json": read_file(args.rpc), "host.json": spec_raw,
             "prepare_faucet.py": read_file(Path(__file__).absolute()), UNIT: unit(args.spec_sha256)}
    validate_payload(files)
    manifest = {"version": 1, "source": SOURCE, "genesis_sha256": GENESIS_SHA256,
                "operators_sha256": OPERATORS_SHA256, "operator_count": 100, "public_switch_allowed": False,
                "files": {name: digest(raw) for name, raw in files.items()}}
    args.output.mkdir(mode=0o700)
    for name, raw in dict(files, **{"manifest.json": encode(manifest)}).items():
        write_new(args.output / name, raw)
    return {"prepared": True, "manifest_sha256": digest(encode(manifest)), "secrets_copied": False}


def read_package(package, expected_sha):
    owner = package.lstat()
    require(stat.S_ISDIR(owner.st_mode) and not owner.st_mode & 0o022, "unsafe package directory")
    safe_parents(package, owner.st_uid)
    raw = read_file(package / "manifest.json", owner.st_uid)
    require(digest(raw) == expected_sha, "manifest pin mismatch")
    manifest = json.loads(raw)
    require(set(manifest) == {"version", "source", "genesis_sha256", "operators_sha256", "operator_count",
                              "public_switch_allowed", "files"}
            and manifest["version"] == 1 and manifest["source"] == SOURCE
            and manifest["genesis_sha256"] == GENESIS_SHA256 and manifest["operators_sha256"] == OPERATORS_SHA256
            and manifest["operator_count"] == 100 and manifest["public_switch_allowed"] is False, "manifest identity mismatch")
    names = {"psy_user_cli", "canonical.json", "rpc.json", "host.json", "prepare_faucet.py", UNIT}
    require(set(manifest["files"]) == names and {p.name for p in package.iterdir()} == names | {"manifest.json"},
            "package inventory mismatch")
    files = {name: read_file(package / name, owner.st_uid) for name in names}
    require(all(digest(raw) == manifest["files"][name] for name, raw in files.items()), "package hash mismatch")
    validate_payload(files)
    return manifest, files


def unit_state(name):
    result = subprocess.run(["systemctl", "show", name, "-p",
                             "LoadState,ActiveState,SubState,MainPID,UnitFileState,Job"],
                            capture_output=True, text=True, timeout=20, env=ENV)
    require(result.returncode in (0, 1), "unit query failed")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def check_stopped():
    for name in ("psy-faucet-r2.service", "parth-faucet-server.service", UNIT):
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


def credential():
    path = OLD_CUSTODY / "operators.cred"
    safe_parents(path)
    ciphertext = read_file(path, 0, private=True)
    audit = json.loads(read_file(OLD_CUSTODY / "installed.json", 0, private=True))
    require(digest(ciphertext) == audit["credential_sha256"] and audit["operators_sha256"] == OPERATORS_SHA256
            and audit["operators"] == 100, "retained credential provenance mismatch")
    raw = run("systemd-creds", "--name=operators.json", "decrypt", "-", "-", data=ciphertext)
    require(digest(raw) == OPERATORS_SHA256, "operator identity hash mismatch")
    require(len(json.loads(raw)["operators"]) == 100, "operator count mismatch")
    return ciphertext


def check_host(spec):
    require(os.geteuid() == 0 and os.uname().machine == "x86_64", "root x86_64 required")
    require(socket.gethostname() == spec["hostname"], "wrong hostname")
    account = pwd.getpwnam(ACCOUNT)
    require(account.pw_uid != 0 and account.pw_gid != 0, "existing nonroot account required")
    addresses = json.loads(run("ip", "-j", "address", "show"))
    host = spec["listen_addr"].rsplit(":", 1)[0]
    require(any(row.get("ifname", "").startswith("wg") and any(a.get("local") == host
                for a in row.get("addr_info", [])) for row in addresses), "WG listener address missing")
    check_stopped()
    with socket.socket() as probe:
        probe.bind((host, 29998))
    for path in (RELEASE, CUSTODY, STATE, UNITS / UNIT):
        require(not os.path.lexists(path), "destination exists; preserve partial state")
        safe_parents(path)
    for root in (UNITS, Path("/run/systemd/system"), Path("/etc/systemd/system.control"),
                 Path("/run/systemd/system.control"), Path("/usr/lib/systemd/system")):
        require(not os.path.lexists(root / UNIT) and not os.path.lexists(root / (UNIT + ".d")), "unit collision")
    return account


def bootstrap(args):
    require(not args.start_private or args.public_ingress_closed, "private startup requires closed public ingress")
    manifest, files = read_package(args.package, args.manifest_sha256)
    spec = validate_spec(files["host.json"])
    account = check_host(spec)
    encrypted = credential()
    check_stopped()
    RELEASE.mkdir(mode=0o755)
    RELEASE.chmod(0o755)
    for name, raw in dict(files, **{"manifest.json": encode(manifest)}).items():
        write_new(RELEASE / name, raw, 0o755 if name == "psy_user_cli" else 0o644)
    CUSTODY.mkdir(mode=0o700)
    write_new(CUSTODY / "operators.cred", encrypted)
    require(digest(read_file(CUSTODY / "operators.cred", 0, private=True)) == digest(encrypted), "credential copy mismatch")
    STATE.mkdir(mode=0o700)
    os.chown(STATE, account.pw_uid, account.pw_gid)
    write_new(UNITS / UNIT, files[UNIT], 0o644)
    run("systemd-analyze", "verify", str(UNITS / UNIT))
    run("systemctl", "daemon-reload")
    check_stopped()
    audit = {"installed": True, "started": False, "enabled": False, "public_switch": False,
             "operators": 100, "operators_sha256": OPERATORS_SHA256, "credential_sha256": digest(encrypted),
             "manifest_sha256": args.manifest_sha256, "operator_plaintext_written": False,
             "old_state_preserved": True, "new_state": str(STATE), "acceptance": "PENDING"}
    write_new(CUSTODY / "installed.json", encode(audit))
    if args.start_private:
        run("systemctl", "start", UNIT)
        audit["started"] = True
        audit["unit"] = unit_state(UNIT)
    return audit


def run_faucet(args):
    require(os.geteuid() == pwd.getpwnam(ACCOUNT).pw_uid != 0, "service account required")
    spec_raw = read_file(RELEASE / "host.json", 0)
    require(digest(spec_raw) == args.spec_sha256, "host spec pin mismatch")
    spec = validate_spec(spec_raw)
    require(socket.gethostname() == spec["hostname"], "wrong hostname")
    raw = (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "operators.json").read_bytes()
    require(digest(raw) == OPERATORS_SHA256, "operator credential hash mismatch")
    env = {name: os.environ[name] for name in ("PSY_NETWORK", "PSY_CONFIG_PATH", "HOME", "RUST_LOG",
        "RAYON_NUM_THREADS", "MALLOC_CONF", "PSY_FAUCET_REQUIRE_TURNSTILE", "PSY_FAUCET_WINDOW_CHECKPOINTS") if name in os.environ}
    env["PATH"] = "/usr/bin:/bin"
    env["PSY_FAUCET_OPERATORS_JSON_B64"] = base64.b64encode(raw).decode("ascii")
    os.execve(str(RELEASE / "psy_user_cli"), ["psy_user_cli", "faucet-server", "--listen-addr",
              spec["listen_addr"], "--rpc-config", str(RELEASE / "rpc.json")], env)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    for name in ("binary", "canonical", "rpc", "host-spec", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--spec-sha256", required=True)
    p = commands.add_parser("bootstrap")
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--manifest-sha256", required=True)
    p.add_argument("--start-private", action="store_true")
    p.add_argument("--public-ingress-closed", action="store_true")
    p = commands.add_parser("run")
    p.add_argument("--spec-sha256", required=True)
    args = parser.parse_args(argv)
    return {"prepare": prepare, "bootstrap": bootstrap, "run": run_faucet}[args.command](args)


if __name__ == "__main__":
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception as error:
        raise SystemExit("Faucet failed: " + type(error).__name__ + "; details suppressed; preserve partial artifacts.") from None
