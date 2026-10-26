#!/usr/bin/env python3
"""Package/check/install fresh proxies without enabling or starting anything.

package --role system|user --source-commit FULL_SHA --binary FILE --binary-manifest FILE
        --binary-manifest-sha256 HASH --network-config FILE --output NEW_DIR
        --rpc-endpoints FILE --rpc-endpoints-sha256 HASH
        [--setup-dir DIR --verifier-dir DIR --setup-manifest FILE --setup-manifest-sha256 HASH]
        [--memory-high-gib N --memory-max-gib N]
verify|check-host|install --package DIR --package-sha256 HASH

The binary manifest is the approved build manifest: source_commit, network,
config_sha256, local_circuits_sha256, binaries.psy_user_cli are required.
The separately approved RPC endpoints JSON has exactly coordinator (id "0"),
realms (ids "0", "1"), prove_proxy_url, system_prove_proxy_url and placement.
URL values are arrays (three per coordinator/realm). placement must contain both
system and user, each with exactly host (hostname) and listen_addr (IP:port).
Placement is covered by rpc_endpoints_sha256 in the version-2 package approval.
Version-1 packages and endpoint maps without placement are rejected.
Only the runtime URL fields change;
build config, P2P and guardian commitments are retained. No network probes run.
Reachability and real RPC behavior require separate pre-activation verification.
MemoryHigh/Max default to 36/44 GiB system and 40/48 GiB user. Overrides may
lower these caps; cold four-cohort preload/proving memory fit remains unverified.
CPU provenance is retained from the build manifest, not an AVX-512 claim.
System additionally requires an approved setup manifest with exactly:
version (1), network, magic, consumer, generator, verifier_solidity_sha256, files.
consumer and generator each contain source_commit, binary_sha256, config_sha256,
local_circuits_sha256. They bind to the same approved build, but consumer uses
psy_user_cli and generator uses psy_relayer_cli. All cohorts must be regenerated
by that candidate. verifier_solidity_sha256 maps bridge_agg, deposit_append,
withdrawal_claim, reward_claim to the hashes of the four actual exported .sol
files supplied in --verifier-dir. files maps twelve runtime-relative paths to
{sha256, size}. Bridge is at root. No unmeasured wrapper fingerprints required.
This is an operator-approved provenance assertion, not a circuit/proof test.
No setup hashes are supplied by this script; user packages reject setup inputs.

Host checks require root to inspect private state paths. Install additionally
requires separate authorization. It only creates fresh paths
and reloads systemd. A partial install must be inspected; never auto-overwritten.
Verify the transferred installer against the reviewed source before executing it.
"""

import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from urllib.parse import urlsplit


RELEASE_ID = "core-testnet-20261026"
MAGIC = "0x1337CF514544CF69"
ROLES = ("system", "user")
MEMORY_GIB = {"system": (36, 44), "user": (40, 48)}
VERIFIERS = {"bridge_agg": "GnarkGroth16Verifier.sol", "deposit_append": "DepositBatchVerifier.sol",
             "withdrawal_claim": "WithdrawalClaimVerifier.sol", "reward_claim": "RewardClaimVerifier.sol"}
COHORTS = tuple(VERIFIERS)
SETUP_NAMES = tuple(("" if cohort == "bridge_agg" else cohort + "/") + name
                    for cohort in COHORTS
                    for name in ("circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"))
RELEASE_ROOT = Path("/opt/psy-core-prove-proxy/releases")
CONFIG_ROOT = Path("/etc/psy-core-prove-proxy")
STATE_ROOT = Path("/var/lib/psy-core-prove-proxy")
UNITS = Path("/etc/systemd/system")
OLD_UNITS = ("parth-prove-proxy@system.service", "parth-prove-proxy@user.service",
             "parth-offsite-prove-proxy.service")


class ProxyError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ProxyError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_hash(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            and value != "0" * 64, "invalid SHA-256 pin")
    return value


def validate_source(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value)
            and value != "0" * 40, "full immutable source commit required")
    return value


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def decode(raw):
    def unique(pairs):
        fields = {}
        for key, value in pairs:
            require(key not in fields, "duplicate JSON field")
            fields[key] = value
        return fields
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: require(False, "nonfinite JSON number"))
    require(isinstance(value, dict), "JSON object required")
    return value


def directory(path):
    path = Path(path).absolute()
    require(".." not in path.parts, "path traversal rejected")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_file(path):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    stream = os.fdopen(fd, "rb")
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        stream.close()
        raise ProxyError("single-link regular file required")
    return stream


def read_json_bytes(path):
    with open_file(path) as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "JSON input too large")
    decode(raw)
    return raw


def file_hash(path):
    with open_file(path) as stream:
        hasher = hashlib.sha256()
        size = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
            size += len(chunk)
    require(size > 0, "empty artifact")
    return {"sha256": hasher.hexdigest(), "size": size}


def validate_public(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            require(normalized not in ("token", "seed", "wallet", "headers")
                and not any(word in normalized for word in (
                "privatekey", "secret", "password", "mnemonic", "seedphrase",
                "credential", "authorization", "accesstoken", "apikey", "accesskey")),
                "secret-bearing JSON field rejected")
            validate_public(child)
    elif isinstance(value, list):
        for child in value:
            validate_public(child)
    elif isinstance(value, str):
        require("PRIVATE KEY" not in value and not value.lower().startswith("bearer "),
                "secret-bearing JSON value rejected")
        if "://" in value:
            require(not any(c.isspace() for c in value), "embedded or whitespace-bearing URL rejected")
            url = urlsplit(value)
            require(not url.username and not url.password and not url.query and not url.fragment,
                    "credential/query-bearing URL rejected")


def validate_build(build, network_raw, source_commit):
    validate_public(build)
    require(build["source_commit"] == validate_source(source_commit) and build["network"] == "testnet",
            "binary source or network mismatch")
    require(validate_hash(build["config_sha256"]) == digest(network_raw),
            "compiled network config mismatch")
    validate_hash(build["local_circuits_sha256"])
    validate_hash(build["binaries"]["psy_user_cli"])


def validate_urls(urls, count=None):
    require(isinstance(urls, list) and len(urls) > 0
            and (count is None or len(urls) == count)
            and all(isinstance(url, str) for url in urls) and len(set(urls)) == len(urls),
            "nonempty distinct RPC URL array required")
    for url in urls:
        validate_public(url)
        parsed = urlsplit(url)
        require(parsed.scheme in ("http", "https") and parsed.hostname
                and parsed.port is not None and 0 < parsed.port < 65536
                and parsed.path in ("", "/"), "RPC endpoint must be an HTTP origin with a port")


def validate_placement(endpoints):
    placement = endpoints.get("placement")
    require(isinstance(placement, dict) and set(placement) == set(ROLES), "complete role placement required")
    for role in ROLES:
        target = placement[role]
        require(isinstance(target, dict) and set(target) == {"host", "listen_addr"}, "placement schema mismatch")
        host, listen = target["host"], target["listen_addr"]
        require(isinstance(host, str) and 0 < len(host) <= 253 and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")),
            "literal hostname required")
        require(isinstance(listen, str) and re.fullmatch(r"[0-9a-fA-F:.\[\]]+", listen),
                "literal IP and port required")
        address = urlsplit("//" + listen)
        require(address.hostname and address.port is not None and 0 < address.port <= 65535,
                "valid listen port required")
        ip = ipaddress.ip_address(address.hostname)
        require(not ip.is_unspecified and not ip.is_multicast, "unicast listen address required")
    return placement


def rpc_config(network_raw, endpoints):
    config = decode(network_raw)
    validate_public(config)
    require(config["defaultNetwork"] == "testnet", "testnet selection required")
    network = config["networks"]["testnet"]
    require(network["magic"] == MAGIC, "testnet magic mismatch")
    require([coordinator["id"] for coordinator in network["coordinator_configs"]] == [0],
            "fresh coordinator configuration required")
    require([realm["id"] for realm in network["realm_configs"]] == [0, 1],
            "fresh realm configuration required")
    require(set(endpoints) == {"coordinator", "realms", "prove_proxy_url", "system_prove_proxy_url", "placement"}
            and set(endpoints["coordinator"]) == {"0"} and set(endpoints["realms"]) == {"0", "1"},
            "complete approved RPC endpoint map required")
    validate_public(endpoints)
    validate_placement(endpoints)
    for group, field in (("coordinator", "coordinator_configs"), ("realms", "realm_configs")):
        for node in network[field]:
            urls = endpoints[group][str(node["id"])]
            validate_urls(urls, 3)
            node["rpc_url"] = urls
    for field in ("prove_proxy_url", "system_prove_proxy_url"):
        validate_urls(endpoints[field])
        network[field] = endpoints[field]
    return encode(config)


def validate_setup(setup, build):
    require(set(setup) == {"version", "network", "magic", "consumer", "generator", "verifier_solidity_sha256", "files"},
            "setup manifest schema mismatch")
    require(type(setup["version"]) is int and setup["version"] == 1
            and setup["network"] == "testnet"
            and setup["magic"] == MAGIC, "setup provenance mismatch")
    provenance_fields = {"source_commit", "config_sha256", "local_circuits_sha256", "binary_sha256"}
    for role, binary in (("consumer", "psy_user_cli"), ("generator", "psy_relayer_cli")):
        provenance = setup[role]
        require(set(provenance) == provenance_fields, "setup provenance schema mismatch")
        for field in ("source_commit", "config_sha256", "local_circuits_sha256"):
            require(provenance[field] == build[field], "setup candidate build binding mismatch")
        require(validate_hash(provenance["binary_sha256"]) == validate_hash(build["binaries"][binary]),
                "setup generator or consumer binary mismatch")
    require(setup["consumer"]["binary_sha256"] != setup["generator"]["binary_sha256"],
            "distinct user and relayer CLI binaries required")
    require(set(setup["verifier_solidity_sha256"]) == set(COHORTS), "all four verifier hashes required")
    for sha256 in setup["verifier_solidity_sha256"].values():
        validate_hash(sha256)
    require(set(setup["files"]) == set(SETUP_NAMES), "exactly twelve setup files required")
    for record in setup["files"].values():
        require(set(record) == {"sha256", "size"} and type(record["size"]) is int
                and 0 < record["size"] < 2**53, "invalid setup file record")
        validate_hash(record["sha256"])


def paths(role):
    name = RELEASE_ID + "-" + role
    return RELEASE_ROOT / name, CONFIG_ROOT / name, STATE_ROOT / name


def unit_name(role):
    return "psy-core-prove-proxy-" + role + ".service"


def memory_limits(role, high=None, maximum=None):
    default_high, default_max = MEMORY_GIB[role]
    high = default_high if high is None else high
    maximum = default_max if maximum is None else maximum
    require(type(high) is int and type(maximum) is int and 0 < high < maximum <= default_max,
            "memory limits must be positive high < max within the approved host cap")
    return high, maximum


def proxy_unit(role, endpoints, high=None, maximum=None):
    release, config, state = paths(role)
    target = validate_placement(endpoints)[role]
    host, listen = target["host"], target["listen_addr"]
    high, maximum = memory_limits(role, high, maximum)
    return ("\n".join([
        "[Unit]", "Description=Psy testnet prove proxy " + role,
        "ConditionHost=" + host, "Wants=network-online.target", "After=network-online.target",
        "StartLimitIntervalSec=600", "StartLimitBurst=3", "",
        "[Service]", "Type=simple", "DynamicUser=yes", "User=psy-core-proxy-" + role,
        "UMask=0077", "StateDirectory=psy-core-prove-proxy/" + state.name,
        "StateDirectoryMode=0700", "WorkingDirectory=" + str(state),
        "Environment=HOME=" + str(release / "home"), "Environment=PSY_NETWORK=testnet",
        "Environment=PSY_CONFIG_PATH=" + str(config / "network.json"),
        "Environment=RUST_LOG=info", "Environment=RUST_MIN_STACK=134217728",
        "Environment=RAYON_NUM_THREADS=12", "Environment=TOKIO_WORKER_THREADS=4",
        "ExecStart=" + str(release / "psy_user_cli") + " prove-proxy --role " + role
        + " --listen-addr " + listen + " --rpc-config " + str(config / "rpc.json"),
        "Restart=on-failure", "RestartSec=15", "TimeoutStopSec=300", "LimitNOFILE=65536",
        f"MemoryHigh={high}G", f"MemoryMax={maximum}G",
        "LimitCORE=0", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true",
        "ProtectSystem=strict", "ReadWritePaths=" + str(state),
        "ReadOnlyPaths=" + str(release) + " " + str(config),
        "StandardOutput=journal", "StandardError=journal", "",
        "[Install]", "WantedBy=multi-user.target", "",
    ])).encode()


def write_new(path, source, expected_hash, mode):
    parent = directory(path.parent)
    temporary = ".proxy-" + os.urandom(12).hex()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as target:
            hasher = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(chunk)
                target.write(chunk)
            require(hasher.hexdigest() == expected_hash, "copy source hash mismatch")
            target.flush()
            os.fchmod(target.fileno(), mode)
            os.fsync(target.fileno())
        os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def create_directory(path, mode=0o755, fresh=False):
    parent = directory(path.parent)
    created = False
    try:
        try:
            os.mkdir(path.name, mode, dir_fd=parent)
            created = True
        except FileExistsError:
            require(not fresh, "destination already exists; inspect partial install")
        fd = directory(path)
        try:
            if created:
                os.fchmod(fd, mode)
            info = os.fstat(fd)
            require(info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                    "unsafe directory owner or mode")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def prepare_package(args):
    require(args.role == "system" or not any((args.setup_dir, args.verifier_dir, args.setup_manifest,
                                             args.setup_manifest_sha256)), "user role forbids setup")
    require(args.role == "user" or all((args.setup_dir, args.verifier_dir, args.setup_manifest,
                                        args.setup_manifest_sha256)), "system role requires all setup inputs")
    build_raw = read_json_bytes(args.binary_manifest)
    require(digest(build_raw) == validate_hash(args.binary_manifest_sha256), "binary manifest pin mismatch")
    build = decode(build_raw)
    network_raw = read_json_bytes(args.network_config)
    validate_build(build, network_raw, args.source_commit)
    endpoints_raw = read_json_bytes(args.rpc_endpoints)
    require(digest(endpoints_raw) == validate_hash(args.rpc_endpoints_sha256), "RPC endpoint approval pin mismatch")
    high, maximum = memory_limits(args.role, args.memory_high_gib, args.memory_max_gib)
    generated = {"build.json": build_raw, "network.json": network_raw, "rpc-endpoints.json": endpoints_raw,
                 "rpc.json": rpc_config(network_raw, decode(endpoints_raw)),
                 unit_name(args.role): proxy_unit(args.role, decode(endpoints_raw), high, maximum)}
    with open_file(Path(__file__).absolute()) as stream:
        generated["prepare_proxies.py"] = stream.read()
    sources = {"psy_user_cli": (args.binary, build["binaries"]["psy_user_cli"])}
    with open_file(args.binary) as stream:
        header = stream.read(20)
    require(len(header) == 20 and header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00",
            "x86_64 ELF binary required")
    setup_hash = None
    if args.role == "system":
        raw = read_json_bytes(args.setup_manifest)
        setup_hash = validate_hash(args.setup_manifest_sha256)
        require(digest(raw) == setup_hash, "setup manifest pin mismatch")
        setup = decode(raw)
        validate_setup(setup, build)
        generated["setup.json"] = raw
        for name in SETUP_NAMES:
            require(file_hash(args.setup_dir / name) == setup["files"][name], "setup artifact mismatch")
            sources["keystore/" + name] = (args.setup_dir / name, setup["files"][name]["sha256"])
        for cohort, name in VERIFIERS.items():
            sha256 = setup["verifier_solidity_sha256"][cohort]
            require(file_hash(args.verifier_dir / name)["sha256"] == sha256, "exported verifier mismatch")
            sources["verifiers/" + name] = (args.verifier_dir / name, sha256)
    require(file_hash(args.binary)["sha256"] == sources["psy_user_cli"][1], "binary hash mismatch")
    generated["package.json"] = encode({"version": 2, "role": args.role,
        "source_commit": args.source_commit,
        "rpc_endpoints_sha256": args.rpc_endpoints_sha256,
        "memory_high_gib": high, "memory_max_gib": maximum,
        "binary_manifest_sha256": args.binary_manifest_sha256, "setup_manifest_sha256": setup_hash,
        "installer_sha256": digest(generated["prepare_proxies.py"])})
    create_directory(args.output, 0o700, fresh=True)
    for name in sorted({str(Path(name).parent) for name in sources if "/" in name}, key=len):
        create_directory(args.output / name, 0o700, fresh=True)
    for name, raw in generated.items():
        write_new(args.output / name, io.BytesIO(raw), digest(raw), 0o600)
    for name, (path, sha256) in sources.items():
        with open_file(path) as stream:
            write_new(args.output / name, stream, sha256, 0o600)
    return {"role": args.role, "package_sha256": digest(generated["package.json"]),
            "started": False, "enabled": False, "claim_ready": False,
            "rpc_reachability_verified": False, "memory_fit_verified": False}


def read_package(package, package_hash):
    raw = read_json_bytes(package / "package.json")
    require(digest(raw) == validate_hash(package_hash), "package approval pin mismatch")
    approval = decode(raw)
    require(set(approval) == {"version", "role", "source_commit", "binary_manifest_sha256", "setup_manifest_sha256",
                              "rpc_endpoints_sha256", "installer_sha256", "memory_high_gib", "memory_max_gib"}
            and type(approval["version"]) is int
            and approval["version"] == 2 and approval["role"] in ROLES, "package schema mismatch")
    role = approval["role"]
    require(file_hash(Path(__file__).absolute())["sha256"] == validate_hash(approval["installer_sha256"]),
            "running installer differs from approved package")
    build_raw = read_json_bytes(package / "build.json")
    require(digest(build_raw) == approval["binary_manifest_sha256"], "binary manifest pin mismatch")
    build = decode(build_raw)
    network_raw = read_json_bytes(package / "network.json")
    validate_build(build, network_raw, approval["source_commit"])
    endpoints_raw = read_json_bytes(package / "rpc-endpoints.json")
    require(digest(endpoints_raw) == validate_hash(approval["rpc_endpoints_sha256"]), "RPC endpoint approval pin mismatch")
    expected = {"package.json": digest(raw), "build.json": digest(build_raw),
                "network.json": digest(network_raw), "rpc-endpoints.json": digest(endpoints_raw),
                "rpc.json": digest(rpc_config(network_raw, decode(endpoints_raw))),
                unit_name(role): digest(proxy_unit(role, decode(endpoints_raw),
                                                   approval["memory_high_gib"], approval["memory_max_gib"])),
                "psy_user_cli": build["binaries"]["psy_user_cli"],
                "prepare_proxies.py": validate_hash(approval["installer_sha256"])}
    if role == "system":
        raw = read_json_bytes(package / "setup.json")
        require(digest(raw) == validate_hash(approval["setup_manifest_sha256"]), "setup manifest pin mismatch")
        setup = decode(raw)
        validate_setup(setup, build)
        expected["setup.json"] = digest(raw)
        for name in SETUP_NAMES:
            require(file_hash(package / "keystore" / name) == setup["files"][name], "setup artifact mismatch")
            expected["keystore/" + name] = setup["files"][name]["sha256"]
        for cohort, name in VERIFIERS.items():
            expected["verifiers/" + name] = setup["verifier_solidity_sha256"][cohort]
    else:
        require(approval["setup_manifest_sha256"] is None, "user role forbids setup")
    found = set()
    expected_dirs = {"."} | {str(Path(name).parent) for name in expected if "/" in name}
    for root, dirs, files in os.walk(package, followlinks=False):
        relative = str(Path(root).relative_to(package))
        require(relative in expected_dirs, "unexpected package directory")
        fd = directory(Path(root))
        os.close(fd)
        require(not any((Path(root) / name).is_symlink() for name in dirs), "package symlink rejected")
        found.update(str((Path(root) / name).relative_to(package)) for name in files)
    require(found == set(expected), "package inventory mismatch")
    for name, sha256 in expected.items():
        require(file_hash(package / name)["sha256"] == sha256, "package file hash mismatch")
    return role, expected


def command(argv):
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        raise ProxyError("host command failed; no command output logged") from None


def check_host(role, endpoints):
    placement = validate_placement(endpoints)
    require(socket.gethostname() == placement[role]["host"], "wrong proxy host")
    require(os.uname().machine == "x86_64", "wrong proxy architecture")
    for unit in (*OLD_UNITS, *(unit_name(role) for role in ROLES)):
        output = command(["systemctl", "show", unit, "--property=LoadState,ActiveState,UnitFileState,MainPID"])
        properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if properties.get("LoadState") == "not-found":
            continue
        require(properties.get("ActiveState") == "inactive" and properties.get("MainPID") == "0"
                and properties.get("UnitFileState") in ("disabled", "masked"),
                "proxy unit is not inactive and disabled")
    jobs = command(["systemctl", "list-jobs", "--no-legend", "--no-pager"])
    require(not any("prove-proxy" in line for line in jobs.splitlines()), "proxy systemd job queued")
    sockets = command(["ss", "-H", "-ltn"])
    ports = {str(urlsplit("//" + target["listen_addr"]).port) for target in placement.values()}
    require(not any(len(fields) > 3 and fields[3].rsplit(":", 1)[-1] in ports
                    for fields in map(str.split, sockets.splitlines())), "proxy port occupied")


def check_destinations(role):
    release, config, state = paths(role)
    roots = (release, config, state, Path("/var/lib/private/psy-core-prove-proxy") / state.name)
    for path in roots:
        require(not os.path.lexists(path), "release/config/state already exists; inspect before retry")
    search = command(["systemd-analyze", "unit-paths"]).splitlines()
    require(str(UNITS) in search and all(path.startswith("/") for path in search), "invalid unit search paths")
    names = (unit_name(role), "psy-core-prove-proxy-.service", "psy-core-prove-.service",
             "psy-core-.service", "psy-.service", "service")
    for root in map(Path, search):
        for name in names:
            require(not os.path.lexists(root / name) and not os.path.lexists(root / (name + ".d")),
                    "existing new unit or inherited override")
    for path in roots:
        for parent in path.parents:
            if not os.path.lexists(parent):
                continue
            fd = directory(parent)
            try:
                info = os.fstat(fd)
                require(info.st_uid == 0 and not info.st_mode & 0o022, "unsafe destination ancestor")
                if path in (release, config):
                    require(info.st_mode & 0o001, "release/config ancestor blocks service traversal")
            finally:
                os.close(fd)
    for parent in (UNITS, *UNITS.parents):
        fd = directory(parent)
        try:
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "unsafe unit directory")
        finally:
            os.close(fd)


def install_proxy(package, package_hash, check_only=True):
    role, expected = read_package(package, package_hash)
    require(os.geteuid() == 0, "host checks require root; install requires separate authorization")
    endpoints_raw = read_json_bytes(package / "rpc-endpoints.json")
    require(digest(endpoints_raw) == expected["rpc-endpoints.json"], "RPC endpoint approval pin mismatch")
    check_host(role, decode(endpoints_raw))
    check_destinations(role)
    if not check_only:
        release, config, state = paths(role)
        targets = {name: release / name for name in expected}
        for name in ("network.json", "rpc.json"):
            targets[name] = config / name
        targets[unit_name(role)] = UNITS / unit_name(role)
        for name in expected:
            if name.startswith("keystore/"):
                targets[name] = release / "home" / ".psy" / name
        directories = {release, config, release / "home"}
        for path in tuple(directories):
            directories.update(path.parents)
        for path in targets.values():
            directories.update(path.parents)
        for path in sorted(directories, key=lambda p: (len(p.parts), str(p))):
            if path == Path("/"):
                continue
            create_directory(path, fresh=path in (release, config, state))
        # Unit last: a failed copy never exposes an incomplete service definition.
        for name in sorted(targets, key=lambda name: name == unit_name(role)):
            with open_file(package / name) as stream:
                write_new(targets[name], stream, expected[name], 0o755 if name == "psy_user_cli" else 0o644)
        command(["systemctl", "daemon-reload"])
    return {"role": role, "mode": "checked" if check_only else "installed", "started": False,
            "enabled": False, "claim_ready": False, "rpc_reachability_verified": False, "memory_fit_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="action", required=True)
    package = commands.add_parser("package")
    package.add_argument("--role", choices=ROLES, required=True)
    package.add_argument("--source-commit", required=True)
    for name in ("binary", "binary-manifest", "network-config", "rpc-endpoints", "output"):
        package.add_argument("--" + name, type=Path, required=True)
    package.add_argument("--binary-manifest-sha256", required=True)
    package.add_argument("--rpc-endpoints-sha256", required=True)
    package.add_argument("--memory-high-gib", type=int)
    package.add_argument("--memory-max-gib", type=int)
    for name in ("setup-dir", "verifier-dir", "setup-manifest"):
        package.add_argument("--" + name, type=Path)
    package.add_argument("--setup-manifest-sha256")
    for name in ("verify", "check-host", "install"):
        action = commands.add_parser(name)
        action.add_argument("--package", type=Path, required=True)
        action.add_argument("--package-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "package":
            report = prepare_package(args)
        elif args.action == "verify":
            role, _ = read_package(args.package, args.package_sha256)
            report = {"role": role, "verified": True, "claim_ready": False,
                      "rpc_reachability_verified": False, "memory_fit_verified": False}
        else:
            report = install_proxy(args.package, args.package_sha256, args.action == "check-host")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        print('{"error":"proxy preparation failed; input or host safety gate rejected; no input values logged"}',
              file=sys.stderr)
        return 1
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
