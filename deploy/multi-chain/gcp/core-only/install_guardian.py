#!/usr/bin/env python3
"""Local-only Guardian installation, reusing this host's retained custody.

python3 -B install_guardian.py plan|check-host|install --spec FILE --spec-sha256 HASH [--apply]
plan reads artifacts only. check-host is read-only/root-only. install needs --apply;
it never enables/starts/stops services, generates keys, migrates DBs or uses SSH.
Failures after writes retain the partial destination for operator inspection.

The operator-owned private JSON has exactly these fields:
version: 3; guardian_id: 1..3; hostname; address (private IPv4);
guardian_history: {listen_address, rpc_url}, explicitly approved private HTTP origin;
proof_origins: {prove_proxy_url: [origins], system_prove_proxy_url: [origins]};
service_user: psy-guardian-N (must already exist, non-root);
memory_high_gib; memory_max_gib; custody_keystore_sha256;
build, binary, canonical_config, rpc_config, wrapper: each {path, sha256};
l1_documents: {} while pending, otherwise exactly sepolia, bscTestnet,
baseSepolia, each {summary: {path, sha256}, receipt: {path, sha256}}.
All input paths are absolute without whitespace, substitutions or traversal.
Spec must be mode 0600, owned by the invoking UID; pin its bytes out of band.
Transfer reviewed installer/wrapper and public artifacts separately; NEVER package
keys or credentials. The installed wrapper must match the reviewed sibling file.
Canonical config is the build-pinned testnet config; rpc_config may change ONLY
coordinator/realm RPC URLs to private origins and proof URLs to proof_origins.
USER proof and L1 document origins require private IPv4 HTTPS or IPv4 loopback
HTTP. SYSTEM proof origins may also use private IPv4 HTTP. No other loopback
exception is permitted; every proof URL must match the explicit operator spec.
An absent/null canonical guardian_history must be filled from the explicit spec;
an existing history must match exactly. Canonical/build bytes remain unchanged.
L1 documents must be real fresh deployment outputs, not proposed addresses.
Pending documents permit plan only. Real RPC/proof/membership acceptance and
any service activation remain separate operator gates, even after installation.
Before activation, confirm /usr/bin/python3 and its resolved executable are
root-owned, executable and not group/other-writable on the target host.
R3 uses new units/releases/state; retained units and custody are never changed.
The assigned R2 Guardian must exist, be inactive with PID zero and disabled.
R1/R2/R3 units are scanned; a static R1 Guardian additionally needs no aliases,
drop-ins, enablement symlinks or queued jobs. This exception never applies to
R2/R3/Relayer. Fresh L1 documents require separate operator approval; retained
deployment documents are not authorization for the new L1 cohort.
"""

import argparse
import copy
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
from urllib.parse import urlsplit


RUNTIME_SOURCE = "3d31758738f833a7eea6f9ff7fd680a69a0d9a44"
KEY_SOURCE = "de539f565ec1a92f91bb4e9686e1442e89ba8639"
BUILD_HASH = "4432ea02ead2f2fd48a723b911049f5dcdb8d1ef80072518361759ab77628072"
MAGIC = "0x1337CF514544CF69"
CUSTODY = Path("/var/lib/psy-guardian-custody")
RELEASES = Path("/opt/psy-guardian/releases/core-testnet-20261027-r3")
STATES = Path("/var/lib/psy-guardian/core-testnet-20261027-r3")
UNITS = Path("/etc/systemd/system")
CHAINS = {"sepolia": (0, 11155111), "bscTestnet": (1, 97), "baseSepolia": (2, 84532)}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: require(False, "nonfinite JSON"))
    require(isinstance(value, dict), "JSON object required")
    return value


def pin(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            and value != "0" * 64, "invalid SHA256")
    return value


def path_value(value):
    require(isinstance(value, str) and re.fullmatch(r"/[a-zA-Z0-9_./-]+", value)
            and ".." not in value.split("/") and "//" not in value, "unsafe absolute path")
    return Path(value)


def directory(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = () if str(path) == "/" else path_value(str(path)).parts[1:]
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, private=False, uid=None, limit=8 * 1024 * 1024):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular single-link file required")
        if private:
            require(info.st_uid == (os.geteuid() if uid is None else uid)
                    and stat.S_IMODE(info.st_mode) == 0o600, "private file owner/mode mismatch")
        raw = stream.read(limit + 1)
        require(0 < len(raw) <= limit, "invalid input size")
        return raw


def artifact(field, limit=8 * 1024 * 1024):
    require(isinstance(field, dict) and set(field) == {"path", "sha256"}, "artifact fields mismatch")
    raw = read(path_value(field["path"]), limit=limit)
    require(digest(raw) == pin(field["sha256"]), "artifact hash mismatch")
    return raw


def private_ip(value):
    address = ipaddress.IPv4Address(value)
    require(any(address in ipaddress.ip_network(block) for block in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")), "private IPv4 required")
    return str(address)


def origins(urls, private=True):
    require(isinstance(urls, list) and 1 <= len(urls) <= 8 and len(set(urls)) == len(urls),
            "distinct nonempty URL list required")
    for value in urls:
        require(isinstance(value, str) and not any(c.isspace() for c in value), "invalid URL")
        url = urlsplit(value)
        require(url.scheme in ("http", "https") and url.hostname and not url.username
                and not url.password and not url.query and not url.fragment
                and url.path in ("", "/"), "HTTP origin required")
        require(url.port is None or 0 < url.port <= 65535, "invalid port")
        if private:
            private_ip(url.hostname)
            require(url.port is not None, "private endpoint port required")


def guardian_origins(urls):
    origins(urls, private=False)
    for value in urls:
        url = urlsplit(value)
        address = ipaddress.IPv4Address(url.hostname)
        if url.scheme == "http":
            require(address.is_loopback, "Guardian proof/L1 HTTP must use loopback")
        else:
            private_ip(str(address))


def validate_rpc(canonical, rpc, spec):
    require(canonical["defaultNetwork"] == "testnet" and rpc["defaultNetwork"] == "testnet",
            "testnet selection required")
    base = canonical["networks"]["testnet"]
    network = rpc["networks"]["testnet"]
    require(base["magic"] == MAGIC, "testnet magic mismatch")
    restored = copy.deepcopy(rpc)
    target = restored["networks"]["testnet"]
    for field, ids in (("coordinator_configs", [0]), ("realm_configs", [0, 1])):
        require([row["id"] for row in network[field]] == ids, "topology mismatch")
        for index, row in enumerate(network[field]):
            origins(row["rpc_url"])
            target[field][index]["rpc_url"] = base[field][index]["rpc_url"]
    proof_fields = ("prove_proxy_url", "system_prove_proxy_url")
    approved = spec["proof_origins"]
    require(isinstance(approved, dict) and set(approved) == set(proof_fields), "explicit proof origins required")
    for field in proof_fields:
        require(network[field] == approved[field], "proof origins differ from operator approval")
        origins(network[field], private=False)
        for value in network[field]:
            if field == "prove_proxy_url":
                guardian_origins([value])
            elif not ipaddress.IPv4Address(urlsplit(value).hostname).is_loopback:
                origins([value])
        target[field] = base[field]
    history = network.get("guardian_history")
    require(isinstance(history, dict) and set(history) == {"listen_address", "rpc_url"}
            and history == spec["guardian_history"], "history must match explicit operator approval")
    listen = urlsplit("//" + history["listen_address"])
    require(listen.hostname and listen.port and not listen.path and not listen.username
            and not listen.password and not listen.query and not listen.fragment, "invalid history listen address")
    private_ip(listen.hostname)
    origins([history["rpc_url"]])
    require(history["rpc_url"] == "http://" + history["listen_address"], "history HTTP origin differs from listen address")
    require(base.get("guardian_history") is None or base["guardian_history"] == history,
            "existing canonical history cannot change")
    if "guardian_history" in base:
        target["guardian_history"] = base["guardian_history"]
    else:
        del target["guardian_history"]
    require(restored == canonical, "non-URL config change rejected")
    guardians = network["guardian_configs"]
    require(sorted(row["id"] for row in guardians) == [1, 2, 3], "three Guardian IDs required")
    local = next(row for row in guardians if row["id"] == spec["guardian_id"])
    listen = urlsplit("//" + local["listen_address"])
    require(listen.hostname == spec["address"] and listen.port and not listen.path, "Guardian bind mismatch")
    hashes = network["guardian_initial_member_hashes"]
    require(isinstance(hashes, list) and len(hashes) == 3
            and len({commitment(value) for value in hashes}) == 3, "three distinct commitments required")
    return network, listen.port


def commitment(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,64}", value), "invalid commitment")
    require(int(value, 16) > 0, "zero commitment")
    return f"{int(value, 16):064x}"


def l1_files(documents):
    require(isinstance(documents, dict) and (not documents or set(documents) == set(CHAINS)),
            "all three real L1 documents required, or empty while pending")
    files = {}
    for name, fields in documents.items():
        require(set(fields) == {"summary", "receipt"}, "L1 fields mismatch")
        summary, receipt = artifact(fields["summary"]), artifact(fields["receipt"])
        doc, proxy = decode(summary), decode(receipt)
        chain = doc["protocol"]["chain"]
        index, chain_id = CHAINS[name]
        require(type(chain["l1ChainIndex"]) is int and chain["l1ChainIndex"] == index
                and str(chain["l1ChainId"]) == str(chain_id) and str(doc["chainId"]) == str(chain_id),
                "L1 testnet identity mismatch")
        guardian_origins([chain["defaultRpcUrl"]])
        bridge = doc["core"]["Bridge"]
        require(isinstance(bridge, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", bridge)
                and int(bridge, 16) != 0 and proxy["address"].lower() == bridge.lower()
                and doc.get("contracts", {}).get("Bridge", bridge).lower() == bridge.lower(), "Bridge receipt mismatch")
        block = proxy["receipt"]["blockNumber"]
        require(type(block) is int and block >= 0, "real deployment block required")
        require(isinstance(doc["network"], str) and doc["network"], "deployment network missing")
        files[f"{name}/deployed-contracts.json"] = summary
        files[f"{name}/Bridge_Proxy.json"] = receipt
    return files


def load_plan(spec_path, spec_hash):
    raw = read(path_value(str(spec_path)), private=True)
    require(digest(raw) == pin(spec_hash), "operator spec hash mismatch")
    spec = decode(raw)
    require(set(spec) == {"version", "guardian_id", "hostname", "address", "guardian_history", "proof_origins", "service_user",
                          "memory_high_gib", "memory_max_gib", "custody_keystore_sha256",
                          "build", "binary", "canonical_config", "rpc_config", "wrapper", "l1_documents"},
            "operator spec fields mismatch")
    guardian_id = spec["guardian_id"]
    require(type(spec["version"]) is int and spec["version"] == 3
            and type(guardian_id) is int and guardian_id in (1, 2, 3), "invalid version or Guardian ID")
    require(isinstance(spec["hostname"], str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", spec["hostname"]),
            "invalid hostname")
    private_ip(spec["address"])
    require(spec["service_user"] == f"psy-guardian-{guardian_id}", "dedicated service user required")
    high, maximum = spec["memory_high_gib"], spec["memory_max_gib"]
    require(type(high) is int and type(maximum) is int and 1 <= high < maximum <= 64, "invalid memory bounds")
    pin(spec["custody_keystore_sha256"])
    build_raw = artifact(spec["build"])
    require(digest(build_raw) == BUILD_HASH, "reviewed build manifest required")
    build = decode(build_raw)
    require(build["source_commit"] == RUNTIME_SOURCE and build["network"] == "testnet", "runtime source mismatch")
    canonical, rpc = artifact(spec["canonical_config"]), artifact(spec["rpc_config"])
    require(digest(canonical) == build["config_sha256"], "canonical build config mismatch")
    network, port = validate_rpc(decode(canonical), decode(rpc), spec)
    binary = artifact(spec["binary"], limit=512 * 1024 * 1024)
    require(digest(binary) == build["binaries"]["psy_relayer_cli"] and binary[:6] == b"\x7fELF\x02\x01"
            and binary[18:20] == b"\x3e\x00", "reviewed x86_64 relayer required")
    wrapper = artifact(spec["wrapper"])
    require(wrapper == read(Path(__file__).absolute().with_name("guardian_exec.py")), "reviewed sibling wrapper required")
    files = {"build.json": build_raw, "canonical.json": canonical, "rpc.json": rpc,
             "psy_relayer_cli": binary, "guardian_exec.py": wrapper, "operator.json": raw}
    files.update(l1_files(spec["l1_documents"]))
    return spec, files, network, port


def unit(spec):
    guardian_id = spec["guardian_id"]
    name = f"guardian-{guardian_id}"
    release, state = RELEASES / name, STATES / name
    credential = f"psy-guardian-{guardian_id}-password"
    return ("\n".join([
        "[Unit]", "Description=Psy testnet Guardian signer", "ConditionHost=" + spec["hostname"],
        "Wants=network-online.target", "After=network-online.target", "StartLimitIntervalSec=600", "StartLimitBurst=3",
        "[Service]", "Type=simple", "User=" + spec["service_user"], "Group=" + spec["service_user"],
        "UMask=0077", "WorkingDirectory=" + str(state), "Environment=HOME=" + str(release / "home"),
        "Environment=PSY_NETWORK=testnet", "Environment=PSY_CONFIG_PATH=" + str(release / "canonical.json"),
        "Environment=RUST_LOG=info", "Environment=RUST_MIN_STACK=134217728",
        f"LoadCredentialEncrypted={credential}:{CUSTODY / name / (credential + '.cred')}",
        f"ExecStart=/usr/bin/python3 -I -B {release / 'guardian_exec.py'} {guardian_id}",
        "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true", "NoNewPrivileges=true",
        "ReadOnlyPaths=" + str(release), "ReadWritePaths=" + str(state / "db"),
        "CapabilityBoundingSet=", "RestrictSUIDSGID=true", "LimitCORE=0", "LimitNOFILE=65536",
        f"MemoryHigh={spec['memory_high_gib']}G", f"MemoryMax={spec['memory_max_gib']}G",
        "Restart=on-failure", "RestartSec=15", "TimeoutStopSec=300",
        "StandardOutput=journal", "StandardError=journal", "", "[Install]", "WantedBy=multi-user.target", "",
    ])).encode()


def command(argv):
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}).stdout
    except (OSError, subprocess.SubprocessError):
        raise ValueError("host command failed; details withheld") from None


def trusted_directory(path, private=False):
    fd = directory(path)
    try:
        info = os.fstat(fd)
        require(info.st_uid == 0 and not info.st_mode & 0o022
                and (not private or stat.S_IMODE(info.st_mode) == 0o700), "unsafe root directory")
    finally:
        os.close(fd)


def static_guardian_unlinked(name):
    require(re.fullmatch(r"psy-guardian-[123]\.service", name), "static exception is old Guardian only")
    values = dict(line.split("=", 1) for line in command([
        "systemctl", "show", name, "--property=FragmentPath,DropInPaths,Names"]).splitlines() if "=" in line)
    require(values.get("FragmentPath") == str(UNITS / name) and values.get("DropInPaths") == ""
            and values.get("Names", "").split() == [name], "static Guardian fragment, drop-in or alias mismatch")
    paths = command(["systemd-analyze", "unit-paths"]).splitlines()
    require(str(UNITS) in paths, "unit search paths invalid")
    def failed(_):
        raise ValueError("cannot inspect unit enablement paths")
    for root in paths:
        path = path_value(root)
        if not os.path.lexists(path):
            continue
        require(path.is_dir(), "unit search root is not a directory")
        for parent, directories, files in os.walk(path, followlinks=False, onerror=failed):
            for entry in directories + files:
                link = Path(parent) / entry
                if not link.is_symlink():
                    continue
                require(not (entry.endswith((".wants", ".requires", ".upholds")) and link.is_dir()),
                        "symlinked enablement directory requires operator inspection")
                require(link.resolve().name != name and entry != name, "static Guardian enablement or alias symlink")


def inactive_units(names, required, static_guardians=()):
    for name in names:
        output = command(["systemctl", "show", name,
                          "--property=LoadState,ActiveState,UnitFileState,MainPID"])
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        static = values.get("UnitFileState") == "static" and name in static_guardians
        require((name not in required and values.get("LoadState") == "not-found") or
                (values.get("LoadState") == "loaded" and values.get("ActiveState") == "inactive"
                 and values.get("MainPID") == "0" and (values.get("UnitFileState") == "disabled" or static)),
                "unit active or enabled, missing retained unit, or not strictly disabled")
        if static:
            static_guardian_unlinked(name)
    jobs = command(["systemctl", "list-jobs", "--no-legend", "--no-pager"])
    require(not any(len(row) > 1 and row[1] in names for row in map(str.split, jobs.splitlines())),
            "unit job queued")


def host_checks(spec, network, port):
    require(os.geteuid() == 0, "host checks require root")
    require(socket.gethostname() == spec["hostname"] and os.uname().machine == "x86_64", "wrong host")
    addresses = json.loads(command(["ip", "-j", "-4", "address", "show"]))
    require(spec["address"] in {a.get("local") for i in addresses for a in i.get("addr_info", [])}, "host IP mismatch")
    account = pwd.getpwnam(spec["service_user"])
    require(account.pw_uid > 0 and account.pw_gid > 0
            and grp.getgrnam(spec["service_user"]).gr_gid == account.pw_gid,
            "dedicated non-root account/group required")
    require(int(command(["systemctl", "--version"]).split()[1]) >= 250, "systemd 250+ required")
    inactive_units([f"psy-guardian-{generation}{i}.service" for generation in ("", "r2-", "r3-") for i in (1, 2, 3)],
                   {f"psy-guardian-r2-{spec['guardian_id']}.service"},
                   {f"psy-guardian-{i}.service" for i in (1, 2, 3)})
    require(not any(len(row) > 3 and row[3].rsplit(":", 1)[-1] == str(port)
                    for row in map(str.split, command(["ss", "-H", "-ltn"]).splitlines())), "Guardian port occupied")
    guardian_id = spec["guardian_id"]
    name = f"guardian-{guardian_id}"
    custody = CUSTODY / name
    for path in (CUSTODY, custody):
        trusted_directory(path, private=True)
    for parent in CUSTODY.parents:
        trusted_directory(parent)
    public = decode(read(custody / "public.json", private=True, uid=0, limit=65536))
    require(public["guardian_id"] == guardian_id and public["node_source"] == KEY_SOURCE
            and public["host"] == spec["address"] and public["destination"] == str(custody), "custody identity mismatch")
    require(commitment(public["public_key_hash"]) == commitment(network["guardian_initial_member_hashes"][guardian_id - 1]),
            "custody does not match Genesis commitment")
    key = read(custody / f"{name}.keystore.json", private=True, uid=0, limit=65536)
    encrypted = decode(key)
    require(encrypted.get("version") == 3 and isinstance(encrypted.get("crypto", encrypted.get("Crypto")), dict)
            and encrypted.get("crypto", encrypted.get("Crypto")), "encrypted keystore required")
    require(digest(key) == public["keystore_sha256"] == spec["custody_keystore_sha256"], "custody key pin mismatch")
    read(custody / f"psy-guardian-{guardian_id}-password.cred", private=True, uid=0, limit=65536)
    for path in (RELEASES / name, STATES / name):
        require(not os.path.lexists(path), "destination exists; inspect partial install")
        for parent in path.parents:
            if os.path.lexists(parent):
                trusted_directory(parent)
                require(os.stat(parent).st_mode & 0o001, "service ancestor blocks traversal")
    unit_paths = command(["systemd-analyze", "unit-paths"]).splitlines()
    require(str(UNITS) in unit_paths, "unit search paths invalid")
    for root in unit_paths:
        for unit_name in (f"psy-guardian-r3-{guardian_id}.service", "psy-guardian-r3-.service",
                          "psy-guardian-.service", "psy-.service", "service"):
            for suffix in ("", ".d"):
                require(not os.path.lexists(path_value(root) / (unit_name + suffix)), "existing unit or inherited drop-in")
    for parent in (UNITS, *UNITS.parents):
        trusted_directory(parent)
    return account, key


def mkdir(path, uid=0, gid=0, mode=0o755):
    parent = directory(path.parent)
    try:
        os.mkdir(path.name, mode, dir_fd=parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def write(path, raw, mode=0o600, uid=0, gid=0):
    parent = directory(path.parent)
    temporary = ".guardian-" + os.urandom(12).hex()
    created = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        created = True
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
    finally:
        if created:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def run(mode, spec_path, spec_hash, apply=False):
    require(mode in ("plan", "check-host", "install") and (apply == (mode == "install")), "install requires --apply only")
    spec, files, network, port = load_plan(spec_path, spec_hash)
    pending = not spec["l1_documents"]
    if mode != "plan":
        require(not pending, "L1 deployment documents pending; plan only")
        account, key = host_checks(spec, network, port)
        if mode == "install":
            name = f"guardian-{spec['guardian_id']}"
            release, state = RELEASES / name, STATES / name
            parents = set(RELEASES.parents) | set(STATES.parents) | {RELEASES, STATES}
            for path in sorted(parents, key=lambda value: len(value.parts)):
                if not os.path.lexists(path):
                    mkdir(path)
            mkdir(release)
            mkdir(state)
            mkdir(state / "db", account.pw_uid, account.pw_gid, 0o700)
            for part in (release / "home", release / "home/.psy", release / "home/.psy/keystore"):
                mkdir(part, account.pw_uid, account.pw_gid, 0o700)
            for chain in CHAINS:
                mkdir(release / chain)
            for name, raw in files.items():
                write(release / name, raw, mode=0o600 if name == "operator.json" else
                      (0o755 if name == "psy_relayer_cli" else 0o644))
            write(release / f"home/.psy/keystore/guardian-{spec['guardian_id']}.keystore.json", key,
                  uid=account.pw_uid, gid=account.pw_gid)
            write(UNITS / f"psy-guardian-r3-{spec['guardian_id']}.service", unit(spec), mode=0o644)
            command(["systemctl", "daemon-reload"])
    return {"guardian_id": spec["guardian_id"], "mode": mode, "runtime_source": RUNTIME_SOURCE,
            "key_source": KEY_SOURCE, "l1_documents_pending": pending, "started": False,
            "enabled": False, "deployment_ready": False, "release_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("plan", "check-host", "install"))
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(run(args.mode, args.spec, args.spec_sha256, args.apply), sort_keys=True))
    except Exception:
        raise SystemExit("Guardian install check failed; details withheld; never overwrite partial destinations") from None


if __name__ == "__main__":
    main()
