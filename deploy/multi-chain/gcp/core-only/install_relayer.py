#!/usr/bin/env python3
"""Install-only Relayer for the approved fresh testnet; never starts or enables.

Keep the reviewed install_guardian.py beside this script; its bytes are pinned
before executing the shared checked filesystem helpers.
Commands: plan|check-host|install --spec <absolute-json> --spec-sha256 <sha256>.
Only install accepts and requires --apply. An empty l1_documents permits plan only.

Requires Python 3.11+. Operator JSON fields: version=3, hostname, address,
guardian_history={listen_address, rpc_url}, service_user=psy-core-relayer,
memory_high_gib, memory_max_gib, keystore_owner, build, binary, canonical_config,
rpc_config, daemon_config, wrapper, l1_keystore, password_credential, l1_documents.
Every artifact is {path: absolute-path, sha256: approved-sha256}. Key/password
artifacts are host-local inputs read only by check-host/install, never plan.
l1_documents maps sepolia/bscTestnet/baseSepolia to {summary: artifact,
receipt: artifact}; receipts are matching Bridge_Proxy.json deployment records.
Concrete endpoints and hosts belong only in the private operator inputs.

daemon_config is the operator's TOML, not generated from retained private keys.
plan parses it offline with tomllib and validates the pinned daemon's fields;
it does not execute the daemon or claim native Rust parse/runtime readiness.
Use the release/state paths below for rpc_config, guardian_root, proof_dir and
keystore_path. Set password_env=PSY_CORE_RELAYER_L1_PASSWORD on all three chains.
Use private HTTP origins for Services and daemon RPCs; no credential-bearing URLs.
Deployment-document and USER proof RPCs must be private IPv4 HTTPS or IPv4 HTTP loopback,
matching Guardian deposit verification. Required local forwarding is a separate
runtime gate. Preserve original deployment exports and hash-pin runtime copies.
An absent/null build guardian_history may be filled only from the approved spec;
existing history cannot be changed. Genesis commitments and build bytes stay fixed.
The encrypted credential must be made on this host with the helper's fixed name.
Before activation, verify /usr/bin/python3 and its resolved executable are
root-owned, executable and not group/other-writable on the target host.
R3 uses a new unit/release/state and copies the existing host-bound credential.
The old psy-core-relayer-r2.service must exist, be inactive with PID zero and
disabled; R1 and R3 are also scanned. Never reuse retained deployment documents
as authorization for the fresh L1 cohort; the operator must approve new exports.
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
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Relayer preparation requires Python 3.11+")
import tomllib
import types
from urllib.parse import urlsplit


_helper = Path(__file__).with_name("install_guardian.py")
try:
    _helper_bytes = _helper.read_bytes()
except OSError:
    raise SystemExit("Reviewed install_guardian.py sibling required") from None
if hashlib.sha256(_helper_bytes).hexdigest() != "b06acdaff8f1df6c3355b74729353b2eabb233d5994be9a2fdd31a9792e0525a":
    raise SystemExit("Reviewed install_guardian.py sibling hash mismatch")
g = types.ModuleType("guardian_install_files")
g.__file__ = str(_helper)
exec(compile(_helper_bytes, str(_helper), "exec"), g.__dict__)
RELEASE = Path("/opt/psy-core-relayer/releases/core-testnet-20261027-r3")
STATE = Path("/var/lib/psy-core-relayer/core-testnet-20261027-r3")
CREDENTIALS = Path("/etc/psy-core-relayer/core-testnet-20261027-r3")
UNITS = Path("/etc/systemd/system")
UNIT = "psy-core-relayer-r3.service"
USER = "psy-core-relayer"
PASSWORD_ENV = "PSY_CORE_RELAYER_L1_PASSWORD"
CREDENTIAL = "psy-core-relayer-l1-password"


def integer(value, low=0, high=2**64 - 1):
    g.require(type(value) is int and low <= value <= high, "integer outside approved bounds")


def input_reference(value):
    g.require(isinstance(value, dict) and set(value) == {"path", "sha256"}, "artifact fields mismatch")
    g.path_value(value["path"])
    g.pin(value["sha256"])


def validate_rpc(canonical, rpc, spec):
    g.require(canonical["defaultNetwork"] == rpc["defaultNetwork"] == "testnet", "testnet selection required")
    base, network = canonical["networks"]["testnet"], rpc["networks"]["testnet"]
    g.require(base["magic"] == g.MAGIC, "testnet magic mismatch")
    restored = copy.deepcopy(rpc)
    for field, ids in (("coordinator_configs", [0]), ("realm_configs", [0, 1])):
        g.require([row["id"] for row in network[field]] == ids, "L2 topology mismatch")
        for index, row in enumerate(network[field]):
            g.origins(row["rpc_url"])
            restored["networks"]["testnet"][field][index]["rpc_url"] = base[field][index]["rpc_url"]
    for field in ("prove_proxy_url", "system_prove_proxy_url"):
        g.origins(network[field], private=False)
        for origin in network[field]:
            if field == "prove_proxy_url":
                validate_guardian_rpc(origin)
            elif not ipaddress.IPv4Address(urlsplit(origin).hostname).is_loopback:
                g.origins([origin])
        restored["networks"]["testnet"][field] = base[field]
    history = network["guardian_history"]
    g.require(isinstance(history, dict) and set(history) == {"listen_address", "rpc_url"}
              and history == spec["guardian_history"], "history must match operator approval")
    g.require(base.get("guardian_history") is None or base["guardian_history"] == history,
              "existing canonical history cannot change")
    if "guardian_history" in base:
        restored["networks"]["testnet"]["guardian_history"] = base["guardian_history"]
    else:
        del restored["networks"]["testnet"]["guardian_history"]
    g.require(restored == canonical, "canonical Guardian/network fields changed")
    g.require(sorted(row["id"] for row in network["guardian_configs"]) == [1, 2, 3], "three Guardians required")
    for guardian in network["guardian_configs"]:
        origin = guardian.get("rpc_url") or "http://" + guardian["listen_address"]
        g.origins([origin])
        g.require(urlsplit(origin).scheme == "http", "Guardian origins must use HTTP")
    members = network["guardian_initial_member_hashes"]
    g.require(len(members) == 3 and len({g.commitment(member) for member in members}) == 3, "invalid Genesis commitments")
    listen = urlsplit("//" + history["listen_address"])
    g.require(listen.hostname == spec["address"] and listen.port and not listen.path
              and not listen.username and not listen.password and not listen.query and not listen.fragment,
              "history bind differs from approved host address")
    g.origins([history["rpc_url"]])
    g.require(history["rpc_url"] == "http://" + history["listen_address"], "history advertised origin differs from bind")
    return listen.port


def validate_guardian_rpc(value):
    g.origins([value], private=False)
    url = urlsplit(value)
    address = ipaddress.IPv4Address(url.hostname)
    if url.scheme == "http":
        g.require(address.is_loopback, "Guardian proof/L1 HTTP must use loopback")
    else:
        g.private_ip(str(address))


def validate_chain(chain):
    required = {"family", "chain_index", "network_id", "deployments_network", "keystore_path", "password_env"}
    g.require(isinstance(chain, dict) and required <= set(chain)
              and set(chain) <= required | {"rpc_urls", "rpc_providers", "fee_policy"}, "unsupported chain fields")
    name = chain["network_id"]
    g.require(name in g.CHAINS and chain["deployments_network"] == name and chain["family"] == "evm", "wrong L1 network")
    integer(chain["chain_index"], 0, 2)
    g.require(chain["chain_index"] == g.CHAINS[name][0], "wrong L1 chain index")
    g.require(chain["keystore_path"] == str(RELEASE / "home/.psy/keystore/bridge-relayer.keystore.json")
              and chain["password_env"] == PASSWORD_ENV, "L1 custody paths mismatch")
    g.require(("rpc_urls" in chain) != ("rpc_providers" in chain), "exactly one L1 RPC list required")
    if "rpc_urls" in chain:
        g.origins(chain["rpc_urls"])
    else:
        providers = chain["rpc_providers"]
        g.require(isinstance(providers, list) and 1 <= len(providers) <= 8, "invalid RPC provider count")
        for provider in providers:
            g.require(isinstance(provider, dict) and {"name", "url"} <= set(provider)
                      and set(provider) <= {"name", "url", "priority_weight", "operator", "quota_group"}, "unsupported RPC provider")
            for field in ("name", "operator", "quota_group"):
                if field in provider:
                    g.require(isinstance(provider[field], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", provider[field]), "unsafe provider label")
            integer(provider.get("priority_weight", 10), 1, 2**31 - 1)
        g.origins([row["url"] for row in providers])
        g.require(len({row["name"] for row in providers}) == len(providers), "duplicate provider name")
    if "fee_policy" in chain:
        policy = chain["fee_policy"]
        g.require(name == "bscTestnet" and isinstance(policy, dict) and set(policy) == {
            "expected_chain_id", "min_priority_fee_wei", "max_priority_fee_wei", "max_fee_per_gas_wei"}, "unsupported fee policy")
        for value in policy.values():
            integer(value, 1)
        g.require(policy["expected_chain_id"] == 97 and policy["min_priority_fee_wei"] <=
                  policy["max_priority_fee_wei"] <= policy["max_fee_per_gas_wei"], "invalid BSC fee policy")


def validate_daemon(raw):
    config = tomllib.loads(raw.decode("utf-8"))
    required = {"rpc_config", "guardian_root", "proof_dir", "services_url", "withdraw_method_id",
                "max_concurrent_l2_batches", "chains"}
    g.require(required <= set(config) and set(config) <= required | {
        "poll_interval_secs", "confirmation_lag_checkpoints", "max_checkpoint_batch"}, "unsupported daemon fields")
    g.require(config["rpc_config"] == str(RELEASE / "rpc.json") and config["guardian_root"] == str(STATE)
              and config["proof_dir"] == str(STATE / "proofs"), "new release/state paths required")
    g.origins([config["services_url"]])
    integer(config["withdraw_method_id"], 1, 2**32 - 1)
    integer(config["max_concurrent_l2_batches"], 1, 1)
    for key in ("poll_interval_secs", "confirmation_lag_checkpoints", "max_checkpoint_batch"):
        if key in config:
            integer(config[key], 0 if key == "confirmation_lag_checkpoints" else 1)
    g.require(isinstance(config["chains"], list) and len(config["chains"]) == 3, "three L1 chains required")
    for chain in config["chains"]:
        validate_chain(chain)
    g.require({row["network_id"] for row in config["chains"]} == set(g.CHAINS), "duplicate/missing L1 chain")
    return config


def load_plan(spec_path, spec_hash):
    raw = g.read(g.path_value(str(spec_path)), private=True)
    g.require(g.digest(raw) == g.pin(spec_hash), "operator spec hash mismatch")
    spec = g.decode(raw)
    g.require(set(spec) == {"version", "hostname", "address", "guardian_history", "service_user", "memory_high_gib", "memory_max_gib",
        "keystore_owner", "build", "binary", "canonical_config", "rpc_config", "daemon_config", "wrapper",
        "l1_keystore", "password_credential", "l1_documents"}, "operator spec fields mismatch")
    integer(spec["version"], 3, 3)
    g.require(isinstance(spec["hostname"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", spec["hostname"]), "invalid hostname")
    g.private_ip(spec["address"])
    g.require(spec["service_user"] == USER, "dedicated non-root service account required")
    g.require(isinstance(spec["keystore_owner"], str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", spec["keystore_owner"]), "invalid custody owner")
    integer(spec["memory_high_gib"], 1, 63)
    integer(spec["memory_max_gib"], spec["memory_high_gib"] + 1, 64)
    input_reference(spec["l1_keystore"])
    input_reference(spec["password_credential"])
    build_raw = g.artifact(spec["build"])
    g.require(g.digest(build_raw) == g.BUILD_HASH, "approved build manifest required")
    build = g.decode(build_raw)
    g.require(build["source_commit"] == g.RUNTIME_SOURCE and build["network"] == "testnet", "runtime source mismatch")
    canonical, rpc = g.artifact(spec["canonical_config"]), g.artifact(spec["rpc_config"])
    g.require(g.digest(canonical) == build["config_sha256"], "canonical build config mismatch")
    port = validate_rpc(g.decode(canonical), g.decode(rpc), spec)
    daemon = g.artifact(spec["daemon_config"])
    validate_daemon(daemon)
    binary = g.artifact(spec["binary"], limit=512 * 1024 * 1024)
    g.require(g.digest(binary) == build["binaries"]["psy_relayer_cli"] and binary[:6] == b"\x7fELF\x02\x01"
              and binary[18:20] == b"\x3e\x00", "approved x86_64 relayer required")
    wrapper = g.artifact(spec["wrapper"])
    g.require(wrapper == g.read(Path(__file__).absolute().with_name("relayer_exec.py")), "reviewed sibling launcher required")
    documents = g.l1_files(spec["l1_documents"])
    for name in spec["l1_documents"]:
        doc = g.decode(documents[f"{name}/deployed-contracts.json"])
        proxy = g.decode(documents[f"{name}/Bridge_Proxy.json"])
        receipt = proxy["receipt"]
        g.require(type(receipt.get("status")) is int and receipt["status"] == 1
                  and isinstance(proxy.get("transactionHash"), str)
                  and re.fullmatch(r"0x[0-9a-fA-F]{64}", proxy["transactionHash"])
                  and receipt.get("transactionHash") == proxy["transactionHash"]
                  and receipt.get("contractAddress", "").lower() == proxy["address"].lower()
                  and receipt["blockNumber"] > 0, "successful Bridge deployment receipt required")
        g.require(doc["network"] == name, "deployment network name mismatch")
        validate_guardian_rpc(doc["protocol"]["chain"]["defaultRpcUrl"])
        for field in ("core", "contracts"):
            g.require(isinstance(doc.get(field), dict)
                      and all(isinstance(value, str) for value in doc[field].values()), "deployment string map required")
        for contract in ("Bridge", "StateManager", "Multicall3"):
            address = doc["core"].get(contract, doc.get("contracts", {}).get(contract))
            g.require(isinstance(address, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", address)
                      and int(address, 16) != 0, "missing deployment contract")
            other = doc.get("contracts", {}).get(contract, address)
            g.require(other.lower() == address.lower(), "conflicting deployment contract")
    files = {"build.json": build_raw, "canonical.json": canonical, "rpc.json": rpc, "daemon.toml": daemon,
             "psy_relayer_cli": binary, "relayer_exec.py": wrapper, "operator.json": raw}
    files.update({"deployments/" + name: data for name, data in documents.items()})
    return spec, files, port


def unit(spec):
    return ("\n".join([
        "[Unit]", "Description=Psy fresh testnet Relayer", "ConditionHost=" + spec["hostname"],
        "Wants=network-online.target", "After=network-online.target", "StartLimitIntervalSec=600", "StartLimitBurst=3",
        "[Service]", "Type=simple", "User=" + USER, "Group=" + USER, "UMask=0077",
        "WorkingDirectory=" + str(STATE),
        f"LoadCredentialEncrypted={CREDENTIAL}:{CREDENTIALS / 'l1-password.cred'}",
        "ExecStart=/usr/bin/python3 -I -B " + str(RELEASE / "relayer_exec.py"),
        "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true", "NoNewPrivileges=true",
        "ReadOnlyPaths=" + str(RELEASE), "ReadWritePaths=" + str(STATE / "db") + " " + str(STATE / "proofs"),
        "CapabilityBoundingSet=", "RestrictSUIDSGID=true", "LimitCORE=0", "LimitNOFILE=65536",
        f"MemoryHigh={spec['memory_high_gib']}G", f"MemoryMax={spec['memory_max_gib']}G",
        "Restart=on-failure", "RestartSec=15", "TimeoutStopSec=300",
        "StandardOutput=journal", "StandardError=journal", "", "[Install]", "WantedBy=multi-user.target", "",
    ])).encode()


def read_keystore(spec):
    path = g.path_value(spec["l1_keystore"]["path"])
    parent = g.directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        g.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular single-link keystore required")
        g.require(info.st_uid == pwd.getpwnam(spec["keystore_owner"]).pw_uid
                  and stat.S_IMODE(info.st_mode) in (0o600, 0o640), "unsafe retained L1 keystore owner/mode")
        key = stream.read(65537)
    g.require(0 < len(key) <= 65536 and g.digest(key) == spec["l1_keystore"]["sha256"], "retained L1 keystore hash mismatch")
    encrypted = g.decode(key)
    g.require(encrypted.get("version") == 3 and isinstance(encrypted.get("crypto", encrypted.get("Crypto")), dict)
              and encrypted.get("crypto", encrypted.get("Crypto")) and "private_key" not in encrypted, "encrypted V3 L1 keystore required")
    return key


def host_checks(spec, port):
    g.require(os.geteuid() == 0, "host checks require root")
    g.require(socket.gethostname() == spec["hostname"] and os.uname().machine == "x86_64", "wrong host")
    addresses = json.loads(g.command(["ip", "-j", "-4", "address", "show"]))
    g.require(spec["address"] in {row.get("local") for interface in addresses for row in interface.get("addr_info", [])}, "history address not assigned to host")
    account = pwd.getpwnam(USER)
    g.require(account.pw_uid > 0 and account.pw_gid > 0 and grp.getgrnam(USER).gr_gid == account.pw_gid, "dedicated non-root user/group required")
    g.require(int(g.command(["systemctl", "--version"]).split()[1]) >= 250, "systemd 250+ required")
    g.inactive_units((UNIT, "psy-core-relayer-r2.service", "psy-core-relayer.service",
                      "parth-bridge-relayer.service", "parth-relayer.service"),
                     {"psy-core-relayer-r2.service"})
    g.require(not any(len(row) > 3 and row[3].rsplit(":", 1)[-1] == str(port)
                      for row in map(str.split, g.command(["ss", "-H", "-ltn"]).splitlines())), "history port occupied")
    for path in (RELEASE, STATE, CREDENTIALS):
        g.require(not os.path.lexists(path), "destination exists; inspect partial install")
        for parent in path.parents:
            if os.path.lexists(parent):
                g.trusted_directory(parent)
                g.require(os.stat(parent).st_mode & 0o001, "service ancestor blocks traversal")
    paths = g.command(["systemd-analyze", "unit-paths"]).splitlines()
    g.require(str(UNITS) in paths, "unit search paths invalid")
    for root in paths:
        for name in (UNIT, "psy-core-relayer-.service", "psy-core-.service", "psy-.service", "service"):
            g.require(not any(os.path.lexists(g.path_value(root) / (name + suffix)) for suffix in ("", ".d")), "existing unit or inherited drop-in")
    for parent in (UNITS, *UNITS.parents):
        g.trusted_directory(parent)
    key = read_keystore(spec)
    credential = g.read(g.path_value(spec["password_credential"]["path"]), private=True, uid=0, limit=65536)
    g.require(g.digest(credential) == spec["password_credential"]["sha256"], "encrypted credential hash mismatch")
    return account, key, credential


def run(mode, spec_path, spec_hash, apply=False):
    g.require(mode in ("plan", "check-host", "install") and apply == (mode == "install"), "install requires --apply only")
    spec, files, port = load_plan(spec_path, spec_hash)
    pending = not spec["l1_documents"]
    if mode != "plan":
        g.require(not pending, "three L1 documents pending; plan only")
        account, key, credential = host_checks(spec, port)
        if mode == "install":
            parents = set(RELEASE.parents) | set(STATE.parents) | set(CREDENTIALS.parents)
            for parent in sorted(parents, key=lambda value: len(value.parts)):
                if not os.path.lexists(parent):
                    g.mkdir(parent)
            for path in (RELEASE, STATE):
                g.mkdir(path)
            g.mkdir(CREDENTIALS, mode=0o700)
            for path in (STATE / "db", STATE / "proofs", RELEASE / "home", RELEASE / "home/.psy", RELEASE / "home/.psy/keystore"):
                g.mkdir(path, account.pw_uid, account.pw_gid, 0o700)
            g.mkdir(RELEASE / "deployments")
            for name in g.CHAINS:
                g.mkdir(RELEASE / "deployments" / name)
            for name, raw in files.items():
                g.write(RELEASE / name, raw, mode=0o600 if name == "operator.json" else (0o755 if name == "psy_relayer_cli" else 0o644))
            g.write(RELEASE / "home/.psy/keystore/bridge-relayer.keystore.json", key, uid=account.pw_uid, gid=account.pw_gid)
            g.write(CREDENTIALS / "l1-password.cred", credential)
            g.write(UNITS / UNIT, unit(spec), mode=0o644)
            g.command(["systemctl", "daemon-reload"])
    return {"mode": mode, "runtime_source": g.RUNTIME_SOURCE, "l1_documents_pending": pending,
            "offline_config_validated": True, "native_config_parse_verified": False,
            "started": False, "enabled": False, "deployment_ready": False}


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
        raise SystemExit("Relayer install check failed; details withheld; preserve partial destinations") from None


if __name__ == "__main__":
    main()
