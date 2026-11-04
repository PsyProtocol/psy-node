#!/usr/bin/env python3
"""Package the Services and indexer inputs per host from the release lock, offline.

Pending mode (no L1 documents) builds every package except the three-chain configuration; the packages are not
installable until real documents are bound. The first-package behaviour fixed after the previous release lives here:
Nostr ingestion on, per-request indexer JWTs (checked in the binary), the Realm indexer first start, Redis pool size.
"""
import hashlib
import json
from pathlib import Path

import install_services as installer
import prepare_services_inputs as inputs

HERE = Path(__file__).resolve().parent
NOSTR_RELAY_URL = "wss://nostr-stg.psy-protocol.xyz/"
NOSTR_LOOKBACK_SECONDS = 172800
REDIS_POOL_SIZE = 10
# A binary built before the per-request JWT fix carries no such symbol; its indexer would be refused after a day.
JWT_RENEWAL_MARKER = b"authorization_header"
CHAIN_IDENTITY = {"sepolia": (0, 11155111), "bscTestnet": (1, 97), "baseSepolia": (2, 84532)}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def check_jwt_renewal(indexer_binary):
    inputs.require(JWT_RENEWAL_MARKER in indexer_binary, "the indexer binary lacks per-request JWT signing")


def service_config(topology, lock, documents):
    """documents maps chain name to the raw L1 summary bytes; empty means pending."""
    chains = []
    for name, (index, chain_id) in CHAIN_IDENTITY.items():
        if documents:
            chains.append({"name": name, "chain_id": chain_id, "chain_index": index,
                           "eth_rpc_url": lock["envio"]["rpc_routes"][name],
                           "state_manager": json.loads(documents[name])["core"]["StateManager"]})
    realm_ids = sorted(int(role[len("realm"):]) for role in topology["indexers"] if role.startswith("realm"))
    endpoints = [{"role": {"type": "Coordinator", "id": 0}, "url": topology["indexers"]["coordinator"]["edge_url"]}]
    endpoints += [{"role": {"type": "Realm", "id": realm_id}, "url": topology["indexers"][f"realm{realm_id}"]["edge_url"]}
                  for realm_id in realm_ids]
    return {
        "service_name": lock["units"]["services"].removesuffix(".service"), "network_type": "psy-public-testnet",
        "database": {"url": "postgresql://unconfigured@127.0.0.1/NOT_CONFIGURED", "run_migrations": True},
        "redis": {"url": topology["redis_url"], "key_prefix": topology["redis_prefix"], "pool_size": REDIS_POOL_SIZE},
        "rpc": {"endpoints": endpoints},
        "api": {"host": topology["services_host"], "port": topology["services_port"], "disable_auth": False},
        "nostr": {"enabled": True, "relay_url": NOSTR_RELAY_URL, "lookback_seconds": NOSTR_LOOKBACK_SECONDS},
        "l1_chains": chains,
    }


def start_env_file(unit_name):
    return f"/run/{unit_name.removesuffix('.service')}.start.env"


def unit(topology, lock, lock_sha256, user, role):
    release = topology["release"]
    name = installer.unit_name(lock, role)
    guard = (f"ExecStartPre=/usr/bin/python3 -I -B {release}/install_services.py guard --package {release} --role {role} "
             f"--release-lock {release}/release-lock.json --release-lock-sha256 {lock_sha256}\n")
    extra, after = "", "network-online.target"
    if role == "services":
        after += " " + topology["bridge_reader_unit"]
        extra = (f"Environment=PSY_ENVIO_READ_PATH=reader\nEnvironment=PSY_BRIDGE_READER_URL={topology['bridge_reader_url']}\n"
                 f"Environment=PSY_BRIDGE_READER_TOKEN_FILE={topology['bridge_reader_token_file']}\n")
        command = (f"{release}/psy-services --config {release}/services.json --network-type psy-public-testnet "
                   f"--genesis-path {release}/genesis.json.zst --run-migrations=true --migrations-path {release}/migrations")
        state = Path(topology["nostr_state"]).name
        writable = f"StateDirectory={state}\nStateDirectoryMode=0700\n"
        writable += f"Environment=PSY_NOSTR_SCAN_STATE_DIR={topology['nostr_state']}/nostr\nReadWritePaths={topology['nostr_state']}\n"
    else:
        item = topology["indexers"][role]
        sources = f"--committed-realm-sources {release}/{role}.json " if role.startswith("realm") else ""
        command = (f"{release}/psy-indexer {sources}--edge-url {item['edge_url']} "
                   f"--psy-services-url {topology['services_url']} --backup-dir {topology['backup_dir']} "
                   f"--network-type psy-public-testnet {item['args']}")
        writable = f"ReadWritePaths={topology['backup_dir']}/indexer_state\n"
        if role.startswith("realm"):
            # A Realm indexer in committed mode refuses to start without a cursor or a start checkpoint. The checkpoint
            # applies only while no cursor exists, so a restart never replays from the beginning.
            cursor = f"{topology['backup_dir']}/indexer_state/realm_{role[len('realm'):]}_1.json"
            env_file = start_env_file(name)
            extra = (f"EnvironmentFile=-{env_file}\nExecStartPre=+/usr/bin/bash -c 'if [ -e {cursor} ]; then : > {env_file}; "
                     f"else echo PSY_INDEXER_START_CHECKPOINT=0 > {env_file}; fi'\n")
    credentials = topology["credentials"] + ("/services.env" if role == "services" else "/indexer.env")
    return (f"[Unit]\nDescription=Fresh testnet {role}\nWants=network-online.target\nAfter={after}\n\n"
            f"[Service]\nType=simple\nUser={user}\nGroup={user}\nWorkingDirectory={release}\n"
            f"EnvironmentFile={credentials}\nEnvironment=PSY_NETWORK_TYPE=psy-public-testnet\nEnvironment=RUST_LOG=info\n"
            f"{extra}{guard}ExecStart={command}\nRestart=on-failure\nRestartSec=10\nNoNewPrivileges=true\nPrivateTmp=true\n"
            f"ProtectSystem=strict\nProtectHome=true\nUMask=0027\nLimitNOFILE=65536\n{writable}\n"
            "[Install]\nWantedBy=multi-user.target\n").encode()


def read_inputs(inputs_dir, input_manifest_sha256, lock):
    """Verify the offline inputs against the lock and return {relative name: hash}."""
    require = inputs.require
    require(inputs.digest(inputs_dir / "input-manifest.json") == input_manifest_sha256, "input manifest mismatch")
    original = json.loads((inputs_dir / "input-manifest.json").read_bytes())
    require(original["genesis_sha256"] == lock["inputs"]["genesis"] and original["services_commit"] == lock["sources"]["services"]
            and original["indexer_commit"] == lock["sources"]["indexer"], "input cohort mismatch")
    actual = {str(p.relative_to(inputs_dir)): inputs.digest(p) for p in inputs_dir.rglob("*")
              if p.is_file() and p.name != "input-manifest.json"}
    require(actual == original["files"], "input inventory mismatch")
    for name in ("psy-services", "psy-indexer"):
        require(actual[name] == lock["binaries"][name], "binary pin mismatch")
    inputs.read_abis(inputs_dir / "genesis_abi")
    return actual


def build_service_packages(lock, lock_sha256, release_dir, inputs_dir, input_manifest_sha256, output, documents):
    """Write one package per Services or indexer host under output and return {host alias: manifest sha256}.

    documents is None (pending) or {chain: raw L1 summary bytes}.
    """
    require = inputs.require
    release_topology_raw = (release_dir / "topology.json").read_bytes()
    require(hashlib.sha256(release_topology_raw).hexdigest() == lock["inputs"]["topology"], "release topology differs from the lock")
    lock_raw = (release_dir / "release-lock.json").read_bytes()
    require(hashlib.sha256(lock_raw).hexdigest() == lock_sha256, "release lock bytes differ from the lock in use")
    for tool in ("install_services.py", "activate_services.py"):
        require(hashlib.sha256((HERE / tool).read_bytes()).hexdigest() == lock["tool_sha256"][tool], f"tool hash differs: {tool}")
    actual = read_inputs(inputs_dir, input_manifest_sha256, lock)
    check_jwt_renewal((inputs_dir / "psy-indexer").read_bytes())
    require(not output.exists(), "output exists; preserve the prior package")
    topology = installer.placement(lock, json.loads(release_topology_raw))
    output.mkdir(mode=0o700, parents=True)
    delivery = {}
    for alias, group in topology["groups"].items():
        files = {"topology.json": encode(topology), "install_services.py": (HERE / "install_services.py").read_bytes(),
                 "activate_services.py": (HERE / "activate_services.py").read_bytes(),
                 "release-lock.json": lock_raw, "release-topology.json": release_topology_raw}
        is_services = "services" in group["roles"]
        binary = "psy-services" if is_services else "psy-indexer"
        files[binary] = (inputs_dir / binary).read_bytes()
        if is_services:
            files["services.json"] = encode(service_config(topology, lock, documents))
            for name in actual:
                if name == "genesis.json.zst" or name.startswith(("genesis_abi/", "migrations/")):
                    files[name] = (inputs_dir / name).read_bytes()
        for role in group["roles"]:
            files["units/" + installer.unit_name(lock, role)] = unit(topology, lock, lock_sha256, group["user"], role)
            if role in topology["realm_sources"]:
                files[role + ".json"] = encode(topology["realm_sources"][role])
        for name, raw in files.items():
            inputs.write_new(output / alias / name, raw)
        manifest = {"group": alias, "runtime_node_commit": lock["sources"]["runtime"], "genesis_sha256": lock["inputs"]["genesis"],
                    "services_commit": lock["sources"]["services"], "indexer_commit": lock["sources"]["indexer"],
                    "input_manifest_sha256": input_manifest_sha256, "l1_ready": documents is not None,
                    "rpc_policy": "protected-alchemy-only-no-fallback",
                    "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
        inputs.write_json(output / alias / "manifest.json", manifest)
        pin = inputs.digest(output / alias / "manifest.json")
        installer.load_package(output / alias, pin, lock, lock_sha256)
        delivery[alias] = pin
    return delivery
