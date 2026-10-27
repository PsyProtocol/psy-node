#!/usr/bin/env python3
"""Package frozen Services inputs offline; missing fresh L1 documents block installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path

import install_services as installer
import prepare_envio
import prepare_services_inputs as inputs

HERE = Path(__file__).resolve().parent


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def deployment_topology():
    value = inputs.topology()
    value["groups"] = {name: {"host": host, "roles": roles,
                              "user": "parth" if name == "services" else "psy-core"}
                       for name, (host, roles) in installer.HOSTS.items()}
    value["services_host"], value["services_port"] = "10.148.0.38", 3001
    value["nostr_state"] = "/var/lib/psy-services-fresh-20261027-r3"
    value["indexers"] = {
        "coordinator": {"args": "coordinator", "backup_subdir": "coordinator_0_0",
                        "core_unit": "psy-core-r3-coordinator-processor.service", "edge_url": "http://10.148.0.25:15370"},
        "realm0": {"args": "realm --realm-id 0 --realm-sub-id 1", "backup_subdir": "realm_0_1",
                   "core_unit": "psy-core-r3-realm-0-v1-processor.service", "edge_url": "http://10.148.0.36:15380"},
        "realm1": {"args": "realm --realm-id 1 --realm-sub-id 1", "backup_subdir": "realm_1_1",
                   "core_unit": "psy-core-r3-realm-1-v1-processor.service", "edge_url": "http://10.148.0.35:15383"},
    }
    return value


def service_config(topology, documents):
    chains = []
    for name, (index, chain_id, _) in prepare_envio.CHAINS.items():
        if documents:
            document = json.loads(documents[f"l1/{name}/summary.json"])
            chains.append({"name": name, "chain_id": chain_id, "chain_index": index,
                           "eth_rpc_url": prepare_envio.RPC_URLS[name],
                           "state_manager": document["core"]["StateManager"],
                           "graphql_url": topology["hasura_url"]})
    return {
        "service_name": "psy-services-fresh-20261027-r3", "network_type": "psy-public-testnet",
        "database": {"url": "postgresql://unconfigured@127.0.0.1/NOT_CONFIGURED", "run_migrations": True},
        "redis": {"url": topology["redis_url"], "key_prefix": topology["redis_prefix"]},
        "rpc": {"endpoints": [{"role": {"type": "Coordinator" if name == "coordinator" else "Realm",
                                        "id": 1 if name == "realm1" else 0}, "url": row["edge_url"]}
                              for name, row in topology["indexers"].items()]},
        "api": {"host": topology["services_host"], "port": topology["services_port"], "disable_auth": False},
        "nostr": {"enabled": False, "relay_url": "wss://nostr-stg.psy-protocol.xyz/", "lookback_seconds": 0},
        "l1_chains": chains,
    }


def unit(topology, group, role, bootstrap_realms=False):
    release = topology["release"]
    if role == "services":
        command = (f"{release}/psy-services --config {release}/services.json --network-type psy-public-testnet "
                   f"--genesis-path {release}/genesis.json.zst --run-migrations=true --migrations-path {release}/migrations")
        writable = "StateDirectory=psy-services-fresh-20261027-r3\nStateDirectoryMode=0700\n"
        writable += f"Environment=PSY_NOSTR_SCAN_STATE_DIR={topology['nostr_state']}/nostr\nReadWritePaths={topology['nostr_state']}\n"
    else:
        item = topology["indexers"][role]
        sources = f"--committed-realm-sources {release}/{role}.json " if role.startswith("realm") else ""
        # This override precedes retained cursors; remove it after first cursor creation.
        start = "--start-checkpoint 0 " if bootstrap_realms and role.startswith("realm") else ""
        command = (f"{release}/psy-indexer {sources}--edge-url {item['edge_url']} "
                   f"--psy-services-url {topology['services_url']} --backup-dir {topology['backup_dir']} "
                   f"--network-type psy-public-testnet {start}{item['args']}")
        writable = f"ReadWritePaths={topology['backup_dir']}/indexer_state\n"
    credentials = topology["credentials"] + ("/services.env" if role == "services" else "/indexer.env")
    restart = "no" if bootstrap_realms and role.startswith("realm") else "on-failure"
    cursor_guard = ""
    if bootstrap_realms and role.startswith("realm"):
        cursor = f"{topology['backup_dir']}/indexer_state/realm_{role[-1]}_1.json"
        cursor_guard = f"ExecStartPre=+/usr/bin/test ! -e {cursor}\nExecStartPre=+/usr/bin/test ! -L {cursor}\n"
    return (f"[Unit]\nDescription=Fresh R3 {role}\nWants=network-online.target\nAfter=network-online.target\n\n"
            f"[Service]\nType=simple\nUser={group['user']}\nGroup={group['user']}\nWorkingDirectory={release}\n"
            f"EnvironmentFile={credentials}\nEnvironment=PSY_NETWORK_TYPE=psy-public-testnet\nEnvironment=RUST_LOG=info\n"
            f"{cursor_guard}"
            f"ExecStartPre=/usr/bin/python3 -I -B {release}/install_services.py guard --package {release} --role {role}\n"
            f"ExecStart={command}\nRestart={restart}\nRestartSec=10\nNoNewPrivileges=true\nPrivateTmp=true\n"
            f"ProtectSystem=strict\nProtectHome=true\nUMask=0027\nLimitNOFILE=65536\n{writable}\n"
            "[Install]\nWantedBy=multi-user.target\n").encode()


def prepare(args):
    inputs.require(inputs.digest(args.inputs / "input-manifest.json") == args.input_manifest_sha256, "input manifest mismatch")
    original = json.loads((args.inputs / "input-manifest.json").read_bytes())
    inputs.require(original["genesis_sha256"] == inputs.GENESIS_SHA256
                   and original["services_commit"] == inputs.SERVICES_COMMIT
                   and original["indexer_commit"] == inputs.INDEXER_COMMIT, "input cohort mismatch")
    actual = {str(p.relative_to(args.inputs)): inputs.digest(p) for p in args.inputs.rglob("*")
              if p.is_file() and p.name != "input-manifest.json"}
    inputs.require(actual == original["files"], "input inventory mismatch")
    for name, pin in inputs.BINARY_SHA256.items():
        inputs.require(actual[name] == pin, "binary pin mismatch")
    inputs.require(json.loads((args.inputs / "topology.json").read_bytes()) == inputs.topology(), "input topology mismatch")
    inputs.read_abis(args.inputs / "genesis_abi")
    documents, networks = {}, []
    if args.envio_spec:
        inputs.require(inputs.digest(args.envio_spec) == args.envio_spec_sha256, "Envio spec mismatch")
        spec = json.loads(args.envio_spec.read_bytes())
        prepare_envio.validate_placement(spec["placement"])
        prepare_envio.validate_routes(spec["rpc_routes"])
        inputs.require(spec["placement"]["postgres_user"] == prepare_envio.DATABASE
                       and spec["placement"]["hasura_bind"] == "10.148.0.24", "fresh Envio identity mismatch")
        if spec["l1_documents"]:
            documents, networks = prepare_envio.l1_files(spec["l1_documents"])
    else:
        inputs.require(not args.envio_spec_sha256, "Envio spec path missing")
    inputs.require(not os.path.lexists(args.output), "output exists; preserve prior package")
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    topology = deployment_topology()
    delivery = {}
    for group, placement in topology["groups"].items():
        root = args.output / group
        files = {"topology.json": encode(topology), "install_services.py": (HERE / "install_services.py").read_bytes(),
                 "activate_services.py": (HERE / "activate_services.py").read_bytes()}
        binary = "psy-services" if group == "services" else "psy-indexer"
        files[binary] = (args.inputs / binary).read_bytes()
        if group == "services":
            files["services.json"] = encode(service_config(topology, documents))
            for name in actual:
                if name == "genesis.json.zst" or name.startswith(("genesis_abi/", "migrations/")):
                    files[name] = (args.inputs / name).read_bytes()
        for role in placement["roles"]:
            files["units/" + installer.unit_name(role)] = unit(topology, placement, role, args.bootstrap_realms)
            if role.startswith("realm"):
                files[role + ".json"] = encode(inputs.realm_sources(int(role[-1])))
        files.update(documents)
        for name, raw in files.items():
            inputs.write_new(root / name, raw)
        manifest = {"group": group, "runtime_node_commit": inputs.RUNTIME_COMMIT,
                    "genesis_sha256": inputs.GENESIS_SHA256, "services_commit": inputs.SERVICES_COMMIT,
                    "indexer_commit": inputs.INDEXER_COMMIT, "node_build_commit": inputs.NODE_BUILD_COMMIT,
                    "input_manifest_sha256": args.input_manifest_sha256,
                    "l1_ready": bool(documents), "envio_spec_sha256": args.envio_spec_sha256,
                    "l1_document_cohort": prepare_envio.L1_DOCUMENT_ROOT,
                    "rpc_policy": "protected-alchemy-only-no-fallback",
                    "envio_networks": networks, "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
        inputs.write_json(root / "manifest.json", manifest)
        pin = inputs.digest(root / "manifest.json")
        installer.load_package(root, pin)
        delivery[group] = {"manifest_sha256": pin, "installable": bool(documents), "started": False}
    inputs.write_json(args.output / "delivery.json", delivery)
    return delivery


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--input-manifest-sha256", required=True)
    parser.add_argument("--envio-spec", type=Path)
    parser.add_argument("--envio-spec-sha256")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-realms", action="store_true",
                        help="Temporary realm start at checkpoint 1; remove after cursor creation before normal operation")
    print(json.dumps(prepare(parser.parse_args()), sort_keys=True))
