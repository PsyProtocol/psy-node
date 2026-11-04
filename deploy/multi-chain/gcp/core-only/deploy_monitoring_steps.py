#!/usr/bin/env python3
"""Step 85: deploy Psy Notifier monitoring for every host of the release, plus L1 gas and settlement alerts."""
import fnmatch
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import tomllib

import release_lock
from release_lock import require
from deploy_remote import OperatorPending, Step, redact_tail, run_operator_command, wait_until


HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent / "deploy-monitoring.sh"
CONTROLLER_HOST = "gcp-faucet"
CONTROLLER_CONFIG = "config/staging/controller.wallet-slack-test.toml"
COLLECTOR_CONFIGS = "config/staging/collectors"
STATUS_URL = "http://127.0.0.1:9099/status"
GCP_ENDPOINT = "http://10.148.0.33:9443"
OFFSITE_ENDPOINT = "http://10.250.0.1:9443"
OFFSITE_PREFIX = "10.250."
EXIT_PENDING = 3
COLLECTOR_FRESH_MS = 120_000
FUTURE_SKEW_MS = 30_000
ADAPTER_TIMEOUT_SECONDS = 3 * 3600
STATUS_POLL_SECONDS = 10
STATUS_TIMEOUT_SECONDS = 300
DISCOVERY_TIMEOUT_SECONDS = 60
# Relayer gas per day. BSC is measured whole-relayer use on SD192 (finalize, batchAppend ~3.4M and
# batchClaimWithdrawal ~1.6M: ~315M/day, 2026-11-02..04) rounded up for load growth. Sepolia and Base
# keep 240 finalizes a day at R3 peaks (700k, 400k); their 1 Gwei price already bounds them from above.
DAILY_GAS = {"sepolia": 168_000_000, "bscTestnet": 400_000_000, "baseSepolia": 96_000_000}
# BSC base fee is 0 and the relayer pays its 0.1 Gwei tip floor.
PRICE_WEI = {"sepolia": 1_000_000_000, "bscTestnet": 100_000_000, "baseSepolia": 1_000_000_000}
WARNING_DAYS = 7
CRITICAL_DAYS = 2
HOST_PROBE_INTERVAL = "5s"
REGENERATED_KINDS = ("coordinator", "realm")
NOSTR_PATTERN_NAME = "psy-services-nostr-unavailable"
NOSTR_FILTER = (f'[[filters.immediate_patterns]]\nname = "{NOSTR_PATTERN_NAME}"\n'
                "regex = 'Nostr subscriber:.*(?:relay unavailable|relay disconnected|relay banned)'\n\n")
NETWORK_IDS = {"sepolia": "sepolia", "bscTestnet": "bsc-testnet", "baseSepolia": "base-sepolia"}
NETWORK_NAMES = {"sepolia": "Ethereum Sepolia", "bscTestnet": "BSC Testnet", "baseSepolia": "Base Sepolia"}


def local_notifier_section(ctx):
    path = ctx.private_dir / "local-inputs.json"
    require(path.is_file(), "local-inputs.json not found in the operator-only directory")
    section = json.loads(path.read_text()).get("notifier")
    require(isinstance(section, dict) and isinstance(section.get("checkout"), str)
            and section["checkout"].startswith("/"), "local-inputs.json notifier.checkout must be an absolute path")
    return section


def check_notifier_checkout(ctx):
    """The local Notifier checkout exists; once the lock pins a commit it must be that commit, clean."""
    checkout = Path(local_notifier_section(ctx)["checkout"])
    require(checkout.is_dir(), "notifier.checkout is not a directory")
    pin = ctx.lock["sources"]["notifier"]
    if not pin:
        return checkout
    head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    dirty = subprocess.run(["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=all"],
                           capture_output=True, text=True, check=False)
    require(head.returncode == 0 and head.stdout.strip() == pin, "notifier checkout HEAD differs from sources.notifier")
    require(dirty.returncode == 0 and not dirty.stdout.strip(), "notifier checkout must be clean")
    return checkout


def release_chains(release_dir):
    chains = release_lock.read_document(release_dir / "release.json")["chains"]
    require(sorted(chain["index"] for chain in chains) == list(range(len(chains))) and chains,
            "release chains need contiguous indexes")
    require(all(chain["name"] in DAILY_GAS for chain in chains), "release chain without a gas basis")
    return chains


def monitoring_hosts(release_dir, lock):
    """Every host the release names, as (alias, zone); nothing is listed in the adapter."""
    topology = release_lock.read_document(release_dir / "topology.json")["hosts"]
    addresses = {**lock["hosts"], **topology}
    return sorted((alias, "offsite" if address.startswith(OFFSITE_PREFIX) else "gcp")
                  for alias, address in addresses.items())


def host_addresses(release_dir, lock):
    return {**lock["hosts"], **release_lock.read_document(release_dir / "topology.json")["hosts"]}


def unit_patterns(lock):
    """Units discovered on hosts; core units come from the topology instead."""
    units = lock["units"]
    prefixes = [units[name] + "*" for name in ("guardian_prefix", "worker_prefix", "proxy_prefix", "indexer_prefix")]
    return prefixes + [units[name] for name in ("relayer", "faucet", "services", "envio")]


def parse_unit_list(text, patterns):
    names = []
    for line in text.splitlines():
        columns = line.split()
        if len(columns) >= 2 and columns[1] == "loaded" and any(fnmatch.fnmatchcase(columns[0], p) for p in patterns):
            names.append(columns[0])
    return sorted(set(names))


def discover_units(ctx, host):
    """systemctl list-units needs no root, so this also works on operator hosts."""
    patterns = unit_patterns(ctx.lock)
    command = shlex.join(["/usr/bin/systemctl", "list-units", "--all", "--type=service", "--plain",
                          "--no-legend", "--no-pager", *patterns])
    return parse_unit_list(ctx.remote.run_script(host, f"set -euo pipefail\n{command}\n", DISCOVERY_TIMEOUT_SECONDS),
                           patterns)


def service_id(lock, unit):
    units = lock["units"]
    exact = {units["services"]: "psy-services", units["relayer"]: "relayer", units["faucet"]: "faucet",
             units["envio"]: "envio"}
    if unit in exact:
        return exact[unit]
    for prefix, label in ((units["guardian_prefix"], "guardian-"), (units["worker_prefix"], "worker-"),
                          (units["proxy_prefix"], "prove-proxy-"), (units["indexer_prefix"], "indexer-")):
        if unit.startswith(prefix):
            return label + unit.removeprefix(prefix).removesuffix(".service")
    return unit.removesuffix(".service")


def service_block(service_name, unit):
    return (f'[[targets.services]]\nid = "{service_name}"\nunit = "{unit}"\n[targets.services.logs]\n'
            f'source = "journald"\nunit = "{unit}"\n\n')


def probe_block(url):
    return ('[[targets.probes]]\nid = "latest-checkpoint"\nkind = "json_rpc"\n'
            f'url = "{url}"\nmethod = "psy_get_latest_checkpoint_id"\ninterval = "30s"\ntimeout = "5s"\n\n')


def target_block(target_id, kind, labels, service_name, unit, probe_url=None):
    text = f'[[targets]]\nid = "{target_id}"\nkind = "{kind}"\n'
    if labels:
        text += "labels = { " + ", ".join(f'{key} = "{value}"' for key, value in labels.items()) + " }\n"
    text += "\n" + service_block(service_name, unit)
    return text + (probe_block(probe_url) if probe_url else "")


def core_targets(lock, topology, host):
    """Coordinator and Realm targets of one host, with checkpoint probes on the release ports."""
    prefix, addresses = lock["units"]["core_prefix"], topology["hosts"]
    unit = lambda name: f"{prefix}{name}.service"
    blocks = []
    coordinator = topology["coordinator"]
    if coordinator["host"] == host:
        blocks.append(target_block("coordinator-processor", "coordinator", {}, "processor",
                                   unit("coordinator-processor")))
        for index, port in enumerate(coordinator["edge_ports"]):
            blocks.append(target_block(f"coordinator-edge-{index}", "coordinator", {"replica_id": str(index)},
                                       "edge", unit(f"coordinator-edge-{index}"),
                                       f"http://{addresses[host]}:{port}"))
    for realm in topology["realms"]:
        for position, validator in enumerate(realm["validators"], 1):
            labels = {"realm_id": str(realm["id"]), "validator_id": str(validator["validator_user_id"]),
                      "registration_id": str(validator["registration_id"]),
                      "expected_validators": str(len(realm["validators"]))}
            name = f"realm-{realm['id']}-v{position}"
            if validator["processor_host"] == host:
                blocks.append(target_block(f"{name}-processor", "realm", labels, "processor", unit(f"{name}-processor")))
            if validator["edge_host"] == host:
                blocks.append(target_block(f"{name}-edge", "realm", labels, "edge", unit(f"{name}-edge"),
                                           f"http://{addresses[host]}:{validator['http_port']}"))
    return blocks


def split_targets(text):
    """Header text and the [[targets]] blocks of a collector config."""
    blocks = re.split(r"(?m)^(?=\[\[targets\]\]$)", text)
    return blocks[0], blocks[1:]


# Probes of components this release no longer runs (Hasura is retired; Envio runs without it).
RETIRED_PROBES = ("hasura-health",)


def drop_retired_services(block):
    head, *parts = re.split(r"(?m)^(?=\[\[targets\.(?:services|probes)\]\]$)", block)
    kept = [part for part in parts
            if not (part.startswith("[[targets.services]]") and re.search(r'(?m)^unit = "parth-', part))
            and not (part.startswith("[[targets.probes]]")
                     and any(re.search(rf'(?m)^id = "{probe}"$', part) for probe in RETIRED_PROBES))]
    return head + "".join(kept)


def keep_targets(base_text):
    """Infrastructure targets of the repository config minus retired parth-* units; Core targets are regenerated."""
    if base_text is None:
        return []
    kept = []
    for block in split_targets(base_text)[1]:
        kind = re.search(r'(?m)^kind = "([^"]+)"', block)
        if kind and kind.group(1) in REGENERATED_KINDS:
            continue
        block = drop_retired_services(block)
        if "[[targets.services]]" in block or "[[targets.probes]]" in block:
            kept.append(block)
    return kept


def keep_filters(base_text):
    """The [filters] section of the repository config header, when it has one."""
    if base_text is None:
        return ""
    found = re.search(r"(?m)^\[\[?filters", split_targets(base_text)[0])
    return split_targets(base_text)[0][found.start():].rstrip("\n") + "\n\n" if found else ""


def render_collector(lock, host, zone, base_text, core_blocks, units):
    region = "offsite" if zone == "offsite" else "gcp-asia-southeast1"
    endpoint = OFFSITE_ENDPOINT if zone == "offsite" else GCP_ENDPOINT
    text = (f'schema_version = 1\n\n[collector]\nid = "{host}"\nenvironment = "staging"\nhostname = "{host}"\n'
            f'labels = {{ region = "{region}", role = "release" }}\n\n[controller]\nendpoint = "{endpoint}"\n\n'
            '[spool]\npath = "/var/lib/parth-sentinel-collector/spool.db"\nmax_size = "512MiB"\nretention = "24h"\n\n')
    filters = keep_filters(base_text)
    if lock["units"]["services"] in units and NOSTR_PATTERN_NAME not in filters:
        filters += NOSTR_FILTER
    text += filters
    kept = keep_targets(base_text)
    if not any('kind = "host"' in block for block in kept):
        kept.insert(0, f'[[targets]]\nid = "{host}-host"\nkind = "host"\n\n[[targets.probes]]\nid = "host-resources"\n'
                       f'kind = "host"\ninterval = "{HOST_PROBE_INTERVAL}"\n\n')
    text += "".join(block.rstrip("\n") + "\n\n" for block in [*kept, *core_blocks])
    if units:
        text += f'[[targets]]\nid = "{host}-release-units"\nkind = "infrastructure"\n\n'
        text += "".join(service_block(service_id(lock, unit), unit) for unit in units)
    tomllib.loads(text)
    return text


def threshold_floors(chain_name):
    per_day = DAILY_GAS[chain_name] * PRICE_WEI[chain_name]
    return WARNING_DAYS * per_day, CRITICAL_DAYS * per_day


def check_thresholds(controller, chains):
    by_chain_id = {monitor["expected_chain_id"]: monitor for monitor in controller["ethereum"]}
    for chain in chains:
        monitor = by_chain_id.get(chain["chain_id"])
        require(monitor is not None, f"Controller config has no balance monitor for chain index {chain['index']}")
        warning_floor, critical_floor = threshold_floors(chain["name"])
        require(int(monitor["balance_warning_wei"]) >= warning_floor
                and int(monitor["balance_critical_wei"]) >= critical_floor,
                f"balance thresholds of chain index {chain['index']} cover less than the gas runway")


EXPECTED_BLOCK = re.compile(r"(?m)^\[\[collectors\.expected\]\]\n(?:^(?!\[).*\n?)*")


def expected_blocks(hosts):
    return "".join(f'[[collectors.expected]]\nid = "{host}"\nenvironment = "staging"\nheartbeat_timeout = "60s"\n\n'
                   for host in hosts)


def render_controller(base_text, signer, settlements, hosts):
    """Signer address, collectors.expected and settlement probes of this release; the rest is the pinned config."""
    lines, in_ethereum, replaced = [], False, 0
    for line in EXPECTED_BLOCK.sub("", base_text).splitlines():
        if line.startswith("["):
            in_ethereum = line == "[[ethereum]]"
        if in_ethereum and re.fullmatch(r'address = "0x[0-9a-fA-F]{40}"', line):
            line, replaced = f'address = "{signer}"', replaced + 1
        lines.append(line)
    require(replaced == len(tomllib.loads(base_text)["ethereum"]), "every balance monitor needs one signer address")
    text = "\n".join(lines).rstrip("\n") + "\n\n" + expected_blocks(hosts) + "".join(settlements)
    rendered = tomllib.loads(text)
    require(sorted(expected["id"] for expected in rendered["collectors"]["expected"]) == sorted(hosts),
            "collectors.expected must list exactly the release hosts")
    return text


def settlement_block(chain, state_manager, monitor):
    require(re.fullmatch(r"0x[0-9a-fA-F]{40}", state_manager) and int(state_manager, 16) != 0,
            "chain index " + str(chain["index"]) + " needs a StateManager address")
    return (f'[[settlement]]\nenvironment = "staging"\nnetwork_id = "{NETWORK_IDS[chain["name"]]}"\n'
            f'network_name = "{NETWORK_NAMES[chain["name"]]}"\nchain_index = {chain["index"]}\n'
            f'expected_chain_id = {chain["chain_id"]}\nstate_manager = "{state_manager}"\n'
            f'primary_url_env = "{monitor["primary_url_env"]}"\ninterval = "1m"\ntimeout = "10s"\n'
            'stall_after = "30m"\n\n')


def read_state_manager(ctx, relayer_host, chain_name):
    path = f"{ctx.lock['paths']['relayer']['release']}/deployments/{chain_name}/deployed-contracts.json"
    document = json.loads(ctx.remote.read_text(relayer_host, path))
    core = document.get("core", {})
    return core.get("StateManager") or document.get("contracts", {}).get("StateManager", "")


def write_private_text(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text)


def render_files(ctx):
    """Write the host list, SSH config, collector configs and Controller config; returns the work directory."""
    repo, chains = check_notifier_checkout(ctx), release_chains(ctx.release_dir)
    hosts = monitoring_hosts(ctx.release_dir, ctx.lock)
    names = [alias for alias, _ in hosts]
    missing = ctx.remote.missing_aliases(names)
    require(not missing, "hosts missing from the access file: " + ", ".join(missing))
    relayer_host = release_lock.read_document(ctx.release_dir / "release.json")["core_placement"]["relayer"]
    require({CONTROLLER_HOST, relayer_host} <= set(names), "the Controller and Relayer hosts must belong to the release")
    topology = release_lock.read_document(ctx.release_dir / "topology.json")
    work = ctx.run_dir / "monitoring"
    (work / "collectors").mkdir(parents=True, exist_ok=True)
    for alias, zone in hosts:
        base = repo / COLLECTOR_CONFIGS / f"{alias}.toml"
        text = render_collector(ctx.lock, alias, zone, base.read_text() if base.is_file() else None,
                                core_targets(ctx.lock, topology, alias), discover_units(ctx, alias))
        (work / "collectors" / f"{alias}.toml").write_text(text)
    addresses = host_addresses(ctx.release_dir, ctx.lock)
    (work / "hosts").write_text("".join(f"{alias} {zone} {addresses[alias]}\n" for alias, zone in hosts))
    write_private_text(work / "ssh_config", ctx.remote.ssh_config())
    base_text = (repo / CONTROLLER_CONFIG).read_text()
    controller = tomllib.loads(base_text)
    check_thresholds(controller, chains)
    by_chain_id = {monitor["expected_chain_id"]: monitor for monitor in controller["ethereum"]}
    settlements = [settlement_block(chain, read_state_manager(ctx, relayer_host, chain["name"]),
                                    by_chain_id[chain["chain_id"]]) for chain in chains]
    (work / "controller.toml").write_text(render_controller(base_text, ctx.lock["l1"]["signer"], settlements, names))
    return work


def chain_indexes(ctx):
    return [chain["index"] for chain in release_chains(ctx.release_dir)]


def adapter_env(ctx, work):
    return {**os.environ, "MONITORING_HOSTS_FILE": str(work / "hosts"),
            "MONITORING_COLLECTOR_DIR": str(work / "collectors"),
            "MONITORING_CONTROLLER_CONFIG": str(work / "controller.toml"),
            "MONITORING_CHAIN_INDEXES": json.dumps(chain_indexes(ctx)),
            "MONITORING_NOTIFIER_DIR": local_notifier_section(ctx)["checkout"],
            "MONITORING_SSH_CONFIG": str(work / "ssh_config")}


def run_adapter(ctx, mode, work):
    try:
        run = subprocess.run(["bash", str(ADAPTER), mode], env=adapter_env(ctx, work), capture_output=True,
                             text=True, timeout=ADAPTER_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"monitoring adapter {mode} timed out") from None
    write_private_text(work / f"adapter{mode}.log", run.stdout + run.stderr)
    return run


def adapter_failure(mode, run):
    return f"monitoring adapter {mode} exited {run.returncode}: " + redact_tail(run.stderr or run.stdout)


def install_commands(stdout):
    """(host, command) for each offsite install the adapter printed; the command runs on that host."""
    marker = "[monitoring] user action: "
    rows = [line.removeprefix(marker).strip().split(None, 1) for line in stdout.splitlines() if line.startswith(marker)]
    return [(host, command) for host, command in rows]


def evaluate_status(status, hosts, chain_indexes, now_ms):
    """Why the Controller status is not ready, or None when every host and chain reports."""
    if status.get("ready") is not True or status.get("evm_all_healthy") is not True:
        return "Controller is not ready or an L1 balance probe is unhealthy"
    if status.get("settlement_all_healthy") is not True:
        return "a settlement probe is unhealthy"
    healthy = sorted(probe["chain_index"] for probe in status.get("settlement_probes", []) if probe.get("healthy"))
    if healthy != sorted(chain_indexes):
        return f"settlement probes report chain indexes {healthy}, expected {sorted(chain_indexes)}"
    fresh = {collector["collector_id"] for collector in status.get("collectors", [])
             if collector.get("environment") == "staging" and isinstance(collector.get("last_seen_ms"), int)
             and now_ms - COLLECTOR_FRESH_MS <= collector["last_seen_ms"] <= now_ms + FUTURE_SKEW_MS}
    missing = sorted(set(hosts) - fresh)
    return f"collectors not reporting: {', '.join(missing)}" if missing else None


def read_status(ctx):
    command = shlex.join(["/usr/bin/curl", "-fsS", "--max-time", "10", STATUS_URL])
    return json.loads(ctx.remote.run_script(CONTROLLER_HOST, f"set -euo pipefail\n{command}\n", 30))


def release_hosts(ctx):
    return [alias for alias, _ in monitoring_hosts(ctx.release_dir, ctx.lock)]


def monitoring_check(ctx):
    work = render_files(ctx)
    run = run_adapter(ctx, "--check", work)
    if run.returncode != 0:
        raise RuntimeError(adapter_failure("--check", run))


def monitoring_apply(ctx):
    work = render_files(ctx)
    if run_adapter(ctx, "--status", work).returncode == 0:
        return
    run = run_adapter(ctx, "--apply", work)
    if run.returncode == EXIT_PENDING:
        waiting = [(host, command) for host, command in install_commands(run.stdout)
                   if not run_operator_command(ctx.remote, host, command)]
        if waiting:
            raise OperatorPending(waiting[0][0], waiting[0][1], str(ctx.run_dir / "deploy_monitoring.json"))
        return
    if run.returncode != 0:
        raise RuntimeError(adapter_failure("--apply", run))


def monitoring_verify(ctx):
    indexes, hosts = chain_indexes(ctx), release_hosts(ctx)
    state = {}

    def is_ready():
        state["status"] = read_status(ctx)
        state["reason"] = evaluate_status(state["status"], hosts, indexes, int(time.time() * 1000))
        return state["reason"] is None

    wait_until(is_ready, lambda: None, STATUS_POLL_SECONDS, STATUS_TIMEOUT_SECONDS, "monitoring readiness")
    status = state["status"]
    return {"hosts": hosts, "collector_count": len(status["collectors"]),
            "settlement": [{"chain_index": probe["chain_index"], "cursor": probe["last_finalized_checkpoint"]}
                           for probe in sorted(status["settlement_probes"], key=lambda probe: probe["chain_index"])],
            "evm_all_healthy": True, "outbox_depth": status["outbox_depth"],
            "firing_incidents_in_page": sum(1 for incident in status["incidents"] if incident.get("lifecycle") == "firing"),
            "alert_delivery": "not verified; confirm a test notification separately"}


MONITORING_STEPS = {
    "deploy_monitoring": Step("deploy_monitoring", monitoring_check, monitoring_apply, monitoring_verify,
                              cutover=False),
}
