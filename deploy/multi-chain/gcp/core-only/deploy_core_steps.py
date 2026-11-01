#!/usr/bin/env python3
"""Cutover steps 65-67: start the core units and the Workers, then pass the L2 stability gate.

These steps start live services on the new chain. A rerun never restarts a unit that is already healthy: a unit
that is active with the pinned binary is skipped, and one that is active with another binary stops the step.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shlex

import deploy_health as health
import install_host
import prepare_workers
import release_lock
from deploy_prepare_steps import (TOOLS_DIR as DEFAULT_TOOLS_DIR, check_host_package, file_sha256, local_path, read_artifacts,
                                  read_state, require, worker_verify, write_state)
from deploy_remote import RemoteError, Step, wait_until


TOOLS_DIR = DEFAULT_TOOLS_DIR
ROOT_PYTHON = ["/usr/bin/python3", "-I", "-B", "/dev/stdin"]
BASH = ["/usr/bin/bash", "-s"]
DOCKER = "/usr/bin/docker"
SCYLLA_HOST, NATS_HOST = "gcp-scylla", "gcp-nats"
COORDINATOR_HOST = "gcp-cp-ce"
INSTALL_TIMEOUT_SECONDS = 900
ACTIVATE_TIMEOUT_SECONDS = 300
PROBE_TIMEOUT_SECONDS = 120
POLL_SECONDS = 10
# Processors build their circuits for about two minutes before they touch the database.
INIT_WAIT_SECONDS = 900
ADVANCE_WAIT_SECONDS = 300
FINAL_READ_ATTEMPTS = 3
WORKER_EVIDENCE_WAIT_SECONDS = 900
# The dot stands for the closing bracket of the log tag; journalctl --grep takes a regular expression.
REALM_INIT_MARKER = "REALM_STARTUP. init_with_setup_and_genesis done"
COORDINATOR_INIT_MARKER = "COORD_STARTUP. init_with_setup_and_genesis done"
WHITELIST_ERROR_PATTERN = "ERROR.*[Ww]hitelist"
NO_TABLET_SUFFIX = "_no_tablet"
CONNECT_WAIT_SECONDS = 180
CONNECTIONS_SCRIPT = ("set -uo pipefail\nss -Htn state established | awk '{print \"conn\", $3, $4}'\nexit 0\n")
WORKER_MARKERS = (("pickup", "Worker: Picked up job"), ("prove", "Worker: Proved job"),
                  ("submit", "Submitter: Successfully submitted proof"))
NANOSECONDS_PER_MILLISECOND = 1_000_000
STAGE_PREFIX = "/var/tmp/psy-release-"

# Runs as root on a host: one row per unit with its load state, restart counter and running executable.
UNIT_PROBE = """import hashlib, json, os, subprocess, sys
report = {}
for unit in sys.argv[1:]:
    shown = subprocess.run(["systemctl", "show", "--no-pager", "--property=LoadState,ActiveState,MainPID,NRestarts",
                            "--", unit], capture_output=True, text=True, check=True).stdout
    fields = dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)
    pid = int(fields.get("MainPID") or 0)
    row = {"load": fields.get("LoadState"), "active": fields.get("ActiveState"), "exe": None, "sha256": None,
           "restarts": int(fields.get("NRestarts") or 0)}
    if row["active"] == "active" and pid > 0:
        try:
            row["exe"] = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/exe", "rb") as stream:
                row["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError:
            pass
    report[unit] = row
print(json.dumps(report))
"""

def read_checked_tool(ctx, name):
    raw = (TOOLS_DIR / name).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ctx.lock["tool_sha256"][name], f"tool hash differs: {name}")
    return raw


def stage_dir(ctx):
    return f"{STAGE_PREFIX}{ctx.lock_sha256[:12]}-start"


def probe_units(ctx, host, units):
    output = ctx.remote.run_root_text(host, [*ROOT_PYTHON, *units], PROBE_TIMEOUT_SECONDS, stdin_text=UNIT_PROBE)
    try:
        rows = json.loads(output)
    except ValueError:
        rows = None
    require(isinstance(rows, dict) and set(rows) == set(units), f"{host}: the unit probe did not report every unit")
    return rows


class UnitSet:
    """The units of one host, the executable they must run, and what a probe says about them."""

    def __init__(self, host, units, exe_path, exe_sha256):
        self.host, self.units, self.exe_path, self.exe_sha256 = host, sorted(units), exe_path, exe_sha256

    def read(self, ctx):
        return probe_units(ctx, self.host, self.units)

    def healthy(self, row):
        return row["active"] == "active" and row["exe"] == self.exe_path and row["sha256"] == self.exe_sha256

    def check_no_foreign_binary(self, rows):
        for unit, row in rows.items():
            if row["active"] == "active" and not self.healthy(row):
                raise ValueError(f"{self.host}: {unit} is active with an unexpected binary; stop it by hand first")

    def subset(self, units):
        return UnitSet(self.host, units, self.exe_path, self.exe_sha256)


def core_unit_sets(ctx):
    release = install_host.load_core_release(ctx.lock)
    exe_path, exe_sha256 = str(release.release_dir / "bin" / "psy_node_cli"), ctx.lock["binaries"]["psy_node_cli"]
    return {host: UnitSet(host, units, exe_path, exe_sha256) for host, units in health.core_units(ctx).items()}


def worker_unit_set(ctx):
    release = prepare_workers.load_worker_release(ctx.lock)
    return UnitSet(health.WORKER_HOST, health.worker_units(ctx), str(release.release_dir / "psy_worker_cli"),
                   ctx.lock["binaries"]["psy_worker_cli"])


def phase_units(unit_set, phase):
    return [unit for unit in unit_set.units if unit.endswith("processor.service") == (phase == "processors")]


def remote_path(stage, relative):
    return str(PurePosixPath(stage, "package", relative))


def stage_files(ctx, host, package_root, tool_names):
    """Copy the package, the reviewed tools and the lock to the host, then check the tool and lock hashes there."""
    stage, remote = stage_dir(ctx), ctx.remote
    files = sorted(path for path in package_root.rglob("*") if path.is_file())
    directories = sorted({path.parent for path in files} | {package_root})
    remote_dirs = [remote_path(stage, directory.relative_to(package_root).as_posix()) for directory in directories]
    made = " ".join(shlex.quote(item) for item in [stage, stage + "/tools", *remote_dirs])
    remote.run_script(host, f"set -euo pipefail\numask 077\ninstall -d -m 0700 -- {made}\n", 60)
    for directory, remote_dir in zip(directories, remote_dirs):
        remote.copy_files(host, [path for path in files if path.parent == directory], remote_dir)
    remote.copy_files(host, [TOOLS_DIR / name for name in tool_names] + [ctx.release_dir / "release-lock.json"],
                      stage + "/tools")
    checks = [f"{ctx.lock['tool_sha256'][name]}  {stage}/tools/{name}" for name in tool_names]
    checks.append(f"{ctx.lock_sha256}  {stage}/tools/release-lock.json")
    remote.run_script(host, f"set -euo pipefail\nchmod -R go-rwx -- {shlex.quote(stage)}\n"
                      "sha256sum -c --quiet - <<'EOF'\n" + "\n".join(checks) + "\nEOF\n", 120)


def unstage(ctx, host):
    try:
        ctx.remote.run_script(host, f"set -euo pipefail\nrm -rf -- {shlex.quote(stage_dir(ctx))}\n", 60)
    except RemoteError:
        pass  # the original failure matters more; the next run stages again


def run_tool(ctx, host, tool, arguments, timeout):
    stage = stage_dir(ctx)
    argv = ["/usr/bin/python3", "-I", "-B", f"{stage}/tools/{tool}", *arguments, "--release-lock",
            f"{stage}/tools/release-lock.json", "--release-lock-sha256", ctx.lock_sha256, "--package", f"{stage}/package"]
    return ctx.remote.run_root_json(host, argv, timeout, show_stderr=True)


def package_root(ctx, name, host=None):
    outputs = read_state(ctx, "prepare_packages")
    require(name in outputs, f"no recorded {name} package; run step prepare_packages")
    root = Path(outputs[name])
    return root / host if host else root


def scylla_keyspaces(ctx):
    script = ('set -eu; cqlsh_path="$(command -v cqlsh || command -v cqlsh.py)"; host="$(hostname -i | awk \'{print $1}\')"; '
              'exec "$cqlsh_path" "$host" 9042 -e "$1"')
    output = ctx.remote.run_root_text(SCYLLA_HOST, [DOCKER, "exec", "scylla-server", "sh", "-c", script, "sh",
                                                    "SELECT keyspace_name FROM system_schema.keyspaces"],
                                      PROBE_TIMEOUT_SECONDS)
    return {line.strip() for line in output.splitlines() if line.strip()}


def realm_namespaces(topology):
    return [validator["namespace"] for realm in topology["realms"] for validator in realm["validators"]]


def keyspaces_of(namespaces):
    """The node creates two keyspaces per namespace, and opens both."""
    return [name for namespace in namespaces for name in (namespace, namespace + NO_TABLET_SUFFIX)]


def marker_counts(ctx, host, units, marker):
    script = "set -uo pipefail\n" + "".join(
        f"echo \"{unit} $(journalctl -u {shlex.quote(unit)} --no-pager -o cat -g {shlex.quote(marker)} 2>/dev/null | wc -l)\"\n"
        for unit in units) + "exit 0\n"
    counts = {}
    for line in ctx.remote.run_root_text(host, BASH, PROBE_TIMEOUT_SECONDS, stdin_text=script).splitlines():
        words = line.split()
        require(len(words) == 2 and words[0] in units and words[1].isdigit(), f"{host}: unexpected marker count line")
        counts[words[0]] = int(words[1])
    require(set(counts) == set(units), f"{host}: marker counts missing for a unit")
    return counts


def unit_failure(ctx, unit_sets):
    """A reason to stop waiting: a unit that is not active, restarted, or logged a panic since it started."""
    for unit_set in unit_sets:
        try:
            report = health.read_units(ctx, unit_set.host, unit_set.units, None)
        except ValueError as error:
            return str(error)
        except RemoteError as error:
            if health.is_unreachable(error):
                continue
            raise
        restarted = sorted(unit for unit, count in report.restarts.items() if count > 0)
        if restarted:
            return f"{unit_set.host}: {restarted[0]} restarted"
        if report.panics:
            return "panic in a unit log: " + report.panics[0][:200]
    return None


def namespace_ready(ctx, namespaces, processor_sets, marker):
    if not set(keyspaces_of(namespaces)) <= scylla_keyspaces(ctx):
        return False
    return all(all(count > 0 for count in marker_counts(ctx, unit_set.host, unit_set.units, marker).values())
               for unit_set in processor_sets)


def wait_for_namespaces(ctx, namespaces, processor_sets, marker, label):
    wait_until(lambda: namespace_ready(ctx, namespaces, processor_sets, marker), lambda: unit_failure(ctx, processor_sets),
               POLL_SECONDS, INIT_WAIT_SECONDS, label)


def silent_names(heights):
    return ", ".join(sorted(name for name, height in heights.items() if height is None))


def wait_for_agreement(ctx, targets, unit_sets, label):
    """Every edge in the list answers and the readings agree within the read skew."""
    state = {}

    def agreed():
        state["heights"] = health.read_edges(ctx, targets)
        return settled_edges(state["heights"])
    try:
        wait_until(agreed, lambda: unit_failure(ctx, unit_sets), POLL_SECONDS, INIT_WAIT_SECONDS, label)
    except TimeoutError:
        heights = state.get("heights", {})
        raise ValueError(f"{label}: the edges did not agree; no answer from [{silent_names(heights)}], "
                         f"readings {sorted(set(v for v in heights.values() if v is not None))}") from None
    return state["heights"]


# Step 65.
def core_check(ctx):
    for name in ("install_host.py", "activate_host.py"):
        read_checked_tool(ctx, name)
    expected = read_artifacts(ctx).get("core_host_packages", {}).get("manifest_sha256", {})
    for host in core_unit_sets(ctx):
        require(host in expected, f"{host}: artifacts core_host_packages has no manifest hash")
        root = package_root(ctx, "core", host)
        require(root.is_dir(), f"{host}: no core package found")
        check_host_package(ctx, host, root, expected[host])


def host_needs_install(unit_set, rows):
    if all(row["load"] == "loaded" for row in rows.values()):
        return False
    require(not any(row["active"] == "active" for row in rows.values()),
            f"{unit_set.host}: some units are active but others are not installed")
    return True


def host_needs_activation(unit_set, rows):
    return any(not unit_set.healthy(row) for row in rows.values())


def activate_phase(ctx, unit_set, phase):
    """Start one phase on one host; units that are already healthy are left alone."""
    selected = unit_set.subset(phase_units(unit_set, phase))
    rows = selected.read(ctx)
    selected.check_no_foreign_binary(rows)
    if not host_needs_activation(selected, rows):
        return
    report = run_tool(ctx, unit_set.host, "activate_host.py", ["--phase", phase, "--apply"], ACTIVATE_TIMEOUT_SECONDS)
    require(report.get("started") is True, f"{unit_set.host}: activation did not report a start")


def start_in_order(ctx, sets, topology, targets):
    coordinator = sets[COORDINATOR_HOST]
    processor = coordinator.subset(phase_units(coordinator, "processors"))
    activate_phase(ctx, coordinator, "processors")
    wait_for_namespaces(ctx, [topology["coordinator"]["namespace"]], [processor], COORDINATOR_INIT_MARKER,
                        "coordinator namespace")
    activate_phase(ctx, coordinator, "edges")
    wait_for_agreement(ctx, [t for t in targets if t.name.startswith("coordinator-")], [coordinator], "coordinator edges")
    processors = [sets[host] for host in install_host.PROCESSORS]
    for unit_set in processors:
        activate_phase(ctx, unit_set, "processors")
    wait_for_namespaces(ctx, realm_namespaces(topology), processors, REALM_INIT_MARKER, "realm namespaces")
    for host in install_host.EDGES:
        activate_phase(ctx, sets[host], "edges")


def core_apply(ctx):
    sets, topology = core_unit_sets(ctx), health.read_topology(ctx)
    states = {host: unit_set.read(ctx) for host, unit_set in sets.items()}
    for host, unit_set in sets.items():
        unit_set.check_no_foreign_binary(states[host])
    work = [host for host, unit_set in sets.items()
            if host_needs_install(unit_set, states[host]) or host_needs_activation(unit_set, states[host])]
    staged = []
    try:
        for host in work:
            staged.append(host)
            stage_files(ctx, host, package_root(ctx, "core", host), ("install_host.py", "activate_host.py"))
        for host in work:
            if host_needs_install(sets[host], states[host]):
                report = run_tool(ctx, host, "install_host.py", [], INSTALL_TIMEOUT_SECONDS)
                require(report.get("mode") == "installed", f"{host}: install did not report an installation")
        start_in_order(ctx, sets, topology, health.edge_targets(topology))
    finally:
        for host in staged:
            unstage(ctx, host)


def check_core_units(ctx, sets):
    summary = {}
    for host, unit_set in sets.items():
        rows = unit_set.read(ctx)
        unhealthy = [unit for unit, row in rows.items() if not unit_set.healthy(row)]
        require(not unhealthy, f"{host}: not active with the pinned binary: {', '.join(unhealthy)}")
        summary[host] = len(rows)
    return summary


def settled_edges(heights):
    known = list(heights.values())
    return bool(known) and None not in known and max(known) - min(known) <= health.READ_SKEW


def read_connections(ctx, host):
    connections = set()
    for line in ctx.remote.run_root_text(host, BASH, PROBE_TIMEOUT_SECONDS, stdin_text=CONNECTIONS_SCRIPT).splitlines():
        words = line.split()
        require(len(words) == 3 and words[0] == "conn", f"{host}: unexpected connection line")
        connections.add((words[1], words[2]))
    return connections


def missing_connections(topology, connections):
    """Per validator, the peer processors and the realm's edges its processor has no established connection to."""
    hosts, missing = topology["hosts"], []
    for realm in topology["realms"]:
        validators = realm["validators"]
        require(len(validators) == 3, f"realm {realm['id']} does not list three validators")
        for position, validator in enumerate(validators, start=1):
            local = f"{hosts[validator['processor_host']]}:{validator['processor_port']}"
            wanted = [f"{hosts[other['processor_host']]}:{other['processor_port']}" for other in validators if other is not validator]
            wanted += [f"{hosts[other['edge_host']]}:{other['edge_port']}" for other in validators]
            lacking = [peer for peer in wanted if (local, peer) not in connections[validator["processor_host"]]]
            if lacking:
                missing.append(f"realm {realm['id']} validator {position} lacks {len(lacking)} of {len(wanted)}")
    return missing


def wait_for_connections(ctx, topology, unit_sets):
    """Each realm processor holds an established connection to its 2 peer processors and its 3 edges."""
    state = {}

    def connected():
        found = {host: read_connections(ctx, host) for host in install_host.PROCESSORS}
        state["missing"] = missing_connections(topology, found)
        return not state["missing"]
    try:
        wait_until(connected, lambda: unit_failure(ctx, unit_sets), POLL_SECONDS, CONNECT_WAIT_SECONDS, "validator connections")
    except TimeoutError:
        raise ValueError("validators are not connected: " + "; ".join(state["missing"])) from None


def read_worker_consumers(ctx):
    """The live consumer configuration from NATS, through the pinned database probe (ack_wait is in nanoseconds)."""
    source = read_checked_tool(ctx, "probe_databases.py").decode()
    output = ctx.remote.run_root_text(NATS_HOST, [*ROOT_PYTHON, "nats-consumers"], PROBE_TIMEOUT_SECONDS, stdin_text=source)
    try:
        report = json.loads(output)
    except ValueError:
        report = None
    require(isinstance(report, dict) and report.get("ok") is True and isinstance(report.get("consumers"), list),
            "the NATS consumer listing failed: " + str(report.get("error") if isinstance(report, dict) else "no report"))
    return [row for row in report["consumers"] if row.get("ack_policy") == "explicit" and row.get("max_deliver") == -1]


def check_ack_wait(ctx, require_consumers):
    expected = ctx.lock["gates"]["worker_queue_ack_wait_ms"] * NANOSECONDS_PER_MILLISECOND
    consumers = read_worker_consumers(ctx)
    wrong = sorted({row.get("ack_wait") for row in consumers if row.get("ack_wait") != expected})
    require(not wrong, f"worker queue consumers have ack_wait {wrong} ns, expected {expected} ns")
    require(consumers or not require_consumers, "no worker queue consumer exists")
    return {"worker_consumers": len(consumers), "ack_wait_ns": expected}


def core_verify(ctx):
    """The 16 units run, the namespaces exist, the nine edges answer and agree, the validators are connected.

    Advance is not judged here: the Coordinator cannot advance before the Workers run.
    """
    sets, topology = core_unit_sets(ctx), health.read_topology(ctx)
    summary = check_core_units(ctx, sets)
    processors = [sets[host] for host in install_host.PROCESSORS]
    coordinator = sets[COORDINATOR_HOST]
    require(namespace_ready(ctx, realm_namespaces(topology), processors, REALM_INIT_MARKER), "realm namespaces are not initialised")
    require(namespace_ready(ctx, [topology["coordinator"]["namespace"]],
                            [coordinator.subset(phase_units(coordinator, "processors"))], COORDINATOR_INIT_MARKER),
            "the coordinator namespace is not initialised")
    heights = wait_for_agreement(ctx, health.edge_targets(topology), list(sets.values()), "nine edges")
    wait_for_connections(ctx, topology, list(sets.values()))
    return {"units": summary, "edge_checkpoints": heights, **check_ack_wait(ctx, True)}


# Step 66.
def worker_policy(ctx):
    """The pinned runtime config must enforce the whitelist, and every Worker identity must be on it."""
    config_path, listed_path = local_path(ctx, "files", "config"), TOOLS_DIR / "worker-whitelist.json"
    require(file_sha256(config_path) == ctx.lock["inputs"]["runtime_config"], "the runtime config differs from the lock")
    require(file_sha256(listed_path) == ctx.lock["inputs"]["worker_whitelist"], "the worker whitelist differs from the lock")
    whitelist = release_lock.read_document(config_path)["networks"]["testnet"]["whitelist"]
    listed = release_lock.read_document(listed_path)["networks"]["testnet"]["whitelist"]
    require(whitelist["enabled"] is True, "the worker whitelist is not enforced in the runtime config")
    require(set(whitelist["secp256k1"]) == set(listed["secp256k1"]),
            "the runtime config whitelist differs from the lock whitelist")
    require(set(prepare_workers.PUBLIC_KEYS.values()) <= set(whitelist["secp256k1"]),
            "a Worker identity is not on the whitelist")
    return len(whitelist["secp256k1"])


def check_edge_configs(ctx):
    expected = ctx.lock["inputs"]["runtime_config"]
    path = str(install_host.load_core_release(ctx.lock).config_dir / "config.json")
    for host in (COORDINATOR_HOST, *install_host.EDGES):
        output = ctx.remote.run_root_text(host, ["/usr/bin/sha256sum", "--", path], PROBE_TIMEOUT_SECONDS)
        require(output.split()[:1] == [expected], f"{host}: the Edge config differs from the pinned runtime config")


def workers_check(ctx):
    read_checked_tool(ctx, "prepare_workers.py")
    root = package_root(ctx, "worker")
    require(root.is_dir(), "no worker package found")
    worker_verify(ctx, {}, root)
    worker_policy(ctx)


def workers_installed(rows):
    loaded = [row["load"] == "loaded" for row in rows.values()]
    require(all(loaded) or not any(loaded), "worker units are partly installed; inspect the host")
    return all(loaded)


def workers_apply(ctx):
    unit_set = worker_unit_set(ctx)
    rows = unit_set.read(ctx)
    unit_set.check_no_foreign_binary(rows)
    installed = workers_installed(rows)
    if installed and not host_needs_activation(unit_set, rows):
        return
    host = unit_set.host
    try:
        stage_files(ctx, host, package_root(ctx, "worker"), ("prepare_workers.py",))
        if not installed:
            run_tool(ctx, host, "prepare_workers.py", ["check-host"], INSTALL_TIMEOUT_SECONDS)
            report = run_tool(ctx, host, "prepare_workers.py", ["install"], INSTALL_TIMEOUT_SECONDS)
            require(report.get("mode") == "installed", f"{host}: worker install did not report an installation")
        report = run_tool(ctx, host, "prepare_workers.py", ["activate"], ACTIVATE_TIMEOUT_SECONDS)
        require(report.get("started") is True, f"{host}: worker activation did not report a start")
    finally:
        unstage(ctx, host)


def all_unit_sets(ctx):
    return [*core_unit_sets(ctx).values(), worker_unit_set(ctx)]


def worker_evidence(ctx, unit_set):
    coordinator = [health.worker_units(ctx)[0]]
    return {label: marker_counts(ctx, unit_set.host, coordinator, marker) for label, marker in WORKER_MARKERS}


def missing_evidence(evidence):
    return sorted(f"{unit}:{label}" for label, counts in evidence.items() for unit, count in counts.items() if count == 0)


def wait_for_advance(ctx, targets, unit_sets):
    first = health.read_edges(ctx, targets)
    start = max((value for value in first.values() if value is not None), default=None)
    state = {}

    def advanced():
        state["heights"] = health.read_edges(ctx, targets)
        return start is not None and settled_edges(state["heights"]) and max(state["heights"].values()) > start
    try:
        wait_until(advanced, lambda: unit_failure(ctx, unit_sets), POLL_SECONDS, ADVANCE_WAIT_SECONDS,
                   "edge checkpoints advancing")
    except TimeoutError:
        raise ValueError("the nine edges did not advance together; no answer from ["
                         + silent_names(state.get("heights", first)) + "]") from None
    return state["heights"]


def workers_verify(ctx):
    """Coordinator pickup, prove and submit, the chain advancing, and every Worker running without whitelist errors.

    An empty chain gives the Realm Workers no jobs, so their proof evidence belongs to acceptance.
    """
    unit_set = worker_unit_set(ctx)
    rows = unit_set.read(ctx)
    unhealthy = [unit for unit, row in rows.items() if not unit_set.healthy(row)]
    require(not unhealthy, f"workers not active with the pinned binary: {', '.join(unhealthy)}")
    listed = worker_policy(ctx)
    check_edge_configs(ctx)
    failure_sets = all_unit_sets(ctx)
    state = {}

    def seen_everything():
        state["evidence"] = worker_evidence(ctx, unit_set)
        return not missing_evidence(state["evidence"])
    try:
        wait_until(seen_everything, lambda: unit_failure(ctx, failure_sets), POLL_SECONDS, WORKER_EVIDENCE_WAIT_SECONDS,
                   "coordinator worker pickup, prove and submit evidence")
    except TimeoutError:
        raise ValueError("missing worker evidence: " + ", ".join(missing_evidence(state["evidence"]))) from None
    errors = {unit: count for unit, count in marker_counts(ctx, unit_set.host, unit_set.units, WHITELIST_ERROR_PATTERN).items()
              if count}
    require(not errors, "worker logs hold whitelist errors: " + ", ".join(sorted(errors)))
    heights = wait_for_advance(ctx, health.edge_targets(health.read_topology(ctx)), failure_sets)
    return {"workers": len(rows), "whitelisted_identities": listed, "whitelist_errors": 0, "edge_checkpoints": heights,
            "coordinator_evidence": {label: sorted(counts.values()) for label, counts in state["evidence"].items()},
            "realm_proof_evidence": "deferred to acceptance: an empty chain has no Realm jobs"}


# Step 67.
def gate_required(ctx):
    count = ctx.lock["gates"]["l2_stability_checkpoint_count"]
    require(type(count) is int and count >= 1, "the lock gate checkpoint count must be a positive integer")
    return count


def gate_check(ctx):
    gate_required(ctx)
    core_unit_sets(ctx)


def highest_checkpoints(samples):
    found = ([value for value in sample.edge_checkpoint_ids.values() if value is not None] for sample in samples)
    return [max(known) for known in found if known]


def describe_unfinished(samples, required):
    last, highest = samples[-1], highest_checkpoints(samples)
    answering = sum(value is not None for value in last.edge_checkpoint_ids.values())
    return (f"L2 stability gate not passed within {health.gate_limit_seconds(required)}s: advanced "
            f"{(highest[-1] - highest[0]) if highest else 0} of {required} checkpoints, {answering} of "
            f"{len(last.edge_checkpoint_ids)} edges answering, {last.proof_upload_count} proof uploads")


def run_gate(ctx, required):
    """Take fresh samples until the rule decides; nothing is carried over from an earlier run."""
    samples, state = [], {}

    def decide():
        samples.append(health.read_chain_sample(ctx))
        try:
            state["result"] = health.evaluate_l2_stability(samples, required)
        except ValueError as error:
            return str(error)
        return None
    try:
        wait_until(lambda: state.get("result") == "passed", decide, POLL_SECONDS, health.gate_limit_seconds(required),
                   "L2 stability gate")
    except TimeoutError:
        raise ValueError(describe_unfinished(samples, required)) from None
    return samples


def gate_apply(ctx):
    samples = run_gate(ctx, gate_required(ctx))
    highest = highest_checkpoints(samples)
    write_state(ctx, "gate_l2_stability", {"samples": len(samples), "advanced": highest[-1] - highest[0],
                                           "proof_uploads": health.uploads_in_run(samples)})


def read_complete_sample(ctx, expected_units):
    """The final check retries a sample that missed a silent host, then judges the last one it got."""
    for _ in range(FINAL_READ_ATTEMPTS):
        sample = health.read_chain_sample(ctx)
        if len(sample.unit_restart_counts) == expected_units and None not in sample.edge_checkpoint_ids.values():
            break
    return sample


def gate_verify(ctx):
    recorded = read_state(ctx, "gate_l2_stability")
    expected_units = sum(len(units) for units in health.core_units(ctx).values()) + len(health.worker_units(ctx))
    sample = read_complete_sample(ctx, expected_units)
    require(len(sample.unit_restart_counts) == expected_units, "not every unit could be read for the final check")
    require(all(count == 0 for count in sample.unit_restart_counts.values()), "a unit has restarted")
    require(not sample.panic_lines, "a unit log has a panic line")
    require(settled_edges(sample.edge_checkpoint_ids), "the nine edges do not agree in the final check")
    return {**recorded, "units": expected_units, "edges": dict(sample.edge_checkpoint_ids), **check_ack_wait(ctx, True)}


CORE_STEPS = {
    "start_core": Step("start_core", core_check, core_apply, core_verify, cutover=True),
    "start_workers": Step("start_workers", workers_check, workers_apply, workers_verify, cutover=True),
    "gate_l2_stability": Step("gate_l2_stability", gate_check, gate_apply, gate_verify, cutover=True),
}
