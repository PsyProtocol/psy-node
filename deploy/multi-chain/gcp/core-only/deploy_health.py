#!/usr/bin/env python3
"""L2 health evidence: one sample of the live chain, and the rule that decides whether the samples pass."""
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import json
import re
import shlex

import install_host
import prepare_workers
import release_lock
from deploy_remote import ROOT_LIMIT_EXIT_CODES, DeployContext, RemoteConnectionError, RemoteError, redact_tail


CHECKPOINT_SECONDS = 11
GATE_LIMIT_FACTOR = 2
# Edges are read one after another, so two readings of the same instant can differ by one checkpoint.
READ_SKEW = 1
MAX_CONSECUTIVE_TIMEOUTS = 3
# A chain that does not advance for this many samples in a row has stalled.
STALL_SAMPLES = 6
# The Coordinator Worker must upload at least one proof per this many checkpoints advanced.
CHECKPOINTS_PER_UPLOAD = 20
SAMPLE_TIMEOUT_SECONDS = 120
EDGE_PASS_TIMEOUT_SECONDS = 30
RPC_TIMEOUT_SECONDS = 3
EDGE_READER_HOST = "gcp-cp-ce"
PANIC_LINES_PER_UNIT = 3
PANIC_LINE_CHARS = 200
UPLOAD_MARKER = "Submitter: Successfully submitted proof"
RPC_BODY = '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}'
LOADED = "LoadState=loaded"
WORKER_HOST = "gcp-c4d-1"


@dataclass(frozen=True)
class ChainSample:
    edge_checkpoint_ids: Mapping[str, int | None]  # None: the Edge gave no usable answer in this sample
    unit_restart_counts: Mapping[str, int]
    panic_lines: tuple[str, ...]
    proof_upload_count: int  # -1: the Worker host could not be read in this sample
    unit_main_pids: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class EdgeTarget:
    name: str
    host: str
    address: str
    port: int


@dataclass(frozen=True)
class HostReport:
    edges: Mapping[str, int | None]
    restarts: Mapping[str, int]
    panics: tuple[str, ...]
    uploads: int
    pids: Mapping[str, int] = field(default_factory=dict)


def gate_limit_seconds(required_checkpoint_count):
    return required_checkpoint_count * CHECKPOINT_SECONDS * GATE_LIMIT_FACTOR


def check_panics(samples):
    for sample in samples:
        if sample.panic_lines:
            raise ValueError("panic in a unit log: " + redact_tail(sample.panic_lines[0], PANIC_LINE_CHARS))


def check_restarts(samples):
    first_pids = {}
    for sample in samples:
        for unit, count in sample.unit_restart_counts.items():
            if count > 0:
                raise ValueError(f"unit restarted: {unit} NRestarts={count}")
        for unit, pid in sample.unit_main_pids.items():
            if first_pids.setdefault(unit, pid) != pid:
                raise ValueError(f"unit restarted: {unit} changed its main process")


def edge_series(samples):
    names = sorted({name for sample in samples for name in sample.edge_checkpoint_ids})
    return {name: [sample.edge_checkpoint_ids.get(name) for sample in samples] for name in names}


def check_edge_series(name, series):
    previous, silent_run = None, 0
    for value in series:
        silent_run = silent_run + 1 if value is None else 0
        if silent_run >= MAX_CONSECUTIVE_TIMEOUTS:
            raise ValueError(f"edge {name} gave no answer in {MAX_CONSECUTIVE_TIMEOUTS} samples in a row")
        if value is None:
            continue
        if previous is not None and value < previous:
            raise ValueError(f"checkpoint regressed on edge {name}: {previous} then {value}")
        previous = value


def check_divergence(samples):
    """An edge behind the leader in two readings in a row has diverged; a silent sample neither clears nor adds."""
    behind = set()
    for sample in samples:
        known = {name: value for name, value in sample.edge_checkpoint_ids.items() if value is not None}
        lagging = {name for name, value in known.items() if max(known.values()) - value > READ_SKEW}
        stuck = behind & lagging
        if stuck:
            raise ValueError(f"edge {sorted(stuck)[0]} stays behind the other edges")
        behind = (behind - set(known)) | lagging


def check_stall(highest):
    stalled = 0
    for before, after in zip(highest, highest[1:]):
        stalled = stalled + 1 if after <= before else 0
        if stalled >= STALL_SAMPLES:
            raise ValueError(f"the chain did not advance in {STALL_SAMPLES} samples in a row")


def uploads_in_run(samples):
    known = [sample.proof_upload_count for sample in samples if sample.proof_upload_count >= 0]
    return known[-1] - known[0] if known else 0


def settled(sample):
    values = list(sample.edge_checkpoint_ids.values())
    return None not in values and bool(values) and max(values) - min(values) <= READ_SKEW


def evaluate_l2_stability(samples: Sequence[ChainSample], required_checkpoint_count: int) -> str | None:
    """None while undecided, "passed" when done, ValueError naming the first failure otherwise."""
    if not samples:
        return None
    check_panics(samples)
    check_restarts(samples)
    for name, series in edge_series(samples).items():
        check_edge_series(name, series)
    check_divergence(samples)
    highest = [max(known) for known in ([v for v in s.edge_checkpoint_ids.values() if v is not None] for s in samples)
               if known]
    check_stall(highest)
    advanced = highest[-1] - highest[0] if highest else 0
    needed_uploads = max(1, advanced // CHECKPOINTS_PER_UPLOAD)
    if advanced >= required_checkpoint_count and settled(samples[-1]) and uploads_in_run(samples) >= needed_uploads:
        return "passed"
    return None


def read_topology(ctx):
    return release_lock.read_document(ctx.release_dir / "topology.json")


def edge_targets(topology, coordinator_edge_count):
    """The running coordinator edges, the coordinator ingress, and every realm edge."""
    hosts = topology["hosts"]
    coordinator = topology["coordinator"]
    address = hosts[coordinator["host"]]
    targets = [EdgeTarget(f"coordinator-{index}", coordinator["host"], address, port)
               for index, port in enumerate(coordinator["edge_ports"][:coordinator_edge_count])]
    targets.append(EdgeTarget("coordinator-ingress", coordinator["host"], address, coordinator["ingress_port"]))
    for realm in topology["realms"]:
        for position, validator in enumerate(realm["validators"], start=1):
            host = validator["edge_host"]
            targets.append(EdgeTarget(f"realm-{realm['id']}-v{position}", host, hosts[host], validator["http_port"]))
    return targets


def core_units(ctx, coordinator_edge_count):
    """{host: sorted unit names} of the core units that run, from the installer's own inventory."""
    release = install_host.load_core_release(ctx.lock)
    hosts = ("gcp-cp-ce", *install_host.PROCESSORS, *install_host.EDGES)
    deferred = {f"{release.unit_prefix}coordinator-edge-{index}.service"
                for index in range(coordinator_edge_count, len(read_topology(ctx)["coordinator"]["edge_ports"]))}
    return {host: sorted(set(install_host.host_inventory(host, release)[0]) - deferred) for host in hosts}


def worker_units(ctx):
    release = prepare_workers.load_worker_release(ctx.lock)
    return [prepare_workers.unit_name(release, role) for role in prepare_workers.THREADS]


def edge_script(targets):
    """All edges at once from one host: every request runs in the background, so the readings share one instant."""
    lines = ["set -uo pipefail", 'dir=$(mktemp -d)', "trap 'rm -rf \"$dir\"' EXIT", "rpc() {",
             f'  /usr/bin/curl -s -m {RPC_TIMEOUT_SECONDS} -X POST -H "content-type: application/json" '
             f"--data {shlex.quote(RPC_BODY)} \"$2\" > \"$dir/$1\" 2>/dev/null || echo timeout > \"$dir/$1\"", "}"]
    lines += [f"rpc {shlex.quote(target.name)} {shlex.quote(f'http://{target.address}:{target.port}')} &" for target in targets]
    lines.append("wait")
    lines += [f'echo "edge {target.name} $(head -c 300 "$dir/{target.name}" | tr -d "\\n")"' for target in targets]
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


def unit_script(units, upload_unit):
    """Per unit: state, restart counter, main process, a positive log control, and panic lines since the unit started."""
    lines = ["set -uo pipefail", "unit() {",
             '  props=$(systemctl show --property=LoadState,ActiveState,MainPID,NRestarts -- "$1" | tr "\\n" " ")',
             '  since=$(systemctl show --property=ActiveEnterTimestamp --value -- "$1")',
             '  echo "unit $1 $props"',
             '  if [ -z "$(journalctl -u "$1" -n 1 -o cat --no-pager 2>/dev/null)" ]; then echo "nolog $1"; return 0; fi',
             f'  journalctl -u "$1" --since "$since" --no-pager -o cat -g "panicked at" 2>/dev/null | tail -n {PANIC_LINES_PER_UNIT}'
             f' | cut -c1-{PANIC_LINE_CHARS} | sed "s/^/panic $1 /"',
             "  return 0", "}"]
    lines += [f"unit {shlex.quote(unit)}" for unit in units]
    if upload_unit:
        lines.append(f'echo "uploads $(journalctl -u {shlex.quote(upload_unit)} --no-pager -o cat '
                     f'-g {shlex.quote(UPLOAD_MARKER)} 2>/dev/null | wc -l)"')
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


def edge_value(body):
    try:
        value = json.loads(body).get("result")
    except (ValueError, AttributeError):
        return None
    return value if type(value) is int and value >= 0 else None


def parse_host_report(output):
    edges, restarts, pids, panics, uploads = {}, {}, {}, [], -1
    for line in output.splitlines():
        words = line.split(" ", 2)
        if words[0] == "edge" and len(words) == 3:
            edges[words[1]] = edge_value(words[2])
        elif words[0] == "unit" and len(words) == 3:
            fields = dict(item.split("=", 1) for item in words[2].split() if "=" in item)
            if fields.get("LoadState") != "loaded" or fields.get("ActiveState") != "active":
                raise ValueError(f"unit {words[1]} is not loaded and active")
            if not (fields.get("NRestarts", "").isdigit() and fields.get("MainPID", "").isdigit()
                    and int(fields["MainPID"]) > 0):
                raise ValueError(f"unit {words[1]} has no restart counter or main process")
            restarts[words[1]], pids[words[1]] = int(fields["NRestarts"]), int(fields["MainPID"])
        elif words[0] == "nolog" and len(words) == 2:
            raise ValueError(f"unit {words[1]} has no log lines, so its panic scan proves nothing")
        elif words[0] == "panic" and len(words) == 3:
            panics.append(f"{words[1]}: {words[2]}")
        elif words[0] == "uploads" and len(words) >= 2 and words[1].isdigit():
            uploads = int(words[1])
        elif line.strip():
            raise ValueError("unexpected line in the host sample")
    return HostReport(edges, restarts, tuple(panics), uploads, pids)


def is_unreachable(error):
    """A host that cannot be reached, or that ran out of time, counts as silent; any other failure is real."""
    if isinstance(error, RemoteConnectionError) or error.exit_code in ROOT_LIMIT_EXIT_CODES:
        return True
    return error.exit_code is None and "timed out" in str(error)


def read_edges(ctx, targets):
    """One quick pass from one host; None for an edge that gave no usable answer, or for all if the host is silent."""
    heights = {target.name: None for target in targets}
    try:
        output = ctx.remote.run_script(EDGE_READER_HOST, edge_script(targets), EDGE_PASS_TIMEOUT_SECONDS)
    except RemoteError as error:
        if not is_unreachable(error):
            raise
        return heights
    heights.update(parse_host_report(output).edges)
    return heights


def read_units(ctx, host, units, upload_unit):
    output = ctx.remote.run_root_text(host, ["/usr/bin/bash", "-s"], SAMPLE_TIMEOUT_SECONDS,
                                      stdin_text=unit_script(units, upload_unit))
    return parse_host_report(output)


def read_chain_sample(ctx: DeployContext, coordinator_edge_count) -> ChainSample:
    """One sample: the edges first, in one pass, then the slow unit pass per host."""
    edges = read_edges(ctx, edge_targets(read_topology(ctx), coordinator_edge_count))
    plan = {host: (units, None) for host, units in core_units(ctx, coordinator_edge_count).items()}
    workers = worker_units(ctx)
    plan[WORKER_HOST] = (workers, workers[0])
    restarts, pids, panics, uploads = {}, {}, [], -1
    for host, (units, upload_unit) in plan.items():
        try:
            report = read_units(ctx, host, units, upload_unit)
        except RemoteError as error:
            if not is_unreachable(error):
                raise
            continue
        restarts.update(report.restarts)
        pids.update(report.pids)
        panics += report.panics
        uploads = max(uploads, report.uploads)
    return ChainSample(edges, restarts, tuple(panics), uploads, pids)
