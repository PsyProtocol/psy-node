#!/usr/bin/env python3
"""Ingress deploy steps: fence and open the public routes through the Caddy maintenance tool."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

import caddy_ingress
from deploy_remote import DeployContext, RemoteError, Step, wait_until


HERE = Path(__file__).resolve().parent
CADDY_HOST = "gcp-nostr"
GATEWAY_HOST = "gcp-gateway"
CADDY_TOOL = "caddy_ingress.py"
FORWARDER_TOOL = "prepare_bridge_forwarders.py"
STAGE_ROOT = "/opt/nostr-relay/caddy_config"
FORWARDER_TOPOLOGY = "/usr/local/lib/psy-bridge-private/topology.json"
FORWARDER_ROUTE_COUNT = 11
PROXY_HOSTS = {"system": "arc99x1", "user": "arc99x3"}
STDIN_PYTHON = ["/usr/bin/python3", "-I", "-B", "/dev/stdin"]
TOOL_TIMEOUT_SECONDS = 300
FORWARDER_TIMEOUT_SECONDS = 120
PROBE_TIMEOUT_SECONDS = 15
PROBE_READ_BYTES = 65536
OPEN_WAIT_SECONDS = 120
POLL_SECONDS = 5
RPC_HOST_PREFIXES = ("coordinator", "realm")
RPC_REQUEST = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "psy_get_latest_checkpoint_id", "params": []}).encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_tool_source(ctx, name):
    raw = (HERE / name).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ctx.lock["tool_sha256"][name], f"tool hash differs: {name}")
    return raw.decode()


def get_ingress(ctx):
    ingress = ctx.lock["ingress"]
    require(CADDY_HOST in ctx.lock["hosts"] and GATEWAY_HOST in ctx.lock["hosts"], "Caddy and gateway hosts must be in the lock")
    return ingress


def require_passwordless(ctx, host):
    require(ctx.remote.sudo_mode(host) == "passwordless", f"{host} needs no-prompt sudo for the ingress tools")


def get_lock_arguments(ctx):
    raw = (ctx.release_dir / "release-lock.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ctx.lock_sha256, "release lock file differs from the loaded lock")
    return ["--release-lock-base64", base64.b64encode(raw).decode(), "--release-lock-sha256", ctx.lock_sha256]


def run_caddy_tool(ctx, arguments):
    argv = [*STDIN_PYTHON, *get_lock_arguments(ctx), *arguments]
    output = ctx.remote.run_root_text(CADDY_HOST, argv, TOOL_TIMEOUT_SECONDS, stdin_text=read_tool_source(ctx, CADDY_TOOL),
                                      show_stderr=True)
    try:
        report = json.loads(output)
    except ValueError:
        report = None
    require(isinstance(report, dict), "Caddy tool did not print a JSON object")
    return report


def read_last_candidate_sha256(ctx):
    documents = [json.loads(path.read_text()) for path in sorted(ctx.state_dir.glob("ingress-*.json"))]
    return max(documents, key=lambda document: document["sequence"])["candidate_sha256"] if documents else None


def require_unedited_since_last_phase(ctx, report):
    last = read_last_candidate_sha256(ctx) if report["phase"] != "fence" and ctx.state_dir.is_dir() else None
    require(last is None or report["files"]["original.Caddyfile"] == last,
            "Caddyfile changed since the last ingress phase was applied")


def preview_phase(ctx, phase):
    """Read-only render and native adaptation of one phase; reports whether the Caddyfile would change."""
    report = run_caddy_tool(ctx, ["stage", "--phase", phase])
    require(report.get("phase") == phase and isinstance(report.get("is_unchanged"), bool), "Caddy preview report is malformed")
    require_unedited_since_last_phase(ctx, report)
    return report


def write_state(ctx, phase, document):
    ctx.state_dir.mkdir(parents=True, exist_ok=True)
    document = dict(document, sequence=time.time_ns())
    (ctx.state_dir / f"ingress-{phase}.json").write_text(json.dumps(document, sort_keys=True) + "\n")


def change_ingress(ctx, phase):
    """Stage, check and apply one phase; a rerun that finds the phase in place changes nothing."""
    stage_dir = f"{STAGE_ROOT}/{phase}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    staged = run_caddy_tool(ctx, ["stage", "--phase", phase, "--output", stage_dir])
    require(isinstance(staged.get("report_sha256"), str), "Caddy stage report has no hash")
    require_unedited_since_last_phase(ctx, staged)
    applied = run_caddy_tool(ctx, ["check", "--stage", stage_dir, "--report-sha256", staged["report_sha256"], "--apply"])
    require(applied.get("result") in ("APPLIED", "ALREADY_IN_STATE"), f"Caddy {phase} was not applied")
    write_state(ctx, phase, {"phase": phase, "result": applied["result"], "stage": stage_dir,
                             "candidate_sha256": staged["files"]["candidate.Caddyfile"]})
    return applied


def fetch_response(host, is_rpc):
    request = urllib.request.Request(
        f"https://{host}/", data=RPC_REQUEST if is_rpc else None, method="POST" if is_rpc else "GET",
        headers={"Content-Type": "application/json", "User-Agent": "psy-deploy-verify"})
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT_SECONDS) as response:
            return response.status, response.read(PROBE_READ_BYTES).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read(PROBE_READ_BYTES).decode("utf-8", errors="replace")


def probe(host):
    try:
        return fetch_response(host, host.startswith(RPC_HOST_PREFIXES))
    except (OSError, http.client.HTTPException):
        return None


def is_fenced(host):
    response = probe(host)
    return response is not None and response[0] == 503 and caddy_ingress.BODY in response[1]


def is_serving(host):
    response = probe(host)
    if response is None or response[0] >= 500 or caddy_ingress.BODY in response[1]:
        return False
    if not host.startswith(RPC_HOST_PREFIXES):
        return True
    try:
        return type(json.loads(response[1]).get("result")) is int
    except (ValueError, AttributeError):
        return False


def require_fenced(hosts):
    unfenced = [host for host in hosts if not is_fenced(host)]
    require(not unfenced, f"hosts do not return the maintenance 503: {', '.join(unfenced)}")


def wait_until_serving(hosts):
    for host in hosts:
        wait_until(lambda: is_serving(host), lambda: None, POLL_SECONDS, OPEN_WAIT_SECONDS, f"public route {host}")


def require_phase_in_place(ctx, phase):
    require(preview_phase(ctx, phase)["is_unchanged"], f"Caddyfile is not in the {phase} state")


def check_phase(ctx, phase):
    get_ingress(ctx)
    require_passwordless(ctx, CADDY_HOST)
    preview_phase(ctx, phase)


def get_expected_forwarder_routes(ctx):
    raw = (ctx.release_dir / "topology.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ctx.lock["inputs"]["topology"], "release topology differs from the lock")
    topology = json.loads(raw)
    hosts = topology["hosts"]
    edges = {"coordinator": hosts[topology["coordinator"]["host"]]}
    for realm in topology["realms"]:
        edge_hosts = {validator["edge_host"] for validator in realm["validators"]}
        require(len(edge_hosts) == 1, f"realm {realm['id']} validators use more than one edge host")
        edges[f"realm{realm['id']}"] = hosts[edge_hosts.pop()]
    return edges, {role: ctx.lock["hosts"][alias] for role, alias in PROXY_HOSTS.items()}


def check_forwarders(ctx):
    """Run the read-only gateway check: eleven retained forwarders with live sockets and answering backends.

    The topology the forwarders were installed from is pinned by the lock and must name the release backends.
    """
    require_passwordless(ctx, GATEWAY_HOST)
    argv = [*STDIN_PYTHON, "check-backends", "--topology", FORWARDER_TOPOLOGY,
            "--topology-sha256", ctx.lock["ingress"]["forwarder_topology_sha256"]]
    output = ctx.remote.run_root_text(GATEWAY_HOST, argv, FORWARDER_TIMEOUT_SECONDS,
                                      stdin_text=read_tool_source(ctx, FORWARDER_TOOL), show_stderr=True)
    try:
        report = json.loads(output.splitlines()[0])
        units, backends = report["units"], report["backends"]
        edges, proxies = report["edges"], report["proxies"]
    except (IndexError, KeyError, ValueError):
        raise RemoteError(f"{GATEWAY_HOST}: forwarder check printed no report", host=GATEWAY_HOST) from None
    require(len(units) == len(backends) == FORWARDER_ROUTE_COUNT
            and all(unit.get("socket_active") is True and unit.get("service_failed") is False for unit in units)
            and all(backend.get("ready") is True for backend in backends),
            f"forwarder check did not report {FORWARDER_ROUTE_COUNT} live sockets with ready backends")
    expected_edges, expected_proxies = get_expected_forwarder_routes(ctx)
    require(edges == expected_edges and proxies == expected_proxies, "forwarder backends differ from the release topology")
    return len(backends)


def apply_fence(ctx):
    change_ingress(ctx, "fence")


def verify_fence(ctx):
    ingress = get_ingress(ctx)
    require_phase_in_place(ctx, "fence")
    hosts = ingress["fenced_hosts"] + ingress["faucet_hosts"]
    require_fenced(hosts)
    return {"fenced_host_count": len(hosts)}


def check_open(ctx):
    check_phase(ctx, "open")
    check_forwarders(ctx)


def apply_open(ctx):
    change_ingress(ctx, "open")


def verify_open(ctx):
    ingress = get_ingress(ctx)
    require_phase_in_place(ctx, "open")
    wait_until_serving(ingress["fenced_hosts"])
    if preview_phase(ctx, "open-faucet")["is_unchanged"]:
        wait_until_serving(ingress["faucet_hosts"])
    else:
        require_fenced(ingress["faucet_hosts"])
    return {"opened_host_count": len(ingress["fenced_hosts"]), "faucet_host_count": len(ingress["faucet_hosts"]),
            "forwarder_route_count": check_forwarders(ctx)}


def open_faucet(ctx: DeployContext) -> dict:
    """Remove only the Faucet maintenance routes, then wait until each Faucet host serves.

    The caller starts the Faucet and checks its readiness first; this function does not.
    Returns {"faucet_host_count": int}.
    """
    ingress = get_ingress(ctx)
    require_passwordless(ctx, CADDY_HOST)
    change_ingress(ctx, "open-faucet")
    require_phase_in_place(ctx, "open-faucet")
    wait_until_serving(ingress["faucet_hosts"])
    return {"faucet_host_count": len(ingress["faucet_hosts"])}


INGRESS_STEPS = {
    "fence_ingress": Step("fence_ingress", lambda ctx: check_phase(ctx, "fence"), apply_fence, verify_fence, cutover=True),
    "open_ingress": Step("open_ingress", check_open, apply_open, verify_open, cutover=True),
}
