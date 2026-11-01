#!/usr/bin/env python3
"""Step 68: install and start the SYSTEM (x1) and USER (x3) prove proxies through operator commands.

Neither host has passwordless sudo. apply stages the reviewed tool and package on one host, raises
OperatorPending with a fixed command that carries hashes only, and the operator runs it. The command writes a
report at a fixed path; a rerun of the same step validates it (lock hash, request digest, role, unit, binary
hash, live unit) and moves to the next host. A host that is validated is never staged or started again.
"""
import hashlib
import json
from pathlib import Path
import secrets
import shlex
from urllib.parse import urlsplit

import release_lock
from deploy_prepare_steps import PROXY_ROLES, check_tool_hash, file_sha256, read_state, require, write_state
from deploy_remote import OperatorPending, RemoteConnectionError, RemoteError, Step, wait_until

PROXY_HOSTS = {"system": "arc99x1", "user": "arc99x3"}
STATE_NAME = "start_proxies"
STAGE_ROOT = "/var/tmp"
STAGED_TOOL = "prepare_proxies.py"
STAGE_COPY_SECONDS = 3600
PYTHON = "/usr/bin/python3"
REPORT_LIMIT_BYTES = 65536
REPORT_FIELDS = {"lock_sha256", "request_sha256", "role", "unit", "pid", "binary_sha256"}
RPC_READY_SECONDS = 1800
RPC_POLL_SECONDS = 15
LOG_LINES = 30
CURL_MARKER = "PSY_PROXY_BODY_END"
WRONG_ROLE_METHODS = {"system": "psy_get_circuits_data", "user": "psy_prove_bridge_agg_groth16"}
METHOD_NOT_FOUND = -32601


def stage_dir(ctx, role):
    return f"{STAGE_ROOT}/psy-proxy-stage-{ctx.lock['release_id']}-{role}"


def report_path(ctx, role):
    state = Path(ctx.lock["paths"]["proxy"]["state"])
    return f"{state.parent}/{ctx.lock['release_id']}-{role}-activation.json"


def proxy_output(ctx):
    outputs = read_state(ctx, "prepare_packages")
    require("proxy" in outputs, "no recorded proxy package output; run prepare_packages first")
    return Path(outputs["proxy"])


def package_hash(ctx, role):
    package = proxy_output(ctx) / role
    require((package / "package.json").is_file(), f"{role} package not found")
    return package, file_sha256(package / "package.json")


def request_digest(ctx, role, nonce):
    package, package_sha256 = package_hash(ctx, role)
    text = json.dumps({"lock_sha256": ctx.lock_sha256, "role": role, "package_sha256": package_sha256,
                       "nonce": nonce}, sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()


def load_progress(ctx):
    path = ctx.state_dir / f"{STATE_NAME}.json"
    if not path.is_file():
        return {"lock_sha256": ctx.lock_sha256, "requests": {}, "validated": {}}
    progress = release_lock.read_document(path)
    require(progress.get("lock_sha256") == ctx.lock_sha256, "recorded proxy state belongs to another release lock")
    return progress


def operator_command(ctx, role, digest):
    stage = stage_dir(ctx, role)
    _, package_sha256 = package_hash(ctx, role)
    tool = f"{stage}/package/{STAGED_TOOL}"
    check = f"echo {shlex.quote(ctx.lock['tool_sha256'][STAGED_TOOL] + '  ' + tool)} | sha256sum -c -"
    return check + " && " + shlex.join(
        ["sudo", PYTHON, "-I", "-B", tool, "activate",
         "--release-lock", f"{stage}/release-lock.json", "--release-lock-sha256", ctx.lock_sha256,
         "--package", f"{stage}/package", "--package-sha256", package_sha256,
         "--request-sha256", digest, "--report-path", report_path(ctx, role)])


def stage_package(ctx, role):
    package, _ = package_hash(ctx, role)
    host, stage = PROXY_HOSTS[role], stage_dir(ctx, role)
    by_directory = {}
    for path in sorted(package.rglob("*")):
        if path.is_file():
            by_directory.setdefault(path.parent.relative_to(package).as_posix(), []).append(path)
    destinations = [f"{stage}/package" + ("" if name == "." else "/" + name) for name in by_directory]
    ctx.remote.run_script(host, "set -euo pipefail\numask 077\nrm -rf -- " + shlex.quote(stage) + "\nmkdir -p -- "
                          + " ".join(shlex.quote(path) for path in destinations) + "\n", 120)
    for name, files in by_directory.items():
        ctx.remote.copy_files(host, files, f"{stage}/package" + ("" if name == "." else "/" + name),
                              timeout_seconds=STAGE_COPY_SECONDS)
    ctx.remote.copy_files(host, [ctx.release_dir / "release-lock.json"], stage)


class ReportRejected(ValueError):
    """The activation report is unusable for this request; the operator command is shown again."""


def read_report(ctx, role):
    """Return the parsed report, or None when no report file exists. Any other failure propagates."""
    path = shlex.quote(report_path(ctx, role))
    text = ctx.remote.run_script(PROXY_HOSTS[role], "set -euo pipefail\nif test -e " + path + f"; then echo present; "
                                 f"head -c {REPORT_LIMIT_BYTES + 1} -- " + path + "; else echo missing; fi\n", 60)
    marker, _, body = text.partition("\n")
    if marker == "missing":
        return None
    if marker != "present" or len(body) > REPORT_LIMIT_BYTES:
        raise ReportRejected(f"{role}: activation report could not be read")
    try:
        return json.loads(body, object_pairs_hook=release_lock.unique_object)
    except ValueError:
        raise ReportRejected(f"{role}: activation report is not valid JSON") from None


def unit_state(ctx, role, unit):
    text = ctx.remote.run_script(PROXY_HOSTS[role], f"systemctl show {shlex.quote(unit)} "
                                 "--property=ActiveState,MainPID,NRestarts\n", 60)
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def installed_binary_sha256(ctx, role):
    path = f"{ctx.lock['paths']['proxy']['release']}-{role}/psy_user_cli"
    text = ctx.remote.run_script(PROXY_HOSTS[role], f"set -euo pipefail\nsha256sum -- {shlex.quote(path)}\n", 120)
    return text.split()[0] if text.split() else ""


def check_live(ctx, role, unit, pid, binary_sha256):
    """True problems of a started proxy as a message, or None when unit and installed binary match."""
    state = unit_state(ctx, role, unit)
    if state.get("ActiveState") != "active" or state.get("MainPID") != str(pid) or state.get("NRestarts") != "0":
        return f"{role}: unit is not active with the reported pid"
    if installed_binary_sha256(ctx, role) != binary_sha256:
        return f"{role}: installed binary differs from the lock"
    return None


def validate_report(ctx, role, document, digest):
    refuse = lambda message: ReportRejected(f"{role}: {message}")
    if not (isinstance(document, dict) and set(document) == REPORT_FIELDS):
        raise refuse("activation report fields differ")
    unit = ctx.lock["units"]["proxy_prefix"] + role + ".service"
    expected = {"lock_sha256": ctx.lock_sha256, "request_sha256": digest, "role": role, "unit": unit,
                "binary_sha256": ctx.lock["binaries"]["psy_user_cli"]}
    for name, value in expected.items():
        if document[name] != value:
            raise refuse(f"activation report {name} differs from this request")
    if type(document["pid"]) is not int or document["pid"] <= 0:
        raise refuse("activation report pid is invalid")
    problem = check_live(ctx, role, unit, document["pid"], document["binary_sha256"])
    if problem:
        raise ReportRejected(problem)
    return {"unit": unit, "pid": document["pid"], "binary_sha256": document["binary_sha256"]}


def listen_address(ctx, role):
    package, _ = package_hash(ctx, role)
    return release_lock.read_document(package / "rpc-endpoints.json")["placement"][role]["listen_addr"]


def start_check(ctx):
    check_tool_hash(ctx, STAGED_TOOL)
    require(ctx.lock["groth16"]["setup_manifest_sha256"], "groth16.setup_manifest_sha256 is not pinned in the lock")
    missing = ctx.remote.missing_aliases(PROXY_HOSTS.values())
    require(not missing, "proxy hosts missing from the access file: " + ", ".join(missing))
    for role in PROXY_ROLES:
        host = PROXY_HOSTS[role]
        require(host in ctx.lock["hosts"], f"{host} is not a host of the release")
        package, package_sha256 = package_hash(ctx, role)
        approval = release_lock.read_document(package / "package.json")
        require(approval["installer_sha256"] == ctx.lock["tool_sha256"][STAGED_TOOL],
                f"{role} package installer differs from the reviewed tool")
        require(urlsplit("//" + listen_address(ctx, role)).hostname == ctx.lock["hosts"][host],
                f"{role} placement listens on an address that is not {host}")


def settle_host(ctx, role, progress):
    """Validate a host's report, or stage and request it; raises OperatorPending until the report is valid."""
    request = progress["requests"].get(role)
    if request is None:
        stage_package(ctx, role)
        request = progress["requests"][role] = {"nonce": secrets.token_hex(32)}
        write_state(ctx, STATE_NAME, progress)
    digest = request_digest(ctx, role, request["nonce"])
    try:
        document = read_report(ctx, role)
        if document is not None:
            progress["validated"][role] = validate_report(ctx, role, document, digest)
            write_state(ctx, STATE_NAME, progress)
            return
    except ReportRejected as rejected:
        print(f"[deploy] activation report refused: {rejected}")
    raise OperatorPending(PROXY_HOSTS[role], operator_command(ctx, role, digest), report_path(ctx, role))


def recheck_validated(ctx, role, record):
    problem = check_live(ctx, role, record["unit"], record["pid"], record["binary_sha256"])
    require(problem is None, (problem or "") + "; nothing was restarted, inspect the host")


def start_apply(ctx):
    progress = load_progress(ctx)
    for role in PROXY_ROLES:
        if role in progress["validated"]:
            recheck_validated(ctx, role, progress["validated"][role])
        else:
            settle_host(ctx, role, progress)


def rpc_text(ctx, role, address, body, timeout):
    require(CURL_MARKER not in body, "request body collides with the here-document marker")
    script = (f"set -euo pipefail\ncurl -sS --max-time {timeout} -H 'content-type: application/json' "
              f"--data-binary @- {shlex.quote('http://' + address + '/')} <<'{CURL_MARKER}'\n{body}\n{CURL_MARKER}\n")
    return ctx.remote.run_script(PROXY_HOSTS[role], script, timeout + 60)


def rpc_call(ctx, role, address, body, timeout):
    text = rpc_text(ctx, role, address, body, timeout)
    try:
        return json.loads(text)
    except ValueError:
        raise ValueError(f"{role}: proxy answered with something other than JSON") from None


def rpc_body(method, params):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def log_panicked(ctx, role, unit):
    script = (f"journalctl -u {shlex.quote(unit)} -n {LOG_LINES} --no-pager -o cat 2>/dev/null "
              "| grep -qiE 'panicked|fatal' && echo panic || true\n")
    return ctx.remote.run_script(PROXY_HOSTS[role], script, 60).strip() == "panic"


def wait_for_role(ctx, role, address, unit):
    def is_ready():
        try:
            answer = rpc_call(ctx, role, address, rpc_body("psy_get_prove_proxy_role", []), 30)
        except RemoteConnectionError:
            raise
        except (RemoteError, ValueError):
            return False
        return "result" in answer

    def read_failure():
        state = unit_state(ctx, role, unit)
        if state.get("ActiveState") != "active" or state.get("NRestarts") != "0":
            return f"{role} proxy unit left the active state or restarted"
        if log_panicked(ctx, role, unit):
            return f"{role} proxy log shows a startup failure"
        return None
    wait_until(is_ready, read_failure, RPC_POLL_SECONDS, RPC_READY_SECONDS, f"{role} proxy RPC")


def check_role_answer(ctx, role, address):
    answered = rpc_call(ctx, role, address, rpc_body("psy_get_prove_proxy_role", []), 30).get("result")
    expected = {"role": role, "user_methods": role == "user", "system_methods": role == "system"}
    require(answered == expected, f"{role}: role answer differs from the expected role and capabilities")
    wrong = rpc_call(ctx, role, address, rpc_body(WRONG_ROLE_METHODS[role], []), 30)
    require(wrong.get("error", {}).get("code") == METHOD_NOT_FOUND, f"{role}: opposite-role method is served")


def start_verify(ctx):
    progress = load_progress(ctx)
    require(sorted(progress["validated"]) == sorted(PROXY_ROLES), "not every proxy host is validated")
    reports = {}
    for role in PROXY_ROLES:
        address, unit = listen_address(ctx, role), progress["validated"][role]["unit"]
        wait_for_role(ctx, role, address, unit)
        check_role_answer(ctx, role, address)
        reports[role] = {**progress["validated"][role], "role_answer": "ok",
                         "wrong_role_method_code": METHOD_NOT_FOUND}
    return {"proxies": reports}


PROXY_STEPS = {"start_proxies": Step("start_proxies", start_check, start_apply, start_verify, cutover=True)}
