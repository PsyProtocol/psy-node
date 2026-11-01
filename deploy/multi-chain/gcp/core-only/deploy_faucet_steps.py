#!/usr/bin/env python3
"""Step 76: install and start the Faucet on the operator host, issue one grant, then remove the Faucet fence.

The host has no passwordless sudo. apply stages the reviewed tool and package, raises OperatorPending with a fixed
command that carries hashes only, and the operator runs it. The command writes a report at a fixed path; a rerun
validates it (lock hash, request digest, unit, binary hash, live unit). A missing, stale or rejected report shows the
current command again. Once validated, the host is only checked, never staged or started again. The grant goes over
the private network; only after it passes is the Faucet maintenance route removed, and that is recorded so a rerun
does not open twice.
"""
import hashlib
import json
from pathlib import Path
import secrets
import shlex

import release_lock
from deploy_prepare_steps import (check_tool_hash, faucet_host, file_sha256, local_inputs, read_state, require,
                                  write_state)
from deploy_remote import OperatorPending, RemoteConnectionError, RemoteError, Step, wait_until

STATE_NAME = "start_faucet"
STAGE_ROOT = "/var/tmp"
STAGED_TOOL = "prepare_faucet.py"
STAGE_COPY_SECONDS = 3600
PYTHON = "/usr/bin/python3"
REPORT_LIMIT_BYTES = 65536
REPORT_FIELDS = {"lock_sha256", "request_sha256", "unit", "pid", "binary_sha256", "operators_sha256"}
# The first start builds the SD-key circuit (about 60 s at 4 threads); one proof then takes about 48 s.
READY_SECONDS = 900
READY_POLL_SECONDS = 15
GRANT_SECONDS = 900
CURL_MARKER = "PSY_FAUCET_BODY_END"
# A Genesis validator of the pinned topology; it is never one of the 100 operators.
DEFAULT_GRANT_RECIPIENT = 262144
LIVE_STATES = ("active", "activating")
INCLUSION_SECONDS = 240
GRANT_FIELDS = {"tx_hash", "operator_user_id", "amount", "checkpoint_id", "window_id", "already_submitted"}


def stage_dir(ctx):
    return f"{STAGE_ROOT}/psy-faucet-stage-{ctx.lock['release_id']}"


def report_path(ctx):
    state = Path(ctx.lock["paths"]["faucet"]["state"])
    return f"{state.parent}/{ctx.lock['release_id']}-faucet-activation.json"


def package_dir(ctx):
    outputs = read_state(ctx, "prepare_packages")
    require("faucet" in outputs, "no recorded faucet package output; run prepare_packages first")
    package = Path(outputs["faucet"])
    require((package / "manifest.json").is_file(), "faucet package not found")
    return package


def package_hash(ctx):
    return file_sha256(package_dir(ctx) / "manifest.json")


def request_digest(ctx, nonce):
    text = json.dumps({"lock_sha256": ctx.lock_sha256, "package_sha256": package_hash(ctx), "nonce": nonce},
                      sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()


def load_progress(ctx):
    path = ctx.state_dir / f"{STATE_NAME}.json"
    if not path.is_file():
        return {"lock_sha256": ctx.lock_sha256, "request": None, "validated": None, "grant": None,
                "inclusion": None, "fence_removed": None}
    progress = release_lock.read_document(path)
    require(progress.get("lock_sha256") == ctx.lock_sha256, "recorded faucet state belongs to another release lock")
    return progress


def operator_command(ctx, digest):
    stage = stage_dir(ctx)
    tool = f"{stage}/package/{STAGED_TOOL}"
    check = f"echo {shlex.quote(ctx.lock['tool_sha256'][STAGED_TOOL] + '  ' + tool)} | sha256sum -c -"
    return check + " && " + shlex.join(
        ["sudo", PYTHON, "-I", "-B", tool, "activate",
         "--release-lock", f"{stage}/release-lock.json", "--release-lock-sha256", ctx.lock_sha256,
         "--package", f"{stage}/package", "--package-sha256", package_hash(ctx),
         "--request-sha256", digest, "--report-path", report_path(ctx)])


def stage_package(ctx):
    package, host, stage = package_dir(ctx), faucet_host(ctx), stage_dir(ctx)
    ctx.remote.run_script(host, "set -euo pipefail\numask 077\nrm -rf -- " + shlex.quote(stage) + "\nmkdir -p -- "
                          + shlex.quote(stage + "/package") + "\n", 120)
    ctx.remote.copy_files(host, sorted(path for path in package.iterdir() if path.is_file()), stage + "/package",
                          timeout_seconds=STAGE_COPY_SECONDS)
    ctx.remote.copy_files(host, [ctx.release_dir / "release-lock.json"], stage)


class ReportRejected(ValueError):
    """The activation report is unusable for this request; the operator command is shown again."""


def read_report(ctx):
    """Return the parsed report, or None when no report file exists. Any other failure propagates."""
    path = shlex.quote(report_path(ctx))
    text = ctx.remote.run_script(faucet_host(ctx), "set -euo pipefail\nif test -e " + path + "; then echo present; "
                                 f"head -c {REPORT_LIMIT_BYTES + 1} -- " + path + "; else echo missing; fi\n", 60)
    marker, _, body = text.partition("\n")
    if marker == "missing":
        return None
    if marker != "present" or len(body) > REPORT_LIMIT_BYTES:
        raise ReportRejected("activation report could not be read")
    try:
        return json.loads(body, object_pairs_hook=release_lock.unique_object)
    except ValueError:
        raise ReportRejected("activation report is not valid JSON") from None


def unit_state(ctx):
    text = ctx.remote.run_script(faucet_host(ctx), f"systemctl show {shlex.quote(ctx.lock['units']['faucet'])} "
                                 "--property=ActiveState,MainPID,NRestarts\n", 60)
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def installed_binary_sha256(ctx):
    path = f"{ctx.lock['paths']['faucet']['release']}/psy_user_cli"
    text = ctx.remote.run_script(faucet_host(ctx), f"set -euo pipefail\nsha256sum -- {shlex.quote(path)}\n", 120)
    return text.split()[0] if text.split() else ""


def check_live(ctx, binary_sha256):
    """A message when the unit is down or the installed binary differs, or None. A restart in progress is fine."""
    if unit_state(ctx).get("ActiveState") not in LIVE_STATES:
        return "faucet unit is not running"
    if installed_binary_sha256(ctx) != binary_sha256:
        return "installed faucet binary differs from the lock"
    return None


def validate_report(ctx, document, digest):
    if not (isinstance(document, dict) and set(document) == REPORT_FIELDS):
        raise ReportRejected("activation report fields differ")
    expected = {"lock_sha256": ctx.lock_sha256, "request_sha256": digest, "unit": ctx.lock["units"]["faucet"],
                "binary_sha256": ctx.lock["binaries"]["psy_user_cli"],
                "operators_sha256": ctx.lock["faucet"]["operators_sha256"]}
    for name, value in expected.items():
        if document[name] != value:
            raise ReportRejected(f"activation report {name} differs from this request")
    if type(document["pid"]) is not int or document["pid"] <= 0:
        raise ReportRejected("activation report pid is invalid")
    problem = check_live(ctx, document["binary_sha256"])
    if problem:
        raise ReportRejected(problem)
    return {"unit": document["unit"], "pid": document["pid"], "binary_sha256": document["binary_sha256"]}


def package_spec(ctx):
    return release_lock.read_document(package_dir(ctx) / "host.json")


def listen_address(ctx):
    return package_spec(ctx)["listen_addr"]


def local_operator_ids(ctx):
    path = package_dir(ctx) / "operators.json"
    require(file_sha256(path) == ctx.lock["faucet"]["operators_sha256"], "package operator set differs from the lock")
    return sorted(int(row["userId"]) for row in json.loads(path.read_bytes())["operators"])


def grant_recipient(ctx):
    group = local_inputs(ctx).get("faucet_grant", {})
    recipient = group.get("recipient_user_id", DEFAULT_GRANT_RECIPIENT)
    require(type(recipient) is int and recipient >= 0, "local-inputs.json faucet_grant.recipient_user_id must be a user id")
    require(recipient not in local_operator_ids(ctx), "the grant recipient must not be a faucet operator")
    return recipient


def ingress_module():
    import deploy_ingress_steps
    return deploy_ingress_steps


def start_check(ctx):
    check_tool_hash(ctx, STAGED_TOOL)
    host = faucet_host(ctx)
    require(ctx.lock["faucet"]["operators_sha256"], "faucet.operators_sha256 is not pinned in the lock")
    missing = ctx.remote.missing_aliases([host])
    require(not missing and host in ctx.lock["hosts"], f"faucet host {host} is missing from the access file or the lock")
    recorded = release_lock.read_document(package_dir(ctx) / "manifest.json")
    require(recorded["release_lock_sha256"] == ctx.lock_sha256, "faucet package belongs to another release lock")
    require(recorded["files"]["prepare_faucet.py"] == ctx.lock["tool_sha256"][STAGED_TOOL],
            "faucet package installer differs from the reviewed tool")
    require(listen_address(ctx) == f"{ctx.lock['hosts'][host]}:{ctx.lock['faucet']['listen_port']}",
            "faucet package listens on an address that is not the faucet host")
    grant_recipient(ctx)
    ingress_module()


def settle_host(ctx, progress):
    """Validate the host's report, or stage and request it; raises OperatorPending until the report is valid."""
    if progress["request"] is None:
        stage_package(ctx)
        progress["request"] = {"nonce": secrets.token_hex(32)}
        write_state(ctx, STATE_NAME, progress)
    digest = request_digest(ctx, progress["request"]["nonce"])
    try:
        document = read_report(ctx)
        if document is not None:
            progress["validated"] = validate_report(ctx, document, digest)
            write_state(ctx, STATE_NAME, progress)
            return
    except ReportRejected as rejected:
        print(f"[deploy] activation report refused: {rejected}")
    raise OperatorPending(faucet_host(ctx), operator_command(ctx, digest), report_path(ctx))


def rpc_call(ctx, body, timeout):
    require(CURL_MARKER not in body, "request body collides with the here-document marker")
    script = (f"set -euo pipefail\ncurl -sS --max-time {timeout} -H 'content-type: application/json' "
              f"--data-binary @- {shlex.quote('http://' + listen_address(ctx) + '/')} <<'{CURL_MARKER}'\n{body}\n"
              f"{CURL_MARKER}\n")
    text = ctx.remote.run_script(faucet_host(ctx), script, timeout + 60)
    try:
        return json.loads(text)
    except ValueError:
        raise ValueError("faucet answered with something other than JSON") from None


def rpc_body(method, params):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def wait_for_faucet(ctx):
    def is_ready():
        try:
            answer = rpc_call(ctx, rpc_body("psy_get_psy_faucet_config", []), 30)
        except RemoteConnectionError:
            raise
        except (RemoteError, ValueError):
            return False
        return "result" in answer

    def read_failure():
        # activating is a restart in progress; the unit's start limit turns a loop into failed.
        if unit_state(ctx).get("ActiveState") not in LIVE_STATES:
            return "faucet unit failed or stopped"
        return None
    wait_until(is_ready, read_failure, READY_POLL_SECONDS, READY_SECONDS, "faucet RPC")


def check_public_config(ctx):
    config = rpc_call(ctx, rpc_body("psy_get_psy_faucet_config", []), 30).get("result")
    require(isinstance(config, dict) and config.get("enabled") is True, "faucet reports itself disabled")
    ids = local_operator_ids(ctx)
    require(sorted(config.get("operator_user_ids", [])) == ids and len(ids) == 100,
            "faucet operator set differs from the Genesis operators")
    return ids


def issue_grant(ctx, progress):
    if progress["grant"] is not None:
        return
    ids = check_public_config(ctx)
    recipient = grant_recipient(ctx)
    answer = rpc_call(ctx, rpc_body("psy_claim_faucet", [{"recipient_user_id": recipient}]), GRANT_SECONDS)
    result = answer.get("result")
    require("error" not in answer and isinstance(result, dict) and set(result) == GRANT_FIELDS
            and result["operator_user_id"] in ids and isinstance(result["tx_hash"], str) and result["tx_hash"],
            "the faucet did not authorize the grant")
    progress["grant"] = {"count": 1, "recipient_user_id": recipient, "operator_user_id": result["operator_user_id"],
                         "checkpoint_id": result["checkpoint_id"], "tx_hash": result["tx_hash"]}
    write_state(ctx, STATE_NAME, progress)


def confirm_inclusion(ctx, progress):
    """The grant response only means the End Cap was uploaded; wait until the chain includes it. Never reclaims."""
    if progress.get("inclusion") is not None:
        return
    grant = progress["grant"]
    release = ctx.lock["paths"]["faucet"]["release"]
    command = shlex.join(
        ["env", "-i", "PATH=/usr/bin:/bin", "HOME=/tmp", "PSY_NETWORK=testnet",
         f"PSY_CONFIG_PATH={release}/canonical.json", f"{release}/psy_user_cli", "tx", "get-status",
         "--rpc-config", f"{release}/rpc.json", "--start-checkpoint-id", str(grant["checkpoint_id"]),
         "--user-id", str(grant["operator_user_id"]), "--end-user-leaf-hash", grant["tx_hash"]])
    ctx.remote.run_script(faucet_host(ctx), "set -euo pipefail\n" + command + " >/dev/null\n", INCLUSION_SECONDS)
    progress["inclusion"] = {"confirmed": True, "start_checkpoint_id": grant["checkpoint_id"]}
    write_state(ctx, STATE_NAME, progress)


def remove_fence(ctx, progress):
    """Open the Faucet route after the grant passed; a recorded removal is never repeated."""
    if progress["fence_removed"] is not None:
        return
    require(progress["grant"] is not None and progress.get("inclusion") is not None,
            "the Faucet fence stays until one grant is included on chain")
    opened = ingress_module().open_faucet(ctx)
    progress["fence_removed"] = {"faucet_host_count": opened["faucet_host_count"]}
    write_state(ctx, STATE_NAME, progress)


def start_apply(ctx):
    progress = load_progress(ctx)
    if progress["validated"] is None:
        settle_host(ctx, progress)
    else:
        problem = check_live(ctx, progress["validated"]["binary_sha256"])
        require(problem is None, (problem or "") + "; nothing was restarted, inspect the host")
    wait_for_faucet(ctx)
    issue_grant(ctx, progress)
    confirm_inclusion(ctx, progress)
    remove_fence(ctx, progress)


def start_verify(ctx):
    progress = load_progress(ctx)
    grant, validated = progress["grant"], progress["validated"]
    require(validated is not None, "the faucet host is not validated")
    require(isinstance(grant, dict) and grant.get("count") == 1 and grant.get("tx_hash"),
            "exactly one authorized grant is required")
    require(progress.get("inclusion") is not None, "the grant is not confirmed on chain")
    require(progress["fence_removed"] is not None, "the Faucet fence is still in place")
    wait_for_faucet(ctx)
    ids = check_public_config(ctx)
    require(grant["operator_user_id"] in ids, "the grant came from an operator outside the set")
    problem = check_live(ctx, validated["binary_sha256"])
    require(problem is None, problem or "")
    return {"faucet": {**validated, "operator_count": len(ids), "grant": grant, "inclusion": progress["inclusion"],
                       "fence": progress["fence_removed"]}}


FAUCET_STEPS = {"start_faucet": Step("start_faucet", start_check, start_apply, start_verify, cutover=True)}
