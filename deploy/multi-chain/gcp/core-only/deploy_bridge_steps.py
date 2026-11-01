#!/usr/bin/env python3
"""Cutover steps 69, 71 and 74: deploy the three L1 chains, start the Guardians, start the Relayer.

An L1 transaction is real and permanent, so resume never broadcasts again. fresh_l1.py runs on the signer host and
keeps one directory per attempt; this module only decides, from that directory, what may still run. A chain that is
completed is verified and skipped. A chain with any other trace of work blocks the step: a person reviews it and
creates the next attempt. Guardians and the Relayer are installed once; a unit that is already enabled and running is
verified and left alone.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import tarfile

import fresh_l1
import release_lock
import deploy_prepare_steps as prepare
from deploy_remote import RemoteConnectionError, RemoteError, Step, wait_until

PYTHON = "/usr/bin/python3"
BUNDLES_ROOT = "/opt/psy-l1-bundles"
NODE_PATH = "/opt/psy-l1-bundles/node-v22.23.4"
NODE_MIN_MAJOR = 18
STAGE_ROOT = "/var/tmp"
CHAIN_ORDER = release_lock.CHAINS
FALLBACK_NAMES = tuple(f"{row[3]}_RPC_FALLBACK_URL" for row in fresh_l1.NETWORKS.values())
WALLET_NAME = "WALLET_" + "PASSWORD"
UPLOAD_SECONDS = 3600
SHORT_SECONDS = 120
CHECK_SECONDS = 1800
ESTIMATE_SECONDS = 300
DEPLOY_SECONDS = 3600
INSTALL_SECONDS = 600
SETTLEMENT_SECONDS = 3600
READY_SECONDS = 300
PROBE_SECONDS = 60
POLL_SECONDS = 30
HEX_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
HEX_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
DOCUMENT_NAMES = {"summary": "deployed-contracts.json", "receipt": "Bridge_Proxy.json"}
HASH_ZERO = "0x" + "0" * 64
VERIFIER_NAMES = ("ZKVerifier", "DepositBatchVerifier", "WithdrawalClaimVerifier", "RewardClaimVerifier")
PUSDT_L2_ID = "0x" + "0" * 63 + "4"
LAST_FINALIZED_SELECTOR = "0x3590a6a3"
UNIT_PROPERTIES = "LoadState,ActiveState,UnitFileState,MainPID,NRestarts"
GUARDIAN_TOOLS = ("install_guardian.py", "guardian_exec.py", "activate_bridge.py", "install_relayer.py")
RELAYER_TOOLS = ("install_relayer.py", "relayer_exec.py", "install_guardian.py", "activate_bridge.py")


class AttemptBlocked(ValueError):
    """The signer host holds an attempt that must be reviewed by a person; nothing may broadcast."""


def lock_hash(ctx):
    return ctx.lock_sha256


def signer_host(ctx):
    return ctx.lock["l1"]["signer_host"]


def quote(value):
    return shlex.quote(str(value))


def bundle_name(ctx):
    return f"{ctx.lock['release_id']}-{ctx.lock['l1']['bundle_sha256'][:12]}"


def bundle_dir(ctx):
    return f"{BUNDLES_ROOT}/{bundle_name(ctx)}"


def inputs_dir(ctx):
    return f"{BUNDLES_ROOT}/{bundle_name(ctx)}-inputs"


def attempt_dir(ctx, number):
    return f"{ctx.lock['l1']['output_root']}/attempt-{number}"


def tool_source(ctx):
    raw = (prepare.TOOLS_DIR / "fresh_l1.py").read_bytes()
    prepare.require(hashlib.sha256(raw).hexdigest() == ctx.lock["tool_sha256"]["fresh_l1.py"],
                    "tool hash differs: fresh_l1.py")
    return raw.decode()


def run_tool(ctx, arguments, timeout):
    """Run the lock-pinned fresh_l1.py as root on the signer host; its source travels on stdin."""
    output = ctx.remote.run_root_text(signer_host(ctx), [PYTHON, "-I", "-B", "/dev/stdin", *arguments], timeout,
                                      stdin_text=tool_source(ctx), show_stderr=True)
    try:
        return json.loads(output, object_pairs_hook=release_lock.unique_object)
    except ValueError:
        raise ValueError("fresh_l1 printed no JSON document") from None


def run_root_script(ctx, host, script, timeout=SHORT_SECONDS):
    return ctx.remote.run_root_text(host, ["/usr/bin/bash", "-s"], timeout, stdin_text="set -euo pipefail\n" + script)


def chain_bundle_arguments(ctx):
    lock = ctx.lock
    return ["--bundle", bundle_dir(ctx), "--manifest-sha256", lock["l1"]["bundle_sha256"],
            "--contracts-commit", lock["sources"]["contracts"]]


def secret_flags():
    return [flag for path in (fresh_l1.WALLET_ENV, fresh_l1.FALLBACK_ENV) for flag in ("--secret-env", path)]


def local_bundle(ctx):
    manifest = prepare.local_path(ctx, "files", "l1_bundle_manifest")
    prepare.require(manifest.name == "manifest.json", "l1_bundle_manifest must be the manifest.json of the bundle")
    return manifest.parent


def local_policy(ctx):
    path = prepare.local_path(ctx, "files", "l1_policy")
    prepare.require(prepare.file_sha256(path) == ctx.lock["l1"]["policy_sha256"], "l1 policy hash differs from the lock")
    policy = release_lock.read_document(path)
    fresh_l1.validate_policy(policy)
    return path, policy


def check_static(ctx):
    """Everything that is decided by the lock and local files; no host is touched."""
    lock = ctx.lock
    for tool in ("fresh_l1.py", "fresh_l1.cjs"):
        prepare.check_tool_hash(ctx, tool)
    for label, value in (("l1.bundle_sha256", lock["l1"]["bundle_sha256"]), ("l1.policy_sha256", lock["l1"]["policy_sha256"]),
                         ("sources.contracts", lock["sources"]["contracts"])):
        prepare.require(value, f"{label} is not pinned in the lock")
    prepare.require(lock["l1"]["signer"].lower() == fresh_l1.SIGNER.lower(), "lock signer differs from the signer in fresh_l1")
    bundle = local_bundle(ctx)
    fresh_l1.verify_bundle(bundle, lock["l1"]["bundle_sha256"], lock["sources"]["contracts"])
    for tool in ("fresh_l1.py", "fresh_l1.cjs"):
        prepare.require(prepare.file_sha256(bundle / tool) == lock["tool_sha256"][tool], f"bundle copy of {tool} differs from the lock")
    local_policy(ctx)
    for chain in CHAIN_ORDER:
        budget, _ = prepare.gas_budget(ctx, chain)
        fresh_l1.validate_budget(budget, chain)


def env_probe_script():
    lines = []
    for path, names in ((fresh_l1.WALLET_ENV, (WALLET_NAME,)), (fresh_l1.FALLBACK_ENV, FALLBACK_NAMES)):
        lines.append(f"if test -f {quote(path)}; then echo \"file {path} $(stat -c '%U %a' -- {quote(path)})\"; else echo \"missing {path}\"; fi")
        for name in names:
            lines.append(f"echo \"name {path} {name} $(grep -c -E '^(export[[:space:]]+)?{name}=' -- {quote(path)} 2>/dev/null || true)\"")
    return "\n".join(lines) + "\n"


def check_signer_env(ctx):
    """Names and file modes only; a value is never read into this process."""
    output = run_root_script(ctx, signer_host(ctx), env_probe_script())
    files, counts = {}, {}
    for line in output.splitlines():
        fields = line.split()
        if fields[:1] == ["file"] and len(fields) == 4:
            files[fields[1]] = (fields[2], int(fields[3], 8))
        elif fields[:1] == ["name"] and len(fields) == 4 and fields[3].isdigit():
            counts[(fields[1], fields[2])] = int(fields[3])
    for path, names in ((fresh_l1.WALLET_ENV, (WALLET_NAME,)), (fresh_l1.FALLBACK_ENV, FALLBACK_NAMES)):
        prepare.require(path in files, f"protected env file missing on the signer host: {path}")
        owner, mode = files[path]
        prepare.require(owner == "root" and not mode & 0o027, f"protected env file must be root-owned and not group-writable: {path}")
        missing = ["wallet entry" if name == WALLET_NAME else name for name in names if counts.get((path, name)) != 1]
        prepare.require(not missing, f"{path} lacks exactly one entry for: {', '.join(missing)}")


def check_node(ctx):
    version = run_root_script(ctx, signer_host(ctx), f"{quote(NODE_PATH)} --version\n").strip()
    match = re.fullmatch(r"v(\d+)\.\d+\.\d+", version)
    prepare.require(match and int(match.group(1)) >= NODE_MIN_MAJOR, f"Node {NODE_MIN_MAJOR}+ required at {NODE_PATH}")


def remote_present(ctx, path):
    output = ctx.remote.run_script(signer_host(ctx), f"test -e {quote(path)} && echo present || echo absent\n", SHORT_SECONDS)
    return output.strip() == "present"


def pack_bundle(source, target):
    """A gzip tar of the bundle owned by root, with no group or other write bit; links stay links."""
    def normalise(info):
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mode &= ~0o022
        return info
    with tarfile.open(target, "w:gz", compresslevel=3) as archive:
        archive.add(source, arcname=".", filter=normalise)


def upload_bundle(ctx):
    host, final = signer_host(ctx), bundle_dir(ctx)
    partial, tarball = final + ".partial", f"{STAGE_ROOT}/{bundle_name(ctx)}.tar.gz"
    local = ctx.run_dir / f"{bundle_name(ctx)}.tar.gz"
    pack_bundle(local_bundle(ctx), local)
    try:
        ctx.remote.copy_files(host, [local], STAGE_ROOT + "/", timeout_seconds=UPLOAD_SECONDS)
    finally:
        local.unlink(missing_ok=True)
    run_root_script(ctx, host, f"rm -rf -- {quote(partial)}\numask 022\nmkdir -m 0755 -- {quote(partial)}\n"
                    f"tar -xzf {quote(tarball)} -C {quote(partial)} --no-same-owner\n", UPLOAD_SECONDS)
    try:
        verified = run_tool(ctx, ["check", "--bundle", partial, "--manifest-sha256", ctx.lock["l1"]["bundle_sha256"],
                                  "--contracts-commit", ctx.lock["sources"]["contracts"]], CHECK_SECONDS)
        prepare.require(verified.get("verified") is True, "uploaded bundle did not verify")
    except (ValueError, RemoteError):
        run_root_script(ctx, host, f"rm -rf -- {quote(partial)}\nrm -f -- {quote(tarball)}\n")
        raise
    run_root_script(ctx, host, f"mv -T -- {quote(partial)} {quote(final)}\nrm -f -- {quote(tarball)}\n")


def ensure_bundle(ctx):
    """The bundle directory is immutable: present means verify, absent means upload, verify, then publish."""
    if not remote_present(ctx, bundle_dir(ctx)):
        upload_bundle(ctx)
    verified = run_tool(ctx, ["check", *chain_bundle_arguments(ctx)], CHECK_SECONDS)
    prepare.require(verified.get("verified") is True, "staged bundle did not verify")


def input_files(ctx):
    policy, _ = local_policy(ctx)
    files = {"policy.json": policy}
    for chain in CHAIN_ORDER:
        files[f"gas-budget.{chain}.json"] = ctx.release_dir / f"fresh_l1_gas_budget.{chain}.json"
    return files


def ensure_inputs(ctx):
    """Policy and budgets are public JSON; the tool re-checks each against the hash it is given."""
    host = signer_host(ctx)
    stage = f"{STAGE_ROOT}/psy-l1-inputs-{bundle_name(ctx)}"
    files = input_files(ctx)
    ctx.remote.run_script(host, f"set -euo pipefail\nrm -rf -- {quote(stage)}\nmkdir -m 0700 -- {quote(stage)}\n", SHORT_SECONDS)
    for name, path in files.items():
        ctx.remote.copy_files(host, [path], f"{stage}/{name}")
    installs = "".join(f"install -m 0600 -o root -g root -- {quote(f'{stage}/{name}')} {quote(f'{inputs_dir(ctx)}/{name}')}\n"
                       for name in files)
    run_root_script(ctx, host, f"install -d -m 0700 -o root -g root -- {quote(inputs_dir(ctx))}\n{installs}"
                    f"rm -rf -- {quote(stage)}\n")


def ensure_output_root(ctx):
    root = ctx.lock["l1"]["output_root"]
    run_root_script(ctx, signer_host(ctx), f"install -d -m 0700 -o root -g root -- {quote(root)}\n")


def read_attempts(ctx):
    report = run_tool(ctx, ["attempts", "--root", ctx.lock["l1"]["output_root"],
                            "--manifest-sha256", ctx.lock["l1"]["bundle_sha256"]], SHORT_SECONDS)
    prepare.require(isinstance(report.get("attempts"), list) and isinstance(report.get("active_deploys"), int),
                    "attempt report has an unexpected shape")
    return report


def next_attempt_command(ctx, number):
    return (f"sudo {PYTHON} -I -B {bundle_dir(ctx)}/fresh_l1.py prepare {' '.join(chain_bundle_arguments(ctx))} "
            f"--output {attempt_dir(ctx, number)}")


def decide_attempt(ctx, report):
    """Return (attempt number, needs_prepare, chains still to deploy). Anything unclear refuses; nothing retries."""
    if report["active_deploys"]:
        raise AttemptBlocked("a fresh_l1 deploy is still running on the signer host; wait for it, then rerun this step")
    rows = report["attempts"]
    if not rows:
        return 1, True, list(CHAIN_ORDER)
    latest = rows[-1]
    number = latest["number"]
    refusal = (f"attempt {number} on the signer host needs review before anything else is broadcast. Review its stage "
               f"journal and receipts, then create the next attempt with: {next_attempt_command(ctx, number + 1)} "
               f"and rerun this step with --from 69")
    if not latest["prepared_for_bundle"]:
        raise AttemptBlocked(f"attempt {number} belongs to another bundle. " + refusal)
    states = [latest["networks"][chain] for chain in CHAIN_ORDER]
    policy = ctx.lock["l1"]["policy_sha256"]
    if any(row["state"] == "partial" or (row["state"] == "completed" and row["policy_sha256"] != policy) for row in states):
        raise AttemptBlocked(f"attempt {number} holds a partial or foreign deployment. " + refusal)
    kinds = [row["state"] for row in states]
    if "untouched" in kinds and "completed" in kinds[kinds.index("untouched"):]:
        raise AttemptBlocked(f"attempt {number} completed a chain out of order. " + refusal)
    return number, False, [chain for chain, row in zip(CHAIN_ORDER, states) if row["state"] == "untouched"]


def live_gates(ctx, chains):
    """Per remaining chain: balance, price cap, equal nonces, and a live creation-gas estimate inside the budget."""
    reports = prepare.read_l1_reports(ctx, signer_host(ctx))
    failures = []
    for chain in chains:
        prepare.check_chain(ctx, chain, reports[chain], failures)
        budget_file = f"{inputs_dir(ctx)}/gas-budget.{chain}.json"
        estimate = run_tool(ctx, ["estimate", *chain_bundle_arguments(ctx), "--network", chain, "--gas-budget", budget_file,
                                  "--gas-budget-sha256", ctx.lock["l1"]["gas_budget_sha256"][chain],
                                  "--rpc-preference", "protected-env-backup", *secret_flags()], ESTIMATE_SECONDS)
        budget, _ = prepare.gas_budget(ctx, chain)
        if not fresh_l1.stack_within_spend(budget, int(reports[chain]["gas_price_wei"])):
            failures.append(f"{chain}: whole-stack cost at the current gas price exceeds maxNativeSpendWei")
        if estimate.get("within_budget") is not True:
            failures.append(f"{chain}: creation gas estimate {estimate.get('required_with_margin')} exceeds the per-transaction "
                            f"budget {estimate.get('max_gas_per_transaction')}")
    prepare.require(not failures, "\n".join(failures))


def deploy_check(ctx):
    check_static(ctx)
    prepare.require(ctx.remote.sudo_mode(signer_host(ctx)) == "passwordless", "signer host needs no-prompt sudo")
    check_signer_env(ctx)
    check_node(ctx)
    ensure_bundle(ctx)
    ensure_inputs(ctx)
    ensure_output_root(ctx)
    _, _, remaining = decide_attempt(ctx, read_attempts(ctx))
    if remaining:
        live_gates(ctx, remaining)


def failure_report(ctx, number, chain, error):
    """After a failed or lost deploy call, re-read the host and say which of three things happened."""
    try:
        report = read_attempts(ctx)
        row = next(row for row in report["attempts"] if row["number"] == number)
        state, running = row["networks"][chain]["state"], report["active_deploys"]
    except (RemoteError, ValueError, StopIteration):
        state, running = "unknown", 0
    base = f"{chain}: deploy call failed ({error})"
    if running:
        return (f"{base}; the deploy is still running on the signer host (a lost connection does not stop it). "
                f"Wait for it to finish, then rerun this step with --from 69; do not create a new attempt")
    if state == "untouched":
        return f"{base}; nothing was written for {chain} in attempt {number}, so rerunning this step with --from 69 is safe"
    if state == "completed":
        return f"{base}; {chain} shows as completed in attempt {number}: rerun this step with --from 69 to verify and record it"
    return (f"{base}; attempt {number} is now partial and is never retried automatically; review it, then create the next "
            f"attempt with: {next_attempt_command(ctx, number + 1)} and rerun this step with --from 69")


def deploy_chain(ctx, number, chain):
    directory = attempt_dir(ctx, number)
    arguments = ["deploy", "--execute", *chain_bundle_arguments(ctx), "--output", directory, "--network", chain,
                 "--policy", f"{inputs_dir(ctx)}/policy.json", "--policy-sha256", ctx.lock["l1"]["policy_sha256"],
                 "--gas-budget", f"{inputs_dir(ctx)}/gas-budget.{chain}.json",
                 "--gas-budget-sha256", ctx.lock["l1"]["gas_budget_sha256"][chain], "--node", NODE_PATH,
                 "--rpc-preference", "protected-env-backup", *secret_flags()]
    try:
        done = run_tool(ctx, arguments, DEPLOY_SECONDS)
    except (RemoteError, ValueError) as error:
        raise RuntimeError(failure_report(ctx, number, chain, error)) from None
    prepare.require(done == {"network": chain, "completed": True}, f"{chain}: deploy reported an unexpected result")


def completed_attempt(ctx, number, chains):
    """Re-read the host: the attempt must now show every named chain as completed with this release's policy."""
    row = next((row for row in read_attempts(ctx)["attempts"] if row["number"] == number), None)
    prepare.require(row is not None, f"attempt {number} vanished from the signer host")
    for chain in chains:
        state = row["networks"][chain]
        prepare.require(state["state"] == "completed" and state["policy_sha256"] == ctx.lock["l1"]["policy_sha256"],
                        f"{chain}: not completed in attempt {number}")


def deploy_apply(ctx):
    report = read_attempts(ctx)
    number, needs_prepare, remaining = decide_attempt(ctx, report)
    if needs_prepare:
        run_tool(ctx, ["prepare", *chain_bundle_arguments(ctx), "--output", attempt_dir(ctx, number)], SHORT_SECONDS)
    for chain in remaining:
        deploy_chain(ctx, number, chain)
        completed_attempt(ctx, number, [chain])
    completed_attempt(ctx, number, CHAIN_ORDER)
    record_documents(ctx, number)


def validate_readback(readback, chain, policy, signer):
    """The tool asserted the chain; this re-reads the saved evidence so a hollow document cannot pass."""
    keys = {"signer", "proposer", "bridge_admin", "l1_acl_guardian", "deposits_paused", "withdrawal_registration_paused",
            "pending_claims_paused", "deposit_mapping", "tokens", "verifiers"}
    verifiers = readback.get("verifiers") if isinstance(readback, dict) else None
    prepare.require(isinstance(verifiers, dict) and set(verifiers) == set(VERIFIER_NAMES)
                    and all(HEX_ADDRESS.fullmatch(str(row.get("address"))) and re.fullmatch(r"[0-9a-f]{64}", str(row.get("code_sha256")))
                            for row in verifiers.values()), f"{chain}: verifier evidence missing or malformed")
    prepare.require(len({row["address"].lower() for row in verifiers.values()}) == len(VERIFIER_NAMES), f"{chain}: verifier addresses collide")
    prepare.require(isinstance(readback, dict) and set(readback) == keys, f"{chain}: readback fields differ")
    prepare.require(str(readback["signer"]).lower() == signer.lower() and readback["proposer"] is True
                    and readback["bridge_admin"] is True, f"{chain}: signer must be proposer and Bridge admin")
    prepare.require(readback["deposits_paused"] is True and readback["withdrawal_registration_paused"] is False
                    and readback["pending_claims_paused"] is False, f"{chain}: pause state differs from the policy")
    mapping = readback["deposit_mapping"]
    prepare.require(mapping.get("native_allowed") is False and set(mapping.get("tokens", {})) == {"PSY", "pUSDT"},
                    f"{chain}: Router token pairs differ")
    for name, expected_id in (("PSY", HASH_ZERO), ("pUSDT", PUSDT_L2_ID)):
        pair = mapping["tokens"][name]
        prepare.require(HEX_ADDRESS.fullmatch(str(pair.get("l1_address"))) and pair.get("l2_contract_id") == expected_id,
                        f"{chain}: Router pair for {name} differs")
    prepare.require(len({pair["l1_address"].lower() for pair in mapping["tokens"].values()}) == 2, f"{chain}: Router pairs collide")
    prepare.require(set(readback["tokens"]) == {"native", "PSY", "pUSDT"}, f"{chain}: token set differs")
    for name, row in readback["tokens"].items():
        prepare.require(row.get("global_flags") == 1 and row.get("token_flags") == 0 and row.get("effective_flags") == 1,
                        f"{chain}: {name} is not paused as the policy requires")
        prepare.require(row.get("config") == policy["networks"][chain][name], f"{chain}: {name} flow limits differ from the policy")


def validate_documents(chain, summary, receipt):
    identity = fresh_l1.NETWORKS[chain]
    bridge = summary["core"]["Bridge"]
    prepare.require(summary.get("network") == chain and str(summary.get("chainId")) == str(identity[0])
                    and summary["protocol"]["chain"]["l1ChainIndex"] == identity[1], f"{chain}: deployment identity differs")
    prepare.require(HEX_ADDRESS.fullmatch(bridge) and HEX_ADDRESS.fullmatch(summary["core"]["StateManager"])
                    and str(receipt.get("address")).lower() == bridge.lower(), f"{chain}: Bridge receipt does not match")
    inner = receipt["receipt"]
    prepare.require(inner.get("status") == 1 and type(inner.get("blockNumber")) is int and inner["blockNumber"] > 0
                    and HEX_HASH.fullmatch(str(receipt.get("transactionHash"))), f"{chain}: Bridge deployment did not succeed")


def fetch_remote_file(ctx, path):
    host = signer_host(ctx)
    text = ctx.remote.run_root_text(host, ["/usr/bin/cat", "--", path], SHORT_SECONDS)
    remote_sum = ctx.remote.run_root_text(host, ["/usr/bin/sha256sum", "--", path], SHORT_SECONDS).split()[0]
    raw = text.encode()
    prepare.require(hashlib.sha256(raw).hexdigest() == remote_sum, "downloaded L1 document differs from the host copy")
    return raw


def store_document(ctx, relative, raw):
    target = ctx.state_dir / "l1" / relative
    if target.exists():
        prepare.require(target.read_bytes() == raw, "a different L1 document is already recorded here; refusing to overwrite")
    else:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
    return {"path": str(target), "sha256": hashlib.sha256(raw).hexdigest()}


def record_documents(ctx, number):
    _, policy = local_policy(ctx)
    chains = {}
    for chain in CHAIN_ORDER:
        root = f"{attempt_dir(ctx, number)}"
        raws = {"summary": fetch_remote_file(ctx, f"{root}/deployments/{chain}/{DOCUMENT_NAMES['summary']}"),
                "receipt": fetch_remote_file(ctx, f"{root}/deployments/{chain}/{DOCUMENT_NAMES['receipt']}"),
                "readback": fetch_remote_file(ctx, f"{root}/readback-{chain}.json")}
        parsed = {name: json.loads(raw, object_pairs_hook=release_lock.unique_object) for name, raw in raws.items()}
        validate_documents(chain, parsed["summary"], parsed["receipt"])
        validate_readback(parsed["readback"], chain, policy, ctx.lock["l1"]["signer"])
        row = {name: store_document(ctx, f"attempt-{number}/{chain}/{filename}", raws[name])
               for name, filename in (("summary", DOCUMENT_NAMES["summary"]), ("receipt", DOCUMENT_NAMES["receipt"]),
                                      ("readback", f"readback-{chain}.json"))}
        inner = parsed["receipt"]["receipt"]
        row.update(chain_id=fresh_l1.NETWORKS[chain][0], bridge=parsed["summary"]["core"]["Bridge"],
                   state_manager=parsed["summary"]["core"]["StateManager"], block_number=inner["blockNumber"],
                   deployment_tx=parsed["receipt"]["transactionHash"])
        chains[chain] = row
    prepare.write_state(ctx, "deploy_l1", {
        "schema_version": 1, "lock_sha256": ctx.lock_sha256, "release_id": ctx.lock["release_id"], "attempt": number,
        "output_dir": attempt_dir(ctx, number), "signer_host": signer_host(ctx),
        "bundle_sha256": ctx.lock["l1"]["bundle_sha256"], "policy_sha256": ctx.lock["l1"]["policy_sha256"],
        "contracts_commit": ctx.lock["sources"]["contracts"], "chains": chains})


def read_deploy_state(ctx):
    document = prepare.read_state(ctx, "deploy_l1")
    prepare.require(document.get("lock_sha256") == ctx.lock_sha256, "recorded L1 documents belong to another release lock")
    prepare.require(set(document.get("chains", {})) == set(CHAIN_ORDER), "recorded L1 documents do not cover three chains")
    return document


def deploy_verify(ctx):
    document = read_deploy_state(ctx)
    number = document["attempt"]
    completed_attempt(ctx, number, CHAIN_ORDER)
    summary = {}
    for chain, row in document["chains"].items():
        for name in ("summary", "receipt", "readback"):
            actual = hashlib.sha256(Path(row[name]["path"]).read_bytes()).hexdigest()
            prepare.require(actual == row[name]["sha256"], f"{chain}: recorded {name} document changed")
        summary[chain] = {"bridge": row["bridge"], "state_manager": row["state_manager"], "block_number": row["block_number"],
                          "summary_sha256": row["summary"]["sha256"]}
    return {"attempt": number, "chains": summary}


def bridge_packages(ctx, role):
    """Read the step 70 contract: {lock_sha256, l1_documents_sha256, guardian: {host: dir}, relayer: {host: dir}}."""
    state = prepare.read_state(ctx, "prepare_bridge_packages")
    prepare.require(state.get("lock_sha256") == ctx.lock_sha256, "recorded bridge packages belong to another release lock")
    deploy_file = ctx.state_dir / "deploy_l1.json"
    prepare.require(deploy_file.is_file() and state.get("l1_documents_sha256") == prepare.file_sha256(deploy_file),
                    "bridge packages were built from different L1 documents than the recorded deployment")
    rows = state.get(role)
    prepare.require(isinstance(rows, dict) and rows, f"no {role} package recorded")
    return {host: read_package(ctx, role, host, Path(path)) for host, path in sorted(rows.items())}


def read_package(ctx, role, host, directory):
    document = release_lock.read_document(directory / "package.json")
    keys = {"role", "host", "spec", "spec_sha256", "stage_dir", "rpc_config", "files"} | ({"guardian_id"} if role == "guardian" else set())
    prepare.require(set(document) == keys and document["role"] == role and document["host"] == host, f"{host}: package.json fields differ")
    prepare.require(re.fullmatch(r"/var/tmp/[A-Za-z0-9._-]+", document["stage_dir"]), f"{host}: stage directory must sit under /var/tmp")
    files = document["files"]
    prepare.require(isinstance(files, dict) and document["spec"] in files and document["rpc_config"] in files,
                    f"{host}: package lacks its spec or RPC config")
    for name, expected in files.items():
        prepare.require(re.fullmatch(r"[A-Za-z0-9._/-]+", name) and ".." not in name.split("/"), f"{host}: unsafe package file name")
        prepare.require(prepare.file_sha256(directory / name) == expected, f"{host}: package file hash differs: {name}")
    prepare.require(files[document["spec"]] == document["spec_sha256"], f"{host}: spec hash differs from the package")
    for tool in (GUARDIAN_TOOLS if role == "guardian" else RELAYER_TOOLS):
        prepare.require(files.get(tool) == ctx.lock["tool_sha256"][tool], f"{host}: package copy of {tool} differs from the lock")
    return {**document, "directory": str(directory)}


def unit_state(ctx, host, unit):
    output = ctx.remote.run_script(host, f"systemctl show {quote(unit)} --property={UNIT_PROPERTIES}\n", SHORT_SECONDS)
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def running(state):
    return (state.get("LoadState") == "loaded" and state.get("ActiveState") == "active" and state.get("UnitFileState") == "enabled"
            and state.get("MainPID", "0").isdigit() and int(state["MainPID"]) > 0)


def stage_package(ctx, package):
    """Copy the package and the release lock to its host; the stage directory is replaced, never merged."""
    host, stage, directory = package["host"], package["stage_dir"], Path(package["directory"])
    by_directory = {}
    for name in package["files"]:
        by_directory.setdefault(str(Path(name).parent), []).append(directory / name)
    targets = {parent: stage if parent == "." else f"{stage}/{parent}" for parent in by_directory}
    run_root_script(ctx, host, f"rm -rf -- {quote(stage)}\n")
    ctx.remote.run_script(host, "set -euo pipefail\numask 077\nmkdir -p -- "
                          + " ".join(quote(path) for path in targets.values()) + "\n", SHORT_SECONDS)
    for parent, paths in by_directory.items():
        ctx.remote.copy_files(host, paths, targets[parent], timeout_seconds=UPLOAD_SECONDS)
    ctx.remote.copy_files(host, [ctx.release_dir / "release-lock.json"], stage)
    spec = f"{stage}/{package['spec']}"
    run_root_script(ctx, host, f"chown -R root:root -- {quote(stage)}\nchmod 0600 -- {quote(spec)}\n")


def remove_stage(ctx, package):
    run_root_script(ctx, package["host"], f"rm -rf -- {quote(package['stage_dir'])}\n")


def run_installer(ctx, package, tool, mode, apply):
    stage = package["stage_dir"]
    argv = [PYTHON, "-I", "-B", f"{stage}/{tool}", mode, "--release-lock", f"{stage}/release-lock.json",
            "--release-lock-sha256", ctx.lock_sha256, "--spec", f"{stage}/{package['spec']}",
            "--spec-sha256", package["spec_sha256"]] + (["--apply"] if apply else [])
    return json.loads(ctx.remote.run_root_text(package["host"], argv, INSTALL_SECONDS, show_stderr=True))


def run_activation(ctx, package, role, apply):
    stage = package["stage_dir"]
    argv = [PYTHON, "-I", "-B", f"{stage}/activate_bridge.py", "--release-lock", f"{stage}/release-lock.json",
            "--release-lock-sha256", ctx.lock_sha256, "--role", role, "--spec", f"{stage}/{package['spec']}",
            "--spec-sha256", package["spec_sha256"]] + (["--apply"] if apply else [])
    return json.loads(ctx.remote.run_root_text(package["host"], argv, INSTALL_SECONDS, show_stderr=True))


def guardian_unit(ctx, package):
    return f"{ctx.lock['units']['guardian_prefix']}{package['guardian_id']}.service"


def start_guardian(ctx, package):
    """Install when the unit is absent, then enable and start it; a running enabled unit is left alone."""
    unit = guardian_unit(ctx, package)
    state = unit_state(ctx, package["host"], unit)
    if running(state):
        return "running"
    stage_package(ctx, package)
    try:
        if state.get("LoadState") != "loaded":
            run_installer(ctx, package, "install_guardian.py", "check-host", False)
            run_installer(ctx, package, "install_guardian.py", "install", True)
        run_activation(ctx, package, "guardian", True)
    finally:
        remove_stage(ctx, package)
    return "started"


def guardian_check(ctx):
    for tool in GUARDIAN_TOOLS:
        prepare.check_tool_hash(ctx, tool)
    read_deploy_state(ctx)
    packages = bridge_packages(ctx, "guardian")
    prepare.require(sorted(p["guardian_id"] for p in packages.values()) == [1, 2, 3], "guardian packages must cover ids 1, 2 and 3")
    relayer = bridge_packages(ctx, "relayer")
    prepare.require(len(relayer) == 1, "exactly one Relayer package is required to check Guardian readiness from its host")


def readiness_from_relayer_host(ctx, guardian_package, relayer_package):
    """Ask the three Guardians from the Relayer host with the Guardians' own RPC config."""
    host, stage = relayer_package["host"], f"{STAGE_ROOT}/psy-guardian-readiness-{ctx.lock['release_id']}"
    directory = Path(guardian_package["directory"])
    rpc_name = guardian_package["rpc_config"]
    rpc_path = directory / rpc_name
    run_root_script(ctx, host, f"rm -rf -- {quote(stage)}\n")
    ctx.remote.run_script(host, f"set -euo pipefail\numask 077\nmkdir -p -- {quote(stage)}\n", SHORT_SECONDS)
    sources = [prepare.TOOLS_DIR / tool for tool in ("activate_bridge.py", "install_guardian.py", "install_relayer.py")]
    ctx.remote.copy_files(host, [*sources, rpc_path, ctx.release_dir / "release-lock.json"], stage)
    argv = [PYTHON, "-I", "-B", f"{stage}/activate_bridge.py", "--release-lock", f"{stage}/release-lock.json",
            "--release-lock-sha256", ctx.lock_sha256, "--role", "guardian-readiness",
            "--rpc-config", f"{stage}/{rpc_path.name}", "--rpc-config-sha256", prepare.file_sha256(rpc_path)]
    reports = []

    def is_ready():
        # A Guardian binds its listener only after journal initialisation, so early refusals are expected.
        try:
            report = json.loads(ctx.remote.run_root_text(host, argv, PROBE_SECONDS, show_stderr=True))
        except (RemoteError, ValueError) as error:
            if isinstance(error, RemoteConnectionError):
                raise
            return False
        reports.append(report)
        return report.get("guardians_ready") == 3

    try:
        wait_until(is_ready, lambda: None, POLL_SECONDS, READY_SECONDS, "Guardian readiness from the Relayer host")
    finally:
        run_root_script(ctx, host, f"rm -rf -- {quote(stage)}\n")
    return reports[-1]


def guardian_apply(ctx):
    packages = bridge_packages(ctx, "guardian")
    for host, package in sorted(packages.items(), key=lambda row: row[1]["guardian_id"]):
        start_guardian(ctx, package)
    (relayer,) = bridge_packages(ctx, "relayer").values()
    readiness_from_relayer_host(ctx, next(iter(packages.values())), relayer)


def guardian_verify(ctx):
    packages = bridge_packages(ctx, "guardian")
    result = {}
    for host, package in packages.items():
        state = unit_state(ctx, host, guardian_unit(ctx, package))
        prepare.require(running(state) and state.get("NRestarts") == "0", f"{host}: Guardian is not running without restarts")
        result[host] = {"guardian_id": package["guardian_id"], "restarts": 0}
    (relayer,) = bridge_packages(ctx, "relayer").values()
    ready = readiness_from_relayer_host(ctx, next(iter(packages.values())), relayer)
    return {"guardians": result, "ready_from_relayer_host": ready["guardians_ready"]}


def relayer_package(ctx):
    packages = bridge_packages(ctx, "relayer")
    prepare.require(len(packages) == 1, "exactly one Relayer package is required")
    return next(iter(packages.values()))


def relayer_check(ctx):
    for tool in RELAYER_TOOLS:
        prepare.check_tool_hash(ctx, tool)
    read_deploy_state(ctx)
    relayer_package(ctx)
    for package in bridge_packages(ctx, "guardian").values():
        prepare.require(package["files"], "guardian package is empty")


def read_checkpoints(ctx, package):
    """lastFinalizedCheckpointId of each StateManager, read from the Relayer host through the private gateway routes."""
    document = read_deploy_state(ctx)
    routes = ctx.lock["envio"]["rpc_routes"]
    targets = {chain: {"route": routes[chain], "state_manager": document["chains"][chain]["state_manager"]} for chain in CHAIN_ORDER}
    script = ("python3 -I - <<'PSY_CHECKPOINT_END'\nimport json, urllib.request\ntargets = json.loads(%r)\nout = {}\n"
              "for chain, row in targets.items():\n    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': "
              "[{'to': row['state_manager'], 'data': %r}, 'latest']}).encode()\n    try:\n        request = urllib.request.Request("
              "row['route'], data=body, headers={'Content-Type': 'application/json'})\n        out[chain] = int(json.loads("
              "urllib.request.urlopen(request, timeout=10).read())['result'], 16)\n    except Exception:\n        out[chain] = None\n"
              "print(json.dumps(out))\nPSY_CHECKPOINT_END\n") % (json.dumps(targets), LAST_FINALIZED_SELECTOR)
    values = json.loads(ctx.remote.run_script(package["host"], script, SHORT_SECONDS))
    prepare.require(set(values) == set(CHAIN_ORDER), "checkpoint read returned the wrong chains")
    return values


def all_advanced(values):
    return all(type(values[chain]) is int and values[chain] > 0 for chain in CHAIN_ORDER)


def relayer_unit(ctx):
    return ctx.lock["units"]["relayer"]


def wait_first_settlement(ctx, package):
    host, unit = package["host"], relayer_unit(ctx)

    def failure():
        state = unit_state(ctx, host, unit)
        if state.get("ActiveState") in ("failed", "inactive") or state.get("NRestarts", "0") != "0":
            return f"Relayer is {state.get('ActiveState')} with {state.get('NRestarts')} restarts"
        return None

    wait_until(lambda: all_advanced(read_checkpoints(ctx, package)), failure, POLL_SECONDS, SETTLEMENT_SECONDS,
               "first settlement on all three chains")


def relayer_apply(ctx):
    package = relayer_package(ctx)
    state = unit_state(ctx, package["host"], relayer_unit(ctx))
    if not running(state):
        stage_package(ctx, package)
        try:
            if state.get("LoadState") != "loaded":
                run_installer(ctx, package, "install_relayer.py", "check-host", False)
                run_installer(ctx, package, "install_relayer.py", "install", True)
            run_activation(ctx, package, "relayer", True)
        finally:
            remove_stage(ctx, package)
    wait_first_settlement(ctx, package)


def relayer_verify(ctx):
    package = relayer_package(ctx)
    state = unit_state(ctx, package["host"], relayer_unit(ctx))
    prepare.require(running(state) and state.get("NRestarts") == "0", "Relayer is not running without restarts")
    values = read_checkpoints(ctx, package)
    prepare.require(all_advanced(values), "a StateManager has not settled a checkpoint yet")
    return {"unit": relayer_unit(ctx), "restarts": 0, "checkpoints": values}


BRIDGE_STEPS = {
    "deploy_l1": Step("deploy_l1", deploy_check, deploy_apply, deploy_verify, cutover=True),
    "start_guardians": Step("start_guardians", guardian_check, guardian_apply, guardian_verify, cutover=True),
    "start_relayer": Step("start_relayer", relayer_check, relayer_apply, relayer_verify, cutover=True),
}
