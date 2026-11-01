#!/usr/bin/env python3
"""Steps 80-84, 87 and 86: acceptance of the live release, then the explicit opening of deposits.

80 public entrypoints, 81 P2P rotation and restart recovery, 82 Faucet batch, 83 five withdrawals in one batch,
84 the three chains one at a time, 87 a PSY withdrawal with the new address after the frontend release. Every
step starts only when the frontends are current (step 79) and no chain is left unpaused. Windows run through
accept_common.unpaused_chain. Step 86 opens deposits for users and needs an explicit CONFIRM variable.
Inputs live in local-inputs.json under "acceptance" (see fresh-192-20261030/README.md). MetaMask flows are
skipped by name and the reward claim is recorded as unverified: no cheap real path exists for either.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import time

import accept_common as ac
import deploy_bridge_steps as bridge_steps
import deploy_prepare_steps as prepare
import public_release as pr
import release_lock
from deploy_prepare_steps import file_sha256, local_inputs, read_state, require, write_state
from deploy_public_steps import l1_documents, require_frontends_current
from deploy_remote import OperatorPending, Step, redact_tail, wait_until

DRIVERS = Path(__file__).resolve().parents[1] / "e2e" / "three-chain"
CHECK_SCRIPT = Path(__file__).resolve().parents[4] / "deploy" / "gcp" / "check-public-entrypoints.sh"
CONFIRM_VARIABLE = "CONFIRM_OPEN_DEPOSITS"
HEAD_AGE_LIMIT_SECONDS = 300
ENTRYPOINT_SECONDS = 900
DRIVER_SECONDS = 3600
POLL_SECONDS = 30
PROVE_WAIT_SECONDS = 90 * 60
SETTLE_WAIT_SECONDS = 60 * 60
DEPOSIT_AMOUNT = 1_000_000
WITHDRAW_AMOUNT = 500_000
FIVE_DEPOSIT, FIVE_WITHDRAW, FIVE_USERS = 200_000, 100_000, ("u01", "u02", "u03", "u04", "u05")
PSY_WITHDRAW_AMOUNT = 1_000_000
BURST_USERS = tuple(f"u{index:02d}" for index in range(1, 11))
SAMPLE_SECONDS = 120
USER_ID = re.compile(r"user_id:\s*(\d+)")
SKIPPED = {"metamask": "not automated: wallet extension flows need a person and a browser"}
UNVERIFIED = {"reward_claim": "unverified: it needs a worker with completed jobs and an L1 claim, and no cheap real path exists"}


def section(ctx):
    value = local_inputs(ctx).get("acceptance")
    require(isinstance(value, dict), "local-inputs.json lacks the acceptance section")
    return value


def work_dir(ctx):
    path = Path(section(ctx)["work_dir"])
    require(path.is_absolute(), "acceptance.work_dir must be an absolute path")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def public_of(ctx):
    return pr.read_public(ctx.release_dir)


def base_check(ctx):
    """Frontends current and no chain left unpaused, before any acceptance step touches anything."""
    require_frontends_current(ctx)
    left = ac.unpaused_chains(ctx)
    require(not left, "deposits are open on " + ", ".join(left) + "; pause them before acceptance")


def user_check(ctx):
    base_check(ctx)
    inputs = section(ctx)
    for name in ("user_rpc_config", "wallet_key_file", "wallet_address"):
        require(isinstance(inputs.get(name), str) and inputs[name], f"acceptance.{name} is required")
    key = Path(inputs["wallet_key_file"])
    require(key.is_file() and not key.stat().st_mode & 0o077, "the wallet key file must be readable only by its owner")
    require(prepare.rebuilt_binary(ctx, "psy_user_cli").is_file(), "the rebuilt psy_user_cli is missing")
    prepare.check_tool_hash(ctx, "admin_pause.py")


def driver_env(ctx, documents):
    inputs = section(ctx)
    deployments = Path(read_state(ctx, "deploy_l1")["chains"][release_lock.CHAINS[0]]["summary"]["path"]).parent.parent
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"),
           "E2E_USER_CLI": str(prepare.rebuilt_binary(ctx, "psy_user_cli")),
           "E2E_RUNTIME_CONFIG": str(prepare.local_path(ctx, "files", "config")), "E2E_USER_RPC_CONFIG": inputs["user_rpc_config"],
           "E2E_DEPLOYMENTS_DIR": str(deployments), "E2E_WALLET_KEY_FILE": inputs["wallet_key_file"],
           "E2E_WALLET_ADDRESS": inputs["wallet_address"], "E2E_WORK_DIR": str(work_dir(ctx))}
    env.update({f"E2E_RPC_{chain.upper()}": ac.local_url(chain) for chain in release_lock.CHAINS})
    return env


def run_driver(env, name, *args, timeout=DRIVER_SECONDS):
    done = subprocess.run(["bash", str(DRIVERS / name), *map(str, args)], env=env, capture_output=True, text=True, timeout=timeout,
                          check=False)
    if done.returncode != 0:
        raise RuntimeError(f"{name} failed (exit {done.returncode}): {redact_tail(done.stderr or done.stdout)}")
    return done.stdout


def load_progress(ctx, name):
    path = ctx.state_dir / f"{name}.json"
    if not path.is_file():
        return {"lock_sha256": ctx.lock_sha256}
    document = release_lock.read_document(path)
    require(document.get("lock_sha256") == ctx.lock_sha256, f"recorded {name} belongs to another release lock")
    return document


def recorded(ctx, name):
    document = read_state(ctx, name)
    require(document.get("lock_sha256") == ctx.lock_sha256, f"recorded {name} belongs to another release lock")
    return document


# ---- step 80: public entrypoints ----

def host_of(url):
    return url.removeprefix("https://").rstrip("/").split("/")[0]


def entrypoint_env(ctx, public, trust_published):
    names = {"sepolia": "sepolia", "bscTestnet": "bsc", "baseSepolia": "base"}
    routes = [{"name": names[chain], "domain": host_of(public["chains"][chain]["rpc_url"]),
               "chain_id": prepare.fresh_l1.NETWORKS[chain][0]} for chain in release_lock.CHAINS]
    trust = public["trust_setup"]
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), "CHECK_PUBLIC_STANDALONE": "1",
            "PUBLIC_NOSTR_DOMAIN": host_of(trust["base_url"]), "PUBLIC_TRUST_SETUP_DOMAIN": host_of(trust["base_url"]),
            "PUBLIC_TRUST_SETUP_PATH": "/" + trust["base_url"].split("//", 1)[1].split("/", 1)[1],
            "TRUST_SETUP_ARCHIVE_NAME": trust["archive"], "CHECK_PUBLIC_TRUST_SETUP": "1" if trust_published else "0",
            "PUBLIC_COORDINATOR_DOMAIN": host_of(public["services"]["coordinator_rpc"]),
            "PUBLIC_REALM0_DOMAIN": host_of(public["services"]["realm_rpcs"][0]),
            "PUBLIC_REALM1_DOMAIN": host_of(public["services"]["realm_rpcs"][1]),
            "PUBLIC_PROVE_PROXY_DOMAIN": host_of(public["services"]["prove_proxy"]),
            "PUBLIC_FAUCET_DOMAIN": host_of(public["services"]["faucet_rpc"]),
            "PUBLIC_PSY_SERVICES_DOMAIN": host_of(public["services"]["psy_services"]),
            "PUBLIC_INDEXER_DOMAIN": host_of(public["services"]["indexer_graphql"]), "PUBLIC_RPC_DOMAIN": "",
            "PUBLIC_L1_RPC_ROUTES_JSON": json.dumps(routes), "CORS_ORIGIN": public["frontends"]["app"].rstrip("/")}


def parse_entrypoint_lines(text):
    lines = text.splitlines()
    return ([line.removeprefix("[ok] ") for line in lines if line.startswith("[ok] ")],
            [line.removeprefix("[DEFERRED] ") for line in lines if line.startswith("[DEFERRED] ")])


def head_ages(public, now, fetch=ac.json_rpc):
    """Age in seconds of the latest block behind each public L1 route; a stale node is an acceptance failure."""
    ages = {}
    for chain in release_lock.CHAINS:
        result, error = fetch(public["chains"][chain]["rpc_url"], "eth_getBlockByNumber", ["latest", False])
        require(error is None and isinstance(result, dict), f"{chain}: the public route returned no block")
        ages[chain] = int(now - int(result["timestamp"], 16))
        require(ages[chain] <= HEAD_AGE_LIMIT_SECONDS, f"{chain}: the public route is {ages[chain]} s behind; its node is stale")
    return ages


def entrypoints_check(ctx):
    require_frontends_current(ctx)
    require(CHECK_SCRIPT.is_file(), "the public entrypoint check script is missing")
    public_of(ctx)


def entrypoints_apply(ctx):
    public = public_of(ctx)
    trust = (ctx.state_dir / "publish_trust_setup.json").is_file()
    done = subprocess.run(["bash", str(CHECK_SCRIPT)], env=entrypoint_env(ctx, public, trust), capture_output=True, text=True,
                          timeout=ENTRYPOINT_SECONDS, check=False)
    passed, deferred = parse_entrypoint_lines(done.stdout)
    if done.returncode != 0:
        raise RuntimeError("public entrypoint check failed: " + redact_tail(done.stderr or done.stdout))
    ages = head_ages(public, time.time())
    write_state(ctx, "accept_entrypoints", {"lock_sha256": ctx.lock_sha256, "checks": len(passed), "deferred": deferred,
                                            "head_age_seconds": ages})


def entrypoints_verify(ctx):
    state = recorded(ctx, "accept_entrypoints")
    require(state["checks"] > 0, "no public entrypoint check passed")
    return {"checks": state["checks"], "deferred": state["deferred"], "head_age_seconds": state["head_age_seconds"]}


# ---- step 81: P2P rotation and recovery ----

PROPOSAL = re.compile(r"realm P2P proposal published .*?realm=(\d+) sub_id=(\d+) epoch=(\d+)")


def processors(ctx):
    """[(realm, sub, host, unit)] of every Realm validator processor, from the release topology."""
    topology = release_lock.read_document(ctx.release_dir / "topology.json")
    prefix = ctx.lock["units"]["core_prefix"]
    return [(realm["id"], sub, validator["processor_host"], f"{prefix}realm-{realm['id']}-v{sub}-processor.service")
            for realm in topology["realms"] for sub, validator in enumerate(realm["validators"], start=1)]


def journal(ctx, host, unit, pattern, since):
    argv = ["/usr/bin/journalctl", "-u", unit, "--since", since, "--no-pager", "-o", "cat", "-g", pattern]
    try:
        return ctx.remote.run_root_text(host, argv, 300)
    except Exception as error:
        if getattr(error, "exit_code", None) == 1:
            return ""
        raise


def proposals(ctx, since):
    seen = {}
    for realm, sub, host, unit in processors(ctx):
        for found in PROPOSAL.finditer(journal(ctx, host, unit, "realm P2P proposal published", since)):
            if int(found.group(1)) == realm and int(found.group(2)) == sub:
                seen.setdefault((realm, sub), set()).add(int(found.group(3)))
    return seen


def require_rotation(seen, realm_ids, subs):
    missing = [f"realm {realm} validator {sub}" for realm in realm_ids for sub in subs if not seen.get((realm, sub))]
    require(not missing, "no proposal published by " + ", ".join(missing))
    return {f"realm{realm}": {f"v{sub}": sorted(seen[(realm, sub)]) for sub in subs} for realm in realm_ids}


def quiet_unit(ctx, realm, sub, host, unit, since):
    """True when the restarted unit has no ERROR line and logged P2P activity since the restart."""
    errors = journal(ctx, host, unit, r"\bERROR\b", since).strip()
    return not errors and bool(journal(ctx, host, unit, "realm P2P", since).strip())


def restart_one(ctx, realm, rows, latest_epoch_proposers):
    """Restart a validator that is not the current proposer; wait until it logs P2P activity without errors."""
    candidates = [row for row in rows if row[0] == realm and row[1] not in latest_epoch_proposers.get(realm, set())]
    require(candidates, f"realm {realm}: every validator is a current proposer; nothing safe to restart")
    _, sub, host, unit = candidates[0]
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    ctx.remote.run_root_text(host, ["/usr/bin/systemctl", "restart", unit], 300)
    wait_until(lambda: quiet_unit(ctx, realm, sub, host, unit, stamp), lambda: None, POLL_SECONDS, 600, f"realm {realm} processor recovery")
    return {"realm": realm, "validator": sub, "unit": unit}


def latest_proposers(ctx):
    """{realm: validators that proposed in the newest epoch seen within the last half hour}."""
    seen = proposals(ctx, "30 minutes ago")
    newest = {realm: max((max(epochs) for (r, _), epochs in seen.items() if r == realm), default=None) for realm in {r for r, _ in seen}}
    return {realm: {sub for (r, sub), epochs in seen.items() if r == realm and newest[realm] in epochs} for realm in newest}


def p2p_check(ctx):
    base_check(ctx)
    require(len(processors(ctx)) == 6, "the topology must list three validators in each of two Realms")


def p2p_apply(ctx):
    progress = load_progress(ctx, "accept_p2p_rotation")
    seen = proposals(ctx, "24 hours ago")
    progress["rotation"] = require_rotation(seen, sorted({row[0] for row in processors(ctx)}), (1, 2, 3))
    restarted = progress.get("restarted", {})
    for realm in sorted({row[0] for row in processors(ctx)}):
        if str(realm) not in restarted:
            restarted[str(realm)] = restart_one(ctx, realm, processors(ctx), latest_proposers(ctx))
            progress["restarted"] = restarted
            write_state(ctx, "accept_p2p_rotation", progress)
    progress["restarted"] = restarted
    write_state(ctx, "accept_p2p_rotation", progress)


def p2p_verify(ctx):
    state = recorded(ctx, "accept_p2p_rotation")
    require(sorted(state["restarted"]) == ["0", "1"], "one processor per Realm must have been restarted")
    return {"rotation": state["rotation"], "restarted": state["restarted"]}


# ---- users, faucet and deposits ----

def ensure_user(ctx, env, name):
    """A registered L2 user: a private key file, the registration, and the user id; reruns reuse what exists."""
    directory = work_dir(ctx) / "users"
    directory.mkdir(mode=0o700, exist_ok=True)
    key, meta = directory / f"{name}.key", directory / f"{name}.json"
    if meta.is_file():
        return {"name": name, "id": json.loads(meta.read_text())["id"], "key": key, "hash": json.loads(meta.read_text())["hash"]}
    if not key.is_file():
        descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(secrets.token_hex(32) + "\n")
    result = directory / f"{name}.registration.json"
    run_driver(env, "user_cli.sh", key, "register-user", "--rpc-config", env["E2E_USER_RPC_CONFIG"], "--result-file", result)
    public_hash = json.loads(result.read_text())["public_key_hash"]
    found = {}

    def resolved():
        out = run_driver(env, "user_cli.sh", key, "get-user-id", "--pub-key", public_hash, "--rpc-config", env["E2E_USER_RPC_CONFIG"])
        match = USER_ID.search(out)
        found["id"] = int(match.group(1)) if match else None
        return found["id"] is not None
    wait_until(resolved, lambda: None, 10, 600, f"user id of {name}")
    meta.write_text(json.dumps({"id": found["id"], "hash": public_hash}))
    meta.chmod(0o600)
    return {"name": name, "id": found["id"], "key": key, "hash": public_hash}


def faucet_claim(public, user_id):
    result, error = ac.json_rpc(public["services"]["faucet_rpc"], "psy_claim_faucet", [{"recipient_user_id": user_id}], timeout=300)
    require(error is None and isinstance(result, dict) and result.get("operator_user_id") is not None,
            f"the faucet refused the grant for user {user_id}")
    return result


def l2_claim(env, user, operator):
    """Claim the faucet grant into the fee balance; the grant may not be included yet, so retry a few times."""
    for attempt in range(3):
        try:
            run_driver(env, "user_cli.sh", user["key"], "call", "--sign-type", "zk", "--rpc-config", env["E2E_USER_RPC_CONFIG"],
                       "--contract-id", 0, "--method-name", "claim", "--inputs", f"[{operator}]", "--wait-until-confirmation",
                       "--result-file", work_dir_of(env) / "users" / f"{user['name']}.claim.json")
            return
        except RuntimeError:
            if attempt == 2:
                raise
            time.sleep(POLL_SECONDS)


def work_dir_of(env):
    return Path(env["E2E_WORK_DIR"])


def fund_user(ctx, env, public, user):
    grant = faucet_claim(public, user["id"])
    l2_claim(env, user, grant["operator_user_id"])
    return grant


def memory_script(unit):
    quoted = shlex.quote(unit)
    return f"for i in $(seq 1 {SAMPLE_SECONDS}); do systemctl show -p MemoryCurrent --value {quoted}; sleep 1; done\n"


def sample_memory(ctx, host, unit):
    out = ctx.remote.run_script(host, memory_script(unit), SAMPLE_SECONDS + 120)
    return [int(line) for line in out.split() if line.isdigit()]


def burst(public, users):
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(users)) as pool:
        return list(pool.map(lambda user: faucet_claim(public, user["id"]), users))


def faucet_apply_burst(ctx, env, public, users):
    host, unit = prepare.faucet_host(ctx), ctx.lock["units"]["faucet"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        sampler = pool.submit(sample_memory, ctx, host, unit)
        time.sleep(2)
        grants = burst(public, users)
        samples = sampler.result()
    limit = ctx.remote.run_script(host, f"systemctl show -p MemoryMax --value {shlex.quote(unit)}\n", 60).strip()
    require(samples and limit.isdigit(), "the faucet memory could not be sampled")
    peak, idle = max(samples), min(samples)
    require(peak < int(limit), "the faucet reached its memory limit during the burst")
    return grants, {"idle_bytes": idle, "peak_bytes": peak, "limit_bytes": int(limit), "samples": len(samples)}


def faucet_check(ctx):
    user_check(ctx)


def faucet_apply(ctx):
    progress = load_progress(ctx, "accept_faucet_batch")
    if progress.get("burst"):
        return
    env, public = driver_env(ctx, l1_documents(ctx)), public_of(ctx)
    users = {name: ensure_user(ctx, env, name) for name in ("u00", *BURST_USERS)}
    first = fund_user(ctx, env, public, users["u00"])
    grants, memory = faucet_apply_burst(ctx, env, public, [users[name] for name in BURST_USERS])
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(lambda pair: l2_claim(env, pair[0], pair[1]["operator_user_id"]), zip((users[n] for n in BURST_USERS), grants)))
    progress.update(funded=["u00", *BURST_USERS], first_grant_operator=first["operator_user_id"],
                    burst={"recipients": len(grants), "batches": len({grant["tx_hash"] for grant in grants}),
                           "operators": sorted({grant["operator_user_id"] for grant in grants})}, memory=memory)
    write_state(ctx, "accept_faucet_batch", progress)


def faucet_verify(ctx):
    state = recorded(ctx, "accept_faucet_batch")
    require(state["burst"]["recipients"] == len(BURST_USERS), "every burst recipient must have been granted")
    return {"burst": state["burst"], "memory": state["memory"]}


# ---- deposits, claims, withdrawals ----

def secrets_file(ctx, label):
    path = work_dir(ctx) / "deposit-secrets" / f"{label}.env"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    if not path.is_file():
        word = lambda: secrets.randbelow(2 ** 32 - 1) + 1
        text = (f"R0={word()}\nR1={word()}\nNOTE_SECRET={','.join(str(word()) for _ in range(4))}\n"
                f"NULLIFIER_SECRET={','.join(str(word()) for _ in range(4))}\n")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)
    return path


def prepare_wallet(env, documents, chain, amount):
    """The wallet holds the USDT it will deposit and has approved the gateway; both work while deposits are paused."""
    core, wallet = documents[chain]["core"], env["E2E_WALLET_ADDRESS"]
    rpc = env[f"E2E_RPC_{chain.upper()}"]
    if ac.read_balance(chain, core["USDTToken"], wallet) < amount:
        run_driver(env, "evm.sh", "send", core["TokenFaucetManager"], "claim(address)", core["USDTToken"], "--rpc-url", rpc)
    run_driver(env, "evm.sh", "send", core["USDTToken"], "approve(address,uint256)", core["ERC20Gateway"], amount, "--rpc-url", rpc)


def deposit_once(ctx, env, documents, chain, user, label, amount):
    result = work_dir(ctx) / "deposits" / f"{chain}-{label}.result.json"
    result.parent.mkdir(mode=0o700, exist_ok=True)
    run_driver(env, "deposit.sh", chain, ac.CHAIN_INDEX[chain], user["id"], secrets_file(ctx, f"{chain}-{label}"), result, amount)
    return result


def wait_proved(chain, bridge, index):
    wait_until(lambda: ac.read_count(chain, bridge, ac.PROVED_COUNT) > index, lambda: None, POLL_SECONDS, PROVE_WAIT_SECONDS,
               f"{chain} deposit proof")


def claim_one(ctx, env, chain, user, label, result, index, amount):
    out = work_dir(ctx) / "claims" / f"{chain}-{label}"
    out.parent.mkdir(mode=0o700, exist_ok=True)
    run_driver(env, "claim_deposit.sh", chain, ac.CHAIN_INDEX[chain], user["id"], user["key"], secrets_file(ctx, f"{chain}-{label}"),
               result, index, amount, out)


def new_nonce():
    return "0x" + secrets.token_hex(32)


def withdraw_one(ctx, env, documents, chain, user, label, asset, amount, contract_id=None, nonce=None):
    result = work_dir(ctx) / "withdrawals" / f"{chain}-{label}.json"
    result.parent.mkdir(mode=0o700, exist_ok=True)
    nonce = nonce or new_nonce()
    args = [chain, ac.CHAIN_INDEX[chain], user["key"], asset, amount, env["E2E_WALLET_ADDRESS"], nonce, result]
    run_driver(env, "withdraw.sh", *args, *([contract_id] if contract_id is not None else []))


def wait_balance(chain, asset, wallet, wanted):
    wait_until(lambda: ac.read_balance(chain, asset, wallet) >= wanted, lambda: None, POLL_SECONDS, SETTLE_WAIT_SECONDS,
               f"{chain} L1 settlement")


def withdrawal_plan(ctx, name, progress, holder, keys, read_baseline):
    """Nonces and the L1 balance baseline are recorded before the first send, so a rerun reuses both."""
    plan = holder.setdefault("withdrawal", {})
    if "baseline" not in plan:
        plan.update(baseline=read_baseline(), nonces={key: new_nonce() for key in keys}, sent=[])
        write_state(ctx, name, progress)
    return plan


def send_withdrawals(ctx, name, progress, plan, send):
    """Send every withdrawal not yet recorded as sent, in parallel, with its recorded nonce; successes are recorded
    even when another one fails, and the first failure is raised."""
    todo = [key for key in plan["nonces"] if key not in plan["sent"]]
    first_error = None
    if todo:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(todo)) as pool:
            futures = {key: pool.submit(send, key, plan["nonces"][key]) for key in todo}
            for key, future in futures.items():
                try:
                    future.result()
                    plan["sent"].append(key)
                except Exception as error:
                    first_error = first_error or error
        write_state(ctx, name, progress)
    if first_error is not None:
        raise first_error


def claim_recorded(ctx, name, progress, holder, key, claim):
    claimed = holder.setdefault("claimed", [])
    if key not in claimed:
        claim()
        claimed.append(key)
        write_state(ctx, name, progress)


def settle_amount(ctx, env, documents, chain, user, label, amount, index, progress, leg):
    """After a deposit: wait for the proof, claim on L2, withdraw half, wait for the L1 balance to return."""
    core, wallet = documents[chain]["core"], env["E2E_WALLET_ADDRESS"]
    name = "accept_three_chains"
    wait_proved(chain, core["Bridge"], index)
    claim_recorded(ctx, name, progress, leg, label, lambda: claim_one(
        ctx, env, chain, user, label, work_dir(ctx) / "deposits" / f"{chain}-{label}.result.json", index, amount))
    plan = withdrawal_plan(ctx, name, progress, leg, [label], lambda: ac.read_balance(chain, core["USDTToken"], wallet))
    send_withdrawals(ctx, name, progress, plan, lambda key, nonce: withdraw_one(
        ctx, env, documents, chain, user, label, core["USDTToken"], amount // 2, nonce=nonce))
    wait_balance(chain, core["USDTToken"], wallet, plan["baseline"] + amount // 2)
    return {"balance_before": plan["baseline"], "returned": amount // 2}


def three_chains_check(ctx):
    user_check(ctx)
    require((ctx.state_dir / "accept_faucet_batch.json").is_file(), "step 82 must have funded the acceptance users first")


def three_chains_apply(ctx):
    progress = load_progress(ctx, "accept_three_chains")
    documents, public = l1_documents(ctx), public_of(ctx)
    env = driver_env(ctx, documents)
    user = ensure_user(ctx, env, "u00")
    with ac.gateway_tunnel(ctx):
        for chain in release_lock.CHAINS:
            leg = progress.setdefault("chains", {}).setdefault(chain, {})
            if leg.get("settled"):
                continue
            core = documents[chain]["core"]
            if leg.get("window") == "opened":
                raise ValueError(f"{chain}: an earlier window did not finish; read the pending deposit count and reconcile, never repeat blindly")
            if "deposit_index" not in leg:
                prepare_wallet(env, documents, chain, DEPOSIT_AMOUNT)
                leg.update(deposit_index=ac.read_count(chain, core["Bridge"], ac.PENDING_COUNT), window="opened")
                write_state(ctx, "accept_three_chains", progress)
                ac.run_window(ctx, chain, documents, env["E2E_WALLET_ADDRESS"],
                              lambda: deposit_once(ctx, env, documents, chain, user, "main", DEPOSIT_AMOUNT))
                leg["window"] = "closed"
                write_state(ctx, "accept_three_chains", progress)
            leg["settled"] = settle_amount(ctx, env, documents, chain, user, "main", DEPOSIT_AMOUNT, leg["deposit_index"], progress, leg)
            write_state(ctx, "accept_three_chains", progress)
    progress.update(skipped=SKIPPED, unverified=UNVERIFIED)
    write_state(ctx, "accept_three_chains", progress)


def three_chains_settled(ctx):
    state = recorded(ctx, "accept_three_chains")
    require(sorted(state.get("chains", {})) == sorted(release_lock.CHAINS) and all(row.get("settled") for row in state["chains"].values()),
            "every chain must have settled a deposit and a withdrawal")
    return state


def three_chains_verify(ctx):
    state = three_chains_settled(ctx)
    left = ac.unpaused_chains(ctx)
    require(not left, "deposits are open on " + ", ".join(left))
    return {"chains": {chain: row["settled"] for chain, row in state["chains"].items()}, "skipped": SKIPPED, "unverified": UNVERIFIED}


# ---- step 83: five withdrawals in one batch ----

def relayer_lines(ctx, pattern, since):
    host = release_lock.read_document(ctx.release_dir / "release.json")["core_placement"]["relayer"]
    return journal(ctx, host, ctx.lock["units"]["relayer"], pattern, since).strip().splitlines()


def five_check(ctx):
    user_check(ctx)
    require((ctx.state_dir / "accept_faucet_batch.json").is_file(), "step 82 must have funded the acceptance users first")


def five_apply(ctx):
    progress = load_progress(ctx, "accept_five_withdrawals")
    if progress.get("settled"):
        return
    documents = l1_documents(ctx)
    env = driver_env(ctx, documents)
    users = [ensure_user(ctx, env, name) for name in FIVE_USERS]
    chain, core = "sepolia", documents["sepolia"]["core"]
    started = progress.setdefault("started", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
    with ac.gateway_tunnel(ctx):
        if progress.get("window") == "opened":
            raise ValueError("an earlier five-deposit window did not finish; read the pending deposit count and reconcile, never repeat blindly")
        if "first_index" not in progress:
            prepare_wallet(env, documents, chain, FIVE_DEPOSIT * len(users))
            progress.update(first_index=ac.read_count(chain, core["Bridge"], ac.PENDING_COUNT), window="opened")
            write_state(ctx, "accept_five_withdrawals", progress)
            ac.run_window(ctx, chain, documents, env["E2E_WALLET_ADDRESS"], lambda: [
                deposit_once(ctx, env, documents, chain, user, f"five-{user['name']}", FIVE_DEPOSIT) for user in users])
            progress["window"] = "closed"
            write_state(ctx, "accept_five_withdrawals", progress)
        wait_proved(chain, core["Bridge"], progress["first_index"] + len(users) - 1)
        for offset, user in enumerate(users):
            claim_recorded(ctx, "accept_five_withdrawals", progress, progress, user["name"], lambda user=user, offset=offset: claim_one(
                ctx, env, chain, user, f"five-{user['name']}", work_dir(ctx) / "deposits" / f"{chain}-five-{user['name']}.result.json",
                progress["first_index"] + offset, FIVE_DEPOSIT))
        wallet = env["E2E_WALLET_ADDRESS"]
        plan = withdrawal_plan(ctx, "accept_five_withdrawals", progress, progress, [user["name"] for user in users],
                               lambda: ac.read_balance(chain, core["USDTToken"], wallet))
        by_name = {user["name"]: user for user in users}
        send_withdrawals(ctx, "accept_five_withdrawals", progress, plan, lambda key, nonce: withdraw_one(
            ctx, env, documents, chain, by_name[key], f"five-{key}", core["USDTToken"], FIVE_WITHDRAW, nonce=nonce))
        wait_balance(chain, core["USDTToken"], wallet, plan["baseline"] + FIVE_WITHDRAW * len(users))
    batch = relayer_lines(ctx, "batch_append_withdrawals_5", started)
    require(batch, "the Relayer never resolved batch_append_withdrawals_5 for these withdrawals")
    quarantined = relayer_lines(ctx, "quarantining withdrawal", started)
    require(not quarantined, f"the Relayer logged {len(quarantined)} quarantining withdrawal line(s) since the five withdrawals began")
    progress["settled"] = {"returned": FIVE_WITHDRAW * len(users), "batch_5_lines": len(batch), "quarantine_lines": 0}
    write_state(ctx, "accept_five_withdrawals", progress)


def five_verify(ctx):
    state = recorded(ctx, "accept_five_withdrawals")
    require(state.get("settled") and state["settled"]["batch_5_lines"] > 0, "the five-withdrawal batch was not recorded")
    require(state["settled"].get("quarantine_lines") == 0, "a quarantine line was recorded for the five withdrawals")
    return state["settled"]


# ---- step 87: a PSY withdrawal with the new address ----

def psy_check(ctx):
    user_check(ctx)
    require((ctx.state_dir / "accept_faucet_batch.json").is_file(), "step 82 must have funded the acceptance users first")


def psy_apply(ctx):
    progress = load_progress(ctx, "accept_psy_withdrawal")
    if progress.get("settled"):
        return
    documents = l1_documents(ctx)
    env = driver_env(ctx, documents)
    user, chain = ensure_user(ctx, env, "u00"), "sepolia"
    psy = documents[chain]["core"]["PsyToken"]
    started = progress.setdefault("started", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
    wallet = env["E2E_WALLET_ADDRESS"]
    with ac.gateway_tunnel(ctx):
        plan = withdrawal_plan(ctx, "accept_psy_withdrawal", progress, progress, ["psy"], lambda: ac.read_balance(chain, psy, wallet))
        send_withdrawals(ctx, "accept_psy_withdrawal", progress, plan, lambda key, nonce: withdraw_one(
            ctx, env, documents, chain, user, "psy", psy, PSY_WITHDRAW_AMOUNT, contract_id=0, nonce=nonce))
        wait_balance(chain, psy, wallet, plan["baseline"] + PSY_WITHDRAW_AMOUNT)
    quarantined = relayer_lines(ctx, "quarantining withdrawal", started)
    require(not quarantined, f"the Relayer logged {len(quarantined)} quarantining withdrawal line(s) since the PSY withdrawal began")
    progress["settled"] = {"asset": "PSY", "amount": PSY_WITHDRAW_AMOUNT, "address_from_documents": psy.lower(), "quarantine_lines": 0}
    write_state(ctx, "accept_psy_withdrawal", progress)


def psy_verify(ctx):
    state = recorded(ctx, "accept_psy_withdrawal")
    require(state.get("settled"), "the PSY withdrawal did not settle on L1")
    require(state["settled"].get("quarantine_lines") == 0, "a quarantine line was recorded for the PSY withdrawal")
    return state["settled"]


# ---- step 86: open deposits ----

def open_check(ctx):
    require_frontends_current(ctx)
    prepare.check_tool_hash(ctx, "admin_pause.py")
    # Opening needs every acceptance step to have finished, not merely to have written progress.
    for verify in (entrypoints_verify, p2p_verify, faucet_verify, five_verify, three_chains_settled, psy_verify):
        verify(ctx)


def open_apply(ctx):
    if os.environ.get(CONFIRM_VARIABLE) != "1":
        raise OperatorPending("local", f"{CONFIRM_VARIABLE}=1 bash deploy/multi-chain/gcp/deploy_all.sh --only 86",
                              str(ctx.state_dir / "open_deposits.json"))
    opened = {}
    for chain in release_lock.CHAINS:
        if chain in ac.unpaused_chains(ctx):
            opened[chain] = {"already_open": True}
            continue
        report = ac.run_admin(ctx, chain, 0, True)
        require(report.get("flags") == [ac.OPEN] * 3, f"{chain}: the unpause was not read back as open")
        opened[chain] = {"hash": report["hash"], "gas_used": report["gasUsed"]}
    write_state(ctx, "open_deposits", {"lock_sha256": ctx.lock_sha256, "chains": opened})


def open_verify(ctx):
    state = recorded(ctx, "open_deposits")
    still_paused = [chain for chain in release_lock.CHAINS if chain not in ac.unpaused_chains(ctx)]
    require(not still_paused, "deposits are still paused on " + ", ".join(still_paused))
    return {"chains": state["chains"]}


ACCEPT_STEPS = {
    "accept_entrypoints": Step("accept_entrypoints", entrypoints_check, entrypoints_apply, entrypoints_verify, cutover=False),
    "accept_p2p_rotation": Step("accept_p2p_rotation", p2p_check, p2p_apply, p2p_verify, cutover=False),
    "accept_faucet_batch": Step("accept_faucet_batch", faucet_check, faucet_apply, faucet_verify, cutover=False),
    "accept_five_withdrawals": Step("accept_five_withdrawals", five_check, five_apply, five_verify, cutover=False),
    "accept_three_chains": Step("accept_three_chains", three_chains_check, three_chains_apply, three_chains_verify, cutover=False),
    "accept_psy_withdrawal": Step("accept_psy_withdrawal", psy_check, psy_apply, psy_verify, cutover=False),
    "open_deposits": Step("open_deposits", open_check, open_apply, open_verify, cutover=False),
}
