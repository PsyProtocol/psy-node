#!/usr/bin/env python3
"""A reusable population of users and contracts for driving the local testnet.

The rollback work kept finding defects that only appear under transaction load,
and every one of them was found late because the load was thinner than it
looked.  Two examples worth keeping in mind while reading this file:

  * `deploy-contract` without `--is-deploy` compiles locally and returns
    success without submitting anything.  The load loop ran that way for 1292
    rounds beside a chain whose only contracts were the six from genesis.
  * `simple_mint` and `simple_transfer` never touch the IMT, so three tables
    went unexercised through eight clean rollback runs.

So this harness reports what actually landed rather than what was attempted,
and keeps its population on disk: registering a user costs a proof, and a run
that has to rebuild its users every time is a run nobody repeats.

    workload.py shapes 20        compile 20 distinct contract shapes
    workload.py users 100        register 100 users, keys saved
    workload.py fund             faucet everyone not yet funded
    workload.py deploy 20        20 users each deploy the sample contract
    workload.py run 200          200 random operations against the population

Or as three long-lived processes, which is what the rollback flow uses -- a
chain busy in the ordinary way rather than a batch that runs once and stops:

    workload.py registrar   --every 30    register and fund, forever
    workload.py deployer    --every 120   deploy contracts, forever
    workload.py transferrer --every 20    move tokens between users, forever

They share the ledger and its locked merge lets them write at the same time.
    workload.py status           what the ledger holds

`run` is the one to leave going in the background during rollback testing;
`deploy` is what puts contract rows inside a rollback window.

One thing this harness cannot do: **call** a user-deployed contract.  Circuits
are generated per deployer at deploy time, and the local prove-proxy only holds
the genesis ones, so a call to a deployed id fails with `fn_circuit proving
error: Wire(...) was set twice` -- for the deployer as much as for anyone else.
Deploys still land and still get rolled back, which is what the contract tables
need; contract-state traffic comes from the genesis token instead.
"""

import argparse
import fcntl
import json
import os
import random
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CLI = REPO / "target/release/psy_user_cli"
CFG = REPO / "client_prover/config.json"
SAMPLE_CONTRACT = REPO / "client_prover/psy_cli/psy_user_cli/contract.json"
COMPILER = Path(os.environ.get("PSY_COMPILER_HOME", REPO.parent / "psy-compiler"))
LEDGER = Path(os.environ.get("PSY_WORKLOAD_LEDGER", REPO / ".local-staging/workload/ledger.json"))
FAUCET = os.environ.get("PSY_WORKLOAD_FAUCET", "http://127.0.0.1:9998")

# Realm 0 owns ids below this; realm 1 above.  Recorded per user because a
# transfer between realms exercises a different path from one inside a realm,
# and because only realm-0 users could be used to reach realm 0's tables.
REALM_SPLIT = 1048576

TOKEN_CONTRACT_ID = 0  # the genesis token: withdraw / simple_mint / simple_transfer

# A faucet claim or a mint returns when its end cap is proved, which is before
# the balance it creates can be read.  Spending inside that gap fails on the
# contract's own assertion -- "insufficient balance (left: 0, right: 1)" -- one
# second after the funding reported success.  Everything that spends therefore
# waits for the credit to settle, which is also how a real user behaves.
SETTLE_SECONDS = int(os.environ.get("PSY_WORKLOAD_SETTLE", "120"))

_lock = threading.Lock()
_log_lock = threading.Lock()

# A user may have only one end cap per pending id.  Two operations by the same
# user in flight together fail with "end cap for user_id N at unique_pending_id
# M has already been submitted", which looks like a chain fault and is not one.
_busy = set()

# Merkle-proof rejections seen this run, surfaced at the end rather than left
# in the middle of a thousand lines of progress.
_suspicious = []

# Counters this process has produced but not yet folded into the ledger file.
_delta = {}
_delta_lock = threading.Lock()


def log(msg):
    with _log_lock:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# --------------------------------------------------------------------------
# ledger


def load():
    if LEDGER.exists():
        return json.loads(LEDGER.read_text())
    return {"users": [], "contracts": [], "stats": {}}


def save(state):
    """Merge this process's changes into the ledger under a lock.

    Writing the whole in-memory copy back was wrong as soon as two commands ran
    at once: a long `run` holds the snapshot it loaded at startup and, on every
    save, put it back over whatever `deploy` and `shapes` had added in the
    meantime.  Twelve deploys and six compiled shapes disappeared that way
    while looking like they had succeeded.

    Written through a temporary file as well, because the private keys in here
    cannot be regenerated and a save interrupted halfway would cost the whole
    population.
    """
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    lock = LEDGER.with_suffix(".lock")
    with open(lock, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            disk = json.loads(LEDGER.read_text()) if LEDGER.exists() else {}
            merged = {
                "users": merge_users(disk.get("users", []), state["users"]),
                "contracts": merge_by(disk.get("contracts", []), state["contracts"], "tx"),
                "shapes": sorted(set(disk.get("shapes", [])) | set(state.get("shapes", []))),
                "stats": dict(disk.get("stats", {})),
            }
            with _delta_lock:
                for key, value in _delta.items():
                    merged["stats"][key] = merged["stats"].get(key, 0) + value
                _delta.clear()
            tmp = LEDGER.with_suffix(".tmp")
            tmp.write_text(json.dumps(merged, indent=1))
            tmp.replace(LEDGER)
            state["stats"] = merged["stats"]
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def merge_users(disk, memory):
    """Union by user id, with this process's copy winning for users it touched.

    Flags like `funded` and `minted_at` only ever move forward, so preferring
    the in-memory entry loses nothing another process could have set."""
    by_id = {u["user_id"]: u for u in disk}
    by_id.update({u["user_id"]: u for u in memory})
    return sorted(by_id.values(), key=lambda u: u["user_id"])


def merge_by(disk, memory, key):
    combined = {entry.get(key): entry for entry in disk}
    for entry in memory:
        existing = combined.get(entry.get(key))
        # A contract id filled in by whichever process saw it first must survive.
        if existing and existing.get("contract_id") is not None and entry.get("contract_id") is None:
            continue
        combined[entry.get(key)] = entry
    return list(combined.values())


def record(state, **counts):
    """Count into a per-process delta, applied to the file at save time.

    Adding straight into `state["stats"]` double-counted as soon as the merge
    above started carrying the file's own totals back in."""
    with _delta_lock:
        for key, value in counts.items():
            _delta[key] = _delta.get(key, 0) + value


# --------------------------------------------------------------------------
# CLI


def run_cli(args, timeout=900, want_result=True):
    """Invoke psy_user_cli and return its structured result, or None.

    Every subcommand used here supports --result-file, which is the only
    trustworthy channel: the human-readable output interleaves prover progress
    from several threads and has changed shape more than once.
    """
    result_path = None
    argv = [str(CLI), *args, "--rpc-config", str(CFG)]
    if want_result:
        handle, result_path = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        argv += ["--result-file", result_path]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=REPO)
        if done.returncode != 0:
            reason = last_error(done.stdout + done.stderr)
            return None, reason
        if not want_result:
            return {}, None
        text = Path(result_path).read_text()
        return (json.loads(text) if text.strip() else {}), None
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except json.JSONDecodeError as exc:
        return None, f"unreadable result file: {exc}"
    finally:
        if result_path:
            Path(result_path).unlink(missing_ok=True)


def last_error(output):
    """Pull the most specific line out of a failed run.

    Contract assertions ("insufficient balance") are the interesting failures
    and they are what the harness is usually being asked about, so they win
    over the generic trailing Error line."""
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    for line in reversed(lines):
        if "assertion failed" in line:
            return line[line.index("assertion failed"):][:160]
    for line in reversed(lines):
        if line.startswith("Error:") or "RpcError" in line:
            return line[:160]
    return lines[-1][:160] if lines else "no output"


# --------------------------------------------------------------------------
# operations


def register_one(state):
    key = secrets.token_hex(32)
    result, why = run_cli(["register-user", "--sign-type", "secp256k1", "-p", key])
    if result is None:
        log(f"register failed: {why}")
        record(state, register_failed=1)
        return None
    pub = result.get("public_key_hash")
    if not pub:
        log("register returned no public key hash")
        record(state, register_failed=1)
        return None

    # The id is assigned by the chain and only readable once the registration
    # is included, so this poll is part of registering, not a nicety.
    user_id = None
    for _ in range(30):
        got, _ = run_cli(["get-user-id", "--pub-key", pub])
        if got and got.get("user_id") is not None:
            user_id = int(got["user_id"])
            break
        time.sleep(10)
    if user_id is None:
        log(f"user {pub[:12]} never got an id")
        record(state, register_failed=1)
        return None

    user = {
        "key": key,
        "public_key_hash": pub,
        "user_id": user_id,
        "realm": 0 if user_id < REALM_SPLIT else 1,
        "funded": False,
        "funded_at": 0,
        "minted": False,
        "minted_at": 0,
        "sent_to": [],
    }
    with _lock:
        state["users"].append(user)
        save(state)
    log(f"user {user_id} (realm {user['realm']})")
    record(state, registered=1)
    return user


def fund_one(state, user):
    # The faucet operators are a small fixed set, so parallel claims contend on
    # the *operator's* end cap rather than the recipient's: 41 of 100 claims
    # failed this way in one pass, all of them "stale nonce".
    ok, why = with_retry(lambda: attempt_fund(user), attempts=4, pause=20)
    if ok is None:
        log(f"faucet {user['user_id']}: {why}")
        record(state, fund_failed=1)
        return False
    with _lock:
        user["funded"] = True
        user["funded_at"] = user.get("funded_at") or time.time()
        save(state)
    log(f"funded {user['user_id']} at checkpoint {ok.get('checkpoint_id')}")
    record(state, funded=1)
    return True


def attempt_fund(user):
    import urllib.request

    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "psy_claim_faucet",
        "params": [{"recipient_user_id": user["user_id"],
                    "recipient_public_key": user["public_key_hash"]}],
    }).encode()
    request = urllib.request.Request(FAUCET, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            payload = json.loads(response.read())
    except Exception as exc:  # noqa: BLE001 - the faucet fails in many ways
        return None, str(exc)[:160]
    if "error" in payload:
        return None, str(payload["error"])[:200]
    return payload.get("result", {}), None


# Failures that mean "the chain moved under you, build it again" rather than
# "this transaction is wrong".  A real client retries these; counting them as
# defects would bury the failures that matter under normal contention.  The
# last three appear only while a rollback is in flight -- the client is holding
# a checkpoint the chain has just discarded -- and during rollback testing they
# are the majority of everything that goes wrong.
TRANSIENT = (
    "stale nonce",
    "stale trace anchor",
    "has already been submitted",
    "chain state advanced",
    "rebuild the trace",
    "but current checkpoint is",
    "Global state roots not found",
    "Latest L2 block state not found",
)

# Retried like the rest, but never quietly: this is what a client sees both
# when a rollback discarded the branch its proof was built against *and* when
# a tree is genuinely corrupt.  Dropping it in with the transients would have
# hidden the keyspace that was destroyed once already, so it is counted apart
# and said out loud, and whether it is benign depends on whether a rollback
# was running -- which the harness cannot know and the reader can.
SUSPICIOUS = ("user tree merkle proof verify failed", "merkle proof")


def is_transient(reason):
    text = reason or ""
    return any(marker in text for marker in TRANSIENT) or any(m in text for m in SUSPICIOUS)


def with_retry(action, attempts=3, pause=25):
    """Run `action` until it succeeds or fails for a reason retrying cannot fix."""
    for attempt in range(attempts):
        # `None` is the only failure signal: a successful command may return an
        # empty result object, which is falsy and would otherwise be retried.
        ok, reason = action()
        if ok is None and any(m in (reason or "") for m in SUSPICIOUS):
            log(f"  !! merkle proof rejected: {reason[:120]}")
            _suspicious.append(reason[:200])
        if ok is not None or not is_transient(reason):
            return ok, reason
        if attempt + 1 < attempts:
            time.sleep(pause)
    return ok, reason


def settled(user, field):
    """True once the user's *first* credit of this kind is old enough to spend.

    Deliberately the first and not the latest: a later faucet claim or mint only
    adds to a balance that already works, and keying off the most recent one let
    the periodic faucet claim inside `run` reset the clock on every user it
    touched.  That starved the run -- twenty operations produced two faucet
    claims and eighteen skips."""
    first = user.get(field, 0)
    return bool(first) and time.time() - first >= SETTLE_SECONDS


def attempt_call(user, contract_id, method, inputs, timeout):
    calls = [{"method_name": method, "inputs": inputs, "contract_id": contract_id}]
    handle, path = tempfile.mkstemp(suffix=".json")
    os.close(handle)
    Path(path).write_text(json.dumps(calls))
    try:
        result, why = run_cli(
            ["call", "--sign-type", "secp256k1", "-p", user["key"], "--contract-calls-file", path],
            timeout=timeout,
        )
    finally:
        Path(path).unlink(missing_ok=True)
    return result, why


def call(state, user, contract_id, method, inputs, timeout=900):
    ok, why = with_retry(lambda: attempt_call(user, contract_id, method, inputs, timeout))
    if ok is None:
        log(f"{method} by {user['user_id']}: {why}")
        record(state, **{f"{method}_failed": 1})
        return False
    record(state, **{method: 1})
    return True


def deploy_one(state, user, shape=None):
    result, why = run_cli(
        ["deploy-contract", "--sign-type", "secp256k1", "-p", user["key"],
         "--contract-path", str(shape or SAMPLE_CONTRACT), "--is-deploy"],
        timeout=3600,
    )
    if result is None:
        log(f"deploy by {user['user_id']}: {why}")
        record(state, deploy_failed=1)
        return False
    # The RPC answers with a submission uuid, not a contract id; the id is
    # assigned when the deploy is included.  `deploy` below fills it in from
    # the ids the chain gained, which is best-effort: another driver deploying
    # at the same time contributes ids too, so a `deployer` here can name the
    # wrong user.  That costs nothing for load -- any user may call any
    # contract -- but do not read this field as ownership.
    with _lock:
        state["contracts"].append({
            "tx": result.get("transaction_hash") or result.get("tx_hash"),
            "deployer": user["user_id"],
            "shape": Path(shape).name if shape else SAMPLE_CONTRACT.name,
            "contract_id": None,
        })
        save(state)
    log(f"deploy submitted by {user['user_id']}")
    record(state, deployed=1)
    return True


def withdraw_one(state, user):
    ok, why = with_retry(lambda: attempt_withdraw(user))
    if ok is None:
        log(f"withdraw by {user['user_id']}: {why}")
        record(state, withdraw_failed=1)
        return False
    log(f"withdraw by {user['user_id']} at checkpoint {ok.get('confirmed_checkpoint')}")
    record(state, withdraw=1)
    return True


def attempt_withdraw(user):
    # A fresh nonce per attempt: the nonce is the IMT key, and reusing one that
    # did land would fail on "nonce already used for withdrawal".
    nonce = secrets.token_hex(32)
    return run_cli([
        "withdraw", "--sign-type", "secp256k1", "-p", user["key"],
        "--contract-id", str(TOKEN_CONTRACT_ID),
        "--destination-chain-index", "1",
        "--token-address", "0x0000000000000000000000000000000000000001",
        "--amount", "1000",
        "--recipient", "0x00000000000000000000000000000000000000ff",
        "--nonce", f"0x{nonce}",
    ])


# --------------------------------------------------------------------------
# commands


SHAPE_TEMPLATE = """use std::prelude::*;

#[contract]
#[derive(Storage)]
struct Contract {{
    pub balance: Felt,
{fields}}}

impl ContractRef {{
    #[contract_method]
    pub fn simple_mint_debug(amount: Felt) {{
        let c = ContractRef::new(ContractMetadata::current());
        c.balance += amount;
{writes}    }}
{extra}}}
"""

EXTRA_METHOD = """
    #[contract_method]
    pub fn bump_{index}(amount: Felt) {{
        let c = ContractRef::new(ContractMetadata::current());
        c.balance += amount + {index};
    }}
"""

# The state tree height is ceil_log2(highest slot index a method *writes*),
# floored at 4 -- see derive_state_tree_height.  A large storage array that
# nothing touches contributes nothing, which is why a first attempt varying an
# array from 64 to 131072 slots produced twelve contracts all at height 4.
# These counts are chosen to land on distinct heights above the floor.
SLOT_COUNTS = (1, 20, 40, 80, 160, 320)


def cmd_shapes(state, args):
    """Compile N distinct contracts.

    Two axes are varied because they land in different tables: the storage
    number of slots a method writes sets `contract_state_tree_height` (genesis
    contracts sit at 32, the checked-in sample at 4), and the method count
    changes the function tree.
    Deploying the same source from different users already yields distinct
    contract ids -- this exists so the *shapes* differ too, rather than one
    shape repeated a hundred times.
    """
    dargo = COMPILER / "target/release/dargo"
    std = COMPILER / "psy-std/std.psy"
    if not dargo.exists():
        sys.exit(f"{dargo} is missing; cargo build --release --package dargo in {COMPILER}")
    root = LEDGER.parent / "shapes"
    root.mkdir(parents=True, exist_ok=True)
    built = []
    for index in range(args.count):
        slots = SLOT_COUNTS[index % len(SLOT_COUNTS)]
        methods = ["simple_mint_debug"] + [f"bump_{i}" for i in range(index % 3)]
        package = root / f"shape_{index:03d}"
        (package / "src").mkdir(parents=True, exist_ok=True)
        (package / "Dargo.toml").write_text(
            f'[package]\nname = "shape_{index:03d}"\ntype = "bin"\nauthors = [""]\n'
        )
        extra = "".join(EXTRA_METHOD.format(index=i) for i in range(index % 3))
        fields = "".join(f"    pub f{i}: Felt,\n" for i in range(slots))
        writes = "".join(f"        c.f{i} += amount;\n" for i in range(slots))
        (package / "src/main.psy").write_text(
            SHAPE_TEMPLATE.format(fields=fields, writes=writes, extra=extra)
        )
        done = subprocess.run(
            [str(dargo), "compile", "--contract-name=ContractRef", "--method-names", *methods],
            cwd=package, capture_output=True, text=True,
            env={**os.environ, "DARGO_STD_PATH": str(std), "RUST_LOG": "dargo=error"},
            timeout=1200,
        )
        artifact = package / f"target/shape_{index:03d}.json"
        if done.returncode != 0 or not artifact.exists():
            log(f"shape {index}: compile failed ({last_error(done.stdout + done.stderr)})")
            record(state, shape_failed=1)
            continue
        built.append(str(artifact))
        log(f"shape {index}: {slots} written slots, {len(methods)} methods")
    with _lock:
        state["shapes"] = sorted(set(state.get("shapes", []) + built))
        save(state)
    record(state, shapes_built=len(built))
    report(state)


def cmd_users(state, args):
    log(f"registering {args.count} users at parallelism {args.parallel}")
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        list(pool.map(lambda _: register_one(state), range(args.count)))
    save(state)
    report(state)


def cmd_fund(state, args):
    pending = [u for u in state["users"] if not u["funded"]]
    log(f"funding {len(pending)} users")
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        list(pool.map(lambda u: fund_one(state, u), pending))
    save(state)
    report(state)


def cmd_deploy(state, args):
    # Only funded users can pay for the end cap, and a user deploying twice
    # gives two contracts rather than one, which is fine -- the point is to put
    # contract rows inside rollback windows, not to model ownership.
    eligible = [u for u in state["users"] if u["funded"]]
    if not eligible:
        sys.exit("no funded users; run `fund` first")
    chosen = random.sample(eligible, min(args.count, len(eligible)))
    before = contract_ids_on_chain()
    log(f"{len(chosen)} deploys (chain has {len(before)} contracts)")
    shapes = state.get("shapes") or [None]
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        list(pool.map(lambda u: deploy_one(state, u, random.choice(shapes)), chosen))

    # Wait for the ids to appear.  A deploy that returns success but never
    # lands is exactly the failure this harness exists to make visible, so the
    # wait ends with a count rather than a silent pass.
    deadline = time.time() + 1200
    while time.time() < deadline:
        now = contract_ids_on_chain()
        if len(now - before) >= len(chosen):
            break
        time.sleep(20)
    new = sorted(contract_ids_on_chain() - before)
    log(f"{len(new)} new contract ids on chain: {new}")
    with _lock:
        unassigned = [c for c in state["contracts"] if c["contract_id"] is None]
        for entry, contract_id in zip(unassigned, new):
            entry["contract_id"] = contract_id
        save(state)
    report(state)


def contract_ids_on_chain():
    """Read the contract ids from Scylla.

    The deploy RPC returns a submission uuid and `DeployResult.contract_id` is
    always None, so the chain's own table is the only source for the numeric id
    a later call needs."""
    query = "SELECT obj_id FROM coordinator.contract_leaf_table;"
    try:
        out = subprocess.run(
            ["docker", "exec", "parth-local-scylla", "cqlsh", "-e", query],
            capture_output=True, text=True, timeout=120,
        ).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return set()
    ids = set()
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.isdigit():
            ids.add(int(stripped))
    return ids


def cmd_run(state, args):
    users = [u for u in state["users"] if u["funded"]]
    if not users:
        sys.exit("no funded users; run `users` and `fund` first")
    log(f"{args.rounds} operations over {len(users)} users")

    def one(_):
        user = pick_idle(users)
        if user is None:
            return record(state, skipped_all_busy=1)
        try:
            operate(user)
        finally:
            with _lock:
                _busy.discard(user["user_id"])

    def operate(user):
        choice = random.random()
        # Weighted so every rollback window sees a mix.  `withdraw` is the only
        # operation that writes the IMT and is deliberately frequent despite
        # being the slowest, because nothing else covers those three tables.
        if choice < 0.30:
            if not settled(user, "funded_at"):
                return record(state, skipped_unsettled=1)  # the fee is still settling
            if call(state, user, TOKEN_CONTRACT_ID, "simple_mint", [10_000_000_000]):
                with _lock:
                    user["minted"] = True
                    user["minted_at"] = user.get("minted_at") or time.time()
                    save(state)
        elif choice < 0.50:
            other = random.choice(users)
            if other["user_id"] == user["user_id"]:
                return
            if not settled(user, "minted_at"):
                return record(state, skipped_unsettled=1)
            if call(state, user, TOKEN_CONTRACT_ID, "simple_transfer",
                    [other["user_id"], 1000]):
                with _lock:
                    user["sent_to"].append(other["user_id"])
                    save(state)
        elif choice < 0.62:
            senders = [u for u in users if user["user_id"] in u["sent_to"]]
            if not senders:
                return record(state, skipped_no_sender=1)
            if not settled(user, "funded_at"):
                return record(state, skipped_unsettled=1)
            call(state, user, TOKEN_CONTRACT_ID, "simple_claim",
                 [random.choice(senders)["user_id"]])
        elif choice < 0.88:
            if not settled(user, "minted_at"):
                # withdraw asserts on a token balance only a settled mint gives
                return record(state, skipped_unsettled=1)
            withdraw_one(state, user)
        else:
            fund_one(state, user)

    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        list(pool.map(one, range(args.rounds)))
    save(state)
    report(state)


def pick_idle(users):
    """Take a user with nothing in flight, or None if they are all busy."""
    order = random.sample(users, len(users))
    with _lock:
        for user in order:
            if user["user_id"] not in _busy:
                _busy.add(user["user_id"])
                return user
    return None


def cmd_registrar(state, args):
    """Register a user every so often, forever.

    One of three long-lived processes that share the ledger, which is what the
    rollback flow wants: a chain that looks busy in the ordinary way rather than
    a batch that runs once and stops. They can be started and stopped
    independently, and the ledger's locked merge is what lets them write to it
    at the same time.
    """
    log(f"registering a user every ~{args.every}s; ledger {LEDGER}")
    while True:
        user = register_one(state)
        if user is not None and args.fund:
            # Funded here rather than in a fourth process: an unfunded user can
            # do nothing, so a registrar that leaves them unfunded is producing
            # rows nobody can use.
            fund_one(state, user)
        time.sleep(args.every)


def cmd_deployer(state, args):
    """Deploy a contract from a settled user every so often, forever."""
    log(f"deploying every ~{args.every}s from users that have settled")
    while True:
        state = load()
        shapes = state.get("shapes") or [None]
        ready = [u for u in state["users"] if u["funded"] and settled(u, "funded_at")]
        if not ready:
            log("no settled user yet")
            time.sleep(args.every)
            continue
        user = pick_idle(ready)
        if user is None:
            time.sleep(args.every)
            continue
        try:
            deploy_one(state, user, random.choice(shapes))
        finally:
            with _lock:
                _busy.discard(user["user_id"])
        time.sleep(args.every)


def cmd_transferrer(state, args):
    """Move tokens between users every so often, forever.

    Transfers only. It is the operation that makes a Realm commit state of its
    own, which is what a rollback needs to have anything of a Realm's to undo,
    and one shape of traffic is enough to keep the chain honestly busy.
    """
    log(f"transferring every ~{args.every}s")
    while True:
        state = load()
        ready = [u for u in state["users"] if u["funded"] and settled(u, "funded_at")]
        if len(ready) < 2:
            log(f"only {len(ready)} settled user(s); need two to transfer")
            time.sleep(args.every)
            continue
        sender = pick_idle(ready)
        if sender is None:
            time.sleep(args.every)
            continue
        try:
            # Mint first if this user has never had a balance: transfer asserts
            # on one, and a transferrer that only ever fails is a process that
            # looks alive and does nothing.
            if not sender["minted"]:
                if call(state, sender, TOKEN_CONTRACT_ID, "simple_mint", [10_000_000_000]):
                    with _lock:
                        sender["minted"] = True
                        sender["minted_at"] = sender.get("minted_at") or time.time()
                        save(state)
            elif settled(sender, "minted_at"):
                recipient = random.choice([u for u in ready if u["user_id"] != sender["user_id"]])
                if call(state, sender, TOKEN_CONTRACT_ID, "simple_transfer",
                        [recipient["user_id"], 1000]):
                    with _lock:
                        sender["sent_to"].append(recipient["user_id"])
                        save(state)
        finally:
            with _lock:
                _busy.discard(sender["user_id"])
        time.sleep(args.every)


def cmd_status(state, _args):
    report(state, verbose=True)


def report(state, verbose=False):
    users = state["users"]
    funded = sum(1 for u in users if u["funded"])
    realm0 = sum(1 for u in users if u["realm"] == 0)
    assigned = [c for c in state["contracts"] if c["contract_id"] is not None]
    print()
    print(f"users      {len(users)} ({funded} funded, {realm0} in realm 0, {len(users)-realm0} in realm 1)")
    print(f"contracts  {len(state['contracts'])} submitted, {len(assigned)} with an id on chain")
    print(f"shapes     {len(state.get('shapes', []))} compiled")
    print(f"ledger     {LEDGER}")
    if _suspicious:
        print(f"merkle proof rejections  {len(_suspicious)}"
              f"  (expected while a rollback runs; a defect otherwise)")
    if state["stats"]:
        print("operations")
        for key in sorted(state["stats"]):
            print(f"  {key:<26} {state['stats'][key]}")
    if verbose and assigned:
        print("contract ids", sorted(c["contract_id"] for c in assigned))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--parallel", type=int, default=4,
                        help="concurrent CLI invocations; each one occupies the prover (default 4)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("shapes", help="compile N distinct contract sources")
    p.add_argument("count", type=int)
    p.set_defaults(func=cmd_shapes)

    p = sub.add_parser("users", help="register users and save their keys")
    p.add_argument("count", type=int)
    p.set_defaults(func=cmd_users)

    p = sub.add_parser("fund", help="faucet every user that is not yet funded")
    p.set_defaults(func=cmd_fund)

    p = sub.add_parser("deploy", help="have N funded users each deploy a contract")
    p.add_argument("count", type=int)
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("run", help="random operations against the population")
    p.add_argument("rounds", type=int)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("registrar", help="register (and fund) a user on a loop, forever")
    p.add_argument("--every", type=int, default=30, help="seconds between users (default 30)")
    p.add_argument("--no-fund", dest="fund", action="store_false",
                   help="leave the users unfunded; they can then do nothing")
    p.set_defaults(func=cmd_registrar, fund=True)

    p = sub.add_parser("deployer", help="deploy a contract on a loop, forever")
    p.add_argument("--every", type=int, default=120, help="seconds between deploys (default 120)")
    p.set_defaults(func=cmd_deployer)

    p = sub.add_parser("transferrer", help="move tokens between users on a loop, forever")
    p.add_argument("--every", type=int, default=20, help="seconds between transfers (default 20)")
    p.set_defaults(func=cmd_transferrer)

    p = sub.add_parser("status", help="what the ledger holds")
    p.set_defaults(func=cmd_status)

    args = parser.parse_args()
    if not CLI.exists():
        sys.exit(f"{CLI} is missing; cargo build --release -p psy_user_cli")
    state = load()
    args.func(state, args)


if __name__ == "__main__":
    main()
