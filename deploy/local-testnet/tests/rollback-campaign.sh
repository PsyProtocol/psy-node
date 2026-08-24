#!/usr/bin/env bash
# One rollback campaign: a fresh chain, a warm-up that has to pass, then
# rollbacks until something breaks -- and then a full stop.
#
# The discipline this encodes is the point of it.  Every rollback matrix run
# before this one died of something the chain had been carrying for hours: a
# second processor left over from an earlier round, a Coordinator parked since
# the previous afternoon, a Realm that had been offline so long it never joined.
# None of those were rollback defects and all of them cost a run.  A campaign
# starts from nothing, proves the chain works *before* touching it, and stops on
# the first thing it cannot explain, so whatever it finds is attributable.
#
# Stopping means stopping.  The chain is left exactly as it is -- processes up,
# database untouched -- because the state at the moment of failure is the
# evidence, and a script that tidies up destroys it.  There is no --continue.
# Fix the defect, then run a new campaign.
#
#   tests/rollback-campaign.sh [--rounds N] [--depth N] [--settle SECONDS]
#
#   --rounds   how many rollbacks to attempt      (default 5)
#   --depth    checkpoints to discard each time   (default 20)
#   --settle   seconds to let the chain run between rollbacks (default 240)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
cd "$REPO_ROOT"

ROUNDS=5
DEPTH=20
SETTLE=240
CRASH_AT=""
CRASH_REALM=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rounds) ROUNDS="$2"; shift 2 ;;
    --depth)  DEPTH="$2";  shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
    # Kill the Realm at a named moment inside the rollback, and then ask the
    # same questions of the chain as an uneventful round does.
    #
    # The dangerous moments are the gaps between doing a thing and recording
    # that it was done: a few milliseconds each, which ordinary running never
    # lands in. Naming them is the only way to test them.
    --crash-at)    CRASH_AT="$2";    shift 2 ;;
    --crash-realm) CRASH_REALM="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

CLI="${PSY_DEV_CLI:-$REPO_ROOT/target/release/psy_dev_cli}"
LOGS="${PSY_LOCAL_STAGING_LOGS:-$REPO_ROOT/.local-staging/logs}"
CQL=(docker exec parth-local-scylla cqlsh -e)
KEYSPACE=coordinator
WORK="$HERE/workload.py"
CAMPAIGN_LOG="${PSY_CAMPAIGN_LOG:-/tmp/rollback-campaign.log}"

say()  { echo "[campaign] $*"; }
step() { echo; echo "[campaign] == $* =="; }

# Stopping is the product, so it says what it saw and where to look, and leaves
# everything running.
halt() {
  echo
  echo "[campaign] ===================== HALTED ====================="
  echo "[campaign] $*"
  echo "[campaign]"
  echo "[campaign] The chain has been left exactly as it is -- that state is the"
  echo "[campaign] evidence.  Nothing was stopped and nothing was cleaned up."
  echo "[campaign]"
  echo "[campaign]   $CLI rollback status"
  echo "[campaign]   tail $LOGS/coordinator-processor.log"
  echo "[campaign]   tail $LOGS/coordinator-worker.log      # Proving failed lives here"
  echo "[campaign]   tail $LOGS/realm-0-processor.log $LOGS/realm-1-processor.log"
  echo "[campaign]"
  echo "[campaign] Fix the defect, then start a new campaign.  Do not resume this one:"
  echo "[campaign] a chain that has already failed once cannot tell you what failed next."
  echo "[campaign] ==================================================="
  exit 1
}

head_now() {
  "${CQL[@]}" "SELECT value FROM $KEYSPACE.u64_singleton_table WHERE obj_id = 1;" 2>/dev/null \
    | sed -n '4p' | tr -d ' '
}
chain_epoch() { "$CLI" rollback status 2>/dev/null | awk '/^chain/{print $3}'; }
realm_commit() {  # realm_commit <realm> <epoch>
  "${CQL[@]}" "SELECT MAX(checkpoint_id) FROM realm_$1_no_tablet.authority_manifest \
               WHERE chain_epoch = $2 ALLOW FILTERING;" 2>/dev/null | sed -n '4p' | tr -d ' '
}
proving_failures() { grep -ac "Proving failed" "$LOGS/coordinator-worker.log" 2>/dev/null || echo 0; }

# How many of an operation the workload has completed, ever.
op_count() {  # op_count <name>
  python3 "$WORK" status 2>/dev/null | awk -v k="$1" '$1==k {print $2}' | head -1
}
contract_count() {
  "${CQL[@]}" "SELECT COUNT(*) FROM $KEYSPACE.contract_leaf_table;" 2>/dev/null \
    | sed -n '4p' | tr -d ' '
}

# The three operations a chain exists to serve, checked by whether they are
# still happening rather than by whether something that implies them is.
#
# "Both Realms are committing" was the old stand-in, and it is not the same
# claim: a Realm commits when it has state of its own, which minting alone
# produces.  A chain came back from a rollback committing on both Realms, at the
# right height, producing blocks -- and refusing every transaction submitted to
# it with "Unique pending ids not found".  Nothing above would have noticed.
transactions_still_work() {  # transactions_still_work <what-for> <ops-before> <contracts-before>
  local what="$1" before="$2" contracts_before="$3"
  local reg_before tx_before waited=0 reg tx con

  reg_before=$(echo "$before" | awk '$1=="registered" {print $2}');      reg_before="${reg_before:-0}"
  tx_before=$(echo "$before" | awk '$1=="simple_transfer" {print $2}');  tx_before="${tx_before:-0}"
  contracts_before="${contracts_before:-0}"

  # Waited for, not sampled once.
  #
  # The three have very different latencies and a deploy is by far the slowest:
  # a rollback discards the ones in flight, the deployer only submits every
  # 150s, and what it submits then has to be gathered, proven and committed.
  # Sampling once at the end of the settle window failed a round where deploys
  # were working perfectly -- nineteen on the chain at the check, thirty-five
  # four minutes later -- and blamed the rollback for it.
  #
  # So each is given time to arrive, and the round only fails if one never does.
  while :; do
    reg=$(op_count registered);        reg="${reg:-0}"
    tx=$(op_count simple_transfer);    tx="${tx:-0}"
    con=$(contract_count);             con="${con:-0}"
    if [ "$reg" -gt "$reg_before" ] && [ "$tx" -gt "$tx_before" ] \
       && [ "$con" -gt "$contracts_before" ]; then
      say "$what: registered $reg_before -> $reg, transfers $tx_before -> $tx, \
contracts on chain $contracts_before -> $con (after ${waited}s)"
      return 0
    fi
    if [ "$waited" -ge "${PSY_CAMPAIGN_TX_WAIT:-900}" ]; then
      say "$what: after ${waited}s -- registered $reg_before -> $reg, transfers \
$tx_before -> $tx, contracts on chain $contracts_before -> $con"
      return 1
    fi
    sleep 30; waited=$((waited + 30))
  done
}

# What "no problems" means.  Used for the warm-up and after every rollback,
# deliberately the same function: a bar that moves between the two would let a
# rollback pass a test the chain never had to pass first.
#
# Heights agreeing is not on the list.  Three participants sitting at one height
# is what a dead chain looks like from outside, and it cost forty minutes once.
healthy() {  # healthy <what-for>
  local what="$1" epoch first second r0 r1 fails_before fails_after

  fails_before=$(proving_failures)
  first=$(head_now)
  [ -n "${first:-}" ] || { say "$what: cannot read the Coordinator's head"; return 1; }
  sleep 60
  second=$(head_now)
  [ -n "${second:-}" ] || { say "$what: cannot read the Coordinator's head"; return 1; }

  # 1. Producing.
  if [ "$second" -le "$first" ]; then
    say "$what: the chain is not producing -- $KEYSPACE sat at $first for 60s"
    return 1
  fi

  # 2. Nothing failing to prove.  A witness nothing can prove stops the chain
  #    while every other signal still reads healthy, so it is checked by whether
  #    the count *grew*, not by whether it is zero.
  fails_after=$(proving_failures)
  if [ "$fails_after" -gt "$fails_before" ]; then
    say "$what: $((fails_after - fails_before)) new proving failure(s) in 60s"
    return 1
  fi

  # 3. Both Realms committing, not merely syncing.  A Realm can follow the chain
  #    perfectly and produce nothing at all, with no error anywhere.
  #    Waited for, not sampled once. A Realm commits when it has transactions of
  #    its own, so how soon it commits after a rollback depends on when traffic
  #    next reaches it -- and after a crash injection, on how long its recovery
  #    took. realm-1 was failed for having committed nothing while its first
  #    commit of the new epoch was at checkpoint 233, forty-seven above the
  #    target: it was slow, not broken, and the round blamed the rollback.
  epoch=$(chain_epoch)
  local waited=0 pending
  while :; do
    pending=""
    for r in 0 1; do
      local own; own=$(realm_commit "$r" "$epoch")
      if [ -z "${own:-}" ] || [ "$own" = "null" ]; then pending="$pending realm-$r"; fi
    done
    [ -z "$pending" ] && break
    if [ "$waited" -ge "${PSY_CAMPAIGN_COMMIT_WAIT:-600}" ]; then
      say "$what:$pending committed nothing in epoch $epoch after ${waited}s"
      return 1
    fi
    sleep 30; waited=$((waited + 30))
  done
  [ "$waited" -gt 0 ] && say "$what: both Realms committing in epoch $epoch (after ${waited}s)"

  #    And still committing, not committed once and stopped. The margin is wide
  #    on purpose -- a Realm with no traffic of its own is quiet, and quiet is
  #    not broken -- so this only catches one that has gone silent for longer
  #    than any traffic pattern explains. realm-1 sat like that for two and a
  #    half hours once, syncing perfectly, with no error anywhere.
  local now; now=$(head_now)
  for r in 0 1; do
    local own; own=$(realm_commit "$r" "$epoch")
    if [ -n "${own:-}" ] && [ "$own" != "null" ] && [ "$own" -lt $((now - 200)) ]; then
      say "$what: realm-$r last committed at $own while the chain is at $now"
      return 1
    fi
  done

  # 4. Nobody parked.  A parked processor skips its whole loop, so anything that
  #    was supposed to notice a rollback never runs.
  for f in coordinator-processor realm-0-processor realm-1-processor; do
    if [ -f "$LOGS/$f.log" ] && tail -400 "$LOGS/$f.log" | grep -aq "parked in Error"; then
      say "$what: $f has parked"
      return 1
    fi
  done

  say "$what: producing ($first -> $second), both Realms committing, nothing parked"
  return 0
}

stop_workload() { pkill -f "workload.py (registrar|deployer|transferrer)" 2>/dev/null || true; }

# --- arming a Realm to die inside the rollback -------------------------------

realm_pids() {  # matched on the program, since `pgrep -f` also matches this script
  pgrep -a psy_node_cli 2>/dev/null \
    | grep "start-realm-processor --realm-id $CRASH_REALM " | awk '{print $1}'
}

# By process group, and confirmed by staying empty: between a child exiting and
# its exit-75 wrapper starting the next one there is a gap with no processor, and
# returning inside it leaves the wrapper alive to spawn a second one. Two
# processors for one Realm both submit, one submission is stale, and the Realm
# parks on an error that reads like a rollback defect.
stop_realm() {
  for p in $(realm_pids); do
    pgid=$(ps -o pgid= -p "$p" 2>/dev/null | tr -d ' ')
    [ -n "${pgid:-}" ] && kill -TERM -"$pgid" 2>/dev/null || true
    kill "$p" 2>/dev/null || true
  done
  local settled=0
  for _ in $(seq 1 60); do
    if [ -z "$(realm_pids)" ]; then
      settled=$((settled + 1)); [ "$settled" -ge 5 ] && return 0
    else
      settled=0
    fi
    sleep 1
  done
  halt "realm-$CRASH_REALM would not stop"
}

# Under the same exit-75 supervisor the stack uses, because the recovery this
# tests ends in exit 75. Started bare it would do the right thing and stay dead.
start_realm() {  # start_realm [crash-point]
  stop_realm
  local point="${1:-}" extra=()
  [ -n "$point" ] && extra=(env "PSY_ROLLBACK_REALM_CRASH_AT=$point")
  local runner='
    while true; do
      "$@"
      code=$?
      if [ "$code" -ne 75 ]; then exit "$code"; fi
      echo "[campaign] realm asked to reload after a rollback; restarting"
    done
  '
  setsid nohup "${extra[@]}" env \
    PSY_ROLLBACK_VERIFICATION_JOURNAL=1 \
    PSY_ROLLBACK_COORDINATOR_NO_TABLET_KEYSPACE=coordinator_no_tablet \
    bash -c "$runner" _ \
    "$REPO_ROOT/target/release/psy_node_cli" start-realm-processor \
      --realm-id "$CRASH_REALM" --realm-sub-id 1 --network local-devnet \
      --db-namespace "realm_$CRASH_REALM" --scylla-db-url 127.0.0.1:9042 \
      --nats-jetstream-url nats://127.0.0.1:4222 --redis-url redis://127.0.0.1:6379 \
      --genesis-data-path "$REPO_ROOT/genesis.json" \
      --checkpoint-backup-path "$REPO_ROOT/.local-staging/checkpoints" \
      --proving-backend plonky2-poseidon-goldilocks \
      --coordinator-api-urls http://127.0.0.1:1337 --verbose \
      >> "$LOGS/realm-$CRASH_REALM-processor.log" 2>&1 < /dev/null &
  for _ in $(seq 1 40); do [ -n "$(realm_pids)" ] && break; sleep 1; done
  [ -n "$(realm_pids)" ] || halt "realm-$CRASH_REALM would not start"
  sleep 3
  local n; n=$(realm_pids | wc -l)
  [ "$n" -eq 1 ] || halt "realm-$CRASH_REALM has $n processors; exactly one was started"
}

crashes_so_far() {
  grep -ac "fault injection" "$LOGS/realm-$CRASH_REALM-processor.log" 2>/dev/null || echo 0
}

exec > >(tee -a "$CAMPAIGN_LOG") 2>&1
say "log: $CAMPAIGN_LOG"

step "1/4  a chain with nothing behind it"
stop_workload

# The stack's own reset takes the database, Redis, NATS and the on-disk
# checkpoint state -- it destroys the docker volumes and archives
# `checkpoints/` -- but it does not know about the workload's ledger, and that
# is chain-coupled state like any other.  It names users by the id the chain
# assigned them, so carrying it into a new chain points every transfer at
# somebody who does not exist: "user never got an id", "insufficient balance",
# a background error rate that looks like the chain misbehaving and is not.
#
# Archived rather than deleted, the way `down.sh` archives the rest, because a
# population that was in the middle of something is worth being able to read.
LEDGER="$REPO_ROOT/.local-staging/workload/ledger.json"
if [ -f "$LEDGER" ]; then
  archive="$REPO_ROOT/.local-staging/reset-archives/$(date -u +%Y%m%dT%H%M%SZ)-workload"
  mkdir -p "$archive"
  mv "$LEDGER" "$archive/ledger.json"
  rm -f "$REPO_ROOT/.local-staging/workload/ledger.lock"
  say "archived the previous chain's workload ledger -> $archive"
fi

"$HERE/chain-up.sh" --reset || halt "the chain would not come up"

step "2/4  a population to transact with"
python3 "$WORK" users 40 || halt "could not register the initial users"
python3 "$WORK" fund     || halt "could not fund the initial users"

# `fund` reports every failure and still exits 0, so the exit code above says
# only that the command ran.  Thirty-six faucet calls were refused one round and
# the campaign carried on to the next step before noticing.  What matters is
# whether anybody actually has money.
funded=$(python3 "$WORK" status 2>/dev/null | sed -n 's/^users .*(\([0-9]*\) funded.*/\1/p')
[ -n "${funded:-}" ] && [ "$funded" -gt 0 ] \
  || halt "the faucet funded nobody (${funded:-unreadable} funded users). \
Check that it is listening on 9998 -- a chain that came up without it looks healthy \
and cannot take a single transaction."
say "$funded users funded"

python3 "$WORK" deploy 8 || halt "could not deploy the initial contracts"
python3 "$WORK" status || true

step "3/4  ordinary traffic, and it has to be healthy before anything is rolled back"
nohup python3 "$WORK" registrar   --every 25  >> "$LOGS/workload-registrar.log"   2>&1 &
nohup python3 "$WORK" transferrer --every 20  >> "$LOGS/workload-transferrer.log" 2>&1 &
nohup python3 "$WORK" deployer    --every 150 >> "$LOGS/workload-deployer.log"    2>&1 &
say "workload started; letting it settle"
sleep 120

# A transfer has to have happened before anything is rolled back.
#
# It is the slowest operation to become possible -- a sender may only transfer
# once its mint is two minutes old -- and it is the one the post-rollback check
# leans on hardest. Without seeing one first, a rollback that broke transfers
# and a chain where transfers never worked look identical afterwards, and the
# rollback gets the blame either way.
waited=0
while :; do
  seen=$(op_count simple_transfer); seen="${seen:-0}"
  [ "$seen" -gt 0 ] 2>/dev/null && break
  sleep 20; waited=$((waited + 20))
  [ "$waited" -lt 900 ] || halt "no transfer completed in ${waited}s of ordinary traffic. \
Nothing has been rolled back yet, so this is not a rollback defect -- but a campaign that \
cannot transfer beforehand cannot tell you whether a rollback broke transferring."
done
say "transfers are working before any rollback ($(op_count simple_transfer) so far, after ${waited}s)"

healthy "warm-up" || halt "the chain was not healthy before any rollback ran. \
Whatever is wrong here is not a rollback defect, and rolling back would only hide it."

for round in $(seq 1 "$ROUNDS"); do
  step "4/4  rollback round $round of $ROUNDS"
  before=$(head_now)
  target=$((before - DEPTH))
  epoch_before=$(chain_epoch)
  ops_before=$(python3 "$WORK" status 2>/dev/null)
  contracts_before=$(contract_count)
  say "head $before, epoch $epoch_before; rolling back to $target"

  if [ -n "$CRASH_AT" ]; then
    crashes_before=$(crashes_so_far)
    say "arming realm-$CRASH_REALM to die at $CRASH_AT"
    start_realm "$CRASH_AT"
    # It has to be caught up to reach the point at all. A Realm still starting
    # when FROZEN is published misses the join and takes the recovery path
    # instead -- a different set of moments, reached silently.
    waited=0
    until [ "$(realm_commit "$CRASH_REALM" "$epoch_before")" != "null" ] || [ $waited -ge 300 ]; do
      sleep 10; waited=$((waited + 10))
    done
    say "realm-$CRASH_REALM is armed and committing again"
  fi

  timeout 1800 "$CLI" rollback to "$target" 2>&1 | grep -aE "RollbackReport|going on without|^done|Error" \
    || halt "round $round: the rollback command failed"

  if [ -n "$CRASH_AT" ]; then
    # Whether it actually died. Silence here would otherwise be read as the
    # point passing, which is how a binary built without the feature reports a
    # clean sweep of eleven crash points it never reached.
    if [ "$(crashes_so_far)" -le "$crashes_before" ]; then
      halt "round $round: realm-$CRASH_REALM never aborted at $CRASH_AT. Either it did not \
reach that point -- it may not have been a participant -- or this binary was built without \
--features rollback-fault-injection, in which case nothing above tested anything."
    fi
    say "realm-$CRASH_REALM aborted at $CRASH_AT; bringing it back to recover on its own"
    start_realm
  fi

  say "waiting ${SETTLE}s for the chain to carry on by itself"
  sleep "$SETTLE"

  healthy "round $round" || halt "round $round: the chain did not come back. \
It was healthy before this rollback ran, so this one is attributable."

  transactions_still_work "round $round" "$ops_before" "$contracts_before" || halt "round $round: the chain is \
producing and both Realms are committing, but it is not accepting the transactions it exists \
to serve. A rollback that leaves the chain unable to register, deploy or transfer has not \
succeeded, however healthy every other signal looks."

  epoch_after=$(chain_epoch)
  if [ "$epoch_after" = "$epoch_before" ]; then
    halt "round $round: the chain epoch is still $epoch_before; the rollback did not take"
  fi
  say "round $round survived: epoch $epoch_before -> $epoch_after, head $(head_now)"
done

echo
say "===================================================="
say "$ROUNDS rollback(s) survived on a chain that was healthy first."
say "The workload is still running; the chain is still up."
say "===================================================="
