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
while [ $# -gt 0 ]; do
  case "$1" in
    --rounds) ROUNDS="$2"; shift 2 ;;
    --depth)  DEPTH="$2";  shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
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
  epoch=$(chain_epoch)
  for r in 0 1; do
    local own; own=$(realm_commit "$r" "$epoch")
    if [ -z "${own:-}" ] || [ "$own" = "null" ]; then
      say "$what: realm-$r has committed nothing in epoch $epoch"
      return 1
    fi
    if [ "$own" -lt $((second - 60)) ]; then
      say "$what: realm-$r last committed at $own while the chain is at $second"
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
python3 "$WORK" users 40   || halt "could not register the initial users"
python3 "$WORK" fund       || halt "could not fund the initial users"
python3 "$WORK" deploy 8   || halt "could not deploy the initial contracts"
python3 "$WORK" status || true

step "3/4  ordinary traffic, and it has to be healthy before anything is rolled back"
nohup python3 "$WORK" registrar   --every 25  >> "$LOGS/workload-registrar.log"   2>&1 &
nohup python3 "$WORK" transferrer --every 20  >> "$LOGS/workload-transferrer.log" 2>&1 &
nohup python3 "$WORK" deployer    --every 150 >> "$LOGS/workload-deployer.log"    2>&1 &
say "workload started; letting it settle"
sleep 120
healthy "warm-up" || halt "the chain was not healthy before any rollback ran. \
Whatever is wrong here is not a rollback defect, and rolling back would only hide it."

for round in $(seq 1 "$ROUNDS"); do
  step "4/4  rollback round $round of $ROUNDS"
  before=$(head_now)
  target=$((before - DEPTH))
  epoch_before=$(chain_epoch)
  say "head $before, epoch $epoch_before; rolling back to $target"

  timeout 1800 "$CLI" rollback to "$target" 2>&1 | grep -aE "RollbackReport|going on without|^done|Error" \
    || halt "round $round: the rollback command failed"

  say "waiting ${SETTLE}s for the chain to carry on by itself"
  sleep "$SETTLE"

  healthy "round $round" || halt "round $round: the chain did not come back. \
It was healthy before this rollback ran, so this one is attributable."

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
