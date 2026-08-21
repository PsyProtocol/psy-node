#!/usr/bin/env bash
# Kill a Realm partway through its part of a rollback, and check the chain
# finishes anyway.
#
# The Coordinator-side matrix cannot produce these failures. A Realm has no
# phase transitions of its own: it observes the phases the Coordinator
# publishes and files receipts that let the barriers close. The dangerous
# moments are therefore the *gaps* -- a Realm that dies after observing DELETING
# and before filing its verify receipt owes a receipt nothing will produce.
#
# What that costs changed when I9 was retired. The barrier is a grace window
# now, so the Coordinator excuses the dead Realm after thirty seconds and
# finishes without it: the chain no longer stops, and the question each point
# asks is no longer "does the barrier deadlock" but "does the Realm that missed
# it undo its own share when it comes back". Every point below was written
# against the blocking barrier and only one of them was ever run, so what they
# test now is largely untested.
#
# Needs a binary built with the hooks compiled in:
#
#   cargo build --release -p psy_node_cli --features rollback-fault-injection
#
#   tests/rollback-realm-crash-matrix.sh [point ...]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

REALM="${PSY_ROLLBACK_CRASH_REALM:-0}"
KEYSPACE="${PSY_ROLLBACK_LIVE_KEYSPACE:-coordinator}"
CQL=(docker exec parth-local-scylla cqlsh -e)
CLI="${PSY_DEV_CLI:-$REPO_ROOT/target/release/psy_dev_cli}"
LOGS="${PSY_LOCAL_STAGING_LOGS:-$REPO_ROOT/.local-staging/logs}"
GROW_LIMIT="${PSY_ROLLBACK_GROW_SECS:-600}"
RECOVER_LIMIT="${PSY_ROLLBACK_RECOVER_SECS:-900}"
LOG=/tmp/realm-crash

# In the order a Realm reaches them.  `AfterFreezeReceipt` and
# `AfterArchiveReceipt` are the gaps that matter most: the receipt is filed, the
# Coordinator has counted it, and the participant that owes the *next* one is
# gone.
# Both paths, because both are now live.
#
# A Realm joins at the moment FROZEN is published and files the receipts the
# barriers wait for -- the `Before*`/`After*` points. That path was dead for as
# long as the Realms were left out of the participant set, and every barrier
# sealed on the Coordinator's own receipt; it is real now, and the Coordinator
# genuinely waits.
#
# The `Recover*` points are the other path: a Realm that was down when FROZEN
# was published finds out from the epoch change and undoes its share on the next
# start, with no barrier protecting it.
#
# The gaps are what matter. A Realm that dies after observing a phase and before
# filing the receipt it owes leaves a barrier that can never close, and no
# Coordinator-side crash can produce that.
ALL_POINTS=(
  BeforeFreezeReceipt
  AfterFreezeReceipt
  BeforeArchive
  AfterArchive
  AfterArchiveReceipt
  BeforeDelete
  BeforeVerifyReceipt
  RecoverBeforeArchive
  RecoverAfterArchive
  RecoverAfterDelete
  RecoverBeforeRestore
)
POINTS=("$@")
[ ${#POINTS[@]} -gt 0 ] || POINTS=("${ALL_POINTS[@]}")

height() { "${CQL[@]}" "SELECT value FROM $1.u64_singleton_table WHERE obj_id = 1;" 2>/dev/null \
             | sed -n '4p' | tr -d ' '; }
fail() { echo "FAIL: $*"; exit 1; }

# Matched on the program, not the arguments: `pgrep -f` also matches the shell
# running this script, so an argument pattern counts one process that is not a
# processor and, worse, kills it.
realm_pids() {
  pgrep -a psy_node_cli 2>/dev/null \
    | grep "start-realm-processor --realm-id $REALM " \
    | awk '{print $1}'
}

stop_realm() {
  for p in $(realm_pids); do
    # The wrapper first: it restarts its child on exit 75, and an abort is not
    # that, but killing the child first races the wrapper's own decision.
    ppid=$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null || true)
    [ -n "${ppid:-}" ] && kill "$ppid" 2>/dev/null || true
    sleep 1
    kill "$p" 2>/dev/null || true
  done
  for _ in $(seq 1 40); do [ -z "$(realm_pids)" ] && return 0; sleep 1; done
  fail "realm-$REALM would not stop"
}

# Under an exit-75 supervisor, exactly as the stack runs it, because the
# recovery paths this matrix exists to test end in exit 75: a Realm that finds
# it was left behind undoes its share and asks to be restarted so its in-memory
# state is rebuilt from the surviving branch. Started bare it would undo its
# share, exit, and stay dead -- and the round would fail on "did not recover"
# about a Realm that did exactly the right thing.
#
# An abort is not exit 75, so a Realm armed to die still dies for good, and the
# wrapper goes with it. That is what the matrix wants: the crash is the event
# under test, the restart afterwards is the test's own doing.
start_realm() {  # start_realm [crash-point]
  local point="${1:-}"
  local extra=()
  [ -n "$point" ] && extra=(env "PSY_ROLLBACK_REALM_CRASH_AT=$point")
  local runner='
    while true; do
      "$@"
      code=$?
      if [ "$code" -ne 75 ]; then exit "$code"; fi
      echo "[realm-crash-matrix] realm asked to reload after a rollback; restarting"
    done
  '
  setsid nohup "${extra[@]}" env \
    PSY_ROLLBACK_VERIFICATION_JOURNAL=1 \
    PSY_ROLLBACK_COORDINATOR_NO_TABLET_KEYSPACE=coordinator_no_tablet \
    bash -c "$runner" _ \
    ./target/release/psy_node_cli start-realm-processor --realm-id "$REALM" --realm-sub-id 1 \
      --network local-devnet --db-namespace "realm_$REALM" --scylla-db-url 127.0.0.1:9042 \
      --nats-jetstream-url nats://127.0.0.1:4222 --redis-url redis://127.0.0.1:6379 \
      --genesis-data-path ./genesis.json --checkpoint-backup-path ./.local-staging/checkpoints \
      --proving-backend plonky2-poseidon-goldilocks --coordinator-api-urls http://127.0.0.1:1337 \
      --verbose >> "$LOGS/realm-$REALM-processor.log" 2>&1 < /dev/null &
  for _ in $(seq 1 40); do [ -n "$(realm_pids)" ] && return 0; sleep 1; done
  fail "realm-$REALM would not start"
}

# A Realm can only join a rollback at the moment FROZEN is published, and only
# if it is running and caught up then.  One that is still starting misses the
# join and takes the recover-afterwards path instead -- a different code path,
# with different crash points, reached silently.  Waiting for it to be level
# with the Coordinator is what makes the crash point under test the one the
# Realm actually reaches.
wait_for_realm_synced() {
  local waited=0
  while :; do
    local c r
    c=$(height "$KEYSPACE"); r=$(height "realm_$REALM")
    [ -n "$c" ] && [ -n "$r" ] && [ "$r" -ge $((c - 1)) ] 2>/dev/null && return 0
    sleep 5; waited=$((waited + 5))
    [ "$waited" -lt 300 ] || fail "realm-$REALM never caught up (coordinator=$c realm=$r)"
  done
}

# Driven through the CLI, which names the Realms as participants. The old test
# driver left `PSY_ROLLBACK_PARTICIPANT_REALMS` unset, so every barrier sealed on
# the Coordinator's own receipt and FROZEN was published and gone in a moment --
# a Realm armed to die at a receipt it was never waited for simply never got
# there, and the round reported "the Realm never aborted" about a Realm that had
# nothing to abort in.
run_rollback() {  # run_rollback <logfile> [target]
  local target="${2:-}"
  if [ -n "$target" ]; then
    timeout 1200 "$CLI" rollback to "$target" > "$1" 2>&1 || true
  else
    timeout 1200 "$CLI" rollback resume > "$1" 2>&1 || true
  fi
}

echo "== realm-$REALM crash matrix: ${#POINTS[@]} points =="
for point in "${POINTS[@]}"; do
  echo
  echo "== $point =="

  before=$(height "$KEYSPACE")
  waited=0
  while [ "$(height "$KEYSPACE")" -lt $((before + 12)) ]; do
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$GROW_LIMIT" ] || fail "$point: the chain stopped producing at $(height "$KEYSPACE")"
  done
  head_before=$(height "$KEYSPACE")

  # A Realm changes state only when it has transactions, so a ten-checkpoint
  # window may hold none of its writes -- and then its recovery returns at the
  # first check, having nothing to undo, and the crash point is never reached.
  # The round would fail on "the Realm never aborted" while nothing was wrong.
  waited=0
  while :; do
    own=$("${CQL[@]}" "SELECT MAX(checkpoint_id) FROM realm_${REALM}_no_tablet.authority_manifest;" \
            2>/dev/null | sed -n '4p' | tr -d ' ')
    now=$(height "$KEYSPACE")
    [ -n "$own" ] && [ -n "$now" ] && [ "$own" -gt $((now - 10)) ] 2>/dev/null && break
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$GROW_LIMIT" ] || fail \
      "$point: realm-$REALM has committed nothing since ${own:-never} while the chain is at \
       ${now:-?}; it needs transactions of its own inside the range about to be discarded"
    head_before=$(height "$KEYSPACE")
  done

  # `grep -c` exits non-zero on no match while still printing 0, so `|| echo 0`
  # yields "0\n0" and every comparison below becomes "integer expected" -- which
  # `if` reads as false, quietly skipping the check that the crash happened at
  # all. A round that cannot fail is worse than no round.
  crashes_before=$(grep -ac "fault injection" "$LOGS/realm-$REALM-processor.log" 2>/dev/null) || crashes_before=0
  stop_realm
  start_realm "$point"
  wait_for_realm_synced

  # The rollback publishes the phases this Realm is waiting on, so it is what
  # walks the Realm into the point it is armed to die at.
  run_rollback "$LOG-$point-rollback.log" "$((head_before - 10))"

  crashes_after=$(grep -ac "fault injection" "$LOGS/realm-$REALM-processor.log" 2>/dev/null) || crashes_after=0
  if [ "$crashes_after" -le "$crashes_before" ]; then
    # Either the Realm never reached the point or the hooks are not compiled in.
    # Both make everything below meaningless.
    fail "$point: the Realm never aborted; was the binary built with --features rollback-fault-injection?"
  fi
  echo "realm-$REALM aborted at $point; chain head $(height "$KEYSPACE")"

  start_realm
  # Resuming is the Coordinator's job, and the restarted Realm rejoins whatever
  # phase is published.  A rollback that had already finished needs no second
  # run; one that is still in flight does.
  run_rollback "$LOG-$point-resume.log"
  grep -aE "finishing the rollback|RollbackReport|G-W checked" "$LOG-$point-resume.log" || true

  waited=0
  while :; do
    c=$(height "$KEYSPACE"); r0=$(height realm_0); r1=$(height realm_1)
    if [ -n "$c" ] && [ "$c" = "$r0" ] && [ "$c" = "$r1" ] && [ "$c" -gt "$head_before" ]; then
      echo "$point: recovered past $head_before, all three at $c"
      break
    fi
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$RECOVER_LIMIT" ] || fail \
      "$point: did not recover within ${RECOVER_LIMIT}s (coordinator=$c realm_0=$r0 realm_1=$r1, was $head_before)"
  done
done

# Hand the Realm back to whatever supervises it normally.  `start_realm` runs
# its own exit-75 loop, which is enough for the matrix but is not the stack's,
# and starting the stack's wrapper on top of a running one is how two processors
# for one Realm end up running at once -- the same hazard as two Coordinators,
# and it happened once already.  So stop first, then hand over.
stop_realm
if [ -n "${PSY_ROLLBACK_REALM_LOOP:-}" ]; then
  setsid nohup bash "$PSY_ROLLBACK_REALM_LOOP" "$REALM" \
    >> "$LOGS/realm-$REALM-processor.log" 2>&1 < /dev/null &
  echo "realm-$REALM handed back to $PSY_ROLLBACK_REALM_LOOP"
else
  start_realm
  echo "realm-$REALM restarted under this script's own exit-75 loop; set \
PSY_ROLLBACK_REALM_LOOP to hand it back to the stack's supervisor instead"
fi

echo
echo "== ${#POINTS[@]} Realm crash points survived =="
