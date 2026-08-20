#!/usr/bin/env bash
# Crash a rollback at each phase transition and check the chain can be finished.
#
# A rollback past the archive barrier cannot be abandoned: until it is carried
# to Idle the chain does not produce, so the resume path is not a nicety, it is
# the only way out.  Every crash seen so far has been incidental -- a guard
# firing, a process dying at whatever phase it happened to be in -- which
# leaves most of the state machine's resume path never executed.
#
# For each transition this:
#   1. lets the chain grow so there is something to discard
#   2. runs a rollback with PSY_ROLLBACK_CRASH_AFTER (or _BEFORE) set, and
#      requires that it actually aborted rather than completing
#   3. reads the phase the chain was left in
#   4. runs the rollback again, with no fault injected, to resume it
#   5. waits for all three keyspaces to pass the head they had before
#
# A phase that "passes" without step 2 having crashed proves nothing, so the
# script fails when the injected crash did not happen.
#
#   tests/rollback-crash-matrix.sh [phase ...]     (default: all of them)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

KEYSPACE="${PSY_ROLLBACK_LIVE_KEYSPACE:-coordinator}"
CQL=(docker exec parth-local-scylla cqlsh -e)
GROW_LIMIT="${PSY_ROLLBACK_GROW_SECS:-600}"
RECOVER_LIMIT="${PSY_ROLLBACK_RECOVER_SECS:-600}"
WHEN="${PSY_ROLLBACK_CRASH_WHEN:-AFTER}"
LOG=/tmp/rollback-crash

# In transition order.  StartRollback and CompleteRollback are the ends of the
# sequence and are included deliberately: crashing at the first leaves a request
# with no work behind it, and at the last leaves everything done but the chain
# still not Idle -- the two that look least like a partial rollback.
ALL_PHASES=(
  StartRollback
  BeginRollbackFreeze
  BeginRollbackArchive
  CompleteRollbackArchiveBarrier
  BeginRollbackDelete
  BeginRollbackRestore
  BeginRollbackVerify
  CompleteRollbackRealmBarrier
  CompleteRollback
)
PHASES=("$@")
[ ${#PHASES[@]} -gt 0 ] || PHASES=("${ALL_PHASES[@]}")

height() { "${CQL[@]}" "SELECT value FROM $1.u64_singleton_table WHERE obj_id = 1;" 2>/dev/null \
             | sed -n '4p' | tr -d ' '; }
phase() {
  # The control word is the fourth column of the canonical head; its first byte
  # after the PSYRBCTL magic and version is the phase discriminant.  Printed
  # rather than parsed: this is for the reader, and a wrong guess at the layout
  # would quietly report the wrong phase.
  "${CQL[@]}" "SELECT rollback_control FROM ${KEYSPACE}_no_tablet.coordinator_canonical_head;" \
    2>/dev/null | sed -n '4p' | tr -d ' ' | cut -c1-34
}
fail() { echo "FAIL: $*"; exit 1; }

run_rollback() {  # run_rollback <logfile> [env assignments...]
  local out="$1"; shift
  env "$@" PSY_ROLLBACK_LIVE_KEYSPACE="$KEYSPACE" PSY_ROLLBACK_VERIFICATION_JOURNAL=1 \
    timeout 1200 cargo test -p psy_node_scylla --test rollback_acceptance \
    -- --ignored --nocapture > "$out" 2>&1 || true
}

echo "== crash matrix: ${#PHASES[@]} phases, crashing $WHEN each transition =="
for target in "${PHASES[@]}"; do
  echo
  echo "== $target =="

  before=$(height "$KEYSPACE")
  waited=0
  while [ "$(height "$KEYSPACE")" -lt $((before + 12)) ]; do
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$GROW_LIMIT" ] || fail "$target: the chain stopped producing at $(height "$KEYSPACE")"
  done
  head_before=$(height "$KEYSPACE")

  run_rollback "$LOG-$target-crash.log" "PSY_ROLLBACK_CRASH_${WHEN}=$target"
  if ! grep -q "aborting inside the rollback" "$LOG-$target-crash.log"; then
    # Either the phase was never reached or the hook is not compiled in; both
    # make the rest of this round meaningless.
    fail "$target: the injected crash never fired (see $LOG-$target-crash.log)"
  fi
  left_in=$(phase)
  echo "crashed at $target, chain left in $left_in"

  # A crash at the last transition lands on Idle: the rollback finished, and
  # there is nothing to resume.  Running one anyway starts a *fresh* rollback
  # from the head the finished one left behind, which is the epoch's own start,
  # so its target falls below it -- and the round fails on a range no rollback
  # was ever allowed to ask for.  What is left to check here is recovery, which
  # the loop below does.
  if [ "${left_in#0x505359524243544c010000}" != "$left_in" ]; then
    echo "$target: the rollback completed before the crash; nothing to resume"
  else
    run_rollback "$LOG-$target-resume.log"
    grep -q "^test result: ok" "$LOG-$target-resume.log" \
      || fail "$target: the rollback could not be resumed (see $LOG-$target-resume.log)"
    grep -aE "rolling back|RollbackReport|recorded as|G-W checked" "$LOG-$target-resume.log" || true
  fi

  waited=0
  while :; do
    c=$(height "$KEYSPACE"); r0=$(height realm_0); r1=$(height realm_1)
    if [ -n "$c" ] && [ "$c" = "$r0" ] && [ "$c" = "$r1" ] && [ "$c" -gt "$head_before" ]; then
      echo "$target: recovered past $head_before, all three at $c"
      break
    fi
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$RECOVER_LIMIT" ] || fail \
      "$target: did not recover within ${RECOVER_LIMIT}s (coordinator=$c realm_0=$r0 realm_1=$r1, was $head_before)"
  done
done

echo
echo "== ${#PHASES[@]} phases survived a crash and were resumed =="
