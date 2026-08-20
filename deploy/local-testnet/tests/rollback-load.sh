#!/usr/bin/env bash
# Rollback acceptance under continuous transaction load.
#
# Runs N rollbacks against a live local testnet and checks, after each one, that
# the chain put itself back together with no intervention.  It exists because
# every one of those checks was learned from a failure that the obvious check
# would have missed:
#
#   heights in step      a Realm can sit at the right height with the wrong
#                        content; being in step is necessary, not sufficient
#   past the old head    recovering to the target and stopping there is the
#                        common failure, and it looks like success
#   merkle proofs        a corrupted tree only shows when the Coordinator next
#                        starts, which is after the round appears to have passed
#   locator conflicts    a Realm that cannot re-commit a rolled-back checkpoint
#                        fails quietly until its next state change
#   processes alive      a node that died is not a node that recovered
#
# It also refuses to start against a chain whose Realms are not committing:
# without that, every round passes and proves nothing, which is how an idle
# chain hid eleven defects for a day.
#
#   tests/rollback-load.sh [rounds]        (default 5)
# `-e` deliberately: without it this script printed "rounds passed" after an
# arithmetic error had skipped every check, which is the exact failure mode the
# checks below exist to catch.  A harness that cannot fail is worse than none.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

ROUNDS="${1:-5}"
KEYSPACE="${PSY_ROLLBACK_LIVE_KEYSPACE:-coordinator}"
LOGS="${PSY_LOCAL_STAGING_LOGS:-$REPO_ROOT/.local-staging/logs}"
CQL=(docker exec parth-local-scylla cqlsh -e)
RECOVER_LIMIT="${PSY_ROLLBACK_RECOVER_SECS:-420}"
GROW_LIMIT="${PSY_ROLLBACK_GROW_SECS:-420}"

height() {  # height <keyspace>
  "${CQL[@]}" "SELECT value FROM $1.u64_singleton_table WHERE obj_id = 1;" 2>/dev/null \
    | sed -n '4p' | tr -d ' '
}
count_in() {  # count_in <log> <pattern>; 0 when absent, and 0 exactly once
  local n
  n=$(grep -c "$2" "$LOGS/$1" 2>/dev/null) || n=0
  echo "${n:-0}"
}
alive() {
  local n
  n=$(ps -eo cmd | grep -c 'psy_node_cli start-') || n=0
  echo "$n"
}

fail() { echo "FAIL: $*"; exit 1; }

echo "== preflight =="
COORD=$(height "$KEYSPACE")
[ -n "$COORD" ] || fail "no chain at $KEYSPACE; bring the stack up first"
echo "chain head: $COORD, node processes: $(alive)"

# A run against Realms that never commit is a run that cannot fail.  Insist on
# evidence that both have state of their own before trusting anything below.
for r in 0 1; do
  changed=$(count_in "realm-$r-processor.log" 'REALM_COMMIT.*Changed')
  echo "realm-$r has recorded $changed state change(s)"
  [ "$changed" -gt 0 ] || fail \
    "realm-$r has never recorded a state change; start tests/txgen.sh and let it run first"
done

for round in $(seq 1 "$ROUNDS"); do
  echo
  echo "== round $round of $ROUNDS =="

  # A rollback cannot reach below the start of the current epoch, so the chain
  # has to have produced past the previous target before the next round has
  # anywhere to go.  Waiting is part of the test, not a workaround.
  before=$(height "$KEYSPACE")
  waited=0
  while [ "$(height "$KEYSPACE")" -lt $((before + 12)) ]; do
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$GROW_LIMIT" ] || fail "the chain stopped producing at $(height "$KEYSPACE")"
  done

  merkle_before=$(count_in coordinator-processor.log 'Failed to verify merkle proof')
  conflict_before=$(( $(count_in realm-0-processor.log 'Conflict { kind: Locator') \
                    + $(count_in realm-1-processor.log 'Conflict { kind: Locator') ))
  head_before=$(height "$KEYSPACE")

  PSY_ROLLBACK_LIVE_KEYSPACE="$KEYSPACE" PSY_ROLLBACK_VERIFICATION_JOURNAL=1 \
    timeout 900 cargo test -p psy_node_scylla --test rollback_acceptance \
    -- --ignored --nocapture > /tmp/rollback-round.log 2>&1 || true
  grep -E "rolling back|finishing|RollbackReport|recorded as|G-W checked|^Error" \
    /tmp/rollback-round.log || true
  grep -q "^test result: ok" /tmp/rollback-round.log \
    || fail "round $round: the rollback itself failed (see /tmp/rollback-round.log)"

  # Recovery is the part no one drives: the Coordinator and both Realms have to
  # notice, undo their share, restart themselves and pass the old head again.
  waited=0
  while :; do
    c=$(height "$KEYSPACE"); r0=$(height realm_0); r1=$(height realm_1)
    if [ -n "$c" ] && [ "$c" = "$r0" ] && [ "$c" = "$r1" ] && [ "$c" -gt "$head_before" ]; then
      echo "recovered past $head_before: all three at $c"
      break
    fi
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$RECOVER_LIMIT" ] || fail \
      "round $round: did not recover within ${RECOVER_LIMIT}s (coordinator=$c realm_0=$r0 realm_1=$r1, was $head_before)"
  done

  merkle_after=$(count_in coordinator-processor.log 'Failed to verify merkle proof')
  conflict_after=$(( $(count_in realm-0-processor.log 'Conflict { kind: Locator') \
                   + $(count_in realm-1-processor.log 'Conflict { kind: Locator') ))
  [ "$merkle_after" = "$merkle_before" ] || fail \
    "round $round: the Coordinator could not verify a merkle proof after the rollback"
  [ "$conflict_after" = "$conflict_before" ] || fail \
    "round $round: a Realm could not re-commit a rolled-back checkpoint"
  [ "$(alive)" -ge 6 ] || fail "round $round: only $(alive) node processes are left"
  echo "round $round: ok"
done

echo
echo "== $ROUNDS rounds passed =="
