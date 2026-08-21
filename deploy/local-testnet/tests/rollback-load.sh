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

# Hands the Realms back before giving up.  A round that stops them for the G-W
# check and then fails used to exit with no Realm running at all, so the chain
# the failure was meant to be diagnosed on had stopped too.
fail() {
  if [ "${realm_procs_stopped:-0}" -gt 0 ] && [ -n "${PSY_ROLLBACK_REALM_LOOP:-}" ]; then
    for r in 0 1; do
      pgrep -a psy_node_cli 2>/dev/null | grep -q "start-realm-processor --realm-id $r " || \
        setsid nohup bash "$PSY_ROLLBACK_REALM_LOOP" "$r" \
          >> "$LOGS/realm-$r-processor.log" 2>&1 < /dev/null &
    done
    echo "(Realms handed back to $PSY_ROLLBACK_REALM_LOOP)"
  fi
  echo "FAIL: $*"
  exit 1
}

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

# A Realm changes state only when it has transactions, so a single round may
# legitimately have nothing of its own to check.  A whole run with nothing to
# check is a run that proves nothing, and only this loop can tell the difference.
realm_gw_total=0
realm_resync_total=0

# Test mode by default: both halves of the Realm assertion run, and every row a
# Realm touched has to be accounted for.  `PSY_ROLLBACK_REALM_ASSERT_SCOPE=lean`
# runs only the manifest-named half -- the rows the rollback plan is actually
# responsible for -- which is the sensible setting once the mechanism is
# trusted and the run is about something else. It is not the default, because a
# narrower assertion is a choice someone should make on purpose.
ASSERT_SCOPE="${PSY_ROLLBACK_REALM_ASSERT_SCOPE:-strict}"

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

  # The Realms took part in that rollback -- they deleted and restored their own
  # rows -- and until now nothing checked that what they restored is what was
  # there before.  Heights in step, no locator conflicts and a live chain were
  # all this harness asked of them, and none of those can tell a correct restore
  # from a wrong one.
  #
  # The range and the branch come from the Coordinator's own report rather than
  # from the Realm's history: after a rollback the head carries manifests from
  # both branches, so a Realm left to pick for itself would compare against the
  # branch that replaced the discarded range.
  rolled_head=$(sed -n 's/.*RollbackReport { target: [0-9]*, head: \([0-9]*\).*/\1/p' /tmp/rollback-round.log | head -1)
  rolled_target=$(sed -n 's/.*RollbackReport { target: \([0-9]*\),.*/\1/p' /tmp/rollback-round.log | head -1)
  discarded_epoch=$(sed -n 's/.*recorded as epoch [0-9]* (was \([0-9]*\)).*/\1/p' /tmp/rollback-round.log | head -1)
  [ -n "$rolled_head" ] && [ -n "$rolled_target" ] && [ -n "$discarded_epoch" ] \
    || fail "round $round: could not read the range out of the rollback report"

  # The Realms have to be still for this.  The tables that carry a Realm's own
  # rollback -- the pending-id maps, the IMT cursor -- have no version axis, so
  # an as-of read returns whatever is stored *now*, and a Realm that has already
  # resynced a few heights has overwritten exactly the rows being checked. The
  # answer then depends on how fast it restarted, which is how one round passed
  # with 474 key positions and the next failed on eight.
  realm_procs_stopped=0
  for r in 0 1; do
    for p in $(pgrep -a psy_node_cli 2>/dev/null | grep "start-realm-processor --realm-id $r " | awk '{print $1}'); do
      ppid=$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null || true)
      [ -n "${ppid:-}" ] && [ "$ppid" != 1 ] && kill "$ppid" 2>/dev/null || true
      sleep 1; kill "$p" 2>/dev/null || true
      realm_procs_stopped=$((realm_procs_stopped + 1))
    done
  done
  for _ in $(seq 1 40); do
    [ "$(pgrep -a psy_node_cli 2>/dev/null | grep -c 'start-realm-processor')" -eq 0 ] && break
    sleep 1
  done

  for r in 0 1; do
    PSY_ROLLBACK_REALM_KEYSPACE="realm_$r" PSY_ROLLBACK_REALM_SUB_ID=1 \
      PSY_ROLLBACK_VERIFY_ONLY=1 PSY_ROLLBACK_HEAD="$rolled_head" \
      PSY_ROLLBACK_TARGET="$rolled_target" PSY_ROLLBACK_CHAIN_EPOCH="$discarded_epoch" \
      PSY_ROLLBACK_REALM_ID="$r" PSY_ROLLBACK_REALM_ASSERT=manifest \
      timeout 600 cargo test -p psy_node_scylla --test rollback_realm_acceptance \
      -- --ignored --nocapture > "/tmp/rollback-round-realm-$r.log" 2>&1 || true
    grep -q "^test result: ok" "/tmp/rollback-round-realm-$r.log" \
      || fail "round $round: realm-$r did not restore the rows its manifest names (see /tmp/rollback-round-realm-$r.log)"
    checked=$(sed -n 's/.*G-W checked \([0-9]*\) Realm key positions.*/\1/p' "/tmp/rollback-round-realm-$r.log" | head -1)
    echo "realm-$r G-W (manifest-named): ${checked:-0} key positions"
    realm_gw_total=$((realm_gw_total + ${checked:-0}))
  done

  # Back under their supervisors, or the next round finds no Realm at all.
  if [ "$realm_procs_stopped" -gt 0 ]; then
    [ -n "${PSY_ROLLBACK_REALM_LOOP:-}" ] || fail \
      "set PSY_ROLLBACK_REALM_LOOP to the realm supervisor script; the Realms were stopped for \
       the G-W check and there is nothing to start them again with"
    for r in 0 1; do
      setsid nohup bash "$PSY_ROLLBACK_REALM_LOOP" "$r" \
        >> "$LOGS/realm-$r-processor.log" 2>&1 < /dev/null &
    done
    sleep 5
  fi

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

  # The other half, and only now: the rows a Realm wrote while syncing are
  # undone by re-fetching from the Coordinator, which is precisely what the
  # recovery above waited for. Checking them while the Realm was stopped asked
  # whether something had happened that had been deliberately prevented.
  if [ "$ASSERT_SCOPE" = "strict" ]; then
    for r in 0 1; do
      PSY_ROLLBACK_REALM_KEYSPACE="realm_$r" PSY_ROLLBACK_REALM_SUB_ID=1 \
        PSY_ROLLBACK_VERIFY_ONLY=1 PSY_ROLLBACK_HEAD="$rolled_head" \
        PSY_ROLLBACK_TARGET="$rolled_target" PSY_ROLLBACK_CHAIN_EPOCH="$discarded_epoch" \
        PSY_ROLLBACK_REALM_ID="$r" PSY_ROLLBACK_REALM_ASSERT=resync \
        timeout 600 cargo test -p psy_node_scylla --test rollback_realm_acceptance \
        -- --ignored --nocapture > "/tmp/rollback-round-realm-$r-resync.log" 2>&1 || true
      grep -q "^test result: ok" "/tmp/rollback-round-realm-$r-resync.log" \
        || fail "round $round: realm-$r still holds what the discarded branch wrote (see /tmp/rollback-round-realm-$r-resync.log)"
      checked=$(sed -n 's/.*G-W checked \([0-9]*\) Realm key positions.*/\1/p' "/tmp/rollback-round-realm-$r-resync.log" | head -1)
      echo "realm-$r G-W (re-fetched): ${checked:-0} key positions"
      realm_resync_total=$((realm_resync_total + ${checked:-0}))
    done
  fi

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

[ "$realm_gw_total" -gt 0 ] || fail \
  "no Realm key was ever checked across $ROUNDS rounds; the Realms were idle, so nothing here \
   says anything about their restore -- drive transactions and run it again"

echo
echo "== $ROUNDS rounds passed: $realm_gw_total manifest-named and $realm_resync_total \
re-fetched Realm key positions checked ($ASSERT_SCOPE) =="
