#!/usr/bin/env bash
# Roll back, let the chain live for a while, roll back again.
#
# Deliberately unhurried, and that is the point. Back-to-back rollbacks produce
# overlapping ranges and give the Realms no time to commit anything of their
# own, so round after round passes over a range with nothing in it -- which
# looks like success and proves nothing. Several of the wrong conclusions drawn
# from this harness came from ranges that were empty for exactly that reason.
#
# Between rollbacks the chain is left alone with its traffic, and what is
# checked is that it came back: the phase returned to Idle, all three keyspaces
# passed the height they were at, and they agree.
#
#   tests/rollback-soak.sh [rounds] [--depth N] [--settle SECONDS]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
cd "$REPO_ROOT"

CLI="${PSY_DEV_CLI:-$REPO_ROOT/target/release/psy_dev_cli}"
ROUNDS="${1:-3}"
DEPTH="${PSY_ROLLBACK_DEPTH:-10}"
SETTLE="${PSY_ROLLBACK_SETTLE:-270}"
RECOVER_LIMIT="${PSY_ROLLBACK_RECOVER_SECS:-600}"
KEYSPACE="${PSY_ROLLBACK_LIVE_KEYSPACE:-coordinator}"
CQL=(docker exec parth-local-scylla cqlsh -e)

[ -x "$CLI" ] || { echo "FAIL: $CLI is missing; cargo build --release -p psy_dev_cli" >&2; exit 1; }

say() { echo "[soak] $*"; }

# Run a G-W check and add what it looked at to the running total.
#
# Immediately after the rollback and *before* waiting for recovery, because the
# answer expires: a row in a table with no version axis has one value, so once
# the chain re-produces the range it holds the new branch's and the question
# cannot be asked. `verify` knows this and skips those rows rather than
# reporting them as wrong, but skipping them is a smaller check -- the window is
# now.
verify_now() {  # verify_now <who> <assert>
  local out
  out=$("$CLI" rollback verify --who "$1" --assert "$2" --head "$rolled_head" \
          --target "$rolled_target" --epoch "$discarded_epoch" 2>&1) || {
    echo "$out" | grep -aE "MISMATCH|Error" | head -5
    fail "round $round: $1 ($2) did not restore what was there before"
  }
  local n
  n=$(echo "$out" | sed -n 's/.*G-W checked \([0-9]*\) key positions.*/\1/p' | head -1)
  local skipped
  skipped=$(echo "$out" | sed -n 's/.*  \([0-9]*\) skipped:.*/\1/p' | head -1)
  say "  $1 ($2): ${n:-0} checked${skipped:+, $skipped skipped}"
  gw_total=$((gw_total + ${n:-0}))
}
fail() { echo "[soak] FAIL: $*" >&2; exit 1; }

status() { "$CLI" rollback status 2>/dev/null; }
head_of() { status | sed -n 's/^chain.*checkpoint \([0-9]*\)/\1/p'; }
phase_of() { status | sed -n 's/^phase *\(.*\)/\1/p' | tr -d ' '; }
# Never fails, because it is read inside `set -e` and a database that hiccups
# once must not end the run. cqlsh exits non-zero on any error and `pipefail`
# carries that out of the pipeline, so an unguarded `now=$(height ...)` kills
# the script *silently* -- no message, no FAIL line, just a log that stops. That
# is exactly how a bring-up appeared to hang for forty minutes while nothing was
# running.
#
# An unreadable height comes back empty, and empty means "not yet" to every
# caller here.
height() {
  local out
  out=$("${CQL[@]}" "SELECT value FROM $1.u64_singleton_table WHERE obj_id = 1;" 2>/dev/null) || return 0
  echo "$out" | sed -n '4p' | tr -d ' '
}
realm_own() {
  local out
  out=$("${CQL[@]}" "SELECT MAX(checkpoint_id) FROM realm_$1_no_tablet.authority_manifest;" \
          2>/dev/null) || return 0
  # `null` is what cqlsh prints for a Realm that has never committed. Left as
  # itself it compares as a string against a number and the round dies on
  # "integer expression expected"; empty is what the callers already handle.
  echo "$out" | sed -n '4p' | tr -d ' ' | grep -v '^null$' || true
}

# A run in which nothing was ever checked proves nothing, however many rounds
# it passed. Only this loop can see that across rounds.
gw_total=0

say "$ROUNDS round(s), $DEPTH checkpoints deep, ${SETTLE}s of ordinary life between them"
[ "$(phase_of)" = "Idle" ] || fail "a rollback is already in flight: $(status | tail -1)"

for round in $(seq 1 "$ROUNDS"); do
  echo
  say "== round $round of $ROUNDS =="

  # Both Realms have to have committed inside the range about to be discarded,
  # or there is nothing of theirs to undo and the round says nothing about them.
  # Waiting for that is part of the test, not a delay before it.
  waited=0
  while :; do
    head=$(head_of)
    floor=$((head - DEPTH))
    own0=$(realm_own 0); own1=$(realm_own 1)
    if [ -n "$head" ] && [ -n "$own0" ] && [ -n "$own1" ] \
       && [ "$own0" -gt "$floor" ] && [ "$own1" -gt "$floor" ]; then
      break
    fi
    sleep 20; waited=$((waited + 20))
    [ "$waited" -lt 900 ] || fail \
      "round $round: realm-0 last committed at ${own0:-never} and realm-1 at ${own1:-never}, \
       both at or below $floor -- the range would hold nothing of theirs. Is the transferrer \
       running?"
  done
  say "realm-0 committed at $own0, realm-1 at $own1, both inside ($floor, $head]"

  head_before=$head
  target=$((head_before - DEPTH))
  "$CLI" rollback to "$target" 2>&1 | grep -aE "rolling back|RollbackReport|^Error" || true
  if [ "$(phase_of)" != "Idle" ]; then
    say "the rollback did not reach Idle; finishing it"
    "$CLI" rollback resume 2>&1 | grep -aE "RollbackReport|^Error" || true
  fi
  [ "$(phase_of)" = "Idle" ] || fail "round $round: still in $(phase_of) after resuming"

  # The range that was actually discarded, from the Coordinator's own record
  # rather than from what was asked for: the head moves between reading it and
  # the executor planning, so the plan legitimately covers more.
  # The range that was actually discarded, from the Coordinator's own record
  # rather than from what was asked for: the head moves between reading it and
  # the executor planning, so the plan legitimately covers more than was typed.
  record=$("${CQL[@]}" "SELECT head, target, previous_epoch FROM \
             ${KEYSPACE}_no_tablet.rollback_event WHERE network_chain_id = 0 LIMIT 1;" \
             2>/dev/null | sed -n '4p') || record=""
  rolled_head=$(echo "$record" | awk -F'|' '{gsub(/ /,"",$1); print $1}')
  rolled_target=$(echo "$record" | awk -F'|' '{gsub(/ /,"",$2); print $2}')
  discarded_epoch=$(echo "$record" | awk -F'|' '{gsub(/ /,"",$3); print $3}')
  [ -n "$rolled_head" ] && [ -n "$rolled_target" ] && [ -n "$discarded_epoch" ] \
    || fail "round $round: could not read the discarded range out of the rollback record"
  say "checking ($rolled_target, $rolled_head] on epoch $discarded_epoch"
  verify_now coordinator manifest
  verify_now 0 manifest
  verify_now 1 manifest

  say "waiting for the chain to come back past $head_before"
  waited=0
  while :; do
    c=$(height coordinator); r0=$(height realm_0); r1=$(height realm_1)
    if [ -n "$c" ] && [ "$c" = "$r0" ] && [ "$c" = "$r1" ] && [ "$c" -gt "$head_before" ]; then
      say "recovered: all three at $c"
      break
    fi
    sleep 15; waited=$((waited + 15))
    [ "$waited" -lt "$RECOVER_LIMIT" ] || fail \
      "round $round: not recovered in ${RECOVER_LIMIT}s (coordinator=$c realm_0=$r0 realm_1=$r1, \
       was $head_before)"
  done

  # The other half, and only now: rows a Realm wrote while syncing are undone by
  # re-fetching from the Coordinator, which is what the recovery above waited
  # for. Asking before it would be asking whether something had happened that
  # had been prevented from happening.
  verify_now 0 resync
  verify_now 1 resync

  if [ "$round" -lt "$ROUNDS" ]; then
    say "letting the chain live for ${SETTLE}s"
    sleep "$SETTLE"
    # Still moving after being left alone, which a chain that recovered just far
    # enough to pass the check above would not be.
    now=$(height coordinator); sleep 30; later=$(height coordinator)
    [ -n "$later" ] && [ "$later" -gt "$now" ] || fail \
      "round $round: the chain stopped at ${now:-?} during the settle period"
    say "still producing: $now -> $later"
  fi
done

echo
[ "$gw_total" -gt 0 ] || fail \
  "$ROUNDS round(s) passed without a single key being checked; the ranges held nothing, so this \
   says nothing about what was restored"

say "== $ROUNDS round(s) passed, $gw_total key positions checked =="
