#!/usr/bin/env bash
# Bring a chain up and wait until it can actually take transactions.
#
# `stack/up.sh` returns when it has *started* everything, which is earlier than
# useful: the prove-proxy preloads Groth16 keystores for ten minutes or more
# before it listens, and until it does every faucet claim and every transaction
# fails with "Connection refused". Forty of forty claims failed that way once and
# the chain was blamed for it.
#
# So this waits for the two ports a client needs, and then for the chain to be
# producing, before saying the word "ready".
#
#   tests/chain-up.sh [--reset]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
cd "$HERE/.."

: "${PSY_COMPILER_HOME:=$REPO_ROOT/../psy-compiler-for-psy-node}"
export PSY_COMPILER_HOME
# Reading the journal is a correctness dependency of restore, and it can only be
# read for a range that was committed while it was being written. Setting it at
# rollback time is too late.
export PSY_ROLLBACK_VERIFICATION_JOURNAL=1
export PSY_ROLLBACK_COORDINATOR_NO_TABLET_KEYSPACE=coordinator_no_tablet
export LOCAL_STAGING_REALMS="${LOCAL_STAGING_REALMS:-0 1}"
# Passed to the one `up.sh` call rather than exported, and unset otherwise.
# Exported it survives into anything the caller runs next, and a second
# bring-up then wipes a chain nobody asked to wipe -- which is how a frozen
# rollback under investigation was lost.
# `stack/local.env` sets LOCAL_STAGING_RESET=1, so an unqualified `up.sh` wipes
# whatever chain is there. That is reasonable for a stack script whose job is to
# hand you a clean environment, and wrong for one whose job is to bring an
# existing chain back -- twice a chain under investigation was destroyed by a
# bring-up that was only meant to restart a processor.
#
# So this passes the flag explicitly, in both directions, and never leaves the
# choice to a file.
RESET_ENV=(LOCAL_STAGING_RESET=0)
if [ "${1:-}" = "--reset" ]; then
  RESET_ENV=(LOCAL_STAGING_RESET=1)
  say_reset=1
fi

LOGS="${PSY_LOCAL_STAGING_LOGS:-$REPO_ROOT/.local-staging/logs}"
UP_LOG="${PSY_CHAIN_UP_LOG:-/tmp/chain-up.log}"
CQL=(docker exec parth-local-scylla cqlsh -e)

say() { echo "[chain-up] $*"; }
fail() { echo "[chain-up] FAIL: $*" >&2; exit 1; }

wait_for_port() {  # wait_for_port <port> <what> <seconds>
  local waited=0
  until ss -ltn 2>/dev/null | grep -q ":$1 "; do
    sleep 10; waited=$((waited + 10))
    [ "$waited" -lt "$3" ] || fail "$2 never listened on $1 after ${3}s"
  done
  say "$2 is listening on $1 (after ${waited}s)"
}

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

[ -n "${say_reset:-}" ] && say "--reset given: the existing chain will be archived and wiped"
say "starting the stack; full output in $UP_LOG"
setsid nohup env "${RESET_ENV[@]}" bash stack/up.sh > "$UP_LOG" 2>&1 < /dev/null &
stack_pid=$!

# With --reset, wait for the old chain to *go* before waiting for a new one to
# arrive.
#
# `up.sh` runs in the background and its reset happens some way into it, so the
# previous stack is still holding these ports when the waits below start. They
# are satisfied instantly by the chain that is about to be destroyed, this
# script says "ready", and whatever runs next populates a chain that disappears
# underneath it a minute later. That is exactly what happened: a campaign
# registered thirty-six users against a chain at height 851, the wipe landed,
# and every faucet call afterwards was refused by a service that no longer
# existed. The chain was fine; the readiness was a lie.
if [ -n "${say_reset:-}" ]; then
  waited=0
  while ss -ltn 2>/dev/null | grep -q ":1337 "; do
    sleep 5; waited=$((waited + 5))
    [ "$waited" -lt 600 ] || fail "the previous chain still holds 1337 after ${waited}s; \
the reset cannot be observed and anything started now would be built on a chain about to be wiped"
  done
  say "the previous chain is down (after ${waited}s); waiting for the new one"
fi

# The edges come up long before the prover does, so waiting on them first gives
# a useful failure when the stack dies early rather than a ten-minute silence.
wait_for_port 1337 "coordinator edge" 1800
wait_for_port 13380 "realm-0 edge" 600
wait_for_port 13390 "realm-1 edge" 600
wait_for_port 9999 "prove-proxy" 2400
wait_for_port 9998 "faucet" 900

say "waiting for the chain to produce"
waited=0
before=""
while :; do
  now=$(height coordinator)
  if [ -n "$now" ] && [ -n "$before" ] && [ "$now" -gt "$before" ]; then break; fi
  # Said out loud every minute. A wait with nothing to show for it is
  # indistinguishable from a wait that has died, and this one has been both.
  [ $((waited % 60)) -eq 0 ] && say "  still waiting; coordinator at ${now:-unreadable} (${waited}s)"
  before="$now"
  sleep 15; waited=$((waited + 15))
  [ "$waited" -lt 900 ] || fail "the chain is not producing (coordinator at ${now:-unreadable})"
done

# Exit 75 is a processor asking to be restarted after a rollback, and up.sh
# already loops on it. Checking rather than assuming, because a chain whose
# processors are unsupervised stops dead at the first rollback and looks exactly
# like a rollback that failed.
# Exit 75 is a processor asking to be restarted after a rollback, and up.sh
# already loops on it. Checked rather than assumed, because a chain whose
# processors are unsupervised stops dead at the first rollback and looks exactly
# like a rollback that failed.
#
# Given time to become true: the chain can be producing before `up.sh` has
# finished starting the last processor, and counting once at that moment failed
# a chain that was fine a second later.
count_supervised() {
  local n=0 parent
  for pid in $(pgrep -a psy_node_cli 2>/dev/null | grep processor | awk '{print $1}'); do
    parent=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null || true)
    tr '\0' ' ' < "/proc/${parent:-0}/cmdline" 2>/dev/null | grep -q 'ne 75' && n=$((n + 1))
  done
  echo "$n"
}
waited=0
supervised=$(count_supervised)
while [ "$supervised" -lt 3 ]; do
  sleep 10; waited=$((waited + 10))
  supervised=$(count_supervised)
  [ "$waited" -lt 300 ] || fail \
    "only $supervised of 3 processors are under an exit-75 supervisor after ${waited}s; a rollback \
     would stop this chain and look like the rollback's fault"
done
say "$supervised processors are under an exit-75 supervisor"

say "ready: coordinator=$(height coordinator) realm_0=$(height realm_0) realm_1=$(height realm_1)"
say "logs in $LOGS"
