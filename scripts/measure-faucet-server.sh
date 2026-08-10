#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-target/debug/psy_user_cli}"
RPC_CONFIG="${RPC_CONFIG:-psy-genesis/config.json}"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:19998}"
SAMPLES="${SAMPLES:-20}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-2}"
LOG="${LOG:-/tmp/psy-faucet-server-measure.log}"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found or not executable: $BIN" >&2
  echo "build it first, for example: cargo build -p psy_user_cli --bin psy_user_cli" >&2
  exit 1
fi

if [[ ! -f "$RPC_CONFIG" ]]; then
  echo "rpc config not found: $RPC_CONFIG" >&2
  exit 1
fi

echo "starting faucet server measurement"
echo "bin=$BIN"
echo "rpc_config=$RPC_CONFIG"
echo "listen_addr=$LISTEN_ADDR"
echo "samples=$SAMPLES interval_seconds=$INTERVAL_SECONDS"
echo "log=$LOG"

"$BIN" faucet-server \
  --rpc-config "$RPC_CONFIG" \
  --listen-addr "$LISTEN_ADDR" \
  >"$LOG" 2>&1 &

pid="$!"
cleanup() {
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

peak_rss_kib=0

for i in $(seq 1 "$SAMPLES"); do
  sleep "$INTERVAL_SECONDS"

  if ! kill -0 "$pid" 2>/dev/null; then
    echo "faucet server exited before measurement completed" >&2
    echo "recent log:" >&2
    tail -80 "$LOG" >&2 || true
    wait "$pid"
  fi

  rss_kib="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")"
  vmsize_kib="$(awk '/^VmSize:/ {print $2}' "/proc/$pid/status")"
  threads="$(awk '/^Threads:/ {print $2}' "/proc/$pid/status")"
  cpu_pct="$(ps -p "$pid" -o pcpu= | awk '{print $1}')"
  etime="$(ps -p "$pid" -o etime= | awk '{print $1}')"

  if (( rss_kib > peak_rss_kib )); then
    peak_rss_kib="$rss_kib"
  fi

  printf 'sample=%02d pid=%s rss_mib=%.1f vmsize_mib=%.1f threads=%s cpu_pct=%s etime=%s\n' \
    "$i" \
    "$pid" \
    "$(awk -v x="$rss_kib" 'BEGIN {print x / 1024}')" \
    "$(awk -v x="$vmsize_kib" 'BEGIN {print x / 1024}')" \
    "$threads" \
    "$cpu_pct" \
    "$etime"
done

printf 'peak_rss_mib=%.1f\n' "$(awk -v x="$peak_rss_kib" 'BEGIN {print x / 1024}')"
