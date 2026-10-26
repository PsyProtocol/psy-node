#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${LOG_FILE:-/var/log/parth/wireguard-traffic.jsonl}"
RATE_PER_GIB="${RATE_PER_GIB:-0.085}"
FREE_GIB_PER_MONTH="${FREE_GIB_PER_MONTH:-200}"
DAYS_PER_MONTH="${DAYS_PER_MONTH:-30}"

if [ ! -s "$LOG_FILE" ]; then
  echo "missing traffic log: $LOG_FILE" >&2
  exit 1
fi

awk \
  -v rate="$RATE_PER_GIB" \
  -v free_gib="$FREE_GIB_PER_MONTH" \
  -v days="$DAYS_PER_MONTH" \
  '
  function get_number(line, key, pattern, value) {
    pattern = "\"" key "\":[0-9]+"
    if (match(line, pattern)) {
      value = substr(line, RSTART + length(key) + 3, RLENGTH - length(key) - 3)
      return value + 0
    }
    return ""
  }
  {
    ts = get_number($0, "ts")
    tx = get_number($0, "wg_tx_bytes")
    rx = get_number($0, "wg_rx_bytes")
    if (ts == "" || tx == "" || rx == "") next
    if (!seen || ts < first_ts) {
      first_ts = ts
      first_tx = tx
      first_rx = rx
    }
    if (!seen || ts > last_ts) {
      last_ts = ts
      last_tx = tx
      last_rx = rx
    }
    seen = 1
  }
  END {
    if (!seen || last_ts <= first_ts) {
      print "need at least two samples with increasing timestamps" > "/dev/stderr"
      exit 1
    }
    seconds = last_ts - first_ts
    tx_bytes = last_tx - first_tx
    rx_bytes = last_rx - first_rx
    gib = 1024 * 1024 * 1024
    tx_gib = tx_bytes / gib
    rx_gib = rx_bytes / gib
    tx_gib_per_day = tx_gib * 86400 / seconds
    rx_gib_per_day = rx_gib * 86400 / seconds
    tx_gib_per_month = tx_gib_per_day * days
    billable_gib = tx_gib_per_month - free_gib
    if (billable_gib < 0) billable_gib = 0
    monthly_cost = billable_gib * rate

    printf "window_seconds=%d\n", seconds
    printf "gcp_egress_tx_gib=%.6f\n", tx_gib
    printf "arc_to_gcp_rx_gib=%.6f\n", rx_gib
    printf "gcp_egress_tx_gib_per_day=%.3f\n", tx_gib_per_day
    printf "arc_to_gcp_rx_gib_per_day=%.3f\n", rx_gib_per_day
    printf "estimated_gcp_egress_tx_gib_per_month=%.1f\n", tx_gib_per_month
    printf "free_gib_per_month=%.1f\n", free_gib
    printf "billable_gib_per_month=%.1f\n", billable_gib
    printf "rate_usd_per_gib=%.3f\n", rate
    printf "estimated_monthly_egress_usd=%.2f\n", monthly_cost
  }' "$LOG_FILE"
