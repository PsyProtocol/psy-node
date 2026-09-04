#!/usr/bin/env bash
set -euo pipefail

UNIT="${UNIT:-parth-performance-monitor@prove-proxy.service}"
REPORT_WINDOW="${REPORT_WINDOW:-2h}"
DB="${PARTH_PERF_DB:-/var/lib/parth-performance-monitor/prove-proxy/metrics.sqlite3}"

sudo systemctl status "$UNIT" --no-pager --full -n 40
echo
sudo env PARTH_PERF_DB="$DB" \
  /usr/local/bin/parth-perf-monitor report "$REPORT_WINDOW"
echo
sudo du -h "$DB" "$DB-wal" "$DB-shm" 2>/dev/null || true
