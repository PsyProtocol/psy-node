#!/usr/bin/env bash
set -euo pipefail

STAGED_ROOT="${STAGED_ROOT:-$HOME/parth-performance-monitor-staged}"
OPS_READ_USER="${OPS_READ_USER:-psy}"
BINARY="$STAGED_ROOT/parth-performance-monitor"
UNIT="$STAGED_ROOT/parth-performance-monitor@.service"
ENV_FILE="$STAGED_ROOT/prove-proxy.env"

for path in "$BINARY" "$UNIT" "$ENV_FILE"; do
  [ -s "$path" ] || {
    echo "missing staged monitor file: $path" >&2
    exit 1
  }
done

sudo install -d -o root -g root -m 0755 \
  /etc/parth \
  /var/lib/parth-performance-monitor
sudo install -d -o root -g root -m 0750 \
  /var/lib/parth-performance-monitor/prove-proxy
sudo install -o root -g root -m 0755 \
  "$BINARY" /usr/local/bin/parth-perf-monitor
sudo install -o root -g root -m 0644 \
  "$UNIT" /etc/systemd/system/parth-performance-monitor@.service
sudo install -o root -g root -m 0640 \
  "$ENV_FILE" /etc/parth/performance-monitor-prove-proxy.env
if ! sudo test -e /etc/parth/performance-monitor-alerts.env; then
  printf '%s\n' \
    '# Optional secret, managed manually:' \
    '# PARTH_PERF_PAGERDUTY_ROUTING_KEY=replace-me' \
    '# PARTH_PERF_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/replace-me' |
    sudo tee /etc/parth/performance-monitor-alerts.env >/dev/null
  sudo chmod 0600 /etc/parth/performance-monitor-alerts.env
fi

if id -u "$OPS_READ_USER" >/dev/null 2>&1; then
  sudo chgrp "$OPS_READ_USER" /var/lib/parth-performance-monitor/prove-proxy
  sudo chmod 2750 /var/lib/parth-performance-monitor/prove-proxy
fi

sudo systemctl daemon-reload
sudo systemctl enable parth-performance-monitor@prove-proxy.service
sudo systemctl restart parth-performance-monitor@prove-proxy.service
sleep 7
sudo systemctl status \
  parth-performance-monitor@prove-proxy.service \
  --no-pager --full -n 40
sudo /usr/local/bin/parth-perf-monitor report 15m
