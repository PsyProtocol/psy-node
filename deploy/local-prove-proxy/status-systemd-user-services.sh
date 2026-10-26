#!/usr/bin/env bash
set -euo pipefail

systemctl --user status parth-local-prove-proxy.service --no-pager --full || true
systemctl --user status parth-local-prove-proxy-tunnel.service --no-pager --full || true
systemctl --user status parth-local-prove-proxy-tunnel-monitor.timer --no-pager --full || true
