#!/usr/bin/env bash
set -euo pipefail

systemctl --user stop parth-local-coordinator-worker@0.service >/dev/null 2>&1 || true
systemctl --user stop parth-local-coordinator-worker@1.service >/dev/null 2>&1 || true
systemctl --user stop parth-local-coordinator-worker-tunnel.service >/dev/null 2>&1 || true

echo "stopped local coordinator worker services"
