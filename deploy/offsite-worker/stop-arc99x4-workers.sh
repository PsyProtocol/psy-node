#!/usr/bin/env bash
set -euo pipefail

OFFSITE_WORKER_HOST="${OFFSITE_WORKER_HOST:-arc99x4}"
SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
units=(
  parth-offsite-worker@coordinator.service
  parth-offsite-worker@realm-0.service
  parth-offsite-worker@realm-1.service
)

printf -v unit_args ' %q' "${units[@]}"
ssh -tt -F "$SSH_CONFIG_FILE" "$OFFSITE_WORKER_HOST" \
  "sudo systemctl stop${unit_args}"

for unit in "${units[@]}"; do
  state="$(ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_WORKER_HOST" "systemctl is-active $(printf '%q' "$unit")" 2>/dev/null || true)"
  if [ "$state" = "active" ] || [ "$state" = "activating" ]; then
    echo "[offsite-worker] failed to stop $unit on $OFFSITE_WORKER_HOST" >&2
    exit 1
  fi
  echo "[offsite-worker] stopped: $unit"
done
