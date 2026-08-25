#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

if [ "${DEPLOY_OFFSITE_WORKERS:-0}" = "1" ]; then
  offsite_host="${OFFSITE_WORKER_HOST:-arc99x4}"
  log_step "stopping offsite workers on ${offsite_host} before clearing shared state"
  offsite_stop_command='
sudo systemctl stop \
  parth-offsite-worker@coordinator.service \
  parth-offsite-worker@realm-0.service \
  parth-offsite-worker@realm-1.service
sudo systemctl reset-failed \
  parth-offsite-worker@coordinator.service \
  parth-offsite-worker@realm-0.service \
  parth-offsite-worker@realm-1.service >/dev/null 2>&1 || true
'
  if [ -f "$SSH_CONFIG_FILE" ]; then
    ssh -tt -F "$SSH_CONFIG_FILE" -o BatchMode=yes "$offsite_host" "$offsite_stop_command"
  else
    ssh -tt -o BatchMode=yes "$offsite_host" "$offsite_stop_command"
  fi
fi

mapfile -t hosts < <(
  {
    deployment_runtime_hosts
    printf '%s\n' "${POSTGRES_VM_NAME:-gcp-postgres}"
  } | unique_hosts
)

for host in "${hosts[@]}"; do
  log_step "stopping parth systemd services on ${host}"
  remote_sudo "$host" '
set -e
units="$(systemctl list-units --all --plain --no-legend "parth-*.service" | awk "{ print \$1 }" || true)"
if [ -n "$units" ]; then
  systemctl stop $units || true
fi
systemctl reset-failed $units >/dev/null 2>&1 || true
'
done
