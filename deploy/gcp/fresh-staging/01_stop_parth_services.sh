#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

verify_offsite_stopped() {
  local host="$1" role="$2" command
  local ssh_args=(-o BatchMode=yes -o ConnectTimeout=10)
  if [ -f "$SSH_CONFIG_FILE" ]; then ssh_args=(-F "$SSH_CONFIG_FILE" "${ssh_args[@]}"); fi
  command='set -eu
for unit in '
  if [ "$role" = worker ]; then
    command+='parth-offsite-worker@coordinator.service parth-offsite-worker@realm-0.service parth-offsite-worker@realm-1.service'
  else
    command+='parth-prove-proxy@user.service parth-prove-proxy@system.service parth-offsite-prove-proxy.service'
  fi
  command+='; do
  if [ "$(systemctl show "$unit" -p LoadState --value)" = not-found ]; then continue; fi
  state=$(systemctl show "$unit" -p ActiveState --value)
  pid=$(systemctl show "$unit" -p MainPID --value)
  case "$state:$pid" in inactive:0|failed:0) ;; *) echo "$unit must be stopped by the operator before clearing state" >&2; exit 1 ;; esac
done'
  log_step "verifying operator stopped $role services on $host"
  ssh "${ssh_args[@]}" "$host" "$command" || {
    echo "Run stop-offsite-for-fresh-deploy.sh $role on $host with sudo, then retry step 01" >&2
    exit 1
  }
}
if [ "${DEPLOY_OFFSITE_WORKERS:-0}" = 1 ]; then
  verify_offsite_stopped "${OFFSITE_WORKER_HOST:-arc99x4}" worker
fi
if [ "${DEPLOY_OFFSITE_PROVE_PROXY:-0}" = 1 ]; then
  verify_offsite_stopped "${OFFSITE_PROVE_PROXY_HOST:-arc99x3}" prove
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
