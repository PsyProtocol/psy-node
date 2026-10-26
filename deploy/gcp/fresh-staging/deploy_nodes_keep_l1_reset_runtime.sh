#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Recover/redeploy staging runtime while preserving durable chain state:
# - preserve Sepolia L1 contracts
# - preserve Scylla L2 checkpoint/state DB
# - preserve Postgres/psy-services/indexer DB
# - reset node release/runtime files and transient Redis/NATS queues
#
# This is intended for cases where the chain is stuck on transient queue/temp-db
# state, but L1 contracts and L2 DB must keep their existing roots/cursors.
if [ "${CONFIRM_REDEPLOY_NODES_KEEP_L1:-0}" != "1" ]; then
  cat >&2 <<'EOF'
This redeploy preserves Sepolia L1 contracts and durable L2/Postgres state, but
clears transient Redis/NATS runtime state.

Set CONFIRM_REDEPLOY_NODES_KEEP_L1=1 to continue.
EOF
  exit 1
fi

# shellcheck source=_common.sh
source "$SCRIPT_DIR/_common.sh"

log_step "clearing transient Redis state on ${REDIS_VM_NAME:-gcp-redis}"
remote_sudo "${REDIS_VM_NAME:-gcp-redis}" '
set -e
docker rm -f valkey-server >/dev/null 2>&1 || true
rm -rf /var/lib/parth/redis
'

log_step "clearing transient NATS state on ${NATS_VM_NAME:-gcp-nats}"
remote_sudo "${NATS_VM_NAME:-gcp-nats}" '
set -e
systemctl disable --now parth-nats-monitor.timer parth-nats-monitor.service >/dev/null 2>&1 || true
docker rm -f nats-server >/dev/null 2>&1 || true
rm -rf /var/lib/parth/nats /var/log/parth/nats-monitor
rm -f /etc/parth/nats-monitor.env
'

if [ "${NATS_MONITOR_ENABLED:-1}" = "1" ]; then
  monitor_upload_host="${NATS_MONITOR_UPLOAD_HOST_VM:-${PARTH_BUNDLE_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}}"
  monitor_upload_root="${NATS_MONITOR_UPLOAD_ROOT:-/var/lib/parth/monitoring-uploads}"
  monitor_upload_nats_q="$(printf '%q' "${monitor_upload_root%/}/nats")"

  log_step "clearing uploaded NATS monitor snapshots on ${monitor_upload_host}"
  remote_sudo "$monitor_upload_host" "
set -e
rm -rf $monitor_upload_nats_q
"
fi

mapfile -t runtime_hosts < <(deployment_runtime_hosts | unique_hosts)

for host in "${runtime_hosts[@]}"; do
  log_step "clearing Parth release/env/runtime state on ${host}; preserving checkpoint backups"
  remote_sudo "$host" '
set -e
systemctl list-units --all --plain --no-legend "parth-*.service" | awk "{ print \$1 }" | xargs -r systemctl stop || true
rm -rf \
  /opt/parth/releases \
  /opt/parth/current \
  /tmp/parth-node-bundle.tar.gz \
  /var/lib/parth/indexer-backups \
  /var/lib/parth/bridge-relayer
rm -f /etc/parth/*.env /etc/parth/bridge-relayer.toml
install -d -m 0755 /var/lib/parth /etc/parth
'
done

export CONFIRM_FULL_FRESH_DEPLOY=1
export REGENERATE_GENESIS="${REGENERATE_GENESIS:-0}"
export DEPLOY_ALL_LAST_STEP="${DEPLOY_ALL_LAST_STEP:-18}"

add_skip_step() {
  local step="$1"
  case " ${SKIP_STEPS:-} " in
    *" ${step} "*) ;;
    *) SKIP_STEPS="${SKIP_STEPS:-} ${step}" ;;
  esac
}

# Runtime state was already cleared above without deleting checkpoint backups.
add_skip_step 02

# Do not clear or recreate durable DB/L1 state.
add_skip_step 03
add_skip_step 05
add_skip_step 08
add_skip_step 09
add_skip_step 10
export SKIP_STEPS

exec bash "$SCRIPT_DIR/deploy_all.sh"
