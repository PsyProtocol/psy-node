#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

log_step "clearing Scylla state"
remote_sudo "${SCYLLA_VM_NAME:-gcp-scylla}" '
set -e
docker rm -f scylla-server >/dev/null 2>&1 || true
rm -rf /var/lib/parth/scylla /var/lib/parth/scylla-udev
'

log_step "clearing Redis state"
remote_sudo "${REDIS_VM_NAME:-gcp-redis}" '
set -e
docker rm -f valkey-server >/dev/null 2>&1 || true
# Remove the legacy colocated NATS container when migrating to a dedicated VM.
docker rm -f nats-server >/dev/null 2>&1 || true
rm -rf /var/lib/parth/redis /var/lib/parth/nats
'

log_step "clearing NATS state"
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
  monitor_upload_root_q="$(printf '%q' "$monitor_upload_root")"
  monitor_upload_nats_q="$(printf '%q' "${monitor_upload_root%/}/nats")"

  log_step "clearing uploaded NATS monitor snapshots on ${monitor_upload_host}"
  remote_sudo "$monitor_upload_host" "
set -e
rm -rf $monitor_upload_nats_q
install -d -m 0755 $monitor_upload_root_q
"
fi

log_step "clearing Postgres and Envio state"
remote_sudo "${POSTGRES_VM_NAME:-gcp-postgres}" '
set -e
systemctl stop parth-envio.service >/dev/null 2>&1 || true
docker ps -a --format "{{.Names}}" \
  | grep -E "^(parth-postgres|generated-|graphql-engine|.*hasura.*|.*envio.*)" \
  | xargs -r docker rm -f >/dev/null 2>&1 || true
docker volume ls -q \
  | grep -E "(generated|envio|hasura)" \
  | xargs -r docker volume rm >/dev/null 2>&1 || true
rm -rf \
  /var/lib/parth/postgres \
  /var/lib/parth/envio \
  /opt/parth/postgres-init \
  /opt/parth/envio \
  /tmp/parth-envio-bundle.tar.gz
'

if [ "${CLEAR_L1_LOCAL_STATE:-0}" = "1" ] || { [ "${L1_DEPLOYMENTS_NETWORK:-localhost}" = "localhost" ] && [ "${CHAIN_ID:-31337}" = "31337" ]; }; then
  log_step "clearing Anvil and local L1 contracts state"
  remote_sudo "${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}" '
set -e
systemctl stop parth-anvil.service >/dev/null 2>&1 || true
docker rm -f parth-anvil >/dev/null 2>&1 || true
rm -rf /var/lib/parth/anvil /opt/parth/l1-contracts /tmp/parth-l1-contracts
'
else
  log_step "preserving local L1 deployment artifacts for L1_DEPLOYMENTS_NETWORK=${L1_DEPLOYMENTS_NETWORK:-} CHAIN_ID=${CHAIN_ID:-}; set CLEAR_L1_LOCAL_STATE=1 to remove them"
fi

if [ "${CLEAR_NOSTR_STATE:-0}" = "1" ]; then
  nostr_home="${NOSTR_HOME:-/opt/nostr-relay}"
  nostr_home_q="$(printf '%q' "$nostr_home")"

  log_step "clearing Nostr relay state for the fresh genesis"
  remote_sudo "${NOSTR_VM_NAME:-gcp-nostr}" "
set -e
docker rm -f nostr-relay >/dev/null 2>&1 || true
rm -rf ${nostr_home_q}/data
install -d -m 0755 ${nostr_home_q}/data
chown -R 1000:1000 ${nostr_home_q}/data
"
else
  log_step "preserving Nostr relay state; set CLEAR_NOSTR_STATE=1 for a fresh genesis"
fi
