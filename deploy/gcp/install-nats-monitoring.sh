#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib/common.sh"

NAME="${NATS_VM_NAME:-gcp-nats}"

if [ "${NATS_MONITOR_ENABLED:-1}" != "1" ]; then
  echo "NATS monitoring is disabled: NATS_MONITOR_ENABLED=${NATS_MONITOR_ENABLED:-}"
  exit 0
fi

upload_host_vm="${NATS_MONITOR_UPLOAD_HOST_VM:-${PARTH_BUNDLE_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}}"
upload_port="${NATS_MONITOR_UPLOAD_PORT:-18090}"
upload_root="${NATS_MONITOR_UPLOAD_ROOT:-/var/lib/parth/monitoring-uploads}"
upload_endpoint="${NATS_MONITOR_UPLOAD_ENDPOINT:-$(ssh_service_endpoint "$upload_host_vm")}"
upload_bind_addr="${NATS_MONITOR_UPLOAD_BIND_ADDR:-$upload_endpoint}"
upload_url="${NATS_MONITOR_UPLOAD_URL:-http://${upload_endpoint}:${upload_port}/nats}"

echo "installing monitoring upload receiver on ${upload_host_vm}: ${upload_bind_addr}:${upload_port} -> ${upload_root}"
provision_vm "$upload_host_vm"
run_remote_script "$upload_host_vm" "$GCP_DIR/remote/install-upload-receiver.sh" \
  "PARTH_UPLOAD_ROOT=$upload_root" \
  "PARTH_UPLOAD_BIND_ADDR=$upload_bind_addr" \
  "PARTH_UPLOAD_PORT=$upload_port" \
  "PARTH_UPLOAD_MAX_BYTES=${NATS_MONITOR_UPLOAD_MAX_BYTES:-16777216}" \
  "PARTH_UPLOAD_TOKEN=${NATS_MONITOR_UPLOAD_TOKEN:-}"

echo "installing NATS performance monitor on ${NAME}; upload target: ${upload_url}"
provision_vm "$NAME"
run_remote_script "$NAME" "$GCP_DIR/remote/install-nats-monitor.sh" \
  "NATS_MONITOR_UPLOAD_URL=$upload_url" \
  "NATS_MONITOR_UPLOAD_TOKEN=${NATS_MONITOR_UPLOAD_TOKEN:-}" \
  "NATS_MONITOR_LOCAL_DIR=${NATS_MONITOR_LOCAL_DIR:-/var/log/parth/nats-monitor}" \
  "NATS_MONITOR_INTERVAL_SECONDS=${NATS_MONITOR_INTERVAL_SECONDS:-60}" \
  "NATS_MONITOR_RETENTION_MINUTES=${NATS_MONITOR_RETENTION_MINUTES:-10080}" \
  "NATS_MONITOR_NATS_HTTP_PORT=${NATS_MONITOR_NATS_HTTP_PORT:-8222}" \
  "NATS_MONITOR_NATS_PORT=${NATS_MONITOR_NATS_PORT:-4222}"

echo "NATS monitoring installed. Latest upload path:"
echo "  ${upload_host_vm}:${upload_root}/nats/<nats-host>/latest.json"
