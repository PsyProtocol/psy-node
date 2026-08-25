#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

NAME="${NATS_VM_NAME:-parth-nats-1}"
provision_vm "$NAME"
run_remote_script "$NAME" "$GCP_DIR/remote/install-nats.sh" \
  "NATS_IMAGE=${NATS_IMAGE:-nats:2.11-alpine}" \
  "NATS_MAX_MEMORY_STORE=${NATS_MAX_MEMORY_STORE:-4G}" \
  "NATS_MAX_FILE_STORE=${NATS_MAX_FILE_STORE:-80G}" \
  "NATS_MAX_ACK_PENDING=${NATS_MAX_ACK_PENDING:-200000}" \
  "NATS_JS_MAX_BUFFERED_MSGS=${NATS_JS_MAX_BUFFERED_MSGS:-10000}" \
  "NATS_JS_MAX_BUFFERED_SIZE=${NATS_JS_MAX_BUFFERED_SIZE:-128MB}" \
  "NATS_JS_REQUEST_QUEUE_LIMIT=${NATS_JS_REQUEST_QUEUE_LIMIT:-10000}" \
  "NATS_MAX_PAYLOAD=${NATS_MAX_PAYLOAD:-8388608}" \
  "NATS_MAX_PENDING=${NATS_MAX_PENDING:-67108864}" \
  "NATS_WRITE_DEADLINE=${NATS_WRITE_DEADLINE:-30s}" \
  "NATS_DOCKER_LOG_MAX_SIZE=${NATS_DOCKER_LOG_MAX_SIZE:-100m}" \
  "NATS_DOCKER_LOG_MAX_FILE=${NATS_DOCKER_LOG_MAX_FILE:-5}"

if [ "${NATS_MONITOR_ENABLED:-1}" = "1" ]; then
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
  run_remote_script "$NAME" "$GCP_DIR/remote/install-nats-monitor.sh" \
    "NATS_MONITOR_UPLOAD_URL=$upload_url" \
    "NATS_MONITOR_UPLOAD_TOKEN=${NATS_MONITOR_UPLOAD_TOKEN:-}" \
    "NATS_MONITOR_LOCAL_DIR=${NATS_MONITOR_LOCAL_DIR:-/var/log/parth/nats-monitor}" \
    "NATS_MONITOR_INTERVAL_SECONDS=${NATS_MONITOR_INTERVAL_SECONDS:-60}" \
    "NATS_MONITOR_RETENTION_MINUTES=${NATS_MONITOR_RETENTION_MINUTES:-10080}" \
    "NATS_MONITOR_NATS_HTTP_PORT=${NATS_MONITOR_NATS_HTTP_PORT:-8222}" \
    "NATS_MONITOR_NATS_PORT=${NATS_MONITOR_NATS_PORT:-4222}"
fi

run_health_check "$NAME" "nats"
