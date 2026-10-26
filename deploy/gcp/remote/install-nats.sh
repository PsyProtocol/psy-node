#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io
  systemctl enable --now docker
fi

: "${NATS_IMAGE:=nats:2.11-alpine}"
: "${NATS_CLIENT_PORT:=4222}"
: "${NATS_MONITOR_PORT:=8222}"
: "${NATS_STORE_DIR:=/var/lib/parth/nats/jetstream}"
: "${NATS_MAX_MEMORY_STORE:=4G}"
: "${NATS_MAX_FILE_STORE:=80G}"
: "${NATS_MAX_ACK_PENDING:=200000}"
: "${NATS_JS_MAX_BUFFERED_MSGS:=10000}"
: "${NATS_JS_MAX_BUFFERED_SIZE:=128MB}"
: "${NATS_JS_REQUEST_QUEUE_LIMIT:=10000}"
: "${NATS_MAX_PAYLOAD:=8388608}"
: "${NATS_MAX_PENDING:=67108864}"
: "${NATS_WRITE_DEADLINE:=30s}"
: "${NATS_DOCKER_LOG_MAX_SIZE:=100m}"
: "${NATS_DOCKER_LOG_MAX_FILE:=5}"

docker rm -f nats-server >/dev/null 2>&1 || true
bash /tmp/mount-data-disk.sh
install -d -m 0755 "$NATS_STORE_DIR" /etc/parth/nats

cat >/etc/parth/nats/server.conf <<EOF
server_name: parth-nats
listen: 0.0.0.0:${NATS_CLIENT_PORT}
http: 0.0.0.0:${NATS_MONITOR_PORT}

max_payload: ${NATS_MAX_PAYLOAD}
max_pending: ${NATS_MAX_PENDING}
write_deadline: "${NATS_WRITE_DEADLINE}"

jetstream {
  store_dir: "${NATS_STORE_DIR}"
  max_memory_store: ${NATS_MAX_MEMORY_STORE}
  max_file_store: ${NATS_MAX_FILE_STORE}
  max_buffered_msgs: ${NATS_JS_MAX_BUFFERED_MSGS}
  max_buffered_size: ${NATS_JS_MAX_BUFFERED_SIZE}
  request_queue_limit: ${NATS_JS_REQUEST_QUEUE_LIMIT}
  limits {
    max_ack_pending: ${NATS_MAX_ACK_PENDING}
  }
}
EOF

docker run -d \
  --name nats-server \
  --restart unless-stopped \
  --log-opt "max-size=${NATS_DOCKER_LOG_MAX_SIZE}" \
  --log-opt "max-file=${NATS_DOCKER_LOG_MAX_FILE}" \
  -p "${NATS_CLIENT_PORT}:${NATS_CLIENT_PORT}" \
  -p "${NATS_MONITOR_PORT}:${NATS_MONITOR_PORT}" \
  -v /etc/parth/nats/server.conf:/etc/nats/nats-server.conf:ro \
  -v /var/lib/parth/nats:/var/lib/parth/nats \
  "$NATS_IMAGE" \
  -c /etc/nats/nats-server.conf

docker ps --filter name=nats-server
