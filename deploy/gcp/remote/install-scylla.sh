#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io
  systemctl enable --now docker
fi

: "${SCYLLA_SMP:=4}"
: "${SCYLLA_IMAGE:=scylladb/scylla:latest}"
# Scylla uses available memory aggressively for cache; cap the container so the
# host keeps OS headroom on small staging VMs.
: "${SCYLLA_MEMORY:=28g}"
: "${SCYLLA_DOCKER_MEMORY:=$SCYLLA_MEMORY}"
: "${SCYLLA_COMMITLOG_SYNC:=batch}"
: "${SCYLLA_COMMITLOG_BATCH_WINDOW:=2}"
: "${SCYLLA_COMMITLOG_PERIOD:=10}"

docker rm -f scylla-server >/dev/null 2>&1 || true
bash /tmp/mount-data-disk.sh
install -d -m 0755 /var/lib/parth/scylla /var/lib/parth/scylla/data /var/lib/parth/scylla/commitlog /var/lib/parth/scylla/hints /var/lib/parth/scylla/view_hints /var/lib/parth/scylla-udev
chown -R 999:1000 /var/lib/parth/scylla /var/lib/parth/scylla-udev

docker_args=(
  -d
  --name scylla-server
  --restart unless-stopped
  --cap-add=PERFMON
  -p 9042:9042
  -v /var/lib/parth/scylla:/var/lib/scylla
  -v /var/lib/parth/scylla-udev:/run/udev/data
)

if [ -n "$SCYLLA_DOCKER_MEMORY" ]; then
  docker_args+=(--memory "$SCYLLA_DOCKER_MEMORY")
fi

scylla_args=(
  --smp "$SCYLLA_SMP"
  --developer-mode 1
  --overprovisioned 1
  --experimental-features=lwt
  --commitlog-sync="$SCYLLA_COMMITLOG_SYNC"
  --commitlog-sync-batch-window-in-ms="$SCYLLA_COMMITLOG_BATCH_WINDOW"
  --commitlog-sync-period-in-ms="$SCYLLA_COMMITLOG_PERIOD"
)

docker run "${docker_args[@]}" \
  "$SCYLLA_IMAGE" \
  "${scylla_args[@]}"

docker ps --filter name=scylla-server
