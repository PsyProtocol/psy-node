#!/usr/bin/env bash
set -euo pipefail

bash /tmp/install-docker.sh 2>/dev/null || true
if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io
  systemctl enable --now docker
fi

: "${VALKEY_MAXMEMORY:=24gb}"
: "${VALKEY_MAXMEMORY_POLICY:=noeviction}"
: "${VALKEY_APPENDONLY:=yes}"
: "${VALKEY_APPENDONLY_FSYNC:=everysec}"
: "${VALKEY_AUTO_AOF_REWRITE_PERCENTAGE:=100}"
: "${VALKEY_AUTO_AOF_REWRITE_MIN_SIZE:=64mb}"
: "${VALKEY_OVERCOMMIT_MEMORY:=1}"

cat >/etc/sysctl.d/99-parth-valkey.conf <<EOF
vm.overcommit_memory = ${VALKEY_OVERCOMMIT_MEMORY}
EOF
sysctl -p /etc/sysctl.d/99-parth-valkey.conf

docker rm -f valkey-server >/dev/null 2>&1 || true
bash /tmp/mount-data-disk.sh
install -d -m 0755 /var/lib/parth/redis
docker run -d \
  --name valkey-server \
  --restart unless-stopped \
  -p 6379:6379 \
  -v /var/lib/parth/redis:/data \
  valkey/valkey:latest \
  valkey-server \
    --dir /data \
    --dbfilename dump.rdb \
    --appendonly "$VALKEY_APPENDONLY" \
    --appendfilename appendonly.aof \
    --appendfsync "$VALKEY_APPENDONLY_FSYNC" \
    --no-appendfsync-on-rewrite yes \
    --auto-aof-rewrite-percentage "$VALKEY_AUTO_AOF_REWRITE_PERCENTAGE" \
    --auto-aof-rewrite-min-size "$VALKEY_AUTO_AOF_REWRITE_MIN_SIZE" \
    --maxmemory "$VALKEY_MAXMEMORY" \
    --maxmemory-policy "$VALKEY_MAXMEMORY_POLICY" \
    --save ""

docker ps --filter name=valkey-server
