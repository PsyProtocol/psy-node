#!/usr/bin/env bash
set -euo pipefail

require_pinned_image() {
  [[ "${!1:-}" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] || {
    echo "$1 must be set to an image pinned by digest (name@sha256:...)" >&2
    exit 1
  }
}
require_pinned_image POSTGRES_IMAGE

if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io
  systemctl enable --now docker
fi

: "${POSTGRES_USER:=postgres}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
# docker takes the value from the environment, so it never appears in a command line.
export POSTGRES_PASSWORD
export PGPASSWORD="$POSTGRES_PASSWORD"

docker rm -f parth-postgres >/dev/null 2>&1 || true
bash /tmp/mount-data-disk.sh
install -d -m 0755 /var/lib/parth/postgres /opt/parth/postgres-init
cat >/opt/parth/postgres-init/001-create-databases.sql <<'SQL'
CREATE DATABASE envio_bridge;
CREATE DATABASE psy_services;
SQL

docker run -d \
  --name parth-postgres \
  --restart unless-stopped \
  --shm-size=2g \
  --log-driver=json-file \
  --log-opt=max-size=100m \
  --log-opt=max-file=100 \
  --log-opt=compress=true \
  -e POSTGRES_USER="$POSTGRES_USER" \
  -e POSTGRES_PASSWORD \
  -e POSTGRES_DB=postgres \
  -p 5432:5432 \
  -v /var/lib/parth/postgres:/var/lib/postgresql/data \
  -v /opt/parth/postgres-init:/docker-entrypoint-initdb.d:ro \
  "$POSTGRES_IMAGE"

policy="$(docker inspect --format '{{.HostConfig.ShmSize}} {{.HostConfig.LogConfig.Type}} {{index .HostConfig.LogConfig.Config "max-size"}} {{index .HostConfig.LogConfig.Config "max-file"}} {{index .HostConfig.LogConfig.Config "compress"}}' parth-postgres)"
if [ "$policy" != "2147483648 json-file 100m 100 true" ]; then
  echo "PostgreSQL container policy not applied" >&2
  docker stop --time 30 parth-postgres >/dev/null || true
  exit 1
fi

for _ in $(seq 1 60); do
  if docker exec -e PGPASSWORD parth-postgres pg_isready -U "$POSTGRES_USER" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

for db in envio_bridge psy_services; do
  if ! docker exec -e PGPASSWORD parth-postgres \
    psql -U "$POSTGRES_USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${db}'" | grep -q 1; then
    docker exec -e PGPASSWORD parth-postgres createdb -U "$POSTGRES_USER" "$db"
  fi
done

docker ps --filter name=parth-postgres
