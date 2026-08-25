#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io
  systemctl enable --now docker
fi

: "${POSTGRES_USER:=postgres}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${POSTGRES_VERSION:=16}"

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
  -e POSTGRES_USER="$POSTGRES_USER" \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -e POSTGRES_DB=postgres \
  -p 5432:5432 \
  -v /var/lib/parth/postgres:/var/lib/postgresql/data \
  -v /opt/parth/postgres-init:/docker-entrypoint-initdb.d:ro \
  "postgres:${POSTGRES_VERSION}"

for _ in $(seq 1 60); do
  if docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" parth-postgres pg_isready -U "$POSTGRES_USER" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

for db in envio_bridge psy_services; do
  if ! docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" parth-postgres \
    psql -U "$POSTGRES_USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${db}'" | grep -q 1; then
    docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" parth-postgres createdb -U "$POSTGRES_USER" "$db"
  fi
done

docker ps --filter name=parth-postgres
