#!/usr/bin/env bash
set -euo pipefail

: "${NOSTR_HOME:=/opt/nostr-relay}"
: "${NOSTR_RELAY_IMAGE:=scsibug/nostr-rs-relay:latest}"
: "${NOSTR_RELAY_URL:?NOSTR_RELAY_URL is required}"
: "${NOSTR_DOMAIN:?NOSTR_DOMAIN is required}"
: "${NOSTR_NAME:=devruntime-nostr-stg}"
: "${NOSTR_DESCRIPTION:=DevRuntime Nostr relay for bridge infrastructure}"
: "${NOSTR_CONTACT:=tyree@zklabs.cn}"
: "${NOSTR_PUBKEY:=}"
: "${NOSTR_INTERNAL_PORT:=8080}"
: "${NOSTR_DB_MIN_CONN:=4}"
: "${NOSTR_DB_MAX_CONN:=16}"
: "${NOSTR_MAX_EVENT_BYTES:=5242880}"
: "${NOSTR_MESSAGES_PER_SEC:=20}"
: "${NOSTR_SUBSCRIPTIONS_PER_MIN:=200}"
: "${NOSTR_MAX_BLOCKING_THREADS:=16}"
: "${NOSTR_EVENT_KIND_ALLOWLIST:=[1059]}"
: "${NOSTR_REJECT_FUTURE_SECONDS:=1800}"
: "${NOSTR_MAINTENANCE_ENABLED:=1}"
: "${NOSTR_MAINTENANCE_ONCALENDAR:=*-*-* 03:00:00 Asia/Singapore}"
: "${NOSTR_DISK_FREE_TARGET_PERCENT:=30}"
: "${NOSTR_RETENTION_WINDOWS_DAYS:=30 15 7 3 1}"
: "${NOSTR_SQLITE_BUSY_TIMEOUT_MS:=30000}"
: "${NOSTR_DB_PATH:=}"
: "${PUBLIC_COORDINATOR_DOMAIN:=}"
: "${PUBLIC_COORDINATOR_UPSTREAM:=}"
: "${PUBLIC_REALM_DOMAIN:=}"
: "${PUBLIC_REALM_UPSTREAM:=}"
: "${PUBLIC_REALM1_DOMAIN:=}"
: "${PUBLIC_REALM1_UPSTREAM:=}"
: "${PUBLIC_PROVE_PROXY_DOMAIN:=}"
: "${PUBLIC_FAUCET_DOMAIN:=}"
: "${PUBLIC_FAUCET_UPSTREAM:=}"
: "${PUBLIC_PROVE_PROXY_UPSTREAM:=}"
: "${PUBLIC_L1_RPC_DOMAIN:=}"
: "${PUBLIC_L1_RPC_UPSTREAM:=}"
: "${PUBLIC_PSY_SERVICES_DOMAIN:=}"
: "${PUBLIC_PSY_SERVICES_UPSTREAM:=}"
: "${PUBLIC_INDEXER_DOMAIN:=}"
: "${PUBLIC_INDEXER_UPSTREAM:=}"
: "${PUBLIC_TRUST_SETUP_PATH:=/trust-setup}"
: "${PUBLIC_TRUST_SETUP_ROOT:=$NOSTR_HOME/public/trust-setup}"
: "${PUBLIC_TRUST_SETUP_CONTAINER_ROOT:=/srv/trust-setup}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl docker.io jq sqlite3 htop ncdu util-linux
systemctl enable --now docker

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  for compose_pkg in docker-compose-v2 docker-compose-plugin docker-compose; do
    if apt-cache show "$compose_pkg" >/dev/null 2>&1; then
      apt-get install -y "$compose_pkg"
      break
    fi
  done
fi

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "Docker Compose is not available from configured apt repositories" >&2
    exit 1
  fi
}

bash /tmp/mount-data-disk.sh

install -d -m 0755 "$NOSTR_HOME" "$NOSTR_HOME/data" "$NOSTR_HOME/caddy_data" "$NOSTR_HOME/caddy_config" "$PUBLIC_TRUST_SETUP_ROOT"
chown -R 1000:1000 "$NOSTR_HOME/data"

cat >"$NOSTR_HOME/config.toml" <<EOF
[info]
relay_url = "${NOSTR_RELAY_URL}"
name = "${NOSTR_NAME}"
description = "${NOSTR_DESCRIPTION}"
contact = "${NOSTR_CONTACT}"
EOF

if [ -n "$NOSTR_PUBKEY" ]; then
  printf 'pubkey = "%s"\n' "$NOSTR_PUBKEY" >>"$NOSTR_HOME/config.toml"
fi

cat >>"$NOSTR_HOME/config.toml" <<EOF

[database]
engine = "sqlite"
data_directory = "/usr/src/app/db"
min_conn = ${NOSTR_DB_MIN_CONN}
max_conn = ${NOSTR_DB_MAX_CONN}

[network]
address = "0.0.0.0"
port = ${NOSTR_INTERNAL_PORT}
remote_ip_header = "x-forwarded-for"

[limits]
max_event_bytes = ${NOSTR_MAX_EVENT_BYTES}
max_ws_message_bytes = ${NOSTR_MAX_EVENT_BYTES}
max_ws_frame_bytes = ${NOSTR_MAX_EVENT_BYTES}
messages_per_sec = ${NOSTR_MESSAGES_PER_SEC}
subscriptions_per_min = ${NOSTR_SUBSCRIPTIONS_PER_MIN}
max_blocking_threads = ${NOSTR_MAX_BLOCKING_THREADS}
event_kind_allowlist = ${NOSTR_EVENT_KIND_ALLOWLIST}

[authorization]
nip42_auth = false
nip42_dms = false

[options]
reject_future_seconds = ${NOSTR_REJECT_FUTURE_SECONDS}
EOF

cat >"$NOSTR_HOME/Caddyfile" <<EOF
${NOSTR_DOMAIN} {
    encode zstd gzip

    handle_path ${PUBLIC_TRUST_SETUP_PATH%/}/* {
        root * ${PUBLIC_TRUST_SETUP_CONTAINER_ROOT}
        header {
            Access-Control-Allow-Origin *
            Cache-Control "public, max-age=3600"
        }
        file_server
    }

    reverse_proxy nostr-relay:${NOSTR_INTERNAL_PORT}
}
EOF

append_public_proxy() {
  local domain="$1"
  local upstream="$2"
  local target="$2"
  local rewrite_path=""

  [ -n "$domain" ] || return 0
  [ -n "$upstream" ] || {
    echo "missing upstream for public domain: $domain" >&2
    exit 1
  }

  if [[ "$upstream" =~ ^https?://[^/]+/.+ ]]; then
    if [[ "$upstream" == https://* ]]; then
      local host_path="${upstream#https://}"
      target="https://${host_path%%/*}"
      rewrite_path="/${host_path#*/}"
    else
      local host_path="${upstream#http://}"
      target="http://${host_path%%/*}"
      rewrite_path="/${host_path#*/}"
    fi
  fi

  cat >>"$NOSTR_HOME/Caddyfile" <<EOF

${domain} {
    encode zstd gzip

    @options method OPTIONS
    respond @options 204

    header {
        Access-Control-Allow-Origin *
        Access-Control-Allow-Methods "GET, POST, OPTIONS"
        Access-Control-Allow-Headers "Content-Type, Authorization"
    }

EOF

  if [ -n "$rewrite_path" ] && [ "$rewrite_path" != "/" ]; then
    cat >>"$NOSTR_HOME/Caddyfile" <<EOF
    rewrite * ${rewrite_path}

EOF
  fi

  cat >>"$NOSTR_HOME/Caddyfile" <<EOF
    reverse_proxy ${target} {
        header_up Host {upstream_hostport}
        header_down -Access-Control-Allow-Origin
        header_down -Access-Control-Allow-Methods
        header_down -Access-Control-Allow-Headers
        header_down -Access-Control-Allow-Credentials
        header_down -Access-Control-Expose-Headers
    }
}
EOF
}

append_public_proxy "$PUBLIC_COORDINATOR_DOMAIN" "$PUBLIC_COORDINATOR_UPSTREAM"
append_public_proxy "$PUBLIC_REALM_DOMAIN" "$PUBLIC_REALM_UPSTREAM"
append_public_proxy "$PUBLIC_REALM1_DOMAIN" "$PUBLIC_REALM1_UPSTREAM"
append_public_proxy "$PUBLIC_PROVE_PROXY_DOMAIN" "$PUBLIC_PROVE_PROXY_UPSTREAM"
append_public_proxy "$PUBLIC_FAUCET_DOMAIN" "$PUBLIC_FAUCET_UPSTREAM"
append_public_proxy "$PUBLIC_L1_RPC_DOMAIN" "$PUBLIC_L1_RPC_UPSTREAM"
append_public_proxy "$PUBLIC_PSY_SERVICES_DOMAIN" "$PUBLIC_PSY_SERVICES_UPSTREAM"
append_public_proxy "$PUBLIC_INDEXER_DOMAIN" "$PUBLIC_INDEXER_UPSTREAM"

cat >"$NOSTR_HOME/docker-compose.yml" <<EOF
version: "3.9"

services:
  nostr-relay:
    image: ${NOSTR_RELAY_IMAGE}
    container_name: nostr-relay
    user: "1000:1000"
    restart: unless-stopped
    volumes:
      - ./config.toml:/usr/src/app/config.toml:ro
      - ./data:/usr/src/app/db
    expose:
      - "${NOSTR_INTERNAL_PORT}"
    networks:
      - nostr-net

  caddy:
    image: caddy:2
    container_name: nostr-caddy
    restart: unless-stopped
    depends_on:
      - nostr-relay
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./caddy_data:/data
      - ./caddy_config:/config
      - ${PUBLIC_TRUST_SETUP_ROOT}:${PUBLIC_TRUST_SETUP_CONTAINER_ROOT}:ro
    networks:
      - nostr-net

networks:
  nostr-net:
EOF

cd "$NOSTR_HOME"
docker rm -f nostr-relay nostr-caddy >/dev/null 2>&1 || true
compose up -d
compose ps

write_env_var() {
  local key="$1"
  printf '%s=%q\n' "$key" "${!key}"
}

if [ "$NOSTR_MAINTENANCE_ENABLED" = "1" ]; then
  [ -f /tmp/nostr-maintenance.sh ] || {
    echo "missing /tmp/nostr-maintenance.sh" >&2
    exit 1
  }
  install -m 0755 /tmp/nostr-maintenance.sh /usr/local/sbin/nostr-maintenance.sh
  {
    write_env_var NOSTR_HOME
    write_env_var NOSTR_DB_PATH
    write_env_var NOSTR_DISK_FREE_TARGET_PERCENT
    write_env_var NOSTR_RETENTION_WINDOWS_DAYS
    write_env_var NOSTR_SQLITE_BUSY_TIMEOUT_MS
  } >/etc/default/nostr-maintenance

  cat >/etc/systemd/system/nostr-maintenance.service <<EOF
[Unit]
Description=Nostr relay SQLite disk maintenance

[Service]
Type=oneshot
EnvironmentFile=/etc/default/nostr-maintenance
ExecStart=/usr/local/sbin/nostr-maintenance.sh
Nice=10
IOSchedulingClass=idle
EOF

  cat >/etc/systemd/system/nostr-maintenance.timer <<EOF
[Unit]
Description=Run Nostr relay SQLite disk maintenance

[Timer]
OnCalendar=${NOSTR_MAINTENANCE_ONCALENDAR}
Persistent=true
RandomizedDelaySec=10m
Unit=nostr-maintenance.service

[Install]
WantedBy=timers.target
EOF

  systemd-analyze calendar "$NOSTR_MAINTENANCE_ONCALENDAR" >/dev/null
  systemctl daemon-reload
  systemctl enable --now nostr-maintenance.timer
else
  systemctl disable --now nostr-maintenance.timer >/dev/null 2>&1 || true
fi
