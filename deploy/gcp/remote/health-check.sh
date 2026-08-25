#!/usr/bin/env bash
set -euo pipefail

: "${HEALTHCHECK_MODE:?HEALTHCHECK_MODE is required}"
: "${HEALTHCHECK_ATTEMPTS:=60}"
: "${HEALTHCHECK_DELAY:=2}"
: "${HEALTHCHECK_START_DELAY:=5}"

log() {
  echo "[healthcheck] $*"
}

fail() {
  echo "[healthcheck] failed: $*" >&2
  exit 1
}

wait_before_check() {
  if [ "$HEALTHCHECK_START_DELAY" -gt 0 ]; then
    log "waiting ${HEALTHCHECK_START_DELAY}s before ${HEALTHCHECK_MODE} check"
    sleep "$HEALTHCHECK_START_DELAY"
  fi
}

wait_tcp() {
  local host="$1"
  local port="$2"
  local attempts="${3:-$HEALTHCHECK_ATTEMPTS}"
  local delay="${4:-$HEALTHCHECK_DELAY}"

  for _ in $(seq 1 "$attempts"); do
    if timeout 2 bash -c "</dev/tcp/${host}/${port}" >/dev/null 2>&1; then
      log "tcp ${host}:${port} is reachable"
      return 0
    fi
    sleep "$delay"
  done

  return 1
}

wait_http_any_status() {
  local url="$1"
  local attempts="${2:-$HEALTHCHECK_ATTEMPTS}"
  local delay="${3:-$HEALTHCHECK_DELAY}"
  local code

  for _ in $(seq 1 "$attempts"); do
    code="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    if [ "$code" != "000" ] && [ -n "$code" ]; then
      log "http ${url} responded with ${code}"
      return 0
    fi
    sleep "$delay"
  done

  return 1
}

wait_http_success() {
  local url="$1"
  local attempts="${2:-$HEALTHCHECK_ATTEMPTS}"
  local delay="${3:-$HEALTHCHECK_DELAY}"

  for _ in $(seq 1 "$attempts"); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      log "http ${url} returned success"
      return 0
    fi
    sleep "$delay"
  done

  return 1
}

wait_jsonrpc_result() {
  local url="$1"
  local method="${2:-psy_get_latest_checkpoint_id}"
  local attempts="${3:-$HEALTHCHECK_ATTEMPTS}"
  local delay="${4:-$HEALTHCHECK_DELAY}"
  local payload
  local response

  payload="$(printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":[]}' "$method")"

  for _ in $(seq 1 "$attempts"); do
    response="$(curl -fsS --max-time 3 \
      -H 'content-type: application/json' \
      --data "$payload" \
      "$url" 2>/dev/null || true)"
    if printf '%s' "$response" | grep -q '"result"'; then
      log "jsonrpc ${url} ${method} returned a result"
      return 0
    fi
    sleep "$delay"
  done

  return 1
}

require_container_running() {
  local container="$1"
  local running

  running="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)"
  [ "$running" = "true" ] || fail "docker container is not running: $container"
}

check_valkey() {
  local port="${VALKEY_PORT:-6379}"
  local payload="parth-hc-$(date +%s)-$$"
  local readback

  wait_tcp 127.0.0.1 "$port" || fail "Valkey port ${port} is not reachable"
  require_container_running valkey-server

  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    if docker exec valkey-server valkey-cli SET __parth_healthcheck "$payload" >/dev/null 2>&1; then
      readback="$(docker exec valkey-server valkey-cli GET __parth_healthcheck | tr -d '\r\n')"
      docker exec valkey-server valkey-cli DEL __parth_healthcheck >/dev/null 2>&1 || true
      [ "$readback" = "$payload" ] && {
        log "Valkey write/read check passed"
        return 0
      }
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  fail "Valkey write/read check did not pass"
}

nats_pubsub_once() {
  local port="${NATS_PORT:-4222}"
  local subject="_parth.healthcheck.$$"
  local payload="ok-$(date +%s)-$$"
  local line
  local got_pong=0
  local expect_payload=0
  local got_payload=0

  exec 3<>"/dev/tcp/127.0.0.1/${port}" || return 1
  IFS= read -r -t 2 line <&3 || true

  printf 'CONNECT {"verbose":false,"pedantic":false,"lang":"bash","version":"1"}\r\n' >&3
  printf 'SUB %s 1\r\n' "$subject" >&3
  printf 'PING\r\n' >&3

  for _ in $(seq 1 20); do
    IFS= read -r -t 1 line <&3 || break
    line="${line%$'\r'}"
    if [ "$line" = "PONG" ]; then
      got_pong=1
      break
    fi
  done

  [ "$got_pong" = "1" ] || {
    exec 3<&-
    exec 3>&-
    return 1
  }

  printf 'PUB %s %s\r\n%s\r\n' "$subject" "${#payload}" "$payload" >&3
  printf 'PING\r\n' >&3

  for _ in $(seq 1 30); do
    IFS= read -r -t 1 line <&3 || break
    line="${line%$'\r'}"
    if [ "$expect_payload" = "1" ]; then
      [ "$line" = "$payload" ] && got_payload=1
      break
    fi
    case "$line" in
      MSG\ "$subject"\ 1\ *) expect_payload=1 ;;
    esac
  done

  exec 3<&-
  exec 3>&-
  [ "$got_payload" = "1" ]
}

check_nats() {
  local port="${NATS_PORT:-4222}"

  wait_tcp 127.0.0.1 "$port" || fail "NATS port ${port} is not reachable"
  require_container_running nats-server

  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    if nats_pubsub_once; then
      log "NATS protocol pub/sub check passed"
      return 0
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  fail "NATS pub/sub check did not pass"
}

check_postgres() {
  : "${POSTGRES_USER:=postgres}"
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required for postgres healthcheck}"

  local port="${POSTGRES_PORT:-5432}"
  local payload="pg-$(date +%s)-$$"
  local readback

  wait_tcp 127.0.0.1 "$port" || fail "Postgres port ${port} is not reachable"
  require_container_running parth-postgres

  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    if docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" parth-postgres \
      pg_isready -U "$POSTGRES_USER" >/dev/null 2>&1; then
      docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" parth-postgres \
        psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres \
        -c "CREATE TABLE IF NOT EXISTS deploy_healthcheck (key text PRIMARY KEY, value text NOT NULL, checked_at timestamptz NOT NULL DEFAULT now());" >/dev/null
      docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" parth-postgres \
        psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres \
        -c "INSERT INTO deploy_healthcheck (key, value, checked_at) VALUES ('last', '${payload}', now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, checked_at = now();" >/dev/null
      readback="$(docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" parth-postgres \
        psql -U "$POSTGRES_USER" -d postgres -tAc "SELECT value FROM deploy_healthcheck WHERE key='last';" | tr -d '[:space:]')"
      [ "$readback" = "$payload" ] && {
        log "Postgres write/read check passed"
        return 0
      }
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  fail "Postgres write/read check did not pass"
}

check_anvil() {
  local port="${ANVIL_PORT:-8545}"
  local chain_id="${ANVIL_CHAIN_ID:-${CHAIN_ID:-31337}}"
  local expected_hex
  local result

  wait_tcp 127.0.0.1 "$port" || fail "Anvil port ${port} is not reachable"
  if [ -n "${SYSTEMD_UNIT:-}" ]; then
    systemctl is-active --quiet "$SYSTEMD_UNIT" || fail "${SYSTEMD_UNIT} is not active"
  fi

  expected_hex="$(printf '0x%x' "$chain_id")"
  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    result="$(curl -fsS --max-time 3 \
      -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
      "http://127.0.0.1:${port}" 2>/dev/null | jq -r '.result // empty' || true)"
    if [ "$result" = "$expected_hex" ]; then
      log "Anvil JSON-RPC check passed: chain_id=${chain_id}"
      return 0
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  fail "Anvil JSON-RPC eth_chainId did not return ${expected_hex}"
}

run_scylla_cql() {
  local query="$1"

  timeout 20 docker exec scylla-server sh -lc '
    set -eu
    cqlsh_path="$(command -v cqlsh || command -v cqlsh.py || find /opt /usr \( -name cqlsh -o -name cqlsh.py \) 2>/dev/null | head -n 1)"
    [ -n "$cqlsh_path" ]
    cql_host="$(hostname -i | awk "{ print \$1 }")"
    exec "$cqlsh_path" "$cql_host" 9042 -e "$1"
  ' sh "$query" 2>/dev/null
}

scylla_node_is_up_normal() {
  timeout 10 docker exec scylla-server nodetool status 2>/dev/null | awk '$1 == "UN" { found = 1 } END { exit found ? 0 : 1 }'
}

check_scylla() {
  local port="${SCYLLA_PORT:-9042}"
  local payload="scylla-$(date +%s)-$$"
  local output
  local has_cqlsh=0

  wait_tcp 127.0.0.1 "$port" "$HEALTHCHECK_ATTEMPTS" "$HEALTHCHECK_DELAY" || fail "Scylla port ${port} is not reachable"
  require_container_running scylla-server
  timeout 5 docker exec scylla-server sh -lc 'command -v cqlsh || command -v cqlsh.py || find /opt /usr \( -name cqlsh -o -name cqlsh.py \) 2>/dev/null | head -n 1' >/dev/null 2>&1 && has_cqlsh=1

  for attempt in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    log "waiting for Scylla readiness: attempt ${attempt}/${HEALTHCHECK_ATTEMPTS}"
    if [ "$has_cqlsh" = "0" ] && scylla_node_is_up_normal; then
      log "Scylla nodetool status check passed; cqlsh is not present in this image, skipping CQL write/read"
      return 0
    fi

    if [ "$has_cqlsh" = "1" ] && run_scylla_cql "CREATE KEYSPACE IF NOT EXISTS parth_healthcheck WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};"; then
      run_scylla_cql "CREATE TABLE IF NOT EXISTS parth_healthcheck.deploy_healthcheck (key text PRIMARY KEY, value text);" >/dev/null
      run_scylla_cql "INSERT INTO parth_healthcheck.deploy_healthcheck (key, value) VALUES ('last', '${payload}');" >/dev/null
      output="$(run_scylla_cql "SELECT value FROM parth_healthcheck.deploy_healthcheck WHERE key='last';" || true)"
      if printf '%s\n' "$output" | grep -q "$payload"; then
        log "Scylla write/read check passed"
        return 0
      fi
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  fail "Scylla healthcheck did not pass"
}

check_envio() {
  : "${ENVIO_PG_USER:=postgres}"
  : "${ENVIO_PG_PASSWORD:=testing}"
  : "${ENVIO_PG_DATABASE:=envio_bridge}"
  : "${ENVIO_DATABASE_URL:?ENVIO_DATABASE_URL is required for Envio healthcheck}"
  : "${HASURA_EXTERNAL_PORT:=18080}"
  : "${HASURA_INTERNAL_PORT:=8080}"
  : "${HASURA_GRAPHQL_ADMIN_SECRET:=testing}"

  local payload="envio-$(date +%s)-$$"
  local readback
  local schema_response=""

  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    systemctl is-active --quiet parth-envio.service && break
    sleep "$HEALTHCHECK_DELAY"
  done
  systemctl is-active --quiet parth-envio.service || fail "parth-envio.service is not active"

  wait_tcp 127.0.0.1 "$HASURA_EXTERNAL_PORT" || fail "Hasura port ${HASURA_EXTERNAL_PORT} is not reachable"
  wait_http_success "http://127.0.0.1:${HASURA_EXTERNAL_PORT}/healthz" || fail "Hasura healthz did not return success"
  wait_tcp 127.0.0.1 "$HASURA_INTERNAL_PORT" || fail "Hasura internal port ${HASURA_INTERNAL_PORT} is not reachable"
  wait_http_success "http://127.0.0.1:${HASURA_INTERNAL_PORT}/hasura/healthz?strict=true" || fail "Envio Hasura strict healthz did not return success"

  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    schema_response="$(curl -fsS --max-time 5 \
      -H 'content-type: application/json' \
      -H "x-hasura-admin-secret: ${HASURA_GRAPHQL_ADMIN_SECRET}" \
      --data '{"query":"query { __schema { queryType { fields { name } } } __type(name: \"Deposit\") { fields { name } } }"}' \
      "http://127.0.0.1:${HASURA_EXTERNAL_PORT}/v1/graphql" || true)"
    if grep -q '"name":"DepositTreeMeta"' <<<"$schema_response" \
      && grep -q '"name":"WithdrawalClaim"' <<<"$schema_response" \
      && grep -q '"name":"note_commitment"' <<<"$schema_response"; then
      log "Hasura GraphQL schema check passed"
      break
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  schema_response="$(curl -fsS --max-time 5 \
    -H 'content-type: application/json' \
    -H "x-hasura-admin-secret: ${HASURA_GRAPHQL_ADMIN_SECRET}" \
    --data '{"query":"query { __schema { queryType { fields { name } } } __type(name: \"Deposit\") { fields { name } } }"}' \
    "http://127.0.0.1:${HASURA_EXTERNAL_PORT}/v1/graphql" || true)"
  grep -q '"name":"DepositTreeMeta"' <<<"$schema_response" \
    || fail "Hasura GraphQL schema is missing DepositTreeMeta"
  grep -q '"name":"WithdrawalClaim"' <<<"$schema_response" \
    || fail "Hasura GraphQL schema is missing WithdrawalClaim"
  grep -q '"name":"note_commitment"' <<<"$schema_response" \
    || fail "Hasura Deposit schema is missing note_commitment"

  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    if psql "$ENVIO_DATABASE_URL" -v ON_ERROR_STOP=1 \
      -c "CREATE TABLE IF NOT EXISTS deploy_healthcheck (key text PRIMARY KEY, value text NOT NULL, checked_at timestamptz NOT NULL DEFAULT now());" >/dev/null 2>&1; then
      psql "$ENVIO_DATABASE_URL" -v ON_ERROR_STOP=1 \
        -c "INSERT INTO deploy_healthcheck (key, value, checked_at) VALUES ('last', '${payload}', now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, checked_at = now();" >/dev/null
      readback="$(psql "$ENVIO_DATABASE_URL" -tAc "SELECT value FROM deploy_healthcheck WHERE key='last';" | tr -d '[:space:]')"
      [ "$readback" = "$payload" ] && {
        log "Envio service, Hasura, and shared Postgres checks passed"
        return 0
      }
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  fail "Envio Postgres write/read check did not pass"
}

check_nostr() {
  local http_port="${NOSTR_HTTP_PORT:-80}"
  local https_port="${NOSTR_HTTPS_PORT:-443}"
  local internal_port="${NOSTR_INTERNAL_PORT:-8080}"
  local relay_ip

  require_container_running nostr-relay
  require_container_running nostr-caddy
  relay_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nostr-relay 2>/dev/null || true)"
  [ -n "$relay_ip" ] || fail "Nostr relay container IP was not found"
  wait_tcp "$relay_ip" "$internal_port" || fail "Nostr relay internal port ${internal_port} is not reachable"
  wait_tcp 127.0.0.1 "$http_port" || fail "Nostr Caddy HTTP port ${http_port} is not reachable"
  wait_tcp 127.0.0.1 "$https_port" || fail "Nostr Caddy HTTPS port ${https_port} is not reachable"
  wait_http_any_status "http://127.0.0.1:${http_port}/" || fail "Nostr Caddy HTTP endpoint did not respond"
  if [ "${NOSTR_MAINTENANCE_ENABLED:-1}" = "1" ]; then
    systemctl is-enabled --quiet nostr-maintenance.timer || fail "nostr-maintenance.timer is not enabled"
    systemctl is-active --quiet nostr-maintenance.timer || fail "nostr-maintenance.timer is not active"
  fi
  log "Nostr relay and Caddy checks passed"
}

check_parth_host() {
  getent passwd parth >/dev/null || fail "missing parth system user"
  [ -d /opt/parth ] || fail "missing /opt/parth"
  [ -d /var/lib/parth ] || fail "missing /var/lib/parth"

  if [ "${PARTH_BUNDLE_EXPECTED:-0}" = "1" ]; then
    [ -d /opt/parth/current ] || fail "missing /opt/parth/current"
    [ -x /opt/parth/current/deploy/bin/run-parth-service ] || fail "missing /opt/parth/current/deploy/bin/run-parth-service"
    [ -x /opt/parth/current/target/release/psy_node_cli ] || fail "missing /opt/parth/current/target/release/psy_node_cli"
    [ -x /opt/parth/current/target/release/psy_worker_cli ] || fail "missing /opt/parth/current/target/release/psy_worker_cli"
  fi

  log "Parth host check passed"
}

check_ports() {
  local ports="${HEALTHCHECK_PORTS:-}"
  local urls="${HEALTHCHECK_HTTP_URLS:-}"
  local port
  local url

  dump_healthcheck_unit_logs() {
    if [ -n "${SYSTEMD_UNIT:-}" ]; then
      systemctl --no-pager --full status "$SYSTEMD_UNIT" || true
      journalctl -u "$SYSTEMD_UNIT" --no-pager -n 80 || true
    fi
  }

  if [ -z "$ports" ] && [ -z "$urls" ]; then
    log "no HEALTHCHECK_PORTS or HEALTHCHECK_HTTP_URLS configured; skipping port checks"
    return 0
  fi

  for port in ${ports//,/ }; do
    [ -z "$port" ] && continue
    wait_tcp 127.0.0.1 "$port" || {
      dump_healthcheck_unit_logs
      fail "port ${port} is not reachable"
    }
  done

  for url in ${urls//,/ }; do
    [ -z "$url" ] && continue
    if [ "${HEALTHCHECK_HTTP_REQUIRE_SUCCESS:-0}" = "1" ]; then
      wait_http_success "$url" || {
        dump_healthcheck_unit_logs
        fail "http endpoint did not return success: ${url}"
      }
    else
      wait_http_any_status "$url" || {
        dump_healthcheck_unit_logs
        fail "http endpoint did not respond: ${url}"
      }
    fi
  done

  log "configured port checks passed"
}

check_jsonrpc() {
  local urls="${HEALTHCHECK_JSONRPC_URLS:-${HEALTHCHECK_HTTP_URLS:-}}"
  local method="${HEALTHCHECK_JSONRPC_METHOD:-psy_get_latest_checkpoint_id}"
  local url

  dump_healthcheck_unit_logs() {
    if [ -n "${SYSTEMD_UNIT:-}" ]; then
      systemctl --no-pager --full status "$SYSTEMD_UNIT" || true
      journalctl -u "$SYSTEMD_UNIT" --no-pager -n 80 || true
    fi
  }

  [ -n "$urls" ] || fail "HEALTHCHECK_JSONRPC_URLS is required for jsonrpc healthcheck"

  for url in ${urls//,/ }; do
    [ -z "$url" ] && continue
    wait_jsonrpc_result "$url" "$method" || {
      dump_healthcheck_unit_logs
      fail "jsonrpc endpoint did not return a result: ${url} method=${method}"
    }
  done

  log "configured jsonrpc checks passed"
}

check_systemd() {
  : "${SYSTEMD_UNIT:?SYSTEMD_UNIT is required for systemd healthcheck}"

  for _ in $(seq 1 "$HEALTHCHECK_ATTEMPTS"); do
    if systemctl is-active --quiet "$SYSTEMD_UNIT"; then
      log "systemd unit is active: ${SYSTEMD_UNIT}"
      return 0
    fi
    sleep "$HEALTHCHECK_DELAY"
  done

  systemctl --no-pager --full status "$SYSTEMD_UNIT" || true
  journalctl -u "$SYSTEMD_UNIT" --no-pager -n 80 || true
  fail "systemd unit did not become active: ${SYSTEMD_UNIT}"
}

wait_before_check

case "$HEALTHCHECK_MODE" in
  valkey) check_valkey ;;
  nats) check_nats ;;
  postgres) check_postgres ;;
  anvil) check_anvil ;;
  scylla) check_scylla ;;
  envio) check_envio ;;
  nostr) check_nostr ;;
  parth-host) check_parth_host ;;
  ports) check_ports ;;
  jsonrpc) check_jsonrpc ;;
  systemd) check_systemd ;;
  *)
    fail "unknown HEALTHCHECK_MODE: ${HEALTHCHECK_MODE}"
    ;;
esac
