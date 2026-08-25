#!/usr/bin/env bash
set -euo pipefail

: "${PARTH_SERVICE:?PARTH_SERVICE is required}"
: "${PARTH_MAKE_TARGET:=}"
: "${PARTH_SYSTEMD_UNIT:?PARTH_SYSTEMD_UNIT is required}"
: "${DEPLOY_INSTANCE:=0}"
: "${DEPLOY_PSY_SERVICES_HOME:=/opt/parth/current/psy-services}"
: "${PARTH_NETWORK:=local-devnet}"
: "${PROVING_BACKEND:=plonky2-poseidon-goldilocks}"
: "${SCYLLA_DB_URL:?SCYLLA_DB_URL is required}"
: "${NATS_JETSTREAM_URL:?NATS_JETSTREAM_URL is required}"
: "${REDIS_URL:?REDIS_URL is required}"

PARTH_HOME="/opt/parth/current"
ENV_DIR="/etc/parth"

fail() {
  echo "[deploy-parth-service] failed: $*" >&2
  exit 1
}

upsert_env() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp

  install -d -m 0755 "$(dirname "$file")"
  touch "$file"
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { done = 0 }
    $0 ~ "^[[:space:]]*#?[[:space:]]*" key "=" {
      if (done == 0) {
        print key "=" value
        done = 1
      }
      next
    }
    { print }
    END {
      if (done == 0) {
        print key "=" value
      }
    }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"
  chmod 0640 "$file"
}

upsert_if_set() {
  local file="$1"
  local key="$2"
  local env_name="$3"

  if [[ -v "$env_name" ]]; then
    upsert_env "$file" "$key" "${!env_name}"
  fi
}

upsert_if_nonempty() {
  local file="$1"
  local key="$2"
  local env_name="$3"

  if [ -n "${!env_name:-}" ]; then
    upsert_env "$file" "$key" "${!env_name}"
  fi
}

delete_env() {
  local file="$1"
  local key="$2"
  local tmp

  [ -f "$file" ] || return 0
  tmp="$(mktemp)"
  awk -v key="$key" '
    $0 ~ "^[[:space:]]*#?[[:space:]]*" key "=" { next }
    { print }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"
  chmod 0640 "$file"
}

[ -d "$PARTH_HOME" ] || fail "missing ${PARTH_HOME}; upload PARTH_BUNDLE first"
[ -x "$PARTH_HOME/deploy/bin/run-parth-service" ] || fail "missing executable ${PARTH_HOME}/deploy/bin/run-parth-service"

cat >/usr/local/bin/parth-wait-jsonrpc <<'SH'
#!/usr/bin/env bash
set -euo pipefail

urls="${1:-}"
method="${2:-psy_get_latest_checkpoint_id}"
attempts="${PARTH_WAIT_JSONRPC_ATTEMPTS:-60}"
delay="${PARTH_WAIT_JSONRPC_DELAY:-2}"
timeout_s="${PARTH_WAIT_JSONRPC_TIMEOUT:-3}"

if [ -z "$urls" ]; then
  echo "[parth-wait-jsonrpc] no urls were provided" >&2
  exit 1
fi

payload="$(printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":[]}' "$method")"

for attempt in $(seq 1 "$attempts"); do
  for url in ${urls//,/ }; do
    [ -z "$url" ] && continue
    response="$(curl -fsS --max-time "$timeout_s" \
      -H 'content-type: application/json' \
      --data "$payload" \
      "$url" 2>/dev/null || true)"
    if printf '%s' "$response" | grep -q '"result"'; then
      echo "[parth-wait-jsonrpc] ${url} ${method} is ready"
      exit 0
    fi
  done
  echo "[parth-wait-jsonrpc] waiting for ${method} (${attempt}/${attempts}): ${urls}"
  sleep "$delay"
done

echo "[parth-wait-jsonrpc] timed out waiting for ${method}: ${urls}" >&2
exit 1
SH
chmod 0755 /usr/local/bin/parth-wait-jsonrpc

cd "$PARTH_HOME"

common_env="${ENV_DIR}/common.env"
upsert_env "$common_env" PARTH_HOME "$PARTH_HOME"
upsert_env "$common_env" NETWORK "$PARTH_NETWORK"
upsert_env "$common_env" PROVING_BACKEND "$PROVING_BACKEND"
upsert_env "$common_env" SCYLLA_DB_URL "$SCYLLA_DB_URL"
upsert_env "$common_env" NATS_JETSTREAM_URL "$NATS_JETSTREAM_URL"
upsert_env "$common_env" REDIS_URL "$REDIS_URL"
upsert_env "$common_env" GENESIS_DATA_PATH "${GENESIS_DATA_PATH:-$PARTH_HOME/genesis.json}"
upsert_env "$common_env" CHECKPOINT_BACKUP_PATH "${CHECKPOINT_BACKUP_PATH:-/var/lib/parth/checkpoints}"
upsert_if_set "$common_env" RUST_LOG RUST_LOG
upsert_if_set "$common_env" RUST_BACKTRACE RUST_BACKTRACE
upsert_if_set "$common_env" VERBOSE VERBOSE

case "$PARTH_SERVICE" in
  coordinator-processor)
    service_env="${ENV_DIR}/coordinator-processor.env"
    upsert_if_set "$service_env" COORDINATOR_ID COORDINATOR_ID
    upsert_if_set "$service_env" COORDINATOR_SUB_ID COORDINATOR_SUB_ID
    upsert_if_set "$service_env" DB_NAMESPACE DB_NAMESPACE
    ;;

  coordinator-edge)
    service_env="${ENV_DIR}/coordinator-edge-${DEPLOY_INSTANCE}.env"
    upsert_if_set "$service_env" COORDINATOR_ID COORDINATOR_ID
    upsert_if_set "$service_env" COORDINATOR_SUB_ID COORDINATOR_SUB_ID
    upsert_if_set "$service_env" DB_NAMESPACE DB_NAMESPACE
    upsert_if_set "$service_env" COORDINATOR_EDGE_PORT COORDINATOR_EDGE_PORT
    upsert_if_set "$service_env" LISTEN_ADDR LISTEN_ADDR
    ;;

  realm-processor)
    service_env="${ENV_DIR}/realm-processor-${DEPLOY_INSTANCE}.env"
    upsert_if_set "$service_env" REALM_ID REALM_ID
    upsert_if_set "$service_env" REALM_SUB_ID REALM_SUB_ID
    upsert_if_set "$service_env" DB_NAMESPACE DB_NAMESPACE
    upsert_if_set "$service_env" COORDINATOR_API_URLS COORDINATOR_API_URLS
    ;;

  realm-edge)
    service_env="${ENV_DIR}/realm-edge-${DEPLOY_INSTANCE}.env"
    upsert_if_set "$service_env" REALM_ID REALM_ID
    upsert_if_set "$service_env" REALM_SUB_ID REALM_SUB_ID
    upsert_if_set "$service_env" DB_NAMESPACE DB_NAMESPACE
    upsert_if_set "$service_env" REALM_EDGE_PORT REALM_EDGE_PORT
    upsert_if_set "$service_env" LISTEN_ADDR LISTEN_ADDR
    ;;

  worker)
    service_env="${ENV_DIR}/worker-${DEPLOY_INSTANCE}.env"
    upsert_if_set "$service_env" WORKER_USER_ID WORKER_USER_ID
    upsert_if_nonempty "$service_env" PRIVATE_KEY PRIVATE_KEY
    upsert_if_nonempty "$service_env" KEYSTORE_PATH KEYSTORE_PATH
    upsert_if_nonempty "$service_env" WALLET_PASSWORD WALLET_PASSWORD
    upsert_if_set "$service_env" COMPLETED_JOBS_LOG_FILE COMPLETED_JOBS_LOG_FILE
    upsert_if_set "$service_env" COORDINATOR_API_URLS COORDINATOR_API_URLS
    upsert_if_set "$service_env" REALM_API_URLS REALM_API_URLS
    upsert_if_set "$service_env" URL_ROTATION_STRATEGY URL_ROTATION_STRATEGY
    upsert_if_set "$service_env" BATCH_SIZE BATCH_SIZE
    ;;

  prove-proxy)
    service_env="${ENV_DIR}/prove-proxy-${DEPLOY_INSTANCE}.env"
    for key in \
      PROVE_PROXY_DISPATCH_WORKERS \
      PROVE_PROXY_LOCAL_FALLBACK \
      PROVE_PROXY_JOB_TIMEOUT_SECS \
      PROVE_PROXY_WORKER_UPSTREAM_URL \
      PROVE_PROXY_WORKER_ID \
      PROVE_PROXY_WORKER_POLL_INTERVAL_MS \
      PROVE_PROXY_WORKER_MAX_JOBS_PER_POLL \
      PROVE_PROXY_WORKER_METHODS \
      PSY_CAPTURE_INPUTS_DIR \
      PSY_CAPTURE_DIR \
      PSY_CAPTURE_METHODS \
      PSY_CAPTURE_LIMIT_PER_METHOD \
      PSY_CAPTURE_INCLUDE_OUTPUTS \
      PSY_FAUCET_OPERATORS_JSON \
      PSY_FAUCET_OPERATORS_JSON_B64 \
      PSY_FAUCET_TURNSTILE_SECRET \
      PSY_FAUCET_REQUIRE_TURNSTILE \
      PSY_FAUCET_WINDOW_CHECKPOINTS; do
      delete_env "$service_env" "$key"
    done
    upsert_if_set "$service_env" PROVE_PROXY_LISTEN_ADDR PROVE_PROXY_LISTEN_ADDR
    upsert_if_set "$service_env" PROVE_PROXY_DISPATCH_WORKERS PROVE_PROXY_DISPATCH_WORKERS
    upsert_if_set "$service_env" PROVE_PROXY_LOCAL_FALLBACK PROVE_PROXY_LOCAL_FALLBACK
    upsert_if_set "$service_env" PROVE_PROXY_JOB_TIMEOUT_SECS PROVE_PROXY_JOB_TIMEOUT_SECS
    upsert_if_nonempty "$service_env" PROVE_PROXY_WORKER_UPSTREAM_URL PROVE_PROXY_WORKER_UPSTREAM_URL
    upsert_if_nonempty "$service_env" PROVE_PROXY_WORKER_ID PROVE_PROXY_WORKER_ID
    upsert_if_set "$service_env" PROVE_PROXY_WORKER_POLL_INTERVAL_MS PROVE_PROXY_WORKER_POLL_INTERVAL_MS
    upsert_if_set "$service_env" PROVE_PROXY_WORKER_MAX_JOBS_PER_POLL PROVE_PROXY_WORKER_MAX_JOBS_PER_POLL
    upsert_if_nonempty "$service_env" PROVE_PROXY_WORKER_METHODS PROVE_PROXY_WORKER_METHODS
    upsert_if_nonempty "$service_env" PSY_CAPTURE_INPUTS_DIR PSY_CAPTURE_INPUTS_DIR
    upsert_if_nonempty "$service_env" PSY_CAPTURE_DIR PSY_CAPTURE_DIR
    upsert_if_nonempty "$service_env" PSY_CAPTURE_METHODS PSY_CAPTURE_METHODS
    upsert_if_set "$service_env" PSY_CAPTURE_LIMIT_PER_METHOD PSY_CAPTURE_LIMIT_PER_METHOD
    upsert_if_set "$service_env" PSY_CAPTURE_INCLUDE_OUTPUTS PSY_CAPTURE_INCLUDE_OUTPUTS
    upsert_if_set "$service_env" RPC_CONFIG RPC_CONFIG
    ;;

  faucet-server)
    service_env="${ENV_DIR}/faucet-server.env"
    upsert_if_set "$service_env" PSY_FAUCET_LISTEN_ADDR PSY_FAUCET_LISTEN_ADDR
    upsert_if_set "$service_env" RPC_CONFIG RPC_CONFIG
    upsert_if_nonempty "$service_env" PSY_FAUCET_OPERATORS_JSON PSY_FAUCET_OPERATORS_JSON
    upsert_if_nonempty "$service_env" PSY_FAUCET_OPERATORS_JSON_B64 PSY_FAUCET_OPERATORS_JSON_B64
    upsert_if_nonempty "$service_env" PSY_FAUCET_TURNSTILE_SECRET PSY_FAUCET_TURNSTILE_SECRET
    upsert_if_set "$service_env" PSY_FAUCET_REQUIRE_TURNSTILE PSY_FAUCET_REQUIRE_TURNSTILE
    upsert_if_set "$service_env" PSY_FAUCET_WINDOW_CHECKPOINTS PSY_FAUCET_WINDOW_CHECKPOINTS
    ;;

  relayer)
    service_env="${ENV_DIR}/relayer.env"
    upsert_if_set "$service_env" RELAYER_CONFIG RELAYER_CONFIG
    upsert_if_set "$service_env" PSY_DEPLOYMENTS_DIR PSY_DEPLOYMENTS_DIR
    upsert_if_set "$service_env" BRIDGE_RELAYER_LOG_FILE BRIDGE_RELAYER_LOG_FILE
    upsert_if_nonempty "$service_env" WALLET_PASSWORD WALLET_PASSWORD
    upsert_if_nonempty "$service_env" KEYSTORE_PATH KEYSTORE_PATH
    upsert_if_nonempty "$service_env" BRIDGE_RELAYER_L2_PRIVATE_KEY BRIDGE_RELAYER_L2_PRIVATE_KEY
    ;;

  psy-services)
    service_env="${ENV_DIR}/psy-services.env"
    if [ -z "${PSY_GENESIS_PATH:-}" ]; then
      PSY_GENESIS_PATH="$PARTH_HOME/genesis_contracts.index.json"
    fi
    [ -s "$PSY_GENESIS_PATH" ] || fail "missing canonical psy-services genesis contract index: $PSY_GENESIS_PATH"
    upsert_env "$service_env" PSY_SERVICES_HOME "$DEPLOY_PSY_SERVICES_HOME"
    upsert_env "$service_env" PSY_SERVICES_MIGRATIONS_PATH "${PSY_SERVICES_MIGRATIONS_PATH:-$DEPLOY_PSY_SERVICES_HOME/migrations}"
    upsert_if_set "$service_env" DATABASE_URL DATABASE_URL
    upsert_if_set "$service_env" PSY_SERVICES_REDIS_URL PSY_SERVICES_REDIS_URL
    upsert_if_set "$service_env" API_LISTEN API_LISTEN
    upsert_if_set "$service_env" PSY_NETWORK_TYPE PSY_NETWORK_TYPE
    upsert_if_set "$service_env" PSY_SERVICES_DISABLE_AUTH PSY_SERVICES_DISABLE_AUTH
    upsert_if_set "$service_env" PSY_JWT_SECRET PSY_JWT_SECRET
    upsert_if_set "$service_env" PSY_SERVICES_RUN_MIGRATIONS PSY_SERVICES_RUN_MIGRATIONS
    upsert_if_set "$service_env" PSY_NOSTR_ENABLED PSY_NOSTR_ENABLED
    upsert_if_set "$service_env" PSY_NOSTR_RELAY_URLS PSY_NOSTR_RELAY_URLS
    upsert_if_set "$service_env" PSY_NOSTR_LOOKBACK_SECONDS PSY_NOSTR_LOOKBACK_SECONDS
    upsert_if_set "$service_env" PSY_GENESIS_PATH PSY_GENESIS_PATH
    if [ -n "${PSY_GENESIS_USERS_PATH:-}" ]; then
      upsert_env "$service_env" PSY_GENESIS_USERS_PATH "$PSY_GENESIS_USERS_PATH"
    else
      delete_env "$service_env" PSY_GENESIS_USERS_PATH
    fi
    upsert_if_set "$service_env" INDEXER_GRAPHQL_URL INDEXER_GRAPHQL_URL
    upsert_if_set "$service_env" HASURA_GRAPHQL_ADMIN_SECRET HASURA_GRAPHQL_ADMIN_SECRET
    upsert_if_set "$service_env" PSY_NODE_URL PSY_NODE_URL
    upsert_if_set "$service_env" L1_RPC_URL L1_RPC_URL
    upsert_if_set "$service_env" STATE_MANAGER_ADDRESS STATE_MANAGER_ADDRESS
    ;;

  psy-indexer)
    service_env="${ENV_DIR}/psy-indexer-${DEPLOY_INSTANCE}.env"
    upsert_env "$service_env" PSY_SERVICES_HOME "$DEPLOY_PSY_SERVICES_HOME"
    upsert_if_set "$service_env" PSY_INDEXER_MODE PSY_INDEXER_MODE
    upsert_if_set "$service_env" PSY_EDGE_RPC_URL PSY_EDGE_RPC_URL
    upsert_if_set "$service_env" PSY_SERVICES_URL PSY_SERVICES_URL
    upsert_if_set "$service_env" PSY_JWT_SECRET PSY_JWT_SECRET
    upsert_if_set "$service_env" PSY_BACKUP_DIR PSY_BACKUP_DIR
    upsert_if_set "$service_env" PSY_POLL_INTERVAL_MS PSY_POLL_INTERVAL_MS
    upsert_if_set "$service_env" PSY_LOG_LEVEL PSY_LOG_LEVEL
    upsert_if_set "$service_env" PSY_NETWORK_TYPE PSY_NETWORK_TYPE
    upsert_if_set "$service_env" REALM_ID REALM_ID
    upsert_if_set "$service_env" REALM_SUB_ID REALM_SUB_ID
    ;;

  *)
    fail "unknown PARTH_SERVICE: ${PARTH_SERVICE}"
    ;;
esac

# Keep shared runtime paths and cluster endpoints in common.env only.
# Service-specific env files can outlive a release; if they retain PARTH_HOME
# or GENESIS_DATA_PATH they override common.env and make automatic/manual
# restarts boot from deleted releases.
for key in \
  PARTH_HOME \
  NETWORK \
  PROVING_BACKEND \
  SCYLLA_DB_URL \
  NATS_JETSTREAM_URL \
  REDIS_URL \
  GENESIS_DATA_PATH \
  CHECKPOINT_BACKUP_PATH \
  RUST_LOG \
  RUST_BACKTRACE \
  VERBOSE; do
  delete_env "$service_env" "$key"
done

unit_file="/etc/systemd/system/${PARTH_SYSTEMD_UNIT}"
syslog_identifier="${PARTH_SYSTEMD_UNIT%.service}"
unit_wants_extra=""
unit_after_extra=""
unit_exec_start_pre=""

case "$PARTH_SERVICE" in
  coordinator-edge)
    unit_wants_extra=" parth-coordinator-processor.service"
    unit_after_extra=" parth-coordinator-processor.service"
    ;;
  realm-processor)
    unit_wants_extra=" parth-coordinator-processor.service parth-coordinator-edge@0.service"
    unit_after_extra=" parth-coordinator-processor.service parth-coordinator-edge@0.service"
    unit_exec_start_pre='ExecStartPre=/usr/bin/env bash -lc '\''exec /usr/local/bin/parth-wait-jsonrpc "$COORDINATOR_API_URLS" "${PARTH_DEPENDENCY_JSONRPC_METHOD:-psy_get_latest_checkpoint_id}"'\'''
    ;;
  realm-edge)
    unit_wants_extra=" parth-realm-processor@${DEPLOY_INSTANCE}.service"
    unit_after_extra=" parth-realm-processor@${DEPLOY_INSTANCE}.service"
    ;;
  psy-indexer)
    unit_exec_start_pre='ExecStartPre=/usr/bin/env bash -lc '\''if [ -n "${PSY_EDGE_RPC_URL:-}" ]; then /usr/local/bin/parth-wait-jsonrpc "$PSY_EDGE_RPC_URL" "${PARTH_DEPENDENCY_JSONRPC_METHOD:-psy_get_latest_checkpoint_id}"; fi'\'''
    ;;
esac

cat >"$unit_file" <<EOF
[Unit]
Description=Parth ${PARTH_SERVICE} (${DEPLOY_INSTANCE})
Wants=network-online.target${unit_wants_extra}
After=network-online.target${unit_after_extra}

[Service]
Type=simple
User=parth
Group=parth
EnvironmentFile=${common_env}
EnvironmentFile=${service_env}
${unit_exec_start_pre}
ExecStart=/usr/bin/env bash -lc 'cd "\$PARTH_HOME" && exec bash deploy/bin/run-parth-service ${PARTH_SERVICE}'
Restart=always
RestartSec=5
TimeoutStopSec=60
KillSignal=SIGINT
LimitNOFILE=1048576
SyslogIdentifier=${syslog_identifier}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$PARTH_SYSTEMD_UNIT" >/dev/null
systemctl restart "$PARTH_SYSTEMD_UNIT"
systemctl --no-pager --full status "$PARTH_SYSTEMD_UNIT" || true
