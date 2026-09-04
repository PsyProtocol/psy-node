#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

# Keep the legacy prove-proxy fallback so older private config files remain
# deployable, but new environments should set FAUCET_VM_NAME explicitly.
NAME="${FAUCET_VM_NAME:-${PROVE_PROXY_VM_NAME:-gcp-prove-proxy}}"
PSY_FAUCET_LISTEN_ADDR="${PSY_FAUCET_LISTEN_ADDR:-0.0.0.0:9998}"
PSY_FAUCET_PORT="${PSY_FAUCET_PORT:-${PSY_FAUCET_LISTEN_ADDR##*:}}"
UNIT="${PSY_FAUCET_SYSTEMD_UNIT:-parth-faucet-server.service}"

if [ -z "${PSY_FAUCET_OPERATORS_JSON:-}" ] && [ -z "${PSY_FAUCET_OPERATORS_JSON_B64:-}" ]; then
  faucet_operators_json="$(bash "$(dirname "$0")/generate-privacy-faucet-operators.sh")"
  PSY_FAUCET_OPERATORS_JSON_B64="$(printf '%s' "$faucet_operators_json" | base64 | tr -d '\n')"
  export PSY_FAUCET_OPERATORS_JSON_B64
  faucet_operator_count="$(jq '.operators | length' <<< "$faucet_operators_json")"
  echo "[deploy-faucet-server] generated operator config: operators=$faucet_operator_count"
fi

echo "[deploy-faucet-server] deploying faucet-server on ${NAME}:${PSY_FAUCET_PORT}"
ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "faucet-server" "deploy-faucet-server" "$UNIT" \
  "DEPLOY_INSTANCE=0" \
  "PSY_FAUCET_LISTEN_ADDR=$PSY_FAUCET_LISTEN_ADDR" \
  "RPC_CONFIG=${RPC_CONFIG:-/opt/parth/current/client_prover/config.json}" \
  "PSY_FAUCET_OPERATORS_JSON=${PSY_FAUCET_OPERATORS_JSON:-}" \
  "PSY_FAUCET_OPERATORS_JSON_B64=${PSY_FAUCET_OPERATORS_JSON_B64:-}" \
  "PSY_FAUCET_TURNSTILE_SECRET=${PSY_FAUCET_TURNSTILE_SECRET:-}" \
  "PSY_FAUCET_REQUIRE_TURNSTILE=${PSY_FAUCET_REQUIRE_TURNSTILE:-0}" \
  "PSY_FAUCET_WINDOW_CHECKPOINTS=${PSY_FAUCET_WINDOW_CHECKPOINTS:-120}"

run_health_check "$NAME" "ports" \
  "HEALTHCHECK_PORTS=${PSY_FAUCET_HEALTHCHECK_PORTS:-$PSY_FAUCET_PORT}" \
  "SYSTEMD_UNIT=$UNIT" \
  "HEALTHCHECK_START_DELAY=${PSY_FAUCET_HEALTHCHECK_START_DELAY:-10}"

run_health_check "$NAME" "jsonrpc" \
  "HEALTHCHECK_JSONRPC_URLS=http://127.0.0.1:${PSY_FAUCET_PORT}" \
  "HEALTHCHECK_JSONRPC_METHOD=psy_get_psy_faucet_config" \
  "SYSTEMD_UNIT=$UNIT" \
  "HEALTHCHECK_START_DELAY=0"
