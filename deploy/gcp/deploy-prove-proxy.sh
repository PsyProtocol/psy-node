#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

PROVE_PROXY_INSTANCE="${PROVE_PROXY_INSTANCE:-1}"
NAME="${PROVE_PROXY_VM_NAME:-parth-prove-proxy-${PROVE_PROXY_INSTANCE}}"
DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-0}"
PROVE_PROXY_LISTEN_ADDR="${PROVE_PROXY_LISTEN_ADDR:-0.0.0.0:9999}"
PROVE_PROXY_PORT="${PROVE_PROXY_PORT:-${PROVE_PROXY_LISTEN_ADDR##*:}}"
UNIT="parth-prove-proxy@${DEPLOY_INSTANCE}.service"

echo "[deploy-prove-proxy] deploying standalone prove-proxy on ${NAME}:${PROVE_PROXY_PORT}"
ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "prove-proxy" "deploy-prove-proxy" "$UNIT" \
  "DEPLOY_INSTANCE=$DEPLOY_INSTANCE" \
  "PROVE_PROXY_LISTEN_ADDR=$PROVE_PROXY_LISTEN_ADDR" \
  "PSY_CAPTURE_INPUTS_DIR=${PSY_CAPTURE_INPUTS_DIR:-}" \
  "PSY_CAPTURE_DIR=${PSY_CAPTURE_DIR:-}" \
  "PSY_CAPTURE_METHODS=${PSY_CAPTURE_METHODS:-}" \
  "PSY_CAPTURE_LIMIT_PER_METHOD=${PSY_CAPTURE_LIMIT_PER_METHOD:-3}" \
  "PSY_CAPTURE_INCLUDE_OUTPUTS=${PSY_CAPTURE_INCLUDE_OUTPUTS:-1}" \
  "RPC_CONFIG=${RPC_CONFIG:-/opt/parth/current/client_prover/config.json}"

if [ "${PROVE_PROXY_CLEAN_LEGACY_WORKERS:-1}" = "1" ]; then
  run_remote_command "$NAME" \
    "sudo systemctl disable --now parth-prove-proxy@1.service >/dev/null 2>&1 || true; sudo systemctl reset-failed parth-prove-proxy@1.service >/dev/null 2>&1 || true"
fi

run_health_check "$NAME" "ports" \
  "HEALTHCHECK_PORTS=${PROVE_PROXY_HEALTHCHECK_PORTS:-$PROVE_PROXY_PORT}" \
  "HEALTHCHECK_HTTP_URLS=${PROVE_PROXY_HEALTHCHECK_HTTP_URLS:-}" \
  "HEALTHCHECK_START_DELAY=${PROVE_PROXY_HEALTHCHECK_START_DELAY:-10}"
