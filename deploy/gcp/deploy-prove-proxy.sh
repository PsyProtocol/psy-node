#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

PROVE_PROXY_INSTANCE="${PROVE_PROXY_INSTANCE:-1}"
NAME="${PROVE_PROXY_VM_NAME:-parth-prove-proxy-${PROVE_PROXY_INSTANCE}}"
DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-0}"
PROVE_PROXY_LISTEN_ADDR="${PROVE_PROXY_LISTEN_ADDR:-0.0.0.0:9999}"
PROVE_PROXY_PORT="${PROVE_PROXY_PORT:-${PROVE_PROXY_LISTEN_ADDR##*:}}"
UNIT="parth-prove-proxy@${DEPLOY_INSTANCE}.service"

# Proof families per instance. One instance runs `all` (the pre-split layout).
# With DEPLOY_SYSTEM_PROVE_PROXY=1 this instance serves wallets only (`user`)
# and a second unit on the same VM serves the relayer (`system`, own port);
# the bundle's client config then points system_prove_proxy_url at it.
DEPLOY_SYSTEM_PROVE_PROXY="${DEPLOY_SYSTEM_PROVE_PROXY:-0}"
if [ "$DEPLOY_SYSTEM_PROVE_PROXY" = "1" ]; then
  PROVE_PROXY_ROLE="${PROVE_PROXY_ROLE:-user}"
else
  PROVE_PROXY_ROLE="${PROVE_PROXY_ROLE:-all}"
fi
# Instance 1 is what PROVE_PROXY_CLEAN_LEGACY_WORKERS disables below, so the
# system unit defaults to instance 2.
SYSTEM_PROVE_PROXY_DEPLOY_INSTANCE="${SYSTEM_PROVE_PROXY_DEPLOY_INSTANCE:-2}"
SYSTEM_PROVE_PROXY_LISTEN_ADDR="${SYSTEM_PROVE_PROXY_LISTEN_ADDR:-0.0.0.0:9997}"
SYSTEM_PROVE_PROXY_PORT="${SYSTEM_PROVE_PROXY_LISTEN_ADDR##*:}"
SYSTEM_UNIT="parth-prove-proxy@${SYSTEM_PROVE_PROXY_DEPLOY_INSTANCE}.service"

echo "[deploy-prove-proxy] deploying standalone prove-proxy on ${NAME}:${PROVE_PROXY_PORT} role=${PROVE_PROXY_ROLE}"
ensure_parth_vm "$NAME"

deploy_parth_service "$NAME" "prove-proxy" "deploy-prove-proxy" "$UNIT" \
  "DEPLOY_INSTANCE=$DEPLOY_INSTANCE" \
  "PROVE_PROXY_LISTEN_ADDR=$PROVE_PROXY_LISTEN_ADDR" \
  "PROVE_PROXY_ROLE=$PROVE_PROXY_ROLE" \
  "PSY_CAPTURE_INPUTS_DIR=${PSY_CAPTURE_INPUTS_DIR:-}" \
  "PSY_CAPTURE_DIR=${PSY_CAPTURE_DIR:-}" \
  "PSY_CAPTURE_METHODS=${PSY_CAPTURE_METHODS:-}" \
  "PSY_CAPTURE_LIMIT_PER_METHOD=${PSY_CAPTURE_LIMIT_PER_METHOD:-3}" \
  "PSY_CAPTURE_INCLUDE_OUTPUTS=${PSY_CAPTURE_INCLUDE_OUTPUTS:-1}" \
  "RPC_CONFIG=${RPC_CONFIG:-/opt/parth/current/client_prover/config.json}"

if [ "$DEPLOY_SYSTEM_PROVE_PROXY" = "1" ]; then
  echo "[deploy-prove-proxy] deploying system prove-proxy on ${NAME}:${SYSTEM_PROVE_PROXY_PORT} role=system"
  DEPLOY_INSTANCE="$SYSTEM_PROVE_PROXY_DEPLOY_INSTANCE" \
    deploy_parth_service "$NAME" "prove-proxy" "deploy-prove-proxy" "$SYSTEM_UNIT" \
      "DEPLOY_INSTANCE=$SYSTEM_PROVE_PROXY_DEPLOY_INSTANCE" \
      "PROVE_PROXY_LISTEN_ADDR=$SYSTEM_PROVE_PROXY_LISTEN_ADDR" \
      "PROVE_PROXY_ROLE=system" \
      "RPC_CONFIG=${RPC_CONFIG:-/opt/parth/current/client_prover/config.json}"
fi

if [ "${PROVE_PROXY_CLEAN_LEGACY_WORKERS:-1}" = "1" ]; then
  run_remote_command "$NAME" \
    "sudo systemctl disable --now parth-prove-proxy@1.service >/dev/null 2>&1 || true; sudo systemctl reset-failed parth-prove-proxy@1.service >/dev/null 2>&1 || true"
fi

healthcheck_ports="${PROVE_PROXY_HEALTHCHECK_PORTS:-$PROVE_PROXY_PORT}"
if [ "$DEPLOY_SYSTEM_PROVE_PROXY" = "1" ]; then
  healthcheck_ports="${healthcheck_ports} ${SYSTEM_PROVE_PROXY_PORT}"
fi
run_health_check "$NAME" "ports" \
  "HEALTHCHECK_PORTS=${healthcheck_ports}" \
  "HEALTHCHECK_HTTP_URLS=${PROVE_PROXY_HEALTHCHECK_HTTP_URLS:-}" \
  "HEALTHCHECK_START_DELAY=${PROVE_PROXY_HEALTHCHECK_START_DELAY:-10}"
