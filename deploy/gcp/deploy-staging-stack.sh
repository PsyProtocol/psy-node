#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

: "${DEPLOY_POSTGRES:=1}"
: "${DEPLOY_ANVIL:=1}"
: "${DEPLOY_L1_CONTRACTS:=1}"
: "${DEPLOY_NOSTR:=1}"
: "${DEPLOY_ENVIO:=1}"
: "${DEPLOY_RELAYER:=0}"
: "${DEPLOY_PROVE_PROXY:=1}"
: "${DEPLOY_WORKERS:=1}"
: "${DEPLOY_PSY_SERVICES:=1}"
: "${DEPLOY_PSY_INDEXER:=1}"

source "$SCRIPT_DIR/lib/common.sh"

if [ -z "${PARTH_BUNDLE:-}" ]; then
  PARTH_BUNDLE="$(bash "$SCRIPT_DIR/build-parth-bundle.sh")"
  export PARTH_BUNDLE
fi

run_parallel() {
  local -a names pids
  local name pid failed=0

  names=()
  pids=()
  for name in "$@"; do
    echo "[stack] starting ${name}"
    bash "$SCRIPT_DIR/${name}" &
    names+=("$name")
    pids+=("$!")
  done

  for i in "${!pids[@]}"; do
    pid="${pids[$i]}"
    name="${names[$i]}"
    if wait "$pid"; then
      echo "[stack] completed ${name}"
    else
      echo "[stack] failed ${name}" >&2
      failed=1
    fi
  done

  [ "$failed" = "0" ]
}

infra_scripts=(create-scylla.sh create-redis.sh create-nats.sh)
[ "$DEPLOY_POSTGRES" = "1" ] && infra_scripts+=(create-postgres.sh)
[ "$DEPLOY_ANVIL" = "1" ] && infra_scripts+=(create-anvil.sh)
[ "$DEPLOY_NOSTR" = "1" ] && infra_scripts+=(create-nostr.sh)

run_parallel "${infra_scripts[@]}"

if [ "$DEPLOY_L1_CONTRACTS" = "1" ]; then
  bash "$SCRIPT_DIR/deploy-l1-contracts.sh"
fi

if [ "$DEPLOY_ENVIO" = "1" ]; then
  bash "$SCRIPT_DIR/create-envio.sh"
fi

bash "$SCRIPT_DIR/deploy-cp-ce-stack.sh"

if [ "$DEPLOY_RELAYER" = "1" ]; then
  bash "$SCRIPT_DIR/deploy-relayer.sh"
fi

if [ "$DEPLOY_PROVE_PROXY" = "1" ]; then
  bash "$SCRIPT_DIR/deploy-prove-proxy.sh"
fi

if [ "$DEPLOY_WORKERS" = "1" ]; then
  bash "$SCRIPT_DIR/deploy-coordinator-workers.sh"
  if [ "${DEPLOY_REALM_WORKERS:-0}" = "1" ]; then
    bash "$SCRIPT_DIR/deploy-worker-1.sh"
  fi
fi

echo "[stack] staging stack deployment finished"
