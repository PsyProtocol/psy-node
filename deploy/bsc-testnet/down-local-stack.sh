#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/full-stack-lib.sh
source "$(dirname "$0")/full-stack-lib.sh"
bsc_full_stack_export

stack_down_args=()
envio_down_args=()
if [ "${BSC_LOCAL_REMOVE_VOLUMES:-0}" = "1" ]; then
  stack_down_args+=(--volumes)
  envio_down_args+=(-v)
fi

LOCAL_STAGING_SOURCE_PARTH_DIR="$BSC_RUNTIME_PARTH_DIR" \
  bash "$PARTH_ROOT/deploy/local-testnet/stack/down.sh" "${stack_down_args[@]}" || true

envio_compose="$BSC_RUNTIME_PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio/generated/docker-compose.yaml"
if [ -f "$envio_compose" ]; then
  docker compose \
    -p "$LOCAL_CF_ENVIO_COMPOSE_PROJECT" \
    -f "$envio_compose" \
    down "${envio_down_args[@]}" || true
fi

bash "$BSC_DEPLOY_DIR/down-local-l1.sh"
echo "[bsc-testnet] full stack stopped"
