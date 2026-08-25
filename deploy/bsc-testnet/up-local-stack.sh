#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/full-stack-lib.sh
source "$(dirname "$0")/full-stack-lib.sh"
bsc_full_stack_export
require_local_transaction_authorization

phase="${1:-${BSC_LOCAL_PHASE:-all}}"
case "$phase" in
  l1 | core | bridge | all) ;;
  *) die "usage: $0 [l1|core|bridge|all]" ;;
esac
export BSC_LOCAL_PHASE="$phase"

if [ "${BSC_LOCAL_RESET:-0}" = "1" ]; then
  echo "[bsc-testnet] resetting isolated BSC full stack"
  BSC_LOCAL_REMOVE_VOLUMES=1 bash "$BSC_DEPLOY_DIR/down-local-stack.sh" || true
fi

bash "$BSC_DEPLOY_DIR/preflight-local-stack.sh"

BSC_LOCAL_RESET="${BSC_LOCAL_RESET:-0}" \
AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 \
  bash "$BSC_DEPLOY_DIR/up-local-l1.sh"

# Reset has already been handled before starting Anvil. Do not let the reused
# local stack reset path stop the fresh chain again.
export LOCAL_STAGING_RESET=0
export BSC_LOCAL_RESET=0

if [ "$phase" = "bridge" ]; then
  curl -fsS --max-time 5 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}' \
    "http://127.0.0.1:$LOCAL_STAGING_COORDINATOR_EDGE_PORT" \
    | jq -e '.error == null and (.result | type == "number")' >/dev/null \
    || die "core phase is not ready: coordinator RPC is unavailable"
  curl -fsS --max-time 5 "http://$LOCAL_STAGING_PSY_SERVICES_ADDR/health" >/dev/null \
    || die "core phase is not ready: psy-services health check failed"
fi

case "$phase" in
  l1) export LOCAL_CF_STOP_AFTER="l1" ;;
  core) export LOCAL_CF_STOP_AFTER="core" ;;
  bridge) export LOCAL_CF_STOP_AFTER="relayer" ;;
  all) unset LOCAL_CF_STOP_AFTER ;;
esac

bash "$PARTH_ROOT/deploy/local-testnet/cloudflare-tunnel/up.sh"

echo "[bsc-testnet] phase complete: $phase"
echo "  status: bash $BSC_DEPLOY_DIR/status-local-stack.sh"
