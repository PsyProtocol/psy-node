#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/full-stack-lib.sh
source "$(dirname "$0")/full-stack-lib.sh"
bsc_full_stack_export

bash "$BSC_DEPLOY_DIR/status-local-l1.sh"
echo
LOCAL_STAGING_SOURCE_PARTH_DIR="$BSC_RUNTIME_PARTH_DIR" \
  bash "$PARTH_ROOT/deploy/local-testnet/stack/status.sh"

echo
printf '%-18s http://127.0.0.1:%s ' "Envio/Hasura" "$LOCAL_STAGING_INDEXER_PORT"
if curl -fsS --max-time 5 "http://127.0.0.1:$LOCAL_STAGING_INDEXER_PORT/healthz" >/dev/null 2>&1; then
  echo "ok"
else
  echo "failed"
fi

relayer_state="$LOCAL_STAGING_RELAYER_PROOF_DIR/daemon_state.toml"
if [ -s "$relayer_state" ]; then
  echo "relayer state: $relayer_state"
  sed -n -E '/^(last_|deposit_|withdrawal_)/p' "$relayer_state" | head -40
else
  echo "relayer state: unavailable"
fi
