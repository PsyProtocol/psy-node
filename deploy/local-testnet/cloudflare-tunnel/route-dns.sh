#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_ensure_cloudflared

for host in \
  "$LOCAL_CF_APP_HOST" \
  "$LOCAL_CF_EXPLORER_HOST" \
  "$LOCAL_CF_IDE_HOST" \
  "$LOCAL_CF_COORDINATOR_HOST" \
  "$LOCAL_CF_REALM0_HOST" \
  "$LOCAL_CF_REALM1_HOST" \
  "$LOCAL_CF_PROVE_HOST" \
  "$LOCAL_CF_FAUCET_HOST" \
  "$LOCAL_CF_SERVICES_HOST" \
  "$LOCAL_CF_INDEXER_HOST" \
  "$LOCAL_CF_L1_RPC_HOST" \
  "$LOCAL_CF_ETH_FAUCET_HOST" \
  "$LOCAL_CF_NOSTR_HOST"
do
  echo "[local-cf-tunnel] routing $host -> $(local_cf_tunnel_ref)"
  cloudflared tunnel route dns "$(local_cf_tunnel_ref)" "$host"
done
