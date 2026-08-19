#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_require_command python3

export LOCAL_CF_ETH_FAUCET_PORT
export LOCAL_CF_ETH_FAUCET_BALANCE_ETH="${LOCAL_CF_ETH_FAUCET_BALANCE_ETH:-10}"
export LOCAL_CF_L1_RPC_HOST
export LOCAL_CF_ETH_FAUCET_PUBLIC_RPC_URL="${LOCAL_CF_ETH_FAUCET_PUBLIC_RPC_URL:-$(local_cf_l1_rpc_public_url)}"
export LOCAL_STAGING_L1_RPC_PORT
export LOCAL_STAGING_L1_CHAIN_ID

exec python3 "$SCRIPT_DIR/eth-faucet.py"
