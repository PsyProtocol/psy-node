#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=deploy/gcp/lib/multichain.sh
source "$(dirname "$0")/../lib/multichain.sh"
export MULTICHAIN_L1_RPC_PROVIDER=alchemy
valid='[{"chain_id":11155111,"rpc_url":"https://eth-sepolia.g.alchemy.com/v2/test"},{"chain_id":97,"rpc_url":"https://bnb-testnet.g.alchemy.com/v2/test"},{"chain_id":84532,"rpc_url":"https://base-sepolia.g.alchemy.com/v2/test"}]'
multichain_validate_rpc_provider <<<"$valid"
for expression in \
  '.[2].rpc_url = "https://base-sepolia-rpc.publicnode.com"' \
  '.[1].rpc_fallback_url = "https://bsc-testnet.drpc.org"' \
  '.[2].rpc_url = "https://eth-sepolia.g.alchemy.com/v2/test"' \
  '.[0].rpc_url = "https://eth-sepolia.g.alchemy.com.evil.example/v2/test"' \
  '.[0].rpc_url = ""'; do
  if jq -c "$expression" <<<"$valid" | multichain_validate_rpc_provider 2>/dev/null; then
    echo "FAIL: accepted invalid RPC configuration" >&2
    exit 1
  fi
done
export MULTICHAIN_L1_RPC_PROVIDER=any
multichain_validate_rpc_provider <<<'[{"chain_id":31337,"rpc_url":"http://127.0.0.1:8545"}]'
echo "PASS: three Alchemy chains, rejection of public/wrong-chain/fallback URLs, unchanged opt-out"
