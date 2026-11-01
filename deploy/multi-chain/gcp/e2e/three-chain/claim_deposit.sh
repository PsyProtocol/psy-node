#!/usr/bin/env bash
# claim_deposit.sh <chain> <chain index> <user id> <user key file> <secrets file> <deposit result> <deposit index> <amount> <out dir>
# Build the deposit proof (resume, no broadcast), then claim-deposit on L2.
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
user_cli_env
chain=$1 chain_index=$2 user_id=$3 key_file=$4 secrets=$5 deposit_result=$6 deposit_index=$7 amount=$8 out=$9
mkdir -p "$out"
tx_hash=$(jq -r .transaction_hash "$deposit_result")
chain_id=$(jq -r .chain_id "$deposit_result")
set -a
. "$secrets"
set +a
token=$(doc "$chain" .protocol.tokens.USDT.l1Address)
router=$(doc "$chain" .proxies.Router_Proxy)
timeout 900 "$E2E_USER_CLI" deposit --l1-rpc-url "$(rpc_url "$chain")" --router-address "$router" --token "$token" --amount "$amount" \
  --user-id "$user_id" --source-chain-index "$chain_index" --l2-token-contract-id 4 --rpc-config "$E2E_USER_RPC_CONFIG" \
  --resume-deposit-index "$deposit_index" --resume-tx-hash "$tx_hash" --resume-chain-id "$chain_id" \
  --deposit-proof-output "$out/deposit-proof.json" --result-file "$out/proof.result.json" > "$out/proof.log" 2>&1 \
  || { tail -3 "$out/proof.log" | cut -c1-200 >&2; exit 1; }
PRIVATE_KEY=$(cat "$key_file") timeout 900 "$E2E_USER_CLI" claim-deposit --sign-type zk --rpc-config "$E2E_USER_RPC_CONFIG" \
  --token-l1-address "$token" --amount "$amount" --source-chain-index "$chain_index" --user-id "$user_id" \
  --deposit-index "$deposit_index" --deposit-proof "$out/deposit-proof.json" --result-file "$out/claim.result.json" \
  > "$out/claim.log" 2>&1 || { tail -3 "$out/claim.log" | cut -c1-200 >&2; exit 1; }
cat "$out/claim.result.json"
