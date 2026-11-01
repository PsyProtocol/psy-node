#!/usr/bin/env bash
# withdraw.sh <chain> <chain index> <user key file> <token address> <amount> <recipient> <nonce> <result file> [contract id]
# One L2 withdrawal. The nonce must be fresh per destination chain; a failed run is never retried blindly here.
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
user_cli_env
chain=$1 chain_index=$2 key_file=$3 token=$4 amount=$5 recipient=$6 nonce=$7 result=$8
contract_id=${9:-}
extra=()
[ -z "$contract_id" ] || extra=(--contract-id "$contract_id")
PRIVATE_KEY=$(cat "$key_file") exec "$E2E_USER_CLI" --result-file "$result" withdraw --sign-type zk \
  --rpc-config "$E2E_USER_RPC_CONFIG" --l1-rpc-url "$(rpc_url "$chain")" --destination-chain-index "$chain_index" \
  --token-address "$token" --amount "$amount" --recipient "$recipient" --nonce "$nonce" "${extra[@]}"
