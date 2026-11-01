#!/usr/bin/env bash
# deposit.sh <chain> <chain index> <user id> <secrets file> <result file> <amount> [extra deposit args]
# One legal USDT deposit from the test wallet; the note secrets come from the file (R0, R1, NOTE_SECRET, NULLIFIER_SECRET).
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
user_cli_env
e2e_require E2E_WALLET_KEY_FILE
chain=$1 chain_index=$2 user_id=$3 secrets=$4 result=$5 amount=$6
shift 6
[ -f "$secrets" ] || { echo "three-chain: secrets file not found" >&2; exit 2; }
set -a
. "$secrets"
set +a
token=$(doc "$chain" .protocol.tokens.USDT.l1Address)
router=$(doc "$chain" .proxies.Router_Proxy)
L1_PRIVATE_KEY=$(cat "$E2E_WALLET_KEY_FILE") timeout "${E2E_DEPOSIT_TIMEOUT:-300}" "$E2E_USER_CLI" deposit \
  --l1-rpc-url "$(rpc_url "$chain")" --router-address "$router" --token "$token" --amount "$amount" \
  --user-id "$user_id" --source-chain-index "$chain_index" --l2-token-contract-id 4 \
  --rpc-config "$E2E_USER_RPC_CONFIG" --result-file "$result" "$@"
