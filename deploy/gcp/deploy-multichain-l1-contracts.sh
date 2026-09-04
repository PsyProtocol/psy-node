#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib/common.sh"
# shellcheck source=lib/multichain.sh
source "$(dirname "$0")/lib/multichain.sh"

multichain_validate_specs
runtime_file="$(multichain_runtime_file)"
runtime_dir="$(dirname "$runtime_file")"
runtime_tmp="$(mktemp)"
l1_host="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
l1_contracts_home="${L1_CONTRACTS_HOME:-/opt/parth/l1-contracts/current}"

mkdir -p "$runtime_dir"
jq -n --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema_version: 1, generated_at: $generated_at, chains: []}' >"$runtime_tmp"

cleanup() {
  rm -f "$runtime_tmp"
}
trap cleanup EXIT

mapfile -t chains < <(multichain_specs_json | jq -c 'sort_by(.chain_index)[]')

for chain in "${chains[@]}"; do
  name="$(jq -r '.name' <<<"$chain")"
  network="$(jq -r '.network' <<<"$chain")"
  chain_id="$(jq -r '.chain_id' <<<"$chain")"
  chain_index="$(jq -r '.chain_index' <<<"$chain")"
  rpc_url="$(jq -r '.rpc_url' <<<"$chain")"

  echo "[multichain-l1] deploying $name network=$network chain_id=$chain_id chain_index=$chain_index"
  MULTICHAIN_CURRENT_L1_NETWORK="$network" \
  MULTICHAIN_CURRENT_CHAIN_ID="$chain_id" \
  MULTICHAIN_CURRENT_L1_RPC_URL="$rpc_url" \
    bash "$GCP_DIR/deploy-l1-contracts.sh"

  remote_env="$(mktemp)"
  run_remote_command "$l1_host" "sudo cat /etc/parth/l1.env" >"$remote_env"
  actual_network="$(awk -F= '$1 == "L1_DEPLOYMENTS_NETWORK" {print substr($0, index($0, "=") + 1); exit}' "$remote_env")"
  actual_chain_id="$(awk -F= '$1 == "CHAIN_ID" {print substr($0, index($0, "=") + 1); exit}' "$remote_env")"
  [ "$actual_network" = "$network" ] || {
    echo "L1 deployment network mismatch: expected $network, got $actual_network" >&2
    rm -f "$remote_env"
    exit 1
  }
  [ "$actual_chain_id" = "$chain_id" ] || {
    echo "L1 deployment chain ID mismatch: expected $chain_id, got $actual_chain_id" >&2
    rm -f "$remote_env"
    exit 1
  }

  mkdir -p "$PSY_CONTRACTS_DIR/deployments/$network"
  rsync -az --delete \
    "$l1_host:$l1_contracts_home/deployments/$network/" \
    "$PSY_CONTRACTS_DIR/deployments/$network/"

  deployed="$PSY_CONTRACTS_DIR/deployments/$network/deployed-contracts.json"
  [ -s "$deployed" ] || {
    echo "missing synced deployed-contracts.json for $network" >&2
    rm -f "$remote_env"
    exit 1
  }
  actual_chain_index="$(jq -er '.protocol.chain.l1ChainIndex' "$deployed")"
  [ "$actual_chain_index" = "$chain_index" ] || {
    echo "L1 chain index mismatch for $network: expected $chain_index, got $actual_chain_index" >&2
    rm -f "$remote_env"
    exit 1
  }

  start_block="$(awk -F= '$1 == "START_BLOCK" {print substr($0, index($0, "=") + 1); exit}' "$remote_env")"
  runtime_entry="$(
    jq -nc \
      --argjson spec "$chain" \
      --argjson start_block "$start_block" \
      --slurpfile deployed "$deployed" '
        $spec + {
          start_block: $start_block,
          contracts: ($deployed[0].core // $deployed[0].contracts),
          protocol: $deployed[0].protocol
        }
      ' </dev/null
  )"
  jq --argjson entry "$runtime_entry" '.chains += [$entry]' "$runtime_tmp" >"${runtime_tmp}.next"
  mv "${runtime_tmp}.next" "$runtime_tmp"
  rm -f "$remote_env"
done

jq -e '
  (.chains | length) >= 2
  and ([.chains[].chain_index] | length == (unique | length))
  and all(.chains[]; .contracts.Bridge and .contracts.StateManager and .contracts.Multicall3)
' "$runtime_tmp" >/dev/null
mv "$runtime_tmp" "$runtime_file"
trap - EXIT

echo "[multichain-l1] wrote runtime manifest: $runtime_file"
jq '{schema_version, generated_at, chains: [.chains[] | {
  name, network, chain_id, chain_index, start_block, public_rpc_domain,
  bridge: .contracts.Bridge, state_manager: .contracts.StateManager
}]}' "$runtime_file"
