#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib/common.sh"
# shellcheck source=lib/multichain.sh
source "$(dirname "$0")/lib/multichain.sh"

multichain_validate_specs
runtime_file="$(multichain_runtime_file)"
runtime_dir="$(dirname "$runtime_file")"
pending_file="${runtime_file}.pending"
(umask 077; mkdir -p "$runtime_dir")
# Serialize invocations before inspecting the progress marker. Keep the lock
# inode stable so a second invocation cannot deploy the same chain concurrently.
saved_umask="$(umask)"
umask 077
exec 9>>"${runtime_file}.lock"
umask "$saved_umask"
flock -n 9 || { echo 'another L1 deployment is running' >&2; exit 1; }
[ ! -e "$pending_file" ] || {
  echo "unfinished L1 deployment: $pending_file; reconcile it before sending new deployment transactions" >&2
  exit 1
}
l1_host="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
l1_contracts_home="${L1_CONTRACTS_HOME:-/opt/parth/l1-contracts/current}"

runtime_tmp="$(mktemp "$runtime_dir/.l1-deployments.XXXXXX")"
install -m 0600 /dev/null "${runtime_tmp}.next"
remote_env=""
jq -n --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema_version: 1, generated_at: $generated_at, chains: []}' >"$runtime_tmp"

cleanup() {
  rm -f "$runtime_tmp" "${runtime_tmp}.next"
  [ -z "$remote_env" ] || rm -f "$remote_env"
}
trap cleanup EXIT

record_pending() {
  install -m 0600 "$runtime_tmp" "${pending_file}.tmp"
  mv "${pending_file}.tmp" "$pending_file"
}
record_pending
mapfile -t chains < <(multichain_specs_json | jq -c 'sort_by(.chain_index)[]')

for chain in "${chains[@]}"; do
  name="$(jq -r '.name' <<<"$chain")"
  network="$(jq -r '.network' <<<"$chain")"
  chain_id="$(jq -r '.chain_id' <<<"$chain")"
  chain_index="$(jq -r '.chain_index' <<<"$chain")"
  rpc_url="$(jq -r '.rpc_url' <<<"$chain")"

  chain_started="$(date +%s)"
  install -m 0600 /dev/null "${runtime_tmp}.next"
  jq --arg network "$network" '.in_progress = $network' "$runtime_tmp" > "${runtime_tmp}.next"
  mv "${runtime_tmp}.next" "$runtime_tmp"
  record_pending
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
  rsync -az --delete --rsync-path='sudo rsync' \
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
  install -m 0600 /dev/null "${runtime_tmp}.next"
  jq --argjson entry "$runtime_entry" '.chains += [$entry] | .in_progress = null' "$runtime_tmp" >"${runtime_tmp}.next"
  mv "${runtime_tmp}.next" "$runtime_tmp"
  record_pending
  rm -f "$remote_env"
  remote_env=""
  echo "[multichain-l1] completed network=$network chain_index=$chain_index start_block=$start_block elapsed_seconds=$(( $(date +%s) - chain_started ))"
  jq '{network, chain_id, chain_index, start_block, bridge: .contracts.Bridge, state_manager: .contracts.StateManager}' <<< "$runtime_entry"
done

jq -e '
  (.chains | length) >= 2
  and ([.chains[].chain_index] | length == (unique | length))
  and all(.chains[]; .contracts.Bridge and .contracts.StateManager and .contracts.Multicall3)
' "$runtime_tmp" >/dev/null
MULTICHAIN_L1_RUNTIME_FILE="$runtime_tmp" multichain_require_runtime
mv "$runtime_tmp" "$runtime_file"
rm -f "$pending_file"
trap - EXIT

echo "[multichain-l1] wrote runtime manifest: $runtime_file"
jq '{schema_version, generated_at, chains: [.chains[] | {
  name, network, chain_id, chain_index, start_block, public_rpc_domain,
  bridge: .contracts.Bridge, state_manager: .contracts.StateManager
}]}' "$runtime_file"
