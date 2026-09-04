#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib/common.sh"
# shellcheck source=lib/multichain.sh
source "$(dirname "$0")/lib/multichain.sh"

multichain_validate_specs
runtime_file="$(multichain_runtime_file)"
runtime_dir="$(dirname "$runtime_file")"
runtime_tmp="$(mktemp)"

cleanup() {
  rm -f "$runtime_tmp" "${runtime_tmp}.next"
}
trap cleanup EXIT

mkdir -p "$runtime_dir"
jq -n --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema_version: 1, generated_at: $generated_at, chains: []}' >"$runtime_tmp"

mapfile -t chains < <(multichain_specs_json | jq -c 'sort_by(.chain_index)[]')
for chain in "${chains[@]}"; do
  network="$(jq -r '.network' <<<"$chain")"
  chain_index="$(jq -r '.chain_index' <<<"$chain")"
  deployment_dir="$PSY_CONTRACTS_DIR/deployments/$network"
  deployed="$deployment_dir/deployed-contracts.json"

  [ -s "$deployed" ] || {
    echo "missing deployed contracts summary for $network: $deployed" >&2
    exit 1
  }

  actual_chain_index="$(jq -er '.protocol.chain.l1ChainIndex' "$deployed")"
  [ "$actual_chain_index" = "$chain_index" ] || {
    echo "L1 chain index mismatch for $network: expected $chain_index, got $actual_chain_index" >&2
    exit 1
  }

  mapfile -t deployment_files < <(find "$deployment_dir" -maxdepth 1 -type f -name '*.json' -print)
  [ "${#deployment_files[@]}" -gt 0 ] || {
    echo "no Hardhat deployment receipts found for $network" >&2
    exit 1
  }
  start_block="$(jq -s '[.[] | .receipt.blockNumber? // empty] | min // empty' "${deployment_files[@]}")"
  [[ "$start_block" =~ ^[0-9]+$ ]] || {
    echo "could not derive deployment start block for $network" >&2
    exit 1
  }

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
  jq --argjson entry "$runtime_entry" '.chains += [$entry]' \
    "$runtime_tmp" >"${runtime_tmp}.next"
  mv "${runtime_tmp}.next" "$runtime_tmp"
done

jq -e '
  (.chains | length) >= 2
  and ([.chains[].chain_index] | length == (unique | length))
  and all(.chains[]; .contracts.Bridge and .contracts.StateManager and .contracts.Multicall3)
' "$runtime_tmp" >/dev/null
mv "$runtime_tmp" "$runtime_file"
trap - EXIT

echo "[multichain-l1] rebuilt runtime manifest from deployment receipts: $runtime_file"
jq '{schema_version, generated_at, chains: [.chains[] | {
  name, network, chain_id, chain_index, start_block, public_rpc_domain,
  bridge: .contracts.Bridge, state_manager: .contracts.StateManager
}]}' "$runtime_file"
