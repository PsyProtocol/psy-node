#!/usr/bin/env bash

multichain_enabled() {
  case "${MULTICHAIN_L1_ENABLED:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

multichain_specs_json() {
  : "${MULTICHAIN_L1_CHAINS_JSON:?MULTICHAIN_L1_CHAINS_JSON is required}"
  printf '%s\n' "$MULTICHAIN_L1_CHAINS_JSON"
}

multichain_runtime_file() {
  local repository_root
  repository_root="${REPO_ROOT:-${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}}"
  printf '%s\n' "${MULTICHAIN_L1_RUNTIME_FILE:-$repository_root/deploy/multi-chain/gcp/runtime/l1-deployments.json}"
}

multichain_validate_specs() {
  local json
  json="$(multichain_specs_json)"

  jq -e '
    type == "array" and length >= 2
    and all(.[ ];
      (.name | type == "string" and length > 0)
      and (.network | type == "string" and test("^[A-Za-z][A-Za-z0-9_-]*$"))
      and (.chain_id | type == "number" and floor == . and . > 0)
      and (.chain_index | type == "number" and floor == . and . >= 0 and . <= 255)
      and (.rpc_url | type == "string" and test("^https?://"))
      and (.public_rpc_domain | type == "string" and test("^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$"))
      and (.explorer_url | type == "string" and test("^https?://"))
    )
    and ([.[].network] | length == (unique | length))
    and ([.[].chain_id] | length == (unique | length))
    and ([.[].chain_index] | length == (unique | length))
    and ([.[].public_rpc_domain] | length == (unique | length))
  ' <<<"$json" >/dev/null || {
    echo "invalid MULTICHAIN_L1_CHAINS_JSON" >&2
    return 1
  }
}

multichain_require_runtime() {
  local runtime_file expected_registry actual_registry
  runtime_file="$(multichain_runtime_file)"
  [ ! -e "${runtime_file}.pending" ] || {
    echo "multichain L1 deployment is incomplete: ${runtime_file}.pending" >&2
    echo "reconcile the recorded L1 transactions before using the previous runtime manifest" >&2
    return 1
  }
  [ -s "$runtime_file" ] || {
    echo "missing multichain L1 runtime manifest: $runtime_file" >&2
    echo "run fresh-staging step 10 before deploying Envio, psy-services, relayer, Caddy, or frontends" >&2
    return 1
  }
  jq -e '
    .schema_version == 1
    and (.chains | type == "array" and length >= 2)
    and ([.chains[].network] | length == (unique | length))
    and ([.chains[].chain_id] | length == (unique | length))
    and ([.chains[].chain_index] | length == (unique | length))
    and all(.chains[];
      (.network | type == "string" and length > 0)
      and (.chain_id | type == "number" and floor == . and . > 0)
      and (.chain_index | type == "number" and floor == . and . >= 0 and . <= 255)
      and (.start_block | type == "number" and floor == . and . >= 0)
      and (.rpc_url | type == "string" and test("^https?://"))
      and (.contracts.Bridge | type == "string" and test("^0x[0-9a-fA-F]{40}$") and . != "0x0000000000000000000000000000000000000000")
      and (.contracts.StateManager | type == "string" and test("^0x[0-9a-fA-F]{40}$") and . != "0x0000000000000000000000000000000000000000")
    )
  ' "$runtime_file" >/dev/null || {
    echo "invalid multichain L1 runtime manifest: $runtime_file" >&2
    return 1
  }

  if [ -n "${MULTICHAIN_L1_CHAINS_JSON:-}" ]; then
    multichain_validate_specs || return 1
    expected_registry="$(multichain_specs_json | jq -c 'sort_by(.chain_index) | map([.network, .chain_id, .chain_index])')"
    actual_registry="$(jq -c '.chains | sort_by(.chain_index) | map([.network, .chain_id, .chain_index])' "$runtime_file")"
    [ "$actual_registry" = "$expected_registry" ] || {
      echo "multichain L1 manifest does not match the configured registry" >&2
      echo "expected: $expected_registry" >&2
      echo "actual:   $actual_registry" >&2
      return 1
    }
  fi
}

multichain_runtime_json() {
  multichain_require_runtime || return
  cat "$(multichain_runtime_file)"
}

multichain_primary_chain() {
  local runtime_file primary_network
  runtime_file="$(multichain_runtime_file)"
  primary_network="${MULTICHAIN_PRIMARY_NETWORK:-sepolia}"
  multichain_require_runtime || return
  jq -ec --arg network "$primary_network" '
    .chains[] | select(.network == $network)
  ' "$runtime_file" | head -n 1
}

multichain_envio_chains_json() {
  local runtime_file
  runtime_file="$(multichain_runtime_file)"
  multichain_require_runtime || return
  jq -c '{chains: [.chains[] | {
    name,
    chain_id,
    chain_index,
    start_block,
    rpc_url,
    hypersync_url: (.hypersync_url // ""),
    use_hypersync: (.use_hypersync // false),
    bridge_address: .contracts.Bridge,
    state_manager_address: .contracts.StateManager
  }]}' "$runtime_file"
}

multichain_relayer_chains_json() {
  local runtime_file
  runtime_file="$(multichain_runtime_file)"
  multichain_require_runtime || return
  jq -c '[.chains[] | {
    family: "evm",
    chain_index,
    network_id: .network,
    rpc_urls: ([.rpc_url, (.rpc_fallback_url // "")] | map(select(length > 0)) | unique),
    deployments_network: .network,
    bridge_address: .contracts.Bridge,
    state_manager: .contracts.StateManager
  }]' "$runtime_file"
}

multichain_services_l1_json() {
  local runtime_file graphql_url
  runtime_file="$(multichain_runtime_file)"
  graphql_url="${INDEXER_GRAPHQL_URL:?INDEXER_GRAPHQL_URL is required}"
  multichain_require_runtime || return
  jq -c --arg graphql_url "$graphql_url" '[.chains[] | {
    name,
    chain_index,
    chain_id,
    graphql_url: $graphql_url,
    eth_rpc_url: .rpc_url,
    state_manager: .contracts.StateManager
  }]' "$runtime_file"
}

multichain_public_rpc_routes_json() {
  local runtime_file
  runtime_file="$(multichain_runtime_file)"
  multichain_require_runtime || return
  jq -c '[.chains[] | {
    name,
    domain: .public_rpc_domain,
    upstream: .rpc_url,
    chain_id
  }]' "$runtime_file"
}

multichain_public_l1_config_json() {
  local runtime_file
  runtime_file="$(multichain_runtime_file)"
  multichain_require_runtime || return
  jq -c '[.chains[] | {
    network,
    bridge_chain: .protocol.chain.bridgeChain,
    chain_id,
    chain_index,
    name: .protocol.chain.name,
    short_name: .protocol.chain.shortName,
    native_currency: .protocol.chain.nativeCurrency,
    rpc_url: ("https://" + .public_rpc_domain),
    explorer_url,
    gas_faucet_url: (.gas_faucet_url // ""),
    contracts,
    tokens: (.protocol.tokens | to_entries | map({
      symbol: .value.symbol,
      decimals: .value.decimals,
      l1_address: .value.l1Address,
      l2_contract_id: .value.l2TokenContractId
    }))
  }]' "$runtime_file"
}

multichain_export_frontend_rpc_urls() {
  local runtime_file
  runtime_file="$(multichain_runtime_file)"
  multichain_require_runtime || return

  SEPOLIA_RPC_URL="$(jq -er '.chains[] | select(.network == "sepolia") | "https://" + .public_rpc_domain' "$runtime_file")"
  BSC_TESTNET_RPC_URL="$(jq -er '.chains[] | select(.network == "bscTestnet") | "https://" + .public_rpc_domain' "$runtime_file")"
  BASE_SEPOLIA_RPC_URL="$(jq -er '.chains[] | select(.network == "baseSepolia") | "https://" + .public_rpc_domain' "$runtime_file")"
  export SEPOLIA_RPC_URL BSC_TESTNET_RPC_URL BASE_SEPOLIA_RPC_URL
}

multichain_write_frontend_deployment() {
  local network="$1"
  local output_file="$2"
  local output_dir public_rpc_domain

  multichain_require_runtime || return
  output_dir="$(dirname "$output_file")"
  public_rpc_domain="$(
    multichain_runtime_json | jq -er --arg network "$network" \
      '.chains[] | select(.network == $network) | .public_rpc_domain'
  )"
  mkdir -p "$output_dir"

  multichain_runtime_json | jq -e \
    --arg network "$network" \
    --arg public_rpc_domain "$public_rpc_domain" '
    .generated_at as $generated_at
    | .chains[]
    | select(.network == $network)
    | {
        chainId: (.chain_id | tostring),
        contracts: .contracts,
        core: .contracts,
        generatedAt: $generated_at,
        implementations: {},
        network: .network,
        protocol: (
          .protocol
          | .chain.defaultRpcUrl = ("https://" + $public_rpc_domain)
        ),
        proxies: {},
        verify: {}
      }
  ' >"${output_file}.tmp"

  mv "${output_file}.tmp" "$output_file"
}
