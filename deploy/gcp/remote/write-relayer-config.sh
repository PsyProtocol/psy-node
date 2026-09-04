#!/usr/bin/env bash
set -euo pipefail

: "${RELAYER_CONFIG:=/etc/parth/bridge-relayer.toml}"
: "${RELAYER_POLL_INTERVAL_SECS:=15}"
: "${RELAYER_CONFIRMATION_LAG_CHECKPOINTS:=3}"
: "${RELAYER_MAX_CHECKPOINT_BATCH:=8}"
: "${RELAYER_SERVICES_EVENT_SETTLE_SECS:=5}"
: "${RELAYER_WITHDRAWAL_SCAN_LOOKBACK_CHECKPOINTS:=64}"
: "${RELAYER_EXIT_AFTER_SUCCESSFUL_ROUNDS:=1}"
: "${RELAYER_WITHDRAW_METHOD_ID:=4159421846}"
: "${RELAYER_SERVICES_URL:?RELAYER_SERVICES_URL is required}"
: "${RELAYER_L2_PRIVATE_KEY:=}"
: "${RELAYER_L2_KEYSTORE_PATH:=}"
: "${RELAYER_L2_WALLET_PASSWORD:=}"
: "${RELAYER_L2_RPC_CONFIG:=/opt/parth/current/client_prover/config.json}"
: "${RELAYER_PROOF_DIR:=/var/lib/parth/bridge-relayer}"
: "${RELAYER_L1_RPC_URL:=}"
: "${RELAYER_L1_RPC_FALLBACK_URL:=}"
: "${RELAYER_DEPLOYMENTS_NETWORK:=localhost}"
: "${RELAYER_FINALIZE_PRIVATE_KEY:=}"
: "${RELAYER_FINALIZE_KEYSTORE_PATH:=}"
: "${RELAYER_FINALIZE_PASSWORD_ENV:=WALLET_PASSWORD}"
: "${RELAYER_BRIDGE_ADDRESS:=}"
: "${RELAYER_STATE_MANAGER_ADDRESS:=}"
: "${RELAYER_MULTICALL3_ADDRESS:=}"
: "${RELAYER_DEPLOYED_CONTRACTS_JSON:=/opt/parth/l1-contracts/current/deployments/${RELAYER_DEPLOYMENTS_NETWORK}/deployed-contracts.json}"
: "${RELAYER_PARTH_HOME:=/opt/parth/current}"
: "${RELAYER_CHAINS_JSON:=}"

toml_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

config_dir="$(dirname "$RELAYER_CONFIG")"
if [ ! -d "$config_dir" ]; then
  install -d -m 0755 "$config_dir"
fi
install -d -m 0755 -o parth -g parth "$RELAYER_PROOF_DIR" 2>/dev/null || install -d -m 0755 "$RELAYER_PROOF_DIR"

if [ -z "$RELAYER_FINALIZE_PRIVATE_KEY" ] && [ -f "$RELAYER_CONFIG" ]; then
  RELAYER_FINALIZE_PRIVATE_KEY="$(
    awk '
      /^\[finalize\]/ { in_finalize = 1; next }
      /^\[/ { in_finalize = 0 }
      in_finalize && $1 == "private_key" {
        value = $0
        sub(/^[^=]*=[[:space:]]*/, "", value)
        gsub(/^"|"$/, "", value)
        print value
        exit
      }
    ' "$RELAYER_CONFIG"
  )"
fi

[ -n "$RELAYER_FINALIZE_PRIVATE_KEY" ] || {
  if [ -z "$RELAYER_FINALIZE_KEYSTORE_PATH" ]; then
    echo "RELAYER_FINALIZE_PRIVATE_KEY or RELAYER_FINALIZE_KEYSTORE_PATH is required; no existing finalize.private_key found in $RELAYER_CONFIG" >&2
    exit 1
  fi
}

if [ -z "$RELAYER_L2_PRIVATE_KEY" ] && [ -z "$RELAYER_L2_KEYSTORE_PATH" ]; then
  echo "RELAYER_L2_PRIVATE_KEY or RELAYER_L2_KEYSTORE_PATH is required" >&2
  exit 1
fi

if [ -n "$RELAYER_CHAINS_JSON" ]; then
  jq -e '
    type == "array" and length >= 2
    and all(.[ ];
      (.family == "evm")
      and (.chain_index | type == "number" and floor == . and . >= 0 and . <= 255)
      and (.network_id | type == "string" and length > 0)
      and (.deployments_network | type == "string" and length > 0)
      and (.rpc_urls | type == "array" and length > 0 and all(.[]; type == "string" and length > 0))
    )
    and ([.[].chain_index] | length == (unique | length))
  ' <<<"$RELAYER_CHAINS_JSON" >/dev/null || {
    echo "invalid RELAYER_CHAINS_JSON" >&2
    exit 1
  }
else
  [ -n "$RELAYER_L1_RPC_URL" ] || {
    echo "RELAYER_L1_RPC_URL is required in single-chain mode" >&2
    exit 1
  }
  [ -n "$RELAYER_BRIDGE_ADDRESS" ] || {
    echo "RELAYER_BRIDGE_ADDRESS is required in single-chain mode" >&2
    exit 1
  }
fi

{
  printf 'rpc_config = "%s"\n' "$(toml_escape "$RELAYER_L2_RPC_CONFIG")"
  printf 'services_url = "%s"\n' "$(toml_escape "$RELAYER_SERVICES_URL")"
  printf 'withdraw_method_id = %s\n' "$RELAYER_WITHDRAW_METHOD_ID"
  printf 'proof_dir = "%s"\n' "$(toml_escape "$RELAYER_PROOF_DIR")"
  printf 'poll_interval_secs = %s\n' "$RELAYER_POLL_INTERVAL_SECS"
  printf 'confirmation_lag_checkpoints = %s\n' "$RELAYER_CONFIRMATION_LAG_CHECKPOINTS"
  printf 'max_checkpoint_batch = %s\n' "$RELAYER_MAX_CHECKPOINT_BATCH"
  printf 'services_event_settle_secs = %s\n' "$RELAYER_SERVICES_EVENT_SETTLE_SECS"
  printf 'withdrawal_scan_lookback_checkpoints = %s\n' "$RELAYER_WITHDRAWAL_SCAN_LOOKBACK_CHECKPOINTS"
  printf 'exit_after_successful_rounds = %s\n\n' "$RELAYER_EXIT_AFTER_SUCCESSFUL_ROUNDS"
  printf '[relayer_wallet]\n'
  printf 'sign_type = "ZKSign"\n'
  if [ -n "$RELAYER_L2_KEYSTORE_PATH" ]; then
    printf 'keystore_path = "%s"\n' "$(toml_escape "$RELAYER_L2_KEYSTORE_PATH")"
    if [ -n "$RELAYER_L2_WALLET_PASSWORD" ]; then
      printf 'wallet_password = "%s"\n' "$(toml_escape "$RELAYER_L2_WALLET_PASSWORD")"
    fi
    printf '\n'
  else
    printf 'private_key = "%s"\n\n' "$(toml_escape "$RELAYER_L2_PRIVATE_KEY")"
  fi
  if [ -n "$RELAYER_CHAINS_JSON" ]; then
    while IFS= read -r chain; do
      printf '[[chains]]\n'
      printf 'family = "%s"\n' "$(toml_escape "$(jq -r '.family' <<<"$chain")")"
      printf 'chain_index = %s\n' "$(jq -r '.chain_index' <<<"$chain")"
      printf 'network_id = "%s"\n' "$(toml_escape "$(jq -r '.network_id' <<<"$chain")")"
      printf 'rpc_urls = ['
      first=1
      while IFS= read -r rpc_url; do
        [ "$first" = "1" ] || printf ', '
        printf '"%s"' "$(toml_escape "$rpc_url")"
        first=0
      done < <(jq -r '.rpc_urls[]' <<<"$chain")
      printf ']\n'
      printf 'deployments_network = "%s"\n' "$(toml_escape "$(jq -r '.deployments_network' <<<"$chain")")"
      if [ -n "$RELAYER_FINALIZE_KEYSTORE_PATH" ]; then
        printf 'keystore_path = "%s"\n' "$(toml_escape "$RELAYER_FINALIZE_KEYSTORE_PATH")"
        printf 'password_env = "%s"\n' "$(toml_escape "$RELAYER_FINALIZE_PASSWORD_ENV")"
      else
        printf 'private_key = "%s"\n' "$(toml_escape "$RELAYER_FINALIZE_PRIVATE_KEY")"
      fi
      state_manager="$(jq -r '.state_manager // ""' <<<"$chain")"
      bridge_address="$(jq -r '.bridge_address // ""' <<<"$chain")"
      [ -z "$state_manager" ] || printf 'state_manager = "%s"\n' "$(toml_escape "$state_manager")"
      [ -z "$bridge_address" ] || printf 'bridge_address = "%s"\n' "$(toml_escape "$bridge_address")"
      printf '\n'
    done < <(jq -c 'sort_by(.chain_index)[]' <<<"$RELAYER_CHAINS_JSON")
  else
    printf '[finalize]\n'
    printf 'l1_rpc_url = "%s"\n' "$(toml_escape "$RELAYER_L1_RPC_URL")"
    if [ -n "$RELAYER_L1_RPC_FALLBACK_URL" ]; then
      printf 'l1_rpc_fallback_url = "%s"\n' "$(toml_escape "$RELAYER_L1_RPC_FALLBACK_URL")"
    fi
    printf 'deployments_network = "%s"\n' "$(toml_escape "$RELAYER_DEPLOYMENTS_NETWORK")"
    if [ -n "$RELAYER_FINALIZE_KEYSTORE_PATH" ]; then
      printf 'keystore_path = "%s"\n' "$(toml_escape "$RELAYER_FINALIZE_KEYSTORE_PATH")"
      printf 'password_env = "%s"\n' "$(toml_escape "$RELAYER_FINALIZE_PASSWORD_ENV")"
    else
      printf 'private_key = "%s"\n' "$(toml_escape "$RELAYER_FINALIZE_PRIVATE_KEY")"
    fi
    printf 'bridge_address = "%s"\n' "$(toml_escape "$RELAYER_BRIDGE_ADDRESS")"
    if [ -n "$RELAYER_STATE_MANAGER_ADDRESS" ]; then
      printf 'state_manager = "%s"\n' "$(toml_escape "$RELAYER_STATE_MANAGER_ADDRESS")"
    fi
  fi
} > "$RELAYER_CONFIG"

chmod 0640 "$RELAYER_CONFIG"
chown root:parth "$RELAYER_CONFIG" 2>/dev/null || true

echo "wrote relayer config: $RELAYER_CONFIG"

if [ -n "$RELAYER_CHAINS_JSON" ]; then
  echo "wrote multichain relayer config with $(jq 'length' <<<"$RELAYER_CHAINS_JSON") chains"
  exit 0
fi

deployments_dir="$RELAYER_PARTH_HOME/psy-contracts/deployments/$RELAYER_DEPLOYMENTS_NETWORK"
deployments_json="$deployments_dir/deployed-contracts.json"
install -d -m 0755 "$deployments_dir"

if [ -s "$RELAYER_DEPLOYED_CONTRACTS_JSON" ]; then
  source_deployments_dir="$(dirname "$RELAYER_DEPLOYED_CONTRACTS_JSON")"
  source_deployments_dir_real="$(readlink -f "$source_deployments_dir" 2>/dev/null || printf '%s' "$source_deployments_dir")"
  deployments_dir_real="$(readlink -f "$deployments_dir" 2>/dev/null || printf '%s' "$deployments_dir")"
  if [ -d "$source_deployments_dir" ] && [ "$source_deployments_dir_real" != "$deployments_dir_real" ]; then
    find "$source_deployments_dir" -maxdepth 1 -type f -name '*.json' -exec install -m 0644 {} "$deployments_dir/" \;
  fi
  source_deployments_json_real="$(readlink -f "$RELAYER_DEPLOYED_CONTRACTS_JSON" 2>/dev/null || printf '%s' "$RELAYER_DEPLOYED_CONTRACTS_JSON")"
  deployments_json_real="$(readlink -f "$deployments_json" 2>/dev/null || printf '%s' "$deployments_json")"
  if [ "$source_deployments_json_real" != "$deployments_json_real" ]; then
    install -m 0644 "$RELAYER_DEPLOYED_CONTRACTS_JSON" "$deployments_json"
  fi
else
  if [ -s "$deployments_json" ]; then
    echo "keeping existing relayer deployments summary: $deployments_json"
  else
    if [ -z "$RELAYER_MULTICALL3_ADDRESS" ]; then
      echo "warning: missing $RELAYER_DEPLOYED_CONTRACTS_JSON and RELAYER_MULTICALL3_ADDRESS; deposit batchAppend will fail until Multicall3 is configured" >&2
    fi
    jq -n \
      --arg network "$RELAYER_DEPLOYMENTS_NETWORK" \
      --arg bridge "$RELAYER_BRIDGE_ADDRESS" \
      --arg state_manager "$RELAYER_STATE_MANAGER_ADDRESS" \
      --arg multicall3 "$RELAYER_MULTICALL3_ADDRESS" \
      '{
        network: $network,
        core: {
          Bridge: $bridge,
          StateManager: $state_manager,
          Multicall3: $multicall3
        },
        contracts: {}
      }' > "$deployments_json"
  fi
fi

chmod 0644 "$deployments_json"
echo "wrote relayer deployments summary: $deployments_json"
