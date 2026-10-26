#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

l1_host="${ANVIL_VM_NAME:-${NODE_VM_NAME:-gcp-cp-ce}}"
l1_contracts_home="${L1_CONTRACTS_HOME:-/opt/parth/l1-contracts/current}"
l1_network="${L1_DEPLOYMENTS_NETWORK:-sepolia}"
l1_rpc_url="${L1_RPC_URL:-${ETH_RPC_URL:-}}"
chain_id="${CHAIN_ID:-11155111}"
keystore_path="${L1_DEPLOYER_KEYSTORE_PATH:-${KEYSTORE_PATH:-}}"
keystore_remote_path="${L1_DEPLOYER_KEYSTORE_REMOTE_PATH:-/var/lib/parth/.psy/keystore/bridge-relayer-dev}"
wallet_password="${L1_DEPLOYER_WALLET_PASSWORD:-${WALLET_PASSWORD:-}}"
upload_root="/tmp/parth-l1-faucet-only"
deployments_dir="$PARTH_DIR/psy-contracts/deployments/$l1_network"
pause_l1_writers="${FAUCET_DEPLOY_PAUSE_L1_WRITERS:-1}"
relayer_host="${RELAYER_VM_NAME:-gcp-relayer}"
relayer_was_active=0

[ -n "$l1_rpc_url" ] || {
  echo "ETH_RPC_URL or L1_RPC_URL is required" >&2
  exit 1
}
[ -d "$deployments_dir" ] || {
  echo "missing local L1 deployments dir: $deployments_dir" >&2
  echo "run step 10 once or sync psy-contracts/deployments/$l1_network before faucet-only deploy" >&2
  exit 1
}
[ -s "$deployments_dir/deployed-contracts.json" ] || {
  echo "missing $deployments_dir/deployed-contracts.json" >&2
  exit 1
}

log_step "deploying only TokenFaucetManager against existing L1 contracts"
provision_vm "$l1_host"

tmp_contracts="$(mktemp -d)"
cleanup() {
  if [ "$relayer_was_active" = "1" ]; then
    echo "restarting L1 writer after faucet deploy: ${relayer_host}:parth-relayer.service"
    run_remote_command "$relayer_host" "sudo systemctl start parth-relayer.service" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_contracts"
}
trap cleanup EXIT

rsync -a --delete \
  --exclude node_modules \
  --exclude cache \
  --exclude artifacts \
  --exclude deployments \
  "$PARTH_DIR/psy-contracts/" \
  "$tmp_contracts/"

install -d -m 0755 "$tmp_contracts/deployments/$l1_network"
rsync -a "$deployments_dir/" "$tmp_contracts/deployments/$l1_network/"
rm -f "$tmp_contracts/deployments/$l1_network/.pendingTransactions"

# If a previous faucet-only run failed after deploying the proxy but before
# syncing artifacts back, recover those remote artifacts so reruns continue the
# same TokenFaucetManager instead of deploying another orphan proxy.
if run_remote_command "$l1_host" "[ -d '$upload_root/deployments/$l1_network' ]" >/dev/null 2>&1; then
  echo "recovering existing remote faucet deployment artifacts: ${l1_host}:${upload_root}/deployments/${l1_network}"
  rsync -az "$l1_host:$upload_root/deployments/$l1_network/" "$tmp_contracts/deployments/$l1_network/"
  rm -f "$tmp_contracts/deployments/$l1_network/.pendingTransactions"
fi

if [ -n "$keystore_path" ]; then
  if [ -f "$keystore_path" ]; then
    remote_tmp="/tmp/parth-l1-deployer-keystore"
    echo "uploading L1 deployer keystore: $keystore_path -> ${l1_host}:${keystore_remote_path}"
    scp_to_remote "$l1_host" "$keystore_path" "$remote_tmp"
    run_remote_command "$l1_host" "sudo install -d -m 0750 -o parth -g parth '$(dirname "$keystore_remote_path")' && sudo install -m 0640 -o parth -g parth '$remote_tmp' '$keystore_remote_path' && rm -f '$remote_tmp'"
    keystore_path="$keystore_remote_path"
  else
    case "$keystore_path" in
      /var/lib/parth/*|/etc/parth/*|/opt/parth/*)
        echo "using remote L1 deployer keystore path: $keystore_path"
        ;;
      *)
        echo "missing local L1 deployer keystore: $keystore_path" >&2
        exit 1
        ;;
    esac
  fi
fi

run_remote_command "$l1_host" "rm -rf '$upload_root' && mkdir -p '$upload_root' && command -v rsync >/dev/null 2>&1 || sudo env DEBIAN_FRONTEND=noninteractive sh -lc 'apt-get update && apt-get install -y rsync'"
echo "uploading faucet-only contracts worktree with rsync --checksum: $tmp_contracts -> ${l1_host}:${upload_root}"
rsync -az --checksum --human-readable --progress "$tmp_contracts/" "${l1_host}:${upload_root}/"

if [ "$pause_l1_writers" = "1" ] || [ "$pause_l1_writers" = "true" ]; then
  if run_remote_command "$relayer_host" "systemctl is-active --quiet parth-relayer.service" >/dev/null 2>&1; then
    relayer_was_active=1
    echo "stopping L1 writer during faucet deploy: ${relayer_host}:parth-relayer.service"
    run_remote_command "$relayer_host" "sudo systemctl stop parth-relayer.service"
  else
    echo "L1 writer is not active or not reachable; continuing: ${relayer_host}:parth-relayer.service"
  fi
fi

network_env_key="ETH_RPC_URL"
if [ "$l1_network" = "localhost" ]; then
  network_env_key="LOCALHOST_RPC_URL"
elif [ "$l1_network" = "sepolia" ]; then
  network_env_key="SEPOLIA_RPC_URL"
elif [ "$l1_network" = "bsc-testnet" ]; then
  network_env_key="BSC_TESTNET_RPC_URL"
fi

remote_script="$(cat <<'REMOTE'
set -euo pipefail

cd "$UPLOAD_ROOT"
rm -f "deployments/$L1_NETWORK/.pendingTransactions"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl jq nodejs npm

if [ -f package-lock.json ]; then
  if ! npm ci; then
    echo "npm ci failed; falling back to npm install --no-package-lock" >&2
    npm install --no-package-lock
  fi
else
  npm install
fi

deployer_private_key=""
deployer_address=""
if [ -n "${KEYSTORE_PATH:-}" ]; then
  [ -n "${WALLET_PASSWORD:-}" ] || {
    echo "WALLET_PASSWORD is required with KEYSTORE_PATH" >&2
    exit 1
  }
  deployer_json="$(KEYSTORE_PATH="$KEYSTORE_PATH" WALLET_PASSWORD="$WALLET_PASSWORD" node <<'NODE'
const { Wallet } = require("ethers");
const fs = require("fs");
(async () => {
  const wallet = await Wallet.fromEncryptedJson(
    fs.readFileSync(process.env.KEYSTORE_PATH, "utf8"),
    process.env.WALLET_PASSWORD,
  );
  process.stdout.write(JSON.stringify({ address: wallet.address, privateKey: wallet.privateKey }));
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
NODE
)"
  deployer_address="$(printf '%s' "$deployer_json" | jq -r '.address')"
  deployer_private_key="$(printf '%s' "$deployer_json" | jq -r '.privateKey')"
fi

if [ -n "$deployer_private_key" ]; then
  install -d -m 0755 config
  config_file="config/${L1_NETWORK}.json"
  [ -f "$config_file" ] || printf '{}\n' > "$config_file"
  tmp_config="$(mktemp)"
  jq --arg address "$deployer_address" '
    .admin = $address |
    .proposer = $address |
    .owner = $address |
    .bridgeAdmin = $address |
    .routerAdmin = $address |
    .stateManagerAdmin = $address
  ' "$config_file" > "$tmp_config"
  mv "$tmp_config" "$config_file"
fi

args=(npx hardhat deploy --network "$L1_NETWORK" --tags token_faucet)
if [ -n "$deployer_private_key" ]; then
  env "$NETWORK_ENV_KEY=$L1_RPC_URL" CHAIN_ID="$CHAIN_ID" \
    PSY_INTERNAL_DEPLOY_FROM_KEYSTORE=1 \
    PSY_INTERNAL_DEPLOY_PRIVATE_KEY="$deployer_private_key" \
    "${args[@]}"
else
  env "$NETWORK_ENV_KEY=$L1_RPC_URL" CHAIN_ID="$CHAIN_ID" "${args[@]}"
fi
deployer_private_key=""

env "$NETWORK_ENV_KEY=$L1_RPC_URL" CHAIN_ID="$CHAIN_ID" npx hardhat deploy --network "$L1_NETWORK" --tags export_deployed_contracts

install -d -m 0755 "$L1_CONTRACTS_HOME/deployments/$L1_NETWORK"
find "deployments/$L1_NETWORK" -maxdepth 1 -type f -name '*.json' -exec install -m 0644 {} "$L1_CONTRACTS_HOME/deployments/$L1_NETWORK/" \;

deployed="$L1_CONTRACTS_HOME/deployments/$L1_NETWORK/deployed-contracts.json"
[ -s "$deployed" ] || {
  echo "missing deployed contracts summary after faucet deploy: $deployed" >&2
  exit 1
}

install -d -m 0755 /etc/parth
if [ -s /etc/parth/l1.env ]; then
  cp /etc/parth/l1.env /tmp/parth-l1.env.next
else
  : > /tmp/parth-l1.env.next
fi

upsert_env() {
  local key="$1"
  local value="$2"
  local tmp
  tmp="$(mktemp)"
  if grep -q "^${key}=" /tmp/parth-l1.env.next; then
    awk -v key="$key" -v value="$value" '$0 ~ "^" key "=" { print key "=" value; next } { print }' /tmp/parth-l1.env.next > "$tmp"
  else
    cp /tmp/parth-l1.env.next "$tmp"
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  mv "$tmp" /tmp/parth-l1.env.next
}

upsert_env ETH_RPC_URL "$L1_RPC_URL"
upsert_env CHAIN_ID "$CHAIN_ID"
upsert_env L1_DEPLOYMENTS_NETWORK "$L1_NETWORK"
upsert_env L1_DEPLOYER_ADDRESS "${deployer_address:-}"
upsert_env ADDRESSES_PROVIDER_ADDRESS "$(jq -r '.core.PsyAddressesProvider // .contracts.PsyAddressesProvider // empty' "$deployed")"
upsert_env BRIDGE_ADDRESS "$(jq -r '.core.Bridge // .contracts.Bridge // empty' "$deployed")"
upsert_env STATE_MANAGER_ADDRESS "$(jq -r '.core.StateManager // .contracts.StateManager // empty' "$deployed")"
upsert_env ROUTER_ADDRESS "$(jq -r '.core.Router // .contracts.Router // empty' "$deployed")"
upsert_env ERC20_GATEWAY_ADDRESS "$(jq -r '.core.ERC20Gateway // .contracts.ERC20Gateway // empty' "$deployed")"
upsert_env ETH_GATEWAY_ADDRESS "$(jq -r '.core.ETHGateway // .contracts.ETHGateway // empty' "$deployed")"
upsert_env WETH_ADDRESS "$(jq -r '.core.WETH9 // .contracts.WETH9 // empty' "$deployed")"
upsert_env PSY_TOKEN_ADDRESS "$(jq -r '.core.PsyToken // .contracts.PsyToken // empty' "$deployed")"
upsert_env MULTICALL3_ADDRESS "$(jq -r '.core.Multicall3 // .contracts.Multicall3 // empty' "$deployed")"
upsert_env TOKEN_FAUCET_MANAGER_ADDRESS "$(jq -r '.core.TokenFaucetManager // .contracts.TokenFaucetManager // empty' "$deployed")"

install -m 0644 /tmp/parth-l1.env.next /etc/parth/l1.env

echo "current L1 faucet deployment:"
jq -r '"TokenFaucetManager=" + (.core.TokenFaucetManager // .contracts.TokenFaucetManager // "")' "$deployed"
jq -r '"PsyToken=" + (.core.PsyToken // .contracts.PsyToken // "")' "$deployed"
jq -r '"USDTToken=" + (.core.USDTToken // .contracts.USDTToken // "")' "$deployed"
REMOTE
)"

run_remote_command "$l1_host" "sudo env \
  UPLOAD_ROOT=$(printf '%q' "$upload_root") \
  L1_CONTRACTS_HOME=$(printf '%q' "$l1_contracts_home") \
  L1_NETWORK=$(printf '%q' "$l1_network") \
  L1_RPC_URL=$(printf '%q' "$l1_rpc_url") \
  CHAIN_ID=$(printf '%q' "$chain_id") \
  NETWORK_ENV_KEY=$(printf '%q' "$network_env_key") \
  KEYSTORE_PATH=$(printf '%q' "$keystore_path") \
  WALLET_PASSWORD=$(printf '%q' "$wallet_password") \
  bash -lc $(printf '%q' "$remote_script")"

log_step "syncing faucet deployment artifacts back to local"
install -d -m 0755 "$deployments_dir"
rsync -az --delete \
  "$l1_host:$l1_contracts_home/deployments/$l1_network/" \
  "$deployments_dir/"

log_step "syncing remote /etc/parth/l1.env into $CONFIG_FILE"
sync_remote_l1_env_to_config

token_faucet="$(jq -r '.core.TokenFaucetManager // .contracts.TokenFaucetManager // empty' "$deployments_dir/deployed-contracts.json")"
[ -n "$token_faucet" ] && update_config_var TOKEN_FAUCET_MANAGER_ADDRESS "$token_faucet"

log_step "faucet-only deploy complete"
printf 'TOKEN_FAUCET_MANAGER_ADDRESS="%s"\n' "$token_faucet"
