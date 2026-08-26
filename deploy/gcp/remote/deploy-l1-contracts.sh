#!/usr/bin/env bash
set -euo pipefail

: "${L1_CONTRACTS_UPLOAD:=/tmp/parth-l1-contracts}"
: "${L1_CONTRACTS_HOME:=/opt/parth/l1-contracts/current}"
: "${L1_RPC_URL:?L1_RPC_URL is required}"
: "${CHAIN_ID:=31337}"
: "${L1_DEPLOYMENTS_NETWORK:=localhost}"
: "${L1_DEPLOYER_PRIVATE_KEY:=}"
: "${L1_DEPLOYER_KEYSTORE_PATH:=}"
: "${L1_DEPLOYER_WALLET_PASSWORD:=}"
: "${L1_DEPLOYER_BALANCE_HEX:=0x21e19e0c9bab2400000}"
: "${L1_DEPLOY_RESET:=1}"

[ -d "$L1_CONTRACTS_UPLOAD" ] || {
  echo "missing uploaded contracts source: $L1_CONTRACTS_UPLOAD" >&2
  exit 1
}

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl jq nodejs npm

rm -rf "$L1_CONTRACTS_HOME"
install -d -m 0755 "$(dirname "$L1_CONTRACTS_HOME")"
cp -a "$L1_CONTRACTS_UPLOAD" "$L1_CONTRACTS_HOME"

cd "$L1_CONTRACTS_HOME"

if [ -f package-lock.json ]; then
  if ! npm ci; then
    echo "npm ci failed; package-lock.json is out of sync with package.json, falling back to npm install --no-package-lock" >&2
    npm install --no-package-lock
  fi
else
  npm install
fi

rpc_ready=0
rpc_chain_id_hex=""
for _ in $(seq 1 60); do
  rpc_chain_id_hex="$(curl -fsS --max-time 3 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    "$L1_RPC_URL" | jq -er '.result' 2>/dev/null || true)"
  if [ -n "$rpc_chain_id_hex" ]; then
    rpc_ready=1
    break
  fi
  sleep 2
done
[ "$rpc_ready" = "1" ] || {
  echo "timed out waiting for L1 RPC: $L1_RPC_URL" >&2
  exit 1
}
actual_chain_id="$((rpc_chain_id_hex))"
[ "$actual_chain_id" = "$CHAIN_ID" ] || {
  echo "L1 RPC chain ID mismatch: expected $CHAIN_ID, got $actual_chain_id ($rpc_chain_id_hex)" >&2
  exit 1
}

predeploy_block_hex="$(curl -fsS --max-time 5 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
  "$L1_RPC_URL" | jq -er '.result')"
L1_DEPLOY_START_BLOCK="$((predeploy_block_hex + 1))"
echo "verified L1 RPC chain_id=$actual_chain_id; deployment event scan starts at block $L1_DEPLOY_START_BLOCK"

deployer_address=""
deployer_private_key=""
if [ -n "$L1_DEPLOYER_KEYSTORE_PATH" ]; then
  [ -f "$L1_DEPLOYER_KEYSTORE_PATH" ] || {
    echo "missing L1 deployer keystore: $L1_DEPLOYER_KEYSTORE_PATH" >&2
    exit 1
  }
  [ -n "$L1_DEPLOYER_WALLET_PASSWORD" ] || {
    echo "L1_DEPLOYER_WALLET_PASSWORD is required with L1_DEPLOYER_KEYSTORE_PATH" >&2
    exit 1
  }
  deployer_json="$(KEYSTORE_PATH="$L1_DEPLOYER_KEYSTORE_PATH" WALLET_PASSWORD="$L1_DEPLOYER_WALLET_PASSWORD" node <<'NODE'
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
elif [ -n "$L1_DEPLOYER_PRIVATE_KEY" ]; then
  L1_DEPLOYER_PRIVATE_KEY="${L1_DEPLOYER_PRIVATE_KEY#0x}"
  if ! printf '%s' "$L1_DEPLOYER_PRIVATE_KEY" | grep -Eq '^[0-9a-fA-F]{64}$'; then
    echo "invalid L1_DEPLOYER_PRIVATE_KEY: expected 64 hex chars / 32 bytes" >&2
    exit 1
  fi
  deployer_private_key="0x${L1_DEPLOYER_PRIVATE_KEY}"

  deployer_address="$(PRIVATE_KEY="$deployer_private_key" node -e 'const { Wallet } = require("ethers"); console.log(new Wallet(process.env.PRIVATE_KEY).address)')"
fi

if [ -n "$deployer_private_key" ]; then
  config_file="config/${L1_DEPLOYMENTS_NETWORK}.json"
  install -d -m 0755 config
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

  if [ "$L1_DEPLOYMENTS_NETWORK" = "localhost" ] || [ "$CHAIN_ID" = "31337" ]; then
    curl -fsS --max-time 5 \
      -H 'content-type: application/json' \
      --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"anvil_setBalance\",\"params\":[\"${deployer_address}\",\"${L1_DEPLOYER_BALANCE_HEX}\"]}" \
      "$L1_RPC_URL" | jq -e '.error == null' >/dev/null
  fi

  echo "using configured L1 deployer for ${L1_DEPLOYMENTS_NETWORK}: ${deployer_address}"
fi

args=(npx hardhat deploy --network "$L1_DEPLOYMENTS_NETWORK")
if [ "$L1_DEPLOY_RESET" = "1" ] || [ "$L1_DEPLOY_RESET" = "true" ]; then
  args+=(--reset)
fi

network_env_key="ETH_RPC_URL"
if [ "$L1_DEPLOYMENTS_NETWORK" = "localhost" ]; then
  network_env_key="LOCALHOST_RPC_URL"
elif [ "$L1_DEPLOYMENTS_NETWORK" = "sepolia" ]; then
  network_env_key="SEPOLIA_RPC_URL"
elif [ "$L1_DEPLOYMENTS_NETWORK" = "bsc-testnet" ]; then
  network_env_key="BSC_TESTNET_RPC_URL"
fi

if [ -n "$deployer_private_key" ]; then
  env "$network_env_key=$L1_RPC_URL" CHAIN_ID="$CHAIN_ID" \
    PSY_INTERNAL_DEPLOY_FROM_KEYSTORE=1 \
    PSY_INTERNAL_DEPLOY_PRIVATE_KEY="$deployer_private_key" \
    "${args[@]}"
else
  env "$network_env_key=$L1_RPC_URL" CHAIN_ID="$CHAIN_ID" "${args[@]}"
fi

deployer_private_key=""

deployed="$L1_CONTRACTS_HOME/deployments/${L1_DEPLOYMENTS_NETWORK}/deployed-contracts.json"
[ -f "$deployed" ] || {
  echo "missing deployed contracts summary: $deployed" >&2
  exit 1
}

state_manager_address="$(jq -r '.core.StateManager // .contracts.StateManager // empty' "$deployed")"
[ -n "$state_manager_address" ] || {
  echo "missing StateManager in deployed contracts summary: $deployed" >&2
  exit 1
}

expected_l1_chain_index="$(jq -r '.protocol.chain.l1ChainIndex // empty' "$deployed")"
[ -n "$expected_l1_chain_index" ] || {
  echo "missing protocol.chain.l1ChainIndex in deployed contracts summary: $deployed" >&2
  exit 1
}

actual_l1_chain_index="$(L1_RPC_URL="$L1_RPC_URL" STATE_MANAGER_ADDRESS="$state_manager_address" node <<'NODE'
const { ethers } = require("ethers");

const provider = new ethers.providers.JsonRpcProvider(process.env.L1_RPC_URL);
const stateManager = new ethers.Contract(
  process.env.STATE_MANAGER_ADDRESS,
  ["function l1ChainIndex() view returns (uint8)"],
  provider,
);

(async () => {
  const value = await stateManager.l1ChainIndex();
  process.stdout.write(value.toString());
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
NODE
)"
if [ "$actual_l1_chain_index" != "$expected_l1_chain_index" ]; then
  cat >&2 <<EOF
deployed StateManager l1ChainIndex mismatch
  expected from deployed-contracts.json: $expected_l1_chain_index
  actual on chain:                       $actual_l1_chain_index
  state manager:                         $state_manager_address
EOF
  exit 1
fi

psy_token_address="$(jq -r '.core.PsyToken // .contracts.PsyToken // empty' "$deployed")"
[ -n "$psy_token_address" ] || {
  echo "missing PsyToken in deployed contracts summary: $deployed" >&2
  exit 1
}

usdt_token_address="$(jq -r '.core.USDTToken // .contracts.USDTToken // empty' "$deployed")"
token_faucet_manager_address="$(jq -r '.core.TokenFaucetManager // .contracts.TokenFaucetManager // empty' "$deployed")"
[ -n "$token_faucet_manager_address" ] || {
  echo "missing TokenFaucetManager in deployed contracts summary: $deployed" >&2
  exit 1
}

config_admin=""
if [ -f "config/${L1_DEPLOYMENTS_NETWORK}.json" ]; then
  config_admin="$(jq -r '.admin // empty' "config/${L1_DEPLOYMENTS_NETWORK}.json")"
fi

install -d -m 0755 /etc/parth
cat >/etc/parth/l1.env <<EOF
ETH_RPC_URL=${L1_RPC_URL}
CHAIN_ID=${CHAIN_ID}
START_BLOCK=${L1_DEPLOY_START_BLOCK}
L1_DEPLOYMENTS_NETWORK=${L1_DEPLOYMENTS_NETWORK}
L1_DEPLOYER_ADDRESS=${deployer_address:-$config_admin}
ADDRESSES_PROVIDER_ADDRESS=$(jq -r '.core.PsyAddressesProvider // .contracts.PsyAddressesProvider // empty' "$deployed")
BRIDGE_ADDRESS=$(jq -r '.core.Bridge // .contracts.Bridge // empty' "$deployed")
STATE_MANAGER_ADDRESS=$(jq -r '.core.StateManager // .contracts.StateManager // empty' "$deployed")
ROUTER_ADDRESS=$(jq -r '.core.Router // .contracts.Router // empty' "$deployed")
ERC20_GATEWAY_ADDRESS=$(jq -r '.core.ERC20Gateway // .contracts.ERC20Gateway // empty' "$deployed")
ETH_GATEWAY_ADDRESS=$(jq -r '.core.ETHGateway // .contracts.ETHGateway // empty' "$deployed")
WETH_ADDRESS=$(jq -r '.core.WETH9 // .contracts.WETH9 // empty' "$deployed")
PSY_TOKEN_ADDRESS=${psy_token_address}
USDT_TOKEN_ADDRESS=${usdt_token_address}
MULTICALL3_ADDRESS=$(jq -r '.core.Multicall3 // .contracts.Multicall3 // empty' "$deployed")
TOKEN_FAUCET_MANAGER_ADDRESS=${token_faucet_manager_address}
EOF
chmod 0644 /etc/parth/l1.env

echo "deployed L1 contracts:"
sed -n '1,120p' /etc/parth/l1.env
