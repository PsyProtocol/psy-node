#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$PARTH_DIR/deploy/gcp/config.env}"
OUT_DIR="${LOCAL_RELAYER_DIR:-$PARTH_DIR/dist/local-relayer}"

[ -f "$CONFIG_FILE" ] || {
  echo "missing config file: $CONFIG_FILE" >&2
  exit 1
}

# shellcheck source=../gcp/config.env
set -a
source "$CONFIG_FILE"
set +a

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "missing required config variable: $name" >&2
    exit 1
  fi
}

require_var BRIDGE_ADDRESS
require_var STATE_MANAGER_ADDRESS
require_var MULTICALL3_ADDRESS
require_var L1_DEPLOYMENTS_NETWORK
require_var CHAIN_ID
require_var ETH_RPC_URL
require_var PUBLIC_COORDINATOR_DOMAIN
require_var PUBLIC_PROVE_PROXY_DOMAIN
require_var PUBLIC_PSY_SERVICES_DOMAIN

realm0_domain="${PUBLIC_REALM0_DOMAIN:-${PUBLIC_REALM_DOMAIN:-}}"
realm1_domain="${PUBLIC_REALM1_DOMAIN:-}"
[ -n "$realm0_domain" ] || {
  echo "missing PUBLIC_REALM0_DOMAIN or PUBLIC_REALM_DOMAIN" >&2
  exit 1
}

relayer_bin="$PARTH_DIR/target/release/psy_relayer_cli"
[ -x "$relayer_bin" ] || {
  echo "missing relayer binary: $relayer_bin" >&2
  echo "build it first: cargo build -p psy_relayer_cli --release" >&2
  exit 1
}

mkdir -p \
  "$OUT_DIR/bin" \
  "$OUT_DIR/client_prover" \
  "$OUT_DIR/proofs" \
  "$OUT_DIR/logs" \
  "$OUT_DIR/psy-contracts/deployments/$L1_DEPLOYMENTS_NETWORK"

cp "$relayer_bin" "$OUT_DIR/bin/psy_relayer_cli"

source_config="$PARTH_DIR/deploy/config/parth/client_prover_config.json"
[ -f "$source_config" ] || {
  echo "missing client prover config template: $source_config" >&2
  exit 1
}

realm_urls="https://$realm0_domain"
if [ -n "$realm1_domain" ]; then
  realm_urls="$realm_urls,https://$realm1_domain"
fi

python3 - "$source_config" "$OUT_DIR/client_prover/config.json" \
  "https://$PUBLIC_COORDINATOR_DOMAIN" \
  "$realm_urls" \
  "https://$PUBLIC_PROVE_PROXY_DOMAIN" \
  "https://$PUBLIC_PSY_SERVICES_DOMAIN" <<'PY'
import json
import sys

source, target, coordinator, realms_csv, prove_proxy, services = sys.argv[1:]
with open(source, "r", encoding="utf-8") as f:
    data = json.load(f)

localhost = data.setdefault("networks", {}).setdefault("localhost", {})
localhost["coordinator_configs"] = [{"id": 0, "rpc_url": [coordinator]}]
localhost["realm_configs"] = [
    {"id": idx, "rpc_url": [url.strip()]}
    for idx, url in enumerate(realms_csv.split(","))
    if url.strip()
]
localhost["prove_proxy_url"] = [prove_proxy]
localhost["api_services_url"] = [services]

with open(target, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY

deployments_dir="$OUT_DIR/psy-contracts/deployments/$L1_DEPLOYMENTS_NETWORK"
source_deployments_dir="$PARTH_DIR/psy-contracts/deployments/$L1_DEPLOYMENTS_NETWORK"
if [ -s "$source_deployments_dir/deployed-contracts.json" ]; then
  rsync -a "$source_deployments_dir/" "$deployments_dir/"
else
  jq -n \
    --arg network "$L1_DEPLOYMENTS_NETWORK" \
    --arg chain_id "$CHAIN_ID" \
    --arg bridge "$BRIDGE_ADDRESS" \
    --arg state_manager "$STATE_MANAGER_ADDRESS" \
    --arg multicall3 "$MULTICALL3_ADDRESS" \
    --arg router "${ROUTER_ADDRESS:-}" \
    --arg erc20_gateway "${ERC20_GATEWAY_ADDRESS:-}" \
    --arg eth_gateway "${ETH_GATEWAY_ADDRESS:-}" \
    --arg weth "${WETH_ADDRESS:-}" \
    --arg psy_token "${PSY_TOKEN_ADDRESS:-}" \
    '{
      network: $network,
      chainId: $chain_id,
      core: {
        Bridge: $bridge,
        StateManager: $state_manager,
        Multicall3: $multicall3,
        Router: $router,
        ERC20Gateway: $erc20_gateway,
        ETHGateway: $eth_gateway,
        WETH9: $weth,
        PsyToken: $psy_token,
        USDTToken: $psy_token
      },
      contracts: {}
    }' > "$deployments_dir/deployed-contracts.json"

  jq -n \
    --arg address "$BRIDGE_ADDRESS" \
    '{
      address: $address,
      receipt: {
        blockNumber: 0
      }
    }' > "$deployments_dir/Bridge_Proxy.json"
fi

l1_keystore_path="${RELAYER_FINALIZE_KEYSTORE_PATH:-${L1_DEPLOYER_KEYSTORE_PATH:-$HOME/.psy/keystore/bridge-relayer}}"
cat > "$OUT_DIR/bridge-relayer.toml" <<EOF
rpc_config = "./client_prover/config.json"
services_url = "https://${PUBLIC_PSY_SERVICES_DOMAIN}"
withdraw_method_id = ${RELAYER_WITHDRAW_METHOD_ID:-4159421846}
proof_dir = "./proofs"
poll_interval_secs = ${RELAYER_POLL_INTERVAL_SECS:-15}
confirmation_lag_checkpoints = ${RELAYER_CONFIRMATION_LAG_CHECKPOINTS:-3}
max_checkpoint_batch = ${RELAYER_MAX_CHECKPOINT_BATCH:-32}
services_event_settle_secs = ${RELAYER_SERVICES_EVENT_SETTLE_SECS:-5}
withdrawal_scan_lookback_checkpoints = ${RELAYER_WITHDRAWAL_SCAN_LOOKBACK_CHECKPOINTS:-64}
exit_after_successful_rounds = ${RELAYER_EXIT_AFTER_SUCCESSFUL_ROUNDS:-0}

[relayer_wallet]
sign_type = "ZKSign"

[finalize]
l1_rpc_url = "${RELAYER_L1_RPC_URL:-$ETH_RPC_URL}"
deployments_network = "${RELAYER_DEPLOYMENTS_NETWORK:-$L1_DEPLOYMENTS_NETWORK}"
keystore_path = "${l1_keystore_path}"
password_env = "WALLET_PASSWORD"
bridge_address = "${BRIDGE_ADDRESS}"
state_manager = "${STATE_MANAGER_ADDRESS}"
EOF

cat > "$OUT_DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

: "${BRIDGE_RELAYER_L2_PRIVATE_KEY:?BRIDGE_RELAYER_L2_PRIVATE_KEY is required}"
: "${WALLET_PASSWORD:?WALLET_PASSWORD is required for the L1 finalize keystore}"

export PSY_DEPLOYMENTS_DIR="$PWD/psy-contracts/deployments"
export RUST_LOG="${RUST_LOG:-info}"

exec "$PWD/bin/psy_relayer_cli" --config "$PWD/bridge-relayer.toml"
EOF
chmod 0755 "$OUT_DIR/run.sh"

cat > "$OUT_DIR/env.example" <<'EOF'
# Do not commit real secrets.
export BRIDGE_RELAYER_L2_PRIVATE_KEY="<genesis user 2 private key>"
export WALLET_PASSWORD="<L1 keystore password>"
export RUST_LOG="info"
EOF

cat > "$OUT_DIR/README.md" <<EOF
# Local Staging Relayer

This directory is generated from \`deploy/local-testnet/relayer/prepare-local-relayer.sh\`.

Run from this directory:

\`\`\`bash
export BRIDGE_RELAYER_L2_PRIVATE_KEY="<genesis user 2 private key>"
export WALLET_PASSWORD="<L1 keystore password>"
./run.sh
\`\`\`

Install as a systemd user service:

\`\`\`bash
bash "$PARTH_DIR/deploy/local-testnet/relayer/install-systemd-user-service.sh"
editor "$HOME/.config/parth-local-relayer/env"
systemctl --user start parth-local-relayer.service
journalctl --user -u parth-local-relayer.service -f
\`\`\`

Before running, make sure the Groth16 setup files exist under:

- \`$HOME/.psy/keystore\`
- \`$HOME/.psy/keystore/deposit_append\`

Only run one active relayer against the same staging bridge unless you are deliberately testing races.
For local testing, stop the cloud relayer first:

\`\`\`bash
ssh gcp-realm-worker-1 'sudo systemctl stop parth-relayer.service'
\`\`\`
EOF

echo "prepared local relayer runtime: $OUT_DIR"
echo "run it with:"
echo "  cd $OUT_DIR"
echo "  export BRIDGE_RELAYER_L2_PRIVATE_KEY='<genesis user 2 private key>'"
echo "  export WALLET_PASSWORD='<L1 keystore password>'"
echo "  ./run.sh"
