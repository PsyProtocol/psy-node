#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROFILE_DIR="$ROOT/deploy/gcp/bsc-testnet"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# The committed profile intentionally overlays the ignored production config.
# An empty base proves all safety-critical BSC and topology values are explicit.
base_config="$tmp_dir/base.env"
: >"$base_config"

common_env=(
  "WORKSPACE_HOME=$(cd "$ROOT/.." && pwd)"
  "BSC_BASE_GCP_CONFIG=$base_config"
  "BSC_TESTNET_RPC_URL=https://bsc-testnet.example.invalid"
  "ENVIO_API_TOKEN=test-only"
  "GCP_DEPLOY_CONFIG=$PROFILE_DIR/config.example.env"
  "DEPLOY_SOURCE_VERSIONS_FILE=$PROFILE_DIR/source-versions.env"
  "BSC_PREFLIGHT_SKIP_RPC=1"
)

preflight_output="$(env "${common_env[@]}" bash "$PROFILE_DIR/preflight.sh")"
grep -q 'machine topology unchanged' <<<"$preflight_output"
grep -q 'network and public namespace checks passed' <<<"$preflight_output"

mock_bin="$tmp_dir/bin"
mkdir -p "$mock_bin"
cat >"$mock_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
payload=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -w) shift 2 ;;
    --data) payload="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "${MOCK_RPC_ERROR:-0}" = "1" ]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"BNB_TESTNET is not enabled for this app"}}' >"$output"
  printf '403'
elif [[ "$payload" == *'eth_chainId'* ]]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":"0x61"}' >"$output"
  printf '200'
elif [[ "$payload" == *'eth_getBalance'* ]]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}' >"$output"
  printf '200'
else
  exit 2
fi
EOF
cat >"$mock_bin/cast" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = "to-dec" ]
[ "$2" = "0xde0b6b3a7640000" ]
printf '%s\n' '1000000000000000000'
EOF
chmod +x "$mock_bin/curl" "$mock_bin/cast"

rpc_env=(
  "WORKSPACE_HOME=$(cd "$ROOT/.." && pwd)"
  "BSC_BASE_GCP_CONFIG=$base_config"
  "BSC_TESTNET_RPC_URL=https://bnb-testnet.g.alchemy.com/v2/redacted-test-key"
  "ENVIO_API_TOKEN=test-only"
  "GCP_DEPLOY_CONFIG=$PROFILE_DIR/config.example.env"
  "DEPLOY_SOURCE_VERSIONS_FILE=$PROFILE_DIR/source-versions.env"
  "L1_DEPLOYER_ADDRESS=0x490f8192725255C2C3dE0CbCE66312335Ca019Ad"
  "PATH=$mock_bin:$PATH"
)
rpc_output="$(env "${rpc_env[@]}" bash "$PROFILE_DIR/preflight.sh")"
grep -q 'verified BSC Testnet RPC chain ID: 97' <<<"$rpc_output"
grep -q 'verified deployer/relayer tBNB balance' <<<"$rpc_output"

if env "${rpc_env[@]}" MOCK_RPC_ERROR=1 bash "$PROFILE_DIR/preflight.sh" \
  >"$tmp_dir/rpc-error.out" 2>"$tmp_dir/rpc-error.err"; then
  echo "BSC preflight unexpectedly accepted a provider RPC error" >&2
  exit 1
fi
grep -q 'BNB_TESTNET is not enabled for this app' "$tmp_dir/rpc-error.err"

if env "${common_env[@]}" bash "$PROFILE_DIR/deploy_all.sh" \
  >"$tmp_dir/deploy.out" 2>"$tmp_dir/deploy.err"; then
  echo "BSC deploy unexpectedly continued without replacement confirmation" >&2
  exit 1
fi
grep -q 'CONFIRM_BSC_REPLACES_SEPOLIA=1' "$tmp_dir/deploy.err" || {
  echo "BSC deploy did not report the destructive replacement confirmation" >&2
  cat "$tmp_dir/deploy.err" >&2
  exit 1
}

echo "[ok] BSC Testnet profile isolates network values and requires replacement confirmation"
