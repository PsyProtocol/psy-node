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
