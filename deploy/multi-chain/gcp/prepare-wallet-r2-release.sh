#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COHORT_ROOT="$(cd "$REPO_ROOT/.." && pwd)"

WALLET_COMMIT="3bb5d09c794176a019b05a8c066527a5bd4283d3"
SDK_BUILD_REPORT_COMMIT="310cd961bb479619069f12ca71c32e133066e2ad"
SDK_SHA256="3b19b24d9c2608670e55e03d741f9aa3df85a0a6df4716afd2136681f36d3643"
SDK_COMPILER_COMMIT="bb79f3ff335d36560b8b6eae880c8404d662d27c"
WALLET_VERSION="0.4.28"
WALLET_ZIP_SHA256="3e754e5f8844f436cc06b2fafde4b146515ed66165554feed35ae416619cbb3d"
WALLET_ZIP_SIZE="25209766"
EXPECTED_CURRENT_WALLET_COMMIT="27ca518dc2d970e411bd43b399f78b8c86dcbb73"
EXPECTED_CURRENT_WALLET_SHA256="ba641a460ec9e2ae410971acd87e28f99ab182b0eb53eab5c31c371d6b0854d1"
STAGE="testnet"
STAGE_MAGIC="0x1337cf514544cf69"
MAINNET_MAGIC="0x1337cf514544c069"

WALLET_DIR="${WALLET_DIR:-$COHORT_ROOT/release-artifacts/wallet-testnet/psy-wallet}"
SDK_ARCHIVE="${SDK_ARCHIVE:-$COHORT_ROOT/artifacts/sdk-310cd961-testnet/psy-protocol-psy-sdk-2.0.4.tgz}"
SDK_PACKAGE_DIR="${SDK_PACKAGE_DIR:-$COHORT_ROOT/release-artifacts/wallet-testnet/psy-sdk/psy-ts-sdk/packages/psy-sdk}"
WALLET_ZIP="${WALLET_ZIP:-$WALLET_DIR/release/staging/psy-wallet/v$WALLET_VERSION/psy-wallet-staging-v$WALLET_VERSION.zip}"
PUBLISHER="$WALLET_DIR/scripts/publish-wallet-r2-stg.sh"

R2_BUCKET="${R2_BUCKET:-psy-wallet-assets-stg}"
R2_PUBLIC_BASE_URL="${R2_PUBLIC_BASE_URL:-https://wallet-assets-stg.psy-protocol.xyz}"
R2_LATEST_METADATA_KEY="${R2_LATEST_METADATA_KEY:-wallet-release.json}"
R2_RELEASE_PREFIX="releases/staging/wallet-$WALLET_COMMIT/sdk-$SDK_BUILD_REPORT_COMMIT/$STAGE/sha256-$WALLET_ZIP_SHA256"
R2_CANDIDATE_METADATA_KEY="$R2_RELEASE_PREFIX/wallet-release-candidate.json"
LOCAL_CANDIDATE_METADATA="${LOCAL_CANDIDATE_METADATA:-$COHORT_ROOT/release-artifacts/wallet-testnet/wallet-release-candidate.json}"

usage() {
  cat <<'USAGE'
Usage: prepare-wallet-r2-release.sh MODE

Modes:
  --prepare           Verify local immutable inputs and render candidate metadata only
  --upload-candidate  Upload the immutable ZIP and candidate metadata, then verify them
  --promote-latest    Re-verify the candidate and switch wallet-release.json

Upload modes require CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in the
environment. They are consumed by wrangler and are never read from command-line
arguments. Set WRANGLER to an installed command if it is not named "wrangler".

--promote-latest also requires CONFIRM_BACKEND_DEPLOYED=1. It must be used only
after the backend compatible with SDK 310cd961 has been deployed and accepted.
USAGE
}

fail() {
  echo "[wallet-r2-prep] ERROR: $*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

require_equal() {
  local actual="$1" expected="$2" label="$3"
  [ "$actual" = "$expected" ] || fail "$label mismatch: got=$actual expected=$expected"
}

verify_local_inputs() {
  local sdk_metadata sdk_name sdk_version wasm_values wasm_stage wasm_magic
  local archive_dir linked_sdk

  [ -x "$PUBLISHER" ] || fail "missing wallet publisher: $PUBLISHER"
  [ -f "$SDK_ARCHIVE" ] || fail "missing SDK archive: $SDK_ARCHIVE"
  [ -f "$WALLET_ZIP" ] || fail "missing wallet ZIP: $WALLET_ZIP"
  [ -f "$SDK_PACKAGE_DIR/dist/local-web-prover/index.mjs" ] \
    || fail "missing extracted SDK package: $SDK_PACKAGE_DIR"

  require_equal "$(git -C "$WALLET_DIR" rev-parse HEAD)" "$WALLET_COMMIT" "wallet commit"
  [ -z "$(git -C "$WALLET_DIR" status --porcelain)" ] || fail "wallet checkout is dirty"
  require_equal "$(sha256_file "$SDK_ARCHIVE")" "$SDK_SHA256" "SDK archive SHA-256"
  require_equal "$(sha256_file "$WALLET_ZIP")" "$WALLET_ZIP_SHA256" "wallet ZIP SHA-256"
  require_equal "$(wc -c <"$WALLET_ZIP" | tr -d ' ')" "$WALLET_ZIP_SIZE" "wallet ZIP size"

  archive_dir="$(mktemp -d)"
  tar -xzf "$SDK_ARCHIVE" -C "$archive_dir"
  if ! diff -qr "$archive_dir/package" "$SDK_PACKAGE_DIR"; then
    rm -rf "$archive_dir"
    fail "extracted SDK directory differs from the pinned archive"
  fi
  [ -L "$WALLET_DIR/node_modules/@psy-protocol/psy-sdk" ] || {
    rm -rf "$archive_dir"
    fail "wallet SDK dependency is not a symlink"
  }
  linked_sdk="$(readlink -f "$WALLET_DIR/node_modules/@psy-protocol/psy-sdk")"
  case "$linked_sdk" in
    "$WALLET_DIR/node_modules/.pnpm/"*) ;;
    *)
      rm -rf "$archive_dir"
      fail "wallet SDK symlink resolves outside its isolated pnpm store: $linked_sdk"
      ;;
  esac
  if ! diff -qr "$archive_dir/package" "$linked_sdk"; then
    rm -rf "$archive_dir"
    fail "wallet-linked SDK differs from the pinned archive"
  fi
  rm -rf "$archive_dir"

  sdk_metadata="$(tar -xOzf "$SDK_ARCHIVE" package/.compiler-artifact.json)"
  require_equal "$(jq -er '.compilerRevision' <<<"$sdk_metadata")" \
    "$SDK_COMPILER_COMMIT" "SDK compiler revision"
  sdk_name="$(tar -xOzf "$SDK_ARCHIVE" package/package.json | jq -er '.name')"
  sdk_version="$(tar -xOzf "$SDK_ARCHIVE" package/package.json | jq -er '.version')"
  require_equal "$sdk_name" "@psy-protocol/psy-sdk" "SDK package name"
  require_equal "$sdk_version" "2.0.4" "SDK package version"
  grep -q QBCDeployContractV2 "$SDK_PACKAGE_DIR/dist/local-prover-rpc/types.d.ts" \
    || fail "SDK declarations lack QBCDeployContractV2"

  wasm_values="$(SDK_PACKAGE_DIR="$SDK_PACKAGE_DIR" node --input-type=module <<'NODE'
const sdk = process.env.SDK_PACKAGE_DIR;
const { initWasmSync, WasmConstants } = await import(`${sdk}/dist/local-web-prover/index.mjs`);
initWasmSync();
const constants = WasmConstants.getAllConstants();
const magic = constants.match(/"psy_network_magic"\s*:\s*(\d+)/)?.[1];
if (!magic) throw new Error("SDK WASM did not report psy_network_magic");
console.log(`${WasmConstants.current_network} 0x${BigInt(magic).toString(16)}`);
NODE
)"
  read -r wasm_stage wasm_magic <<<"$(tail -n 1 <<<"$wasm_values")"
  require_equal "$wasm_stage" "$STAGE" "SDK WASM stage"
  require_equal "$wasm_magic" "$STAGE_MAGIC" "SDK WASM magic"

  require_equal "$(jq -er '.networks.testnet.magic | ascii_downcase' "$WALLET_DIR/psy-genesis/config.json")" \
    "$STAGE_MAGIC" "wallet testnet magic"
  require_equal "$(jq -er '.networks.mainnet.magic | ascii_downcase' "$WALLET_DIR/psy-genesis/config.json")" \
    "$MAINNET_MAGIC" "wallet mainnet magic"
  [ "$STAGE_MAGIC" != "$MAINNET_MAGIC" ] || fail "testnet and mainnet magic must differ"

  unzip -p "$WALLET_ZIP" src/content/webHook.js | grep -q psy_getNetworkConfig \
    || fail "wallet ZIP content-script guard failed"

  echo "[wallet-r2-prep] wallet=$WALLET_COMMIT"
  echo "[wallet-r2-prep] sdk_build_report_commit=$SDK_BUILD_REPORT_COMMIT archive_sha256=$SDK_SHA256 compiler=$SDK_COMPILER_COMMIT"
  echo "[wallet-r2-prep] wallet_sdk_realpath=$linked_sdk"
  echo "[wallet-r2-prep] stage=$STAGE magic=$STAGE_MAGIC mainnet_magic=$MAINNET_MAGIC"
  echo "[wallet-r2-prep] zip=$WALLET_ZIP_SHA256"
  echo "[wallet-r2-prep] immutable_key=$R2_RELEASE_PREFIX/$(basename "$WALLET_ZIP")"
  echo "[wallet-r2-prep] candidate_metadata_key=$R2_CANDIDATE_METADATA_KEY"
}

publisher_env() {
  env \
    CI=true \
    HUSKY=0 \
    SKIP_WALLET_BUILD=1 \
    WALLET_COMMIT="$WALLET_COMMIT" \
    WALLET_REF="$WALLET_COMMIT" \
    CF_ENV_FILE= \
    WALLET_PACKAGE_MODE=staging \
    R2_BUCKET="$R2_BUCKET" \
    R2_PUBLIC_BASE_URL="$R2_PUBLIC_BASE_URL" \
    R2_RELEASE_PREFIX="$R2_RELEASE_PREFIX" \
    PUBLIC_COORDINATOR_DOMAIN=coordinator-stg.psy-protocol.xyz \
    PUBLIC_PROVE_PROXY_DOMAIN=prove-stg.psy-protocol.xyz \
    NOSTR_DOMAIN=nostr-stg.psy-protocol.xyz \
    PUBLIC_PSY_EXPLORER_URL=https://explorer-stg.psy-protocol.xyz/ \
    "$@"
}

prepare() {
  verify_local_inputs
  mkdir -p "$(dirname "$LOCAL_CANDIDATE_METADATA")"
  publisher_env \
    R2_SKIP_UPLOAD=1 \
    R2_METADATA_KEY="$R2_CANDIDATE_METADATA_KEY" \
    R2_DRY_RUN_METADATA_FILE="$LOCAL_CANDIDATE_METADATA" \
    bash "$PUBLISHER"
  echo "[wallet-r2-prep] candidate metadata: $LOCAL_CANDIDATE_METADATA"
}

upload_candidate() {
  verify_local_inputs
  command -v "${WRANGLER:-wrangler}" >/dev/null 2>&1 \
    || fail "wrangler is not installed; set WRANGLER to its executable name"
  : "${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"
  : "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
  publisher_env \
    WRANGLER="${WRANGLER:-wrangler}" \
    R2_SKIP_UPLOAD=0 \
    R2_SKIP_VERIFY=0 \
    R2_METADATA_KEY="$R2_CANDIDATE_METADATA_KEY" \
    bash "$PUBLISHER"
  verify_public_release "$R2_CANDIDATE_METADATA_KEY"
}

verify_public_release() {
  local metadata_key="$1"
  local metadata_url expected_zip_url metadata public_zip

  metadata_url="${R2_PUBLIC_BASE_URL%/}/$metadata_key"
  expected_zip_url="${R2_PUBLIC_BASE_URL%/}/$R2_RELEASE_PREFIX/$(basename "$WALLET_ZIP")"
  metadata="$(curl -fsSL "$metadata_url")" || fail "release metadata is not public: $metadata_url"
  require_equal "$(jq -er '.walletCommit' <<<"$metadata")" "$WALLET_COMMIT" "public wallet commit"
  require_equal "$(jq -er '.sha256' <<<"$metadata")" "$WALLET_ZIP_SHA256" "public wallet SHA-256"
  require_equal "$(jq -er '.zipUrl' <<<"$metadata")" "$expected_zip_url" "public wallet ZIP URL"
  require_equal "$(jq -er '.sizeBytes | tostring' <<<"$metadata")" "$WALLET_ZIP_SIZE" "public wallet ZIP size"
  require_equal "$(jq -er '.network' <<<"$metadata")" "staging" "public wallet network"

  public_zip="$(mktemp /tmp/psy-wallet-public.XXXXXX.zip)"
  if ! curl -fsSL "$expected_zip_url" -o "$public_zip"; then
    rm -f "$public_zip"
    fail "release ZIP is not public: $expected_zip_url"
  fi
  require_equal "$(sha256_file "$public_zip")" "$WALLET_ZIP_SHA256" "public wallet ZIP SHA-256"
  require_equal "$(wc -c <"$public_zip" | tr -d ' ')" "$WALLET_ZIP_SIZE" "downloaded wallet ZIP size"
  rm -f "$public_zip"
  echo "[wallet-r2-prep] independently verified metadata and ZIP: $metadata_url"
}

promote_latest() {
  verify_local_inputs
  [ "${CONFIRM_BACKEND_DEPLOYED:-0}" = 1 ] \
    || fail "set CONFIRM_BACKEND_DEPLOYED=1 only after backend acceptance"

  local latest
  verify_public_release "$R2_CANDIDATE_METADATA_KEY"

  latest="$(curl -fsSL "${R2_PUBLIC_BASE_URL%/}/$R2_LATEST_METADATA_KEY")" \
    || fail "cannot read current latest wallet metadata"
  require_equal "$(jq -er '.walletCommit' <<<"$latest")" \
    "$EXPECTED_CURRENT_WALLET_COMMIT" "current latest wallet commit"
  require_equal "$(jq -er '.sha256' <<<"$latest")" \
    "$EXPECTED_CURRENT_WALLET_SHA256" "current latest wallet SHA-256"

  upload_candidate_env=(
    WRANGLER="${WRANGLER:-wrangler}"
    R2_SKIP_UPLOAD=0
    R2_SKIP_VERIFY=0
    R2_METADATA_KEY="$R2_LATEST_METADATA_KEY"
  )
  command -v "${WRANGLER:-wrangler}" >/dev/null 2>&1 \
    || fail "wrangler is not installed; set WRANGLER to its executable name"
  : "${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"
  : "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
  publisher_env "${upload_candidate_env[@]}" bash "$PUBLISHER"
  verify_public_release "$R2_LATEST_METADATA_KEY"
}

case "${1:---prepare}" in
  --prepare) prepare ;;
  --upload-candidate) upload_candidate ;;
  --promote-latest) promote_latest ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
