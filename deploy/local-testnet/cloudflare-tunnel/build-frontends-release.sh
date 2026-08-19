#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_render_chain_config

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[local-cf-release] missing command: $1" >&2
    exit 1
  }
}

require_command bash
require_command curl
require_command date
require_command git
require_command jq
require_command mkdir
require_command rm
require_command sha256sum
require_command sleep

LOCAL_CF_FRONTEND_RELEASES_DIR="${LOCAL_CF_FRONTEND_RELEASES_DIR:-$PARTH_DIR/.local-staging/nginx/html/.releases/frontends}"
local_cf_default_release_id() {
  local git_sha deployment_file deployment_sha

  git_sha="$(git -C "$PARTH_DIR" rev-parse --short=12 HEAD)"
  deployment_file="$PARTH_DIR/psy-contracts/deployments/localhost/deployed-contracts.json"
  if [ ! -s "$deployment_file" ]; then
    printf '%s\n' "$git_sha"
    return
  fi

  deployment_sha="$(sha256sum "$deployment_file" | awk '{print substr($1, 1, 12)}')"
  printf '%s-%s\n' "$git_sha" "$deployment_sha"
}

LOCAL_CF_FRONTEND_RELEASE_ID="${LOCAL_CF_FRONTEND_RELEASE_ID:-$(local_cf_default_release_id)}"
LOCAL_CF_FRONTEND_RELEASE_DIR="${LOCAL_CF_FRONTEND_RELEASE_DIR:-$LOCAL_CF_FRONTEND_RELEASES_DIR/$LOCAL_CF_FRONTEND_RELEASE_ID}"
LOCAL_CF_FRONTEND_OVERWRITE_RELEASE="${LOCAL_CF_FRONTEND_OVERWRITE_RELEASE:-1}"
LOCAL_CF_WALLET_RELEASE_URL="${LOCAL_CF_WALLET_RELEASE_URL:-https://wallet-assets-stg.psy-protocol.xyz/local-devnet/wallet-release.json}"

LOCAL_CF_AUTODEPLOY_BUILD_WALLET="${LOCAL_CF_AUTODEPLOY_BUILD_WALLET:-1}"
LOCAL_CF_AUTODEPLOY_BUILD_SDK="${LOCAL_CF_AUTODEPLOY_BUILD_SDK:-1}"
LOCAL_CF_WALLET_R2_METADATA_KEY="${LOCAL_CF_WALLET_R2_METADATA_KEY:-local-devnet/wallet-release.json}"
LOCAL_CF_WALLET_R2_RELEASE_NONCE="${LOCAL_CF_WALLET_R2_RELEASE_NONCE:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
LOCAL_CF_WALLET_R2_RELEASE_PREFIX="${LOCAL_CF_WALLET_R2_RELEASE_PREFIX:-local-devnet/releases/$LOCAL_CF_FRONTEND_RELEASE_ID/$LOCAL_CF_WALLET_R2_RELEASE_NONCE}"
LOCAL_CF_WALLET_R2_STAGE_METADATA_KEY="${LOCAL_CF_WALLET_R2_STAGE_METADATA_KEY:-$LOCAL_CF_WALLET_R2_RELEASE_PREFIX/wallet-release.json}"
LOCAL_CF_WALLET_R2_REUSE_MATCHING_RELEASE="${LOCAL_CF_WALLET_R2_REUSE_MATCHING_RELEASE:-1}"
LOCAL_CF_WALLET_R2_BUCKET="${R2_BUCKET:-psy-wallet-assets-stg}"
LOCAL_CF_WALLET_R2_PUBLIC_BASE_URL="${R2_PUBLIC_BASE_URL:-https://wallet-assets-stg.psy-protocol.xyz}"
LOCAL_CF_WALLET_R2_PROMOTION_FILE="$LOCAL_CF_FRONTEND_RELEASE_DIR/wallet-r2-promotion.json"
LOCAL_CF_WALLET_PACKAGE_MODE="${LOCAL_CF_WALLET_PACKAGE_MODE:-dev}"
LOCAL_CF_WALLET_BUILD_COMMAND="${LOCAL_CF_WALLET_BUILD_COMMAND:-pnpm build:dev}"
LOCAL_CF_WALLET_REMOTE="${LOCAL_CF_WALLET_REMOTE:-origin}"
LOCAL_CF_WALLET_BRANCH="${LOCAL_CF_WALLET_BRANCH:-feat/improve-bridge-relayer}"
PSY_WALLET_DIR="${PSY_WALLET_DIR:-$PARTH_DIR/../psy-wallet}"
LOCAL_CF_SDK_REMOTE="${LOCAL_CF_SDK_REMOTE:-origin}"
LOCAL_CF_SDK_BRANCH="${LOCAL_CF_SDK_BRANCH:-feat/improve-bridge-relayer}"
PSY_SDK_DIR="${PSY_SDK_DIR:-$PARTH_DIR/../psy-sdk}"
PSY_SDK_PACKAGE_DIR="${PSY_SDK_PACKAGE_DIR:-$PSY_SDK_DIR/psy-ts-sdk/packages/psy-sdk}"
LOCAL_CF_WALLET_SOURCE_REF=""
LOCAL_CF_WALLET_SOURCE_SHA=""
LOCAL_CF_SDK_SOURCE_REF=""
LOCAL_CF_SDK_SOURCE_SHA=""
LOCAL_CF_SDK_BUILD_ATTEMPTS="${LOCAL_CF_SDK_BUILD_ATTEMPTS:-2}"
LOCAL_CF_SDK_BUILD_RETRY_DELAY_SECONDS="${LOCAL_CF_SDK_BUILD_RETRY_DELAY_SECONDS:-10}"

verify_sdk_source() {
  [ "$LOCAL_CF_AUTODEPLOY_BUILD_SDK" = "1" ] || return 0

  local sdk_branch sdk_remote_head
  if ! git -C "$PSY_SDK_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    echo "[local-cf-release] SDK checkout is not a git repository: $PSY_SDK_DIR" >&2
    exit 1
  fi

  sdk_branch="$(git -C "$PSY_SDK_DIR" branch --show-current)"
  LOCAL_CF_SDK_SOURCE_REF="$LOCAL_CF_SDK_REMOTE/$LOCAL_CF_SDK_BRANCH"
  if [ "$sdk_branch" != "$LOCAL_CF_SDK_BRANCH" ]; then
    echo "[local-cf-release] SDK branch mismatch: current=$sdk_branch required=$LOCAL_CF_SDK_BRANCH" >&2
    exit 1
  fi
  if ! sdk_remote_head="$(git -C "$PSY_SDK_DIR" rev-parse --verify "$LOCAL_CF_SDK_SOURCE_REF")"; then
    echo "[local-cf-release] SDK remote ref is unavailable: $LOCAL_CF_SDK_SOURCE_REF (fetch before publishing)" >&2
    exit 1
  fi
  LOCAL_CF_SDK_SOURCE_SHA="$(git -C "$PSY_SDK_DIR" rev-parse HEAD)"
  if [ "$LOCAL_CF_SDK_SOURCE_SHA" != "$sdk_remote_head" ]; then
    echo "[local-cf-release] SDK checkout is not synchronized: HEAD=$LOCAL_CF_SDK_SOURCE_SHA $LOCAL_CF_SDK_SOURCE_REF=$sdk_remote_head" >&2
    exit 1
  fi
  if [ -n "$(git -C "$PSY_SDK_DIR" status --porcelain)" ]; then
    echo "[local-cf-release] SDK checkout is dirty: $PSY_SDK_DIR" >&2
    exit 1
  fi
  if [ ! -f "$PSY_SDK_PACKAGE_DIR/package.json" ]; then
    echo "[local-cf-release] SDK package is missing: $PSY_SDK_PACKAGE_DIR/package.json" >&2
    exit 1
  fi
}

verify_wallet_source() {
  [ "$LOCAL_CF_AUTODEPLOY_BUILD_WALLET" = "1" ] || return 0

  local wallet_branch wallet_remote_head
  if ! git -C "$PSY_WALLET_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    echo "[local-cf-release] wallet checkout is not a git repository: $PSY_WALLET_DIR" >&2
    exit 1
  fi

  wallet_branch="$(git -C "$PSY_WALLET_DIR" branch --show-current)"
  LOCAL_CF_WALLET_SOURCE_REF="$LOCAL_CF_WALLET_REMOTE/$LOCAL_CF_WALLET_BRANCH"
  if [ "$wallet_branch" != "$LOCAL_CF_WALLET_BRANCH" ]; then
    echo "[local-cf-release] wallet branch mismatch: current=$wallet_branch required=$LOCAL_CF_WALLET_BRANCH" >&2
    exit 1
  fi
  if ! wallet_remote_head="$(git -C "$PSY_WALLET_DIR" rev-parse --verify "$LOCAL_CF_WALLET_SOURCE_REF")"; then
    echo "[local-cf-release] wallet remote ref is unavailable: $LOCAL_CF_WALLET_SOURCE_REF (fetch before publishing)" >&2
    exit 1
  fi
  LOCAL_CF_WALLET_SOURCE_SHA="$(git -C "$PSY_WALLET_DIR" rev-parse HEAD)"
  if [ "$LOCAL_CF_WALLET_SOURCE_SHA" != "$wallet_remote_head" ]; then
    echo "[local-cf-release] wallet checkout is not synchronized: HEAD=$LOCAL_CF_WALLET_SOURCE_SHA $LOCAL_CF_WALLET_SOURCE_REF=$wallet_remote_head" >&2
    exit 1
  fi
  if [ -n "$(git -C "$PSY_WALLET_DIR" status --porcelain)" ]; then
    echo "[local-cf-release] wallet checkout is dirty: $PSY_WALLET_DIR" >&2
    exit 1
  fi
}

verify_sdk_source
verify_wallet_source

if [ -e "$LOCAL_CF_FRONTEND_RELEASE_DIR" ]; then
  if [ "$LOCAL_CF_FRONTEND_OVERWRITE_RELEASE" != "1" ]; then
    echo "[local-cf-release] release already exists: $LOCAL_CF_FRONTEND_RELEASE_DIR" >&2
    exit 1
  fi
  rm -rf "$LOCAL_CF_FRONTEND_RELEASE_DIR"
fi

mkdir -p "$LOCAL_CF_FRONTEND_RELEASE_DIR"

build_sdk_if_requested() {
  [ "$LOCAL_CF_AUTODEPLOY_BUILD_SDK" = "1" ] || {
    echo "[local-cf-release] SDK build skipped"
    return 0
  }

  echo "[local-cf-release] building SDK from $LOCAL_CF_SDK_SOURCE_REF@$LOCAL_CF_SDK_SOURCE_SHA"
  (
    sdk_config="$PSY_SDK_DIR/config.json"
    sdk_config_backup="$(mktemp)"
    cp "$sdk_config" "$sdk_config_backup"
    restore_sdk_config() {
      cp "$sdk_config_backup" "$sdk_config"
      rm -f "$sdk_config_backup"
      git -C "$PSY_SDK_DIR" restore --worktree -- \
        Cargo.lock \
        psy-ts-sdk/packages/psy-sdk/src/local-prover/psy_prover.d.ts \
        psy-ts-sdk/packages/psy-sdk/src/local-prover/psy_prover_bg.wasm.d.ts \
        psy-ts-sdk/packages/psy-sdk/src/local-web-compiler/psy_compiler.d.ts \
        psy-ts-sdk/packages/psy-sdk/src/local-web-compiler/psy_compiler_bg.wasm.d.ts \
        psy-ts-sdk/packages/psy-sdk/src/local-web-prover/psy_prover.d.ts \
        psy-ts-sdk/packages/psy-sdk/src/local-web-prover/psy_prover_bg.wasm.d.ts
    }
    trap restore_sdk_config EXIT

    cp "$LOCAL_CF_CHAIN_CONFIG_FILE" "$sdk_config"
    cd "$PSY_SDK_PACKAGE_DIR"
    pnpm install --frozen-lockfile
    sdk_build_attempt=1
    while true; do
      if PSY_COMPILER_DIR="$PARTH_DIR/client_prover/psy_ide" pnpm run build; then
        break
      fi
      if [ "$sdk_build_attempt" -ge "$LOCAL_CF_SDK_BUILD_ATTEMPTS" ]; then
        echo "[local-cf-release] SDK build failed after $sdk_build_attempt attempt(s)" >&2
        return 1
      fi
      echo "[local-cf-release] SDK build attempt $sdk_build_attempt failed; retrying in ${LOCAL_CF_SDK_BUILD_RETRY_DELAY_SECONDS}s" >&2
      sdk_build_attempt=$((sdk_build_attempt + 1))
      sleep "$LOCAL_CF_SDK_BUILD_RETRY_DELAY_SECONDS"
    done
  )
}

publish_wallet_to_r2() {
  [ "$LOCAL_CF_AUTODEPLOY_BUILD_WALLET" = "1" ] || {
    echo "[local-cf-release] wallet R2 publish skipped"
    return 0
  }

  local wallet_publish="$PSY_WALLET_DIR/scripts/publish-wallet-r2-stg.sh"
  local published_metadata=""
  local published_commit=""
  local published_zip_url=""

  if [ "$LOCAL_CF_WALLET_R2_REUSE_MATCHING_RELEASE" = "1" ]; then
    published_metadata="$(curl -fsSL --max-time 20 "$LOCAL_CF_WALLET_RELEASE_URL" 2>/dev/null || true)"
    published_commit="$(printf '%s' "$published_metadata" | jq -r '.walletCommit // empty' 2>/dev/null || true)"
    published_zip_url="$(printf '%s' "$published_metadata" | jq -r '.zipUrl // empty' 2>/dev/null || true)"
    if [ "$published_commit" = "$LOCAL_CF_WALLET_SOURCE_SHA" ] \
      && [ -n "$published_zip_url" ] \
      && curl -fsSI --max-time 20 "$published_zip_url" >/dev/null 2>&1; then
      echo "[local-cf-release] reusing wallet R2 package for commit $published_commit"
      jq -n \
        --argjson required false \
        --arg walletCommit "$LOCAL_CF_WALLET_SOURCE_SHA" \
        --arg targetUrl "$LOCAL_CF_WALLET_RELEASE_URL" \
        '{required: $required, walletCommit: $walletCommit, targetUrl: $targetUrl}' \
        > "$LOCAL_CF_WALLET_R2_PROMOTION_FILE"
      return 0
    fi
  fi

  if [ ! -f "$wallet_publish" ]; then
    echo "[local-cf-release] missing wallet R2 publish script: $wallet_publish" >&2
    exit 1
  fi

  echo "[local-cf-release] staging wallet package from $LOCAL_CF_WALLET_SOURCE_REF@$LOCAL_CF_WALLET_SOURCE_SHA to R2 metadata=$LOCAL_CF_WALLET_R2_STAGE_METADATA_KEY"
  (
    cd "$PSY_WALLET_DIR"

    wallet_config="$PSY_WALLET_DIR/config.json"
    wallet_config_backup="$(mktemp)"
    wallet_config_tmp="${wallet_config}.tmp.$$"
    cp "$wallet_config" "$wallet_config_backup"
    restore_wallet_config() {
      cp "$wallet_config_backup" "$wallet_config"
      rm -f "$wallet_config_backup" "$wallet_config_tmp"
    }
    trap restore_wallet_config EXIT

    jq -s \
      '.[0] as $wallet | .[1] as $tunnel | $wallet | .networks.localhost = $tunnel.networks.localhost' \
      "$wallet_config" "$LOCAL_CF_CHAIN_CONFIG_FILE" > "$wallet_config_tmp"
    mv "$wallet_config_tmp" "$wallet_config"

    WALLET_PACKAGE_MODE="$LOCAL_CF_WALLET_PACKAGE_MODE" \
    WALLET_BUILD_COMMAND="$LOCAL_CF_WALLET_BUILD_COMMAND" \
    R2_METADATA_KEY="$LOCAL_CF_WALLET_R2_STAGE_METADATA_KEY" \
    R2_RELEASE_PREFIX="$LOCAL_CF_WALLET_R2_RELEASE_PREFIX" \
    VITE_NETWORK=localhost \
    PUBLIC_COORDINATOR_DOMAIN="$LOCAL_CF_COORDINATOR_HOST" \
    PUBLIC_PROVE_PROXY_DOMAIN="$LOCAL_CF_PROVE_HOST" \
    PUBLIC_FAUCET_DOMAIN="$LOCAL_CF_FAUCET_HOST" \
    PUBLIC_PSY_EXPLORER_URL="$(local_cf_url "$LOCAL_CF_EXPLORER_HOST")" \
    VITE_NOSTR_RELAY="$LOCAL_CF_NOSTR_RELAY_URL" \
    VITE_NOSTR_RELAY_URL="$LOCAL_CF_NOSTR_RELAY_URL" \
      bash "$wallet_publish"
  )

  jq -n \
    --argjson required true \
    --arg walletCommit "$LOCAL_CF_WALLET_SOURCE_SHA" \
    --arg bucket "$LOCAL_CF_WALLET_R2_BUCKET" \
    --arg stagedKey "$LOCAL_CF_WALLET_R2_STAGE_METADATA_KEY" \
    --arg stagedUrl "${LOCAL_CF_WALLET_R2_PUBLIC_BASE_URL%/}/$LOCAL_CF_WALLET_R2_STAGE_METADATA_KEY" \
    --arg targetKey "$LOCAL_CF_WALLET_R2_METADATA_KEY" \
    --arg targetUrl "$LOCAL_CF_WALLET_RELEASE_URL" \
    '{
      required: $required,
      walletCommit: $walletCommit,
      bucket: $bucket,
      stagedKey: $stagedKey,
      stagedUrl: $stagedUrl,
      targetKey: $targetKey,
      targetUrl: $targetUrl
    }' > "$LOCAL_CF_WALLET_R2_PROMOTION_FILE"
}

write_manifest() {
  local output="$1"
  local status="$2"
  local git_sha git_branch published_at

  git_sha="$(git -C "$PARTH_DIR" rev-parse HEAD)"
  git_branch="$(git -C "$PARTH_DIR" rev-parse --abbrev-ref HEAD)"
  published_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  jq -n \
    --arg releaseId "$LOCAL_CF_FRONTEND_RELEASE_ID" \
    --arg status "$status" \
    --arg gitSha "$git_sha" \
    --arg gitBranch "$git_branch" \
    --arg publishedAt "$published_at" \
    --arg appUrl "$(local_cf_url "$LOCAL_CF_APP_HOST")" \
    --arg explorerUrl "$(local_cf_url "$LOCAL_CF_EXPLORER_HOST")" \
    --arg ideUrl "$(local_cf_url "$LOCAL_CF_IDE_HOST")" \
    --arg walletReleaseUrl "$LOCAL_CF_WALLET_RELEASE_URL" \
    '{
      releaseId: $releaseId,
      status: $status,
      gitSha: $gitSha,
      gitBranch: $gitBranch,
      publishedAt: $publishedAt,
      urls: {
        app: $appUrl,
        explorer: $explorerUrl,
        ide: $ideUrl,
        walletRelease: $walletReleaseUrl
      }
    }' > "$output"
}

build_sdk_if_requested
publish_wallet_to_r2

echo "[local-cf-release] building tunnel-configured frontends -> $LOCAL_CF_FRONTEND_RELEASE_DIR"
LOCAL_STAGING_NGINX_ROOT="$LOCAL_CF_FRONTEND_RELEASE_DIR" \
LOCAL_CF_WALLET_RELEASE_URL="$LOCAL_CF_WALLET_RELEASE_URL" \
LOCAL_STAGING_NPM_INSTALL="${LOCAL_STAGING_NPM_INSTALL:-1}" \
  bash "$SCRIPT_DIR/publish-frontends.sh"

write_manifest "$LOCAL_CF_FRONTEND_RELEASE_DIR/frontend-release.json" "built"

echo "[local-cf-release] built release: $LOCAL_CF_FRONTEND_RELEASE_DIR"
if [ -n "${LOCAL_CF_FRONTEND_RELEASE_DIR_FILE:-}" ]; then
  printf '%s\n' "$LOCAL_CF_FRONTEND_RELEASE_DIR" > "$LOCAL_CF_FRONTEND_RELEASE_DIR_FILE"
fi
echo "$LOCAL_CF_FRONTEND_RELEASE_DIR"
