#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="${LOCAL_CF_SOURCE_PARTH_DIR:-${PARTH_DIR:-$(cd "$SCRIPT_DIR/../../.." && pwd)}}"

# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_staging_source_env_defaults "$SCRIPT_DIR/local.env"

: "${LOCAL_STAGING_STATE_DIR:=$PARTH_DIR/.local-staging}"
: "${LOCAL_STAGING_BUILD_FRONTENDS:=1}"
: "${LOCAL_STAGING_NPM_INSTALL:=0}"
: "${LOCAL_STAGING_BUILD_WALLET:=0}"
: "${LOCAL_STAGING_WALLET_BUILD_SCRIPT:=build:dev}"
: "${LOCAL_STAGING_WALLET_BUILD_ID:=local-cf-faucet-server-split-20260717-1}"
: "${LOCAL_STAGING_WALLET_RELEASE_DIR:=release/dev/psy-wallet}"
: "${LOCAL_STAGING_WALLET_ZIP_GLOB:=psy-wallet-dev-v*.zip}"
: "${LOCAL_STAGING_WALLET_LATEST_ZIP:=psy-wallet-dev-latest.zip}"
: "${PSY_WALLET_DIR:=$PARTH_DIR/../psy-wallet}"
: "${LOCAL_STAGING_ALLOW_PUBLISH_WITH_CF:=0}"

NGINX_ROOT="${LOCAL_STAGING_NGINX_ROOT:-$LOCAL_STAGING_STATE_DIR/nginx/html}"
APP_DIR="$PARTH_DIR/client_prover/psy-privacy-bridge"
EXPLORER_DIR="$PARTH_DIR/client_prover/psy_explorer"
IDE_DIR="$PARTH_DIR/client_prover/psy_ide/frontend"

require_dir() {
  local path="$1"
  [ -d "$path" ] || {
    echo "[local-staging] missing directory: $path" >&2
    exit 1
  }
}

guard_cf_tunnel_publish_profile() {
  if [ "$LOCAL_STAGING_ALLOW_PUBLISH_WITH_CF" = "1" ]; then
    return
  fi
  local cloudflared_pid_file="$PARTH_DIR/.local-staging/pids/cloudflared.pid"
  local cloudflared_pid=""
  if [ -f "$cloudflared_pid_file" ]; then
    cloudflared_pid="$(cat "$cloudflared_pid_file" 2>/dev/null || true)"
  fi
  if { [ -n "$cloudflared_pid" ] && kill -0 "$cloudflared_pid" >/dev/null 2>&1; } ||
    pgrep -f 'cloudflared .*psy-local-staging|cloudflared .*app-local\.psy-protocol\.xyz|cloudflared .*\.local-staging-cf-tunnel/cloudflared/config\.yml' >/dev/null 2>&1; then
    cat >&2 <<EOF
[local-staging] refusing to publish localhost-configured frontends while the CF tunnel is running.
[local-staging] Use deploy/local-testnet/cloudflare-tunnel/publish-frontends.sh for app-local.psy-protocol.xyz.
[local-staging] Set LOCAL_STAGING_ALLOW_PUBLISH_WITH_CF=1 only from a wrapper that has already applied tunnel-safe config.
EOF
    exit 1
  fi
}

run_npm_install_if_requested() {
  local dir="$1"
  if [ "$LOCAL_STAGING_NPM_INSTALL" = "1" ] && [ ! -d "$dir/node_modules" ]; then
    if grep -Eq '"[^"]+"[[:space:]]*:[[:space:]]*"file:' "$dir/package.json"; then
      echo "[local-staging] npm install with local file dependencies in $dir"
      (cd "$dir" && npm install --no-package-lock)
    elif [ -f "$dir/pnpm-lock.yaml" ]; then
      echo "[local-staging] pnpm install --frozen-lockfile in $dir"
      if ! (cd "$dir" && pnpm install --frozen-lockfile); then
        echo "[local-staging] warning: stale pnpm lockfile in $dir; installing without modifying the tracked lockfile" >&2
        (cd "$dir" && pnpm install --no-frozen-lockfile --lockfile=false)
      fi
    elif [ -f "$dir/package-lock.json" ]; then
      echo "[local-staging] npm ci in $dir"
      (cd "$dir" && npm ci)
    else
      echo "[local-staging] pnpm install without a lockfile in $dir"
      (cd "$dir" && pnpm install --no-frozen-lockfile)
    fi
  fi
}

build_frontend() {
  local label="$1"
  local dir="$2"

  require_dir "$dir"
  if [ "$LOCAL_STAGING_BUILD_FRONTENDS" = "1" ]; then
    run_npm_install_if_requested "$dir"
    if [ ! -d "$dir/node_modules" ]; then
      echo "[local-staging] missing node_modules for $label: $dir" >&2
      echo "run LOCAL_STAGING_NPM_INSTALL=1 bash deploy/local-testnet/stack/publish-frontends.sh, or install dependencies manually" >&2
      exit 1
    fi
    echo "[local-staging] building $label"
    (cd "$dir" && PSY_SKIP_CONFIG_SYNC=1 VITE_NETWORK=localhost npm run build)
  fi

  [ -d "$dir/dist" ] || {
    echo "[local-staging] missing dist for $label: $dir/dist" >&2
    echo "build it first or set LOCAL_STAGING_BUILD_FRONTENDS=1" >&2
    exit 1
  }
}

copy_dist() {
  local label="$1"
  local source="$2"
  local target="$3"

  echo "[local-staging] publishing $label -> $target"
  rm -rf "$target"
  mkdir -p "$target"
  cp -a "$source"/. "$target"/
}

publish_wallet_downloads() {
  local downloads_dir="$NGINX_ROOT/downloads"
  mkdir -p "$downloads_dir"

  if [ "$LOCAL_STAGING_BUILD_WALLET" = "1" ]; then
    require_dir "$PSY_WALLET_DIR"
    if [ ! -d "$PSY_WALLET_DIR/node_modules" ]; then
      echo "[local-staging] missing wallet node_modules: $PSY_WALLET_DIR" >&2
      echo "install wallet dependencies first, or set LOCAL_STAGING_BUILD_WALLET=0" >&2
      exit 1
    fi
    echo "[local-staging] building wallet package ($LOCAL_STAGING_WALLET_BUILD_SCRIPT)"
    (cd "$PSY_WALLET_DIR" && VITE_NETWORK=localhost pnpm "$LOCAL_STAGING_WALLET_BUILD_SCRIPT")
  fi

  if [ -d "$PSY_WALLET_DIR/$LOCAL_STAGING_WALLET_RELEASE_DIR" ]; then
    find "$PSY_WALLET_DIR/$LOCAL_STAGING_WALLET_RELEASE_DIR" -type f -name "$LOCAL_STAGING_WALLET_ZIP_GLOB" -exec cp -a {} "$downloads_dir"/ \;
  fi

  if [ -d "$APP_DIR/public/downloads" ]; then
    find "$APP_DIR/public/downloads" -maxdepth 1 -type f -name '*.zip' -exec cp -a {} "$downloads_dir"/ \;
  fi

  latest_zip="$(find "$downloads_dir" -maxdepth 1 -type f -name "$LOCAL_STAGING_WALLET_ZIP_GLOB" | sort -V | tail -1)"
  if [ -n "$latest_zip" ]; then
    cp -a "$latest_zip" "$downloads_dir/$LOCAL_STAGING_WALLET_LATEST_ZIP"
    version="$(basename "$latest_zip" | sed -E 's/.*-v([0-9.]+)\.zip/\1/')"
    sha="$(sha256sum "$latest_zip" | awk '{print $1}')"
    cat > "$downloads_dir/wallet-release.json" <<JSON
{
  "version": "$version",
  "network": "local-devnet",
  "buildId": "$LOCAL_STAGING_WALLET_BUILD_ID",
  "zipName": "$LOCAL_STAGING_WALLET_LATEST_ZIP",
  "zipUrl": "/downloads/$LOCAL_STAGING_WALLET_LATEST_ZIP?sha=$sha",
  "sha256": "$sha",
  "endpoints": [
    { "label": "Coordinator", "value": "https://coordinator-local.psy-protocol.xyz" },
    { "label": "Prove proxy", "value": "https://prove-local.psy-protocol.xyz" },
    { "label": "Faucet", "value": "https://faucet-local.psy-protocol.xyz" },
    { "label": "Services", "value": "https://services-local.psy-protocol.xyz" }
  ],
  "steps": [
    "Download the wallet package.",
    "Unzip it locally.",
    "Open chrome://extensions or edge://extensions.",
    "Enable Developer mode.",
    "Choose Load unpacked and select the Psy Wallet folder."
  ]
}
JSON
    echo "[local-staging] wallet download: $downloads_dir/$(basename "$latest_zip")"
    echo "[local-staging] wallet latest:   $downloads_dir/$LOCAL_STAGING_WALLET_LATEST_ZIP"
  else
    echo "[local-staging] no wallet zip found; app /wallet page may show its fallback URL only"
  fi
}

main() {
  mkdir -p "$NGINX_ROOT"
  guard_cf_tunnel_publish_profile

  build_frontend app "$APP_DIR"
  build_frontend explorer "$EXPLORER_DIR"
  build_frontend ide "$IDE_DIR"

  copy_dist app "$APP_DIR/dist" "$NGINX_ROOT/app"
  copy_dist explorer "$EXPLORER_DIR/dist" "$NGINX_ROOT/explorer"
  copy_dist ide "$IDE_DIR/dist" "$NGINX_ROOT/ide"
  publish_wallet_downloads

  echo "[local-staging] frontend publish complete"
}

main "$@"
