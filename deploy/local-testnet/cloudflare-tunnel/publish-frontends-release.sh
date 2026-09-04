#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_render_all

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[local-cf-release] missing command: $1" >&2
    exit 1
  }
}

require_command awk
require_command basename
require_command cp
require_command curl
require_command date
require_command find
require_command ln
require_command mkdir
require_command mv
require_command readlink
require_command rm
require_command seq
require_command sort

LOCAL_CF_FRONTEND_RELEASES_DIR="${LOCAL_CF_FRONTEND_RELEASES_DIR:-$PARTH_DIR/.local-staging/nginx/html/.releases/frontends}"
LOCAL_CF_NGINX_HTML_ROOT="${LOCAL_CF_NGINX_HTML_ROOT:-$PARTH_DIR/.local-staging/nginx/html}"
LOCAL_CF_FRONTEND_RELEASE_KEEP="${LOCAL_CF_FRONTEND_RELEASE_KEEP:-5}"
LOCAL_CF_WALLET_RELEASE_URL="${LOCAL_CF_WALLET_RELEASE_URL:-https://wallet-assets-stg.psy-protocol.xyz/local-devnet/wallet-release.json}"
LOCAL_CF_FRONTEND_SMOKE="${LOCAL_CF_FRONTEND_SMOKE:-1}"
LOCAL_CF_FRONTEND_SMOKE_PUBLIC="${LOCAL_CF_FRONTEND_SMOKE_PUBLIC:-1}"

release_arg="${1:-}"
if [ -z "$release_arg" ]; then
  echo "usage: $0 <release-id-or-release-dir>" >&2
  exit 1
fi

if [ -d "$release_arg" ]; then
  RELEASE_DIR="$(cd "$release_arg" && pwd)"
  RELEASE_ID="$(basename "$RELEASE_DIR")"
else
  RELEASE_ID="$release_arg"
  RELEASE_DIR="$LOCAL_CF_FRONTEND_RELEASES_DIR/$RELEASE_ID"
fi

[ -d "$RELEASE_DIR/app" ] || {
  echo "[local-cf-release] release app dir missing: $RELEASE_DIR/app" >&2
  exit 1
}
[ -d "$RELEASE_DIR/explorer" ] || {
  echo "[local-cf-release] release explorer dir missing: $RELEASE_DIR/explorer" >&2
  exit 1
}
[ -d "$RELEASE_DIR/ide" ] || {
  echo "[local-cf-release] release ide dir missing: $RELEASE_DIR/ide" >&2
  exit 1
}

CURRENT_LINK="$LOCAL_CF_FRONTEND_RELEASES_DIR/current"
CURRENT_LINK_NEXT="$LOCAL_CF_FRONTEND_RELEASES_DIR/.current.next"
PREVIOUS_RELEASE_ID=""
WALLET_METADATA_PROMOTED=0
WALLET_METADATA_HAD_BACKUP=0
WALLET_METADATA_BACKUP=""
WALLET_METADATA_BUCKET=""
WALLET_METADATA_TARGET_KEY=""
RELEASE_ACTIVATED=0
PUBLISH_COMMITTED=0

run_wrangler() {
  local -a wrangler_command
  if [ -n "${WRANGLER:-}" ]; then
    read -r -a wrangler_command <<< "$WRANGLER"
    "${wrangler_command[@]}" "$@"
  elif command -v wrangler >/dev/null 2>&1; then
    wrangler "$@"
  else
    npx --yes wrangler "$@"
  fi
}

source_cloudflare_env() {
  [ -n "${CF_ENV_FILE:-}" ] || return 0
  [ -f "$CF_ENV_FILE" ] || {
    echo "[local-cf-release] missing Cloudflare env file: $CF_ENV_FILE" >&2
    return 1
  }
  set -a
  # shellcheck source=/dev/null
  source "$CF_ENV_FILE"
  set +a
}

promote_wallet_metadata() {
  local promotion_file="$RELEASE_DIR/wallet-r2-promotion.json"
  local required staged_url target_url expected_commit candidate probe attempt

  [ -s "$promotion_file" ] || return 0
  required="$(jq -r '.required // false' "$promotion_file")" || return $?
  [ "$required" = "true" ] || return 0

  require_command jq
  if [ -z "${WRANGLER:-}" ] && ! command -v wrangler >/dev/null 2>&1; then
    require_command npx
  fi
  source_cloudflare_env || return $?
  if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
    echo "[local-cf-release] CLOUDFLARE_API_TOKEN is required to promote wallet metadata" >&2
    return 1
  fi
  if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
    echo "[local-cf-release] CLOUDFLARE_ACCOUNT_ID is required to promote wallet metadata" >&2
    return 1
  fi

  staged_url="$(jq -er '.stagedUrl' "$promotion_file")" || return $?
  target_url="$(jq -er '.targetUrl' "$promotion_file")" || return $?
  expected_commit="$(jq -er '.walletCommit' "$promotion_file")" || return $?
  WALLET_METADATA_BUCKET="$(jq -er '.bucket' "$promotion_file")" || return $?
  WALLET_METADATA_TARGET_KEY="$(jq -er '.targetKey' "$promotion_file")" || return $?
  candidate="$(mktemp)" || return $?
  WALLET_METADATA_BACKUP="$(mktemp)" || {
    rm -f "$candidate"
    return 1
  }

  if ! curl -fsSL --max-time 30 "${staged_url}?release=$RELEASE_ID" -o "$candidate"; then
    rm -f "$candidate"
    return 1
  fi
  if [ "$(jq -r '.walletCommit // empty' "$candidate")" != "$expected_commit" ]; then
    echo "[local-cf-release] staged wallet metadata commit mismatch" >&2
    rm -f "$candidate"
    return 1
  fi
  if curl -fsSL --max-time 30 "${target_url}?backup=$RELEASE_ID" -o "$WALLET_METADATA_BACKUP"; then
    WALLET_METADATA_HAD_BACKUP=1
  fi

  echo "[local-cf-release] promoting wallet metadata: $WALLET_METADATA_TARGET_KEY"
  if ! run_wrangler r2 object put "$WALLET_METADATA_BUCKET/$WALLET_METADATA_TARGET_KEY" \
    --file "$candidate" \
    --content-type application/json \
    --cache-control "public, max-age=60" \
    --remote; then
    rm -f "$candidate"
    return 1
  fi
  rm -f "$candidate"
  WALLET_METADATA_PROMOTED=1

  probe="$(mktemp)"
  for attempt in $(seq 1 12); do
    if curl -fsSL --max-time 30 "${target_url}?release=$RELEASE_ID-$attempt" -o "$probe" \
       && [ "$(jq -r '.walletCommit // empty' "$probe" 2>/dev/null)" = "$expected_commit" ]; then
      rm -f "$probe"
      return 0
    fi
    sleep 5
  done
  rm -f "$probe"
  echo "[local-cf-release] promoted wallet metadata did not become visible" >&2
  return 1
}

rollback_wallet_metadata() {
  [ "$WALLET_METADATA_PROMOTED" = "1" ] || return 0
  echo "[local-cf-release] rolling back wallet metadata" >&2
  if [ "$WALLET_METADATA_HAD_BACKUP" = "1" ]; then
    run_wrangler r2 object put "$WALLET_METADATA_BUCKET/$WALLET_METADATA_TARGET_KEY" \
      --file "$WALLET_METADATA_BACKUP" \
      --content-type application/json \
      --cache-control "public, max-age=60" \
      --remote || return $?
  else
    run_wrangler r2 object delete "$WALLET_METADATA_BUCKET/$WALLET_METADATA_TARGET_KEY" --remote || return $?
  fi
  WALLET_METADATA_PROMOTED=0
}

cleanup_wallet_metadata() {
  [ -z "$WALLET_METADATA_BACKUP" ] || rm -f "$WALLET_METADATA_BACKUP"
}

finish_publish() {
  local exit_code=$?
  trap - EXIT
  if [ "$exit_code" -ne 0 ] && [ "$PUBLISH_COMMITTED" != "1" ]; then
    if [ "$RELEASE_ACTIVATED" = "1" ]; then
      if [ -n "$PREVIOUS_RELEASE_ID" ] \
         && [ -d "$LOCAL_CF_FRONTEND_RELEASES_DIR/$PREVIOUS_RELEASE_ID" ]; then
        echo "[local-cf-release] publish failed; rolling back to release: $PREVIOUS_RELEASE_ID" >&2
        activate_release "$PREVIOUS_RELEASE_ID" || true
        write_current_release_id "$PREVIOUS_RELEASE_ID" || true
      else
        echo "[local-cf-release] publish failed; removing the failed release pointer" >&2
        rm -f \
          "$CURRENT_LINK" \
          "$CURRENT_LINK_NEXT" \
          "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.current" \
          "$LOCAL_CF_NGINX_HTML_ROOT/.frontend-release.current.next"
      fi
    fi
    rollback_wallet_metadata || true
  fi
  cleanup_wallet_metadata
  exit "$exit_code"
}

trap finish_publish EXIT

current_release_id() {
  local target=""

  if [ -L "$CURRENT_LINK" ]; then
    target="$(readlink "$CURRENT_LINK")"
    basename "$target"
    return 0
  fi
  if [ -s "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.current" ]; then
    cat "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.current"
    return 0
  fi
  if [ -L "$LOCAL_CF_NGINX_HTML_ROOT/app" ]; then
    target="$(readlink "$LOCAL_CF_NGINX_HTML_ROOT/app")"
    basename "$(dirname "$target")"
  fi
}

activate_release() {
  local release_id="$1"
  ln -sfn "$release_id" "$CURRENT_LINK_NEXT"
  mv -Tf "$CURRENT_LINK_NEXT" "$CURRENT_LINK"
}

write_current_release_id() {
  local release_id="$1"
  local next="$LOCAL_CF_NGINX_HTML_ROOT/.frontend-release.current.next"

  printf '%s\n' "$release_id" > "$next"
  mv -Tf "$next" "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.current"
}

install_stable_path() {
  local name="$1"
  local target=".releases/frontends/current/$1"
  local next="$LOCAL_CF_NGINX_HTML_ROOT/.$name.next"
  local current="$LOCAL_CF_NGINX_HTML_ROOT/$name"

  ln -sfn "$target" "$next"
  if [ -L "$current" ]; then
    mv -Tf "$next" "$current"
  else
    rm -rf "$current"
    mv -T "$next" "$current"
  fi
}

mkdir -p "$LOCAL_CF_NGINX_HTML_ROOT"
PREVIOUS_RELEASE_ID="$(current_release_id || true)"
if [ -n "$PREVIOUS_RELEASE_ID" ] && [ -d "$LOCAL_CF_FRONTEND_RELEASES_DIR/$PREVIOUS_RELEASE_ID" ]; then
  activate_release "$PREVIOUS_RELEASE_ID"
fi

mkdir -p "$RELEASE_DIR/downloads"
install_stable_path app
install_stable_path explorer
install_stable_path ide
install_stable_path downloads

manifest_next="$LOCAL_CF_NGINX_HTML_ROOT/.frontend-release.json.next"
ln -sfn ".releases/frontends/current/frontend-release.json" "$manifest_next"
if [ -e "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.json" ] \
   || [ -L "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.json" ]; then
  rm -f "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.json"
fi
mv -T "$manifest_next" "$LOCAL_CF_NGINX_HTML_ROOT/frontend-release.json"

if ! promote_wallet_metadata; then
  rollback_wallet_metadata || true
  exit 1
fi

activate_release "$RELEASE_ID"
RELEASE_ACTIVATED=1
write_current_release_id "$RELEASE_ID"

smoke_url() {
  local label="$1"
  local url="$2"
  echo "[local-cf-release] smoke $label $url"
  curl -fsS --max-time 12 "$url" >/dev/null
}

run_smoke_checks() {
  [ "$LOCAL_CF_FRONTEND_SMOKE" = "1" ] || return 0

  smoke_url "local app" "http://127.0.0.1:${LOCAL_STAGING_APP_PORT}/" || return $?
  smoke_url "local app wallet install" "http://127.0.0.1:${LOCAL_STAGING_APP_PORT}/wallet/install" || return $?
  smoke_url "local explorer" "http://127.0.0.1:${LOCAL_STAGING_EXPLORER_PORT}/" || return $?
  smoke_url "local ide" "http://127.0.0.1:${LOCAL_STAGING_IDE_PORT}/" || return $?

  if [ -n "$LOCAL_CF_WALLET_RELEASE_URL" ]; then
    smoke_url "wallet release metadata" "$LOCAL_CF_WALLET_RELEASE_URL" || return $?
  fi

  if [ "$LOCAL_CF_FRONTEND_SMOKE_PUBLIC" = "1" ]; then
    smoke_url "public app" "$(local_cf_url "$LOCAL_CF_APP_HOST")/" || return $?
    smoke_url "public explorer" "$(local_cf_url "$LOCAL_CF_EXPLORER_HOST")/" || return $?
    smoke_url "public ide" "$(local_cf_url "$LOCAL_CF_IDE_HOST")/" || return $?
  fi
}

if ! run_smoke_checks; then
  echo "[local-cf-release] smoke failed; keeping the previous release" >&2
  exit 1
fi

PUBLISH_COMMITTED=1

if [ "$LOCAL_CF_FRONTEND_RELEASE_KEEP" -gt 0 ] 2>/dev/null; then
  find "$LOCAL_CF_FRONTEND_RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
    | sort -rn \
    | awk -v keep="$LOCAL_CF_FRONTEND_RELEASE_KEEP" -v current="$RELEASE_DIR" 'NR > keep && $2 != current {print $2}' \
    | while IFS= read -r old_release; do
        [ -n "$old_release" ] || continue
        echo "[local-cf-release] pruning old release: $old_release"
        rm -rf "$old_release"
      done
fi

echo "[local-cf-release] published release: $RELEASE_ID"
