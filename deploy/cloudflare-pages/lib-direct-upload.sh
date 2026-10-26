#!/usr/bin/env bash
set -euo pipefail

CF_PAGES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$CF_PAGES_DIR/../.." && pwd)"

# shellcheck source=../gcp/lib/public-domains.sh
source "$ROOT/deploy/gcp/lib/public-domains.sh"

export npm_config_cache="${npm_config_cache:-/tmp/npm-cache}"
export VITE_PSY_STAGE="${VITE_PSY_STAGE:-testnet}"

# Reuse the accepted SDK artifact instead of rebuilding WASM during publishing.
run_frontend_build() (
  set -euo pipefail
  local dir="$1" runner="${2:-npm}" package_dir="" module="" saved=""
  # shellcheck disable=SC2329 # Invoked by the EXIT trap.
  cleanup_sdk_override() {
    if [ -n "$module" ]; then
      rm -f "$module"
      if [ -n "$saved" ]; then mv "$saved" "$module"; fi
    fi
    if [ -n "$package_dir" ]; then rm -rf "$package_dir"; fi
  }
  trap cleanup_sdk_override EXIT
  if [ -n "${PSY_FRONTEND_SDK_ARCHIVE:-}" ]; then
    : "${PSY_FRONTEND_SDK_SHA256:?pinned SDK SHA256 is required}"
    [ "$(sha256sum "$PSY_FRONTEND_SDK_ARCHIVE" | awk '{print $1}')" = "$PSY_FRONTEND_SDK_SHA256" ] || {
      echo "frontend SDK archive SHA256 mismatch" >&2; exit 1;
    }
    package_dir="$(mktemp -d)"
    tar -xzf "$PSY_FRONTEND_SDK_ARCHIVE" -C "$package_dir"
    SDK_PACKAGE_DIR="$package_dir/package" node --input-type=module <<'NODE'
import fs from 'node:fs';
const root = process.env.SDK_PACKAGE_DIR;
const pkg = JSON.parse(fs.readFileSync(`${root}/package.json`, 'utf8'));
if (pkg.name !== '@psy-protocol/psy-sdk') throw new Error('Unexpected SDK package');
const { initWasmSync, WasmConstants } = await import(`${root}/dist/local-web-prover/index.mjs`);
initWasmSync();
if (WasmConstants.current_network !== process.env.VITE_PSY_STAGE) {
  throw new Error('SDK WASM stage does not match frontend stage');
}
console.log(`[cloudflare-pages] verified SDK stage=${WasmConstants.current_network}`);
NODE
    local target="$dir/node_modules/@psy-protocol/psy-sdk"
    mkdir -p "$(dirname "$target")"
    if [ -e "$target" ] || [ -L "$target" ]; then
      saved="$package_dir/original-module"
      mv "$target" "$saved"
    fi
    module="$target"
    ln -s "$package_dir/package" "$module"
  fi
  cd "$dir"
  "$runner" run build
)

set_default_env() {
  local name="$1"
  local value="$2"

  if [ -z "${!name:-}" ]; then
    export "$name=$value"
  else
    export "${name?}"
  fi
}

require_cloudflare_env() {
  : "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
  : "${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"
}

build_frontend_dir() {
  local dir="$1"
  local label="$2"
  local workspace_dir

  echo "[cloudflare-pages] building ${label} in ${dir}"
  if [ "${CF_PAGES_SKIP_INSTALL:-0}" = "1" ]; then
    echo "[cloudflare-pages] skipping dependency install for ${label}; CF_PAGES_SKIP_INSTALL=1"
    if command -v npm >/dev/null 2>&1 && [ -f "$dir/package.json" ]; then
      run_frontend_build "$dir"
    elif command -v bun >/dev/null 2>&1 && [ -f "$dir/package.json" ]; then
      run_frontend_build "$dir" bun
    else
      echo "npm or bun is required to build ${label}" >&2
      exit 1
    fi
  elif [ -f "$dir/package-lock.json" ]; then
    command -v npm >/dev/null 2>&1 || {
      echo "npm is required to build ${label} from package-lock.json" >&2
      exit 1
    }
    (cd "$dir" && npm ci)
    run_frontend_build "$dir"
  elif [ -f "$dir/pnpm-lock.yaml" ]; then
    command -v pnpm >/dev/null 2>&1 || {
      echo "pnpm is required to build ${label} from pnpm-lock.yaml" >&2
      exit 1
    }
    (cd "$dir" && pnpm install --frozen-lockfile)
    run_frontend_build "$dir" pnpm
  elif workspace_dir="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" \
    && [ -f "$workspace_dir/pnpm-workspace.yaml" ] \
    && [ -f "$workspace_dir/pnpm-lock.yaml" ]; then
    command -v pnpm >/dev/null 2>&1 || {
      echo "pnpm is required to build ${label} from workspace $workspace_dir" >&2
      exit 1
    }
    (cd "$workspace_dir" && pnpm install --frozen-lockfile)
    run_frontend_build "$dir" pnpm
  elif [ -f "$dir/bun.lock" ]; then
    command -v bun >/dev/null 2>&1 || {
      echo "bun is required to build ${label} from bun.lock" >&2
      exit 1
    }
    (cd "$dir" && bun install --frozen-lockfile)
    run_frontend_build "$dir" bun
  elif command -v npm >/dev/null 2>&1; then
    (cd "$dir" && npm install)
    run_frontend_build "$dir"
  elif command -v bun >/dev/null 2>&1; then
    (cd "$dir" && bun install)
    run_frontend_build "$dir" bun
  else
    echo "bun or npm is required to build ${label}" >&2
    exit 1
  fi

  [ -f "$dir/dist/index.html" ] || {
    echo "missing build output: $dir/dist/index.html" >&2
    exit 1
  }
}

restore_tracked_node_modules() {
  local dir="$1"

  if git -C "$dir" ls-files --error-unmatch node_modules >/dev/null 2>&1; then
    if [ -d "$dir/node_modules" ] && [ ! -L "$dir/node_modules" ]; then
      local tmp
      tmp="/tmp/$(basename "$dir")-node_modules-$(date +%Y%m%d%H%M%S)"
      mv "$dir/node_modules" "$tmp"
      git -C "$dir" restore node_modules
      echo "[cloudflare-pages] moved tracked node_modules build dir to ${tmp}"
    fi
  fi
}

deploy_pages_dir() {
  local dist_dir="$1"
  local project="$2"
  local branch="${3:-staging}"

  if [ "${CF_PAGES_SKIP_DEPLOY:-0}" = "1" ]; then
    echo "[cloudflare-pages] skip deploy requested; artifact is ready at ${dist_dir}"
    return 0
  fi

  require_cloudflare_env

  echo "[cloudflare-pages] deploying ${dist_dir} -> ${project} branch=${branch}"
  npx --yes wrangler pages deploy "$dist_dir" \
    --project-name "$project" \
    --branch "$branch"
}
