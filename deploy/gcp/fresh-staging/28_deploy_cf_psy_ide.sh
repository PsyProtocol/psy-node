#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

# shellcheck source=../../cloudflare-pages/lib-direct-upload.sh
source "$REPO_ROOT/deploy/cloudflare-pages/lib-direct-upload.sh"

require_cloudflare_pages_env
export_public_frontend_env

FRONTEND_DIR="$PSY_DAPP_DIR/apps/ide"
PROJECT_NAME="${CF_PAGES_PROJECT:-psy-ide-stg}"
BRANCH="${CF_PAGES_BRANCH:-staging}"
PSY_SDK_DIR="${PSY_SDK_DIR:-$WORKSPACE_HOME/psy-sdk}"
PSY_SDK_PACKAGE_DIR="${PSY_SDK_PACKAGE_DIR:-$PSY_SDK_DIR/psy-ts-sdk/packages/psy-sdk}"
if [ -z "${BUILD_LOCAL_PSY_SDK+x}" ]; then
  BUILD_LOCAL_PSY_SDK=1
fi
trap 'restore_tracked_node_modules "$FRONTEND_DIR"' EXIT

[ -d "$FRONTEND_DIR" ] || {
  echo "missing Psy IDE frontend: $FRONTEND_DIR" >&2
  exit 1
}

log_step "deploying Cloudflare Pages project ${PROJECT_NAME}"
if [ "${BUILD_LOCAL_PSY_SDK:-0}" = "1" ]; then
  echo "[28_deploy_cf_psy_ide.sh] building local @psy-protocol/psy-sdk package in $PSY_SDK_PACKAGE_DIR"
  (
    cd "$PSY_SDK_PACKAGE_DIR"
    pnpm install --frozen-lockfile
    PSY_COMPILER_WASM_WORKSPACE="${PSY_COMPILER_WASM_WORKSPACE:-$PARTH_DIR/client_prover/psy_ide}" \
      pnpm run build
  )
  echo "[28_deploy_cf_psy_ide.sh] installing frontend dependencies from pnpm lockfile"
  (
    cd "$FRONTEND_DIR"
    pnpm install --frozen-lockfile
  )
  sdk_module_dir="$FRONTEND_DIR/node_modules/@psy-protocol/psy-sdk"
  rm -rf "$sdk_module_dir"
  mkdir -p "$(dirname "$sdk_module_dir")"
  ln -s "$PSY_SDK_PACKAGE_DIR" "$sdk_module_dir"
  echo "[28_deploy_cf_psy_ide.sh] local SDK override: $sdk_module_dir -> $PSY_SDK_PACKAGE_DIR"
  CF_PAGES_SKIP_INSTALL=1 build_frontend_dir "$FRONTEND_DIR" "psy_ide"
else
  build_frontend_dir "$FRONTEND_DIR" "psy_ide"
fi
deploy_pages_dir "$FRONTEND_DIR/dist" "$PROJECT_NAME" "$BRANCH"
