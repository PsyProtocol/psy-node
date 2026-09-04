#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

require_cloudflare_pages_env
export_public_frontend_env
export VITE_PSY_RPC_MODE="${VITE_PSY_RPC_MODE:-remote}"
export VITE_L1_FORK="${VITE_L1_FORK:-false}"
export PSY_PRIVACY_BRIDGE_DEMO_DIR="${PSY_PRIVACY_BRIDGE_DEMO_DIR:-$PSY_DAPP_DIR/apps/bridge}"

project_name="${CF_PAGES_APP_PROJECT:-${CF_PAGES_PROJECT:-psy-privacy-bridge-demo-stg}}"
log_step "deploying Cloudflare Pages project $project_name"
CF_PAGES_PROJECT="$project_name" \
CF_PAGES_BRANCH="${CF_PAGES_BRANCH:-staging}" \
bash "$REPO_ROOT/deploy/cloudflare-pages/deploy-privacy-bridge-demo.sh"
