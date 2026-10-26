#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

require_cloudflare_pages_env

project_name="${CF_PAGES_EXPLORER_PROJECT:-${CF_PAGES_PROJECT:-psy-explorer-stg}}"
log_step "deploying Cloudflare Pages project $project_name"

CF_PAGES_PROJECT="$project_name" \
CF_PAGES_BRANCH="${CF_PAGES_BRANCH:-staging}" \
bash "$REPO_ROOT/deploy/cloudflare-pages/deploy-psy-explorer.sh"
