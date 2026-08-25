#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

require_cloudflare_pages_env

log_step "deploying Cloudflare Pages project psy-explorer-stg"

bash "$REPO_ROOT/deploy/cloudflare-pages/deploy-psy-explorer.sh"
