#!/usr/bin/env bash
set -euo pipefail

FRESH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_common.sh
source "$FRESH_DIR/_common.sh"

project_name="${CF_PAGES_CONFIG_PROJECT:-${CF_PAGES_PROJECT:-psy-config-stg}}"
log_step "deploying Cloudflare Pages project $project_name"
CF_PAGES_PROJECT="$project_name" \
CF_PAGES_BRANCH="${CF_PAGES_BRANCH:-staging}" \
bash "$REPO_ROOT/deploy/cloudflare-pages/deploy-staging-config.sh"
