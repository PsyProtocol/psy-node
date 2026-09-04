#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

log_step "deploying local prove proxy tunnel for public prove endpoint"
bash "$REPO_ROOT/deploy/local-prove-proxy/deploy_all.sh"
