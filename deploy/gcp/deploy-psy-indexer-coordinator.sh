#!/usr/bin/env bash
set -euo pipefail

export PSY_INDEXER_MODE="${PSY_INDEXER_MODE:-coordinator}"
export DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-coordinator}"

exec "$(dirname "$0")/deploy-psy-indexer.sh"
