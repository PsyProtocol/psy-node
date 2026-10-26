#!/usr/bin/env bash
set -euo pipefail

export PSY_INDEXER_MODE="${PSY_INDEXER_MODE:-realm}"
export REALM_ID="${REALM_ID:-0}"
export REALM_SUB_ID="${REALM_SUB_ID:-1}"
export DEPLOY_INSTANCE="${DEPLOY_INSTANCE:-realm-${REALM_ID}}"

exec "$(dirname "$0")/deploy-psy-indexer.sh"
