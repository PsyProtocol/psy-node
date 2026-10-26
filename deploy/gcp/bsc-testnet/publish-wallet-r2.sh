#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${GCP_DEPLOY_CONFIG:-}" ] && [ -f "$SCRIPT_DIR/config.env" ]; then
  export GCP_DEPLOY_CONFIG="$SCRIPT_DIR/config.env"
fi
exec bash "$SCRIPT_DIR/../../bsc-testnet/gcp/publish-wallet-r2.sh" "$@"
