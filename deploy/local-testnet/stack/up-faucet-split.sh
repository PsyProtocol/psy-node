#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export LOCAL_STAGING_FAUCET_SPLIT_ONLY=1
exec bash "$SCRIPT_DIR/up.sh" "$@"
