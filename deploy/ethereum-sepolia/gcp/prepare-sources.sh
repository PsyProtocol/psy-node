#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/../../scripts/prepare-profile-sources.sh" \
  "$SCRIPT_DIR/source-versions.env"
