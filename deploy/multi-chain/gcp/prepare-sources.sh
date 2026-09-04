#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# psy-dapp deliberately uses `update = none` in the superproject for normal
# developer checkouts. Deployment profiles need the exact pinned frontend, so
# explicitly override that policy before the shared source preparer validates it.
git -C "$REPO_ROOT" -c submodule.psy-dapp.update=checkout \
  submodule update --init psy-dapp

exec bash "$SCRIPT_DIR/../../scripts/prepare-profile-sources.sh" \
  "$SCRIPT_DIR/source-versions.env"
