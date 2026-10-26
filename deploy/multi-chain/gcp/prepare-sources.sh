#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Initialize only missing children. Existing checkouts must pass the shared
# dirty-tree guard before any profile checkout; do not update them here.
for child in psy-genesis psy-contracts psy-dapp; do
  if [ ! -e "$REPO_ROOT/$child/.git" ]; then
    git -C "$REPO_ROOT" -c submodule.psy-dapp.update=checkout \
      submodule update --init "$child"
  fi
done

bash "$SCRIPT_DIR/../../scripts/prepare-profile-sources.sh" \
  "${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

bash "$SCRIPT_DIR/prepare-psy-services-source.sh"
