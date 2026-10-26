#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"
if [ -n "${DEPLOY_TOPOLOGY_FILE:-}" ]; then
  python3 "$REPO_ROOT/deploy/multi-chain/gcp/fresh-topology/steps.py" 17-caddy \
    --topology "$DEPLOY_TOPOLOGY_FILE" --config "$CONFIG_FILE" \
    --versions "$SOURCE_VERSIONS_FILE" --apply
  exit 0
fi

# Step 03 removes the relay container and its database during a full reset.
# Recreate the Nostr stack here; create-nostr.sh renders the authoritative
# Caddy entrypoints after the relay is running.
run_gcp_script create-nostr.sh
