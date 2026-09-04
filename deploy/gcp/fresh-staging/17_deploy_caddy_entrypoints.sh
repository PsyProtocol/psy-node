#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

# Step 03 removes the relay container and its database during a full reset.
# Recreate the Nostr stack here; create-nostr.sh renders the authoritative
# Caddy entrypoints after the relay is running.
run_gcp_script create-nostr.sh
