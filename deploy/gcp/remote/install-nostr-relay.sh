#!/usr/bin/env bash
# Rebuilds only the relay container from a digest-pinned image; Caddy, its config and certificates stay as they are.
set -euo pipefail

require_pinned_image() {
  [[ "${!1:-}" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] || {
    echo "$1 must be set to an image pinned by digest (name@sha256:...)" >&2
    exit 1
  }
}
require_pinned_image NOSTR_RELAY_IMAGE
: "${NOSTR_RELAY_HOME:?NOSTR_RELAY_HOME is required}"
: "${NOSTR_RELAY_NETWORK:?NOSTR_RELAY_NETWORK is required}"
: "${NOSTR_RELAY_CONTAINER:=nostr-relay}"

[ -f "$NOSTR_RELAY_HOME/config.toml" ] || { echo "missing $NOSTR_RELAY_HOME/config.toml" >&2; exit 1; }
docker network inspect "$NOSTR_RELAY_NETWORK" >/dev/null

docker rm -f "$NOSTR_RELAY_CONTAINER" >/dev/null 2>&1 || true
install -d -m 0700 -o 1000 -g 1000 "$NOSTR_RELAY_HOME/data"
# Caddy proxies to the network alias nostr-relay, so the alias must stay.
docker run -d \
  --name "$NOSTR_RELAY_CONTAINER" \
  --network "$NOSTR_RELAY_NETWORK" \
  --network-alias nostr-relay \
  --user 1000:1000 \
  --restart unless-stopped \
  -v "$NOSTR_RELAY_HOME/data:/usr/src/app/db" \
  -v "$NOSTR_RELAY_HOME/config.toml:/usr/src/app/config.toml:ro" \
  "$NOSTR_RELAY_IMAGE"

docker ps --filter "name=$NOSTR_RELAY_CONTAINER"
