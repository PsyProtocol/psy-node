#!/usr/bin/env bash
set -euo pipefail

echo "deprecated: use arc99x4-switch-wireguard-gateway.sh" >&2
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CONFIG="${CONFIG:-$HOME/parth-wg0-nostr.conf}"
exec "$SCRIPT_DIR/arc99x4-switch-wireguard-gateway.sh"
