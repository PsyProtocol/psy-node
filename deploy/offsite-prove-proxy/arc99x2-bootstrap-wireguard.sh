#!/usr/bin/env bash
set -euo pipefail

: "${GATEWAY_PUBLIC_KEY:?set GATEWAY_PUBLIC_KEY to the GCP WireGuard gateway public key}"
: "${GATEWAY_ENDPOINT:?set GATEWAY_ENDPOINT to the GCP gateway public-ip:port}"

STATE_DIR="${STATE_DIR:-$HOME/.config/parth/offsite-prove-proxy}"
PRIVATE_KEY_FILE="$STATE_DIR/wireguard.key"
CONFIG_FILE="${CONFIG_FILE:-$HOME/parth-wg0-gateway.conf}"
WG_ADDRESS="${WG_ADDRESS:-10.250.0.12/24}"
MTU="${MTU:-1380}"

if command -v pacman >/dev/null 2>&1; then
  sudo pacman -S --needed --noconfirm wireguard-tools jq curl rsync
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends wireguard-tools jq curl rsync
else
  echo "unsupported package manager" >&2
  exit 1
fi

install -d -m 0700 "$STATE_DIR"
if [ ! -s "$PRIVATE_KEY_FILE" ]; then
  umask 077
  wg genkey >"$PRIVATE_KEY_FILE"
fi
chmod 0600 "$PRIVATE_KEY_FILE"

private_key="$(cat "$PRIVATE_KEY_FILE")"
cat >"$CONFIG_FILE" <<EOF
[Interface]
Address = $WG_ADDRESS
PrivateKey = $private_key
MTU = $MTU

[Peer]
PublicKey = $GATEWAY_PUBLIC_KEY
Endpoint = $GATEWAY_ENDPOINT
AllowedIPs = 10.250.0.0/24
PersistentKeepalive = 15
EOF
chmod 0600 "$CONFIG_FILE"

echo "Prepared protected config: $CONFIG_FILE"
echo "arc99x2 WireGuard public key:"
wg pubkey <"$PRIVATE_KEY_FILE"
echo
echo "The interface is not activated yet. Install this public key on the gateway first."
