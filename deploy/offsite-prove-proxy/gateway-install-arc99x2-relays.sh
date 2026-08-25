#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo ARC99X2_PUBLIC_KEY=... bash $0" >&2
  exit 1
fi

: "${ARC99X2_PUBLIC_KEY:?set ARC99X2_PUBLIC_KEY to the arc99x2 WireGuard public key}"

WG_IFACE="${WG_IFACE:-wg0}"
WG_CONFIG="${WG_CONFIG:-/etc/wireguard/wg0.conf}"
WG_GATEWAY_IP="${WG_GATEWAY_IP:-10.250.0.1}"
ARC_WG_IP="${ARC_WG_IP:-10.250.0.12}"
ARC_PROVE_PROXY_PORT="${ARC_PROVE_PROXY_PORT:-9999}"
PARTH_RPC_IP="${PARTH_RPC_IP:-10.148.0.25}"
GATEWAY_RELAY_PORT="${GATEWAY_RELAY_PORT:-19999}"
VPC_ADDRESS="${VPC_ADDRESS:-$(ip -4 route get 1.1.1.1 | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }')}"
PEER_KEY_FILE="/etc/parth/offsite-prove-proxy-peer.pub"
MARKER_BEGIN="# BEGIN PARTH ARC99X2 PROVE-PROXY"
MARKER_END="# END PARTH ARC99X2 PROVE-PROXY"

if [ ! -s "$WG_CONFIG" ]; then
  echo "missing WireGuard gateway config: $WG_CONFIG" >&2
  exit 1
fi
if ! systemctl is-active --quiet "wg-quick@$WG_IFACE.service"; then
  echo "WireGuard gateway is not active: $WG_IFACE" >&2
  exit 1
fi
if [ -z "$VPC_ADDRESS" ]; then
  echo "could not determine VPC address; set VPC_ADDRESS" >&2
  exit 1
fi

socket_proxyd=""
for candidate in \
  "$(command -v systemd-socket-proxyd 2>/dev/null || true)" \
  /lib/systemd/systemd-socket-proxyd \
  /usr/lib/systemd/systemd-socket-proxyd; do
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    socket_proxyd="$candidate"
    break
  fi
done
if [ -z "$socket_proxyd" ]; then
  echo "systemd-socket-proxyd is not installed" >&2
  exit 1
fi

conflicting_peer="$(
  wg show "$WG_IFACE" allowed-ips |
    awk -v address="$ARC_WG_IP/32" -v key="$ARC99X2_PUBLIC_KEY" \
      '$1 != key && index(" " $0 " ", " " address " ") { print $1; exit }'
)"
if [ -n "$conflicting_peer" ]; then
  echo "$ARC_WG_IP/32 is already assigned to peer $conflicting_peer" >&2
  exit 1
fi

install -d -o root -g root -m 0755 /etc/parth
old_public_key="$(cat "$PEER_KEY_FILE" 2>/dev/null || true)"

# Validate and apply the new peer before persisting it.
wg set "$WG_IFACE" peer "$ARC99X2_PUBLIC_KEY" allowed-ips "$ARC_WG_IP/32"
if [ -n "$old_public_key" ] && [ "$old_public_key" != "$ARC99X2_PUBLIC_KEY" ]; then
  wg set "$WG_IFACE" peer "$old_public_key" remove || true
fi

tmp_config="$(mktemp)"
trap 'rm -f "$tmp_config"' EXIT
awk -v begin="$MARKER_BEGIN" -v end="$MARKER_END" '
  $0 == begin { skipping = 1; next }
  $0 == end { skipping = 0; next }
  !skipping { print }
' "$WG_CONFIG" >"$tmp_config"
cat >>"$tmp_config" <<EOF

$MARKER_BEGIN
[Peer]
PublicKey = $ARC99X2_PUBLIC_KEY
AllowedIPs = $ARC_WG_IP/32
$MARKER_END
EOF
install -o root -g root -m 0600 "$tmp_config" "$WG_CONFIG"
printf '%s\n' "$ARC99X2_PUBLIC_KEY" >"$PEER_KEY_FILE"
chmod 0600 "$PEER_KEY_FILE"

install_socket_proxy() {
  local name="$1"
  local listen_address="$2"
  local target_address="$3"

  cat >"/etc/systemd/system/$name.socket" <<EOF
[Unit]
Description=Socket for $name

[Socket]
ListenStream=$listen_address
NoDelay=true

[Install]
WantedBy=sockets.target
EOF

  cat >"/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=TCP relay for $name
Requires=$name.socket
After=network-online.target wg-quick@$WG_IFACE.service

[Service]
ExecStart=$socket_proxyd $target_address
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
EOF
}

# arc99x2 uses these WireGuard-only listeners for backend RPC access.
install_socket_proxy parth-offsite-prove-rpc-coordinator \
  "$WG_GATEWAY_IP:11337" "$PARTH_RPC_IP:1337"
install_socket_proxy parth-offsite-prove-rpc-realm0 \
  "$WG_GATEWAY_IP:11338" "$PARTH_RPC_IP:1338"
install_socket_proxy parth-offsite-prove-rpc-realm1 \
  "$WG_GATEWAY_IP:11339" "$PARTH_RPC_IP:1339"
install_socket_proxy parth-offsite-prove-rpc-services \
  "$WG_GATEWAY_IP:11300" "$PARTH_RPC_IP:3000"

# Existing GCP callers reach this VPC listener; it forwards over WireGuard.
install_socket_proxy parth-offsite-prove-ingress \
  "$VPC_ADDRESS:$GATEWAY_RELAY_PORT" "$ARC_WG_IP:$ARC_PROVE_PROXY_PORT"

socket_units=(
  parth-offsite-prove-rpc-coordinator.socket
  parth-offsite-prove-rpc-realm0.socket
  parth-offsite-prove-rpc-realm1.socket
  parth-offsite-prove-rpc-services.socket
  parth-offsite-prove-ingress.socket
)
systemctl daemon-reload
systemctl enable "${socket_units[@]}"
systemctl restart "${socket_units[@]}"

echo "WireGuard peer installed:"
wg show "$WG_IFACE"
echo
echo "Gateway relay target for gcp-prove-proxy: $VPC_ADDRESS:$GATEWAY_RELAY_PORT"
echo
systemctl --no-pager --full status "${socket_units[@]}"
