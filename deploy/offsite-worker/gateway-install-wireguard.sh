#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo ARC_PUBLIC_KEY=... bash $0" >&2
  exit 1
fi

: "${ARC_PUBLIC_KEY:?set ARC_PUBLIC_KEY to the arc99x4 WireGuard public key}"

WG_PORT="${WG_PORT:-51820}"
WG_ADDRESS="${WG_ADDRESS:-10.250.0.1/24}"
ARC_WG_IP="${ARC_WG_IP:-10.250.0.11/32}"
PARTH_RPC_IP="${PARTH_RPC_IP:-10.148.0.25}"
MTU="${MTU:-1380}"
VPC_INTERFACE="${VPC_INTERFACE:-$(ip -4 route show default | awk 'NR == 1 { print $5 }')}"

if [ -z "$VPC_INTERFACE" ]; then
  echo "could not determine the default VPC interface; set VPC_INTERFACE" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends wireguard-tools iptables ca-certificates curl

install -d -o root -g root -m 0700 /etc/wireguard
if [ ! -s /etc/wireguard/gateway.key ]; then
  umask 077
  wg genkey > /etc/wireguard/gateway.key
fi
chmod 0600 /etc/wireguard/gateway.key

install -o root -g root -m 0644 /dev/stdin \
  /etc/sysctl.d/99-parth-wireguard-forward.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
sysctl --system >/dev/null

private_key="$(cat /etc/wireguard/gateway.key)"
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $WG_ADDRESS
ListenPort = $WG_PORT
PrivateKey = $private_key
MTU = $MTU
PostUp = iptables -A FORWARD -i %i -s $ARC_WG_IP -d $PARTH_RPC_IP/32 -p tcp -m multiport --dports 1337:1339 -j ACCEPT
PostUp = iptables -A FORWARD -o %i -d $ARC_WG_IP -s $PARTH_RPC_IP/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostUp = iptables -A FORWARD -i %i -j DROP
PostUp = iptables -t nat -A POSTROUTING -s $ARC_WG_IP -d $PARTH_RPC_IP/32 -o $VPC_INTERFACE -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s $ARC_WG_IP -d $PARTH_RPC_IP/32 -o $VPC_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j DROP
PostDown = iptables -D FORWARD -o %i -d $ARC_WG_IP -s $PARTH_RPC_IP/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -D FORWARD -i %i -s $ARC_WG_IP -d $PARTH_RPC_IP/32 -p tcp -m multiport --dports 1337:1339 -j ACCEPT

[Peer]
PublicKey = $ARC_PUBLIC_KEY
AllowedIPs = $ARC_WG_IP
EOF
chmod 0600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0.service
systemctl restart wg-quick@wg0.service

echo "Gateway WireGuard public key (safe to copy to arc99x4):"
wg pubkey < /etc/wireguard/gateway.key
echo
echo "Gateway interface: $VPC_INTERFACE"
echo "WireGuard UDP port: $WG_PORT"
echo "Next: update arc99x4 with this public key and the reserved public IP."
