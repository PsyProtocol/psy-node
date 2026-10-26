#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-$HOME/parth-wg0-gateway.conf}"
TARGET="/etc/wireguard/wg0.conf"
BACKUP="/etc/wireguard/wg0.conf.before-offsite-prove-proxy"
EXPECTED_ADDRESS="${EXPECTED_ADDRESS:-10.250.0.12/24}"

if [ ! -s "$CONFIG" ]; then
  echo "missing protected WireGuard config: $CONFIG" >&2
  exit 1
fi

for placeholder in \
  REPLACE_WITH_ARC99X2_PRIVATE_KEY \
  REPLACE_WITH_GCP_GATEWAY_PUBLIC_KEY \
  REPLACE_WITH_GCP_GATEWAY_PUBLIC_IP; do
  if grep -q "$placeholder" "$CONFIG"; then
    echo "WireGuard config still contains placeholder: $placeholder" >&2
    exit 1
  fi
done

if ! grep -Eq "^[[:space:]]*Address[[:space:]]*=[[:space:]]*$EXPECTED_ADDRESS([[:space:]]*)$" "$CONFIG"; then
  echo "WireGuard config must assign Address = $EXPECTED_ADDRESS" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
install -m 0600 "$CONFIG" "$tmp_dir/wg0.conf"
sudo wg-quick strip "$tmp_dir/wg0.conf" >/dev/null

if sudo test -f "$TARGET"; then
  sudo cp -a "$TARGET" "$BACKUP"
fi
sudo install -d -o root -g root -m 0700 /etc/wireguard
sudo install -o root -g root -m 0600 "$CONFIG" "$TARGET"

if ! sudo systemctl enable --now wg-quick@wg0.service; then
  echo "new WireGuard config failed; restoring $BACKUP" >&2
  if sudo test -f "$BACKUP"; then
    sudo install -o root -g root -m 0600 "$BACKUP" "$TARGET"
    sudo systemctl restart wg-quick@wg0.service
  fi
  exit 1
fi

sudo systemctl restart wg-quick@wg0.service
sudo systemctl status wg-quick@wg0.service --no-pager --full -n 30
sudo wg show wg0
ip route get 10.250.0.1
