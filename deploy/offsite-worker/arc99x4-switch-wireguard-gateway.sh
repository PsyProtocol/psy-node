#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-$HOME/parth-wg0-gateway.conf}"
TARGET="/etc/wireguard/wg0.conf"
BACKUP="/etc/wireguard/wg0.conf.before-gateway"

if [ ! -s "$CONFIG" ]; then
  echo "missing protected WireGuard config: $CONFIG" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
install -m 0600 "$CONFIG" "$tmp_dir/wg0.conf"
sudo wg-quick strip "$tmp_dir/wg0.conf" >/dev/null
if sudo test -f "$TARGET"; then
  sudo cp -a "$TARGET" "$BACKUP"
fi
sudo install -o root -g root -m 0600 "$CONFIG" "$TARGET"

if ! sudo systemctl restart wg-quick@wg0.service; then
  echo "new gateway config failed; restoring $BACKUP" >&2
  if sudo test -f "$BACKUP"; then
    sudo install -o root -g root -m 0600 "$BACKUP" "$TARGET"
    sudo systemctl restart wg-quick@wg0.service
  fi
  exit 1
fi

sudo systemctl status wg-quick@wg0.service --no-pager --full -n 30
sudo wg show wg0
ip route get 10.148.0.25
