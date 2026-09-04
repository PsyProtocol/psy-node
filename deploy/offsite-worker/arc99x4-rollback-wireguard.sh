#!/usr/bin/env bash
set -euo pipefail

BACKUP="${BACKUP:-/etc/wireguard/wg0.conf.before-gateway}"

if ! sudo test -s "$BACKUP"; then
  echo "missing WireGuard rollback config: $BACKUP" >&2
  exit 1
fi

sudo install -o root -g root -m 0600 "$BACKUP" /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0.service
sudo systemctl status wg-quick@wg0.service --no-pager --full -n 30
sudo wg show wg0
ip route get 10.148.0.25
