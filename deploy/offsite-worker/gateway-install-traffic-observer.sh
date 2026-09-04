#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo bash $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -o root -g root -m 0755 \
  "$SCRIPT_DIR/gateway-traffic-snapshot.sh" \
  /usr/local/sbin/parth-wireguard-traffic-snapshot

install -o root -g root -m 0755 \
  "$SCRIPT_DIR/gateway-traffic-estimate.sh" \
  /usr/local/sbin/parth-wireguard-traffic-estimate

install -o root -g root -m 0644 \
  "$SCRIPT_DIR/parth-wireguard-traffic-snapshot.service" \
  /etc/systemd/system/parth-wireguard-traffic-snapshot.service

install -o root -g root -m 0644 \
  "$SCRIPT_DIR/parth-wireguard-traffic-snapshot.timer" \
  /etc/systemd/system/parth-wireguard-traffic-snapshot.timer

install -d -o root -g adm -m 0750 /var/log/parth
touch /var/log/parth/wireguard-traffic.jsonl
chown root:adm /var/log/parth/wireguard-traffic.jsonl
chmod 0640 /var/log/parth/wireguard-traffic.jsonl

systemctl daemon-reload
systemctl enable --now parth-wireguard-traffic-snapshot.timer
systemctl list-timers parth-wireguard-traffic-snapshot.timer --no-pager

echo
echo "Traffic samples will be appended to:"
echo "  /var/log/parth/wireguard-traffic.jsonl"
echo
echo "Manual sample:"
echo "  sudo /usr/local/sbin/parth-wireguard-traffic-snapshot"
echo
echo "Run-rate estimate:"
echo "  sudo /usr/local/sbin/parth-wireguard-traffic-estimate"
