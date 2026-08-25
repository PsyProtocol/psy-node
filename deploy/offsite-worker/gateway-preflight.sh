#!/usr/bin/env bash
set -euo pipefail

MAX_HANDSHAKE_AGE="${MAX_HANDSHAKE_AGE:-180}"
PARTH_RPC_IP="${PARTH_RPC_IP:-10.148.0.25}"

if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
  echo "net.ipv4.ip_forward is not enabled" >&2
  exit 1
fi

systemctl is-enabled wg-quick@wg0.service
systemctl is-active wg-quick@wg0.service
ip route get "$PARTH_RPC_IP"

latest="$(wg show wg0 latest-handshakes | awk 'NR == 1 { print $2 }')"
now="$(date +%s)"
if [ -z "$latest" ] || [ "$latest" -eq 0 ] || [ $((now - latest)) -gt "$MAX_HANDSHAKE_AGE" ]; then
  echo "WireGuard handshake is missing or older than ${MAX_HANDSHAKE_AGE}s" >&2
  wg show wg0
  exit 1
fi

for port in 1337 1338 1339; do
  curl -sS --fail --max-time 10 "http://${PARTH_RPC_IP}:${port}" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}'
  echo
done

echo "Forward rules:"
iptables -S FORWARD | grep -E 'wg0|10\.250\.0\.11|10\.148\.0\.25'
iptables -t nat -S POSTROUTING | grep -E '10\.250\.0\.11|10\.148\.0\.25'
echo "Gateway preflight passed."
