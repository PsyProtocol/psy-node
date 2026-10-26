#!/usr/bin/env bash
set -euo pipefail

rpc() {
  local role="$1"
  local port="$2"
  local response

  response="$(curl -sS --fail --max-time 10 "http://10.148.0.25:$port" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}')"
  printf '%-12s %s\n' "$role" "$response"
}

echo "WireGuard service:"
systemctl is-enabled wg-quick@wg0.service
systemctl is-active wg-quick@wg0.service

echo
echo "Route:"
ip route get 10.148.0.25

echo
echo "WireGuard peer state:"
sudo wg show wg0

echo
echo "Private RPCs:"
rpc coordinator 1337
rpc realm0 1338
rpc realm1 1339

echo
echo "Worker units (expected inactive before shadow start):"
for role in coordinator realm-0 realm-1; do
  unit="parth-offsite-worker@$role.service"
  printf '%-46s enabled=%-8s active=%s\n' \
    "$unit" \
    "$(systemctl is-enabled "$unit" 2>/dev/null || true)" \
    "$(systemctl is-active "$unit" 2>/dev/null || true)"
done

echo
echo "Release:"
readlink -f /opt/parth/current
sha256sum /opt/parth/current/target/release/psy_worker_cli
sha256sum /opt/parth/current/genesis.json
