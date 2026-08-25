#!/usr/bin/env bash
set -euo pipefail

WG_IFACE="${WG_IFACE:-wg0}"
WG_ADDRESS="${WG_ADDRESS:-10.250.0.12}"
UNIT="${UNIT:-parth-offsite-prove-proxy.service}"

echo "Service:"
systemctl is-enabled "$UNIT" 2>/dev/null || true
systemctl is-active "$UNIT" 2>/dev/null || true
systemctl status "$UNIT" --no-pager --full -n 30 || true

echo
echo "Resources:"
free -h
df -h /
systemctl show "$UNIT" \
  -p MainPID \
  -p MemoryCurrent \
  -p MemoryPeak \
  -p CPUUsageNSec \
  -p NRestarts

echo
echo "WireGuard:"
ip -4 address show dev "$WG_IFACE"
sudo wg show "$WG_IFACE"

echo
echo "Listener:"
ss -ltn | grep -E "LISTEN.+${WG_ADDRESS}:9999" || true

echo
echo "RPC health:"
response="$(curl -sS --fail --max-time 30 "http://$WG_ADDRESS:9999" \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_fn_id","params":[0,"simple_claim"]}' || true)"
printf '%s\n' "$response"
if ! jq -e '.result == 4' >/dev/null 2>&1 <<<"$response"; then
  echo "prove-proxy RPC health check failed" >&2
  exit 1
fi

echo
echo "Release:"
readlink -f /opt/parth/current
sha256sum /opt/parth/current/target/release/psy_user_cli

echo
echo "Groth16 setup:"
for path in \
  /var/lib/parth/.psy/keystore \
  /var/lib/parth/.psy/keystore/deposit_append \
  /var/lib/parth/.psy/keystore/withdrawal_claim; do
  sha256sum \
    "$path/circuit_groth16.bin" \
    "$path/pk_groth16.bin" \
    "$path/vk_groth16.bin"
done

echo
echo "Recent log:"
journalctl -u "$UNIT" -n 80 --no-pager
