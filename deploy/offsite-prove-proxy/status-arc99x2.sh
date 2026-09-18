#!/usr/bin/env bash
set -euo pipefail

WG_IFACE="${WG_IFACE:-wg0}"
WG_ADDRESS="${WG_ADDRESS:-10.250.0.12}"
UNITS=(
  parth-prove-proxy@user.service
  parth-prove-proxy@system.service
)

echo "Service:"
systemctl is-enabled "${UNITS[@]}" 2>/dev/null || true
systemctl is-active "${UNITS[@]}" 2>/dev/null || true
systemctl status "${UNITS[@]}" --no-pager --full -n 30 || true

echo
echo "Resources:"
free -h
df -h /
systemctl show "${UNITS[@]}" \
  -p Id \
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
ss -ltn | grep -E "LISTEN.+${WG_ADDRESS}:(9999|9998)" || true

echo
echo "RPC health:"
check_role() {
  local port="$1" role="$2" response
  response="$(curl -sS --fail --max-time 30 "http://$WG_ADDRESS:$port" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_prove_proxy_role","params":[]}' || true)"
  printf '%s\n' "$response"
  jq -e --arg role "$role" \
    '.error == null and .result.role == $role and
     .result.user_methods == ($role == "user") and
     .result.system_methods == ($role == "system")' \
    >/dev/null 2>&1 <<<"$response" || {
    echo "$role prove-proxy RPC role check failed" >&2
    exit 1
  }
}
check_role 9999 user
check_role 9998 system

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
journalctl -u 'parth-prove-proxy@*' -n 120 --no-pager
