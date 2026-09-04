#!/usr/bin/env bash
set -euo pipefail

WG_IFACE="${WG_IFACE:-wg0}"
WG_ADDRESS="${WG_ADDRESS:-10.250.0.12}"
WG_GATEWAY_IP="${WG_GATEWAY_IP:-10.250.0.1}"
MIN_MEMORY_KIB="${MIN_MEMORY_KIB:-58720256}"
MIN_CPU_COUNT="${MIN_CPU_COUNT:-16}"
MIN_DISK_FREE_KIB="${MIN_DISK_FREE_KIB:-31457280}"
MAX_HANDSHAKE_AGE_SECS="${MAX_HANDSHAKE_AGE_SECS:-180}"

fail() {
  echo "[preflight] FAIL: $*" >&2
  exit 1
}

rpc() {
  local role="$1"
  local port="$2"
  local response

  response="$(curl -sS --fail --max-time 10 "http://$WG_GATEWAY_IP:$port" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}')" ||
    fail "$role RPC is not reachable through the WireGuard gateway"
  jq -e '.result | numbers' >/dev/null <<<"$response" ||
    fail "$role RPC returned an invalid response: $response"
  printf '%-12s %s\n' "$role" "$response"
}

memory_kib="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
cpu_count="$(nproc)"
disk_free_kib="$(df -Pk / | awk 'NR == 2 { print $4 }')"

[ "$memory_kib" -ge "$MIN_MEMORY_KIB" ] ||
  fail "requires at least $((MIN_MEMORY_KIB / 1024 / 1024)) GiB RAM; found $((memory_kib / 1024 / 1024)) GiB"
[ "$cpu_count" -ge "$MIN_CPU_COUNT" ] ||
  fail "requires at least $MIN_CPU_COUNT logical CPUs; found $cpu_count"
[ "$disk_free_kib" -ge "$MIN_DISK_FREE_KIB" ] ||
  fail "requires at least $((MIN_DISK_FREE_KIB / 1024 / 1024)) GiB free on /; found $((disk_free_kib / 1024 / 1024)) GiB"

systemctl is-active --quiet "wg-quick@$WG_IFACE.service" ||
  fail "wg-quick@$WG_IFACE.service is not active"
ip -4 address show dev "$WG_IFACE" | grep -q "inet $WG_ADDRESS/" ||
  fail "$WG_IFACE does not have $WG_ADDRESS"

latest_handshake="$(sudo wg show "$WG_IFACE" latest-handshakes | awk '{ if ($2 > latest) latest = $2 } END { print latest + 0 }')"
now="$(date +%s)"
[ "$latest_handshake" -gt 0 ] || fail "WireGuard has never completed a handshake"
handshake_age=$((now - latest_handshake))
[ "$handshake_age" -le "$MAX_HANDSHAKE_AGE_SECS" ] ||
  fail "WireGuard handshake is stale: ${handshake_age}s"

echo "Host resources:"
printf '  memory: %s GiB\n' "$((memory_kib / 1024 / 1024))"
printf '  cpus:   %s\n' "$cpu_count"
printf '  disk:   %s GiB free\n' "$((disk_free_kib / 1024 / 1024))"
printf '  swap:   %s\n' "$(free -h | awk '/^Swap:/ { print $2 }')"

echo
echo "WireGuard:"
printf '  address:       %s\n' "$WG_ADDRESS"
printf '  handshake age: %ss\n' "$handshake_age"
ip route get "$WG_GATEWAY_IP"

echo
echo "Private RPC relays:"
rpc coordinator 11337
rpc realm0 11338
rpc realm1 11339

echo
echo "Psy services relay:"
curl -sS --fail --max-time 10 "http://$WG_GATEWAY_IP:11300/health" >/dev/null ||
  fail "psy-services health endpoint is not reachable through the WireGuard gateway"
echo "  healthy"

echo
echo "[preflight] PASS"
