#!/usr/bin/env bash
set -euo pipefail

WG_IFACE="${WG_IFACE:-wg0}"
ARC_WG_IP="${ARC_WG_IP:-10.250.0.11}"
PARTH_RPC_IP="${PARTH_RPC_IP:-10.148.0.25}"
LOG_FILE="${LOG_FILE:-}"

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

json_escape() {
  sed 's/\\/\\\\/g; s/"/\\"/g'
}

now_epoch="$(date +%s)"
now_iso="$(date -Is)"

wg_dump="$(run_root wg show "$WG_IFACE" dump)"
peer_line="$(printf '%s\n' "$wg_dump" | awk 'NR == 2 { print }')"

if [ -z "$peer_line" ]; then
  echo "missing WireGuard peer on $WG_IFACE" >&2
  exit 1
fi

peer_public_key="$(printf '%s\n' "$peer_line" | awk '{ print $1 }' | json_escape)"
endpoint="$(printf '%s\n' "$peer_line" | awk '{ print $3 }' | json_escape)"
allowed_ips="$(printf '%s\n' "$peer_line" | awk '{ print $4 }' | json_escape)"
latest_handshake="$(printf '%s\n' "$peer_line" | awk '{ print $5 }')"
wg_rx_bytes="$(printf '%s\n' "$peer_line" | awk '{ print $6 }')"
wg_tx_bytes="$(printf '%s\n' "$peer_line" | awk '{ print $7 }')"

forward_table="$(run_root iptables -L FORWARD -v -n -x)"
arc_to_rpc_bytes="$(
  printf '%s\n' "$forward_table" |
    awk -v src="$ARC_WG_IP" -v dst="$PARTH_RPC_IP" \
      '$0 ~ src && $0 ~ dst && $0 ~ /1337:1339/ { print $2; found=1; exit } END { if (!found) print 0 }'
)"
rpc_to_arc_bytes="$(
  printf '%s\n' "$forward_table" |
    awk -v src="$PARTH_RPC_IP" -v dst="$ARC_WG_IP" \
      '$0 ~ src && $0 ~ dst && $0 ~ /RELATED,ESTABLISHED/ { print $2; found=1; exit } END { if (!found) print 0 }'
)"

line="$(
  printf '{"ts":%s,"ts_iso":"%s","iface":"%s","peer_public_key":"%s","endpoint":"%s","allowed_ips":"%s","latest_handshake":%s,"wg_rx_bytes":%s,"wg_tx_bytes":%s,"forward_arc_to_rpc_bytes":%s,"forward_rpc_to_arc_bytes":%s}\n' \
    "$now_epoch" \
    "$now_iso" \
    "$WG_IFACE" \
    "$peer_public_key" \
    "$endpoint" \
    "$allowed_ips" \
    "$latest_handshake" \
    "$wg_rx_bytes" \
    "$wg_tx_bytes" \
    "$arc_to_rpc_bytes" \
    "$rpc_to_arc_bytes"
)"

if [ -n "$LOG_FILE" ]; then
  install -d -o root -g adm -m 0750 "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  chown root:adm "$LOG_FILE"
  chmod 0640 "$LOG_FILE"
  printf '%s\n' "$line" >>"$LOG_FILE"
else
  printf '%s\n' "$line"
fi
