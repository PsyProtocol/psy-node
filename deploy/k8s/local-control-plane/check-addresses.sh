#!/usr/bin/env bash
# Operator-run, read-only duplicate address probe on the local physical machine.
set -euo pipefail
[[ $(hostname -s) == arch3900x ]] || { echo 'Run on arch3900x only' >&2; exit 1; }
[[ $(cat /sys/class/net/enp5s0/address) == 14:d8:64:07:69:36 ]] || { echo 'Physical NIC identity changed' >&2; exit 1; }
command -v arping >/dev/null
interface=enp5s0
if [[ -d /sys/class/net/br0/bridge ]]; then interface=br0; fi
for address in 192.168.5.210 192.168.5.211 192.168.5.213 192.168.5.215 192.168.5.217; do
  if ! arping -D -I "$interface" -c 3 -w 4 "$address"; then
    echo "Probe failed or address in use: $address. Inspect before creating VMs. Raw socket access may require sudo." >&2
    exit 1
  fi
done
echo 'No ARP replies observed now. Router reservations are still required; offline devices cannot be detected.'
