#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  prove)
    units=(parth-prove-proxy@user.service parth-prove-proxy@system.service
      parth-offsite-prove-proxy.service)
    ;;
  worker)
    units=(parth-offsite-worker@coordinator.service
      parth-offsite-worker@realm-0.service parth-offsite-worker@realm-1.service)
    ;;
  *) echo 'Usage: bash stop-offsite-for-fresh-deploy.sh prove|worker' >&2; exit 2 ;;
esac
units+=(parth-sentinel-collector.service psy-notifier-collector.service
  parth-performance-monitor@prove-proxy.service)

sudo -v
for unit in "${units[@]}"; do
  if [ "$(systemctl show "$unit" -p LoadState --value)" = not-found ]; then
    continue
  fi
  sudo systemctl disable --now "$unit"
  state="$(systemctl show "$unit" -p ActiveState --value)"
  pid="$(systemctl show "$unit" -p MainPID --value)"
  case "$state:$pid" in
    inactive:0|failed:0) printf '%s stopped (state=%s pid=%s)\n' "$unit" "$state" "$pid" ;;
    *) echo "$unit did not stop: state=$state pid=$pid" >&2; exit 1 ;;
  esac
done
echo 'Stopped. No data was deleted; WireGuard and SSH were left running.'
echo 'Do not restart the old services. Use the new release installer when instructed.'
