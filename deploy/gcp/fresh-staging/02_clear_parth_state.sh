#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

mapfile -t hosts < <(deployment_runtime_hosts | unique_hosts)

for host in "${hosts[@]}"; do
  log_step "clearing Parth release/env/runtime state on ${host}"
  remote_sudo "$host" '
set -e
systemctl list-units --all --plain --no-legend "parth-*.service" | awk "{ print \$1 }" | xargs -r systemctl stop || true
# Deliberately preserve /var/lib/parth/.psy/keystore and
# /var/lib/parth/keystore. These contain stable L1/L2 service identities,
# including the Sepolia-funded relayer signer.
rm -rf \
  /opt/parth/releases \
  /opt/parth/current \
  /tmp/parth-node-bundle.tar.gz \
  /var/lib/parth/checkpoints \
  /var/lib/parth/indexer-backups \
  /var/lib/parth/bridge-relayer \
  /var/lib/parth/bridge-relayer-repair \
  /var/lib/parth/prove-captures \
  /var/log/parth
rm -f /etc/parth/*.env /etc/parth/bridge-relayer.toml
install -d -m 0755 /var/lib/parth /var/log/parth /etc/parth
'
done
