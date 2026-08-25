#!/usr/bin/env bash
set -euo pipefail

STAGED_ROOT="${STAGED_ROOT:-$HOME/parth}"
STAGED_RELEASE="${STAGED_RELEASE:-$STAGED_ROOT/staged-release}"
STAGED_ETC="${STAGED_ETC:-$STAGED_ROOT/staged-etc}"
RELEASE_ID="${RELEASE_ID:-20260712-e774b801-arc99x4}"
RELEASE_DIR="/opt/parth/releases/$RELEASE_ID"
OPS_READ_USER="${OPS_READ_USER:-psy}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SOURCE="$SCRIPT_DIR/parth-offsite-worker@.service"

required_files=(
  "$STAGED_RELEASE/target/release/psy_worker_cli"
  "$STAGED_RELEASE/deploy/bin/run-parth-service"
  "$STAGED_RELEASE/genesis.json"
  "$STAGED_ETC/offsite-worker-coordinator.env"
  "$STAGED_ETC/offsite-worker-realm-0.env"
  "$STAGED_ETC/offsite-worker-realm-1.env"
  "$UNIT_SOURCE"
)

for path in "${required_files[@]}"; do
  if [ ! -f "$path" ]; then
    echo "missing staged deployment file: $path" >&2
    exit 1
  fi
done

echo "Installing release without starting workers: $RELEASE_DIR"

id -u parth >/dev/null 2>&1 || \
  sudo useradd --system --home /var/lib/parth --shell /usr/bin/nologin parth

sudo install -d -o root -g root -m 0755 /opt/parth /opt/parth/releases
sudo install -d -o root -g root -m 0755 "$RELEASE_DIR"
sudo cp -a "$STAGED_RELEASE/." "$RELEASE_DIR/"
sudo chown -R root:root "$RELEASE_DIR"
sudo chmod 0755 \
  "$RELEASE_DIR" \
  "$RELEASE_DIR/target" \
  "$RELEASE_DIR/target/release" \
  "$RELEASE_DIR/deploy" \
  "$RELEASE_DIR/deploy/bin"
sudo chmod 0755 "$RELEASE_DIR/target/release/psy_worker_cli"
sudo chmod 0755 "$RELEASE_DIR/deploy/bin/run-parth-service"
sudo -u parth test -x "$RELEASE_DIR"
sudo -u parth test -x "$RELEASE_DIR/deploy/bin/run-parth-service"

sudo ln -sfn "$RELEASE_DIR" /opt/parth/current

sudo install -d -o root -g root -m 0755 /etc/parth
for role in coordinator realm-0 realm-1; do
  sudo install -o root -g root -m 0600 \
    "$STAGED_ETC/offsite-worker-$role.env" \
    "/etc/parth/offsite-worker-$role.env"
done

if id -u "$OPS_READ_USER" >/dev/null 2>&1; then
  sudo install -d -o parth -g "$OPS_READ_USER" -m 2750 /var/lib/parth/checkpoints
  sudo find /var/lib/parth/checkpoints -maxdepth 1 -type f \
    -exec chgrp "$OPS_READ_USER" {} \; \
    -exec chmod g+r {} \;
else
  sudo install -d -o parth -g parth -m 0750 /var/lib/parth/checkpoints
fi
sudo install -o root -g root -m 0644 \
  "$UNIT_SOURCE" /etc/systemd/system/parth-offsite-worker@.service

sudo systemctl daemon-reload

echo
echo "Installed but not started or enabled:"
echo "  parth-offsite-worker@coordinator.service"
echo "  parth-offsite-worker@realm-0.service"
echo "  parth-offsite-worker@realm-1.service"
echo
echo "Next: run arc99x4-preflight.sh after the GCP UDP firewall is open."
