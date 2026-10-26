#!/usr/bin/env bash
set -euo pipefail

RELEASE_ID="${RELEASE_ID:?set RELEASE_ID to the staged release identifier}"
STAGED_ROOT="${STAGED_ROOT:-$HOME/parth}"
STAGED_RELEASE="${STAGED_RELEASE:-$STAGED_ROOT/staged-release-$RELEASE_ID}"
STAGED_ETC="${STAGED_ETC:-$STAGED_ROOT/staged-etc}"
RESET_OFFSITE_WORKER_STATE="${RESET_OFFSITE_WORKER_STATE:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "$RELEASE_ID" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "invalid RELEASE_ID: $RELEASE_ID" >&2
  exit 1
}

RELEASE_ID="$RELEASE_ID" \
STAGED_ROOT="$STAGED_ROOT" \
STAGED_RELEASE="$STAGED_RELEASE" \
STAGED_ETC="$STAGED_ETC" \
  bash "$SCRIPT_DIR/arc99x4-install-staged.sh"

if [ "$RESET_OFFSITE_WORKER_STATE" = "1" ]; then
  archive="/var/lib/parth/checkpoints/archive-$RELEASE_ID"
  sudo install -d -o parth -g parth -m 0750 "$archive"
  sudo find /var/lib/parth/checkpoints -maxdepth 1 -type f -name '*.backup' \
    -exec mv -t "$archive" {} +
fi

units=(
  parth-offsite-worker@coordinator.service
  parth-offsite-worker@realm-0.service
  parth-offsite-worker@realm-1.service
)

sudo systemctl enable "${units[@]}"
sudo systemctl restart "${units[@]}"

for unit in "${units[@]}"; do
  sudo systemctl is-active --quiet "$unit"
done

echo "Offsite workers are running from /opt/parth/releases/$RELEASE_ID"
sudo systemctl --no-pager --full status "${units[@]}"
