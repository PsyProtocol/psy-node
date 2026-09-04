#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INSTALL_SCRIPT="$ROOT/deploy/offsite-worker/arc99x4-install-staged.sh"
DEPLOY_SCRIPT="$ROOT/deploy/offsite-worker/deploy-arc99x4-release.sh"
APPLY_SCRIPT="$ROOT/deploy/offsite-worker/arc99x4-apply-staged.sh"
STOP_SCRIPT="$ROOT/deploy/gcp/fresh-staging/01_stop_parth_services.sh"

grep -F '"$RELEASE_DIR" \' "$INSTALL_SCRIPT" >/dev/null || {
  echo "offsite worker installer must set release root traversal permissions" >&2
  exit 1
}

grep -F 'sudo -u parth test -x "$RELEASE_DIR"' \
  "$INSTALL_SCRIPT" >/dev/null || {
  echo "offsite worker release must be traversable by the service user" >&2
  exit 1
}

grep -F 'arc99x4-apply-staged.sh' "$DEPLOY_SCRIPT" >/dev/null || {
  echo "offsite worker deploy must invoke the staged apply helper" >&2
  exit 1
}

grep -F 'sudo systemctl restart "${units[@]}"' "$APPLY_SCRIPT" >/dev/null || {
  echo "offsite worker apply helper must restart services onto the new release" >&2
  exit 1
}

if grep -F 'sudo systemctl enable --now' "$DEPLOY_SCRIPT" "$APPLY_SCRIPT" >/dev/null; then
  echo "enable --now can leave old offsite worker processes running" >&2
  exit 1
fi

grep -F 'stopping offsite workers' "$STOP_SCRIPT" >/dev/null || {
  echo "fresh deployment must stop old offsite workers before clearing shared state" >&2
  exit 1
}

echo "[ok] offsite workers are stopped before reset and restarted onto the new release"
