#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
APPLY_SCRIPT="$ROOT/deploy/offsite-prove-proxy/arc99x2-apply-staged.sh"
INSTALL_SCRIPT="$ROOT/deploy/offsite-prove-proxy/arc99x2-install-staged.sh"

grep -F 'sudo systemctl restart parth-offsite-prove-proxy.service' \
  "$APPLY_SCRIPT" >/dev/null || {
  echo "offsite prove release apply must restart the active service" >&2
  exit 1
}

if grep -F 'systemctl enable --now parth-offsite-prove-proxy.service' \
  "$APPLY_SCRIPT" >/dev/null; then
  echo "enable --now can leave the old offsite prove process running" >&2
  exit 1
fi

grep -F 'sudo -u parth test -x "$RELEASE_DIR"' \
  "$INSTALL_SCRIPT" >/dev/null || {
  echo "offsite prove release must be traversable by the service user" >&2
  exit 1
}

echo "[ok] offsite prove release is accessible and explicitly restarted"

exit 0
