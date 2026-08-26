#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CONFIG_EXAMPLE="$ROOT/deploy/gcp/config.example.env"
EXPECTED_WORKSPACE="$(cd "$ROOT/.." && pwd)"

actual_workspace="$(
  env -u WORKSPACE_HOME GCP_DEPLOY_CONFIG="$CONFIG_EXAMPLE" bash -c '
    source "$1"
    printf "%s\n" "$WORKSPACE_HOME"
  ' _ "$ROOT/deploy/gcp/lib/common.sh"
)"

[ "$actual_workspace" = "$EXPECTED_WORKSPACE" ] || {
  echo "WORKSPACE_HOME inference mismatch" >&2
  echo "expected: $EXPECTED_WORKSPACE" >&2
  echo "actual:   $actual_workspace" >&2
  exit 1
}

legacy_absolute="/home/peter/git/"bridge_zilong
legacy_home='$HOME/git/'bridge_zilong
if grep -R -n -F --binary-files=without-match --exclude-dir=target \
  -e "$legacy_absolute" -e "$legacy_home" "$ROOT/deploy"; then
  echo "deployment files must derive paths from WORKSPACE_HOME" >&2
  exit 1
fi

echo "[ok] deployment paths derive from WORKSPACE_HOME"

exit 0
