#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
export GCP_DEPLOY_CONFIG="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
export DEPLOY_SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

[ "${CONFIRM_PSY_SERVICES_ROLLBACK:-0}" = "1" ] || {
  echo "set CONFIRM_PSY_SERVICES_ROLLBACK=1 to activate the previous binaries" >&2
  echo "warning: this does not reverse PostgreSQL migrations" >&2
  exit 1
}

# shellcheck disable=SC1091
source "$REPO_ROOT/deploy/gcp/lib/common.sh"
host="${NODE_VM_NAME:-gcp-cp-ce}"

# The single-quoted command is intentionally expanded by the remote shell.
# shellcheck disable=SC2016
run_remote_command "$host" '
  set -e
  root=/opt/parth/psy-services
  [ -L "$root/previous" ] || { echo "no previous psy-services release" >&2; exit 1; }
  [ -L "$root/current" ] || { echo "no current psy-services release" >&2; exit 1; }
  previous=$(readlink -f "$root/previous")
  current=$(readlink -f "$root/current")
  [ -n "$previous" ] || { echo "no previous psy-services release" >&2; exit 1; }
  [ -n "$current" ] || { echo "no current psy-services release" >&2; exit 1; }
  [ "$previous" != "$current" ] || { echo "previous and current releases are identical" >&2; exit 1; }
  sudo ln -s "$current" "$root/rollback-from.next.$$"
  sudo mv -Tf "$root/rollback-from.next.$$" "$root/previous"
  sudo ln -s "$previous" "$root/current.next.$$"
  sudo mv -Tf "$root/current.next.$$" "$root/current"
  sudo systemctl restart parth-psy-services.service
  sudo systemctl restart parth-psy-indexer@coordinator.service
  sudo systemctl restart parth-psy-indexer@realm-0.service
  sudo systemctl restart parth-psy-indexer@realm-1.service
  for unit in parth-psy-services.service parth-psy-indexer@coordinator.service parth-psy-indexer@realm-0.service parth-psy-indexer@realm-1.service; do
    sudo systemctl is-active --quiet "$unit"
  done
  echo "rolled back psy-services binaries to $previous"
'

curl -fsS --max-time 15 "https://${PUBLIC_PSY_SERVICES_DOMAIN}/health" >/dev/null
echo "[psy-services-rollback] health check passed"
