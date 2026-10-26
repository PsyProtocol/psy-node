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
  # Migration 051 is a data repair. Old writers can undo it, and SQLx in an
  # older release rejects migration versions absent from its directory.
  sudo systemctl disable --now parth-psy-indexer@coordinator.service parth-psy-indexer@realm-0.service parth-psy-indexer@realm-1.service
  sudo systemctl stop parth-psy-services.service
  sudo install -d -m 0755 /etc/systemd/system/parth-psy-services.service.d
  printf "%s\n" "PSY_SERVICES_RUN_MIGRATIONS=false" | sudo tee /etc/parth/psy-services-rollback.env >/dev/null
  printf "%s\n" "[Service]" "EnvironmentFile=/etc/parth/psy-services-rollback.env" |
    sudo tee /etc/systemd/system/parth-psy-services.service.d/90-rollback-migrations.conf >/dev/null
  sudo systemctl daemon-reload
  sudo ln -s "$current" "$root/rollback-from.next.$$"
  sudo mv -Tf "$root/rollback-from.next.$$" "$root/previous"
  sudo ln -s "$previous" "$root/current.next.$$"
  sudo mv -Tf "$root/current.next.$$" "$root/current"
  sudo systemctl restart parth-psy-services.service
  sudo systemctl is-active --quiet parth-psy-services.service
  echo "rolled back psy-services binaries to $previous"
  echo "indexers intentionally remain stopped; old registration writers are unsafe after migration 051"
'

curl -fsS --max-time 15 "https://${PUBLIC_PSY_SERVICES_DOMAIN}/health" >/dev/null
echo "[psy-services-rollback] API health passed; indexing is paused until a forward fix"
