#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
export WORKSPACE_HOME
export GCP_DEPLOY_CONFIG="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
export DEPLOY_SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

# shellcheck disable=SC1090
source "$DEPLOY_SOURCE_VERSIONS_FILE"
archive="${PSY_SERVICES_RELEASE_ARCHIVE:-$REPO_ROOT/dist/psy-services/psy-services-${EXPECTED_PSY_SERVICES_COMMIT}.tar.gz}"

if [ "${DRY_RUN:-0}" = "1" ]; then
  cat <<EOF
[psy-services-update][dry-run] source: $EXPECTED_PSY_SERVICES_REPOSITORY ${EXPECTED_PSY_SERVICES_BRANCH:-unknown} $EXPECTED_PSY_SERVICES_COMMIT
[psy-services-update][dry-run] prepare external psy-services checkout
[psy-services-update][dry-run] build psy-services and psy-indexer only in Debian Bookworm
[psy-services-update][dry-run] install independent release on ${NODE_VM_NAME:-gcp-cp-ce}
[psy-services-update][dry-run] stop three indexers; restart psy-services; restart coordinator/realm indexers
[psy-services-update][dry-run] verify health, release manifest, process executable paths, and Explorer bridge activity API
[psy-services-update][dry-run] untouched: /opt/parth/current, genesis, nodes, workers, prove-proxy, faucet, relayer, Caddy, and frontends
EOF
  exit 0
fi

[ "${CONFIRM_PSY_SERVICES_UPDATE:-0}" = "1" ] || {
  echo "set CONFIRM_PSY_SERVICES_UPDATE=1 to update the online psy-services release" >&2
  exit 1
}

bash "$SCRIPT_DIR/prepare-psy-services-source.sh"

# shellcheck disable=SC1090
source "$GCP_DEPLOY_CONFIG"
PSY_SERVICES_DIR="${PSY_SERVICES_DIR:-$WORKSPACE_HOME/psy-services-merge-multi-chain}"
export PSY_SERVICES_DIR

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  PSY_SERVICES_RELEASE_ARCHIVE="$archive" \
    bash "$REPO_ROOT/deploy/gcp/build-psy-services-release.sh"
fi
[ -f "$archive" ] || { echo "missing release archive: $archive" >&2; exit 1; }

# shellcheck disable=SC1091
source "$REPO_ROOT/deploy/gcp/lib/common.sh"

host="${NODE_VM_NAME:-gcp-cp-ce}"
remote_archive="/tmp/psy-services-release.tar.gz"
archive_sha="$(sha256sum "$archive" | awk '{print $1}')"
deployment_started_at="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
export DEPLOY_PSY_SERVICES_HOME="/opt/parth/psy-services/current"
export SKIP_PARTH_BUNDLE_UPLOAD=1

ensure_parth_vm "$host"
# Resolve the rollback target from the running process instead of trusting an
# independent release symlink that may have been left by an older deployment.
# The single-quoted command is intentionally expanded by the remote shell.
# shellcheck disable=SC2016
active_services_home="$(run_remote_command "$host" '
  set -e
  for unit in parth-psy-services.service parth-psy-indexer@coordinator.service parth-psy-indexer@realm-0.service parth-psy-indexer@realm-1.service; do
    if [ "$unit" != parth-psy-services.service ] && sudo test -f /etc/parth/psy-services-rollback.env; then
      continue
    fi
    sudo systemctl is-active --quiet "$unit" || {
      echo "pre-deployment service is not active: $unit" >&2
      exit 1
    }
  done
  pid=$(sudo systemctl show -p MainPID --value parth-psy-services.service)
  test "$pid" -gt 0
  exe=$(sudo readlink -f "/proc/$pid/exe")
  active_home=$(dirname "$(dirname "$(dirname "$exe")")")
  case "$active_home" in /opt/parth/*) ;; *) echo "unexpected active psy-services home: $active_home" >&2; exit 1 ;; esac
  sudo test -x "$active_home/target/release/psy-services"
  sudo test -x "$active_home/target/release/psy-indexer"
  sudo test -d "$active_home/migrations"
  printf "%s\n" "$active_home"
')"
echo "[psy-services-update] active rollback target=$active_services_home"
curl -fsS --max-time 15 "https://${PUBLIC_PSY_SERVICES_DOMAIN}/health" >/dev/null

rsync_to_remote "$host" "$archive" "$remote_archive"
run_remote_script "$host" "$REPO_ROOT/deploy/gcp/remote/install-psy-services-release.sh" \
  "PSY_SERVICES_RELEASE_ARCHIVE=$remote_archive" \
  "PSY_SERVICES_ACTIVE_HOME=$active_services_home" \
  "PSY_SERVICES_LEGACY_HOME=${PSY_SERVICES_LEGACY_HOME:-/opt/parth/current/psy-services}" \
  "PSY_SERVICES_RELEASE_SHA256=$archive_sha" \
  "EXPECTED_PSY_SERVICES_REPOSITORY=$EXPECTED_PSY_SERVICES_REPOSITORY" \
  "EXPECTED_PSY_SERVICES_COMMIT=$EXPECTED_PSY_SERVICES_COMMIT" \
  "PSY_SERVICES_KEEP_RELEASES=${PSY_SERVICES_KEEP_RELEASES:-3}"

indexer_units=(
  parth-psy-indexer@coordinator.service
  parth-psy-indexer@realm-0.service
  parth-psy-indexer@realm-1.service
)
quoted_units="$(printf ' %q' "${indexer_units[@]}")"
run_remote_command "$host" "sudo systemctl stop$quoted_units"

# Remove only our rollback override; the new release must apply migrations.
run_remote_command "$host" '
  sudo rm -f /etc/systemd/system/parth-psy-services.service.d/90-rollback-migrations.conf /etc/parth/psy-services-rollback.env
  sudo systemctl daemon-reload
'

PSY_SERVICES_RUN_MIGRATIONS=true \
  bash "$REPO_ROOT/deploy/gcp/deploy-psy-services.sh"

DEPLOY_INSTANCE=coordinator PSY_INDEXER_MODE=coordinator \
  bash "$REPO_ROOT/deploy/gcp/deploy-psy-indexer.sh"
DEPLOY_INSTANCE=realm-0 PSY_INDEXER_MODE=realm REALM_ID=0 REALM_SUB_ID=1 \
  bash "$REPO_ROOT/deploy/gcp/deploy-psy-indexer.sh"
DEPLOY_INSTANCE=realm-1 PSY_INDEXER_MODE=realm REALM_ID=1 REALM_SUB_ID=1 \
  bash "$REPO_ROOT/deploy/gcp/deploy-psy-indexer.sh"

services_url="https://${PUBLIC_PSY_SERVICES_DOMAIN}"
curl -fsS --max-time 15 "$services_url/health" >/dev/null
activity_response="$(mktemp)"
trap 'rm -f "$activity_response"' EXIT
activity_status="$(curl -sS --max-time 30 -o "$activity_response" -w '%{http_code}' \
  "$services_url/api/v1/explorer/bridge/activity?limit=1")"
[ "$activity_status" = "200" ] || {
  echo "Explorer bridge activity smoke test returned HTTP $activity_status" >&2
  exit 1
}
jq -e '
  .success == true
  and ((.data.chains | map(.chain_index) | sort) == [0, 1, 2])
' "$activity_response" >/dev/null

run_remote_command "$host" "
  set -e
  current=\$(sudo readlink -f /opt/parth/psy-services/current)
  parth_current=\$(sudo readlink -f /opt/parth/current)
  test \"\$current\" != \"\$parth_current\"
  sudo grep -Fxq 'PSY_SERVICES_REPOSITORY=$EXPECTED_PSY_SERVICES_REPOSITORY' \"\$current/BUILD-MANIFEST.env\"
  sudo grep -Fxq 'PSY_SERVICES_COMMIT=$EXPECTED_PSY_SERVICES_COMMIT' \"\$current/BUILD-MANIFEST.env\"
  for unit in parth-psy-services.service parth-psy-indexer@coordinator.service parth-psy-indexer@realm-0.service parth-psy-indexer@realm-1.service; do
    sudo systemctl is-active --quiet \"\$unit\"
    pid=\$(sudo systemctl show -p MainPID --value \"\$unit\")
    exe=\$(sudo readlink -f \"/proc/\$pid/exe\")
    case \"\$exe\" in /opt/parth/psy-services/releases/*/target/release/*) ;; *) echo \"unexpected executable for \$unit: \$exe\" >&2; exit 1 ;; esac
    echo \"[psy-services-update] \$unit -> \$exe\"
  done
  errors=\$(sudo journalctl -q \
    -u parth-psy-services.service \
    -u parth-psy-indexer@coordinator.service \
    -u parth-psy-indexer@realm-0.service \
    -u parth-psy-indexer@realm-1.service \
    --since '$deployment_started_at' -p err --no-pager -o cat)
  if [ -n \"\$errors\" ]; then
    echo \"new psy-services/indexer errors after deployment:\" >&2
    printf '%s\n' \"\$errors\" >&2
    exit 1
  fi
"

echo "[psy-services-update] deployed $EXPECTED_PSY_SERVICES_REPOSITORY@$EXPECTED_PSY_SERVICES_COMMIT"
echo "[psy-services-update] health=$services_url/health"
echo "[psy-services-update] explorer_activity=$services_url/api/v1/explorer/bridge/activity?limit=1"
