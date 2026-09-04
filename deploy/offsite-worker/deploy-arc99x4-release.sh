#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OFFSITE_WORKER_HOST="${OFFSITE_WORKER_HOST:-arc99x4}"
SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
PARTH_BUNDLE="${PARTH_BUNDLE:-$REPO_ROOT/dist/parth-node-bundle.tar.gz}"
RELEASE_ID="${OFFSITE_WORKER_RELEASE_ID:-$(date -u +%Y%m%d%H%M%S)-offsite}"
RESET_OFFSITE_WORKER_STATE="${RESET_OFFSITE_WORKER_STATE:-0}"

[[ "$RELEASE_ID" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "invalid OFFSITE_WORKER_RELEASE_ID: $RELEASE_ID" >&2
  exit 1
}
[ -f "$PARTH_BUNDLE" ] || {
  echo "missing Parth bundle: $PARTH_BUNDLE" >&2
  exit 1
}

for path in \
  ./target/release/psy_worker_cli \
  ./deploy/bin/run-parth-service \
  ./genesis.json \
  ./BUILD-MANIFEST.env
do
  tar -tzf "$PARTH_BUNDLE" "$path" >/dev/null || {
    echo "bundle is missing $path" >&2
    exit 1
  }
done

remote_home="$(ssh -F "$SSH_CONFIG_FILE" -o BatchMode=yes "$OFFSITE_WORKER_HOST" 'printf %s "$HOME"')"
remote_root="$remote_home/parth"
remote_incoming="$remote_root/incoming/$RELEASE_ID"
remote_release="$remote_root/staged-release-$RELEASE_ID"

ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_WORKER_HOST" \
  "mkdir -p $(printf '%q' "$remote_incoming") $(printf '%q' "$remote_root/deploy/offsite-worker")"
scp -F "$SSH_CONFIG_FILE" "$PARTH_BUNDLE" \
  "$OFFSITE_WORKER_HOST:$remote_incoming/parth-node-bundle.tar.gz"
scp -F "$SSH_CONFIG_FILE" \
  "$SCRIPT_DIR/arc99x4-install-staged.sh" \
  "$SCRIPT_DIR/arc99x4-apply-staged.sh" \
  "$SCRIPT_DIR/parth-offsite-worker@.service" \
  "$OFFSITE_WORKER_HOST:$remote_root/deploy/offsite-worker/"

ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_WORKER_HOST" "
set -euo pipefail
rm -rf $(printf '%q' "$remote_release")
mkdir -p $(printf '%q' "$remote_release")
tar -xzf $(printf '%q' "$remote_incoming/parth-node-bundle.tar.gz") -C $(printf '%q' "$remote_release")
test -x $(printf '%q' "$remote_release/target/release/psy_worker_cli")
test -x $(printf '%q' "$remote_release/deploy/bin/run-parth-service")
test -s $(printf '%q' "$remote_release/genesis.json")
"

remote_command="
set -euo pipefail
export RELEASE_ID=$(printf '%q' "$RELEASE_ID")
export STAGED_ROOT=$(printf '%q' "$remote_root")
export STAGED_RELEASE=$(printf '%q' "$remote_release")
export STAGED_ETC=$(printf '%q' "$remote_root/staged-etc")
export RESET_OFFSITE_WORKER_STATE=$(printf '%q' "$RESET_OFFSITE_WORKER_STATE")
bash $(printf '%q' "$remote_root/deploy/offsite-worker/arc99x4-apply-staged.sh")
"

ssh -tt -F "$SSH_CONFIG_FILE" "$OFFSITE_WORKER_HOST" "$remote_command"

echo "[offsite-worker] deployed release $RELEASE_ID to $OFFSITE_WORKER_HOST"
ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_WORKER_HOST" '
  printf "current="; readlink -f /opt/parth/current
  printf "worker_sha256="; sha256sum /opt/parth/current/target/release/psy_worker_cli | cut -d" " -f1
  printf "genesis_sha256="; sha256sum /opt/parth/current/genesis.json | cut -d" " -f1
'
