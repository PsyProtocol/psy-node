#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OFFSITE_PROVE_PROXY_HOST="${OFFSITE_PROVE_PROXY_HOST:-arc99x2}"
OFFSITE_PROVE_PROXY_APPLY_STAGED="${OFFSITE_PROVE_PROXY_APPLY_STAGED:-0}"
SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
PARTH_BUNDLE="${PARTH_BUNDLE:-$REPO_ROOT/dist/parth-node-bundle.tar.gz}"
GROTH16_SETUP_ROOT="${GROTH16_SETUP_ROOT:-$REPO_ROOT/dist/groth16-keystore}"
RELEASE_ID="${OFFSITE_PROVE_PROXY_RELEASE_ID:-$(date -u +%Y%m%d%H%M%S)-offsite-prove}"

[[ "$RELEASE_ID" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "invalid OFFSITE_PROVE_PROXY_RELEASE_ID: $RELEASE_ID" >&2
  exit 1
}
[ -f "$PARTH_BUNDLE" ] || {
  echo "missing Parth bundle: $PARTH_BUNDLE" >&2
  exit 1
}

for path in \
  ./target/release/psy_user_cli \
  ./deploy/bin/run-parth-service \
  ./client_prover/config.json \
  ./BUILD-MANIFEST.env; do
  tar -tzf "$PARTH_BUNDLE" "$path" >/dev/null || {
    echo "bundle is missing $path" >&2
    exit 1
  }
done
for kind in bridge deposit_batch_append withdrawal_claim; do
  for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    [ -s "$GROTH16_SETUP_ROOT/$kind/$file" ] || {
      echo "missing Groth16 setup: $GROTH16_SETUP_ROOT/$kind/$file" >&2
      exit 1
    }
  done
done

remote_home="$(
  ssh -F "$SSH_CONFIG_FILE" -o BatchMode=yes "$OFFSITE_PROVE_PROXY_HOST" \
    'printf %s "$HOME"'
)"
remote_root="$remote_home/parth-prove-proxy"
remote_incoming="$remote_root/incoming/$RELEASE_ID"
remote_release="$remote_root/staged-release-$RELEASE_ID"
remote_setup="$remote_root/staged-setup"
remote_scripts="$remote_root/deploy/offsite-prove-proxy"

ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_PROVE_PROXY_HOST" \
  "mkdir -p $(printf '%q' "$remote_incoming") $(printf '%q' "$remote_scripts")"

rsync -a --partial --info=progress2 \
  -e "ssh -F $SSH_CONFIG_FILE" \
  "$PARTH_BUNDLE" \
  "$OFFSITE_PROVE_PROXY_HOST:$remote_incoming/parth-node-bundle.tar.gz"
rsync -a --partial --info=progress2 \
  -e "ssh -F $SSH_CONFIG_FILE" \
  "$GROTH16_SETUP_ROOT/" \
  "$OFFSITE_PROVE_PROXY_HOST:$remote_setup/"
rsync -a \
  -e "ssh -F $SSH_CONFIG_FILE" \
  "$SCRIPT_DIR/" \
  "$OFFSITE_PROVE_PROXY_HOST:$remote_scripts/"

ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_PROVE_PROXY_HOST" "
set -euo pipefail
rm -rf $(printf '%q' "$remote_release")
mkdir -p $(printf '%q' "$remote_release")
tar -xzf $(printf '%q' "$remote_incoming/parth-node-bundle.tar.gz") \
  -C $(printf '%q' "$remote_release")
test -x $(printf '%q' "$remote_release/target/release/psy_user_cli")
test -x $(printf '%q' "$remote_release/deploy/bin/run-parth-service")
test -s $(printf '%q' "$remote_release/client_prover/config.json")
"

echo
echo "Staged release $RELEASE_ID on $OFFSITE_PROVE_PROXY_HOST."
echo "After the WireGuard peer is installed on the GCP gateway, run on arc99x2:"
echo
printf '  RELEASE_ID=%q bash %q\n' \
  "$RELEASE_ID" "$remote_scripts/arc99x2-apply-staged.sh"

case "$OFFSITE_PROVE_PROXY_APPLY_STAGED" in
  1|true|TRUE|yes|YES|on|ON)
    [ -t 0 ] || {
      cat >&2 <<EOF
OFFSITE_PROVE_PROXY_APPLY_STAGED requires an interactive terminal because
arc99x2 may prompt for sudo. Re-run this deployment from a terminal.
EOF
      exit 1
    }
    echo
    echo "Applying staged release $RELEASE_ID on $OFFSITE_PROVE_PROXY_HOST..."
    ssh -tt -F "$SSH_CONFIG_FILE" "$OFFSITE_PROVE_PROXY_HOST" \
      "RELEASE_ID=$(printf '%q' "$RELEASE_ID") bash $(printf '%q' "$remote_scripts/arc99x2-apply-staged.sh")"
    ;;
esac
