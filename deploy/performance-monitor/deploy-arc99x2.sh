#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OFFSITE_PROVE_PROXY_HOST="${OFFSITE_PROVE_PROXY_HOST:-arc99x2}"
SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
TARGET_DIR="${TARGET_DIR:-}"
MANIFEST="$SCRIPT_DIR/Cargo.toml"
BINARY="$SCRIPT_DIR/target/release/parth-performance-monitor"

for command in cargo rsync ssh; do
  command -v "$command" >/dev/null || {
    echo "missing executable: $command" >&2
    exit 1
  }
done

cargo build --release --locked --manifest-path "$MANIFEST"
[ -x "$BINARY" ] || {
  echo "monitor binary was not generated: $BINARY" >&2
  exit 1
}

remote_home="$(
  ssh -F "$SSH_CONFIG_FILE" -o BatchMode=yes "$OFFSITE_PROVE_PROXY_HOST" \
    'printf %s "$HOME"'
)"
TARGET_DIR="${TARGET_DIR:-$remote_home/parth-performance-monitor-staged}"

ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_PROVE_PROXY_HOST" \
  "mkdir -p $(printf '%q' "$TARGET_DIR")"
rsync -a \
  -e "ssh -F $SSH_CONFIG_FILE" \
  "$BINARY" \
  "$SCRIPT_DIR/parth-performance-monitor@.service" \
  "$SCRIPT_DIR/prove-proxy.env" \
  "$SCRIPT_DIR/install-arc99x2.sh" \
  "$OFFSITE_PROVE_PROXY_HOST:$TARGET_DIR/"

echo "Staged performance monitor on $OFFSITE_PROVE_PROXY_HOST:$TARGET_DIR"
echo "Installing it requires sudo on arc99x2."
ssh -tt -F "$SSH_CONFIG_FILE" "$OFFSITE_PROVE_PROXY_HOST" \
  "STAGED_ROOT=$(printf '%q' "$TARGET_DIR") bash $(printf '%q' "$TARGET_DIR/install-arc99x2.sh")"
