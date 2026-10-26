#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PREPARE="$ROOT/deploy/gcp/fresh-staging/04_prepare_local_bundle.sh"
BOOKWORM_BUILD="$ROOT/deploy/scripts/build-linux-artifacts-bookworm.sh"

grep -Fq 'PSY_SERVICES_DIR="${PSY_SERVICES_DIR:-$WORKSPACE_HOME/psy-services}"' "$PREPARE" || {
  echo "fresh deployment must forward the selected psy-services checkout to the child build" >&2
  exit 1
}

grep -Fq 'rustup toolchain install \${RUST_TOOLCHAIN} --profile minimal --component rust-src' "$BOOKWORM_BUILD" || {
  echo "Bookworm builder must install rust-src for the workspace build-std configuration" >&2
  exit 1
}
grep -Fq '$PARTH_DIR/rust-toolchain.toml' "$BOOKWORM_BUILD"
grep -Fq 'RUSTUP_TOOLCHAIN="$RUST_TOOLCHAIN"' "$BOOKWORM_BUILD"

echo "[ok] fresh deployment forwards the selected psy-services checkout"
