#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOURCE_ROOT="${GROTH16_SETUP_KEYSTORE_ROOT:-$PARTH_DIR/dist/groth16-keystore}"
TARGET_ROOT="${LOCAL_GROTH16_KEYSTORE_ROOT:-$HOME/.psy/keystore}"

copy_setup() {
  local source_dir="$1"
  local target_dir="$2"
  local label="$3"

  for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    [ -s "$source_dir/$file" ] || {
      echo "missing $label setup file: $source_dir/$file" >&2
      return 1
    }
  done

  mkdir -p "$target_dir"
  rsync -a --checksum --human-readable --progress \
    "$source_dir/circuit_groth16.bin" \
    "$source_dir/pk_groth16.bin" \
    "$source_dir/vk_groth16.bin" \
    "$target_dir/"
  chmod 0600 "$target_dir/"*_groth16.bin
  echo "installed $label Groth16 setup: $target_dir"
}

copy_setup "$SOURCE_ROOT/bridge" "$TARGET_ROOT" "bridge"
copy_setup "$SOURCE_ROOT/deposit_batch_append" "$TARGET_ROOT/deposit_append" "deposit_batch_append"

if [ -d "$SOURCE_ROOT/withdrawal_claim" ]; then
  copy_setup "$SOURCE_ROOT/withdrawal_claim" "$TARGET_ROOT/withdrawal_claim" "withdrawal_claim"
else
  echo "withdrawal_claim setup not found under $SOURCE_ROOT; skipping"
fi

echo "local Groth16 setup install complete"
