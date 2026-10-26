#!/usr/bin/env bash
set -euo pipefail

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$GCP_DIR/lib/common.sh"

source_root="${GROTH16_SETUP_KEYSTORE_ROOT:-$REPO_ROOT/dist/groth16-keystore}"
out_root="${PUBLIC_TRUST_SETUP_SOURCE_ROOT:-$REPO_ROOT/dist/public-trust-setup-source}"

die() {
  echo "[trust-setup-stage] failed: $*" >&2
  exit 1
}

copy_kind() {
  local kind="$1"
  local target_subdir="$2"
  local source_dir="$source_root/$kind"
  local target_dir="$out_root/keystore/$target_subdir"
  local file

  [ -d "$source_dir" ] || die "missing Groth16 setup directory: $source_dir"
  mkdir -p "$target_dir"

  for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    [ -s "$source_dir/$file" ] || die "missing Groth16 setup file: $source_dir/$file"
    install -m 0644 "$source_dir/$file" "$target_dir/$file"
  done

  if [ -s "$source_dir/.setup-metadata.env" ]; then
    install -m 0644 "$source_dir/.setup-metadata.env" "$target_dir/.setup-metadata.env"
  fi
}

[ -n "$out_root" ] && [ "$out_root" != "/" ] || die "invalid output root: $out_root"

rm -rf "$out_root"
mkdir -p "$out_root/keystore"

copy_kind bridge "."
copy_kind deposit_batch_append "deposit_append"
copy_kind withdrawal_claim "withdrawal_claim"

printf '%s\n' "$out_root"
