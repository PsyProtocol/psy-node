#!/usr/bin/env bash
# Build psy-bridge-reader from a clean psy-node checkout at sources.bridge_reader in the pinned Bookworm builder.
# Usage: build_bridge_reader.sh <psy-node source> <target> <out>
# Env: READER_BUILD_CARGO_HOME, READER_BUILD_COMMIT (sources.bridge_reader of the release lock).
# Fixed container paths and --locked --offline match build_services.sh; step 52 compares the result with the lock.
set -euo pipefail

image=sha256:02a4dd5c2ea776982084a4a856610836fc9f944203e85948fd4b475177f6b4af
[[ $# -eq 3 ]] || { echo "usage: $0 <psy-node source> <target> <out>" >&2; exit 2; }
source_dir=$(realpath -e "$1")
mkdir -p "$2"
target=$(realpath -e "$2")
out=$3
cargo_home=$(realpath -e "${READER_BUILD_CARGO_HOME:?READER_BUILD_CARGO_HOME is required}")
commit=${READER_BUILD_COMMIT:?READER_BUILD_COMMIT is required}
jobs=${READER_BUILD_JOBS:-12}

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$commit" ]] || {
  echo "source is not at READER_BUILD_COMMIT" >&2
  exit 1
}
[[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=no)" ]] || {
  echo "source has uncommitted changes" >&2
  exit 1
}
[[ "$(docker image inspect --format '{{.Id}}' "$image")" == "$image" ]] || {
  echo "builder image $image is not present" >&2
  exit 1
}

docker run --rm --network none --user "$(id -u):$(id -g)" \
  -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e RUSTUP_HOME=/usr/local/rustup -e RUSTUP_TOOLCHAIN=nightly-2025-09-20 \
  -e CARGO_HOME=/build/cargo -e CARGO_TARGET_DIR=/build/target \
  -e "RUSTFLAGS=--remap-path-prefix=/build/source=/src --remap-path-prefix=/build/cargo=/cargo" \
  -e CARGO_BUILD_JOBS="$jobs" -e CARGO_INCREMENTAL=0 -e HOME=/tmp \
  -v "$source_dir:/build/source:ro" -v "$cargo_home:/build/cargo" -v "$target:/build/target" \
  -w /build/source "$image" cargo build --release --locked --offline -p psy_bridge_reader_cli

mkdir -p "$out"
chmod 0700 "$out"
cp "$target/release/psy-bridge-reader" "$out/"
(cd "$out" && sha256sum psy-bridge-reader > SHA256SUMS && cat SHA256SUMS)
