#!/usr/bin/env bash
# Build or test a Services source tree in the pinned Bookworm builder.
# Usage: build_services.sh build <src> <target> <out> | test <src> <target>
# Env: SERVICES_BUILD_CARGO_HOME, PSY_CONFIG_PATH, SERVICES_BUILD_CONFIG_SHA256.
# Fixed container paths and --locked --offline keep the binaries reproducible.
set -euo pipefail

image=sha256:02a4dd5c2ea776982084a4a856610836fc9f944203e85948fd4b475177f6b4af
mode=${1:-}
case "$mode" in
  build) [[ $# -eq 4 ]] || { echo "usage: $0 build <src> <target> <out>" >&2; exit 2; } ;;
  test) [[ $# -eq 3 ]] || { echo "usage: $0 test <src> <target>" >&2; exit 2; } ;;
  *) echo "usage: $0 build <src> <target> <out> | test <src> <target>" >&2; exit 2 ;;
esac
source_dir=$(realpath -e "$2")
mkdir -p "$3"
target=$(realpath -e "$3")
cargo_home=$(realpath -e "${SERVICES_BUILD_CARGO_HOME:?SERVICES_BUILD_CARGO_HOME is required}")
config_path=$(realpath -e "${PSY_CONFIG_PATH:?PSY_CONFIG_PATH is required}")
expected_config=${SERVICES_BUILD_CONFIG_SHA256:?SERVICES_BUILD_CONFIG_SHA256 is required}
jobs=${SERVICES_BUILD_JOBS:-12}

[[ "$(docker image inspect --format '{{.Id}}' "$image")" == "$image" ]] || {
  echo "builder image $image is not present" >&2
  exit 1
}
[[ "$(sha256sum "$config_path" | cut -d ' ' -f1)" == "$expected_config" ]] || {
  echo "runtime config digest does not match SERVICES_BUILD_CONFIG_SHA256" >&2
  exit 1
}

if [[ "$mode" == build ]]; then
  cargo_args=(build --release --locked --offline --bin psy-services --bin psy-indexer)
else
  cargo_args=(test --release --locked --offline -p psy_services --lib)
fi

docker run --rm --network "${SERVICES_TEST_NETWORK:-none}" --user "$(id -u):$(id -g)" \
  -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e RUSTUP_HOME=/usr/local/rustup -e RUSTUP_TOOLCHAIN=nightly-2025-09-20 \
  -e CARGO_HOME=/build/cargo -e CARGO_TARGET_DIR=/build/target \
  -e "RUSTFLAGS=--remap-path-prefix=/build/source=/src --remap-path-prefix=/build/cargo=/cargo" \
  -e CARGO_BUILD_JOBS="$jobs" -e CARGO_INCREMENTAL=0 -e RAYON_NUM_THREADS="$jobs" \
  -e HOME=/tmp -e PSY_NETWORK=testnet -e PSY_CONFIG_PATH=/build/config.json \
  -e PSY_REGENERATE_PROOF_FIXTURE \
  -e DATABASE_URL -e REDIS_URL -e NOSTR_TEST_REDIS_URL \
  -v "$config_path:/build/config.json:ro" -v "$source_dir:/build/source" \
  -v "$cargo_home:/build/cargo" -v "$target:/build/target" \
  -w /build/source "$image" cargo "${cargo_args[@]}"

if [[ "$mode" == build ]]; then
  out=$4
  mkdir -p "$out"
  chmod 0700 "$out"
  cp "$target/release/psy-services" "$target/release/psy-indexer" "$out/"
  (cd "$out" && sha256sum psy-services psy-indexer > SHA256SUMS && cat SHA256SUMS)
fi
