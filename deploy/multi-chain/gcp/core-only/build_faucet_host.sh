#!/usr/bin/env bash
# Build psy_user_cli on the Faucet host itself with -C target-cpu=native (AVX-512 on
# the current host), inside the pinned bookworm builder image used by build_runtime.py.
# The binary is host-specific: run it only on the machine that built it.
#
# BUILD_ROOT must contain:
#   src/       the psy-node source at the pinned commit, with psy-genesis/ populated
#              exactly as build_runtime.py mounts it (Genesis bundle + config.json)
#   cargo/     the offline Cargo home (registry and git checkouts)
#   go/        the offline Go module cache (GOPATH)
#   go-build/  the Go build cache (GOCACHE)
# It produces target/ and out/psy_user_cli and prints the binary SHA256. The pinned
# BINARY_SHA256 in prepare_faucet.py was produced from a `git archive` source tree
# (no .git) and a fresh target/; reproduce it the same way.
#
# usage: BUILD_ROOT=<dir> BUILDER_IMAGE=sha256:<local image id> build_faucet_host.sh
set -euo pipefail
: "${BUILD_ROOT:?BUILD_ROOT is required}"
: "${BUILDER_IMAGE:?BUILDER_IMAGE (local image id of the bookworm builder) is required}"
build_jobs=${BUILD_JOBS:-12}
build_memory=${BUILD_MEMORY:-12g}
for dir in src cargo go go-build; do
  test -d "$BUILD_ROOT/$dir" || { echo "missing $BUILD_ROOT/$dir" >&2; exit 1; }
done
test -f "$BUILD_ROOT/src/psy-genesis/config.json" || { echo "missing src/psy-genesis/config.json" >&2; exit 1; }
mkdir -p "$BUILD_ROOT/target" "$BUILD_ROOT/out"
# Capped so a Faucet and other services on the same host keep their memory.
docker run --rm --pull never --network none --cpus "$build_jobs" --memory "$build_memory" --memory-swap "$build_memory" \
  --user "$(id -u):$(id -g)" \
  -e PATH=/usr/local/cargo/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e RUSTUP_HOME=/usr/local/rustup -e RUSTUP_TOOLCHAIN=nightly-2025-09-20 \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS="$build_jobs" -e CARGO_INCREMENTAL=0 \
  -e CARGO_NET_OFFLINE=true -e CARGO_TERM_COLOR=never -e HOME=/tmp \
  -e GOPATH=/go -e GOCACHE=/go-build -e GOPROXY=off -e GOSUMDB=off \
  -e PSY_NETWORK=testnet -e PSY_CONFIG_PATH=/psy-node/psy-genesis/config.json \
  -e RUSTFLAGS="-C target-cpu=native" \
  --mount type=bind,src="$BUILD_ROOT/src",dst=/psy-node,readonly \
  --mount type=bind,src="$BUILD_ROOT/cargo",dst=/cargo \
  --mount type=bind,src="$BUILD_ROOT/target",dst=/target \
  --mount type=bind,src="$BUILD_ROOT/go",dst=/go \
  --mount type=bind,src="$BUILD_ROOT/go-build",dst=/go-build \
  -w /psy-node "$BUILDER_IMAGE" \
  sh -c 'rustc --version && cargo build --offline --locked --release --bin psy_user_cli'
cp "$BUILD_ROOT/target/release/psy_user_cli" "$BUILD_ROOT/out/psy_user_cli"
sha256sum "$BUILD_ROOT/out/psy_user_cli"
