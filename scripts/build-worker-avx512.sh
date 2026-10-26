#!/usr/bin/env bash
# Build psy_worker_cli for hosts with AVX-512.
#
# The batched Poseidon hashing in the prover only pays off with wide vectors:
# on the benchmark CPU (Ryzen 9 9900X) a build for the default x86-64 target
# was no faster than the scalar code. This builds for x86-64-v4 with fat LTO
# and a single codegen unit. The binary stops with an illegal instruction on
# a CPU without AVX-512, so use it only on hosts that have it and keep the
# generic build for everything else. The build host needs AVX-512 as well:
# without a --target, the same flags apply to the build scripts it runs.
#
#   PSY_NETWORK=localhost scripts/build-worker-avx512.sh
#
# PSY_NETWORK selects constants that are compiled in. It must be the value the
# deployed nodes were built with. Before deploying a build, replay captured
# jobs with `psy_worker_cli replay --require-equivalent`.
#
# The output is target/worker-avx512/release/psy_worker_cli. A separate target
# directory keeps the generic build, and whatever is running from it, intact.
set -euo pipefail

cd "$(dirname "$0")/.."
: "${PSY_NETWORK:?PSY_NETWORK is required: the value the deployed nodes were built with}"

# x86-64-v4 is AVX-512 F, BW, CD, DQ and VL.
for flag in avx512f avx512bw avx512cd avx512dq avx512vl; do
  if ! grep -qw "$flag" /proc/cpuinfo; then
    echo "this host has no $flag: neither the build nor the binary would run here." >&2
    exit 1
  fi
done

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/worker-avx512}"
export CARGO_PROFILE_RELEASE_LTO=fat
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C target-cpu=x86-64-v4"

cargo build --release --locked -p psy_worker_cli
echo "built $CARGO_TARGET_DIR/release/psy_worker_cli"
