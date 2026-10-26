#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../lib/build-parallelism.sh
source "$ROOT/deploy/scripts/lib/build-parallelism.sh"

assert_eq() {
  local expected="$1"
  local actual="$2"
  local message="$3"

  [ "$actual" = "$expected" ] || {
    echo "FAIL: $message: expected $expected, got $actual" >&2
    exit 1
  }
}

fake_bin="$(mktemp -d)"
trap 'rm -rf "$fake_bin"' EXIT
cat > "$fake_bin/nproc" <<'EOF'
#!/usr/bin/env bash
printf '32\n'
EOF
chmod +x "$fake_bin/nproc"

jobs="$(
  PATH="$fake_bin:$PATH" \
  RUST_BUILD_AVAILABLE_MEMORY_KIB=134217728 \
    detect_rust_build_jobs
)"
assert_eq 32 "$jobs" "128 GiB host should use all 32 logical CPUs"

jobs="$(
  PATH="$fake_bin:$PATH" \
  RUST_BUILD_AVAILABLE_MEMORY_KIB=25165824 \
    detect_rust_build_jobs
)"
assert_eq 8 "$jobs" "24 GiB available memory should cap parallel jobs"

assert_eq 12 "$(resolve_rust_build_jobs 12)" "explicit stage override"
assert_eq 20 "$(LOCAL_RUST_BUILD_JOBS=20 resolve_rust_build_jobs)" "global override"

if resolve_rust_build_jobs invalid >/dev/null 2>&1; then
  echo "FAIL: invalid override should be rejected" >&2
  exit 1
fi

echo "[ok] Rust build parallelism selection"
