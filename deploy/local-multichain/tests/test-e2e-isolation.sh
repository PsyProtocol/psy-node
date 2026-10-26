#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_MULTICHAIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT="$(cd "$LOCAL_MULTICHAIN_DIR/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
child_pid=""
cleanup() {
  if [ -n "$child_pid" ]; then
    kill "$child_pid" 2>/dev/null || true
    wait "$child_pid" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

default_root="$(
  unset PSY_NODE_DIR LOCAL_MULTICHAIN_ENV_FILE
  # shellcheck source=../lib.sh
  source "$LOCAL_MULTICHAIN_DIR/lib.sh"
  printf '%s\n' "$PSY_NODE_DIR"
)"
[ "$default_root" = "$ROOT" ] || {
  echo "default PSY_NODE_DIR changed: $default_root" >&2
  exit 1
}

override_root="$TMP_DIR/runtime"
mkdir -p "$override_root"
override_result="$(
  unset E2E_CONTAMINATION
  PSY_NODE_DIR="$override_root"
  LOCAL_MULTICHAIN_ENV_FILE=/dev/null
  export PSY_NODE_DIR LOCAL_MULTICHAIN_ENV_FILE
  # shellcheck source=../lib.sh
  source "$LOCAL_MULTICHAIN_DIR/lib.sh"
  printf '%s:%s\n' "$PSY_NODE_DIR" "${E2E_CONTAMINATION:-absent}"
)"
[ "$override_result" = "$override_root:absent" ] || {
  echo "root override or /dev/null env isolation failed: $override_result" >&2
  exit 1
}

expected_root="$TMP_DIR/expected-runtime"
wrong_root="$TMP_DIR/wrong-runtime"
mkdir -p "$expected_root/target/release" "$wrong_root/target/release"
cp "$(command -v sleep)" "$wrong_root/target/release/psy_relayer_cli"
"$wrong_root/target/release/psy_relayer_cli" 60 &
child_pid=$!

LOCAL_MULTICHAIN_ENV_FILE=/dev/null
export LOCAL_MULTICHAIN_ENV_FILE
# shellcheck source=../lib.sh
source "$LOCAL_MULTICHAIN_DIR/lib.sh"
if local_deploy_verify_owned_pid "$child_pid" "$expected_root" psy_relayer_cli \
  >"$TMP_DIR/pid.out" 2>"$TMP_DIR/pid.err"; then
  echo "wrong-root relayer PID was accepted" >&2
  exit 1
fi
grep -Fq "executable is outside" "$TMP_DIR/pid.err"

echo "[ok] local multichain E2E isolation options"
