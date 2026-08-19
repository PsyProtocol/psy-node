#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TMP_ROOT="$(mktemp -d)"
FIXTURE="$TMP_ROOT/parth"
BIN_DIR="$TMP_ROOT/bin"
TRACE_FILE="$TMP_ROOT/trace"

cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

mkdir -p \
  "$FIXTURE/deploy/local-testnet/stack" \
  "$FIXTURE/deploy/local-testnet/cloudflare-tunnel" \
  "$TMP_ROOT/psy-services" \
  "$TMP_ROOT/psy-compiler" \
  "$TMP_ROOT/psy-wallet" \
  "$TMP_ROOT/psy-sdk" \
  "$BIN_DIR"

cp "$REPO_ROOT/deploy/local-testnet/deploy-all.sh" \
  "$FIXTURE/deploy/local-testnet/deploy-all.sh"

cat > "$FIXTURE/deploy/local-testnet/stack/lib.sh" <<'EOF'
local_staging_source_env_defaults() {
  return 0
}

local_staging_compose() {
  shift
  case "$1 $2 ${3:-}" in
    "config --services ")
      printf '%s\n' nginx nostr postgres
      ;;
    "ps --status running")
      printf '%s\n' nginx nostr postgres
      ;;
    *)
      return 1
      ;;
  esac
}
EOF

cat > "$FIXTURE/deploy/local-testnet/cloudflare-tunnel/up.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'up build=%s reset=%s\n' \
  "\${LOCAL_STAGING_BUILD:-}" "\${LOCAL_STAGING_RESET:-}" >> "$TRACE_FILE"
EOF

cat > "$FIXTURE/deploy/local-testnet/cloudflare-tunnel/install-frontend-autodeploy-user-service.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
echo autodeploy >> "$TRACE_FILE"
EOF

cat > "$FIXTURE/deploy/local-testnet/stack/status.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${TEST_FAIL_STATUS:-0}" = "1" ]; then
  echo "faucet-server failed"
  exit 0
fi
echo "local stack ok"
EOF

cat > "$FIXTURE/deploy/local-testnet/cloudflare-tunnel/status.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "public endpoints ok"
EOF

cat > "$BIN_DIR/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "info" ]
EOF

cat > "$BIN_DIR/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [ -f "$TMP_ROOT/checkpoint-advanced" ]; then
  checkpoint=101
else
  checkpoint=100
fi
printf '{"jsonrpc":"2.0","id":1,"result":%s}\n' "\$checkpoint"
EOF

cat > "$BIN_DIR/sleep" <<EOF
#!/usr/bin/env bash
set -euo pipefail
touch "$TMP_ROOT/checkpoint-advanced"
EOF

cat > "$BIN_DIR/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--user" ] && [ "${2:-}" = "is-active" ]; then
  exit 0
fi
exit 1
EOF

chmod +x \
  "$FIXTURE/deploy/local-testnet/deploy-all.sh" \
  "$FIXTURE/deploy/local-testnet/cloudflare-tunnel/up.sh" \
  "$FIXTURE/deploy/local-testnet/cloudflare-tunnel/install-frontend-autodeploy-user-service.sh" \
  "$FIXTURE/deploy/local-testnet/stack/status.sh" \
  "$FIXTURE/deploy/local-testnet/cloudflare-tunnel/status.sh" \
  "$BIN_DIR/curl" \
  "$BIN_DIR/docker" \
  "$BIN_DIR/sleep" \
  "$BIN_DIR/systemctl"

printf '/genesis.json\n/private_keys.json\n' > "$FIXTURE/.gitignore"
git -C "$FIXTURE" init -q -b deploy-unified
git -C "$FIXTURE" config user.email test@example.com
git -C "$FIXTURE" config user.name Test
git -C "$FIXTURE" add .
git -C "$FIXTURE" commit -qm fixture
parth_runtime_commit="$(git -C "$FIXTURE" rev-parse HEAD)"

for source_repo in \
  "$TMP_ROOT/psy-services" \
  "$TMP_ROOT/psy-compiler" \
  "$TMP_ROOT/psy-wallet" \
  "$TMP_ROOT/psy-sdk"; do
  git -C "$source_repo" init -q -b feat/improve-bridge-relayer
  git -C "$source_repo" config user.email test@example.com
  git -C "$source_repo" config user.name Test
  touch "$source_repo/.keep"
  git -C "$source_repo" add .keep
  git -C "$source_repo" commit -qm fixture
done

mkdir -p "$FIXTURE/deploy"
cat > "$FIXTURE/deploy/source-versions.env" <<EOF
export EXPECTED_PARTH_RUNTIME_COMMIT="$parth_runtime_commit"
export EXPECTED_PSY_SERVICES_COMMIT="$(git -C "$TMP_ROOT/psy-services" rev-parse HEAD)"
export EXPECTED_PSY_COMPILER_COMMIT="$(git -C "$TMP_ROOT/psy-compiler" rev-parse HEAD)"
export EXPECTED_PSY_WALLET_COMMIT="$(git -C "$TMP_ROOT/psy-wallet" rev-parse HEAD)"
export EXPECTED_PSY_SDK_COMMIT="$(git -C "$TMP_ROOT/psy-sdk" rev-parse HEAD)"
export EXPECTED_GENESIS_CONTRACTS_SHA256="0000000000000000000000000000000000000000000000000000000000000000"
export EXPECTED_GENESIS_SHA256="$(printf '{}\n' | sha256sum | awk '{print $1}')"
export EXPECTED_GENESIS_PRIVATE_KEYS_SHA256="$(printf '[]\n' | sha256sum | awk '{print $1}')"
EOF
printf '{}\n' > "$FIXTURE/genesis.json"
printf '[]\n' > "$FIXTURE/private_keys.json"
git -C "$FIXTURE" add deploy/source-versions.env
git -C "$FIXTURE" commit -qm versions

output="$(
  PATH="$BIN_DIR:$PATH" \
    bash "$FIXTURE/deploy/local-testnet/deploy-all.sh" --no-build
)"

grep -q '^up build=0 reset=0$' "$TRACE_FILE"
grep -q '^autodeploy$' "$TRACE_FILE"
grep -q 'all startup stages and health checks passed' <<< "$output"
grep -q 'checkpoints advanced and synchronized' <<< "$output"
grep -q 'this script is exiting' <<< "$output"

if failure_output="$(
  PATH="$BIN_DIR:$PATH" TEST_FAIL_STATUS=1 \
    bash "$FIXTURE/deploy/local-testnet/deploy-all.sh" --no-build 2>&1
)"; then
  echo "deploy-all accepted a failed component" >&2
  exit 1
fi
grep -q 'local stack status reported a failed component' <<< "$failure_output"

echo changed > "$TMP_ROOT/psy-wallet/.keep"
git -C "$TMP_ROOT/psy-wallet" add .keep
git -C "$TMP_ROOT/psy-wallet" commit -qm changed
if version_output="$(
  PATH="$BIN_DIR:$PATH" \
    bash "$FIXTURE/deploy/local-testnet/deploy-all.sh" --no-build 2>&1
)"; then
  echo "deploy-all accepted a mismatched wallet commit" >&2
  exit 1
fi
grep -q 'psy-wallet commit mismatch' <<< "$version_output"

git -C "$TMP_ROOT/psy-wallet" reset --hard -q HEAD^
printf '{"different":true}\n' > "$FIXTURE/genesis.json"
if genesis_output="$(
  PATH="$BIN_DIR:$PATH" \
    bash "$FIXTURE/deploy/local-testnet/deploy-all.sh" --no-build 2>&1
)"; then
  echo "deploy-all accepted a genesis that differs from GCP" >&2
  exit 1
fi
grep -q 'GCP genesis is missing or mismatched' <<< "$genesis_output"

echo "deploy-all orchestration test: PASS"
