#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
source "$ROOT/deploy/cloudflare-pages/lib-direct-upload.sh"
mkdir -p "$TMP/package/dist/local-web-prover" "$TMP/app/node_modules/@psy-protocol" "$TMP/original"
printf '%s\n' '{"name":"@psy-protocol/psy-sdk"}' > "$TMP/package/package.json"
printf '%s\n' 'export function initWasmSync() {}' \
  'export const WasmConstants = { current_network: "testnet" };' > "$TMP/package/dist/local-web-prover/index.mjs"
printf '%s\n' '{"scripts":{"build":"node verify.cjs"}}' > "$TMP/app/package.json"
cat > "$TMP/app/verify.cjs" <<'NODE'
const fs = require('fs');
const sdk = JSON.parse(fs.readFileSync('node_modules/@psy-protocol/psy-sdk/package.json', 'utf8'));
if (sdk.name !== '@psy-protocol/psy-sdk') throw new Error('wrong SDK selected');
if (process.env.TEST_BUILD_FAIL === '1') process.exit(42);
NODE
ln -s "$TMP/original" "$TMP/app/node_modules/@psy-protocol/psy-sdk"
tar -czf "$TMP/sdk.tgz" -C "$TMP" package
export PSY_FRONTEND_SDK_ARCHIVE="$TMP/sdk.tgz"
export PSY_FRONTEND_SDK_SHA256
PSY_FRONTEND_SDK_SHA256="$(sha256sum "$TMP/sdk.tgz" | awk '{print $1}')"
export VITE_PSY_STAGE=testnet
run_frontend_build "$TMP/app"
for runner in pnpm bun; do
  command -v "$runner" >/dev/null
  run_frontend_build "$TMP/app" "$runner"
done
test "$(readlink "$TMP/app/node_modules/@psy-protocol/psy-sdk")" = "$TMP/original"
if TEST_BUILD_FAIL=1 bash -c 'source "$1/deploy/cloudflare-pages/lib-direct-upload.sh"; run_frontend_build "$2/app"' _ "$ROOT" "$TMP"; then exit 1; fi
test "$(readlink "$TMP/app/node_modules/@psy-protocol/psy-sdk")" = "$TMP/original"
if VITE_PSY_STAGE=mainnet bash -c 'source "$1/deploy/cloudflare-pages/lib-direct-upload.sh"; run_frontend_build "$2/app"' _ "$ROOT" "$TMP"; then exit 1; fi
if PSY_FRONTEND_SDK_SHA256=invalid bash -c 'source "$1/deploy/cloudflare-pages/lib-direct-upload.sh"; run_frontend_build "$2/app"' _ "$ROOT" "$TMP"; then exit 1; fi
test "$(readlink "$TMP/app/node_modules/@psy-protocol/psy-sdk")" = "$TMP/original"
echo 'frontend SDK artifact tests passed'
