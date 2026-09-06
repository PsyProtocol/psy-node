#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SUITE_DIR="$REPO_DIR/deploy/multi-chain/gcp/e2e/browser"
RUNTIME_FILE="${MULTICHAIN_RUNTIME_FILE:-$REPO_DIR/deploy/multi-chain/gcp/runtime/l1-deployments.json}"
APP_URL="${APP_URL:-https://app-stg.psy-protocol.xyz}"
EXPLORER_URL="${EXPLORER_URL:-https://explorer-stg.psy-protocol.xyz}"
EVIDENCE_DIR="${1:-$REPO_DIR/.private/e2e-runs/staging-browser.$(date -u +%Y%m%dT%H%M%SZ).$$}"

fail() {
  echo "[staging-browser-e2e] ERROR: $*" >&2
  exit 1
}

for command in git jq npm npx tee; do
  command -v "$command" >/dev/null || fail "missing executable: $command"
done
[ -f "$RUNTIME_FILE" ] || fail "missing multichain runtime: $RUNTIME_FILE"
[ -d "$SUITE_DIR" ] || fail "missing browser suite: $SUITE_DIR"

umask 077
mkdir -p "$EVIDENCE_DIR"
chmod 700 "$EVIDENCE_DIR"

jq --arg created_at "$(date --iso-8601=seconds)" \
  --arg repo_revision "$(git -C "$REPO_DIR" rev-parse HEAD)" \
  --arg app_url "$APP_URL" \
  --arg explorer_url "$EXPLORER_URL" '
    {
      version: 1,
      created_at: $created_at,
      repo_revision: $repo_revision,
      app_url: $app_url,
      explorer_url: $explorer_url,
      required_order: ["baseSepolia", "bscTestnet", "sepolia"],
      chains: [.chains[] | {
        name, network, chain_id, chain_index, public_rpc_domain,
        bridge: .contracts.Bridge
      }]
    }
  ' "$RUNTIME_FILE" >"$EVIDENCE_DIR/context.json"

run_suite() {
  cd "$SUITE_DIR"
  npm ci
  local chromium_path
  if chromium_path="$(command -v chromium 2>/dev/null)"; then
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium_path" \
      PLAYWRIGHT_JSON_OUTPUT_NAME="$EVIDENCE_DIR/playwright-report.json" \
      APP_URL="$APP_URL" \
      EXPLORER_URL="$EXPLORER_URL" \
      MULTICHAIN_RUNTIME_FILE="$RUNTIME_FILE" \
      npx playwright test --reporter=line,json --output="$EVIDENCE_DIR/test-results"
  else
    npx playwright install chromium
    PLAYWRIGHT_JSON_OUTPUT_NAME="$EVIDENCE_DIR/playwright-report.json" \
      APP_URL="$APP_URL" \
      EXPLORER_URL="$EXPLORER_URL" \
      MULTICHAIN_RUNTIME_FILE="$RUNTIME_FILE" \
      npx playwright test --reporter=line,json --output="$EVIDENCE_DIR/test-results"
  fi
}

started_at="$(date --iso-8601=seconds)"
set +e
run_suite 2>&1 | tee "$EVIDENCE_DIR/run.log"
result=${PIPESTATUS[0]}
set -e

jq -n \
  --arg status "$([ "$result" -eq 0 ] && printf PASS || printf FAIL)" \
  --arg started_at "$started_at" \
  --arg finished_at "$(date --iso-8601=seconds)" \
  --argjson exit_code "$result" \
  '{version:1,status:$status,started_at:$started_at,finished_at:$finished_at,exit_code:$exit_code}' \
  >"$EVIDENCE_DIR/result.json"
chmod 600 "$EVIDENCE_DIR"/*.json "$EVIDENCE_DIR/run.log"

if [ "$result" -ne 0 ]; then
  fail "browser E2E failed; evidence=$EVIDENCE_DIR"
fi
echo "[staging-browser-e2e] PASS evidence=$EVIDENCE_DIR"
