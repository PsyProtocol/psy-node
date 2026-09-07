#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/repo"
profile="$repo/deploy/multi-chain/gcp"
fresh="$repo/deploy/gcp/fresh-staging"
mkdir -p "$profile" "$fresh" "$repo/deploy/gcp/lib"
cp "$ROOT/deploy/multi-chain/gcp/deploy_all.sh" "$profile/"
cp "$ROOT/deploy/multi-chain/gcp/steps.tsv" "$profile/"
cp "$ROOT/deploy/multi-chain/gcp/source-versions.env" "$profile/"
cat > "$profile/config.env" <<'SH'
DEPLOY_OFFSITE_WORKERS=1
OFFSITE_WORKER_HOST=arc99x4
OFFSITE_PROVE_PROXY_HOST=arc99x3
SH
cp "$profile/config.env" "$profile/config.example.env"

# All execution takes place in a fake repository. No SSH, Docker, builds or
# transactions are involved; the real orchestration logic remains unchanged.
export TEST_CALLS="$tmp/calls" TEST_RUNTIME="$tmp/runtime-ready" TEST_EXPECTED_UMASK
TEST_EXPECTED_UMASK="$(umask)"
cat > "$profile/prepare-sources.sh" <<'SH'
echo prepare >> "$TEST_CALLS"
SH
cat > "$profile/preflight.sh" <<'SH'
echo preflight >> "$TEST_CALLS"
exit "${TEST_PREFLIGHT_EXIT:-0}"
SH
cat > "$fresh/preflight.sh" <<'SH'
echo "selected=$DEPLOY_ALL_SELECTED_STEPS" >> "$TEST_CALLS"
SH
cat > "$repo/deploy/gcp/lib/multichain.sh" <<'SH'
multichain_require_runtime() {
  [ -f "$TEST_RUNTIME" ] || { echo 'missing runtime'; return 9; }
}
SH
while IFS=$'\t' read -r id script _description; do
  [[ "$id" =~ ^[0-9]{2}$ ]] || continue
  cat > "$fresh/$script" <<'SH'
step="$(basename "$0")"
step="${step%%_*}"
[ "$(umask)" = "$TEST_EXPECTED_UMASK" ] || exit 10
echo "$step" >> "$TEST_CALLS"
echo "step=$step"
if [ "$step" = "${TEST_FAIL_STEP:-}" ]; then exit 7; fi
SH
done < "$profile/steps.tsv"

export GCP_DEPLOY_CONFIG="$profile/config.env"
export DEPLOY_SOURCE_VERSIONS_FILE="$profile/source-versions.env"
runner="$profile/deploy_all.sh"
bash "$runner" --plan > "$tmp/plan"
[ ! -e "$TEST_CALLS" ]
[ ! -d "$profile/runtime" ]
grep -q 'prove host: arc99x3' "$tmp/plan"
[ "$(grep -cE '^[0-9]{2}  ' "$tmp/plan")" = 21 ]
DRY_RUN=1 bash "$runner" > "$tmp/dry-run"
cmp "$tmp/plan" "$tmp/dry-run"

bash "$runner" --plan --from 16 --until 18 > "$tmp/range"
[ "$(awk '/^[0-9][0-9]  / {print $1}' "$tmp/range" | paste -sd, -)" = '16,17,29,18' ]
bash "$runner" --plan --only 11 > "$tmp/only"
[ "$(grep -cE '^[0-9]{2}  ' "$tmp/only")" = 1 ]
SKIP_STEPS='17,29' bash "$runner" --plan --from 16 --until 18 > "$tmp/skip"
[ "$(awk '/^[0-9][0-9]  / {print $1}' "$tmp/skip" | paste -sd, -)" = '16,18' ]
if bash "$runner" --plan --from 18 --until 17 > /dev/null 2>&1; then exit 1; fi
if bash "$runner" --plan --only 11 --from 10 > /dev/null 2>&1; then exit 1; fi
if bash "$runner" --plan --only 99 > /dev/null 2>&1; then exit 1; fi
if bash "$runner" --plan --from > /dev/null 2>&1; then exit 1; fi
if bash "$runner" --only 11 > /dev/null 2>&1; then exit 1; fi
[ ! -e "$TEST_CALLS" ]

export CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1 CONFIRM_FULL_FRESH_DEPLOY=1
if bash "$runner" --only 03 > /dev/null 2>&1; then exit 1; fi
[ ! -e "$TEST_CALLS" ]

set +e
TEST_FAIL_STEP=06 bash "$runner" --from 04 --until 08 > "$tmp/failure" 2>&1
result=$?
set -e
[ "$result" = 7 ]
[ "$(grep -E '^[0-9]{2}$' "$TEST_CALLS" | paste -sd, -)" = '04,05,06' ]
if grep -q '^prepare$' "$TEST_CALLS"; then exit 1; fi
status_file="$(find "$profile/runtime/runs" -name status.tsv -print -quit)"
awk -F '\t' '$1 == "06" && $2 == "FAILED" && $3 == "7" {found=1} END {exit !found}' "$status_file"
[ "$(stat -c %a "$status_file")" = 600 ]
[ "$(stat -c %a "$(dirname "$status_file")/06.log")" = 600 ]

: > "$TEST_CALLS"
set +e
bash "$runner" --only 11 > "$tmp/missing-runtime" 2>&1
result=$?
set -e
[ "$result" = 9 ]
if grep -q '^11$' "$TEST_CALLS"; then exit 1; fi
grep -q 'FAILED 11' "$tmp/missing-runtime"

touch "$TEST_RUNTIME"
: > "$TEST_CALLS"
bash "$runner" --only 30 > "$tmp/frontends"
grep -q '^selected=30 21 26 28$' "$TEST_CALLS"
grep -q '^30$' "$TEST_CALLS"
if grep -q '^prepare$' "$TEST_CALLS"; then exit 1; fi

: > "$TEST_CALLS"
bash "$runner" > "$tmp/full"
grep -q '^prepare$' "$TEST_CALLS"
[ "$(grep -Ec '^[0-9]{2}$' "$TEST_CALLS")" = 21 ]
[ "$(tail -n 1 "$TEST_CALLS")" = 31 ]

: > "$TEST_CALLS"
if TEST_PREFLIGHT_EXIT=5 bash "$runner" --only 11 > /dev/null 2>&1; then exit 1; fi
if grep -q '^11$' "$TEST_CALLS"; then exit 1; fi
echo '[ok] multichain planning, range selection, failure logging and preflight gates'
