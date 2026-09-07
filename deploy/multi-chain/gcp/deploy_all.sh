#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"

export WORKSPACE_HOME
export GCP_DEPLOY_CONFIG="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
export DEPLOY_SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

usage() {
  cat <<'EOF'
Usage: bash deploy/multi-chain/gcp/deploy_all.sh [options]

  --plan          Print the selected steps without preparing sources or using SSH/RPC
  --from ID       Start at this step in the listed execution order
  --until ID      Stop after this step in the listed execution order
  --only ID       Run exactly one step (cannot be combined with --from/--until)
  --help          Show this help

DRY_RUN=1 is equivalent to --plan. SKIP_STEPS accepts comma/space-separated IDs.
Real execution requires CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1 and
CONFIRM_FULL_FRESH_DEPLOY=1. Step selection is manual, not automatic recovery.
Logs and status.tsv are stored under runtime/runs/<run-id>/.
EOF
}

fail() { echo "[multichain-deploy] $*" >&2; exit 1; }

plan_only="${DRY_RUN:-0}"
from_step=""
until_step=""
only_step=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plan) plan_only=1; shift ;;
    --from|--until|--only)
      [ "$#" -ge 2 ] && [[ "$2" =~ ^[0-9]{1,2}$ ]] || fail "$1 requires a numeric step ID"
      normalized="$(printf '%02d' "$((10#$2))")"
      case "$1" in
        --from) from_step="$normalized" ;;
        --until) until_step="$normalized" ;;
        --only) only_step="$normalized" ;;
      esac
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown option: $1 (see --help)" ;;
  esac
done
[ -z "$only_step" ] || { [ -z "$from_step$until_step" ] || fail "--only cannot be combined with --from/--until"; }

config_to_read="$GCP_DEPLOY_CONFIG"
if [ ! -f "$config_to_read" ]; then
  [ "$plan_only" = "1" ] || fail "missing config: $config_to_read"
  config_to_read="$SCRIPT_DIR/config.example.env"
  echo "[multichain-deploy] planning with example config; no live config exists"
fi
bash -n "$config_to_read"
set -a
# shellcheck disable=SC1090
source "$config_to_read"
# shellcheck disable=SC1090
source "$DEPLOY_SOURCE_VERSIONS_FILE"
set +a
[ -z "${DEPLOY_ALL_LAST_STEP:-}" ] || fail "use --until ID instead of legacy DEPLOY_ALL_LAST_STEP"

declare -a order=() selected=()
declare -A scripts=() descriptions=() skipped=()
while IFS=$'\t' read -r id script description; do
  [[ "$id" =~ ^[0-9]{2}$ ]] || continue
  order+=("$id")
  scripts[$id]="$REPO_ROOT/deploy/gcp/fresh-staging/$script"
  descriptions[$id]="$description"
done < "$SCRIPT_DIR/steps.tsv"

for id in "$from_step" "$until_step" "$only_step"; do
  [ -z "$id" ] || [ -n "${scripts[$id]:-}" ] || fail "unknown step: $id"
done
skip_ids="${SKIP_STEPS:-}"
skip_ids="${skip_ids//,/ }"
for id in $skip_ids; do
  [[ "$id" =~ ^[0-9]{1,2}$ ]] || fail "invalid SKIP_STEPS ID: $id"
  id="$(printf '%02d' "$((10#$id))")"
  [ -n "${scripts[$id]:-}" ] || fail "unknown SKIP_STEPS ID: $id"
  skipped[$id]=1
done
if [ "${DEPLOY_OFFSITE_WORKERS:-0}" != "1" ]; then
  [ "$only_step" != "31" ] || fail "step 31 requires DEPLOY_OFFSITE_WORKERS=1 in config"
  skipped[31]=1
fi

selecting=0
[ -n "$from_step" ] || selecting=1
for id in "${order[@]}"; do
  if [ "$id" = "$from_step" ]; then selecting=1; fi
  if [ -n "$only_step" ]; then
    [ "$id" = "$only_step" ] || continue
  elif [ "$selecting" != "1" ]; then
    continue
  fi
  if [ -z "${skipped[$id]:-}" ]; then selected+=("$id"); fi
  if [ "$id" = "$until_step" ]; then break; fi
done
[ "${#selected[@]}" -gt 0 ] || fail "no steps selected"
if [ -n "$from_step" ] && [ -n "$until_step" ]; then
  range=" ${selected[*]} "
  [[ "$range" == *" $until_step "* ]] || fail "--until must follow --from and must not be skipped"
fi

echo "[multichain-deploy] config: $config_to_read"
echo "[multichain-deploy] source pins: $DEPLOY_SOURCE_VERSIONS_FILE"
echo "[multichain-deploy] chains: Sepolia=0 (11155111), BSC=1 (97), Base=2 (84532)"
echo "[multichain-deploy] prove host: ${OFFSITE_PROVE_PROXY_HOST:-unset}; offsite workers: ${OFFSITE_WORKER_HOST:-unset}"
for id in "${selected[@]}"; do
  [ -f "${scripts[$id]}" ] || fail "missing script: ${scripts[$id]}"
  printf '%s  %s\n    %s\n' "$id" "${descriptions[$id]}" "${scripts[$id]#"$REPO_ROOT"/}"
done
if [ "$plan_only" = "1" ]; then
  echo "[multichain-deploy] plan only; no source preparation, network checks or deployment performed"
  exit 0
fi

if [ "${CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING:-0}" != "1" ] \
  || [ "${CONFIRM_FULL_FRESH_DEPLOY:-0}" != "1" ]; then
  cat >&2 <<'EOF'
This profile reuses the current staging GCP hosts and persistent state paths.
A fresh deployment erases the current Psy L2/databases and deploys new bridge
contracts on Sepolia, BSC Testnet, and Base Sepolia.

Set both confirmations for the real deployment:
  CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1
  CONFIRM_FULL_FRESH_DEPLOY=1
EOF
  exit 1
fi

has_step() { [[ " ${selected[*]} " == *" $1 "* ]]; }
if { has_step 02 || has_step 03; } && ! has_step 10; then
  fail "clearing L2 state requires step 10 in the same plan to replace all L1 roots"
fi

# Only a full run prepares checkouts. Resuming must retain generated files and
# the sources used by earlier stages; preflight still validates their pins.
if [ -z "$from_step$until_step$only_step" ] && [ -z "${SKIP_STEPS:-}" ]; then
  bash "$SCRIPT_DIR/prepare-sources.sh"
fi
bash "$SCRIPT_DIR/preflight.sh"
preflight_steps="${selected[*]}"
if has_step 30; then preflight_steps+=" 21 26 28"; fi
DEPLOY_ALL_SELECTED_STEPS="$preflight_steps" \
  bash "$REPO_ROOT/deploy/gcp/fresh-staging/preflight.sh"

export REGENERATE_GENESIS="${REGENERATE_GENESIS:-1}"
if has_step 02 && has_step 03; then
  export PARTH_ALLOW_GENESIS_OVERWRITE=1
else
  export PARTH_ALLOW_GENESIS_OVERWRITE="${PARTH_ALLOW_GENESIS_OVERWRITE:-0}"
fi

# Private permissions are needed because lower-level tools can include RPC
# credentials in their output. Persist status without sourcing it on resume.
original_umask="$(umask)"
umask 077
run_parent="$SCRIPT_DIR/runtime/runs"
mkdir -p "$run_parent"
run_dir="$(mktemp -d "$run_parent/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
status_file="$run_dir/status.tsv"
printf 'step\tstate\texit_code\telapsed_seconds\tlog\n' > "$status_file"
umask "$original_umask"
echo "[multichain-deploy] logs: $run_dir"
# shellcheck source=../../gcp/lib/multichain.sh
source "$REPO_ROOT/deploy/gcp/lib/multichain.sh"

run_step_script() {
  local step="$1"
  # Step 10 writes the manifest. Every downstream consumer must see the full
  # registry, including when it is invoked alone or after an interrupted run.
  case "$step" in 11|12|16|17|18|27|30) multichain_require_runtime || return ;; esac
  bash "${scripts[$step]}"
}

for id in "${selected[@]}"; do
  echo "[multichain-deploy] START $id: ${descriptions[$id]}"
  step_log="$run_dir/$id.log"
  install -m 0600 /dev/null "$step_log"
  started="$(date +%s)"
  printf '%s\tSTARTED\t\t0\t%s\n' "$id" "$step_log" >> "$status_file"
  set +e
  run_step_script "$id" 2>&1 | tee "$step_log"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e
  result="${pipeline_status[0]}"
  [ "$result" != "0" ] || result="${pipeline_status[1]}"
  elapsed="$(( $(date +%s) - started ))"
  if [ "$result" != "0" ]; then
    printf '%s\tFAILED\t%s\t%s\t%s\n' "$id" "$result" "$elapsed" "$step_log" >> "$status_file"
    echo "[multichain-deploy] FAILED $id (exit=$result); inspect $step_log" >&2
    echo "[multichain-deploy] after resolving the cause, select --from $id; no automatic retry" >&2
    if [ "$id" = "10" ]; then
      echo "[multichain-deploy] L1 transactions may already exist; verify each chain before rerunning step 10" >&2
    fi
    exit "$result"
  fi
  printf '%s\tSUCCEEDED\t0\t%s\t%s\n' "$id" "$elapsed" "$step_log" >> "$status_file"
  echo "[multichain-deploy] OK $id (${elapsed}s)"
done
echo "[multichain-deploy] selected steps completed; status: $status_file"
echo "[multichain-deploy] three-chain transaction E2E is a separate acceptance step"
