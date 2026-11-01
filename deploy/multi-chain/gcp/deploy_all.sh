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
Step tables may use py:<name> and py-cutover:<name> rows, run by
core-only/deploy.py with DEPLOY_RELEASE_DIR (default: the step table directory),
DEPLOY_ACCESS_FILE and DEPLOY_PRIVATE_DIR. py-cutover rows need the two
confirmations in the process environment on every run, not in config.env. A
step that exits 3 is recorded as PENDING; resume with --from <same step>.
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

# Cutover confirmations must come from the invoking environment, not config.env.
env_confirm_replace="${CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING:-0}"
env_confirm_fresh="${CONFIRM_FULL_FRESH_DEPLOY:-0}"

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
declare -A scripts=() descriptions=() skipped=() topology_steps=() py_names=() py_kinds=()
steps_file="${DEPLOY_STEPS_FILE:-$SCRIPT_DIR/steps.tsv}"
while IFS=$'\t' read -r id script description; do
  [[ "$id" =~ ^[0-9]{2}$ ]] || continue
  [ -z "${scripts[$id]:-}" ] || fail "duplicate step ID in $steps_file: $id"
  order+=("$id")
  if [[ "$script" == py:* || "$script" == py-cutover:* ]]; then
    py_kinds[$id]="${script%%:*}"
    py_names[$id]="${script#*:}"
    [[ "${py_names[$id]}" =~ ^[a-z][a-z0-9_]*$ ]] || fail "invalid step name for step $id"
    scripts[$id]="py"
  elif [[ "$script" == topology:* ]]; then
    [ -n "${DEPLOY_TOPOLOGY_FILE:-}" ] || fail 'topology steps require DEPLOY_TOPOLOGY_FILE'
    topology_steps[$id]="${script#topology:}"
    scripts[$id]="$SCRIPT_DIR/fresh-topology/steps.py"
  elif [[ "$script" == *:* ]]; then
    fail "unknown step type for step $id"
  else
    scripts[$id]="$REPO_ROOT/deploy/gcp/fresh-staging/$script"
  fi
  descriptions[$id]="$description"
done < "$steps_file"

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
case "${DEPLOY_MONITORING:-1}" in
  1) ;;
  0)
    [ "$only_step" != "32" ] || fail "step 32 requires DEPLOY_MONITORING=1"
    skipped[32]=1
    [ "${#py_kinds[@]}" -gt 0 ] || echo "[multichain-deploy] monitoring explicitly disabled; this run cannot accept monitoring coverage"
    ;;
  *) fail "DEPLOY_MONITORING must be 0 or 1" ;;
esac

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

py_count=0
for id in "${selected[@]}"; do
  [ -z "${py_kinds[$id]:-}" ] || py_count=$((py_count + 1))
done
py_run=0
if [ "$py_count" -gt 0 ]; then
  [ "$py_count" = "${#selected[@]}" ] || fail "python steps cannot mix with other step types in one run"
  py_run=1
  release_dir="${DEPLOY_RELEASE_DIR:-$(dirname "$steps_file")}"
  release_dir="$(cd "$release_dir" 2>/dev/null && pwd)" || fail "release directory not found; set DEPLOY_RELEASE_DIR"
fi

if [ "$py_run" = "1" ]; then
  echo "[multichain-deploy] release directory: $release_dir"
else
  echo "[multichain-deploy] config: $config_to_read"
  echo "[multichain-deploy] source pins: $DEPLOY_SOURCE_VERSIONS_FILE"
  echo "[multichain-deploy] chains: Sepolia=0 (11155111), BSC=1 (97), Base=2 (84532)"
  if [ -n "${DEPLOY_TOPOLOGY_FILE:-}" ]; then
    echo "[multichain-deploy] topology: $DEPLOY_TOPOLOGY_FILE; host roles are inventory-driven"
  else
    echo "[multichain-deploy] prove host: ${OFFSITE_PROVE_PROXY_HOST:-unset}; offsite workers: ${OFFSITE_WORKER_HOST:-unset}"
  fi
fi
for id in "${selected[@]}"; do
  if [ -n "${py_kinds[$id]:-}" ]; then
    printf '%s  %s\n    %s:%s\n' "$id" "${descriptions[$id]}" "${py_kinds[$id]}" "${py_names[$id]}"
    continue
  fi
  [ -f "${scripts[$id]}" ] || fail "missing script: ${scripts[$id]}"
  printf '%s  %s\n    %s\n' "$id" "${descriptions[$id]}" "${scripts[$id]#"$REPO_ROOT"/}"
  if [ "$plan_only" = "1" ] && [ -n "${topology_steps[$id]:-}" ]; then
    python3 "${scripts[$id]}" "${topology_steps[$id]}" --topology "$DEPLOY_TOPOLOGY_FILE"
  fi
done
if [ "$plan_only" = "1" ]; then
  echo "[multichain-deploy] plan only; no source preparation, network checks or deployment performed"
  exit 0
fi

if [ "$py_run" = "1" ]; then
  has_cutover=0
  for id in "${selected[@]}"; do
    [ "${py_kinds[$id]}" != "py-cutover" ] || has_cutover=1
  done
  if [ "$has_cutover" = "1" ] \
    && { [ "$env_confirm_replace" != "1" ] || [ "$env_confirm_fresh" != "1" ]; }; then
    cat >&2 <<'EOF'
The selected cutover steps stop and erase the current staging services and
state. Confirmations are required on every run, including --from and --only,
and must be set in the process environment (config.env does not count):
  CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1
  CONFIRM_FULL_FRESH_DEPLOY=1
EOF
    exit 1
  fi
  [ -n "${DEPLOY_ACCESS_FILE:-}" ] || fail "DEPLOY_ACCESS_FILE is not set (private SSH configuration file)"
  [ -f "$DEPLOY_ACCESS_FILE" ] || fail "DEPLOY_ACCESS_FILE does not name a file"
  [ -n "${DEPLOY_PRIVATE_DIR:-}" ] || fail "DEPLOY_PRIVATE_DIR is not set (private directory with retired-state.json and retained-paths.json)"
  [ -d "$DEPLOY_PRIVATE_DIR" ] || fail "DEPLOY_PRIVATE_DIR does not name a directory"
  [ -f "$SCRIPT_DIR/core-only/deploy.py" ] || fail "missing core-only/deploy.py"
  # Values sourced from config.env must not reach deploy.py or its children.
  unset REGENERATE_GENESIS PARTH_ALLOW_GENESIS_OVERWRITE
  if [ "$env_confirm_replace" = "1" ]; then export CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1; else unset CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING; fi
  if [ "$env_confirm_fresh" = "1" ]; then export CONFIRM_FULL_FRESH_DEPLOY=1; else unset CONFIRM_FULL_FRESH_DEPLOY; fi
else
  # Fail before *any* stop/reset while the split-fleet reset and artifact gates
  # remain unresolved. The legacy host enumeration is not safe for this fleet.
  if [ -n "${DEPLOY_TOPOLOGY_FILE:-}" ]; then
    for id in "${selected[@]}"; do
      [[ "${descriptions[$id]}" != BLOCKED* ]] || fail "step $id is not implemented for this topology: ${descriptions[$id]}"
    done
    python3 "$SCRIPT_DIR/fresh-topology/steps.py" readiness --topology "$DEPLOY_TOPOLOGY_FILE"
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

  # Detect missing or unreviewed monitoring sources before stopping the network.
  if has_step 32; then
    bash "$SCRIPT_DIR/deploy-monitoring.sh" --check
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
if [ "$py_run" != "1" ]; then
  # shellcheck source=../../gcp/lib/multichain.sh
  source "$REPO_ROOT/deploy/gcp/lib/multichain.sh"
fi

run_step_script() {
  local step="$1"
  if [ -n "${py_kinds[$step]:-}" ]; then
    python3 -u "$SCRIPT_DIR/core-only/deploy.py" "${py_names[$step]}" --release-dir "$release_dir" \
      --access "$DEPLOY_ACCESS_FILE" --run-dir "$run_dir" --private-dir "$DEPLOY_PRIVATE_DIR" \
      --steps-file "$steps_file"
    return
  fi
  # Step 10 writes the manifest. Every downstream consumer must see the full
  # registry, including when it is invoked alone or after an interrupted run.
  case "$step" in 11|12|16|17|18|27|30|40|41|42|43|44|45|46|47) multichain_require_runtime || return ;; esac
  if [ -n "${topology_steps[$step]:-}" ]; then
    python3 "${scripts[$step]}" "${topology_steps[$step]}" \
      --topology "$DEPLOY_TOPOLOGY_FILE" --config "$GCP_DEPLOY_CONFIG" \
      --versions "$DEPLOY_SOURCE_VERSIONS_FILE" --apply
  else
    bash "${scripts[$step]}"
  fi
}

# Before any wipe, the whole step table must be registered and the release lock valid.
if [ "$py_run" = "1" ] && [ "${has_cutover:-0}" = "1" ]; then
  python3 -u "$SCRIPT_DIR/core-only/deploy.py" "${py_names[${selected[0]}]}" --plan --release-dir "$release_dir" \
    --access "$DEPLOY_ACCESS_FILE" --run-dir "$run_dir" --private-dir "$DEPLOY_PRIVATE_DIR" \
    --steps-file "$steps_file" || fail "step table check failed; nothing was started"
fi

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
  if [ -n "${py_kinds[$id]:-}" ] && [ "$result" = "3" ] && [ "${pipeline_status[1]}" = "0" ]; then
    printf '%s\tPENDING\t3\t%s\t%s\n' "$id" "$elapsed" "$step_log" >> "$status_file"
    echo "[multichain-deploy] PENDING $id: complete the operator action printed in $step_log, then rerun with --from $id" >&2
    exit 3
  fi
  if [ "$id" = "32" ] && [ "$result" = "3" ] && [ "${pipeline_status[1]}" = "0" ]; then
    printf '%s\tPENDING\t3\t%s\t%s\n' "$id" "$elapsed" "$step_log" >> "$status_file"
    echo '[multichain-deploy] PENDING 32: finish offsite monitoring installation, then run deploy-monitoring.sh --status' >&2
    exit 3
  fi
  if [ "$result" != "0" ]; then
    printf '%s\tFAILED\t%s\t%s\t%s\n' "$id" "$result" "$elapsed" "$step_log" >> "$status_file"
    echo "[multichain-deploy] FAILED $id (exit=$result); inspect $step_log" >&2
    echo "[multichain-deploy] after resolving the cause, select --from $id; no automatic retry" >&2
    if [ "$id" = "10" ] || [ "${py_names[$id]:-}" = "deploy_l1" ]; then
      echo "[multichain-deploy] L1 transactions may already exist; verify each chain before rerunning step $id" >&2
    fi
    exit "$result"
  fi
  printf '%s\tSUCCEEDED\t0\t%s\t%s\n' "$id" "$elapsed" "$step_log" >> "$status_file"
  echo "[multichain-deploy] OK $id (${elapsed}s)"
done
echo "[multichain-deploy] selected steps completed; status: $status_file"
[ "$py_run" = "1" ] || echo "[multichain-deploy] three-chain transaction E2E is a separate acceptance step"
