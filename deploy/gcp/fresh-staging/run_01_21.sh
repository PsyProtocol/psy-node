#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash deploy/gcp/fresh-staging/run_01_21.sh [FROM] [TO]

Defaults:
  FROM=1
  TO=23

Examples:
  bash deploy/gcp/fresh-staging/run_01_21.sh
  bash deploy/gcp/fresh-staging/run_01_21.sh 1 17
  bash deploy/gcp/fresh-staging/run_01_21.sh 21 21
  YES=1 bash deploy/gcp/fresh-staging/run_01_21.sh 1 23
  DRY_RUN=1 bash deploy/gcp/fresh-staging/run_01_21.sh 1 23

Notes:
  Steps 01..03 are destructive: they stop services and clear remote staging data.
  Step 15 uploads local bridge Groth16 trust setup before starting relayer.
  Step 23 is disabled by default; set SMOKE_SIMPLE_MINT_ENABLED=1 to mint 100
  PSY to the relayer genesis user and verify the result.
EOF
}

validate_step() {
  local value="$1"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "invalid step number: $value" >&2
    exit 1
  fi
  if (( value < 1 || value > 23 )); then
    echo "step out of supported range 1..23: $value" >&2
    exit 1
  fi
}

resolve_step_script() {
  local step="$1"
  local prefix
  prefix="$(printf '%02d' "$step")"

  mapfile -t matches < <(find "$FRESH_DIR" -maxdepth 1 -type f -name "${prefix}_*.sh" | sort)
  if (( ${#matches[@]} == 0 )); then
    case "$prefix" in
      19|20|22)
        return 1
        ;;
    esac
    echo "missing script for step ${prefix}" >&2
    exit 1
  fi
  if (( ${#matches[@]} > 1 )); then
    echo "multiple scripts found for step ${prefix}:" >&2
    printf '  %s\n' "${matches[@]}" >&2
    exit 1
  fi

  printf '%s\n' "${matches[0]}"
}

confirm_destructive_range() {
  local from="$1"
  local to="$2"

  if (( from <= 3 && to >= 1 )) && [ "${YES:-0}" != "1" ]; then
    cat >&2 <<'EOF'
This run includes destructive fresh-deploy steps:
  01 stop Parth services
  02 clear Parth release/state
  03 clear Scylla/Redis/NATS/Postgres/Envio/Anvil data

Type "yes" to continue:
EOF
    read -r answer
    if [ "$answer" != "yes" ]; then
      echo "aborted" >&2
      exit 1
    fi
  fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

from="${1:-${FROM:-1}}"
to="${2:-${TO:-23}}"

validate_step "$from"
validate_step "$to"

if (( from > to )); then
  echo "FROM must be <= TO: ${from} > ${to}" >&2
  exit 1
fi

cd "$REPO_ROOT"

log_step "fresh staging runner from $(printf '%02d' "$from") to $(printf '%02d' "$to")"
if [ "${DRY_RUN:-0}" != "1" ]; then
  selected_steps=()
  for ((step = from; step <= to; step++)); do
    if resolve_step_script "$step" >/dev/null; then
      selected_steps+=("$(printf '%02d' "$step")")
    fi
  done
  DEPLOY_ALL_SELECTED_STEPS="${selected_steps[*]}" bash "$FRESH_DIR/preflight.sh"

  if (( from <= 2 && to >= 3 )); then
    export PARTH_ALLOW_GENESIS_OVERWRITE="${PARTH_ALLOW_GENESIS_OVERWRITE:-1}"
  else
    export PARTH_ALLOW_GENESIS_OVERWRITE="${PARTH_ALLOW_GENESIS_OVERWRITE:-0}"
  fi
  echo "[runner] PARTH_ALLOW_GENESIS_OVERWRITE=${PARTH_ALLOW_GENESIS_OVERWRITE}"
  confirm_destructive_range "$from" "$to"
fi

for ((step = from; step <= to; step++)); do
  if ! script="$(resolve_step_script "$step")"; then
    log_step "skipping removed legacy frontend step $(printf '%02d' "$step")"
    continue
  fi
  rel_path="${script#"$REPO_ROOT"/}"

  if [ "${DRY_RUN:-0}" = "1" ]; then
    printf '[dry-run] bash %s\n' "$rel_path"
    continue
  fi

  log_step "starting ${rel_path}"
  start_ts="$(date +%s)"
  bash "$script"
  end_ts="$(date +%s)"
  log_step "completed ${rel_path} in $((end_ts - start_ts))s"
done

log_step "completed fresh staging steps $(printf '%02d' "$from")..$(printf '%02d' "$to")"
