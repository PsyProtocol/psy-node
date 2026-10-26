#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Redeploy code/runtime/public entrypoints/frontends while preserving both:
# - L1 Sepolia contract state
# - L2 database/checkpoint state
#
# This is the safe path for code/config refreshes after staging is already
# initialized.
export CONFIRM_FULL_FRESH_DEPLOY="${CONFIRM_FULL_FRESH_DEPLOY:-1}"
export REGENERATE_GENESIS="${REGENERATE_GENESIS:-0}"

add_skip_step() {
  local step="$1"
  case " ${SKIP_STEPS:-} " in
    *" ${step} "*) ;;
    *) SKIP_STEPS="${SKIP_STEPS:-} ${step}" ;;
  esac
}

add_skip_step 2
add_skip_step 3
add_skip_step 5
add_skip_step 6
add_skip_step 7
add_skip_step 8
add_skip_step 9
add_skip_step 10
export SKIP_STEPS

exec bash "$SCRIPT_DIR/deploy_all.sh"
