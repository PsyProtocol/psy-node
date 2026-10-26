#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# This path preserves existing Sepolia contracts. Clearing L2/database state
# while preserving L1 is normally unsafe because StateManager keeps finalized
# checkpoint roots and consumed deposit indexes on-chain.
if [ "${ALLOW_L1_L2_STATE_MISMATCH:-0}" != "1" ]; then
  cat >&2 <<'EOF'
Refusing to reset L2/database state while keeping existing L1 contracts.

Reason:
  Sepolia StateManager/Bridge keep on-chain state such as lastFinalizedCheckpointId,
  lastVerifiedCheckpointRoot, nextConsumedDepositIndex, deposit frontier, and
  known subtree roots. A fresh L2 DB cannot continue from those roots.

Use one of:
  1. Full fresh deploy including step 10 L1 contracts:
     CONFIRM_FULL_FRESH_DEPLOY=1 REGENERATE_GENESIS=1 bash deploy/gcp/fresh-staging/deploy_all.sh

  2. Keep L1 and do not clear DB/state; redeploy binaries/services/frontends only.

Set ALLOW_L1_L2_STATE_MISMATCH=1 only for deliberate debugging.
EOF
  exit 1
fi

# Debug-only path for resetting staging L2/database/runtime state while keeping
# existing Sepolia contracts and addresses in deploy/gcp/config.env.
export CONFIRM_FULL_FRESH_DEPLOY="${CONFIRM_FULL_FRESH_DEPLOY:-1}"
export REGENERATE_GENESIS="${REGENERATE_GENESIS:-0}"

existing_skip_steps=" ${SKIP_STEPS:-} "
case "$existing_skip_steps" in
  *" 10 "*) ;;
  *) export SKIP_STEPS="${SKIP_STEPS:-} 10" ;;
esac

exec bash "$SCRIPT_DIR/deploy_all.sh"
