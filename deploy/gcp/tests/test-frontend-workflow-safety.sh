#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MOVED_WORKFLOW="$ROOT/.github/workflows/deploy-multichain-psy-dapp.yml"
LEGACY_WORKFLOW="$ROOT/.github/workflows/deploy-shield-frontends.yml"
DAPP_CODE_WORKFLOW="$ROOT/psy-dapp/.github/workflows/deploy-multichain-staging.yml"
APP_DEPLOY="$ROOT/deploy/cloudflare-pages/deploy-privacy-bridge-demo.sh"
EXPLORER_DEPLOY="$ROOT/deploy/cloudflare-pages/deploy-psy-explorer.sh"

[ ! -e "$MOVED_WORKFLOW" ] || {
  echo "psy-node must not own the frontend deployment workflow: $MOVED_WORKFLOW" >&2
  exit 1
}

[ ! -e "$LEGACY_WORKFLOW" ] || {
  echo "legacy shield frontend workflow must be removed: $LEGACY_WORKFLOW" >&2
  exit 1
}

[ ! -e "$DAPP_CODE_WORKFLOW" ] || {
  echo "the psy-dapp code branch must not contain the deployment-branch workflow: $DAPP_CODE_WORKFLOW" >&2
  exit 1
}

grep -Fq 'refusing frontend publish:' "$APP_DEPLOY" || {
  echo "app deployment lost its fail-closed pre-publish guard" >&2
  exit 1
}
for explorer_guard in \
  "selected explorer config '" \
  'explorer deployment metadata does not match the selected runtime'; do
  grep -Fq "$explorer_guard" "$EXPLORER_DEPLOY" || {
    echo "explorer deployment lost its fail-closed guard: $explorer_guard" >&2
    exit 1
  }
done

echo "[ok] psy-node owns no frontend workflow; manual app/explorer publishers remain fail-closed"
