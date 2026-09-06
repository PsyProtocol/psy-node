#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/deploy-multichain-psy-dapp.yml"
LEGACY_WORKFLOW="$ROOT/.github/workflows/deploy-shield-frontends.yml"
APP_DEPLOY="$ROOT/deploy/cloudflare-pages/deploy-privacy-bridge-demo.sh"

[ -s "$WORKFLOW" ] || {
  echo "missing frontend deployment workflow: $WORKFLOW" >&2
  exit 1
}

[ ! -e "$LEGACY_WORKFLOW" ] || {
  echo "legacy shield frontend workflow must be removed: $LEGACY_WORKFLOW" >&2
  exit 1
}

grep -Fq 'contents: read' "$WORKFLOW" || {
  echo "frontend workflow must use read-only repository permissions" >&2
  exit 1
}

for forbidden in \
  'contents: write' \
  'mainnet-beta' \
  'deployment-profile' \
  'rsync -a --delete' \
  'git push' \
  'git commit' \
  'git checkout -B' \
  'force-with-lease'; do
  if grep -Fq "$forbidden" "$WORKFLOW"; then
    echo "frontend workflow contains forbidden branch mutation: $forbidden" >&2
    exit 1
  fi
done

grep -Fq -- '- deploy/multi-chain-gcp' "$WORKFLOW" || {
  echo "frontend workflow does not listen to the deployment branch" >&2
  exit 1
}
# These are literal GitHub Actions and shell expressions in the YAML file.
# shellcheck disable=SC2016
grep -Fq 'ref: ${{ github.sha }}' "$WORKFLOW" || {
  echo "frontend workflow does not check out the triggering deployment snapshot" >&2
  exit 1
}
# shellcheck disable=SC2016
grep -Fq 'if [ "$GITHUB_REF_NAME" != "deploy/multi-chain-gcp" ]' "$WORKFLOW" || {
  echo "frontend workflow does not reject manual runs from other branches" >&2
  exit 1
}
grep -Fq "MULTICHAIN_L1_ENABLED: '1'" "$WORKFLOW" || {
  echo "frontend workflow does not force the multichain deployment profile" >&2
  exit 1
}
grep -Fq 'deploy/multi-chain/gcp/runtime/l1-deployments.json' "$WORKFLOW" || {
  echo "frontend workflow does not use the canonical runtime manifest" >&2
  exit 1
}
grep -Fq 'refusing frontend publish:' "$APP_DEPLOY" || {
  echo "app deployment lost its fail-closed pre-publish guard" >&2
  exit 1
}
grep -Fq 'deploy-privacy-bridge-demo.sh' "$WORKFLOW" || {
  echo "frontend workflow does not deploy the bridge app" >&2
  exit 1
}
grep -Fq 'deploy-psy-explorer.sh' "$WORKFLOW" || {
  echo "frontend workflow does not deploy the explorer" >&2
  exit 1
}
grep -Fq 'secrets.PSY_DAPP_READ_TOKEN' "$WORKFLOW" || {
  echo "frontend workflow cannot authenticate to the private psy-dapp repository" >&2
  exit 1
}

for forbidden_backend in \
  'deploy_all.sh' \
  'deploy-psy-services' \
  'deploy-indexer' \
  'deploy-relayer' \
  'deploy-workers' \
  'deploy-caddy'; do
  if grep -Fiq "$forbidden_backend" "$WORKFLOW"; then
    echo "frontend workflow invokes a backend deployment: $forbidden_backend" >&2
    exit 1
  fi
done

if grep -Eq '^[[:space:]]+(CHAIN_ID|BRIDGE_ADDRESS|ROUTER_ADDRESS|USDT_TOKEN_ADDRESS):' "$WORKFLOW"; then
  echo "frontend workflow contains legacy single-chain address overrides" >&2
  exit 1
fi

echo "[ok] workflow follows the read-only deployment branch and deploys only app/explorer frontends"
