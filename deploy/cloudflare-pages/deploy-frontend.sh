#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FRONTEND_NAME="${1:-}"
PROJECT_NAME="${2:-}"
BRANCH="${CF_PAGES_BRANCH:-staging}"

usage() {
  cat >&2 <<'USAGE'
usage: deploy/cloudflare-pages/deploy-frontend.sh <frontend> <cloudflare-pages-project>

frontends:
  psy_bridge
  psy_privacy

required env:
  CLOUDFLARE_API_TOKEN
  CLOUDFLARE_ACCOUNT_ID

optional env:
  CF_PAGES_BRANCH=staging
USAGE
}

if [ -z "$FRONTEND_NAME" ] || [ -z "$PROJECT_NAME" ]; then
  usage
  exit 1
fi

case "$FRONTEND_NAME" in
  psy_bridge|psy_privacy) ;;
  *)
    echo "unknown frontend: $FRONTEND_NAME" >&2
    usage
    exit 1
    ;;
esac

: "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
: "${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"

directory="$ROOT/deploy/artifacts/frontend/$FRONTEND_NAME"
[ -f "$directory/index.html" ] || {
  echo "missing frontend artifact: $directory/index.html" >&2
  echo "run: bash deploy/scripts/package-local-artifacts.sh" >&2
  exit 1
}

echo "[cloudflare-pages] deploying ${FRONTEND_NAME} -> ${PROJECT_NAME} from ${directory}"
npx --yes wrangler pages deploy "$directory" \
  --project-name "$PROJECT_NAME" \
  --branch "$BRANCH"
