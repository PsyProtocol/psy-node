#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

SERVICE_NAME="${LOCAL_CF_AUTODEPLOY_SERVICE_NAME:-parth-local-frontend-autodeploy}"
STATE_DIR="${LOCAL_CF_AUTODEPLOY_STATE_DIR:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging-cf-tunnel/autodeploy}"
SOURCE_ROOT="${LOCAL_CF_AUTODEPLOY_SOURCE_ROOT:-$(dirname "$LOCAL_CF_LIVE_PARTH_DIR")/frontend-autodeploy}"
NGINX_ROOT="${LOCAL_CF_NGINX_HTML_ROOT:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging/nginx/html}"

echo "== frontend auto deploy timer =="
systemctl --user --no-pager status "$SERVICE_NAME.timer" || true
echo
echo "== latest run =="
systemctl --user --no-pager status "$SERVICE_NAME.service" || true

echo
echo "== release =="
printf 'current: '
cat "$NGINX_ROOT/frontend-release.current" 2>/dev/null || echo unavailable
jq '{releaseId, gitSha, gitBranch, publishedAt}' "$NGINX_ROOT/frontend-release.json" 2>/dev/null || true

for state_name in current-source last-attempt last-success last-blocked last-failure; do
  echo
  echo "== $state_name =="
  jq . "$STATE_DIR/$state_name.json" 2>/dev/null || echo unavailable
done

if [ -s "$STATE_DIR/last-error.log" ]; then
  echo
  echo "== last error =="
  tail -80 "$STATE_DIR/last-error.log"
fi

echo
echo "== source checkouts =="
for repo_dir in "$SOURCE_ROOT/psy-node" "$SOURCE_ROOT/psy-wallet" "$SOURCE_ROOT/psy-sdk"; do
  if git -C "$repo_dir" rev-parse --git-dir >/dev/null 2>&1; then
    printf '%s branch=%s sha=%s\n' \
      "$repo_dir" \
      "$(git -C "$repo_dir" branch --show-current)" \
      "$(git -C "$repo_dir" rev-parse HEAD)"
  else
    echo "$repo_dir unavailable"
  fi
done
