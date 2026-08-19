#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$SCRIPT_DIR/stack"
CF_DIR="$SCRIPT_DIR/cloudflare-tunnel"

# shellcheck source=stack/lib.sh
source "$STACK_DIR/lib.sh"

local_staging_source_env_defaults \
  "${LOCAL_TESTNET_ENV_FILE:-$SCRIPT_DIR/local.env}"
local_staging_source_env_defaults "$STACK_DIR/local.env"
local_staging_source_env_defaults "$CF_DIR/local.env"

: "${LOCAL_CF_AUTODEPLOY_SERVICE_NAME:=parth-local-frontend-autodeploy}"

REMOVE_VOLUMES=0

usage() {
  cat <<'EOF'
Usage: deploy/local-testnet/stop-all.sh [--volumes]

Stop the frontend auto-deploy timer and every local-testnet process and
container. State and Docker volumes are preserved unless --volumes is given.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --volumes)
      REMOVE_VOLUMES=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now "$LOCAL_CF_AUTODEPLOY_SERVICE_NAME.timer" \
    >/dev/null 2>&1 || true
  systemctl --user stop "$LOCAL_CF_AUTODEPLOY_SERVICE_NAME.service" \
    >/dev/null 2>&1 || true
fi

if [ "$REMOVE_VOLUMES" = "1" ]; then
  bash "$STACK_DIR/down.sh" --volumes
else
  bash "$STACK_DIR/down.sh"
fi

echo "[local-testnet] complete environment stopped"
