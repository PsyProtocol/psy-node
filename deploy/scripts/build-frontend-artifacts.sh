#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PARTH_DIR="${PARTH_DIR:-$ROOT}"
DEPLOY_ROOT="$ROOT/deploy"
PSY_DAPP_DIR="${PSY_DAPP_DIR:-$PARTH_DIR/psy-dapp}"
FRONTENDS="${FRONTENDS:-bridge explorer ide}"
SYNC_AFTER_BUILD="${SYNC_AFTER_BUILD:-1}"

frontend_dir() {
  case "$1" in
    bridge) printf '%s\n' "$PSY_DAPP_DIR/apps/bridge" ;;
    explorer) printf '%s\n' "$PSY_DAPP_DIR/apps/explorer" ;;
    ide) printf '%s\n' "$PSY_DAPP_DIR/apps/ide" ;;
    *)
      echo "unknown frontend: $1" >&2
      echo "supported frontends: bridge explorer ide" >&2
      exit 1
      ;;
  esac
}

build_frontend() {
  local name="$1"
  local dir="$2"

  echo "[frontend-build] building ${name}"
  (cd "$dir" && pnpm run build)
}

sync_frontend_artifact() {
  local name="$1"
  local dir="$2"
  local output="$DEPLOY_ROOT/artifacts/frontend/$name"

  [ -f "$dir/dist/index.html" ] || {
    echo "missing frontend dist: $dir/dist/index.html" >&2
    exit 1
  }

  mkdir -p "$output"
  rsync -a --delete "$dir/dist/" "$output/"
  echo "[frontend-build] synced ${name} artifact -> ${output}"
}

command -v pnpm >/dev/null 2>&1 || {
  echo "pnpm is required to build psy-dapp frontend artifacts" >&2
  exit 1
}
(cd "$PSY_DAPP_DIR" && pnpm install --frozen-lockfile)

for frontend in $FRONTENDS; do
  dir="$(frontend_dir "$frontend")"
  build_frontend "$frontend" "$dir"
  if [ "$SYNC_AFTER_BUILD" = "1" ]; then
    sync_frontend_artifact "$frontend" "$dir"
  fi
done

echo "[frontend-build] done"
