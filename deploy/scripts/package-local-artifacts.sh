#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="$ROOT/deploy"
PARTH_DIR="${PARTH_DIR:-$ROOT}"
WORKSPACE_ROOT="${WORKSPACE_HOME:-$(cd "$ROOT/.." && pwd)}"
PSY_SERVICES_DIR="${PSY_SERVICES_DIR:-$WORKSPACE_ROOT/psy-services}"
PARTH_DIR="$(cd "$PARTH_DIR" && pwd -P)"
PSY_GENESIS_DIR="${PSY_GENESIS_DIR:-$PARTH_DIR/psy-genesis}"
PSY_DAPP_DIR="${PSY_DAPP_DIR:-$PARTH_DIR/psy-dapp}"
PSY_SERVICES_DIR="$(cd "$PSY_SERVICES_DIR" && pwd -P)" || {
  echo "missing psy-services checkout: ${PSY_SERVICES_DIR}" >&2
  exit 1
}

require_file() {
  if [ ! -f "$1" ]; then
    echo "required file missing: $1" >&2
    exit 1
  fi
}

require_dir() {
  if [ ! -d "$1" ]; then
    echo "required directory missing: $1" >&2
    exit 1
  fi
}

require_dir "$PARTH_DIR"
require_dir "$PSY_SERVICES_DIR"
require_file "$PARTH_DIR/genesis.json"
require_file "$PSY_GENESIS_DIR/genesis_contracts.json"
require_file "$PSY_GENESIS_DIR/config.json"
require_dir "$PSY_GENESIS_DIR/genesis_abi"

mkdir -p \
  "$DEPLOY_DIR/artifacts/bin/parth" \
  "$DEPLOY_DIR/artifacts/bin/psy-services" \
  "$DEPLOY_DIR/artifacts/envio" \
  "$DEPLOY_DIR/artifacts/frontend" \
  "$DEPLOY_DIR/config/parth" \
  "$DEPLOY_DIR/config/psy-services" \
  "$DEPLOY_DIR/scripts" \
  "$DEPLOY_DIR/sources"

echo "[package] copying Parth release binaries"
for bin in psy_node_cli psy_worker_cli psy_user_cli psy_relayer_cli psy_dev_cli; do
  require_file "$PARTH_DIR/target/release/$bin"
  install -m 0755 "$PARTH_DIR/target/release/$bin" "$DEPLOY_DIR/artifacts/bin/parth/$bin"
  if command -v strip >/dev/null 2>&1; then
    strip "$DEPLOY_DIR/artifacts/bin/parth/$bin" 2>/dev/null || true
  fi
done

echo "[package] copying psy-services release binaries"
for bin in psy-services psy-indexer; do
  require_file "$PSY_SERVICES_DIR/target/release/$bin"
  install -m 0755 "$PSY_SERVICES_DIR/target/release/$bin" "$DEPLOY_DIR/artifacts/bin/psy-services/$bin"
  if command -v strip >/dev/null 2>&1; then
    strip "$DEPLOY_DIR/artifacts/bin/psy-services/$bin" 2>/dev/null || true
  fi
done

echo "[package] copying frontend dist outputs when present"
copy_frontend_dist() {
  local name="$1"
  local dist_dir="$2"
  local output="$DEPLOY_DIR/artifacts/frontend/$name"

  if [ ! -d "$dist_dir" ]; then
    echo "[package] skipping ${name}; missing dist: $dist_dir"
    return 0
  fi

  mkdir -p "$output"
  rsync -a --delete "$dist_dir/" "$output/"
}

copy_frontend_dist "psy-privacy-bridge" "$PSY_DAPP_DIR/apps/bridge/dist"
copy_frontend_dist "psy_ide" "$PSY_DAPP_DIR/apps/ide/dist"
copy_frontend_dist "psy_explorer" "$PSY_DAPP_DIR/apps/explorer/dist"

echo "[package] copying Envio indexer project"
require_dir "$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio"
rsync -a --delete \
  --exclude 'node_modules' \
  --exclude 'generated/node_modules' \
  "$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio/" "$DEPLOY_DIR/artifacts/envio/psy-relayer-envio/"

echo "[package] copying deployment configs"
install -m 0644 "$PARTH_DIR/Makefile" "$DEPLOY_DIR/config/parth/Makefile"
install -m 0644 "$PSY_GENESIS_DIR/config.json" "$DEPLOY_DIR/config/parth/client_prover_config.json"

install -m 0644 "$PARTH_DIR/genesis.json" "$DEPLOY_DIR/config/parth/genesis.json"
install -m 0644 "$PSY_GENESIS_DIR/genesis_contracts.json" "$DEPLOY_DIR/config/parth/genesis_contracts.json"
rsync -a --delete "$PSY_GENESIS_DIR/genesis_abi/" "$DEPLOY_DIR/config/parth/genesis_abi/"

if [ -d "$PARTH_DIR/psy_cli/psy_relayer_cli/config" ]; then
  rsync -a --delete "$PARTH_DIR/psy_cli/psy_relayer_cli/config/" "$DEPLOY_DIR/config/parth/psy_relayer_cli/"
fi

if [ -d "$PSY_SERVICES_DIR/migrations" ]; then
  rsync -a --delete "$PSY_SERVICES_DIR/migrations/" "$DEPLOY_DIR/config/psy-services/migrations/"
fi

if [ -d "$PSY_SERVICES_DIR/genesis_contracts" ]; then
  rsync -a --delete "$PSY_SERVICES_DIR/genesis_contracts/" "$DEPLOY_DIR/config/psy-services/genesis_contracts/"
fi

echo "[package] copying deployment scripts"
if [ -d "$PARTH_DIR/deploy" ] && [ "$(cd "$PARTH_DIR/deploy" && pwd)" != "$(cd "$DEPLOY_DIR" && pwd)" ]; then
  rsync -a --delete --exclude 'gcp' "$PARTH_DIR/deploy/" "$DEPLOY_DIR/scripts/parth/"
elif [ -d "$PARTH_DIR/deploy" ]; then
  echo "[package] using in-repo deployment scripts directly"
fi

if [ "${PACKAGE_SOURCES:-0}" = "1" ]; then
  echo "[package] syncing source snapshots"
  rsync -a --delete \
    --exclude '.git' \
    --exclude 'target' \
    --exclude 'node_modules' \
    --exclude 'dist' \
    --exclude 'logs' \
    --exclude 'local_checkpoints' \
    --exclude 'private_keys.json' \
    --exclude 'genesis.json' \
    "$PARTH_DIR/" "$DEPLOY_DIR/sources/psy-node/"

  rsync -a --delete \
    --exclude '.git' \
    --exclude 'target' \
    --exclude 'node_modules' \
    --exclude 'logs' \
    "$PSY_SERVICES_DIR/" "$DEPLOY_DIR/sources/psy-services/"
else
  echo "[package] skipping source snapshots; set PACKAGE_SOURCES=1 to refresh deploy/sources"
fi

echo "[package] done"
echo "$DEPLOY_DIR"
