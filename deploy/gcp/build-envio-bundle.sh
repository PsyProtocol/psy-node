#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="$ROOT/deploy"
cd "$ROOT"

: "${OUT_DIR:=dist}"
: "${OUT_FILE:=$OUT_DIR/parth-envio-bundle.tar.gz}"

if [ ! -d "$DEPLOY_DIR/artifacts/envio/psy-relayer-envio" ]; then
  echo "missing Envio artifact directory: $DEPLOY_DIR/artifacts/envio/psy-relayer-envio" >&2
  echo "run: bash deploy/scripts/package-local-artifacts.sh" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
tar -C "$DEPLOY_DIR/artifacts/envio" -czf "$OUT_FILE" psy-relayer-envio
echo "$OUT_FILE"
