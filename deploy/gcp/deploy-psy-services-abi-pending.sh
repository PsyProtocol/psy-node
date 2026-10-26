#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PARTH_DIR="${PARTH_DIR:-$REPO_ROOT}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi
# shellcheck source=lib/public-domains.sh
source "$SCRIPT_DIR/lib/public-domains.sh"
set_public_domain_defaults

cd "$PARTH_DIR"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "[deploy-abi-pending] building release artifacts and bundle"
  PACKAGE_ARTIFACTS=1 BUILD_PARTH_BUNDLE=1 \
    bash deploy/scripts/build-linux-artifacts-bookworm.sh
else
  echo "[deploy-abi-pending] SKIP_BUILD=1; using existing bundle"
fi

bundle="${PARTH_BUNDLE:-$PARTH_DIR/dist/parth-node-bundle.tar.gz}"
if [ ! -f "$bundle" ]; then
  echo "missing bundle: $bundle" >&2
  echo "run without SKIP_BUILD=1, or set PARTH_BUNDLE=/path/to/parth-node-bundle.tar.gz" >&2
  exit 1
fi

echo "[deploy-abi-pending] deploying psy-services only"
PARTH_BUNDLE="$bundle" \
PSY_SERVICES_RUN_MIGRATIONS="${PSY_SERVICES_RUN_MIGRATIONS:-true}" \
  bash deploy/gcp/deploy-psy-services.sh

services_url="https://${PUBLIC_PSY_SERVICES_DOMAIN}"
echo "[deploy-abi-pending] checking $services_url/health"
curl -fsS "$services_url/health" >/dev/null
echo "[deploy-abi-pending] psy-services health ok"

if [ "${RUN_ABI_DEPLOY_TEST:-0}" = "1" ]; then
  echo "[deploy-abi-pending] running deploy-contract-with-abi smoke test"
  PARTH_BUNDLE="$bundle" bash deploy/gcp/test-staging-deploy-contract-with-abi.sh
fi
