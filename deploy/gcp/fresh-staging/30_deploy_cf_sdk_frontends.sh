#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[30_deploy_cf_sdk_frontends.sh] deploying frontends that depend on @psy-protocol/psy-sdk"

bash "$SCRIPT_DIR/21_deploy_cf_privacy_bridge_demo.sh"
bash "$SCRIPT_DIR/26_deploy_cf_psy_explorer.sh"
bash "$SCRIPT_DIR/28_deploy_cf_psy_ide.sh"

echo "[30_deploy_cf_sdk_frontends.sh] completed"
