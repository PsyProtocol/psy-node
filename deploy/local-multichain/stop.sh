#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_deploy_stop_pid cloudflared "$LOCAL_DEPLOY_PID_DIR/cloudflared.pid"
local_deploy_stop_pid "config page" "$LOCAL_DEPLOY_PID_DIR/config-page.pid"
local_deploy_stop_pid eth-faucet "$LOCAL_DEPLOY_PID_DIR/eth-faucet.pid"
local_deploy_stop_pid bsc-faucet "$LOCAL_DEPLOY_PID_DIR/bsc-faucet.pid"
local_deploy_stop_pid base-faucet "$LOCAL_DEPLOY_PID_DIR/base-faucet.pid"
local_deploy_stop_pid devnet "$LOCAL_DEPLOY_PID_DIR/devnet.pid"

# If the supervisor PID was lost, use the native non-purging teardown to stop
# only known devnet processes/containers while retaining chain/database state.
if pgrep -f "$PSY_NODE_DIR/dev/locSetupV4.ts" >/dev/null 2>&1; then
  (cd "$PSY_NODE_DIR" && bun run dev/locSetupV4.ts --teardown) || true
fi

local_deploy_restore_dapp
local_deploy_restore_genesis_stamp
local_deploy_restore_node
echo "[local-multichain] stopped; local state preserved"
