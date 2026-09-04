#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_render_all

echo "[local-cf-tunnel] cloudflared config: $LOCAL_CF_CONFIG_FILE"
echo "[local-cf-tunnel] tunnel chain config: $LOCAL_CF_CHAIN_CONFIG_FILE"
echo
local_cf_print_urls
