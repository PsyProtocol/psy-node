#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

local_cf_ensure_cloudflared
local_cf_render_cloudflared_config

echo "[local-cf-tunnel] using config: $LOCAL_CF_CONFIG_FILE"
echo "[local-cf-tunnel] tunnel: $(local_cf_tunnel_ref)"
echo
local_cf_print_urls
echo

if [ "$#" -gt 0 ]; then
  exec cloudflared "$@"
fi

exec cloudflared tunnel --config "$LOCAL_CF_CONFIG_FILE" run "$(local_cf_tunnel_ref)"
