#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cloudflared_bin="$(local_deploy_cloudflared)"
while IFS= read -r host; do
  echo "[local-multichain] routing $host -> $(local_deploy_tunnel_ref)"
  "$cloudflared_bin" tunnel route dns --overwrite-dns "$(local_deploy_tunnel_ref)" "$host"
done < <(local_deploy_hosts)
