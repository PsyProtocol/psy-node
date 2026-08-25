#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$PARTH_DIR/deploy/gcp/config.env}"

[ -f "$CONFIG_FILE" ] || {
  echo "missing config file: $CONFIG_FILE" >&2
  exit 1
}

set -a
# shellcheck source=../gcp/config.env
source "$CONFIG_FILE"
set +a

SSH_CONFIG="${SSH_CONFIG:-$HOME/.ssh/config}"
REMOTE_HOST="${LOCAL_PROVE_PROXY_TUNNEL_HOST:-${PROVE_PROXY_VM_NAME:-gcp-prove-proxy}}"
REMOTE_BIND_ADDR="${LOCAL_PROVE_PROXY_TUNNEL_BIND_ADDR:-${PROVE_PROXY_HOST:-10.148.0.26}}"
REMOTE_PORT="${LOCAL_PROVE_PROXY_TUNNEL_REMOTE_PORT:-9999}"
DISABLE_CLOUD_PROVE_PROXY="${DISABLE_CLOUD_PROVE_PROXY:-1}"

echo "configuring reverse tunnel target: $REMOTE_HOST"
echo "remote bind target: ${REMOTE_BIND_ADDR}:${REMOTE_PORT}"

ssh -F "$SSH_CONFIG" "$REMOTE_HOST" \
  "set -euo pipefail
   sudo mkdir -p /etc/ssh/sshd_config.d
   tmp=\$(mktemp)
   {
     echo 'GatewayPorts clientspecified'
     echo 'AllowTcpForwarding yes'
     echo 'TCPKeepAlive yes'
   } > \"\$tmp\"
   sudo install -m 0644 \"\$tmp\" /etc/ssh/sshd_config.d/99-parth-reverse-tunnel.conf
   rm -f \"\$tmp\"
   if command -v systemctl >/dev/null 2>&1; then
     sudo systemctl restart ssh || sudo systemctl restart sshd
   else
     sudo service ssh restart || sudo service sshd restart
   fi
   if [ '$DISABLE_CLOUD_PROVE_PROXY' = '1' ]; then
     sudo systemctl stop parth-prove-proxy@0.service 2>/dev/null || true
     sudo systemctl disable parth-prove-proxy@0.service 2>/dev/null || true
   fi
   sudo ss -ltnp | grep ':$REMOTE_PORT' || true
   sudo sshd -T | grep -iE 'gatewayports|allowtcpforwarding'
  "

echo "remote tunnel target configured"
