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
LOCAL_HOST="${LOCAL_PROVE_PROXY_TUNNEL_LOCAL_HOST:-127.0.0.1}"
LOCAL_PORT="${LOCAL_PROVE_PROXY_TUNNEL_LOCAL_PORT:-9999}"
SERVICE_NAME="${LOCAL_PROVE_PROXY_TUNNEL_SERVICE_NAME:-parth-local-prove-proxy-tunnel.service}"
MONITOR_SERVICE_NAME="${LOCAL_PROVE_PROXY_TUNNEL_MONITOR_SERVICE_NAME:-parth-local-prove-proxy-tunnel-monitor.service}"
MONITOR_TIMER_NAME="${LOCAL_PROVE_PROXY_TUNNEL_MONITOR_TIMER_NAME:-parth-local-prove-proxy-tunnel-monitor.timer}"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
ENV_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/parth-local-prove-proxy"
ENV_FILE="${LOCAL_PROVE_PROXY_TUNNEL_ENV_FILE:-$ENV_DIR/tunnel.env}"
SERVICE_FILE="$SYSTEMD_USER_DIR/$SERVICE_NAME"
MONITOR_SERVICE_FILE="$SYSTEMD_USER_DIR/$MONITOR_SERVICE_NAME"
MONITOR_TIMER_FILE="$SYSTEMD_USER_DIR/$MONITOR_TIMER_NAME"
CHECK_SCRIPT="$ENV_DIR/check-tunnel.sh"

mkdir -p "$SYSTEMD_USER_DIR" "$ENV_DIR"

cat > "$ENV_FILE" <<EOF
SSH_CONFIG=$SSH_CONFIG
REMOTE_HOST=$REMOTE_HOST
REMOTE_BIND_ADDR=$REMOTE_BIND_ADDR
REMOTE_PORT=$REMOTE_PORT
LOCAL_HOST=$LOCAL_HOST
LOCAL_PORT=$LOCAL_PORT
TUNNEL_SERVICE_NAME=$SERVICE_NAME
EOF
chmod 0600 "$ENV_FILE"

cat > "$CHECK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${SSH_CONFIG:?}"
: "${REMOTE_HOST:?}"
: "${REMOTE_BIND_ADDR:?}"
: "${REMOTE_PORT:?}"
: "${LOCAL_HOST:?}"
: "${LOCAL_PORT:?}"
: "${TUNNEL_SERVICE_NAME:?}"

if ! timeout 5 bash -lc "</dev/tcp/${LOCAL_HOST}/${LOCAL_PORT}" >/dev/null 2>&1; then
  echo "local prove proxy is not reachable at ${LOCAL_HOST}:${LOCAL_PORT}" >&2
  systemctl --user restart "$TUNNEL_SERVICE_NAME"
  exit 1
fi

if ! ssh -F "$SSH_CONFIG" -o BatchMode=yes -o ConnectTimeout=5 "$REMOTE_HOST" \
  "timeout 5 bash -lc '</dev/tcp/${REMOTE_BIND_ADDR}/${REMOTE_PORT}'" >/dev/null 2>&1; then
  echo "remote tunnel is not reachable at ${REMOTE_BIND_ADDR}:${REMOTE_PORT}; restarting tunnel" >&2
  systemctl --user restart "$TUNNEL_SERVICE_NAME"
  exit 1
fi
EOF
chmod 0755 "$CHECK_SCRIPT"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Parth Local Prove Proxy Reverse Tunnel
Wants=network-online.target parth-local-prove-proxy.service
After=network-online.target parth-local-prove-proxy.service

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/ssh -F "\${SSH_CONFIG}" -N -T \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=15 \\
  -o ServerAliveCountMax=3 \\
  -o TCPKeepAlive=yes \\
  -R "\${REMOTE_BIND_ADDR}:\${REMOTE_PORT}:\${LOCAL_HOST}:\${LOCAL_PORT}" \\
  "\${REMOTE_HOST}"
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

cat > "$MONITOR_SERVICE_FILE" <<EOF
[Unit]
Description=Check Parth Local Prove Proxy Reverse Tunnel

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
ExecStart=$CHECK_SCRIPT
EOF

cat > "$MONITOR_TIMER_FILE" <<EOF
[Unit]
Description=Monitor Parth Local Prove Proxy Reverse Tunnel

[Timer]
OnBootSec=20
OnUnitActiveSec=${LOCAL_PROVE_PROXY_TUNNEL_MONITOR_INTERVAL:-30}
AccuracySec=5
Unit=$MONITOR_SERVICE_NAME

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable "$SERVICE_NAME"
systemctl --user enable "$MONITOR_TIMER_NAME"

echo "installed tunnel service: $SERVICE_FILE"
echo "installed tunnel monitor timer: $MONITOR_TIMER_FILE"
echo "env file: $ENV_FILE"
echo
echo "start:"
echo "  systemctl --user start parth-local-prove-proxy.service"
echo "  systemctl --user start $SERVICE_NAME"
echo "  systemctl --user start $MONITOR_TIMER_NAME"
echo
echo "logs:"
echo "  journalctl --user -u $SERVICE_NAME -f"
