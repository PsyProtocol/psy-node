#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNTIME_DIR="${LOCAL_PROVE_PROXY_DIR:-$PARTH_DIR/dist/local-prove-proxy}"
SERVICE_NAME="${LOCAL_PROVE_PROXY_SERVICE_NAME:-parth-local-prove-proxy.service}"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/$SERVICE_NAME"
ENV_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/parth-local-prove-proxy"
ENV_FILE="${LOCAL_PROVE_PROXY_ENV_FILE:-$ENV_DIR/env}"

if [ ! -x "$RUNTIME_DIR/run.sh" ]; then
  echo "missing runtime at $RUNTIME_DIR; preparing it first"
  LOCAL_PROVE_PROXY_DIR="$RUNTIME_DIR" bash "$SCRIPT_DIR/prepare-local-prove-proxy.sh"
fi

mkdir -p "$SYSTEMD_USER_DIR" "$ENV_DIR"

if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<'EOF'
RUST_LOG=info
LOCAL_PROVE_PROXY_LISTEN_ADDR=127.0.0.1:9999
EOF
  chmod 0600 "$ENV_FILE"
  echo "created env file: $ENV_FILE"
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Parth Local Prove Proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$RUNTIME_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$RUNTIME_DIR/run.sh
Restart=always
RestartSec=10
TimeoutStopSec=60
KillSignal=SIGINT
LimitNOFILE=1048576

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable "$SERVICE_NAME"

echo "installed user systemd service: $SERVICE_FILE"
echo "env file: $ENV_FILE"
echo
echo "start:"
echo "  systemctl --user start $SERVICE_NAME"
echo
echo "logs:"
echo "  journalctl --user -u $SERVICE_NAME -f"
