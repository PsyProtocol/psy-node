#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNTIME_DIR="${LOCAL_RELAYER_DIR:-$PARTH_DIR/dist/local-relayer}"
SERVICE_NAME="${LOCAL_RELAYER_SERVICE_NAME:-parth-local-relayer.service}"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/$SERVICE_NAME"
ENV_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/parth-local-relayer"
ENV_FILE="${LOCAL_RELAYER_ENV_FILE:-$ENV_DIR/env}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$PARTH_DIR/deploy/gcp/config.env}"

if [ -f "$CONFIG_FILE" ]; then
  set -a
  # shellcheck source=../gcp/config.env
  source "$CONFIG_FILE"
  set +a
fi

if [ ! -x "$RUNTIME_DIR/run.sh" ]; then
  echo "missing runtime at $RUNTIME_DIR; preparing it first"
  LOCAL_RELAYER_DIR="$RUNTIME_DIR" bash "$SCRIPT_DIR/prepare-local-relayer.sh"
fi

mkdir -p "$SYSTEMD_USER_DIR" "$ENV_DIR"

if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
# Required. Do not commit this file.
BRIDGE_RELAYER_L2_PRIVATE_KEY=${BRIDGE_RELAYER_L2_PRIVATE_KEY:-${RELAYER_L2_PRIVATE_KEY:-}}
WALLET_PASSWORD=${RELAYER_L2_WALLET_PASSWORD:-${L1_DEPLOYER_WALLET_PASSWORD:-${WALLET_PASSWORD:-}}}

# Optional.
RUST_LOG=info
EOF
  chmod 0600 "$ENV_FILE"
  echo "created env file: $ENV_FILE"
  echo "edit it before starting the service"
elif [ "${LOCAL_RELAYER_SYNC_ENV:-1}" = "1" ]; then
  tmp_env="$(mktemp)"
  sync_bridge_relayer_l2_private_key="${BRIDGE_RELAYER_L2_PRIVATE_KEY:-${RELAYER_L2_PRIVATE_KEY:-}}"
  sync_wallet_password="${RELAYER_L2_WALLET_PASSWORD:-${L1_DEPLOYER_WALLET_PASSWORD:-${WALLET_PASSWORD:-}}}"
  awk -F= \
    -v sync_bridge_relayer_l2_private_key="$sync_bridge_relayer_l2_private_key" \
    -v sync_wallet_password="$sync_wallet_password" \
    '
    BEGIN {
      seen_key = 0
      seen_password = 0
    }
    $1 == "BRIDGE_RELAYER_L2_PRIVATE_KEY" {
      print "BRIDGE_RELAYER_L2_PRIVATE_KEY=" sync_bridge_relayer_l2_private_key
      seen_key = 1
      next
    }
    $1 == "WALLET_PASSWORD" {
      print "WALLET_PASSWORD=" sync_wallet_password
      seen_password = 1
      next
    }
    { print }
    END {
      if (!seen_key) {
        print "BRIDGE_RELAYER_L2_PRIVATE_KEY=" sync_bridge_relayer_l2_private_key
      }
      if (!seen_password) {
        print "WALLET_PASSWORD=" sync_wallet_password
      }
    }
  ' "$ENV_FILE" > "$tmp_env"
  install -m 0600 "$tmp_env" "$ENV_FILE"
  rm -f "$tmp_env"
  echo "synced env file from config: $ENV_FILE"
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Parth Local Bridge Relayer
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
echo
echo "optional, keep it running after logout:"
echo "  loginctl enable-linger \"$USER\""
