#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${LOCAL_RELAYER_SERVICE_NAME:-parth-local-relayer.service}"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/$SERVICE_NAME"

systemctl --user disable --now "$SERVICE_NAME" 2>/dev/null || true
rm -f "$SERVICE_FILE"
systemctl --user daemon-reload

echo "removed user systemd service: $SERVICE_NAME"
echo "kept env file under: ${XDG_CONFIG_HOME:-$HOME/.config}/parth-local-relayer/env"
