#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${LOCAL_CF_AUTODEPLOY_SERVICE_NAME:-parth-local-frontend-autodeploy}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

systemctl --user disable --now "$SERVICE_NAME.timer" >/dev/null 2>&1 || true
systemctl --user stop "$SERVICE_NAME.service" >/dev/null 2>&1 || true
rm -f "$UNIT_DIR/$SERVICE_NAME.service" "$UNIT_DIR/$SERVICE_NAME.timer"
systemctl --user daemon-reload
echo "[local-cf-autodeploy] removed $SERVICE_NAME user service and timer"
