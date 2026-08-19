#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

SERVICE_NAME="${LOCAL_CF_AUTODEPLOY_SERVICE_NAME:-parth-local-frontend-autodeploy}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_FILE="$UNIT_DIR/$SERVICE_NAME.service"
TIMER_FILE="$UNIT_DIR/$SERVICE_NAME.timer"
INTERVAL_SECONDS="${LOCAL_CF_AUTODEPLOY_INTERVAL_SECONDS:-120}"

command -v systemctl >/dev/null 2>&1 || {
  echo "[local-cf-autodeploy] systemctl is required" >&2
  exit 1
}

mkdir -p "$UNIT_DIR"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Parth local frontend-only auto deploy
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$LOCAL_CF_TOOLS_PARTH_DIR
Environment=LOCAL_CF_AUTODEPLOY_ONCE=1
Environment=PATH=$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.npm-global/bin:$HOME/.bun/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/lib/rustup/bin:$HOME/.foundry/bin
ExecStart=/usr/bin/env bash $SCRIPT_DIR/autodeploy-frontends.sh
TimeoutStartSec=6h
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=6

[Install]
WantedBy=default.target
EOF

cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Poll improve-relayer frontends every ${INTERVAL_SECONDS}s

[Timer]
OnBootSec=30s
OnUnitInactiveSec=${INTERVAL_SECONDS}s
AccuracySec=5s
Persistent=true
Unit=$SERVICE_NAME.service

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now "$SERVICE_NAME.timer"
systemctl --user start "$SERVICE_NAME.service"

echo "[local-cf-autodeploy] installed service: $SERVICE_FILE"
echo "[local-cf-autodeploy] installed timer:   $TIMER_FILE"
systemctl --user --no-pager status "$SERVICE_NAME.timer" || true
