#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$PARTH_DIR/deploy/gcp/config.env}"
RUNTIME_DIR="${LOCAL_COORDINATOR_WORKERS_DIR:-$PARTH_DIR/dist/local-coordinator-workers}"
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
ENV_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/parth-local-coordinator-workers"
ENV_FILE="${LOCAL_COORDINATOR_WORKERS_ENV_FILE:-$ENV_DIR/env}"
TUNNEL_SERVICE="parth-local-coordinator-worker-tunnel.service"
WORKER_SERVICE_TEMPLATE="parth-local-coordinator-worker@.service"

[ -f "$CONFIG_FILE" ] || {
  echo "missing config file: $CONFIG_FILE" >&2
  exit 1
}

set -a
# shellcheck source=../gcp/config.env
source "$CONFIG_FILE"
set +a

if [ ! -x "$RUNTIME_DIR/run-worker.sh" ]; then
  echo "missing runtime at $RUNTIME_DIR; preparing it first"
  LOCAL_COORDINATOR_WORKERS_DIR="$RUNTIME_DIR" bash "$SCRIPT_DIR/prepare-local-coordinator-workers.sh"
fi

mkdir -p "$SYSTEMD_USER_DIR" "$ENV_DIR"

cat > "$ENV_FILE" <<EOF
LOCAL_SSH_JUMP_HOST=${LOCAL_SSH_JUMP_HOST:-gcp-cp-ce}
LOCAL_SCYLLA_HOST=${LOCAL_SCYLLA_HOST:-${SCYLLA_HOST:-10.148.0.23}}
LOCAL_SCYLLA_PORT=${LOCAL_SCYLLA_PORT:-19042}
LOCAL_NATS_HOST=${LOCAL_NATS_HOST:-${NATS_HOST:-10.148.0.20}}
LOCAL_NATS_PORT=${LOCAL_NATS_PORT:-14222}
LOCAL_REDIS_HOST=${LOCAL_REDIS_HOST:-${REDIS_HOST:-10.148.0.12}}
LOCAL_REDIS_PORT=${LOCAL_REDIS_PORT:-16379}
EOF
chmod 0600 "$ENV_FILE"

cat > "$SYSTEMD_USER_DIR/$TUNNEL_SERVICE" <<EOF
[Unit]
Description=Parth Local Coordinator Worker VPC Tunnels
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/ssh -F $HOME/.ssh/config -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \\
  -L 127.0.0.1:\${LOCAL_SCYLLA_PORT}:\${LOCAL_SCYLLA_HOST}:9042 \\
  -L 127.0.0.1:\${LOCAL_NATS_PORT}:\${LOCAL_NATS_HOST}:4222 \\
  -L 127.0.0.1:\${LOCAL_REDIS_PORT}:\${LOCAL_REDIS_HOST}:6379 \\
  \${LOCAL_SSH_JUMP_HOST}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

cat > "$SYSTEMD_USER_DIR/$WORKER_SERVICE_TEMPLATE" <<EOF
[Unit]
Description=Parth Local Coordinator Worker %i
Wants=network-online.target $TUNNEL_SERVICE
After=network-online.target $TUNNEL_SERVICE

[Service]
Type=simple
WorkingDirectory=$RUNTIME_DIR
EnvironmentFile=$RUNTIME_DIR/env
ExecStart=$RUNTIME_DIR/run-worker.sh %i
Restart=always
RestartSec=10
TimeoutStopSec=60
KillSignal=SIGINT
LimitNOFILE=1048576

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable "$TUNNEL_SERVICE"
systemctl --user enable parth-local-coordinator-worker@0.service
systemctl --user enable parth-local-coordinator-worker@1.service

echo "installed local coordinator worker services:"
echo "  $SYSTEMD_USER_DIR/$TUNNEL_SERVICE"
echo "  $SYSTEMD_USER_DIR/$WORKER_SERVICE_TEMPLATE"
echo
echo "start:"
echo "  systemctl --user start $TUNNEL_SERVICE"
echo "  systemctl --user start parth-local-coordinator-worker@0.service"
echo "  systemctl --user start parth-local-coordinator-worker@1.service"
echo
echo "logs:"
echo "  journalctl --user -u $TUNNEL_SERVICE -f"
echo "  journalctl --user -u 'parth-local-coordinator-worker@*.service' -f"
