#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

ACTION="${ACTION:-status}"
TARGET_HOST="${TARGET_HOST:-}"
TARGET_PORT="${TARGET_PORT:-19999}"
CLOUD_UNIT="${CLOUD_UNIT:-parth-prove-proxy@0.service}"
FAUCET_UNIT="${FAUCET_UNIT:-parth-faucet-server.service}"
FORWARD_NAME="parth-offsite-prove-forwarder"
FORWARD_SOCKET="$FORWARD_NAME.socket"
FORWARD_SERVICE="$FORWARD_NAME.service"
CLOUD_DISABLE_DIR="/etc/systemd/system/$CLOUD_UNIT.d"
CLOUD_DISABLE_FILE="$CLOUD_DISABLE_DIR/offsite-disabled.conf"

socket_proxyd=""
for candidate in \
  "$(command -v systemd-socket-proxyd 2>/dev/null || true)" \
  /lib/systemd/systemd-socket-proxyd \
  /usr/lib/systemd/systemd-socket-proxyd; do
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    socket_proxyd="$candidate"
    break
  fi
done
[ -n "$socket_proxyd" ] || {
  echo "systemd-socket-proxyd is not installed" >&2
  exit 1
}

rpc_health() {
  local url="$1"
  local response

  response="$(curl -sS --fail --max-time 30 "$url" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_fn_id","params":[0,"simple_claim"]}')" ||
    return 1
  jq -e '.result == 4' >/dev/null <<<"$response"
}

install_forwarder() {
  cat >"/etc/systemd/system/$FORWARD_SOCKET" <<EOF
[Unit]
Description=Socket for offsite Parth prove-proxy forwarder

[Socket]
ListenStream=0.0.0.0:9999
NoDelay=true

[Install]
WantedBy=sockets.target
EOF

  cat >"/etc/systemd/system/$FORWARD_SERVICE" <<EOF
[Unit]
Description=Forward Parth prove-proxy traffic to WireGuard gateway
Requires=$FORWARD_SOCKET
After=network-online.target

[Service]
ExecStart=$socket_proxyd $TARGET_HOST:$TARGET_PORT
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
EOF
}

rollback_cloud() {
  systemctl disable --now "$FORWARD_SOCKET" >/dev/null 2>&1 || true
  systemctl stop "$FORWARD_SERVICE" >/dev/null 2>&1 || true
  rm -f "$CLOUD_DISABLE_FILE"
  rmdir "$CLOUD_DISABLE_DIR" 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable "$CLOUD_UNIT"
  systemctl restart "$CLOUD_UNIT"

  deadline=$((SECONDS + 300))
  while ((SECONDS < deadline)); do
    if rpc_health http://127.0.0.1:9999; then
      systemctl restart "$FAUCET_UNIT"
      echo "cloud prove-proxy restored"
      return 0
    fi
    if ! systemctl is-active --quiet "$CLOUD_UNIT"; then
      systemctl status "$CLOUD_UNIT" --no-pager --full -n 80 || true
      return 1
    fi
    sleep 5
  done
  echo "timed out waiting for cloud prove-proxy" >&2
  return 1
}

case "$ACTION" in
  cutover)
    : "${TARGET_HOST:?set TARGET_HOST to the WireGuard gateway VPC address}"
    rpc_health "http://$TARGET_HOST:$TARGET_PORT" || {
      echo "offsite prove-proxy is not healthy through gateway $TARGET_HOST:$TARGET_PORT" >&2
      exit 1
    }

    install_forwarder
    install -d -o root -g root -m 0755 "$CLOUD_DISABLE_DIR"
    cat >"$CLOUD_DISABLE_FILE" <<'EOF'
[Unit]
ConditionPathExists=/etc/parth/cloud-prove-proxy-enabled
EOF
    rm -f /etc/parth/cloud-prove-proxy-enabled
    systemctl daemon-reload
    systemctl disable "$CLOUD_UNIT" >/dev/null 2>&1 || true
    systemctl stop "$CLOUD_UNIT"
    systemctl reset-failed "$CLOUD_UNIT" >/dev/null 2>&1 || true

    if ! systemctl enable --now "$FORWARD_SOCKET"; then
      echo "forwarder failed to start; restoring cloud prove-proxy" >&2
      rollback_cloud
      exit 1
    fi
    if ! rpc_health http://127.0.0.1:9999; then
      echo "local forwarder health check failed; restoring cloud prove-proxy" >&2
      rollback_cloud
      exit 1
    fi

    systemctl restart "$FAUCET_UNIT"
    echo "cut over to offsite prove-proxy at $TARGET_HOST:$TARGET_PORT"
    ;;
  rollback)
    rollback_cloud
    ;;
  status)
    echo "Cloud prove-proxy:"
    systemctl is-enabled "$CLOUD_UNIT" 2>/dev/null || true
    systemctl is-active "$CLOUD_UNIT" 2>/dev/null || true
    echo
    echo "Offsite forwarder:"
    systemctl is-enabled "$FORWARD_SOCKET" 2>/dev/null || true
    systemctl is-active "$FORWARD_SOCKET" 2>/dev/null || true
    systemctl status "$FORWARD_SOCKET" --no-pager --full -n 30 || true
    echo
    echo "Local RPC:"
    if rpc_health http://127.0.0.1:9999; then
      echo "healthy"
    else
      echo "unhealthy"
      exit 1
    fi
    ;;
  *)
    echo "ACTION must be one of: cutover, rollback, status" >&2
    exit 1
    ;;
esac
