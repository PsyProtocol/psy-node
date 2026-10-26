#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${LOCAL_RELAYER_SERVICE_NAME:-parth-local-relayer.service}"

systemctl --user status "$SERVICE_NAME" --no-pager --full || true
echo
echo "recent logs:"
journalctl --user -u "$SERVICE_NAME" --no-pager -n "${LOCAL_RELAYER_LOG_LINES:-80}" || true
