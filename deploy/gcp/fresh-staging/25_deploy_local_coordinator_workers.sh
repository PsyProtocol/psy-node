#!/usr/bin/env bash
set -euo pipefail

FRESH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$FRESH_DIR/../../.." && pwd)"

bash "$PARTH_DIR/deploy/local-coordinator-workers/prepare-local-coordinator-workers.sh"
bash "$PARTH_DIR/deploy/local-coordinator-workers/install-systemd-user-services.sh"

if [ "${START_LOCAL_COORDINATOR_WORKERS:-0}" = "1" ]; then
  bash "$PARTH_DIR/deploy/local-coordinator-workers/start-systemd-user-services.sh"
else
  cat <<'EOF'
Local coordinator worker services are installed but not started.

Start them with:
  bash deploy/local-coordinator-workers/start-systemd-user-services.sh

Or run this wrapper with:
  START_LOCAL_COORDINATOR_WORKERS=1 bash deploy/gcp/fresh-staging/25_deploy_local_coordinator_workers.sh
EOF
fi
