#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGED_ROOT="${STAGED_ROOT:-$HOME/parth-prove-proxy}"
RELEASE_ID="${RELEASE_ID:?set RELEASE_ID to the staged release ID}"

CONFIG="${CONFIG:-$HOME/parth-wg0-gateway.conf}" \
  bash "$SCRIPT_DIR/arc99x2-install-wireguard.sh"

bash "$SCRIPT_DIR/arc99x2-host-preflight.sh"

export RELEASE_ID
export STAGED_ROOT
export STAGED_RELEASE="$STAGED_ROOT/staged-release-$RELEASE_ID"
export STAGED_SETUP="$STAGED_ROOT/staged-setup"
bash "$SCRIPT_DIR/arc99x2-install-staged.sh"

# A new release changes /opt/parth/current while the old process may still be
# active. `enable --now` does not restart an already-running unit.
sudo systemctl enable parth-offsite-prove-proxy.service
sudo systemctl restart parth-offsite-prove-proxy.service

deadline=$((SECONDS + 300))
while ((SECONDS < deadline)); do
  response="$(curl -sS --max-time 5 http://10.250.0.12:9999 \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_fn_id","params":[0,"simple_claim"]}' || true)"
  if jq -e '.result == 4' >/dev/null 2>&1 <<<"$response"; then
    echo "offsite prove-proxy is ready: $response"
    sudo systemctl status parth-offsite-prove-proxy.service --no-pager --full -n 50
    exit 0
  fi
  if ! sudo systemctl is-active --quiet parth-offsite-prove-proxy.service; then
    sudo systemctl status parth-offsite-prove-proxy.service --no-pager --full -n 80 || true
    sudo journalctl -u parth-offsite-prove-proxy.service -n 120 --no-pager || true
    exit 1
  fi
  sleep 5
done

echo "timed out waiting for offsite prove-proxy" >&2
sudo journalctl -u parth-offsite-prove-proxy.service -n 120 --no-pager || true
exit 1
