#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
APPLY_SCRIPT="$ROOT/deploy/offsite-prove-proxy/arc99x2-apply-staged.sh"
INSTALL_SCRIPT="$ROOT/deploy/offsite-prove-proxy/arc99x2-install-staged.sh"
GATEWAY_SCRIPT="$ROOT/deploy/offsite-prove-proxy/gateway-install-arc99x2-relays.sh"
UPLOAD_SCRIPT="$ROOT/deploy/offsite-prove-proxy/deploy-arc99x2-release.sh"
UNIT_TEMPLATE="$ROOT/deploy/offsite-prove-proxy/parth-prove-proxy@.service"

for role in user system; do
  grep -F "parth-prove-proxy@$role.service" "$APPLY_SCRIPT" >/dev/null || {
    echo "offsite prove release does not manage the $role unit" >&2
    exit 1
  }
done

grep -F 'for unit in parth-offsite-prove-proxy.service "${units[@]}"' "$APPLY_SCRIPT" >/dev/null || {
  echo "offsite prove release must retire the legacy singleton" >&2
  exit 1
}
grep -F "grep -q -- '--role'" "$INSTALL_SCRIPT" >/dev/null || {
  echo "offsite prove release must reject binaries without role support" >&2
  exit 1
}
grep -F 'psy_get_prove_proxy_role' "$APPLY_SCRIPT" >/dev/null || {
  echo "offsite prove release must gate readiness on the role RPC" >&2
  exit 1
}
grep -F 'psy_prove_deposit_batch_append_groth16' "$APPLY_SCRIPT" >/dev/null || {
  echo "user role must reject a system proof method" >&2
  exit 1
}
grep -F 'psy_get_circuits_data' "$APPLY_SCRIPT" >/dev/null || {
  echo "system role must reject a user proof method" >&2
  exit 1
}
grep -F 'trap stop_failed_candidate EXIT' "$APPLY_SCRIPT" >/dev/null || {
  echo "failed role startup must stop candidate units" >&2
  exit 1
}
if grep -Fq 'restart parth-offsite-prove-proxy.service' "$APPLY_SCRIPT"; then
  echo "failure handling must not claim rollback after replacing shared setup" >&2
  exit 1
fi

grep -F 'sudo -u parth test -x "$RELEASE_DIR"' \
  "$INSTALL_SCRIPT" >/dev/null || {
  echo "offsite prove release must be traversable by the service user" >&2
  exit 1
}

grep -F 'Environment=PROVE_PROXY_ROLE=%i' "$UNIT_TEMPLATE" >/dev/null
grep -F 'EnvironmentFile=/etc/parth/offsite-prove-proxy-%i.env' "$UNIT_TEMPLATE" >/dev/null
grep -F 'release ID already exists; choose a unique RELEASE_ID' "$INSTALL_SCRIPT" >/dev/null
if grep -Fq 'rm -rf "$RELEASE_DIR"' "$INSTALL_SCRIPT"; then
  echo "installer must never delete an existing release directory" >&2
  exit 1
fi
grep -F 'parth-prove-proxy@.service' "$UPLOAD_SCRIPT" >/dev/null || {
  echo "upload path must require and verify the live role unit template" >&2
  exit 1
}
grep -F 'bundle psy_user_cli does not support prove-proxy --role' "$UPLOAD_SCRIPT" >/dev/null || {
  echo "upload path must reject a bundle without role support before SSH" >&2
  exit 1
}

grep -F '"$VPC_ADDRESS:$GATEWAY_RELAY_PORT" "$ARC_WG_IP:$ARC_PROVE_PROXY_PORT"' \
  "$GATEWAY_SCRIPT" >/dev/null || {
  echo "public user proof relay is missing" >&2
  exit 1
}
grep -F '"$VPC_ADDRESS:$SYSTEM_GATEWAY_RELAY_PORT"' "$GATEWAY_SCRIPT" >/dev/null
grep -F '"$ARC_WG_IP:$ARC_SYSTEM_PROVE_PROXY_PORT" "$SYSTEM_PROVE_CLIENT_IP"' \
  "$GATEWAY_SCRIPT" >/dev/null
grep -F 'IPAddressDeny=any' "$GATEWAY_SCRIPT" >/dev/null

echo "[ok] offsite prove release installs independent role-gated services and private routing"

exit 0
