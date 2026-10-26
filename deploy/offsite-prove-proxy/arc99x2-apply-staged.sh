#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGED_ROOT="${STAGED_ROOT:-$HOME/parth-prove-proxy}"
RELEASE_ID="${RELEASE_ID:?set RELEASE_ID to the staged release ID}"
OPS_READ_USER="${OPS_READ_USER:-psy}"

CONFIG="${CONFIG:-$HOME/parth-wg0-gateway.conf}" \
  bash "$SCRIPT_DIR/arc99x2-install-wireguard.sh"

bash "$SCRIPT_DIR/arc99x2-host-preflight.sh"

export RELEASE_ID
export STAGED_ROOT
export STAGED_RELEASE="$STAGED_ROOT/staged-release-$RELEASE_ID"
export STAGED_SETUP="$STAGED_ROOT/staged-setup"
bash "$SCRIPT_DIR/arc99x2-install-staged.sh"

units=(
  parth-prove-proxy@user.service
  parth-prove-proxy@system.service
)

stop_failed_candidate() {
  local rc=$?
  trap - EXIT
  sudo systemctl disable --now "${units[@]}" >/dev/null 2>&1 || true
  echo "role-scoped startup failed; candidate units were stopped" >&2
  echo "shared setup or release state may have changed; recover manually from reviewed state" >&2
  exit "$rc"
}
trap stop_failed_candidate EXIT

for unit in parth-offsite-prove-proxy.service "${units[@]}"; do
  if sudo systemctl cat "$unit" >/dev/null 2>&1; then
    sudo systemctl disable --now "$unit"
  fi
done

sudo install -d -o parth -g parth -m 0750 \
  /var/lib/parth \
  /var/lib/parth/.psy \
  /var/lib/parth/.psy/keystore \
  /var/lib/parth/.psy/keystore/deposit_append \
  /var/lib/parth/.psy/keystore/withdrawal_claim \
  /var/lib/parth/prove-captures/user \
  /var/lib/parth/prove-captures/system
if id -u "$OPS_READ_USER" >/dev/null 2>&1; then
  sudo chgrp -R "$OPS_READ_USER" /var/lib/parth/prove-captures
  sudo chmod 2750 /var/lib/parth/prove-captures/{user,system}
fi
install_setup_kind() {
  local source_kind="$1" target_dir="$2" file
  for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    sudo install -o parth -g parth -m 0600 \
      "/opt/parth/releases/$RELEASE_ID/groth16-keystore/$source_kind/$file" \
      "$target_dir/$file"
  done
}
install_setup_kind bridge /var/lib/parth/.psy/keystore
install_setup_kind deposit_batch_append /var/lib/parth/.psy/keystore/deposit_append
install_setup_kind withdrawal_claim /var/lib/parth/.psy/keystore/withdrawal_claim

sudo ln -sfn "/opt/parth/releases/$RELEASE_ID" /opt/parth/current
sudo systemctl reset-failed "${units[@]}" >/dev/null 2>&1 || true
sudo systemctl enable "${units[@]}"
sudo systemctl restart "${units[@]}"

rpc() {
  local port="$1" method="$2"
  curl -sS --max-time 5 "http://10.250.0.12:$port" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}"
}

roles_ready() {
  rpc 9999 psy_get_prove_proxy_role |
    jq -e '.error == null and .result.role == "user" and .result.user_methods == true and .result.system_methods == false' >/dev/null &&
    rpc 9998 psy_get_prove_proxy_role |
      jq -e '.error == null and .result.role == "system" and .result.user_methods == false and .result.system_methods == true' >/dev/null &&
    rpc 9999 psy_prove_deposit_batch_append_groth16 |
      jq -e '.error.code == -32601' >/dev/null &&
    rpc 9998 psy_get_circuits_data |
      jq -e '.error.code == -32601' >/dev/null
}

deadline=$((SECONDS + 1200))
while ((SECONDS < deadline)); do
  if roles_ready 2>/dev/null; then
    user_pid="$(sudo systemctl show "${units[0]}" -p MainPID --value)"
    system_pid="$(sudo systemctl show "${units[1]}" -p MainPID --value)"
    [ "$user_pid" -gt 0 ] && [ "$system_pid" -gt 0 ] && [ "$user_pid" != "$system_pid" ] || {
      echo "offsite prove-proxy roles are not independent processes" >&2
      exit 1
    }
    legacy_pid="$(sudo systemctl show parth-offsite-prove-proxy.service -p MainPID --value 2>/dev/null || true)"
    [ -z "$legacy_pid" ] || [ "$legacy_pid" = 0 ] || {
      echo "legacy offsite prove-proxy is still running" >&2
      exit 1
    }
    echo "offsite user and system prove-proxy roles are ready"
    sudo systemctl status "${units[@]}" --no-pager --full -n 50
    trap - EXIT
    exit 0
  fi
  for unit in "${units[@]}"; do
    if ! sudo systemctl is-active --quiet "$unit"; then
      sudo systemctl status "$unit" --no-pager --full -n 80 || true
      sudo journalctl -u "$unit" -n 120 --no-pager || true
      exit 1
    fi
  done
  sleep 5
done

echo "timed out waiting for role-scoped offsite prove-proxies" >&2
sudo journalctl -u 'parth-prove-proxy@*' -n 120 --no-pager || true
exit 1
