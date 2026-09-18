#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ "$(id -u)" != 0 ]; then exec sudo bash "$0" "${1:-deploy}"; fi
action=${1:-deploy}
old=parth-offsite-prove-proxy.service
root=/opt/parth/role-rollouts/3a81f59e-split
release=/opt/parth/prove-proxy-role-releases/3a81f59e
template=/etc/systemd/system/parth-prove-proxy@.service
units=(parth-prove-proxy@user.service parth-prove-proxy@system.service)
mkdir -p "$root"
chmod 0700 "$root"
exec 9>"$root/lock"
flock -n 9 || exit 1
rpc() {
  curl -fsS --max-time 5 "http://10.250.0.12:$1" -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":[]}"
}
roles_ready() {
  rpc 9999 psy_get_prove_proxy_role | jq -e '.error == null and .result.role == "user" and .result.user_methods == true and .result.system_methods == false' >/dev/null &&
  rpc 9998 psy_get_prove_proxy_role | jq -e '.error == null and .result.role == "system" and .result.user_methods == false and .result.system_methods == true' >/dev/null
}
verify() {
  roles_ready
  rpc 9999 psy_prove_deposit_batch_append_groth16 | jq -e '.error.code == -32601' >/dev/null
  rpc 9998 psy_get_circuits_data | jq -e '.error.code == -32601' >/dev/null
  local user_pid system_pid
  user_pid=$(systemctl show "${units[0]}" -p MainPID --value)
  system_pid=$(systemctl show "${units[1]}" -p MainPID --value)
  test "$user_pid" -gt 0
  test "$system_pid" -gt 0
  test "$user_pid" != "$system_pid"
  test "$(readlink -f "/proc/$user_pid/exe")" = "$release/psy_user_cli"
  test "$(readlink -f "/proc/$system_pid/exe")" = "$release/psy_user_cli"
  test "$(systemctl show "$old" -p MainPID --value)" = 0
  systemctl show "${units[@]}" -p Id -p MainPID -p ActiveState -p NRestarts -p MemoryCurrent
}
restore() {
  test -f "$root/READY"
  systemctl disable --now "${units[@]}"
  if [ "$(cat "$root/old-enabled")" = enabled ]; then systemctl enable "$old"; fi
  systemctl reset-failed "$old"
  systemctl start "$old"
  printf 'rolled-back\n' > "$root/state"
  for _ in $(seq 1 240); do
    if rpc 9999 psy_get_circuits_data | jq -e '.error == null and .result != null' >/dev/null; then
      echo 'Previous single-process proxy restored'; return 0
    fi
    sleep 5
  done
  echo 'Old service started; RPC readiness timed out' >&2
  return 1
}
case "$action" in
  verify) verify; exit ;;
  rollback) restore; exit ;;
  deploy) ;;
  *) echo 'Usage: deploy|verify|rollback'; exit 2 ;;
esac
if [ -f "$root/state" ] && [ "$(cat "$root/state")" = applied ]; then verify; exit; fi
(cd "$HERE/out-arch" && sha256sum -c SHA256SUMS)
"$HERE/out-arch/psy_user_cli" prove-proxy --help | grep -- --role >/dev/null
if ldd "$HERE/out-arch/psy_user_cli" 2>&1 | grep 'not found'; then exit 1; fi
systemctl is-active --quiet "$old"
if ss -ltnH | awk '{print $4}' | grep -Eq ':9998$'; then
  echo 'Port 9998 is already occupied' >&2; exit 1
fi
if [ ! -f "$root/READY" ]; then
  test ! -e "$template"
  for unit in "${units[@]}"; do
    test ! -e "/etc/systemd/system/$unit"
    test ! -d "/etc/systemd/system/$unit.d"
  done
  systemctl is-enabled "$old" > "$root/old-enabled" || true
  sha256sum /opt/parth/current/genesis.json /opt/parth/current/client_prover/config.json \
    /opt/parth/current/target/release/psy_user_cli /opt/parth/current/deploy/bin/run-parth-service \
    /etc/parth/offsite-prove-proxy.env > "$root/preserved.sha256"
  touch "$root/READY"
fi
install -d -m 0755 "$release"
if [ -f "$release/psy_user_cli" ]; then
  cmp "$HERE/out-arch/psy_user_cli" "$release/psy_user_cli"
else
  install -m 0755 "$HERE/out-arch/psy_user_cli" "$release/psy_user_cli"
fi
install -m 0755 "$HERE/run-role.sh" "$release/run-role.sh"
install -m 0644 "$HERE/parth-prove-proxy@.service" "$template"
systemd-analyze verify "$template"
systemctl daemon-reload
changed=0
finish() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ] && [ "$changed" = 1 ]; then restore || true; fi
  exit "$rc"
}
trap finish EXIT
changed=1
systemctl disable --now "$old"
systemctl reset-failed "${units[@]}" || true
systemctl enable --now "${units[@]}"
echo 'Starting two independent processes: user :9999 and system :9998.'
ready=0
for attempt in $(seq 1 240); do
  if roles_ready 2>/dev/null; then ready=1; break; fi
  if [ "$((attempt % 12))" = 0 ]; then
    systemctl show "${units[@]}" -p Id -p MainPID -p ActiveState -p MemoryCurrent
  fi
  sleep 5
done
test "$ready" = 1
verify
sha256sum -c "$root/preserved.sha256"
printf 'applied\n' > "$root/state"
echo 'SUCCESS: user and system are separate processes. Activate the relayer system endpoint next.'
