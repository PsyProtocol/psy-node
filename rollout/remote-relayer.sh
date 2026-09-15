#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ "$(id -u)" != 0 ]; then exec sudo bash "$0" "${1:-verify}"; fi
action=${1:-verify}
unit=parth-relayer.service
root=/opt/parth/role-rollouts/3a81f59e-relayer
config=/opt/parth/current/client_prover/config.json
url=http://10.148.0.32:19998
role_ready() {
  curl -fsS --max-time 10 "$url" -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_prove_proxy_role","params":[]}' |
    jq -e '.error == null and .result.role == "system" and .result.user_methods == false and .result.system_methods == true' >/dev/null
}
case "$action" in deploy|verify|rollback) ;; *) echo 'Usage: deploy|verify|rollback'; exit 2 ;; esac
if [ "$action" != rollback ]; then
  role_ready || { echo 'BLOCKED: dedicated system proxy is not ready; relayer was not modified.' >&2; exit 1; }
fi
if [ "$action" = verify ]; then
  systemctl show "$unit" -p ActiveState -p MainPID -p NRestarts
  jq -e --arg url "$url" '.networks[.defaultNetwork].system_prove_proxy_url == [$url]' "$config"
  exit
fi
mkdir -p "$root"
chmod 0700 "$root"
exec 9>"$root/lock"
flock -n 9 || exit 1
replace() {
  install -m "$3" "$1" "$2.role-next"
  chown --reference="$2" "$2.role-next"
  mv -fT "$2.role-next" "$2"
}
restore() {
  test -f "$root/backup/READY"
  local release
  release=$(cat "$root/backup/release")
  test "$(readlink -f /opt/parth/current)" = "$release"
  systemctl stop "$unit"
  replace "$root/backup/psy_relayer_cli" "$release/target/release/psy_relayer_cli" 0755
  replace "$root/backup/config.json" "$config" "$(stat -c %a "$root/backup/config.json")"
  systemctl start "$unit"
  printf 'rolled-back\n' > "$root/state"
  echo 'Old relayer restored; inspect progress separately from process state.'
}
if [ "$action" = rollback ]; then restore; exit; fi
(cd "$HERE/out" && sha256sum -c SHA256SUMS)
test "$(cat "$HERE/out/SOURCE_COMMIT")" = 3a81f59e0cf9333fc2ad4aefda7c83787660c9ab
"$HERE/out/psy_relayer_cli" --help >/dev/null
test "$(jq -r .defaultNetwork "$config")" = localhost
systemctl is-active --quiet "$unit"
release=$(readlink -f /opt/parth/current)
bin="$release/target/release/psy_relayer_cli"
pid=$(systemctl show "$unit" -p MainPID --value)
test "$(readlink -f "/proc/$pid/exe")" = "$bin"
if [ -f "$root/state" ] && [ "$(cat "$root/state")" = applied ]; then
  echo 'Release already applied'; exit
fi
if [ ! -f "$root/backup/READY" ]; then
  mkdir -p "$root/backup"
  cp -p "$bin" "$root/backup/"
  cp -p "$config" "$root/backup/config.json"
  printf '%s\n' "$release" > "$root/backup/release"
  sha256sum /etc/parth/common.env /etc/parth/relayer.env /etc/parth/bridge-relayer.toml \
    "$release/genesis.json" > "$root/backup/preserved.sha256"
  touch "$root/backup/READY"
fi
test "$(cat "$root/backup/release")" = "$release"
jq --arg url "$url" '.networks[.defaultNetwork].system_prove_proxy_url = [$url]' "$config" > "$root/config.json"
changed=0
finish() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ] && [ "$changed" = 1 ]; then restore || true; fi
  exit "$rc"
}
trap finish EXIT
changed=1
systemctl stop "$unit"
replace "$HERE/out/psy_relayer_cli" "$bin" 0755
replace "$root/config.json" "$config" "$(stat -c %a "$config")"
systemctl start "$unit"
pid=$(systemctl show "$unit" -p MainPID --value)
invocation=$(systemctl show "$unit" -p InvocationID --value)
ready=0
for _ in $(seq 1 60); do
  test "$(systemctl show "$unit" -p MainPID --value)" = "$pid"
  journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat > "$root/startup.log"
  if grep -q 'system prove proxy verified' "$root/startup.log"; then ready=1; break; fi
  sleep 2
done
test "$ready" = 1
sleep 10
systemctl is-active --quiet "$unit"
test "$(systemctl show "$unit" -p MainPID --value)" = "$pid"
sha256sum -c "$root/backup/preserved.sha256"
printf 'applied\n' > "$root/state"
systemctl show "$unit" -p MainPID -p ActiveState -p NRestarts
echo 'Relayer role handshake verified. L1 RPC quotas and bridge E2E require separate verification.'
