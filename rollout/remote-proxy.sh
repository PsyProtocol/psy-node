#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ "$(id -u)" != 0 ]; then exec sudo bash "$0" "${1:-deploy}"; fi
action=${1:-deploy}
unit=parth-offsite-prove-proxy.service
root=/opt/parth/role-rollouts/3a81f59e-proxy
envfile=/etc/parth/offsite-prove-proxy.env
url=http://10.250.0.12:9999
mkdir -p "$root"
chmod 0700 "$root"
exec 9>"$root/lock"
flock -n 9 || { echo 'Another proxy rollout is running'; exit 1; }
role_ready() {
  curl -fsS --max-time 5 "$url" -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_prove_proxy_role","params":[]}' |
    jq -e '.error == null and .result.role == "all" and .result.user_methods == true and .result.system_methods == true' >/dev/null
}
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
  replace "$root/backup/psy_user_cli" "$release/target/release/psy_user_cli" 0755
  replace "$root/backup/run-parth-service" "$release/deploy/bin/run-parth-service" 0755
  replace "$root/backup/proxy.env" "$envfile" "$(stat -c %a "$root/backup/proxy.env")"
  systemctl start "$unit"
  printf 'rolled-back\n' > "$root/state"
  echo 'Old proxy restored; waiting for its user RPC (it has no role RPC).'
  for _ in $(seq 1 240); do
    if curl -fsS --max-time 5 "$url" -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_circuits_data","params":[]}' |
      jq -e '.error == null and .result != null' >/dev/null; then
      echo 'Old proxy RPC ready'; return 0
    fi
    sleep 5
  done
  echo 'Rollback started, but old RPC readiness timed out' >&2
  return 1
}
case "$action" in
  verify) role_ready; systemctl show "$unit" -p ActiveState -p MainPID -p NRestarts; exit ;;
  rollback) restore; exit ;;
  deploy) ;;
  *) echo 'Usage: bash remote-proxy.sh deploy|verify|rollback' >&2; exit 2 ;;
esac
if [ -f "$root/state" ] && [ "$(cat "$root/state")" = applied ]; then
  role_ready
  echo 'This release is already applied'; exit
fi
(cd "$HERE/out-arch" && sha256sum -c SHA256SUMS)
"$HERE/out-arch/psy_user_cli" prove-proxy --help | grep -- --role >/dev/null
if ldd "$HERE/out-arch/psy_user_cli" 2>&1 | grep 'not found'; then exit 1; fi
systemctl is-active --quiet "$unit"
release=$(readlink -f /opt/parth/current)
pid=$(systemctl show "$unit" -p MainPID --value)
test "$(readlink -f "/proc/$pid/exe")" = "$release/target/release/psy_user_cli"
if [ ! -f "$root/backup/READY" ]; then
  mkdir -p "$root/backup"
  cp -p "$release/target/release/psy_user_cli" "$root/backup/"
  cp -p "$release/deploy/bin/run-parth-service" "$root/backup/"
  cp -p "$envfile" "$root/backup/proxy.env"
  printf '%s\n' "$release" > "$root/backup/release"
  sha256sum "$release/genesis.json" "$release/client_prover/config.json" > "$root/backup/preserved.sha256"
  touch "$root/backup/READY"
fi
test "$(cat "$root/backup/release")" = "$release"
awk '!/^PROVE_PROXY_ROLE=/' "$envfile" > "$root/proxy.env"
printf 'PROVE_PROXY_ROLE=all\n' >> "$root/proxy.env"
changed=0
finish() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ] && [ "$changed" = 1 ]; then
    echo 'Deployment failed; rolling back proxy only' >&2
    restore || true
  fi
  exit "$rc"
}
trap finish EXIT
changed=1
systemctl stop "$unit"
replace "$HERE/out-arch/psy_user_cli" "$release/target/release/psy_user_cli" 0755
replace "$HERE/out-arch/run-parth-service" "$release/deploy/bin/run-parth-service" 0755
replace "$root/proxy.env" "$envfile" "$(stat -c %a "$envfile")"
systemctl start "$unit"
echo 'Proxy is starting role=all; circuit/keystore loading may take several minutes.'
ready=0
for attempt in $(seq 1 240); do
  if role_ready 2>/dev/null; then ready=1; break; fi
  if [ "$((attempt % 12))" = 0 ]; then
    systemctl show "$unit" -p ActiveState -p MainPID -p NRestarts -p MemoryCurrent
  fi
  sleep 5
done
test "$ready" = 1
sha256sum -c "$root/backup/preserved.sha256"
printf 'applied\n' > "$root/state"
systemctl show "$unit" -p ActiveState -p MainPID -p NRestarts
echo 'SUCCESS: proxy role=all. Relayer may now be upgraded.'
