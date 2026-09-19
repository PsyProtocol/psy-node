#!/usr/bin/env bash
set -euo pipefail

role="${1:?Usage: repair-release-readability.sh proxy|workers}"
release_id="${RELEASE_ID:?Set the installed release ID}"
genesis_sha="${GENESIS_SHA256:?Set the verified Genesis SHA256}"
binary_sha="${BINARY_SHA256:?Set the verified binary SHA256}"
[[ "$release_id" =~ ^[A-Za-z0-9._-]+$ ]] || exit 1
[[ "$genesis_sha" =~ ^[a-f0-9]{64}$ && "$binary_sha" =~ ^[a-f0-9]{64}$ ]] || exit 1
release="/opt/parth/releases/$release_id"
case "$role" in
  proxy)
    command -v curl >/dev/null
    command -v jq >/dev/null
    units=(parth-prove-proxy@user.service parth-prove-proxy@system.service)
    binary=psy_user_cli
    ;;
  workers)
    [ "${CONFIRM_CLOUD_BASELINE_READY:-0}" = 1 ] || exit 1
    units=(parth-offsite-worker@coordinator.service parth-offsite-worker@realm-0.service parth-offsite-worker@realm-1.service)
    binary=psy_worker_cli
    ;;
  *) exit 1 ;;
esac
sudo -v
[ "$(readlink -f /opt/parth/current)" = "$release" ] || {
  echo 'Current release differs; refusing to modify it' >&2; exit 1;
}
for unit in "${units[@]}"; do
  state="$(systemctl show "$unit" -p ActiveState --value)"
  [[ "$state" == inactive || "$state" == failed ]] &&
    [ "$(systemctl show "$unit" -p MainPID --value)" = 0 ] || {
      echo "Stop $unit before repair" >&2; exit 1;
    }
done
printf '%s  %s\n' "$genesis_sha" "$release/genesis.json" \
  "$binary_sha" "$release/target/release/$binary" | sudo sha256sum -c -
sudo test ! -L "$release/genesis.json"
sudo test -f "$release/genesis.json"
if [ "$role" = proxy ]; then
  sudo test ! -L "$release/client_prover"
  sudo test -d "$release/client_prover"
  sudo test ! -L "$release/client_prover/config.json"
  sudo test -f "$release/client_prover/config.json"
  config_before="$(sudo sha256sum "$release/client_prover/config.json")"
  sudo chown root:parth "$release/client_prover" "$release/client_prover/config.json"
  sudo chmod 0750 "$release/client_prover"
  sudo chmod 0640 "$release/client_prover/config.json"
  sudo -u parth test -r "$release/client_prover/config.json"
  [ "$config_before" = "$(sudo sha256sum "$release/client_prover/config.json")" ]
else
  staged_etc="${STAGED_ETC:?Set the verified fresh worker env directory}"
  for worker in coordinator realm-0 realm-1; do
    sudo cmp "$staged_etc/offsite-worker-$worker.env" "/etc/parth/offsite-worker-$worker.env"
  done
  archive="/var/lib/parth/checkpoints/archive-$release_id-$(date -u +%Y%m%dT%H%M%SZ)"
  sudo install -d -o parth -g parth -m 0750 "$archive"
  sudo find /var/lib/parth/checkpoints -maxdepth 1 -type f -name '*.backup' -exec mv -t "$archive" {} +
fi
sudo chown root:parth "$release/genesis.json"
sudo chmod 0640 "$release/genesis.json"
sudo -u parth test -r "$release/genesis.json"
printf '%s  %s\n' "$genesis_sha" "$release/genesis.json" | sudo sha256sum -c -

stop_on_failure() {
  rc=$?
  trap - EXIT
  sudo systemctl disable --now "${units[@]}" || true
  echo 'Startup check failed; repaired candidate stopped. Inspect journals.' >&2
  exit "$rc"
}
trap stop_on_failure EXIT
sudo systemctl reset-failed "${units[@]}"
sudo systemctl enable --now "${units[@]}"
if [ "$role" = proxy ]; then
  deadline=$((SECONDS + 1200))
  ready=0
  while ((SECONDS < deadline)); do
    ready=1
    for entry in user:9999 system:9998; do
      name="${entry%:*}"; port="${entry#*:}"
      sudo systemctl is-active --quiet "parth-prove-proxy@$name.service"
      if ! curl -fsS --max-time 5 "http://10.250.0.12:$port" \
        -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_prove_proxy_role","params":[]}' 2>/dev/null |
        jq -e --arg role "$name" '.error == null and .result.role == $role and .result.user_methods == ($role == "user") and .result.system_methods == ($role == "system")' >/dev/null; then
        ready=0
      fi
    done
    [ "$ready" = 1 ] && break
    sleep 5
  done
  [ "$ready" = 1 ] || { echo 'Timed out waiting for prove roles' >&2; exit 1; }
else
  sleep 20
fi
for unit in "${units[@]}"; do
  sudo systemctl is-active --quiet "$unit"
  [ "$(systemctl show "$unit" -p NRestarts --value)" = 0 ]
  systemctl show "$unit" -p Id -p ActiveState -p MainPID -p NRestarts
done
trap - EXIT
echo 'Readability repaired without changing Genesis/config contents. Startup checks passed.'
