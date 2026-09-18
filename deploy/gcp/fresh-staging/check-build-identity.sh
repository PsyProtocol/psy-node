#!/usr/bin/env bash
# Read-only gate for processes that load psy_config. Node/edge/worker binaries
# require a separate provenance check; this gate does not claim to cover them.
set -euo pipefail

expected_magic="${EXPECTED_MAGIC:-0x1337CF514544CF69}"
expected_stage="${EXPECTED_STAGE:-testnet}"
targets="${IDENTITY_TARGETS-arc99x3/parth-prove-proxy@user.service arc99x3/parth-prove-proxy@system.service gcp-faucet/parth-faucet-server.service gcp-faucet/parth-relayer.service}"
if [[ -v IDENTITY_HOSTS || -v IDENTITY_UNITS ]]; then
  echo 'Use IDENTITY_TARGETS="ssh-alias/unit.service ...", not IDENTITY_HOSTS/IDENTITY_UNITS' >&2
  exit 1
fi
if [[ -z "${targets//[[:space:]]/}" ]]; then
  echo 'IDENTITY_TARGETS must contain at least one host/unit pair' >&2
  exit 1
fi
if [[ ! "$expected_magic" =~ ^0[xX][[:xdigit:]]{16}$ ]]; then
  echo 'EXPECTED_MAGIC must be a 64-bit hex value with a 0x prefix' >&2
  exit 1
fi
case "$expected_stage" in localhost|testnet|mainnet) ;; *)
  echo 'EXPECTED_STAGE must be localhost, testnet, or mainnet' >&2; exit 1;;
esac

read -r -a target_list <<< "${targets//$'\n'/ }"
for target in "${target_list[@]}"; do
  if [[ ! "$target" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*/[a-zA-Z0-9][a-zA-Z0-9@_.-]*\.service$ ]]; then
    echo "Invalid host/unit pair: $target" >&2
    exit 1
  fi
done

ok=0
failed=0
for target in "${target_list[@]}"; do
  host="${target%%/*}"
  unit="${target#*/}"
  if ! output="$(ssh -F "${SSH_CONFIG:-$HOME/.ssh/config}" \
    -o BatchMode=yes -o ConnectTimeout=10 "$host" bash -s -- "$unit" <<'REMOTE'
set -euo pipefail
unit="$1"
active="$(systemctl show "$unit" -p ActiveState --value)"
pid="$(systemctl show "$unit" -p MainPID --value)"
invocation="$(systemctl show "$unit" -p InvocationID --value)"
[[ "$active" == active && "$pid" =~ ^[1-9][0-9]*$ && "$invocation" =~ ^[[:xdigit:]]{32}$ ]] || {
  echo "service is not active with a valid invocation: $unit" >&2; exit 1;
}
line="$(sudo -n journalctl -u "$unit" "_SYSTEMD_INVOCATION_ID=$invocation" -o cat --no-pager |
  awk '/psy build identity:/ { last=$0 } END { print last }')"
[[ -n "$line" ]] || { echo "no build identity in current invocation: $unit" >&2; exit 1; }
[[ "$(systemctl show "$unit" -p InvocationID --value)" == "$invocation" && "$(systemctl show "$unit" -p ActiveState --value)" == active ]] || {
  echo "service changed during inspection: $unit" >&2; exit 1;
}
printf '%s\n' "$line"
printf 'observed unit=%s pid=%s invocation=%s\n' "$unit" "$pid" "$invocation" >&2
REMOTE
  )"; then
    echo "FAIL $target: unable to verify current process"
    failed=$((failed + 1))
    continue
  fi
  magic="$(printf '%s\n' "$output" | sed -nE 's/.* magic=(0[xX][0-9a-fA-F]+).*/\1/p')"
  stage="$(printf '%s\n' "$output" | sed -nE 's/.* stage=([^ ]+).*/\1/p')"
  network="$(printf '%s\n' "$output" | sed -nE 's/.* config_network=([^ ]+).*/\1/p')"
  if [[ "${magic,,}" == "${expected_magic,,}" && "$stage" == "$expected_stage" && "$network" == "$expected_stage" ]]; then
    echo "OK $target: $output"
    ok=$((ok + 1))
  else
    echo "FAIL $target: expected stage=$expected_stage magic=$expected_magic config_network=$expected_stage; observed $output"
    failed=$((failed + 1))
  fi
done
echo "summary: ok=$ok failed=$failed expected=${#target_list[@]}"
[[ "$ok" -gt 0 && "$failed" -eq 0 && "$ok" -eq "${#target_list[@]}" ]]
