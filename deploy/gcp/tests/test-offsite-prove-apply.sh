#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SOURCE="$ROOT/deploy/offsite-prove-proxy"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local case_dir="$1" role_support="$2"
  local scripts="$case_dir/scripts" staged="$case_dir/staged"
  mkdir -p "$scripts" "$case_dir/bin" "$case_dir/root/etc/systemd/system" \
    "$staged/staged-release-case/target/release" \
    "$staged/staged-release-case/deploy/bin" \
    "$staged/staged-release-case/client_prover" \
    "$staged/staged-setup"/{bridge,deposit_batch_append,withdrawal_claim}

  cp "$SOURCE/arc99x2-apply-staged.sh" "$SOURCE/arc99x2-install-staged.sh" \
    "$SOURCE/parth-prove-proxy@.service" "$scripts/"
  sed -i \
    -e "s|/opt/parth|$case_dir/root/opt/parth|g" \
    -e "s|/var/lib/parth|$case_dir/root/var/lib/parth|g" \
    -e "s|/etc/systemd/system|$case_dir/root/etc/systemd/system|g" \
    -e "s|/etc/parth|$case_dir/root/etc/parth|g" \
    -e 's/deadline=$((SECONDS + 1200))/deadline=$((SECONDS + 1))/' \
    "$scripts/arc99x2-apply-staged.sh" "$scripts/arc99x2-install-staged.sh" \
    "$scripts/parth-prove-proxy@.service"

  printf '#!/usr/bin/env bash\nexit 0\n' >"$scripts/arc99x2-install-wireguard.sh"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$scripts/arc99x2-host-preflight.sh"
  chmod +x "$scripts/"*.sh

  if [ "$role_support" = 1 ]; then
    cat >"$staged/staged-release-case/target/release/psy_user_cli" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Usage: psy_user_cli prove-proxy --role <ROLE>'
EOF
  else
    cat >"$staged/staged-release-case/target/release/psy_user_cli" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Usage: psy_user_cli prove-proxy'
EOF
  fi
  chmod +x "$staged/staged-release-case/target/release/psy_user_cli"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$staged/staged-release-case/deploy/bin/run-parth-service"
  chmod +x "$staged/staged-release-case/deploy/bin/run-parth-service"
  printf 'fixture\n' >"$staged/staged-release-case/BUILD-MANIFEST.env"
  cat >"$staged/staged-release-case/client_prover/config.json" <<'EOF'
{"defaultNetwork":"testnet","networks":{"testnet":{}}}
EOF
  for kind in bridge deposit_batch_append withdrawal_claim; do
    for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
      printf '%s-%s\n' "$kind" "$file" >"$staged/staged-setup/$kind/$file"
    done
  done

  make_mocks "$case_dir"
}

make_mocks() {
  local case_dir="$1"
  local bin="$case_dir/bin"
  cat >"$bin/sudo" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = -u ]; then shift 2; fi
exec "$@"
EOF
  cat >"$bin/id" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = -u ] && [ "${2:-}" = parth ]; then echo 1001; exit 0; fi
if [ "${1:-}" = -u ] && [ "${2:-}" = psy ]; then exit 1; fi
exec /usr/bin/id "$@"
EOF
  cat >"$bin/install" <<'EOF'
#!/usr/bin/env bash
args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|-g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec /usr/bin/install "${args[@]}"
EOF
  cat >"$bin/chown" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  cat >"$bin/ln" <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/ln "$@"
EOF
  cat >"$bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_LOG"
command="${1:-}"
shift || true
case "$command" in
  cat)
    case "${1:-}" in parth-prove-proxy@*) exit 0 ;; *) exit 1 ;; esac
    ;;
  is-active) exit 0 ;;
  show)
    unit="${1:-}"
    if [[ " $* " == *" MainPID "* ]]; then
      case "$unit" in
        parth-prove-proxy@user.service) echo 4101 ;;
        parth-prove-proxy@system.service)
          if [ "$TEST_MODE" = same_pid ]; then echo 4101; else echo 4102; fi
          ;;
        *) echo 0 ;;
      esac
    fi
    ;;
  *) exit 0 ;;
esac
EOF
  cat >"$bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *psy_prove_deposit_batch_append_groth16* ]] ||
   [[ "$args" == *psy_get_circuits_data* ]]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}'
elif [[ "$args" == *:9999* ]]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"role":"user","user_methods":true,"system_methods":false}}'
elif [ "$TEST_MODE" = invalid_role ]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"role":"user","user_methods":true,"system_methods":false}}'
else
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"role":"system","user_methods":false,"system_methods":true}}'
fi
EOF
  cat >"$bin/sleep" <<'EOF'
#!/usr/bin/env bash
/usr/bin/sleep 1
EOF
  cat >"$bin/journalctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$bin/"*
}

run_case() {
  local name="$1" mode="$2" role_support="$3" expected="$4"
  local case_dir="$tmp/$name" output rc=0
  make_fixture "$case_dir" "$role_support"
  : >"$case_dir/systemctl.log"
  output="$(
    PATH="$case_dir/bin:$PATH" \
    MOCK_LOG="$case_dir/systemctl.log" \
    TEST_MODE="$mode" \
    STAGED_ROOT="$case_dir/staged" \
    RELEASE_ID=case \
    CONFIG="$case_dir/wg.conf" \
      bash "$case_dir/scripts/arc99x2-apply-staged.sh" 2>&1
  )" || rc=$?
  if [ "$expected" = success ]; then
    [ "$rc" -eq 0 ] || { printf '%s\n' "$output" >&2; return 1; }
    test -L "$case_dir/root/opt/parth/current"
    grep -Fq 'restart parth-prove-proxy@user.service parth-prove-proxy@system.service' "$case_dir/systemctl.log"
    jq -e '.networks.testnet.prove_proxy_url == ["http://10.250.0.12:9999"] and
           .networks.testnet.system_prove_proxy_url == ["http://10.250.0.12:9998"]' \
      "$case_dir/root/opt/parth/releases/case/client_prover/config.json" >/dev/null
  else
    [ "$rc" -ne 0 ] || { echo "$name unexpectedly succeeded" >&2; return 1; }
  fi
  printf '%s\n' "$output" >"$case_dir/output.log"
}

run_case fresh-success success 1 success
run_case invalid-role invalid_role 1 failure
grep -Fq 'disable --now parth-prove-proxy@user.service parth-prove-proxy@system.service' \
  "$tmp/invalid-role/systemctl.log"

run_case same-pid same_pid 1 failure
grep -Fq 'offsite prove-proxy roles are not independent processes' "$tmp/same-pid/output.log"
grep -Fq 'disable --now parth-prove-proxy@user.service parth-prove-proxy@system.service' \
  "$tmp/same-pid/systemctl.log"

run_case old-binary success 0 failure
if grep -Eq 'disable --now|restart parth-prove-proxy@' "$tmp/old-binary/systemctl.log"; then
  echo "old binary reached service activation" >&2
  exit 1
fi
grep -Fq 'does not support prove-proxy --role' "$tmp/old-binary/output.log"

echo "[ok] mocked offsite apply covers fresh success and fail-closed role activation"
