#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/sudo" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = -v ]; then exit 0; fi
exec "$@"
EOF
cat >"$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$TEST_LOG"
if [ "$1" = show ]; then
  case "$4" in
    LoadState)
      case "$2" in psy-notifier-*|parth-performance-*|parth-offsite-prove-*) echo not-found ;; *) echo loaded ;; esac
      ;;
    ActiveState) if [ "$TEST_MODE" = stuck ]; then echo active; else echo inactive; fi ;;
    MainPID) if [ "$TEST_MODE" = stuck ]; then echo 123; else echo 0; fi ;;
    *) exit 2 ;;
  esac
elif [ "$1" = disable ]; then
  [ "$TEST_MODE" != stop-failed ] || exit 1
else
  exit 2
fi
EOF
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH" TEST_LOG="$tmp/systemctl.log" TEST_MODE=ok
script="$ROOT/deploy/multi-chain/gcp/stop-offsite-for-fresh-deploy.sh"
bash "$script" prove >"$tmp/prove.log"
grep -Fxq 'disable --now parth-prove-proxy@user.service' "$TEST_LOG"
grep -Fxq 'disable --now parth-prove-proxy@system.service' "$TEST_LOG"
grep -Fxq 'disable --now parth-sentinel-collector.service' "$TEST_LOG"
if grep -E 'disable.*(notifier|performance|offsite-prove)' "$TEST_LOG"; then exit 1; fi
bash "$script" worker >"$tmp/worker.log"
for role in coordinator realm-0 realm-1; do
  grep -Fxq "disable --now parth-offsite-worker@$role.service" "$TEST_LOG"
done
for mode in stuck stop-failed; do
  if TEST_MODE="$mode" bash "$script" prove >"$tmp/$mode.log" 2>&1; then
    echo "unsafe stop success for $mode" >&2
    exit 1
  fi
done
if bash "$script" unsupported >"$tmp/invalid.log" 2>&1; then exit 1; fi

# Exercise step 01's remote gate without loading live deployment configuration.
# shellcheck disable=SC1090
source <(sed -n '/^verify_offsite_stopped() {/,/^}/p' "$ROOT/deploy/gcp/fresh-staging/01_stop_parth_services.sh")
log_step() { :; }
ssh() { printf '%s\n' "$@" >"$tmp/ssh-args"; }
export SSH_CONFIG_FILE="$tmp/missing-config"
verify_offsite_stopped mock-host worker
if grep -Fxq -- -F "$tmp/ssh-args"; then exit 1; fi
touch "$tmp/config"
SSH_CONFIG_FILE="$tmp/config"
verify_offsite_stopped mock-host prove
grep -Fxq -- -F "$tmp/ssh-args"
grep -Fxq "$tmp/config" "$tmp/ssh-args"
echo '[ok] offsite stop handles both roles, absent units and failure without deleting state'
