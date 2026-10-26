#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate="$root/fresh-staging/check-build-identity.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${MOCK_MODE:-}" != unreachable ]] || exit 255
# Execute the actual remote check locally, with mock systemd/journal binaries.
bash -s -- "${@: -1}"
EOF
cat > "$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$4" in
  ActiveState) if [[ "${MOCK_MODE:-}" == inactive ]]; then echo failed; else echo active; fi ;;
  MainPID) echo 123 ;;
  InvocationID) echo 0123456789abcdef0123456789abcdef ;;
  *) exit 1 ;;
esac
EOF
cat > "$tmp/bin/sudo" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == -n ]] || exit 1
shift
exec "$@"
EOF
cat > "$tmp/bin/journalctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ " $* " == *' _SYSTEMD_INVOCATION_ID=0123456789abcdef0123456789abcdef '* ]] || exit 1
case "${MOCK_MODE:-}" in
  stale) exit 0 ;;
  magic) echo 'psy build identity: stage=testnet magic=0x1337CF514544C069 config_network=testnet' ;;
  stage) echo 'psy build identity: stage=localhost magic=0x1337CF514544CF69 config_network=testnet' ;;
  network) echo 'psy build identity: stage=testnet magic=0x1337CF514544CF69 config_network=localhost' ;;
  *) echo 'psy build identity: stage=testnet magic=0x1337CF514544CF69 config_network=testnet' ;;
esac
EOF
chmod +x "$tmp/bin/ssh" "$tmp/bin/systemctl" "$tmp/bin/sudo" "$tmp/bin/journalctl"
export PATH="$tmp/bin:$PATH"
unset IDENTITY_HOSTS IDENTITY_UNITS
export EXPECTED_MAGIC=0x1337CF514544CF69 EXPECTED_STAGE=testnet
export IDENTITY_TARGETS='fake-host/parth-prove-proxy@user.service fake-host/parth-prove-proxy@system.service'
pass=0
assert_failure() {
  if "$@" > "$tmp/output" 2>&1; then
    cat "$tmp/output" >&2
    echo "expected failure: $*" >&2
    exit 1
  fi
  pass=$((pass + 1))
}
bash "$gate" > "$tmp/output" 2>&1
grep -q 'summary: ok=2 failed=0 expected=2' "$tmp/output"
pass=$((pass + 1))
for mode in unreachable inactive stale magic stage network; do
  assert_failure env MOCK_MODE="$mode" bash "$gate"
done
assert_failure env IDENTITY_TARGETS=' ' bash "$gate"
assert_failure env IDENTITY_TARGETS='' bash "$gate"
assert_failure env IDENTITY_TARGETS='-invalid/unit.service' bash "$gate"
assert_failure env IDENTITY_HOSTS=fake IDENTITY_UNITS=' ' bash "$gate"
assert_failure env EXPECTED_MAGIC=garbage bash "$gate"
assert_failure env EXPECTED_STAGE=sepolia bash "$gate"
echo "[ok] $pass build-identity gate cases passed (no network requests)"
