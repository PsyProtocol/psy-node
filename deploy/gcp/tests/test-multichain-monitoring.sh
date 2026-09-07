#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/notifier"
mkdir -p "$repo/deploy/staging" "$repo/config/staging/collectors" \
  "$repo/target/bookworm/release" "$tmp/bin" "$tmp/registry"
export TEST_CALLS="$tmp/calls" TEST_HEALTH="$tmp/health.json"
hosts=(gcp-cp-ce gcp-coordinator-worker gcp-faucet gcp-postgres gcp-scylla
       gcp-nats gcp-redis gcp-nostr gcp-gateway arc99x4 arc99x3)
for host in "${hosts[@]}"; do
  printf 'id = "%s"\n' "$host" > "$repo/config/staging/collectors/$host.toml"
done
touch "$tmp/ssh-config" "$repo/config/staging/controller.wallet-slack-test.toml"
printf 'target/\n' > "$repo/.gitignore"
for script in deploy-staging-all.sh deploy-staging-controller.sh deploy-wireguard-forward.sh status-staging.sh; do
  cat > "$repo/deploy/staging/$script" <<'SH'
#!/usr/bin/env bash
name="$(basename "$0")"
[[ -n "$*" || "$name" == status-staging.sh ]] || exit 0
echo "$name $*" >> "$TEST_CALLS"
if [[ "$name" == deploy-staging-all.sh && "${TEST_FLEET_FAIL:-0}" == 1 ]]; then exit 17; fi
SH
done
git -C "$repo" init -q
git -C "$repo" add .gitignore config deploy
git -C "$repo" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm fixture
git -C "$repo" remote add origin git@github.com:PsyProtocol/psy-notifier.git
sha="$(git -C "$repo" rev-parse HEAD)"
cat > "$tmp/pins.env" <<SH
EXPECTED_PSY_NOTIFIER_REPOSITORY=PsyProtocol/psy-notifier
EXPECTED_PSY_NOTIFIER_COMMIT=$sha
SH
cat > "$tmp/config.env" <<SH
PSY_NOTIFIER_DIR=$repo
NOTIFIER_SSH_CONFIG=$tmp/ssh-config
NOTIFIER_CARGO_REGISTRY=$tmp/registry
SH
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
echo docker >> "$TEST_CALLS"
exit "${TEST_BUILD_EXIT:-0}"
SH
cat > "$tmp/bin/ssh" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == *'test -s'* ]]; then
  echo credentials-check >> "$TEST_CALLS"
  exit "${TEST_CREDENTIAL_EXIT:-0}"
fi
echo status-query >> "$TEST_CALLS"
cat "$TEST_HEALTH"
SH
cat > "$tmp/bin/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
for role in collector controller; do
  cat > "$repo/target/bookworm/release/psy-notifier-$role" <<'SH'
#!/usr/bin/env bash
[[ "$1 $2" == 'config validate' ]] || exit 19
echo validate >> "$TEST_CALLS"
SH
  chmod +x "$repo/target/bookworm/release/psy-notifier-$role"
done
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH" GCP_DEPLOY_CONFIG="$tmp/config.env" DEPLOY_SOURCE_VERSIONS_FILE="$tmp/pins.env"
runner="$ROOT/deploy/multi-chain/gcp/deploy-monitoring.sh"
filter="$ROOT/deploy/multi-chain/gcp/notifier-ready.jq"
hosts_json="$(printf '%s\n' "${hosts[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
now="$(date +%s%3N)"
jq -n --argjson hosts "$hosts_json" --argjson now "$now" '{ready:true,evm_all_healthy:true,
  evm_probes: [97,84532,11155111] | map({chain_id:.,healthy:true}),
  collectors: $hosts | map({collector_id:.,environment:"staging",last_seen_ms:$now}),
  incidents: [],outbox_depth:0}' > "$TEST_HEALTH"

bash "$runner" --check > "$tmp/check.log"
[ ! -e "$TEST_CALLS" ]
bash "$runner" --apply > "$tmp/apply.log"
[ "$(grep -c '^validate$' "$TEST_CALLS")" = 12 ]
grep -q '^deploy-staging-all.sh --skip-build --apply$' "$TEST_CALLS"
grep -q '^deploy-wireguard-forward.sh --apply$' "$TEST_CALLS"
grep -q 'PASS: Controller ready' "$tmp/apply.log"

: > "$TEST_CALLS"
bash "$runner" --status > "$tmp/status.log"
if grep -Eq 'docker|^deploy-|credentials-check' "$TEST_CALLS"; then exit 1; fi
: > "$TEST_CALLS"
if TEST_CREDENTIAL_EXIT=5 bash "$runner" --apply > /dev/null 2>&1; then exit 1; fi
[ "$(cat "$TEST_CALLS")" = credentials-check ]
: > "$TEST_CALLS"
if TEST_BUILD_EXIT=6 bash "$runner" --apply > /dev/null 2>&1; then exit 1; fi
if grep -q '^deploy-' "$TEST_CALLS"; then exit 1; fi
if TEST_FLEET_FAIL=1 bash "$runner" --apply > /dev/null 2>&1; then exit 1; fi

accepts() { jq -e --argjson hosts "$hosts_json" --argjson now "$now" -f "$filter" >/dev/null; }
accepts < "$TEST_HEALTH"
for mutation in '.ready=false' '.evm_all_healthy=false' '.evm_probes=[]' \
  '.evm_probes[0].healthy=false' '.collectors[0].last_seen_ms=0' \
  '.collectors[0].last_seen_ms=null' '.collectors[0].environment="local"' \
  'del(.collectors[0])'; do
  if jq "$mutation" "$TEST_HEALTH" | accepts; then echo "unexpectedly accepted: $mutation"; exit 1; fi
done
jq '.collectors=[]' "$TEST_HEALTH" > "$tmp/stale.json"
if TEST_HEALTH="$tmp/stale.json" bash "$runner" --status > "$tmp/stale.log" 2>&1; then exit 1; fi
grep -q 'freshness check failed' "$tmp/stale.log"

printf '# dirty\n' >> "$repo/deploy/staging/deploy-staging-all.sh"
if bash "$runner" --check > /dev/null 2>&1; then exit 1; fi
git -C "$repo" add deploy/staging/deploy-staging-all.sh
git -C "$repo" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm different
if bash "$runner" --check > /dev/null 2>&1; then exit 1; fi
echo '[ok] monitoring pin/clean-source gates, safe check mode, build/fleet failure propagation and fresh three-chain telemetry'
