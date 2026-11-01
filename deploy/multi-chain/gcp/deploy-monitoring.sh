#!/usr/bin/env bash
set -euo pipefail

PROFILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$PROFILE/../../.." && pwd)"
export WORKSPACE_HOME="${WORKSPACE_HOME:-$(cd "$ROOT/.." && pwd)}"
config="${GCP_DEPLOY_CONFIG:-$PROFILE/config.env}"
mode="${1:---check}"
fail() { echo "[monitoring] $*" >&2; exit 1; }
[[ "$#" -le 1 && "$mode" =~ ^--(check|apply|status)$ ]] || fail 'usage: deploy-monitoring.sh [--check|--apply|--status]'
[[ -f "$config" ]] || fail "missing private deployment config: $config"
set -a
# shellcheck disable=SC1090
source "$config"
# shellcheck disable=SC1090
source "${DEPLOY_SOURCE_VERSIONS_FILE:-$PROFILE/source-versions.env}"
set +a
[[ "${DEPLOY_MONITORING:-1}" == 1 ]] || fail 'monitoring is disabled in config'
repo="${MONITORING_NOTIFIER_DIR:-${PSY_NOTIFIER_DIR:-$WORKSPACE_HOME/parth-sentinel}}"
export SSH_CONFIG="${MONITORING_SSH_CONFIG:-${NOTIFIER_SSH_CONFIG:-$HOME/.ssh/config}}"
[[ -f "$SSH_CONFIG" ]] || fail "missing SSH config: $SSH_CONFIG"
[[ -d "$repo" ]] || fail "missing pinned Psy Notifier checkout: $repo"
origin="$(git -C "$repo" remote get-url origin)"
case "$origin" in
  "git@github.com:${EXPECTED_PSY_NOTIFIER_REPOSITORY}.git"|"https://github.com/${EXPECTED_PSY_NOTIFIER_REPOSITORY}.git") ;;
  *) fail 'Psy Notifier origin does not match source-versions.env' ;;
esac
[[ "$(git -C "$repo" rev-parse HEAD)" == "$EXPECTED_PSY_NOTIFIER_COMMIT" ]] || fail 'Psy Notifier HEAD does not match the pinned commit'
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=all)" ]] || fail 'Psy Notifier checkout must be clean; preserve edits in another worktree'
# The Notifier's WireGuard forwarder only admits the retired offsite peers. Install the same helper
# with this release's offsite addresses as a second unit; the pinned Notifier files stay untouched.
forward_release_peers() {
  local gateway=gcp-gateway helper unit work peers address tag
  [[ "${#offsite_addresses[@]}" -gt 0 ]] || return 0
  helper="$repo/deploy/staging/gateway/parth-sentinel-wireguard-forward"
  unit="$repo/deploy/staging/gateway/parth-sentinel-wireguard-forward.service"
  work="$(mktemp -d)"
  peers="$(printf '"%s" ' "${offsite_addresses[@]}")"
  sed -E "s|^offsite_peers=\(.*\)$|offsite_peers=(${peers% })|" "$helper" > "$work/helper"
  grep -q "^offsite_peers=(${peers% })$" "$work/helper" || fail 'cannot rewrite the forwarder peer list'
  sed -e 's|parth-sentinel-wireguard-forward|psy-monitoring-release-forward|g' \
    -e 's|^Description=.*|Description=Forward release offsite Notifier Collectors through the WireGuard gateway|' \
    "$unit" > "$work/unit"
  tag="psy-monitoring-release-forward.$$"
  scp -F "$SSH_CONFIG" "$work/helper" "$gateway:/tmp/$tag"
  scp -F "$SSH_CONFIG" "$work/unit" "$gateway:/tmp/$tag.service"
  ssh -F "$SSH_CONFIG" "$gateway" "sudo install -m 0755 /tmp/$tag /usr/local/libexec/psy-monitoring-release-forward \
    && sudo install -m 0644 /tmp/$tag.service /etc/systemd/system/psy-monitoring-release-forward.service \
    && sudo systemctl daemon-reload && sudo systemctl enable psy-monitoring-release-forward.service \
    && sudo systemctl restart psy-monitoring-release-forward.service \
    && sudo systemctl is-active psy-monitoring-release-forward.service; rm -f /tmp/$tag /tmp/$tag.service"
  rm -rf -- "$work"
}

# The fleet comes from the release: deploy_monitoring_steps.py writes one "<host> <gcp|offsite>"
# line per release host and a matching collector config directory and Controller config.
hosts_file="${MONITORING_HOSTS_FILE:-}"
collector_dir="${MONITORING_COLLECTOR_DIR:-}"
chain_indexes="${MONITORING_CHAIN_INDEXES:-}"
[[ -s "$hosts_file" && -d "$collector_dir" && -n "$chain_indexes" ]] \
  || fail 'MONITORING_HOSTS_FILE, MONITORING_COLLECTOR_DIR and MONITORING_CHAIN_INDEXES are required (run step 85)'
hosts=()
offsite_hosts=()
offsite_addresses=()
while read -r host zone address; do
  [[ -n "$host" ]] || continue
  hosts+=("$host")
  if [[ "$zone" == offsite ]]; then
    offsite_hosts+=("$host")
    [[ "$address" =~ ^10\.250\.[0-9]+\.[0-9]+$ ]] || fail "offsite host $host needs a WireGuard address in the hosts file"
    offsite_addresses+=("$address")
  fi
done < "$hosts_file"
for host in "${hosts[@]}"; do
  [[ -f "$collector_dir/$host.toml" ]] || fail "missing collector config: $host"
done
collector_config() { printf '%s' "$collector_dir/$1.toml"; }
for script in deploy-staging-all.sh deploy-staging-controller.sh deploy-wireguard-forward.sh; do
  bash -n "$repo/deploy/staging/$script"
done

# The fleet is the release's (see above); the Controller location is fixed. Avoid ambient
# overrides silently moving the Controller or disabling Slack.
export SENTINEL_CONTROLLER_HOST=gcp-faucet
export SENTINEL_CONTROLLER_CONFIG="${MONITORING_CONTROLLER_CONFIG:-$repo/config/staging/controller.wallet-slack-test.toml}"
export SENTINEL_CONTROLLER_GRPC_LISTEN=10.148.0.33:9443
export SENTINEL_CONTROLLER_GCP_ENDPOINT=http://10.148.0.33:9443
export SENTINEL_CONTROLLER_OFFSITE_ENDPOINT=http://10.250.0.1:9443
if [[ "$mode" == --check ]]; then
  bash "$repo/deploy/staging/deploy-staging-all.sh"
  echo '[monitoring] local source/inventory check passed; remote credentials and health have not been checked'
  exit 0
fi

if [[ "$mode" == --apply ]]; then
  # Check the existing credential without retrieving or logging its contents.
  ssh -F "$SSH_CONFIG" -o BatchMode=yes -o ConnectTimeout=8 gcp-faucet \
    sudo -n test -s /etc/parth-sentinel/secrets/slack-webhook-url
  registry="${NOTIFIER_CARGO_REGISTRY:-${CARGO_HOME:-$HOME/.cargo}/registry}"
  [[ -d "$registry" ]] || fail "missing Cargo registry cache: $registry"
  # Same Bookworm build as the Notifier installer, without its hard-coded home.
  docker run --rm --user "$(id -u):$(id -g)" \
    --tmpfs "/cargo:uid=$(id -u),gid=$(id -g),mode=0700" \
    --volume "$registry:/cargo/registry" --volume "$repo:/workspace" \
    --workdir /workspace --env CARGO_HOME=/cargo \
    --env CARGO_TARGET_DIR=/workspace/target/bookworm --env RUSTUP_TOOLCHAIN=1.97.1 \
    --env PSY_NETWORK="${PSY_NETWORK:-localhost}" \
    "${NOTIFIER_BOOKWORM_BUILDER_IMAGE:-parth-bookworm-builder:latest}" \
    cargo build --workspace --release --locked
  binaries="$repo/target/bookworm/release"
  for host in "${hosts[@]}"; do
    "$binaries/psy-notifier-collector" config validate --config "$(collector_config "$host")"
  done
  "$binaries/psy-notifier-controller" config validate --config "$SENTINEL_CONTROLLER_CONFIG"
  bash "$repo/deploy/staging/deploy-wireguard-forward.sh" --apply
  forward_release_peers
  # The fleet wrapper checks every collector even in controller-only mode.
  # Install/verify the Controller independently before staging the collectors.
  bash "$repo/deploy/staging/deploy-staging-controller.sh" --skip-build --apply
  expected_sha="$(sha256sum "$binaries/psy-notifier-collector" | awk '{print $1}')"
  for host in "${hosts[@]}"; do
    [[ " ${offsite_hosts[*]} " == *" $host "* ]] && continue
    bash "$repo/deploy/staging/deploy-collector.sh" --host "$host" \
      --config "$(collector_config "$host")" \
      --controller-endpoint "$SENTINEL_CONTROLLER_GCP_ENDPOINT" \
      --binary "$binaries/psy-notifier-collector" --apply
    actual_sha="$(ssh -F "$SSH_CONFIG" -o BatchMode=yes "$host" \
      sha256sum /usr/local/bin/psy-notifier-collector | awk '{print $1}')"
    [[ "$actual_sha" == "$expected_sha" ]] || fail "collector binary mismatch on $host"
  done
  for host in "${offsite_hosts[@]}"; do
    bash "$repo/deploy/staging/prepare-offsite-collector.sh" --host "$host" \
      --config "$(collector_config "$host")" \
      --controller-endpoint "$SENTINEL_CONTROLLER_OFFSITE_ENDPOINT" \
      --binary "$binaries/psy-notifier-collector"
    # "<host> <command>": the command runs on that host, by ssh from step 85 or by the operator at its prompt.
    printf '[monitoring] user action: %s cd ~/psy-notifier-install && sudo ./install-collector.sh ./psy-notifier-collector ./collector.toml ./parth-sentinel-collector.service\n' "$host"
  done
  echo '[monitoring] PENDING: cloud installed; offsite packages staged, not activated. Run --status after user installation.'
  exit 3
fi

# The Notifier's status-staging.sh lists a fixed fleet; check the release hosts instead.
collector_failures=0
for host in "${hosts[@]}"; do
  state="$(ssh -F "$SSH_CONFIG" -o BatchMode=yes -o ConnectTimeout=8 "$host" \
    systemctl is-active parth-sentinel-collector.service 2>/dev/null)" || state=unreachable-or-missing
  printf '%-28s %s\n' "$host" "$state"
  [[ "$state" == active ]] || collector_failures=$((collector_failures + 1))
done
[[ "$collector_failures" -eq 0 ]] || fail "$collector_failures of ${#hosts[@]} collectors are not active"
hosts_json="$(printf '%s\n' "${hosts[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
for attempt in {1..30}; do
  if status="$(ssh -F "$SSH_CONFIG" -o BatchMode=yes -o ConnectTimeout=8 gcp-faucet \
      curl -fsS --max-time 10 http://127.0.0.1:9099/status)" \
    && jq -e --argjson hosts "$hosts_json" --argjson chains "$chain_indexes" --argjson now "$(date +%s%3N)" \
      -f "$PROFILE/notifier-ready.jq" <<< "$status" >/dev/null; then
    echo "[monitoring] PASS: Controller ready, three EVM and settlement probes healthy, all ${#hosts[@]} release collectors reporting within 120s"
    jq '{ready, evm_all_healthy, settlement_all_healthy, collector_count: (.collectors | length), outbox_depth,
      firing_incidents_in_page: ([.incidents[] | select(.lifecycle == "firing")] | length)}' <<< "$status"
    echo '[monitoring] transport/readiness verified; incident review and notification delivery are separate acceptance checks'
    exit 0
  fi
  echo "[monitoring] awaiting fresh fleet reports ($attempt/30)"
  sleep 2
done
fail 'Controller/three-chain probes/collector freshness check failed; inspect monitoring services, do not redeploy the chain'
