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
repo="${PSY_NOTIFIER_DIR:-$WORKSPACE_HOME/parth-sentinel}"
export SSH_CONFIG="${NOTIFIER_SSH_CONFIG:-$HOME/.ssh/config}"
[[ -f "$SSH_CONFIG" ]] || fail "missing SSH config: $SSH_CONFIG"
[[ -d "$repo" ]] || fail "missing pinned Psy Notifier checkout: $repo"
origin="$(git -C "$repo" remote get-url origin)"
case "$origin" in
  "git@github.com:${EXPECTED_PSY_NOTIFIER_REPOSITORY}.git"|"https://github.com/${EXPECTED_PSY_NOTIFIER_REPOSITORY}.git") ;;
  *) fail 'Psy Notifier origin does not match source-versions.env' ;;
esac
[[ "$(git -C "$repo" rev-parse HEAD)" == "$EXPECTED_PSY_NOTIFIER_COMMIT" ]] || fail 'Psy Notifier HEAD does not match the pinned commit'
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=all)" ]] || fail 'Psy Notifier checkout must be clean; preserve edits in another worktree'
hosts=(gcp-cp-ce gcp-coordinator-worker gcp-faucet gcp-postgres gcp-scylla
       gcp-nats gcp-redis gcp-nostr gcp-gateway arc99x4 arc99x3)
for host in "${hosts[@]}"; do
  [[ -f "$repo/config/staging/collectors/$host.toml" ]] || fail "missing collector inventory: $host"
done
for script in deploy-staging-all.sh deploy-staging-controller.sh deploy-wireguard-forward.sh status-staging.sh; do
  bash -n "$repo/deploy/staging/$script"
done

# This adapter deliberately targets the reviewed, fixed staging fleet. Avoid
# ambient legacy overrides silently moving the Controller or disabling Slack.
export SENTINEL_CONTROLLER_HOST=gcp-faucet
export SENTINEL_CONTROLLER_CONFIG="$repo/config/staging/controller.wallet-slack-test.toml"
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
    "${NOTIFIER_BOOKWORM_BUILDER_IMAGE:-parth-bookworm-builder:latest}" \
    cargo build --workspace --release --locked
  binaries="$repo/target/bookworm/release"
  for host in "${hosts[@]}"; do
    "$binaries/psy-notifier-collector" config validate --config "$repo/config/staging/collectors/$host.toml"
  done
  "$binaries/psy-notifier-controller" config validate --config "$SENTINEL_CONTROLLER_CONFIG"
  bash "$repo/deploy/staging/deploy-wireguard-forward.sh" --apply
  # Upstream verifies installed checksums and uses an interactive SSH PTY for
  # offsite sudo. No --test-slack: real notification tests need separate consent.
  bash "$repo/deploy/staging/deploy-staging-all.sh" --skip-build --apply
fi

bash "$repo/deploy/staging/status-staging.sh"
hosts_json="$(printf '%s\n' "${hosts[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
for attempt in {1..30}; do
  if status="$(ssh -F "$SSH_CONFIG" -o BatchMode=yes -o ConnectTimeout=8 gcp-faucet \
      curl -fsS --max-time 10 http://127.0.0.1:9099/status)" \
    && jq -e --argjson hosts "$hosts_json" --argjson now "$(date +%s%3N)" \
      -f "$PROFILE/notifier-ready.jq" <<< "$status" >/dev/null; then
    echo '[monitoring] PASS: Controller ready, three EVM probes healthy, all 11 collectors reporting within 120s'
    jq '{ready, evm_all_healthy, collector_count: (.collectors | length), outbox_depth,
      firing_incidents_in_page: ([.incidents[] | select(.lifecycle == "firing")] | length)}' <<< "$status"
    echo '[monitoring] transport/readiness verified; incident review and notification delivery are separate acceptance checks'
    exit 0
  fi
  echo "[monitoring] awaiting fresh fleet reports ($attempt/30)"
  sleep 2
done
fail 'Controller/three-chain probes/collector freshness check failed; inspect monitoring services, do not redeploy the chain'
