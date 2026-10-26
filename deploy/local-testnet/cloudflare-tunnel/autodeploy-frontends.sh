#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[local-cf-autodeploy] missing command: $1" >&2
    exit 1
  }
}

for command_name in cat date flock gh git jq ln mkdir mv rm sha256sum sleep; do
  require_command "$command_name"
done

LOCAL_CF_AUTODEPLOY_REMOTE="${LOCAL_CF_AUTODEPLOY_REMOTE:-origin}"
LOCAL_CF_AUTODEPLOY_BRANCH="${LOCAL_CF_AUTODEPLOY_BRANCH:-mainnet-beta}"
LOCAL_CF_AUTODEPLOY_WALLET_BRANCH="${LOCAL_CF_AUTODEPLOY_WALLET_BRANCH:-feat/improve-bridge-relayer}"
LOCAL_CF_AUTODEPLOY_SDK_BRANCH="${LOCAL_CF_AUTODEPLOY_SDK_BRANCH:-feat/improve-bridge-relayer}"
LOCAL_CF_AUTODEPLOY_PARTH_REPOSITORY="${LOCAL_CF_AUTODEPLOY_PARTH_REPOSITORY:-https://github.com/PsyProtocol/psy-node.git}"
LOCAL_CF_AUTODEPLOY_WALLET_REPOSITORY="${LOCAL_CF_AUTODEPLOY_WALLET_REPOSITORY:-https://github.com/PsyProtocol/psy-wallet.git}"
LOCAL_CF_AUTODEPLOY_SDK_REPOSITORY="${LOCAL_CF_AUTODEPLOY_SDK_REPOSITORY:-https://github.com/PsyProtocol/psy-sdk.git}"
LOCAL_CF_AUTODEPLOY_SOURCE_ROOT="${LOCAL_CF_AUTODEPLOY_SOURCE_ROOT:-$(dirname "$LOCAL_CF_LIVE_PARTH_DIR")/frontend-autodeploy}"
LOCAL_CF_AUTODEPLOY_PARTH_DIR="${LOCAL_CF_AUTODEPLOY_PARTH_DIR:-$LOCAL_CF_AUTODEPLOY_SOURCE_ROOT/psy-node}"
LOCAL_CF_AUTODEPLOY_WALLET_DIR="${LOCAL_CF_AUTODEPLOY_WALLET_DIR:-$LOCAL_CF_AUTODEPLOY_SOURCE_ROOT/psy-wallet}"
LOCAL_CF_AUTODEPLOY_SDK_DIR="${LOCAL_CF_AUTODEPLOY_SDK_DIR:-$LOCAL_CF_AUTODEPLOY_SOURCE_ROOT/psy-sdk}"
LOCAL_CF_AUTODEPLOY_INTERVAL_SECONDS="${LOCAL_CF_AUTODEPLOY_INTERVAL_SECONDS:-120}"
LOCAL_CF_AUTODEPLOY_ALLOW_DIRTY="${LOCAL_CF_AUTODEPLOY_ALLOW_DIRTY:-0}"
LOCAL_CF_AUTODEPLOY_ONCE="${LOCAL_CF_AUTODEPLOY_ONCE:-0}"
LOCAL_CF_AUTODEPLOY_FORCE="${LOCAL_CF_AUTODEPLOY_FORCE:-0}"
LOCAL_CF_AUTODEPLOY_BOOTSTRAP_OBSERVE_ONLY="${LOCAL_CF_AUTODEPLOY_BOOTSTRAP_OBSERVE_ONLY:-1}"
LOCAL_CF_AUTODEPLOY_RETRY_FAILED_AFTER_SECONDS="${LOCAL_CF_AUTODEPLOY_RETRY_FAILED_AFTER_SECONDS:-1800}"
LOCAL_CF_AUTODEPLOY_STATE_DIR="${LOCAL_CF_AUTODEPLOY_STATE_DIR:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging-cf-tunnel/autodeploy}"
LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE="${LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE:-$LOCAL_CF_AUTODEPLOY_STATE_DIR/current-source.json}"
LOCAL_CF_AUTODEPLOY_LAST_ATTEMPT_FILE="${LOCAL_CF_AUTODEPLOY_LAST_ATTEMPT_FILE:-$LOCAL_CF_AUTODEPLOY_STATE_DIR/last-attempt.json}"
LOCAL_CF_AUTODEPLOY_LAST_SUCCESS_FILE="${LOCAL_CF_AUTODEPLOY_LAST_SUCCESS_FILE:-$LOCAL_CF_AUTODEPLOY_STATE_DIR/last-success.json}"
LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE="${LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE:-$LOCAL_CF_AUTODEPLOY_STATE_DIR/last-failure.json}"
LOCAL_CF_AUTODEPLOY_LAST_BLOCKED_FILE="${LOCAL_CF_AUTODEPLOY_LAST_BLOCKED_FILE:-$LOCAL_CF_AUTODEPLOY_STATE_DIR/last-blocked.json}"
LOCAL_CF_AUTODEPLOY_LAST_ERROR_FILE="${LOCAL_CF_AUTODEPLOY_LAST_ERROR_FILE:-$LOCAL_CF_AUTODEPLOY_STATE_DIR/last-error.log}"
LOCAL_CF_AUTODEPLOY_LOCK_FILE="${LOCAL_CF_AUTODEPLOY_LOCK_FILE:-$LOCAL_CF_AUTODEPLOY_STATE_DIR/autodeploy.lock}"
LOCAL_CF_FRONTEND_RELEASES_DIR="${LOCAL_CF_FRONTEND_RELEASES_DIR:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging/nginx/html/.releases/frontends}"
LOCAL_CF_NGINX_HTML_ROOT="${LOCAL_CF_NGINX_HTML_ROOT:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging/nginx/html}"
LOCAL_CF_LIVE_DEPLOYMENT_FILE="${LOCAL_CF_LIVE_DEPLOYMENT_FILE:-$LOCAL_CF_LIVE_PARTH_DIR/psy-contracts/deployments/localhost/deployed-contracts.json}"
LOCAL_CF_AUTODEPLOY_REQUIRE_ABI_MATCH="${LOCAL_CF_AUTODEPLOY_REQUIRE_ABI_MATCH:-1}"
LOCAL_CF_AUTODEPLOY_BACKEND_ABI_DIR="${LOCAL_CF_AUTODEPLOY_BACKEND_ABI_DIR:-$LOCAL_CF_LIVE_PARTH_DIR/.local-staging/backend-abi/current}"

mkdir -p "$LOCAL_CF_AUTODEPLOY_STATE_DIR" "$LOCAL_CF_AUTODEPLOY_SOURCE_ROOT"

log() {
  echo "[local-cf-autodeploy] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

git_without_lfs() {
  GIT_LFS_SKIP_SMUDGE=1 git \
    -c filter.lfs.process= \
    -c filter.lfs.smudge= \
    -c filter.lfs.required=false \
    "$@"
}

git_with_auth() {
  git_without_lfs -c credential.helper='!gh auth git-credential' "$@"
}

ensure_clean_tracked_worktree() {
  local repo_dir="$1"
  local label="$2"

  [ "$LOCAL_CF_AUTODEPLOY_ALLOW_DIRTY" = "1" ] && return 0
  if ! git -C "$repo_dir" diff --quiet --ignore-submodules -- \
    || ! git -C "$repo_dir" diff --cached --quiet --ignore-submodules --; then
    echo "[local-cf-autodeploy] $label checkout has tracked changes: $repo_dir" >&2
    return 1
  fi
}

ensure_checkout() {
  local label="$1"
  local repository="$2"
  local branch="$3"
  local repo_dir="$4"

  if git -C "$repo_dir" rev-parse --git-dir >/dev/null 2>&1; then
    return 0
  fi

  if [ -e "$repo_dir" ]; then
    echo "[local-cf-autodeploy] $label source path exists but is not a git checkout: $repo_dir" >&2
    return 1
  fi

  log "cloning $label branch=$branch into $repo_dir"
  mkdir -p "$(dirname "$repo_dir")"
  git_with_auth clone --single-branch --branch "$branch" "$repository" "$repo_dir" || return $?
}

sync_checkout() {
  local label="$1"
  local branch="$2"
  local repo_dir="$3"
  local current_branch local_sha remote_sha

  ensure_clean_tracked_worktree "$repo_dir" "$label" || return $?
  current_branch="$(git -C "$repo_dir" branch --show-current)" || return $?
  if [ "$current_branch" != "$branch" ]; then
    echo "[local-cf-autodeploy] $label branch mismatch: current=$current_branch required=$branch" >&2
    return 1
  fi

  log "fetching $label $LOCAL_CF_AUTODEPLOY_REMOTE/$branch"
  git_with_auth -C "$repo_dir" fetch --no-tags "$LOCAL_CF_AUTODEPLOY_REMOTE" \
    "refs/heads/$branch:refs/remotes/$LOCAL_CF_AUTODEPLOY_REMOTE/$branch" || return $?

  local_sha="$(git -C "$repo_dir" rev-parse HEAD)" || return $?
  remote_sha="$(git -C "$repo_dir" rev-parse "$LOCAL_CF_AUTODEPLOY_REMOTE/$branch")" || return $?
  if [ "$local_sha" = "$remote_sha" ]; then
    return 0
  fi
  if ! git -C "$repo_dir" merge-base --is-ancestor "$local_sha" "$remote_sha"; then
    echo "[local-cf-autodeploy] refusing non-fast-forward $label update: local=$local_sha remote=$remote_sha" >&2
    return 1
  fi

  log "fast-forwarding $label local=$local_sha remote=$remote_sha"
  git_without_lfs -C "$repo_dir" merge --ff-only "$LOCAL_CF_AUTODEPLOY_REMOTE/$branch" || return $?
  ensure_clean_tracked_worktree "$repo_dir" "$label" || return $?
}

sync_sources() {
  ensure_checkout "parth" "$LOCAL_CF_AUTODEPLOY_PARTH_REPOSITORY" "$LOCAL_CF_AUTODEPLOY_BRANCH" "$LOCAL_CF_AUTODEPLOY_PARTH_DIR" || return $?
  ensure_checkout "wallet" "$LOCAL_CF_AUTODEPLOY_WALLET_REPOSITORY" "$LOCAL_CF_AUTODEPLOY_WALLET_BRANCH" "$LOCAL_CF_AUTODEPLOY_WALLET_DIR" || return $?
  ensure_checkout "sdk" "$LOCAL_CF_AUTODEPLOY_SDK_REPOSITORY" "$LOCAL_CF_AUTODEPLOY_SDK_BRANCH" "$LOCAL_CF_AUTODEPLOY_SDK_DIR" || return $?

  sync_checkout "parth" "$LOCAL_CF_AUTODEPLOY_BRANCH" "$LOCAL_CF_AUTODEPLOY_PARTH_DIR" || return $?
  sync_checkout "wallet" "$LOCAL_CF_AUTODEPLOY_WALLET_BRANCH" "$LOCAL_CF_AUTODEPLOY_WALLET_DIR" || return $?
  sync_checkout "sdk" "$LOCAL_CF_AUTODEPLOY_SDK_BRANCH" "$LOCAL_CF_AUTODEPLOY_SDK_DIR" || return $?
  git_with_auth -C "$LOCAL_CF_AUTODEPLOY_PARTH_DIR" \
    -c submodule.psy-dapp.update=checkout \
    submodule update --init --recursive psy-dapp psy-genesis psy-contracts || return $?
}

abi_manifest_hash() {
  local abi_dir="$1"
  local abi_file
  local abi_files=(
    PsyDepositTreeContract.json
    PsyFaucetContract.json
    PsyTokenContract.json
    PsyWithdrawalTreeContract.json
    USDTTokenContract.json
  )

  for abi_file in "${abi_files[@]}"; do
    [ -s "$abi_dir/$abi_file" ] || {
      echo "[local-cf-autodeploy] missing ABI file: $abi_dir/$abi_file" >&2
      return 1
    }
  done

  {
    for abi_file in "${abi_files[@]}"; do
      printf '%s\n' "$abi_file"
      jq -S -c . "$abi_dir/$abi_file" || return $?
    done
  } | sha256sum | awk '{print $1}'
}

write_current_source() {
  local parth_sha wallet_sha sdk_sha deployment_sha source_abi_sha backend_abi_sha abi_compatible
  local source_key release_id next_file

  [ -s "$LOCAL_CF_LIVE_DEPLOYMENT_FILE" ] || {
    echo "[local-cf-autodeploy] missing live L1 deployment file: $LOCAL_CF_LIVE_DEPLOYMENT_FILE" >&2
    return 1
  }

  parth_sha="$(git -C "$LOCAL_CF_AUTODEPLOY_PARTH_DIR" rev-parse HEAD)" || return $?
  wallet_sha="$(git -C "$LOCAL_CF_AUTODEPLOY_WALLET_DIR" rev-parse HEAD)" || return $?
  sdk_sha="$(git -C "$LOCAL_CF_AUTODEPLOY_SDK_DIR" rev-parse HEAD)" || return $?
  deployment_sha="$(sha256sum "$LOCAL_CF_LIVE_DEPLOYMENT_FILE" | awk '{print $1}')" || return $?
  source_abi_sha="$(abi_manifest_hash "$LOCAL_CF_AUTODEPLOY_PARTH_DIR/psy-genesis/genesis_abi")" || return $?
  backend_abi_sha="$(abi_manifest_hash "$LOCAL_CF_AUTODEPLOY_BACKEND_ABI_DIR")" || return $?
  abi_compatible=false
  if [ "$source_abi_sha" = "$backend_abi_sha" ]; then
    abi_compatible=true
  fi
  source_key="$(printf '%s\n%s\n%s\n%s\n%s\n' \
    "$parth_sha" "$wallet_sha" "$sdk_sha" "$deployment_sha" "$backend_abi_sha" \
    | sha256sum | awk '{print $1}')" || return $?
  release_id="p${parth_sha:0:12}-w${wallet_sha:0:12}-s${sdk_sha:0:12}-d${deployment_sha:0:12}"
  next_file="$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE.next.$$"

  jq -n \
    --arg sourceKey "$source_key" \
    --arg releaseId "$release_id" \
    --arg parthBranch "$LOCAL_CF_AUTODEPLOY_BRANCH" \
    --arg parthSha "$parth_sha" \
    --arg walletBranch "$LOCAL_CF_AUTODEPLOY_WALLET_BRANCH" \
    --arg walletSha "$wallet_sha" \
    --arg sdkBranch "$LOCAL_CF_AUTODEPLOY_SDK_BRANCH" \
    --arg sdkSha "$sdk_sha" \
    --arg deploymentSha "$deployment_sha" \
    --arg sourceAbiSha "$source_abi_sha" \
    --arg backendAbiSha "$backend_abi_sha" \
    --argjson abiCompatible "$abi_compatible" \
    --arg observedAt "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    '{
      sourceKey: $sourceKey,
      releaseId: $releaseId,
      parth: {branch: $parthBranch, sha: $parthSha},
      wallet: {branch: $walletBranch, sha: $walletSha},
      sdk: {branch: $sdkBranch, sha: $sdkSha},
      deploymentSha: $deploymentSha,
      abi: {
        sourceSha: $sourceAbiSha,
        backendSha: $backendAbiSha,
        compatible: $abiCompatible
      },
      observedAt: $observedAt
    }' > "$next_file" || {
      rm -f "$next_file"
      return 1
    }
  mv -f "$next_file" "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE"
}

manifest_key() {
  local file="$1"
  [ -s "$file" ] || return 0
  jq -r '.sourceKey // empty' "$file"
}

failed_retry_due() {
  local current_key="$1"
  local failed_key failed_epoch now_epoch

  [ -s "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE" ] || return 0
  failed_key="$(manifest_key "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE")"
  [ "$failed_key" = "$current_key" ] || return 0
  failed_epoch="$(jq -r '.failedEpoch // 0' "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE")"
  now_epoch="$(date +%s)"
  [ $((now_epoch - failed_epoch)) -ge "$LOCAL_CF_AUTODEPLOY_RETRY_FAILED_AFTER_SECONDS" ]
}

prepare_source_deployment_file() {
  local source_deployment_file="$1"
  mkdir -p "$(dirname "$source_deployment_file")"
  cp "$LOCAL_CF_LIVE_DEPLOYMENT_FILE" "$source_deployment_file"
}

build_and_publish() (
  local release_id release_dir_file release_dir source_deployment_file live_parth_dir live_state_dir
  release_id="$(jq -r '.releaseId' "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE")"
  release_dir_file="$LOCAL_CF_AUTODEPLOY_STATE_DIR/release-dir.$$"
  source_deployment_file="$LOCAL_CF_AUTODEPLOY_PARTH_DIR/psy-dapp/psy-contracts/deployments/localhost/deployed-contracts.json"
  live_parth_dir="$LOCAL_CF_LIVE_PARTH_DIR"
  live_state_dir="$LOCAL_CF_STATE_DIR"

  cleanup_build_inputs() {
    rm -f "$release_dir_file" "$source_deployment_file"
  }
  trap cleanup_build_inputs EXIT
  prepare_source_deployment_file "$source_deployment_file" || return $?

  log "building frontend release=$release_id"
  LOCAL_CF_SOURCE_PARTH_DIR="$LOCAL_CF_AUTODEPLOY_PARTH_DIR" \
  LOCAL_CF_LIVE_PARTH_DIR="$live_parth_dir" \
  LOCAL_CF_STATE_DIR="$live_state_dir" \
  LOCAL_CF_CHAIN_CONFIG_FILE="$live_state_dir/client_prover/config.json" \
  LOCAL_CF_FRONTEND_RELEASES_DIR="$LOCAL_CF_FRONTEND_RELEASES_DIR" \
  LOCAL_CF_NGINX_HTML_ROOT="$LOCAL_CF_NGINX_HTML_ROOT" \
  LOCAL_CF_FRONTEND_RELEASE_ID="$release_id" \
  LOCAL_CF_FRONTEND_RELEASE_DIR_FILE="$release_dir_file" \
  LOCAL_CF_WALLET_BRANCH="$LOCAL_CF_AUTODEPLOY_WALLET_BRANCH" \
  LOCAL_CF_SDK_BRANCH="$LOCAL_CF_AUTODEPLOY_SDK_BRANCH" \
  PSY_WALLET_DIR="$LOCAL_CF_AUTODEPLOY_WALLET_DIR" \
  PSY_SDK_DIR="$LOCAL_CF_AUTODEPLOY_SDK_DIR" \
  LOCAL_STAGING_NPM_INSTALL=1 \
    bash "$SCRIPT_DIR/build-frontends-release.sh" || return $?

  release_dir="$(cat "$release_dir_file")" || return $?
  LOCAL_CF_SOURCE_PARTH_DIR="$LOCAL_CF_AUTODEPLOY_PARTH_DIR" \
  LOCAL_CF_LIVE_PARTH_DIR="$live_parth_dir" \
  LOCAL_CF_STATE_DIR="$live_state_dir" \
  LOCAL_CF_FRONTEND_RELEASES_DIR="$LOCAL_CF_FRONTEND_RELEASES_DIR" \
  LOCAL_CF_NGINX_HTML_ROOT="$LOCAL_CF_NGINX_HTML_ROOT" \
    bash "$SCRIPT_DIR/publish-frontends-release.sh" "$release_dir" || return $?

  ensure_clean_tracked_worktree "$LOCAL_CF_AUTODEPLOY_PARTH_DIR" "parth" || return $?
  ensure_clean_tracked_worktree "$LOCAL_CF_AUTODEPLOY_WALLET_DIR" "wallet" || return $?
  ensure_clean_tracked_worktree "$LOCAL_CF_AUTODEPLOY_SDK_DIR" "sdk" || return $?
)

deploy_if_needed() {
  local current_key attempted_key failed_epoch source_abi_sha backend_abi_sha
  current_key="$(manifest_key "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE")"
  attempted_key="$(manifest_key "$LOCAL_CF_AUTODEPLOY_LAST_ATTEMPT_FILE")"

  if [ "$LOCAL_CF_AUTODEPLOY_REQUIRE_ABI_MATCH" = "1" ] \
     && [ "$(jq -r '.abi.compatible // false' "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE")" != "true" ]; then
    source_abi_sha="$(jq -r '.abi.sourceSha' "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE")"
    backend_abi_sha="$(jq -r '.abi.backendSha' "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE")"
    cp "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE" "$LOCAL_CF_AUTODEPLOY_LAST_ATTEMPT_FILE"
    jq \
      --arg blockedAt "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      --arg reason "source ABI differs from the deployed backend; update the backend manually before publishing this frontend" \
      '. + {blockedAt: $blockedAt, reason: $reason}' \
      "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE" > "$LOCAL_CF_AUTODEPLOY_LAST_BLOCKED_FILE"
    rm -f "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE" "$LOCAL_CF_AUTODEPLOY_LAST_ERROR_FILE"
    log "frontend update waiting for backend ABI source=$source_abi_sha backend=$backend_abi_sha"
    return 0
  fi

  rm -f "$LOCAL_CF_AUTODEPLOY_LAST_BLOCKED_FILE"

  if [ ! -s "$LOCAL_CF_AUTODEPLOY_LAST_ATTEMPT_FILE" ] \
     && [ "$LOCAL_CF_AUTODEPLOY_BOOTSTRAP_OBSERVE_ONLY" = "1" ] \
     && [ "$LOCAL_CF_AUTODEPLOY_FORCE" != "1" ]; then
    cp "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE" "$LOCAL_CF_AUTODEPLOY_LAST_ATTEMPT_FILE"
    log "recorded initial source baseline without replacing the tested frontend release"
    return 0
  fi

  if [ "$LOCAL_CF_AUTODEPLOY_FORCE" != "1" ] && [ "$current_key" = "$attempted_key" ]; then
    if [ "$(manifest_key "$LOCAL_CF_AUTODEPLOY_LAST_SUCCESS_FILE")" = "$current_key" ]; then
      log "source tuple already deployed key=$current_key"
      return 0
    fi
    if [ "$(manifest_key "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE")" != "$current_key" ]; then
      log "source tuple already recorded as the bootstrap baseline key=$current_key"
      return 0
    fi
    if ! failed_retry_due "$current_key"; then
      failed_epoch="$(jq -r '.failedEpoch // 0' "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE" 2>/dev/null || true)"
      log "same failed source is cooling down failed_epoch=${failed_epoch:-unknown}"
      return 0
    fi
  fi

  cp "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE" "$LOCAL_CF_AUTODEPLOY_LAST_ATTEMPT_FILE"
  if ! build_and_publish; then
    jq --arg failedAt "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      --argjson failedEpoch "$(date +%s)" \
      '. + {failedAt: $failedAt, failedEpoch: $failedEpoch}' \
      "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE" > "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE"
    return 1
  fi

  jq --arg deployedAt "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    '. + {deployedAt: $deployedAt}' \
    "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE" > "$LOCAL_CF_AUTODEPLOY_LAST_SUCCESS_FILE"
  rm -f "$LOCAL_CF_AUTODEPLOY_LAST_FAILURE_FILE" "$LOCAL_CF_AUTODEPLOY_LAST_ERROR_FILE"
  log "published source key=$current_key release=$(jq -r '.releaseId' "$LOCAL_CF_AUTODEPLOY_CURRENT_SOURCE_FILE")"
}

run_once() {
  (
    flock -n 9 || {
      log "another frontend deploy is active; skipping"
      return 0
    }
    sync_sources || return $?
    write_current_source || return $?
    deploy_if_needed || return $?
  ) 9>"$LOCAL_CF_AUTODEPLOY_LOCK_FILE"
}

while true; do
  current_error_file="$LOCAL_CF_AUTODEPLOY_LAST_ERROR_FILE.current.$$"
  if ! run_once 2>"$current_error_file"; then
    mv -f "$current_error_file" "$LOCAL_CF_AUTODEPLOY_LAST_ERROR_FILE"
    log "frontend deploy failed; keeping the current release"
    cat "$LOCAL_CF_AUTODEPLOY_LAST_ERROR_FILE" >&2 || true
    if [ "$LOCAL_CF_AUTODEPLOY_ONCE" = "1" ]; then
      exit 1
    fi
  else
    rm -f "$current_error_file"
  fi

  if [ "$LOCAL_CF_AUTODEPLOY_ONCE" = "1" ]; then
    exit 0
  fi
  sleep "$LOCAL_CF_AUTODEPLOY_INTERVAL_SECONDS"
done
