#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

log_step "running staging deployment preflight checks"

require_cmd jq
require_cmd tar
require_cmd awk
require_cmd find

default_steps="01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 29 18 27 21 26 28 23 30"
selected_steps=" ${DEPLOY_ALL_SELECTED_STEPS:-$default_steps} "

has_step() {
  local step="$1"
  case "$selected_steps" in
    *" $step "*) return 0 ;;
    *) return 1 ;;
  esac
}

has_any_step() {
  local step
  for step in "$@"; do
    has_step "$step" && return 0
  done
  return 1
}

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

is_local_l1_deployment() {
  [ "${L1_DEPLOYMENTS_NETWORK:-localhost}" = "localhost" ] \
    || [ "${CHAIN_ID:-31337}" = "31337" ]
}

verify_clean_git_source() {
  local label="$1"
  local dir="$2"
  local expected="$3"
  local match_mode="$4"
  local actual dirty unexpected_dirty non_deploy_changes

  [ -e "$dir/.git" ] || {
    echo "$label is not a Git checkout: $dir" >&2
    exit 1
  }
  actual="$(git -C "$dir" rev-parse HEAD)"
  dirty="$(git -C "$dir" status --porcelain --untracked-files=normal)"
  if [ -n "$dirty" ] && ! is_truthy "${ALLOW_DIRTY_DEPLOY_SOURCES:-0}"; then
    if [ "$match_mode" = "deploy-only" ]; then
      # A network profile may detach these submodule worktrees at commits that
      # differ from the superproject gitlinks. Their exact commits are checked
      # independently below; every other dirty path remains a hard failure.
      unexpected_dirty="$(
        printf '%s\n' "$dirty" \
          | awk '
              {
                status = substr($0, 1, 2)
                path = substr($0, 4)
                if (!(status == " M" && path ~ /^(psy-genesis|psy-contracts|psy-dapp)$/)) {
                  print
                }
              }
            '
      )"
    else
      unexpected_dirty="$dirty"
    fi

    if [ -n "$unexpected_dirty" ]; then
      echo "$label source tree is dirty: $dir" >&2
      printf '%s\n' "$unexpected_dirty" >&2
      echo "commit/stash the changes or set ALLOW_DIRTY_DEPLOY_SOURCES=1 for deliberate debugging" >&2
      exit 1
    fi
  fi

  if [ -n "$expected" ]; then
    if [ "$match_mode" = "ancestor" ]; then
      git -C "$dir" merge-base --is-ancestor "$expected" "$actual" || {
        echo "$label HEAD $actual does not contain required commit $expected" >&2
        exit 1
      }
    elif [ "$match_mode" = "deploy-only" ]; then
      git -C "$dir" merge-base --is-ancestor "$expected" "$actual" || {
        echo "$label HEAD $actual does not contain required runtime commit $expected" >&2
        exit 1
      }
      non_deploy_changes="$(
        git -C "$dir" diff --name-only "$expected" "$actual" \
          | awk '$0 !~ /^deploy\//'
      )"
      if [ -n "$non_deploy_changes" ]; then
        echo "$label contains product changes after runtime commit $expected:" >&2
        printf '%s\n' "$non_deploy_changes" >&2
        echo "only deploy/ may differ on the deployment branch" >&2
        exit 1
      fi
    elif [ "$actual" != "$expected" ]; then
      echo "$label HEAD mismatch: expected $expected, got $actual" >&2
      exit 1
    fi
  fi

  echo "[preflight] $label source: $actual ($dir)"
}

verify_github_repository() {
  local label="$1"
  local dir="$2"
  local expected="$3"
  local origin

  origin="$(git -C "$dir" remote get-url origin 2>/dev/null || true)"
  case "$origin" in
    "git@github.com:${expected}"|"git@github.com:${expected}.git" \
      |"ssh://git@github.com/${expected}"|"ssh://git@github.com/${expected}.git" \
      |"https://github.com/${expected}"|"https://github.com/${expected}.git")
      ;;
    *)
      echo "$label origin mismatch: expected GitHub repository $expected, got ${origin:-<missing>}" >&2
      exit 1
      ;;
  esac

  echo "[preflight] $label repository: $expected"
}

if has_any_step 19 20 21 26 27 28; then
  require_cloudflare_pages_env
fi

if has_any_step 30 31; then
  require_cmd ssh
  require_cmd scp
fi

if has_step 16 && ! is_local_l1_deployment; then
  require_cmd cast

  relayer_expected_address="${RELAYER_FINALIZE_EXPECTED_ADDRESS:-${L1_DEPLOYER_ADDRESS:-}}"
  relayer_keystore="${RELAYER_FINALIZE_KEYSTORE_PATH:-${L1_DEPLOYER_KEYSTORE_PATH:-}}"
  relayer_password="${RELAYER_FINALIZE_WALLET_PASSWORD:-${L1_DEPLOYER_WALLET_PASSWORD:-${WALLET_PASSWORD:-}}}"
  relayer_private_key="${RELAYER_FINALIZE_PRIVATE_KEY:-${L1_DEPLOYER_PRIVATE_KEY:-}}"

  [[ "$relayer_expected_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || {
    echo "RELAYER_FINALIZE_EXPECTED_ADDRESS or L1_DEPLOYER_ADDRESS must contain the stable public-L1 relayer address" >&2
    exit 1
  }

  if [ -n "$relayer_keystore" ] && [ -f "$relayer_keystore" ]; then
    [ -n "$relayer_password" ] || {
      echo "a relayer finalize keystore password is required for preflight verification" >&2
      exit 1
    }
    relayer_actual_address="$(
      cast wallet address \
        --keystore "$relayer_keystore" \
        --password "$relayer_password"
    )"
  elif [ -n "$relayer_private_key" ]; then
    relayer_actual_address="$(cast wallet address "$relayer_private_key")"
  else
    echo "a local relayer finalize keystore or explicit private key is required before a destructive public-L1 deployment" >&2
    exit 1
  fi

  if [ "$(printf '%s' "$relayer_actual_address" | tr '[:upper:]' '[:lower:]')" \
    != "$(printf '%s' "$relayer_expected_address" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "relayer finalize signer mismatch; refusing deployment before any destructive step" >&2
    echo "expected: $relayer_expected_address" >&2
    echo "actual:   $relayer_actual_address" >&2
    exit 1
  fi
  echo "[preflight] verified stable ${L1_DEPLOYMENTS_NETWORK} relayer signer: $relayer_actual_address"
fi

if has_step 21 \
  && [ "${REGENERATE_GENESIS:-1}" = "1" ] \
  && ! is_truthy "${PSY_FAUCET_SERVER_MODE:-1}" \
  && [ "${GENERATE_PRIVACY_FAUCET_OPERATORS:-0}" != "1" ]; then
  cat >&2 <<'EOF'
Refusing deploy plan: genesis is being regenerated but privacy faucet operator
config generation is disabled while local/browser faucet signing is selected.

Use the default PSY_FAUCET_SERVER_MODE=1, keep GENERATE_PRIVACY_FAUCET_OPERATORS=1
for local/browser mode, or skip step 21 until the frontend can be rebuilt from
the new genesis keys.
EOF
  exit 1
fi

if has_step 13 \
  && is_truthy "${PSY_FAUCET_SERVER_MODE:-1}" \
  && is_truthy "${PSY_FAUCET_REQUIRE_TURNSTILE:-1}"; then
  [ -n "${PSY_FAUCET_TURNSTILE_SECRET:-}" ] || {
    echo "PSY_FAUCET_TURNSTILE_SECRET is required when PSY_FAUCET_REQUIRE_TURNSTILE=1" >&2
    exit 1
  }
fi

if has_step 13 && ! deploys_cloud_prove_proxy; then
  [ -n "${CLIENT_PROVE_PROXY_URL:-}" ] || {
    echo "CLIENT_PROVE_PROXY_URL is required when the cloud prove-proxy is disabled" >&2
    exit 1
  }
  [ -n "${PUBLIC_PROVE_PROXY_UPSTREAM:-}" ] || {
    echo "PUBLIC_PROVE_PROXY_UPSTREAM is required when the cloud prove-proxy is disabled" >&2
    exit 1
  }
  is_truthy "${DEPLOY_OFFSITE_PROVE_PROXY:-0}" || {
    echo "DEPLOY_OFFSITE_PROVE_PROXY=1 is required for a fresh offsite prove deployment" >&2
    exit 1
  }
  is_truthy "${OFFSITE_PROVE_PROXY_APPLY_STAGED:-0}" || {
    echo "OFFSITE_PROVE_PROXY_APPLY_STAGED=1 is required so deploy_all cannot continue with a stale prove bundle" >&2
    exit 1
  }
  require_cmd ssh
  require_cmd rsync
  [ -x "$REPO_ROOT/deploy/offsite-prove-proxy/deploy-arc99x2-release.sh" ] || {
    echo "missing offsite prove deployment script" >&2
    exit 1
  }
fi

if has_step 21 \
  && is_truthy "${PSY_FAUCET_SERVER_MODE:-1}" \
  && is_truthy "${PSY_FAUCET_REQUIRE_TURNSTILE:-1}"; then
  [ -n "${PSY_FAUCET_TURNSTILE_SITE_KEY:-}" ] || {
    echo "PSY_FAUCET_TURNSTILE_SITE_KEY is required when PSY_FAUCET_REQUIRE_TURNSTILE=1" >&2
    exit 1
  }
fi

if has_step 29 && [ "${PUBLISH_PUBLIC_TRUST_SETUP:-1}" = "1" ]; then
  public_trust_uses_current="${PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE:-1}"

  if [ "${GROTH16_REGENERATE_SETUP:-0}" = "1" ] \
    && [ "${GROTH16_REGENERATE_OPTIONAL:-0}" != "1" ] \
    && [ "$public_trust_uses_current" = "1" ]; then
    cat >&2 <<'EOF'
Refusing deploy plan: public trust setup publishing is enabled while Groth16
setup is being regenerated, but optional setup regeneration is disabled.

The public package includes bridge, deposit_batch_append, and withdrawal_claim.
Use GROTH16_REGENERATE_OPTIONAL=1 so all public files come from the same run,
or set PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE=0 with an explicit complete
TRUST_SETUP_SOURCE_PSY_ROOT source directory.
EOF
    exit 1
  fi

  if [ -n "${GROTH16_REGENERATE_KINDS:-}" ] \
    && [ "$public_trust_uses_current" = "1" ] \
    && [ "${ALLOW_MIXED_PUBLIC_TRUST_SETUP:-0}" != "1" ]; then
    cat >&2 <<'EOF'
Refusing deploy plan: public trust setup publishing is enabled while only a
subset of Groth16 kinds is being regenerated. That can publish a mixed package.

Regenerate the full setup, set PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE=0 with
an explicit complete TRUST_SETUP_SOURCE_PSY_ROOT source directory, or set
ALLOW_MIXED_PUBLIC_TRUST_SETUP=1 for deliberate debugging.
EOF
    exit 1
  fi

  if [ "$public_trust_uses_current" != "1" ] && [ -z "${TRUST_SETUP_SOURCE_PSY_ROOT:-}" ]; then
    echo "TRUST_SETUP_SOURCE_PSY_ROOT is required when PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE=0" >&2
    exit 1
  fi
fi

if has_any_step 17 18; then
  declare -A public_domains_seen=()

  register_public_domains() {
    local label="$1"
    local domains="$2"
    local domain

    for domain in $domains; do
      [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || {
        echo "invalid public domain in $label: $domain" >&2
        exit 1
      }
      if [ -n "${public_domains_seen[$domain]:-}" ]; then
        echo "duplicate public domain $domain in $label and ${public_domains_seen[$domain]}" >&2
        exit 1
      fi
      public_domains_seen[$domain]="$label"
    done
  }

  register_public_domains nostr "$NOSTR_DOMAIN ${NOSTR_ALIAS_DOMAINS:-}"
  register_public_domains coordinator "$PUBLIC_COORDINATOR_DOMAIN ${PUBLIC_COORDINATOR_ALIAS_DOMAINS:-}"
  register_public_domains realm0 "$PUBLIC_REALM_DOMAIN ${PUBLIC_REALM_ALIAS_DOMAINS:-}"
  register_public_domains realm1 "$PUBLIC_REALM1_DOMAIN ${PUBLIC_REALM1_ALIAS_DOMAINS:-}"
  register_public_domains prove-proxy "$PUBLIC_PROVE_PROXY_DOMAIN ${PUBLIC_PROVE_PROXY_ALIAS_DOMAINS:-}"
  register_public_domains faucet "$PUBLIC_FAUCET_DOMAIN ${PUBLIC_FAUCET_ALIAS_DOMAINS:-}"
  register_public_domains l1-rpc "${PUBLIC_L1_RPC_DOMAIN:-} ${PUBLIC_L1_RPC_ALIAS_DOMAINS:-}"
  register_public_domains psy-services "$PUBLIC_PSY_SERVICES_DOMAIN ${PUBLIC_PSY_SERVICES_ALIAS_DOMAINS:-}"
  register_public_domains indexer "$PUBLIC_INDEXER_DOMAIN ${PUBLIC_INDEXER_ALIAS_DOMAINS:-}"
fi

if has_step 04; then
  require_cmd git
  require_cmd sha256sum
  require_cmd zstdcat
  psy_services_dir="${PSY_SERVICES_DIR:-$WORKSPACE_HOME/psy-services}"
  psy_genesis_dir="${PSY_GENESIS_DIR:-$PARTH_DIR/psy-genesis}"
  psy_contracts_dir="${PSY_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}"
  : "${EXPECTED_PARTH_RUNTIME_REPOSITORY:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PARTH_RUNTIME_COMMIT:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_GENESIS_REPOSITORY:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_GENESIS_COMMIT:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_CONTRACTS_REPOSITORY:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_CONTRACTS_COMMIT:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_SERVICES_REPOSITORY:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_SERVICES_COMMIT:?missing from deploy/source-versions.env}"
  : "${EXPECTED_GENESIS_CONTRACTS_SHA256:?missing from deploy/source-versions.env}"

  verify_github_repository "psy-node" "$PARTH_DIR" "$EXPECTED_PARTH_RUNTIME_REPOSITORY"
  verify_clean_git_source "psy-node" "$PARTH_DIR" "$EXPECTED_PARTH_RUNTIME_COMMIT" deploy-only
  [ -d "$psy_genesis_dir" ] || {
    echo "missing psy-genesis submodule: $psy_genesis_dir" >&2
    exit 1
  }
  verify_github_repository "psy-genesis" "$psy_genesis_dir" "$EXPECTED_PSY_GENESIS_REPOSITORY"
  verify_clean_git_source "psy-genesis" "$psy_genesis_dir" "$EXPECTED_PSY_GENESIS_COMMIT" exact
  [ -d "$psy_contracts_dir" ] || {
    echo "missing psy-contracts submodule: $psy_contracts_dir" >&2
    exit 1
  }
  verify_github_repository "psy-contracts" "$psy_contracts_dir" "$EXPECTED_PSY_CONTRACTS_REPOSITORY"
  verify_clean_git_source "psy-contracts" "$psy_contracts_dir" "$EXPECTED_PSY_CONTRACTS_COMMIT" exact
  [ -d "$psy_services_dir" ] || {
    echo "missing psy-services checkout: $psy_services_dir" >&2
    exit 1
  }
  verify_github_repository "psy-services" "$psy_services_dir" "$EXPECTED_PSY_SERVICES_REPOSITORY"
  verify_clean_git_source "psy-services" "$psy_services_dir" "$EXPECTED_PSY_SERVICES_COMMIT" exact
  if ! grep -R -E "CREATE TABLE IF NOT EXISTS[[:space:]]+pending_contract_abis" \
    "$psy_services_dir/migrations" >/dev/null 2>&1; then
    echo "psy-services pending_contract_abis migration is missing; ABI upload deploys would fail" >&2
    exit 1
  fi
  if ! grep -R "pending_contract_abis" "$psy_services_dir/src" >/dev/null 2>&1; then
    echo "psy-services pending ABI code is missing; deploy contract ABI binding would not work" >&2
    exit 1
  fi

  [ -s "$psy_genesis_dir/genesis_contracts.json" ] || {
    echo "missing canonical genesis contracts: $psy_genesis_dir/genesis_contracts.json" >&2
    exit 1
  }
  [ -s "$psy_genesis_dir/config.json" ] || {
    echo "missing canonical Psy config: $psy_genesis_dir/config.json" >&2
    exit 1
  }
  [ -d "$psy_genesis_dir/genesis_abi" ] || {
    echo "missing canonical genesis ABI directory: $psy_genesis_dir/genesis_abi" >&2
    exit 1
  }
  actual_genesis_contracts_sha256="$(sha256sum "$psy_genesis_dir/genesis_contracts.json" | awk '{print $1}')"
  [ "$actual_genesis_contracts_sha256" = "$EXPECTED_GENESIS_CONTRACTS_SHA256" ] || {
    echo "canonical genesis_contracts.json checksum mismatch: expected $EXPECTED_GENESIS_CONTRACTS_SHA256, got $actual_genesis_contracts_sha256" >&2
    exit 1
  }
  echo "[preflight] verified canonical genesis contracts artifact: $actual_genesis_contracts_sha256"
fi

if has_any_step 21 26 28; then
  require_cmd git
  psy_dapp_dir="${PSY_DAPP_DIR:-$PARTH_DIR/psy-dapp}"
  : "${EXPECTED_PSY_DAPP_REPOSITORY:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_DAPP_COMMIT:?missing from deploy/source-versions.env}"
  [ -d "$psy_dapp_dir" ] || {
    echo "missing psy-dapp submodule: $psy_dapp_dir" >&2
    exit 1
  }
  verify_github_repository "psy-dapp" "$psy_dapp_dir" "$EXPECTED_PSY_DAPP_REPOSITORY"
  verify_clean_git_source "psy-dapp" "$psy_dapp_dir" "$EXPECTED_PSY_DAPP_COMMIT" exact
fi

if has_step 21 && is_truthy "${INCLUDE_WALLET_DOWNLOAD:-0}"; then
  require_cmd git
  psy_wallet_dir="${PSY_WALLET_DIR:-$WORKSPACE_HOME/psy-wallet}"
  : "${EXPECTED_PSY_WALLET_REPOSITORY:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_WALLET_COMMIT:?missing from deploy/source-versions.env}"

  [ -d "$psy_wallet_dir" ] || {
    echo "missing psy-wallet checkout: $psy_wallet_dir" >&2
    exit 1
  }
  verify_github_repository "psy-wallet" "$psy_wallet_dir" "$EXPECTED_PSY_WALLET_REPOSITORY"
  verify_clean_git_source "psy-wallet" "$psy_wallet_dir" "$EXPECTED_PSY_WALLET_COMMIT" exact
fi

if has_step 28 && is_truthy "${BUILD_LOCAL_PSY_SDK:-1}"; then
  require_cmd git
  psy_sdk_dir="${PSY_SDK_DIR:-$WORKSPACE_HOME/psy-sdk}"
  : "${EXPECTED_PSY_SDK_REPOSITORY:?missing from deploy/source-versions.env}"
  : "${EXPECTED_PSY_SDK_COMMIT:?missing from deploy/source-versions.env}"

  [ -d "$psy_sdk_dir" ] || {
    echo "missing psy-sdk checkout: $psy_sdk_dir" >&2
    exit 1
  }
  verify_github_repository "psy-sdk" "$psy_sdk_dir" "$EXPECTED_PSY_SDK_REPOSITORY"
  verify_clean_git_source "psy-sdk" "$psy_sdk_dir" "$EXPECTED_PSY_SDK_COMMIT" exact
fi

echo "[preflight] selected steps: ${DEPLOY_ALL_SELECTED_STEPS:-$default_steps}"
echo "[preflight] checks passed"
