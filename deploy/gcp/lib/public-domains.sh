#!/usr/bin/env bash

public_env_slug() {
  printf '%s' "${PUBLIC_ENV_SLUG:-stg}"
}

public_base_domain() {
  printf '%s' "${PUBLIC_BASE_DOMAIN:-psy-protocol.xyz}"
}

public_staging_host() {
  local service="$1"
  printf '%s-%s.%s' "$service" "$(public_env_slug)" "$(public_base_domain)"
}

public_release_host() {
  local service="$1"
  printf '%s.%s' "$service" "$(public_base_domain)"
}

public_https_origin() {
  local service="$1"
  printf 'https://%s' "$(public_staging_host "$service")"
}

public_https_url() {
  local service="$1"
  printf '%s/' "$(public_https_origin "$service")"
}

set_public_domain_defaults() {
  : "${PUBLIC_BASE_DOMAIN:=psy-protocol.xyz}"
  : "${PUBLIC_ENV_SLUG:=stg}"
  : "${PUBLIC_ENABLE_RELEASE_BACKEND_ALIASES:=1}"

  : "${NOSTR_DOMAIN:=$(public_staging_host nostr)}"
  if [ "$PUBLIC_ENABLE_RELEASE_BACKEND_ALIASES" = "1" ]; then
    : "${NOSTR_ALIAS_DOMAINS:=$(public_release_host nostr)}"
    : "${PUBLIC_COORDINATOR_ALIAS_DOMAINS:=$(public_release_host coordinator)}"
    : "${PUBLIC_REALM_ALIAS_DOMAINS:=$(public_release_host realm0)}"
    : "${PUBLIC_REALM1_ALIAS_DOMAINS:=$(public_release_host realm1)}"
    : "${PUBLIC_PROVE_PROXY_ALIAS_DOMAINS:=$(public_release_host prove)}"
    : "${PUBLIC_FAUCET_ALIAS_DOMAINS:=$(public_release_host faucet)}"
    : "${PUBLIC_PSY_SERVICES_ALIAS_DOMAINS:=$(public_release_host services)}"
    : "${PUBLIC_INDEXER_ALIAS_DOMAINS:=$(public_release_host indexer)}"
  else
    NOSTR_ALIAS_DOMAINS=""
    PUBLIC_COORDINATOR_ALIAS_DOMAINS=""
    PUBLIC_REALM_ALIAS_DOMAINS=""
    PUBLIC_REALM1_ALIAS_DOMAINS=""
    PUBLIC_PROVE_PROXY_ALIAS_DOMAINS=""
    PUBLIC_FAUCET_ALIAS_DOMAINS=""
    PUBLIC_PSY_SERVICES_ALIAS_DOMAINS=""
    PUBLIC_INDEXER_ALIAS_DOMAINS=""
  fi
  : "${NOSTR_RELAY_URL:=wss://${NOSTR_DOMAIN}/}"

  : "${PUBLIC_COORDINATOR_DOMAIN:=$(public_staging_host coordinator)}"
  : "${PUBLIC_REALM_DOMAIN:=$(public_staging_host realm0)}"
  : "${PUBLIC_REALM0_DOMAIN:=${PUBLIC_REALM_DOMAIN}}"
  : "${PUBLIC_REALM1_DOMAIN:=$(public_staging_host realm1)}"
  : "${PUBLIC_PROVE_PROXY_DOMAIN:=$(public_staging_host prove)}"
  : "${PUBLIC_FAUCET_DOMAIN:=$(public_staging_host faucet)}"
  case "${MULTICHAIN_L1_ENABLED:-0}" in
    1|true|TRUE|yes|YES|on|ON)
      # Multichain profiles expose one hostname per L1 through
      # PUBLIC_L1_RPC_ROUTES_JSON instead of one ambiguous RPC hostname.
      PUBLIC_L1_RPC_DOMAIN="${PUBLIC_L1_RPC_DOMAIN-}"
      ;;
    *)
      : "${PUBLIC_L1_RPC_DOMAIN:=$(public_staging_host rpc)}"
      ;;
  esac
  : "${PUBLIC_L1_RPC_ALIAS_DOMAINS:=}"
  if [ -n "$PUBLIC_L1_RPC_DOMAIN" ]; then
    : "${PUBLIC_RPC_DOMAIN:=${PUBLIC_L1_RPC_DOMAIN}}"
  else
    PUBLIC_RPC_DOMAIN="${PUBLIC_RPC_DOMAIN-}"
  fi
  : "${PUBLIC_PSY_SERVICES_DOMAIN:=$(public_staging_host services)}"
  : "${PUBLIC_INDEXER_DOMAIN:=$(public_staging_host indexer)}"
  : "${PUBLIC_TRUST_SETUP_DOMAIN:=${NOSTR_DOMAIN}}"

  : "${PUBLIC_PRIVACY_BRIDGE_ORIGIN:=$(public_https_origin app)}"
  : "${PUBLIC_PRIVACY_BRIDGE_URL:=${PUBLIC_PRIVACY_BRIDGE_ORIGIN}/}"
  : "${PUBLIC_PSY_EXPLORER_URL:=$(public_https_url explorer)}"
  : "${PUBLIC_PSY_IDE_URL:=$(public_https_url ide)}"
  : "${PUBLIC_CONFIG_PAGE_URL:=$(public_https_url config)}"
  : "${PUBLIC_WALLET_DOWNLOAD_URL:=${PUBLIC_PRIVACY_BRIDGE_ORIGIN}/wallet}"

  export PUBLIC_BASE_DOMAIN PUBLIC_ENV_SLUG PUBLIC_ENABLE_RELEASE_BACKEND_ALIASES
  export NOSTR_DOMAIN NOSTR_ALIAS_DOMAINS NOSTR_RELAY_URL
  export PUBLIC_COORDINATOR_DOMAIN PUBLIC_REALM_DOMAIN PUBLIC_REALM0_DOMAIN PUBLIC_REALM1_DOMAIN
  export PUBLIC_COORDINATOR_ALIAS_DOMAINS PUBLIC_REALM_ALIAS_DOMAINS PUBLIC_REALM1_ALIAS_DOMAINS
  export PUBLIC_PROVE_PROXY_DOMAIN PUBLIC_FAUCET_DOMAIN PUBLIC_L1_RPC_DOMAIN PUBLIC_RPC_DOMAIN
  export PUBLIC_PROVE_PROXY_ALIAS_DOMAINS PUBLIC_FAUCET_ALIAS_DOMAINS PUBLIC_L1_RPC_ALIAS_DOMAINS
  export PUBLIC_PSY_SERVICES_DOMAIN PUBLIC_INDEXER_DOMAIN PUBLIC_TRUST_SETUP_DOMAIN
  export PUBLIC_PSY_SERVICES_ALIAS_DOMAINS PUBLIC_INDEXER_ALIAS_DOMAINS
  export PUBLIC_PRIVACY_BRIDGE_ORIGIN PUBLIC_PRIVACY_BRIDGE_URL
  export PUBLIC_PSY_EXPLORER_URL PUBLIC_PSY_IDE_URL PUBLIC_CONFIG_PAGE_URL
  export PUBLIC_WALLET_DOWNLOAD_URL
}
