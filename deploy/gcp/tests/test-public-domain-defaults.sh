#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

(
  unset NOSTR_ALIAS_DOMAINS \
    PUBLIC_COORDINATOR_ALIAS_DOMAINS \
    PUBLIC_REALM_ALIAS_DOMAINS \
    PUBLIC_REALM1_ALIAS_DOMAINS \
    PUBLIC_PROVE_PROXY_ALIAS_DOMAINS \
    PUBLIC_PSY_SERVICES_ALIAS_DOMAINS \
    PUBLIC_INDEXER_ALIAS_DOMAINS
  PUBLIC_BASE_DOMAIN="example.test"
  PUBLIC_ENV_SLUG="stg"
  PUBLIC_ENABLE_RELEASE_BACKEND_ALIASES="1"
  # shellcheck source=deploy/gcp/lib/public-domains.sh
  source "$GCP_DIR/lib/public-domains.sh"
  set_public_domain_defaults

  [ "$PUBLIC_COORDINATOR_DOMAIN" = "coordinator-stg.example.test" ]
  [ "$PUBLIC_COORDINATOR_ALIAS_DOMAINS" = "coordinator.example.test" ]
  [ "$NOSTR_ALIAS_DOMAINS" = "nostr.example.test" ]
  [ "$PUBLIC_INDEXER_ALIAS_DOMAINS" = "indexer.example.test" ]
)

(
  PUBLIC_BASE_DOMAIN="example.test"
  PUBLIC_ENABLE_RELEASE_BACKEND_ALIASES="0"
  NOSTR_ALIAS_DOMAINS="should-be-cleared.example.test"
  PUBLIC_COORDINATOR_ALIAS_DOMAINS="should-be-cleared.example.test"
  # shellcheck source=deploy/gcp/lib/public-domains.sh
  source "$GCP_DIR/lib/public-domains.sh"
  set_public_domain_defaults

  [ -z "$NOSTR_ALIAS_DOMAINS" ]
  [ -z "$PUBLIC_COORDINATOR_ALIAS_DOMAINS" ]
)

echo "[ok] release backend alias defaults and disable switch"
