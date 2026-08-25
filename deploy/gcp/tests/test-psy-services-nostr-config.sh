#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=deploy/gcp/lib/psy-services-nostr.sh
source "$GCP_DIR/lib/psy-services-nostr.sh"

(
  unset PSY_NOSTR_ENABLED PSY_NOSTR_RELAY_URLS PSY_NOSTR_LOOKBACK_SECONDS
  NOSTR_RELAY_URL="wss://nostr-stg.example.test/"
  resolve_psy_services_nostr_config
  [ "$PSY_NOSTR_ENABLED" = "1" ]
  [ "$PSY_NOSTR_RELAY_URLS" = "$NOSTR_RELAY_URL" ]
  [ "$PSY_NOSTR_LOOKBACK_SECONDS" = "259200" ]
)

(
  unset NOSTR_RELAY_URL PSY_NOSTR_RELAY_URLS PSY_NOSTR_LOOKBACK_SECONDS
  PSY_NOSTR_ENABLED="false"
  resolve_psy_services_nostr_config
  [ "$PSY_NOSTR_ENABLED" = "0" ]
  [ -z "$PSY_NOSTR_RELAY_URLS" ]
)

if (
  unset NOSTR_RELAY_URL PSY_NOSTR_RELAY_URLS PSY_NOSTR_LOOKBACK_SECONDS
  PSY_NOSTR_ENABLED="true"
  resolve_psy_services_nostr_config
) 2>/dev/null; then
  echo "expected enabled Nostr config without a relay URL to fail" >&2
  exit 1
fi

grep -Fq '"PSY_NOSTR_ENABLED=$PSY_NOSTR_ENABLED"' "$GCP_DIR/deploy-psy-services.sh"
grep -Fq '"PSY_NOSTR_ENABLED=$PSY_NOSTR_ENABLED"' "$GCP_DIR/deploy-cp-ce-stack.sh"
grep -Fq 'upsert_if_set "$service_env" PSY_NOSTR_ENABLED PSY_NOSTR_ENABLED' \
  "$GCP_DIR/remote/deploy-parth-service.sh"

echo "[ok] psy-services Nostr subscriber deployment config"
