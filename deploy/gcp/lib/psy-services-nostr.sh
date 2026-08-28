#!/usr/bin/env bash

resolve_psy_services_nostr_config() {
  if [ -z "${PSY_NOSTR_RELAY_URL:-}" ]; then
    local configured_relays="${PSY_NOSTR_RELAY_URLS:-${NOSTR_RELAY_URL:-}}"
    PSY_NOSTR_RELAY_URL="${configured_relays%%,*}"
  fi
  PSY_NOSTR_RELAY_URLS="${PSY_NOSTR_RELAY_URLS:-$PSY_NOSTR_RELAY_URL}"
  PSY_NOSTR_LOOKBACK_SECONDS="${PSY_NOSTR_LOOKBACK_SECONDS:-259200}"

  if [ -z "${PSY_NOSTR_ENABLED:-}" ]; then
    if [ -n "$PSY_NOSTR_RELAY_URL" ]; then
      PSY_NOSTR_ENABLED="1"
    else
      PSY_NOSTR_ENABLED="0"
    fi
  fi

  case "${PSY_NOSTR_ENABLED,,}" in
    1|true|yes|on)
      PSY_NOSTR_ENABLED="1"
      if [ -z "$PSY_NOSTR_RELAY_URL" ]; then
        echo "PSY_NOSTR_RELAY_URL is required when PSY_NOSTR_ENABLED=1" >&2
        return 1
      fi
      ;;
    0|false|no|off)
      PSY_NOSTR_ENABLED="0"
      ;;
    *)
      echo "PSY_NOSTR_ENABLED must be 0/1, true/false, yes/no, or on/off" >&2
      return 1
      ;;
  esac

  if ! [[ "$PSY_NOSTR_LOOKBACK_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "PSY_NOSTR_LOOKBACK_SECONDS must be a positive integer" >&2
    return 1
  fi

  export PSY_NOSTR_ENABLED PSY_NOSTR_RELAY_URL PSY_NOSTR_RELAY_URLS PSY_NOSTR_LOOKBACK_SECONDS
}
