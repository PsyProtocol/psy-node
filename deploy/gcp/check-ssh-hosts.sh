#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib/common.sh"

hosts=()

add_host() {
  local host="$1"
  local existing

  [ -z "$host" ] && return 0
  for existing in "${hosts[@]}"; do
    [ "$existing" = "$host" ] && return 0
  done
  hosts+=("$host")
}

add_host "${SCYLLA_VM_NAME:-}"
add_host "${NATS_VM_NAME:-}"
add_host "${REDIS_VM_NAME:-}"
add_host "${POSTGRES_VM_NAME:-}"
add_host "${NODE_VM_NAME:-}"
add_host "${RELAYER_VM_NAME:-}"
add_host "${ANVIL_VM_NAME:-}"
add_host "${COORDINATOR_WORKER_VM_NAME:-}"
case "${DEPLOY_CLOUD_PROVE_PROXY:-1}" in
  1|true|TRUE|yes|YES|on|ON) add_host "${PROVE_PROXY_VM_NAME:-}" ;;
esac
add_host "${FAUCET_VM_NAME:-${PROVE_PROXY_VM_NAME:-}}"
case "${DEPLOY_REALM_WORKERS:-0}" in
  1|true|TRUE|yes|YES|on|ON)
    add_host "${REALM_WORKER_1_VM_NAME:-}"
    add_host "${REALM_WORKER_2_VM_NAME:-}"
    ;;
esac
add_host "${NOSTR_VM_NAME:-}"
add_host "${ENVIO_VM_NAME:-}"

for host in "${hosts[@]}"; do
  wait_ssh_ready "$host"
  printf '%s service endpoint: %s\n' "$host" "$(ssh_service_endpoint "$host")"
done
