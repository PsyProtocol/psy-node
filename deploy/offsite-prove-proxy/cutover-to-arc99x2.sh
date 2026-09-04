#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
OFFSITE_PROVE_PROXY_HOST="${OFFSITE_PROVE_PROXY_HOST:-arc99x2}"
GCP_PROVE_PROXY_HOST="${GCP_PROVE_PROXY_HOST:-gcp-prove-proxy}"
GATEWAY_VPC_HOST="${GATEWAY_VPC_HOST:-10.148.0.32}"
GATEWAY_RELAY_PORT="${GATEWAY_RELAY_PORT:-19999}"
PUBLIC_PROVE_PROXY_URL="${PUBLIC_PROVE_PROXY_URL:-https://prove-stg.psy-protocol.xyz}"
REMOTE_CONTROL="/tmp/gcp-prove-forwarder-control.sh"

rpc_health() {
  local url="$1"
  local response

  response="$(curl -sS --fail --max-time 30 "$url" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_fn_id","params":[0,"simple_claim"]}')" ||
    return 1
  jq -e '.result == 4' >/dev/null <<<"$response"
}

echo "Checking arc99x2 prove-proxy..."
ssh -F "$SSH_CONFIG_FILE" "$OFFSITE_PROVE_PROXY_HOST" \
  'systemctl is-active --quiet parth-offsite-prove-proxy.service &&
   response="$(curl -sS --fail --max-time 30 http://10.250.0.12:9999 \
     -H "content-type: application/json" \
     --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"psy_get_fn_id\",\"params\":[0,\"simple_claim\"]}")" &&
   jq -e ".result == 4" >/dev/null <<<"$response"'

echo "Checking gateway relay from gcp-prove-proxy..."
ssh -F "$SSH_CONFIG_FILE" "$GCP_PROVE_PROXY_HOST" \
  "response=\"\$(curl -sS --fail --max-time 30 http://$GATEWAY_VPC_HOST:$GATEWAY_RELAY_PORT \
    -H 'content-type: application/json' \
    --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"psy_get_fn_id\",\"params\":[0,\"simple_claim\"]}')\" &&
   jq -e '.result == 4' >/dev/null <<<\"\$response\""

scp -F "$SSH_CONFIG_FILE" \
  "$SCRIPT_DIR/gcp-prove-forwarder-control.sh" \
  "$GCP_PROVE_PROXY_HOST:$REMOTE_CONTROL"

ssh -tt -F "$SSH_CONFIG_FILE" "$GCP_PROVE_PROXY_HOST" \
  "sudo env ACTION=cutover TARGET_HOST=$(printf '%q' "$GATEWAY_VPC_HOST") TARGET_PORT=$(printf '%q' "$GATEWAY_RELAY_PORT") bash $REMOTE_CONTROL"

echo "Checking public prove-proxy..."
if ! rpc_health "$PUBLIC_PROVE_PROXY_URL"; then
  echo "public health check failed; rolling back immediately" >&2
  ssh -tt -F "$SSH_CONFIG_FILE" "$GCP_PROVE_PROXY_HOST" \
    "sudo env ACTION=rollback bash $REMOTE_CONTROL"
  exit 1
fi

echo "Cutover complete: $PUBLIC_PROVE_PROXY_URL -> arc99x2"
