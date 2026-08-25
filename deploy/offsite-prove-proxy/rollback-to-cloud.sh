#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_CONFIG_FILE="${SSH_CONFIG_FILE:-$HOME/.ssh/config}"
GCP_PROVE_PROXY_HOST="${GCP_PROVE_PROXY_HOST:-gcp-prove-proxy}"
PUBLIC_PROVE_PROXY_URL="${PUBLIC_PROVE_PROXY_URL:-https://prove-stg.psy-protocol.xyz}"
REMOTE_CONTROL="/tmp/gcp-prove-forwarder-control.sh"

scp -F "$SSH_CONFIG_FILE" \
  "$SCRIPT_DIR/gcp-prove-forwarder-control.sh" \
  "$GCP_PROVE_PROXY_HOST:$REMOTE_CONTROL"
ssh -tt -F "$SSH_CONFIG_FILE" "$GCP_PROVE_PROXY_HOST" \
  "sudo env ACTION=rollback bash $REMOTE_CONTROL"

response="$(curl -sS --fail --max-time 30 "$PUBLIC_PROVE_PROXY_URL" \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_fn_id","params":[0,"simple_claim"]}')"
jq -e '.result == 4' >/dev/null <<<"$response"
echo "Rollback complete: $PUBLIC_PROVE_PROXY_URL -> cloud prove-proxy"
