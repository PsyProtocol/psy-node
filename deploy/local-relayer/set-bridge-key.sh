#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNTIME_DIR="${LOCAL_RELAYER_DIR:-$PARTH_DIR/dist/local-relayer}"
ENV_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/parth-local-relayer"
ENV_FILE="${LOCAL_RELAYER_ENV_FILE:-$ENV_DIR/env}"
SERVICE_NAME="${LOCAL_RELAYER_SERVICE_NAME:-parth-local-relayer.service}"
KEYS_FILE="${GENESIS_PRIVATE_KEYS_FILE:-$PARTH_DIR/private_keys.json}"
KEY_INDEX="${BRIDGE_RELAYER_KEY_INDEX:-2}"
EXPECTED_USER_ID="${BRIDGE_USER_ID:-524288}"
USER_CLI="${USER_CLI:-$PARTH_DIR/target/release/psy_user_cli}"
RPC_CONFIG="${LOCAL_RELAYER_RPC_CONFIG:-$RUNTIME_DIR/client_prover/config.json}"

require_file() {
  local path="$1"
  [ -f "$path" ] || {
    echo "missing file: $path" >&2
    exit 1
  }
}

require_executable() {
  local path="$1"
  [ -x "$path" ] || {
    echo "missing executable: $path" >&2
    exit 1
  }
}

require_file "$KEYS_FILE"
require_file "$RPC_CONFIG"
require_executable "$USER_CLI"
command -v jq >/dev/null 2>&1 || {
  echo "missing command: jq" >&2
  exit 1
}

private_key="$(jq -er --argjson i "$KEY_INDEX" '.[$i] | select(type == "string")' "$KEYS_FILE")"
private_key="${private_key#0x}"
if ! [[ "$private_key" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "invalid private key at ${KEYS_FILE}[$KEY_INDEX]: expected 64 hex chars" >&2
  exit 1
fi

public_key="$(cd "$PARTH_DIR" && RUST_LOG=error "$USER_CLI" wallet info -p "$private_key" | awk '/^public_key:/{print $2}')"
[ -n "$public_key" ] || {
  echo "failed to derive public key from private key index $KEY_INDEX" >&2
  exit 1
}

resolved_user_id="$(cd "$PARTH_DIR" && RUST_LOG=error "$USER_CLI" get-user-id --rpc-config "$RPC_CONFIG" --pub-key "$public_key" | awk '/user_id:/{print $2}')"
if [ "$resolved_user_id" != "$EXPECTED_USER_ID" ]; then
  cat >&2 <<EOF
bridge relayer key mismatch
  key source:      ${KEYS_FILE}[$KEY_INDEX]
  public key:      ${public_key:0:12}...
  resolved user:   $resolved_user_id
  expected user:   $EXPECTED_USER_ID

Refusing to update $ENV_FILE. Set BRIDGE_RELAYER_KEY_INDEX or BRIDGE_USER_ID only if the deployed genesis mapping changed.
EOF
  exit 1
fi

mkdir -p "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<'EOF'
# Required. Do not commit this file.
BRIDGE_RELAYER_L2_PRIVATE_KEY=
WALLET_PASSWORD=

# Optional.
RUST_LOG=info
EOF
  chmod 0600 "$ENV_FILE"
fi

tmp_file="$(mktemp)"
awk -v key="$private_key" '
  BEGIN { seen = 0 }
  /^BRIDGE_RELAYER_L2_PRIVATE_KEY=/ {
    print "BRIDGE_RELAYER_L2_PRIVATE_KEY=" key
    seen = 1
    next
  }
  { print }
  END {
    if (!seen) {
      print "BRIDGE_RELAYER_L2_PRIVATE_KEY=" key
    }
  }
' "$ENV_FILE" > "$tmp_file"
install -m 0600 "$tmp_file" "$ENV_FILE"
rm -f "$tmp_file"

echo "updated local relayer bridge key:"
echo "  env file:      $ENV_FILE"
echo "  key index:     $KEY_INDEX"
echo "  public key:    ${public_key:0:12}..."
echo "  user id:       $resolved_user_id"

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user restart "$SERVICE_NAME"
  echo "restarted user service: $SERVICE_NAME"
else
  echo "systemctl not found; restart the relayer manually" >&2
fi
