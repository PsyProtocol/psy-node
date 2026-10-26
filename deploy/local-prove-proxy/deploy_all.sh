#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARTH_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$PARTH_DIR/deploy/gcp/config.env}"

[ -f "$CONFIG_FILE" ] || {
  echo "missing config file: $CONFIG_FILE" >&2
  exit 1
}

set -a
# shellcheck source=../gcp/config.env
source "$CONFIG_FILE"
set +a

# shellcheck source=../gcp/lib/public-domains.sh
source "$PARTH_DIR/deploy/gcp/lib/public-domains.sh"
set_public_domain_defaults

log() {
  echo
  echo "[local-prove-proxy] $*"
}

run() {
  log "running: $*"
  "$@"
}

copy_withdrawal_claim_setup() {
  local source_root="${GROTH16_SETUP_KEYSTORE_ROOT:-$PARTH_DIR/dist/groth16-keystore}"
  local target_root="${LOCAL_GROTH16_KEYSTORE_ROOT:-$HOME/.psy/keystore}"
  local source_dir="$source_root/withdrawal_claim"
  local target_dir="$target_root/withdrawal_claim"

  for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    [ -s "$source_dir/$file" ] || {
      echo "missing withdrawal_claim setup file: $source_dir/$file" >&2
      echo "generate it first with: bash deploy/gcp/generate-upload-groth16-setup.sh --kind withdrawal_claim --no-upload" >&2
      exit 1
    }
  done

  log "syncing withdrawal_claim Groth16 setup to $target_dir"
  mkdir -p "$target_dir"
  rsync -a --checksum --human-readable --progress \
    "$source_dir/circuit_groth16.bin" \
    "$source_dir/pk_groth16.bin" \
    "$source_dir/vk_groth16.bin" \
    "$target_dir/"
  chmod 0600 "$target_dir/"*_groth16.bin
}

wait_local_tcp() {
  local host="$1"
  local port="$2"
  local attempts="${3:-60}"
  local delay="${4:-2}"
  local i

  for i in $(seq 1 "$attempts"); do
    if timeout 2 bash -lc "</dev/tcp/$host/$port" >/dev/null 2>&1; then
      log "local tcp is ready: $host:$port"
      return 0
    fi
    sleep "$delay"
  done

  echo "local tcp did not become ready: $host:$port" >&2
  return 1
}

wait_remote_tcp() {
  local remote_host="$1"
  local bind_addr="$2"
  local port="$3"
  local attempts="${4:-60}"
  local delay="${5:-2}"
  local ssh_config="${SSH_CONFIG:-$HOME/.ssh/config}"
  local i

  for i in $(seq 1 "$attempts"); do
    if ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 "$remote_host" \
      "timeout 2 bash -lc '</dev/tcp/$bind_addr/$port'" >/dev/null 2>&1; then
      log "remote tcp is ready: $remote_host $bind_addr:$port"
      return 0
    fi
    sleep "$delay"
  done

  echo "remote tcp did not become ready: $remote_host $bind_addr:$port" >&2
  return 1
}

public_healthcheck() {
  local domain="${PUBLIC_PROVE_PROXY_DOMAIN}"
  local body='{"jsonrpc":"2.0","id":1,"method":"psy_get_circuits_data","params":[]}'

  log "checking public prove proxy endpoint: https://$domain/"
  curl -fsS --max-time "${LOCAL_PROVE_PROXY_PUBLIC_CHECK_TIMEOUT:-30}" \
    "https://$domain/" \
    -H "Origin: ${PUBLIC_PRIVACY_BRIDGE_URL%/}" \
    -H 'Content-Type: application/json' \
    --data "$body" >/dev/null
  log "public prove proxy check passed"
}

main() {
  local remote_host="${LOCAL_PROVE_PROXY_TUNNEL_HOST:-${PROVE_PROXY_VM_NAME:-gcp-prove-proxy}}"
  local remote_bind_addr="${LOCAL_PROVE_PROXY_TUNNEL_BIND_ADDR:-${PROVE_PROXY_HOST:-10.148.0.26}}"
  local remote_port="${LOCAL_PROVE_PROXY_TUNNEL_REMOTE_PORT:-9999}"
  local local_host="${LOCAL_PROVE_PROXY_TUNNEL_LOCAL_HOST:-127.0.0.1}"
  local local_port="${LOCAL_PROVE_PROXY_TUNNEL_LOCAL_PORT:-9999}"

  log "repo: $PARTH_DIR"
  log "config: $CONFIG_FILE"
  log "public endpoint: https://${PUBLIC_PROVE_PROXY_DOMAIN}/"
  log "reverse tunnel: $remote_host $remote_bind_addr:$remote_port -> $local_host:$local_port"

  if [ "${LOCAL_PROVE_PROXY_INSTALL_GROTH16:-1}" = "1" ]; then
    copy_withdrawal_claim_setup
  fi

  run bash "$SCRIPT_DIR/prepare-local-prove-proxy.sh"
  run bash "$SCRIPT_DIR/install-systemd-user-service.sh"

  if [ "${LOCAL_PROVE_PROXY_CONFIGURE_REMOTE:-1}" = "1" ]; then
    run bash "$SCRIPT_DIR/configure-remote-tunnel-target.sh"
  fi

  run bash "$SCRIPT_DIR/install-reverse-tunnel-service.sh"

  if [ "${LOCAL_PROVE_PROXY_START:-1}" = "1" ]; then
    log "starting local prove proxy service"
    systemctl --user restart parth-local-prove-proxy.service
    wait_local_tcp "$local_host" "$local_port"

    log "starting reverse tunnel service and monitor"
    systemctl --user restart parth-local-prove-proxy-tunnel.service
    systemctl --user restart parth-local-prove-proxy-tunnel-monitor.timer
    wait_remote_tcp "$remote_host" "$remote_bind_addr" "$remote_port"

    if [ "${LOCAL_PROVE_PROXY_PUBLIC_CHECK:-1}" = "1" ]; then
      public_healthcheck
    fi
  fi

  log "completed local prove proxy deployment"
}

main "$@"
