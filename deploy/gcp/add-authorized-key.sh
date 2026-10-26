#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

DEFAULT_PUBLIC_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICpdEuNTTwQ5Gm9v/PdOs/iDo/K6Tlw7d/p7UVNzY4ym long@longerM.local'

usage() {
  cat <<'EOF'
Usage:
  bash deploy/gcp/add-authorized-key.sh [public-key]

Environment:
  SSH_PUBLIC_KEY     Public key to add. Overrides the default embedded key.
  TARGET_HOSTS       Space-separated SSH aliases to update. Defaults to all
                     configured staging hosts in deploy/gcp/config.env.
  DRY_RUN=1          Print target hosts without changing remote machines.

Examples:
  bash deploy/gcp/add-authorized-key.sh
  DRY_RUN=1 bash deploy/gcp/add-authorized-key.sh
  TARGET_HOSTS="gcp-nostr gcp-cp-ce" bash deploy/gcp/add-authorized-key.sh
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

public_key="${SSH_PUBLIC_KEY:-${1:-$DEFAULT_PUBLIC_KEY}}"

case "$public_key" in
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *|sk-ssh-ed25519@openssh.com\ *|sk-ecdsa-sha2-nistp256@openssh.com\ *)
    ;;
  *)
    echo "invalid or unsupported SSH public key format" >&2
    exit 1
    ;;
esac

unique_hosts_from_config() {
  {
    printf '%s\n' \
      "${SCYLLA_VM_NAME:-}" \
      "${NATS_VM_NAME:-}" \
      "${REDIS_VM_NAME:-}" \
      "${POSTGRES_VM_NAME:-}" \
      "${NODE_VM_NAME:-}" \
      "${ANVIL_VM_NAME:-}" \
      "${FAUCET_VM_NAME:-${PROVE_PROXY_VM_NAME:-}}" \
      "${COORDINATOR_WORKER_VM_NAME:-}" \
      "${NOSTR_VM_NAME:-}" \
      "${ENVIO_VM_NAME:-}"

    case "${DEPLOY_REALM_WORKERS:-0}" in
      1|true|TRUE|yes|YES|on|ON)
        printf '%s\n' \
          "${REALM_WORKER_1_VM_NAME:-}" \
          "${REALM_WORKER_2_VM_NAME:-}"
        ;;
    esac

    case "${DEPLOY_CLOUD_PROVE_PROXY:-1}" in
      1|true|TRUE|yes|YES|on|ON)
        printf '%s\n' "${PROVE_PROXY_VM_NAME:-}"
        ;;
    esac
  } | awk 'NF && !seen[$0]++'
}

if [ -n "${TARGET_HOSTS:-}" ]; then
  # shellcheck disable=SC2206
  hosts=($TARGET_HOSTS)
else
  mapfile -t hosts < <(unique_hosts_from_config)
fi

if [ "${#hosts[@]}" -eq 0 ]; then
  echo "no target hosts found" >&2
  exit 1
fi

echo "target hosts:"
printf '  %s\n' "${hosts[@]}"

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "DRY_RUN=1; no remote changes made"
  exit 0
fi

key_q="$(printf '%q' "$public_key")"

for host in "${hosts[@]}"; do
  echo "updating authorized_keys on ${host}"
  wait_ssh_ready "$host" >/dev/null
  run_remote_command "$host" "
    set -e
    key=$key_q
    umask 077
    mkdir -p \"\$HOME/.ssh\"
    touch \"\$HOME/.ssh/authorized_keys\"
    chmod 700 \"\$HOME/.ssh\"
    chmod 600 \"\$HOME/.ssh/authorized_keys\"
    if grep -qxF \"\$key\" \"\$HOME/.ssh/authorized_keys\"; then
      echo \"already present: ${host}\"
    else
      cp \"\$HOME/.ssh/authorized_keys\" \"\$HOME/.ssh/authorized_keys.bak.\$(date +%Y%m%d%H%M%S)\"
      printf '%s\n' \"\$key\" >> \"\$HOME/.ssh/authorized_keys\"
      echo \"added: ${host}\"
    fi
  "
done

echo "done"
