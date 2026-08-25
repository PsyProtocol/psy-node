#!/usr/bin/env bash
set -euo pipefail

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$GCP_DIR/../.." && pwd)"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$GCP_DIR/config.env}"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
export WORKSPACE_HOME

: "${PARTH_DIR:=$REPO_ROOT}"
: "${PSY_GENESIS_DIR:=$PARTH_DIR/psy-genesis}"
: "${PSY_CONTRACTS_DIR:=$PARTH_DIR/psy-contracts}"
: "${PSY_DAPP_DIR:=$PARTH_DIR/psy-dapp}"

if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
else
  echo "missing config file: $CONFIG_FILE" >&2
  echo "copy deploy/gcp/config.example.env to deploy/gcp/config.env first" >&2
  exit 1
fi

SOURCE_VERSIONS_FILE="$REPO_ROOT/deploy/source-versions.env"
[ -f "$SOURCE_VERSIONS_FILE" ] || {
  echo "missing deployment source versions: $SOURCE_VERSIONS_FILE" >&2
  exit 1
}
bash -n "$SOURCE_VERSIONS_FILE"
# Load this after config.env so repository pins have one authoritative source.
# shellcheck disable=SC1090
source "$SOURCE_VERSIONS_FILE"

# shellcheck source=public-domains.sh
source "$GCP_DIR/lib/public-domains.sh"
set_public_domain_defaults

: "${SSH_SERVICE_ENDPOINT_MODE:=private-ip}"
: "${SSH_CONFIG_FILE:=$HOME/.ssh/config}"
: "${DATA_DISK_DEVICE:=}"
: "${DATA_DISK_MOUNTPOINT:=/var/lib/parth}"
: "${PARTH_PRIVATE_KEYS_FILE:=$PARTH_DIR/private_keys.json}"
: "${PARTH_BUNDLE_DISTRIBUTION_MODE:=cache-host}"
: "${PARTH_BUNDLE_CACHE_HOST:=${NODE_VM_NAME:-gcp-cp-ce}}"
: "${PARTH_BUNDLE_CACHE_DIR:=/tmp/parth-bundle-cache}"
: "${PARTH_BUNDLE_CACHE_PORT:=18088}"
: "${PARTH_BUNDLE_CACHE_BIND_ADDR:=}"

ssh_base_args() {
  if [ -f "$SSH_CONFIG_FILE" ]; then
    printf '%s\n' ssh -F "$SSH_CONFIG_FILE" -o BatchMode=yes "$1"
  else
    printf '%s\n' ssh -o BatchMode=yes "$1"
  fi
}

scp_base_args() {
  if [ -f "$SSH_CONFIG_FILE" ]; then
    printf '%s\n' scp -F "$SSH_CONFIG_FILE" -q
  else
    printf '%s\n' scp -q
  fi
}

run_remote_command() {
  local name="$1"
  local command="$2"
  local -a ssh_args
  mapfile -t ssh_args < <(ssh_base_args "$name")

  "${ssh_args[@]}" "$command"
}

url_encode() {
  local value="$1"

  if command -v jq >/dev/null 2>&1; then
    jq -rn --arg value "$value" '$value|@uri'
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$value"
    return 0
  fi

  echo "jq or python3 is required for URL encoding" >&2
  exit 1
}

postgres_url() {
  local host="$1"
  local port="$2"
  local database="$3"
  local user="${4:-${POSTGRES_USER:-postgres}}"
  local password="${5:-${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}}"

  printf 'postgres://%s:%s@%s:%s/%s' \
    "$(url_encode "$user")" \
    "$(url_encode "$password")" \
    "$host" \
    "$port" \
    "$(url_encode "$database")"
}

genesis_private_key() {
  local index="$1"

  command -v jq >/dev/null 2>&1 || {
    echo "jq is required to read private keys from ${PARTH_PRIVATE_KEYS_FILE}" >&2
    return 1
  }
  [ -f "$PARTH_PRIVATE_KEYS_FILE" ] || {
    echo "missing private keys file: ${PARTH_PRIVATE_KEYS_FILE}; run make generate-genesis-data in psy-node" >&2
    return 1
  }

  jq -er --argjson index "$index" '
    .[$index]
    | select(type == "string")
    | select(test("^[0-9a-fA-F]{64}$"))
  ' "$PARTH_PRIVATE_KEYS_FILE"
}

genesis_private_key_or_empty() {
  local index="$1"
  local key

  key="$(genesis_private_key "$index" 2>/dev/null)" || return 0
  printf '%s\n' "$key"
}

reverse_bits_in_limit() {
  local value="$1"
  local bit_count="$2"
  local out=0
  local i

  for ((i = 0; i < bit_count; i++)); do
    out=$(( (out << 1) | ((value >> i) & 1) ))
  done
  printf '%s\n' "$out"
}

genesis_user_id_for_key_index() {
  local key_index="$1"
  local realm_user_tree_height="${GENESIS_REALM_USER_TREE_HEIGHT:-20}"
  local group_realm_height="${GENESIS_GROUP_REALM_HEIGHT:-1}"
  local realm_mask=$(( (1 << group_realm_height) - 1 ))
  local user_mask=$(( (1 << realm_user_tree_height) - 1 ))
  local realm_index=$(( key_index & realm_mask ))
  local user_index=$(( (key_index >> group_realm_height) & user_mask ))
  local group_id=$(( key_index >> (group_realm_height + realm_user_tree_height) ))
  local reversed_realm_index
  local reversed_user_index
  local full_realm_id

  reversed_realm_index="$(reverse_bits_in_limit "$realm_index" "$group_realm_height")"
  reversed_user_index="$(reverse_bits_in_limit "$user_index" "$realm_user_tree_height")"
  full_realm_id=$(( (group_id << group_realm_height) | reversed_realm_index ))
  printf '%s\n' "$(( (full_realm_id << realm_user_tree_height) | reversed_user_index ))"
}

select_cyclic_space_list_item() {
  local list="$1"
  local slot="${2:-0}"
  local -a items

  read -r -a items <<< "$list"
  [ "${#items[@]}" -gt 0 ] || return 1
  printf '%s\n' "${items[$((slot % ${#items[@]}))]}"
}

scp_to_remote() {
  local name="$1"
  local source="$2"
  local destination="$3"
  local attempt attempts delay
  local -a scp_args

  mapfile -t scp_args < <(scp_base_args)

  attempts="${SSH_TRANSFER_ATTEMPTS:-5}"
  delay="${SSH_TRANSFER_RETRY_DELAY:-5}"
  for attempt in $(seq 1 "$attempts"); do
    if "${scp_args[@]}" "$source" "${name}:${destination}"; then
      return 0
    fi
    if [ "$attempt" = "$attempts" ]; then
      break
    fi
    echo "scp to ${name} failed; retrying in ${delay}s (${attempt}/${attempts})" >&2
    sleep "$delay"
  done

  echo "scp to ${name} failed after ${attempts} attempts: ${source} -> ${destination}" >&2
  return 1
}

rsync_to_remote() {
  local name="$1"
  local source="$2"
  local destination="$3"
  local attempt attempts delay
  local -a rsync_args

  command -v rsync >/dev/null 2>&1 || {
    echo "local rsync is required for bundle upload" >&2
    exit 1
  }
  run_remote_command "$name" "command -v rsync >/dev/null 2>&1 || sudo env DEBIAN_FRONTEND=noninteractive sh -lc 'apt-get update && apt-get install -y rsync'" >/dev/null

  rsync_args=(rsync -az --checksum --human-readable --progress)
  if [ -f "$SSH_CONFIG_FILE" ]; then
    rsync_args+=(-e "ssh -F $SSH_CONFIG_FILE -o BatchMode=yes")
  else
    rsync_args+=(-e "ssh -o BatchMode=yes")
  fi

  attempts="${SSH_TRANSFER_ATTEMPTS:-5}"
  delay="${SSH_TRANSFER_RETRY_DELAY:-5}"
  for attempt in $(seq 1 "$attempts"); do
    if "${rsync_args[@]}" "$source" "${name}:${destination}"; then
      return 0
    fi
    if [ "$attempt" = "$attempts" ]; then
      break
    fi
    echo "rsync to ${name} failed; retrying in ${delay}s (${attempt}/${attempts})" >&2
    sleep "$delay"
  done

  echo "rsync to ${name} failed after ${attempts} attempts: ${source} -> ${destination}" >&2
  return 1
}

ensure_parth_bundle_cache() {
  local bundle="$1"
  local bundle_sha="$2"
  local bundle_size="$3"
  local remote_source="${4:-}"
  local cache_host="${PARTH_BUNDLE_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}"
  local cache_dir="${PARTH_BUNDLE_CACHE_DIR:-/tmp/parth-bundle-cache}"
  local cache_port="${PARTH_BUNDLE_CACHE_PORT:-18088}"
  local cache_bind_addr
  local remote_cache_dir="${cache_dir}/${bundle_sha}"
  local remote_cache_bundle="${remote_cache_dir}/parth-node-bundle.tar.gz"
  local remote_cache_sha="${remote_cache_dir}/.sha256"

  provision_vm "$cache_host"
  cache_bind_addr="${PARTH_BUNDLE_CACHE_BIND_ADDR:-$(ssh_service_endpoint "$cache_host")}"
  run_remote_command "$cache_host" "missing=''; command -v rsync >/dev/null 2>&1 || missing=\"\$missing rsync\"; command -v python3 >/dev/null 2>&1 || missing=\"\$missing python3\"; command -v ss >/dev/null 2>&1 || missing=\"\$missing iproute2\"; if [ -n \"\$missing\" ]; then sudo env DEBIAN_FRONTEND=noninteractive sh -lc \"apt-get update && apt-get install -y \$missing\"; fi"
  run_remote_command "$cache_host" "mkdir -p '$remote_cache_dir'"

  if run_remote_command "$cache_host" "[ -f '$remote_cache_sha' ] && [ \"\$(cat '$remote_cache_sha')\" = '$bundle_sha' ] && [ -f '$remote_cache_bundle' ]" >/dev/null 2>&1; then
    echo "Parth bundle already staged on cache host ${cache_host}: sha256=${bundle_sha}"
  elif [ -n "$remote_source" ] && run_remote_command "$cache_host" "[ -f '$remote_source' ] && [ \"\$(sha256sum '$remote_source' | awk '{ print \$1 }')\" = '$bundle_sha' ]" >/dev/null 2>&1; then
    echo "staging Parth bundle on cache host from existing remote file: ${cache_host}:${remote_source} -> ${remote_cache_bundle}"
    run_remote_command "$cache_host" "cp '$remote_source' '$remote_cache_bundle'; printf '%s\n' '$bundle_sha' > '$remote_cache_sha'"
  else
    echo "staging Parth bundle on cache host with rsync --checksum: $bundle (${bundle_size}, sha256=${bundle_sha}) -> ${cache_host}:${remote_cache_bundle}"
    rsync_to_remote "$cache_host" "$bundle" "$remote_cache_bundle"
    run_remote_command "$cache_host" "printf '%s\n' '$bundle_sha' > '$remote_cache_sha'"
  fi

  run_remote_command "$cache_host" "find '$cache_dir' -mindepth 1 -maxdepth 1 -type d ! -name '$bundle_sha' -print -exec rm -rf {} +"

  if run_remote_command "$cache_host" "ss -ltn | awk '{ print \$4 }' | grep -Eq '(^|:)${cache_port}$'" >/dev/null 2>&1; then
    echo "Parth bundle cache server already listening on ${cache_host}:${cache_port}"
  else
    echo "starting Parth bundle cache server on ${cache_host}:${cache_bind_addr}:${cache_port}"
    run_remote_command "$cache_host" "nohup python3 -m http.server '$cache_port' --bind '$cache_bind_addr' --directory '$cache_dir' >/tmp/parth-bundle-cache-http.log 2>&1 &"
  fi
}

parth_bundle_cache_url() {
  local bundle_sha="$1"
  local cache_host="${PARTH_BUNDLE_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}"
  local cache_port="${PARTH_BUNDLE_CACHE_PORT:-18088}"
  local cache_endpoint

  cache_endpoint="${PARTH_BUNDLE_CACHE_ENDPOINT:-$(ssh_service_endpoint "$cache_host")}"
  printf 'http://%s:%s/%s/parth-node-bundle.tar.gz\n' "$cache_endpoint" "$cache_port" "$bundle_sha"
}

remote_private_ip() {
  local name="$1"

  run_remote_command "$name" "ip_addr=\$(hostname -I | awk '{ for (i = 1; i <= NF; i++) if (\$i !~ /^127\\./ && \$i !~ /^169\\.254\\./ && \$i !~ /:/) { print \$i; exit } }'); if [ -z \"\$ip_addr\" ]; then ip_addr=\$(ip -o -4 addr show scope global | awk '{ split(\$4, a, \"/\"); print a[1]; exit }'); fi; [ -n \"\$ip_addr\" ] || exit 1; printf '%s\n' \"\$ip_addr\""
}

ssh_service_endpoint() {
  local name="$1"

  case "$SSH_SERVICE_ENDPOINT_MODE" in
    private-ip)
      remote_private_ip "$name"
      ;;
    ssh-hostname)
      if [ -f "$SSH_CONFIG_FILE" ]; then
        ssh -F "$SSH_CONFIG_FILE" -G "$name" | awk '/^hostname / { print $2; exit }'
      else
        ssh -G "$name" | awk '/^hostname / { print $2; exit }'
      fi
      ;;
    ssh-alias)
      printf '%s\n' "$name"
      ;;
    *)
      echo "SSH_SERVICE_ENDPOINT_MODE must be private-ip, ssh-hostname, or ssh-alias" >&2
      exit 1
      ;;
  esac
}

instance_internal_ip() {
  remote_private_ip "$1"
}

instance_internal_dns() {
  ssh_service_endpoint "$1"
}

wait_ssh_ready() {
  local name="$1"

  for _ in $(seq 1 60); do
    if run_remote_command "$name" "true" >/dev/null 2>&1; then
      echo "SSH is ready: $name"
      return 0
    fi
    echo "waiting for SSH: $name"
    sleep 5
  done

  echo "timed out waiting for SSH: $name" >&2
  return 1
}

provision_vm() {
  local name="$1"

  echo "using existing SSH host: $name"
  wait_ssh_ready "$name"
}

run_remote_script() {
  local name="$1"
  local script_path="$2"
  shift 2

  local remote
  local -a env_args

  remote="/tmp/$(basename "$script_path")"
  scp_to_remote "$name" "$script_path" "$remote"
  for support in install-docker.sh mount-data-disk.sh prepare-parth-host.sh nostr-maintenance.sh write-relayer-config.sh; do
    if [ -f "$GCP_DIR/remote/$support" ]; then
      scp_to_remote "$name" "$GCP_DIR/remote/$support" "/tmp/$support"
    fi
  done

  env_args=()
  for key in DATA_DISK_DEVICE DATA_DISK_MOUNTPOINT; do
    if [[ -v "$key" ]]; then
      env_args+=("$(printf '%q' "${key}=${!key}")")
    fi
  done
  for item in "$@"; do
    env_args+=("$(printf '%q' "$item")")
  done

  run_remote_command "$name" "sudo env ${env_args[*]} bash '$remote'"
}

run_health_check() {
  local name="$1"
  local mode="$2"
  shift 2

  run_remote_script "$name" "$GCP_DIR/remote/health-check.sh" \
    "HEALTHCHECK_MODE=$mode" \
    "HEALTHCHECK_ATTEMPTS=${HEALTHCHECK_ATTEMPTS:-60}" \
    "HEALTHCHECK_DELAY=${HEALTHCHECK_DELAY:-2}" \
    "HEALTHCHECK_START_DELAY=${HEALTHCHECK_START_DELAY:-5}" \
    "$@"
}

upload_bundle_if_configured() {
  local name="$1"
  local bundle="${PARTH_BUNDLE:-}"
  local remote_bundle="/tmp/parth-node-bundle.tar.gz"
  local bundle_size
  local bundle_sha
  local cache_host="${PARTH_BUNDLE_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}"
  local distribution_mode="${PARTH_BUNDLE_DISTRIBUTION_MODE:-cache-host}"
  local cache_url

  [ -z "$bundle" ] && return 0
  [ -f "$bundle" ] || {
    echo "PARTH_BUNDLE does not exist: $bundle" >&2
    exit 1
  }

  bundle_size="$(du -h "$bundle" | awk '{ print $1 }')"
  bundle_sha="$(sha256sum "$bundle" | awk '{ print $1 }')"

  if run_remote_command "$name" "sudo sh -lc '[ -f /opt/parth/current/.bundle.sha256 ] && [ \"\$(cat /opt/parth/current/.bundle.sha256)\" = \"$bundle_sha\" ]'" >/dev/null 2>&1; then
    echo "Parth bundle already installed on ${name}: sha256=${bundle_sha}; skipping upload"
    return 0
  fi

  run_remote_command "$name" "if [ -d /opt/parth/releases ]; then current=\$(readlink -f /opt/parth/current 2>/dev/null || true); find /opt/parth/releases -mindepth 1 -maxdepth 1 -type d | while IFS= read -r release; do if [ -n \"\$current\" ] && [ \"\$release\" = \"\$current\" ]; then continue; fi; echo removing old Parth release before upload: \"\$release\"; sudo rm -rf \"\$release\"; done; fi; sudo rm -f '$remote_bundle'" || true

  if [ "$distribution_mode" = "cache-host" ] && [ "$name" != "$cache_host" ]; then
    ensure_parth_bundle_cache "$bundle" "$bundle_sha" "$bundle_size"
    cache_url="$(parth_bundle_cache_url "$bundle_sha")"
    echo "downloading Parth bundle from cache host over VPC: ${cache_url} -> ${name}:${remote_bundle}"
    if run_remote_command "$name" "[ -f '$remote_bundle' ] && [ \"\$(sha256sum '$remote_bundle' | awk '{ print \$1 }')\" = '$bundle_sha' ]" >/dev/null 2>&1; then
      echo "Parth bundle already present in upload cache on ${name}: ${remote_bundle}; skipping download"
    else
      run_remote_command "$name" "command -v curl >/dev/null 2>&1 || sudo env DEBIAN_FRONTEND=noninteractive sh -lc 'apt-get update && apt-get install -y curl'; curl -fL --retry 3 --connect-timeout 10 '$cache_url' -o '${remote_bundle}.tmp'; test \"\$(sha256sum '${remote_bundle}.tmp' | awk '{ print \$1 }')\" = '$bundle_sha'; mv '${remote_bundle}.tmp' '$remote_bundle'"
      echo "downloaded Parth bundle from cache host: ${name}:${remote_bundle}"
    fi
  else
    echo "uploading Parth bundle with rsync --checksum: $bundle (${bundle_size}, sha256=${bundle_sha}) -> ${name}:${remote_bundle}"
    if run_remote_command "$name" "[ -f '$remote_bundle' ] && [ \"\$(sha256sum '$remote_bundle' | awk '{ print \$1 }')\" = '$bundle_sha' ]" >/dev/null 2>&1; then
      echo "Parth bundle already present in upload cache on ${name}: ${remote_bundle}; skipping transfer"
    else
      rsync_to_remote "$name" "$bundle" "$remote_bundle"
      echo "uploaded Parth bundle: ${name}:${remote_bundle}"
    fi
    if [ "$distribution_mode" = "cache-host" ] && [ "$name" = "$cache_host" ]; then
      ensure_parth_bundle_cache "$bundle" "$bundle_sha" "$bundle_size" "$remote_bundle"
    fi
  fi
  run_remote_script "$name" "$GCP_DIR/remote/install-parth-bundle.sh" \
    "PARTH_BUNDLE_SHA256=$bundle_sha" \
    "PARTH_KEEP_RELEASES=${PARTH_KEEP_RELEASES:-2}" \
    "PARTH_ALLOW_GENESIS_OVERWRITE=${PARTH_ALLOW_GENESIS_OVERWRITE:-0}"
}

upload_envio_bundle() {
  local name="$1"
  local bundle="$2"
  local remote_bundle="/tmp/parth-envio-bundle.tar.gz"
  local bundle_size
  local bundle_sha

  [ -f "$bundle" ] || {
    echo "Envio bundle does not exist: $bundle" >&2
    exit 1
  }

  bundle_size="$(du -h "$bundle" | awk '{ print $1 }')"
  bundle_sha="$(sha256sum "$bundle" | awk '{ print $1 }')"

  if run_remote_command "$name" "[ -f /opt/parth/envio/current/.bundle.sha256 ] && [ \"\$(cat /opt/parth/envio/current/.bundle.sha256)\" = '$bundle_sha' ]" >/dev/null 2>&1; then
    echo "Envio bundle already installed on ${name}: sha256=${bundle_sha}; skipping upload"
    return 0
  fi

  echo "uploading Envio bundle with rsync --checksum: $bundle (${bundle_size}, sha256=${bundle_sha}) -> ${name}:${remote_bundle}"
  if run_remote_command "$name" "[ -f '$remote_bundle' ] && [ \"\$(sha256sum '$remote_bundle' | awk '{ print \$1 }')\" = '$bundle_sha' ]" >/dev/null 2>&1; then
    echo "Envio bundle already present in upload cache on ${name}: ${remote_bundle}; skipping transfer"
  else
    rsync_to_remote "$name" "$bundle" "$remote_bundle"
    echo "uploaded Envio bundle: ${name}:${remote_bundle}"
  fi
  run_remote_script "$name" "$GCP_DIR/remote/install-envio-bundle.sh" "ENVIO_BUNDLE_SHA256=$bundle_sha"
}

ensure_parth_vm() {
  local name="$1"

  provision_vm "$name"
  run_remote_script "$name" "$GCP_DIR/remote/prepare-parth-host.sh"
  upload_bundle_if_configured "$name"

  local bundle_expected=0
  [ -n "${PARTH_BUNDLE:-}" ] && bundle_expected=1
  run_health_check "$name" "parth-host" "PARTH_BUNDLE_EXPECTED=$bundle_expected"
}

ensure_postgres_database() {
  local db="$1"
  local name="${POSTGRES_VM_NAME:-gcp-postgres}"
  local user="${POSTGRES_USER:-postgres}"
  local password="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
  local user_q password_q db_q db_sql

  [[ "$db" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || {
    echo "invalid Postgres database name: $db" >&2
    exit 1
  }

  user_q="$(printf '%q' "$user")"
  password_q="$(printf '%q' "$password")"
  db_q="$(printf '%q' "$db")"
  db_sql="${db//\'/\'\'}"

  echo "ensuring Postgres database exists: ${db} on ${name}"
  run_remote_command "$name" "sudo env PGPASSWORD=$password_q docker exec -e PGPASSWORD parth-postgres psql -U $user_q -d postgres -tAc \"SELECT 1 FROM pg_database WHERE datname='${db_sql}'\" | grep -q 1 || sudo env PGPASSWORD=$password_q docker exec -e PGPASSWORD parth-postgres createdb -U $user_q $db_q"
}

parth_common_env_args() {
  local scylla_host nats_host redis_host

  scylla_host="${SCYLLA_HOST:-$(instance_internal_dns "${SCYLLA_VM_NAME:-gcp-scylla}")}"
  nats_host="${NATS_HOST:-$(instance_internal_dns "${NATS_VM_NAME:-gcp-nats}")}"
  redis_host="${REDIS_HOST:-$(instance_internal_dns "${REDIS_VM_NAME:-gcp-redis}")}"

  printf '%s\n' \
    "PARTH_NETWORK=${PARTH_NETWORK:-local-devnet}" \
    "PROVING_BACKEND=${PROVING_BACKEND:-plonky2-poseidon-goldilocks}" \
    "SCYLLA_DB_URL=${SCYLLA_DB_URL:-${scylla_host}:9042}" \
    "NATS_JETSTREAM_URL=${NATS_JETSTREAM_URL:-nats://${nats_host}:4222}" \
    "REDIS_URL=${REDIS_URL:-redis://${redis_host}:6379}" \
    "NATS_EPHEMERAL_ACK_WAIT_MS=${NATS_EPHEMERAL_ACK_WAIT_MS:-5000}" \
    "NATS_WORKER_ACK_WAIT_MS=${NATS_WORKER_ACK_WAIT_MS:-30000}" \
    "NATS_EPHEMERAL_INACTIVE_THRESHOLD_MS=${NATS_EPHEMERAL_INACTIVE_THRESHOLD_MS:-600000}" \
    "NATS_WORKER_INACTIVE_THRESHOLD_MS=${NATS_WORKER_INACTIVE_THRESHOLD_MS:-3600000}"
  [ -n "${RUST_LOG:-}" ] && printf '%s\n' "RUST_LOG=$RUST_LOG"
  [ -n "${RUST_BACKTRACE:-}" ] && printf '%s\n' "RUST_BACKTRACE=$RUST_BACKTRACE"
  [ -n "${VERBOSE:-}" ] && printf '%s\n' "VERBOSE=$VERBOSE"
}

deploy_parth_service() {
  local name="$1"
  local service="$2"
  local target="$3"
  local unit="$4"
  shift 4

  local -a common_args service_args
  mapfile -t common_args < <(parth_common_env_args)
  service_args=(
    "PARTH_SERVICE=$service"
    "PARTH_MAKE_TARGET=$target"
    "PARTH_SYSTEMD_UNIT=$unit"
    "DEPLOY_INSTANCE=${DEPLOY_INSTANCE:-0}"
    "DEPLOY_PSY_SERVICES_HOME=${DEPLOY_PSY_SERVICES_HOME:-/opt/parth/current/psy-services}"
  )

  run_remote_script "$name" "$GCP_DIR/remote/deploy-parth-service.sh" \
    "${common_args[@]}" \
    "${service_args[@]}" \
    "$@"
  run_health_check "$name" "systemd" "SYSTEMD_UNIT=$unit"
}
