#!/usr/bin/env bash

local_staging_source_env_defaults() {
  local env_file="$1"
  [ -f "$env_file" ] || return 0

  local line trimmed assignment name
  while IFS= read -r line || [ -n "$line" ]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    [ -n "$trimmed" ] || continue
    [[ "$trimmed" == \#* ]] && continue

    assignment="${trimmed#export }"
    [[ "$assignment" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]] || continue
    name="${BASH_REMATCH[1]}"
    if [ -z "${!name+x}" ]; then
      eval "$assignment"
      export "${name?}"
    fi
  done < "$env_file"
}

local_staging_dir() {
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

local_staging_parth_dir() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd
}

local_staging_compose() {
  local script_dir="$1"
  shift

  local compose_project="${LOCAL_STAGING_COMPOSE_PROJECT:-parth-local-staging}"

  if docker compose version >/dev/null 2>&1; then
    docker compose -p "$compose_project" -f "$script_dir/docker-compose.yml" "$@"
    return $?
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose -p "$compose_project" -f "$script_dir/docker-compose.yml" "$@"
    return $?
  fi

  echo "docker compose or docker-compose is required" >&2
  return 1
}

local_staging_wait_tcp() {
  local host="$1"
  local port="$2"
  local label="${3:-$host:$port}"
  local attempts="${4:-90}"
  local delay="${5:-2}"
  local i

  for i in $(seq 1 "$attempts"); do
    if timeout 2 bash -lc "</dev/tcp/$host/$port" >/dev/null 2>&1; then
      echo "[local-staging] ready: $label"
      return 0
    fi
    sleep "$delay"
  done

  echo "[local-staging] timed out waiting for $label" >&2
  return 1
}

local_staging_wait_http() {
  local url="$1"
  local label="${2:-$url}"
  local attempts="${3:-90}"
  local delay="${4:-2}"
  local i

  for i in $(seq 1 "$attempts"); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      echo "[local-staging] ready: $label"
      return 0
    fi
    sleep "$delay"
  done

  echo "[local-staging] timed out waiting for $label" >&2
  return 1
}

local_staging_wait_scylla_ready() {
  local container="${1:-parth-local-scylla}"
  local attempts="${2:-120}"
  local delay="${3:-5}"
  local i

  for i in $(seq 1 "$attempts"); do
    if docker exec "$container" nodetool status 2>/dev/null | grep -q 'UN'; then
      echo "[local-staging] ready: scylla CQL/node status"
      return 0
    fi
    # Recent Scylla images can make nodetool fail when the host AIO quota is
    # exhausted even though the server is already accepting CQL requests.
    if docker exec "$container" cqlsh -e \
      'SELECT release_version FROM system.local;' >/dev/null 2>&1; then
      echo "[local-staging] ready: scylla CQL query"
      return 0
    fi
    sleep "$delay"
    echo "[local-staging] waiting for Scylla node status (${i}/${attempts})"
  done

  echo "[local-staging] timed out waiting for Scylla node status" >&2
  return 1
}

local_staging_reverse_bits_in_limit() {
  local value="$1"
  local bit_count="$2"
  local out=0
  local i

  for ((i = 0; i < bit_count; i++)); do
    out=$(( (out << 1) | ((value >> i) & 1) ))
  done
  printf '%s\n' "$out"
}

local_staging_user_id_for_key_index() {
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

  reversed_realm_index="$(local_staging_reverse_bits_in_limit "$realm_index" "$group_realm_height")"
  reversed_user_index="$(local_staging_reverse_bits_in_limit "$user_index" "$realm_user_tree_height")"
  full_realm_id=$(( (group_id << group_realm_height) | reversed_realm_index ))
  printf '%s\n' "$(( (full_realm_id << realm_user_tree_height) | reversed_user_index ))"
}

local_staging_private_key_at_index() {
  local keys_file="$1"
  local index="$2"

  command -v jq >/dev/null 2>&1 || {
    echo "jq is required to read $keys_file" >&2
    return 1
  }
  [ -f "$keys_file" ] || {
    echo "missing private keys file: $keys_file" >&2
    return 1
  }

  jq -er --argjson index "$index" '
    .[$index]
    | select(type == "string")
    | select(test("^[0-9a-fA-F]{64}$"))
  ' "$keys_file"
}

local_staging_jsonrpc_result() {
  local url="$1"
  local method="$2"

  curl -fsS --max-time 5 "$url" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}"
}
