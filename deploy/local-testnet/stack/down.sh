#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_STAGING_TOOLS_PARTH_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PARTH_DIR="${LOCAL_STAGING_SOURCE_PARTH_DIR:-$LOCAL_STAGING_TOOLS_PARTH_DIR}"

# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

: "${LOCAL_STAGING_STATE_DIR:=$PARTH_DIR/.local-staging}"

PID_DIR="$LOCAL_STAGING_STATE_DIR/pids"
KEEP_INFRA=0
REMOVE_VOLUMES=0

archive_local_runtime_state() {
  local archive_root="$LOCAL_STAGING_STATE_DIR/reset-archives"
  local archive_dir
  archive_dir="$archive_root/$(date -u +%Y%m%dT%H%M%SZ)-$$"
  local name
  local moved=0

  for name in checkpoints indexer-backups bridge-relayer; do
    if [ -e "$LOCAL_STAGING_STATE_DIR/$name" ]; then
      mkdir -p "$archive_dir"
      mv "$LOCAL_STAGING_STATE_DIR/$name" "$archive_dir/$name"
      moved=1
    fi
  done

  if [ "$moved" = "1" ]; then
    echo "[local-staging] archived local runtime state -> $archive_dir"
  fi
}

stop_runtime_pid() {
  local label="$1"
  local pid="$2"

  echo "[local-staging] stopping $label pid=$pid"
  # Most local services are launched with setsid. Stop the process group first
  # so wrapper processes such as pnpm/envio do not leave worker children behind.
  kill -- "-$pid" >/dev/null 2>&1 || true
  kill "$pid" >/dev/null 2>&1 || true
}

force_runtime_pid() {
  local pid="$1"

  kill -9 -- "-$pid" >/dev/null 2>&1 || true
  kill -9 "$pid" >/dev/null 2>&1 || true
}

stop_envio_orphans() {
  local envio_dir="$PARTH_DIR/psy_cli/psy_relayer_cli/indexer/envio"
  local pid

  {
    pgrep -f "$envio_dir/.*/envio dev --config ./config.yaml" || true
    pgrep -f "$envio_dir/generated/.*/ts-node/.*/bin.js src/Index.res.js" || true
  } | sort -u | while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" >/dev/null 2>&1; then
      stop_runtime_pid "envio-orphan" "$pid"
    fi
  done
}

for arg in "$@"; do
  case "$arg" in
    --keep-infra)
      KEEP_INFRA=1
      ;;
    --volumes)
      REMOVE_VOLUMES=1
      ;;
    *)
      echo "usage: $0 [--keep-infra] [--volumes]" >&2
      exit 1
      ;;
  esac
done

if [ -d "$PID_DIR" ]; then
  for pid_file in "$PID_DIR"/*.pid; do
    [ -e "$pid_file" ] || continue
    label="$(basename "$pid_file" .pid)"
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      stop_runtime_pid "$label" "$pid"
    fi
  done

  sleep 2

  for pid_file in "$PID_DIR"/*.pid; do
    [ -e "$pid_file" ] || continue
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
      echo "[local-staging] forcing pid=$pid"
      force_runtime_pid "$pid"
    fi
    rm -f "$pid_file"
  done
fi

stop_envio_orphans

if [ "$KEEP_INFRA" != "1" ]; then
  if [ "$REMOVE_VOLUMES" = "1" ]; then
    local_staging_compose "$SCRIPT_DIR" down -v
    archive_local_runtime_state
  else
    local_staging_compose "$SCRIPT_DIR" down
  fi
fi

echo "[local-staging] stopped"
