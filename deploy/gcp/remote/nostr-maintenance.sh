#!/usr/bin/env bash
set -euo pipefail

: "${NOSTR_HOME:=/opt/nostr-relay}"
: "${NOSTR_DB_PATH:=}"
: "${NOSTR_DISK_FREE_TARGET_PERCENT:=30}"
: "${NOSTR_RETENTION_WINDOWS_DAYS:=30 15 7 3 1}"
: "${NOSTR_SQLITE_BUSY_TIMEOUT_MS:=30000}"
: "${NOSTR_MAINTENANCE_LOCK_FILE:=/var/lock/nostr-maintenance.lock}"

log() {
  echo "[nostr-maintenance] $*"
}

fail() {
  echo "[nostr-maintenance] failed: $*" >&2
  exit 1
}

is_positive_int() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

free_percent() {
  df -P "$NOSTR_HOME" | awk 'NR == 2 { print int(($4 * 100) / $2) }'
}

find_db() {
  if [ -n "$NOSTR_DB_PATH" ]; then
    printf '%s\n' "$NOSTR_DB_PATH"
    return 0
  fi

  if [ -f "$NOSTR_HOME/data/nostr.db" ]; then
    printf '%s\n' "$NOSTR_HOME/data/nostr.db"
    return 0
  fi

  find "$NOSTR_HOME/data" "$NOSTR_HOME" -maxdepth 2 -type f \
    \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) \
    ! -name '*-wal' ! -name '*-shm' -print -quit 2>/dev/null
}

sqlite_scalar() {
  local db_path="$1"
  local sql="$2"

  sqlite3 "$db_path" "$sql" | tr -d '[:space:]'
}

event_column_exists() {
  local db_path="$1"
  local column="$2"

  [ "$(sqlite_scalar "$db_path" "SELECT COUNT(*) FROM pragma_table_info('event') WHERE lower(name)=lower('${column}');")" != "0" ]
}

cleanup_to_window() {
  local db_path="$1"
  local days="$2"
  local hidden_sql=""
  local hidden_count="0"
  local old_count

  if event_column_exists "$db_path" "hidden"; then
    hidden_sql="DELETE FROM event WHERE hidden=true;"
    hidden_count="$(sqlite_scalar "$db_path" "SELECT COUNT(*) FROM event WHERE hidden=true;")"
  fi
  old_count="$(sqlite_scalar "$db_path" "SELECT COUNT(*) FROM event WHERE first_seen < CAST(strftime('%s', date('now', '-${days} day')) AS INT);")"

  log "retention window ${days}d: hidden=${hidden_count}, old=${old_count}"
  sqlite3 "$db_path" >/dev/null <<SQL
.timeout ${NOSTR_SQLITE_BUSY_TIMEOUT_MS}
PRAGMA busy_timeout=${NOSTR_SQLITE_BUSY_TIMEOUT_MS};
PRAGMA foreign_keys = ON;
${hidden_sql}
DELETE FROM event WHERE first_seen < CAST(strftime('%s', date('now', '-${days} day')) AS INT);
PRAGMA wal_checkpoint(TRUNCATE);
VACUUM;
SQL
}

main() {
  local db_path
  local current_free
  local days

  is_positive_int "$NOSTR_DISK_FREE_TARGET_PERCENT" || fail "NOSTR_DISK_FREE_TARGET_PERCENT must be a positive integer"
  is_positive_int "$NOSTR_SQLITE_BUSY_TIMEOUT_MS" || fail "NOSTR_SQLITE_BUSY_TIMEOUT_MS must be a positive integer"

  exec 9>"$NOSTR_MAINTENANCE_LOCK_FILE"
  if ! flock -n 9; then
    log "another maintenance run is active; skipping"
    exit 0
  fi

  [ -d "$NOSTR_HOME" ] || fail "NOSTR_HOME does not exist: $NOSTR_HOME"
  db_path="$(find_db)"
  [ -n "$db_path" ] || fail "SQLite database was not found under $NOSTR_HOME"
  [ -f "$db_path" ] || fail "SQLite database does not exist: $db_path"

  sqlite3 "$db_path" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='event';" | grep -q 1 || fail "missing event table in $db_path"
  event_column_exists "$db_path" "first_seen" || fail "missing event.first_seen column in $db_path"

  current_free="$(free_percent)"
  log "free space before cleanup: ${current_free}%"
  if [ "$current_free" -ge "$NOSTR_DISK_FREE_TARGET_PERCENT" ]; then
    log "free space target already satisfied: ${current_free}% >= ${NOSTR_DISK_FREE_TARGET_PERCENT}%"
    exit 0
  fi

  for days in $NOSTR_RETENTION_WINDOWS_DAYS; do
    is_positive_int "$days" || fail "invalid retention window: $days"
    cleanup_to_window "$db_path" "$days"
    current_free="$(free_percent)"
    log "free space after ${days}d cleanup: ${current_free}%"
    if [ "$current_free" -ge "$NOSTR_DISK_FREE_TARGET_PERCENT" ]; then
      log "free space target satisfied after ${days}d cleanup"
      exit 0
    fi
  done

  fail "free space remains below target after all cleanup windows: ${current_free}% < ${NOSTR_DISK_FREE_TARGET_PERCENT}%"
}

main "$@"
