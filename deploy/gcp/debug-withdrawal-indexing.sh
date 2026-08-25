#!/usr/bin/env bash
set -euo pipefail

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "$GCP_DIR/lib/common.sh"

FROM_CHECKPOINT=""
TO_CHECKPOINT=""
AROUND_CHECKPOINT=""
RADIUS="20"
SINCE=""
NO_LOGS="0"
WITHDRAWAL_CONTRACT_ID="${WITHDRAWAL_CONTRACT_ID:-0}"
WITHDRAWAL_METHOD_ID="${WITHDRAWAL_METHOD_ID:-${RELAYER_WITHDRAW_METHOD_ID:-4159421846}}"

usage() {
  cat <<'USAGE'
Usage:
  deploy/gcp/debug-withdrawal-indexing.sh --from <checkpoint> --to <checkpoint> [--since <journalctl since>]
  deploy/gcp/debug-withdrawal-indexing.sh --around <checkpoint> [--radius <n>] [--since <journalctl since>]

Examples:
  bash deploy/gcp/debug-withdrawal-indexing.sh --from 9036 --to 9055 --since "2026-05-01 03:00:00"
  bash deploy/gcp/debug-withdrawal-indexing.sh --around 9052 --radius 30

What it checks:
  - coordinator_checkpoints latest and checkpoint created_at in the range
  - contract_events rows in the range, especially withdrawal events
  - whether contract_events.created_at is later than coordinator_checkpoints.created_at
  - relayer logs that treated the range as empty
  - psy-services logs for contract_events submissions
USAGE
}

die() {
  echo "[debug-withdrawal-indexing] failed: $*" >&2
  exit 1
}

ssh_quick_args() {
  local host="$1"

  if [ -f "$SSH_CONFIG_FILE" ]; then
    printf '%s\n' \
      ssh \
      -F "$SSH_CONFIG_FILE" \
      -o BatchMode=yes \
      -o ConnectTimeout=10 \
      -o ServerAliveInterval=5 \
      -o ServerAliveCountMax=2 \
      "$host"
  else
    printf '%s\n' \
      ssh \
      -o BatchMode=yes \
      -o ConnectTimeout=10 \
      -o ServerAliveInterval=5 \
      -o ServerAliveCountMax=2 \
      "$host"
  fi
}

run_remote_quick() {
  local host="$1"
  local command="$2"
  local -a ssh_args

  mapfile -t ssh_args < <(ssh_quick_args "$host")
  "${ssh_args[@]}" "$command"
}

is_u64() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from)
      FROM_CHECKPOINT="${2:-}"
      shift 2
      ;;
    --to)
      TO_CHECKPOINT="${2:-}"
      shift 2
      ;;
    --around)
      AROUND_CHECKPOINT="${2:-}"
      shift 2
      ;;
    --radius)
      RADIUS="${2:-}"
      shift 2
      ;;
    --since)
      SINCE="${2:-}"
      shift 2
      ;;
    --no-logs)
      NO_LOGS="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

if [ -n "$AROUND_CHECKPOINT" ]; then
  is_u64 "$AROUND_CHECKPOINT" || die "--around must be an integer"
  is_u64 "$RADIUS" || die "--radius must be an integer"
  if [ "$AROUND_CHECKPOINT" -gt "$RADIUS" ]; then
    FROM_CHECKPOINT="$((AROUND_CHECKPOINT - RADIUS))"
  else
    FROM_CHECKPOINT="0"
  fi
  TO_CHECKPOINT="$((AROUND_CHECKPOINT + RADIUS))"
fi

[ -n "$FROM_CHECKPOINT" ] || die "--from or --around is required"
[ -n "$TO_CHECKPOINT" ] || die "--to or --around is required"
is_u64 "$FROM_CHECKPOINT" || die "--from must be an integer"
is_u64 "$TO_CHECKPOINT" || die "--to must be an integer"
[ "$FROM_CHECKPOINT" -le "$TO_CHECKPOINT" ] || die "--from must be <= --to"

POSTGRES_HOST_ALIAS="${POSTGRES_VM_NAME:-gcp-postgres}"
NODE_HOST_ALIAS="${NODE_VM_NAME:-gcp-cp-ce}"
RELAYER_HOST_ALIAS="${RELAYER_VM_NAME:-gcp-relayer}"
POSTGRES_DB="${PSY_SERVICES_DATABASE_NAME:-psy_services}"
POSTGRES_USER_VALUE="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD_VALUE="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required in deploy/gcp/config.env}"

if [ -z "$SINCE" ]; then
  # Wide enough for most staging debugging while keeping journal output bounded.
  SINCE="24 hours ago"
fi

sql_file="$(mktemp)"
trap 'rm -f "$sql_file"' EXIT

cat > "$sql_file" <<SQL
\\pset pager off
\\pset null '(null)'
\\timing on

\\echo ''
\\echo '=== latest coordinator checkpoints ==='
SELECT checkpoint_id, committed_at, created_at
FROM coordinator_checkpoints
ORDER BY checkpoint_id DESC
LIMIT 10;

\\echo ''
\\echo '=== coordinator checkpoints in requested range ==='
SELECT
  checkpoint_id,
  committed_at,
  created_at,
  ROUND(EXTRACT(EPOCH FROM (created_at - committed_at))::numeric, 3) AS created_minus_committed_sec
FROM coordinator_checkpoints
WHERE checkpoint_id BETWEEN :from_checkpoint AND :to_checkpoint
ORDER BY checkpoint_id ASC;

\\echo ''
\\echo '=== event counts in requested range, grouped by contract/method ==='
SELECT
  contract_id,
  method_id,
  COUNT(*) AS events,
  MIN(checkpoint_id) AS first_checkpoint,
  MAX(checkpoint_id) AS last_checkpoint,
  MIN(created_at) AS first_created_at,
  MAX(created_at) AS last_created_at
FROM contract_events
WHERE checkpoint_id BETWEEN :from_checkpoint AND :to_checkpoint
GROUP BY contract_id, method_id
ORDER BY events DESC, contract_id, method_id;

\\echo ''
\\echo '=== withdrawal events in requested range ==='
SELECT
  e.id,
  e.checkpoint_id,
  e.realm_id,
  e.user_id,
  e.event_index,
  e.created_at AS event_created_at,
  c.created_at AS checkpoint_created_at,
  ROUND(EXTRACT(EPOCH FROM (e.created_at - c.created_at))::numeric, 3) AS event_after_checkpoint_sec,
  e.data
FROM contract_events e
LEFT JOIN coordinator_checkpoints c ON c.checkpoint_id = e.checkpoint_id
WHERE e.checkpoint_id BETWEEN :from_checkpoint AND :to_checkpoint
  AND e.contract_id = :withdrawal_contract_id
  AND e.method_id = :withdrawal_method_id
ORDER BY e.checkpoint_id ASC, e.event_index ASC, e.id ASC;

\\echo ''
\\echo '=== checkpoint/event visibility summary ==='
SELECT
  c.checkpoint_id,
  c.created_at AS checkpoint_created_at,
  COUNT(e.id) AS withdrawal_events,
  MIN(e.created_at) AS first_withdrawal_event_created_at,
  MAX(e.created_at) AS last_withdrawal_event_created_at,
  ROUND(EXTRACT(EPOCH FROM (MIN(e.created_at) - c.created_at))::numeric, 3) AS first_event_after_checkpoint_sec
FROM coordinator_checkpoints c
LEFT JOIN contract_events e
  ON e.checkpoint_id = c.checkpoint_id
 AND e.contract_id = :withdrawal_contract_id
 AND e.method_id = :withdrawal_method_id
WHERE c.checkpoint_id BETWEEN :from_checkpoint AND :to_checkpoint
GROUP BY c.checkpoint_id, c.created_at
ORDER BY c.checkpoint_id ASC;

\\echo ''
\\echo '=== all events around checkpoints with created_at, useful when withdrawal filter is wrong ==='
SELECT
  id,
  checkpoint_id,
  realm_id,
  user_id,
  contract_id,
  method_id,
  event_index,
  created_at,
  data
FROM contract_events
WHERE checkpoint_id BETWEEN :from_checkpoint AND :to_checkpoint
ORDER BY checkpoint_id ASC, event_index ASC, id ASC
LIMIT 200;
SQL

echo "[debug-withdrawal-indexing] checkpoint range: ${FROM_CHECKPOINT}..${TO_CHECKPOINT}"
echo "[debug-withdrawal-indexing] withdrawal filter: contract_id=${WITHDRAWAL_CONTRACT_ID}, method_id=${WITHDRAWAL_METHOD_ID}"
echo "[debug-withdrawal-indexing] postgres host: ${POSTGRES_HOST_ALIAS}, database: ${POSTGRES_DB}"

run_remote_quick "$POSTGRES_HOST_ALIAS" "true" >/dev/null
mapfile -t postgres_ssh_args < <(ssh_quick_args "$POSTGRES_HOST_ALIAS")

"${postgres_ssh_args[@]}" \
  "sudo docker exec -i -e PGPASSWORD=$(printf '%q' "$POSTGRES_PASSWORD_VALUE") parth-postgres psql -U $(printf '%q' "$POSTGRES_USER_VALUE") -d $(printf '%q' "$POSTGRES_DB") -v ON_ERROR_STOP=1 -v from_checkpoint='${FROM_CHECKPOINT}' -v to_checkpoint='${TO_CHECKPOINT}' -v withdrawal_contract_id='${WITHDRAWAL_CONTRACT_ID}' -v withdrawal_method_id='${WITHDRAWAL_METHOD_ID}'" \
  < "$sql_file"

if [ "$NO_LOGS" = "1" ]; then
  exit 0
fi

echo ''
echo "[debug-withdrawal-indexing] relayer logs since: ${SINCE}"
if run_remote_quick "$RELAYER_HOST_ALIAS" "true" >/dev/null 2>&1; then
  run_remote_quick "$RELAYER_HOST_ALIAS" "
    sudo journalctl -u parth-relayer.service --since $(printf '%q' "$SINCE") --no-pager \
      | grep -E 'bridge relayer checkpoint window|bridge relayer starting append/finalize round|fetched events from psy-services|fetched bridge withdrawals fallback|no withdrawal events found|bridge L2 round withdrawal plan|evaluated raw withdrawal event|evaluated fallback withdrawal|claiming current batch withdrawals|batch withdrawal step finished|advancing claim cursor' \
      | tail -n 300 || true
  "
else
  echo "[debug-withdrawal-indexing] skipped relayer logs: cannot SSH to ${RELAYER_HOST_ALIAS}" >&2
fi

echo ''
echo "[debug-withdrawal-indexing] psy-services logs since: ${SINCE}"
if run_remote_quick "$NODE_HOST_ALIAS" "true" >/dev/null 2>&1; then
  run_remote_quick "$NODE_HOST_ALIAS" "
    sudo journalctl -u parth-psy-services.service --since $(printf '%q' "$SINCE") --no-pager \
      | grep -E 'Received contract_events submission|Failed to insert contract events|Failed to upsert event bloom filter|contract_events|checkpoint_id=' \
      | tail -n 300 || true
  "
else
  echo "[debug-withdrawal-indexing] skipped psy-services logs: cannot SSH to ${NODE_HOST_ALIAS}" >&2
fi

echo ''
echo "[debug-withdrawal-indexing] interpretation:"
echo "  - If event_created_at is later than a relayer 'treating range as empty' log, the event was API/DB-visible too late."
echo "  - If withdrawal_events=0 but all-events shows a similar event under a different contract_id/method_id, the relayer filter is wrong."
echo "  - If event rows existed before the relayer scan but relayer saw raw_events=0, query/API/filter behavior needs deeper inspection."
