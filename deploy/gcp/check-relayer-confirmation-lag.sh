#!/usr/bin/env bash
set -euo pipefail

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "$GCP_DIR/lib/common.sh"

RELAYER_HOST_ALIAS="${RELAYER_VM_NAME:-gcp-relayer}"
RELAYER_UNIT="${RELAYER_UNIT:-parth-relayer.service}"
RELAYER_REMOTE_CONFIG="${RELAYER_REMOTE_CONFIG:-${RELAYER_CONFIG:-/etc/parth/bridge-relayer.toml}}"
SINCE="2 hours ago"
SAMPLES="20"

usage() {
  cat <<'USAGE'
Usage:
  bash deploy/gcp/check-relayer-confirmation-lag.sh [--since <journalctl since>] [--samples <n>]

Examples:
  bash deploy/gcp/check-relayer-confirmation-lag.sh
  bash deploy/gcp/check-relayer-confirmation-lag.sh --since "2026-05-01 08:00:00" --samples 50

What it verifies:
  - remote relayer config has confirmation_lag_checkpoints
  - each recent relayer round uses confirmed_to_checkpoint = latest_checkpoint - confirmation_lag_checkpoints
  - each to_checkpoint is <= confirmed_to_checkpoint
  - max_checkpoint_batch is also respected when configured
  - L2 calls that land after the initial scan window are not rescanned until they also satisfy the lag
USAGE
}

die() {
  echo "[check-relayer-confirmation-lag] failed: $*" >&2
  exit 1
}

is_u64() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --since)
      SINCE="${2:-}"
      shift 2
      ;;
    --samples)
      SAMPLES="${2:-}"
      shift 2
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

[ -n "$SINCE" ] || die "--since cannot be empty"
is_u64 "$SAMPLES" || die "--samples must be an integer"
[ "$SAMPLES" -gt 0 ] || die "--samples must be > 0"

tmp_config="$(mktemp)"
tmp_log="$(mktemp)"
trap 'rm -f "$tmp_config" "$tmp_log"' EXIT

echo "[check-relayer-confirmation-lag] relayer host: ${RELAYER_HOST_ALIAS}"
echo "[check-relayer-confirmation-lag] unit: ${RELAYER_UNIT}"
echo "[check-relayer-confirmation-lag] config: ${RELAYER_REMOTE_CONFIG}"
echo "[check-relayer-confirmation-lag] since: ${SINCE}"

run_remote_command "$RELAYER_HOST_ALIAS" "sudo cat '$RELAYER_REMOTE_CONFIG'" > "$tmp_config"
run_remote_command "$RELAYER_HOST_ALIAS" "sudo journalctl -u '$RELAYER_UNIT' --since '$SINCE' --no-pager -o cat" > "$tmp_log"

python3 - "$tmp_config" "$tmp_log" "$SAMPLES" <<'PY'
import re
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
sample_count = int(sys.argv[3])

ansi_re = re.compile(r"\x1b\[[0-9;]*m")
field_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=([A-Za-z0-9_]+)")

def parse_toml_int(text: str, key: str) -> int | None:
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*([0-9]+)\s*$", text)
    if not match:
        return None
    return int(match.group(1))

config = config_path.read_text()
configured_lag = parse_toml_int(config, "confirmation_lag_checkpoints")
configured_batch = parse_toml_int(config, "max_checkpoint_batch")

if configured_lag is None:
    raise SystemExit("missing confirmation_lag_checkpoints in remote relayer config")

rounds: list[dict[str, int | str]] = []
confirmed_waits: list[dict[str, int | str]] = []
for raw in log_path.read_text(errors="replace").splitlines():
    line = ansi_re.sub("", raw)
    fields: dict[str, int | str] = {}
    for key, value in field_re.findall(line):
        if value.isdigit():
            fields[key] = int(value)
        else:
            fields[key] = value
    if "bridge relayer starting append/finalize round" in line:
        rounds.append(fields)
    elif "checkpoint has enough confirmations for bridge event scan" in line:
        confirmed_waits.append(fields)

if not rounds:
    raise SystemExit("no relayer round logs found in the requested journal window")

rounds = rounds[-sample_count:]
confirmed_waits = confirmed_waits[-sample_count:]
errors: list[str] = []

for idx, fields in enumerate(rounds, 1):
    required = [
        "from_checkpoint",
        "to_checkpoint",
        "latest_checkpoint",
        "confirmation_lag_checkpoints",
        "confirmed_to_checkpoint",
        "max_checkpoint_batch",
    ]
    missing = [key for key in required if key not in fields]
    if missing:
        errors.append(f"round {idx}: missing fields: {', '.join(missing)}")
        continue

    from_checkpoint = int(fields["from_checkpoint"])
    to_checkpoint = int(fields["to_checkpoint"])
    latest_checkpoint = int(fields["latest_checkpoint"])
    lag = int(fields["confirmation_lag_checkpoints"])
    confirmed_to_checkpoint = int(fields["confirmed_to_checkpoint"])
    max_checkpoint_batch = int(fields["max_checkpoint_batch"])
    expected_confirmed = latest_checkpoint - lag

    if lag != configured_lag:
        errors.append(
            f"round {idx}: log lag {lag} != config lag {configured_lag}"
        )
    if latest_checkpoint < lag:
        errors.append(
            f"round {idx}: latest_checkpoint {latest_checkpoint} < lag {lag}; this round should not have started"
        )
    elif confirmed_to_checkpoint != expected_confirmed:
        errors.append(
            f"round {idx}: confirmed_to_checkpoint {confirmed_to_checkpoint} != latest_checkpoint - lag {expected_confirmed}"
        )
    if to_checkpoint > confirmed_to_checkpoint:
        errors.append(
            f"round {idx}: to_checkpoint {to_checkpoint} > confirmed_to_checkpoint {confirmed_to_checkpoint}"
        )
    if max_checkpoint_batch > 0:
        expected_batch_end = from_checkpoint + max_checkpoint_batch - 1
        if to_checkpoint > expected_batch_end:
            errors.append(
                f"round {idx}: to_checkpoint {to_checkpoint} > from + batch - 1 {expected_batch_end}"
            )

for idx, fields in enumerate(confirmed_waits, 1):
    required = ["checkpoint_id", "latest_checkpoint", "confirmation_lag_checkpoints"]
    missing = [key for key in required if key not in fields]
    if missing:
        errors.append(f"wait guard {idx}: missing fields: {', '.join(missing)}")
        continue

    checkpoint_id = int(fields["checkpoint_id"])
    latest_checkpoint = int(fields["latest_checkpoint"])
    lag = int(fields["confirmation_lag_checkpoints"])
    if lag != configured_lag:
        errors.append(
            f"wait guard {idx}: log lag {lag} != config lag {configured_lag}"
        )
    if latest_checkpoint < lag or latest_checkpoint - lag < checkpoint_id:
        errors.append(
            f"wait guard {idx}: checkpoint_id {checkpoint_id} was accepted before latest_checkpoint - lag ({latest_checkpoint} - {lag})"
        )

if errors:
    print("remote config:")
    print(f"  confirmation_lag_checkpoints={configured_lag}")
    if configured_batch is not None:
        print(f"  max_checkpoint_batch={configured_batch}")
    print("")
    print("violations:")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

latest = rounds[-1]
print("remote config:")
print(f"  confirmation_lag_checkpoints={configured_lag}")
if configured_batch is not None:
    print(f"  max_checkpoint_batch={configured_batch}")
print("")
print(f"checked rounds: {len(rounds)}")
print(f"checked landed-checkpoint wait guards: {len(confirmed_waits)}")
print("latest checked round:")
for key in [
    "from_checkpoint",
    "to_checkpoint",
    "latest_checkpoint",
    "confirmation_lag_checkpoints",
    "confirmed_to_checkpoint",
    "max_checkpoint_batch",
    "is_catchup_batch",
]:
    if key in latest:
        print(f"  {key}={latest[key]}")
print("")
print("result: OK - relayer did not scan past latest_checkpoint - confirmation_lag_checkpoints")
PY
