#!/usr/bin/env bash
set -euo pipefail

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/common.sh
source "$GCP_DIR/lib/common.sh"

RELAYER_HOST_ALIAS="${RELAYER_VM_NAME:-gcp-relayer}"
RELAYER_UNIT="${RELAYER_UNIT:-parth-relayer.service}"
RELAYER_REMOTE_CONFIG="${RELAYER_REMOTE_CONFIG:-${RELAYER_CONFIG:-/etc/parth/bridge-relayer.toml}}"
SINCE="4 hours ago"
SAMPLES="20"

usage() {
  cat <<'USAGE'
Usage:
  bash deploy/gcp/check-relayer-withdrawal-deferral.sh [--since <journalctl since>] [--samples <n>]

Examples:
  bash deploy/gcp/check-relayer-withdrawal-deferral.sh
  bash deploy/gcp/check-relayer-withdrawal-deferral.sh --since "2026-05-01 08:00:00" --samples 20

What it verifies:
  - withdrawal append rounds land on L2 before finalize
  - the landed checkpoint is not rescanned until it satisfies confirmation_lag_checkpoints
  - the relayer waits services_event_settle_secs before rescanning psy-services
  - the rescan includes the landed checkpoint and observes appended withdrawals as already_appended
  - the round finalizes at or beyond the landed checkpoint instead of advancing past unseen events
USAGE
}

die() {
  echo "[check-relayer-withdrawal-deferral] failed: $*" >&2
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

echo "[check-relayer-withdrawal-deferral] relayer host: ${RELAYER_HOST_ALIAS}"
echo "[check-relayer-withdrawal-deferral] unit: ${RELAYER_UNIT}"
echo "[check-relayer-withdrawal-deferral] config: ${RELAYER_REMOTE_CONFIG}"
echo "[check-relayer-withdrawal-deferral] since: ${SINCE}"

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
leaf_re = re.compile(r"\bleaf_hash=([0-9a-fA-Fx]+)")

def parse_toml_int(text: str, key: str) -> int | None:
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*([0-9]+)\s*$", text)
    if not match:
        return None
    return int(match.group(1))

def parse_line(raw: str, idx: int) -> dict:
    line = ansi_re.sub("", raw)
    fields: dict[str, int | str | bool] = {"idx": idx, "line": line}
    for key, value in field_re.findall(line):
        if value.isdigit():
            fields[key] = int(value)
        elif value == "true":
            fields[key] = True
        elif value == "false":
            fields[key] = False
        else:
            fields[key] = value
    leaf_match = leaf_re.search(line)
    if leaf_match:
        fields["leaf_hash"] = leaf_match.group(1).lower()
    return fields

config = config_path.read_text()
configured_lag = parse_toml_int(config, "confirmation_lag_checkpoints")
configured_settle = parse_toml_int(config, "services_event_settle_secs")
configured_lookback = parse_toml_int(config, "withdrawal_scan_lookback_checkpoints")

if configured_lag is None:
    raise SystemExit("missing confirmation_lag_checkpoints in remote relayer config")
if configured_settle is None:
    raise SystemExit("missing services_event_settle_secs in remote relayer config")
if configured_lookback is None:
    raise SystemExit("missing withdrawal_scan_lookback_checkpoints in remote relayer config")

events: list[dict] = []
for idx, raw in enumerate(log_path.read_text(errors="replace").splitlines()):
    line = ansi_re.sub("", raw)
    marker = None
    if "evaluated raw withdrawal event" in line or "evaluated fallback withdrawal" in line:
        marker = "evaluated_withdrawal"
    elif "bridge L2 round withdrawal plan" in line:
        marker = "withdrawal_plan"
    elif "submitted combined L2 bridge round call" in line:
        marker = "submitted"
    elif "combined L2 bridge round call landed" in line:
        marker = "landed"
    elif "checkpoint has enough confirmations for bridge event scan" in line:
        marker = "confirmed"
    elif "waiting for psy-services contract-event visibility before rescanning bridge events" in line:
        marker = "settle"
    elif "bridge daemon finalized round" in line:
        marker = "finalized"
    if marker:
        item = parse_line(raw, idx)
        item["marker"] = marker
        events.append(item)

submissions = [
    e for e in events
    if e["marker"] == "submitted" and int(e.get("withdrawal_appends_count", 0)) > 0
]
submissions = submissions[-sample_count:]

if not submissions:
    raise SystemExit("no withdrawal append submissions found in the requested journal window")

errors: list[str] = []
checked: list[dict] = []

def next_event(after_idx: int, marker: str, predicate=lambda _e: True) -> dict | None:
    for event in events:
        if event["idx"] > after_idx and event["marker"] == marker and predicate(event):
            return event
    return None

for seq, submitted in enumerate(submissions, 1):
    submitted_idx = int(submitted["idx"])
    submitted_to = int(submitted.get("to_checkpoint", 0))
    submitted_scan_from = int(submitted.get("scan_from_checkpoint", 0))
    submitted_appends = int(submitted.get("withdrawal_appends_count", 0))

    pre_evals = [
        e for e in events
        if e["marker"] == "evaluated_withdrawal"
        and e["idx"] < submitted_idx
        and e["idx"] >= max(0, submitted_idx - 80)
        and e.get("already_appended") is False
    ]
    pre_leaf_hashes = {str(e["leaf_hash"]) for e in pre_evals if "leaf_hash" in e}

    landed = next_event(submitted_idx, "landed")
    if not landed:
        errors.append(f"submission {seq}: missing L2 landed log after withdrawal append submission")
        continue
    landed_checkpoint = int(landed.get("landed_checkpoint", 0))

    confirmed = next_event(
        int(landed["idx"]),
        "confirmed",
        lambda e: int(e.get("checkpoint_id", -1)) == landed_checkpoint,
    )
    if not confirmed:
        errors.append(
            f"submission {seq}: landed checkpoint {landed_checkpoint} was not confirmed by lag guard before rescan"
        )
        continue
    latest_checkpoint = int(confirmed.get("latest_checkpoint", 0))
    lag = int(confirmed.get("confirmation_lag_checkpoints", -1))
    if lag != configured_lag:
        errors.append(f"submission {seq}: lag guard used {lag}, config is {configured_lag}")
    if latest_checkpoint - lag < landed_checkpoint:
        errors.append(
            f"submission {seq}: lag guard accepted checkpoint {landed_checkpoint} before latest-lag ({latest_checkpoint}-{lag})"
        )

    settle = next_event(
        int(confirmed["idx"]),
        "settle",
        lambda e: int(e.get("landed_checkpoint", -1)) == landed_checkpoint,
    )
    if not settle:
        errors.append(f"submission {seq}: missing services visibility settle wait after checkpoint {landed_checkpoint}")
        continue
    settle_secs = int(settle.get("settle_secs", -1))
    if settle_secs != configured_settle:
        errors.append(f"submission {seq}: settle wait used {settle_secs}s, config is {configured_settle}s")

    post_evals = [
        e for e in events
        if e["marker"] == "evaluated_withdrawal"
        and e["idx"] > int(settle["idx"])
        and e.get("already_appended") is True
        and (not pre_leaf_hashes or str(e.get("leaf_hash", "")).lower() in pre_leaf_hashes)
    ]
    post_eval = post_evals[0] if post_evals else None

    post_plan = next_event(
        int(settle["idx"]),
        "withdrawal_plan",
        lambda e: int(e.get("scan_to_checkpoint", -1)) >= landed_checkpoint,
    )
    if not post_plan:
        errors.append(f"submission {seq}: missing withdrawal rescan through landed checkpoint {landed_checkpoint}")
        continue
    post_scan_to = int(post_plan.get("scan_to_checkpoint", 0))
    post_scan_from = int(post_plan.get("scan_from_checkpoint", 0))
    post_appends = int(post_plan.get("append_withdrawals_count", -1))
    post_claims = int(post_plan.get("claim_withdrawals_count", -1))
    if post_scan_to < landed_checkpoint:
        errors.append(
            f"submission {seq}: rescan only reached {post_scan_to}, below landed checkpoint {landed_checkpoint}"
        )
    if post_scan_from > submitted_scan_from:
        errors.append(
            f"submission {seq}: rescan started at {post_scan_from}, after original scan_from {submitted_scan_from}"
        )
    if post_appends != 0:
        errors.append(f"submission {seq}: rescan still wanted {post_appends} withdrawal appends")
    if pre_leaf_hashes and post_eval is None:
        errors.append(
            f"submission {seq}: no already_appended=true evaluation found after settle for appended withdrawal leaf"
        )

    finalized = next_event(
        int(post_plan["idx"]),
        "finalized",
        lambda e: int(e.get("to_checkpoint", -1)) >= landed_checkpoint,
    )
    if not finalized:
        errors.append(f"submission {seq}: no finalized round found at or beyond landed checkpoint {landed_checkpoint}")
        continue

    checked.append({
        "submitted_to": submitted_to,
        "submitted_appends": submitted_appends,
        "landed_checkpoint": landed_checkpoint,
        "latest_at_confirm": latest_checkpoint,
        "post_scan_from": post_scan_from,
        "post_scan_to": post_scan_to,
        "post_claims": post_claims,
        "finalized_to": int(finalized.get("to_checkpoint", 0)),
        "leaf_confirmed_appended": post_eval is not None,
    })

if errors:
    print("remote config:")
    print(f"  confirmation_lag_checkpoints={configured_lag}")
    print(f"  services_event_settle_secs={configured_settle}")
    print(f"  withdrawal_scan_lookback_checkpoints={configured_lookback}")
    print("")
    print("violations:")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print("remote config:")
print(f"  confirmation_lag_checkpoints={configured_lag}")
print(f"  services_event_settle_secs={configured_settle}")
print(f"  withdrawal_scan_lookback_checkpoints={configured_lookback}")
print("")
print(f"checked withdrawal append submissions: {len(checked)}")
print("latest checked deferral:")
for key, value in checked[-1].items():
    print(f"  {key}={value}")
print("")
print("result: OK - withdrawal append rounds waited, rescanned, observed appended leaves, and finalized safely")
PY
