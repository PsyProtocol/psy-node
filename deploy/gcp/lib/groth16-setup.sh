#!/usr/bin/env bash

groth16_setup_file_mtime() {
  local path="$1"
  [ -e "$path" ] || {
    printf '0\n'
    return 0
  }
  stat -c '%Y' "$path" 2>/dev/null || printf '0\n'
}

groth16_setup_path_newest_mtime() {
  local path="$1"
  local ts

  if [ -f "$path" ]; then
    groth16_setup_file_mtime "$path"
    return 0
  fi
  if [ -d "$path" ]; then
    ts="$(
      find "$path" -type f -printf '%T@\n' 2>/dev/null \
        | sort -nr \
        | head -n 1 \
        | awk -F. '{ print $1 }'
    )"
    printf '%s\n' "${ts:-0}"
    return 0
  fi
  printf '0\n'
}

groth16_setup_relevant_paths() {
  local kind="$1"

  case "$kind" in
    bridge)
      printf '%s\n' \
        "$PARTH_DIR/psy_plonky2_circuits/src/bridge" \
        "$PARTH_DIR/psy_plonky2_circuits/src/circuit_library" \
        "$PARTH_DIR/psy_plonky2_circuits/src/generated/cached_circuit_library.rs" \
        "$PARTH_DIR/psy_cli/psy_relayer_cli/src/bridge"
      ;;
    deposit_batch_append)
      printf '%s\n' \
        "$PARTH_DIR/psy_plonky2_common_circuits/src/bridge/deposit_batch_append_circuit.rs" \
        "$PARTH_DIR/psy_plonky2_circuits/src/bridge/circuits/bridge_wrap.rs"
      ;;
    withdrawal_claim)
      printf '%s\n' \
        "$PARTH_DIR/psy_plonky2_common_circuits/src/bridge/withdrawal_batch_claim_circuit.rs" \
        "$PARTH_DIR/psy_plonky2_circuits/src/bridge/circuits/bridge_wrap.rs"
      ;;
    *)
      return 1
      ;;
  esac
}

groth16_setup_format_time() {
  local ts="$1"
  if [ "$ts" -gt 0 ] 2>/dev/null; then
    date -d "@$ts" '+%Y-%m-%d %H:%M:%S %z'
  else
    printf 'unknown'
  fi
}

groth16_setup_validate_freshness() {
  local kind="$1"
  local keystore_dir="$2"
  local host_hint="${3:-}"
  local setup_file setup_ts setup_oldest newest_ts newest_path path ts

  [ "${GROTH16_SKIP_SETUP_FRESHNESS_CHECK:-0}" != "1" ] || return 0

  setup_oldest=""
  for setup_file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    [ -s "$keystore_dir/$setup_file" ] || return 0
    setup_ts="$(groth16_setup_file_mtime "$keystore_dir/$setup_file")"
    if [ -z "$setup_oldest" ] || [ "$setup_ts" -lt "$setup_oldest" ]; then
      setup_oldest="$setup_ts"
    fi
  done

  newest_ts=0
  newest_path=""
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    ts="$(groth16_setup_path_newest_mtime "$path")"
    if [ "$ts" -gt "$newest_ts" ]; then
      newest_ts="$ts"
      newest_path="$path"
    fi
  done < <(groth16_setup_relevant_paths "$kind")

  if [ "${GROTH16_SETUP_CHECK_BINARY_MTIME:-0}" = "1" ] && [ -n "${PSY_GROTH16_CLI:-}" ]; then
    ts="$(groth16_setup_path_newest_mtime "$PSY_GROTH16_CLI")"
    if [ "$ts" -gt "$newest_ts" ]; then
      newest_ts="$ts"
      newest_path="$PSY_GROTH16_CLI"
    fi
  fi

  if [ "$newest_ts" -gt 0 ] && [ "$setup_oldest" -lt "$newest_ts" ]; then
    {
      printf 'Groth16 setup for %s is older than current circuit inputs.\n' "$kind"
      printf '  setup dir:    %s\n' "$keystore_dir"
      printf '  setup mtime:  %s\n' "$(groth16_setup_format_time "$setup_oldest")"
      printf '  newest input: %s (%s)\n' "$newest_path" "$(groth16_setup_format_time "$newest_ts")"
      printf '\n'
      printf 'Regenerate before deploying L1 verifier contracts, for example:\n'
      printf '  GROTH16_FORCE_REGENERATE=1 GROTH16_REGENERATE_SETUP=1 bash deploy/gcp/fresh-staging/15_upload_bridge_trust_setup.sh\n'
      if [ -n "$host_hint" ]; then
        printf 'or directly:\n'
        printf '  bash deploy/gcp/generate-upload-groth16-setup.sh --host %s --kind %s --force\n' "$host_hint" "$kind"
      fi
      printf '\n'
      printf 'Set GROTH16_SKIP_SETUP_FRESHNESS_CHECK=1 only after manually verifying the setup matches the current circuit.\n'
    } >&2
    return 1
  fi
}
