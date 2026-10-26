#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

prove_proxy_host=""
if deploys_cloud_prove_proxy; then
  prove_proxy_host="${GROTH16_PROVE_PROXY_HOST:-${PROVE_PROXY_VM_NAME:-}}"
fi
host="${GROTH16_SETUP_HOST:-${prove_proxy_host:-${NODE_VM_NAME:-gcp-cp-ce}}}"
export GROTH16_SETUP_DISTRIBUTION_MODE="${GROTH16_SETUP_DISTRIBUTION_MODE:-cache-host}"
export GROTH16_SETUP_CACHE_HOST="${GROTH16_SETUP_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}"
required_kinds="${GROTH16_REQUIRED_KINDS:-bridge deposit_batch_append}"
optional_kinds="${GROTH16_OPTIONAL_KINDS:-withdrawal_claim}"
regenerate_all="${GROTH16_REGENERATE_SETUP:-0}"
force_regenerate="${GROTH16_FORCE_REGENERATE:-0}"
regenerate_kinds_raw="${GROTH16_REGENERATE_KINDS:-}"
regenerate_kinds_raw="${regenerate_kinds_raw//,/ }"
regenerate_kinds=" $regenerate_kinds_raw "

kind_env_suffix() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr '-' '_'
}

should_regenerate_kind() {
  local kind="$1"
  local required="${2:-1}"
  [ "$regenerate_all" = "1" ] && { [ "$required" = "1" ] || [ "${GROTH16_REGENERATE_OPTIONAL:-0}" = "1" ]; } && return 0
  case "$regenerate_kinds" in
    *" $kind "*) return 0 ;;
  esac
  return 1
}

run_setup_upload() {
  local kind="$1"
  local required="$2"
  local suffix wrapped_dir_var remote_wrapped_dir_var wrapped_dir remote_wrapped_dir
  local args

  suffix="$(kind_env_suffix "$kind")"
  wrapped_dir_var="GROTH16_WRAPPED_DIR_${suffix}"
  remote_wrapped_dir_var="GROTH16_REMOTE_WRAPPED_DIR_${suffix}"
  wrapped_dir="${!wrapped_dir_var:-}"
  remote_wrapped_dir="${!remote_wrapped_dir_var:-}"

  args=(--host "$host" --kind "$kind")
  if should_regenerate_kind "$kind" "$required"; then
    [ "$force_regenerate" != "1" ] || args+=(--force)
    if [ -n "$wrapped_dir" ]; then
      args+=(--wrapped-dir "$wrapped_dir")
    elif [ -n "$remote_wrapped_dir" ]; then
      args+=(--remote-wrapped-dir "$remote_wrapped_dir")
    else
      args+=(--pull-remote)
    fi
  else
    args+=(--upload-existing)
  fi
  [ "$required" = "1" ] || args+=(--skip-missing-existing)

  bash "$GCP_DIR/generate-upload-groth16-setup.sh" "${args[@]}"
}

upload_existing_setup_to_host() {
  local kind="$1"
  local required="$2"
  local target_host="$3"
  local args=(--host "$target_host" --kind "$kind" --upload-existing)

  [ "$required" = "1" ] || args+=(--skip-missing-existing)
  bash "$GCP_DIR/generate-upload-groth16-setup.sh" "${args[@]}"
}

for kind in $required_kinds; do
  log_step "uploading required Groth16 trust setup: ${kind}"
  run_setup_upload "$kind" 1
done

if [ "${GROTH16_UPLOAD_OPTIONAL:-1}" = "1" ]; then
  for kind in $optional_kinds; do
    log_step "uploading optional Groth16 trust setup if present: ${kind}"
    run_setup_upload "$kind" 0
  done
fi

if [ -n "$prove_proxy_host" ] && [ "$prove_proxy_host" != "$host" ]; then
  for kind in $required_kinds; do
    log_step "uploading required Groth16 trust setup to prove proxy: ${kind} -> ${prove_proxy_host}"
    upload_existing_setup_to_host "$kind" 1 "$prove_proxy_host"
  done

  if [ "${GROTH16_UPLOAD_OPTIONAL:-1}" = "1" ]; then
    for kind in $optional_kinds; do
      log_step "uploading optional Groth16 trust setup to prove proxy if present: ${kind} -> ${prove_proxy_host}"
      upload_existing_setup_to_host "$kind" 0 "$prove_proxy_host"
    done
  fi
fi
