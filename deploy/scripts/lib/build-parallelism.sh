#!/usr/bin/env bash

detect_rust_build_jobs() {
  local cpu_count memory_available_kib memory_per_job_mib memory_per_job_kib
  local memory_jobs jobs

  if command -v nproc >/dev/null 2>&1; then
    cpu_count="$(nproc)"
  elif command -v getconf >/dev/null 2>&1; then
    cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
  else
    cpu_count=1
  fi

  memory_available_kib="${RUST_BUILD_AVAILABLE_MEMORY_KIB:-}"
  if [ -z "$memory_available_kib" ] && [ -r /proc/meminfo ]; then
    memory_available_kib="$(awk '$1 == "MemAvailable:" { print $2; exit }' /proc/meminfo)"
  fi
  memory_available_kib="${memory_available_kib:-0}"

  memory_per_job_mib="${RUST_BUILD_MEMORY_PER_JOB_MIB:-3072}"
  case "$memory_per_job_mib" in
    ''|*[!0-9]*|0)
      echo "RUST_BUILD_MEMORY_PER_JOB_MIB must be a positive integer" >&2
      return 1
      ;;
  esac

  jobs="$cpu_count"
  if [ "$memory_available_kib" -gt 0 ]; then
    memory_per_job_kib=$((memory_per_job_mib * 1024))
    memory_jobs=$((memory_available_kib / memory_per_job_kib))
    [ "$memory_jobs" -ge 1 ] || memory_jobs=1
    [ "$memory_jobs" -ge "$jobs" ] || jobs="$memory_jobs"
  fi

  [ "$jobs" -ge 1 ] || jobs=1
  printf '%s\n' "$jobs"
}

resolve_rust_build_jobs() {
  local requested="${1:-${LOCAL_RUST_BUILD_JOBS:-}}"

  if [ -z "$requested" ]; then
    detect_rust_build_jobs
    return
  fi

  case "$requested" in
    ''|*[!0-9]*|0)
      echo "Rust build jobs must be a positive integer, got: $requested" >&2
      return 1
      ;;
  esac
  printf '%s\n' "$requested"
}
