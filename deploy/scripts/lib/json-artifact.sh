#!/usr/bin/env bash

json_artifact_is_zstd() {
  local artifact_path="$1"
  local magic

  [ -f "$artifact_path" ] || return 1
  magic="$(od -An -tx1 -N4 "$artifact_path" | tr -d '[:space:]')"
  [ "$magic" = "28b52ffd" ]
}

json_artifact_cat() {
  local artifact_path="$1"

  [ -s "$artifact_path" ] || {
    echo "missing JSON artifact: $artifact_path" >&2
    return 1
  }

  if json_artifact_is_zstd "$artifact_path"; then
    command -v zstdcat >/dev/null 2>&1 || {
      echo "zstdcat is required to read compressed JSON artifact: $artifact_path" >&2
      return 1
    }
    zstdcat -- "$artifact_path"
  else
    cat -- "$artifact_path"
  fi
}

json_artifact_is_nonempty_array() {
  local artifact_path="$1"

  [ -s "$artifact_path" ] || return 1
  json_artifact_cat "$artifact_path" \
    | jq -e 'type == "array" and length > 0' >/dev/null 2>&1
}
