#!/usr/bin/env bash
# Refuses an image variable that is unset or not pinned by digest; sourced before any other work.

require_pinned_image() {
  [[ "${!1:-}" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] || {
    echo "$1 must be set to an image pinned by digest (name@sha256:...)" >&2
    exit 1
  }
}
