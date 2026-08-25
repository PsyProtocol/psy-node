#!/usr/bin/env bash
set -euo pipefail

systemctl --user --no-pager --full status \
  parth-local-coordinator-worker-tunnel.service \
  parth-local-coordinator-worker@0.service \
  parth-local-coordinator-worker@1.service || true
