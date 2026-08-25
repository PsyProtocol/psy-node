#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"
run_gcp_script deploy-cp-ce-stack.sh
