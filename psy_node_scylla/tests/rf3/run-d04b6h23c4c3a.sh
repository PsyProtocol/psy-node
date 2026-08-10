#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

export PSY_D04B6H23C4C3A_RF3=1
export PSY_D04B6H23C4C2B4E3_REPORT_OVERRIDE="${WORKSPACE_DIR}/target/d04b6h23c4c3a-durable-capture-owner-rf3-report.json"

exec "${SCRIPT_DIR}/run-d04b6h23c4c2b4e3.sh"
