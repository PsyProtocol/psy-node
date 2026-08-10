#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

export PSY_D04B6H23C4C2B3B2C2B_TEST_NAME="rollback::realm_user_update_admission_rf3::d04b6h23c4c2b3b4_direct_durable_consumer_rf3"
export PSY_D04B6H23C4C2B3B2C2B_REPORT_OVERRIDE="${WORKSPACE_DIR}/target/d04b6h23c4c2b3b4-direct-durable-consumer-rf3-report.json"

exec "${SCRIPT_DIR}/run-d04b6h23c4c2b3b2c2b.sh"
