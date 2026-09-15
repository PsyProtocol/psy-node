#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec bash "$HERE/remote-proxy-split.sh" "${1:-deploy}"
