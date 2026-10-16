#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ $# == 1 ]] || { echo 'Usage: bash check_host.sh local|x2|x3|x4' >&2; exit 1; }
exec python3 host_setup.py "$1" check
