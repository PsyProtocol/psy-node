#!/usr/bin/env bash
set -euo pipefail
role=${1:?user or system}
case "$role" in
  user) addr=10.250.0.12:9999 ;;
  system) addr=10.250.0.12:9998 ;;
  *) echo 'Expected user or system' >&2; exit 2 ;;
esac
addr=${PROVE_PROXY_ROLE_LISTEN_ADDR:-$addr}
exec /opt/parth/prove-proxy-role-releases/3a81f59e/psy_user_cli prove-proxy \
  --role "$role" --listen-addr "$addr" \
  --rpc-config "${RPC_CONFIG:-${PARTH_HOME:-/opt/parth/current}/client_prover/config.json}"
