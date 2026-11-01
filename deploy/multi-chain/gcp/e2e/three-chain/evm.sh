#!/usr/bin/env bash
# evm.sh send|call|estimate <cast args...>: the EVM test wallet through the private gateway; the key never reaches a log.
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
e2e_require E2E_WALLET_KEY_FILE E2E_WALLET_ADDRESS
mode=$1
shift
case "$mode" in
  send) exec cast send "$@" --private-key "$(cat "$E2E_WALLET_KEY_FILE")" ;;
  call) exec cast call "$@" ;;
  estimate) exec cast estimate "$@" --from "$E2E_WALLET_ADDRESS" ;;
  *) echo "three-chain: unknown mode" >&2; exit 2 ;;
esac
