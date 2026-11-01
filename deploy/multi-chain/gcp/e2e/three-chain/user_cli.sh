#!/usr/bin/env bash
# user_cli.sh <key file> <psy_user_cli args...>: run the user CLI as the user whose key is in the file.
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
user_cli_env
key_file=$1
shift
[ -f "$key_file" ] || { echo "three-chain: key file not found" >&2; exit 2; }
PRIVATE_KEY=$(cat "$key_file") exec "$E2E_USER_CLI" "$@"
