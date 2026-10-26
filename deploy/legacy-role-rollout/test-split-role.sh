#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for script in remote-proxy.sh remote-proxy-split.sh remote-relayer.sh run-role.sh gateway-system-proxy.sh stage-role-release.sh; do
  bash -n "$HERE/$script"
done
# Test the actual jq predicates used by both deployment gates against good,
# mixed-role, legacy, malformed-capability and JSON-RPC error responses.
user_filter=$(sed -n 's/.*jq -e '\''\(.*\)'\'' >\/dev\/null.*/\1/p' "$HERE/remote-proxy-split.sh" | head -n 1)
system_filter=$(sed -n 's/.*jq -e '\''\(.*\)'\'' >\/dev\/null.*/\1/p' "$HERE/remote-relayer.sh" | head -n 1)
test -n "$user_filter"
test -n "$system_filter"
user='{"result":{"role":"user","user_methods":true,"system_methods":false}}'
system='{"result":{"role":"system","user_methods":false,"system_methods":true}}'
jq -en --argjson response "$user" '$response' | jq -e "$user_filter" >/dev/null
jq -en --argjson response "$system" '$response' | jq -e "$system_filter" >/dev/null
for invalid in \
  '{"result":{"role":"all","user_methods":true,"system_methods":true}}' \
  '{"error":{"code":-32601}}' \
  '{"result":{"role":"system","system_methods":"true","user_methods":false}}' \
  '{"result":{"role":"user","user_methods":true,"system_methods":true}}' \
  '{"result":{"role":"system","system_methods":true}}'; do
  if printf '%s' "$invalid" | jq -e "$user_filter" >/dev/null; then exit 1; fi
  if printf '%s' "$invalid" | jq -e "$system_filter" >/dev/null; then exit 1; fi
done
if printf '%s' "$system" | jq -e "$user_filter" >/dev/null; then exit 1; fi
if printf '%s' "$user" | jq -e "$system_filter" >/dev/null; then exit 1; fi
# shellcheck disable=SC2016
grep -Fq -- '--role "$role"' "$HERE/run-role.sh"
grep -Fq 'user) addr=10.250.0.12:9999' "$HERE/run-role.sh"
grep -Fq 'system) addr=10.250.0.12:9998' "$HERE/run-role.sh"
grep -Fq 'url=http://10.148.0.32:19998' "$HERE/remote-relayer.sh"
echo 'PASS: separate roles, strict capability gates, port routing, and shell syntax'
