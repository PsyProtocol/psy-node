#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/gcp/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=deploy/gcp/lib/multichain.sh
source "$SCRIPT_DIR/lib/multichain.sh"

: "${PUBLIC_NOSTR_DOMAIN:=${NOSTR_DOMAIN}}"
: "${PUBLIC_RPC_DOMAIN:=${PUBLIC_L1_RPC_DOMAIN:-}}"
: "${PUBLIC_TRUST_SETUP_DOMAIN:=${PUBLIC_NOSTR_DOMAIN}}"
: "${PUBLIC_TRUST_SETUP_PATH:=/trust-setup}"
: "${TRUST_SETUP_ARCHIVE_NAME:=psy-groth16-trust-setup.tar.gz}"
: "${CHECK_PUBLIC_TRUST_SETUP:=1}"
: "${CORS_ORIGIN:=${PUBLIC_PRIVACY_BRIDGE_ORIGIN}}"
PUBLIC_L1_RPC_ROUTES_JSON="${PUBLIC_L1_RPC_ROUTES_JSON:-}"
if multichain_enabled; then
  PUBLIC_L1_RPC_ROUTES_JSON="$(multichain_public_rpc_routes_json)"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

pass() {
  printf '[ok] %s\n' "$1"
}

fail() {
  printf '[fail] %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

curl_expect_status() {
  local label="$1"
  local expected="$2"
  shift 2

  local body="$TMP_DIR/${label//[^A-Za-z0-9_.-]/_}.body"
  local status
  status="$(curl -sS --max-time 20 -o "$body" -w '%{http_code}' "$@")" || {
    cat "$body" >&2 || true
    fail "$label curl failed"
  }

  [ "$status" = "$expected" ] || {
    cat "$body" >&2 || true
    fail "$label expected HTTP $expected, got $status"
  }

  pass "$label HTTP $status"
}

jsonrpc_expect_result() {
  local label="$1"
  local url="$2"
  local method="$3"
  local params="${4:-[]}"
  local body="$TMP_DIR/${label//[^A-Za-z0-9_.-]/_}.json"
  local status

  status="$(curl -sS --max-time 30 -o "$body" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
    "$url")" || {
    cat "$body" >&2 || true
    fail "$label JSON-RPC curl failed"
  }

  [ "$status" = "200" ] || {
    cat "$body" >&2 || true
    fail "$label expected HTTP 200, got $status"
  }

  jq -e '.error == null and has("result")' "$body" >/dev/null || {
    cat "$body" >&2
    fail "$label JSON-RPC result missing"
  }

  pass "$label JSON-RPC ${method}"
}

jsonrpc_expect_chain_id() {
  local label="$1"
  local url="$2"
  local expected_chain_id="$3"
  local body="$TMP_DIR/${label//[^A-Za-z0-9_.-]/_}.chain-id.json"
  local status actual_hex actual_decimal

  status="$(curl -sS --max-time 30 -o "$body" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    "$url")" || fail "$label JSON-RPC curl failed"
  [ "$status" = "200" ] || fail "$label expected HTTP 200, got $status"
  actual_hex="$(jq -er '.result | select(type == "string" and test("^0x[0-9a-fA-F]+$"))' "$body")" || {
    cat "$body" >&2
    fail "$label returned an invalid eth_chainId"
  }
  actual_decimal="$((actual_hex))"
  [ "$actual_decimal" = "$expected_chain_id" ] || {
    fail "$label chain ID mismatch: expected $expected_chain_id, got $actual_decimal"
  }
  pass "$label eth_chainId=$actual_decimal"
}

graphql_expect_result() {
  local label="$1"
  local url="$2"
  shift 2
  local expected_fields=("$@")
  local body="$TMP_DIR/${label//[^A-Za-z0-9_.-]/_}.json"
  local status

  status="$(curl -sS --max-time 20 -o "$body" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data '{"query":"query { __schema { queryType { fields { name } } } }"}' \
    "$url")" || {
    cat "$body" >&2 || true
    fail "$label GraphQL curl failed"
  }

  [ "$status" = "200" ] || {
    cat "$body" >&2 || true
    fail "$label expected HTTP 200, got $status"
  }

  jq -e '.data.__schema.queryType.fields | type == "array" and length > 0' "$body" >/dev/null || {
    cat "$body" >&2
    fail "$label GraphQL query fields missing"
  }

  for field in "${expected_fields[@]}"; do
    jq -e --arg field "$field" '.data.__schema.queryType.fields[] | select(.name == $field)' "$body" >/dev/null || {
      cat "$body" >&2
      fail "$label GraphQL field missing: $field"
    }
  done

  pass "$label GraphQL schema"
}

cors_preflight() {
  local label="$1"
  local url="$2"

  curl_expect_status "$label CORS preflight" 204 \
    -X OPTIONS \
    -H "Origin: $CORS_ORIGIN" \
    -H 'Access-Control-Request-Method: POST' \
    "$url"
}

check_nostr_domain() {
  local label="$1"
  local domain="$2"
  curl_expect_status "$label NIP-11" 200 \
    -H 'Accept: application/nostr+json' \
    "https://${domain}/"
}

check_rpc_domain() {
  local label="$1"
  local domain="$2"
  local method="$3"
  jsonrpc_expect_result "$label" "https://${domain}/" "$method"
  cors_preflight "$label" "https://${domain}/"
}

check_services_domain() {
  local label="$1"
  local domain="$2"
  curl_expect_status "$label health" 200 "https://${domain}/health"
  cors_preflight "$label" "https://${domain}/health"
}

check_indexer_domain() {
  local label="$1"
  local domain="$2"
  curl_expect_status "$label Hasura health" 200 "https://${domain}/healthz"
  graphql_expect_result "$label Hasura" "https://${domain}/v1/graphql" \
    Deposit DepositTreeMeta WithdrawalClaim FinalizedBatch
  cors_preflight "$label Hasura" "https://${domain}/v1/graphql"
}

main() {
  require_command curl
  require_command jq

  check_nostr_domain "nostr" "$PUBLIC_NOSTR_DOMAIN"
  for domain in ${NOSTR_ALIAS_DOMAINS:-}; do
    check_nostr_domain "nostr alias ${domain}" "$domain"
  done
  if [ "$CHECK_PUBLIC_TRUST_SETUP" = "1" ]; then
    trust_setup_path="${PUBLIC_TRUST_SETUP_PATH%/}"
    trust_setup_cache_bust="$(date +%s)"
    curl_expect_status "public trust setup archive" 200 \
      -I \
      -H 'Cache-Control: no-cache' \
      "https://${PUBLIC_TRUST_SETUP_DOMAIN}${trust_setup_path}/${TRUST_SETUP_ARCHIVE_NAME}?check=${trust_setup_cache_bust}"
  else
    pass "public trust setup archive skipped"
  fi

  jsonrpc_expect_result "coordinator edge" "https://${PUBLIC_COORDINATOR_DOMAIN}/" "psy_get_latest_checkpoint_id"
  for domain in ${PUBLIC_COORDINATOR_ALIAS_DOMAINS:-}; do
    jsonrpc_expect_result "coordinator alias ${domain}" "https://${domain}/" "psy_get_latest_checkpoint_id"
  done
  jsonrpc_expect_result "realm0 edge" "https://${PUBLIC_REALM0_DOMAIN}/" "psy_get_latest_checkpoint_tree_root"
  for domain in ${PUBLIC_REALM_ALIAS_DOMAINS:-}; do
    jsonrpc_expect_result "realm0 alias ${domain}" "https://${domain}/" "psy_get_latest_checkpoint_tree_root"
  done
  jsonrpc_expect_result "realm1 edge" "https://${PUBLIC_REALM1_DOMAIN}/" "psy_get_latest_checkpoint_tree_root"
  for domain in ${PUBLIC_REALM1_ALIAS_DOMAINS:-}; do
    jsonrpc_expect_result "realm1 alias ${domain}" "https://${domain}/" "psy_get_latest_checkpoint_tree_root"
  done
  jsonrpc_expect_result "prove proxy" "https://${PUBLIC_PROVE_PROXY_DOMAIN}/" "psy_get_circuits_data"
  jsonrpc_expect_result "Psy faucet" "https://${PUBLIC_FAUCET_DOMAIN}/" "psy_get_psy_faucet_config"
  for domain in ${PUBLIC_PROVE_PROXY_ALIAS_DOMAINS:-}; do
    jsonrpc_expect_result "prove proxy alias ${domain}" "https://${domain}/" "psy_get_circuits_data"
  done
  for domain in ${PUBLIC_FAUCET_ALIAS_DOMAINS:-}; do
    jsonrpc_expect_result "Psy faucet alias ${domain}" "https://${domain}/" "psy_get_psy_faucet_config"
  done
  if [ -n "$PUBLIC_RPC_DOMAIN" ]; then
    jsonrpc_expect_result "public L1 RPC" "https://${PUBLIC_RPC_DOMAIN}/" "eth_chainId"
    for domain in ${PUBLIC_L1_RPC_ALIAS_DOMAINS:-}; do
      check_rpc_domain "public L1 RPC alias ${domain}" "$domain" "eth_chainId"
    done
  else
    pass "public L1 RPC skipped"
  fi
  if [ -n "$PUBLIC_L1_RPC_ROUTES_JSON" ]; then
    while IFS=$'\t' read -r name domain chain_id; do
      jsonrpc_expect_chain_id "public ${name} RPC" "https://${domain}/" "$chain_id"
      cors_preflight "public ${name} RPC" "https://${domain}/"
    done < <(jq -r '.[] | [.name, .domain, (.chain_id | tostring)] | @tsv' <<<"$PUBLIC_L1_RPC_ROUTES_JSON")
  fi

  curl_expect_status "psy-services health" 200 "https://${PUBLIC_PSY_SERVICES_DOMAIN}/health"
  for domain in ${PUBLIC_PSY_SERVICES_ALIAS_DOMAINS:-}; do
    check_services_domain "psy-services alias ${domain}" "$domain"
  done
  curl_expect_status "indexer Hasura health" 200 "https://${PUBLIC_INDEXER_DOMAIN}/healthz"
  graphql_expect_result "indexer Hasura" "https://${PUBLIC_INDEXER_DOMAIN}/v1/graphql" \
    Deposit DepositTreeMeta WithdrawalClaim FinalizedBatch
  for domain in ${PUBLIC_INDEXER_ALIAS_DOMAINS:-}; do
    check_indexer_domain "indexer alias ${domain}" "$domain"
  done

  cors_preflight "coordinator edge" "https://${PUBLIC_COORDINATOR_DOMAIN}/"
  for domain in ${PUBLIC_COORDINATOR_ALIAS_DOMAINS:-}; do cors_preflight "coordinator alias ${domain}" "https://${domain}/"; done
  cors_preflight "realm0 edge" "https://${PUBLIC_REALM0_DOMAIN}/"
  for domain in ${PUBLIC_REALM_ALIAS_DOMAINS:-}; do cors_preflight "realm0 alias ${domain}" "https://${domain}/"; done
  cors_preflight "realm1 edge" "https://${PUBLIC_REALM1_DOMAIN}/"
  for domain in ${PUBLIC_REALM1_ALIAS_DOMAINS:-}; do cors_preflight "realm1 alias ${domain}" "https://${domain}/"; done
  cors_preflight "prove proxy" "https://${PUBLIC_PROVE_PROXY_DOMAIN}/"
  for domain in ${PUBLIC_PROVE_PROXY_ALIAS_DOMAINS:-}; do cors_preflight "prove proxy alias ${domain}" "https://${domain}/"; done
  cors_preflight "Psy faucet" "https://${PUBLIC_FAUCET_DOMAIN}/"
  for domain in ${PUBLIC_FAUCET_ALIAS_DOMAINS:-}; do cors_preflight "Psy faucet alias ${domain}" "https://${domain}/"; done
  if [ -n "$PUBLIC_RPC_DOMAIN" ]; then
    cors_preflight "public L1 RPC" "https://${PUBLIC_RPC_DOMAIN}/"
  fi
  cors_preflight "psy-services" "https://${PUBLIC_PSY_SERVICES_DOMAIN}/health"
  cors_preflight "indexer Hasura" "https://${PUBLIC_INDEXER_DOMAIN}/v1/graphql"
}

main "$@"
