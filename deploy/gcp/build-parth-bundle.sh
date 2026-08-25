#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="$ROOT/deploy"
GCP_DIR="$DEPLOY_DIR/gcp"
PARTH_DIR="${PARTH_DIR:-$ROOT}"
PSY_GENESIS_DIR="${PSY_GENESIS_DIR:-$PARTH_DIR/psy-genesis}"
PSY_CONTRACTS_DIR="${PSY_CONTRACTS_DIR:-$PARTH_DIR/psy-contracts}"
PSY_DAPP_DIR="${PSY_DAPP_DIR:-$PARTH_DIR/psy-dapp}"
cd "$ROOT"

# Loads config.env plus SSH endpoint helpers. The bundle is consumed by cloud
# services, so the embedded client RPC config must use reachable staging hosts,
# not localhost.
source "$GCP_DIR/lib/common.sh"
# shellcheck source=../scripts/lib/json-artifact.sh
source "$DEPLOY_DIR/scripts/lib/json-artifact.sh"

: "${OUT_DIR:=dist}"
: "${OUT_FILE:=$OUT_DIR/parth-node-bundle.tar.gz}"

source_commit() {
  local dir="$1"
  if [ -e "$dir/.git" ]; then
    git -C "$dir" rev-parse HEAD
  else
    printf 'unknown\n'
  fi
}

client_endpoint() {
  local explicit="$1"
  local vm_name="$2"

  if [ -n "$explicit" ]; then
    printf '%s\n' "$explicit"
    return 0
  fi

  ssh_service_endpoint "$vm_name"
}

render_client_prover_config() {
  local source_config="$1"
  local target_config="$2"
  local node_host
  local prove_proxy_host
  local psy_services_host
  local coordinator_url
  local realm_urls
  local prove_proxy_url
  local prove_proxy_listen
  local prove_proxy_port
  local psy_services_url

  node_host=""
  prove_proxy_host=""

  if [ -z "${CLIENT_COORDINATOR_URL:-}" ] || { [ -z "${CLIENT_REALM_URLS:-}" ] && [ -z "${CLIENT_REALM_URL:-}" ]; } || [ -z "${CLIENT_PSY_SERVICES_URL:-}" ]; then
    node_host="$(client_endpoint "${NODE_HOST:-}" "${NODE_VM_NAME:-}")"
  fi
  if [ -z "${CLIENT_PROVE_PROXY_URL:-}" ]; then
    prove_proxy_host="$(client_endpoint "${PROVE_PROXY_HOST:-}" "${PROVE_PROXY_VM_NAME:-}")"
  fi
  psy_services_host="${PSY_SERVICES_HOST:-$node_host}"
  prove_proxy_listen="${PROVE_PROXY_LISTEN_ADDR:-0.0.0.0:9999}"
  prove_proxy_port="${prove_proxy_listen##*:}"

  coordinator_url="${CLIENT_COORDINATOR_URL:-http://${node_host}:${COORDINATOR_EDGE_PORT:-1337}}"
  if [ -n "${CLIENT_REALM_URLS:-}" ]; then
    realm_urls="$CLIENT_REALM_URLS"
  elif [ -n "${CLIENT_REALM_URL:-}" ]; then
    realm_urls="$CLIENT_REALM_URL"
  else
    realm_urls=""
    for realm_id in ${REALM_IDS:-${REALM_ID:-0}}; do
      local port_var="REALM${realm_id}_EDGE_PORT"
      local port="${!port_var:-$(( ${REALM_EDGE_BASE_PORT:-1338} + realm_id * ${REALM_EDGE_PORT_STRIDE:-1} ))}"
      if [ -n "$realm_urls" ]; then
        realm_urls+=","
      fi
      realm_urls+="http://${node_host}:${port}"
    done
  fi
  prove_proxy_url="${CLIENT_PROVE_PROXY_URL:-http://${prove_proxy_host}:${prove_proxy_port}}"
  psy_services_url="${CLIENT_PSY_SERVICES_URL:-http://${psy_services_host}:${PSY_SERVICES_PORT:-3000}}"

  echo "rendering bundled client_prover/config.json:" >&2
  echo "  coordinator: ${coordinator_url}" >&2
  echo "  realms:      ${realm_urls}" >&2
  echo "  prove proxy: ${prove_proxy_url}" >&2
  echo "  services:    ${psy_services_url}" >&2

  python3 - "$source_config" "$target_config" \
    "$coordinator_url" "$realm_urls" "$prove_proxy_url" "$psy_services_url" <<'PY'
import json
import sys

source, target, coordinator, realms_csv, prove_proxy, services = sys.argv[1:]

with open(source, "r", encoding="utf-8") as f:
    data = json.load(f)

localhost = data.setdefault("networks", {}).setdefault("localhost", {})
localhost["coordinator_configs"] = [{"id": 0, "rpc_url": [coordinator]}]
realms = [item.strip() for item in realms_csv.split(",") if item.strip()]
localhost["realm_configs"] = [{"id": idx, "rpc_url": [url]} for idx, url in enumerate(realms)]
localhost["prove_proxy_url"] = [prove_proxy]
localhost["api_services_url"] = [services]

with open(target, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/target/release" \
  "$tmp/psy-services/target/release" \
  "$tmp/psy-services/migrations" \
  "$tmp/psy-services/genesis_contracts" \
  "$tmp/client_prover" \
  "$tmp/psy_cli/psy_relayer_cli/config" \
  "$tmp/deploy"

if [ -n "${PARTH_BUNDLE_MAKEFILE:-}" ]; then
  cp "$PARTH_BUNDLE_MAKEFILE" "$tmp/Makefile"
elif [ -f "$DEPLOY_DIR/config/parth/Makefile" ]; then
  cp "$DEPLOY_DIR/config/parth/Makefile" "$tmp/Makefile"
elif [ -f "$PARTH_DIR/Makefile" ]; then
  cp "$PARTH_DIR/Makefile" "$tmp/Makefile"
else
  cp "$DEPLOY_DIR/sources/psy-node/Makefile" "$tmp/Makefile"
fi
parth_deploy_scripts="$DEPLOY_DIR/scripts/parth"
if [ -d "$PARTH_DIR/deploy/bin" ]; then
  parth_deploy_scripts="$PARTH_DIR/deploy"
fi
rsync -a --exclude 'gcp' "$parth_deploy_scripts/" "$tmp/deploy/"
chmod 0755 "$tmp/deploy/bin/run-parth-service"
cp "$DEPLOY_DIR/config/parth/genesis.json" "$tmp/genesis.json"
mkdir -p "$tmp/genesis_abi"
if [ -d "$DEPLOY_DIR/config/parth/genesis_abi" ]; then
  cp -R "$DEPLOY_DIR/config/parth/genesis_abi/." "$tmp/genesis_abi/"
fi

# psy-services only needs contract identity and function metadata. Derive that
# compact index from the exact generated contracts embedded into this bundle so
# its genesis rows cannot drift from the coordinator's contract tree.
json_artifact_cat "$DEPLOY_DIR/config/parth/genesis_contracts.json" \
  | jq '
  [
    .[]
    | {
        name,
        deployer,
        function_whitelist,
        code_root,
        code_definition: {
          state_tree_height: .code_definition.state_tree_height,
          functions: [
            .code_definition.functions[]
            | {
                method_id,
                num_inputs,
                num_outputs,
                vm_type
              }
          ]
        }
      }
  ]
' > "$tmp/genesis_contracts.index.json"

runtime_contract_count="$(jq '.contracts | length' "$tmp/genesis.json")"
indexed_contract_count="$(jq 'length' "$tmp/genesis_contracts.index.json")"
if [ "$runtime_contract_count" -ne "$indexed_contract_count" ]; then
  echo "genesis contract count mismatch: runtime=${runtime_contract_count} services_index=${indexed_contract_count}" >&2
  exit 1
fi
if ! jq -e --slurpfile indexed "$tmp/genesis_contracts.index.json" '
  [
    .contracts[].code_definition
    | {
        state_tree_height,
        functions: [
          .functions[]
          | {method_id, num_inputs, num_outputs, vm_type}
        ]
      }
  ] == [
    $indexed[0][].code_definition
    | {
        state_tree_height,
        functions: [
          .functions[]
          | {method_id, num_inputs, num_outputs, vm_type}
        ]
      }
  ]
' "$tmp/genesis.json" >/dev/null; then
  echo "genesis contract definitions do not match the psy-services contract index" >&2
  exit 1
fi

render_client_prover_config \
  "$DEPLOY_DIR/config/parth/client_prover_config.json" \
  "$tmp/client_prover/config.json"
cp -R "$DEPLOY_DIR/config/parth/psy_relayer_cli" "$tmp/psy_cli/psy_relayer_cli/config"

for bin in psy_node_cli psy_worker_cli psy_user_cli psy_relayer_cli; do
  cp "$DEPLOY_DIR/artifacts/bin/parth/$bin" "$tmp/target/release/$bin"
done

for bin in psy-services psy-indexer; do
  cp "$DEPLOY_DIR/artifacts/bin/psy-services/$bin" "$tmp/psy-services/target/release/$bin"
done

if [ -d "$DEPLOY_DIR/config/psy-services/migrations" ]; then
  cp -R "$DEPLOY_DIR/config/psy-services/migrations/." "$tmp/psy-services/migrations/"
fi

if [ -d "$DEPLOY_DIR/config/psy-services/genesis_contracts" ]; then
  cp -R "$DEPLOY_DIR/config/psy-services/genesis_contracts/." "$tmp/psy-services/genesis_contracts/"
fi

psy_services_dir="${PSY_SERVICES_DIR:-$WORKSPACE_HOME/psy-services}"
: "${EXPECTED_PARTH_RUNTIME_COMMIT:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_GENESIS_REPOSITORY:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_GENESIS_COMMIT:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_CONTRACTS_REPOSITORY:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_CONTRACTS_COMMIT:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_DAPP_REPOSITORY:?missing from deploy/source-versions.env}"
: "${EXPECTED_PSY_DAPP_COMMIT:?missing from deploy/source-versions.env}"
cat >"$tmp/BUILD-MANIFEST.env" <<EOF
BUILT_AT_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PSY_NODE_DEPLOYMENT_COMMIT=$(source_commit "$PARTH_DIR")
REQUIRED_PARTH_RUNTIME_COMMIT=$EXPECTED_PARTH_RUNTIME_COMMIT
PSY_SERVICES_COMMIT=$(source_commit "$psy_services_dir")
PSY_GENESIS_REPOSITORY=$EXPECTED_PSY_GENESIS_REPOSITORY
PSY_GENESIS_COMMIT=$(source_commit "$PSY_GENESIS_DIR")
PSY_CONTRACTS_REPOSITORY=$EXPECTED_PSY_CONTRACTS_REPOSITORY
PSY_CONTRACTS_COMMIT=$(source_commit "$PSY_CONTRACTS_DIR")
PSY_DAPP_REPOSITORY=$EXPECTED_PSY_DAPP_REPOSITORY
PSY_DAPP_COMMIT=$(source_commit "$PSY_DAPP_DIR")
GENESIS_SHA256=$(sha256sum "$DEPLOY_DIR/config/parth/genesis.json" | awk '{print $1}')
GENESIS_CONTRACTS_SHA256=$(sha256sum "$DEPLOY_DIR/config/parth/genesis_contracts.json" | awk '{print $1}')
EOF

mkdir -p "$OUT_DIR"
tar -C "$tmp" -czf "$OUT_FILE" .
echo "bundle build manifest:"
cat "$tmp/BUILD-MANIFEST.env"
echo "$OUT_FILE"
