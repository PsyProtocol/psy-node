#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=deploy/bsc-testnet/full-stack-lib.sh
source "$(dirname "$0")/full-stack-lib.sh"
bsc_full_stack_export

for command in anvil cargo curl docker jq pnpm sha256sum ss; do
  require_command "$command"
done

for directory in \
  "$BSC_RUNTIME_PARTH_DIR" \
  "$PSY_CONTRACTS_DIR" \
  "$BSC_PSY_GENESIS_DIR" \
  "$BSC_PSY_DAPP_DIR" \
  "$PSY_SERVICES_HOME"; do
  [ -d "$directory" ] || die "missing source directory: $directory"
done

[ -f "$BSC_RUNTIME_PARTH_DIR/Cargo.toml" ] || die "invalid BSC runtime checkout: $BSC_RUNTIME_PARTH_DIR"
[ -f "$PSY_CONTRACTS_DIR/config/bsc-testnet.json" ] || die "missing BSC contracts profile"
[ -f "$BSC_PSY_GENESIS_DIR/config.json" ] || die "missing BSC genesis config"
[ "$BSC_LOCAL_CHAIN_ID" -eq 97 ] || die "BSC local chain ID must be 97"
[ "$LOCAL_STAGING_L1_DEPLOYMENTS_NETWORK" = "bsc-testnet" ] || die "unexpected deployments network"
[ "$LOCAL_STAGING_COMPOSE_PROJECT" != "parth-local-staging" ] || die "BSC compose project overlaps localhost"
[ "$LOCAL_STAGING_CONTAINER_PREFIX" != "parth-local" ] || die "BSC container prefix overlaps localhost"
[ "$LOCAL_STAGING_STATE_DIR" != "$BSC_RUNTIME_PARTH_DIR/.local-staging" ] || die "BSC state overlaps localhost state"

jq -e '
  .networks["bsc-testnet"].l1_chain_id == 97
  and .networks["bsc-testnet"].anvilForkSourceUrlEnv == "BSC_TESTNET_RPC_URL"
' "$BSC_PSY_GENESIS_DIR/config.json" >/dev/null || die "invalid BSC genesis network profile"

jq -e '
  .l1ChainIndex == 1
  and .rootHistorySize > 0
' "$PSY_CONTRACTS_DIR/config/bsc-testnet.json" >/dev/null || die "invalid BSC contract profile"

phase="${BSC_LOCAL_PHASE:-all}"
case "$phase" in
  preflight | l1 | core | bridge | all) ;;
  *) die "invalid BSC_LOCAL_PHASE: $phase" ;;
esac

ports=()
if [ "$phase" = "preflight" ] || [ "$phase" = "l1" ] || [ "$phase" = "all" ]; then
  ports+=("$BSC_LOCAL_RPC_PORT")
fi
if [ "$phase" = "preflight" ] || [ "$phase" = "core" ] || [ "$phase" = "all" ]; then
  ports+=(
    "$LOCAL_STAGING_COORDINATOR_EDGE_PORT"
    "$LOCAL_STAGING_REALM_EDGE_BASE_PORT"
    "$((LOCAL_STAGING_REALM_EDGE_BASE_PORT + LOCAL_STAGING_REALM_EDGE_PORT_STRIDE))"
    "${LOCAL_STAGING_PROVE_PROXY_ADDR##*:}"
    "${LOCAL_STAGING_FAUCET_ADDR##*:}"
    "${LOCAL_STAGING_PSY_SERVICES_ADDR##*:}"
    "$LOCAL_REDIS_PORT"
    "$LOCAL_NATS_PORT"
    "$LOCAL_SCYLLA_PORT"
    "$LOCAL_NOSTR_PORT"
    "$LOCAL_POSTGRES_PORT"
  )
fi
if [ "$phase" = "preflight" ] || [ "$phase" = "bridge" ] || [ "$phase" = "all" ]; then
  ports+=("$LOCAL_STAGING_INDEXER_PORT" "$LOCAL_CF_ENVIO_PG_PORT")
fi

duplicates="$(printf '%s\n' "${ports[@]}" | sort | uniq -d)"
[ -z "$duplicates" ] || die "duplicate BSC local ports: $duplicates"

if [ "$BSC_LOCAL_REQUIRE_FREE_PORTS" = "1" ]; then
  occupied=()
  for port in "${ports[@]}"; do
    if ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
      occupied+=("$port")
    fi
  done
  if [ "${#occupied[@]}" -gt 0 ]; then
    die "ports required by phase '$phase' are already listening: ${occupied[*]}"
  fi
fi

if { [ "$phase" = "preflight" ] || [ "$phase" = "core" ] || [ "$phase" = "all" ]; } \
  && [ "$BSC_LOCAL_REQUIRE_SCYLLA_AIO" = "1" ]; then
  current_aio_nr="$(cat /proc/sys/fs/aio-max-nr)"
  if [ "$current_aio_nr" -lt "$BSC_LOCAL_MIN_AIO_NR" ]; then
    die "fs.aio-max-nr=$current_aio_nr is below Scylla minimum $BSC_LOCAL_MIN_AIO_NR; raise it before the core phase"
  fi
fi

if [ "$LOCAL_STAGING_BUILD" != "1" ]; then
  for executable in \
    "$LOCAL_STAGING_TARGET_DIR/release/psy_node_cli" \
    "$LOCAL_STAGING_TARGET_DIR/release/psy_worker_cli" \
    "$LOCAL_STAGING_TARGET_DIR/release/psy_user_cli" \
    "$LOCAL_STAGING_TARGET_DIR/release/psy_relayer_cli" \
    "$LOCAL_STAGING_PSY_SERVICES_TARGET_DIR/release/psy-services" \
    "$LOCAL_STAGING_PSY_SERVICES_TARGET_DIR/release/psy-indexer"; do
    [ -x "$executable" ] || die "missing executable (set BSC_LOCAL_BUILD=1): $executable"
  done
fi

bash "$BSC_DEPLOY_DIR/render-local-config.sh"

echo "[bsc-testnet] full-stack preflight passed"
echo "  runtime:       $BSC_RUNTIME_PARTH_DIR"
echo "  state:         $LOCAL_STAGING_STATE_DIR"
echo "  contracts:     $PSY_CONTRACTS_DIR"
echo "  chain/rpc:     $BSC_LOCAL_CHAIN_ID $BSC_LOCAL_RPC_URL"
echo "  phase:         $phase"
echo "  compose:       $LOCAL_STAGING_COMPOSE_PROJECT"
echo "  envio compose: $LOCAL_CF_ENVIO_COMPOSE_PROJECT"
