#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${ACCEPTANCE_ROOT:?Set ACCEPTANCE_ROOT to the prepared isolated runtime}"
root=$(realpath "$ACCEPTANCE_ROOT")
export PSY_ACCEPTANCE=1
instance=${ACCEPTANCE_INSTANCE:-stages-20260918}
[[ "$instance" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || exit 2
export COMPOSE_PROJECT_NAME="psy-accept-$instance-envio"
infra_project="psy-accept-$instance-infra"
export ENVIO_PG_PORT=${ENVIO_PG_PORT:-15433}
export HASURA_EXTERNAL_PORT=${HASURA_EXTERNAL_PORT:-9080}
export CARGO_HOME=${CARGO_HOME:-"$HOME/.cargo"}
export RUSTUP_HOME=${RUSTUP_HOME:-"$HOME/.rustup"}
export HOME="$root/home"
export PSY_PROJECTS_DIR="$root/projects"
export PSY_CONFIG_PATH="$root/psy-node/psy-genesis/config.json"
export PSY_NETWORK=testnet VITE_PSY_STAGE=testnet VITE_NETWORK=localhost VITE_FORK=false
export L1_RPC_HOST=127.0.0.1 LOCALHOST_RPC_URL=http://127.0.0.1:8545
export LOCALHOST_BSC_RPC_URL=http://127.0.0.1:9545 LOCALHOST_BASE_RPC_URL=http://127.0.0.1:10545
unset PRIVATE_KEY BRIDGE_RELAYER_KEYSTORE_PATH BRIDGE_RELAYER_L2_PRIVATE_KEY
export PSY_SKIP_BRANCH_CHECK=1 PSY_SKIP_KEYSTORE=1 PSY_SKIP_BUILD=1
export WALLET_PASSWORD=local-acceptance-only
export KEYSTORE_PASSWORD_ENV=WALLET_PASSWORD
export KEYSTORE_PATH="$HOME/.psy/keystore/bridge-relayer"
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-8}
for name in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    for prefix in '' deposit_append/ withdrawal_claim/; do
        [[ -s "$HOME/.psy/keystore/$prefix$name" ]] || { echo "Missing fresh setup: $prefix$name" >&2; exit 1; }
    done
done
[[ -f "$root/evidence/runtime-sha256.txt" ]] || exit 1
(cd "$root" && sha256sum -c evidence/runtime-sha256.txt)
[[ -f "$root/evidence/setup-sha256.txt" ]] || { echo 'Missing verified setup manifest' >&2; exit 1; }
(cd "$root" && sha256sum -c evidence/setup-sha256.txt)
# Check all ports before any mutating command. Never terminate an existing listener.
node --input-type=module - "$ENVIO_PG_PORT" "$HASURA_EXTERNAL_PORT" <<'JS'
import net from 'node:net';
const ports = [1337,13380,13390,6379,4222,9042,8081,8545,9545,10545,9898,9998,9999,3000,
    ...process.argv.slice(2).map(Number)];
if (new Set(ports).size !== ports.length) throw new Error('Duplicate acceptance ports');
for (const port of ports) {
    await new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', reject);
        server.listen(port, '127.0.0.1', () => server.close(resolve));
    });
}
JS
infra=(docker compose -p "$infra_project" -f "$script_dir/infra.compose.yaml")
if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$infra_project")" ]]; then
    echo 'Acceptance infrastructure already exists; inspect it before restarting.' >&2
    exit 1
fi
cleanup() {
    # No volume deletion and no process-name/port scans.
    if [[ -n "${child:-}" ]]; then
        kill -TERM -- "-$child" 2>/dev/null || true
    fi
    "${infra[@]}" stop || true
    compose="$root/psy-node/psy_cli/psy_relayer_cli/indexer/envio/generated/docker-compose.yaml"
    if [[ -f "$compose" ]]; then docker compose -p "$COMPOSE_PROJECT_NAME" -f "$compose" stop || true; fi
}
trap cleanup EXIT
"${infra[@]}" up -d --wait --wait-timeout 240
cd "$root/psy-node"
setsid make run-all LOCSETUP_START_ARGS='--proving-backend plonky2-poseidon-goldilocks --coordinator --realms-count 2 --coordinator-workers 1 --realm-workers 1 --prove-proxy 1 --faucet-server --l1 --relayer --env RUST_LOG=info' &
child=$!
stop_child() {
    trap '' INT TERM
    kill -TERM -- "-$child" 2>/dev/null || true
    wait "$child" || true
    exit 130
}
trap stop_child INT TERM
wait "$child"
