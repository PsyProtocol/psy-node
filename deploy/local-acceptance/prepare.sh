#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/multi-chain/gcp/source-versions.env
source "$script_dir/../multi-chain/gcp/source-versions.env"
: "${COHORT_DIR:?Set COHORT_DIR to the reviewed sibling repository directory}"
: "${NODE_ARTIFACT_DIR:?Set NODE_ARTIFACT_DIR to the final release binary directory}"
: "${SERVICES_ARTIFACT_DIR:?Set SERVICES_ARTIFACT_DIR to the verified services binary directory}"
root=${ACCEPTANCE_ROOT:-"$COHORT_DIR/local-acceptance"}
runtime="$root/psy-node"
for binary in psy_node_cli psy_worker_cli psy_relayer_cli psy_user_cli psy_dev_cli psy-mcp-server; do
    [[ -x "$NODE_ARTIFACT_DIR/$binary" ]] || { echo "Missing binary: $binary" >&2; exit 1; }
done
for binary in psy-services psy-indexer; do
    [[ -x "$SERVICES_ARTIFACT_DIR/$binary" ]] || { echo "Missing binary: $binary" >&2; exit 1; }
done
for pair in "psy-node:$EXPECTED_PARTH_RUNTIME_COMMIT" "psy-compiler:$EXPECTED_PSY_COMPILER_COMMIT" \
    "psy-sdk:$EXPECTED_PSY_SDK_COMMIT" "psy-services:$EXPECTED_PSY_SERVICES_COMMIT" \
    "psy-wallet:$EXPECTED_PSY_WALLET_COMMIT"; do
    repo=${pair%%:*}; expected=${pair#*:}
    actual=$(git -C "$COHORT_DIR/$repo" rev-parse HEAD)
    [[ "$actual" == "$expected" ]] || { echo "$repo pin mismatch" >&2; exit 1; }
    [[ -z "$(git -C "$COHORT_DIR/$repo" status --porcelain --untracked-files=normal)" ]] || {
        echo "$repo source is dirty; use a clean pinned checkout" >&2
        exit 1
    }
done
[[ ! -e "$runtime" ]] || { echo "Refusing to overwrite existing runtime: $runtime" >&2; exit 1; }
mkdir -p "$root/home" "$root/projects" "$root/evidence"
git clone --no-hardlinks --no-checkout "$COHORT_DIR/psy-node" "$runtime"
git -C "$runtime" remote set-url origin https://github.com/PsyProtocol/psy-node.git
git -C "$runtime" checkout --detach "$EXPECTED_PARTH_RUNTIME_COMMIT"
git -C "$runtime" -c submodule.psy-dapp.update=checkout submodule update --init --recursive
mkdir -p "$runtime/deploy/local-acceptance"
cp "$script_dir/isolation.ts" "$runtime/deploy/local-acceptance/"
git -C "$runtime" apply --check "$script_dir/native-launcher.patch"
git -C "$runtime" apply "$script_dir/native-launcher.patch"
cp "$runtime/psy-genesis/config.json" "$root/evidence/source-config.json"
node "$script_dir/render-config.mjs" "$root/evidence/source-config.json" "$runtime/psy-genesis/config.json" "${HASURA_EXTERNAL_PORT:-9080}"
(cd "$runtime/psy-contracts" && pnpm install --frozen-lockfile)
envio="$runtime/psy_cli/psy_relayer_cli/indexer/envio"
cp "$script_dir/envio-pnpm-lock.yaml" "$envio/pnpm-lock.yaml"
(cd "$envio" && pnpm install --frozen-lockfile)
mkdir -p "$runtime/target/release" "$runtime/psy-dapp/apps/bridge/src/config"
for binary in psy_node_cli psy_worker_cli psy_relayer_cli psy_user_cli psy_dev_cli psy-mcp-server; do
    install -m 755 "$NODE_ARTIFACT_DIR/$binary" "$runtime/target/release/$binary"
done
# Public Anvil development key only. Never inherit a real relayer key from HOME.
env -u KEYSTORE_PATH -u BRIDGE_RELAYER_KEYSTORE_PATH -u BRIDGE_RELAYER_L2_PRIVATE_KEY -u WALLET_PASSWORD \
    PSY_NETWORK=testnet PSY_CONFIG_PATH="$COHORT_DIR/psy-node/psy-genesis/config.json" \
    PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    CARGO_TARGET_DIR="$(dirname "$NODE_ARTIFACT_DIR")" \
    make -C "$COHORT_DIR/psy-node" generate-genesis-data
for file in genesis.json private_keys.json; do
    install -m 600 "$COHORT_DIR/psy-node/$file" "$runtime/$file"
done
install -m 600 "$COHORT_DIR/psy-node/psy-dapp/apps/bridge/src/config/faucetOperators.json" \
    "$runtime/psy-dapp/apps/bridge/src/config/faucetOperators.json"
for repo in psy-compiler psy-sdk; do ln -s "$COHORT_DIR/$repo" "$root/projects/$repo"; done
git clone --no-hardlinks "$COHORT_DIR/psy-wallet" "$root/projects/psy-wallet"
git -C "$root/projects/psy-wallet" remote set-url origin https://github.com/PsyProtocol/psy-wallet.git
git -C "$root/projects/psy-wallet" checkout --detach "$EXPECTED_PSY_WALLET_COMMIT"
# Services gets its own checkout because runtime state must not touch the source tree.
git clone --no-hardlinks "$COHORT_DIR/psy-services" "$root/projects/psy-services"
git -C "$root/projects/psy-services" remote set-url origin https://github.com/PsyProtocol/psy-services.git
git -C "$root/projects/psy-services" checkout --detach "$EXPECTED_PSY_SERVICES_COMMIT"
mkdir -p "$root/projects/psy-services/target/release"
for binary in psy-services psy-indexer; do
    install -m 755 "$SERVICES_ARTIFACT_DIR/$binary" "$root/projects/psy-services/target/release/$binary"
done
sha256sum "$runtime"/target/release/psy* "$runtime/psy-genesis/genesis_contracts.json" \
    "$runtime/psy-genesis/config.json" "$runtime/genesis.json" "$runtime/private_keys.json" \
    "$runtime/psy-dapp/apps/bridge/src/config/faucetOperators.json" \
    "$runtime/dev/locSetupV4.ts" "$runtime/deploy/local-acceptance/isolation.ts" \
    "$runtime/psy-contracts/pnpm-lock.yaml" "$envio/pnpm-lock.yaml" \
    "$root/projects/psy-services/target/release/psy-services" \
    "$root/projects/psy-services/target/release/psy-indexer" > "$root/evidence/runtime-sha256.txt"
cp "$script_dir/../multi-chain/gcp/source-versions.env" "$root/evidence/source-versions.env"
cp "$script_dir/native-launcher.patch" "$root/evidence/native-launcher.patch"
printf '%s\n' "$root"
echo 'Prepared only. Generate a fresh trust setup in home/.psy/keystore before running run.sh.'
