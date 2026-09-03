PROVING_BACKEND := plonky2-poseidon-goldilocks
BIN_PREFIX   := ./target/release/
PSY_CONFIG_PATH := $(CURDIR)/psy-genesis/config.json
ifneq (,$(wildcard ./.env))
include .env
export
endif

LOG_LEVEL    := psy_node_common=debug,psy_worker_core=debug,psy_node_core=debug
VITE_NETWORK  ?= localhost
VITE_FORK    ?= false
SEPOLIA_RPC_URL ?= https://ethereum-sepolia-rpc.publicnode.com
PSY_SKIP_BRANCH_CHECK ?= 1
PSY_SKIP_KEYSTORE ?= 1
PSY_SKIP_BUILD ?= 1
# PROVING_BACKEND := jtmb-poseidon-goldilocks

.PHONY: all build clean test check check-all deploy-contracts register-users query-chain-info run-all staging-server restart restart-all shutdown clean-db run-dummy-prover config_gen_v2 generate-genesis-data generate-groth16 regen-groth16-keystore regen-bridge-agg-keystore export-solidity-verifier export-solidity-verifier-deposit export-solidity-verifier-withdrawal mint-relayer-deposit-withdrawal

all: build

build:
	PSY_CONFIG_PATH=$(PSY_CONFIG_PATH) cargo build --release --example realm_repl --example coordinator_repl --bin psy_worker_cli --bin psy_node_cli --bin psy_dev_cli --bin psy_relayer_cli --bin psy_user_cli --bin psy-mcp-server

clean:
	cargo clean

check:
	@PSY_CONFIG_PATH=$(PSY_CONFIG_PATH) cargo check --workspace --all-targets --tests --benches --examples --bins

check-all: check

test:
	PSY_CONFIG_PATH=$(PSY_CONFIG_PATH) cargo test

verify-contracts:
	@cd psy-contracts && npx hardhat verify-contracts --network ${NETWORK}

verify-contracts-localhost:
	@cd psy-contracts && npx hardhat verify-contracts --network localhost

verify-contracts-sepolia:
	@cd psy-contracts && npx hardhat verify-contracts --network sepolia

verify-contracts-ethereum:
	@cd psy-contracts && npx hardhat verify-contracts --network ethereum

deploy-contracts:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/examples/deploy_contracts

register-users:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/examples/register_user

query-chain-info:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/examples/query_chain_info

staging-server:
	VITE_NETWORK=sepolia VITE_FORK=false bun run dev/locSetupV4.ts --psy-privacy-bridge --ide --explorer

LOCSETUP_START_ARGS = --proving-backend ${PROVING_BACKEND} --db --coordinator --realms-count 2 --coordinator-workers 2 --realm-workers 1 --prove-proxy 1 --faucet-server --l1 --relayer --psy-privacy-bridge --ide --explorer --mode-a-web-wallet-bridge --env RUST_LOG=${LOG_LEVEL}


run-all:
	@if [ "$(VITE_NETWORK)" = "ethereum" ] && [ -z "$$ETH_RPC_URL" ]; then echo "ETH_RPC_URL is required when VITE_NETWORK=ethereum" >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "sepolia" ] && [ -z "$(SEPOLIA_RPC_URL)" ]; then echo "SEPOLIA_RPC_URL is required when VITE_NETWORK=sepolia. Use a private RPC endpoint." >&2; exit 1; fi
	VITE_NETWORK=$(VITE_NETWORK) VITE_FORK=$(VITE_FORK) SEPOLIA_RPC_URL=$(SEPOLIA_RPC_URL) ETH_RPC_URL=$(ETH_RPC_URL) REDEPLOY_L1=$(REDEPLOY_L1) PSY_SKIP_BRANCH_CHECK=$(PSY_SKIP_BRANCH_CHECK) PSY_SKIP_KEYSTORE=$(PSY_SKIP_KEYSTORE) PSY_SKIP_BUILD=$(PSY_SKIP_BUILD) bun run dev/locSetupV4.ts $(LOCSETUP_START_ARGS)

restart: restart-all

restart-all:
	@if [ "$(VITE_NETWORK)" = "ethereum" ] && [ -z "$$ETH_RPC_URL" ]; then echo "ETH_RPC_URL is required when VITE_NETWORK=ethereum" >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "sepolia" ] && [ -z "$(SEPOLIA_RPC_URL)" ]; then echo "SEPOLIA_RPC_URL is required when VITE_NETWORK=sepolia. Use a private RPC endpoint." >&2; exit 1; fi
	bun run dev/locSetupV4.ts --teardown
	VITE_NETWORK=$(VITE_NETWORK) VITE_FORK=$(VITE_FORK) SEPOLIA_RPC_URL=$(SEPOLIA_RPC_URL) ETH_RPC_URL=$(ETH_RPC_URL) REDEPLOY_L1=$(REDEPLOY_L1) PSY_SKIP_BRANCH_CHECK=$(PSY_SKIP_BRANCH_CHECK) PSY_SKIP_KEYSTORE=$(PSY_SKIP_KEYSTORE) PSY_SKIP_BUILD=$(PSY_SKIP_BUILD) bun run dev/locSetupV4.ts $(LOCSETUP_START_ARGS)

run-dummy-prover:
	@echo "Starting dummy prover for all realms using random users..."
	@./dev/dummy_prover.sh prove_random -p ${PROVING_BACKEND}

deposit:
	@TOKEN_ADDR=$${TOKEN_ADDRESS:-$$(python3 -c 'import json; print(json.load(open("psy-contracts/deployments/localhost/deployed-contracts.json"))["core"].get("PsyToken", json.load(open("psy-contracts/deployments/localhost/deployed-contracts.json"))["core"].get("USDTToken", "")))' 2>/dev/null || echo "")}; \
	ROUTER_ADDR=$$(python3 -c 'import json; print(json.load(open("psy-contracts/deployments/localhost/deployed-contracts.json"))["core"]["Router"])' 2>/dev/null); \
	if [ -z "$${NOTE_COMMITMENT}" ]; then echo "NOTE_COMMITMENT is required; for claimable deposits derive hash(nullifier_secret, raw note_secret)." >&2; exit 1; fi; \
	NC=$${NOTE_COMMITMENT}; \
	RUST_LOG=$${RUST_LOG:-info} ./target/release/psy_user_cli deposit \
		--l1-rpc-url $${L1_RPC_URL:-http://127.0.0.1:8545} \
		-p $${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80} \
		--router-address $$ROUTER_ADDR \
		--token $$TOKEN_ADDR \
		--amount $${AMOUNT:-5000000000} \
		$$(if [ -n "$${L2_RECIPIENT}" ]; then echo "--shield-address $${L2_RECIPIENT}"; else echo "--user-id $${USER_ID:-0} --r0 $${R0:-0} --r1 $${R1:-0}"; fi) \
		--note-commitment $$NC
shutdown:
	bun run dev/locSetupV4.ts --teardown --purge

clean-db:
	rm -fr local_checkpoints logs || true
	rm -fr psy-contracts/deployments/localhost || true
	rm -fr psy-contracts/deployments/localhostBsc || true
	rm -fr psy-contracts/deployments/localhostBase || true
	-docker stop -t 15 valkey-server nats-server scylla-server nostr-relay generated-envio-postgres-1 generated-graphql-engine-1 2>/dev/null || true
	-docker rm -f valkey-server nats-server scylla-server nostr-relay generated-envio-postgres-1 generated-graphql-engine-1 2>/dev/null || true
	# Drop the envio postgres volume before wiping generated/ so the compose file still exists.
	-docker compose -f psy_cli/psy_relayer_cli/indexer/envio/generated/docker-compose.yaml down -v 2>/dev/null || true
	rm -fr psy_cli/psy_relayer_cli/indexer/envio/generated || true
	docker volume rm generated_db_data psy-devnet-redis psy-devnet-scylla psy-devnet-scylla-data psy-devnet-nats 2>/dev/null || true

config_gen_v2:
	cargo run --release --package psy_plonky2_circuits --example config_gen_v2

generate-genesis-data:
	cargo test --release --package psy_plonky2_circuits --lib -- node::config::networks::local_devnet::tests --nocapture

# Regenerates client_prover/psy_prover/src/wallet/local_circuits.json (embedded
# zk-sign + privacy base circuits). Needed whenever the circuit-defining
# constants (e.g. TOKEN_CONTRACT_STATE_TREE_HEIGHT from genesis contracts)
# change.
generate-local-circuits:
	cargo test --release -p psy_prover generate_local_circuits_json -- --ignored --nocapture

data := ./psy_cli/psy_relayer_cli/data
KEYSTORE_DIR ?= $(HOME)/.psy/keystore
generate-groth16:
	${BIN_PREFIX}/psy_relayer_cli generate-groth16  ${data}/common_circuit_data.json \
													  ${data}/proof_with_public_inputs.json \
													  ${data}/verifier_only_circuit_data.json \
													  ${data}/ \
													  ${data}/out_proof.json \
													  ${data}/out_vk.json

regen-groth16-keystore:
	${BIN_PREFIX}/psy_relayer_cli regenerate-groth16-keystore --keystore-dir $(KEYSTORE_DIR) --include-bridge-agg

regen-bridge-agg-keystore:
	${BIN_PREFIX}/psy_relayer_cli regenerate-groth16-keystore --keystore-dir $(KEYSTORE_DIR) --skip-deposit-append --skip-withdrawal-claim --include-bridge-agg

keystore := $(KEYSTORE_DIR)
export-solidity-verifier:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore} ./psy-contracts/src/GnarkGroth16Verifier.sol

export-solidity-verifier-deposit:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore}/deposit_append ./psy-contracts/src/DepositBatchVerifier.sol

export-solidity-verifier-withdrawal:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore}/withdrawal_claim ./psy-contracts/src/WithdrawalClaimVerifier.sol

export-all-solidity-verifier: export-solidity-verifier export-solidity-verifier-deposit export-solidity-verifier-withdrawal

BRIDGE_TO_CHECKPOINT ?= 10
BRIDGE_FROM_CHECKPOINT ?= 1
BRIDGE_PROOF_JSON ?= /tmp/bridge_batch_$(BRIDGE_TO_CHECKPOINT).json
BRIDGE_L1_RPC_URL ?= http://127.0.0.1:8545
BRIDGE_DEPLOYMENTS_NETWORK ?= localhost
BRIDGE_WITHDRAW_AMOUNT ?= 3456
BRIDGE_WITHDRAW_NONCE ?= 8
RELAYER_PRIVATE_KEY ?= edf57fe965a149aa63ba8441afc3e7ff8be22e991942e9741be7bdee55edd902
RELAYER_FEE_MINT_AMOUNT ?= 1000000000000
RELAYER_FEE_CONTRACT_ID ?= 0
INDEXER_POSTGRES_CONTAINER ?= generated-envio-postgres-1
INDEXER_DB_USER ?= postgres
INDEXER_DB_NAME ?= envio-dev
BRIDGE_CHAIN_INDEX ?= 0
BRIDGE_TREE_OWNER_USER_ID ?= 524288
BRIDGE_DEPOSIT_TREE_CONTRACT_ID ?= 2
ROOT_RPC_CONFIG ?= psy-genesis/config.json

mint-relayer:
	@RUST_LOG=$${RUST_LOG:-info} ./target/release/psy_user_cli call \
		--rpc-config $(ROOT_RPC_CONFIG) \
		-p $${PRIVATE_KEY:-$(RELAYER_PRIVATE_KEY)} \
		--contract-id $${CONTRACT_ID:-$(RELAYER_FEE_CONTRACT_ID)} \
		--method-name simple_mint \
		--inputs "[$${AMOUNT:-$(RELAYER_FEE_MINT_AMOUNT)}]" \
		--wait-until-confirmation

withdraw:
	@TOKEN_ADDR=$${TOKEN_ADDRESS:-$$(python3 -c 'import json; print("0x" + json.load(open("psy-contracts/deployments/localhost/deployed-contracts.json"))["core"]["PsyToken"][2:].zfill(64))')}; \
	RECIPIENT_ADDR=$${RECIPIENT:-$$(python3 -c 'import os; print("0x" + os.environ.get("L1_RECIPIENT", "f39fd6e51aad88f6f4ce6ab8827279cfffb92266").removeprefix("0x").zfill(64))')}; \
	RUST_LOG=$${RUST_LOG:-info} ./target/release/psy_user_cli withdraw \
		--rpc-config $(ROOT_RPC_CONFIG) \
		-p $${PRIVATE_KEY:-c71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359} \
		--destination-chain-id $${DESTINATION_CHAIN_ID:-0} \
		--token-address "$$TOKEN_ADDR" \
		--amount $${AMOUNT:-$(BRIDGE_WITHDRAW_AMOUNT)} \
		--recipient "$$RECIPIENT_ADDR" \
		--nonce $${NONCE:-$(BRIDGE_WITHDRAW_NONCE)}
