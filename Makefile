PROVING_BACKEND := plonky2-poseidon-goldilocks
BIN_PREFIX      := ./target/release/
PSY_CONFIG_PATH := $(CURDIR)/psy-genesis/config.json
ifneq (,$(wildcard ./.env))
include .env
export
endif

LOG_LEVEL    := psy_node_common=debug,psy_worker_core=debug,psy_node_core=debug
VITE_NETWORK  ?= localhost
VITE_FORK    ?= false
SEPOLIA_RPC_URL ?= https://ethereum-sepolia-rpc.publicnode.com
CLEAN_DB    ?=
# PROVING_BACKEND := jtmb-poseidon-goldilocks

.PHONY: all build clean test check check-all deploy-contracts register-users query-chain-info run-all staging-server restart restart-soft shutdown shutdown-soft clean-db run-dummy-prover config_gen_v2 generate-genesis-data mint-relayer-deposit-withdrawal

all: build

build:
	PSY_CONFIG_PATH=$(PSY_CONFIG_PATH) cargo build --release --example realm_repl --example coordinator_repl --bin psy_worker_cli --bin psy_node_cli --bin psy_dev_cli --bin psy_relayer_cli --bin psy_user_cli

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

run-all: shutdown
	@if [ "$(VITE_NETWORK)" = "ethereum" ] && [ -z "$$ETH_RPC_URL" ]; then echo "ETH_RPC_URL is required when VITE_NETWORK=ethereum" >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "sepolia" ] && [ -z "$(SEPOLIA_RPC_URL)" ]; then echo "SEPOLIA_RPC_URL is required when VITE_NETWORK=sepolia. Use a private RPC endpoint." >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "bsc" ] && [ "$(VITE_FORK)" = "true" ] && [ -z "$$BSC_RPC_URL" ]; then echo "BSC_RPC_URL is required when VITE_NETWORK=bsc and VITE_FORK=true" >&2; exit 1; fi
	@$(MAKE) clean-db
	VITE_NETWORK=$(VITE_NETWORK) VITE_FORK=$(VITE_FORK) SEPOLIA_RPC_URL=$(SEPOLIA_RPC_URL) ETH_RPC_URL=$(ETH_RPC_URL) BSC_RPC_URL=$(BSC_RPC_URL) REDEPLOY_L1=$(REDEPLOY_L1) bun run dev/locSetupV4.ts --proving-backend ${PROVING_BACKEND} --db --coordinator --realms-count 2 --coordinator-workers 2 --realm-workers 1 --prove-proxy 1 --l1 --relayer --psy-privacy-bridge --ide --explorer --env RUST_LOG=${LOG_LEVEL}

restart: shutdown
	@if [ "$(VITE_NETWORK)" = "ethereum" ] && [ -z "$$ETH_RPC_URL" ]; then echo "ETH_RPC_URL is required when VITE_NETWORK=ethereum" >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "sepolia" ] && [ -z "$(SEPOLIA_RPC_URL)" ]; then echo "SEPOLIA_RPC_URL is required when VITE_NETWORK=sepolia. Use a private RPC endpoint." >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "bsc" ] && [ "$(VITE_FORK)" = "true" ] && [ -z "$$BSC_RPC_URL" ]; then echo "BSC_RPC_URL is required when VITE_NETWORK=bsc and VITE_FORK=true" >&2; exit 1; fi
	VITE_NETWORK=$(VITE_NETWORK) VITE_FORK=$(VITE_FORK) SEPOLIA_RPC_URL=$(SEPOLIA_RPC_URL) ETH_RPC_URL=$(ETH_RPC_URL) BSC_RPC_URL=$(BSC_RPC_URL) REDEPLOY_L1=$(REDEPLOY_L1) bun run dev/locSetupV4.ts --proving-backend ${PROVING_BACKEND} --db --coordinator --realms-count 2 --coordinator-workers 2 --realm-workers 1 --prove-proxy 1 --l1 --relayer --psy-privacy-bridge --ide --explorer --env RUST_LOG=${LOG_LEVEL}

restart-soft: shutdown-soft
	@if [ "$(VITE_NETWORK)" = "ethereum" ] && [ -z "$$ETH_RPC_URL" ]; then echo "ETH_RPC_URL is required when VITE_NETWORK=ethereum" >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "sepolia" ] && [ -z "$(SEPOLIA_RPC_URL)" ]; then echo "SEPOLIA_RPC_URL is required when VITE_NETWORK=sepolia. Use a private RPC endpoint." >&2; exit 1; fi
	@if [ "$(VITE_NETWORK)" = "bsc" ] && [ "$(VITE_FORK)" = "true" ] && [ -z "$$BSC_RPC_URL" ]; then echo "BSC_RPC_URL is required when VITE_NETWORK=bsc and VITE_FORK=true" >&2; exit 1; fi
	VITE_NETWORK=$(VITE_NETWORK) VITE_FORK=$(VITE_FORK) SEPOLIA_RPC_URL=$(SEPOLIA_RPC_URL) ETH_RPC_URL=$(ETH_RPC_URL) BSC_RPC_URL=$(BSC_RPC_URL) REDEPLOY_L1=$(REDEPLOY_L1) bun run dev/locSetupV4.ts --proving-backend ${PROVING_BACKEND} --db --coordinator --realms-count 2 --coordinator-workers 2 --realm-workers 1 --prove-proxy 1 --l1 --relayer --psy-privacy-bridge --ide --explorer --env RUST_LOG=${LOG_LEVEL}

run-dummy-prover:
	@echo "Starting dummy prover for all realms using random users..."
	@./dev/dummy_prover.sh prove_random -p ${PROVING_BACKEND}

deposit:
	@TOKEN_ADDR=$${TOKEN_ADDRESS:-$$(python3 -c 'import json; print(json.load(open("psy-contracts/deployments/localhost/deployed-contracts.json"))["core"].get("PsyToken", json.load(open("psy-contracts/deployments/localhost/deployed-contracts.json"))["core"].get("USDTToken", "")))' 2>/dev/null || echo "")}; \
	ROUTER_ADDR=$$(python3 -c 'import json; print(json.load(open("psy-contracts/deployments/localhost/deployed-contracts.json"))["core"]["Router"])' 2>/dev/null); \
	NSH=$${NOTE_SECRET_HASH:-$$(python3 -c 'import hashlib; print("0x" + hashlib.sha256(str(__import__("time").time()).encode()).hexdigest()[:64])')}; \
	RUST_LOG=$${RUST_LOG:-info} ./target/release/psy_user_cli deposit \
		--l1-rpc-url $${L1_RPC_URL:-http://127.0.0.1:8545} \
		-p $${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80} \
		--router-address $$ROUTER_ADDR \
		--token $$TOKEN_ADDR \
		--amount $${AMOUNT:-5000000000} \
		$$(if [ -n "$${L2_RECIPIENT}" ]; then echo "--shield-address $${L2_RECIPIENT}"; else echo "--user-id $${USER_ID:-0} --r0 $${R0:-0} --r1 $${R1:-0}"; fi) \
		--note-secret-hash $$NSH
shutdown:
	-docker stop -t 15 valkey-server nats-server scylla-server nostr-relay 2>/dev/null || true
	-docker rm -f valkey-server nats-server scylla-server nostr-relay 2>/dev/null || true
	# Properly tear down envio's docker stack (containers, volumes, networks).
	# Using docker compose down -v instead of raw docker rm -f + docker volume rm
	# to avoid a race where a running container holds the volume reference and
	# prevents docker volume rm from succeeding (volume in use).
	-docker compose -f psy_cli/psy_relayer_cli/indexer/envio/generated/docker-compose.yaml down -v 2>/dev/null || true
	# Kill envio indexer and other managed daemon processes.
	# Order: docker compose down -v above already stopped envio postgres/hasura,
	# so the envio indexer process (if still alive) will lose its DB connection.
	# The bash loop uses pgrep + grep -vw "$$$$" to avoid killing its own shell
	# (which appears in pgrep output because the regex pattern text is part of
	# the shell's -c / -l argument).
	-@bash -lc 'patterns=("bash dev/start_db.sh" "bun run dev/locSetupV4.ts" "psy_node_cli" "psy_worker_cli" "psy_user_cli prove-proxy" "psy-services/target/release/psy-services" "psy-services/target/release/psy-indexer" "cargo run --release --bin psy-services" "cargo run --release --bin psy-indexer" "anvil --port 8545" "hardhat node" "dummy_prover.sh prove_random" "client_prover/psy_bridge" "client_prover/psy_privacy" "psy-dapp/apps/bridge" "psy-dapp/apps/ide" "psy-dapp/apps/explorer" "pnpm dev" "envio/bin.js" "envio-linux"); for p in "$${patterns[@]}"; do pgrep -f "$$p" 2>/dev/null | grep -vw "$$$$" | grep -vw "$$PPID" | xargs -r kill -9 2>/dev/null || true; done'
	-@bash -lc 'ports="3000 5433 8080 8545 9898 5174 5175 5176 5177 5178"; for p in $$(seq 1337 1346); do ports="$$ports $$p"; done; for p in $$(seq 9999 10008); do ports="$$ports $$p"; done; for p in $$(seq 13380 10 14670); do ports="$$ports $$p"; done; for port in $$ports; do if command -v lsof >/dev/null 2>&1; then lsof -tiTCP:$$port -sTCP:LISTEN 2>/dev/null | xargs -r kill -9 2>/dev/null || true; elif command -v fuser >/dev/null 2>&1; then fuser -k $$port/tcp >/dev/null 2>&1 || true; fi; done'
	-rm -rf logs local_checkpoints
	-rm -rf psy-contracts/deployments/localhost psy-contracts/deployments/sepolia psy-contracts/deployments/ethereum
	-# generated_db_data is now removed by docker compose down -v above
	-docker volume rm psy-devnet-redis psy-devnet-scylla psy-devnet-scylla-data 2>/dev/null || true

shutdown-soft:
	-docker stop -t 15 valkey-server nats-server scylla-server nostr-relay 2>/dev/null || true
	-docker rm -f valkey-server nats-server scylla-server nostr-relay 2>/dev/null || true
	-docker compose -f psy_cli/psy_relayer_cli/indexer/envio/generated/docker-compose.yaml down -v 2>/dev/null || true
	-@bash -lc 'patterns=("bash dev/start_db.sh" "bun run dev/locSetupV4.ts" "psy_node_cli" "psy_worker_cli" "psy_user_cli prove-proxy" "psy-services/target/release/psy-services" "psy-services/target/release/psy-indexer" "cargo run --release --bin psy-services" "cargo run --release --bin psy-indexer" "anvil --port 8545" "hardhat node" "dummy_prover.sh prove_random" "client_prover/psy_bridge" "client_prover/psy_privacy" "psy-dapp/apps/bridge" "psy-dapp/apps/ide" "psy-dapp/apps/explorer" "pnpm dev" "envio/dev" "generated/src/Index.res.js"); for p in "$${patterns[@]}"; do pgrep -f "$$p" 2>/dev/null | grep -vw "$$$$" | grep -vw "$$PPID" | xargs -r kill -9 2>/dev/null || true; done'
	-@bash -lc 'ports="3000 5433 8080 8081 8545 9898 5174 5175 5176 5177 5178"; for p in $$(seq 1337 1346); do ports="$$ports $$p"; done; for p in $$(seq 9999 10008); do ports="$$ports $$p"; done; for p in $$(seq 13380 10 14670); do ports="$$ports $$p"; done; for port in $$ports; do if command -v lsof >/dev/null 2>&1; then lsof -tiTCP:$$port -sTCP:LISTEN 2>/dev/null | xargs -r kill -9 2>/dev/null || true; elif command -v fuser >/dev/null 2>&1; then fuser -k $$port/tcp >/dev/null 2>&1 || true; fi; done'

clean-db:
	rm -fr local_checkpoints logs || true
	rm -fr psy-contracts/deployments/localhost || true
	-docker stop -t 15 valkey-server nats-server scylla-server nostr-relay 2>/dev/null || true
	-docker rm -f valkey-server nats-server scylla-server nostr-relay 2>/dev/null || true
	# generated_db_data is handled by docker compose down -v in shutdown
	-docker compose -f psy_cli/psy_relayer_cli/indexer/envio/generated/docker-compose.yaml down -v 2>/dev/null || true
	docker volume rm psy-devnet-redis psy-devnet-scylla psy-devnet-scylla-data psy-devnet-nats 2>/dev/null || true

config_gen_v2:
	cargo run --release --package psy_plonky2_circuits --example config_gen_v2

generate-genesis-data:
	cargo test --release --package psy_plonky2_circuits --lib -- node::config::networks::local_devnet::tests --nocapture

data := ./psy_cli/psy_relayer_cli/data
generate-groth16:
	${BIN_PREFIX}/psy_relayer_cli generate-groth16  ${data}/common_circuit_data.json \
													  ${data}/proof_with_public_inputs.json \
													  ${data}/verifier_only_circuit_data.json \
													  ${data}/ \
													  ${data}/out_proof.json \
													  ${data}/out_vk.json
keystore := $(HOME)/.psy/keystore
export-solidity-verifier:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore} ./psy-contracts/src/GnarkGroth16Verifier.sol

export-solidity-verifier-deposit:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore}/deposit_append ./psy-contracts/src/DepositBatchVerifier.sol

export-solidity-verifier-withdrawal:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore}/withdrawal_claim ./psy-contracts/src/WithdrawalClaimVerifier.sol

BRIDGE_TO_CHECKPOINT ?= 10
BRIDGE_FROM_CHECKPOINT ?= 1
BRIDGE_PROOF_JSON ?= /tmp/bridge_batch_$(BRIDGE_TO_CHECKPOINT).json
BRIDGE_L1_RPC_URL ?= http://127.0.0.1:8545
BRIDGE_DEPLOYMENTS_NETWORK ?= localhost
BRIDGE_DEPOSITS_CONSUMED ?= 0
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
