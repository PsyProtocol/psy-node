PROVING_BACKEND := plonky2-poseidon-goldilocks
BIN_PREFIX   := ./target/release/
PSY_CONFIG_PATH := $(CURDIR)/psy-genesis/config.json
# 本机开发默认 localhost 阶段；部署构建在部署脚本里显式覆盖。
PSY_NETWORK ?= localhost
export PSY_NETWORK
ifneq (,$(wildcard ./.env))
include .env
export
endif

PSY_DEVNET_DIR ?= $(HOME)/.psy/devnet/local
PSY_RELAYER_MULTISIG_ACCOUNT ?= $(PSY_DEVNET_DIR)/relayer-multisig-account.json
PSY_MULTISIG_POLICY_ARTIFACT ?= $(PSY_DEVNET_DIR)/inputs/multisig_policy.json
PSY_BRIDGE_DAEMON_CONFIG ?= $(PSY_DEVNET_DIR)/daemon.toml
PSY_GUARDIAN_CONFIG ?= $(if $(strip $(PSY_GUARDIANS_ROOT)),$(PSY_GUARDIANS_ROOT),$(PSY_DEVNET_DIR)/guardians)/config.json

LOG_LEVEL    := psy_node_common=debug,psy_node_cli=info,psy_worker_core=debug,psy_node_core=debug
VITE_NETWORK  ?= localhost
VITE_FORK    ?= false
SEPOLIA_RPC_URL ?= https://ethereum-sepolia-rpc.publicnode.com
PSY_SKIP_BRANCH_CHECK ?= 1
PSY_SKIP_KEYSTORE ?= 1
PSY_SKIP_BUILD ?= 1
PURGE ?= 1
# PROVING_BACKEND := jtmb-poseidon-goldilocks

.PHONY: all build clean test check check-all psy-data-coverage psy-vm-coverage psy-node-common-coverage psy-prover-coverage psy-prover-coverage-offline psy-prover-coverage-online deploy-contracts register-users query-chain-info run-all rollback-db rollback-stop rollback-resume staging-server restart shutdown clean-db clean-guardian run-dummy-prover config_gen_v2 generate-genesis-data generate-guardians-root check-guardians-root-inputs prepare-realm-p2p build-guardian-tools prepare-guardian-account prepare-multisig-policy-artifact prepare-guardian-inputs prepare-guardian-config check-guardian-genesis check-guardians check-guardians-live generate-groth16 regen-groth16-keystore regen-bridge-agg-keystore export-solidity-verifier export-solidity-verifier-deposit export-solidity-verifier-withdrawal export-solidity-verifier-reward

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

# Line coverage for node-side data, VM, and common runtime crates.
PSY_CRATE_COVERAGE_MIN_LINES ?= 85
PSY_CRATE_COVERAGE_MIN_FUNCTIONS ?= 85
PSY_CRATE_COVERAGE_ARGS := --release --locked --lib --summary-only --fail-under-lines $(PSY_CRATE_COVERAGE_MIN_LINES) --fail-under-functions $(PSY_CRATE_COVERAGE_MIN_FUNCTIONS)

psy-data-coverage:
	cargo llvm-cov $(PSY_CRATE_COVERAGE_ARGS) -p psy_data

psy-vm-coverage:
	cargo llvm-cov $(PSY_CRATE_COVERAGE_ARGS) -p psy_vm

psy-node-common-coverage:
	cargo llvm-cov $(PSY_CRATE_COVERAGE_ARGS) -p psy_node_common

# The full suite includes async_split_tests, which exercise live node services.
# Keep explicit online and offline targets for environments without those services.
PSY_PROVER_TEST_NETWORK ?= sepolia
PSY_PROVER_COV_ARGS := --release --locked -p psy_prover --lib --ignore-filename-regex '(/|^)examples/|ordering_tests\.rs$$'
PSY_PROVER_COV_OFFLINE_TESTS := --skip session::session::async_split_tests

psy-prover-coverage:
	PSY_PROVER_TEST_NETWORK=$(PSY_PROVER_TEST_NETWORK) cargo llvm-cov $(PSY_PROVER_COV_ARGS) --summary-only --fail-under-lines $(PSY_CRATE_COVERAGE_MIN_LINES) --fail-under-functions $(PSY_CRATE_COVERAGE_MIN_FUNCTIONS) -- --test-threads=1

psy-prover-coverage-offline:
	cargo llvm-cov $(PSY_PROVER_COV_ARGS) --summary-only -- $(PSY_PROVER_COV_OFFLINE_TESTS) --test-threads=1

psy-prover-coverage-online:
	PSY_PROVER_TEST_NETWORK=$(PSY_PROVER_TEST_NETWORK) cargo llvm-cov $(PSY_PROVER_COV_ARGS) --summary-only -- session::session::async_split_tests --test-threads=1

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
	PSY_DEVNET_DIR="$(PSY_DEVNET_DIR)" PSY_BRIDGE_DAEMON_CONFIG="$(PSY_BRIDGE_DAEMON_CONFIG)" PSY_GUARDIAN_AUTO_PREPARE=1 VITE_NETWORK=$(VITE_NETWORK) VITE_FORK=$(VITE_FORK) SEPOLIA_RPC_URL=$(SEPOLIA_RPC_URL) ETH_RPC_URL=$(ETH_RPC_URL) REDEPLOY_L1=$(REDEPLOY_L1) PSY_SKIP_BRANCH_CHECK=$(PSY_SKIP_BRANCH_CHECK) PSY_SKIP_KEYSTORE=$(PSY_SKIP_KEYSTORE) PSY_SKIP_BUILD=$(PSY_SKIP_BUILD) bun run dev/locSetupV4.ts $(LOCSETUP_START_ARGS)

restart:
	bun run dev/locSetupV4.ts --control restart

rollback-stop:
	bun run dev/locSetupV4.ts --control rollback-stop

rollback-resume:
	bun run dev/locSetupV4.ts --control rollback-resume

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

rollback-db:
	bash dev/start_db.sh --persist

shutdown:
	bun run dev/locSetupV4.ts --teardown $(if $(filter 1,$(PURGE)),--purge)

clean-db:
	$(MAKE) clean-guardian

clean-guardian:
	@test -z "$(strip $(PSY_GUARDIANS_ROOT) $(PSY_GUARDIAN_CHAINS) $(PSY_GUARDIAN_L1_ENDPOINTS) $(PSY_GUARDIAN_APPROVED_CONTRACTS))" || { echo "Refusing explicit Guardian path overrides; unset them or clean that operator configuration explicitly" >&2; exit 1; }
	@test "$(abspath $(PSY_GUARDIAN_CONFIG))" = "$(abspath $(PSY_DEVNET_DIR)/guardians/config.json)" || { echo "PSY_GUARDIAN_CONFIG is outside PSY_DEVNET_DIR; unset the stale override" >&2; exit 1; }
	@test "$(abspath $(PSY_BRIDGE_DAEMON_CONFIG))" = "$(abspath $(PSY_DEVNET_DIR)/daemon.toml)" || { echo "PSY_BRIDGE_DAEMON_CONFIG is outside PSY_DEVNET_DIR; unset the stale override" >&2; exit 1; }
	$(MAKE) shutdown PURGE=1
	@root="$(abspath $(PSY_DEVNET_DIR))"; \
	case "$$root" in /|"$(abspath $(HOME))"|"$(abspath $(CURDIR))") echo "Refusing unsafe PSY_DEVNET_DIR: $$root" >&2; exit 1;; esac; \
	if [ ! -e "$$root" ]; then echo "Guardian state already absent: $$root"; exit 0; fi; \
	backup="$$root.before-guardian-regeneration-$$(date +%Y%m%d-%H%M%S)"; \
	test ! -e "$$backup" || { echo "Guardian backup already exists: $$backup" >&2; exit 1; }; \
	mv -- "$$root" "$$backup"; \
	echo "Guardian public state moved to $$backup"; \
	echo "Guardian signing keys under $(HOME)/.psy/keystore were preserved"
config_gen_v2:
	cargo run --release --package psy_plonky2_circuits --example config_gen_v2

# Public-only registration 2 (user_id 524288), independent of L1 signer custody.
# Supply PSY_RELAYER_MULTISIG_ACCOUNT and PSY_MULTISIG_POLICY_ARTIFACT public JSON paths.
# With PSY_GUARDIANS_ROOT, read existing genesis.json and generate Guardian configuration.
GUARDIANS_ROOT_ARGS = $(if $(strip $(PSY_GUARDIANS_ROOT)),--guardians-root "$(PSY_GUARDIANS_ROOT)" --chains "$(PSY_GUARDIAN_CHAINS)" --l1-endpoints "$(PSY_GUARDIAN_L1_ENDPOINTS)" --approved-contracts "$(PSY_GUARDIAN_APPROVED_CONTRACTS)")
ifneq ($(strip $(PSY_GUARDIANS_ROOT) $(PSY_GUARDIAN_CHAINS) $(PSY_GUARDIAN_L1_ENDPOINTS) $(PSY_GUARDIAN_APPROVED_CONTRACTS)),)
generate-genesis-data: check-guardians-root-inputs
endif
generate-genesis-data:
	@test -n "$(PSY_RELAYER_MULTISIG_ACCOUNT)" || { echo "PSY_RELAYER_MULTISIG_ACCOUNT is required" >&2; exit 1; }
	@test -n "$(PSY_MULTISIG_POLICY_ARTIFACT)" || { echo "PSY_MULTISIG_POLICY_ARTIFACT is required" >&2; exit 1; }
	@env -u PRIVATE_KEY -u BRIDGE_RELAYER_L2_PRIVATE_KEY -u KEYSTORE_PATH -u PSY_BRIDGE_RELAYER_KEYSTORE_PATH -u BRIDGE_RELAYER_KEYSTORE_PATH -u WALLET_PASSWORD ${BIN_PREFIX}psy_dev_cli generate-genesis-data --repo-root "$(CURDIR)" --relayer-multisig-account "$(PSY_RELAYER_MULTISIG_ACCOUNT)" --multisig-policy-artifact "$(PSY_MULTISIG_POLICY_ARTIFACT)" $(GUARDIANS_ROOT_ARGS)

check-guardians-root-inputs:
	@test -n "$(strip $(PSY_GUARDIANS_ROOT))" || { echo "PSY_GUARDIANS_ROOT is required" >&2; exit 1; }
	@test -n "$(strip $(PSY_GUARDIAN_CHAINS))" || { echo "PSY_GUARDIAN_CHAINS is required" >&2; exit 1; }
	@test -n "$(strip $(PSY_GUARDIAN_L1_ENDPOINTS))" || { echo "PSY_GUARDIAN_L1_ENDPOINTS is required" >&2; exit 1; }
	@test -n "$(strip $(PSY_GUARDIAN_APPROVED_CONTRACTS))" || { echo "PSY_GUARDIAN_APPROVED_CONTRACTS is required" >&2; exit 1; }
	@test -r "$(PSY_GUARDIAN_CHAINS)" || { echo "Missing reviewed chains input: $(PSY_GUARDIAN_CHAINS)" >&2; exit 1; }
	@test -r "$(PSY_GUARDIAN_L1_ENDPOINTS)" || { echo "Missing reviewed L1 endpoints input: $(PSY_GUARDIAN_L1_ENDPOINTS)" >&2; exit 1; }
	@test -r "$(PSY_GUARDIAN_APPROVED_CONTRACTS)" || { echo "Missing approved contracts input: $(PSY_GUARDIAN_APPROVED_CONTRACTS)" >&2; exit 1; }
	@test ! -e "$(PSY_GUARDIANS_ROOT)" || { echo "Guardian root already exists; preserve it and select a new PSY_DEVNET_DIR or PSY_GUARDIANS_ROOT" >&2; exit 1; }

prepare-realm-p2p:
	bun run dev/locSetupV4.ts --prepare-realm-p2p --realms-count 2

build-guardian-tools:
	cargo build --release --bin psy_relayer_cli --bin psy_dev_cli

prepare-guardian-account: build-guardian-tools
	@${BIN_PREFIX}psy_relayer_cli guardian-prepare-account --output "$(PSY_RELAYER_MULTISIG_ACCOUNT)"

prepare-multisig-policy-artifact:
	@bun run dev/guardianInputs.ts --output "$(PSY_DEVNET_DIR)/inputs" --policy-only $(if $(strip $(PSY_COMPILER_ARTIFACTS_DIR)),--compiler-artifacts "$(PSY_COMPILER_ARTIFACTS_DIR)")

prepare-guardian-inputs: build-guardian-tools
	@bun run dev/guardianInputs.ts --output "$(PSY_DEVNET_DIR)/inputs" $(if $(strip $(PSY_COMPILER_ARTIFACTS_DIR)),--compiler-artifacts "$(PSY_COMPILER_ARTIFACTS_DIR)")

prepare-guardian-config:
	@bun run dev/guardianConfig.ts "$(PSY_GUARDIAN_CONFIG)" "$(PSY_BRIDGE_DAEMON_CONFIG)"

generate-guardians-root:
	@$(MAKE) generate-genesis-data \
		PSY_GUARDIANS_ROOT="$(or $(PSY_GUARDIANS_ROOT),$(PSY_DEVNET_DIR)/guardians)" \
		PSY_GUARDIAN_CHAINS="$(or $(PSY_GUARDIAN_CHAINS),$(PSY_DEVNET_DIR)/inputs/chains.json)" \
		PSY_GUARDIAN_L1_ENDPOINTS="$(or $(PSY_GUARDIAN_L1_ENDPOINTS),$(PSY_DEVNET_DIR)/inputs/l1-endpoints.json)" \
		PSY_GUARDIAN_APPROVED_CONTRACTS="$(or $(PSY_GUARDIAN_APPROVED_CONTRACTS),$(PSY_DEVNET_DIR)/inputs/approved-contracts.json)"

check-guardian-genesis:
	@${BIN_PREFIX}psy_dev_cli check-guardian-genesis --config "$(PSY_GUARDIAN_CONFIG)" --genesis-data "$(CURDIR)/genesis.json"

check-guardians: check-guardian-genesis
	@${BIN_PREFIX}psy_relayer_cli guardian-service-check --config "$(PSY_GUARDIAN_CONFIG)" --genesis-data "$(CURDIR)/genesis.json"

check-guardians-live: check-guardian-genesis
	@${BIN_PREFIX}psy_relayer_cli guardian-service-check --config "$(PSY_GUARDIAN_CONFIG)" --genesis-data "$(CURDIR)/genesis.json" --live

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
	${BIN_PREFIX}/psy_relayer_cli regenerate-groth16-keystore --keystore-dir $(KEYSTORE_DIR)

regen-bridge-agg-keystore:
	${BIN_PREFIX}/psy_relayer_cli regenerate-groth16-keystore --keystore-dir $(KEYSTORE_DIR) --skip-deposit-append --skip-withdrawal-claim --skip-reward-claim

keystore := $(KEYSTORE_DIR)
export-solidity-verifier:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore} ./psy-contracts/src/GnarkGroth16Verifier.sol

export-solidity-verifier-deposit:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore}/deposit_append ./psy-contracts/src/DepositBatchVerifier.sol

export-solidity-verifier-withdrawal:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore}/withdrawal_claim ./psy-contracts/src/WithdrawalClaimVerifier.sol

export-solidity-verifier-reward:
	${BIN_PREFIX}/psy_relayer_cli export-solidity-verifier ${keystore}/reward_claim ./psy-contracts/src/RewardClaimVerifier.sol

export-all-solidity-verifier: export-solidity-verifier export-solidity-verifier-deposit export-solidity-verifier-withdrawal export-solidity-verifier-reward
