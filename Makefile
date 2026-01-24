PROVING_BACKEND := plonky2-poseidon-goldilocks
BIN_PREFIX      := ./target/release/
# PROVING_BACKEND := jtmb-poseidon-goldilocks

.PHONY: all build clean test deploy-contracts register-users query-chain-info run-all restart shutdown clean-db run-dummy-prover

all: build

build:
	cargo build --release --examples --bin psy_worker_cli --bin psy_node_cli

clean:
	cargo clean

check:
	@cargo check --workspace --all-targets --tests --benches --examples --bins

test:
	cargo test

deploy-contracts:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/examples/deploy_contracts

register-users:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/examples/register_user

query-chain-info:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/examples/query_chain_info

run-all: shutdown clean-db
	bun run dev/locSetupV4.ts --proving-backend ${PROVING_BACKEND} --db-only --coordinator-only --realm-only --start-realm-id 0 --end-realm-id 3 --workers-only --coordinator-workers 1 --realm-workers 4 --env RUST_LOG=psy_node_common=debug,psy_worker_core=debug,psy_node_core=debug

restart: shutdown
	bun run dev/locSetupV4.ts --proving-backend ${PROVING_BACKEND} --coordinator-only --realm-only --start-realm-id 0 --end-realm-id 3 --workers-only --coordinator-workers 1 --realm-workers 4

run-dummy-prover:
	@echo "Starting dummy prover for all realms using random users..."
	@./dev/dummy_prover.sh prove_random -p ${PROVING_BACKEND}

shutdown:
	-ps aux | grep "[p]sy_node_cli" | awk '{print $$2}' | xargs kill -KILL 2>/dev/null || true
	-ps aux | grep "[p]sy_worker_cli" | awk '{print $$2}' | xargs kill -KILL 2>/dev/null || true

clean-db:
	sudo rm -fr local_checkpoints logs db || true

config_gen_v2:
	cargo run --release --package psy_plonky2_circuits --example config_gen_v2

generate-genesis-data:
	cargo test --release --package psy_plonky2_circuits --lib -- node::config::networks::local_devnet::tests --nocapture
