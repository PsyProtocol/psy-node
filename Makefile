# Makefile for Psy project

.PHONY: all build clean test deploy-contracts register-users query-chain-info run-all restart shutdown clean-db init-db run-coordinator-processor run-coordinator-edge run-realm-0-processor run-realm-0-edge run-realm-1-processor run-realm-1-edge run-worker-coordinator run-worker-realm-0 run-worker-realm-1 run-dummy-prover

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
	./target/release/examples/deploy_contracts

register-users:
	./target/release/examples/register_user

query-chain-info:
	./target/release/examples/query_chain_info

all: build

run-all: shutdown clean-db init-db
	./run_all.sh

restart: shutdown
	./run_all.sh

init-db:
	docker run --rm --name valkey-server -p 6379:6379 -d valkey/valkey
	docker run --rm --name nats-server -p 4222:4222 -d nats -js
	docker run --rm --name scylla-server -p 9042:9042 -d scylladb/scylla
	sleep 10

run-coordinator-processor:
	./target/release/psy_node_cli start-coordinator-processor --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml

run-coordinator-edge:
	./target/release/psy_node_cli start-coordinator-edge --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml

run-realm-0-processor:
	./target/release/psy_node_cli start-realm-processor --config ./psy_cli/example_node_configs/realm_processor_1.yaml

run-realm-0-edge:
	./target/release/psy_node_cli start-realm-edge --config ./psy_cli/example_node_configs/realm_edge_1.yaml

run-realm-1-processor:
	./target/release/psy_node_cli start-realm-processor --config ./psy_cli/example_node_configs/realm_processor_2.yaml

run-realm-1-edge:
	./target/release/psy_node_cli start-realm-edge --config ./psy_cli/example_node_configs/realm_edge_2.yaml

run-worker-coordinator:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --config ./psy_cli/example_node_configs/worker_1.yml

run-worker-realm-0:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --config ./psy_cli/example_node_configs/worker_realm_1.yml

run-worker-realm-1:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --config ./psy_cli/example_node_configs/worker_realm_2.yml

run-dummy-prover:
	./target/release/psy_worker_cli dummy-end-cap-prover --url http://127.0.0.1:1338 --user 0 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

shutdown:
	pkill -f "psy_node_cli" || true
	pkill -f "psy_worker_cli" || true

clean-db:
	docker rm -f scylla-server || true
	docker rm -f nats-server || true
	docker rm -f valkey-server || true
	rm -fr local_checkpoints logs || true

config_gen_v2:
	cargo run --release --package psy_plonky2_circuits --example config_gen_v2
