PROVING_BACKEND := plonky2-poseidon-goldilocks
BIN_PREFIX      := ./target/release/
# PROVING_BACKEND := jtmb-poseidon-goldilocks

.PHONY: all build clean test deploy-contracts register-users query-chain-info run-all restart shutdown clean-db init-db run-coordinator-processor run-coordinator-edge run-realm-0-processor run-realm-0-edge run-realm-1-processor run-realm-1-edge run-realm-2-processor run-realm-2-edge run-realm-3-processor run-realm-3-edge run-worker-coordinator run-worker-realm-0 run-worker-realm-1 run-worker-realm-2 run-worker-realm-3

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

run-all: shutdown clean-db init-db
	./run_all.sh --proving-backend ${PROVING_BACKEND}

restart: shutdown
	./run_all.sh --proving-backend ${PROVING_BACKEND}

init-db:
	docker run --rm --name valkey-server -p 6379:6379 -d valkey/valkey
	docker run --rm --name nats-server -p 4222:4222 -d nats -js
	docker run --rm --name scylla-server -p 9042:9042 -d scylladb/scylla
	sleep 10

run-coordinator-processor:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-coordinator-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml

run-coordinator-edge:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-coordinator-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml

run-realm-0-processor:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_0_processor.yaml

run-realm-0-edge:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_0_edge.yaml

run-realm-1-processor:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_1_processor.yaml

run-realm-1-edge:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_1_edge.yaml

run-realm-2-processor:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_2_processor.yaml

run-realm-2-edge:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_2_edge.yaml

run-realm-3-processor:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_3_processor.yaml

run-realm-3-edge:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_3_edge.yaml

run-worker-coordinator:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_coordinator.yml

run-worker-realm-0:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_0.yml

run-worker-realm-1:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_1.yml

run-worker-realm-2:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_2.yml

run-worker-realm-3:
	RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_3.yml


shutdown:
	-ps aux | grep "[p]sy_node_cli" | awk '{print $$2}' | xargs kill -KILL 2>/dev/null || true
	-ps aux | grep "[p]sy_worker_cli" | awk '{print $$2}' | xargs kill -KILL 2>/dev/null || true

clean-db:
	docker rm -f scylla-server || true
	docker rm -f nats-server || true
	docker rm -f valkey-server || true
	rm -fr local_checkpoints logs || true

config_gen_v2:
	cargo run --release --package psy_plonky2_circuits --example config_gen_v2
