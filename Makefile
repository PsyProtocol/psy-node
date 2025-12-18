# Makefile for Psy project

.PHONY: all build clean test deploy-contracts register-users query-chain-info run-all restart shutdown clean-db init-db run-coordinator-processor run-coordinator-edge run-realm-0-processor run-realm-0-edge run-realm-1-processor run-realm-1-edge run-realm-2-processor run-realm-2-edge run-realm-3-processor run-realm-3-edge run-worker-coordinator run-worker-realm-0 run-worker-realm-1 run-worker-realm-2 run-worker-realm-3 run-dummy-prover-realm0-user0 run-dummy-prover-realm0-user1024 run-dummy-prover-realm0-user2048 run-dummy-prover-realm1-user1048576 run-dummy-prover-realm1-user1049600 run-dummy-prover-realm1-user1050624 run-dummy-prover-realm2-user2097152 run-dummy-prover-realm2-user2098176 run-dummy-prover-realm2-user2099200 run-dummy-prover-realm3-user3145728 run-dummy-prover-realm3-user3146752 run-dummy-prover-realm3-user3147776 run-dummy-provers

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
	./target/release/psy_node_cli start-coordinator-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml

run-coordinator-edge:
	./target/release/psy_node_cli start-coordinator-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml

run-realm-0-processor:
	./target/release/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_0_processor.yaml

run-realm-0-edge:
	./target/release/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_0_edge.yaml

run-realm-1-processor:
	./target/release/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_1_processor.yaml

run-realm-1-edge:
	./target/release/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_1_edge.yaml

run-realm-2-processor:
	./target/release/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_2_processor.yaml

run-realm-2-edge:
	./target/release/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_2_edge.yaml

run-realm-3-processor:
	./target/release/psy_node_cli start-realm-processor --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_3_processor.yaml

run-realm-3-edge:
	./target/release/psy_node_cli start-realm-edge --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/realm_3_edge.yaml

run-worker-coordinator:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_coordinator.yml

run-worker-realm-0:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_0.yml

run-worker-realm-1:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_1.yml

run-worker-realm-2:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_2.yml

run-worker-realm-3:
	./target/release/psy_worker_cli worker --user 0 --network local-devnet --proving-backend ${PROVING_BACKEND} --config ./psy_cli/example_node_configs/worker_realm_3.yml

run-dummy-prover-realm0-user0:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1338 --user 0 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm0-user1024:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1338 --user 1024 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm0-user2048:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1338 --user 2048 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm1-user1048576:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1339 --user 1048576 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm1-user1049600:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1339 --user 1049600 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm1-user1050624:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1339 --user 1050624 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm2-user2097152:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1340 --user 2097152 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm2-user2098176:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1340 --user 2098176 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm2-user2099200:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1340 --user 2099200 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm3-user3145728:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1341 --user 3145728 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm3-user3146752:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1341 --user 3146752 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-prover-realm3-user3147776:
	./target/release/psy_worker_cli dummy-end-cap-prover --proving-backend ${PROVING_BACKEND} --coordinator-url http://127.0.0.1:1337 --url http://127.0.0.1:1341 --user 3147776 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1

run-dummy-provers: run-dummy-prover-realm0-user0 run-dummy-prover-realm0-user1024 run-dummy-prover-realm0-user2048 run-dummy-prover-realm1-user1048576 run-dummy-prover-realm1-user1049600 run-dummy-prover-realm1-user1050624 run-dummy-prover-realm2-user2097152 run-dummy-prover-realm2-user2098176 run-dummy-prover-realm2-user2099200 run-dummy-prover-realm3-user3145728 run-dummy-prover-realm3-user3146752 run-dummy-prover-realm3-user3147776

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
