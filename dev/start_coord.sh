#!/bin/bash
cargo build --release
./target/release/psy_node_cli start-coordinator-processor --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml > logs/coordinator_processor_1_logs.txt 2>&1 &
sleep 5
./target/release/psy_node_cli start-coordinator-edge --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml > logs/coordinator_edge_1_logs.txt 2>&1 &
./target/release/psy_worker_cli worker --user 0 --network local-devnet --config ./psy_cli/example_node_configs/worker_1.yml > logs/worker_1_logs.txt 2>&1 &


