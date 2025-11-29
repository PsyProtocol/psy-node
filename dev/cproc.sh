#!/bin/bash

cargo build --release
./target/release/psy_node_cli start-coordinator-processor --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml > ./logs/coordinator_processor_1_logs.txt 
