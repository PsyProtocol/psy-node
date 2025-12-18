#!/bin/bash

# Configuration
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# 1. Build / Setup Phase (Running synchronously)
echo "-----------------------------------------------------"
echo "Running Config Gen and Build..."
echo "-----------------------------------------------------"

#cargo run --release --package psy_plonky2_circuits --example config_gen_v2
#if [ $? -ne 0 ]; then echo "Config gen failed"; exit 1; fi

cargo build --release
if [ $? -ne 0 ]; then echo "Build failed"; exit 1; fi

echo "-----------------------------------------------------"
echo "Starting Services..."
echo "Press Ctrl+C to stop all services gracefully."
echo "-----------------------------------------------------"

# Array to keep track of Process IDs (PIDs)
PIDS=()

# Function to handle Ctrl+C
cleanup() {
    echo ""
    echo "-----------------------------------------------------"
    echo "Received Ctrl+C. Forwarding SIGINT to processes..."
    echo "-----------------------------------------------------"
    
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping PID $pid..."
            kill -SIGINT "$pid"
        fi
    done

    # Wait for all background processes to finish cleaning up
    wait
    echo "All services stopped."
    exit 0
}

# Register the trap
trap cleanup SIGINT

# -----------------------------------------------------
# Start Service 1: Coordinator Processor
# -----------------------------------------------------
# We use > >(pipe) so that $! captures the binary PID, not the logger PID
./target/release/psy_node_cli start-coordinator-processor \
    --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml \
    > >(tee "$LOG_DIR/coordinator_processor_1_logs.txt" | sed -u 's/^/[COORD-PROC] /') 2>&1 &

PID_1=$!
PIDS+=($PID_1)
echo "Started Coordinator Processor (PID: $PID_1)"

# Sleep as requested
sleep 5

# -----------------------------------------------------
# Start Service 2: Coordinator Edge
# -----------------------------------------------------
./target/release/psy_node_cli start-coordinator-edge \
    --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml \
    > >(tee "$LOG_DIR/coordinator_edge_1_logs.txt" | sed -u 's/^/[COORD-EDGE] /') 2>&1 &

PID_2=$!
PIDS+=($PID_2)
echo "Started Coordinator Edge (PID: $PID_2)"

# -----------------------------------------------------
# Start Service 3: Worker
# -----------------------------------------------------
./target/release/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --config ./psy_cli/example_node_configs/worker_coordinator.yml \
    > >(tee "$LOG_DIR/worker_coordinator_logs.txt" | sed -u 's/^/[WORKER-COORD]   /') 2>&1 &

PID_3=$!
PIDS+=($PID_3)
echo "Started Worker (PID: $PID_3)"

# Wait allows the script to sit idle until a signal (Ctrl+C) is caught
wait