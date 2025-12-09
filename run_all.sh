#!/bin/bash

# Comprehensive startup script for all services
# Based on existing dev scripts, starts all components in proper order
#
# Usage: ./run_all.sh [--rebuild]
#   --rebuild: Force rebuild even if binaries exist

set -e  # Exit on any error

# Configuration
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "-----------------------------------------------------"
echo "Starting All Services..."
echo "Press Ctrl+C to stop all services gracefully."
echo "-----------------------------------------------------"

# Function to handle Ctrl+C
cleanup() {
    echo ""
    echo "-----------------------------------------------------"
    echo "Received Ctrl+C. Stopping Psy services..."
    echo "-----------------------------------------------------"

    # Kill all psy_node_cli and psy_worker_cli processes
    pkill -f "psy_node_cli" || true
    pkill -f "psy_worker_cli" || true

    # Wait for all background processes to finish cleaning up
    wait
    echo "All services stopped."
    exit 0
}

# Register the trap
trap cleanup SIGINT

# Build the project (skip if binaries exist and no rebuild requested)
if [ ! -f "target/release/psy_node_cli" ] || [ ! -f "target/release/psy_worker_cli" ]; then
    echo -e "${YELLOW}Building project...${NC}"
    cargo build --release --bin psy_node_cli --bin psy_worker_cli
    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed${NC}"
        exit 1
    fi
    echo -e "${GREEN}Build completed${NC}"
fi

# -----------------------------------------------------
# Start Coordinator Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting coordinator processor...${NC}"

./target/release/psy_node_cli start-coordinator-processor \
    --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml \
    > >(tee "$LOG_DIR/coordinator_0_1_processor_logs.txt" | sed -u 's/^/[COORD-PROC] /') 2>&1 &

echo "Started Coordinator Processor"

sleep 5

# -----------------------------------------------------
# Start Coordinator Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting coordinator edge...${NC}"

./target/release/psy_node_cli start-coordinator-edge \
    --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml \
    > >(tee "$LOG_DIR/coordinator_0_1_edge_logs.txt" | sed -u 's/^/[COORD-EDGE] /') 2>&1 &

echo "Started Coordinator Edge"

sleep 2

# -----------------------------------------------------
# Start Coordinator Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting coordinator worker...${NC}"

./target/release/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --config ./psy_cli/example_node_configs/worker_1.yml \
    > >(tee "$LOG_DIR/worker_coordinator_logs.txt" | sed -u 's/^/[WORKER-COORD] /') 2>&1 &

echo "Started Coordinator Worker"

sleep 2

# -----------------------------------------------------
# Start Realm 0 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 processor...${NC}"

./target/release/psy_node_cli start-realm-processor \
    --config ./psy_cli/example_node_configs/realm_processor_1.yaml \
    > >(tee "$LOG_DIR/realm_0_1_processor_logs.txt" | sed -u 's/^/[REALM0-PROC] /') 2>&1 &

echo "Started Realm 0 Processor"

sleep 2

# -----------------------------------------------------
# Start Realm 0 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 edge...${NC}"

./target/release/psy_node_cli start-realm-edge \
    --config ./psy_cli/example_node_configs/realm_edge_1.yaml \
    > >(tee "$LOG_DIR/realm_0_1_edge_logs.txt" | sed -u 's/^/[REALM0-EDGE] /') 2>&1 &

echo "Started Realm 0 Edge"

sleep 2

# -----------------------------------------------------
# Start Realm 0 Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 worker...${NC}"

./target/release/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --config ./psy_cli/example_node_configs/worker_realm_1.yml \
    > >(tee "$LOG_DIR/worker_realm_0_logs.txt" | sed -u 's/^/[WORKER-R0] /') 2>&1 &

echo "Started Realm 0 Worker"

sleep 2

# -----------------------------------------------------
# Start Realm 1 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 processor...${NC}"

./target/release/psy_node_cli start-realm-processor \
    --config ./psy_cli/example_node_configs/realm_processor_2.yaml \
    > >(tee "$LOG_DIR/realm_1_1_processor_logs.txt" | sed -u 's/^/[REALM1-PROC] /') 2>&1 &

echo "Started Realm 1 Processor"

sleep 3

# -----------------------------------------------------
# Start Realm 1 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 edge...${NC}"

./target/release/psy_node_cli start-realm-edge \
    --config ./psy_cli/example_node_configs/realm_edge_2.yaml \
    > >(tee "$LOG_DIR/realm_1_1_edge_logs.txt" | sed -u 's/^/[REALM1-EDGE] /') 2>&1 &

echo "Started Realm 1 Edge"

sleep 2

# -----------------------------------------------------
# Start Realm 1 Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 worker...${NC}"

./target/release/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --config ./psy_cli/example_node_configs/worker_realm_2.yml \
    > >(tee "$LOG_DIR/worker_realm_1_logs.txt" | sed -u 's/^/[WORKER-R1] /') 2>&1 &

echo "Started Realm 1 Worker"

sleep 2

# -----------------------------------------------------
# Start Dummy Prover
# -----------------------------------------------------
# Start Dummy End Cap Prover (will wait for system to be fully ready)
# -----------------------------------------------------
echo -e "${YELLOW}Starting dummy end cap prover...${NC}"
echo -e "${YELLOW}Note: Waiting for system to fully initialize before starting dummy prover.${NC}"

# Wait for all services to be fully initialized
sleep 20

./target/release/psy_worker_cli dummy-end-cap-prover \
    --url http://127.0.0.1:1338 --user 0 \
    > >(tee "$LOG_DIR/dummy_end_cap_prover_logs.txt" | sed -u 's/^/[DUMMY-PROVER] /') 2>&1 &

echo "Started Dummy End Cap Prover"

# Give it time to run or fail gracefully
sleep 5



echo ""
echo -e "${GREEN}All services started successfully!${NC}"
echo "-----------------------------------------------------"
echo "Active processes:"
echo "  Coordinator Processor"
echo "  Coordinator Edge"
echo "  Realm 0 Processor"
echo "  Realm 0 Edge"
echo "  Realm 1 Processor"
echo "  Realm 1 Edge"
echo "  Dummy End Cap Prover"
echo "  Coordinator Worker"
echo "  Realm 0 Worker"
echo "  Realm 1 Worker"
echo "-----------------------------------------------------"
echo "Logs are being saved to $LOG_DIR/"
echo "Press Ctrl+C to stop all services gracefully."
echo "-----------------------------------------------------"

# Wait allows the script to sit idle until a signal (Ctrl+C) is caught
wait
