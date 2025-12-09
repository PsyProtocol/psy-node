#!/bin/bash

# Comprehensive startup script for all services
# Based on existing dev scripts, starts all components in proper order
#
# Usage: ./run_all.sh [--rebuild]
#   --rebuild: Force rebuild even if binaries exist

set -e  # Exit on any error

# Parse arguments
REBUILD=false
if [ "$1" = "--rebuild" ]; then
    REBUILD=true
fi

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

# Array to keep track of Process IDs (PIDs)
PIDS=()

# Function to handle Ctrl+C
cleanup() {
    echo ""
    echo "-----------------------------------------------------"
    echo "Received Ctrl+C. Stopping all Psy processes..."
    echo "-----------------------------------------------------"

    # Kill all psy_node_cli and psy_worker_cli processes
    pkill -f "psy_node_cli" || true
    pkill -f "psy_worker_cli" || true

    # Also try the stored PIDs (though they may be bash PIDs)
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

# Build the project (skip if binaries exist and no rebuild requested)
if [ "$REBUILD" = true ] || [ ! -f "target/release/psy_node_cli" ] || [ ! -f "target/release/psy_worker_cli" ]; then
    echo -e "${YELLOW}Building project...${NC}"
    cargo build --release
    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed${NC}"
        exit 1
    fi
    echo -e "${GREEN}Build completed${NC}"
else
    echo -e "${GREEN}Using existing binaries (use --rebuild to force rebuild)${NC}"
fi

# Clean up data and containers first
# -----------------------------------------------------
echo -e "${YELLOW}Cleaning up data and containers...${NC}"

# Stop and remove existing containers
docker stop valkey-server nats-server scylla-server 2>/dev/null || true
docker rm valkey-server nats-server scylla-server 2>/dev/null || true

# Clean up checkpoint backups to avoid integrity errors
echo "Cleaning up checkpoint backups..."
rm -rf ./local_checkpoints
mkdir -p ./local_checkpoints

echo -e "${GREEN}Cleanup completed${NC}"

# -----------------------------------------------------
# Start Database Services
# -----------------------------------------------------
echo -e "${YELLOW}Starting database services...${NC}"

# Start Valkey (Redis)
docker run --rm --name valkey-server -p 6379:6379 -d valkey/valkey
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to start Valkey${NC}"
    exit 1
fi
echo "Started Valkey (Redis) on port 6379"

# Start NATS
docker run --rm --name nats-server -p 4222:4222 -d nats -js
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to start NATS${NC}"
    exit 1
fi
echo "Started NATS on port 4222"

# Start Scylla
docker run --rm --name scylla-server -p 9042:9042 -d scylladb/scylla
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to start Scylla${NC}"
    exit 1
fi
echo "Started Scylla on port 9042"

# Wait for databases to be ready
sleep 10
echo -e "${GREEN}Database services ready${NC}"

# -----------------------------------------------------
# Start Coordinator Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting coordinator processor...${NC}"

./target/release/psy_node_cli start-coordinator-processor \
    --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml \
    > >(tee "$LOG_DIR/coordinator_0_1_processor_logs.txt" | sed -u 's/^/[COORD-PROC] /') 2>&1 &

PID_COORD_PROC=$!
PIDS+=($PID_COORD_PROC)
echo "Started Coordinator Processor (PID: $PID_COORD_PROC)"

sleep 5

# -----------------------------------------------------
# Start Coordinator Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting coordinator edge...${NC}"

./target/release/psy_node_cli start-coordinator-edge \
    --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml \
    > >(tee "$LOG_DIR/coordinator_0_1_edge_logs.txt" | sed -u 's/^/[COORD-EDGE] /') 2>&1 &

PID_COORD_EDGE=$!
PIDS+=($PID_COORD_EDGE)
echo "Started Coordinator Edge (PID: $PID_COORD_EDGE)"

sleep 5

# -----------------------------------------------------
# Start Realm 0 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 processor...${NC}"

./target/release/psy_node_cli start-realm-processor \
    --config ./psy_cli/example_node_configs/realm_processor_1.yaml \
    > >(tee "$LOG_DIR/realm_0_1_processor_logs.txt" | sed -u 's/^/[REALM0-PROC] /') 2>&1 &

PID_REALM0_PROC=$!
PIDS+=($PID_REALM0_PROC)
echo "Started Realm 0 Processor (PID: $PID_REALM0_PROC)"

sleep 3

# -----------------------------------------------------
# Start Realm 0 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 edge...${NC}"

./target/release/psy_node_cli start-realm-edge \
    --config ./psy_cli/example_node_configs/realm_edge_1.yaml \
    > >(tee "$LOG_DIR/realm_0_1_edge_logs.txt" | sed -u 's/^/[REALM0-EDGE] /') 2>&1 &

PID_REALM0_EDGE=$!
PIDS+=($PID_REALM0_EDGE)
echo "Started Realm 0 Edge (PID: $PID_REALM0_EDGE)"

sleep 3

# -----------------------------------------------------
# Start Realm 1 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 processor...${NC}"

./target/release/psy_node_cli start-realm-processor \
    --config ./psy_cli/example_node_configs/realm_processor_2.yaml \
    > >(tee "$LOG_DIR/realm_1_1_processor_logs.txt" | sed -u 's/^/[REALM1-PROC] /') 2>&1 &

PID_REALM1_PROC=$!
PIDS+=($PID_REALM1_PROC)
echo "Started Realm 1 Processor (PID: $PID_REALM1_PROC)"

sleep 3

# -----------------------------------------------------
# Start Realm 1 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 edge...${NC}"

./target/release/psy_node_cli start-realm-edge \
    --config ./psy_cli/example_node_configs/realm_edge_2.yaml \
    > >(tee "$LOG_DIR/realm_1_1_edge_logs.txt" | sed -u 's/^/[REALM1-EDGE] /') 2>&1 &

PID_REALM1_EDGE=$!
PIDS+=($PID_REALM1_EDGE)
echo "Started Realm 1 Edge (PID: $PID_REALM1_EDGE)"

sleep 3

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

PID_DUMMY_PROVER=$!
PIDS+=($PID_DUMMY_PROVER)
echo "Started Dummy End Cap Prover (PID: $PID_DUMMY_PROVER)"

# Give it time to run or fail gracefully
sleep 5

# -----------------------------------------------------
# Start Worker Services
# -----------------------------------------------------
echo -e "${YELLOW}Starting worker services...${NC}"

# Start Coordinator Worker
./target/release/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --config ./psy_cli/example_node_configs/worker_1.yml \
    > >(tee "$LOG_DIR/worker_coordinator_logs.txt" | sed -u 's/^/[WORKER-COORD] /') 2>&1 &

PID_WORKER_COORD=$!
PIDS+=($PID_WORKER_COORD)
echo "Started Coordinator Worker (PID: $PID_WORKER_COORD)"

sleep 2

# Start Realm 0 Worker
./target/release/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --config ./psy_cli/example_node_configs/worker_realm_1.yml \
    > >(tee "$LOG_DIR/worker_realm_0_logs.txt" | sed -u 's/^/[WORKER-R0] /') 2>&1 &

PID_WORKER_R0=$!
PIDS+=($PID_WORKER_R0)
echo "Started Realm 0 Worker (PID: $PID_WORKER_R0)"

sleep 2

# Start Realm 1 Worker
./target/release/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --config ./psy_cli/example_node_configs/worker_realm_2.yml \
    > >(tee "$LOG_DIR/worker_realm_1_logs.txt" | sed -u 's/^/[WORKER-R1] /') 2>&1 &

PID_WORKER_R1=$!
PIDS+=($PID_WORKER_R1)
echo "Started Realm 1 Worker (PID: $PID_WORKER_R1)"

echo ""
echo -e "${GREEN}All services started successfully!${NC}"
echo "-----------------------------------------------------"
echo "Active processes:"
echo "  Coordinator Processor: $PID_COORD_PROC"
echo "  Coordinator Edge: $PID_COORD_EDGE"
echo "  Realm 0 Processor: $PID_REALM0_PROC"
echo "  Realm 0 Edge: $PID_REALM0_EDGE"
echo "  Realm 1 Processor: $PID_REALM1_PROC"
echo "  Realm 1 Edge: $PID_REALM1_EDGE"
echo "  Dummy End Cap Prover: $PID_DUMMY_PROVER"
echo "  Coordinator Worker: $PID_WORKER_COORD"
echo "  Realm 0 Worker: $PID_WORKER_R0"
echo "  Realm 1 Worker: $PID_WORKER_R1"
echo "-----------------------------------------------------"
echo "Logs are being saved to $LOG_DIR/"
echo "Press Ctrl+C to stop all services gracefully."
echo "-----------------------------------------------------"

# Wait allows the script to sit idle until a signal (Ctrl+C) is caught
wait
