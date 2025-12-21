#!/bin/bash

# Comprehensive startup script for all services
# Based on existing dev scripts, starts all components in proper order
#
# Usage: ./run_all.sh [--proving-backend BACKEND]
#   --proving-backend BACKEND: Specify proving backend (default: jtmb-poseidon-goldilocks)

set -e  # Exit on any error

# Configuration
LOG_DIR="logs"
PROVING_BACKEND="plonky2-poseidon-goldilocks"
BIN_PREFIX="./target/release/"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --proving-backend)
            PROVING_BACKEND="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--proving-backend BACKEND]"
            echo ""
            echo "Options:"
            echo "  --proving-backend BACKEND Specify proving backend (default: jtmb-poseidon-goldilocks)"
            echo ""
            echo "Available proving backends:"
            echo "  jtmb-poseidon-goldilocks  JTMB Poseidon Goldilocks (default)"
            echo "  plonky2-poseidon-goldilocks Plonky2 Poseidon Goldilocks"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--proving-backend BACKEND]"
            exit 1
            ;;
    esac
done


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

# Build the project (skip if binaries exist)
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

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-coordinator-processor \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml \
    > >(tee -a "$LOG_DIR/coordinator_0_1_processor_logs.txt" | sed -u 's/^/[COORD-PROC] /') 2>&1 &

echo "Started Coordinator Processor"

sleep 5

# -----------------------------------------------------
# Start Coordinator Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting coordinator edge...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-coordinator-edge \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml \
    > >(tee -a "$LOG_DIR/coordinator_0_1_edge_logs.txt" | sed -u 's/^/[COORD-EDGE] /') 2>&1 &

echo "Started Coordinator Edge"

sleep 2

# -----------------------------------------------------
# Start Coordinator Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting coordinator worker...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/worker_coordinator.yml \
    > >(tee -a "$LOG_DIR/worker_coordinator_logs.txt" | sed -u 's/^/[WORKER-COORD] /') 2>&1 &

echo "Started Coordinator Worker"

sleep 2

# -----------------------------------------------------
# Start Realm 0 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 processor...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_0_processor.yaml \
    > >(tee -a "$LOG_DIR/realm_0_processor_logs.txt" | sed -u 's/^/[REALM0-PROC] /') 2>&1 &

echo "Started Realm 0 Processor"

sleep 2

# -----------------------------------------------------
# Start Realm 0 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 edge...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_0_edge.yaml \
    > >(tee -a "$LOG_DIR/realm_0_edge_logs.txt" | sed -u 's/^/[REALM0-EDGE] /') 2>&1 &

echo "Started Realm 0 Edge"

sleep 2

# -----------------------------------------------------
# Start Realm 0 Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 0 worker...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/worker_realm_0.yml \
    > >(tee -a "$LOG_DIR/worker_realm_0_logs.txt" | sed -u 's/^/[WORKER-R0] /') 2>&1 &

echo "Started Realm 0 Worker"

sleep 2

# -----------------------------------------------------
# Start Realm 1 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 processor...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_1_processor.yaml \
    > >(tee -a "$LOG_DIR/realm_1_processor_logs.txt" | sed -u 's/^/[REALM1-PROC] /') 2>&1 &

echo "Started Realm 1 Processor"

sleep 3

# -----------------------------------------------------
# Start Realm 1 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 edge...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_1_edge.yaml \
    > >(tee -a "$LOG_DIR/realm_1_edge_logs.txt" | sed -u 's/^/[REALM1-EDGE] /') 2>&1 &

echo "Started Realm 1 Edge"

sleep 2

# -----------------------------------------------------
# Start Realm 1 Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 1 worker...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/worker_realm_1.yml \
    > >(tee -a "$LOG_DIR/worker_realm_1_logs.txt" | sed -u 's/^/[WORKER-R1] /') 2>&1 &

echo "Started Realm 1 Worker"

sleep 3

# -----------------------------------------------------
# Start Realm 2 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 2 processor...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_2_processor.yaml \
    > >(tee -a "$LOG_DIR/realm_2_processor_logs.txt" | sed -u 's/^/[REALM2-PROC] /') 2>&1 &

echo "Started Realm 2 Processor"

sleep 3

# -----------------------------------------------------
# Start Realm 2 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 2 edge...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_2_edge.yaml \
    > >(tee -a "$LOG_DIR/realm_2_edge_logs.txt" | sed -u 's/^/[REALM2-EDGE] /') 2>&1 &

echo "Started Realm 2 Edge"

sleep 5

# -----------------------------------------------------
# Start Realm 2 Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 2 worker...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/worker_realm_2.yml \
    > >(tee -a "$LOG_DIR/worker_realm_2_logs.txt" | sed -u 's/^/[WORKER-R2] /') 2>&1 &

echo "Started Realm 2 Worker"

sleep 3

# -----------------------------------------------------
# Start Realm 3 Processor
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 3 processor...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-processor \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_3_processor.yaml \
    > >(tee -a "$LOG_DIR/realm_3_processor_logs.txt" | sed -u 's/^/[REALM3-PROC] /') 2>&1 &

echo "Started Realm 3 Processor"

sleep 3

# -----------------------------------------------------
# Start Realm 3 Edge
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 3 edge...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_node_cli start-realm-edge \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/realm_3_edge.yaml \
    > >(tee -a "$LOG_DIR/realm_3_edge_logs.txt" | sed -u 's/^/[REALM3-EDGE] /') 2>&1 &

echo "Started Realm 3 Edge"

sleep 5

# -----------------------------------------------------
# Start Realm 3 Worker
# -----------------------------------------------------
echo -e "${YELLOW}Starting realm 3 worker...${NC}"

RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli worker \
    --user 0 --network local-devnet \
    --proving-backend $PROVING_BACKEND \
    --config ./psy_cli/example_node_configs/worker_realm_3.yml \
    > >(tee -a "$LOG_DIR/worker_realm_3_logs.txt" | sed -u 's/^/[WORKER-R3] /') 2>&1 &

echo "Started Realm 3 Worker"

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

# Dummy prover for Realm 0 (user 0)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1338 --user 0 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm0_user0_logs.txt" | sed -u 's/^/[DUMMY-R0-U0] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 0 (User 0)"

sleep 2

# Dummy prover for Realm 0 (user 1024)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1338 --user 1024 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm0_user1024_logs.txt" | sed -u 's/^/[DUMMY-R0-U1024] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 0 (User 1024)"

sleep 2

# Dummy prover for Realm 0 (user 2048)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1338 --user 2048 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm0_user2048_logs.txt" | sed -u 's/^/[DUMMY-R0-U2048] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 0 (User 2048)"

sleep 2

# Dummy prover for Realm 1 (user 524288)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1339 --user 524288 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm1_user524288_logs.txt" | sed -u 's/^/[DUMMY-R1-U524288] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 1 (User 524288)"

sleep 2

# Dummy prover for Realm 1 (user 525312)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1339 --user 525312 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm1_user525312_logs.txt" | sed -u 's/^/[DUMMY-R1-U525312] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 1 (User 525312)"

sleep 2

# Dummy prover for Realm 1 (user 526336)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1339 --user 526336 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm1_user526336_logs.txt" | sed -u 's/^/[DUMMY-R1-U526336] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 1 (User 526336)"

sleep 2

# Dummy prover for Realm 2 (user 262144)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1340 --user 262144 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm2_user262144_logs.txt" | sed -u 's/^/[DUMMY-R2-U262144] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 2 (User 262144)"

sleep 2

# Dummy prover for Realm 2 (user 263168)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1340 --user 263168 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm2_user263168_logs.txt" | sed -u 's/^/[DUMMY-R2-U263168] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 2 (User 263168)"

sleep 2

# Dummy prover for Realm 2 (user 264192)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1340 --user 264192 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm2_user264192_logs.txt" | sed -u 's/^/[DUMMY-R2-U264192] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 2 (User 264192)"

sleep 2

# Dummy prover for Realm 3 (user 786432)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1341 --user 786432 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm3_user786432_logs.txt" | sed -u 's/^/[DUMMY-R3-U786432] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 3 (User 786432)"

sleep 2

# Dummy prover for Realm 3 (user 787456)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1341 --user 787456 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm3_user787456_logs.txt" | sed -u 's/^/[DUMMY-R3-U787456] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 3 (User 787456)"

sleep 2

# Dummy prover for Realm 3 (user 788480)
RUST_LOG=psy_node_common=debug ${BIN_PREFIX}/psy_worker_cli dummy-end-cap-prover \
    --proving-backend $PROVING_BACKEND \
    --coordinator-url http://127.0.0.1:1337 \
    --url http://127.0.0.1:1341 --user 788480 --min-state-updates 1 --max-state-updates 2 --max-contract-calls 1 \
    > >(tee -a "$LOG_DIR/dummy_prover_realm3_user788480_logs.txt" | sed -u 's/^/[DUMMY-R3-U788480] /') 2>&1 &

echo "Started Dummy End Cap Prover for Realm 3 (User 788480)"

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
echo "  Realm 2 Processor"
echo "  Realm 2 Edge"
echo "  Realm 3 Processor"
echo "  Realm 3 Edge"
echo "  Dummy End Cap Provers (12 total):"
echo "    - Realm 0 (User 0)"
echo "    - Realm 0 (User 1024)"
echo "    - Realm 0 (User 2048)"
echo "    - Realm 1 (User 1048576)"
echo "    - Realm 1 (User 1049600)"
echo "    - Realm 1 (User 1050624)"
echo "    - Realm 2 (User 2097152)"
echo "    - Realm 2 (User 2098176)"
echo "    - Realm 2 (User 2099200)"
echo "    - Realm 3 (User 3145728)"
echo "    - Realm 3 (User 3146752)"
echo "    - Realm 3 (User 3147776)"
echo "  Coordinator Worker"
echo "  Realm 0 Worker"
echo "  Realm 1 Worker"
echo "  Realm 2 Worker"
echo "  Realm 3 Worker"
echo "-----------------------------------------------------"
echo "Logs are being saved to $LOG_DIR/"
echo "Press Ctrl+C to stop all services gracefully."
echo "-----------------------------------------------------"

# Wait allows the script to sit idle until a signal (Ctrl+C) is caught
wait
