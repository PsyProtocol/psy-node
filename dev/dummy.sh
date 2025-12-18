#!/bin/bash

# --- Default Options ---
COORDINATOR_API_URL="http://127.0.0.1:1337"
PROVING_BACKEND="jtmb-poseidon-goldilocks"
REALM_API_HOSTNAME="127.0.0.1"
REALM_API_START_PORT=13370
REALM_EDGE_NODES=4
MIN_STATE_UPDATES=1
MAX_STATE_UPDATES=2
NETWORK="local-devnet"
MAX_CONTRACT_CALLS=1
GROUP_SIZE=100
DUMMY_GROUPS=1

show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --coordinator-api-url VAL    (Default: $COORDINATOR_API_URL)"
    echo "  --proving-backend VAL        (Default: $PROVING_BACKEND)"
    echo "  --realm-api-hostname VAL     (Default: $REALM_API_HOSTNAME)"
    echo "  --realm-api-start-port VAL   (Default: $REALM_API_START_PORT)"
    echo "  --realm-edge-nodes VAL       (Default: $REALM_EDGE_NODES)"
    echo "  --min-state-updates VAL      (Default: $MIN_STATE_UPDATES)"
    echo "  --max-state-updates VAL      (Default: $MAX_STATE_UPDATES)"
    echo "  --network VAL                (Default: $NETWORK)"
    echo "  --max-contract-calls VAL     (Default: $MAX_CONTRACT_CALLS)"
    echo "  --group-size VAL             (Default: $GROUP_SIZE)"
    echo "  --groups VAL                 (Default: $DUMMY_GROUPS)"
    echo "  -h, --help                   Show this help message"
    echo ""
    exit 0
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --coordinator-api-url) COORDINATOR_API_URL="$2"; shift 2 ;;
        --proving-backend)     PROVING_BACKEND="$2"; shift 2 ;;
        --realm-api-hostname)  REALM_API_HOSTNAME="$2"; shift 2 ;;
        --realm-api-start-port)REALM_API_START_PORT="$2"; shift 2 ;;
        --realm-edge-nodes)    REALM_EDGE_NODES="$2"; shift 2 ;;
        --min-state-updates)   MIN_STATE_UPDATES="$2"; shift 2 ;;
        --max-state-updates)   MAX_STATE_UPDATES="$2"; shift 2 ;;
        --network)             NETWORK="$2"; shift 2 ;;
        --max-contract-calls)  MAX_CONTRACT_CALLS="$2"; shift 2 ;;
        --group-size)          GROUP_SIZE="$2"; shift 2 ;;
        --groups)              DUMMY_GROUPS="$2"; shift 2 ;;
        -h|--help)             show_help ;;
        *)                     echo "Unknown option: $1"; show_help ;;
    esac
done

echo "Starting $DUMMY_GROUPS groups of dummy-end-cap-provers..."

# --- Execution Loop ---
pids=()

for (( i=0; i<$DUMMY_GROUPS; i++ )); do
    # Calculate values for this group
    START_USER_ID=$(( i * GROUP_SIZE ))
    END_USER_ID=$(( START_USER_ID + GROUP_SIZE - 1 ))
    
    # Port wraps around based on edge nodes
    PORT_OFFSET=$(( i % REALM_EDGE_NODES ))
    CURRENT_PORT=$(( REALM_API_START_PORT + PORT_OFFSET ))
    
    REALM_URL="http://${REALM_API_HOSTNAME}:${CURRENT_PORT}"
    PREFIX="USERS ${START_USER_ID}-${END_USER_ID}"

    # Construct the command
    ./target/release/psy_worker_cli dummy-end-cap-prover-lite \
        --proving-backend "$PROVING_BACKEND" \
        --coordinator-url "$COORDINATOR_API_URL" \
        --url "$REALM_URL" \
        --min-state-updates "$MIN_STATE_UPDATES" \
        --max-state-updates "$MAX_STATE_UPDATES" \
        --batches 1 \
        --network "$NETWORK" \
        --max-contract-calls "$MAX_CONTRACT_CALLS" \
        --count "$GROUP_SIZE" \
        --start-user-id "$START_USER_ID" 2>&1 | sed "s/^/[$PREFIX] /" &
    
    pids+=($!)
done

# Trap Ctrl+C to kill all background processes
trap "kill ${pids[@]} 2>/dev/null; exit" SIGINT SIGTERM

# Wait for all processes to finish
wait "${pids[@]}"