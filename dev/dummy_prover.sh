#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipes will fail if any command in the pipe fails, not just the last one.
set -o pipefail

# --- Configuration ---
CLI_EXECUTABLE="./target/release/psy_worker_cli"
COORDINATOR_URL="http://127.0.0.1:1337"
WORKER_URL="http://127.0.0.1:1338"
LOG_DIR="./logs"
END_CAP_COUNT=1

# --- Helper Functions ---

# Function to print usage information
usage() {
  cat <<EOF
Usage: $0 <command> [options]

A script to run dummy provers for psy_worker_cli.

Commands:
  prove         Run a single dummy prover instance.
  prove_many    Run multiple dummy prover instances in parallel.

'prove' options:
  -u, --user-id <id>                 The user ID to run the prover for. (Required)
  -p, --proving-backend <backend>    The proving backend to use. (Required)

'prove_many' options:
  --start-user-id <id>             The starting user ID for the range. (Required)
  --end-user-id <id>               The ending user ID for the range (inclusive). (Required)
  -p, --proving-backend <backend>    The proving backend to use for all instances. (Required)

Available Proving Backends:
  - plonky2-poseidon-goldilocks
  - jtmb-poseidon-goldilocks
  - jtmb-sha256-u64

Example for 'prove':
  $0 prove -u 101 -p jtmb-poseidon-goldilocks

Example for 'prove_many':
  $0 prove_many --start-user-id 1 --end-user-id 5 -p plonky2-poseidon-goldilocks
EOF
  exit 1
}

# Function to validate the proving backend name
validate_backend() {
  local backend=$1
  case "$backend" in
    "plonky2-poseidon-goldilocks" | "jtmb-poseidon-goldilocks" | "jtmb-sha256-u64")
      # Valid backend, do nothing
      ;;
    *)
      echo "Error: Invalid proving backend '$backend'."
      echo "See '$0 --help' for available backends."
      exit 1
      ;;
  esac
}

# Function to run a single prover instance.
# This is the core command that will be executed.
run_single_prover() {
    local user_id=$1
    local proving_backend=$2
    local log_file="${LOG_DIR}/dummy_end_cap_prover_logs_${user_id}.txt"

    echo "Starting prover for USER_ID: ${user_id}. Logging to ${log_file}"

    # The command to execute
    # 2>&1 redirects stderr to stdout
    # tee splits the output to the specified log file AND to its own stdout (for the next pipe)
    "${CLI_EXECUTABLE}" dummy-end-cap-prover \
        --proving-backend "${proving_backend}" \
        --coordinator-url "${COORDINATOR_URL}" \
        --url "${WORKER_URL}" \
        --user "${user_id}" \
        --end-cap-count "${END_CAP_COUNT}" 2>&1 | tee "${log_file}"
}

# Function to run a prover and prefix its output for parallel execution
run_and_prefix_prover() {
    local user_id=$1
    local proving_backend=$2
    local log_file="${LOG_DIR}/dummy_end_cap_prover_logs_${user_id}.txt"

    # Execute the command, redirect stderr to stdout, and pipe it.
    # The first `tee` writes the raw, unprefixed output to the log file.
    # The `while` loop reads the output from `tee` line-by-line and prefixes it for console display.
    "${CLI_EXECUTABLE}" dummy-end-cap-prover \
        --proving-backend "${proving_backend}" \
        --coordinator-url "${COORDINATOR_URL}" \
        --url "${WORKER_URL}" \
        --user "${user_id}" \
        --end-cap-count "${END_CAP_COUNT}" 2>&1 | tee "${log_file}" | while IFS= read -r line; do
            echo "[USER_ID: ${user_id}] $line"
        done
}


# --- Main Logic ---

# Check if at least a subcommand is provided
if [[ $# -lt 1 ]]; then
  usage
fi

# Ensure the log directory exists
mkdir -p "$LOG_DIR"

# Get the subcommand
SUBCOMMAND=$1
shift # Consume the subcommand argument

case "$SUBCOMMAND" in
  prove)
    # --- Handle 'prove' subcommand ---
    USER_ID=""
    PROVING_BACKEND=""

    # Parse arguments for 'prove'
    while [[ $# -gt 0 ]]; do
      key="$1"
      case $key in
        -u|--user-id)
          USER_ID="$2"
          shift 2
          ;;
        -p|--proving-backend)
          PROVING_BACKEND="$2"
          shift 2
          ;;
        *)
          echo "Error: Unknown option '$1' for 'prove' command."
          usage
          ;;
      esac
    done

    # Validate arguments
    if [[ -z "$USER_ID" ]] || [[ -z "$PROVING_BACKEND" ]]; then
      echo "Error: Missing required arguments for 'prove' command."
      usage
    fi
    validate_backend "$PROVING_BACKEND"

    # Execute the single prover command
    run_single_prover "$USER_ID" "$PROVING_BACKEND"
    ;;

  prove_many)
    # --- Handle 'prove_many' subcommand ---
    START_USER_ID=""
    END_USER_ID=""
    PROVING_BACKEND=""

    # Parse arguments for 'prove_many'
    while [[ $# -gt 0 ]]; do
      key="$1"
      case $key in
        --start-user-id)
          START_USER_ID="$2"
          shift 2
          ;;
        --end-user-id)
          END_USER_ID="$2"
          shift 2
          ;;
        -p|--proving-backend)
          PROVING_BACKEND="$2"
          shift 2
          ;;
        *)
          echo "Error: Unknown option '$1' for 'prove_many' command."
          usage
          ;;
      esac
    done

    # Validate arguments
    if [[ -z "$START_USER_ID" ]] || [[ -z "$END_USER_ID" ]] || [[ -z "$PROVING_BACKEND" ]]; then
      echo "Error: Missing required arguments for 'prove_many' command."
      usage
    fi
    if ! [[ "$START_USER_ID" =~ ^[0-9]+$ ]] || ! [[ "$END_USER_ID" =~ ^[0-9]+$ ]]; then
        echo "Error: User IDs must be integers."
        exit 1
    fi
    if (( START_USER_ID > END_USER_ID )); then
        echo "Error: --start-user-id must be less than or equal to --end-user-id."
        exit 1
    fi
    validate_backend "$PROVING_BACKEND"

    # Execute provers in parallel
    echo "Starting provers for user IDs from ${START_USER_ID} to ${END_USER_ID} in parallel..."

    pids=()
    for (( i=START_USER_ID; i<=END_USER_ID; i++ )); do
      # Run the function in the background
      run_and_prefix_prover "$i" "$PROVING_BACKEND" &
      # Store the process ID of the background job
      pids+=($!)
    done

    # Wait for all background jobs to finish
    echo "All prover processes have been launched. Waiting for them to complete..."
    # The `wait` command without arguments waits for all child processes of the current shell to terminate.
    wait
    echo "All prover processes have finished."
    ;;
  --help|-h)
    usage
    ;;
  *)
    echo "Error: Unknown command '$SUBCOMMAND'"
    usage
    ;;
esac