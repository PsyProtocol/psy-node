#!/bin/bash
BASH_FILE_ME=${BASH_SOURCE[0]}

# Ensure logs directory exists
mkdir -p logs

build_if_needed() {
    # if -c flag is passed, run config_gen_v2 and build
    if [ "$1" = "-b" ]; then
        echo "Building project..."
        cargo build --release
        if [ $? -ne 0 ]; then
            echo "Build failed"
            exit 1
        fi
    fi
    # if -c flag is passed, run config_gen_v2 and build
    if [ "$1" = "-g" ]; then
        echo "Building project..."
        cargo build --release
        rm -rf ./local_checkpoints/coordinator_0_0
        if [ $? -ne 0 ]; then
            echo "Build failed"
            exit 1
        fi
    fi
    if [ "$1" = "-c" ]; then
        echo "Running config gen and building the project..."
        cargo run --release --package psy_plonky2_circuits --example config_gen_v2
        cargo build --release
        if [ $? -ne 0 ]; then
            echo "Build failed"
            exit 1
        fi
    fi
}
build_if_needed_realm() {
    # if -c flag is passed, run config_gen_v2 and build
    if [ "$1" = "-b" ]; then
        echo "Building project..."
        cargo build --release
        if [ $? -ne 0 ]; then
            echo "Build failed"
            exit 1
        fi
    fi
    # if -c flag is passed, run config_gen_v2 and build
    if [ "$1" = "-g" ]; then
        echo "Building project..."
        cargo build --release
        rm -rf ./local_checkpoints/realm_0_1
        if [ $? -ne 0 ]; then
            echo "Build failed"
            exit 1
        fi
    fi
    if [ "$1" = "-c" ]; then
        echo "Running config gen and building the project..."
        cargo run --release --package psy_plonky2_circuits --example config_gen_v2
        cargo build --release
        if [ $? -ne 0 ]; then
            echo "Build failed"
            exit 1
        fi
    fi
}

start_processor() {
    build_if_needed $1
    # 2>&1 redirects stderr to stdout so errors are captured too
    # | tee writes to the file AND displays to console
    ./target/release/psy_node_cli start-coordinator-processor --config ./psy_cli/example_node_configs/coordinator_processor_1.yaml 2>&1 | tee logs/coordinator_processor_1_logs.txt
}

start_edge() {
    build_if_needed $1
    ./target/release/psy_node_cli start-coordinator-edge --config ./psy_cli/example_node_configs/coordinator_edge_1.yaml 2>&1 | tee logs/coordinator_edge_1_logs.txt
}

start_realm_edge() {
    build_if_needed_realm $1
    ./target/release/psy_node_cli start-realm-edge --config ./psy_cli/example_node_configs/realm_edge_1.yaml 2>&1 | tee logs/realm_edge_1_logs.txt
}

start_realm_processor() {
    build_if_needed_realm $1
    # 2>&1 redirects stderr to stdout so errors are captured too
    # | tee writes to the file AND displays to console
    ./target/release/psy_node_cli start-realm-processor --config ./psy_cli/example_node_configs/realm_processor_1.yaml 2>&1 | tee logs/realm_processor_1_logs.txt
}

start_worker() {
    build_if_needed $1
    ./target/release/psy_worker_cli worker --user 0 --network local-devnet --config ./psy_cli/example_node_configs/worker_1.yml 2>&1 | tee logs/worker_1_logs.txt
}
start_worker_realm() {
    build_if_needed_realm $1
    ./target/release/psy_worker_cli worker --user 0 --network local-devnet --config ./psy_cli/example_node_configs/worker_realm_1.yml 2>&1 | tee logs/worker_realm_1_logs.txt
}
start_dummy_prover() {
    build_if_needed $1
    ./target/release/psy_worker_cli dummy-prover --user 0 --network local-devnet --config ./psy_cli/example_node_configs/dummy_prover_1.yml 2>&1 | tee logs/dummy_prover_1_logs.txt
}
sub_worker() {
    start_worker $1
}
sub_w() {
    start_worker $1
}

sub_realm_worker() {
    start_worker_realm $1
}
sub_rw() {
    start_worker_realm $1
}

sub_e() {
    start_edge $1
}
sub_edge() {
    start_edge $1
}

sub_processor() {
  start_processor $1
}
sub_p() {
  start_processor $1
}


sub_re() {
    start_realm_edge $1
}
sub_realm_edge() {
    start_realm_edge $1
}

sub_realm_processor() {
  start_realm_processor $1
}
sub_rp() {
  start_realm_processor $1
}

sub_dummy_prover() {
    ./target/release/psy_worker_cli dummy-end-cap-prover --url http://127.0.0.1:1338 --user 0 > logs/dummy_end_cap_prover_logs.txt 2>&1 & | tee logs/dummy_end_cap_prover_logs.txt
}
sub_help() {
    echo "Usage: $BASH_FILE_ME <subcommand> [options]"
    echo ""
    echo "Subcommands:"
    echo "  processor, p       Start the coordinator processor"
    echo "  edge, e            Start the coordinator edge"
    echo "  worker, w          Start the worker"
    echo ""
    echo "Options:"
    echo "  -b                 Build before starting"
    echo "  -c                 Run config_gen_v2 and build before starting"
    echo ""
    echo "Examples:"
    echo "  $BASH_FILE_ME [realm_processor|realm_edge|processor|edge|worker|realm_worker] -b   # Build and start"
    echo "  $BASH_FILE_ME [realm_processor|realm_edge|processor|edge|worker|realm_worker] -c   # Run config_gen_v2 and build before starting"
    echo "  $BASH_FILE_ME realm_edge           # Start the realm edge"
    echo "  $BASH_FILE_ME realm_processor      # Start the realm processor"
    echo "  $BASH_FILE_ME edge           # Start the edge"
    echo "  $BASH_FILE_ME worker         # Start the coordinator worker"
    echo "  $BASH_FILE_ME realm_worker   # Start the realm worker"
    echo "  $BASH_FILE_ME processor      # Start the processor"
}
subcommand=$1
case $subcommand in
    "" | "-h" | "--help")
        sub_help
        ;;
    *)
        shift
        sub_${subcommand} $@
        if [ $? = 127 ]; then
            echo "Error: '$subcommand' is not a known subcommand." >&2
            echo "       Run '$ProgName --help' for a list of known subcommands." >&2
            exit 1
        fi
        ;;
esac