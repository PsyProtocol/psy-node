# Makefile for Psy project

.PHONY: all build clean test deploy-contracts register-users query-chain-info run-all

all: build

build:
	cargo build --release --examples

clean:
	cargo clean

test:
	cargo test

deploy-contracts:
	./target/release/examples/deploy_contracts

register-users:
	./target/release/examples/register_user

query-chain-info:
	./target/release/examples/query_chain_info

all: build

run-all:
	./run_all.sh
