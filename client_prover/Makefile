export SQLX_OFFLINE=true

# All builds now go through the root workspace
ROOT_DIR := $(shell cd .. && pwd)
PROFILE := release
BIN_DIR := $(ROOT_DIR)/target/$(PROFILE)
ROOT_CONFIG_PATH := $(CURDIR)/config.json
PRIVATE_KEYS_FILE ?= $(ROOT_DIR)/private_keys.json
CARGO := cd $(ROOT_DIR) && PSY_CONFIG_PATH=$(ROOT_CONFIG_PATH) cargo
USER_CLI := $(BIN_DIR)/psy_user_cli
LOG_LEVEL := psy_ups_circuit=trace,psy_dpn_circuit=trace,psy_user_cli=debug,psy_common_circuit=trace,psy_network_circuit=trace,psy_prover=trace,psy_client_data=trace,plonky2=error

BACKUP ?= false
ifeq ($(BACKUP),true)
	# configure backup credentials through the standard provider credential chain or environment variables
	export PSY_BACKUP_BUCKET=psy-backup
endif

default: build

.PHONY: \
	default build check fix fmt install clean help \
	run-prove-proxy get-public-key wallet random-wallet \
	register-user register-random-user register-sdc-user \
	deploy-contract get-deploy-contract-cmd multi-contract-call \
	mint mint-sdc \
	transfer claim return-back claim-rewards withdraw \
	get-slot-value \
	get-contract-leaf-data get-checkpoint-leaf-data get-contract-code-definition get-latest-block-state get-block-state \
	get-checkpoint-tree-root get-latest-checkpoint-tree-root get-checkpoint-tree-leaf-hash get-checkpoint-tree-merkle-proof \
	get-user-leaf-data-by-pubkey get-user-leaf-data-by-userid get-user-leaf-data \
	get-user-tree-root get-user-tree-leaf-hash get-user-tree-merkle-proof get-user-sub-tree-merkle-proof \
	get-user-registration-tree-root get-user-registration-tree-leaf-hash get-user-registration-tree-merkle-proof \
	get-user-contract-tree-root get-user-contract-state-tree-root get-user-contract-tree-merkle-proof get-user-contract-state-tree-merkle-proof \
	get-psy-sdc-fingerprint get-endcap-common-data generate-trace prove-trace

check:
	@$(CARGO) check --workspace --all-targets --tests --benches --examples --bins

fix:
	@cd $(ROOT_DIR) && cargo fix --all-targets --allow-dirty --allow-staged

build:
	@RUSTFLAGS="-A warnings" $(CARGO) build --profile $(PROFILE) --bin psy_user_cli

fmt:
	@cd $(ROOT_DIR) && cargo fmt

install:
	@cd $(ROOT_DIR) && cargo install --path client_prover/psy_cli/psy_user_cli --locked

clean:
	@cd $(ROOT_DIR) && rm -rf target

################################################################################
#                                   TMP                                        #
################################################################################
USER0_PRIVATE_KEY        := $(shell jq -r '.[0]' $(PRIVATE_KEYS_FILE))
USER0_PUBLIC_KEY         := cc92647d3a77819dec2f054a241d0863c9bd54cf5a1103ca560ed85ad59c460d
USER0_SECP_ZK_PUBLIC_KEY := 49deab842acf3d26236419d4fce1b2cb01081aef55d4ef0e566f980e3890cf2f
USER1_PRIVATE_KEY        := $(shell jq -r '.[1]' $(PRIVATE_KEYS_FILE))
USER1_PUBLIC_KEY         := cf62ae15751624548ad897c22fa1598ab82b7a2ad7de6e42c921d433efa10c91
USER1_SECP_ZK_PUBLIC_KEY := ac85e11f5c8a53241502c4519567aa3f02d30b1639fc49bb94c1d61335197e1a
USER2_PRIVATE_KEY        := $(shell jq -r '.[2]' $(PRIVATE_KEYS_FILE))
USER2_PUBLIC_KEY         := 7fe4d043d0d6ac7383800233d503e6f94797ab6733f57c24f93a31a1cb242b21
USER2_SECP_ZK_PUBLIC_KEY := 2b280f7354a6648e1d37499d211876d4f68d703c4dbf4dd8ccee032a4da5f220
USER3_PRIVATE_KEY        := $(shell jq -r '.[3]' $(PRIVATE_KEYS_FILE))
USER3_PUBLIC_KEY         := f79b7a821bb0a4e027b212c5534338617013e171d54e1131ab5f0a9dabebba82
USER3_SECP_ZK_PUBLIC_KEY := 1e44a84db33d52243068ccfbf6519beb1e072d1128ee792fe62896a3338db2a4

USER4_PRIVATE_KEY        := $(shell jq -r '.[4]' $(PRIVATE_KEYS_FILE))

CURRENT_USER_PRIVATE_KEY := ${USER0_PRIVATE_KEY}
CURRENT_USER_PUBLIC_KEY  := ${USER0_PUBLIC_KEY}

CHECKPOINT_ID            := 18446744073709551615
LEAF_CHECKPOINT_ID       := ${CHECKPOINT_ID}
USER_ID                  := 0
CONTRACT_ID              := 0
SLOT_ID                  := 0
CONTRACT_STATE_HEIGHT    := 32
REALM_ID                 := 0
REGISTRATION_ID          := 1
STRATEGY                 := 5
SIGN_TYPE                := zk

COORDINATOR_RPC_URL      := $(shell jq -r '.networks.localhost.coordinator_configs[].rpc_url[]' $(ROOT_CONFIG_PATH))
REALM_RPC_URL            := $(shell jq -r '.networks.localhost.realm_configs[${REALM_ID}].rpc_url[]' $(ROOT_CONFIG_PATH))

GLOBAL_USER_TREE_HEIGHT  := $(shell jq -r '.networks.localhost.global_user_tree_height' $(ROOT_CONFIG_PATH))
REALM_USER_TREE_HEIGHT   := $(shell jq -r '.networks.localhost.realm_user_tree_height' $(ROOT_CONFIG_PATH))
REALM_TREE_LEAF_LEVEL    := $(shell echo $$(($(GLOBAL_USER_TREE_HEIGHT) - $(REALM_USER_TREE_HEIGHT))))
USER1_ID                 := 1

SDC_PATH                 := "sdc.json"
SDC_FINGERPRINT          := "136ed39299c17a8cc4ea84e0b676e74c70d2a1668abaf346088d2df4087304c5"
SD_KEY_FINGERPRINT      := "38755910c4dfb3c9bef528a4af697edced7e2607a6b769d054c4985a7000f0eb"
TRACE_FILE               ?= trace.json
METHOD_NAME              ?= simple_transfer
TX_INPUTS                ?= [0, 11000000000]

WITHDRAW_DEST_CHAIN_ID   ?= 1
WITHDRAW_TOKEN_ADDRESS   ?= 0x0000000000000000000000001111111111111111111111111111111111111111
WITHDRAW_RECIPIENT       ?= 0x0000000000000000000000002222222222222222222222222222222222222222
WITHDRAW_AMOUNT          ?= 1
WITHDRAW_NONCE           ?= 1

run-prove-proxy:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) prove-proxy --rpc-config $(ROOT_CONFIG_PATH)

get-public-key:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) wallet info --private-key=${CURRENT_USER_PRIVATE_KEY} --sign-type ${SIGN_TYPE}

wallet:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) wallet create

random-wallet:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) wallet random --sign-type ${SIGN_TYPE}

register-user:
	@echo "Registering all 4 users..."
	@RUST_LOG=error $(USER_CLI) register-user --private-key=${USER0_PRIVATE_KEY} --sign-type zk | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error $(USER_CLI) register-user --private-key=${USER1_PRIVATE_KEY} --sign-type zk | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error $(USER_CLI) register-user --private-key=${USER2_PRIVATE_KEY} --sign-type zk | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error $(USER_CLI) register-user --private-key=${USER0_PRIVATE_KEY} --sign-type secp256k1 | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error $(USER_CLI) register-user --private-key=${USER1_PRIVATE_KEY} --sign-type secp256k1 | tail -5 | jq .
	@sleep 0.5
	@RUST_LOG=error $(USER_CLI) register-user --private-key=${USER2_PRIVATE_KEY} --sign-type secp256k1 | tail -5 | jq .
	@echo "Waiting 6s for users to be registered..."
	@sleep 6

register-random-user:
	@echo "Registering random users..."
	@RUST_LOG=error $(USER_CLI) register-user | tail -6 | jq .
	@sleep 0.5
	@RUST_LOG=error $(USER_CLI) register-user | tail -6 | jq .
	@sleep 0.5

deploy-contract:
	@echo "Deploying contracts..."
	@echo "USER0 deploying token contract..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) deploy-contract --private-key=${USER0_PRIVATE_KEY} --contract-path ${PWD}/token.json --is-deploy
	@echo "USER1 deploying token contract..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) deploy-contract --private-key=${USER1_PRIVATE_KEY} --contract-path ${PWD}/token.json --is-deploy

get-deploy-contract-cmd:
	@echo "Deploying contracts..."
	@echo "USER0 deploying token contract..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) deploy-contract --private-key=${USER0_PRIVATE_KEY} --contract-path ${PWD}/token.json --output-path ./genesis_contracts.json
	@echo "USER1 deploying token contract..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) deploy-contract --private-key=${USER1_PRIVATE_KEY} --contract-path ${PWD}/token.json --output-path ./genesis_contracts.json

multi-contract-call:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID}

mint:
	@echo "All users minting 1000 tokens..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]"

transfer:
	@echo "USER0 transferring 250 to USER1..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[1, 250000000000]" --sign-type $(SIGN_TYPE)
	@echo "USER1 transferring 250 to USER0..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER1_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[0, 250000000000]" --sign-type $(SIGN_TYPE)

claim:
	@echo "USER1 claiming transfer..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER1_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_claim --inputs "[0]" --sign-type $(SIGN_TYPE)
	@echo "USER0 claiming transfer..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_claim --inputs "[$(USER1_ID)]" --sign-type $(SIGN_TYPE)

return-back:
	@echo "USER1 transferring back to USER0..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER1_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[0, 250000000000]" --sign-type $(SIGN_TYPE)
	@echo "USER0 transferring back to USER1..."
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_transfer --inputs "[$(USER1_ID), 250000000000]" --sign-type $(SIGN_TYPE)

claim-rewards:
	@RUST_LOG=info $(USER_CLI) claim-rewards --private-key ${USER0_PRIVATE_KEY} --jobs-file $(ROOT_DIR)/local_checkpoints/realm_worker_0.backup

withdraw:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) withdraw \
		-p ${CURRENT_USER_PRIVATE_KEY} \
		--destination-chain-id ${WITHDRAW_DEST_CHAIN_ID} \
		--token-address ${WITHDRAW_TOKEN_ADDRESS} \
		--amount ${WITHDRAW_AMOUNT} \
		--recipient ${WITHDRAW_RECIPIENT} \
		--nonce ${WITHDRAW_NONCE} \
		--sign-type ${SIGN_TYPE}

# Unified RPC commands using psy_user_cli automatic routing
get-slot-value:
	@RUST_LOG=error $(USER_CLI) get-user-contract-state-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID} --height ${CONTRACT_STATE_HEIGHT} --leaf-id ${SLOT_ID} | jq '.value' | tr -d '"'

# Metadata RPC commands
get-contract-leaf-data:
	@$(USER_CLI) get-contract-leaf-data --contract-id ${CONTRACT_ID}

get-checkpoint-leaf-data:
	@$(USER_CLI) get-checkpoint-leaf-data --checkpoint-id ${CHECKPOINT_ID}

get-contract-code-definition:
	@$(USER_CLI) get-contract-code-definition --contract-id ${CONTRACT_ID}

get-latest-block-state:
	@$(USER_CLI) get-latest-block-state

get-block-state:
	@$(USER_CLI) get-block-state --checkpoint-id ${CHECKPOINT_ID}

# Tree structure RPC commands
get-checkpoint-tree-root:
	@$(USER_CLI) get-checkpoint-tree-root --checkpoint-id ${CHECKPOINT_ID}

get-latest-checkpoint-tree-root:
	@$(USER_CLI) get-latest-checkpoint-tree-root

get-checkpoint-tree-leaf-hash:
	@$(USER_CLI) get-checkpoint-tree-leaf-hash --checkpoint-id ${CHECKPOINT_ID} --leaf-checkpoint-id ${LEAF_CHECKPOINT_ID}

get-checkpoint-tree-merkle-proof:
	@$(USER_CLI) get-checkpoint-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --leaf-checkpoint-id ${LEAF_CHECKPOINT_ID}

# User tree RPC commands
get-user-leaf-data-by-pubkey:
	@$(USER_CLI) get-user-leaf --checkpoint-id ${CHECKPOINT_ID} --pub-key ${CURRENT_USER_PUBLIC_KEY}

get-user-leaf-data-by-userid:
	@$(USER_CLI) get-user-leaf --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-leaf-data: get-user-leaf-data-by-pubkey

get-user-tree-root:
	@$(USER_CLI) get-user-tree-root --checkpoint-id ${CHECKPOINT_ID}

get-user-tree-leaf-hash:
	@$(USER_CLI) get-user-tree-leaf-hash --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-tree-merkle-proof:
	@$(USER_CLI) get-user-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-sub-tree-merkle-proof:
	@$(USER_CLI) get-user-sub-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --root-level 0 --leaf-level ${REALM_TREE_LEAF_LEVEL} --leaf-index ${REALM_ID}

get-user-registration-tree-root:
	@$(USER_CLI) get-user-registration-tree-root --checkpoint-id ${CHECKPOINT_ID}

get-user-registration-tree-leaf-hash:
	@$(USER_CLI) get-user-registration-tree-leaf-hash --checkpoint-id ${CHECKPOINT_ID} --registration-id ${REGISTRATION_ID}

get-user-registration-tree-merkle-proof:
	@$(USER_CLI) get-user-registration-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --registration-id ${REGISTRATION_ID}

# User contract tree RPC commands
get-user-contract-tree-root:
	@$(USER_CLI) get-user-contract-tree-root --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID}

get-user-contract-state-tree-root:
	@$(USER_CLI) get-user-contract-state-tree-root --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID}

get-user-contract-tree-merkle-proof:
	@$(USER_CLI) get-user-contract-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID}

get-user-contract-state-tree-merkle-proof:
	@$(USER_CLI) get-user-contract-state-tree-merkle-proof --checkpoint-id ${CHECKPOINT_ID} --user-id ${USER_ID} --contract-id ${CONTRACT_ID} --height ${CONTRACT_STATE_HEIGHT} --leaf-id ${SLOT_ID}

get-psy-sdc-fingerprint:
	@$(USER_CLI) get-psy-sdc-fingerprint --sdc-path ${SDC_PATH}

register-sdc-user:
	@$(USER_CLI) register-user --private-key ${USER0_PRIVATE_KEY} --fingerprint ${SDC_FINGERPRINT} --sign-type "software-defined-dpn"

mint-sdc:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_mint --inputs "[1000000000000]" --sign-type "software-defined-dpn" --fingerprint ${SDC_FINGERPRINT}

get-endcap-common-data:
	@$(USER_CLI) get-user-end-cap-common-data

get-sd-key-fingerprint:
	@RUST_LOG=$${RUST_LOG:-info} $(USER_CLI) wallet sd-key-fingerprint \
		--allowed-contract-id 5 \
		--allowed-contract-id 0 \
		--allowed-contract-id 0 \
    	--allowed-method-id 3375543263 \
		--allowed-method-id 354447671 \
		--allowed-method-id 2923993647 \
		--expected-tx-count 3

make register-sd-key-user:
	@RUST_LOG=$${RUST_LOG:-info} $(USER_CLI) register-user \
		--sign-type sd-key \
		-p $(USER4_PRIVATE_KEY) \
		--fingerprint $(SD_KEY_FINGERPRINT)

faucet:
	@RUST_LOG=$${RUST_LOG:-info} $(USER_CLI) call \
    	--sign-type sd-key \
    	--private-key $(USER4_PRIVATE_KEY) \
    	--fingerprint $(SD_KEY_FINGERPRINT) \
    	--sd-key-allowed-contract-id 5 \
		--sd-key-allowed-contract-id 0 \
		--sd-key-allowed-contract-id 0 \
    	--sd-key-allowed-method-id 3375543263 \
		--sd-key-allowed-method-id 354447671 \
		--sd-key-allowed-method-id 2923993647 \
    	--sd-key-expected-tx-count 3 \
    	--contract-id 5 \
    	--method-name faucet \
    	--inputs '[0, 666000000000]'

error-faucet:
	@RUST_LOG=$${RUST_LOG:-info} $(USER_CLI) call \
    	--sign-type sd-key \
    	--private-key $(USER4_PRIVATE_KEY) \
    	--fingerprint $(SD_KEY_FINGERPRINT) \
    	--sd-key-allowed-contract-id 5 \
		--sd-key-allowed-contract-id 0 \
		--sd-key-allowed-contract-id 0 \
    	--sd-key-allowed-method-id 3375543263 \
		--sd-key-allowed-method-id 354447671 \
		--sd-key-allowed-method-id 2923993647 \
    	--sd-key-expected-tx-count 3 \
    	--contract-id 0 \
    	--method-name simple_transfer \
    	--inputs '[0, 666000000000]' \
		--contract-id 0 \
    	--method-name simple_transfer \
    	--inputs '[0, 334000000000]' 

claim-faucet:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) call -p ${USER0_PRIVATE_KEY} --contract-id ${CONTRACT_ID} --method-name simple_claim --inputs "[262144]" --sign-type $(SIGN_TYPE)

################################################################################
#                          Trace generation & proving                           #
################################################################################
# Variables (override on command line):
#   TRACE_FILE   — path to trace JSON          (default: trace.json)
#   CONTRACT_ID  — contract to call            (default: 0)
#   METHOD_NAME  — method to call              (default: simple_mint)
#   TX_INPUTS    — JSON array of u64 inputs    (default: [1000000000000])
#
# Multicall example (two CFC steps):
#   make generate-trace \
#     CONTRACT_ID="0 --contract-id 0" \
#     METHOD_NAME="simple_mint --method-name simple_transfer" \
#     TX_INPUTS="[1000000000000] --inputs [1,250000000000]"

# Generate an unproved trace from a contract call.
generate-trace:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) generate-tx-trace \
		--private-key ${CURRENT_USER_PRIVATE_KEY} \
		--sign-type ${SIGN_TYPE} \
		--contract-id ${CONTRACT_ID} \
		--method-name ${METHOD_NAME} \
		--inputs '${TX_INPUTS}' \
		--output ${TRACE_FILE}

# Prove a trace using the default graph path.
prove-trace:
	@RUST_LOG=${LOG_LEVEL} $(USER_CLI) prove-tx-trace \
		--private-key ${CURRENT_USER_PRIVATE_KEY} \
		--sign-type ${SIGN_TYPE} \
		--input ${TRACE_FILE}

help:
	@grep -E '^[a-zA-Z_-]+:.*?' $(lastword $(MAKEFILE_LIST)) | cut -d: -f1 | sort
