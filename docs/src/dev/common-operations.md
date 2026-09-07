# Common Operations

> Repository-only operations manual. Wallet, registration, funding, query, and contract procedures are owned here; bridge procedures are in `docs/src/dev/bridge-common-operations.md`.

## Abstract

Executable local-devnet procedures for wallet creation, account registration (zk and secp256k1), identity and state queries, contract deployment and update, and per-user contract-state reads. Run every command from `<repo-root>` with the release binary `./target/release/psy_user_cli`. Replace only angle-bracket values. Never place a real private key in this document, a result file, or a shared shell history.

Related: `docs/src/dev/devnet_lifecycle.md` for startup and shutdown; `docs/src/dev/private-transfer.md` for private transfers.

## Table of Contents

- [1. Conventions](#1-conventions)
- [2. Wallet Lifecycle](#2-wallet-lifecycle)
- [3. Register an Account](#3-register-an-account)
- [4. Query Public Key and User ID](#4-query-public-key-and-user-id)
- [5. Query the User Leaf](#5-query-the-user-leaf)
- [5.1. Fund PSY Through the Faucet](#51-fund-psy-through-the-faucet)
- [6. Deploy a Contract](#6-deploy-a-contract)
- [7. Update a Contract](#7-update-a-contract)
- [8. Query Contract Identity and Code](#8-query-contract-identity-and-code)
- [9. Query User State Inside a Contract](#9-query-user-state-inside-a-contract)
- [10. Call and Simulate Methods](#10-call-and-simulate-methods)
- [11. Exact Failure Responses](#11-exact-failure-responses)
- [12. References](#12-references)

## 1. Conventions

- `RPC_CONFIG` is the network config, normally `psy-genesis/config.json`.
- Every command accepts the global `--result-file <PATH>`; the file is atomically published only on success and contains secret-free results (`client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs:47-54`, `client_prover/psy_cli/psy_user_cli/src/result.rs:299-372`).
- For a latest-state user-leaf read, explicitly pass `--checkpoint-id 999999`. Historical reads use an exact checkpoint ID; do not rely on the user-leaf command's default of `100` (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:146-155`). Tree-query examples below require an explicit checkpoint ID; choose one committed snapshot for related proofs.
- Sign types: `zk` (default), `secp256k1`, `eth-personal-secp256k1`, `software-defined-dpn`, `software-defined-plonky2`, `sd-key`.
- Create `<result-dir>` with `mkdir -p <result-dir>` before using `--result-file`; its parent directory must already exist (`client_prover/psy_cli/psy_user_cli/src/result.rs:347-358`).

## 2. Wallet Lifecycle

```bash
# Create an encrypted keystore wallet
./target/release/psy_user_cli wallet create --output <wallet-path> --password '<password>'

# Generate a random ephemeral wallet and print its keys to stdout
./target/release/psy_user_cli wallet random

# Load a keystore and print its address/public key
./target/release/psy_user_cli wallet load --keystore-path <wallet-path> --wallet-password '<password>'

# Show the key material derived from a private key for a sign type
./target/release/psy_user_cli wallet info --sign-type zk -p '<private-key>'
./target/release/psy_user_cli wallet info --sign-type secp256k1 -p '<private-key>'
```

`wallet info --sign-type zk` prints `fingerprint`, `public_key_param`, and `public_key` (the 32-byte public-key hash used as the on-chain identity). Wallet command definitions: `client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:7-53`. Wallet output can expose key material; keep it out of shared logs.

## 3. Register an Account

Registration submits a coordinator registration request; wait for an assigned user ID before submitting account operations (`client_prover/psy_cli/psy_user_cli/src/subcommand/register_user.rs:25-46`).

```bash
./target/release/psy_user_cli \
  --result-file <result-dir>/register-user.json \
  register-user \
  --sign-type zk \
  -p '<private-key>' \
  --rpc-config psy-genesis/config.json
```

For a secp256k1 identity use `--sign-type secp256k1` (or `eth-personal-secp256k1`). The command returns `pending` for a new registration and `registered` when the key already exists (`client_prover/psy_cli/psy_user_cli/src/subcommand/register_user.rs:15-46`). Obtain the public-key hash from the registration result's `public_key_hash` field.

Poll for the assigned ID (registration inclusion usually lands within a few checkpoints):

```bash
for attempt in $(seq 1 60); do
  ./target/release/psy_user_cli \
    --result-file <result-dir>/get-user-id.json \
    get-user-id --pub-key '<public-key-hash>' --rpc-config psy-genesis/config.json
  USER_ID="$(jq -r '.user_id // empty' <result-dir>/get-user-id.json)"
  test -n "$USER_ID" && break
  sleep 2
done
test -n "${USER_ID:-}"
```

## 4. Query Public Key and User ID

```bash
# Resolve user IDs from a public key hash (coordinator path)
./target/release/psy_user_cli get-user-id --pub-key '<public-key-hash>' --rpc-config psy-genesis/config.json
```

## 5. Query the User Leaf

The user leaf carries the native fee `balance`, `nonce`, `last_checkpoint_id`, and `event_index`. Token balances of contract 0 (PSY) are **not** this field; they live in the user's contract-0 state tree (Section 9).

```bash
./target/release/psy_user_cli get-user-leaf \
  --user-id '<user-id>' --checkpoint-id 999999 --rpc-config psy-genesis/config.json
# or resolve through the coordinator:
./target/release/psy_user_cli get-user-leaf \
  --pub-key '<public-key-hash>' --rpc-config psy-genesis/config.json
```

For a historical read, replace `999999` with the exact checkpoint ID.

### 5.1. Fund PSY Through the Faucet

Do not call `simple_mint` on genesis contract 0: its deployer is the compiler's `DEFAULT_DEPLOYER`, not a local devnet wallet (`psy-compiler/psy-dargo-cli/examples/gen_deploy_json.rs:29-30`). Use the faucet operator's transfer and then claim it into the registered user's contract-0 balance.

The local faucet listens on port `9998` (`dev/locSetupV4.ts:4676-4678`). Its public configuration returns the amount, checkpoint window, and operator user IDs; the local genesis configuration uses `1000000000000` per claim and a 120-checkpoint window. Operators are genesis `sd-key` users, not keys to copy into this runbook. Request and response fields, operator validation, and remote method names are defined in `client_prover/psy_prover/src/local/native/faucet.rs:19-49,196-197,212-241,482-488`.

```bash
mkdir -p <result-dir>
curl -fsS -X POST http://127.0.0.1:9998 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_psy_faucet_config","params":[]}'

curl -fsS -X POST http://127.0.0.1:9998 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"psy_claim_faucet","params":{"input":{"recipient_user_id":<user-id>,"recipient_public_key":"<public-key-hash>"}}}' \
  > <result-dir>/faucet.json
jq -e '.error == null and (.result.operator_user_id != null)' <result-dir>/faucet.json
OPERATOR_USER_ID="$(jq -r '.result.operator_user_id' <result-dir>/faucet.json)"

./target/release/psy_user_cli \
  --result-file <result-dir>/claim-psy.json \
  call --sign-type zk -p '<private-key>' \
  --rpc-config psy-genesis/config.json \
  --contract-id 0 --method-name simple_claim \
  --inputs "[$OPERATOR_USER_ID]" --wait-until-confirmation
jq -e '.status == "confirmed" and (.confirmed_checkpoint != null)' <result-dir>/claim-psy.json
```

The faucet response identifies the submitting operator; use that `operator_user_id`, not the recipient user ID, as the `simple_claim` input. Wait for the operator transfer to be included before claiming. If the claim finds no transfer yet, inspect the returned `tx_hash` and wait for inclusion rather than requesting another transfer. Confirm the PSY token balance using the contract-0, leaf-0 query in Section 9 before starting a bridge or private-transfer operation. Keep all recipient calls serial: funding must return `confirmed` before the next call starts.

The recipient claim reads the operator's cumulative transfer amount and credits the unclaimed difference (`psy-compiler/psy-precompiles/token/src/main.psy:444-465`).

## 6. Deploy a Contract

```bash
./target/release/psy_user_cli \
  --result-file <result-dir>/deploy.json \
  deploy-contract \
  -p '<private-key>' \
  --contract-path <compiled-contract.json> \
  --rpc-config psy-genesis/config.json
```

`compile-and-deploy` compiles a `.psy.rs` source and deploys in one step. The deployer identity stored on-chain is the caller's public-key hash; `only deployer can mint`-style guards compare against it (token precompile guard: `psy-compiler/psy-precompiles/token/src/main.psy:397-399`). Genesis contracts 0-5 are owned by the compiler's `DEFAULT_DEPLOYER` constant, which no local devnet key holds — genesis-owned methods such as `simple_mint` cannot be called by a normal devnet wallet (`psy-compiler/psy-dargo-cli/examples/gen_deploy_json.rs:24-30`).

## 7. Update a Contract

Only the original deployer can update a contract; the state-tree height is immutable (`psy_node_common/src/coordinator/edge/handler.rs:532-558`).

```bash
./target/release/psy_user_cli \
  --result-file <result-dir>/update.json \
  update-contract \
  --private-key '<private-key>' \
  --contract-id '<contract-id>' \
  --contract-path <compiled-contract.json> \
  --rpc-config psy-genesis/config.json
```

Pass `--old-abi-path` and `--new-abi-path` when the update changes the ABI layout. If omitted, the new ABI is read from the compilation artifact and the old ABI is assumed to match it (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:79-105`).

## 8. Query Contract Identity and Code

```bash
# Contract leaf: deployer, function tree root, state tree height
./target/release/psy_user_cli get-contract-leaf-data --contract-id '<contract-id>' --rpc-config psy-genesis/config.json

# Code definition and method ids
./target/release/psy_user_cli get-contract-code-definition --contract-id '<contract-id>' --rpc-config psy-genesis/config.json

# Contract tree membership proofs
./target/release/psy_user_cli get-contract-tree-root --checkpoint-id '<checkpoint-id>' --rpc-config psy-genesis/config.json
./target/release/psy_user_cli get-contract-tree-leaf-hash --checkpoint-id '<checkpoint-id>' --contract-id '<contract-id>' --rpc-config psy-genesis/config.json
./target/release/psy_user_cli get-contract-tree-merkle-proof --checkpoint-id '<checkpoint-id>' --contract-id '<contract-id>' --rpc-config psy-genesis/config.json
```

A deployed contract's ID is returned by `deploy-contract` in its result file; contract IDs 0-5 are the genesis contracts (token, mining_rewards, deposit_tree, withdrawal_tree, usdt_token, faucet, in deployment order — `psy-compiler/Makefile:229-236`).

## 9. Query User State Inside a Contract

Each user keeps a per-contract state tree. For contract 0, query `get-user-contract-state-tree-leaf-hash --leaf-id 0`; its value limb is the PSY token balance. This is separate from the user-leaf fee `balance`.

```bash
# State-tree root for (user, contract)
./target/release/psy_user_cli get-user-contract-state-tree-root \
  --user-id '<user-id>' --contract-id '<contract-id>' --checkpoint-id 999999 \
  --rpc-config psy-genesis/config.json

# Leaf hash at a tree position
./target/release/psy_user_cli get-user-contract-state-tree-leaf-hash \
  --user-id '<user-id>' --contract-id '<contract-id>' --leaf-id '<leaf-id>' \
  --checkpoint-id 999999 --rpc-config psy-genesis/config.json

# Storage IMT preimage (decoded field values)
./target/release/psy_user_cli get-user-contract-state-imt-leaf-preimage \
  --user-id '<user-id>' --contract-id '<contract-id>' --leaf-index '<leaf-index>' \
  --checkpoint-id 999999 --rpc-config psy-genesis/config.json

# Merkle proof for a state leaf
./target/release/psy_user_cli get-user-contract-state-tree-merkle-proof \
  --user-id '<user-id>' --contract-id '<contract-id>' --leaf-id '<leaf-id>' \
  --checkpoint-id 999999 --rpc-config psy-genesis/config.json
```

Verified behavior: a user with no storage record at an index fails `get-user-contract-state-imt-leaf-preimage` with `Leaf preimage not found at index <n>`; that is the empty-state signal, not a transport error.

## 10. Call and Simulate Methods

```bash
# State-changing call; produces a real EndCap and waits for inclusion
./target/release/psy_user_cli call \
  --sign-type zk -p '<private-key>' \
  --rpc-config psy-genesis/config.json \
  --contract-id '<contract-id>' \
  --method-name '<method>' \
  --inputs '[<arg0>, <arg1>]' \
  --wait-until-confirmation

# Read-only simulation without proofs
./target/release/psy_user_cli simulate --source <contract.psy.rs> --contract-id '<contract-id>' --method '<method>' --inputs '<arg0>' --inputs '<arg1>'
```

Unlike `call`, `simulate` accepts repeated integer `--inputs` arguments, not a JSON array (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:609-637`). It executes against an empty in-memory state backend, not live chain storage (`client_prover/psy_cli/psy_user_cli/src/subcommand/simulate.rs:41-53`).

`call --wait-until-confirmation` returns the included checkpoint and EndCap transaction hash. Serial rule: for one user, never run two L2 calls concurrently.

## 11. Exact Failure Responses

| Response | Meaning | Required action |
|---|---|---|
| result file absent after nonzero exit | Command failed; stale success was removed fail-closed | Read stderr, correct the cause, rerun |
| `no user ids found` / `status: "not_registered"` | Registration not yet included or key never registered | Keep polling `get-user-id`; do not submit L2 calls |
| `only deployer can mint` | Caller is not the contract deployer | Use the faucet procedure in Section 5.1 for genesis PSY funding; do not retry `simple_mint` |
| `Leaf preimage not found at index <n>` | No storage record at that index for (user, contract) | Treat as empty state; verify contract id and leaf index |
| EndCap inclusion timeout after 180 seconds | Call submitted but inclusion not observed | Check the transaction hash and realm state; never run another same-user call concurrently |

## 12. References

- Command registry: `client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs:47-159`.
- Result-file contract: `client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs:47-54`, `client_prover/psy_cli/psy_user_cli/src/result.rs:299-372`.
- Registration/ID semantics: `client_prover/psy_cli/psy_user_cli/src/subcommand/register_user.rs:15-46`, `client_prover/psy_cli/psy_user_cli/src/subcommand/get_user_id.rs:9-30`.
- Deployer guard example: `psy-compiler/psy-precompiles/token/src/main.psy:397-402`; update authorization: `psy_node_common/src/coordinator/edge/handler.rs:532-553`.
- Genesis deployment generation: `psy-compiler/Makefile:216-236`, `psy-compiler/psy-dargo-cli/examples/gen_deploy_json.rs:24-30`.