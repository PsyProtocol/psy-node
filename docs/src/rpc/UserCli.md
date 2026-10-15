# User CLI (`psy_user_cli`)

> Regenerated 2026-09-08 from live `target/release/psy_user_cli --help` and
> `client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs`.

## Abstract

Client CLI for wallet, contract deploy/call, tree/metadata queries, proving helpers, bridge flows, and private-note operations. Global flag: `--result-file <PATH>`.

## Currency notes

- Coordinator public-key lookup over RPC is `psy_get_user_ids_for_public_key` → `Vec<u64>`.
- CLI `get-user-id` resolves the session/local user-id path (see command help); do not treat it as a single-id coordinator hash lookup.
- Tip checkpoint RPC name is `psy_get_latest_checkpoint_id`.
- L2 block getters use `*_l2_block_state` / CLI `get-latest-block-state` / `get-block-state`.

## Subcommand inventory (62 commands)

| Command |
|---|
| `wallet` |
| `register-user` |
| `deploy-contract` |
| `update-contract` |
| `call` |
| `get-user-id` |
| `get-user-event-data` |
| `get-user-leaf` |
| `get-user-contract-state-tree-root` |
| `get-user-contract-state-tree-leaf-hash` |
| `get-user-contract-state-imt-leaf-preimage` |
| `get-user-contract-state-tree-merkle-proof` |
| `get-user-contract-tree-root` |
| `get-user-contract-tree-leaf-hash` |
| `get-user-contract-tree-merkle-proof` |
| `get-user-registration-tree-root` |
| `get-user-registration-tree-leaf-hash` |
| `get-user-registration-tree-merkle-proof` |
| `get-user-tree-root` |
| `get-user-tree-leaf-hash` |
| `get-user-tree-merkle-proof` |
| `get-user-sub-tree-merkle-proof` |
| `get-contract-function-tree-root` |
| `get-contract-function-tree-leaf-hash` |
| `get-contract-function-tree-merkle-proof` |
| `get-contract-tree-root` |
| `get-contract-tree-leaf-hash` |
| `get-contract-tree-merkle-proof` |
| `get-withdrawal-tree-root` |
| `get-latest-checkpoint-tree-root` |
| `get-checkpoint-tree-root` |
| `get-checkpoint-tree-leaf-hash` |
| `get-checkpoint-tree-merkle-proof` |
| `get-contract-leaf-data` |
| `get-checkpoint-leaf-data` |
| `get-contract-code-definition` |
| `get-latest-block-state` |
| `get-block-state` |
| `local-prover` |
| `prove-proxy` |
| `faucet-server` |
| `get-claim-amount` |
| `batch-claim` |
| `tx` |
| `get-checkpoint-id-for-unique-pending-id` |
| `generate-batch-proof-miner-reward-proofs` |
| `claim-rewards` |
| `get-psy-sdc-fingerprint` |
| `get-user-end-cap-common-data` |
| `compile` |
| `compile-and-deploy` |
| `simulate` |
| `generate-tx-trace` |
| `prove-tx-trace` |
| `private-transfer` |
| `private-claim` |
| `derive-shield` |
| `claim-deposit` |
| `withdraw` |
| `deposit` |
| `claim-withdrawal` |
| `export-private-key` |

## Groups (informational)

| Group | Commands |
|---|---|
| Wallet / identity | `wallet`, `register-user`, `get-user-id`, `export-private-key` |
| Contract | `deploy-contract`, `update-contract`, `call`, `compile`, `compile-and-deploy`, `simulate` |
| Tree queries | `get-user-*`, `get-contract-*`, `get-withdrawal-tree-root`, `get-*-checkpoint-tree-*` |
| Metadata | `get-contract-leaf-data`, `get-checkpoint-leaf-data`, `get-contract-code-definition`, `get-latest-block-state`, `get-block-state` |
| Proving | `local-prover`, `prove-proxy`, `generate-tx-trace`, `prove-tx-trace`, `get-user-end-cap-common-data` |
| Rewards / jobs | `get-claim-amount`, `batch-claim`, `claim-rewards`, `get-checkpoint-id-for-unique-pending-id`, `generate-batch-proof-miner-reward-proofs` |
| Bridge | `deposit`, `claim-deposit`, `withdraw`, `claim-withdrawal` |
| Privacy | `private-transfer`, `private-claim`, `derive-shield` |
| Misc | `tx`, `faucet-server`, `get-psy-sdc-fingerprint`, `get-user-event-data`, `get-user-leaf` |

## Reward setup

`claim-rewards` loads `RewardClient` from the existing `--rpc-config`. That file supplies the reward token and the circuits through `UserRewardCircuits::build`. There is no external setup document, source-identity field, or second configuration file.

`claim-rewards` mints eligible unclaimed checkpoint groups first through L1 `claimReward(bytes,bytes32,uint32,address,uint32[],uint256)` on the configured reward token. It builds authenticated Roots and a checkpoint aggregate, sends the wrap witness to the prove-proxy, and confirms the receipt, the token `RewardClaimed` event, the mint `Transfer`, and exact `claimed(user,id)` pairs before refreshing state and preaggregating remaining jobs. Confirm rediscovers the token and `STATE_MANAGER` from the provider at the receipt block. Each transaction keeps the complete public ID list and proved total; more than 64 eligible checkpoints repeat the same artifact. Eligibility uses recognized finalized roots and token claimed pairs, never a payer cursor.

Required flags beyond the ZK wallet source are `--recipient`, `--user-id`, `--l1-rpc-url`, `--l1-private-key`, and `--prove-proxy-url`. `--proof-cache-dir` defaults to `reward-proof-cache`; keep original `--jobs-file` binary metadata outside it. Cache loss rebuilds with original selections and available historical source/path material. A retained cache matches network magic, source fingerprints, common digests, verifier digests, and the proof; it is not paid state. `--services-url` is optional transport configuration. Unknown checkpoint mappings fail closed to prevent omitted-job forfeiture; independently identified later unavailable material stays pending. Failed or pending L1 claims do not enable remaining proving. New source and regression coverage require execution; no E2E pass is asserted.


## Source

- `client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs`
- `client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs`
