# Reward Claim Operations

> Repository-only reward runbook. Status: Review. Owning design: [Checkpoint Reward Claim Cutover](checkpoint-claim-cutover.md). Commands and eligibility below describe the source implementation, not deployment readiness.

## Abstract

Run a proof-mining worker with durable job metadata, select owned reward-tree jobs, and submit `psy_user_cli claim-rewards` to the Ethereum reward token. Keep the reward owner, worker request signer, Ethereum transaction signer, and recipient separate. The claim command authenticates owned jobs and registration, checks finalized roots and claimed pairs, then verifies the transaction receipt and mint events (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:41-68,118-209`). Run commands from the repository root; replace angle-bracket values with this deployment's values. Never put secrets in this document or result files.

## Table of Contents

- [Terminology](#terminology)
- [0. End-to-End Path](#0-end-to-end-path)
- [1. Mine and Preserve Job Metadata](#1-mine-and-preserve-job-metadata)
- [2. Select Eligible Work](#2-select-eligible-work)
- [3. Query Before Claiming](#3-query-before-claiming)
- [4. Submit the Claim](#4-submit-the-claim)
- [5. Interpret Results and Cache State](#5-interpret-results-and-cache-state)
- [6. Exact Failure Responses](#6-exact-failure-responses)
- [Related Documents](#related-documents)

## Terminology

- **GUTA**: global user-tree aggregator.
- **L1**: Ethereum settlement chain; **L2**: Psy execution chain.
- **CLI**: command-line interface; **RPC**: remote procedure call; **API**: application programming interface.
- **ZK**: zero-knowledge authorization; **EVM**: Ethereum Virtual Machine.
- **PSY**: Psy token; **JSON**: JavaScript Object Notation.

## 0. End-to-End Path

1. Create a ZK wallet and register it; wait for its assigned user ID using [Common Operations §2–3](common-operations.md#3-register-an-account) (`client_prover/psy_cli/psy_user_cli/src/subcommand/register_user.rs:25-46`).
2. **Start the worker before user operations**, with `--user <registered-id>` and a writable backup, following [Section 1](#1-mine-and-preserve-job-metadata). Attribution is attached to the worker's work request, not retroactively to the transaction sender; starting after the transition's GUTA jobs are taken cannot reattribute them (`psy_worker_core/src/api/basic_job_fetcher.rs:45-55,218-224`).
3. Fund the operating wallet through [Common Operations §5.1](common-operations.md#51-fund-psy-through-the-faucet), then execute contract 0 method `claim` with the returned faucet operator ID. Wait for confirmation before further calls (`docs/src/dev/common-operations.md:110-134`).
4. Submit real state-changing `call` operations and wait for committed confirmation; a query or idle checkpoint is not payable work. The faucet `claim` above is itself a state-changing call (`docs/src/dev/common-operations.md:123-134`; `psy_plonky2_circuits/src/guta/gadgets/guta_no_change_gadget.rs:50-65`). Any registered key can operate its own account and transact; it need not be the reward owner. **The claim keystore must hold the key registered at `--user-id`**, regardless of who submitted the proved transactions (`psy_worker_core/src/api/basic_job_fetcher.rs:45-55,218-224`; `client_prover/psy_prover/src/local/reward_client.rs:1040-1051`).
5. Preserve the full backup and select complete records for eligible circuits **and matching preimage user**, following [Section 2](#2-select-eligible-work); circuit IDs alone are insufficient (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:326-341,346-382`).
6. Run the `get-claim-amount` precheck in [Section 3](#3-query-before-claiming) for the relevant L2 source/claiming users. It checks L2 user-to-user claims, **not** an Ethereum mining-reward quote; separately check Section 2's selected-job arithmetic (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_amount.rs:7-25`).
7. Run `claim-rewards` with the selected jobs and registered owner's keystore using [Section 4](#4-submit-the-claim); require `confirmed`, not merely `proof_only`, under [Section 5](#5-interpret-results-and-cache-state) (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:195-255`).

## 1. Mine and Preserve Job Metadata

Use a worker configuration for the selected network and worker signing identity, then explicitly set reward attribution and a writable backup destination:

> **Worker environment requirement:** unset `PSY_CONFIG_PATH` and `PSY_NETWORK` in the worker's launch environment. A bad inherited configuration can produce `Started N worker threads` followed within milliseconds by `Worker exit.` without an error line: the outer task checks only join failures and discards an inner `Result::Err` (`psy_cli/psy_worker_cli/src/subcommand/worker.rs:54-59,114-121,156-175`). These variables are build-time inputs to `psy_config`, not worker CLI options (`client_prover/psy_core/psy_config/build.rs:6,43-56`; `psy_cli/psy_worker_cli/src/subcommand.rs:30-73`), **but they also affect runtime circuit initialization**: `PSY_NETWORK` must match the selected network, and `PSY_CONFIG_PATH` restricts validator lookup to that one file, suppressing the generated-runtime-config fallback. A file without injected validators therefore fails initialization (`psy_data/src/config/network_config.rs:28-57`; `psy_plonky2_circuits/src/circuit_library/core.rs:27-28`). Pass `--network` explicitly to the worker and `--rpc-config` explicitly to user CLI commands; the worker has no `--rpc-config` option (`psy_cli/psy_worker_cli/src/subcommand.rs:30-73`; `client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:542-566`).

```bash
env -u PSY_CONFIG_PATH -u PSY_NETWORK ./target/release/psy_worker_cli worker \
  --config '<worker-config.json>' --network local-devnet \
  --user '<reward-owner-user-id>' \
  --coordinator-api-url '<coordinator-edge-url>' \
  --realm-api-url '<realm-edge-url>' \
  --completed-jobs-log-file worker.backup
```

The exact worker options are declared in `psy_cli/psy_worker_cli/src/subcommand.rs:30-73`:

| Option | Meaning / default |
|---|---|
| `--config` | Optional configuration file. |
| `--private-key`, `--keystore-path`, `--wallet-password` | Worker signing source; environment variables `PRIVATE_KEY`, `KEYSTORE_PATH`, `WALLET_PASSWORD`. Do not supply secret literals in shared command history. |
| `--user` | Reward-attribution user ID. |
| `--network`, `--proving-backend` | Network and proving backend overrides; omitted backend resolves to `plonky2-poseidon-goldilocks` (`psy_cli/psy_worker_cli/src/subcommand/worker.rs:102-104`). |
| `--completed-jobs-log-file` | Optional append-only binary claim metadata destination; explicitly set it to preserve claim material. |
| `--coordinator-api-url`, `--realm-api-url` | Repeatable coordinator-edge and realm-edge work sources respectively. |
| `--url-rotation-strategy` | Default `random`; advertised choices: `round-robin`, `random`, `continue-until-failure`, `continue-until-failure-or-no-work-for-3-seconds`, `smart-swap-v1`. |
| `--batch-size` | Concurrent job count, default `4`. |
| `--proving-pools` | `per-job` (default) or `shared`; also `PROVING_POOLS`. |
| `--threads-per-job` | Optional concurrent per-job pool size; also `THREADS_PER_JOB`; help specifies half of all threads by default. |

`--user` is **not the owner of transactions being proved** and is not an Ethereum address. The worker builds each reward tag preimage as `[user_id, 0, random_a, random_b]`, then hashes the preimage with itself. The separate worker API signer signs the work request carrying that tag (`psy_worker_core/src/api/basic_job_fetcher.rs:45-55,84-90,218-224`). Coordinator and realm URLs select separate work queues; a single configured class is used alone, and with both classes the fetcher selects its current mode (`psy_worker_core/src/api/basic_job_fetcher.rs:184-227`). CLI URLs are concatenated with configuration URLs (`psy_worker_core/src/config/worker_cli_config.rs:102-106`).

Check that the backup destination is writable before mining. Opening it can print `Failed to open backup file: {error}` and continue without a backup; completed records are serialized, appended and flushed when a backup is open (`psy_worker_core/src/api/basic_job_fetcher.rs:59-70,104-129`). Preserve the original file separately from disposable proof caches.

### Binary backup layout

Each record is **173 bytes**, concatenated without a JSON wrapper. Offsets below are zero-based, end-exclusive; integers and hash limbs are little-endian. This is the serialized layout, not Rust structure padding. Writer: `psy_data/src/worker/proving_work_history.rs:123-141`; decoder and size: `client_prover/psy_core/psy_data/src/api/reward.rs:7-23,64-132`.

| Byte range | Bytes | Field | Decoder source |
|---|---:|---|---|
| `[0,24)` | 24 | `job_id`, without `slot_id` | `client_prover/psy_core/psy_data/src/api/reward.rs:75-77` |
| `[24,56)` | 32 | `reward_tree_tag` | `client_prover/psy_core/psy_data/src/api/reward.rs:79-82` |
| `[56,88)` | 32 | `reward_tree_tag_preimage` | `client_prover/psy_core/psy_data/src/api/reward.rs:84-87` |
| `[88,96)` | 8 | `proving_duration_ms` | `client_prover/psy_core/psy_data/src/api/reward.rs:89-91` |
| `[96,104)` | 8 | `job_submitted_at` | `client_prover/psy_core/psy_data/src/api/reward.rs:93-95` |
| `[104,112)` | 8 | `unique_pending_id` | `client_prover/psy_core/psy_data/src/api/reward.rs:97-99` |
| `[112,120)` | 8 | `realm_id` | `client_prover/psy_core/psy_data/src/api/reward.rs:101-103` |
| `[120,128)` | 8 | `realm_sub_id` | `client_prover/psy_core/psy_data/src/api/reward.rs:105-107` |
| `[128,129)` | 1 | `reward_tree_node_key.level` | `client_prover/psy_core/psy_data/src/api/reward.rs:109-111` |
| `[129,137)` | 8 | `reward_tree_node_key.index` | `client_prover/psy_core/psy_data/src/api/reward.rs:112-117` |
| `[137,138)` | 1 | `reward_tree_hash_mode` | `client_prover/psy_core/psy_data/src/api/reward.rs:119-121` |
| `[138,140)` | 2 | `reward_tree_node_children` | `client_prover/psy_core/psy_data/src/api/reward.rs:123-125` |
| `[140,141)` | 1 | `node_type` | `client_prover/psy_core/psy_data/src/api/reward.rs:127-129` |
| `[141,173)` | 32 | `api_url_hash` | `client_prover/psy_core/psy_data/src/api/reward.rs:131-132` |

`--jobs-file` requires whole records: byte length must be divisible by 173. It is not the JSON job-ID input accepted by `generate-batch-proof-miner-reward-proofs`. The loader rejects indices exceeding 56 bits, packs `(level << 56) | index`, and routes `node_type == 1` to realm lookup and other values to coordinator lookup (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:346-382`; `client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:526-539`).

## 2. Select Eligible Work

Select owned work in the GUTA reward subtree. The relevant work circuit IDs are **7–14, 55–60, and 63** (`psy_core/src/job/job_id.rs:141-149,183-192`):

| IDs | Circuits |
|---|---|
| 7–11 | `GUTATwoEndCap`, `GUTATwoGUTA`, `GUTALeftEndCapRightGUTA`, `GUTALeftGUTARightEndCap`, `GUTASingleEndCap` |
| 12–14 | `GUTARegisterUsers`, `GUTAVerifyToCap`, `GUTAOnlyRegisterUsers` |
| 55–56 | `GUTATwoGUTAWithCheckpointUpgrade`, `GUTAVerifyToCapWithCheckpointUpgrade` |
| 57–60 | `GUTATwoGUTALinear`, `GUTATwoGUTALinearUpgradeCheckpoint`, `GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint`, `GUTAVerifyLeftLeafRightLinearUpgradeCheckpoint` |
| 63 | `RealmFinalizeGUTA` |

A circuit ID alone does not authorize a claim: the claim circuit binds the user to the first tag-preimage limb, requires a nonzero preimage and owned tag, and checks its authenticated reward path (`psy_plonky2_circuits/src/bridge/circuits/user_reward_tree.rs:63-115`). The GUTA subtree starts at level **2**, index **0**. Registration, deployment and update roots are at `(3,2)`, `(4,6)` and `(4,7)` respectively, outside that subtree (`psy_data/src/rewards_tree/offsets.rs:52-62`).

**Idle-root caution:** circuit **15**, `GUTANoChange`, is the idle root, not evidence of payable work. Its state is unchanged and its GUTA statistics are zero (`psy_plonky2_circuits/src/guta/gadgets/guta_no_change_gadget.rs:50-65`). Do not claim an idle checkpoint with zero fees. Also do not use “circuit 15 is never published” as a diagnostic: the source identifies the all-idle root set in `get_root_job_ids`, but still calls first-level publication; the queue publishes every item in each nonempty level (`psy_node_common/src/coordinator/processor/core/process_block.rs:219-225,630-646,149-172`; `psy_node_nats/src/queue.rs:1496-1501`). Publication and payable eligibility are separate checks.

For each selected coordinate require:

- `2 <= h <= 21` and `0 <= path < 2^(h-2)`; the claim-local nullifier index is `2^(h-2) - 1 + path` (`psy_plonky2_circuits/src/bridge/gadgets/reward_nullifier.rs:27-34`; circuit enforcement: `psy_plonky2_circuits/src/bridge/circuits/user_reward_tree.rs:35,63-87`).
- `0 < selected_job_count <= checkpoint.stats.pm_jobs_completed.gutas_completed`, with `gutas_completed > 0`. For each checkpoint independently, `amount = floor(selected_job_count * guta_fees_collected / gutas_completed)`; the remainder is strictly less than the denominator (`psy_plonky2_circuits/src/bridge/circuits/user_reward_tree.rs:543-565,583-588,619-628`).
- A positive amount. A zero result is rejected by `RewardClaim::from_public_inputs`, even though the payout arithmetic can produce zero (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:98-100`; `client_prover/psy_core/psy_data/src/reward_claim.rs:75-105`).
- An unclaimed `(user_id, checkpoint_id)` under a recognized finalized root. Claiming consumes the checkpoint pair, not just the selected jobs: select all intended owned jobs for that checkpoint before paying it (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:63-68,125-128,208-209`).
- Recognition requires `checkpointTreeRootsClean()` and a nonzero `checkpointTreeRootCheckpointId(bytes32)` no greater than the finalized tip. After a real force-set, administrators revoke named abandoned roots with `revokeCheckpointTreeRoots(bytes32[])` and explicitly call `setCheckpointTreeRootsClean(true)` only after cleanup verification. Revocation preserves unnamed historical roots and never resets claimed pairs; there is no root count or automatic clean transition.

## 3. Query Before Claiming

Confirm registration through [Common Operations](common-operations.md), then query the owner's state and each backup pending ID:

```bash
./target/release/psy_user_cli get-user-leaf \
  --rpc-config '<rpc-config.json>' --user-id '<reward-owner-user-id>' \
  --checkpoint-id '<checkpoint-id>' --result-file user-leaf.json

./target/release/psy_user_cli get-checkpoint-id-for-unique-pending-id \
  --rpc-config '<rpc-config.json>' --unique-pending-id '<backup-pending-id>' \
  --provider-type coordinator --result-file reward-checkpoint.json
```

`get-user-leaf --user-id` queries the corresponding realm; `--pub-key` instead queries the coordinator and conflicts with `--user-id`. Its checkpoint default is `100`, so specify the intended checkpoint (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:152-162`). Use `--provider-type realm` for a realm pending ID and `coordinator` for a coordinator pending ID. The result is `{"checkpoint_id": ...}` with an optional ID, not proof that Ethereum recognizes that checkpoint (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:510-524`; `client_prover/psy_cli/psy_user_cli/src/subcommand/get_checkpoint_id_for_unique_pending_id.rs:7-21`).

The separate user-to-user claim-amount query is:

```bash
./target/release/psy_user_cli get-claim-amount \
  --rpc-config '<rpc-config.json>' --checkpoint-id '<checkpoint-id>' \
  --user-id '<claiming-user-id>' --claim-user-id '<source-user-id>' \
  --result-file claim-amount.json
```

This returns `claim_amount` for those two L2 users; omitting `--checkpoint-id` selects the latest block. **It is not the selected-job Ethereum reward quote** and is not a prerequisite L2 transaction (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:466-479`; `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_amount.rs:7-25`). Use the checkpoint arithmetic in Section 2 for reward eligibility. For L2 balance reads using `get-user-contract-state-tree-leaf-hash`, follow [Common Operations §9](common-operations.md#9-query-user-state-inside-a-contract); do not mistake the user-leaf fee balance or L2 token balance for the Ethereum mint destination.

## 4. Submit the Claim

Set up the registered ZK wallet using [Common Operations](common-operations.md). Supply its keystore through `--keystore-path` and password securely through `WALLET_PASSWORD`. Supply the **separate Ethereum signing key** through `L1_PRIVATE_KEY`; it signs the EVM transaction, while the held ZK key proves registration ownership (`client_prover/psy_core/psy_common/src/args.rs:91-100`; `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:46-50,130-175`; `client_prover/psy_prover/src/local/reward_client.rs:1029-1051`).

> **Address casing:** supply both `--reward-token` and `--recipient` as `0x` plus exactly 40 **lowercase** hexadecimal characters. `lowercase_address` validates; it does not convert checksummed input. Deployment discovery validates the token through this same helper, so an uppercase token fails with `recipient must be 0x plus 40 lowercase hex characters` even when the recipient is valid. The error names `recipient` regardless of which address failed (`client_prover/psy_prover/src/local/reward_client.rs:749-753,1156-1158,1177-1178`).

```bash
./target/release/psy_user_cli claim-rewards \
  --rpc-config '<rpc-config.json>' \
  --reward-token '<ethereum-reward-token-address>' \
  --recipient '<ethereum-recipient-address>' \
  --user-id '<reward-owner-user-id>' \
  --sign-type zk --keystore-path '<registered-wallet-keystore.json>' \
  --jobs-file worker.backup \
  --proof-cache-dir reward-proof-cache \
  --l1-rpc-url '<ethereum-rpc-url>' \
  --prove-proxy-url '<prove-proxy-url>' \
  --result-file reward-claim-result.json
```

Exact claim-specific flags (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:542-566`):

| Flag | Contract |
|---|---|
| `--rpc-config` | Psy RPC configuration; default `config.json`. |
| `--reward-token` | Ethereum reward-token address; its addresses provider discovers StateManager. |
| `--recipient` | Independent, nonzero 160-bit Ethereum address, not derived from the registration key or required to equal the transaction signer. |
| `--user-id` | L2 reward owner; CLI accepts an integer then requires conversion to `u32`. Must equal each backup tag preimage's first limb. |
| `--jobs-file` | Original binary backup, default `worker.backup`; not consumed or deleted. |
| `--proof-cache-dir` | Disposable aggregate cache, default `reward-proof-cache`; keep original jobs outside it. |
| `--l1-rpc-url` | Ethereum RPC for roots, claimed pairs, transaction submission and receipt checks. |
| `--l1-private-key` | Ethereum transaction signer; use `L1_PRIVATE_KEY` instead of a literal command-line key. |
| `--prove-proxy-url` | Groth16 reward-wrap proof service. |
| `--prove-proxy-token` | Optional bearer token; use its environment input rather than a literal in shared history. |

The flattened wallet flags are `--sign-type` (default `zk`), `--private-key`/`-p`, `--keystore-path`, `--wallet-password`, `--fingerprint`, `--sd-key-allowed-contract-id`, `--sd-key-allowed-method-id`, and `--sd-key-expected-tx-count` (default `2`). Private key and keystore conflict. Reward claims accept only ZK authorization, so do not use the software-defined-key flags to bypass that restriction (`client_prover/psy_core/psy_common/src/args.rs:91-111`; `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:46-50`). `--result-file` is a global option (`client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs:70-71`).

Recipient decoding accepts 20 bytes or zero-padded 32 bytes, rejects high bits and zero, and passes the chosen address into the authenticated claim statement. `--user-id` is separately checked against backup preimages and the registered held key (`client_prover/psy_prover/src/local/reward_client.rs:135-155,1029-1051`; `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:42-44,117-123,326-341`). Supported Ethereum chain identities are `1`, `31337`, and `11155111` (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:51-53`).

## 5. Interpret Results and Cache State

Read the result file only after a successful process exit. The JSON object has `transaction_hash`, `status`, and `chain_id`; it is not wrapped in a command enum (`client_prover/psy_cli/psy_user_cli/src/result.rs:105-119,270-279`).

- `status: "confirmed"`: at least one payout is confirmed; `transaction_hash` is the **last** confirmed transaction. Receipt success, reward event, mint transfer and every claimed pair are checked (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:195-228`).
- `status: "proof_only"`, `transaction_hash: null`: no payout was confirmed. Already-claimed pairs are skipped; unfinalized selections can be preaggregated. This status does **not** assert a mint or that every pending source was available (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:63-76,93-104,223-255`). If every checkpoint is deferred with `historical checkpoint root differs from finalized L1 root`, follow [L1 reward-root recovery after rollback](rollback-operations.md#9-l1-reward-root-recovery-after-rollback) rather than replacing the jobs file (`client_prover/psy_prover/src/local/reward_client.rs:998-1002`).
- After execution begins, errors remove the result file rather than publishing stale success. Results are written atomically. Use a dedicated output path, never an input file (`client_prover/psy_cli/psy_user_cli/src/result.rs:301-374`; `client_prover/psy_cli/psy_user_cli/src/main.rs:270-312`).
- An error can follow an actual payout. Preserve `confirmed_tx=...` and `submitted_tx=...` from the error chain and inspect those receipts before retrying; absent output does not prove no transaction was sent (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:214-221,261-268`).

Cache files are named by network magic, user and source checkpoint. Reuse checks circuit identity, exact selected jobs and complete source leaf; cache decode/mismatch failures cause reconstruction from original jobs, not a claim-authority shortcut. It is safe to discard the cache, not the original backup (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:234-246`; `client_prover/psy_prover/src/local/reward_client.rs:553-565,601-628`).

## 6. Exact Failure Responses

Braces below denote values interpolated by the source. Do not replace these responses with invented “not eligible” labels.

| Response | Meaning and required action | Source |
|---|---|---|
| `recipient must be 0x plus 40 lowercase hex characters` | Token **or** recipient address has invalid casing/format. Supply both as `0x` plus 40 lowercase hex characters; the error always names recipient. | `client_prover/psy_prover/src/local/reward_client.rs:749-753,1156-1158,1177-1178` |
| `reward source is newer than the recognized anchor` | Source checkpoint exceeds the L1 anchor. Wait for settlement to advance the recognized anchor, then retry with unchanged jobs. | `client_prover/psy_prover/src/local/reward_client.rs:541-544` |
| `Failed to open backup file: {error}` | Backup cannot be opened for append (for example, unwritable destination). Mining continues **without durable claim metadata**. Fix the destination before mining more work. | `psy_worker_core/src/api/basic_job_fetcher.rs:59-70` |
| `reward registration leaf does not match the private key` | Unregistered or different held ZK key at the anchor. Confirm registration and use the matching wallet; the Ethereum signer cannot substitute. | `client_prover/psy_prover/src/local/reward_client.rs:1043-1045` |
| `reward root accepts only ZK authorization` | Unsupported wallet signing type. Select the registered ZK wallet. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:49` |
| `jobs file {file} contains a reward for user_id {record_user}, but current wallet user_id is {expected_user}: {source}, job_id={job:?}` | Wrong tag-preimage first limb. Select the correct owner's records; do not edit their preimages. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:326-341` |
| `reward tag preimage does not belong to the user` / `reward tag leaf does not prove user ownership` | Invalid preimage or tag binding. Restore authentic metadata for that owner. | `client_prover/psy_prover/src/local/reward_client.rs:153-155` |
| `reward nullifier height is outside 2..=21` / `reward nullifier path exceeds its height` | Coordinates outside the GUTA claim range. Check source reward paths; do not truncate or rewrite coordinates. | `psy_plonky2_circuits/src/bridge/gadgets/reward_nullifier.rs:29-31` |
| `reward job count exceeds completed jobs or is zero` | Zero denominator/count or count exceeds checkpoint total. Recheck the source checkpoint and selection. | `psy_plonky2_circuits/src/bridge/circuits/user_reward_tree.rs:623-625` |
| `invalid encoding: nonzero bytes above declared width` | Also the exact zero-payout rejection, not solely a width error. Check the integer payout; do not submit zero-fee idle work. | `client_prover/psy_core/psy_data/src/reward_claim.rs:12-13,20-21,102-105` |
| `reward checkpoint {id} is already claimed; rebuild the selected unclaimed batch` | Pair became claimed before submission. Refresh claimed pairs; never resubmit that paid checkpoint. Initially claimed pairs are silently skipped. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:67,125-128` |
| `reward checkpoint root is no longer recognized` | Finalized anchor is no longer accepted. Refresh authoritative root and rebuild. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:125` |
| `reward cache identity mismatch` / `reward cache circuit mismatch` | Internal cache validation failures; the CLI rebuilds instead of surfacing them as fatal cache errors. Preserve originals; discard only disposable cache if necessary. | `client_prover/psy_prover/src/local/reward_client.rs:603-607,621-625`; `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:239-245` |
| `original jobs must be outside the disposable cache directory` | Backup is nested under cache. Put the original backup outside that directory. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:237` |
| `jobs backup length {length} is not a multiple of record size {size}` | Partial or nonbinary backup. Restore complete 173-byte records from a preserved copy. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:355-361` |
| `no reward jobs selected` | Empty backup. Supply actual completed job metadata. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:58-59` |
| `reward source groups unavailable: {ids}; original jobs file unchanged` | Source groups could not be loaded. Restore/query the correct source service; preserve jobs and check any attached confirmed transaction hashes. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:70-72,219-221` |
| `reward recipient must be nonzero` / `address exceeds 160 bits` (CLI) / `recipient exceeds 160 bits` (internal circuit check) | Invalid payout address. Supply the intended nonzero Ethereum address. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:43-44`; `client_prover/psy_prover/src/local/reward_client.rs:135-138`; `psy_plonky2_circuits/src/bridge/circuits/user_reward_tree.rs:620` |
| `reward claim receipt not observed within 120s: tx_hash={hash}` | Submitted transaction is not yet observed. Inspect this hash before retrying. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:185-189,230` |
| `reward claim transaction reverted: tx_hash={hash}, reason={reason}` | Receipt failed; reason is `unknown` if tracing supplies none. Inspect the receipt and trace before correcting the input. | `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:200-203` |

## Related Documents

- [Checkpoint Reward Claim Cutover](checkpoint-claim-cutover.md) — owning design document; this runbook documents executable source behavior only.
- [Common Operations](common-operations.md) — wallet, registration and L2 state queries; [§9](common-operations.md#9-query-user-state-inside-a-contract) owns balance-read commands.
- [Bridge Common Operations](bridge-common-operations.md) — deposit, withdrawal and relayer settlement procedures.
- [Reward Tree Circuits](reward-tree-circuits.md) — reward-tree circuit reference.
- [Devnet Lifecycle](devnet_lifecycle.md) — startup and shutdown.
