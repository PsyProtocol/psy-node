# Realm P2P Validators: Becoming a Validator

> Updated: 2026-09-03.

## Abstract

A Psy validator is a Realm processor that participates in the Realm P2P consensus path: it verifies GUTA proposals, signs BLS votes, and — when scheduled — submits the epoch's GUTA proposal with a validator certificate to the Coordinator. The validator set is currently **fixed at genesis**: every validator is a `(realm_id, realm_sub_id)` pair listed in `genesis.json` `validators` and in the per-deployment `validators.json` manifest. There is no on-chain join or leave flow today. Dynamic validator sets (staking, on-chain registration, validator-tree state transitions) are future work and out of scope here; the reserved `validator_tree_root` in the checkpoint state is where that evolution lands.

## Table of Contents

- [Terminology](#terminology)
- [1. Rules and Bounds](#1-rules-and-bounds)
- [2. What a Validator Must Have](#2-what-a-validator-must-have)
- [3. Onboarding Steps](#3-onboarding-steps)
  - [3.1 Generate keys](#31-generate-keys)
  - [3.2 Bind the set into genesis](#32-bind-the-set-into-genesis)
  - [3.3 Start the Coordinator with the registry](#33-start-the-coordinator-with-the-registry)
  - [3.4 Start the Realm processor as a validator](#34-start-the-realm-processor-as-a-validator)
  - [3.5 Start the Realm edges](#35-start-the-realm-edges)
- [4. Validator Runtime Duties](#4-validator-runtime-duties)
- [5. Verification](#5-verification)
- [6. Dynamic Validator Sets](#6-dynamic-validator-sets)

## Terminology

| Term | Definition |
|---|---|
| Validator | A Realm processor identity with a `(realm_id, realm_sub_id)` slot, a libp2p Ed25519 identity, and a 48-byte BLS public key. |
| `validator_user_id` | Deterministic user-tree slot: `(realm_id << 20) \| sub_id` (`psy_cli/psy_node_cli/src/node/realm_p2p.rs:85`). |
| `node_id` | 38-byte raw Ed25519 public key of the node's libp2p identity. |
| Proposer | The single validator scheduled to submit GUTA for a Realm for the whole epoch. |
| Certificate | Aggregated BLS votes meeting the replication threshold `ceil(n/2)`. |
| `validators.json` | Per-deployment manifest produced by `psy_node_cli init-realm-p2p-keys`, consumed by processors, edges, and the Coordinator. |

## 1. Rules and Bounds

1. Validators per Realm: `MIN_VALIDATORS_PER_REALM = 1`, `MAX_VALIDATORS_PER_REALM = 64` (`psy_data/src/p2p/limits.rs:87-90`). Registration rejects counts outside this range (`psy_data/src/p2p/validator_tree.rs:306-310`).
2. A certificate must carry at least `ceil(n/2)` signer votes (`psy_data/src/p2p/limits.rs:124-126`), every signer bitmap bit must name a validator leaf, and the aggregate must verify over the reconstructed `vote_message` (`psy_node_common/src/realm/processor/consensus.rs:303-332`).
3. Rotation is enabled only when `checkpoints_per_epoch > 0` and the validator list is non-empty (`parth_common/src/realm_rotation.rs:45-47`); otherwise every GUTA submission is accepted through the rotation-disabled path.
4. One validator identity per `(realm_id, realm_sub_id)`: duplicates are rejected both in the genesis registry and in `validators.json` parsing (`psy_node_common/src/coordinator/validator_registry.rs:24-35`; `psy_cli/psy_node_cli/src/node/realm_p2p.rs:88-92`).
5. The Coordinator accepts a GUTA submission only from the scheduled proposer of the current epoch (`psy_node_common/src/coordinator/edge/handler.rs:887-900`).

## 2. What a Validator Must Have

| Requirement | Detail |
|---|---|
| libp2p identity keys | Ed25519 protobuf files for the processor and, if the deployment runs one, the edge: `realm_{id}_sub_{sub}_processor_identity.key`, `realm_{id}_sub_{sub}_edge_identity.key` (`psy_cli/psy_node_cli/src/subcommand/init_realm_p2p_keys.rs:3-8`). |
| BLS secret key | File `realm_{id}_sub_{sub}_bls.key` with 64 hex chars and no newline; secrets are never printed to stdout (`psy_cli/psy_node_cli/src/subcommand/init_realm_p2p_keys.rs:11-12`). |
| Deployment manifest entry | An entry in `validators.json`: the `coordinator` bootnode entry plus `realms.{realm_id}.{sub_id}` with node ids, peer ids, BLS public hex, and key paths (`psy_cli/psy_node_cli/src/subcommand/init_realm_p2p_keys.rs:31-52`). |
| Genesis entry | An entry in `genesis.json` `validators` with `realm_id`, `realm_sub_id`, `validator_user_id`, `node_id`, and `bls_public_key` (`dev/locSetupV4.ts:1005-1035`). |

## 3. Onboarding Steps

### 3.1 Generate keys

```bash
<repo-root>/target/release/psy_node_cli init-realm-p2p-keys \
  --out-dir local_checkpoints/realm_p2p \
  --realm-ids 0,1 \
  --sub-ids 1,2
```

This writes, per `(realm, sub)` pair, the processor identity, edge identity, and BLS key files, plus one `coordinator_identity.key` and the single `validators.json` manifest (`psy_cli/psy_node_cli/src/subcommand/init_realm_p2p_keys.rs:60-116`). Paths recorded in the manifest are repo-relative, taken verbatim from `--out-dir` (`psy_cli/psy_node_cli/src/subcommand/init_realm_p2p_keys.rs:55-58`). Re-running the launcher reuses an existing complete manifest instead of regenerating (`dev/locSetupV4.ts:1047-1060`).

### 3.2 Bind the set into genesis

The startup pipeline injects the manifest's processor identities into `genesis.json` `validators` (`injectGenesisValidators`, `dev/locSetupV4.ts:1010-1035`). Two properties matter:

| Start mode | `validators` behavior |
|---|---|
| P2P | `--genesis-data-path` is input **and output**: startup rewrites the `validators` list. Use a disposable copy when preserving an existing list matters (`docs/src/node/devnet-launcher-reference.md:968-969`). |
| Non-P2P | Startup rewrites `validators` to an empty list, leaving no stale entries (`dev/locSetupV4.ts:1006-1009`). |

### 3.3 Start the Coordinator with the registry

The Coordinator edge needs the manifest and the epoch length, both or neither (`psy_node_core/src/config/node_start_config.rs:172-182`):

```bash
psy_node_cli start-coordinator-edge \
  --p2p-validators-path local_checkpoints/realm_p2p/validators.json \
  --p2p-checkpoints-per-epoch 10
```

The handler loads the registry from the manifest (`psy_cli/psy_node_cli/src/node/startup_edge_plonky2_scylla.rs:92-95`) and enforces the rotation schedule and certificate checks on every GUTA submission (`psy_node_common/src/coordinator/edge/handler.rs:798-905`).

### 3.4 Start the Realm processor as a validator

Required arguments use devnet values from `realmP2pProcessorExtraArgs` (`dev/locSetupV4.ts:1078-1115`):

| Argument | Purpose |
|---|---|
| `--p2p-identity-key` | This validator processor's Ed25519 identity file |
| `--p2p-bls-key` | This validator's BLS secret key file |
| `--p2p-listen` | libp2p multiaddr to listen on (devnet: `/ip4/<host>/tcp/41000+realm*20+sub`) |
| `--p2p-coordinator` | Coordinator bootnode multiaddr (devnet port 40999) |
| `--p2p-validator-sub-ids` | All validator sub-ids of the Realm, comma-separated (devnet: `1,2`) |
| `--p2p-checkpoints-per-epoch` | Epoch length; must match the Coordinator value |
| `--p2p-validator-user-id` | This validator's `validator_user_id` (`(realm_id << 20) \| sub_id`) |
| `--p2p-validators-path` | The shared `validators.json` |
| `--p2p-bootnode` | One per peer validator processor |

Startup fails closed: the manifest must contain one proposer `NodeId` per validator sub-id (`psy_cli/psy_node_cli/src/node/realm_p2p.rs:230-233`), and the configured `--p2p-validator-user-id` must equal the genesis entry for that `(realm_id, sub_id)` slot (`psy_node_common/src/coordinator/validator_registry.rs:77-86`).

### 3.5 Start the Realm edges

Edges forward EndCap proofs and never sign votes. Required arguments use devnet values from `realmP2pEdgeExtraArgs` (`dev/locSetupV4.ts:1117-1140`):

| Argument | Purpose |
|---|---|
| `--p2p-identity-key` | This edge's Ed25519 identity file |
| `--p2p-listen` | libp2p multiaddr to listen on (devnet: `/ip4/<host>/tcp/41100+realm*20+sub`) |
| `--p2p-validator-sub-ids` and `--p2p-checkpoints-per-epoch` | Same values as the processor |
| `--p2p-bootnode` | One per peer validator processor, plus one per peer edge |
| `--p2p-proposer-node-id <sub_id>:<node_id_hex38>` | One per validator sub-id |

## 4. Validator Runtime Duties

| Duty | Validator behavior |
|---|---|
| Propose (scheduled validator only) | For each target checkpoint, the deterministic Poseidon swap-or-not schedule seeded by the epoch anchor checkpoint's random seed selects exactly one proposer for the whole epoch (`parth_common/src/realm_rotation.rs:3-7,49-117`). Only that sub-id may submit the GUTA proposal. |
| Verify and vote (every non-proposer) | A validator verifies the proposal body (strict three-section length-prefixed decode plus SHA-256 hash checks, `psy_node_common/src/realm/processor/consensus.rs:46-137`), verifies the GUTA proof, commit output, and in-band FFS state updates, then produces a BLS `Vote` over the reconstructed `vote_message` (`sign_vote`, `psy_node_common/src/realm/processor/consensus.rs:17-21`). |
| Certificate admission | The Coordinator requires a `Proposal` and `Certificate` whenever rotation is enabled, checks `proposal_id`, the scheduled proposer, proposer validator membership, the `ceil(n/2)` threshold with `FastAggregateVerify`, proposer-inclusion in the certificate, and nonzero validator-tree roots (`psy_node_common/src/coordinator/edge/handler.rs:798-905`; `psy_node_common/src/realm/processor/consensus.rs:303-332`). |
| No replay here | The consensus module performs no state replay and keeps no per-validator tracking set (`psy_node_common/src/realm/processor/consensus.rs:17-18`); admission and state application stay in the Coordinator pipeline. |

## 5. Verification

1. With rotation enabled, a GUTA submission from a non-scheduled validator is rejected with `NotScheduledProposer` (`psy_node_common/src/coordinator/edge/handler.rs:890-900`).
2. A submission whose certificate has fewer than `ceil(n/2)` verified signers is rejected.
3. The P2P E2E acceptance criteria (identical roots across endpoints, two-validator certificate evidence, forward/accept id matching) are in `docs/src/node/circuit-and-verifier-operations.md` §7.
4. Devnet wiring end-to-end: `make run-all` with `--realm-p2p` selects sub-ids 1 and 2, reuses or generates keys, injects genesis validators, and passes the arguments above (`docs/src/node/devnet-launcher-reference.md:274,616-619`).

## 6. Dynamic Validator Sets

Today the set changes only by editing `genesis.json` `validators` plus the deployment `validators.json` and restarting the cohort. Dynamic membership — on-chain registration, stake bonding, validator-tree state transitions, and epoch-bound set changes — is future work and out of scope. The groundwork already reserved for it:

| Reserved element | Constraint |
|---|---|
| `validator_tree_root` | Part of the checkpoint global state roots (`psy_data/src/v1/qdata/checkpoint.rs:156-167`), currently pinned to the Poseidon empty-tree root at height 20 (`VALIDATOR_TREE_HEIGHT`, `psy_data/src/v1/qdata/checkpoint.rs:160-167`). |
| Validator bounds and leaf payload | `MIN_VALIDATORS_PER_REALM`/`MAX_VALIDATORS_PER_REALM` and `ValidatorLeafPreimage`, a fixed 104-byte payload binding `chain_id`/`realm_id`/`realm_sub_id`/`validator_user_id`/`node_id`/`bls_public_key`, are already enforced by shared helpers (`psy_data/src/p2p/validator_tree.rs:36-56`), so a dynamic set must reuse the same leaf format and bounds. |

Any dynamic-membership design must not weaken the `ceil(n/2)` replication threshold, the scheduled-proposer gate, or the genesis-identity binding of `validator_user_id`.
