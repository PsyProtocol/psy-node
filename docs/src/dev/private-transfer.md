# Private Transfer Flow

> Updated: 2026-09-04.

## Abstract

This document describes the private transfer and private claim flow on the Psy protocol. It is intended for auditors and integrators who need to verify the correctness of shielded transfers between users.

Related: `docs/src/dev/devnet_lifecycle.md` for startup and shutdown; `docs/src/dev/common-operations.md` for wallet, registration, and PSY funding.

**Substitutions:** the values below are operator-supplied public parameters for a single run: paths, contract IDs, amounts, addresses, npubs, and the note's `r0`/`r1`. Replace them before use. This document shows no executable command that carries a signing key: the current private-transfer and private-claim CLIs cannot accept a key without placing it in the process argument list, which the credential rules of this repository forbid (see Steps 2 and 5).

## Table of Contents

- [1. Overview](#1-overview)
- [2. Architecture](#2-architecture)
- [3. Private Transfer Flow](#3-private-transfer-flow)
- [4. Key Invariants](#4-key-invariants)
- [5. Error Cases](#5-error-cases)
- [6. Verification](#6-verification)
- [7. Nostr Delivery Security](#7-nostr-delivery-security)

## 1. Overview

A private transfer allows a sender to move tokens to a receiver without revealing the amount or recipient on the public L2 state. The flow uses a shielded note system:

1. The **sender** creates a private note, generates a ZK proof, and publishes it via Nostr.
2. The **receiver** discovers the note, verifies the proof, and submits a `private_claim` to credit the amount to their L2 balance.

The key cryptographic primitive is the `PrivateNoteInclusionCircuit`, which proves that a note exists in the note tree and that the sender is authorized to spend it. The L2 `private_claim` method does not re-verify that proof; it binds the UPS session proof tree to the circuit's minifier fingerprint `private_note_inclusion_fingerprint`. Updating that constant is a separate compiler/Genesis procedure: `docs/src/dev/token-privacy-circuit-fingerprints.md`.

## 2. Architecture

### Roles

| Role | Component | Responsibility |
|------|-----------|----------------|
| Sender | CLI / Wallet | Creates note, generates ZK proof, publishes via Nostr |
| Receiver | CLI / Wallet | Discovers note, verifies proof, claims on L2 |
| Psy Services | `psy-services` | Indexes Nostr events, provides claimable API |
| Nostr Relay | Nostr server | Delivers encrypted note metadata to receiver |

### Cryptographic Primitives

| Primitive | Description |
|-----------|-------------|
| Shield Address | `PoseidonHash(user_id, 1337, r0, r1)` — derives a shielded receiving address from the user's L2 ID and two random values |
| Note Commitment | `PoseidonHash(nullifier_secret || note_secret)` — binds the nullifier to the note |
| Nullifier Hash | `PoseidonHash(nullifier_secret)` — public nullifier used for spend tracking |
| PrivateNoteInclusionCircuit | ZK circuit proving the note exists in the note tree and the sender is authorized to spend it |

## 3. Private Transfer Flow

### Preconditions

1. Both sender and receiver are registered L2 users with assigned `user_id` values.
2. The sender has sufficient public L2 token balance for the transfer amount and transaction fee.
3. The receiver has sufficient L2 PSY balance to pay the claim transaction fee (the claim itself burns a fee).
4. Release binaries are used for all operations.

### Step 1: Derive Receiver Shield Address

The receiver derives a shield address using two random values (`r0`, `r1`) and either their private key or a known `user_id`:

```text
shield_address = PoseidonHash(user_id, 1337, r0, r1)
```

The receiver must remember `r0` and `r1` — they are required to claim the note. `psy_user_cli derive-shield` prints `shield_address`; the private-key path also prints the Nostr npub (`client_prover/psy_cli/psy_user_cli/src/subcommand/shield_address.rs:66-112`, `args.rs:823-835`).

### Step 2: Execute Private Transfer

The sender calls `private-transfer` with the receiver's shield address. Its public parameters (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:704-728`):

| Flag | Operator-supplied value | Notes |
|------|--------------------------|-------|
| `--rpc-config` | RPC config path | Defaults to `config.json`; also reads from the environment |
| `--contract-id` | token contract ID | Defaults to `0` |
| `--amount` | transfer amount | Positive integer |
| `--receiver` | receiver's shield address | Alias `--owner` |
| `--note-root-slot` | `2147483649` | Default value, shown explicitly |
| `--nostr-recipient-pubkey` | receiver's npub | Routes the backup delivery |
| `--output` | output file path | Defaults to `note_proof.json` |

**Signing-key constraint — blocked:** the current `private-transfer` and `private-claim` CLIs accept the signing key only through `-p/--private-key` (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:686-687,708-709`); they have no environment or keystore alternative. Every invocation therefore places the key in the process argument list, where other processes and argv logging can read it, and no shell technique — quoted variables, `read -rs`, or history tricks — removes that exposure. This violates the credential-handling rule this runbook applies everywhere else, so no executable example is shown. The concrete missing prerequisite is secure key input on these two commands: an environment-sourced key read without echo, or a keystore-path alternative, defined in `args.rs`. Until that lands, this step cannot be run compliantly; the parameter rows above are unaffected.

**Internal execution path:**

1. The sender's wallet session generates a transaction trace (`generate_tx_trace`).
2. The trace is proven (`prove_tx_trace`) — this includes the `private_transfer` contract call, burn fee, and end-cap proof.
3. The transaction is signed and submitted to L2.
4. After inclusion, a `PrivateNoteInclusionCircuit` proof is generated and written to the output file.

**Output: `NoteProofOutput`**

| Field | Type | Description |
|-------|------|-------------|
| `nullifier` | u64×4 | Nullifier hash of the spent note |
| `owner` | u64×4 | Receiver's shield address |
| `amount` | string | Transfer amount |
| `user_tree_root` | u64×4 | User tree root at proof time |
| `checkpoint_id` | string | L2 checkpoint when proof was generated |
| `note_root_slot` | string | Slot index in the note tree |
| `note_proof_fingerprint` | u64×4 | Circuit fingerprint for verifier data lookup |
| `note_proof` | byte array | Bincode-serialized `ProofWithPublicInputs` |

### Step 3: Nostr Delivery (Two-Event Protocol)

The sender publishes two Nostr events keyed by the same `backup_id` (= `note_commitment`):

**Event 1 — Plaintext proof metadata:**

| Field | Value |
|-------|-------|
| `kind` | 1059 |
| `t` tag | `psy_private_transfer_proof` |
| `content` | Plaintext JSON containing the `PrivateNoteInclusionCircuit` proof |
| `tags` | `p=<recipient_npub>`, `backup_id=<note_commitment>`, `shield_address`, `nullifier` |

**Event 2 — Encrypted claim material:**

| Field | Value |
|-------|-------|
| `kind` | 1059 |
| `t` tag | `psy_private_transfer_secrets` |
| `content` | NIP-59 encrypted JSON containing encrypted claim metadata |
| `tags` | `p=<recipient_npub>`, `backup_id=<same note_commitment>` |

The two-event design separates the public proof (verifiable by anyone) from the encrypted claim material (only the receiver can decrypt). Services indexes Event 1 and verifies it with `PrivateNoteInclusionCircuit`. Event 2 is stored as opaque encrypted data and returned to the receiver via the claimable API.

### Step 4: Receiver Discovers Claimable Note

The receiver discovers claimable private transfers via the psy-services API:

```text
POST /api/v1/wallet/private-claimable
{
  "nostr_pubkeys": [<receiver_npub>],
  "shield_addresses": [<receiver_shield_address>],
  "token_contract_ids": [<token_ids>]
}
```

The response includes items with `kind: "private_transfer"`, each containing:
- `note_proof_raw`: the serialized `PrivateNoteInclusionCircuit` proof
- `nullifier_hash`: the spent nullifier
- `amount`, `shield_address`, `token_contract_id`

Items already flagged as `claimed` by the indexer are excluded.

### Step 5: Execute Private Claim

The receiver claims the note by submitting a `private_claim` contract call. Its public parameters (`client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:682-702`):

| Flag | Operator-supplied value | Notes |
|------|--------------------------|-------|
| `--rpc-config` | RPC config path | Defaults to `config.json`; also reads from the environment |
| `--contract-id` | token contract ID | Defaults to `0` |
| `--note-proof` | note proof file path | The Step 2 output, or Nostr-delivered material saved to a file |
| `--nostr-secret-key` | optional Nostr signing key | Secret; argv-only like the signing key, so the same constraint applies |
| `--random0` / `--random1` | receiver's retained `r0` / `r1` | Claim material from Step 1 |

The Step 2 signing-key constraint applies unchanged to the receiver's key: the CLI still accepts it only as `-p` or `--private-key`, and the step stays blocked until the same secure key input prerequisite lands. No executable example is shown.

**Internal execution path:**

1. The `NoteProofOutput` is loaded from file (or received from Nostr via services).
2. The `PrivateNoteInclusionCircuit` proof is deserialized.
3. A `ClaimBatchItem::PrivateTransfer` is constructed with the note proof and receiver's `r0`/`r1`.
4. `WalletSession::claim_batch()` is called:
   - Starts the receiver's proving session.
   - Inserts the note proof as an external proof via `add_external_proof()`.
   - Builds `private_claim` inputs from the note data, leaf proof, and proof index.
   - Proves the `private_claim` contract call.
   - Proves the burn fee.
   - Signs and submits.
5. The L2 contract verifies the proof and credits the receiver's balance.
6. The nullifier is recorded in the claim nullifier tree.

**Output:** A 9-felt `PrivateClaimEvent` is emitted on L2, and `psy-services` records the claim in `nullifier_claims`.

## 4. Key Invariants

### 1. Proof is Sender-Generated, Receiver-Submitted

The `PrivateNoteInclusionCircuit` proof is generated entirely by the sender. The receiver does not need any private inputs beyond `r0`/`r1` (which they chose) to claim the note. The proof is a complete spending authorization — the receiver simply submits it.

### 2. Nullifier Uniqueness

Each private note has a unique `nullifier_hash = PoseidonHash(nullifier_secret)`. Once claimed, the nullifier is recorded in the L2 claim nullifier tree. A second claim attempt using the same proof is rejected:

```text
assertion failed: nullifier already claimed
```

### 3. Shield Address Binding

The `owner` field in the `NoteProofOutput` is the receiver's shield address (`PoseidonHash(user_id, 1337, r0, r1)`). The claiming user must match this address. Using a different private key or different `r0`/`r1` values results in:

```text
receiver does not match claiming user
```

### 4. Fee Requirement for Claim

The receiver must have sufficient L2 PSY balance to pay the claim transaction fee. The `private_claim` call includes a burn fee step. A receiver with zero L2 balance cannot claim.

### 5. External Proof Ordering

In the proving session, the external proof (note inclusion) must be inserted **before** the `private_claim` contract call step. The proof tree root changes after external proof insertion, and the claim inputs reference the new root. This ordering is enforced by `claim_batch()`.

## 5. Error Cases

| Error | Cause | Resolution |
|-------|-------|------------|
| `receiver does not match claiming user` | Wrong private key or wrong `r0`/`r1` | Ensure the receiver key and randoms match the shield address |
| `nullifier already claimed` | Note was already claimed by someone | Check claim status before attempting |
| `insufficient balance for fee` | Receiver has no L2 PSY for gas | Fund the receiver through `docs/src/dev/common-operations.md` Section 5.1; genesis `mint` is not available to devnet wallets |
| `note proof deserialization failed` | Corrupted or wrong format proof file | Regenerate the proof file |
| `stale trace anchor` | Checkpoint advanced during proving | Regenerate trace with fresh anchor |
| `proof tree root mismatch` | `private_note_inclusion_fingerprint` or the PI `hash([...])` list does not match the circuit that produced the session leaf | Follow `docs/src/dev/token-privacy-circuit-fingerprints.md` |

## 6. Verification

### Verifying the Transfer Succeeded

1. Check the sender's L2 balance decreased by `amount + fee`.
2. Check the note tree root advanced (new leaf inserted at `note_root_slot`).
3. Verify the `NoteProofOutput` file contains valid proof bytes.

### Verifying the Claim Succeeded

1. Check the receiver's L2 balance increased by `amount`.
2. Query the L2 claim nullifier tree for the note's `nullifier_hash` — it should be present.
3. Check `psy-services` `nullifier_claims` table for a record with `claim_type=transfer`.
4. Attempting the same claim again should fail with `nullifier already claimed`.

## 7. Nostr Delivery Security

- Event 1 (proof metadata) is published in plaintext. It contains the ZK proof and public inputs, which are safe to share — the proof reveals nothing about the private inputs.
- Event 2 (claim material) is encrypted via NIP-59 gift wrap to the receiver's Nostr public key. Only the receiver can decrypt it.
- Services does not decrypt Event 2. It stores it as opaque encrypted data and returns it to the receiver via the claimable API.
- The `backup_id` (= `note_commitment`) links the two events. Services uses it to join the proof metadata with the encrypted claim material.