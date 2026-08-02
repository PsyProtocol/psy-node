# Private Transfer Flow

This document describes the private transfer and private claim flow on the Psy protocol. It is intended for auditors and integrators who need to verify the correctness of shielded transfers between users.

## Overview

A private transfer allows a sender to move tokens to a receiver without revealing the amount or recipient on the public L2 state. The flow uses a shielded note system:

1. The **sender** creates a private note, generates a ZK proof, and publishes it via Nostr.
2. The **receiver** discovers the note, verifies the proof, and submits a `private_claim` to credit the amount to their L2 balance.

The key cryptographic primitive is the `PrivateNoteInclusionCircuit`, which proves that a note exists in the note tree and that the sender is authorized to spend it.

## Architecture

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

## Private Transfer Flow

### Preconditions

1. Both sender and receiver are registered L2 users with assigned `user_id` values.
2. The sender has sufficient public L2 token balance for the transfer amount and transaction fee.
3. The receiver has sufficient L2 PSY balance to pay the claim transaction fee (the claim itself burns a fee).
4. Release binaries are used for all operations.

### Step 1: Derive Receiver Note Owner

The receiver derives a shielded note owner using their private key and two random values (`r0`, `r1`):

```
note_owner = PoseidonHash(user_id, 1337, r0, r1)
```

The receiver must remember `r0` and `r1` — they are required to claim the note later. The `derive-note-owner` CLI command outputs the note owner hash and optionally a Nostr npub for delivery.

### Step 2: Execute Private Transfer

The sender calls `private-transfer` with the receiver's note owner:

```
psy_user_cli private-transfer \
  --rpc-config <config> \
  -p <sender_private_key> \
  --contract-id <token_contract_id> \
  --amount <amount> \
  --receiver <receiver_note_owner_hash> \
  --note-root-slot 8388609 \
  --output <output_file>
```

**Internal execution path:**

1. The sender's wallet session generates a transaction trace (`generate_tx_trace`).
2. The trace is proven (`prove_tx_trace`) — this includes the `private_transfer` contract call, burn fee, and end-cap proof.
3. The transaction is signed and submitted to L2.
4. After inclusion, a `PrivateNoteInclusionCircuit` proof is generated and written to the output file.

**Output: `NoteProofOutput`**

| Field | Type | Description |
|-------|------|-------------|
| `nullifier` | u64×4 | Nullifier hash of the spent note |
| `owner` | u64×4 | Receiver's note owner hash |
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

```
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

The receiver claims the note by submitting a `private_claim` contract call:

```
psy_user_cli private-claim \
  --rpc-config <config> \
  -p <receiver_private_key> \
  --contract-id <token_contract_id> \
  --note-proof <note_proof_file> \
  --random0 <r0> \
  --random1 <r1>
```

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

## Key Invariants

### 1. Proof is Sender-Generated, Receiver-Submitted

The `PrivateNoteInclusionCircuit` proof is generated entirely by the sender. The receiver does not need any private inputs beyond `r0`/`r1` (which they chose) to claim the note. The proof is a complete spending authorization — the receiver simply submits it.

### 2. Nullifier Uniqueness

Each private note has a unique `nullifier_hash = PoseidonHash(nullifier_secret)`. Once claimed, the nullifier is recorded in the L2 claim nullifier tree. A second claim attempt using the same proof is rejected:

```
assertion failed: nullifier already claimed
```

### 3. Note Owner Binding

The `owner` field in the `NoteProofOutput` is the receiver's note owner hash (`PoseidonHash(user_id, 1337, r0, r1)`). The claiming user must match this owner. Using a different private key or different `r0`/`r1` values results in:

```
receiver does not match claiming user
```

### 4. Fee Requirement for Claim

The receiver must have sufficient L2 PSY balance to pay the claim transaction fee. The `private_claim` call includes a burn fee step. A receiver with zero L2 balance cannot claim.

### 5. External Proof Ordering

In the proving session, the external proof (note inclusion) must be inserted **before** the `private_claim` contract call step. The proof tree root changes after external proof insertion, and the claim inputs reference the new root. This ordering is enforced by `claim_batch()`.

## Error Cases

| Error | Cause | Resolution |
|-------|-------|------------|
| `receiver does not match claiming user` | Wrong private key or wrong `r0`/`r1` | Ensure the receiver key and randoms match the note owner |
| `nullifier already claimed` | Note was already claimed by someone | Check claim status before attempting |
| `insufficient balance for fee` | Receiver has no L2 PSY for gas | Fund receiver with `simple_mint` first |
| `note proof deserialization failed` | Corrupted or wrong format proof file | Regenerate the proof file |
| `stale trace anchor` | Checkpoint advanced during proving | Regenerate trace with fresh anchor |

## Verification

### Verifying the Transfer Succeeded

1. Check the sender's L2 balance decreased by `amount + fee`.
2. Check the note tree root advanced (new leaf inserted at `note_root_slot`).
3. Verify the `NoteProofOutput` file contains valid proof bytes.

### Verifying the Claim Succeeded

1. Check the receiver's L2 balance increased by `amount`.
2. Query the L2 claim nullifier tree for the note's `nullifier_hash` — it should be present.
3. Check `psy-services` `nullifier_claims` table for a record with `claim_type=transfer`.
4. Attempting the same claim again should fail with `nullifier already claimed`.

## Nostr Delivery Security

- Event 1 (proof metadata) is published in plaintext. It contains the ZK proof and public inputs, which are safe to share — the proof reveals nothing about the private inputs.
- Event 2 (claim material) is encrypted via NIP-59 gift wrap to the receiver's Nostr public key. Only the receiver can decrypt it.
- Services does not decrypt Event 2. It stores it as opaque encrypted data and returns it to the receiver via the claimable API.
- The `backup_id` (= `note_commitment`) links the two events. Services uses it to join the proof metadata with the encrypted claim material.