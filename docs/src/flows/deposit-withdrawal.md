# Deposit and Withdrawal Flow

This document describes the end-to-end bridge flow for L1→L2 deposits and L2→L1 withdrawals on the Psy protocol. It is intended for auditors and integrators who need to verify the correctness of the full bridge lifecycle.

## Overview

The bridge connects an EVM L1 (e.g. Ethereum, Anvil) to the Psy L2. Two assets flow across it:

- **Deposits** (L1→L2): A user locks ERC-20 tokens on L1 via the Router contract. A relayer proves the deposit on L2, after which the user claims the deposited amount on L2.
- **Withdrawals** (L2→L1): A user burns L2 tokens via a `withdraw` contract call. A relayer aggregates withdrawals and submits a Groth16 proof to L1, releasing the tokens to the original recipient.

## Architecture

### Roles

| Role | Component | Responsibility |
|------|-----------|----------------|
| Depositor | L1 wallet / CLI | Calls `Router.deposit()`, generates deposit inclusion proof |
| Bridge Relayer | `psy_relayer_cli` daemon | Proves deposits on L2, appends to L1 `Bridge.batchAppend()`, finalizes, claims withdrawals on L1 |
| Prove Proxy | `psy_prove_proxy` | Generates Groth16 proofs for withdrawal claims |
| Psy Services | `psy-services` | Indexes deposits/withdrawals, provides claim-proof API |
| L2 User | CLI / Wallet | Claims deposits on L2, initiates withdrawals |

### Contracts (L1)

| Contract | Purpose |
|----------|---------|
| `Router` | Entry point for deposits; delegates to `Gateway` |
| `ERC20Gateway` | Handles ERC-20 token deposits; calls `Bridge.recordDepositFromGateway()` |
| `Bridge` | Records deposit leaves, proves deposits via `batchAppend()`, releases withdrawals via `batchClaimWithdrawal()` |

### L2 Components

| Component | Purpose |
|-----------|---------|
| `deposit_tree` contract | Stores L1 deposit roots per chain index |
| `withdrawal_tree` contract | Stores L2 withdrawal leaves |
| Token contracts (e.g. PSY=0, USDT=4) | User balances and claim nullifier tracking |

## Deposit Flow (L1→L2)

### Preconditions

1. Local devnet is running with all services healthy (L1 RPC, coordinator, realms, relayer, psy-services, prove-proxy).
2. Contracts are deployed. Read addresses from `psy-contracts/deployments/localhost/deployed-contracts.json`.
3. The depositor has sufficient L1 ERC-20 balance and ETH for gas.
4. The depositor has approved the **ERC20Gateway** (not just the Router) to spend the deposit token.
5. The L2 user is registered and has an assigned `user_id`.

### Step 1: Generate Deposit Material

The receiver already owns a shield address. The depositor supplies claim material
for this specific deposit:

- `shield_address`: the receiver's existing shield receive address (from the
  wallet extension or a pasted `shield#npub` payload).
- `nullifier_secret`: 4 × u64 random values, freshly generated per deposit.
- `note_secret`: 4 × u64 random values, freshly generated per deposit.
- `note_commitment = PoseidonHash(nullifier_secret || note_secret)`.

The receiver-side `r0` / `r1` are **not** part of the sender-side
`DepositInclusionCircuit`; receiver ownership is checked later by
`claim_deposit`. The `note_commitment` binds the nullifier to the note,
preventing unauthorized claims.

### Step 2: Submit L1 Deposit

The depositor calls `Router.deposit(token, amount, shieldAddress, noteCommitment)` on L1.

- The Router delegates to the appropriate Gateway (ERC20 or ETH).
- The Gateway calls `Bridge.recordDepositFromGateway()` which computes the deposit leaf hash and stores it.
- The Bridge emits a `DepositRecorded` event with the deposit index and leaf hash.

**Deposit leaf encoding:**

```
leaf = keccak256(abi.encodePacked(
    shieldAddress,       // bytes32
    tokenBytes32,        // bytes32 (left-padded EVM address)
    l2TokenContractId,   // bytes32
    amount,              // uint256
    uint32(chainIndex),  // bridge chain index
    noteCommitment       // bytes32
))
```

### Step 3: Relayer Proves the Deposit

The bridge relayer daemon performs the following in a loop:

1. Fetches L1 pending deposits and computes the per-chain deposit root.
2. Submits L2 `deposit_tree.set_chain_root(chain_index, absolute_count, new_root)`.
3. Advances L1 `Bridge.provedDepositCount` to the same absolute target with one or more `batchAppend()` calls.
4. Finalizes the L2 state.

### Step 4: Wait for Deposit Claim Proof

Once the relayer has proven the deposit, the sender-side backup generator can
fetch a Merkle inclusion proof from psy-services:

```
GET /api/v1/bridge/deposit-claim-proof
    ?deposit_index=<index>
    &source_chain_index=<chain_index>
    &proved_deposit_count=<provedDepositCount>
    [&tree_count=<snapshotCount>]
```

The response contains:
- `found`: boolean indicating proof readiness
- `deposit_root`: root of the proven deposit tree
- `leaf_hash`: Poseidon deposit leaf hash
- `siblings`: Merkle path
- `deposit`: deposit payload (shield_address, token, amount, etc.)
- `chain_local_deposit_index` / `deposit_index`
- `proved_deposit_count` / `tree_count`: the snapshot count this proof was built against

### Step 5: Generate Deposit Inclusion ZK Proof

The depositor generates a `DepositInclusionCircuit` ZK proof using the Merkle
inclusion proof and the note material:

- **Private inputs (witnesses):** `nullifier_secret`, `note_secret`, `shield_address`
- **Public inputs:** `deposit_root`, `nullifier_hash`, `note_commitment`, `deposit_index`, token, amount, source chain index
- The proof is serialized as `deposit_proof_bincode_b64`.
- Nostr delivery uses a **two-event** protocol keyed by `backup_id = note_commitment`:
  - Event 1: `psy_deposit_proof` — plaintext proof metadata + `deposit_proof`
  - Event 2: `psy_deposit_secrets` — encrypted `nullifier_secret` +
    `note_secret`

### Step 6: Claim Deposit on L2

The receiver claims the deposit by submitting a `claim_deposit` contract call on L2:

- The sender-generated `deposit_proof_bincode_b64` is inserted as an external
  proof into the user's proving session.
- The claim consumes `nullifier_hash` and `note_commitment` (hashes, not raw
  secrets) alongside that ZK proof.
- The L2 contract verifies the proof and credits the receiver's balance.
- The nullifier is marked as spent in the claim nullifier tree.

**Verification of claim status:**

```
nullifier_hash = PoseidonHash(nullifier_secret)
claimKey = PoseidonHash(SHIELD_CLAIM_NAMESPACE, nullifier_hash)
isClaimed = query L2 IMT for claimKey in token contract
```

### Error Cases

| Error | Cause | Resolution |
|-------|-------|------------|
| `ERC20InsufficientAllowance` | ERC20Gateway not approved | Approve the Gateway, not just the Router |
| `proof not ready` | Relayer has not yet proven the deposit | Wait for `provedDepositCount` to advance |
| `shield_address mismatch` | r0/r1 or user_id inconsistent with deposit | Ensure the same user_id and r0/r1 are used |
| `nullifier already claimed` | Deposit was already claimed | Check `isDepositClaimed()` before attempting |
| `stale trace anchor` | Checkpoint advanced during proving | Regenerate trace with fresh anchor |

## Withdrawal Flow (L2→L1)

### Preconditions

1. The user has sufficient L2 token balance for the withdrawal amount.
2. The user has sufficient L2 PSY balance for the transaction fee.
3. The L2 token contract ID is known (e.g. PSY=0, USDT=4 on localhost).

### Step 1: Submit L2 Withdraw

The user calls the `withdraw` method on the appropriate L2 token contract:

```
inputs: [dest_chain_id, token_address_u32x8, amount_u32x8, recipient_u32x8, nonce]
```

- `dest_chain_id` is the **bridge chain index** (0 for local L1), not the EVM chain ID.
- `nonce` must be unique per withdrawal (a bytes32 value).
- `recipient` is the L1 address that will receive the funds.

### Step 2: Relayer Appends Withdrawal

The relayer daemon:
1. Scans pending withdrawals from psy-services.
2. Computes withdrawal leaf hashes using Poseidon (not keccak):
   ```
   leaf = PoseidonHash(sender_user_id_u32 ++ recipient_u32x8 ++ token_address_u32x8 ++ amount_u32x8 ++ nonce_u32x8 ++ dest_chain_index_u32)
   ```
3. Submits L2 `append_withdrawal` / `batch_append_withdrawals` contract calls.
4. Finalizes the L2 state.

### Step 3: Fetch Withdrawal Claim Proof

Once the withdrawal is finalized, psy-services provides a claim proof:

```
GET /api/v1/bridge/withdrawal-claim-proof
```

The response contains:
- `found`: boolean
- `leaf_index`: position in the withdrawal tree
- `withdrawal_root`: root of the withdrawal subtree
- `subtree_proof`: Merkle proof
- `withdrawal`: payload (recipient, token, amount, nonce, etc.)

### Step 4: Generate Groth16 Proof

The prove-proxy generates a Groth16 proof from the withdrawal claim proof:

- Input: `subtree_proof` + `withdrawal` payload
- Output: `solidity_proof[8]`, `public_inputs[18]`, `slot_data[1088]`

### Step 5: Submit L1 Claim

The relayer (or manual CLI) calls `Bridge.batchClaimWithdrawal()` on L1:

- Submits the Groth16 proof and public inputs.
- The Bridge verifies the proof, checks `claimedNullifiers[nonce]` is not already set, and releases the tokens.
- Emits `WithdrawalClaimed(nonce, recipient, token, amount)`.

**Idempotency check:**

```
isClaimed = Bridge.claimedNullifiers(raw_nonce_bytes32)
```

### Error Cases

| Error | Cause | Resolution |
|-------|-------|------------|
| `NullifierAlreadyClaimed()` | Relayer already claimed this withdrawal | Check `claimedNullifiers` before manual claims |
| `withdrawal-claim-proof not found` | Withdrawal not yet finalized | Wait for relayer to append and finalize |
| `bridge ERC20 liquidity insufficient` | Bridge contract lacks token balance | Deposit tokens to bridge first |
| `destination chain index out of range` | Used EVM chainId instead of bridge chain index | Use bridge chain index (0 for local) |

## Full Round-Trip Verification

A complete deposit→claim→withdraw→claim cycle:

1. **Deposit**: Lock tokens on L1 → relayer proves → L2 claim succeeds.
2. **Withdraw**: Burn tokens on L2 → relayer appends → L1 claim releases tokens.
3. **Balance verification**:
   - L1 token balance: `initial - deposit_amount + withdrawal_amount`
   - L2 token balance: `0 + deposit_amount - withdrawal_amount`
   - `Bridge.claimedNullifiers(withdrawal_nonce) == true`
   - L2 IMT shows deposit nullifier as claimed

## Key Invariants

1. **Deposit leaf binding**: `note_commitment = PoseidonHash(nullifier_secret || note_secret)` — the commitment cryptographically binds the nullifier to the note, preventing unauthorized claims.
2. **Nullifier uniqueness**: Each deposit and withdrawal has a unique nullifier. Double-claims are rejected by the L2 contract (deposits) or L1 contract (withdrawals).
3. **Proof split**: The `DepositInclusionCircuit` proof is generated by the depositor (sender-side) and consumed by the receiver. The receiver does not re-prove deposit inclusion.
4. **Relayer race**: The bridge relayer auto-claims withdrawals. Manual claims may race with the relayer and receive `NullifierAlreadyClaimed()`, which is an idempotent rejection, not an error.
5. **Bridge chain index**: Withdrawals use the bridge chain index (0-255), not the EVM chain ID. Confusing these causes `destination chain index out of range` errors.
