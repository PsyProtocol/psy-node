# psy_relayer_cli (Bridge Commands)

Proposer CLI wired to `gnark-plonky2-verifier`.

## Commands

```bash
cargo run -p psy_relayer_cli -- generate-groth16 \
  <common_circuit_data.json> \
  <proof_with_public_inputs.json> \
  <verifier_only_circuit_data.json> \
  <keystore_dir> \
  <out_proof.json> \
  <out_vk.json>

cargo run -p psy_relayer_cli -- verify-groth16 \
  <proof.json> <vk.json>

cargo run -p psy_relayer_cli -- export-solidity-verifier \
  <keystore_dir> <out_verifier.sol>
```

## Notes

- Current implementation uses the Rust FFI crate `gnark-plonky2-verifier-ffi`; it no longer shells out through a local Go adapter directory.
- Any local checkout path for `gnark-plonky2-verifier` should be configured in the FFI dependency layer, not hardcoded in this README.
- `generate-groth16` / `verify-groth16` currently use uncompressed proof/vk only.

## Guardian request archive

The relayer archive advances each frozen request through `Request → Signed → Proved → Included`.
Signing and proving preserve the request bytes, account identity derived from the configured member hashes, and deposit prefixes;
proving also preserves the collected signatures. Exact retries keep the current stage and
proof, while conflicting payloads and backward transitions are rejected. Authenticated
inclusion commits the account checkpoint, deposit prefixes, and withdrawal indexes together.
`relayer_request` keeps the latest `Included` row and at most one unresolved next request. The schema-3 compression migration is lossless and bumps the schema marker 2→3: every existing request row stays until the next authenticated import deletes the older ones in that commit. Bounded retention required no further marker bump. Only those large request rows are bounded. Withdrawal indexes and `retired_claim_withdrawals` still grow. Freed redb pages are reused; the file shrinks only by an offline compact. A Guardian exactly one session behind can catch up from the retained `Included` row. A larger gap stays unavailable. Deleting the database and starting over is not supported, and a saved copy of the previous `Included` row does not recover the gap without the checkpoint's canonical conditions. Pruning is not a rollback or timeout repair.

### Schema 3

Each of the four journals is its own redb file and its own transaction. A commit in one file does not commit the other three.

Guardian `db/guardian-{id}.redb` (`guardian_common::db`, marker `guardian_schema` `u32` **3**) has exactly these eight tables:

| Table | Key | Value |
|---|---|---|
| `deposit_tree_states` | `(network_magic, user_id, chain_index)` | bincode `DepositTreeState` |
| `guardian_account` | `(network_magic, user_id)` | bincode `GuardianAccount` |
| `guardian_schema` | `()` | `u32` marker `3` |
| `guardian_session` | `(network_magic, user_id, nonce)` | `PSYGR001` envelope of bincode `GuardianSession` |
| `guardian_signed` | `(network_magic, user_id, nonce)` | `PSYGR001` envelope of bincode `GuardianSigned` |
| `guardian_signer` | `()` | compressed signing key `[u8; 33]` |
| `guardian_withdrawal_nonce` | `(network_magic, user_id, chain_index, nonce)` | `u64` |
| `included_withdrawal_burns` | `(network_magic, user_id, sender, token_contract, burn_nonce)` | `u64` |

On a successful `import_session` of nonce `N`, `prune_imported_history` deletes this account's `guardian_signed` rows through `N` (included bound) and `guardian_session` rows strictly below `N` (excluded bound). Session `N` stays. Signed rows above `N` stay. Deposit, account, and both withdrawal indexes are not pruned (`psy_cli/guardian_common/src/db.rs:777-787`).

Relayer `db/relayer.redb` (`journal_schema` `u64` **3**) has exactly these eight tables:

| Table | Key | Value |
|---|---|---|
| `journal_schema` | `()` | `u64` marker `3` |
| `chain_claims` | `u8` `chain_index` | `ChainClaims` (`pending_claim_withdrawals`, `claim_retry`, `retired_claim_withdrawals`) |
| `finalization_batch` | `()` | `pending_finalization_range` plus `finalized_chains` |
| `guardian_account` | `(network_magic, user_id)` | bincode `GuardianAccount` |
| `deposit_tree_states` | `(network_magic, user_id, chain_index)` | bincode `DepositTreeState` |
| `included_withdrawal_burns` | `(network_magic, user_id, sender, token_contract, burn_nonce)` | `u64` |
| `guardian_withdrawal_nonce` | `(network_magic, user_id, chain_index, nonce)` | `u64` |
| `relayer_request` | `u64` `session_nonce` | `PSYGR001` envelope of the canonical JSON stage row. Steady state: latest `Included` plus at most one unresolved next nonce. Migration keeps every row until the next authenticated import |

Startup of either database accepts a tableless redb file or that exact eight-table set with marker `3`. A zero-length file, marker `2`, a partial set, and any other table set are rejected. Neither open migrates them.

### Record envelope

`encode_record` / `decode_record` (`psy_cli/guardian_common/src/protocol.rs`) wrap exact inner bytes. Little-endian layout: `PSYGR001` (8) | version `u32` `1` | uncompressed length `u64` | exactly one zstd frame at level `3`. There is no fixed decoded or compressed cap; the declared uncompressed length is the only size statement and it must be exact. Decode checks the magic, the version, the zstd magic, and that the inflated length equals the advertised length, rejecting any excess frame output. Request work is bounded by the request deadline and the service concurrency limits, not by a memory ceiling. JSON rows and responses keep the same identifiers and no schema bump accompanies the removed caps; a binary record representation is not implemented yet.

The inner business request is `PSYGS002`: magic, `schema_version`, network magic, user id, session nonce, operation, trace text, deposit anchors, and withdrawal records; `request_id` is `sha256` of those canonical bytes. New relayer requests use `schema_version` `3`: the trace encodes its seven heavy byte fields as standard base64 instead of JSON digit arrays, still carrying the full code and trace bytes — nothing is dropped or re-fetched from RPC. `schema_version` `2` remains a retained-row reader for stored journal rows, which are never rewritten, so old `request_id` values stay valid. Deploy only after the drain gate: every schema-2 request settled to `Included` and no unsigned journal rows, on every guardian and the relayer.

### HTTP

`POST /v1/sign-session` requires `Content-Type: application/vnd.psy.guardian-record+zstd`. The body is `encode_record` of the canonical request JSON. Any other media type, including `application/json`, is `415` with an empty `application/json` body. The success body and `GuardianSignErrorResponse` stay `application/json`. There is no `Content-Encoding: zstd`.

`GET /v1/sessions` negotiates with `Accept` (`session_representation`). No `Accept`, accepted `application/json`, or a higher-quality JSON / `*/*` entry returns the same JSON page as before. `application/vnd.psy.guardian-record+zstd` at a positive quality not beaten by JSON or `*/*` returns `encode_record` of that JSON and sets that custom type as `Content-Type`. Quality `0` excludes a type. A request that accepts neither is `406`. Responses set `Vary: accept`. The relayer history client sends the custom type on `Accept` and continues only for that type or `application/json`.

### Offline migration

`migrate-guardian-journals` is the only schema-2 to schema-3 path. Stop all three guardians and the relayer first. `--rpc-config` and `--guardian-root` are required; repeat `--l1-config` only to replace `l1_config_url`:

```bash
psy_relayer_cli migrate-guardian-journals \
  --rpc-config <rpc-config.json> \
  --guardian-root <guardian-root> \
  [--l1-config <deployment.json> ...]
```

Repeat `--l1-config` to replace `l1_config_url`, the same way `guardian-service` does. The command loads `GuardianConfig` and does not open keystores or read `GUARDIAN_{1,2,3}_KEYSTORE_PASSWORD`. Signer identity is the existing `guardian_signer` singleton; `migration_signer` checks that compressed key and does not prove key possession. Normal guardian startup still authenticates the keystore. It does not write config, keystores, or password files.

It opens the four existing `db/guardian-1.redb`, `db/guardian-2.redb`, `db/guardian-3.redb`, and `db/relayer.redb` files and holds all four exclusive handles before any migration call. It does not create a missing file. Each database then commits alone, in order guardian 1, 2, 3, relayer. Failure before that database's commit leaves it unchanged. Failure after its commit can leave that database already migrated. Earlier commits remain. Marker `3` is validated and not rewritten, so a stopped run can be repeated. Guardian output is `database=<name> schema=3 signed_rows=<n> session_rows=<n> rewritten=<bool>`. Relayer output is `database=relayer.redb schema=3 request_rows=<n>`.

Deposit cold scans use the in-memory `ChainEndpoint.deployment_block` as an inclusive lower bound. A local `--l1-config` summary takes that bound from its sibling `Bridge_Proxy.json`: `address` must match the summary bridge, and the value is `receipt.blockNumber`. A remote `l1_config_url` registry requires `deployment_block` on every `l1_chains` entry. A missing value fails startup. There is no block-zero fallback and no automatic remote migration (`psy_cli/guardian_common/src/runtime.rs:188-315`).

## Withdrawal batch claims

`batchClaimWithdrawal` pays small withdrawals directly (`WithdrawalClaimed`) and registers medium/governed withdrawals as pending (`WithdrawalPendingCreated`). Medium payouts use `claimPendingWithdrawal` after `claimableAt`. Large withdrawals or withdrawals crossing the token lifetime cap require the governance executor's `forceClaimWithdrawal`, which also enforces `claimableAt`. The CLI counts either direct payment or pending registration as a successfully submitted slot; `Registered` is the queue-resolution outcome, not proof that every slot is still pending.

One transaction carries up to 32 slots. The proof, the public inputs, and the slot-data commit are all-or-nothing: a bad proof, a root that is neither the current `withdrawalSubtreeRoot` nor historically known, a bad `realCount`, a `bridgeUserId` mismatch, a commit mismatch, or nonzero padding reverts the whole transaction and registers nothing.

Per-slot failures do not revert. The contract returns `failedSlotIndexes` and `failureReasons`, parallel arrays of the failed slots only, but a mined transaction has no return data, so the receipt is the only record. It carries one `WithdrawalClaimBatchResult(batchCommit, realCount, succeededCount, failedCount)` and one `WithdrawalClaimItemFailed(nonce, slotIndex, reason)` per failed slot. `parse_claim_receipt` accepts the receipt only when the summary names the commit and real count actually sent, the failed events reproduce that summary with each slot's own nonce, and every counted success has exactly one `WithdrawalPendingCreated` or `WithdrawalClaimed` (never both). Anything else fails the whole chunk with nothing resolved. The same nonce can appear in both event kinds when two slots share it; `slotIndex` distinguishes them.

### Reason codes

The contract emits reasons 1 through 10, named exactly `CLAIM_REASON_ADDRESS_HIGH_BITS` (1), `CLAIM_REASON_WRONG_DESTINATION_CHAIN` (2), `CLAIM_REASON_ZERO_ADDRESS` (3), `CLAIM_REASON_ZERO_AMOUNT` (4), `CLAIM_REASON_NULLIFIER_ALREADY_CLAIMED` (5), `CLAIM_REASON_TOKEN_NOT_CONFIGURED` (6), `CLAIM_REASON_REGISTRATION_PAUSED` (7), `CLAIM_REASON_AMOUNT_OUT_OF_RANGE` (8), `CLAIM_REASON_TOTAL_AMOUNT_OVERFLOW` (9), and `CLAIM_REASON_CLAIMABLE_AT_OVERFLOW` (10). `0` means valid; `11..255` are reserved. A receipt event whose reason is outside `1..=10` makes the whole receipt unusable.

### Reason 5 is a consumed nonce, not this leaf

`WithdrawalPendingCreated` carries nonce, token, recipient, amount, and claimable time. It does not carry sender, contract, or destination. The same payout tuple can belong to a different sender. Reason 5 therefore stays `NonceConflict` and is terminal. A historical or pending payout tuple never upgrades it to already claimed. The only success is the slot in this same transaction whose own `WithdrawalPendingCreated` or `WithdrawalClaimed` matches that slot and is the only slot with that nonce. CLI and frontend status readers have the same limitation: they cannot invent a sender field from these events.

Registration is decided only by the receipt of the claim transaction itself: a historical or pending payout tuple under the same nonce is never treated as this leaf's claim, and no fresh-claim eligibility filter runs before the send.

### How a leaf is classified today

The pending claim queue, the attempt ledger, and the retired set are all keyed by the full leaf hash. `event_id` is only the indexed append ordering of the source-chain event, never a queue key: an imported row carries `0` where a replayed event carries the real index, and that difference is not a content conflict. An equal full leaf already queued is skipped, while distinct leaves that share a nonce each keep their own entry.

`submit_batch` returns one `ClaimOutcome` per attempted slot, in source order, so identical-leaf duplicates keep their own outcomes. `daemon::record_claim_outcome` accounts each unique leaf once — a registration wins, otherwise an unresolved signed transaction outranks an ordinary failure — and removes a pending leaf only for that leaf's own `Registered` outcome. `Terminal` retires that leaf, `OperatorPending` and `Held` spend no attempt, and only `AttemptSpent` counts. A generic whole-batch error records at most one strike per leaf and never clears a hold. Registration is not payout. Reason 5 does not remove a different sender's leaf. Every indexed row is one slot, in `(destination_chain_index, event_id)` order. L1 returns one `WithdrawalClaimItemFailed(nonce, slotIndex, reason)` per failed slot. Reasons 1 through 10 map to `HighAddress`, `WrongChain`, `ZeroAddress`, `ZeroAmount`, `NonceConflict`, `TokenNotConfigured`, `RegistrationPaused`, `AmountOutOfRange`, `TotalOverflow`, and `ClaimableOverflow`.

A signed claim hash is written to the existing per-leaf `ReceiptUnknown` hold before broadcast, reloading the saved state so earlier chunks remain. The daemon re-adopts those persisted holds when the batch fails, so the caller state stays the single authoritative copy and a round's save cannot overwrite a known hash with a stale absence. Only a local fill or sign rejection spends `SendFailed`. A JSON-RPC response error, transport error, or timeout keeps the hash. Delayed receipts decode the recorded transaction input after its block and hash are canonical, and one recorded transaction is read once for every pending leaf held on it: receipt, pin, and decoded batch are shared, so a full batch is applied once for all its leaves instead of one re-apply per leaf. A failed or invalid decode keeps the hash and does not spend an attempt.

| `ClaimAction` | `ClaimCode`s |
|---|---|
| `Terminal` | `HighAddress`, `WrongChain`, `ZeroAddress`, `ZeroAmount`, `AmountOutOfRange`, `NonceConflict` |
| `OperatorPending` | `TokenNotConfigured`, `RegistrationPaused`, `TotalOverflow`, `ClaimableOverflow` |
| `Held` | `ProofNotReady`, `RpcUnavailable`, `ReceiptUnknown`, `FeeRefused`, `LiquidityShort` |
| `AttemptSpent` | `MalformedReceipt`, `RootUnauthorized`, `ProofDataInvalid`, `ProofGenerationFailed`, `SendFailed`, `BatchReverted` |
