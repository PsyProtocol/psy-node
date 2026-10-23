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

`encode_record` / `decode_record` (`psy_cli/guardian_common/src/protocol.rs`) wrap exact inner bytes. Little-endian layout: `PSYGR001` (8) | version `u32` `1` | uncompressed length `u64` | one zstd frame at level `3`. The compressed frame is capped at 128 MiB including the 20-byte header. The uncompressed payload is capped at `MAX_BODY_BYTES` (128 MiB). `MAX_SESSION_RECORD_BYTES` is that same 128 MiB for a session or relayer row, because a session page must still pass `GuardianSessionsResponse::to_bytes`. Decode checks the magic, the version, the zstd magic, and that the inflated length equals the advertised length.

The inner business request is unchanged `PSYGS002`: magic, `schema_version` `2`, network magic, user id, session nonce, operation, the original trace text, deposit anchors, and withdrawal records. `request_id` is `sha256` of those canonical bytes. Compression does not drop code, trace, signature, or proof bytes and does not re-fetch them from RPC.

### HTTP

`POST /v1/sign-session` requires `Content-Type: application/vnd.psy.guardian-record+zstd`. The body is `encode_record` of the canonical request JSON (`limit` `MAX_BODY_BYTES`). Any other media type, including `application/json`, is `415` with an empty `application/json` body. The success body and `GuardianSignErrorResponse` stay `application/json`. There is no `Content-Encoding: zstd`.

`GET /v1/sessions` negotiates with `Accept` (`session_representation`). No `Accept`, accepted `application/json`, or a higher-quality JSON / `*/*` entry returns the same JSON page as before. `application/vnd.psy.guardian-record+zstd` at a positive quality not beaten by JSON or `*/*` returns `encode_record` of that JSON (`limit` `MAX_SESSION_RECORD_BYTES`) and sets that custom type as `Content-Type`. Quality `0` excludes a type. A request that accepts neither is `406`. Responses set `Vary: accept`. The relayer history client sends the custom type on `Accept` and continues only for that type or `application/json`.

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
