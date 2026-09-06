# Internal: Fn-Circuit Fingerprint and Uninitialized-Contract Proving Playbook

> Internal — NOT published to mdBook (dev/ section, no SUMMARY registration).
> Last updated: 2026-09-06
> Repositories: `psy-node`, `psy-compiler`, `psy-genesis`
> Context: audit-branch pure-node Plonky2 E2E; the three-layer faucet claim / EndCap-proposer failure chain.

## Overview

This document records the three-layer failure chain behind the 2026-09-06 E2E faucet claim and EndCap submission: root-cause evidence per layer, the fix pattern, verification commands, and measured pure-node devnet timings. Before changing any `DapenContractFunctionCircuit`, UPS signature circuit, or `UPSEndCapCircuit` constraint, read this document plus `docs/src/node/circuit-and-verifier-operations.md` first.

## 1. Layer 1: uninitialized-contract ZERO leaf vs empty tree root (circuit convention gap)

**Symptom**: prove-proxy reports `Partition containing VirtualTarget { index: N } was set twice with different values: <zero_hash_literal> != 0` (for example `8603459983426387388 != 0`, where the literal equals `CACHED_ZERO_HASHES[31]`, the empty tree root for a height-31 contract — confirm bit-exact).

**Root cause**: on an operator's first call into a contract, that contract is uninitialized in the user contract tree (UCON), so the leaf value is `ZERO`; but the session-side `get_call_start_data` returns `get_zero_hash(state_tree_height)` for uninitialized contracts (`psy_core/psy_data/src/qstore/controllers/proving_session.rs:621-641`). Any circuit that unconditionally `connect_hashes` the UCON leaf value to the contract storage start root conflicts on first use.

**Established convention** (documented by the UPS layer at `psy_network_circuit/src/ups/gadgets/ups_standard_cfc_state_delta.rs:193-230`): when `is_zero_hash(leaf_value)` is true, the start root must bind to the default empty tree root for the contract's compile-time height; otherwise exact equality.

**Fix pattern** (all four touch sites):

```rust
let default_root = builder.constant_hash(<H as MerkleZeroHasher<_>>::get_zero_hash(contract_state_tree_height));
let is_first = builder.is_zero_hash(<leaf_value_target>);
builder.connect_hashes_switch(is_first, <start_root_target>, default_root, <leaf_value_target>);
```

| Touch site | Location |
|---|---|
| DPN fn_circuit start-contract root | `psy_dpn_circuit/src/vm/compile.rs` (`get_self_user_current_contract_state_slot_hash` path) |
| UPS signature circuit, current contract | `psy_ups_circuit/src/signature/state_reader.rs:102` |
| UPS signature circuit, external | same file `:237` (`get_self_user_external_contract_state_slot_hash`, `slot_proof.root <- uct_proof.value`) |
| UPS signature circuit, other user | same file `:385` (`get_other_user_contract_state_slot_hash`, same pattern) |

**Localization method** (VT-index map, decisive rather than guesswork): replicate the circuit construction, record every `connect_hashes`/`connect` target index, and map the reported `VirtualTarget index N` back to its gadget. Reference: the `vt626_index_map` test in `psy_network_circuit/src/ups/circuits/ups_cfc_standard.rs` (cfg(test) diagnostic).

**Verification**: `cargo test --release -p psy_dpn_circuit` (ucon_leaf_prove_tests: uninitialized proves, initialized behavior unchanged, negative control reproduces the set-twice).

## 2. Layer 2: function-tree whitelist fingerprint mismatch (VT626, two non-zero values)

**Symptom**: `ups_cfc_standard_tx proving error: Partition containing VirtualTarget { index: 626 } was set twice: 7671487131530644792 != 4162245137908165195` (both values non-zero).

**Root cause**: the contract function tree whitelist leaves ARE the fn_circuit plonky2 circuit fingerprints (`psy_prover/src/session/session.rs:181`, `whitelist_leaves.push(c.get_fingerprint())`, interleaved with `(method_id, io_combo)` leaves). The function tree is chain state (`CONTRACT_FUNCTION_TREE_ID=4`, anchored at `PsyContractLeaf.function_tree_root`); genesis contracts bake their whitelist into genesis.json at generation time under the constraints in effect then. ANY `DapenContractFunctionCircuit` constraint change (including the layer-1 fix itself) shifts every fn_circuit fingerprint, so the on-chain old fingerprints no longer match the fresh runtime attest fingerprint (`ups_cfc_verify_inclusion.rs:87` equality).

**This is by design**: fingerprint binding guarantees only on-chain-registered circuits execute. The cost is that every fn_circuit constraint change requires the full regeneration chain (see section 4).

**Discrimination**: layer-1 error values hit the zero-hash table; layer-2 values are both non-zero (old vs new fingerprint limbs). Use the VT-index map to identify which side of the copy-connect conflicted (here: VT626 = function-tree leaf, VT297-300 = attest fingerprint, `connect_hashes(fn_fp, attest_fp)`).

## 3. Layer 3: EndCap proposer verification failure (Verifier Artifact Boundary)

**Symptom**: EndCap forward rejected by the proposer; the real error (not a schedule rejection) is `Condition failed: vanishing_polys_zeta[i] == z_h_zeta * reduce_with_powers(...)`.

**Root cause**: DPN/UPS circuit changes alter the EndCap circuit shape; the fresh proof mismatches the proposer's PROMOTED stale `END_CAP_ALT_VERIFIER_DATA_SERIALIZED` constant. This triggers the AGENTS.md End-Cap Verifier Artifact Boundary and trigger-matrix row 1 of `circuit-and-verifier-operations.md` (EndCap metadata: Yes, cache pair: Yes, Genesis outputs: No).

**Fix sequence** (authoritative commands in `circuit-and-verifier-operations.md` sections 4-5; quick form):

1. `PSY_CONFIG_PATH=<repo>/psy-genesis/config.json PSY_NETWORK=localhost cargo run --release -p psy_user_cli --no-default-features -- get-user-end-cap-common-data` (all four output records from one successful invocation; compare magic numerically against config.json, stop on mismatch)
2. Copy `alt_verify_data` verbatim into `psy_plonky2_circuits/src/circuit_library/end_cap_verifier_data.rs:27`; copy the `endcap_fingerprint_u64x4` limbs verbatim, in printed order, into the localhost constant — located at `psy_core/src/network_config/local_devnet.rs:17`, NOT in the verifier-data file (easy to miss)
3. `RUST_MIN_STACK=134217728 cargo run --release -p psy_plonky2_circuits --example config_gen_v2 --no-default-features --features std,serialize_rkyv,serialize_speedy,serialize_postcard`
4. Run the identical command a second time; both generated files must report "up to date"
5. `make build` -> `make shutdown` -> `PSY_SKIP_BUILD=1 PSY_SKIP_BRANCH_CHECK=1 PSY_SKIP_KEYSTORE=1 RUST_LOG=info make run-all`
6. Re-register users -> faucet claim (should still pass) -> resubmit the EndCap

**Forbidden**: `make config_gen_v2` or config_gen_v2 without `--no-default-features` (gnark-wrap mutates Groth16 setup).
**Not triggered**: genesis regeneration, token privacy fingerprints, Groth16/Bridge cohorts.

## 4. Full regeneration chain for fn_circuit constraint changes (node -> compiler -> genesis)

1. Commit the psy-node circuit delivery; record the SHA.
2. `../psy-compiler/Cargo.toml`: comment out the remote rev pins (:31-41) and enable the local path deps (:44-54) — the sanctioned local-dev mechanism, no push required.
3. In `../psy-compiler`: regenerate `Cargo.lock` through cargo, then `make check && make build`.
4. `make gen-deploy-json` — produces genesis.json with the new whitelist fingerprints plus token.json.
5. Verify both compiler-artifact stamps' `compilerRevision`.
6. `make shutdown` -> install the fresh genesis.json -> re-run the launcher setup (`injectGenesisValidators`; confirm the validators array is non-empty before starting processors) -> `make run-all`.
7. Re-register users -> faucet -> transfer.

**Forbidden**: hand-editing genesis.json fingerprints; adding [patch]/[replace] overrides for the pinned node revision.

## 5. Layer 4 addendum: checkpoint-metadata circular wait (realm processor)

Distinct from the three layers above, observed during the P2P E2E: `sync_with_coordinator` (`psy_node_common/src/realm/processor/db/sync.rs`) advanced `gathering_checkpoint_id` to the coordinator head without persisting checkpoint metadata, and `set_new_unique_ids` (`db/commit.rs:102-109`) published that base to the gatherer before its full checkpoint leaf row existed; `finalizer_identity` (`realm_end_cap_gatherer.rs:482`) then failed forever with `Checkpoint leaf not found for id N` because the serial runner cannot reach the metadata path while awaiting the Finalize reply. The durable fix persists the canonical metadata range through the synced head before any state advancement, including empty checkpoints, and drops the redundant second header-only startup fetch. See commit `0b7c23c0`.

## 6. Layer 5 addendum: peer vote validation rejects the finalizer root proof

The mandatory finalizer makes RealmFinalizeGUTA (circuit 63) the proposal root job, but the peer-side inference whitelist only knew the 13 ordinary GUTA types, so peers rejected every proposal and never voted; wait_votes timed out fatally. Fix: `infer_ordinary_guta_job_type` renamed to `infer_root_job_type` with the finalizer accepted through the registered runtime verifier data, fail-closed preserved. Verified live: peer vote received, certificate formed, and identical FFS end roots on proposer and non-proposer at checkpoint 431. See commit `f3e0ee3c`.

## 7. Measured timings (16-core 9950X, pure-node 2-realm stack, 2026-09-06)

| Item | Measured | Notes |
|---|---|---|
| prove-proxy warmup (before :9999 listens) | ~5-10 min | UPS circuit manager + contract function registration + BatchDeployContracts ~8000 rows; stretched by concurrent realm-processor prebuilds. :9999 listening means ready; :9998 (faucet) follows. Only investigate `prove_proxy_0_errs.txt` if :9999 is still absent after ~15 min |
| psy-node full release build | ~4-4.5 min | measured 4m23s after the promote |
| compiler local-path release build | ~2m16s | first full compile after the pin switch |
| `make gen-deploy-json` | minutes | produces a ~782MB genesis.json |
| config_gen_v2 cache run | ~1.5 min | stability loop requires two runs |
| coordinator empty-checkpoint cadence | ~5-8 s each | a fresh chain advances hundreds of checkpoints in minutes |
| validators injection | required after every restart | genesis.json `validators` is `[]` until the launcher injects |

## 8. Triage order

1. `PartitionWitness set twice` — check whether the literal hits `CACHED_ZERO_HASHES` (layer 1) or both values are non-zero (layer 2/3).
2. Layer 2 — use the VT-index map test to identify the copy-connect side: function-tree leaf vs attest fingerprint.
3. `vanishing_polys` — layer 3: check whether the promoted EndCap metadata predates the current circuit source.
4. `Checkpoint leaf not found` repeating — the realm-side metadata circular wait (section 4 addendum); check sync ordering before blaming lag.
5. Zero peer votes / wait_votes timeout — check whether the peer whitelist accepts the current root job type (layer 5).
6. Any circuit constraint change — pass the `circuit-and-verifier-operations.md` section 3.1 trigger matrix first, then follow section 4 (regeneration chain) or section 3 (promotion sequence) as required.