# SD-Key Calldata Capacity

## Source Change

The candidate branch `fix/sd-key-calldata-196-20261030` starts from
`deploy/testnet` at `2b9268f786fc7be6631b0b951154a37957a69ffb`.
It increases `SDKEY_MAX_CALLDATA_WORDS` from 128 to 196 Felt words per
transaction. `MAX_INTROSPECTABLE_TRANSACTIONS` remains 64.

The authority is
`client_prover/psy_core/psy_data/src/dpn/sd_key.rs:19`. Native VM validation,
policy validation, the compiler, and circuit construction consume that
constant. Do not replace unrelated values such as JSON depth, byte limits,
cache budgets, or transaction counts.

Word indices are zero-based: index 195 is valid for 196 inputs; index 196
is invalid. The actual `inputs_length` is still enforced, so a shorter
transaction cannot read its padded tail.

## Batch Impact

Five 35-word withdrawal entries encoded with one count word occupy
`1 + 5 * 35 = 176` Felt words. That payload fits the new bound. This is a
capacity calculation, not proof of a successful five-withdrawal bridge
transaction or a change to any Relayer batch setting. Existing 128-word
payloads remain within the new bound. SD-keys constructed here with at least
one introspection slot acquire new circuit fingerprints and account public-key
identities; their old fingerprints must not be reused.

## Compatibility Boundary

- Programmable SD-key construction allocates and authenticates calldata using
  this bound (`client_prover/psy_circuit/psy_ups_circuit/src/signature/sd_key_dpn.rs`,
  `build_from_dpn_function` and `build_tx_introspection`). Rebuild and measure
  affected SD-key fingerprints, including allow-method keys, before reuse.
  This includes the Genesis Faucet policy: `faucet_sd_key_fingerprint` and
  `compact_user` in `psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs`
  derive Faucet account identities from that circuit. The planned fresh
  deployment requires a newly generated Genesis with all 100 operators from
  the new policy. Preserve private-key material where possible, but do not
  bypass the imported-account identity check: old public identities differ.
  Retained chains require an explicit key-rotation plan instead.
- The DPN function circuit creates a bounded transaction context when a function
  uses transaction-introspection opcodes
  (`client_prover/psy_circuit/psy_dpn_circuit/src/vm/compile.rs`,
  `add_virtual_to`'s transaction-context construction). It hashes every
  possible calldata prefix. Such functions acquire new circuit fingerprints;
  inspect Genesis and deployed contract definitions for those opcodes and
  rebuild their registered function roots before adopting this source. A
  higher limit increases construction/proving work; no throughput or
  peak-memory improvement is claimed.
- The published SDK 2.1.0 belongs to the previous capacity cohort. Rebuild the
  SDK/WASM and compatible native consumers from one immutable Node revision;
  do not advertise 196-word support for the unchanged published package.
- Follow [Circuit and Verifier Operations](circuit-and-verifier-operations.md)
  to determine affected metadata, caches, embedded circuits and wrapper setup
  from actual circuit changes. Do not hand-edit generated fingerprints or
  reuse stale artifacts. Genesis is triggered here by the changed Faucet
  public-key construction input, not by a blanket circuit-refresh rule.
  EndCap, cache and Groth16 regeneration still require their own triggers.

## Focused Validation

All Rust commands require `PSY_NETWORK=testnet`, the intended
`PSY_CONFIG_PATH`, and `--release`:

```sh
cargo test --locked --release -p psy_vm --lib transaction_ -- --test-threads=1
cargo test --locked --release -p psy_client_data --lib dpn::sd_key -- --test-threads=1
cargo test --locked --release -p psy_compiler --test sd_key_introspection_test
cargo test --locked --release -p psy_dpn_circuit --lib transaction_input_word_enforces_196_word_capacity
cargo test --locked --release -p psy_ups_circuit --lib dpn_function_transaction_input_word_ -- --test-threads=1 --skip accepts_last_transaction_at_max_count
```

The tests cover 128, 176 and 196 input words, the last valid word, compiler
rejection of index 196, rejection of 197 inputs, empty input reads and padded
tail reads. Raw-witness circuit tests also reject index 196 and length 197
without relying on prover input guards. Positive SD-key tests generate and verify real minified Plonky2
proofs. Their synthetic calldata does not substitute for bridge E2E.
The expensive 64-transaction circuit-capacity test is explicitly excluded
from this focused command; measure full-capacity resources before rollout.

## Release Status

This change is source preparation, not deployment acceptance. This branch
does not publish npm, update downstream pins, regenerate circuit artifacts,
reset a chain, change L1 contracts, or restart live services. Before rollout,
complete the affected artifact/client work, real batch E2E, resource checks,
and a separate release review. The baseline release holds are recorded in
`deploy/multi-chain/gcp/fresh-sdk210-20261030/REVIEW-NOTES.md`. Its instruction
to keep capacity 128 describes the historical candidate, not this 196-word
proposal. This proposal removes that numerical mismatch only; it does not
close the withdrawal-packing acceptance hold. Retain real 2 + 2 + 1 and
Guardian acceptance coverage, and add a real five-entry batch test before
promoting that batch shape. The other independent holds remain unresolved.
