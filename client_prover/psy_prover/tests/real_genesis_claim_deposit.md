# Real Genesis Deposit Claim Regression

Status for the SDK 2.1.0 preparation: PENDING. This test has not been accepted
against the final Genesis of this cohort.

Historical result at `e6693c8723932ab80c3d90e282800c2a42cd6c27`: the main thread
reported successful no-run compilation and execution in 10.41 seconds. That run
confirmed the exact old-fingerprint failure, new production claim VM/CFC
success, and tampering rejection. This is the bounded token4 regression result,
not full E2E or deployment acceptance. This fixture adds no production code,
dependencies, network listeners, or generated files.
The source baseline is `e6693c8723932ab80c3d90e282800c2a42cd6c27`.

## Scope

One production token4 `claim_deposit`, not a simplified contract. The test:

1. SHA256-checks public new and retained old Genesis files through environment
   paths. It decodes only their contracts, skipping the other JSON fields.
2. Validates new canonical token/deposit-tree layouts, decodes unmodified
   production CBOR, and recomputes the contract code roots.
3. Generates and verifies a real minified `DepositInclusionCircuit` proof;
   rejects a changed public input. Inserts its measured fingerprint and PI hash
   into a real height-16 session proof tree.
4. Executes the entire old `claim_deposit` in the production VM and requires
   exactly the original `proof tree root mismatch` failure, not any error.
5. Executes the entire new method, checks the balance credit and deposit event,
   reconstructs its CFC, and requires its fingerprint to match the new Genesis
   function whitelist. Proves and verifies that CFC, then rejects a changed
   session proof root witness.

There is no mocked successful submit. The test uses a synthetic in-memory
checkpoint and two public test users, not the retained accounts or their keys.
The bridge user's known-root IMT membership, contract trees, state trees and
checkpoint root are constructed and authenticated by the normal VM/CFC. IMT
lookup caches contain the actual membership leaf; empty token IMT lookups use
the existing memory backend's absent-key behavior. The old negative fixture
uses the new validated layout with old unmodified code, to isolate the stale
code failure; this does not certify migration of an old layout.

The session proof tree is assembled by the fixture after independent inclusion
proof verification. This is NOT recursive UPS aggregation or EndCap inclusion.
Full Genesis/checkpoint replay, token0, private_claim, fees, Guardian multisig,
Faucet SD-key policy, network admission and committed checkpoint inclusion
remain separate gates. No overall deployment-ready claim follows from a pass.

## Main-Thread Invocation

Only the owner of the build cache may compile/run this test. Use the checked-in
test from the prepared, dependency-complete build cohort. Build against the
unified Node/config/Genesis inputs, never localhost defaults
or `is_sync`. The test also checks the compiled testnet network magic.

Set these paths/hashes explicitly; do not point to private_keys.json:

```bash
export PSY_NETWORK=testnet
export PSY_CONFIG_PATH="$APPROVED_CANONICAL_CONFIG"
export PSY_CLAIM_GENESIS="$FINAL_PUBLIC_GENESIS"
export PSY_CLAIM_GENESIS_SHA256="$FINAL_PUBLIC_GENESIS_SHA256"
export PSY_CLAIM_OLD_GENESIS="$RETAINED_OLD_PUBLIC_GENESIS"
export PSY_CLAIM_OLD_GENESIS_SHA256="$RETAINED_OLD_PUBLIC_GENESIS_SHA256"
cargo test --release -p psy_prover --test real_genesis_claim_deposit \
  real_token4_claim_deposit_new_passes_old_fingerprint_fails \
  -- --ignored --exact --nocapture --test-threads=1
```

Require `1 passed`, not zero matches or an ignored test. Missing fixtures,
missing `sha256sum`, hash mismatches and wrong network are errors, never skips.
Keep fixture files immutable throughout the run. The executable uses the real
Plonky2 Poseidon/Goldilocks types directly; no JTMB option exists.

Retained public R1 candidate hash:
`f839b453ab130c29998620c4c5d4bf9a30ce341a2e7c480aa9dbd8ed10902173`.
Retained old public Genesis hash:
`a5465bd712ceb66585660fddb4ac233afb747938395adaa200a63ead2f25f2c8`.
Use the newly measured unified Genesis hash instead of the R1 value when ready.

Historical test execution time was 10.41 seconds; compilation time and peak memory
were not reported. It builds one inclusion circuit and one full production
claim CFC plus their minifiers. Run serially with resource monitoring. A
timeout/OOM/compile failure is PENDING or FAILED evidence, never an acceptance.
