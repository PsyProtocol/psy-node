# IMT lookup repair and test handoff

## Candidate

- Branch: `fix/imt-predecessor-not-found-20260923`
- Base: `f3d1fb437a41080f4312a0363e32acd4ea275e9b` (`origin/multi_chain` at preparation).
- No live service, database, deployment manifest, Genesis, or trust setup was changed.

## Changes

1. Restore the previous-bucket predecessor ordering fix from legacy Parth
   `522e5b94a78b5aa72d7627a5756f1870d0e45de3` (PR #254). Scylla returns
   `encoded_key DESC`; reversing the rows chooses a smaller predecessor.
   Candidates retain this order and exclude keys born after the requested checkpoint.
2. Translate only exact legacy RPC absence responses (`-32001` plus the expected
   complete message and requested leaf index) into `ImtLookupNotFound`. No RPC wire
   format changes are required. Absence is DEBUG at the provider boundary; other
   server errors retain ERROR. Context determines whether absence is acceptable.
3. Propagate remote predecessor failures instead of converting every error to
   `None`. Local candidates cannot safely replace an unknown remote predecessor.
4. Replace IMT preimage `unwrap_or_default` fallbacks with typed absence handling.
   Insert targets, virgin sentinels, and no-op slots can default only when their
   Merkle slot value is zero. Non-empty missing slots and transport, database,
   decoding, and validation failures return errors. Updates still require a
   preimage, and their error causes are retained.

The observed `Leaf preimage not found at index 18157` is not evidence by itself
of the ordering bug. Absence at an earlier checkpoint followed by presence at a
later checkpoint can be a normal insertion lookup.

## Repeatable local tests

Initialize the pinned Genesis submodule, then run from this worktree:

```bash
git submodule update --init psy-genesis
PSY_NETWORK=testnet cargo test --locked \
  -p psy_client_data -p psy_vm -p psy_provider -p psy_node_core \
  --lib imt -- --skip export_bindings
```

Result: 73 passed (65 data, 1 node core, 2 provider, 5 VM), including 11 new
regression tests. No network transactions or database services are needed.
The ordering test covers the production candidate iterator; it is not a live
Scylla integration test.

Broader library run before the final three merge-helper tests: node core 35/35,
provider 149/149, VM 51/51. The data library had 176 passes and these three failures,
all reproduced on the unmodified base with the same pinned Genesis:

- `api::reward::tests::read_from_bin_file`: requires an external binary fixture
  via `PSY_TEST_REWARD_CLAIM_METADATA_FILE`.
- `deploy_v2_rejects_missing_proof_and_capacity_overflow`: existing capacity assertion failure.
- `update_rejects_zero_id_missing_proof_and_capacity_overflow`: same existing assertion issue.

Type export tests write generated bindings. Use `--skip export_bindings` to
avoid unrelated generated-file changes. Do not call the full suite green.

Local evidence:

- `/tmp/psy-imt-fix-20260923-focused.log`
- `/tmp/psy-imt-fix-20260923-tests.log`
- `/tmp/psy-imt-fix-20260923-other-tests.log`
- `/tmp/psy-imt-baseline-20260923-tests.log`

## Integration gate before deployment

1. Review the candidate and build the affected node/edge and prove-proxy consumers
   from one pinned revision. The VM/data/provider changes also affect SDK consumers;
   follow `AGENTS.md` applicability and downstream build gates before publication.
   This patch does not authorize SDK releases or a production rollout.
2. On an isolated test network, insert keys across a bucket boundary with multiple
   older-bucket candidates, then update an existing key. Verify the returned
   predecessor, proof acceptance, values, and state roots.
3. Inject a remote predecessor timeout while a local candidate exists. The proof
   attempt must fail with the original error, not use a guessed predecessor.
4. Exercise first insertion, a later insertion before the first key (sentinel path),
   and missing preimages on occupied slots. Only confirmed empty slots may default.
5. After explicit deployment authorization, run the three-chain deposit/claim and
   withdrawal E2E. Record transaction hashes, checkpoints, final balances, and errors;
   compare all claims against chain state, not just the absence of ERROR logs.

Not yet performed: live Scylla fixture tests, proof-generating transaction E2E,
release binaries, SDK/WASM release validation, or online deployment.
The existing `LIMIT 5` predecessor query and missing-row scan behavior are unchanged;
this repair is not a claim that all historical IMT lookup edge cases are solved.
