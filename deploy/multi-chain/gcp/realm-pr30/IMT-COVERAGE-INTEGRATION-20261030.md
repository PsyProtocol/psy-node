# IMT Coverage Integration

Status: source integration only. No live services were changed by this task.
The deployed Processor manifest remains `imt-metadata-live-release.json`;
do not interpret this document as a replacement artifact or rollout record.

## Source Mapping

- Repository: `PsyProtocol/psy-node`; destination: `deploy/testnet`.
- Deployment base: `695e5fead6e2ddd9364a9b417d755b77d1d48c5a`.
- Requested upstream fix: `a9b9ac38dd4d5ea13f6068d67f6cb0181d56ba5d`.
- Runtime integration commit: `48a490e2` (the preceding code-only commit).
- This is a compatible backport, not a merge of the upstream branch's history.
- The upstream changes to `processor/db/records.rs`, `db/commit.rs` and
  `ffs/verify.rs` are already covered by `cd93078a`, the deployment backport of
  `67634280`. Preserve those implementations and their stronger regression tests.
- Preserve the `024d21a0` unchanged-checkpoint metadata fix and the existing
  PR30 admission/redelivery compare-and-set logic.

## Included Behavior

1. Edge admission requires IMT records when a nonzero final positional value
   changes a leaf with an existing checkpoint IMT preimage. Ordinary positional
   leaves, unchanged leaves and finally-cleared leaves retain their exemptions.
   IMT coverage is grouped by contract across all histories in the EndCap.
2. The proposer verifies aggregated updates against its processing checkpoint
   before publishing the P2P proposal or submitting the GUTA to the Coordinator.
   The same authenticated baseline verifier remains on the follower path.
3. Client proving-session output omits no-op positional updates and empty
   contract histories. An empty history must not change the user-contract root.
   No-op IMT operations remain present because modified-key accounting replays
   their first and repeated touches.

Review found and corrected one upstream edge case: checking each intermediate
positional value rejects a valid `H -> X -> H` or `H -> X -> zero` history.
The backport checks the final positional value per contract/leaf instead,
matching commit-path coverage. The new regression failed against the original
guard and passed after this correction.

## Verification

- Four focused Edge coverage tests passed in release mode with
  `PSY_NETWORK=testnet`, including the restored/finally-cleared regression.
- Common-library release regression: 687 passed, zero failed, one existing
  ignore and the long randomized `test_rgp_chain_state_basic` filtered out.
- Client-data release unit suite: 196 passed, zero failed. This is not real-proof
  acceptance of the changed proving-session output.
- `psy_node_cli` release build and `--help` smoke check passed. This was a
  validation build, not a published release artifact; rebuild from the frozen
  runtime commit before any rollout.
- The three runtime files passed independent review after the intermediate
  value issue was corrected. The integration record is reviewed separately.
- No circuit source, cached circuit artifact, Genesis, dependency pin, database
  schema, signing magic or wire-format definition is changed.

Checks used the existing offline Bookworm/R3 builder image
`sha256:02a4dd5c2ea776982084a4a856610836fc9f944203e85948fd4b475177f6b4af`,
Rust `nightly-2025-09-20`, `PSY_NETWORK=testnet` and retained R3 configuration
and Genesis contract inputs. Test-only TypeScript binding exports used writable
temporary mounts, not changes to tracked source. Commands:

```sh
cargo test --offline --locked --release -p psy_node_common --lib -- --skip test_rgp_chain_state_basic
cargo test --offline --locked --release -p psy_client_data --lib
cargo build --offline --locked --release --bin psy_node_cli
```

## Deployment Boundary

This task does not authorize or perform rollout, reset, new transactions, npm
publication, SDK repinning or wallet publication. The client-data source change
does not update an already-published wallet or an already-running Faucet/proxy.
Affected consumers need their own pinned build, review and release acceptance.

A later rollout needs both Realm Edge and Realm Processor changes; retain
per-component hotfixes and install new immutable binaries rather than replacing
the shared R3 executable. Preserve the current Genesis, databases, queues, keys
and rollback artifacts. The older Processor-only `imt-metadata` profile is not
a complete rollout procedure for this broader integration.

The Edge adds checkpoint preimage reads per unique uncovered positional leaf;
the proposer adds full baseline reconstruction/replay. Runtime latency, memory
and database overhead have not been benchmarked on the live dataset. The unit
fixtures are not a real-proof, live P2P or bridge end-to-end acceptance.

This Realm fix does not resolve the separate Relayer native-token mapping
mismatch or replay/refund an already-accepted L1 deposit.
