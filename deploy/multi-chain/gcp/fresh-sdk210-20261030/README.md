# SDK 2.1.0 Fresh-Testnet Preparation

This directory is a source-preparation record for operator review. It is not an
executable rollout profile, a release approval, or permission to reset a chain.
`candidate.json` deliberately sets `deployment_ready` to false. Keep the existing
R3 deployment and rollback profiles unchanged until the new profile is accepted.

## Frozen Choices

- Adopt the colleague's published SDK 2.1.0, whose actual WASM reports `testnet`
  and magic `0x1337CF514544CF69`. Do not relabel it as localhost or republish it.
- Keep `SDKEY_MAX_CALLDATA_WORDS = 128`. No circuit-capacity increase is included.
- Use Plonky2, not JTMB. Preserve Guardian, validator, worker, and 100 Faucet
  operator identities. No keys were read, generated, or changed by this push.
- Preserve prior deployment-side Genesis layout, account-reuse, and Realm IMT
  fixes while integrating the reviewed runtime candidate.
- Keep the historical contracts/DApp gitlinks and DApp `update = none` behavior.
  They are retained rollback anchors, not the final fresh-cohort client pins.
  The independently inspected sibling candidates are listed separately.

## Evidence And Boundaries

The SDK archive integrity was verified against the registry. All three complete
inner circuit strings in Node's wallet bundle occur byte-for-byte in the npm
WASM. The native testnet CLI constructed the EndCap circuit: its full verifier
object and four fingerprint limbs match the adopted metadata. A guarded
`PsyPublicTestnet` loader and a verifier-derived fingerprint test cover the
network boundary. Mainnet and other unvalidated selectors remain rejected.

The original candidate passed five release CLI builds, 705 Node-common tests,
18 forwarding tests, two privacy-fingerprint tests, and two final EndCap tests.
The deployment-integrated candidate passed 714 Node-common tests, with one
existing ignored test and the explicitly skipped long random test. Withdrawal
quarantine tests passed 17/17 after reproducing and repairing the offset bug:
only leading invalid records may acquire markers before a valid prefix lands.

Generated wallet/cache blobs were mechanically compared with adopted Audit
artifacts, not claimed to have received manual base64 review. Different-model
review read the textual delivery in disjoint parts. Its verdict was changes
requested; remaining findings and their scope are in `REVIEW-NOTES.md`. This is
not a fully approved release or proof that all imported Audit behavior is safe.

The published npm compiler stamp references an unavailable historical Node
revision. Artifact identity is established, but full source reproducibility
across that rewritten history is not. Current downstream Cargo pins still use
the adopted protocol source; a final unified release pin is a later gate.

## Before Any Rollout

1. Have the operator review this candidate and triage `REVIEW-NOTES.md`.
2. Prepare a new epoch-32 deployment profile. Existing R3 scripts pin epoch 10,
   old source, and old database names; they are not the new rollout plan.
3. Resolve the 128-word withdrawal packing issue before bridge acceptance:
   five 35-word withdrawals require 176 inputs. Use bounded calls such as
   2 + 2 + 1 rather than raising the circuit limit in this cohort.
4. Freeze and publish compatible producer commits, downstream references,
   contracts/client gitlinks, actual Genesis, and matching proving setup.
5. Build Services/Indexer and the clients, choose a wallet version newer than
   the existing published version, and complete the three-chain real flow.

This push updates only PsyProtocol/psy-node's deployment branch. It does not
push sibling repositories, publish npm or clients, update L1 contracts, clear
databases, restart services, or authorize any such action.
