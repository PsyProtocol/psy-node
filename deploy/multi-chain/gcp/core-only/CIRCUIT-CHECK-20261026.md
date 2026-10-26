# Three-Validator Circuit Check

Date: 2026-10-26. This records source preparation, not a completed deployment.

## PR28 Supersedes The Prepared Release

The historical artifacts below are NOT the release candidate after PR28.
Do not start the fresh chain with those binaries or that Genesis.

- Remote `testnet-dev` integrated PR28 `b280d714` through merge `ee281dc2`.
- `efb42e9e` advances `psy-genesis` to
  `59462d73c3b46d0211c5223f700e7f7142e0c2ab`, published on its
  `feat/full-sd-key` branch. Its compiler producer is `3533edac`.
- Follow-up `c8931002b61d026ed78c9cfb3426cf7094c1584c` binds Genesis Faucet
  accounts and operator output to the same derived SD policy fingerprint. It
  also corrects the checkpoint-one anchor test fixture without changing its
  production handler. Independent review approved those two files. The five
  Faucet-related unit tests passed in both CLI targets, the Faucet policy
  integration test passed, and the checkpoint-one regression passed.
- At `efb42e9e`, core Node/Worker/DevCLI/UserCLI and Node library test targets
  passed release compilation checks with the intended testnet configuration.
  This is compilation evidence, not service-start or transaction acceptance.
- An actual testnet EndCap construction matched the complete checked-in verifier
  JSON and fingerprint limbs
  `[7003881527231760035, 6208563064171912847, 8989269122100945112, 8698490262779479146]`.
  The emitted network magic was `0x1337cf514544cf69`.

The cache-only generator ran twice from `c8931002` with the public testnet
configuration below. Both resulting file hashes matched; the second run reported
both files up to date. Only circuit entries 32, 40, 63 and inclusion proofs changed
relative to that source. The circuit count (25), inclusion-proof mapping and
EndCap entry were unchanged. Neither run emitted a Groth16 setup marker.

| PR28 three-validator artifact | SHA-256 |
| --- | --- |
| Cached circuit library, both runs | `3f9744b90bf5e8a8b6ad6f01585843fa3385f7df9f1a55bc17153cc84eff6917` |
| Cached common data, unchanged | `0a33b47a5a7235260d759ed2e34c29a33198b4e20794054fe452f17a0c03a8ac` |

Final binaries, regenerated Genesis and runtime acceptance must be recorded
separately before startup. Retain the
existing Guardian and P2P signing identities. Do not overwrite private key
inventory while regenerating public artifacts.

Branch integration does not approve the old Faucet launch scripts: several
still pass the removed `sd-key` sign type and expected-transaction-count flags.
The new generator uses caller-aware SD policy and min/max transaction counts.
Keep those old launchers out of this core-only rollout. Downstream SDK/compiler
and wallet compatibility is a separate gate before exposing public applications.

## Source And Inputs

- Functional branch: `testnet-dev`; deployment automation: `deploy/testnet`.
- Generator source: `0cb10be58405c75c6aa019bcd686858dc99b4a41`.
- Cache adoption: `143fe6eb`; fresh-Genesis key protection: `c145507d`.
- Integrated functional source: `ce6c7f95f4f677f9994fbc2504a33ef3f3047926`.
- Build/config selection: `PSY_NETWORK=testnet`, CLI `psy-public-testnet`,
  Plonky2; two Realms with three validators each.
- Public configuration SHA-256:
  `c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0`.

## Executed Checks

The documented cache-only generator ran twice in release mode with
`--no-default-features --features std,serialize_rkyv,serialize_speedy,serialize_postcard`.
Both executions used the same public configuration. The second reported both
generated files up to date, and byte comparisons agreed. No Groth16 setup was
generated in this check. Independent review approved the cache source change.

| Artifact | SHA-256 |
| --- | --- |
| Previous cached circuit library | `beb8f0f100beb6a94bf541743015c1daed63f86b28627ffbab2fde89365cc90c` |
| New cached circuit library, both runs | `cf09bd8763040e97621875542821d8e2f3067b9a75e0af0e79bf8cc8c62e98d0` |
| Cached common data, unchanged | `0a33b47a5a7235260d759ed2e34c29a33198b4e20794054fe452f17a0c03a8ac` |

Only circuit entries 63 (`RealmFinalizeGUTA`), 40
(`AggUserRegisterDeployContractsGUTA`) and 32
(`GenerateRollupStateTransitionProof`) changed fingerprints and verifier data.
The inclusion-proof mapping is unchanged; the whitelist proofs/root changed
with circuit 63. The UserEndCap entry is unchanged. This is not proof of a real
EndCap transaction or of P2P rotation working on the deployed network.

The Genesis module release tests passed: **26 passed, 0 failed, 1 ignored**.
The metadata-only Guardian preflight test required a sibling public DApp fixture
and synthetic mode-0600 files under a separate test HOME. Initial runs without
these fixtures failed; no real Guardian key was used or regenerated. The ignored
test requires approved contract artifacts and remains separate QA work.

The integrated source built successfully in the Bookworm builder with
`PSY_NETWORK=testnet`, the public configuration above, and
`cargo build --offline --locked --release -p psy_node_cli -p psy_worker_cli -p psy_dev_cli`.

| Binary | SHA-256 |
| --- | --- |
| psy_node_cli | `3d073be422598482eeb70f0ec7e318f0e23ab8624b2000ff77c4cacefeaeab6a` |
| psy_worker_cli | `74f21631a008beb073e5d7079b56f55bec48cfc3c8ee1e2e320332a220e9e669` |
| psy_dev_cli | `6876d201fbd11738d8d0f83088d59348ebfbec58e239fa9a771ca5a785e87ec6` |

First Genesis generation succeeded with 107 users: six validator accounts,
the public multisig relayer at registration 2, and 100 Faucet operators.
The operator file has 100 distinct user IDs and addresses; private outputs
are mode 0600 and retained outside Git. Guardian and P2P transport/BLS identities
were not regenerated. New validator ZK account keys belong to this new Genesis
and must be used instead of any earlier bootstrap ZK keys.

The raw Genesis is 718,298,669 bytes with SHA-256
`a29ac62483c259a59b20f679b416dd4a555fd2b643a4364ec02fbba622132495`.
Do not deploy that raw file: its validator list is empty. After public membership
injection, the final Genesis has six validators and SHA-256
`1bbd09905c1ea6379645b6d9a353b950c215492c6a268466274496aba6941152`.
Combined Genesis/config/whitelist input consistency passed. This is structural
consistency, not a real proof or runtime acceptance result.

Large embedded contract definitions exceeded the assembler's former 64 MiB
input limit. Only `--genesis-in` now permits up to 1 GiB; configuration inputs
remain limited to 64 MiB. Same-descriptor, no-follow and post-read bounds are
retained. The actual generated file was accepted and all 85 deployment-tool
tests passed, including metadata/read-growth boundaries and call-site scope.

The offline preview still exits 2 and reports `deployment_ready=false`. Its
null runtime pin is an unfinished release record, not evidence that the source
above is unpublished. Finalize that record, host installation and worker
mapping before starting the cloud services. No cloud service was started by
the checks recorded here.

## Startup Boundary

This cache is specific to the intended three-validator configuration. Do not
silently regenerate it using a default network or a different validator count.
Node and Worker must be rebuilt from the integrated source, not reused from the
earlier build that embedded the previous cache.

Before core startup, authenticate the generated Genesis, all six validator
identities, the retained three Guardian commitments, the 100 Faucet operators,
worker reward mapping and the final binary/config hashes. Preserve existing
Guardian and P2P keys. Startup acceptance requires real proofs and committed
checkpoint progress, followed by P2P rotation checks; an active service is not
sufficient evidence.

The changed checkpoint transition invalidates the associated `bridge_agg`
Groth16 wrapper materials. Keep bridge services disabled until the matching
setup and Solidity verifier are rebuilt, verified and deployed coherently.
Do not use the old chain's setup/verifier with the new core. Other peripheral
services may be delivered later; this does not waive their compatibility checks.
