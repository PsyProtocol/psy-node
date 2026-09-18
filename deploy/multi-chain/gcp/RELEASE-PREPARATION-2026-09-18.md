# Multichain stage integration candidate

Status: source integration only. NOT approved for an online fresh deployment.
No online service, database, L1 contract, wallet artifact or frontend was changed
by this preparation. Do not run the destructive fresh-deployment steps until the
remaining gates below are resolved.

## Repository cohort

All repositories belong to PsyProtocol. Product integration targets `multi_chain`;
deployment scripts remain on `psy-node:deploy/multi-chain-gcp`.

| Repository | Candidate commit | Notes |
| --- | --- | --- |
| psy-node | b78dd6c75418ad7f668afeeb021de9264c1433ba | Stage guards, builder validation, deposit recovery and relayer logging fixes |
| psy-genesis | 2d37e44504c452a361c488cea35376f859c705d2 | Merge head; consumers pin reachable 9acf4bf8aae281f75e17eb6c186ccde922b2897f, identical tree |
| psy-contracts | d23bb8ca60f3da3347c7eb16d1f8c917396c1e7c | Deployment profile gitlink; no product changes in this task |
| psy-services | 32218c2d417ec3e023e6f81eec34e25f4dad8fe6 | Already on multi_chain; proof compatibility still needs verification |
| psy-compiler | 469d15f80e7e32c2c0e355aa9c32603f80751600 | Existing candidate, NOT newly regenerated or verified |
| psy-sdk | fec061eb2344a6eb9b9dd536833a1d85872c9e8a | Source only; new testnet WASM/package not published |
| psy-wallet | 3bb5d09c794176a019b05a8c066527a5bd4283d3 | Stage migration plus fail-closed identity storage reads |
| psy-dapp | b41d717e5a60b73df0547c998a21691c1f1046a0 | Psy stage separated from L1 network choice |

The authoritative deployment pins are in `source-versions.env`. Its SDK npm
version is the source package version (2.0.4), not a claim that the matching
artifact is published. Never substitute an existing npm package by version alone.

SDK Cargo dependencies all use the published node source
`cf12c3a9e3fd93c970725a5c89ab61e01106186c`. The later node changes up to b78dd6c7
affect the DApp gitlink, CLI recovery, relayer logging and Makefile commands, not
SDK-consumed crate source. Services and compiler retain their older node pins;
their compatibility cannot be inferred from equal tree heights.

## Completed source validation

- psy_config: 12 tests each for localhost, testnet and mainnet.
- Wallet: 679 tests, including storage-read failure and retry regressions.
- DApp: 19 focused stage/config/Explorer tests; not full browser acceptance.
- Deposit CLI: 10 library and 10 binary tests with default features disabled.
- Relayer: 25 claim-related tests.
- SDK: locked metadata and dependency-pin consistency; no WASM build yet.
- Build-identity collector: 13 offline regression cases, including stale journal
  invocation, wrong stage/magic, missing identity and empty coverage.
- Legacy two-role rollout, runtime-source fixture and manifest structure tests.

Historical root `rollout/` scripts now live under `deploy/legacy-role-rollout/`.
They are revision-pinned historical tooling, not the new fresh-deploy entrypoint.

## Release blockers

1. **Magic policy confirmation.** Delivered branches retain testnet magic
   `0x1337CF514544CF69`, the same as localhost and the current chain. Earlier
   discussion instead chose protocol testnet `0x1337CF514544C169`. This integration
   does not silently change that decision. Confirm policy before building final
   circuits, WASM and trust setup. Shared magic does not provide stage separation
   at a runtime guard that compares only magic.
2. **SDK artifact.** Build/pack the testnet SDK from the candidate; record its
   SHA-256 and provenance. Publish only when authorized, then update wallet's
   three `PSY_SDK_*` workflow pins. They still reference 4146f805. Verify DApp's
   actual dependency resolution too. Changing source pins alone is insufficient.
3. **Genesis provenance.** The prior 2026-09-17 compiler audit found differences
   in withdrawal contract functions 5/6 during regeneration. Explain or resolve
   them before accepting generated contracts or a new setup. The manifest hash
   identifies checked-in bytes, not successful reproduction from the compiler.
4. **Services/compiler compatibility.** Run proof fingerprint/verification and
   ABI/method checks against the final node + Genesis cohort, including Nostr
   deposit and private-transfer proofs. No reuse approval has been granted.
5. **Whole-stack tests.** Run the isolated fresh stack, three-chain CLI E2E and
   Bridge/Explorer browser tests. Test wallet migration, preserved keys and
   cross-stage rejection. Tests skipped are not passes.
6. **Build/type coverage.** Wallet full typecheck is not green in the current
   validation setup; after using the verified old SDK types, four pre-existing
   `globalThis.chrome` typing errors remain. Validate against the new SDK and
   production build environment rather than treating unit tests as a release.

The current identity collector checks user/system prove-proxy, faucet and relayer
using their current systemd invocation only. Coordinator, realm, edge and worker
do not emit this identity record; audit their executable/config hashes separately.

## Safe next steps

Resolve the blockers while the current network keeps running. Build all artifacts
and stage immutable files before any service stop. Then get explicit fresh-deploy
approval and execute `deploy/multi-chain/gcp/deploy_all.sh` with the reviewed
private configuration. Retain the user-operated sudo boundary for offsite hosts.
Monitoring must be enabled last, after business-service and worker acceptance.
