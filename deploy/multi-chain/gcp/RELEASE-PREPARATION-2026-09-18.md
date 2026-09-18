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
| psy-node | 159c8f9860a3c0ebe8b7db89ab30682eecf1b461 | Runtime fix plus canonical artifact tests, Genesis gitlink and clean-checkout generation fix |
| psy-genesis | cb3ea4a1e743c3c01037ae968e10f27389788a7d | Full generation reproduced twice byte-for-byte |
| psy-contracts | d23bb8ca60f3da3347c7eb16d1f8c917396c1e7c | Deployment profile gitlink; no product changes in this task |
| psy-services | 32218c2d417ec3e023e6f81eec34e25f4dad8fe6 | Already on multi_chain; proof compatibility still needs verification |
| psy-compiler | bb79f3ff335d36560b8b6eae880c8404d662d27c | Pins deterministic VM, stage-aware build, withdrawal reproducibility check |
| psy-sdk | 310cd961bb479619069f12ca71c32e133066e2ad | Testnet WASM built and package dry-run checked; NOT published |
| psy-wallet | 3bb5d09c794176a019b05a8c066527a5bd4283d3 | Stage migration plus fail-closed identity storage reads |
| psy-dapp | b41d717e5a60b73df0547c998a21691c1f1046a0 | Psy stage separated from L1 network choice |

The authoritative deployment pins are in `source-versions.env`. Its SDK npm
version is the source package version (2.0.4), not a claim that the matching
artifact is published. Never substitute an existing npm package by version alone.

Compiler and SDK Cargo dependencies all use the published node source
`769711acfe3ba23dc0124f961ff361478e52b89b`. Later Node integration commits
change only tests, the Genesis gitlink and the test-only Genesis generator.
Services retains its older node pin; compatibility still requires real proof
verification, not an inference from equal tree heights.

## Completed source validation

- psy_config: 12 tests each for localhost, testnet and mainnet.
- Wallet: 679 tests, including storage-read failure and retry regressions.
- DApp: 19 focused stage/config/Explorer tests; not full browser acceptance.
- Deposit CLI: 10 library and 10 binary tests with default features disabled.
- Relayer: 25 claim-related tests.
- Node VM: 48 library tests; canonical Genesis artifact tests: 8/8.
- Compiler: release build/check, 374 interpreter tests and three independent
  withdrawal compilation runs with identical output bytes.
- Genesis: two complete generation runs with identical contracts, token/update
  artifacts, ABI files and provenance. Only contract 3's generated executable
  definition/root/whitelist changed from the prior artifact.
- SDK: release WASM build, workspace check, TypeScript build, package dry-run
  inspection and 20 focused tests. Instantiating the actual WASM reports
  `current_network=testnet` and magic `0x1337CF514544CF69`.
- Native runtime: release build after the Genesis update; local Genesis
  generation passed 3/3 tests, including a previously missing output directory.
- Build-identity collector: 13 offline regression cases, including stale journal
  invocation, wrong stage/magic, missing identity and empty coverage.
- Legacy two-role rollout, runtime-source fixture and manifest structure tests.

Historical root `rollout/` scripts now live under `deploy/legacy-role-rollout/`.
They are revision-pinned historical tooling, not the new fresh-deploy entrypoint.

## Confirmed magic policy

Confirmed by the operator on 2026-09-18: this release keeps testnet magic
`0x1337CF514544CF69`, matching the current network and the delivered branches.
This supersedes the earlier proposal to switch to `0x1337CF514544C169` for this
release. The magic decision is closed; no runtime/config change is needed for it.

Localhost and testnet therefore still share magic. A runtime guard that compares
only magic cannot distinguish those stages. Do not claim otherwise in acceptance
results. Matching magic alone also does not establish circuit fingerprint, SDK,
Genesis or Groth16 setup compatibility; the remaining gates still apply.

## Release blockers

1. **SDK consumer rollout.** Build/pack validation is complete. Package the
   immutable release and record its SHA-256 before distribution. Publish only
   when authorized, then update wallet's
   three `PSY_SDK_*` workflow pins. They still reference 4146f805. Verify DApp's
   actual dependency resolution too. Changing source pins alone is insufficient.
2. **Fresh proof artifacts.** Genesis nondeterminism is resolved: the pinned
   streaming XXH3 implementation used uninitialized buffer tail bytes for
   certain symbolic inputs. One-shot XXH3 fixes this without changing inline
   constant/input encoding. Generate and validate a fresh local Groth16 setup
   before starting the acceptance stack; never silently reuse published setup.
3. **Services/compiler compatibility.** Run proof fingerprint/verification and
   ABI/method checks against the final node + Genesis cohort, including Nostr
   deposit and private-transfer proofs. No reuse approval has been granted.
4. **Whole-stack tests.** Run the isolated fresh stack, three-chain CLI E2E and
   Bridge/Explorer browser tests. Test wallet migration, preserved keys and
   cross-stage rejection. Tests skipped are not passes.
5. **Build/type coverage.** Wallet full typecheck is not green in the current
   validation setup; after using the verified old SDK types, four pre-existing
   `globalThis.chrome` typing errors remain. Validate against the new SDK and
   production build environment rather than treating unit tests as a release.

Local launch safety: the legacy `deploy/local-multichain/start.sh` is NOT the
acceptance entrypoint. It can stop processes by name/port, use existing Envio
ports, patch compiler sources and remove provenance. The isolated acceptance
entrypoint must fail on occupied ports, preserve stamps, use a dedicated HOME
and Compose projects, and never start a Cloudflare tunnel. Whole-stack tests
have not passed merely because source/build checks above passed.

The current identity collector checks user/system prove-proxy, faucet and relayer
using their current systemd invocation only. Coordinator, realm, edge and worker
do not emit this identity record; audit their executable/config hashes separately.

## Safe next steps

Resolve the blockers while the current network keeps running. Build all artifacts
and stage immutable files before any service stop. Then get explicit fresh-deploy
approval and execute `deploy/multi-chain/gcp/deploy_all.sh` with the reviewed
private configuration. Retain the user-operated sudo boundary for offsite hosts.
Monitoring must be enabled last, after business-service and worker acceptance.
