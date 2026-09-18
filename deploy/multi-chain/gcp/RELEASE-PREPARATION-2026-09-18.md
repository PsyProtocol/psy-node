# Multichain stage integration candidate

Status: source/build preparation complete in part; online release packaging is
still outstanding. Not yet ready to stop or clear the existing network.
No online service, database, L1 contract, wallet artifact or frontend was changed
by this preparation. Do not run the destructive fresh-deployment steps until the
remaining gates below are resolved.

## Operator Update: Online Acceptance Instead Of Local E2E

On 2026-09-18 the operator stopped local acceptance work and chose to run the
remaining tests on the freshly deployed online testnet. Local three-chain E2E
and browser acceptance are therefore **skipped, not passed**. The isolated
launcher, its node process group, and its four infrastructure containers have
been stopped. Artifacts and logs are retained; online services were not changed.

The following preparation is complete:

- Native and Debian Bookworm release binaries for Node and services are built.
  The Bookworm build uses the pinned nightly-2025-09-20 toolchain and locked
  dependencies. All seven release executables require at most GLIBC 2.34.
- All three fresh Groth16 setup groups generated and self-verified successfully.
- Their corresponding Solidity verifiers exported successfully in the isolated
  runtime and from the Bookworm relayer. Verified setup files are staged under
  `dist/groth16-keystore/{bridge,deposit_batch_append,withdrawal_claim}`;
  matching exported verifiers are under `dist/verifiers`. Both have SHA256SUMS.
- Local SDK archive exists for commit `310cd961bb479619069f12ca71c32e133066e2ad`:
  SHA256 `3b19b24d9c2608670e55e03d741f9aa3df85a0a6df4716afd2136681f36d3643`.
  It has not been published to npm or R2.
- Wallet `3bb5d09c` was built in an isolated checkout using that exact local SDK.
  Frozen offline dependency installation, typecheck and staging build passed.
  ZIP SHA256: `3e754e5f8844f436cc06b2fafde4b146515ed66165554feed35ae416619cbb3d`.
  The operator explicitly chose not to upload the SDK. Use the wallet candidate
  publisher described in `WALLET-R2-CANDIDATE-2026-09-18.md`; do not switch the
  default wallet download before the matching backend is accepted.
- Fresh Genesis generation passed 3/3 tests with the established online relayer
  L2 key at index 2. No disposable local-test wallet was copied into the release.

Before stopping the current network:

1. Produce and inspect the Debian Bookworm-compatible cloud bundle, including
   services/indexer; keep an independently verified Arch release for offsite hosts.
2. Use the verified local SDK for matching wallet/DApp builds; SDK upload is
   deferred. The wallet workflow still selects the old `4146f805` archive and
   must not be used to overwrite this candidate.
3. Package the new setup and matching verifier sources with the cloud deployment;
   verify Genesis/config/source hashes and prevent reuse of stale artifacts.
4. Run the private-config preflight: three RPC chain IDs, signer balances,
   deployment topology, SSH reachability and immutable source/artifact pins.

Only then stop/reset and deploy. The numbered deployment sequence still places
its build step after stop/reset; do not blindly run the full sequence before
preparing artifacts separately. Services proof compatibility, continuous block
production, and all three deposit/withdraw flows become online acceptance gates.
Do not declare the network ready for normal use until those gates pass.

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

1. **SDK consumer rollout.** Wallet local-SDK build validation is complete.
   Publish its immutable candidate separately from the default download. No SDK
   upload is needed for this manual release. The workflow still references
   4146f805; automatic release alignment remains deferred. Verify DApp's actual
   dependency resolution too. Changing source pins alone is insufficient.
2. **Fresh proof artifacts.** Genesis nondeterminism is resolved: the pinned
   streaming XXH3 implementation used uninitialized buffer tail bytes for
   certain symbolic inputs. One-shot XXH3 fixes this without changing inline
   constant/input encoding. Fresh setup generation and self-verification are
   complete; inspect the final bundle and hash manifest before deployment.
   Never silently reuse the old published setup.
3. **Services/compiler compatibility.** Run proof fingerprint/verification and
   ABI/method checks against the final node + Genesis cohort, including Nostr
   deposit and private-transfer proofs. No reuse approval has been granted.
4. **Whole-stack tests.** Per the operator update above, run three-chain CLI E2E
   and Bridge/Explorer browser tests on the fresh online testnet instead of
   continuing the local stack. Test wallet migration, preserved keys and
   cross-stage rejection. Tests skipped are not passes.
5. **Dual-role topology.** PsyProtocol/psy-node PR #10 is still open as of this
   preparation. Candidate runtime `159c8f98` lacks `prove-proxy --role`, while
   the live host runs separate user/system processes. It provides the legacy
   combined API, but cannot be deployed as the agreed dual-role layout. Resolve
   the runtime merge and rebuild applicable artifacts before stopping services;
   do not silently deploy a legacy single-process replacement.

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
