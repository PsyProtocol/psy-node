# Preparation Status: 2026-10-31

This is an offline preparation checkpoint, not a completed deployment or an
activation package. No database, live service, L1 contract, key or npm package
was changed by this work.

## Repair Checklist: 2026-10-31

These are preparation tasks, not permission to activate services. Source fixes
are prepared separately from deployment scripts. A source application without
tests and independent review is not complete.

| Task | Status | Acceptance |
|---|---|---|
| Faucet batch departure and safe retries | Published in `15d6316d`; scoped tests/review passed | Port `b9c1cdd9` from `c4bf6e16`, `16d3b773`, `afc27728`; atomic bounded queue, policy-bound batch capacity, uncertain delivery never switches operator |
| Relayer readiness and deposit admission | Published in `15d6316d`; scoped tests/review passed | Port `c9a2dfe7`; Services read 2s, row 70s / round 75s to allow L1 pool failover; event-id cursor; root-not-yet-known spends no attempt; at most 32 finalized deposits per chain per round |
| Worker reputation and fetch replay | Published in `15d6316d`; scoped tests/review passed | Port `310d35c5`, reputation/replay only from `876c1432`; preserve whitelist and PR30/IMT; real Redis replay tests 2/2 passed |
| BSC fees | Published in `15d6316d`; scoped tests/review passed | Port `1f1e2f0a` from `c9105056`, observed-history strategy and strict config parsing; no packed-deposit port |
| Deployment inputs and Router | Core packages complete; peripheral installers pending | Fixed Router base `394153fa`; role inventory, internal Coordinator and epoch-32 binding; six private core packages / 16 units verified; 532 core deployment tests and 23 fresh-profile tests passed |
| Build isolation and consumer pins | Native CLIs, actual Genesis and SDK/WASM prepared | Isolated CLI and WASM builds; immutable source `15d6316d`; published SDK `a2e3dc8c`; final Genesis gitlinks integrated after child publication; full proving/client/runtime acceptance remains pending |

The complete fleet package, proving setup and real E2E
acceptance remain separate release gates below. Do not advance their pins or
claim activation readiness while this checklist is incomplete.

### Current Work And Remaining Boundaries

The tested intermediate source was `b9c1cdd9`, based on `e2884812`. Its complete
non-deployment tree was imported onto `testnet-dev` at `671093a2`, without
merging deployment history backward. The final source is published as
`15d6316d1bd28bb535698a4797e3c6261e6c9597` on both `testnet-dev` and
`prepare/testnet-dev-runtime-20261031`. It also retains the six local-tool
updates from Audit `dbcdc7c9`, English source comments, and focused review
corrections. The restored epoch-32 prerequisite `psy-genesis` at `9ed70c1` was
already published; it is not promotion of new final artifacts.

The deployment merge's non-`deploy/` tree must be byte-identical to this source
except the explicitly integrated `psy-genesis` gitlink at `8346116`. Parent
integration `a515b950` changes only that gitlink; downstream Cargo pins and the
immutable runtime build worktree remain at `15d6316d`.
`runtime_inputs_frozen` is now true for the offline version-2 build:
the published Node/consumer pins, clean regenerated public contracts and
retained-membership config have been reviewed together. The build spec must
separately bind the exact config, external bundle, stamp and release profile.
This is build-input approval only, not runtime, installation or activation
approval. Actual-key Genesis and its native bootstrap replay are now verified
offline, as recorded below. Core host packages and SDK/WASM build/init checks
are also complete; peripheral packages, full proving/resource tests, setup,
runtime review holds and E2E remain open.

The current preview profile SHA-256 is
`8c9a4de713f343240e081e7d1aa253ea02c340edae2df3411ffbf05e59bc3282`.
This is a preparation checkpoint, not the eventual final release hash. The CLI
planner requires that hash and checks supplied config bytes against the profile.

Scoped release-mode results after corrections:

| Suite | Passed |
|---|---:|
| Faucet | 32 |
| Submission-error classification | 4 |
| Provider (unchanged since its first passing port run) | 162 |
| Relayer, including BSC fee policy | 423 |
| Reputation, Worker API and PR30 redelivery | 68 |
| Rollback snapshot/executor regression | 84 |
| Node core | 69 |
| Memory store | 6 |
| NATS unit tests | 7 |
| Real Redis replay integration | 2 |
| Build / plan / L1 packaging | 89 |
| Config preparation / preflight | 23 |

Failures from earlier runs are retained. Old Faucet/Worker fixtures were fixed
without relaxing production authentication. The Relayer regression now supplies
one explicit outcome per attempted row, preserving the existing failure charge
for genuinely missing outcomes. Two build-gate regressions failed before their
fixes (unfrozen profile and uncached local dependency cleanup), then passed.
These are scoped tests, not the full release DAG or real new-chain acceptance.
Evidence logs are local `tmp/fresh-*-20261031.log`; no logs or generated binaries
belong in this Git delivery. No live service was contacted or changed.

Source-integration checks: lifecycle **181 passed**, config **16 passed**,
CLI sibling-path test passed in both library and binary targets, wire validation
**1 passed**, and the XOR gadget prove/verify test passed in each of its two
crates on both baseline and final source. XOR production algorithms and gates
were not changed. The real public-token4 bytecode rejected all six high amount
words in the new ignored regression (**1 passed**). It returned no claim
witness and preserved the immutable backing checkpoint. VM assertions follow
speculative local writes, so failed sessions must be discarded; this is not
transactional rollback of a failed temporary session. Final token0/token4
Genesis/CFC/UPS acceptance and L1 oversized-admission caps remain pending.

Expanded deployment checks initially had **506 run, 4 failures, 9 errors**;
the unmodified published baseline `8db67eca` reproduced the same named failures
in 496 tests. Follow-up inspection confirmed a real adapter defect, not merely
a fixture error: `place_realm1_on_coordinator.py` required R3 package provenance
but requested R2 unit names and slice. Its unit names/slice now match the pinned
R3 installer. It still rejects both R2 and fresh SD192 package provenance before
deriving or writing output. The restart tests assert each component's actual
historical cohort independently: core/Workers are R3, while the old Proxy
packager deliberately remains R2. No artifact pin or runtime guard was relaxed.

After this correction, **507 core deployment tests passed**, including the new
cross-cohort refusal regression; the focused placement/restart suite passed
**15/15**. The fresh-profile tests also pass **23/23**. Preserve the earlier
baseline/failure logs, `tmp/deploy-legacy-isolation-red-20261031.log`, its green
counterpart and `tmp/deploy-core-all-tests-r2-20261031.log`. This closes those
13 historical failures, not the complete runtime/proof/E2E release DAG.

Before enabling the reputation port, all Edges must share one private Redis
database with `maxmemory-policy noeviction`. Every Edge and queue-creating unit
must agree on `NATS_WORKER_ACK_WAIT_MS` and existing consumer `ack_wait`.
The fresh planner emits one explicit lease on all 16 units; live acceptance
must still check Redis policy and actual consumers. No Worker upgrade is needed
for fresh fetch signatures or matching submit tags.

Known residual risk: an in-flight accepted proof can race with job redelivery;
the replaced claimant may receive one lease-expiry penalty and miss its success
credit. Removing this race needs a claim-lifecycle change, not a weakened proof
check. Readiness age/timeout WARN metrics are also follow-up work.
The pre-zero claim absorption applies only while the worker remains at zero.
After recovery an old claim may cause another penalty: the record does not
persist a separate historical zero-transition timestamp. This is a disclosed
policy limitation, not a claim that every outage is globally deduplicated.

Faucet full-policy proof/memory acceptance, including the default 10-recipient
batch, is still pending. Pure capacity checks do not prove that resource gate.
The stale-anchor retry can exhaust the only operator's exclusion set; before-
submit already-claimed now returns immediately, but that exact behavior lacks
a standalone end-to-end test. These affect retry availability, not permission
to retry an uncertain submission. Final Guardian/deposit-cap acceptance and
sanitized readiness failure classifications remain release follow-ups.

The old host, Services and Faucet installers are still R3-only. In particular,
the old Faucet source/artifact pin must not be renamed to an unbuilt candidate.
Finish their release/namespace/artifact migration after final hashes exist.
The version-2 core plan is a preview, not an installation package.

## Source And Consumers: Current Preparation

Every active Node Cargo dependency in Compiler, SDK and Services now resolves
the published source `15d6316d1bd28bb535698a4797e3c6261e6c9597`. The native
release library checks passed for all three using locked/offline resolution,
testnet selection, and the canonical epoch-32 config. These are not WASM or
final generated-artifact checks. The exact staged TOML/lock deltas passed
independent review: only Node SHA strings changed; package versions, registry
checksums, features, aliases and dependency lists were preserved.

| Repository | Preparation Commit | Destination |
|---|---|---|
| Node | `15d6316d1bd28bb535698a4797e3c6261e6c9597` | `testnet-dev`, `prepare/testnet-dev-runtime-20261031` |
| Compiler | `e9cc57fe5b1d7068f5c40f03b8b7f03058f6813f` | `prepare/sd192-20261030` |
| SDK | `a2e3dc8c59e11465208f43e45250b74d96983032` | `prepare/sd192-20261030` |
| Services | `e04493b70673e5d5314aa203ab293997c8c5e4fa` | `prepare/sd192-20261030` |
| Genesis contract artifacts | `8346116acce272196bcfeb4d9885a9e9f790f171` | `prepare/sd192-20261030` |

Use the canonical `PsyProtocol` repositories. The local Services worktree's
configured origin still points to `QEDProtocol`; publication uses the explicit
authorized `PsyProtocol/psy-services` destination without changing shared Git
configuration. The existing withdrawal-identity fix remains in its ancestry.
No npm version was reserved or published. SDK release WASM/TypeScript and dry
packing are complete, as detailed below. The SDK and Node parent Genesis
gitlinks now reference published `8346116`; Node integration is `a515b950`.
The new client cohort and full proving acceptance remain pending. No Cargo
consumer moved away from immutable source `15d6316d`.

### SDK Build And Core Packages: October 31

SDK `a2e3dc8c` was built through the existing `pnpm` build and `publish:check`
entrypoints, not manual replacement of generated bindings. Web and Node.js
prover WASM, compiler WASM and TypeScript builds passed; all three packages
passed dry packing without npm publication. Nine offline SDK test suites passed
**62 tests**. Actual initialization of both prover modules and the compiler
module passed; both provers report `testnet`, identical constants and bigint
fees. This is build/initialization evidence, not full EndCap proving acceptance.

The SDK uses the public canonical config (`7274eebb...07b9db9`), not the retained
private-topology runtime config (`04d3056c...72f8024d`). Both use epoch 32 and
the same consensus constants. Private Guardian/P2P custody and private runtime
endpoints are not copied into public WASM. Compiler provenance is clean
`e9cc57fe`, and both SDK and Genesis stamps were regenerated by their owning
scripts. Package versions remain unchanged; these candidate bytes are not a
newly published npm `2.1.0` release.

The pinned Bookworm builder ran offline with a 96 GiB memory limit, no extra
container swap and a dedicated SDK target directory. It used Rust
`nightly-2025-09-20`, Node `22.23.4`, pnpm `10.34.5` and official wasm-pack
`0.13.1` musl (archive SHA-256
`c539d91ccab2591a7e975bcf82c82e1911b03335c80aa83d67ad25ed2ad06539`).
SDK/Compiler use their respective locked wasm-bindgen `0.2.126`/`0.2.125`
executables; no version or lockfile was falsified to bypass tool selection.
The host glibc-linked wasm-pack and two incomplete npm mounts failed before
the successful runs. These environment failures are retained separately.

Core preparation commit `79286147` adds explicit `--cohort sd192` packaging
and installation. Historical R3 remains the default; its activation and
temporary placement tools remain R3-only. Independent review approved the
delivery. Its conditional compatibility question was checked: shipped R3
`topology.json` already has the exact R3 release/source fields, and all old
tests still pass. The complete core suite passed **532 tests**, including
**13** new cohort tests; fresh-profile tests passed **23 tests**.

The real six host packages are local-only under
`.private/core-testnet-20261031-sd192-packages/`. They contain **16 units** and
only each host's required keys (**24 scoped key files** total). Every package
passed the installer's read-only payload/permissions/hash validation. The
builder reused the successful actual-key Genesis and 100-operator export;
it neither regenerated identities nor distributed the full key/operator list.
Nothing was transferred, installed, enabled or started. See
[the core packaging procedure](../core-only/README.md#fresh-sd192-preparation).

Public package-manifest and WASM hashes are in [artifacts.json](artifacts.json).
Local evidence: `tmp/fresh-host-packages-20261031.log`,
`tmp/fresh-host-packages-verified-20261031.json`,
`tmp/sdk-sd192-build-r4-20261031.log`,
`tmp/sdk-sd192-drypack-r3-20261031.log`, `tmp/sdk-sd192-unit-20261031.log`,
and `tmp/sdk-sd192-wasm-smoke-r2-20261031.log`. The first smoke invocation did
not attach stdin to Docker and executed no assertions; only the second log is
acceptance evidence. Hashes in the public receipt refer only to successful
runs. Private package contents and binaries are deliberately not committed.

### Current Full Contract Generation

The current producer is published Compiler `e9cc57fe`, still consuming Node
`15d6316d`, with published Genesis artifacts `8346116`. The full original Make
recipe exited zero again after the canonical-layout correction below. All six
compiler artifacts and exported ABIs now carry `contract.state_layout`.
Lossless JSON comparison against `6ec29ad9` confirms every non-layout value in
the two token artifacts and six ABIs is unchanged. The ABI index and compressed
contract bundle are byte-identical. The current token hashes are:

| Artifact | SHA-256 |
|---|---|
| `token.json` | `0a7ace149a23f2380c1dff715b4e2bad204ccd900bfdb43a44d4962418e255df` |
| `token.update.json` | `895df2389d9d2108fcd2cfff8484ef4a3b5becfe6892105600b695062c8b9f57` |
| Compiler stamp | `4b22bb7aed61caf4156f1709a52ccc43999737f6bf29342f58d8c63cea4d8c61` |

The constructor process approached the initial 32 GiB container ceiling, which
was increased to 48 GiB during this successful offline recipe. This is not a
runtime service sizing result or an exact peak-memory measurement. The operator
subsequently approved a **96 GiB** local build ceiling; the maintained pinned
CLI builder now applies it, without extra swap allowance or preallocation.

#### Retained Earlier Contract Generation

Clean published Compiler `81e0a022`, consuming Node `15d6316d`, completed the
entire original `make gen-deploy-json` recipe in the pinned Bookworm image:
six real Plonky2 contract circuit sets, token/update artifacts, all six ABI
exports and the automatic provenance step. The successful run exited zero and
ended with `psy-genesis contract artifact + genesis_abi/ + compiler provenance
regenerated`. No manual stamp recovery was used.

The first run stopped before contract compilation because Make expected its
default local `target/release/dargo`, while the build uses an external Cargo
target. The corrected invocation uses Make's existing `DARGO` override to the
same just-built binary. Node is mounted read-only and the clean Compiler Git
metadata is exposed read-only for the original provenance step. Keep both
`tmp/compiler-runtime-genesis-generation-20261031.log` and the successful
`tmp/compiler-runtime-genesis-generation-r2-20261031.log`; the former is not
reported as a success. The reusable invocation is in [README.md](README.md).

The bundle, token/update files and every ABI are byte-identical to `a486a531`:

| Artifact | SHA-256 |
|---|---|
| `genesis_contracts.json` | `0f4a4a8cbeaff5621d05fa795b6aa157809eb5753fde1c5da62027753bbb9c9f` |
| `token.json` | `36cb09dc75798a28a09586067f6b577da4e1eb675522d5bea4507fb15d886ddd` |
| `token.update.json` | `d4fdcd384595bc4899a4115275f78fe72e8c3a1c726f18844245b58f22858ff6` |

Only the automatic Compiler revision/source hash and the Genesis README
changed in `6ec29ad9`. Their exact staged diff passed independent review.
This closes public contract regeneration, not actual-key network Genesis,
native bootstrap, full-policy SD-key proof/memory, five-entry EndCap,
SDK/WASM, bridge setup or three-chain E2E gates.

### Actual Genesis Attempt And Layout Correction

The first real spec-v2 import attempt used the final measured privacy circuits,
the retained 107-slot key array, old public Genesis `f839b453...`, and config
`04d3056c...`. It failed closed at token0 before native account-output writes:
the Compiler ABI lacked `contract.state_layout`. Public bundle regeneration
and its provenance alone had not established native input compatibility.
The protected failed directory and private child log were retained; the log
contents were not published. No key was regenerated and no old file overwritten.

The missing producer change was the already-published `4579984c` canonical ABI
export, omitted from the newer preparation branch. Its narrow port `e9cc57fe`
changes only ABI extraction/types/tests, not Cargo pins, token source, circuit
logic or storage footprints. All **25 `psy-abi` release tests passed**, including
six layout regressions using both real token ASTs, map padding and refusal cases.
The full staged source port and generated artifact diffs passed independent
review before publication. Source Node `15d6316d` remains unchanged.

Genesis native children now receive fixed `RAYON_NUM_THREADS=4`, even when the
shell supplies 128. The regression failed before this change and all **22**
Genesis-adapter tests pass after it. The complete core deployment suite passed
**519/519** after that correction; the subsequent 96 GiB container change passed
all **21** build-runtime tests. These are not real proof/E2E acceptance.

Fresh CLI/tool manifests must bind the new compiler stamp rather than rewriting
the older receipts. The earlier five-CLI builds were byte-identical and passed
five help/GLIBC checks, but their stamp points to superseded Compiler `81e0a022`.
Keep those artifacts as evidence, not the final package.

The refreshed build completed against Compiler `e9cc57fe`, config `04d3056c...`
and the new stamp `4b22bb7a...`. All five CLIs again passed help checks and require
at most GLIBC 2.34. Their executable bytes are identical to the two earlier
clean builds; the new receipt records the changed provenance and 720 release
library hashes rather than rewriting an old manifest.

| Local Receipt | SHA-256 |
|---|---|
| CLI build `fresh-runtime-release-r3-20261031/manifest.json` | `b0bc11e35553a3fb71c068e05b9aeadb478366290fb38adfa370a8dd2284064c` |
| Linked tools `fresh-genesis-tools-r5-20261031/manifest.json` | `c61c14f9c37c97befe6fe21407eea95be99cda4f3afe8ad8e12e6b7ebc0af092` |
| Final privacy measurement JSON | `d2fdb8bc4d715adc17722a62d5511f18652b59768d676579ca73fd20eb7a258a` |

These directory suffixes identify local build attempts, not the deployed R3
chain. The measurement constructed both real minifier circuits and matched the
previously recorded deposit/private-note limbs. The tool linker also passed
two invalid-argument checks; its Rust unit harness was not run or counted.
Both receipts still report `deployment_ready=false`.

The next actual import reached the account-input guard after contract checks,
then correctly refused an environment ownership mismatch: this managed shell's
directory descriptors reported root ancestors as UID 65534, while path-based
stat displayed UID 0. Public path permissions and retained key bytes were not
the defect. That FAILED directory was retained too; no account output was
written. A read-only-root, network-disabled builder container was verified to
report descriptor UID 0 with effective UID 1000. The unchanged preparation
script completed there with the same spec/inputs, read-only custody mounts,
a separate writable private output parent, and the approved 96 GiB ceiling.
No importer permission check was weakened. The environment-wrapper procedure
is in [GENESIS.md](../core-only/GENESIS.md#managed-shell-directory-ownership).

The real import and typed validator both exited zero. The result is
`READY_STATIC`, not deployment approval. The final public Genesis SHA-256 is
`a448ef86cedea5c35847e22f635e912b77948715dcbb899191301361985dd29f`.
The original 107-slot private-key array and new protected export are byte-identical;
the inventory contains 100 distinct Faucet user IDs. All operators use the
measured SD192 full-policy fingerprint `d48255a1...ca95a109`, min/max transaction
counts 1/64, with the expected caller restrictions. Validator identities and
Guardian policy parameters passed the strict retained-account checks; only
the explicitly opted-in Faucet/Relayer fingerprints changed.

The existing `retained_genesis_token_layout_must_be_nonempty` test then replayed
that exact public artifact through the production Genesis builder in release
testnet mode: **1 passed, 0 failed**. It checked both token layouts (8 fields,
8,594,128,984 felt slots each), all 107 registrations and six memberships,
nonempty global roots, and the checkpoint-0 base. The public replay log SHA-256
is `9c7705f9fde2d0652ecd4621b2fdf1dd63c1f585eeda5278e7b72a0e75e0caff`.
This initializes trees without opening a database/network or producing a proof.

Local retained output: `.private/core-testnet-20261031-sd192-genesis-container/attempt1`.
Key exports and both child logs remain protected and are not Git artifacts.
The public [artifact receipt](artifacts.json) records only identities/hashes,
checks and remaining holds. Old installers do not consume or approve this receipt.

## Historical October-30 Preparation

The published Node candidate is
`e28848127f4cef87bea4e63cc9fb9b79edc18d93`, on the historical topic
`fix/sd-key-calldata-196-20261030`. It contains the final **192**-word limit
and the explicit independent fresh Faucet/Relayer identity transitions. Earlier
GitHub SSH failures were resolved by explicitly selecting the existing local
identity with `IdentitiesOnly=yes`; no agent or replacement key was needed.
The reviewed deployment integration and build-log improvement were pushed
through `f5712365` before this status update. Never force-push.

Three isolated consumer candidates are committed and published on `prepare/sd192-20261030`:

| Repository | Published Commit | Checks Passed |
|---|---|---|
| Compiler | `2cc4f670c20443cab10c6cb7462135f856d8527b` | Locked metadata and release check of `psy-precompiles --lib` at predecessor `708c4c6b`; full-recipe ABI regression at `2cc4f670` |
| SDK | `e85f44cc09873117eeff6beb65c182473e567eb7` | Locked metadata; release library check |
| Services | `4e79359f7e2bc1960e8520cec44201bc82fb50bb` | Locked metadata; release library check |

All three dependency graphs resolve one consumed Node revision: `3c34ab57`.
The later Node CLI/tests/docs fixes through `e2884812` change no consumed library
source; final cohort pin/build reconciliation remains required before
release. Only Git
source pins changed in their TOML/locks; package versions, features, aliases,
registry versions/checksums and dependency lists stayed unchanged. Compiler
and SDK also resolve the already-selected Node Gnark closure to the
`hellojason3/gnark-plonky2-verifier` commit
`96a1d13b31f440316af1af7225943a1260f5150d`, rather than the old upstream pin.
Services has no Gnark dependency. The three-repository dependency-pin diff
passed independent review before commits; the later Compiler Makefile/test fix
was reviewed separately. These candidate branches are pushed
but not integrated; no new npm version is reserved or published.

The checks used the immutable Bookworm image, release mode and compiled
testnet selection. They used the canonical template config, not the final
membership-populated config below. They are compilation checks, not WASM,
new compiler-contract generation or final release artifact acceptance.

## Actual Config Candidate

**Superseded:** the old hash below describes the October-30 candidate. It omitted
the retained internal Coordinator endpoints and is no longer accepted by the
repaired preparation/preflight. The repaired script has now regenerated the
config from the same two hash-verified public inputs, retaining internal ports
15370/15371/15372. The new hash is
`04d3056c4e1d000e6b67f11f6f1a4bc2f5c7df9024f182e71c6ced7472f8024d`,
frozen as `runtime_config_sha256` in the profile. Local candidate:
`tmp/fresh-runtime-config-20261031/`. No private keys were read. Use build-spec
v2 after final source publication; do not reuse the superseded output.

The canonical checked-in config defaults to localhost and has no testnet
Guardian, Validator or Worker identities. `PSY_NETWORK=testnet` selected
testnet during the checks; the template itself is not a usable host config.

`prepare_config.py` assembled a candidate from that hash-pinned canonical
config and the retained approved public testnet config. No private-key files
were opened by the script. It selects testnet, keeps epoch **32**, retains **3 Guardian commitments,
6 Validator memberships and 2 Worker whitelist keys**, and enables the
whitelist. Existing identity files were not edited.

| Input/Output | SHA-256 |
|---|---|
| Canonical template | `7274eebbd98e17c1e76ead05793a9d5c503311469990a93d7aad1e07e07b9db9` |
| Retained approved config | `c8ee7c97e1158cd09e8fee5167f80f838f6048084028f3f9e80e239aac24e8d0` |
| Candidate config | `d044bb4b16fc1a06a2c5a44a771271665b98c08a8db3d10ba0a6d1829d88ffbf` |

The hardened script rejects unknown nested fields, credential-bearing RPC URLs,
nonempty old Guardian history and hashes outside the checked-in release profile.
Ordered Guardian endpoint ids match the three commitment slots; this is not
cryptographic endpoint authentication or proof of possession.

Local artifacts: `tmp/sd-key-calldata-196-20261030/runtime-config-192-reviewed/`.
Read-only preflight passed both exact source and config checks. Its output
still says `deployment_ready=false` and `activation_authorized=false`.
Host/key provenance and native acceptance are separate checks.

## Completed Regression Milestones

- Native Genesis tests: **57 passed, 1 previously ignored**. Both fingerprint
  transitions failed against their old guards and pass with independent opt-ins.
- Genesis adapter: **22 passed**, including old-v1 preservation and explicit
  v2 epoch-32/combined command forwarding. Children are mocked.
- Network assembly: **37 passed**; the historical default remains epoch 10.
- Source/config preflight: **11 passed**; config preparation: **8 passed**.
- Fingerprint measurements remain as recorded in [FINGERPRINT-AUDIT.md](FINGERPRINT-AUDIT.md).

## Remaining Work

1. Keep the published source and deployment runtime trees aligned. Runtime
   integration into `testnet-dev` is complete at `15d6316d`; never merge
   deployment scripts backward. The historical deployment-test failures are
   resolved above; the remaining runtime and actual-artifact gates still apply.
2. Public contract regeneration is complete as recorded above; rebuild again
   if the consumed library or generation inputs change. Rebuild
   compatible SDK/WASM if inputs change; the current build/init and parent
   gitlink milestones are complete. Publish producers before downstream pins.
3. Actual-key Genesis and the 100-operator export are complete using spec v2 and
   explicit `fresh-faucet-and-relayer` mode. The retained R3 Genesis has the
   old registration-2 multisig fingerprint. The separate Relayer opt-in accepts
   only the current compiled fingerprint; every public-key parameter, Guardian
   policy and Validator identity stays strict. Never widen the Faucet flag or
   overwrite the old Genesis. Keep the successful output and both failure
   directories as evidence; do not generate another set just for packaging.
4. Five CLIs, typed Genesis checks and production-builder replay are complete.
   Keep completed parent gitlinks and SDK artifacts on this accepted cohort,
   without moving downstream Cargo pins off source `15d6316d`.
5. Prepare matching Bridge setup/verifiers, peripheral packages and isolated state;
   measure full-policy proving/memory and pass real five-withdrawal and
   three-chain deposit/claim/withdrawal acceptance before activation.

Evidence logs and dependency graph audit remain under
`tmp/sd-key-calldata-196-20261030/`. Native check log SHA-256 values:

```text
SDK      195f4f61368d71567d9a175a3fc44729f411b6224a219ca7b4765fd3010eeba3
Compiler 996068f45e5793901e3fec2cf93b1d86ab3344ec7d5d749d1982f337a2bfa866
Services 0dcc27e1b3ecf613234e96b359fa9ef1966fdd6bbb673197d7e11ac31925d425
Lock DAG 76ac257a81a815946ae93e59f9297bac3fba5bf976643f5db5eb9621b266b959
```

## Historical Full Contract Generation: October 30

Published Genesis artifact candidate:
`a486a5314ce81f63dad76f9839f69380f0784be0`, branch `prepare/sd192-20261030`.
The clean published Compiler `2cc4f670` ran its original `make gen-deploy-json`
recipe with consumed Node revision `3c34ab57`, not `e2884812`.
All six full contracts, the token update variant, real Plonky2 bundle
construction and all ABI exports completed. The compressed bundle and both
token JSON files are byte-identical to their previous verified hashes in
[FINGERPRINT-AUDIT.md](FINGERPRINT-AUDIT.md).

The full recipe exposed two build-environment omissions: Docker did not supply
`PWD` (so Make selected an invalid standard-library path), and the pinned Rust/Go
image did not contain Node for the final provenance step. The temporary build
wrapper was changed to set `PWD` and mount the retained Node 22.23.4 executable
read-only. The corrected `PWD` allowed the contract and ABI stages to complete;
the Node mount/version was verified separately inside Bookworm. The full
Make recipe has not been rerun successfully with both corrections. No compiler
Rust or contract source was changed for those environment corrections.

The final provenance operation was recovered by replaying the exact original
`node -e` command extracted from `make -n gen-deploy-json`, at clean Compiler
`2cc4f670`, using host Node 26.12.1. No stamp fields were manually invented.
Retain `compiler192-generation.log`, `compiler192-generation-pwd.log` and
`complete-compiler-stamp.py`; this was not an uninterrupted successful Make run.
The recovered command's script SHA-256 is
`ba1cbdcf39ddce9e102da039f790e58ac08a701f5a4434f8f1edd3e428c5bc1b`.

The only Genesis repository content changes are updated Compiler provenance
and the withdrawal-tree ABI entry for the already-compiled `set_chain_root`
(selector 4192350829, 10 input Felts, no outputs). The recipe omission had a
failing regression, now passing across all six compiled/exported method sets.
Both source and generated diffs passed independent review before publication.
This is compiler contract-artifact preparation, not generation or acceptance
of the new network bootstrap `genesis.json`.
