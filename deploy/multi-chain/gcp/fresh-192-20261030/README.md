# Fresh Testnet: 192-Word Preparation

This is the next source/config preparation profile, not an activation package.
The published runtime candidate is
`15d6316d1bd28bb535698a4797e3c6261e6c9597`. Deployment scripts stay on
`deploy/testnet`; the same runtime source is published on `testnet-dev` and
`prepare/testnet-dev-runtime-20261031` without deployment history.
Neither a successful preflight nor a Git push authorizes reset or activation.

The runtime inputs are now frozen for the offline version-2 build only: source
`15d6316d`, the retained-membership epoch-32 config, and public contracts from
Genesis `8346116` / Compiler `e9cc57fe`. `runtime_inputs_frozen: true` permits
that build; it is not runtime approval or permission to reset/install/start.
The build spec separately pins the exact bundle, provenance and profile bytes.
Actual-key Genesis and production-builder replay are complete; the public
[artifact receipt](artifacts.json) records their hashes without private data.
Installer migration and all remaining acceptance gates below are still required.
The receipt is not an activation package and is not consumed by old installers.

`release.json` is the preparation role inventory. Historical `fresh-topology/`
and `live/components.json` describe older cohorts, not this deployment's inputs.
For this cohort: Relayer stays on `gcp-coordinator-worker`, Faucet on `arc99x2`,
SYSTEM on `arc99x1`, USER on `arc99x3`. Do not rewrite old observations as live
measurements. `topology.json` here is the core-only version-2 planning input.

```sh
python3 -B deploy/multi-chain/gcp/core-only/plan.py \
  --topology deploy/multi-chain/gcp/fresh-192-20261030/topology.json \
  --release-profile deploy/multi-chain/gcp/fresh-192-20261030/release.json \
  --release-profile-sha256 "$RELEASE_PROFILE_SHA256"
```

This read-only preview returns 2 until acceptance is complete. It renders 16 core
units only when the caller supplies the reviewed profile SHA-256. Obtain that
hash from the accepted preparation record, not an untrusted replacement profile.
When config is supplied, its exact bytes must match the profile too. It renders
units in seven fresh namespaces from `namespace_prefix`; it does not install
them. The historical host, Services and Faucet installers still require their
own artifact/namespace migration and must not be used with these new inputs.
All core Edges must use the same private Redis database for cross-Edge fetch
replay protection. Per-role namespaces do not partition the replay keys.
The version-2 plan sets `NATS_WORKER_ACK_WAIT_MS` on all 16 units from one
release value (initially the unchanged 30000 ms default). Before activation,
check actual JetStream consumer `ack_wait` against it and measured proof p99;
adjust the release value consistently if necessary, never only the Edge.
Check the shared Redis instance uses `maxmemory-policy noeviction`: eviction of
a live replay key would reopen that signature. The offline planner cannot
certify either live Redis policy or existing JetStream consumer configuration.

## Preparation Parameters

`release.json` records testnet magic `0x1337CF514544CF69`, Plonky2, epoch 32,
192 calldata words, 64 introspectable transactions, 100 Faucet operators,
two Realms with three validators each, and the three existing Guardians.
Bridge Reader is excluded. Only PSY (L2 contract 0) and pUSDT (contract 4)
may be admitted; native deposits and initial public deposits stay disabled.
Host roles are preparation inputs, not fresh SSH or resource measurements.

See [the measured circuit alignment](FINGERPRINT-AUDIT.md). Inclusion, EndCap,
ZK and both secp fingerprints match; Faucet SD-key identity changes. These
measurements do not replace the downstream rebuild and Genesis gates below.
See [the latest preparation status](PREPARATION-STATUS.md) for local consumer
commits, actual config evidence and remaining release work.

The Relayer candidate already supports L2 withdrawal-tree append packs of
1, 2 and 5. Five withdrawals use one `batch_append_withdrawals_5` call with
176 Felt inputs, fitting 192. Use that existing packing rather than porting
the old 128-word `2 + 2 + 1` workaround into this cohort. This is not five
parallel L1 sends, nor a change to L1 deposit aggregation. Keep smaller-pack
regressions and require real five-entry Guardian/SD-key/EndCap acceptance
against the new Genesis before rollout.

## Read-Only Preflight

```sh
python3 -B deploy/multi-chain/gcp/fresh-192-20261030/preflight.py \
  --source "$RUNTIME_SOURCE" --config "$CANONICAL_RUNTIME_CONFIG"
```

This only reads public files and local Git identity/status. It never contacts
nodes, reads private keys, runs Cargo, writes configuration, broadcasts, or
starts/stops services. Missing or inconsistent inputs return 2. Input contents
are not logged. The selected runtime config must already select testnet,
use epoch 32, enable the owned worker whitelist, and carry the retained public
Guardian commitments and six-validator membership. Format checks do not prove
curve-point validity, key possession, provenance or native Genesis acceptance.
Those remain separate runtime checks. A zero exit means these limited input
checks passed, never that `deployment_ready` or `activation_authorized` is true.
The source checkout is operator-trusted: repository-configured Git filters may
execute during status checks. Inherited Git directory/worktree overrides are
removed. All six validator identities must be structurally complete and unique;
this does not establish retained-key provenance or curve-point validity.

The historical `core-only` version-1 planner default and installers still pin
R3 source, epoch 10, old account identities, artifact hashes and namespaces.
The new version-2 preview above is not an updated installer. Do not call old installers with
renamed inputs or replace only their version strings. Likewise, the historical
`source-versions.env` and published SDK 2.1.0 are not this release lock.

## Preparation And Remaining Gates

1. Source publication and all three downstream Node Cargo pins are complete
   at `15d6316d`; retain that immutable source during final artifact integration.
2. Rebuild Compiler and full contract artifacts, measuring affected fingerprints
   and checking token0/token4 layouts, methods and privacy bindings. Public
   contract regeneration completed at Genesis `8346116`, including canonical
   ABI layouts missing from the predecessor; final native
   actual-key network acceptance is still required.
3. Prepare a fresh Genesis and 100 Faucet public identities. Retain Guardian,
   P2P, worker and operator private-key material; the changed Faucet fingerprint
   does not preserve old public identity. Use the reviewed explicit transition
   below; never rewrite the old baseline or disable its identity check.
4. Rebuild the SDK/WASM and clients from the accepted cohort. No npm publication
   is included here. Measure the full 64-slot SD-key resource envelope.
5. Build the five CLIs with the pinned offline Bookworm procedure in
   [BUILD_RUNTIME.md](../core-only/BUILD_RUNTIME.md). Bind the actual config,
   bundle/stamp, source and image, retaining build manifests and hashes. A cache
   build against previous bundle inputs is preliminary, not the final package.
6. Adapt packages/activation scripts and isolated namespaces, journals and
   indexer cursors. Do not transplant old chain state. Resolve baseline holds
   from [REVIEW-NOTES.md](../fresh-sdk210-20261030/REVIEW-NOTES.md).
7. Prepare matching L1 setup/verifiers and paused fresh contracts for all three
   chains. The shared L1 runner now checks the compiled Router ABI before
   broadcasting and checks dual mappings/native rejection at one block before
   writing success readbacks. It does not automatically recover or redeploy
   after a partial deployment or failed readback.
8. Complete real illegal-then-legal deposit, claim and withdrawal E2E for each
   chain before opening public deposits. Mocked readbacks are not this gate.

The PostgreSQL installer now fixes 2 GiB Docker shared memory and compressed
`100m`/100-file logs, checking actual container policy before readiness. It is
a fresh installer that replaces a container, not a live database maintenance
command. Hasura's existing bounded logging remains unchanged.

## Fresh Faucet And Relayer Generation

Before network Genesis assembly, regenerate the compiler-owned public contracts
from the clean published Compiler with the same published Node Cargo revision.
Use the pinned Bookworm build environment and its accepted public config. The
original Make recipe supports an external Cargo target directory through this
explicit command override:

```sh
PSY_NETWORK=testnet PSY_CONFIG_PATH="$PINNED_CANONICAL_CONFIG" \
  make gen-deploy-json PSY_NETWORK=testnet PSY_GENESIS="$PREPARED_GENESIS_REPO" \
  DARGO="RUST_LOG=dargo=info $CARGO_TARGET_DIR/release/dargo"
```

Do not use the default repository-local `target/release/dargo` when Cargo writes
to an external target. Require the recipe's final provenance marker and a zero
exit; compilation alone is not success. The image must include Node and expose
the clean Compiler's Git metadata read-only for the original provenance step.
Inspect generated diffs, hashes and ABIs before publishing the Genesis child.
This builds `genesis_contracts.json`, not the membership-populated network
`genesis.json` or any private keys. Actual network assembly follows below.

The native generator now accepts `--fresh-faucet-identities` only alongside
hash-pinned imported keys and prior public Genesis. It permits a common old
Faucet fingerprint to change to a common new nonzero fingerprint for every
operator. In `fresh-faucet` mode, every public-key parameter and all Validator/Relayer fingerprints and
the six Validator role mappings remain checked. The normal import mode still
rejects all fingerprint changes. This is not a live account migration.

Use the existing `core-only/prepare_genesis.py` entrypoint, not manual JSON
rewrites. Its version-2 public spec adds these exact fields to the version-1
input set documented in [GENESIS.md](../core-only/GENESIS.md):

```json
{
  "schema_version": 2,
  "checkpoints_per_epoch": 32,
  "account_identity_mode": "fresh-faucet-and-relayer"
}
```

The block time, eight pinned public inputs, six complete compiler artifacts and
separately hash-pinned private-key array are still required. The snippet is not
a complete generation spec. Run `plan` first, then `generate` with the same
spec, keys and new protected output path. Both record the selected identity
mode and epoch; combined generation passes each native opt-in flag exactly once.
Version 1 remains strict import with epoch 10. Nothing silently upgrades it.

The retained R3 Genesis also has an older registration-2 multisig fingerprint.
The combined mode adds the separately guarded `--fresh-relayer-fingerprint`:
only that registration may change to the compiled multisig fingerprint, and
its public-key parameter/Guardian policy must stay equal to the prior Genesis.
The original `fresh-faucet` mode never permits this additional transition.
Do not reuse old-chain Guardian/Relayer journals with the new identity.

The generator transition passed 57 release tests (1 existing ignored test).
Deployment adapter tests passed 22 tests, and the network-assembly regressions
passed 37. Adapter children are mocked: these results do not establish that
the final actual-key Genesis or matching Compiler/SDK artifacts exist.

## Retained Public Configuration

`prepare_config.py` creates a new protected candidate directory from two
hash-pinned JSON inputs: the canonical config at the selected Node/Genesis
revision and the retained approved testnet config. It keeps canonical
consensus parameters and selects testnet, retaining only Guardian commitments,
the approved ordered Guardian endpoints, internal Coordinator endpoints, Realm membership and the Worker
whitelist from the prior config. Nested identity objects have exact field
allowlists; credential-bearing RPC URLs reject. Nonempty Guardian governance
history rejects and no history is copied. The two input hashes must match
`release.json`, not merely caller-supplied hashes. The script opens only these
config files and the release profile, never keystores or private-key files;
it does not modify inputs or contact hosts. Inputs remain operator-trusted.

```sh
python3 -B deploy/multi-chain/gcp/fresh-192-20261030/prepare_config.py \
  --canonical "$CANONICAL_CONFIG" --canonical-sha256 "$CANONICAL_SHA256" \
  --retained "$RETAINED_CONFIG" --retained-sha256 "$RETAINED_SHA256" \
  --output "$NEW_CONFIG_DIRECTORY"
```

Outputs are mode-0600 `config.json` and `manifest.json` in a new mode-0700
directory. Existing output paths reject rather than overwrite. Preserve any
partial output for inspection. This establishes only local format/identity
continuity: verify actual private-key possession, host addresses, native config
acceptance and Guardian quorum before rollout. Keep generated configs outside
Git and public client artifacts. Build final caches/artifacts with this exact
accepted config; the earlier template-based checks are not that final build.
