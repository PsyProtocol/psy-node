# Offline Genesis Preparation

This is the deployment-branch entry for the Genesis refresh. Runtime fixes belong
on `testnet-dev`; reusable deployment tools and this procedure belong on
`deploy/testnet`, under `deploy/`. Temporary directories hold build outputs and
evidence, not an alternative deployment implementation.

## Scope And Order

Use the `PsyProtocol` repository organization for release sources. Check the
actual remote URL, not just the name `origin`: the historical QEDProtocol
compiler fork has a different `mainnet-beta`. Retain useful fixes from it as
reviewed narrow ports, not by replacing the current compiler with its old tree.
Select the compatible Genesis commit recorded by the release, not whichever
divergent branch happens to be called `mainnet-beta`.

1. Freeze and review the Node and compiler sources. Use `PSY_NETWORK=testnet`,
   the approved testnet config and Plonky2 throughout. Generate the full six
   compiler contracts with `make gen-deploy-json`, not the token update variant.
2. Rebuild the generator against the final contract bundle. Re-measure both
   compiled privacy-circuit fingerprints after regeneration; the final token
   bytecode must contain these same values. Retain build commands and hashes.
3. Compile `verify_genesis.rs` with the generator's exact release dependency
   rlibs and Rust toolchain. A verifier from an older release is not a substitute.
4. Prepare the hash-pinned public spec described below, then run `plan` and
   `generate`. Existing account keys, Guardian commitments and P2P membership
   are inputs, not values to generate again.
5. Replay the resulting Genesis through the production builder and complete
   the actual claim, Guardian, Faucet and P2P acceptance gates before rollout.
6. Only after acceptance, prepare a new release manifest and host packages using
   `plan.py` and `prepare_host_packages.py`, then install with `install_host.py`.
   Reconcile their source pins, release ID and fresh database namespaces first.

The topology, planner and network assembler now select the r3 preparation below;
host installers remain pinned to the preceding cohort. This procedure does not
repin installers, stop services, clear databases, install host packages, reset L1
contracts, or open public admission. Do not run an old
full-stack reset/start entrypoint to complete these steps. L1 replacement and
service startup require their own reviewed deployment steps after this gate.

## R3 Topology Preparation

Only `topology.json`, `plan.py` and `prepare_network.py` select:

- Runtime `3d31758738f833a7eea6f9ff7fd680a69a0d9a44`, not a later test-only commit.
- Release `core-testnet-20261027-r3`.
- All 16 planned units use `psy-core-r3-`, distinct from existing `psy-core-r2-`
  units; this is not an overwrite of same-name units.
- Namespaces `fresh20261027r3_coordinator` and `fresh20261027r3_r{0,1}_v{1,2,3}`,
  with each namespace bound to its exact role.
- Both Realms' Processor positions 1/2/3 on `.37/.42/.43`; the six retained
  Validator identities, registration order, ports and Edge placement are unchanged.

The tests consume the checked-in topology without overriding its cohort fields.
The planner still reports `deployment_ready=false`, `release_approved=false`
and exits 2 even when input consistency passes. Guardian custody provenance
remains `de539f565ec1a92f91bb4e9686e1442e89ba8639`.

Pending integration, not approved by this preparation:

| Files | Required before packaging or installation |
| --- | --- |
| `prepare_host_packages.py`, `install_host.py` | Freeze final binary/build identity and independently verified Genesis/config hashes; align r3 paths and namespace checks together. Existing r2 artifact pins are unchanged and reject an r3 package. |
| `prepare_workers.py` | Freeze worker, topology, build and attestation hashes; review release paths and slice names. |
| `prepare_proxies.py` | Freeze runtime/package pins and review retained-setup compatibility without bypassing circuit/config/bundle comparisons. |
| `install_guardian.py`, `guardian_exec.py` | Align runtime/release/state paths while retaining custody source and key hashes. |
| `install_relayer.py` | Align release/state/credential paths and refresh the exact imported Guardian helper hash after review. |

Do not copy old checkpoints or journals into fresh r3 state. Before activation,
the deployment owner must fence every old instance, including temporary Realm 1
Processors on `.25`, and review exact old unit/drop-in retirement separately.
New unit names do not authorize concurrent r2/r3 instances. Keep old r2 units
fenced before starting r3; do not narrow the installer's `psy-core-*` discovery
or its stopped-service/queued-job checks to only the new r3 names.
Keep the installer's existing-file, drop-in, active-service and queued-job guards.
Expanded hosts still require measured memory headroom and port/storage checks;
the core unit template does not itself impose MemoryHigh/MemoryMax limits.

Local direct tests, with no Cargo or remote operations:

```sh
python3 -B -m unittest discover -s deploy/multi-chain/gcp/core-only -p test_plan.py -v
python3 -B -m unittest discover -s deploy/multi-chain/gcp/core-only -p test_prepare_network.py -v
python3 -B -m unittest discover -s deploy/multi-chain/gcp/core-only -p test_prepare_genesis.py -v
```

## Pinned Inputs

`prepare_genesis.py` takes an absolute public spec path. Version 1 contains:

- `schema_version`: `1`.
- `block_time`: the approved Genesis timestamp, in seconds.
- `inputs`: `binary`, `config`, `bundle`, `bundle_stamp`, `validator`,
  `measurements`, `build_identity`, and `prior_genesis`.
- `compiler_artifacts`: `token`, `multisig_policy`, `deposit_tree`,
  `withdrawal_tree`, `usdt_token`, and `faucet`.

Every input/artifact entry is an object with an absolute `path` and a lowercase
SHA256 `sha256`. `bundle` is the full compressed contract bundle; `bundle_stamp`
is its compiler provenance file. Each compiler artifact is the corresponding
full compiled JSON, including its ABI and canonical layout metadata.
`prior_genesis` is the retained public account/Validator identity baseline;
its old contract bytecode is not reused.

Spec version 1 remains the historical R3 input: strict account identity import
and epoch 10. Version 2 requires two additional fields:
`checkpoints_per_epoch: 32` and `account_identity_mode`, either `preserve` or
`fresh-faucet`. Use `fresh-faucet` only for an approved fresh chain with a
changed Faucet policy/circuit. It adds the native generator's explicit
`--fresh-faucet-identities` flag; all private-key parameters, non-Faucet
fingerprints and validator roles still have to match the unchanged prior
Genesis. The plan and result record both choices. No version has a random-key
fallback, and version 2 does not repin the old host installers or build inputs.

`build_identity` contains exactly `schema_version=1`, `source_commit` (40 hex),
`psy_network=testnet`, `cli_network=psy-public-testnet`,
`proving_backend=plonky2-poseidon-goldilocks`, `private_keys_mode=import-only`,
`binary_sha256` and `config_sha256`. This is a caller-approved build record,
not an attestation generated by the wrapper.

`measurements` contains `schema_version=1`, `network=testnet`,
`node_source_commit`, `config_sha256`, `deposit_inclusion_fingerprint` and
`private_note_inclusion_fingerprint`. Both fingerprints are four decimal u64
limbs measured from the frozen build, not copied from the old token source.

Inputs must be regular, non-symlink, single-link files. Copy a Cargo executable
to the retained artifact directory if Cargo's output is hard-linked. The private
key input must be owned mode `0600`, with a protected parent accepted by the
native importer. Never put its contents in the public spec, shell output or Git.

## Commands

Run from the deployment repository, setting these variables to the reviewed
absolute paths and recorded private-key file hash. Use the **same inputs and
new output path** for both commands; `plan` does not create the output directory.

```sh
python3 -B deploy/multi-chain/gcp/core-only/prepare_genesis.py plan \
  --spec "$GENESIS_SPEC" \
  --private-keys-in "$GENESIS_KEYS" \
  --private-keys-sha256 "$GENESIS_KEYS_SHA256" \
  --output "$GENESIS_OUTPUT"

python3 -B deploy/multi-chain/gcp/core-only/prepare_genesis.py generate \
  --spec "$GENESIS_SPEC" \
  --private-keys-in "$GENESIS_KEYS" \
  --private-keys-sha256 "$GENESIS_KEYS_SHA256" \
  --output "$GENESIS_OUTPUT"
```

Generation imports the existing 107 registration slots, checks account
fingerprints/public-key parameters and six Validator role mappings before
writing, retains the 100 Faucet operators, injects the approved public P2P
membership through `prepare_network.py`, and runs the typed bytecode/layout
verifier. It has no random-key fallback.

## Outputs And Failure Handling

- `genesis.json`: final membership-injected candidate.
- `generated-genesis.json`: native output before public membership injection.
- `private_keys.json` and `faucetOperators.json`: protected custody outputs;
  never commit, publish or package them with public artifacts.
- `plan.json`, `measurements.json`, `result.json`: retained generation evidence.
- `generate-genesis-data.private.log`, `typed-cbor-validation.private.log`:
  mode-`0600` child diagnostics, never stream or publish them.

The output directory is create-only and mode `0700`; files are mode `0600`.
On failure, preserve the directory, logs and `FAILED` marker. Fix the cause and
use a separately reviewed new output path; do not overwrite, auto-clean, resume
or silently fall back to old contracts or new keys.

`READY_STATIC` means the offline checks completed, not deployment approval.
`deployment_ready` stays `false`. The typed verifier does not run real proofs,
construct a checkpoint or attest the supplied fingerprint measurements. The
generator owns compiler/deployment root agreement; the production builder and
real transaction tests remain separate acceptance gates.

## Tool Tests

```sh
cd deploy/multi-chain/gcp/core-only
python3 -B -m unittest -v test_prepare_genesis
```

These mocked-child tests cover orchestration, failure retention and input/key
boundaries. They are not evidence of successful real Genesis generation.
