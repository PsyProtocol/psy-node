# Pinned Offline Node Build

Use the deployment checkout's entrypoint, independently of the runtime checkout:

```sh
bash deploy/scripts/build-linux-artifacts-bookworm.sh --pinned-node-spec "$BUILD_SPEC"
```

`BUILD_SPEC` names an operator-owned JSON file outside tracked source. This mode
builds only `psy_node_cli`, `psy_worker_cli`, `psy_user_cli`, `psy_relayer_cli`,
and `psy_dev_cli`. It never builds Services, packages host releases, generates
Genesis/circuits/keys, or performs remote operations. Without the explicit flag,
the historical shell entrypoint is unchanged. Services builds remain separate.

## Spec

All fields below are required; extra or duplicate fields are rejected. All paths
are absolute, have no symlink components, and contain no parent traversal or
Docker mount delimiters. Supply only approved public artifacts, never keys or
runtime environments. Python 3.11+, Git and local Docker are prerequisites.

| Field | Value |
| --- | --- |
| `schema_version` | Integer `1` for historical epoch-10 R3; integer `2` for the fresh epoch-32 cohort |
| `source` | Object with `path` and full lowercase 40-hex `commit` |
| `inputs` | `config`, `bundle`, `bundle_stamp`; version 2 also requires `release_profile` |
| Each input | Object with `path` and lowercase 64-hex `sha256` |
| `builder_image` | Already available local `sha256:` image ID, 64 lowercase hex digits, linux/amd64 |
| `caches` | Object with existing directory paths `cargo`, `target`, `go`, `go_build` |
| `output` | New directory; existing owned parent, not group/world writable |
| `jobs` | Positive integer, at most 256 |

Version 2 binds the full source commit, selected testnet config SHA-256, magic,
epoch **32** and `plonky2-poseidon-goldilocks` to the separately hash-pinned release
profile. The profile needs `runtime_config_sha256` from the final accepted config
and an explicit `runtime_inputs_frozen: true`. The preparation profile stays false
until source publication, consumer alignment and input review; it cannot build a release. Version 1
cannot build epoch 32. Profile/config hashes are checked around every phase.

The selected source must match its commit and be clean, including initialized
submodules. An existing **empty** `source/psy-genesis` directory is supported;
unused DApp or contracts submodules need not be populated. The pinned source's
recorded submodule identities are provenance, not the external bundle identity.

`bundle` must be named `genesis_contracts.json`. Its parent is the external full
Genesis directory; `bundle_stamp` must be in that same directory. The stamp must
bind the exact compressed/plain bundle bytes, byte size and compiler revision.
This directory must contain a regular `config.json`, even when its bytes differ
from the separately pinned canonical config. The source and external Genesis
directory must be separate. The entire external directory is mounted read-only
at `source/psy-genesis`, then the pinned `config` is mounted read-only over its
`config.json`. Thus an empty source directory needs no copied files, and both
`PSY_CONFIG_PATH` and the nested build-script read see the same canonical config.
Only testnet magic is accepted; no arbitrary child arguments/environment, target
features, network selector or fallback config can be supplied through the spec.

## Build Boundary

- The source, Git metadata, external Genesis, canonical config and output are
  read-only container mounts. Four selected caches are writable. Cache/output
  paths must not overlap one another, inputs or Git metadata.
- Existing builder image only: `--pull never`, `--network none`, caller UID/GID,
  isolated HOME and explicit environment. No image build, package install,
  host SSH agent/key mount or online fallback. Missing dependencies fail.
- Cargo uses `--offline --locked --release`; Go uses the supplied module/build
  caches with `GOPROXY=off` and `GOSUMDB=off`. The dated Rust toolchain comes from
  the pinned source. Cargo, Rust and Go caches are trusted operator inputs;
  this is not protection against malicious cache contents or build scripts.
- All local packages discovered from full locked Cargo metadata, including path
  dependencies outside the workspace, are cleaned before compilation with
  `--offline --locked`; registry/Git dependencies remain reusable. The clean command and package
  list are recorded. This prevents a different checkout at `/psy-node` from
  inheriting newer workspace objects solely because of file mtimes.
- Advisory locks are held in all four caches. Active Rust/Go build processes or
  running containers with overlapping writable mounts cause refusal. Other
  build operators must honor exclusive cache ownership for the whole run;
  the checks cannot prevent an unrelated writer racing them.
- Source, config, bundle, stamp and spec are rechecked around every command.
  Output is create-only, mode 0700; partial binaries/logs remain on failure.
  Never delete a failed output directory to pretend the attempt did not happen.
  Choose a new output after diagnosing the failure.
- Each copied ELF must have detectable GLIBC requirements no newer than 2.36
  and pass `--help` inside the same pinned image. `manifest.json` is written
  last, recording source/tree/submodules, consumed artifact hashes, compiler
  stamp revision, source lock/circuit hashes, image/toolchain, commands,
  environment, binary hashes and log hashes. Keep output private.

While holding all cache locks, the manifest also snapshots the SHA-256 of every
release rlib named by Cargo's structured compiler-artifact output. These are
`release_libraries`; the filenames alone do not prove cache contents remained
unchanged after the build. The Genesis tool linker requires these producer
hashes and rejects missing receipts or a library replaced at the same path.
Do not add hashes retroactively to an old manifest from its current cache.

`release-build.log` retains Cargo's JSON compiler-artifact records with rendered
diagnostics. Use those exact filenames when compiling the standalone Genesis
validator against this generator's dependency rlibs; never select a library by
mtime or a wildcard from a cache containing several source/feature cohorts.
Host build-dependency records use a different optimization profile. The linker
requires one unambiguous release library per dependency, including the rebuilt
`std`/`core` set when Cargo's build-std is active. The JSON records and producer
hashes establish linkage provenance, not proof or new-chain acceptance.

This manifest is **build evidence only**: `runtime_approved=false` and
`deployment_ready=false`. No exact circuit tests or new-Genesis native acceptance
are claimed. The previous four regression tests, if run separately, cannot
replace the current complete Genesis/fingerprint/identity acceptance gates.
Packaging and activation must bind these binaries to the separately reviewed
Genesis and release manifest, not infer deployment readiness from CLI help.

## Tool Tests

These tests use synthetic files and mock Docker; they do not run Cargo, Docker
build, real release binaries or network probes:

```sh
cd deploy/multi-chain/gcp/core-only
python3 -B -m unittest -v test_build_runtime.py
```
