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
| `schema_version` | Integer `1` |
| `source` | Object with `path` and full lowercase 40-hex `commit` |
| `inputs` | Object with exactly `config`, `bundle`, `bundle_stamp` |
| Each input | Object with `path` and lowercase 64-hex `sha256` |
| `builder_image` | Already available local `sha256:` image ID, 64 lowercase hex digits, linux/amd64 |
| `caches` | Object with existing directory paths `cargo`, `target`, `go`, `go_build` |
| `output` | New directory; existing owned parent, not group/world writable |
| `jobs` | Positive integer, at most 256 |

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
