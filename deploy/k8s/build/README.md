# Local Kubernetes build preparation

This is deployment tooling for a **new isolated local lab**, based on deployment
commit `1ba693d72bc2eba846e26c919d08c224c21ce4df`. It does not install Kubernetes,
change services, initialize chain state, deploy contracts, publish packages,
push images, or update the running testnet.

Applicability: deployment/local tooling only. No runtime, Cargo dependency,
Genesis generation, ABI, SDK, wallet or frontend source change is included.

## Inputs and scope

`versions.json` is the candidate build input for this lab only. Existing public
testnet `deploy/multi-chain/gcp/source-versions.env` and the observed component
map are unchanged. In particular, the historical full-cohort manifest is not
treated as the current live hotfix set. The lab source candidate is not an
assertion that all live artifacts are built from the stable branch tip.

| Input | Selected revision/version |
| --- | --- |
| Node/Worker/User CLI/Relayer | `ec215c6d9d7b26c985067c229090bad06f2cf550` |
| Services API | `f4d6ee8a4f55a69586e4ed8d5a3f0a9bc4422ded` |
| L2 Indexer | `7c1e1f61673949bb7343529d4dd51d66f631d236` |
| Genesis source | `cb3ea4a1e743c3c01037ae968e10f27389788a7d` |
| Rust | `nightly-2025-09-20`, rustc 1.92 nightly |
| Go FFI toolchain | 1.22.3, matching the existing verified recipe |
| Platform/CPU | Debian Bookworm, linux/amd64, Rust x86-64, Go v1 |
| Build stage | Explicit `localhost` |

Services retains its own locked protocol dependency revisions; the script does
not rewrite Cargo pins to the selected Node revision. Their interoperability
must be verified on the independent lab chain before release. Existing sources
map localhost/testnet to the same historical magic; explicit network isolation,
new state and independent lab signing keys are still required. This builder
does not generate signing material or load a production Genesis state dump.

The Node pin adds optional Scylla credentials from mounted files and a mode that
requires precreated keyspaces. It preserves the frozen `e46df92d` protocol,
Cargo.lock and Genesis inputs. See `psy_node_scylla/README.md` in that source.
The source commit was published before this build pin; real compilation and
CLI transaction acceptance are still required.

Builder/runtime base images and dependency images have fixed registry digests.
Rust and Go identities are checked inside the builder, not inferred from its
tag. The cached `psy-bookworm-builder:nightly-2025-09-20` actually defaults to
Rust 1.97, so every compilation explicitly sets `RUSTUP_TOOLCHAIN`.

An existing verified builder is frozen by its local image ID; preserve/export
that image if moving the build. `Dockerfile.builder` can construct a new one
from the pinned base, dated Rust toolchain and SHA256-verified Go archive.
Debian package installation still uses repository metadata, not a dated APT
snapshot. Builder/runtime image IDs and runtime package inventory are recorded;
building on a later date may produce a different image. This is not a claim of
bit-identical builds. Go/toolchain upgrades require their own FFI/proof checks.

## Commands

Run from this repository. Python 3.11+, Git, Docker, readelf and objdump are
required. Default output is `dist/kubernetes-build` under this checkout.
For a full build use persistent disk space, not the RAM-backed `/tmp` mount.
The default free-space gate is 80 GiB; it is an initial guard, not a measured
maximum. Build-cache growth can require more space.

Read-only plan:

```bash
python3 deploy/k8s/build/build.py plan
```

Prepare exact committed sources from existing local repositories:

```bash
python3 deploy/k8s/build/build.py prepare \
  --node-repo /home/peter/git/bridge_zilong/psy-node-testnet-stable \
  --services-repo /home/peter/git/bridge_zilong/psy-services-response-deadline-20261012 \
  --genesis-repo /home/peter/git/bridge_zilong/psy-node-testnet-stable/psy-genesis
```

Preparation needs a new empty output directory. It uses local Git objects at
the locked revisions, ignores the original worktrees' uncommitted contents,
then checks clean snapshots, origins, Cargo.lock and Genesis hashes. It never
switches, resets, stashes or updates submodules in the original worktrees.
Snapshots use read-only shared Git object stores to avoid copying the 8 GiB
Node history; preserve these local object stores until compilation finishes.
Genesis is a separate pinned checkout, mounted read-only at build time.

Select an existing builder, or omit `--use-builder` to build the recipe:

```bash
python3 deploy/k8s/build/build.py builder \
  --use-builder psy-bookworm-builder:nightly-2025-09-20
```

Compile all six core runtime components, sequentially by source group:

```bash
bash deploy/k8s/build/compile.sh
```

Or select a subset:

```bash
bash deploy/k8s/build/compile.sh --component node,worker
```

Private Cargo Git dependencies need an authorized SSH agent and verified host
keys. Nothing copies a private key into source, image layers or build output:

```bash
bash deploy/k8s/build/compile.sh \
  --ssh-agent "$SSH_AUTH_SOCK" --known-hosts "$HOME/.ssh/known_hosts"
```

`--offline` is available after dependency caches have been populated. Default
budgets are four Cargo jobs, six CPU equivalents, 16 GiB memory and no extra
build swap. Source is read-only, caches/target are isolated by source and policy,
and the container uses the calling user's UID/GID. Portable target flags are
explicit; host `native`, CUDA and inherited Cargo/Rust flags are not used.
The driver supplies read-only passwd/group mappings for that UID/GID, preserving
existing builder accounts. This lets SSH resolve the build user without adding
host users, changing the builder image, or running compilation as root.

Verify and package runtime images:

```bash
python3 deploy/k8s/build/build.py verify
bash deploy/k8s/build/build-images.sh --image-prefix psy-local
```

Each image contains its binary, build receipt, and only explicitly selected
public resources. Services/Indexer include tracked migrations/contract metadata;
ignored `.env` files and the whole workspace are excluded. Images run as UID
10001, with exec-form entrypoints. A network-disabled, read-only `--help` smoke
checks dynamic linking/CLI startup; it does not perform proving or E2E.
Writable state, proof parameters and runtime configuration will be separate
volumes in the deployment phase. Non-root PVC permissions still need validation.

Artifacts contain binary/source/lock/Genesis/config hashes, stage, toolchain,
CPU profile, GLIBC requirement and builder identity. `images.json` records local
image IDs. **Registry digests remain null until a separately performed registry
push**; a local image ID is not presented as a registry manifest digest.
No collector/controller image is built.

## Remaining image inputs

The six Rust image paths are implemented. The other three planned images are
explicitly not treated as ready:

- Envio: source has Envio 2.32.10 but no committed pnpm lock; freeze generated
  code and the history/RPC patches first. Do not generate/install dependencies
  from floating ranges in a release image.
- Frontend: freeze the DApp/SDK cohort and independent lab endpoints/contracts
  before compiling static assets. This tool does not fetch staging config or
  trigger SDK/npm/wallet publication.
- Admission: archive and pin the existing Realm1 gateway source, then verify
  Coordinator/Realm0 method policy and multi-instance maintenance state.

Published platform candidates are recorded separately in `versions.json`:
K3s 1.35.9+k3s1, MetalLB chart 0.16.1, kube-vip 1.2.4, Traefik 3.7.14 and
kube-prometheus-stack chart 92.3.1 / Operator 0.94.1. They have not yet passed
chart-rendering, Gateway API, K3s scrape or GKE compatibility validation.
Do not combine independent Traefik with the enabled bundled K3s Traefik.
Anvil and the complete rendered platform image set will be pinned when their
installation profiles are prepared; they are not silently replaced by latest.

Official version references:

- [K3s release](https://github.com/k3s-io/k3s/releases/tag/v1.35.9%2Bk3s1)
- [MetalLB chart release](https://github.com/metallb/metallb/releases/tag/metallb-chart-0.16.1)
- [kube-vip release](https://github.com/kube-vip/kube-vip/releases/tag/v1.2.4)
- [Traefik release](https://github.com/traefik/traefik/releases/tag/v3.7.14)
- [Prometheus chart](https://github.com/prometheus-community/helm-charts/tree/kube-prometheus-stack-92.3.1/charts/kube-prometheus-stack)
- [Go archive checksums](https://go.dev/dl/)

## Validation

```bash
python3 deploy/k8s/build/test_build.py
bash -n deploy/k8s/build/compile.sh deploy/k8s/build/build-images.sh
```

Optional real Docker/Rust harness smoke, in a new temporary directory:

```bash
python3 deploy/k8s/build/test_build.py \
  --docker-smoke /tmp/psy-k8s-harness-smoke-unique
```

Check SSH user resolution with no network connection:

```bash
python3 deploy/k8s/build/test_build.py \
  --identity-smoke /tmp/psy-k8s-identity-smoke-unique
```

That test creates **synthetic fixture programs**, compiles all six packaging
paths offline with the fixed compiler, builds six images, checks CLI startup,
non-root execution, receipts and exclusion of a fixture `.env`. It does not
compile the real Psy programs, run proofs or establish compatibility. Test
images use the `psy-build-fixture/` prefix and are not deployment artifacts.
Production/shared Git repositories are not committed or changed by these tests.
