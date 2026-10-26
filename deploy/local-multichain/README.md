# Local Multichain Deployment

## Fresh testnet preparation and builds (2026-10-23)

Use `fresh.py` for the new `testnet-dev` candidate. It prepares eight isolated
worktrees and runs explicit build stages. **It does not start, stop, reset or
deploy a network.** The legacy commands further down this page are not the new
Guardian launcher. They reject Guardian-capable runtime checkouts before
performing lifecycle or E2E actions.

`fresh-sources.json` freezes the eight inputs from the October 23 handoff;
Node is `b805a6701c5f3a381c5b77fb89cb1be4dea9d931`. The file is an inventory,
not a compatible release lock. Compiler, SDK and Services initially consume
another Node revision, and recorded Genesis/DApp gitlinks and compiler stamps
still differ. Preparation does not silently reconcile or waive those findings.

Run from this deployment checkout. Choose a new root; the example is ignored
runtime state, not a directory to commit:

```bash
LOCAL_FRESH_WORKSPACE=$(cd .. && pwd)
LOCAL_FRESH_ROOT="$PWD/deploy/local-multichain/.runtime/fresh-20261023"
fresh() {
  python3 -B deploy/local-multichain/fresh.py \
    --workspace "$LOCAL_FRESH_WORKSPACE" --root "$LOCAL_FRESH_ROOT" "$@"
}

fresh plan
fresh prepare                 # Preview only; no directories or branches
fresh prepare --apply         # Create the eight worktrees at exact SHAs
fresh submodules              # Preview the recorded-gitlink initialization
fresh submodules --apply
fresh deps --mode show        # Read-only canonical workspace dependency report
```

Python 3.11+ and Linux are required. The dependency helper requires Bun 1.3.14+
(`Bun.JSON5.parse`); the workstation's Bun 1.2.19 is an observed blocker, not
something this script upgrades automatically. Install the repository-pinned
Rust toolchains and package-manager versions before actual builds.

The local continuation prepared Bun 1.3.14, Corepack 0.36.0 and pnpm 10.34.5
under `<root>/tools`, without replacing global executables. `fresh.py` prefers
`<root>/tools/bin` when present and keeps Corepack's cache inside that same
owned root. Bun's archive was checked against its official release SHA256;
Corepack's archive was checked against its registry SHA512 integrity. The Bun
identity is recorded in `<root>/evidence/bun-tool.json`. Reproducing the run
requires those versions (or an explicitly reviewed tool change), not an
unrecorded upgrade to a moving latest release.

Preparation checks canonical `PsyProtocol` origins and commit availability in
all source checkouts before writing. Dirty source worktrees are inventoried
but never copied, reset, stashed, staged or switched. Existing destinations or
branches fail; partial worktrees are retained for inspection. No moving remote
head is selected or fetched by preparation. The branch defaults to
`local/psy-fresh-local-20261023`; choose another `--namespace` before preparation
for a distinct cohort. Recorded submodules may require network access. Node's
`update = none` DApp is explicitly initialized; no `--remote` is used.
Registration precedes temporary canonical URL overrides, because a linked
worktree can inherit another checkout's local submodule URL. The overrides
apply only to that Git invocation; existing shared URL settings are not
rewritten. Registering a previously absent module still uses ordinary Git
submodule initialization, so populated nested modules do not remain marked `-`.

Reserve 150 GiB before creating the cohort and 100 GiB before each build.
These are planning reserves, not measured minimums or hard disk quotas. Actual
build peaks can still exceed them. Never remove someone else's data to pass.
Use persistent storage; `/tmp` is RAM-backed on this workstation.

### Resolve dependencies before building

Follow the candidate Node's owning `docs/src/dev/worktree-cohort.md` and
`docs/src/dev/circuit-and-verifier-operations.md`. The deployment tool delegates
dependency changes to that Node's `scripts/workspace.ts`:

```bash
fresh deps --mode node            # Preview the exact command; no remote read
fresh deps --mode node --apply    # Align Cargo pins to frozen, published R_node
```

The canonical helper verifies remote reachability and may fetch/resolve locks
on apply. It requires clean owned files and a common topic branch. A divergent
history fails by default. After reviewing consumed protocol/API changes and
confirming the deliberately selected source cohort, an explicit local switch is:

```bash
fresh deps --mode node --allow-history-switch          # Preview
fresh deps --mode node --allow-history-switch --apply
```

The flag is accepted only for `--mode node` and is never inferred. The local
continuation reviewed the caller-ordered multisig and reward-wrapper changes,
then aligned all three consumer locks to frozen `b805a670`; this is not an online
state migration or a release certificate. Review and commit only the isolated manifest/lock edits before
generating compiler-stamped artifacts. The scripts never stage or commit them.

`fresh deps --mode local [--apply]` delegates to the canonical **whole-cohort**
local-dependency switch. It also changes npm consumers and requires prebuilt
SDK/EVM package entrypoints. The `sdk` stage builds Utils, Psy SDK and EVM Wallet
in that order. If those outputs are missing, first align Cargo with
`--mode node`, review/commit that milestone and build the SDK. Then perform the
local switch, review/commit it and regenerate compiler/Genesis/SDK artifacts
from the resulting compiler revision. Do not treat bootstrap SDK output as the
final local cohort or edit only some locks. Installation/consumer refresh after
an SDK rebuild follows the canonical helper's documented explicit install mode.

### Explicit build stages

Every build is a preview unless `--apply` is present. A stage failure stops the
command, retains partial output and never starts a service:

```bash
fresh build --stage compiler --apply
fresh build --stage genesis-artifacts --apply
fresh build --stage sdk --apply
fresh build --stage contracts --apply
fresh build --stage clients --apply
# Build these after the final reviewed/generated cohort inputs are stable:
fresh build --stage services --apply
fresh build --stage node --apply
fresh preflight
fresh preflight --ports           # Host bind checks; requires network permission
```

There is no automatic `build all`: dependency and provenance review boundaries
must be completed deliberately. `genesis-artifacts` runs the compiler's real
`make gen-deploy-json`, writing **node's nested** `psy-genesis`, not every sibling
Genesis checkout. It does not generate root `genesis.json`. The stage hashes all
six bytecode targets and structured ABIs as well as the Genesis payloads/stamp.
Services verifies that recorded artifact set and compiler identity, then creates
byte-identical ABI aliases at the older synchronizer's expected target paths.
Existing different aliases fail before copying; none are overwritten. Services
then synchronizes its metadata without another implicit compile. Build Services
before the final Node build so those synchronized metadata files are included
in both recorded cohort identities.
Genesis/gitlink propagation and review remain explicit; do
not replace submodule directories with symlinks or dirty copies. The canonical
`gitlinks sync` procedure requires descendant commits and stages gitlinks; it
must not be used to conceal conflicting histories.

The builder checks the real Cargo metadata graph against frozen R_node or the
owned sibling crate paths. Cargo builds use `--release --locked`; a native Make
recipe that changes a Cargo lock fails the stage after retaining the change.
Compiler sources must be clean before Genesis/SDK/Services generation.
Build defaults are four jobs, four Rayon threads, `PSY_NETWORK=localhost`, and
`-C target-cpu=x86-64-v3 -C debuginfo=0`; AVX2 is checked. Native Make recipes may
override `RUSTFLAGS` (the compiler recipe uses `-A warnings`), so the evidence
records the requested environment and exact commands rather than claiming all
nested invocations use identical flags. No AVX-512 binary is imported.
Subprocess `PWD` is bound to its actual working directory, since the compiler
Makefile derives output paths from it. Cargo's automatic global cache cleanup
is disabled (`CARGO_CACHE_AUTO_CLEAN_FREQUENCY=never`); this profile does not
delete unrelated caches to make room.

Each executed build records commands, public build settings, source HEADs,
tracked/untracked nonignored content identities, nested checkout identities,
failure/success, and CLI SHA256s under `<root>/evidence/`. The preflight verifies
the latest node/Services build against current inputs and binaries, checks real
compiler/Genesis/SDK provenance and Genesis payload hashes, and reports stale
pins and missing submodules. It does not inspect or print private keys or raw
environment variables. No wallet or Guardian password is passed to builds.

### Startup gates remain separate

`preflight` exit 0 means only its **build checks** passed. Its JSON always says
`runtime_ready: false`; it is not a startup/release authorization. Pending gates
are printed even after a successful build check:

- The tested `fresh-runtime.patch` and `fresh-envio.ts` cover native checks,
  generated Compose and Envio's child environment on frozen `b805a670`.
  Apply them only to the owned runtime and retain native namespace-derived
  volume/network names. The patch is frozen to that source and uses
  `git apply --check --unidiff-zero` followed by `git apply --unidiff-zero`.
  The helper must be copied into the runtime's
  `deploy/local-multichain/` before importing it. The patch does not configure
  canonical Genesis endpoints or start a service. Final adaptation must cover
  all runtime configuration, Envio's
  `ENVIO_PG_*`, Services and all clients. Proposed PostgreSQL/Hasura ports are
  15433/9080; existing 5433/8080 services must remain untouched. `plan` prints
  all proposed ports, including four processor/edge pairs and Guardians.
- Provision local-only Guardian keystores, ordered public member commitments,
  protected shared root and compatible schema-3 journals. Provide passwords only
  through the documented Guardian environment variables; never use argv/files.
  The root must be inside the owned Node checkout (`guardians-root/db`), and the
  four new redb filenames must be absent, not empty touched files. Current Rust
  checks use schema 3 despite stale schema-2 lifecycle prose. Guardian History
  port 15450 is served by the Relayer; a fourth signer is not required. The
  daemon TOML must explicitly select all three local chains, because its minimal
  four-field template falls back to a single chain.
- Prepare matching Groth16 setup/verifiers for every enabled proof family,
  frozen Envio dependencies, daemon config and Guardian History availability.
- Align consumed Genesis/ABI/SDK gitlinks and provision Worker identities,
  fresh reward-account mappings and required Edge whitelists.
- Run the candidate's native foreground supervisor, then prove both Realms'
  real work, P2P forwarding/rotation, Guardian quorum, three-chain settlement,
  clients, state-preserving application restart and resource behavior.

`make run-all` on the new runtime always creates a fresh chain; a complete
teardown is not a state-preserving restart. Follow the candidate lifecycle guide
for every future start/restart/stop. Neither these scripts nor preparation tests
authorize a public reset, cloud provisioning, Cloudflare/R2/npm publication or
Git push. Notifier remains an optional later observer, outside the eight-repo
build cohort.

Run preparation regressions without compiling Rust or starting a network:

```bash
python3 -B deploy/local-multichain/fresh_test.py
bash deploy/local-multichain/tests/test-e2e-isolation.sh
```

## Historical multi_chain deployment (legacy)

The remainder describes the old deployment only. Its start/stop/E2E scripts
are retained for that runtime and reject the new Guardian source tree. In
particular its background launcher, provenance-stamp workaround and mandatory
public tunnel must not be reused as the fresh candidate workflow.

This deployment profile runs the `psy-node` `multi_chain` development stack
and exposes it through the existing `psy-local-staging` Cloudflare named
tunnel. It intentionally lives entirely under `deploy/`, so the deployment
branch can keep following `origin/multi_chain` without mixing deployment code
into product branches.

The native `dev/locSetupV4.ts` remains the owner of the Psy runtime. It starts:

- coordinator, two realms, workers, prove-proxy and faucet;
- psy-services, Psy indexers, Nostr and multichain Envio;
- local Ethereum (`31337` / `8545`), BSC (`31338` / `9545`) and Base
  (`31339` / `10545`) Anvil chains;
- one L1 contract deployment per local chain and the unified multichain
  relayer;
- Bridge, Explorer and IDE development frontends.

This profile adds process supervision around that launcher, three local-gas
faucets, a generated multichain Psy Config page, public frontend endpoint
injection, Cloudflare ingress, DNS routing, and local/public health checks. It points locSetup at private, deployment-owned
cohort checkouts under `deploy/local-multichain/.runtime/projects`; this avoids
building or changing dirty sibling repositories elsewhere in the workspace.
The services checkout follows `PsyProtocol/psy-services` branch `multi_chain`;
the launcher verifies its HEAD against `origin/multi_chain` before every start.

## Configuration

Copy the example only when overriding defaults:

```bash
cp deploy/local-multichain/local.env.example deploy/local-multichain/local.env
```

The default hostnames reuse the existing `psy-protocol.xyz` local test zone.
`local.env` is ignored and may contain machine-specific values. Cloudflare
credentials remain in the normal cloudflared credentials store and must never
be committed. Envio binds to host port `9080` by default because this machine's
Signal daemon owns `127.0.0.1:8080`; override `LOCAL_DEPLOY_ENVIO_PORT` when
needed.

## Start or restart

Build release binaries, restart without deleting chain/database state, start
the named tunnel, and verify everything:

```bash
bash deploy/local-multichain/start.sh
```

Reuse existing release binaries:

```bash
bash deploy/local-multichain/start.sh --no-build
```

`--fresh` is intentionally explicit because it removes local checkpoints,
generated local L1 deployments and devnet Docker volumes.

```bash
bash deploy/local-multichain/start.sh --fresh
```

## DNS and status

Route all configured public names to the named tunnel (one-time or after a
hostname change):

```bash
bash deploy/local-multichain/route-dns.sh
```

Check local endpoints and the public HTTPS routes:

```bash
bash deploy/local-multichain/status.sh
```

Run the complete bridge E2E matrix. Each L1 is an independent test case that
must pass deposit, Psy claim, withdrawal and settlement assertions:

```bash
bash deploy/local-multichain/e2e.sh
```

Run or validate one chain while diagnosing a failure:

```bash
bash deploy/local-multichain/e2e.sh --chain bsc
bash deploy/local-multichain/e2e.sh --chain base --preflight-only
```

The cases map Ethereum, BSC and Base to Psy chain indexes `0`, `1` and `2`.
Results and generated deposit proofs are written below the ignored
`deploy/local-multichain/.runtime/e2e/` directory. E2E changes local chain and
Psy state; `status.sh` and `e2e.sh --preflight-only` are read-only.

Stop while preserving state:

```bash
bash deploy/local-multichain/stop.sh
```

## Source-update workflow

Stop the deployment, merge or rebase the latest `origin/multi_chain` into the
deployment branch, review that only `deploy/` is deployment-owned, then start
again. The launcher temporarily patches the nested DApp checkout so a browser
outside this host uses the public BSC and Base RPC names. It also applies
deployment-owned compatibility patches to the native launcher and private
compiler checkout. Root/submodule files can therefore appear modified while
the stack is running; `stop.sh` restores the tracked source files. These are
runtime overlays, not product changes.

Share these entry points with testers:

- `https://app-local.psy-protocol.xyz`
- `https://config-local.psy-protocol.xyz`
- `https://explorer-local.psy-protocol.xyz`
- `https://ide-local.psy-protocol.xyz`
- `https://eth-faucet-local.psy-protocol.xyz`
- `https://bnb-faucet-local.psy-protocol.xyz`
- `https://base-faucet-local.psy-protocol.xyz`

Integration endpoints:

- Psy RPC: `https://coordinator-local.psy-protocol.xyz`,
  `https://realm0-local.psy-protocol.xyz`, and
  `https://realm1-local.psy-protocol.xyz`
- L1 RPC: `https://rpc-local.psy-protocol.xyz`,
  `https://rpc-bsc-local.psy-protocol.xyz`, and
  `https://rpc-base-local.psy-protocol.xyz`
- APIs: `https://services-local.psy-protocol.xyz`,
  `https://indexer-local.psy-protocol.xyz`,
  `https://prove-local.psy-protocol.xyz`, and
  `https://faucet-local.psy-protocol.xyz`
- Nostr: `https://nostr-local.psy-protocol.xyz`
