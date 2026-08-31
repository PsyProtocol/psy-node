# AGENTS.md — psy-node

## Scope

This file governs `psy-node` and coordinated changes across the sibling PsyProtocol repositories:

- `../psy-compiler`
- `../psy-genesis`
- `../psy-sdk`
- `../psy-services`
- `../psy-dapp`
- `../psy-wallet`
- `../psy-contracts`

It supplements higher-level agent rules. The stricter rule wins.

## Required Devnet Lifecycle Reading

Before any devnet startup, shutdown, restart, rollback, or live E2E operation, every AI agent MUST read and follow `docs/src/node/devnet_lifecycle.md`. JTMB remains test-only and is not rollback-validation evidence. Rollback validation uses the Plonky2 path; all lifecycle stop/resume, artifact, and verification procedures remain authoritative.

## Local Devnet Startup Preflight

Keep the cohort repositories as sibling directories under one parent whenever possible: `psy-node`, `psy-compiler`, `psy-sdk`, `psy-genesis`, `psy-services`, `psy-contracts`, `psy-dapp`, and `psy-wallet`. The build and generation scripts use these sibling paths; a different layout requires explicit path configuration rather than copied repositories or ad-hoc symlinks.

Before `make run-all`, restart, rollback validation, or a live E2E:

1. Initialize all required submodules recursively and confirm no required submodule status begins with `-`, `+`, or `U`. The node parent, nested DApp, SDK, and wallet gitlinks must resolve to their recorded SHAs.
2. Confirm `genesis.json` already exists. Generate it only under the Genesis Regeneration Boundary; absence is a blocker, not permission to regenerate after unrelated changes.
3. Build release `psy_node_cli`, `psy_worker_cli`, `psy_dev_cli`, `psy_relayer_cli`, and `psy_user_cli`. Build `psy-services` and `psy-indexer` in `../psy-services` before starting a stack that enables services/indexers.
4. Install frozen frontend dependencies in `./psy-dapp` and its standalone `./psy-dapp/mode-a-web-wallet-bridge` workspace. Install `../psy-wallet` dependencies only when the wallet surface is exercised; do not let startup mutate dependency versions or lockfiles.
5. Verify the compiler revision matches the SDK and Genesis compiler artifact stamps and that required generated circuit, WASM, verifier, and Genesis artifacts match current source.
6. For local startup use `PSY_SKIP_KEYSTORE=1` and `PSY_SKIP_BRANCH_CHECK=1` unless the user explicitly requests keystore synchronization or branch synchronization. Use `PSY_SKIP_BUILD=1` only after the release binaries above are verified against current source.
7. Run the lifecycle command only from the foreground supervisor path documented in `docs/src/node/devnet_lifecycle.md`; never replace it with manual per-service starts.

## Genesis Regeneration Boundary

Regenerate `genesis.json` only after a change to `psy_vm`, `psy_compiler`, `psy_precompiles`, or the serialized `genesis.json` format. No other change class authorizes regeneration. This restriction governs the Genesis step of the Applicability Gate; a broader release class does not authorize Genesis regeneration unless one of these four inputs changed. When none changed, retain the existing verified `genesis.json`.

## Proving Backend Boundary

The JTMB ("just trust me bro") proving backend is test-only. Production, devnet, rollback validation, and live E2E operations MUST use Plonky2. An explicit request for a JTMB-only test authorizes only that test; it does not authorize JTMB on any Plonky2-required path or make JTMB output evidence for such a path.

## End-Cap Verifier Artifact Boundary

Changes to DPN circuits, UPS circuits, ZK-signature or secp256k1 circuits, or the user-ID strategy invalidate the user end-cap verifier artifact. Regenerate it by constructing the release `UPSStandardEndCapCircuit`, serializing its verifier-only data as `AltVerifierOnlyCircuitData`, and computing its fingerprint from that same verifier data. The current tree has no active checked-in regeneration command—the construction in `psy_plonky2_circuits/examples/config_gen_v2.rs:86-91` is commented out—so stop rather than reuse or hand-edit stale data until the release generator is restored. Once generated, replace `END_CAP_ALT_VERIFIER_DATA_SERIALIZED` in `psy_plonky2_circuits/src/circuit_library/end_cap_verifier_data.rs` and replace `END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4` in every affected `psy_core/src/network_config/` file and circuit test configuration. The serialized verifier data and fingerprint are one atomic artifact set. After both are updated, run `RUST_MIN_STACK=134217728 make config_gen_v2` and require the fingerprint check to pass.

## Network Circuit Artifact Boundary

After any network-circuit change, register every new or changed circuit triplet and parent/child inclusion relationship in `psy_plonky2_circuits/examples/config_gen_v2.rs` and the owning circuit manager, then run `RUST_MIN_STACK=134217728 make config_gen_v2`. Commit both generated outputs, `psy_plonky2_circuits/src/generated/cached_circuit_library.rs` and `psy_plonky2_circuits/src/generated/cached_common_data.rs`. Accept the result only when the regenerated GUTA whitelist, verifier library, common-data library, end-cap fingerprint check, and affected circuit fingerprints are mutually consistent. Never regenerate or replace only one generated library file.

## Groth16 Trusted-Setup Boundary

Changes to the bridge aggregation circuit, checkpoint recursive transition circuit, deposit batch-append circuit, or withdrawal batch-claim circuit invalidate the corresponding Groth16 wrapper setup. Regenerate the affected setup with the release `psy_relayer_cli regenerate-groth16-keystore` path, then export and replace the matching tracked verifier in `psy-contracts/src/`: `GnarkGroth16Verifier.sol` for bridge aggregation/checkpoint wrapping, `DepositBatchVerifier.sol` for deposit batch append, and `WithdrawalClaimVerifier.sol` for withdrawal batch claim. Treat the circuit, wrapper common/verifier data, `circuit_groth16.bin`, `pk_groth16.bin`, `vk_groth16.bin`, and Solidity verifier as one atomic artifact set. Never reuse a prior key or verifier after an input circuit changes. Verify an export to a temporary file is byte-identical to the tracked Solidity verifier, then rebuild and run the corresponding real bridge E2E against an authorized deployment. Redeploy the affected verifier and update deployment records only when the user separately authorizes that exact deployment and network.


## Release Safety

1. Run the applicability gate before generation, deployment, publication, downstream version changes, or gitlink changes.
2. Treat every unowned staged, unstaged, untracked, or nested-submodule change as another contributor's work. Never overwrite, reformat, remove, stage, unstage, commit, or push it.
3. Use a clean clone or dedicated clean worktree for coordinated releases. Never auto-stash a shared worktree.
4. Stage only explicitly owned paths. Never use `git add .`, `git add -A`, `git commit -a`, or broad pathspecs.
5. Push is disabled unless the user explicitly authorizes the exact repository, destination ref, and scope in the current task. Never force-push.
6. npm publication, deployment, and Git push are separate authorizations. Authorization for one does not authorize either of the others.
7. Every staged delivery set must be reviewed by a different model before commit or push. The reviewer must read every staged diff line. Any post-review edit requires another staged-diff review.
8. Freeze and remotely publish an upstream commit before placing its SHA in a downstream manifest or gitlink.
9. Use one immutable `psy-node` source revision for all downstream Cargo pins in one release. Do not pin downstream repositories to the later parent-integration commit when that commit changes only generated artifacts or gitlinks.
10. Record the exact release SHAs and npm versions in the task output. Do not rely on branch names as provenance.
11. Commit each independent task or verified dependency milestone immediately after its scoped tests and independent review pass, before starting the next dependent milestone. Never accumulate several successful milestones into one unreviewed working-tree bundle.
12. Never run formatters or make style-only formatting changes unless the user explicitly requests formatting. Surgical edits must preserve surrounding formatting.
13. Prefer surgical changes in existing files. A new module must own one named domain; `Defaults`, `Utils`, `Helpers`, and similar grab-bag modules are forbidden. TypeScript tests remain adjacent as `<name>.test.ts`.

## Repository Cohort

| Repository | Owns | Consumes |
|---|---|---|
| `psy-node` | Node runtime, circuits, CLIs, parent gitlinks, `client_prover/token.json`, `client_prover/token.abi.json` | `psy-genesis`, `psy-contracts`, `psy-dapp` gitlinks |
| `psy-compiler` | Psy compiler, precompiles, ABI and Genesis generation | Git-pinned `psy-node` crates in `../psy-compiler/Cargo.toml:31-41` |
| `psy-genesis` | Canonical network config, compressed Genesis contracts, ABIs, compiler provenance | Generated from clean `psy-compiler` HEAD by `../psy-compiler/Makefile:205-250` |
| `psy-sdk` | Rust SDK, prover WASM, compiler WASM, TypeScript packages | Git-pinned `psy-node` crates, `psy-genesis` gitlink, sibling `psy-compiler` provenance |
| `psy-services` | API, indexer, migrations, generated Genesis ABI metadata | Git-pinned `psy-node` crates and sibling `psy-compiler` targets; it has no `psy-genesis` gitlink |
| `psy-contracts` | L1 contracts, Groth16 verifiers, deployments, protocol config | `export-solidity-verifier*` Makefile targets |
| `psy-dapp` | Bridge, Explorer, IDE | Matching local SDK or explicitly authorized published npm SDK, plus `psy-genesis` and `psy-contracts` gitlinks |
| `psy-wallet` | Browser wallet | Local `file:../psy-sdk/psy-ts-sdk/packages/psy-sdk` plus `psy-genesis` gitlink |

The gitlink topology is authoritative:

- `.gitmodules:1-12` links `psy-genesis`, `psy-contracts`, and `psy-dapp`.
- `../psy-dapp/.gitmodules:1-8` links `psy-contracts` and `psy-genesis`.
- `../psy-sdk/.gitmodules:1-4` links `psy-genesis`.
- `../psy-wallet/.gitmodules:1-3` links `psy-genesis`.

## Applicability Gate

Classify the changed inputs before release work.

| Change class | Required delivery | Explicitly excluded unless another class applies |
|---|---|---|
| Documentation, tests, `AGENTS.md`, or local tooling only | Changed repository only | Deployment, Genesis generation, SDK WASM, npm, frontend dependency changes |
| Node server behavior only, including node-local whitelist, rate-limit, or governance logic | `psy-node`; deployment only when explicitly requested | Compiler, Genesis, SDK, npm, DApp, Wallet |
| A `psy-node` crate consumed by compiler, SDK, or services | Freeze and push `psy-node`, then update only the affected consumers | Genesis and npm unless generated or packed outputs change |
| Compiler, VM, circuit, precompile, method, event, ABI, or executable contract change | Full node → compiler → Genesis → SDK chain; services when copied ABI data changes | npm only when package outputs change and publication is authorized |
| `psy-genesis/config.json` only | Update Genesis gitlinks in consumers that need the config; validate their builds | Compiler generation and npm unless their actual inputs or packed bytes change |
| SDK Rust, public TypeScript, generated types, compiler WASM, or prover WASM | SDK build and pack; npm only after output comparison and authorization | Genesis regeneration unless Genesis inputs changed |
| L1 contract, verifier, deployment, or protocol config | `psy-contracts`, affected DApp build, downstream gitlinks; deployment only when authorized | SDK and Genesis unless their inputs changed |
| Services API, indexer, migration, or copied ABI only | `psy-services` | SDK, npm, DApp, Wallet unless a consumed contract changed |
| DApp or Wallet UI only | The changed frontend repository | Upstream generation and npm |

Node-local whitelist, rate-limit, and governance changes do not by themselves require Genesis regeneration, compiler WASM, prover WASM, a new npm version, or frontend SDK changes.

## Dependency DAG

```text
psy-node source revision R_node, committed and pushed first
  ├── psy-compiler pins R_node → R_compiler
  ├── psy-sdk pins the same R_node before any WASM build
  ├── psy-services pins R_node only when consumed crates changed
  └── psy-contracts changes only when L1/verifier/deploy/config changed

frozen R_node + clean R_compiler
  ├── psy-sdk builds prover/compiler WASM + provenance
  ├── psy-compiler generates psy-genesis artifacts → R_genesis
  ├── psy-node receives token.json + token.abi.json, held for parent-last
  └── psy-services syncs compiler ABI targets when required

pushed R_genesis + completed R_sdk_build
  ├── psy-sdk / psy-dapp / psy-wallet advance required Genesis gitlinks
  ├── psy-wallet consumes the local file: SDK
  └── psy-dapp consumes either the matching local SDK or an authorized npm version

pushed R_contracts / R_genesis / R_dapp, as applicable
  └── psy-node generated artifacts and parent gitlinks, committed and pushed last
```

`R_node` is the source pin. The final `psy-node` integration commit may contain regenerated `client_prover/token.json`, `client_prover/token.abi.json`, Genesis-dependent tracked outputs, and child gitlinks. Downstream Cargo manifests continue to pin `R_node` when the later integration commit changes no consumed Rust crate.

## Preflight for Every Repository

Before modifying or delivering a repository, run:

```bash
git status --short
git diff
git diff --cached
git diff --check
git diff --cached --check
git branch --show-current
git remote -v
git remote get-url origin
git config --get-regexp '^submodule\..*\.url$'

```

Release work requires:

- the expected branch or an explicitly named release branch;
- no unowned staged paths;
- no unowned edits in files a generator will overwrite;
- canonical `PsyProtocol` origins and submodule URLs;
- release inputs committed before provenance is computed;
- release-mode binaries and WASM.

If the shared worktree is dirty, preserve it and perform release work elsewhere. Never clean, restore, reset, or stash another contributor's changes.

## Matching Branch and Gitlink Order

The Applicability Gate decides which repositories participate. Create one identical matching branch name in every affected repository, based on that repository's current `origin/mainnet-beta`. Do not create matching branches in unaffected repositories. Branch names are coordination labels, not provenance; record immutable SHAs.

Create, review, commit, and remotely publish producers before consumers in this order, skipping repositories excluded by the gate:

1. `psy-node` source first; record `R_node`. Do not include parent gitlinks or generated `client_prover/token.json` / `token.abi.json` yet.
2. `psy-compiler` next; pin every active node dependency to pushed `R_node`, then publish `R_compiler`.
3. `psy-sdk` next; pin every active node dependency to the same pushed `R_node` before building WASM.
4. From clean `R_compiler` and the SDK node pin, build the SDK WASM artifacts and generate Genesis artifacts. Generation writes `psy-genesis` plus node `token.json` and `token.abi.json`; hold the node files for parent-last.
5. Publish `psy-genesis` as `R_genesis`, then complete the SDK provenance and Genesis gitlink and publish the tested build commit as `R_sdk_build`.
6. For local matching-branch testing, wallet keeps its `file:../psy-sdk/psy-ts-sdk/packages/psy-sdk` dependency and DApp may use the matching local SDK. Publish npm only with explicit authorization; when using npm, confirm the exact version before updating DApp.
7. Update every required `psy-genesis` / `psy-contracts` consumer gitlink only after the child SHA is reachable on its remote matching branch. `psy-services` is an optional insert after `R_node` / `R_compiler` when consumed crates or ABI metadata changed; it has no Genesis gitlink. `psy-contracts` is an optional insert before DApp and parent gitlink updates when L1 or verifier artifacts changed.
8. Commit the parent `psy-node` generated artifacts and gitlinks last as `R_node_integration`. Cargo consumers remain pinned to `R_node` unless the integration commit changes a consumed crate.

Gitlink SHAs are the pins; `.gitmodules branch` fields are tracking hints. Never use `git submodule update --remote` to advance a release pin, never rewrite `.gitmodules branch` to the matching branch, and never assume updating one parent/nested gitlink updates the others. Check out the already-pushed child SHA and stage the gitlink path. A matching-branch gitlink may be reachable only from `origin/<matching-branch>` until integration; test reachability against the destination ref that actually contains it. Preserve `psy-dapp`'s `update = none` behavior in the node parent.

## Ordered Release State Machine

### 1. Freeze and Push the Node Source Revision

1. Isolate only the node source changes required by the release. Exclude parent gitlink changes and compiler-generated `client_prover/token.json` and `client_prover/token.abi.json` until the final integration commit.
2. Run task-specific tests plus the relevant release checks. The repository build target is `make build` at `Makefile:22-23`.
3. Review the staged diff with a different model.
4. Commit and, only with exact authorization, push the source commit.
5. Record the pushed SHA as `R_node`.
6. Do not amend, rebase, or replace `R_node` after downstream repositories pin it.

### 2. Pin Node Inputs in the Compiler

1. Set every active `psy-node` `rev` in `../psy-compiler/Cargo.toml:31-41` to the same `R_node`.
2. Regenerate `../psy-compiler/Cargo.lock` through Cargo. Never hand-edit lockfile checksums.
3. Run from `../psy-compiler`:

```bash
make check
make build
```

4. Run compiler tests that cover the changed compiler, VM, circuit, precompile, ABI, event, or method contract.
5. Review, commit, and push the compiler source and pin change.
6. Record the pushed clean compiler HEAD as `R_compiler`.

### 3. Pin SDK Inputs, Build WASM, and Generate Genesis Artifacts

Before building either SDK WASM artifact, set every active `psy-node` `rev` in `../psy-sdk/Cargo.toml:24-33` to `R_node`, regenerate `../psy-sdk/Cargo.lock` through Cargo, review the pin-only SDK commit, and publish it to the matching branch as `R_sdk_pin`.

With the SDK at `R_sdk_pin` and sibling compiler clean at `R_compiler`, run from `../psy-sdk`:

```bash
make check
make build
```

Then run from clean `R_compiler` in `../psy-compiler`:

```bash
make gen-deploy-json
```

This writes the Genesis artifacts and provenance and copies `client_prover/token.json` and `client_prover/token.abi.json` into `psy-node`. Verify both SDK and Genesis compiler stamps equal `R_compiler`, their source hashes match, the Genesis artifact hash/size match, and the canonical node regression passes:

```bash
cargo test --release -p psy_user_cli --test token_artifact_events
```

Review and publish only the generated `psy-genesis` files as `R_genesis`; hold the node token files for parent-last. Advance the SDK `psy-genesis` gitlink to pushed `R_genesis` when Genesis changed, rerun affected SDK tests and `pnpm run publish:check`, then publish the tested SDK build commit as `R_sdk_build`. If packed outputs did not change, do not change versions or publish npm.

### 4. Fan Out to Services and Contracts When Applicable

Services and contracts are optional affected-repository branches, not prerequisites for SDK/Genesis generation. Services may proceed after `R_node` and `R_compiler` when consumed crates or ABI metadata changed. Contracts may proceed after the relevant L1 or proving inputs are immutable when L1, verifier, deployment, or protocol-config artifacts changed.

#### Services

Update the `psy-node` revisions in `../psy-services/Cargo.toml:12-23` only when the consumed node crates changed. When compiler ABI or Genesis contract metadata changed, ensure sibling `../psy-compiler` is clean and exactly at `R_compiler`. Abort unless `git -C ../psy-compiler status --porcelain` is empty and `git -C ../psy-compiler rev-parse HEAD` equals `R_compiler`. Then run from `../psy-services`:

```bash
make sync-genesis-contract-abis
cargo check --release -p psy_services
cargo build --release --bin psy-services --bin psy-indexer
cargo test --release -p psy_services --lib
```

The synchronization script owns `genesis_contracts/`; `psy-services` has no Genesis submodule. Review, commit, and push services independently. Record `R_services`.

#### Contracts

Change `psy-contracts` only when L1 contracts, verifier sources, deployments, or protocol config changed. Node verifier exports are defined by the `export-solidity-verifier*` Makefile targets. Validate from `../psy-contracts`:

```bash
pnpm install --frozen-lockfile
pnpm run build
pnpm run test:hardhat
pnpm run test:foundry
```

Commit and push source or generated verifier changes before any consumer gitlink update. Record `R_contracts`. Contract deployment requires separate authorization and the repository's `deploy:keystore` scripts. A source push never authorizes deployment.

### 5. Version and Publish SDK Packages Conditionally

npm publication occurs only when packed package bytes or public package contracts changed and the user explicitly authorizes the exact package and version.

The repository `publish:*` scripts mutate versions and pass `--no-git-checks` at `../psy-sdk/psy-ts-sdk/package.json:22-28`. Use the safer split sequence:

1. In a clean SDK release worktree, run only the required version mutation:

```bash
cd ../psy-sdk/psy-ts-sdk
pnpm run version:patch:psy-sdk
pnpm install --lockfile-only
```

2. Bump `utils` only when its output changed. Bump `contract-sdk` when it is published against a new SDK or its own output changed.
3. Review package manifests, provenance, Genesis gitlink, Cargo pins, `Cargo.lock`, and `pnpm-lock.yaml`.
4. Commit and push the reviewed, versioned SDK release commit. Record `R_sdk_release` and the intended versions.
5. Re-run:

```bash
pnpm install --frozen-lockfile
pnpm run publish:check
```

6. After explicit npm authorization, publish the already-versioned packages in dependency order, skipping unchanged packages:

```bash
pnpm --filter @psy-protocol/utils publish --access public --registry=https://registry.npmjs.org/ --no-git-checks
pnpm --filter @psy-protocol/psy-sdk publish --access public --registry=https://registry.npmjs.org/ --no-git-checks
pnpm --filter @psy-protocol/contract-sdk publish --access public --registry=https://registry.npmjs.org/ --no-git-checks
```

Do not run `publish:psy-sdk`, `publish:utils`, `publish:contract-sdk`, or `publish:all` after the separate version step; those scripts would increment versions again. Immediately before each direct publish command, require a clean worktree, the reviewed commit at HEAD, and an exact package/version authorization.

7. Confirm every published version from the registry before downstream updates. Publication is irreversible; do not reuse or overwrite a published version.

### 6. Update DApp and Wallet Consumers

After `R_sdk_build` is published to the matching branch. Use the local SDK path for matching-branch testing; wait for registry confirmation only when npm publication was explicitly authorized and use `R_sdk_release` for that versioned path.

#### DApp

1. Update all affected SDK declarations in `../psy-dapp/apps/bridge/package.json`, `apps/explorer/package.json`, and `apps/ide/package.json`.
2. Advance `psy-genesis` to `R_genesis` and `psy-contracts` to `R_contracts` when those inputs changed.
3. Regenerate `pnpm-lock.yaml` through pnpm.
4. Validate from `../psy-dapp`:

```bash
pnpm install --frozen-lockfile
PSY_SKIP_CONFIG_SYNC=1 pnpm build:bridge
pnpm build:explorer
pnpm build:ide
```

`PSY_SKIP_CONFIG_SYNC=1` keeps the Bridge build on the reviewed deployment file instead of fetching mutable staging configuration through `apps/bridge/scripts/sync-staging-config.mjs:14-31`.

5. Review, commit, and push DApp. Record `R_dapp`.

#### Wallet

1. Keep `../psy-wallet/package.json` on `file:../psy-sdk/psy-ts-sdk/packages/psy-sdk`; refresh `pnpm-lock.yaml` only when the local SDK contents changed. Do not add an npm version unless the user explicitly switches wallet off the local path.
2. Advance its `psy-genesis` gitlink to `R_genesis` when Genesis config changed.
3. Validate from `../psy-wallet`:

```bash
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm run test
pnpm run build:dev
```

4. Review, commit, and push Wallet. Record `R_wallet`.

A Genesis or contracts gitlink update without an SDK package change must not fabricate a new SDK version.

### 7. Update Parent Node Artifacts and Gitlinks Last

Before changing a parent gitlink, prove the child commit is contained by the remote destination branch that carries it:

```bash
destination_ref=${MATCHING_BRANCH:-mainnet-beta}
genesis_commit=$(git -C psy-genesis rev-parse HEAD)
git -C psy-genesis fetch origin "$destination_ref"
git -C psy-genesis merge-base --is-ancestor "$genesis_commit" "origin/$destination_ref"
```

Apply the same check to `psy-contracts` and `psy-dapp`. Reachability is required; merely having the object in a local clone is insufficient.

Then, in the clean node integration worktree:

1. Advance `psy-genesis` to `R_genesis`.
2. Advance `psy-contracts` to `R_contracts` when contracts changed.
3. Advance `psy-dapp` to `R_dapp` when DApp changed.
4. Include the compiler-generated `client_prover/token.json` and `client_prover/token.abi.json` when they changed.
5. Run `make generate-genesis-data` when Genesis-dependent node circuit data changed.
6. Run the token artifact regression and all node tests covering the changed runtime, circuits, generated data, or CLIs.
7. For an authorized runtime release, smoke-test the actual stack only through:

```bash
make shutdown
PSY_SKIP_BUILD=1 PSY_SKIP_BRANCH_CHECK=1 PSY_SKIP_KEYSTORE=1 RUST_LOG=info make run-all
```

8. Review and stage only the generated node artifacts and intended gitlinks.
9. Commit and push this parent integration commit last. Record it as `R_node_integration`.

Do not repin compiler, SDK, or services from `R_node` to `R_node_integration` unless the integration commit changes a crate they consume.

## Commit and Push Gates

Before every commit:

```bash
git status --short
git diff
git diff --cached
git diff --check
git diff --cached --check
git diff --cached --name-only
```

Required conditions:

- every staged path is owned by the current delivery;
- no unrelated source, lockfile, generated artifact, or gitlink is staged;
- the staged set has passed independent review;
- the commit message describes one coherent delivery;
- post-commit HEAD contains exactly the reviewed staged diff.

Before an authorized push:

```bash
destination_ref=${MATCHING_BRANCH:-mainnet-beta}
git fetch origin "$destination_ref"
head_commit=$(git rev-parse HEAD)
remote_commit=$(git rev-parse "origin/$destination_ref")
test "$head_commit" != "$remote_commit"
git merge-base --is-ancestor "origin/$destination_ref" HEAD
git push origin "HEAD:$destination_ref"
test "$(git ls-remote origin "refs/heads/$destination_ref" | cut -f1)" = "$head_commit"
```

Push only the named repository and exact authorized destination ref. Never push tags or additional refs unless separately authorized. Never force-push to repair ordering or publication mistakes.

`AGENTS.md` is intentionally ignored by the repository's current `.gitignore`. When this policy file is the explicitly authorized delivery, stage exactly it with `git add -f AGENTS.md`; force-adding any other ignored path is forbidden.

## Failure and Recovery Rules

1. Stop the release DAG at the first failed generation, provenance, build, test, pack, reachability, publication, deployment, or clone gate.
2. A failed child repository leaves all downstream manifests and parent gitlinks unchanged.
3. A pushed child commit with no parent update is safe. Resume by verifying remote reachability; do not rewrite the child commit.
4. A generator failure may leave owned outputs dirty. Inspect them in the isolated release worktree. Never restore, reset, clean, or delete files in a shared worktree.
5. A provenance mismatch invalidates the generated artifact. Rebuild from the committed clean input revision; never edit provenance JSON by hand.
6. A push rejection requires fetch and review. Never resolve it with force-push or history replacement.
7. npm publication is irreversible. After partial publication, stop, record the exact successful package versions, confirm registry state, and continue only with a forward version for unpublished or corrected packages.
8. A deployment failure does not authorize source-history rollback. Restore service using the last known-good released commits and artifacts, then fix forward.
9. If final recursive-clone verification fails after a parent push, fix child reachability or add a forward parent gitlink commit. Never mutate an already-pushed release commit.

## Final Fresh-Clone Verification

After all authorized pushes, verify the remote graph from a new checkout rather than existing local objects:

```bash
destination_ref=${MATCHING_BRANCH:-mainnet-beta}
verify_dir=$(mktemp -d)
git clone --branch "$destination_ref" --filter=blob:none git@github.com:PsyProtocol/psy-node.git "$verify_dir/psy-node"
git -C "$verify_dir/psy-node" -c submodule.psy-dapp.update=checkout submodule update --init --recursive
git -C "$verify_dir/psy-node" submodule status --recursive
test -f "$verify_dir/psy-node/psy-genesis/config.json"
test -f "$verify_dir/psy-node/psy-genesis/genesis_contracts.json"
test -f "$verify_dir/psy-node/psy-contracts/package.json"
test -f "$verify_dir/psy-node/psy-dapp/package.json"
test -f "$verify_dir/psy-node/psy-dapp/psy-genesis/config.json"
test -f "$verify_dir/psy-node/psy-dapp/psy-contracts/package.json"
```

Reject any submodule status line beginning with `-`, `+`, or `U`. Confirm the checked-out SHAs equal the recorded release SHAs. The release is complete only after this fresh clone can initialize every required child and read every required payload.

## Devnet Artifact Provenance

1. Devnet startup requires both compiler artifact stamps to match the current sibling `psy-compiler` HEAD: `../psy-sdk/psy-ts-sdk/packages/psy-sdk/.compiler-artifact.json` and `psy-genesis/.genesis_contracts.compiler-artifact.json`.
2. After `psy-compiler` HEAD changes, run `make gen-deploy-json` in `../psy-compiler`, rebuild `../psy-sdk/psy-ts-sdk/packages/psy-sdk`, and verify both `compilerRevision` fields before `make run-all`.
3. `PSY_SKIP_BUILD=1` rejecting `compiler revision changed` is a safety gate. Regenerate artifacts; never weaken the check.
4. Use `CARGO_NET_GIT_FETCH_WITH_CLI=true` for SDK builds that resolve SSH submodules. Cargo's default libgit2 backend may not authenticate to `git@github.com`.
5. A cached pinned `psy-node` checkout must contain populated `psy-genesis` and `psy-contracts` submodule directories. Repair empty cached submodules with local `file://` URL rewrites or a normal authenticated submodule update; never delete the Cargo git cache.
6. A submodule `early EOF` is a transient transfer failure. Retry the same authenticated command; do not add `[patch]` or `[replace]` overrides for the pinned node revision.
7. Build release binaries before devnet startup. `PSY_SKIP_BUILD=1` reuses existing binaries and does not prove they match the current source.
8. Use `make rollback-stop` to pause applications for offline rollback. Use `make shutdown` to stop the stack while retaining paired Anvil/L2 state. Use `PURGE=1 make shutdown` or `make restart-all` only for a fresh chain.
