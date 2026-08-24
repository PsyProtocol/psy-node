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

## Repository Cohort

| Repository | Owns | Consumes |
|---|---|---|
| `psy-node` | Node runtime, circuits, CLIs, parent gitlinks, `client_prover/token.json` | `psy-genesis`, `psy-contracts`, `psy-dapp` gitlinks |
| `psy-compiler` | Psy compiler, precompiles, ABI and Genesis generation | Git-pinned `psy-node` crates in `../psy-compiler/Cargo.toml:31-41` |
| `psy-genesis` | Canonical network config, compressed Genesis contracts, ABIs, compiler provenance | Generated from clean `psy-compiler` HEAD by `../psy-compiler/Makefile:191-233` |
| `psy-sdk` | Rust SDK, prover WASM, compiler WASM, TypeScript packages | Git-pinned `psy-node` crates, `psy-genesis` gitlink, sibling `psy-compiler` provenance |
| `psy-services` | API, indexer, migrations, copied Genesis contract metadata | Git-pinned `psy-node` crates and compiler-generated ABI inputs; it has no `psy-genesis` gitlink |
| `psy-contracts` | L1 contracts, verifiers, deployments, protocol config | Conditional verifier output from `Makefile:128-135` |
| `psy-dapp` | Bridge, Explorer, IDE | npm SDK plus `psy-genesis` and `psy-contracts` gitlinks |
| `psy-wallet` | Browser wallet | npm SDK plus `psy-genesis` gitlink |

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
  ├── psy-compiler pins R_node
  │     └── clean compiler revision R_compiler
  │           ├── psy-genesis artifacts + provenance → R_genesis
  │           ├── psy-sdk compiler WASM + provenance
  │           └── psy-services copied ABI metadata, when changed
  ├── psy-sdk pins R_node
  ├── psy-services pins R_node, when consumed crates changed
  └── psy-contracts verifier source, when proving artifacts changed

R_node + R_compiler + R_genesis
  └── psy-sdk release commit R_sdk
        └── authorized npm version V_sdk
              ├── psy-dapp package manifests + lockfile
              └── psy-wallet package manifest + lockfile

R_genesis + R_contracts
  ├── psy-sdk Genesis gitlink
  ├── psy-dapp Genesis and contracts gitlinks
  └── psy-wallet Genesis gitlink

pushed R_genesis + R_contracts + R_dapp
  └── psy-node generated artifacts and parent gitlinks, committed and pushed last
```

`R_node` is the source pin. The final `psy-node` integration commit may contain regenerated `client_prover/token.json`, Genesis-dependent tracked outputs, and child gitlinks. Downstream Cargo manifests continue to pin `R_node` when the later integration commit changes no consumed Rust crate.

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

## Ordered Release State Machine

### 1. Freeze and Push the Node Source Revision

1. Isolate only the node source changes required by the release. Exclude parent gitlink changes and compiler-generated `client_prover/token.json` until the final integration commit.
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

### 3. Generate and Push Genesis Artifacts

The compiler tree must be clean and exactly at `R_compiler`. `make gen-deploy-json` reads compiler HEAD for provenance, writes `../psy-genesis/genesis_contracts.json`, refreshes `../psy-genesis/genesis_abi/`, writes `../psy-genesis/.genesis_contracts.compiler-artifact.json`, and copies the token artifact into `../psy-node/client_prover/token.json` through `../psy-compiler/Makefile:199-233`.

Run from `../psy-compiler`:

```bash
make gen-deploy-json
```

Then verify:

1. `compilerRevision` in the Genesis stamp equals `R_compiler`.
2. `compilerSourcesHash` matches the clean compiler source tree.
3. `artifactSha256` and `artifactByteSize` match `genesis_contracts.json`.
4. Only the expected Genesis artifacts and `../psy-node/client_prover/token.json` changed.
5. The canonical node regression passes:

```bash
cargo test --release -p psy_user_cli --test token_artifact_events
```

Run that command from `psy-node`. It validates compiler provenance and artifact bytes at `client_prover/psy_cli/psy_user_cli/tests/token_artifact_events.rs:271-321`.

Review, commit, and push only the generated `psy-genesis` files. Record the pushed SHA as `R_genesis`. Keep the generated node token artifact for the final node integration commit.

### 4. Fan Out to SDK, Services, and Contracts

These branches may proceed in parallel after `R_node`, `R_compiler`, and `R_genesis` are immutable.

#### SDK

1. Set every active `psy-node` `rev` in `../psy-sdk/Cargo.toml:24-33` to `R_node` and regenerate `Cargo.lock`.
2. Advance the `psy-genesis` gitlink to `R_genesis` when Genesis changed.
3. Ensure the sibling compiler is clean and at `R_compiler`.
4. Build from `../psy-sdk`:

```bash
make check
make build
```

The SDK build creates prover WASM from `psy-rust-sdk`, compiler WASM from sibling `psy-compiler`, generated TypeScript WASM modules, and the tracked compiler stamp. The compiler build rejects dirty compiler sources at `../psy-sdk/psy-ts-sdk/packages/psy-sdk/src/local-web-compiler/compiler-provenance.ts:56-73`.

5. Confirm `../psy-sdk/psy-ts-sdk/packages/psy-sdk/.compiler-artifact.json` records `R_compiler` and the same compiler source hash as Genesis.
6. Run the SDK tests covering changed Rust, TypeScript, generated types, prover, or compiler behavior.
7. From `../psy-sdk/psy-ts-sdk`, validate package contents without publishing:

```bash
pnpm install --frozen-lockfile
pnpm run publish:check
```

8. If packed outputs did not change, do not change package versions and do not publish npm.

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

Change `psy-contracts` only when L1 contracts, verifier sources, deployments, or protocol config changed. Node verifier exports are defined at `Makefile:128-135`. Validate from `../psy-contracts`:

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
4. Commit and push the reviewed SDK release commit. Record `R_sdk` and the intended versions.
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

After npm confirms the exact SDK version:

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

1. Update `../psy-wallet/package.json` and `pnpm-lock.yaml` when the SDK version changed.
2. Advance its `psy-genesis` gitlink to `R_genesis` when Genesis config changed.
3. Validate from `../psy-wallet`:

```bash
pnpm install --frozen-lockfile
pnpm run typecheck
pnpm run test
pnpm run build:dev
```

4. Review, commit, and push Wallet. Record `R_wallet`.

A Genesis or contracts gitlink update without an npm change must not fabricate a new SDK version.

### 7. Update Parent Node Artifacts and Gitlinks Last

Before changing a parent gitlink, prove the child commit is contained by its remote branch. Example for Genesis:

```bash
genesis_commit=$(git -C psy-genesis rev-parse HEAD)
git -C psy-genesis fetch origin mainnet-beta
git -C psy-genesis merge-base --is-ancestor "$genesis_commit" origin/mainnet-beta
```

Apply the same check to `psy-contracts` and `psy-dapp`. Reachability is required; merely having the object in a local clone is insufficient.

Then, in the clean node integration worktree:

1. Advance `psy-genesis` to `R_genesis`.
2. Advance `psy-contracts` to `R_contracts` when contracts changed.
3. Advance `psy-dapp` to `R_dapp` when DApp changed.
4. Include the compiler-generated `client_prover/token.json` when it changed.
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
git fetch origin mainnet-beta
head_commit=$(git rev-parse HEAD)
remote_commit=$(git rev-parse origin/mainnet-beta)
test "$head_commit" != "$remote_commit"
git merge-base --is-ancestor origin/mainnet-beta HEAD
git push origin HEAD:mainnet-beta
test "$(git ls-remote origin refs/heads/mainnet-beta | cut -f1)" = "$head_commit"
```

Push only the named repository and ref. Never push tags or additional refs unless separately authorized. Never force-push to repair ordering or publication mistakes.

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
verify_dir=$(mktemp -d)
git clone --branch mainnet-beta --filter=blob:none git@github.com:PsyProtocol/psy-node.git "$verify_dir/psy-node"
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
