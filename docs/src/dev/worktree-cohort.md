# Worktree Cohort

> Internal developer documentation — repository-only. Not part of the published mdBook (SUMMARY.md).
>
> Updated: 2026-10-15. Status: Review.

## Overview

Create one linked worktree per cohort repository on one new branch, check out every recorded gitlink, then retarget cross-repository dependencies to sibling paths and build in dependency order. The commands below are the tutorial. They do not start a stack, generate root `genesis.json`, publish a package, or change the release Git pins in the source checkouts.

## Background

A cohort worktree is an additional checkout of an existing local repository, not a fresh `git clone` and not a copy of dirty source contents. `psy-node/.gitmodules:8-12` sets `psy-dapp` to `update = none`, so a recursive submodule update from the node worktree skips DApp. SDK, Wallet, node, and DApp each record their own child SHAs. Those gitlinks are independent of the matching sibling repository `HEAD`.

Release publication order stays [circuit-and-verifier-operations.md](circuit-and-verifier-operations.md) §8. Section 6 here is local mode only: path and `file:` edits inside the new worktrees. Sibling ownership is `AGENTS.md:27,87-102`.

## Bun workspace workflow

`scripts/workspace.ts` provides the automated Git-only workflow below. The later
shell tutorial also describes optional local dependency edits and builds; the Bun
commands do **not** perform those edits, install dependencies, or start services.
Run from a workspace root containing the eight sibling repositories:

```bash
bun psy-node/scripts/workspace.ts --help
bun psy-node/scripts/workspace.ts status
bun psy-node/scripts/workspace.ts create --source . --destination ../feature-demo --branch feature/demo
bun psy-node/scripts/workspace.ts commit --source ../feature-demo --repo psy-sdk --message 'Update client' -- psy-ts-sdk/src/client.ts
# Alternatively, review the index yourself first, then commit only that index:
bun psy-node/scripts/workspace.ts commit --source ../feature-demo --repo psy-sdk --message 'Update client' --staged
# Explicit user-run publication of clean topic branches (optionally --repo NAME):
bun psy-node/scripts/workspace.ts push --source ../feature-demo
bun psy-node/scripts/workspace.ts merge --source ../feature-demo --target . --branch feature/demo --integration ../integration-demo
# Explicit user-run publication; use a fresh integration directory:
bun psy-node/scripts/workspace.ts merge --source ../feature-demo --target . --branch feature/demo --integration ../integration-publish --push
```

The default base is `mainnet-beta`; the default remote is `origin`. `status` is
read-only and is the default command. All mutations require an explicit source.
Creation checks all repositories first and creates real topic branches from
committed base refs; it never copies dirty files, secrets, ledgers, or local
configuration. Missing repositories use the documented official origin. Recorded
submodules are initialized, including node's `update = none` DApp gitlink.

`commit` requires exactly one repository, a message, and either literal paths
after `--` or `--staged`. Explicit paths require an empty index and cannot name
the repository root. There is no blanket staging. `push` refuses detached HEAD,
base/main/master branches, dirty trees, and non-fast-forward remote topics. It
preflights every selected repository before the first push; it never forces.

`merge` requires clean topic worktrees but permits dirty target worktrees because
it **never changes target files, indexes, or local base branches**. It freezes
each target's local base commit and the actual remote base SHA using `ls-remote`.
Required remote objects are fetched into immutable
`refs/prefetch/workspace/<sha>` refs with an empty refmap; remote-tracking refs
are not updated. Current remote base must be an ancestor of local base, so local
unpublished base commits are retained and newer public commits cannot be dropped.
The integration directory must be new and outside both workspaces, with an
existing parent. Its basename identifies the new `workspace-integration/...`
branch in each target repository.

Ordering comes from the union of recorded gitlinks in the topic tree and the
merge ancestor of the topic and frozen target base trees, with
compiler/contracts/genesis/sdk/services/wallet/dapp/node as tie order.
Cycles fail before worktree creation. Only `.gitmodules` URLs whose basename is
one of those repositories form cohort edges; external submodules and historical
Cargo/package pins do not. A gitlink counts as changed only against that merge
ancestor: a pin the topic kept while the target base advanced is not a topic
change, and the target pin survives the squash. Unchanged historical gitlinks
remain unchanged. A changed cohort gitlink must equal its sibling topic HEAD,
and that child topic must descend from its frozen local base. The parent index
then records the child's completed integration hash, never its stranded
pre-squash topic hash. Nested target checkouts are never retargeted.

All squash results are prepared on isolated integration branches before any
publication. Conflicts stop immediately and retain every created worktree for
inspection; only gitlink-only conflicts with a validated child mapping can be
resolved automatically. No automatic removal, stash, reset, switch, or rollback
occurs. Fix the topic/base explicitly, then rerun with a fresh integration path.
Local refs and actual remote tips are checked again after integration. `--push`
alone authorizes dependency-ordered base publication, checking the expected remote
tip again before each ordinary non-force push. Cross-repository publication is
not atomic: failure can leave earlier dependencies published; the command stops
and retains all integration branches. No credential URLs are stored in metadata.

After merge, **local `mainnet-beta` remains unchanged**, even after `--push`.
The command prints an exact `git -C ... -c submodule.recurse=false merge --ff-only
<integration-sha>` for each repository. Run it yourself only after confirming the
target is clean and already on the intended base branch. Preserve or explicitly
commit existing user work first; never reset or discard it to synchronize.


## Table of Contents

- [1. Inputs](#1-inputs)
- [2. Preflight](#2-preflight)
- [3. Create](#3-create)
- [4. Gitlinks](#4-gitlinks)
- [5. Verify](#5-verify)
- [6. Local Dependencies](#6-local-dependencies)
- [7. Build](#7-build)
- [8. Cleanup](#8-cleanup)
- [9. Security](#9-security)

## 1. Inputs

```bash
set -euo pipefail
: "${SOURCE_ROOT:?set SOURCE_ROOT to the parent of the eight source checkouts}"
: "${DESTINATION_ROOT:?set DESTINATION_ROOT to the new sibling parent}"
: "${BRANCH:?set BRANCH to the new branch name}"
SOURCE_ROOT=$(realpath "$SOURCE_ROOT")
DESTINATION_ROOT=$(realpath -m "$DESTINATION_ROOT")
repos=(psy-node psy-compiler psy-genesis psy-services psy-contracts psy-dapp psy-wallet psy-sdk)
```

`DESTINATION_ROOT` must not exist yet. `realpath -m` only normalizes the path. Optional `BASE_SHA_<NAME>` overrides replace `origin/mainnet-beta` for that repository. Example: `BASE_SHA_PSY_NODE=<full-sha>`. Do not read the base from a dirty index or the current branch.

The same `BRANCH` is created in each distinct repository. If that branch name already exists in a repository, preflight stops. Do not pass `-B`, `--force`, `reset`, or `stash`.

```text
SOURCE_ROOT/                         DESTINATION_ROOT/
  psy-node/          git worktree add    psy-node/      BRANCH @ frozen SHA
  psy-compiler/  ----------------------> psy-compiler/
  ... seven more siblings               ... same eight names
```

## 2. Preflight

Run this to completion before creating any worktree. It does not add a worktree or change a branch. `git fetch` does update `FETCH_HEAD` and `origin/mainnet-beta` in each source repository.

```bash
set -euo pipefail
declare -A base_sha expect_ssh expect_https
expect_ssh[psy-node]=git@github.com:PsyProtocol/psy-node.git
expect_https[psy-node]=https://github.com/PsyProtocol/psy-node.git
expect_ssh[psy-compiler]=git@github.com:PsyProtocol/psy-compiler.git
expect_https[psy-compiler]=https://github.com/PsyProtocol/psy-compiler.git
expect_ssh[psy-genesis]=git@github.com:PsyProtocol/psy-genesis.git
expect_https[psy-genesis]=https://github.com/PsyProtocol/psy-genesis.git
expect_ssh[psy-services]=git@github.com:PsyProtocol/psy-services.git
expect_https[psy-services]=https://github.com/PsyProtocol/psy-services.git
expect_ssh[psy-contracts]=git@github.com:PsyProtocol/psy-contracts.git
expect_https[psy-contracts]=https://github.com/PsyProtocol/psy-contracts.git
expect_ssh[psy-dapp]=git@github.com:PsyProtocol/psy-dapp.git
expect_https[psy-dapp]=https://github.com/PsyProtocol/psy-dapp.git
expect_ssh[psy-wallet]=git@github.com:PsyProtocol/psy-wallet.git
expect_https[psy-wallet]=https://github.com/PsyProtocol/psy-wallet.git
expect_ssh[psy-sdk]=git@github.com:PsyProtocol/psy-sdk.git
expect_https[psy-sdk]=https://github.com/PsyProtocol/psy-sdk.git

test ! -e "$DESTINATION_ROOT"
case "$DESTINATION_ROOT" in
  "$SOURCE_ROOT"|"$SOURCE_ROOT"/*) echo "destination is inside source root" >&2; exit 1 ;;
esac
for name in "${repos[@]}"; do
  src=$(realpath "$SOURCE_ROOT/$name")
  case "$DESTINATION_ROOT" in
    "$src"|"$src"/*) echo "destination is inside $name" >&2; exit 1 ;;
  esac
  git -C "$src" rev-parse --is-inside-work-tree >/dev/null
  top=$(realpath "$(git -C "$src" rev-parse --show-toplevel)")
  test "$top" = "$src"
  url=$(git -C "$src" remote get-url origin)
  url=${url%.git}.git
  test "$url" = "${expect_ssh[$name]}" || test "$url" = "${expect_https[$name]}"
  git -C "$src" fetch origin mainnet-beta
  key=BASE_SHA_$(printf '%s' "$name" | tr '[:lower:]-' '[:upper:]_')
  if [ -n "${!key:-}" ]; then
    git -C "$src" cat-file -e "${!key}^{commit}"
    base_sha[$name]=${!key}
  else
    base_sha[$name]=$(git -C "$src" rev-parse FETCH_HEAD)
  fi
  if git -C "$src" show-ref --verify --quiet "refs/heads/$BRANCH"; then
    echo "$name already has branch $BRANCH" >&2
    exit 1
  fi
done
```

`FETCH_HEAD` after that fetch is the frozen default base. A `BASE_SHA_*` value must already be a commit object. Fetch does not obtain an arbitrary ref. The remote-tracking update is a source-repository ref change, not a checkout change.

## 3. Create

```bash
set -euo pipefail
mkdir -p "$DESTINATION_ROOT"
created=()
for name in "${repos[@]}"; do
  git -C "$SOURCE_ROOT/$name" worktree add -b "$BRANCH" \
    "$DESTINATION_ROOT/$name" "${base_sha[$name]}"
  created+=("$name")
done
```

`-b` creates `BRANCH` at the frozen SHA. It fails when the name exists. Do not replace it with `-B`.

## 4. Gitlinks

Seven gitlink edges are recorded: node to genesis, node to contracts, node to dapp, dapp to genesis, dapp to contracts, sdk to genesis, and wallet to genesis. Contracts records `lib/forge-std`, and the DApp contracts gitlink records it again. Recursive checkout follows those nested links. It does not move a gitlink to the sibling repository `HEAD`.

`update = none` makes a recursive node update skip `psy-dapp`. Initialize the other seven edges recursively, then check out the node DApp gitlink explicitly and recurse from there:

```bash
set -euo pipefail
for name in "${repos[@]}"; do
  git -C "$DESTINATION_ROOT/$name" submodule update --init --recursive
done
git -C "$DESTINATION_ROOT/psy-node" submodule update --init --checkout -- psy-dapp
git -C "$DESTINATION_ROOT/psy-node/psy-dapp" submodule update --init --recursive
```

Do not use `--remote`. The node DApp checkout is the recorded gitlink, not `$DESTINATION_ROOT/psy-dapp`.

## 5. Verify

```bash
set -euo pipefail
for name in "${repos[@]}"; do
  top="$DESTINATION_ROOT/$name"
  test "$(git -C "$top" rev-parse HEAD)" = "${base_sha[$name]}"
  test "$(git -C "$top" branch --show-current)" = "$BRANCH"
  git -C "$SOURCE_ROOT/$name" worktree list
  git -C "$top" submodule status --recursive
done
```

Every status line must start with a space. `-` means a gitlink is not checked out. `+` or `U` means the checkout does not match the recorded SHA. Stop before Section 6.

## 6. Local Dependencies

Edit only the new worktrees. Keep package aliases, `default-features`, feature lists, and each existing `[patch."https://github.com/PsyProtocol/plonky2-hwa"]` block. The patch URL uses a doubled slash and revision `736572e9dd3ca93566471cf5a2a1cb67a13fe01d` at `psy-node/Cargo.toml:375-379`, `psy-compiler/Cargo.toml:244-248`, `psy-sdk/Cargo.toml:57-61`, and `psy-services/Cargo.toml:133-137`. Replace `git` and `rev` with `path`. Do not add a second patch or a `[replace]` table.

Compiler keys at `psy-compiler/Cargo.toml:31-41`:

| Key | package | path under the node worktree |
|---|---|---|
| `psy_vm` | | `client_prover/psy_vm` |
| `psy_crypto` | | `client_prover/psy_core/psy_crypto` |
| `psy_data` | `psy_client_data` | `client_prover/psy_core/psy_data` |
| `psy_common_core` | `psy_client_common` | `client_prover/psy_core/psy_common` |
| `psy_config` | | `client_prover/psy_core/psy_config` |
| `psy_prover` | | `client_prover/psy_prover` |
| `psy_common_circuit` | | `client_prover/psy_circuit/psy_common_circuit` |
| `psy_dpn_circuit` | | `client_prover/psy_circuit/psy_dpn_circuit` |
| `psy_ups_circuit` | | `client_prover/psy_circuit/psy_ups_circuit` |
| `psy_network_circuit` | | `client_prover/psy_circuit/psy_network_circuit` |
| `kvq` | | `client_prover/psy_core/kvq` |

`psy_vm`, `psy_data`, `psy_prover`, and the four circuit crates keep `default-features = false`.

Services keys at `psy-services/Cargo.toml:12-25`, plus dev-dependency `psy_client_data` at line 127. The key is the package name. `default-features = false` stays on `psy_common_circuit`, `psy_dpn_circuit`, `psy_client_data`, and `psy_plonky2_circuits`.

| Key | Directory under the node worktree |
|---|---|
| `psy_core` | `psy_core` |
| `psy_api_core` | `psy_api_core` |
| `parth_core` | `parth_core` |
| `psy_data` | `psy_data` |
| `psy_node_core` | `psy_node_core` |
| `psy_serialize` | `psy_serialize` |
| `psy_plonky2_circuits` | `psy_plonky2_circuits` |
| `psy_client_common` | `client_prover/psy_core/psy_common` |
| `psy_client_data` | `client_prover/psy_core/psy_data` |
| `psy_config` | `client_prover/psy_core/psy_config` |
| `psy_crypto` | `client_prover/psy_core/psy_crypto` |
| `psy_common_circuit` | `client_prover/psy_circuit/psy_common_circuit` |
| `psy_dpn_circuit` | `client_prover/psy_circuit/psy_dpn_circuit` |
| `psy_provider` | `client_prover/psy_provider` |

SDK keys at `psy-sdk/Cargo.toml:24-33` use the same directories. `package` equals the key except `psy_data` = `psy_client_data` and `psy_common` = `psy_client_common`. `psy_vm`, `psy_data`, `psy_prover`, `psy_common_circuit`, `psy_dpn_circuit`, and `psy_ups_circuit` keep `default-features = false`. SDK has no `psy_network_circuit` pin.

Wallet `package.json:43` is `file:../psy-sdk/psy-ts-sdk/packages/psy-sdk`, one level above `psy-wallet`, so it is `$DESTINATION_ROOT/psy-sdk`. DApp app manifests keep `file:../../../psy-sdk/psy-ts-sdk/packages/psy-sdk` (account also has `evm-wallet` at line 26, bridge line 38, explorer line 21, ide line 17). From `apps/<app>/package.json`, `../../..` is the parent of `psy-dapp`, which is `$DESTINATION_ROOT`, not `psy-dapp/psy-sdk` and not four levels up. The lockfile records that same target as `file:../psy-sdk/...` from the `psy-dapp` workspace root (`psy-dapp/pnpm-lock.yaml:20-24,1284-1285`). Do not rewrite those specifiers. `apps/site` and `apps/wallet` have no `@psy-protocol/*` dependency.

Refresh each edited Cargo lock without rewriting unrelated versions. Discard the metadata document:

```bash
set -euo pipefail
for name in psy-compiler psy-services psy-sdk; do
  cargo metadata --format-version 1 --manifest-path "$DESTINATION_ROOT/$name/Cargo.toml" >/dev/null
done
```

For an edited pnpm manifest, refresh only its lockfile:

```bash
pnpm install --lockfile-only --ignore-scripts --dir "$DESTINATION_ROOT/psy-dapp"
pnpm install --lockfile-only --ignore-scripts --dir "$DESTINATION_ROOT/psy-wallet"
```

Commit those manifest and lockfile edits in the owning worktree before Section 7. `psy-compiler/Makefile:270-309` stamps `compilerRevision` from `git rev-parse HEAD`. An uncommitted local-mode edit stamps the wrong source. Do not run `make gen-deploy-json` or `make generate-genesis-data` from this tutorial. Absence of root `genesis.json` is not permission to generate it.

## 7. Build

Build the eight sibling worktrees under `$DESTINATION_ROOT`. Do not build `psy-node/psy-dapp` or `psy-node/psy-contracts`. Those are recorded gitlinks from Section 4, not the cohort branches. Do not run `make run-all` or start a service.

`PSY_NETWORK` is required. The package script would otherwise default it to `testnet` (`psy-sdk/psy-ts-sdk/packages/psy-sdk/package.json:75-76`). For this local tutorial set `localhost`. `DARGO_STD_PATH` is the compiler worktree's std file, the same path `psy-compiler/Makefile:13` exports as `$(PWD)/psy-std/std.psy`.

SDK install uses `psy-sdk/psy-ts-sdk/pnpm-lock.yaml`, then one `pnpm build`. That script runs `prepare:wasm` and compile: web prover WASM, nodejs prover WASM, then compiler WASM (`package.json:75-79`). Do not also run `psy-sdk/Makefile` `build`. Contracts has `pnpm-lock.yaml` and no `package-lock.json`, so do not use `npm ci`. `pnpm run build` is `hardhat compile` (`psy-contracts/package.json:6`). Wallet `build:dev` typechecks, cleans, and builds with `VITE_NETWORK=localhost` (`psy-wallet/package.json:14`).

```bash
set -euo pipefail
: "${PSY_NETWORK:?set PSY_NETWORK, localhost for this tutorial}"
export PSY_NETWORK
export DARGO_STD_PATH="$DESTINATION_ROOT/psy-compiler/psy-std/std.psy"
test -f "$DARGO_STD_PATH"
( cd "$DESTINATION_ROOT/psy-node" && cargo build --release --locked \
    --bin psy_node_cli --bin psy_worker_cli --bin psy_dev_cli \
    --bin psy_relayer_cli --bin psy_user_cli )
( cd "$DESTINATION_ROOT/psy-compiler" && cargo build --release --locked --bin dargo )
( cd "$DESTINATION_ROOT/psy-sdk/psy-ts-sdk" && pnpm install --frozen-lockfile )
( cd "$DESTINATION_ROOT/psy-sdk/psy-ts-sdk" && \
    pnpm --filter @psy-protocol/psy-sdk run build )
( cd "$DESTINATION_ROOT/psy-services" && cargo build --release --locked \
    --bin psy-services --bin psy-indexer )
( cd "$DESTINATION_ROOT/psy-contracts" && pnpm install --frozen-lockfile && pnpm run build )
( cd "$DESTINATION_ROOT/psy-dapp" && pnpm install --frozen-lockfile )
( cd "$DESTINATION_ROOT/psy-dapp" && pnpm run build:bridge && pnpm run build:explorer \
    && pnpm run build:ide && pnpm run build:account )
( cd "$DESTINATION_ROOT/psy-wallet" && HUSKY=0 pnpm install --frozen-lockfile )
( cd "$DESTINATION_ROOT/psy-wallet" && pnpm build:dev )
```

`dev/locSetupV4.ts:2190-2213` omits `--frozen-lockfile` unless `.npmrc` contains `lockfile=true`, and lines 3128-3154 retry `pnpm approve-builds --all`. Do not use that path. `psy-wallet/pnpm-workspace.yaml:1-3` does not authorize a registry SDK version in place of the `file:` dependency. Forge uses the Section 4 `lib/forge-std` checkout. `foundry.toml:4-5` sets its lib and test dirs. Do not run `forge install`.

## 8. Cleanup

This procedure does not remove cohort worktrees. `git worktree remove` exits 128 with `working trees containing submodules cannot be moved or removed` after the gitlinks in Section 4 are initialized. `submodule deinit` does not make that removal succeed, so do not run it as a prelude. Do not pass `--force`, do not delete the worktree directory, and do not delete `BRANCH`.

An uninitialized worktree can be removed only before Section 4, and only by an operator who has reviewed that it contains no other work. After Section 4, keep the cohort. Any later removal is a separate operator-reviewed action outside this procedure. This document does not claim that removal succeeds.

## 9. Security

1. Do not copy `node_modules`, Cargo `target`, keystores, `private_keys.json`, faucet operator keys, or deployment secrets into `DESTINATION_ROOT`.
2. Do not share Anvil state, databases, Redis, NATS, ports, or process supervisors with the source checkout.
3. Do not add symlinks between the trees. The Git worktree metadata is the only link.
4. Local mode does not authorize a Git push, package publish, or contract deploy.
5. A failed preflight creates no worktree. It does update the fetched remote-tracking refs. After Section 4, this procedure has no removal step.

## Related Documents

- [Circuit and verifier operations](circuit-and-verifier-operations.md) §8
- [Devnet lifecycle](devnet_lifecycle.md)
- [Terminology](TERMINOLOGY.md)
