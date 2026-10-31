# Worktree Cohort

> Internal developer documentation — repository-only. Not part of the published mdBook (SUMMARY.md).
>
> Updated: 2026-10-20. Status: Review.

## Overview

Create one linked worktree per cohort repository on one new branch, check out every recorded gitlink, then retarget cross-repository dependencies to sibling paths and build in dependency order. The commands below are the tutorial. They do not start a stack, generate root `genesis.json`, publish a package, or change the release Git pins in the source checkouts.

## Background

A cohort worktree is an additional checkout of an existing local repository, not a fresh `git clone` and not a copy of dirty source contents. `psy-node` records only `psy-genesis` as a submodule; `psy-contracts` and `psy-dapp` are sibling repositories of the workspace, not gitlinks of `psy-node`. SDK and Wallet each record their own `psy-genesis` child SHA, and DApp records `psy-genesis` and `psy-contracts`. Those gitlinks are independent of the matching sibling repository `HEAD`.

Release publication order stays [circuit-and-verifier-operations.md](circuit-and-verifier-operations.md) §8. Section 6 here is local mode only: path and `file:` edits inside the new worktrees. Sibling ownership is `AGENTS.md:27,87-102`.

## Bun workspace workflow

`scripts/workspace.ts` is the only workspace command. Cohort gitlink staging is
`gitlinks sync`. Integration preparation is `prepare-merge`. Dependency reads
and switches are `deps` subcommands, and SDK version, pack, and publish steps
are `packages` subcommands. None of these commands build packages or start
services. `psy-node` in these commands is the cohort repository, not Node.js.
Run from a workspace root containing the eight sibling repositories:

```bash
bun psy-node/scripts/workspace.ts --help
bun psy-node/scripts/workspace.ts status
bun psy-node/scripts/workspace.ts create --source . --destination ../feature-demo --branch feature/demo
bun psy-node/scripts/workspace.ts gitlinks sync --source ../feature-demo
bun psy-node/scripts/workspace.ts commit --source ../feature-demo --repo psy-sdk --message 'Update client' -- psy-ts-sdk/packages/psy-sdk/src/coord-edge-rpc/client.ts
# Alternatively, review the index yourself first, then commit only that index:
bun psy-node/scripts/workspace.ts commit --source ../feature-demo --repo psy-sdk --message 'Update client' --staged
# Preview selected local commits in dependency order; nothing is written:
bun psy-node/scripts/workspace.ts prepare --source ../feature-demo --repo psy-node,psy-sdk --commit-path psy-sdk=psy-ts-sdk/packages/psy-sdk/src/coord-edge-rpc/client.ts --message 'Prepare cohort pins'
# Apply the same plan: stage only owned paths, resolve Cargo locks, commit; never pushes:
bun psy-node/scripts/workspace.ts prepare --source ../feature-demo --repo psy-node,psy-sdk --commit-path psy-sdk=psy-ts-sdk/packages/psy-sdk/src/coord-edge-rpc/client.ts --message 'Prepare cohort pins' --apply
# Preview freezes each selected HEAD against the live origin tip. Publication needs --push:
bun psy-node/scripts/workspace.ts push --source ../feature-demo
bun psy-node/scripts/workspace.ts push --source ../feature-demo --repo psy-contracts,psy-node --push
bun psy-node/scripts/workspace.ts prepare-merge --source ../feature-demo --target . --branch feature/demo --integration ../integration-demo
# Explicit user-run publication; use a fresh integration directory:
bun psy-node/scripts/workspace.ts prepare-merge --source ../feature-demo --target . --branch feature/demo --integration ../integration-publish --push
```

The default base is `mainnet-beta`; the default remote is `origin`. `status`,
`gitlinks sync`, and `deps show` default to the workspace containing this script;
every other command requires an explicit source. `gitlinks sync` is Git-only and local:
it does not fetch
from a remote, does not edit Cargo or npm pins, and does not commit. Creation
checks all repositories first and creates real topic branches from committed
base refs; it never copies dirty files, secrets, ledgers, or local
configuration. Missing repositories use the documented official origin. Recorded
submodules are initialized (`psy-node` records only `psy-genesis` now). A
create failure exits nonzero and keeps every directory already created.

`commit` requires exactly one repository, a message, and either literal paths
after `--` or `--staged`. Explicit paths require an empty index and cannot name
the repository root. There is no blanket staging. `push` freezes every selected
HEAD (or an optional explicit reviewed SHA) and the live origin tip of its
checked-out `mainnet-beta` or topic branch. That tip must be an ancestor of the
frozen commit. Dirty files are printed and excluded. Nothing is merged, squashed,
or published unless `--push` is present, and publication never forces. `push`
itself never fetches: without `--push` it only checks local objects and live
remote tips, and publication performs no fetch either.

`prepare`, `push`, and `prepare-merge` are distinct: `prepare` commits selected
local work on the current branches; `push` publishes already-existing commits to
the live tip of each checked-out branch without merging, squashing, or rewriting
pins; `prepare-merge` builds dependency-ordered squash commits on new
`workspace-integration/...` branches in the target workspace, and only
`prepare-merge --push` publishes those integration commits to the remote base.

`prepare` selection is explicit and unique (`--repo NAME[,NAME...]`); unselected
siblings are outside the plan and are never touched or automatically updated.
`--commit-path NAME=LITERAL_FILE` (repeatable) owns individual literal files —
never a repository root, directory, or symlink — and a path that is a recorded
gitlink requires selecting its child repository. Order is derived automatically
from selected gitlink children and psy-node Cargo pins, children first; a cycle
fails before any write. Gitlink paths, plus `Cargo.toml` and `Cargo.lock` when
the repository carries psy-node pins and psy-node is selected, are automatically
owned: they must be clean unless explicitly named with `--commit-path`, and a
dirty `.gitmodules` beside a moving gitlink must be explicitly owned with its
submodule mappings unchanged (mapping changes are committed separately before
prepare). Unowned dirt is preserved and never staged; every index must be empty
and conflict-free. The preview performs no writes, fetches, or Cargo resolution;
it freezes branch, HEAD, owned bytes, gitlink index values, and nested
checkouts, and `--apply` re-verifies all of it before its first write. `--apply`
stages only owned paths and commits once per changed repository, reporting an
unchanged repository as skipped. It never pushes, and its Git operations contact
no remote: a moving gitlink is imported from the sibling repository into the
nested checkout (`refs/prefetch/workspace/<sha>`, no fetch head) and may only
move forward to a prepared child commit that descends from the recorded pin;
psy-node Cargo pins are rewritten to canonical Git `rev` pins at the prepared
psy-node commit, and `cargo metadata` (then `--locked`) resolves and validates
`Cargo.lock`. psy crates resolve from local sibling paths and a temporary local
git db seeded with the prepared psy-node commit. Cargo Git fetch is CLI-backed
with `GIT_ALLOW_PROTOCOL=file`: selected siblings are rewritten to those local
paths, so other external Git dependencies resolve only from cache or a local
file. An uncached HTTPS or SSH Git dependency cannot be fetched even when the
network is available; registry network access is separate, and no fully offline
run is claimed. npm versions are never bumped,
implicitly or otherwise, and nothing is pushed. A failure retains every partial
commit, pin, lock edit, and index or worktree change for inspection (no reset,
no stash, no rollback). Reconcile that state deliberately until every selected
index is empty and conflict-free, then preview the new plan; rerunning the same
command is not a resume and does not discard retained changes.

`prepare-merge` requires clean topic worktrees but permits dirty target worktrees because
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
remain unchanged, except a pin that still equals the child topic HEAD: the
squash commit is a new SHA even when the child tree matches the merge ancestor,
so the parent index records that integration hash instead of the stranded topic
tip. A changed cohort gitlink must equal its sibling topic HEAD, and that child
topic must descend from its frozen local base. The parent index then records
the child's completed integration hash, never its stranded pre-squash topic
hash. Nested target checkouts are never retargeted.

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

After prepare-merge, **local `mainnet-beta` remains unchanged**, even after `--push`.
The command prints an exact `git -C ... -c submodule.recurse=false merge --ff-only
<integration-sha>` for each repository. Run it yourself only after confirming the
target is clean and already on the intended base branch. Preserve or explicitly
commit existing user work first; never reset or discard it to synchronize.

`prepare-merge` also reads `Cargo.toml` from the source tip and the merge ancestor of
`psy-compiler`, `psy-sdk`, and `psy-services` before it creates the integration
directory. It uses the node remote base already frozen by that preflight. A
psy-node `rev` the topic introduces must be that frozen remote base or its
ancestor. Commits reachable from the source node tip but not from that remote
base are the commits this squash drops; a retained pin that names one of them
fails. Unchanged historical pins are printed and left alone, including pins
whose objects are not in this checkout. A repository with no `Cargo.toml`
(fixture trees) contributes no pins. A present but malformed manifest fails.
This check does not edit Cargo files and does not contact the network again.

Cargo and npm publication is a separate two-pass flow through the same
`scripts/workspace.ts` entrypoint, not something `prepare-merge` performs and not
something this document claims has been published. `deps use-node-commit` changes
Cargo pins only. `deps use-npm-version` changes the wallet and dapp SDK and EVM dependency versions only. There is no
combined pin command.

1. Freeze the node code revision that consumers will name, and get that exact
   SHA onto the published base history (`deps use-node-commit` only after that SHA exists
   on the remote base). Do not point Cargo `rev` values at a pre-squash topic
   tip or an unpublished integration commit. A published integration SHA is valid.
2. On a separate dependency topic, set explicit SDK versions (`packages set-version`),
   pack and validate the four tarballs (`packages pack`), then publish those
   tarballs (`packages publish`). Registry confirmation is required before
   consumers move. Publish uploads already packed tarballs only. It does not
   build, commit, stage, or reset.
3. Switch wallet and dapp SDK and EVM dependencies together (`deps use-npm-version`), then `gitlinks sync`
   cohort gitlinks and `prepare-merge` them. Nested dapp links must already be inside
   the dapp commit that node records.

`packages set-version` and `packages pack` require the selected SDK version to
satisfy EVM wallet's declared SDK peer range. `deps use-npm-version` checks that range
from published registry metadata before changing manifests or locks; matching
package versions alone do not establish compatibility. Missing peer metadata
also stops the switch. The peer gate supports exact `major.minor.patch` and
caret `^major.minor.patch` ranges, including the current `^2.0.0`; malformed or
other range syntax is rejected explicitly rather than interpreted permissively.

### Local dependency cutover and return to published dependencies

```bash
# Read-only dependency report. show may omit --source; check requires it:
bun psy-node/scripts/workspace.ts deps show --source ../feature-demo
bun psy-node/scripts/workspace.ts deps check --source ../feature-demo
# Read-only plan; requires eight siblings on the same topic branch:
bun psy-node/scripts/workspace.ts deps use-local --source ../feature-demo
# Rewrite manifests and resolve locks only (network/cache access is possible):
bun psy-node/scripts/workspace.ts deps use-local --source ../feature-demo --apply
# --install is rejected unless --apply is also present. It activates consumer
# node_modules with lifecycle scripts disabled:
bun psy-node/scripts/workspace.ts deps use-local --source ../feature-demo --apply --install
# Return Cargo to an explicit revision already reachable from the remote base.
# This does not change npm consumers:
bun psy-node/scripts/workspace.ts deps use-node-commit --source ../feature-demo --rev FULL_PUBLISHED_SHA --apply
# Return npm to an explicit, published, peer-compatible version.
# This does not change Cargo pins:
bun psy-node/scripts/workspace.ts deps use-npm-version --source ../feature-demo --version 2.0.8 --apply --install
# Set four explicit SDK versions, then pack and publish those tarballs only:
bun psy-node/scripts/workspace.ts packages set-version --source ../feature-demo --version 2.0.8 --apply
bun psy-node/scripts/workspace.ts packages pack --source ../feature-demo --out ../sdk-packs --version 2.0.8
bun psy-node/scripts/workspace.ts packages publish --source ../feature-demo --out ../sdk-packs --version 2.0.8 --tag latest
```

Choose the lock-only or install form, not both sequentially against dirty owned
files. These operations permit unrelated source dirt, but require their own
manifests and locks to be tracked and clean before any writes. Review and commit
each completed switch explicitly before another switch. All eight sibling HEADs,
branches, and owned-file bytes are rechecked immediately before mutation.
Nothing is staged, committed, reset, restored, built, or published automatically.
Failure retains all partial edits and installs for inspection; there is no
automatic retry over dirty output.

Local Cargo mode rewrites 36 direct declarations in compiler, SDK, and services,
using `package` rather than dependency alias to locate each concrete node crate.
It preserves aliases, features and existing patch tables. The virtual node root
is never used as a crate. Cargo itself updates each lock through `metadata`, then
`metadata --locked` checks the graph. Remaining remote node packages or wrong
sibling crate paths fail. `deps use-node-commit` reverses local paths to explicit Git pins
and rejects mixed local/published graphs; divergent published revisions still
require `--allow-history-switch`.

Local npm mode changes five consumer manifests: wallet plus DApp account,
bridge, explorer and IDE. Account changes SDK and EVM wallet together. Source
package names, declared prebuilt entrypoints and the EVM SDK peer range must be
valid before any write; the helper never builds missing output. Real pnpm
updates wallet's lock, DApp's root lock, and account's standalone lock (using
`--ignore-workspace`). Real Bun updates account's compatibility `bun.lock` with
`--lockfile-only --ignore-scripts`; parsing uses the available `Bun.JSON5.parse`
API (Bun 1.3.14 or newer), not text stripping. Bridge's inactive legacy pnpm lock
is left unchanged with a warning. Published mode checks actual registry
integrities in all active locks, not just manifest versions.

Only `--apply --install` changes `node_modules`. It invokes scripts-disabled
pnpm `install --force --frozen-lockfile` at wallet and DApp root, not account's
standalone compatibility root. Force explicitly requests refresh after an SDK
build atomically replaces output files. The helper compares installed declared
entrypoint/provenance bytes and package identity to the sibling, failing if stale.
An isolated authored-package fixture with pnpm 10.34.5 demonstrated offline
forced frozen installation refreshing a rename-replaced `dist` directory and a
new export in all five consumers. Real Cargo, pnpm, and Bun resolvers completed
the local-to-published round trip; this is not a full SDK/consumer build verification.
Workspace `link:` records are accepted only when their importer-relative target
matches the expected sibling. Unknown Bun tuple shapes fail closed.
After a later SDK rebuild, rerun the explicit install form with clean owned files.
Pack, publish, push and prepare-merge reject local dependency declarations/locks; return
to published dependencies and review the resulting commits before publication.
Cargo publication inspection covers tracked member manifests and locks, not only
root manifests. A source-less lock package is rejected only when its name belongs
to a concrete node crate and is not a package declared by that consumer itself;
ordinary consumer workspace packages and node's own internal paths remain valid.



`gitlinks sync` is the cohort gitlink command. It reads every sibling, then refuses to
write until the whole graph is valid. All eight repositories must be on the same
checked-out topic branch (not the base, not detached, not
`workspace-integration/...`). A cohort gitlink whose recorded SHA is not an
ancestor of that sibling's HEAD fails closed, including a pin that has commits
the sibling does not. External gitlinks such as `lib/forge-std` are not cohort
edges and are left alone. A pin that already equals the sibling HEAD must also
match the on-disk nested checkout; an index-only match is not enough. The parent
repository does not store child commits, so ancestry is compared in the sibling
repository after a local import of the recorded pin from the nested checkout
when that object is missing there. Superproject dirt other than the gitlinks
about to be staged fails the command. A dirty or missing nested checkout fails
it too: gitlinks sync never discards nested files and never initializes a new checkout.
Those checks finish before any index write. The recorded-pin import is local
and does not stage. After that preflight, each sibling HEAD is imported from
the sibling repository directly into that nested checkout's object database
(`refs/prefetch/workspace/<sha>`, empty refmap, no fetch head, no remote), the
superproject index is staged with `update-index --cacheinfo 160000`, then the
path is checked out with `git submodule update --checkout --no-fetch`.
`--no-fetch` blocks falling back to the nested origin. An `update = none`
gitlink is overridden for that one invocation. The index stays staged.
Commit it yourself with `commit --staged` after review.

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

Five gitlink edges are recorded: node to genesis, dapp to genesis, dapp to contracts, sdk to genesis, and wallet to genesis. Contracts records `lib/forge-std`, and the DApp contracts gitlink records it again. `psy-contracts` and `psy-dapp` themselves are sibling repositories of the workspace, not gitlinks of `psy-node`. Recursive checkout follows those nested links. It does not move a gitlink to the sibling repository `HEAD`.

Initialize each checkout's recorded submodules recursively:

```bash
set -euo pipefail
for name in "${repos[@]}"; do
  git -C "$DESTINATION_ROOT/$name" submodule update --init --recursive
done
```

Do not use `--remote`. The `psy-contracts` and `psy-dapp` checkouts are the workspace sibling repositories at `$DESTINATION_ROOT/psy-contracts` and `$DESTINATION_ROOT/psy-dapp`, not nested checkouts of `psy-node`.

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

Local mode computes relative `file:` paths from each consumer manifest to the
sibling SDK package. Wallet uses `file:../psy-sdk/psy-ts-sdk/packages/psy-sdk`;
DApp apps use `file:../../../psy-sdk/psy-ts-sdk/packages/psy-sdk`, and account
also uses the adjacent `evm-wallet` package. These are local-mode values, not
the published defaults. `apps/site` and `apps/wallet` have no SDK dependency.

Use `workspace.ts deps use-local` above instead of manually updating
only a subset of locks. `--apply` updates all three Cargo locks and all four
active npm locks without installing `node_modules`. `--install` requires `--apply`
and additionally activates the two consumer roots with lifecycle scripts disabled.

Commit those manifest and lockfile edits in the owning worktree before Section 7. `make gen-deploy-json` reads the compiler `HEAD` while it writes `.genesis_contracts.compiler-artifact.json`, so an uncommitted compiler edit would not be the recorded revision (`<workspace>/psy-compiler/Makefile:270-309`). Do not run `make gen-deploy-json` or `make generate-genesis-data` from this tutorial. Absence of root `genesis.json` is not permission to generate it.

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

`dev/locSetupV4.ts:2338` tests whether `.npmrc` contains `lockfile=true`. `dev/locSetupV4.ts:2358` then chooses `--frozen-lockfile` or `--no-frozen-lockfile`. Lines `3403` and `3427` run `pnpm approve-builds`. Do not use that path. `psy-wallet/pnpm-workspace.yaml:1-3` does not authorize a registry SDK version in place of the `file:` dependency. Forge uses the Section 4 `lib/forge-std` checkout. `foundry.toml:4-5` sets its lib and test dirs. Do not run `forge install`.

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
