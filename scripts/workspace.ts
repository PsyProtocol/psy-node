#!/usr/bin/env bun
import { existsSync, mkdirSync, realpathSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { createWorkspace, WORKSPACE_REPOS } from "./workspace-create";
import { assertNoLocalDependencies, type CargoGuardContext } from "./workspace-dependencies";
import {
  assertPublishedDependencies as assertDependenciesPublished,
  guardSquashPins,
  inconsistent,
  inspectRelease,
  loadValidatedPack,
  packPackages,
  pinsFromManifest,
  preparePackages,
  printReport,
  publishPackages,
  redact,
  registryPackage,
  runCommand,
  SDK_PACKAGES,
  switchConsumers,
  switchLocal,
  switchNodeRevision,
  type PinSnapshot,
} from "./workspace-operations";

const names: readonly string[] = WORKSPACE_REPOS;
const help = `Usage: bun psy-node/scripts/workspace.ts [command] [options]

Commands (default: status; no implicit mutations):
  status [--source DIR]                 Show branches, heads and dirty paths.
  create --source DIR --destination DIR --branch TOPIC [--base mainnet-beta]
  gitlinks sync [--source DIR] [--base mainnet-beta]
  commit --source DIR --repo NAME --message TEXT [--staged | -- PATH...]
  push --source DIR [--repo NAME] [--base mainnet-beta] [--remote origin]
  prepare-merge --source DIR --target DIR --branch TOPIC --integration NEW_DIR
        [--base mainnet-beta] [--remote origin] [--message TEXT] [--push]

  deps show [--source DIR]
  deps check --source DIR
  deps use-local --source DIR [--apply] [--install]
  deps use-node-commit --source DIR --rev FULL_SHA [--allow-history-switch] [--apply]
                [--remote origin] [--base mainnet-beta]
  deps use-npm-version --source DIR --version VERSION [--apply] [--install]

  packages set-version --source DIR --version VERSION [--apply]
  packages pack --source DIR --out DIR --version VERSION
  packages publish --source DIR --out DIR --version VERSION --tag TAG

DIR is a workspace containing all eight sibling psy-* repositories.
Status defaults to the workspace containing this script. All mutations require
explicit --source except gitlinks sync, which defaults like status and only stages.
gitlinks sync requires every sibling on the same non-base topic branch and clean except
for gitlinks it will stage. Every initialized cohort checkout, including nested
checkouts inside a moving pin, must already equal its recorded gitlink before
any index write. gitlinks sync fast-forwards a recorded cohort pin to sibling HEAD only
when that pin is an ancestor, imports the commit from the sibling, checks that
path out, then materializes child gitlinks that commit records when the nested
checkout already has them. It never discards uncommitted nested changes and
never uses a recursive overwrite. A moving pin whose recorded child gitlink
differs from the initialized nested checkout fails until that child is synced.
External gitlinks (forge-std) are left unchanged. A direct or nested target pin
that would leave an external checkout at a different SHA fails before staging.
Commit requires a topic branch: named paths require an empty index and are
staged literally; --staged commits only the existing index.
Push publishes clean topic branches only, never the base branch and never force.
prepare-merge prepares dependency-ordered squash commits on retained integration branches.
It never moves local base branches or changes target working files, even if dirty.
A cohort pin that still names the child topic HEAD is rewritten to that child's
integration hash even when the pin equals the merge ancestor, because the squash
SHA differs from the topic tip. Other unchanged historical pins stay.
Only prepare-merge --push publishes the validated integration commits to the remote base.
Before any integration directory, prepare-merge checks compiler/sdk/services Cargo
psy-node pins from the source tip and the merge ancestor, and push and prepare-merge
both reject local node or SDK dependencies in the committed source manifests
and active locks. A pin this topic introduces must already be on the frozen
fetched node remote base. A pin kept from the ancestor is reported, not
rewritten, unless it names a node commit this squash removes. Repos with no
Cargo.toml contribute no pins. No Cargo edits. Conflicts stop and retain
worktrees for inspection; no automatic cleanup/rollback. For these Git commands,
remote reads and fetches occur only on explicit push and prepare-merge. Create may clone a missing sibling from its
documented origin and initialize recorded submodules, but never fetches to
refresh a present local base. gitlinks sync uses local sibling objects only. No installs
or services.

deps and packages never build, bump a version implicitly, commit, stage, push,
or reset. deps show may default to this workspace; every other deps or
packages command requires --source. deps use-local, deps use-node-commit, and
deps use-npm-version are separate: nothing rewrites Cargo pins and npm versions together.
use-local previews sibling paths. --apply resolves Cargo and all active npm locks
without installing node_modules. --install requires --apply and is accepted
only by deps use-local and deps use-npm-version; it activates wallet and dapp roots with scripts
disabled and a forced refresh. deps check fails when the inspected cohort is
inconsistent. use-node-commit preview and apply both read the remote base with
ls-remote and fetch that tip before printing a plan. use-npm-version preview and
apply both query the npm registry for the named version before printing a plan.
use-node-commit converts local paths or Git pins to one explicit
published revision and validates Cargo metadata --locked. use-npm-version sets the
wallet and dapp SDK and EVM dependencies to one published version and updates
their active locks.
Both require clean owned files on the same eight-repository topic; unrelated
dirt is allowed. packages set-version sets four explicit SDK versions. pack
validates existing output and real tarballs; publish uploads those tarballs
only.

Examples:
  bun psy-node/scripts/workspace.ts status
  bun psy-node/scripts/workspace.ts create --source ../mainnet-beta --destination ../feature --branch feature/demo
  bun psy-node/scripts/workspace.ts gitlinks sync --source ../feature
  bun psy-node/scripts/workspace.ts commit --source ../feature --repo psy-sdk --message 'Fix SDK' -- psy-ts-sdk/src/client.ts
  bun psy-node/scripts/workspace.ts commit --source ../feature --repo psy-sdk --message 'Fix SDK' --staged
  bun psy-node/scripts/workspace.ts push --source ../feature
  bun psy-node/scripts/workspace.ts prepare-merge --source ../feature --target ../mainnet-beta --branch feature/demo --integration ../integration-demo
  # User-executed publication (choose a fresh integration directory):
  bun psy-node/scripts/workspace.ts prepare-merge --source ../feature --target ../mainnet-beta --branch feature/demo --integration ../integration-publish --push
  bun psy-node/scripts/workspace.ts deps show
  bun psy-node/scripts/workspace.ts deps use-local --source ../feature
  bun psy-node/scripts/workspace.ts deps use-local --source ../feature --apply
  bun psy-node/scripts/workspace.ts deps use-local --source ../feature --apply --install
  bun psy-node/scripts/workspace.ts deps use-node-commit --source ../feature --rev FULL_SHA --apply
  bun psy-node/scripts/workspace.ts deps use-npm-version --source ../feature --version 2.0.8 --apply --install
  bun psy-node/scripts/workspace.ts packages set-version --source ../feature --version 2.0.8 --apply
  bun psy-node/scripts/workspace.ts packages pack --source ../feature --out ../packs --version 2.0.8
  bun psy-node/scripts/workspace.ts packages publish --source ../feature --out ../packs --version 2.0.8 --tag latest
`;

type Options = Map<string, string>;
const gitEnvironment: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete gitEnvironment[key];
function fail(message: string): never {
  throw new Error(redact(message));
}
function git(repo: string, args: string[], allowed = [0]): string {
  const result = Bun.spawnSync(["git", "-C", repo, ...args], { stdout: "pipe", stderr: "pipe", env: gitEnvironment });
  if (!allowed.includes(result.exitCode)) fail(`${repo}: git ${args[0]} failed (${result.exitCode}): ${result.stderr.toString().trim()}`);
  return result.stdout.toString().trimEnd();
}
function ancestor(repo: string, older: string, newer: string): boolean {
  const result = Bun.spawnSync(["git", "-C", repo, "merge-base", "--is-ancestor", older, newer], { stdout: "pipe", stderr: "pipe", env: gitEnvironment });
  const stderr = result.stderr.toString().trim();
  if (stderr || result.exitCode > 1) fail(`${repo}: cannot compare ancestry: ${stderr}`);
  return result.exitCode === 0;
}
function required(options: Options, name: string): string { return options.get(name) || fail(`--${name} is required`); }
function branch(repo: string): string { return git(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"], [0, 1]); }
function head(repo: string, ref = "HEAD"): string { return git(repo, ["rev-parse", "--verify", `${ref}^{commit}`]); }
function dirty(repo: string): string { return git(repo, ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"]); }
function clean(repo: string): void { const changes = dirty(repo); if (changes) fail(`${repo}: dirty worktree; commit explicitly first:\n${changes}`); }
function repository(root: string, name: string): string {
  const path = join(root, name);
  if (realpathSync(git(path, ["rev-parse", "--show-toplevel"])) !== realpathSync(path)) fail(`${path}: not a repository root`);
  return path;
}
function validateBranch(repo: string, name: string): void {
  if (name.startsWith("-")) fail("Branch cannot start with '-'");
  git(repo, ["check-ref-format", `refs/heads/${name}`]);
}
function topic(repo: string, base: string): string {
  const current = branch(repo);
  if (!current || current === base || ["mainnet-beta", "main", "master"].includes(current) || current.startsWith("workspace-integration/")) fail(`${repo}: expected a checked-out topic branch, not ${current || "detached HEAD"}`);
  return current;
}
function selected(options: Options): readonly string[] {
  const name = options.get("repo");
  if (name && !names.includes(name)) fail(`Unknown repository: ${name}`);
  return name ? [name] : names;
}
function remoteTip(repo: string, remote: string, ref: string): string {
  const lines = git(repo, ["ls-remote", "--refs", remote, `refs/heads/${ref}`]);
  return lines ? lines.split(/\s+/)[0] : "";
}
function fetchTip(repo: string, remote: string, ref: string, expected: string): void {
  const prefetch = `refs/prefetch/workspace/${expected}`;
  git(repo, ["fetch", "--refmap=", "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no", remote, `${expected}:${prefetch}`]);
  if (head(repo, prefetch) !== expected || remoteTip(repo, remote, ref) !== expected) fail(`${repo}: remote ${ref} changed during preflight; rerun`);
}
function remoteName(repo: string, name: string): void {
  if (name.startsWith("-")) fail("Remote name cannot start with '-'");
  if (!git(repo, ["remote"]).split("\n").includes(name)) fail(`${repo}: unknown remote name ${name}`);
  const fetchUrls = git(repo, ["remote", "get-url", "--all", name]).split("\n");
  const pushUrls = git(repo, ["remote", "get-url", "--push", "--all", name]).split("\n");
  if (fetchUrls.length !== 1 || pushUrls.length !== 1 || fetchUrls[0] !== pushUrls[0]) fail(`${repo}: require one identical fetch/push URL for ancestry validation`);
}
function commit(root: string, options: Options, paths: string[]): void {
  const name = required(options, "repo");
  selected(options);
  const repo = repository(root, name);
  topic(repo, options.get("base") || "mainnet-beta");
  const message = required(options, "message");
  if (options.has("staged") === (paths.length > 0)) fail("Choose exactly one of --staged or explicit paths after --");
  if (paths.length) {
    if (git(repo, ["diff", "--cached", "--name-only"])) fail(`${repo}: index must be empty before staging explicit paths`);
    for (const path of paths) {
      const rel = relative(repo, resolve(repo, path));
      if (!rel || rel === ".." || rel.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(rel)) fail(`Specify individual paths inside ${name}, not its root: ${path}`);
    }
    git(repo, ["--literal-pathspecs", "add", "--", ...paths]);
  }
  if (!git(repo, ["diff", "--cached", "--name-only"])) fail(`${repo}: no staged changes`);
  git(repo, ["commit", "-m", message]);
  console.log(`${name}: committed ${head(repo)}`);
}
function push(root: string, options: Options): void {
  const base = options.get("base") || "mainnet-beta";
  const remote = options.get("remote") || "origin";
  const plans = ordered(selected(options).map(name => {
    const repo = repository(root, name);
    const ref = topic(repo, base);
    clean(repo);
    remoteName(repo, remote);
    const tip = head(repo);
    return { name, repo, ref, tip, expected: "", links: links(repo, tip), baseLinks: [] as Link[] };
  }));
  for (const plan of plans) assertPublishedDependencies(plan.repo, plan.name, plan.tip);
  for (const plan of plans) plan.expected = remoteTip(plan.repo, remote, plan.ref);
  for (const plan of plans) {
    if (!plan.expected) continue;
    fetchTip(plan.repo, remote, plan.ref, plan.expected);
    if (!ancestor(plan.repo, plan.expected, plan.tip)) fail(`${plan.repo}: topic push would not fast-forward`);
  }
  for (const plan of plans) {
    clean(plan.repo);
    if (head(plan.repo) !== plan.tip || branch(plan.repo) !== plan.ref || remoteTip(plan.repo, remote, plan.ref) !== plan.expected) fail(`${plan.repo}: state changed since preflight`);
  }
  for (const plan of plans) {
    if (remoteTip(plan.repo, remote, plan.ref) !== plan.expected) fail(`${plan.repo}: remote topic changed; publication stopped (earlier repositories may be published)`);
    git(plan.repo, ["push", "--no-follow-tags", "--recurse-submodules=no", remote, `${plan.tip}:refs/heads/${plan.ref}`]);
    console.log(`${basename(plan.repo)}: pushed ${plan.ref} ${plan.tip}`);
  }
}

type SyncMove = { repo: string; name: string; path: string; from: string; to: string; child: string };

function indexGitlink(repo: string, gitlinkPath: string): string {
  const line = git(repo, ["ls-files", "-s", "--", gitlinkPath]).split("\n").find(entry => entry.startsWith("160000 "));
  return line ? line.split(" ")[1] : "";
}

function superprojectDirt(repo: string, moving: Record<string, true>): string {
  return dirty(repo).split("\n").filter(Boolean).filter(line => {
    if (line.startsWith("?? ")) return true;
    return !moving[line.slice(3)];
  }).join("\n");
}

function nestedCheckout(repo: string, gitlinkPath: string): string {
  const nested = join(repo, gitlinkPath);
  if (!existsSync(join(nested, ".git"))) fail(`${repo}/${gitlinkPath}: nested checkout is missing; initialize recorded gitlinks before gitlinks sync`);
  return nested;
}

function importCommit(dest: string, source: string, sha: string): void {
  const prefetch = `refs/prefetch/workspace/${sha}`;
  if (Bun.spawnSync(["git", "-C", dest, "cat-file", "-e", `${sha}^{commit}`], { stdout: "pipe", stderr: "pipe", env: gitEnvironment }).exitCode !== 0) {
    git(dest, ["fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "--recurse-submodules=no", source, `${sha}:${prefetch}`]);
  }
  if (head(dest, sha) !== sha) fail(`${dest}: local import of ${sha} from ${source} failed`);
}

function submoduleCheckoutOverrides(repo: string, gitlinkPath: string): string[] {
  const overrides: string[] = [];
  const config = git(repo, ["config", "--file", ".gitmodules", "--get-regexp", "^submodule\\..*\\.path$"], [0, 1]);
  for (const line of config.split("\n").filter(Boolean)) {
    const split = line.indexOf(" ");
    if (line.slice(split + 1) !== gitlinkPath) continue;
    const key = line.slice(0, split).replace(/^submodule\./, "").replace(/\.path$/, "");
    const update = git(repo, ["config", "--file", ".gitmodules", "--get", `submodule.${key}.update`], [0, 1]);
    if (update === "none") overrides.push("-c", `submodule.${key}.update=checkout`);
  }
  return overrides;
}
const dependencyPaths = /(?:^|\/)(?:Cargo\.toml|Cargo\.lock|package\.json|pnpm-lock\.yaml|bun\.lock)$/;

function packageNames(repo: string, rev: string): string[] {
  const names: string[] = [];
  for (const path of git(repo, ["ls-tree", "-r", "-z", "--name-only", rev]).split("\0").filter(path => /(?:^|\/)Cargo\.toml$/.test(path))) {
    const parsed = Bun.TOML.parse(git(repo, ["show", `${rev}:${path}`]));
    const section = parsed && typeof parsed === "object" && "package" in parsed ? parsed.package : undefined;
    const name = section && typeof section === "object" && "name" in section ? section.name : undefined;
    if (typeof name === "string") names.push(name);
  }
  return names;
}

function assertPublishedDependencies(repo: string, name: string, rev: string): void {
  const root = join(repo, "..");
  const nodeRev = names.includes(name) && existsSync(join(root, "psy-node/.git")) ? head(join(root, "psy-node")) : "";
  const cargo: CargoGuardContext | undefined = nodeRev && ["psy-compiler", "psy-sdk", "psy-services"].includes(name) ? {
    nodePackages: packageNames(join(root, "psy-node"), nodeRev),
    consumerPackages: packageNames(repo, rev),
  } : undefined;
  for (const path of git(repo, ["ls-tree", "-r", "-z", "--name-only", rev]).split("\0").filter(path => dependencyPaths.test(path))) assertNoLocalDependencies(name, path, git(repo, ["show", `${rev}:${path}`]), cargo);
}

function cohortChildren(checkout: string, rev: string): Link[] {
  return links(checkout, rev).filter(link => link.child);
}

function sync(root: string, options: Options): void {
  const base = options.get("base") || "mainnet-beta";
  const repos = names.map(name => ({ name, path: repository(root, name) }));
  const topicBranch = topic(repos[0].path, base);
  for (const repo of repos) {
    if (topic(repo.path, base) !== topicBranch) fail(`${repo.path}: cohort is not all on ${topicBranch}`);
  }
  const heads: Record<string, string> = {};
  for (const repo of repos) heads[repo.name] = head(repo.path);
  const moves: SyncMove[] = [];
  for (const repo of repos) {
    for (const link of links(repo.path, "HEAD")) {
      if (!link.child) continue;
      const sibling = heads[link.child];
      const siblingRepo = join(root, link.child);
      if (!sibling) fail(`${repo.name}/${link.path}: cohort child ${link.child} is not in this workspace`);
      const nested = nestedCheckout(repo.path, link.path);
      if (head(nested) !== link.sha) fail(`${repo.name}/${link.path}: initialized nested HEAD ${head(nested)} differs from recorded gitlink ${link.sha}; refusing before any index write`);
      if (link.sha === sibling) continue;
      // Parent gitlink SHAs are not parent objects. Compare in the child DB.
      importCommit(siblingRepo, nested, link.sha);
      if (!ancestor(siblingRepo, link.sha, sibling)) fail(`${repo.name}/${link.path}: pin ${link.sha} is not an ancestor of sibling HEAD ${sibling}; refusing backward or divergent gitlink`);
      moves.push({ repo: repo.path, name: repo.name, path: link.path, from: link.sha, to: sibling, child: link.child });
    }
  }
  for (const repo of repos) {
    const moving: Record<string, true> = {};
    for (const move of moves) if (move.repo === repo.path) moving[move.path] = true;
    const extra = superprojectDirt(repo.path, moving);
    if (extra) fail(`${repo.path}: dirty worktree beyond gitlinks sync will stage; commit explicitly first:\n${extra}`);
    for (const move of moves) {
      if (move.repo !== repo.path) continue;
      const nested = nestedCheckout(repo.path, move.path);
      const nestedDirty = dirty(nested);
      if (nestedDirty) fail(`${nested}: dirty nested checkout; commit explicitly first (no discard):\n${nestedDirty}`);
      for (const child of cohortChildren(nested, "HEAD")) {
        const checkout = nestedCheckout(nested, child.path);
        if (head(checkout) !== child.sha) fail(`${move.name}/${move.path}/${child.path}: initialized nested HEAD ${head(checkout)} differs from recorded gitlink ${child.sha}; refusing before any index write`);
        const childDirty = dirty(checkout);
        if (childDirty) fail(`${checkout}: dirty nested checkout; commit explicitly first (no discard):\n${childDirty}`);
      }
    }
  }
  for (const move of moves) {
    const recorded = links(move.repo, "HEAD").find(link => link.path === move.path);
    if (!recorded || recorded.sha !== move.from || recorded.child !== move.child || head(join(root, move.child)) !== move.to || branch(move.repo) !== topicBranch) fail(`${move.name}: state changed since preflight; no gitlinks staged`);
  }
  if (!moves.length) {
    console.log("gitlinks sync: cohort gitlinks already match sibling HEADs");
    return;
  }
  const staged: string[] = [];
  try {
    for (const move of moves) importCommit(nestedCheckout(move.repo, move.path), join(root, move.child), move.to);
    const childMoves: { nested: string; path: string; sha: string }[] = [];
    for (const move of moves) {
      const nested = nestedCheckout(move.repo, move.path);
      const changedExternal = links(nested, move.to).find(link => !link.child && (!existsSync(join(nested, link.path, ".git")) || head(join(nested, link.path)) !== link.sha));
      if (changedExternal) fail(`${move.name}/${move.path}: external gitlink ${changedExternal.path} changes to ${changedExternal.sha} while its checkout stays unchanged; sync children explicitly or leave this pin`);
      for (const child of cohortChildren(nested, move.to)) {
        const checkout = nestedCheckout(nested, child.path);
        if (head(checkout) === child.sha) continue;
        importCommit(checkout, join(root, child.child), child.sha);
        const changedExternal = links(checkout, child.sha).find(link => !link.child && (!existsSync(join(checkout, link.path, ".git")) || head(join(checkout, link.path)) !== link.sha));
        if (changedExternal) fail(`${move.name}/${move.path}/${child.path}: external gitlink ${changedExternal.path} changes to ${changedExternal.sha} while its checkout stays unchanged; sync children explicitly or leave this pin`);
        const grandchild = cohortChildren(checkout, child.sha).find(link => !existsSync(join(checkout, link.path, ".git")) || head(join(checkout, link.path)) !== link.sha);
        if (grandchild) fail(`${move.name}/${move.path}/${child.path}: recorded child gitlink ${grandchild.path} ${grandchild.sha} differs from its initialized checkout; sync that child explicitly before ${move.path}`);
        childMoves.push({ nested, path: child.path, sha: child.sha });
      }
    }
    for (const move of moves) {
      const nested = nestedCheckout(move.repo, move.path);
      git(move.repo, ["update-index", "--cacheinfo", "160000", move.to, move.path]);
      staged.push(`${move.name}/${move.path}`);
      if (indexGitlink(move.repo, move.path) !== move.to) fail(`${move.name}/${move.path}: index was not updated`);
      git(move.repo, [...submoduleCheckoutOverrides(move.repo, move.path), "submodule", "update", "--checkout", "--no-fetch", "--", move.path]);
      if (head(nested) !== move.to) fail(`${move.name}/${move.path}: nested checkout is not ${move.to}`);
      if (indexGitlink(move.repo, move.path) !== move.to) fail(`${move.name}/${move.path}: checkout changed the staged gitlink`);
      console.log(`${move.name}/${move.path}: staged ${move.from} -> ${move.to} (not committed)`);
    }
    for (const child of childMoves) {
      const checkout = nestedCheckout(child.nested, child.path);
      git(child.nested, [...submoduleCheckoutOverrides(child.nested, child.path), "submodule", "update", "--checkout", "--no-fetch", "--", child.path]);
      if (head(checkout) !== child.sha || indexGitlink(child.nested, child.path) !== child.sha) fail(`${child.nested}/${child.path}: nested child was not materialized at ${child.sha}`);
      const childDirty = dirty(checkout);
      if (childDirty) fail(`${checkout}: materializing ${child.sha} left uncommitted nested changes:\n${childDirty}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    fail(staged.length ? `${message}\npartial sync retained (no reset): ${staged.join(", ")}` : message);
  }

}

type Link = { path: string; sha: string; child: string };
type Plan = { name: string; source: string; target: string; tip: string; base: string; remote: string; links: Link[]; baseLinks: Link[]; worktree: string; integrationBranch: string; merged: string };

function links(repo: string, ref: string): Link[] {
  const entries = git(repo, ["ls-tree", "-r", "-z", ref]).split("\0").filter(Boolean);
  const modules = new Map<string, string>();
  if (entries.some(entry => entry.endsWith("\t.gitmodules"))) {
    const config = git(repo, ["config", "--blob", `${ref}:.gitmodules`, "--get-regexp", "^submodule\\..*\\.path$"], [0, 1]);
    for (const line of config.split("\n").filter(Boolean)) {
      const split = line.indexOf(" ");
      const key = line.slice(0, split);
      const path = line.slice(split + 1);
      const url = git(repo, ["config", "--blob", `${ref}:.gitmodules`, "--get", key.replace(/\.path$/, ".url")]);
      const child = url.replace(/\/$/, "").split(/[/:]/).pop()!.replace(/\.git$/, "");
      if (names.includes(child)) modules.set(path, child);
    }
  }
  return entries.filter(entry => entry.startsWith("160000 ")).map(entry => {
    const [metadata, path] = entry.split("\t");
    return { path, sha: metadata.split(" ")[2], child: modules.get(path) || "" };
  });
}

function ordered<T extends { name: string; links: Link[]; baseLinks: Link[] }>(plans: T[]): T[] {
  const pending = new Map(plans.map(plan => [plan.name, plan]));
  const complete = new Set<string>();
  const included = new Set(plans.map(plan => plan.name));
  const output: T[] = [];
  while (pending.size) {
    const next = [...pending.values()].find(plan => [...plan.links, ...plan.baseLinks].every(link => !included.has(link.child) || complete.has(link.child)));
    if (!next) fail(`Gitlink dependency cycle: ${[...pending.keys()].join(", ")}`);
    pending.delete(next.name);
    complete.add(next.name);
    output.push(next);
  }
  return output;
}

function merge(root: string, options: Options): void {
  const targetRoot = realpathSync(resolve(required(options, "target")));
  const integration = resolve(required(options, "integration"));
  const topicBranch = required(options, "branch");
  const baseBranch = options.get("base") || "mainnet-beta";
  const remote = options.get("remote") || "origin";
  const integrationBranch = `workspace-integration/${basename(integration)}`;
  if (existsSync(integration)) fail(`Integration directory already exists: ${integration}`);
  const parent = realpathSync(resolve(integration, ".."));
  for (const workspace of [realpathSync(root), targetRoot]) {
    if (parent === workspace || parent.startsWith(`${workspace}/`)) fail("Integration directory must be outside source and target workspaces");
  }
  const plans: Plan[] = names.map(name => {
    const source = repository(root, name);
    const target = repository(targetRoot, name);
    if (topic(source, baseBranch) !== topicBranch) fail(`${source}: not on requested topic ${topicBranch}`);
    clean(source);
    validateBranch(source, baseBranch);
    validateBranch(target, integrationBranch);
    if (git(target, ["for-each-ref", "--format=%(refname)", `refs/heads/${integrationBranch}`]).split("\n").includes(`refs/heads/${integrationBranch}`)) fail(`${target}: integration branch already exists`);
    remoteName(target, remote);
    git(target, ["var", "GIT_AUTHOR_IDENT"]);
    git(target, ["var", "GIT_COMMITTER_IDENT"]);
    const tip = head(source);
    const base = head(target, `refs/heads/${baseBranch}`);
    return { name, source, target, tip, base, remote: "", links: links(source, tip), baseLinks: [] as Link[], worktree: join(integration, name), integrationBranch, merged: "" };
  });
  for (const plan of plans) assertPublishedDependencies(plan.source, plan.name, plan.tip);
  for (const plan of plans) {
    plan.remote = remoteTip(plan.target, remote, baseBranch);
    if (!plan.remote) fail(`${plan.target}: remote base branch is missing`);
  }
  const byName = new Map(plans.map(plan => [plan.name, plan]));
  for (const plan of plans) {
    fetchTip(plan.target, remote, baseBranch, plan.remote);
    if (!ancestor(plan.target, plan.remote, plan.base)) fail(`${plan.name}: local base lacks current remote commits; reconcile explicitly before merge`);
    // Local transport imports objects only: no topic/base/tracking refs are moved.
    git(plan.target, ["fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "--recurse-submodules=no", plan.source, `${plan.tip}:refs/prefetch/workspace/${plan.tip}`]);
    const mergeBase = git(plan.target, ["merge-base", plan.base, plan.tip]);
    // Gitlink edits are classified against the merge ancestor of the topic and
    // the frozen target base, not the current base tree: a pin the topic kept
    // while the target advanced is not a topic change.
    plan.baseLinks = links(plan.target, mergeBase);
  }
  const order = ordered(plans);
  // Validate every intended gitlink transition before creating worktrees.
  for (const plan of plans) {
    for (const link of plan.links) {
      const previous = plan.baseLinks.find(entry => entry.path === link.path);
      if (!link.child || (previous?.sha === link.sha && previous.child === link.child)) continue;
      const child = byName.get(link.child)!;
      if (link.sha !== child.tip) fail(`${plan.name}/${link.path}: changed gitlink must name sibling topic HEAD; historical pins are preserved only unchanged`);
    }
  }
  for (const plan of plans) {
    for (const link of plan.links) {
      const previous = plan.baseLinks.find(entry => entry.path === link.path);
      if (!link.child || (previous?.sha === link.sha && previous.child === link.child)) continue;
      const child = byName.get(link.child)!;
      // child.target holds both compared commits: its own frozen base ref and
      // the child tip imported above; child.source may lack the target base.
      if (!ancestor(child.target, child.base, child.tip)) fail(`${plan.name}/${link.path}: changed child topic must descend from frozen child base`);
    }
  }
  const nodePlan = byName.get("psy-node")!;
  const cargoRepos = ["psy-compiler", "psy-sdk", "psy-services"] as const;
  const pinSnapshot = (plan: Plan, rev: string): PinSnapshot => {
    const spec = `${rev}:Cargo.toml`;
    const listed = Bun.spawnSync(["git", "-C", plan.target, "ls-tree", "-z", rev, "--", "Cargo.toml"], { stdout: "pipe", stderr: "pipe", env: gitEnvironment });
    if (listed.exitCode !== 0) fail(`${plan.name}: cannot list ${spec}: ${listed.stderr.toString().trim()}`);
    if (!listed.stdout.toString()) return { repo: plan.name, pins: [] };
    const present = Bun.spawnSync(["git", "-C", plan.target, "cat-file", "-e", spec], { stdout: "pipe", stderr: "pipe", env: gitEnvironment });
    if (present.exitCode !== 0) fail(`${plan.name}: ${spec} is listed but unreadable: ${present.stderr.toString().trim()}`);
    const text = git(plan.target, ["show", spec]);
    return { repo: plan.name, pins: pinsFromManifest(text, `${plan.name}@${spec}`).map(pin => ({ crate: `${pin.table}.${pin.key}`, rev: pin.rev })) };
  };
  const guarded = guardSquashPins({
    source: cargoRepos.map(name => pinSnapshot(byName.get(name)!, byName.get(name)!.tip)),
    base: cargoRepos.map(name => {
      const plan = byName.get(name)!;
      return pinSnapshot(plan, git(plan.target, ["merge-base", plan.base, plan.tip]));
    }),
    nodeOriginBase: nodePlan.remote,
    topicNodeCommits: git(nodePlan.target, ["rev-list", nodePlan.tip, `^${nodePlan.remote}`]).split("\n").filter(Boolean),
    isOnNodeOrigin: rev => rev === nodePlan.remote || (Bun.spawnSync(["git", "-C", nodePlan.target, "cat-file", "-e", `${rev}^{commit}`], { stdout: "pipe", stderr: "pipe", env: gitEnvironment }).exitCode === 0 && ancestor(nodePlan.target, rev, nodePlan.remote)),
  });
  for (const pin of guarded.unchanged) console.log(`${pin.repo}: keeping historical ${pin.crate} pin ${pin.rev}`);
  mkdirSync(integration);
  console.log(`Integration retained at ${integration}; target working files and local ${baseBranch} refs remain unchanged.`);
  for (const plan of order) {
    git(plan.target, ["worktree", "add", "-b", integrationBranch, plan.worktree, plan.base]);
    const mapped = new Map<string, string>();
    for (const link of plan.links) {
      if (!link.child) continue;
      const previous = plan.baseLinks.find(entry => entry.path === link.path);
      const child = byName.get(link.child)!;
      const changed = previous?.sha !== link.sha || previous.child !== link.child;
      // pin == child.tip still needs the integration SHA: squash is not the topic tip
      // even when the child tree is unchanged relative to the merge ancestor.
      if (changed || (link.sha === child.tip && child.merged !== child.tip)) {
        if (!child.merged) fail(`${plan.name}/${link.path}: child integration is not complete`);
        mapped.set(link.path, child.merged);
      }
    }
    const squash = Bun.spawnSync(["git", "-C", plan.worktree, "-c", "submodule.recurse=false", "merge", "--squash", "--no-commit", plan.tip], { stdout: "pipe", stderr: "pipe", env: gitEnvironment });
    const conflicts = git(plan.worktree, ["diff", "--name-only", "--diff-filter=U", "-z"]).split("\0").filter(Boolean);
    const unmerged = git(plan.worktree, ["ls-files", "--unmerged", "-z"]).split("\0").filter(Boolean);
    if (unmerged.some(entry => !entry.startsWith("160000 "))) fail(`${plan.name}: non-gitlink conflict retained at ${plan.worktree}`);
    if (conflicts.some(path => !mapped.has(path)) || (squash.exitCode !== 0 && !conflicts.length)) fail(`${plan.name}: squash stopped; inspect ${plan.worktree}\n${squash.stderr}`);
    for (const [path, sha] of mapped) git(plan.worktree, ["update-index", "--add", "--cacheinfo", "160000", sha, path]);
    if (git(plan.worktree, ["diff", "--name-only", "--diff-filter=U"])) fail(`${plan.name}: unresolved conflicts retained at ${plan.worktree}`);
    if (git(plan.worktree, ["diff", "--cached", "--name-only"])) git(plan.worktree, ["commit", "-m", options.get("message") || `Squash ${topicBranch} into ${baseBranch} (${plan.name})`]);
    plan.merged = head(plan.worktree);
    if (!ancestor(plan.target, plan.base, plan.merged)) fail(`${plan.name}: integration does not preserve local base ancestry`);
    console.log(`${plan.name}: ${plan.merged} (${integrationBranch})`);
  }
  for (const plan of plans) {
    clean(plan.source);
    if (head(plan.source) !== plan.tip || branch(plan.source) !== topicBranch || head(plan.target, `refs/heads/${baseBranch}`) !== plan.base || remoteTip(plan.target, remote, baseBranch) !== plan.remote) fail(`${plan.name}: source/base/remote changed; integration retained, nothing published`);
  }
  if (options.has("push")) {
    for (const plan of order) {
      if (remoteTip(plan.target, remote, baseBranch) !== plan.remote) fail(`${plan.name}: remote base changed; stopped (earlier repositories may be published)`);
      git(plan.target, ["push", "--no-follow-tags", "--recurse-submodules=no", remote, `${plan.merged}:refs/heads/${baseBranch}`]);
      console.log(`${plan.name}: published ${plan.merged} to ${baseBranch}`);
    }
  }
  console.log(`Local ${baseBranch} is unchanged. For each CLEAN target already on ${baseBranch}, explicitly fast-forward with:`);
  for (const plan of order) console.log(`git -C ${JSON.stringify(plan.target)} -c submodule.recurse=false merge --ff-only ${plan.merged}`);
}

type CommandSpec = { valued: readonly string[]; flags: readonly string[]; paths: boolean; sourceDefault: boolean; required: readonly string[] };
const commandGroups: Record<string, true> = { gitlinks: true, deps: true, packages: true };
const commandSpecs: Record<string, CommandSpec> = {
  status: { valued: ["source"], flags: [], paths: false, sourceDefault: true, required: [] },
  create: { valued: ["source", "destination", "branch", "base"], flags: [], paths: false, sourceDefault: false, required: ["source", "destination", "branch"] },
  "gitlinks sync": { valued: ["source", "base"], flags: [], paths: false, sourceDefault: true, required: [] },
  commit: { valued: ["source", "repo", "message", "base"], flags: ["staged"], paths: true, sourceDefault: false, required: ["source", "repo", "message"] },
  push: { valued: ["source", "repo", "base", "remote"], flags: [], paths: false, sourceDefault: false, required: ["source"] },
  "prepare-merge": { valued: ["source", "target", "branch", "integration", "base", "remote", "message"], flags: ["push"], paths: false, sourceDefault: false, required: ["source", "target", "branch", "integration"] },
  "deps show": { valued: ["source"], flags: [], paths: false, sourceDefault: true, required: [] },
  "deps check": { valued: ["source"], flags: [], paths: false, sourceDefault: false, required: ["source"] },
  "deps use-local": { valued: ["source"], flags: ["apply", "install"], paths: false, sourceDefault: false, required: ["source"] },
  "deps use-node-commit": { valued: ["source", "rev", "remote", "base"], flags: ["allow-history-switch", "apply"], paths: false, sourceDefault: false, required: ["source", "rev"] },
  "deps use-npm-version": { valued: ["source", "version"], flags: ["apply", "install"], paths: false, sourceDefault: false, required: ["source", "version"] },
  "packages set-version": { valued: ["source", "version"], flags: ["apply"], paths: false, sourceDefault: false, required: ["source", "version"] },
  "packages pack": { valued: ["source", "out", "version"], flags: [], paths: false, sourceDefault: false, required: ["source", "out", "version"] },
  "packages publish": { valued: ["source", "out", "version", "tag"], flags: [], paths: false, sourceDefault: false, required: ["source", "out", "version", "tag"] },
};

function parseInvocation(argv: string[]): { command: string; options: Options; paths: string[] } {
  const args = [...argv];
  let command: string;
  if (args[0] && !args[0].startsWith("--") && commandGroups[args[0]]) {
    const group = args.shift()!;
    const sub = args[0];
    if (!sub || sub.startsWith("--") || !commandSpecs[`${group} ${sub}`]) fail(`Unknown command: ${sub && !sub.startsWith("--") ? `${group} ${sub}` : group}`);
    command = `${group} ${args.shift()}`;
  } else if (!args[0] || args[0].startsWith("--")) command = "status";
  else {
    command = args.shift()!;
    if (!commandSpecs[command]) fail(`Unknown command: ${command}`);
  }
  const spec = commandSpecs[command];
  const allowed = [...spec.valued, ...spec.flags];
  const options: Options = new Map();
  let paths: string[] = [];
  while (args.length) {
    const arg = args.shift()!;
    if (arg === "--" && spec.paths) { paths = args.splice(0); break; }
    const key = arg.slice(2);
    if (!arg.startsWith("--") || !allowed.includes(key) || options.has(key)) fail(`Unexpected or duplicate option: ${arg}`);
    if (spec.flags.includes(key)) { options.set(key, "true"); continue; }
    const value = args.shift();
    if (!value || value.startsWith("--")) fail(`Missing value for ${arg}`);
    options.set(key, value);
  }
  return { command, options, paths };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args[0] === "help") { console.log(help); return; }
  const { command, options, paths } = parseInvocation(args);
  if ((command === "deps use-local" || command === "deps use-npm-version") && options.has("install") && !options.has("apply")) fail("--install requires --apply");
  for (const name of commandSpecs[command].required) required(options, name);
  const root = resolve(commandSpecs[command].sourceDefault ? options.get("source") || join(import.meta.dir, "../..") : required(options, "source"));
  if (command === "status") {
    for (const name of names) { const repo = repository(root, name); console.log(`${name}\t${branch(repo) || "(detached)"}\t${head(repo)}\n${dirty(repo) || "clean"}`); }
  } else if (command === "create") {
    await createWorkspace({ source: root, destination: resolve(required(options, "destination")), branch: required(options, "branch"), base: options.get("base") || "mainnet-beta" });
  } else if (command === "gitlinks sync") sync(root, options);
  else if (command === "commit") commit(root, options, paths);
  else if (command === "push") push(root, options);
  else if (command === "prepare-merge") merge(root, options);
  else if (command === "deps show" || command === "deps check") {
    const report = inspectRelease(root);
    printReport(report);
    if (command === "deps check" && inconsistent(report)) fail("actionable dependency inconsistency");
  } else if (command === "deps use-local") {
    for (const path of switchLocal(root, options.has("apply"), options.has("install"))) console.log(`${path}\tlocal sibling dependencies`);
  } else if (command === "deps use-node-commit") {
    const changed = switchNodeRevision(root, required(options, "rev"), options.has("apply"), options.has("allow-history-switch"), options.get("remote") || "origin", options.get("base") || "mainnet-beta");
    for (const item of changed) console.log(`${item.repo}\t${item.from.join(",")} -> ${item.to}\tadded ${item.added.length}\tremoved ${item.removed.length}`);
  } else if (command === "deps use-npm-version") {
    const version = required(options, "version");
    for (const item of await switchConsumers(root, version, options.has("apply"), registryPackage, runCommand, options.has("install"))) console.log(`${item.path}\t${Object.entries(item.before).map(([dep, value]) => `${dep}:${value}->${version}`).join(" ")}`);
  } else if (command === "packages set-version") {
    for (const item of preparePackages(root, required(options, "version"), options.has("apply"))) console.log(`${item.name}\t${item.from} -> ${item.to}`);
  } else if (command === "packages pack") {
    const packs = packPackages(root, resolve(required(options, "out")), required(options, "version"));
    for (const item of packs) console.log(`${item.name}\t${item.version}\t${item.integrity}\tpacked\t${item.path}`);
  } else if (command === "packages publish") {
    assertDependenciesPublished(root);
    const packs = SDK_PACKAGES.map(item => loadValidatedPack(resolve(required(options, "out")), item.name, required(options, "version")));
    for (const item of await publishPackages(packs, required(options, "tag"))) console.log(`${item.name}\t${item.state}\t${item.integrity}`);
  } else fail(`Unknown command: ${command}`);
}

main().catch(error => { console.error(`workspace: ${redact(error instanceof Error ? error.message : String(error))}`); process.exitCode = 1; });
