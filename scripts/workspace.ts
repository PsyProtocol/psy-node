#!/usr/bin/env bun
import { existsSync, mkdirSync, realpathSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { createWorkspace, WORKSPACE_REPOS } from "./workspace-create";

const names: readonly string[] = WORKSPACE_REPOS;
const help = `Usage: bun psy-node/scripts/workspace.ts [command] [options]

Commands (default: status; no implicit mutations):
  status [--source DIR]                 Show branches, heads and dirty paths.
  create --source DIR --destination DIR --branch TOPIC [--base mainnet-beta]
  commit --source DIR --repo NAME --message TEXT [--staged | -- PATH...]
  push --source DIR [--repo NAME] [--base mainnet-beta] [--remote origin]
  merge --source DIR --target DIR --branch TOPIC --integration NEW_DIR
        [--base mainnet-beta] [--remote origin] [--message TEXT] [--push]

DIR is a workspace containing all eight sibling psy-* repositories.
Status defaults to the workspace containing this script. All mutations require
explicit --source. Commit requires a topic branch: named paths require an empty
index and are staged literally; --staged commits only the existing index.
Push publishes clean topic branches only, never the base branch and never force.
Merge prepares dependency-ordered squash commits on retained integration branches.
It never moves local base branches or changes target working files, even if dirty.
Only merge --push publishes the validated integration commits to the remote base.
Conflicts stop and retain worktrees for inspection; no automatic cleanup/rollback.
Remote reads/fetches occur only on explicit push/merge. No installs or services.

Examples:
  bun psy-node/scripts/workspace.ts status
  bun psy-node/scripts/workspace.ts create --source ../mainnet-beta --destination ../feature --branch feature/demo
  bun psy-node/scripts/workspace.ts commit --source ../feature --repo psy-sdk --message 'Fix SDK' -- psy-ts-sdk/src/client.ts
  bun psy-node/scripts/workspace.ts commit --source ../feature --repo psy-sdk --message 'Fix SDK' --staged
  bun psy-node/scripts/workspace.ts push --source ../feature
  bun psy-node/scripts/workspace.ts merge --source ../feature --target ../mainnet-beta --branch feature/demo --integration ../integration-demo
  # User-executed publication (choose a fresh integration directory):
  bun psy-node/scripts/workspace.ts merge --source ../feature --target ../mainnet-beta --branch feature/demo --integration ../integration-publish --push
`;

type Options = Map<string, string>;
const gitEnvironment: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete gitEnvironment[key];
function fail(message: string): never {
  throw new Error(message.replace(/(https?:\/\/)[^\s/@]+(?::[^\s/@]*)?@/g, "$1[redacted]@"));
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
  git(repo, ["fetch", "--refmap=", "--no-tags", "--no-write-fetch-head", remote, `${expected}:${prefetch}`]);
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
    return { name, repo, ref, tip, expected: remoteTip(repo, remote, ref), links: links(repo, tip), baseLinks: [] as Link[] };
  }));
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
    const expected = remoteTip(target, remote, baseBranch);
    if (!expected) fail(`${target}: remote base branch is missing`);
    return { name, source, target, tip, base, remote: expected, links: links(source, tip), baseLinks: [] as Link[], worktree: join(integration, name), integrationBranch, merged: "" };
  });
  const byName = new Map(plans.map(plan => [plan.name, plan]));
  for (const plan of plans) {
    fetchTip(plan.target, remote, baseBranch, plan.remote);
    if (!ancestor(plan.target, plan.remote, plan.base)) fail(`${plan.name}: local base lacks current remote commits; reconcile explicitly before merge`);
    // Local transport imports objects only: no topic/base/tracking refs are moved.
    git(plan.target, ["fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", plan.source, `${plan.tip}:refs/prefetch/workspace/${plan.tip}`]);
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
  mkdirSync(integration);
  console.log(`Integration retained at ${integration}; target working files and local ${baseBranch} refs remain unchanged.`);
  for (const plan of order) {
    git(plan.target, ["worktree", "add", "-b", integrationBranch, plan.worktree, plan.base]);
    const mapped = new Map<string, string>();
    for (const link of plan.links) {
      const previous = plan.baseLinks.find(entry => entry.path === link.path);
      if (link.child && (previous?.sha !== link.sha || previous.child !== link.child)) {
        const merged = byName.get(link.child)!.merged;
        if (!merged) fail(`${plan.name}/${link.path}: child integration is not complete`);
        mapped.set(link.path, merged);
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

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args[0] === "help") { console.log(help); return; }
  const command = args[0] && !args[0].startsWith("--") ? args.shift()! : "status";
  const allowed: Record<string, string[]> = {
    status: ["source"], create: ["source", "destination", "branch", "base"],
    commit: ["source", "repo", "message", "staged", "base"],
    push: ["source", "repo", "base", "remote"],
    merge: ["source", "target", "branch", "integration", "base", "remote", "message", "push"],
  };
  if (!allowed[command]) fail(`Unknown command: ${command}`);
  const options: Options = new Map();
  let paths: string[] = [];
  while (args.length) {
    const arg = args.shift()!;
    if (arg === "--" && command === "commit") { paths = args.splice(0); break; }
    const key = arg.slice(2);
    if (!arg.startsWith("--") || !allowed[command].includes(key) || options.has(key)) fail(`Unexpected or duplicate option: ${arg}`);
    if (["staged", "push"].includes(key)) { options.set(key, "true"); continue; }
    const value = args.shift();
    if (!value || value.startsWith("--")) fail(`Missing value for ${arg}`);
    options.set(key, value);
  }
  const root = resolve(command === "status" ? options.get("source") || join(import.meta.dir, "../..") : required(options, "source"));
  if (command === "status") {
    for (const name of names) { const repo = repository(root, name); console.log(`${name}\t${branch(repo) || "(detached)"}\t${head(repo)}\n${dirty(repo) || "clean"}`); }
  } else if (command === "create") {
    await createWorkspace({ source: root, destination: resolve(required(options, "destination")), branch: required(options, "branch"), base: options.get("base") || "mainnet-beta" });
  } else if (command === "commit") commit(root, options, paths);
  else if (command === "push") push(root, options);
  else merge(root, options);
}

main().catch(error => { console.error(`workspace: ${error.message}`); process.exitCode = 1; });
