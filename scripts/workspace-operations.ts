// Dependency and package operations used by workspace.ts. Not a command
// entrypoint. Never builds, bumps implicitly, commits, or pushes.
// Installs require --apply --install; other applies resolve locks.
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, relative, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { WORKSPACE_REPOS } from "./workspace-create";
import { assertLocalCargoGraph, assertNoLocalDependencies, nodeCratePaths, nodeDependencies, parseBunLock, rewriteNodeDependencies } from "./workspace-dependencies";

const CARGO_REPOS = ["psy-compiler", "psy-sdk", "psy-services"] as const;
export const SDK_PACKAGES = [
  { dir: "packages/utils", name: "@psy-protocol/utils" },
  { dir: "packages/psy-sdk", name: "@psy-protocol/psy-sdk" },
  { dir: "packages/contract-sdk", name: "@psy-protocol/contract-sdk" },
  { dir: "packages/evm-wallet", name: "@psy-protocol/evm-wallet" },
] as const;
const CONSUMERS = [
  { repo: "psy-wallet", importer: ".", manifest: "package.json", packages: ["@psy-protocol/psy-sdk"] },
  { repo: "psy-dapp", importer: "apps/account", manifest: "apps/account/package.json", packages: ["@psy-protocol/psy-sdk", "@psy-protocol/evm-wallet"] },
  { repo: "psy-dapp", importer: "apps/bridge", manifest: "apps/bridge/package.json", packages: ["@psy-protocol/psy-sdk"] },
  { repo: "psy-dapp", importer: "apps/explorer", manifest: "apps/explorer/package.json", packages: ["@psy-protocol/psy-sdk"] },
  { repo: "psy-dapp", importer: "apps/ide", manifest: "apps/ide/package.json", packages: ["@psy-protocol/psy-sdk"] },
] as const;
const WORKSPACE_LINKS = [
  ["packages/contract-sdk/node_modules/@psy-protocol/psy-sdk", "packages/psy-sdk", "@psy-protocol/psy-sdk"],
  ["packages/contract-sdk/node_modules/@psy-protocol/utils", "packages/utils", "@psy-protocol/utils"],
  ["packages/evm-wallet/node_modules/@psy-protocol/psy-sdk", "packages/psy-sdk", "@psy-protocol/psy-sdk"],
] as const;
export const NPM_REGISTRY = "https://registry.npmjs.org/";
export const PNPM_LOCK_ONLY_ARGS = ["install", "--lockfile-only", "--ignore-scripts", "--ignore-pnpmfile", "--no-frozen-lockfile"] as const;
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const SHA = /^[0-9a-f]{40}$/;
const TWO_PASS = "Integrate node code first and publish that exact revision onto the base history, then create the dependency-release topic. Do not rewrite Cargo pins to the node squash result.";

type Json = Record<string, unknown>;
type DepMap = Record<string, string | { version?: string }>;
type Manifest = Json & {
  name?: string; version?: string; private?: boolean; scripts?: Record<string, string>; files?: unknown; main?: unknown; module?: unknown;
  types?: unknown; exports?: unknown; dependencies?: DepMap; devDependencies?: DepMap; peerDependencies?: DepMap; optionalDependencies?: DepMap;
  publishConfig?: { directory?: string; registry?: string }; packageManager?: string;
};
type ArchiveEntry = { name: string; type: string };
export type CargoPin = { table: string; key: string; url: string; rev: string; rest: Json };
export type PinSnapshot = { repo: string; pins: { crate: string; rev: string }[] };
export type RunResult = { code: number; out: string; err: string };
export type Runner = (command: string[], cwd?: string, env?: NodeJS.ProcessEnv) => RunResult;
export type RegistryPackage = { version: string; integrity: string; tarball: string; peerDependencies?: Record<string, string> };
export type RegistryLookup = (name: string, version: string) => Promise<RegistryPackage | null>;
export type Pack = { name: string; version: string; path: string; integrity: string; manifest: Manifest; entries: ArchiveEntry[] };
type MetadataPackage = { name?: string; version?: string; id?: string; source?: string | null; dependencies?: { name?: string; source?: string | null }[] };
type Metadata = { packages?: MetadataPackage[]; resolve?: { nodes?: { id?: string; deps?: { pkg?: string }[] }[] } };

const gitEnvironment: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]) delete gitEnvironment[key];

export function redact(message: string): string {
  return message
    .replace(/(https?:\/\/)[^\s/@]+(?::[^\s/@]*)?@/g, "$1[redacted]@")
    .replace(/([?&](?:access_token|token|auth|key|password)=)[^&\s]+/gi, "$1[redacted]")
    .replace(/(authorization:\s*)[^\r\n]*/gi, "$1[redacted]")
    .replace(/((?:_authToken|npm_token|npm_config__authToken)=)\S+/gi, "$1[redacted]");
}

export function fail(message: string): never {
  throw new Error(redact(message));
}

export function runCommand(command: string[], cwd?: string, env: NodeJS.ProcessEnv = process.env): RunResult {
  const result = Bun.spawnSync(command, { cwd, stdout: "pipe", stderr: "pipe", env });
  return { code: result.exitCode, out: result.stdout.toString(), err: result.stderr.toString() };
}

function git(repo: string, args: string[], allowed = [0]): string {
  const result = runCommand(["git", "-C", repo, ...args], undefined, gitEnvironment);
  if (!allowed.includes(result.code)) fail(`${repo}: git ${args[0]} failed (${result.code}): ${result.err.trim()}`);
  return result.out.trimEnd();
}

function isAncestor(repo: string, older: string, newer: string): boolean {
  const result = runCommand(["git", "-C", repo, "merge-base", "--is-ancestor", older, newer], undefined, gitEnvironment);
  if (result.err.trim() || result.code > 1) fail(`${repo}: cannot compare ancestry: ${result.err.trim()}`);
  return result.code === 0;
}

function repository(root: string, name: string): string {
  const path = join(root, name);
  if (!existsSync(path) || realpathSync(git(path, ["rev-parse", "--show-toplevel"])) !== realpathSync(path)) fail(`${path}: not a repository root`);
  return path;
}

function assertClean(repo: string): void {
  const changes = git(repo, ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"]);
  if (changes) fail(`${repo}: dirty worktree; commit explicitly first:\n${changes}`);
}

function assertKnownRemote(repo: string, name: string): void {
  if (name.startsWith("-") || !git(repo, ["remote"]).split("\n").includes(name)) fail(`${repo}: unknown remote ${name}`);
  const fetchUrls = git(repo, ["remote", "get-url", "--all", name]).split("\n").filter(Boolean);
  const pushUrls = git(repo, ["remote", "get-url", "--push", "--all", name]).split("\n").filter(Boolean);
  if (fetchUrls.length !== 1 || pushUrls.length !== 1 || fetchUrls[0] !== pushUrls[0]) fail(`${repo}: require one identical fetch/push URL`);
}

function readJson(path: string): Manifest {
  try { return JSON.parse(readFileSync(path, "utf8")) as Manifest; }
  catch (error) { fail(`${path}: invalid JSON (${error instanceof Error ? error.message : error})`); }
}

export function normalizeGitUrl(value: string): string {
  let raw = value.trim();
  const scp = /^git@([^:]+):(.+)$/.exec(raw);
  if (scp) raw = `https://${scp[1]}/${scp[2]}`;
  if (raw.startsWith("ssh://git@")) raw = `https://${raw.slice("ssh://git@".length)}`;
  if (raw.startsWith("git+")) raw = raw.slice(4);
  let url: URL;
  try { url = new URL(raw); }
  catch { fail(`invalid git URL ${value}`); }
  const path = url.pathname.replace(/\/+$/, "").replace(/\.git$/i, "").toLowerCase();
  return `${url.hostname.toLowerCase()}${path}`;
}
function quoted(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isPsyNode(url: string): boolean {
  return normalizeGitUrl(url) === "github.com/psyprotocol/psy-node";
}

function dependencyTables(value: Json): { table: string; entries: Json }[] {
  const tables: { table: string; entries: Json }[] = [];
  const workspace = value.workspace;
  if (workspace && typeof workspace === "object" && !Array.isArray(workspace)) {
    const entries = (workspace as Json).dependencies;
    if (entries) {
      if (typeof entries !== "object" || Array.isArray(entries)) fail("[workspace.dependencies] is not a table");
      tables.push({ table: "workspace.dependencies", entries: entries as Json });
    }
  }
  for (const table of ["dependencies", "dev-dependencies", "build-dependencies"]) {
    const entries = value[table];
    if (!entries) continue;
    if (typeof entries !== "object" || Array.isArray(entries)) fail(`[${table}] is not a table`);
    tables.push({ table, entries: entries as Json });
  }
  return tables;
}

function recognizedPin(path: string[]): boolean {
  return (path.length === 2 && ["dependencies", "dev-dependencies", "build-dependencies"].includes(path[0]))
    || (path.length === 3 && path[0] === "workspace" && path[1] === "dependencies");
}

function assertKnownPinLocations(value: Json, label: string): void {
  const visit = (node: unknown, path: string[]): void => {
    if (!node || typeof node !== "object" || Array.isArray(node)) return;
    const record = node as Json;
    if (typeof record.git === "string" && isPsyNode(String(record.git))) {
      if (!recognizedPin(path)) fail(`${label}: ${path.join(".")} is not a recognized psy-node dependency declaration`);
      return;
    }
    for (const [key, child] of Object.entries(record)) visit(child, [...path, key]);
  };
  visit(value, []);
}

export function pinsFromManifest(toml: string, label = "Cargo.toml"): CargoPin[] {
  let value: Json;
  try { value = Bun.TOML.parse(toml) as Json; }
  catch (error) { fail(`${label}: invalid TOML (${error instanceof Error ? error.message : error})`); }
  assertKnownPinLocations(value, label);
  const found: CargoPin[] = [];
  for (const { table, entries } of dependencyTables(value)) {
    for (const [key, raw] of Object.entries(entries)) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw) || typeof (raw as Json).git !== "string" || !isPsyNode(String((raw as Json).git))) continue;
      const dep = raw as Json;
      if (typeof dep.rev !== "string" || !SHA.test(dep.rev)) fail(`${label}: ${table}.${key} requires a full 40-character rev`);
      if (!/^[A-Za-z0-9_-]+$/.test(key)) fail(`${label}: ${table}.${key} has an unsupported key`);
      const rest = { ...dep };
      delete rest.git;
      delete rest.rev;
      found.push({ table, key, url: String(dep.git), rev: dep.rev, rest });
    }
  }
  return found;
}

export function replacePsyNodeRevs(toml: string, rev: string, label = "Cargo.toml"): string {
  if (!SHA.test(rev)) fail("revision must be a full 40-character SHA");
  const deps = pinsFromManifest(toml, label);
  let next = toml;
  for (const dep of deps) {
    const pattern = new RegExp(`(^\\[${quoted(dep.table)}\\][\\s\\S]*?^\\s*${dep.key}\\s*=\\s*\\{[^}\\n]*\\brev\\s*=\\s*")${dep.rev}(")`, "m");
    if (!pattern.test(next)) fail(`${label}: unfamiliar formatting for ${dep.table}.${dep.key}; refusing broad replacement`);
    next = next.replace(pattern, `$1${rev}$2`);
  }
  const after = pinsFromManifest(next, label);
  if (after.length !== deps.length) fail(`${label}: psy-node dependency set changed during rewrite`);
  for (let i = 0; i < deps.length; i++) {
    if (after[i].table !== deps[i].table || after[i].key !== deps[i].key || after[i].url !== deps[i].url || after[i].rev !== rev) fail(`${label}: rewrite changed more than ${deps[i].table}.${deps[i].key} rev`);
    if (JSON.stringify(after[i].rest) !== JSON.stringify(deps[i].rest)) fail(`${label}: rewrite changed properties of ${deps[i].table}.${deps[i].key}`);
  }
  return next;
}

export function parseGitSource(source: string): { url: string; rev: string } | null {
  const match = /^(git\+(https?:\/\/[^?#\s]+?))(?:\?rev=([0-9a-f]{40}))?(?:#([0-9a-f]{40}))?$/.exec(source);
  if (!match) return null;
  if (match[3] && match[4] && match[3] !== match[4]) fail(`git source rev and commit disagree: ${source}`);
  return { url: match[2], rev: match[4] || match[3] || "" };
}

export function validateCargoGraph(metadataJson: string, lockToml: string, rev: string): string[] {
  if (!SHA.test(rev)) fail("revision must be a full 40-character SHA");
  let meta: Metadata;
  try { meta = JSON.parse(metadataJson) as Metadata; }
  catch { fail("cargo metadata was not JSON"); }
  const nodes = meta.resolve?.nodes || [];
  if (!nodes.length || !Array.isArray(meta.packages)) fail("cargo metadata is missing the resolve graph");
  const ids: Record<string, true> = {};
  for (const node of nodes) {
    if (!node.id) fail("cargo metadata resolve node has no id");
    ids[node.id] = true;
  }
  for (const node of nodes) {
    for (const dep of node.deps || []) {
      if (!dep.pkg || !ids[dep.pkg]) fail(`cargo metadata resolve graph is missing ${dep.pkg || "a dependency"}`);
    }
  }
  for (const pkg of meta.packages) {
    if (pkg.id && !ids[pkg.id]) fail(`cargo metadata package ${pkg.name} is absent from the resolve graph`);
    if (!pkg.source) continue;
    const parsed = parseGitSource(pkg.source);
    if (parsed && isPsyNode(parsed.url) && parsed.rev !== rev) fail(`resolved ${pkg.name} is ${parsed.rev || "unknown"}, expected ${rev}`);
  }
  let lock: Json;
  try { lock = Bun.TOML.parse(lockToml) as Json; }
  catch (error) { fail(`Cargo.lock is invalid TOML (${error instanceof Error ? error.message : error})`); }
  const packages = Array.isArray(lock.package) ? lock.package as Json[] : [];
  const found: string[] = [];
  for (const pkg of packages) {
    if (typeof pkg.source !== "string") continue;
    const parsed = parseGitSource(pkg.source);
    if (!parsed || !isPsyNode(parsed.url)) continue;
    if (parsed.rev !== rev) fail(`Cargo.lock records ${String(pkg.name)} at ${parsed.rev || "unknown"}, expected ${rev}`);
    found.push(`${String(pkg.name)}@${String(pkg.version)}`);
  }
  if (!found.length) fail("resolved graph contains no psy-node package");
  return found.sort();
}

export function lockIdentities(lockToml: string): string[] {
  const lock = Bun.TOML.parse(lockToml) as Json;
  const packages = Array.isArray(lock.package) ? lock.package as Json[] : [];
  return packages.map(pkg => `${String(pkg.name)}@${String(pkg.version)} ${typeof pkg.source === "string" ? pkg.source : "path"}`).sort();
}

export function diffIdentities(before: string[], after: string[]): { added: string[]; removed: string[] } {
  const prior: Record<string, true> = {};
  const next: Record<string, true> = {};
  for (const item of before) prior[item] = true;
  for (const item of after) next[item] = true;
  return { added: after.filter(item => !prior[item]), removed: before.filter(item => !next[item]) };
}

function selectedPnpm(repo: string, runner: Runner): string {
  const pinned = readJson(join(repo, "package.json")).packageManager || "";
  const expected = pinned.startsWith("pnpm@") ? pinned.slice("pnpm@".length) : "";
  const result = runner(["corepack", "pnpm", "--config.ignore-pnpmfile=true", "--config.ignore-scripts=true", "--version"], repo, packEnvironment());
  if (result.code !== 0) fail(`${repo}: pnpm prerequisite failed with package-manager downloads disabled: ${result.err.trim() || result.out.trim()}`);
  const actual = result.out.trim();
  if (expected && actual !== expected) fail(`${repo}: packageManager requires pnpm ${expected}; corepack selected ${actual}. Install that exact version before continuing; do not substitute another pnpm.`);
  return actual;
}

export type ReleaseReport = {
  cargo: { repo: string; count: number; revs: string[]; lockRevs: string[] }[];
  packages: { name: string; version: string; workspace: string[]; hooks: string[] }[];
  consumers: { path: string; specs: Record<string, string> }[];
  tools: { repo: string; packageManager: string; pnpm: string; error?: string }[];
  discrepancies: string[];
};

function dependencySpec(value: string | { version?: string } | undefined): string {
  return typeof value === "string" ? value : value?.version || "";
}

function lockRevs(lockToml: string): string[] {
  const found: string[] = [];
  for (const identity of lockIdentities(lockToml)) {
    const parsed = parseGitSource(identity.slice(identity.indexOf(" ") + 1));
    if (parsed && isPsyNode(parsed.url) && !found.includes(parsed.rev)) found.push(parsed.rev);
  }
  return found;
}

export function inspectRelease(root: string, runner: Runner = runCommand): ReleaseReport {
  const cargo = CARGO_REPOS.map(repo => {
    const manifest = join(repository(root, repo), "Cargo.toml");
    const found = nodeDependencies(readFileSync(manifest, "utf8"));
    const revs: string[] = [];
    for (const pin of found) { const source = String(pin.value.rev || "local"); if (!revs.includes(source)) revs.push(source); }
    const lockPath = join(repository(root, repo), "Cargo.lock");
    return { repo, count: found.length, revs, lockRevs: existsSync(lockPath) ? lockRevs(readFileSync(lockPath, "utf8")) : [] };
  });
  const sdk = join(repository(root, "psy-sdk"), "psy-ts-sdk");
  const packages = SDK_PACKAGES.map(item => {
    const manifest = readJson(join(sdk, item.dir, "package.json"));
    const workspace = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"].flatMap(section => {
      const deps = manifest[section as "dependencies"];
      return deps ? Object.entries(deps).filter(([, value]) => /^(workspace:|file:|link:)/.test(dependencySpec(value))).map(([name, value]) => `${section}:${name}=${dependencySpec(value)}`) : [];
    });
    const hooks = ["prepublishOnly", "prepack", "prepare", "publish"].filter(hook => manifest.scripts?.[hook]);
    return { name: item.name, version: String(manifest.version || ""), workspace, hooks };
  });
  const consumers = CONSUMERS.map(item => {
    const path = join(repository(root, item.repo), item.manifest);
    const manifest = readJson(path);
    const specs: Record<string, string> = {};
    for (const name of item.packages) specs[name] = dependencySpec(manifest.dependencies?.[name]);
    return { path: relative(root, path), specs };
  });
  const tools = ["psy-sdk/psy-ts-sdk", "psy-wallet", "psy-dapp"].map(suffix => {
    const repo = suffix.includes("/") ? join(repository(root, "psy-sdk"), "psy-ts-sdk") : repository(root, suffix);
    const manager = existsSync(join(repo, "package.json")) ? readJson(join(repo, "package.json")).packageManager || "" : "";
    try { return { repo: suffix, packageManager: manager, pnpm: selectedPnpm(repo, runner) }; }
    catch (error) { return { repo: suffix, packageManager: manager, pnpm: "", error: error instanceof Error ? error.message : String(error) }; }
  });
  const discrepancies: string[] = [];
  const prepared = packages.find(item => item.name === "@psy-protocol/psy-sdk")?.version || "";
  for (const item of consumers) for (const [name, value] of Object.entries(item.specs)) if (value !== prepared) discrepancies.push(`${item.path} ${name}=${value || "absent"}, prepared ${prepared}`);
  for (const item of cargo) if (item.lockRevs.join(",") !== item.revs.join(",")) discrepancies.push(`${item.repo} lock ${item.lockRevs.join(",") || "none"} disagrees with manifest ${item.revs.join(",")}`);
  return { cargo, packages, consumers, tools, discrepancies };
}

export function printReport(report: ReleaseReport): void {
  for (const item of report.cargo) console.log(`${item.repo}\t${item.count} psy-node pins\t${item.revs.join(",") || "(none)"}\tlock ${item.lockRevs.join(",") || "(none)"}`);
  for (const item of report.packages) console.log(`${item.name}\t${item.version}\t${item.workspace.join(",") || "(no workspace protocol)"}\thooks ${item.hooks.join(",") || "(none)"}`);
  for (const item of report.consumers) console.log(`${item.path}\t${Object.entries(item.specs).map(([name, value]) => `${name}=${value || "(absent)"}`).join(" ")}`);
  for (const item of report.tools) console.log(`${item.repo}\t${item.packageManager || "(no packageManager)"}\tpnpm ${item.pnpm || "unavailable"}${item.error ? `\t${item.error}` : ""}`);
  for (const item of report.discrepancies) console.log(`discrepancy\t${item}`);
}

export function publishedOnBase(rev: string, baseTip: string, ancestor: (older: string, newer: string) => boolean): boolean {
  return rev === baseTip || ancestor(rev, baseTip);
}

export function requiresHistorySwitch(oldRevs: string[], rev: string, ancestor: (older: string, newer: string) => boolean): boolean {
  return oldRevs.some(old => old !== rev && !ancestor(old, rev));
}

function requireFreshBase(node: string, remote: string, base: string, rev: string): string {
  if (!SHA.test(rev)) fail("--rev must be the full 40-character commit SHA");
  git(node, ["check-ref-format", `refs/heads/${base}`]);
  assertKnownRemote(node, remote);
  const lines = git(node, ["ls-remote", "--refs", remote, `refs/heads/${base}`]);
  const tip = lines ? lines.split(/\s+/)[0] : "";
  if (!SHA.test(tip)) fail(`psy-node: cannot read fresh ${remote}/${base}`);
  const prefetch = `refs/prefetch/workspace-dependencies/${tip}`;
  git(node, ["fetch", "--refmap=", "--no-tags", "--no-write-fetch-head", remote, `${tip}:${prefetch}`]);
  if (git(node, ["rev-parse", "--verify", `${prefetch}^{commit}`]) !== tip) fail("psy-node: fetched base does not match the fresh remote tip");
  if (!publishedOnBase(rev, tip, (older, newer) => isAncestor(node, older, newer))) fail(`${rev} is not reachable from freshly observed ${remote}/${base}; publish that revision before switching consumers`);
  return tip;
}

function resolveCargo(repo: string, rev: string, runner: Runner): { packages: string[]; added: string[]; removed: string[] } {
  const label = basename(repo);
  const before = lockIdentities(readFileSync(join(repo, "Cargo.lock"), "utf8"));
  const env = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  const updating = runner(["cargo", "metadata", "--format-version", "1", "--manifest-path", "Cargo.toml"], repo, env);
  if (updating.code !== 0) fail(`${label}: cargo metadata resolver failed; changes remain, no reset:\n${updating.err.trim()}`);
  const locked = runner(["cargo", "metadata", "--format-version", "1", "--manifest-path", "Cargo.toml", "--locked"], repo, env);
  if (locked.code !== 0) fail(`${label}: cargo metadata --locked failed after resolution; changes remain, no reset:\n${locked.err.trim()}`);
  const lockToml = readFileSync(join(repo, "Cargo.lock"), "utf8");
  const packages = validateCargoGraph(locked.out, lockToml, rev);
  const delta = diffIdentities(before, lockIdentities(lockToml));
  return { packages, ...delta };
}

export function switchNodeRevision(root: string, rev: string, apply: boolean, allowHistorySwitch: boolean, remote = "origin", base = "mainnet-beta", runner: Runner = runCommand): { repo: string; from: string[]; to: string; packages: string[]; added: string[]; removed: string[] }[] {
  const snapshot = mutationSnapshot(root, cargoFiles(root));
  const crates = nodeCratePaths(repository(root, "psy-node"));
  const node = repository(root, "psy-node");
  const plans = CARGO_REPOS.map(name => {
    const repo = repository(root, name);
    const path = join(repo, "Cargo.toml");
    if (!existsSync(join(repo, "Cargo.lock"))) fail(`${name}: Cargo.lock is required`);
    const text = readFileSync(path, "utf8");
    const deps = nodeDependencies(text).map(dep => ({ ...dep, rev: String(dep.value.rev || "local") }));
    if (!deps.length) fail(`${name}: no psy-node Cargo dependencies found`);
    return { name, repo, path, text, deps };
  });
  if (new Set(plans.flatMap(plan => plan.deps.map(dep => dep.rev))).size !== 1) fail("mixed node dependency graph across consumers");
  requireFreshBase(node, remote, base, rev);
  const oldRevs = plans.flatMap(plan => plan.deps.map(dep => dep.rev)).filter(rev => rev !== "local");
  for (const old of oldRevs) {
    if (runCommand(["git", "-C", node, "cat-file", "-e", `${old}^{commit}`], undefined, gitEnvironment).code !== 0) fail(`psy-node: current pin ${old} is not a local commit, so its history cannot be compared`);
  }
  if (requiresHistorySwitch(oldRevs, rev, (older, newer) => isAncestor(node, older, newer)) && !allowHistorySwitch) {
    fail(`current psy-node pin is not an ancestor of ${rev}; rerun with --allow-history-switch for this divergent or backward switch`);
  }
  const preview = plans.map(plan => {
    const from: string[] = [];
    for (const dep of plan.deps) if (!from.includes(dep.rev)) from.push(dep.rev);
    return { repo: plan.name, from, to: rev, packages: plan.deps.map(dep => `${dep.table}.${dep.key}`), added: [] as string[], removed: [] as string[] };
  });
  if (!apply) return preview;
  for (const plan of plans) if (runner(["cargo", "--version"], plan.repo).code !== 0) fail(`${plan.name}: cargo is unavailable in that repository`);
  const current = [...new Set(plans.flatMap(plan => plan.deps.map(dep => dep.rev)))];
  if (current.length !== 1) fail(`current psy-node pins disagree: ${current.join(", ")}`);
  const rewrites = plans.map(plan => {
    lockIdentities(readFileSync(join(plan.repo, "Cargo.lock"), "utf8"));
    return { plan, text: rewriteNodeDependencies(plan.text, plan.repo, crates, rev) };
  });
  snapshot();
  const completed: string[] = [];
  try {
    for (const { plan, text } of rewrites) {
      writeFileSync(plan.path, text);
      const resolved = resolveCargo(plan.repo, rev, runner);
      const locked = runner(["cargo", "metadata", "--format-version", "1", "--locked"], plan.repo);
      if (locked.code !== 0) fail(`${plan.name}: locked graph validation failed`);
      assertLocalCargoGraph(locked.out, readFileSync(join(plan.repo, "Cargo.lock"), "utf8"), crates, plan.deps.map(dep => dep.package), false);
      completed.push(plan.name);
      const row = preview.find(item => item.repo === plan.name)!;
      row.packages = resolved.packages;
      row.added = resolved.added;
      row.removed = resolved.removed;
    }
  } catch (error) {
    fail(`partial Cargo update (${completed.join(", ") || "none"} resolved); edited files were kept and nothing was reset. ${error instanceof Error ? error.message : error}`);
  }
  return preview;
}

export function replaceTopVersion(text: string, version: string, label: string): string {
  if (!VERSION.test(version)) fail("version must be an explicit semantic version, not an inferred bump");
  const parsed = JSON.parse(text) as Manifest;
  const from = String(parsed.version || "");
  const pattern = /("version"\s*:\s*")([^"\n]*)(")/;
  if (!pattern.test(text) || pattern.exec(text)?.[2] !== from) fail(`${label}: top-level version field is unfamiliar`);
  const next = text.replace(pattern, `$1${version}$3`);
  const after = JSON.parse(next) as Manifest;
  if (after.version !== version) fail(`${label}: version was not updated`);
  after.version = from;
  parsed.version = from;
  if (JSON.stringify(after) !== JSON.stringify(parsed)) fail(`${label}: version rewrite changed another field`);
  return next;
}

export function assertEvmSdkPeer(version: string, range: unknown): void {
  if (typeof range !== "string" || !range.trim()) fail("@psy-protocol/evm-wallet has a missing peer range for SDK");
  if (!/^\^?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(range)) fail(`@psy-protocol/evm-wallet has unsupported SDK peer range ${range}; expected an exact or caret major.minor.patch version`);
  if (!Bun.semver.satisfies(version, range)) fail(`@psy-protocol/evm-wallet requires SDK ${range}, incompatible with ${version}`);
}

export function preparePackages(root: string, version: string, apply: boolean, runner: Runner = runCommand): { name: string; from: string; to: string }[] {
  for (const name of WORKSPACE_REPOS) assertClean(repository(root, name));
  const sdk = join(repository(root, "psy-sdk"), "psy-ts-sdk");
  selectedPnpm(sdk, runner);
  const changes = SDK_PACKAGES.map(item => {
    const manifest = readJson(join(sdk, item.dir, "package.json"));
    if (manifest.name !== item.name) fail(`${item.dir}: expected ${item.name}`);
    return { name: item.name, from: String(manifest.version || ""), to: version };
  });
  if (!VERSION.test(version)) fail("version must be an explicit semantic version, not an inferred bump");
  assertEvmSdkPeer(version, readJson(join(sdk, "packages/evm-wallet/package.json")).peerDependencies?.["@psy-protocol/psy-sdk"]);
  Bun.YAML.parse(readFileSync(join(sdk, "pnpm-lock.yaml"), "utf8"));
  const rewrites = SDK_PACKAGES.map(item => {
    const path = join(sdk, item.dir, "package.json");
    return { path, text: replaceTopVersion(readFileSync(path, "utf8"), version, path) };
  });
  if (!apply) return changes;
  for (const item of rewrites) writeFileSync(item.path, item.text);
  const locked = runner(["corepack", "pnpm", ...PNPM_LOCK_ONLY_ARGS], sdk, packEnvironment());
  if (locked.code !== 0) fail(`psy-sdk lock resolution failed; package versions remain changed, no reset:\n${locked.err.trim()}`);
  return changes;
}


function entrySatisfies(entries: ArchiveEntry[], spec: string): boolean {
  const clean = spec.replace(/^\.\//, "");
  if (!clean || clean.includes("..")) return false;
  const regular = (entry: ArchiveEntry): boolean => entry.type === "0" || entry.type === "\0";
  if (clean.includes("*")) {
    const pattern = new RegExp(`^package/${clean.split("*").map(quoted).join("[^/]*")}$`);
    return entries.some(entry => regular(entry) && pattern.test(entry.name));
  }
  const exact = `package/${clean}`;
  if (/\.[A-Za-z0-9]+$/.test(clean)) return entries.some(entry => entry.name === exact && regular(entry));
  return entries.some(entry => entry.name === exact && entry.type === "5") || entries.some(entry => regular(entry) && entry.name.startsWith(`${exact}/`));
}

function declaredPaths(manifest: Manifest): string[] {
  const paths: string[] = [];
  const visit = (value: unknown): void => {
    if (typeof value === "string") paths.push(value);
    else if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === "object") Object.values(value).forEach(visit);
  };
  visit(manifest.files); visit(manifest.main); visit(manifest.module); visit(manifest.types); visit(manifest.exports);
  return paths;
}

export function validatePacked(manifest: Manifest, version: string, entries: ArchiveEntry[], siblingVersions: Record<string, string> = {}, expectedPeers: Record<string, string> = {}): void {
  if (manifest.name === undefined || manifest.version !== version) fail(`${manifest.name || "package"}: tarball version is ${String(manifest.version)}, expected ${version}`);
  const problems: string[] = [];
  for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] as const) {
    for (const [name, value] of Object.entries(manifest[section] || {})) {
      const declaration = dependencySpec(value);
      if (/^(workspace:|file:|link:)/.test(declaration)) problems.push(`${section}.${name} still uses ${declaration}`);
      if (section === "dependencies" && siblingVersions[name] && declaration !== siblingVersions[name]) problems.push(`${section}.${name} is ${declaration}, expected ${siblingVersions[name]}`);
    }
  }
  for (const [name, expected] of Object.entries(expectedPeers)) {
    if (dependencySpec(manifest.peerDependencies?.[name]) !== expected) problems.push(`peer ${name} is ${dependencySpec(manifest.peerDependencies?.[name]) || "absent"}, expected ${expected}`);
  }
  for (const spec of declaredPaths(manifest)) if (!entrySatisfies(entries, spec)) problems.push(`missing concrete archive member for ${spec}`);
  if (manifest.name === "@psy-protocol/psy-sdk" && !entries.some(entry => entry.name === "package/.compiler-artifact.json" && (entry.type === "0" || entry.type === "\0"))) problems.push("missing compiler provenance file");
  if (problems.length) fail(`${manifest.name}: invalid packed archive:\n${problems.join("\n")}`);
  if (manifest.name === "@psy-protocol/evm-wallet") assertEvmSdkPeer(version, manifest.peerDependencies?.["@psy-protocol/psy-sdk"]);
}

function currentCompilerProvenance(root: string, compilerDir: string): { compilerRevision: string; compilerSourcesHash: string } {
  const helper = join(root, "psy-sdk/psy-ts-sdk/packages/psy-sdk/src/local-web-compiler/compiler-provenance.ts");
  if (!existsSync(helper)) fail(`${helper}: compiler provenance helper is absent`);
  const env = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"]) delete env[key];
  const script = `import { readCompilerProvenance } from ${JSON.stringify(helper)};\nconst value = readCompilerProvenance(process.argv[1]);\nprocess.stdout.write(JSON.stringify(value));\n`;
  const result = runCommand(["bun", "-e", script, compilerDir], compilerDir, env);
  if (result.code !== 0) fail(`compiler provenance failed: ${result.err.trim()}`);
  return assertCompilerProvenance(result.out);
}

function acceptedPack(name: string, version: string, archive: { manifest: Manifest; entries: ArchiveEntry[]; texts: Record<string, string> }, siblings: Record<string, string>, peers: Record<string, string>, root?: string, compilerDir?: string): void {
  if (archive.manifest.name !== name) fail(`${name}: archive contains ${String(archive.manifest.name)}`);
  validatePacked(archive.manifest, version, archive.entries, siblings, peers);
  if (name !== "@psy-protocol/psy-sdk") return;
  const artifact = archive.texts["package/.compiler-artifact.json"];
  if (artifact === undefined) fail(`${name}: compiler provenance missing or invalid`);
  const provenance = assertCompilerProvenance(artifact);
  if (!root || !compilerDir) return;
  const current = currentCompilerProvenance(root, compilerDir);
  if (provenance.compilerRevision !== current.compilerRevision || provenance.compilerSourcesHash !== current.compilerSourcesHash) fail(`${name}: compiler provenance is not the current compiler revision and source hash`);
}

export function assertCompilerProvenance(text: string): { compilerRevision: string; compilerSourcesHash: string } {
  let parsed: Json;
  try { parsed = JSON.parse(text) as Json; }
  catch { fail("compiler provenance is not JSON"); }
  const keys = Object.keys(parsed).sort().join(",");
  if (keys !== "compilerRevision,compilerSourcesHash") fail("compiler provenance must contain only compilerRevision and compilerSourcesHash");
  const compilerRevision = String(parsed.compilerRevision);
  const compilerSourcesHash = String(parsed.compilerSourcesHash);
  if (!SHA.test(compilerRevision) || !/^[0-9a-f]{64}$/.test(compilerSourcesHash)) fail("compiler provenance fields have the wrong shape");
  return { compilerRevision, compilerSourcesHash };
}

function textAt(bytes: Uint8Array, offset: number, length: number): string {
  const slice = bytes.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end === -1 ? slice : slice.subarray(0, end)).trim();
}

export function readPackedArchive(bytes: Uint8Array): { manifest: Manifest; entries: ArchiveEntry[]; texts: Record<string, string> } {
  const data = gunzipSync(bytes);
  const entries: ArchiveEntry[] = [];
  const texts: Record<string, string> = {};
  let longName = "";
  for (let offset = 0; offset + 512 <= data.length;) {
    const header = data.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) break;
    const size = Number.parseInt(textAt(header, 124, 12) || "0", 8);
    const type = String.fromCharCode(header[156] || 0);
    const prefix = textAt(header, 345, 155);
    const name = longName || (prefix ? `${prefix}/${textAt(header, 0, 100)}` : textAt(header, 0, 100));
    longName = "";
    const content = data.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === "L") { longName = new TextDecoder().decode(content).replace(/\0+$/, ""); continue; }
    if (type === "x" || type === "g") continue;
    entries.push({ name, type });
    if (name === "package/package.json" || name === "package/.compiler-artifact.json") texts[name] = new TextDecoder().decode(content);
  }
  if (!texts["package/package.json"]) fail("packed archive has no package/package.json");
  return { manifest: JSON.parse(texts["package/package.json"]) as Manifest, entries, texts };
}

export function assertWorkspaceLink(linkPath: string, targetPath: string, packageName: string): void {
  if (!existsSync(linkPath) || !lstatSync(linkPath).isSymbolicLink()) fail(`${linkPath}: existing workspace link is required before packing`);
  if (realpathSync(linkPath) !== realpathSync(targetPath)) fail(`${linkPath}: link does not resolve to ${targetPath}`);
  const linked = readJson(join(realpathSync(linkPath), "package.json"));
  if (linked.name !== packageName || linked.version !== readJson(join(targetPath, "package.json")).version) fail(`${linkPath}: linked package does not match ${packageName}`);
}

function assertPackable(manifest: Manifest, dir: string): void {
  if (manifest.private === true) fail(`${manifest.name}: private packages are not packed`);
  if (manifest.publishConfig?.directory) fail(`${manifest.name}: unexpected publish directory`);
  if (manifest.publishConfig?.registry && manifest.publishConfig.registry !== NPM_REGISTRY) fail(`${manifest.name}: unexpected publish registry`);
  for (const hook of ["prepack", "postpack", "prepare", "publish"]) if (manifest.scripts?.[hook]) fail(`${manifest.name}: unexpected ${hook} hook`);
  for (const spec of declaredPaths(manifest)) {
    const clean = spec.replace(/^\.\//, "");
    if (!clean.includes("*") && !clean.includes("..") && !existsSync(join(dir, clean))) fail(`${manifest.name}: audited output ${clean} is absent; pack does not build`);
  }
}

export function packCommand(out: string): string[] {
  return ["corepack", "pnpm", "--config.ignore-pnpmfile=true", "--config.ignore-scripts=true", "pack", "--pack-destination", out, "--json"];
}

export function packEnvironment(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return { ...base, COREPACK_ENABLE_NETWORK: "0", npm_config_ignore_scripts: "true", npm_config_ignore_pnpmfile: "true" };
}

export function packPackages(root: string, out: string, version: string, runner: Runner = runCommand): Pack[] {
  for (const name of WORKSPACE_REPOS) assertClean(repository(root, name));
  assertPublishedDependencies(root);
  const sdk = join(repository(root, "psy-sdk"), "psy-ts-sdk");
  selectedPnpm(sdk, runner);
  const prepared = SDK_PACKAGES.map(item => {
    const dir = join(sdk, item.dir);
    const manifest = readJson(join(dir, "package.json"));
    if (manifest.name !== item.name || manifest.version !== version) fail(`${item.name}: source version must already be ${version}`);
    assertPackable(manifest, dir);
    return { ...item, dir, manifest };
  });
  assertEvmSdkPeer(version, prepared.find(item => item.name === "@psy-protocol/evm-wallet")!.manifest.peerDependencies?.["@psy-protocol/psy-sdk"]);
  for (const [link, target, name] of WORKSPACE_LINKS) assertWorkspaceLink(join(sdk, link), join(sdk, target), name);
  const artifactPath = join(sdk, "packages/psy-sdk/.compiler-artifact.json");
  if (!existsSync(artifactPath)) fail(`${artifactPath}: compiler provenance is absent`);
  const declared = assertCompilerProvenance(readFileSync(artifactPath, "utf8"));
  const current = currentCompilerProvenance(root, join(root, "psy-compiler"));
  if (declared.compilerRevision !== current.compilerRevision || declared.compilerSourcesHash !== current.compilerSourcesHash) fail("@psy-protocol/psy-sdk: compiler provenance is not the current compiler revision and source hash");
  mkdirSync(out, { recursive: true });
  const packs: Pack[] = [];
  const siblings = { "@psy-protocol/utils": version, "@psy-protocol/psy-sdk": version };
  for (const item of prepared) {
    const packed = runner(packCommand(out), item.dir, packEnvironment());
    if (packed.code !== 0) fail(`${item.name}: pnpm pack failed:\n${packed.err.trim()}`);
    const listed = JSON.parse(packed.out) as { filename?: string }[] | { filename?: string };
    const filename = (Array.isArray(listed) ? listed[0] : listed)?.filename;
    if (!filename) fail(`${item.name}: pnpm pack returned no archive`);
    const path = isAbsolute(filename) ? filename : join(out, basename(filename));
    const bytes = readFileSync(path);
    const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    const archive = readPackedArchive(bytes);
    const peers = item.name === "@psy-protocol/evm-wallet" ? { "@psy-protocol/psy-sdk": dependencySpec(item.manifest.peerDependencies?.["@psy-protocol/psy-sdk"]) } : {};
    acceptedPack(item.name, version, archive, item.name === "@psy-protocol/contract-sdk" ? siblings : {}, peers, item.name === "@psy-protocol/psy-sdk" ? root : undefined, item.name === "@psy-protocol/psy-sdk" ? join(root, "psy-compiler") : undefined);
    if (item.name === "@psy-protocol/psy-sdk" && archive.texts["package/.compiler-artifact.json"].trim() !== readFileSync(join(item.dir, ".compiler-artifact.json"), "utf8").trim()) fail(`${item.name}: packed compiler provenance differs from the workspace artifact`);
    packs.push({ name: item.name, version, path, integrity, manifest: archive.manifest, entries: archive.entries });
  }
  return packs;
}

export function loadValidatedPack(out: string, name: string, version: string): Pack {
  const filename = `${name.replace("@", "").replace("/", "-")}-${version}.tgz`;
  const path = join(out, filename);
  if (!existsSync(path)) fail(`${path}: validated tarball is absent; run pack before publish`);
  const bytes = readFileSync(path);
  const archive = readPackedArchive(bytes);
  const siblings = name === "@psy-protocol/contract-sdk" ? { "@psy-protocol/utils": version, "@psy-protocol/psy-sdk": version } : {};
  acceptedPack(name, version, archive, siblings, {});
  return { name, version, path, integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`, manifest: archive.manifest, entries: archive.entries };
}

export async function registryPackage(name: string, version: string): Promise<RegistryPackage | null> {
  const result = runCommand(["npm", "view", `${name}@${version}`, "version", "dist.integrity", "dist.tarball", "peerDependencies", "--json", `--registry=${NPM_REGISTRY}`]);
  const text = `${result.out}\n${result.err}`;
  if (result.code !== 0 && /E404|404 Not Found/.test(text)) return null;
  if (result.code !== 0) fail(`registry lookup failed for ${name}@${version}; not treating this as absent:\n${result.err.trim()}`);
  const parsed = JSON.parse(result.out) as { version?: string; "dist.integrity"?: string; "dist.tarball"?: string; peerDependencies?: Record<string, string> };
  if (parsed.version !== version || !parsed["dist.integrity"]?.startsWith("sha512-") || !parsed["dist.tarball"]?.startsWith(NPM_REGISTRY)) fail(`registry returned incomplete metadata for ${name}@${version}`);
  return { version: parsed.version, integrity: parsed["dist.integrity"], tarball: parsed["dist.tarball"], peerDependencies: parsed.peerDependencies };
}

export async function publishPackages(packs: Pack[], tag: string, lookup: RegistryLookup = registryPackage, runner: Runner = runCommand): Promise<{ name: string; integrity: string; state: "published" | "already-present" }[]> {
  if (!/^[A-Za-z0-9._-]+$/.test(tag) || tag.startsWith(".")) fail("--tag must be an npm dist-tag");
  if (packs.map(pack => pack.name).join(",") !== SDK_PACKAGES.map(item => item.name).join(",")) fail("publish requires utils, psy-sdk, contract-sdk, then evm-wallet");
  for (const pack of packs) {
    for (const section of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] as const) {
      for (const [name, spec] of Object.entries(pack.manifest[section] || {})) if (/^(file:|link:|workspace:)/.test(dependencySpec(spec))) fail(`${pack.name}: refusing publication of local dependency ${name}`);
    }
  }
  const existing: Record<string, RegistryPackage | null> = {};
  for (const pack of packs) {
    const found = await lookup(pack.name, pack.version);
    if (found && (found.version !== pack.version || found.integrity !== pack.integrity)) fail(`${pack.name}@${pack.version} exists with integrity ${found.integrity}, not ${pack.integrity}`);
    existing[pack.name] = found;
  }
  const states: { name: string; integrity: string; state: "published" | "already-present" }[] = [];
  for (const pack of packs) {
    if (existing[pack.name]) { states.push({ name: pack.name, integrity: pack.integrity, state: "already-present" }); continue; }
    const published = runner(["npm", "publish", pack.path, "--ignore-scripts", "--access", "public", "--tag", tag, `--registry=${NPM_REGISTRY}`]);
    if (published.code !== 0) fail(`${pack.name}: publish failed; earlier packages may already be on the registry, resume by integrity:\n${published.err.trim()}`);
    const confirmed = await lookup(pack.name, pack.version);
    if (confirmed?.integrity !== pack.integrity) fail(`${pack.name}: registry integrity does not match packed tarball`);
    states.push({ name: pack.name, integrity: pack.integrity, state: "published" });
  }
  return states;
}

export function replaceDirectDependencies(text: string, versions: Record<string, string>, label: string): string {
  let next = text;
  for (const [name, version] of Object.entries(versions)) {
    if (!VERSION.test(version) && !/^file:\.\.\//.test(version)) fail("dependency must be an explicit version or sibling file path");
    const pattern = new RegExp(`("dependencies"\\s*:\\s*\\{[\\s\\S]*?"${quoted(name)}"\\s*:\\s*")([^"\\n]*)(")`);
    const found = pattern.exec(next);
    if (!found) fail(`${label}: ${name} must be a direct string dependency`);
    if (found[2].startsWith("{")) fail(`${label}: ${name} dependency must be a string`);
    next = next.replace(pattern, `$1${version}$3`);
  }
  const before = JSON.parse(text) as Manifest;
  const after = JSON.parse(next) as Manifest;
  for (const [name, version] of Object.entries(versions)) {
    if (after.dependencies?.[name] !== version) fail(`${label}: ${name} was not updated`);
    delete before.dependencies?.[name];
    delete after.dependencies?.[name];
  }
  if (JSON.stringify(before) !== JSON.stringify(after)) fail(`${label}: dependency rewrite changed another field`);
  return next;
}

type LockDependency = { specifier?: unknown; version?: unknown };
type LockDocument = { importers?: Record<string, { dependencies?: Record<string, LockDependency> }>; packages?: Record<string, { resolution?: { integrity?: unknown } }>; snapshots?: Record<string, { dependencies?: Record<string, unknown> }> };

export function assertPnpmLockfile(lockText: string, checks: { importer: string; name: string; version: string; integrity: string }[]): void {
  let lock: LockDocument;
  try { lock = Bun.YAML.parse(lockText) as LockDocument; }
  catch (error) { fail(`pnpm lock is invalid YAML (${error instanceof Error ? error.message : error})`); }
  for (const check of checks) {
    const dependency = lock.importers?.[check.importer]?.dependencies?.[check.name];
    const selected = typeof dependency?.version === "string" ? dependency.version : "";
    const exact = selected === check.version || selected.startsWith(`${check.version}(`);
    if (dependency?.specifier !== check.version || !exact) fail(`${check.importer}: ${check.name} resolved ${selected || "nothing"}, expected ${check.version}`);
    const resolution = lock.packages?.[`${check.name}@${check.version}`]?.resolution?.integrity;
    if (resolution !== check.integrity) fail(`${check.name}@${check.version}: lock integrity ${String(resolution)} does not match registry ${check.integrity}`);
    const snapshot = lock.snapshots?.[`${check.name}@${selected}`];
    if (!snapshot) fail(`${check.importer}: snapshot ${check.name}@${selected} is absent`);
    for (const [dependencyName, dependencyVersion] of Object.entries(snapshot.dependencies || {})) {
      if (!lock.snapshots?.[`${dependencyName}@${String(dependencyVersion)}`]) fail(`${check.importer}: snapshot ${dependencyName}@${String(dependencyVersion)} is absent`);
    }
    if (check.name === "@psy-protocol/evm-wallet") {
      const peer = snapshot.dependencies?.["@psy-protocol/psy-sdk"];
      const sdk = checks.find(item => item.importer === check.importer && item.name === "@psy-protocol/psy-sdk");
      if (sdk && peer !== sdk.version) fail(`${check.importer}: evm-wallet snapshot depends on SDK ${String(peer)}, expected ${sdk.version}`);
    }
  }
}

export async function switchConsumers(root: string, version: string, apply: boolean, lookup: RegistryLookup = registryPackage, runner: Runner = runCommand, install = false): Promise<{ path: string; before: Record<string, string> }[]> {
  if (install && !apply) fail("--install requires --apply");
  if (!VERSION.test(version)) fail("version must be an explicit semantic version");
  const evidence: Record<string, string> = {};
  for (const name of ["@psy-protocol/psy-sdk", "@psy-protocol/evm-wallet"]) {
    const found = await lookup(name, version);
    if (!found?.integrity.startsWith("sha512-") || found.version !== version) fail(`${name}@${version} has no published registry integrity`);
    if (name === "@psy-protocol/evm-wallet") assertEvmSdkPeer(version, found.peerDependencies?.["@psy-protocol/psy-sdk"]);
    evidence[name] = found.integrity;
  }

  const snapshot = mutationSnapshot(root, npmFiles(root));
  preflightNpm(root, runner);
  const plan = CONSUMERS.map(item => {
    const path = join(repository(root, item.repo), item.manifest);
    const manifest = readJson(path);
    const before: Record<string, string> = {};
    for (const name of item.packages) {
      const current = manifest.dependencies?.[name];
      if (typeof current !== "string") fail(`${path}: ${name} must be a direct string dependency`);
      before[name] = current;
    }
    return { path, before };
  });
  if (!apply) return plan;
  const rewrites = CONSUMERS.map(item => {
    const path = join(repository(root, item.repo), item.manifest);
    const versions: Record<string, string> = {};
    for (const name of item.packages) versions[name] = version;
    return { path, text: replaceDirectDependencies(readFileSync(path, "utf8"), versions, path) };
  });
  snapshot();
  for (const item of rewrites) writeFileSync(item.path, item.text);

  try {
    resolveNpm(root, version, evidence, runner);
    if (install) activateConsumers(root, runner);
  } catch (error) {
    fail(`partial consumer update; all changed files remain, no reset. ${error instanceof Error ? error.message : error}`);
  }
  return plan;
}

function cargoFiles(root: string): string[] {
  return CARGO_REPOS.flatMap(repo => [join(root, repo, "Cargo.toml"), join(root, repo, "Cargo.lock")]);
}

function npmFiles(root: string): string[] {
  return [...CONSUMERS.map(item => join(root, item.repo, item.manifest)),
    join(root, "psy-wallet/pnpm-lock.yaml"), join(root, "psy-dapp/pnpm-lock.yaml"),
    join(root, "psy-dapp/apps/account/pnpm-lock.yaml"), join(root, "psy-dapp/apps/account/bun.lock")];
}

// Snapshot only owned files, but freeze every sibling's branch/HEAD. Unrelated
// source edits are allowed; staged, unstaged and untracked owned files are not.
function mutationSnapshot(root: string, files: string[]): () => void {
  const heads = WORKSPACE_REPOS.map(name => {
    const repo = repository(root, name);
    const branch = git(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"]);
    if (!branch || ["main", "master", "mainnet-beta"].includes(branch) || branch.startsWith("workspace-integration/")) fail(`${name}: a checked-out topic branch is required`);
    return { repo, branch, head: git(repo, ["rev-parse", "HEAD"]) };
  });
  if (new Set(heads.map(item => item.branch)).size !== 1) fail("all eight repositories must use the same topic branch");
  const bytes = files.map(path => {
    const owner = heads.find(item => path.startsWith(`${item.repo}/`));
    if (!owner) fail(`${path}: not a cohort file`);
    const local = relative(owner.repo, path);
    if (git(owner.repo, ["status", "--porcelain=v1", "--untracked-files=all", "--", local])) fail(`${local}: owned manifest/lock is dirty; commit or resolve it explicitly before switching`);
    if (!existsSync(path) || !lstatSync(path).isFile()) fail(`${path}: regular tracked file required`);
    git(owner.repo, ["ls-files", "--error-unmatch", "--", local]);
    return { path, bytes: readFileSync(path), repo: owner.repo, local };
  });
  return () => {
    for (const item of heads) if (git(item.repo, ["rev-parse", "HEAD"]) !== item.head || git(item.repo, ["symbolic-ref", "--quiet", "--short", "HEAD"]) !== item.branch) fail(`${item.repo}: HEAD changed during preflight`);
    for (const item of bytes) if (!readFileSync(item.path).equals(item.bytes) || git(item.repo, ["status", "--porcelain=v1", "--untracked-files=all", "--", item.local])) fail(`${item.path}: changed during preflight; nothing written`);
  };
}

function npmRoots(root: string): { path: string; standalone: boolean; consumers: typeof CONSUMERS[number][] }[] {
  return [
    { path: join(root, "psy-wallet"), standalone: false, consumers: CONSUMERS.filter(item => item.repo === "psy-wallet") },
    { path: join(root, "psy-dapp"), standalone: false, consumers: CONSUMERS.filter(item => item.repo === "psy-dapp") },
    { path: join(root, "psy-dapp/apps/account"), standalone: true, consumers: CONSUMERS.filter(item => item.importer === "apps/account") },
  ];
}

function preflightNpm(root: string, runner: Runner): void {
  for (const item of npmRoots(root)) {
    selectedPnpm(item.path, runner);
    Bun.YAML.parse(readFileSync(join(item.path, "pnpm-lock.yaml"), "utf8"));
  }
  parseBunLock(readFileSync(join(root, "psy-dapp/apps/account/bun.lock"), "utf8"));
  if (runner(["bun", "--version"], root).code !== 0) fail("Bun is required for account's compatibility lock");
  console.warn("warning: psy-dapp/apps/bridge/pnpm-lock.yaml is an inactive legacy lock; left unchanged");
}

function localSpec(root: string, manifestPath: string, name: string): string {
  const source = SDK_PACKAGES.find(item => item.name === name) || fail(`unknown SDK package ${name}`);
  return `file:${relative(dirname(manifestPath), join(root, "psy-sdk/psy-ts-sdk", source.dir))}`;
}

export function assertLocalPnpmLock(text: string, checks: { importer: string; name: string; spec: string; directory: string }[]): void {
  const lock = Bun.YAML.parse(text) as LockDocument;
  for (const check of checks) {
    const dep = lock.importers?.[check.importer]?.dependencies?.[check.name];
    const selected = String(dep?.version || "");
    if (dep?.specifier !== check.spec) fail(`${check.importer}: ${check.name} specifier disagrees with manifest`);
    if (selected.startsWith("link:")) {
      if (isAbsolute(selected.slice(5)) || normalize(join(check.importer, selected.slice(5))) !== normalize(check.directory)) fail(`${check.importer}: ${check.name} link does not target the sibling directory`);
      continue;
    }
    if (selected !== `file:${check.directory}` && !selected.startsWith(`file:${check.directory}(`)) fail(`${check.importer}: ${check.name} did not resolve to the sibling directory`);
    const entry = lock.packages?.[`${check.name}@file:${check.directory}`];
    const resolution = entry?.resolution as { directory?: string; type?: string } | undefined;
    if (resolution?.type !== "directory" || resolution.directory !== check.directory || !lock.snapshots?.[`${check.name}@${selected}`]) fail(`${check.name}: missing local package resolution or snapshot`);
    if (check.name === "@psy-protocol/evm-wallet") {
      const sdk = checks.find(item => item.importer === check.importer && item.name === "@psy-protocol/psy-sdk");
      const peer = lock.snapshots?.[`${check.name}@${selected}`]?.dependencies?.["@psy-protocol/psy-sdk"];
      if (sdk && typeof peer === "string") {
        const selectedSdk = lock.importers?.[sdk.importer]?.dependencies?.[sdk.name]?.version;
        if (peer !== selectedSdk && peer !== `file:${sdk.directory}`) fail(`${check.importer}: local EVM snapshot has the wrong SDK peer`);
      } else if (sdk) fail(`${check.importer}: local EVM snapshot has no SDK peer`);
    }
  }
}

export function assertBunLock(text: string, specs: Record<string, string>, evidence: Record<string, string> = {}): void {
  const lock = parseBunLock(text);
  for (const [name, spec] of Object.entries(specs)) {
    if (lock.workspaces?.[""]?.dependencies?.[name] !== spec) fail(`${name}: Bun importer disagrees with manifest`);
    const entry = lock.packages?.[name];
    if (!Array.isArray(entry) || typeof entry[0] !== "string") fail(`${name}: Bun resolved package is missing`);
    if (spec.startsWith("file:")) {
      if (entry.length !== 2 || !entry[1] || typeof entry[1] !== "object" || Array.isArray(entry[1])) fail(`${name}: unknown Bun local package tuple`);
      const prefix = `${name}@file:`;
      if (!entry[0].startsWith(prefix) || normalize(entry[0].slice(prefix.length)) !== normalize(spec.slice(5))) fail(`${name}: Bun local package targets the wrong sibling`);
    } else {
      if (entry.length !== 4 || typeof entry[1] !== "string" || !entry[2] || typeof entry[2] !== "object" || Array.isArray(entry[2])) fail(`${name}: unknown Bun registry package tuple`);
      if (entry[0] !== `${name}@${spec}` || entry[3] !== evidence[name]) fail(`${name}: Bun registry identity or integrity mismatch`);
    }
  }
}

export function assertPublishedDependencies(root: string): void {
  const nodePackages = [...nodeCratePaths(repository(root, "psy-node")).keys()];
  for (const name of CARGO_REPOS) {
    const repo = repository(root, name);
    const paths = git(repo, ["ls-files", "-z"]).split("\0").filter(path => /(?:^|\/)Cargo\.(?:toml|lock)$/.test(path));
    const files = paths.map(path => ({ path, text: readFileSync(join(repo, path), "utf8") }));
    const consumerPackages: string[] = [];
    for (const file of files) {
      if (!file.path.endsWith("Cargo.toml")) continue;
      const manifest = Bun.TOML.parse(file.text) as { package?: { name?: unknown } };
      if (typeof manifest.package?.name === "string") consumerPackages.push(manifest.package.name);
    }
    for (const file of files) assertNoLocalDependencies(name, file.path, file.text, { nodePackages, consumerPackages });
  }
  for (const path of npmFiles(root)) {
    const local = relative(root, path);
    assertNoLocalDependencies(local.split("/")[0], local.split("/").slice(1).join("/"), readFileSync(path, "utf8"));
  }
}

function resolveNpm(root: string, version: string | undefined, evidence: Record<string, string>, runner: Runner): void {
  for (const item of npmRoots(root)) {
    const flags = item.standalone ? ["--ignore-workspace"] : [];
    const result = runner(["corepack", "pnpm", ...PNPM_LOCK_ONLY_ARGS, ...flags], item.path, packEnvironment());
    if (result.code !== 0) fail(`${item.path}: pnpm lock resolution failed: ${result.err.trim()}`);
    const checks = item.consumers.flatMap(consumer => consumer.packages.map(name => {
      const manifest = join(root, consumer.repo, consumer.manifest);
      const spec = version || localSpec(root, manifest, name);
      return { importer: item.standalone ? "." : consumer.importer, name, version: spec, integrity: evidence[name], spec,
        directory: relative(item.path, resolve(dirname(manifest), spec.slice(5))) };
    }));
    const text = readFileSync(join(item.path, "pnpm-lock.yaml"), "utf8");
    if (version) assertPnpmLockfile(text, checks);
    else assertLocalPnpmLock(text, checks);
  }
  const account = join(root, "psy-dapp/apps/account");
  const result = runner(["bun", "install", "--lockfile-only", "--ignore-scripts", `--registry=${NPM_REGISTRY}`], account, packEnvironment());
  if (result.code !== 0) fail(`account Bun lock resolution failed: ${result.err.trim()}`);
  const specs: Record<string, string> = {};
  for (const name of CONSUMERS[1].packages) specs[name] = version || localSpec(root, join(account, "package.json"), name);
  assertBunLock(readFileSync(join(account, "bun.lock"), "utf8"), specs, evidence);
  if (version) for (const path of npmFiles(root)) assertNoLocalDependencies(path.includes("/psy-wallet/") ? "psy-wallet" : "psy-dapp", relative(root, path).split("/").slice(1).join("/"), readFileSync(path, "utf8"));
}

function activateConsumers(root: string, runner: Runner): void {
  // Force is explicit and limited to the two active consumer install roots.
  // Account's standalone lock is compatibility evidence, not a second install.
  for (const name of ["psy-wallet", "psy-dapp"]) {
    const result = runner(["corepack", "pnpm", "install", "--force", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"], join(root, name), packEnvironment());
    if (result.code !== 0) fail(`${name}: activation failed; partial installation retained: ${result.err.trim()}`);
  }
  for (const item of CONSUMERS) {
    const consumer = dirname(join(root, item.repo, item.manifest));
    const manifest = readJson(join(consumer, "package.json"));
    for (const name of item.packages) {
      const spec = dependencySpec(manifest.dependencies?.[name]);
      const installed = join(consumer, "node_modules", name);
      if (!existsSync(join(installed, "package.json"))) fail(`${item.manifest}: ${name} was not activated`);
      if (!spec.startsWith("file:")) {
        if (readJson(join(installed, "package.json")).version !== spec) fail(`${item.manifest}: installed ${name} is not ${spec}`);
        continue;
      }
      const source = resolve(consumer, spec.slice(5));
      const sourceManifest = readJson(join(source, "package.json"));
      const paths = [...new Bun.Glob("dist/**/*").scanSync({ cwd: source, onlyFiles: true, followSymlinks: false })];
      const entrypoints = declaredPaths({ ...sourceManifest, files: undefined });
      const files = paths.filter(path => entrypoints.some(spec => entrySatisfies([{ name: `package/${path}`, type: "0" }], spec)));
      if (Array.isArray(sourceManifest.files) && sourceManifest.files.includes(".compiler-artifact.json")) files.push(".compiler-artifact.json");
      const installedManifest = readJson(join(installed, "package.json"));
      if (installedManifest.name !== name || installedManifest.version !== sourceManifest.version) fail(`${item.manifest}: installed local package identity differs`);
      for (const spec of entrypoints) if (!entrySatisfies(files.map(path => ({ name: `package/${path}`, type: "0" })), spec)) fail(`${item.manifest}: missing local entrypoint ${spec}`);
      for (const path of files) if (!existsSync(join(installed, path)) || !readFileSync(join(source, path)).equals(readFileSync(join(installed, path)))) fail(`${item.manifest}: stale local ${name}/${path} after pnpm force; installation retained`);
    }
  }
}

function prebuiltLocalPackages(root: string): void {
  const sdk = join(root, "psy-sdk/psy-ts-sdk");
  const manifests = SDK_PACKAGES.filter(item => ["@psy-protocol/psy-sdk", "@psy-protocol/evm-wallet"].includes(item.name)).map(item => {
    const directory = join(sdk, item.dir);
    const manifest = readJson(join(directory, "package.json"));
    if (manifest.name !== item.name || !manifest.version || !VERSION.test(manifest.version)) fail(`${item.name}: invalid source package`);
    const paths = [...new Bun.Glob("dist/**/*").scanSync({ cwd: directory, onlyFiles: true, followSymlinks: false })];
    if (existsSync(join(directory, ".compiler-artifact.json"))) paths.push(".compiler-artifact.json");
    const entries = paths.map(path => ({ name: `package/${path}`, type: "0" }));
    for (const path of declaredPaths(manifest)) if (!entrySatisfies(entries, path)) fail(`${item.name}: missing prebuilt ${path}; build explicitly before local activation`);
    return manifest;
  });
  assertEvmSdkPeer(manifests[0].version!, manifests[1].peerDependencies?.["@psy-protocol/psy-sdk"]);
}

export function switchLocal(root: string, apply: boolean, install = false, runner: Runner = runCommand): string[] {
  if (install && !apply) fail("--install requires --apply");
  const snapshot = mutationSnapshot(root, [...cargoFiles(root), ...npmFiles(root)]);
  const crates = nodeCratePaths(repository(root, "psy-node"));
  prebuiltLocalPackages(root);
  const cargo = CARGO_REPOS.map(name => {
    const repo = join(root, name);
    const path = join(repo, "Cargo.toml");
    const text = readFileSync(path, "utf8");
    return { repo, path, text: rewriteNodeDependencies(text, repo, crates), packages: nodeDependencies(text).map(dep => dep.package), sources: nodeDependencies(text).map(dep => dep.value.path ? "local" : dep.value.rev) };
  });
  if (new Set(cargo.flatMap(item => item.sources)).size !== 1) fail("mixed node dependency graph across consumers");
  const npm = CONSUMERS.map(item => {
    const path = join(root, item.repo, item.manifest);
    const specs: Record<string, string> = {};
    for (const name of item.packages) specs[name] = localSpec(root, path, name);
    return { path, text: replaceDirectDependencies(readFileSync(path, "utf8"), specs, path) };
  });
  const paths = [...cargo, ...npm].map(item => relative(root, item.path));
  if (!apply) {
    console.warn("preview only: no manifests, locks or installations changed; inactive bridge legacy lock will remain unchanged");
    return paths;
  }
  preflightNpm(root, runner);
  for (const item of cargo) if (runner(["cargo", "--version"], item.repo).code !== 0) fail(`${item.repo}: Cargo unavailable`);
  snapshot();
  try {
    for (const item of [...cargo, ...npm]) writeFileSync(item.path, item.text);
    for (const item of cargo) {
      const result = runner(["cargo", "metadata", "--format-version", "1"], item.repo);
      if (result.code !== 0) fail(`${item.repo}: Cargo resolution failed: ${result.err.trim()}`);
      const locked = runner(["cargo", "metadata", "--format-version", "1", "--locked"], item.repo);
      if (locked.code !== 0) fail(`${item.repo}: locked Cargo validation failed: ${locked.err.trim()}`);
      assertLocalCargoGraph(locked.out, readFileSync(join(item.repo, "Cargo.lock"), "utf8"), crates, item.packages, true);
    }
    resolveNpm(root, undefined, {}, runner);
    if (install) activateConsumers(root, runner);
  } catch (error) {
    fail(`partial local update; all changed files and installations remain, no reset. ${error instanceof Error ? error.message : error}`);
  }
  return paths;
}

export function guardSquashPins(input: {
  source: PinSnapshot[];
  base: PinSnapshot[];
  nodeOriginBase: string;
  topicNodeCommits?: string[];
  isOnNodeOrigin: (rev: string) => boolean;
}): { unchanged: { repo: string; crate: string; rev: string }[] } {
  if (!SHA.test(input.nodeOriginBase)) fail("node origin base must be a full commit SHA");
  const topic: Record<string, true> = {};
  for (const rev of input.topicNodeCommits || []) {
    if (!SHA.test(rev)) fail("topic node commit must be a full SHA");
    topic[rev] = true;
  }
  const unchanged: { repo: string; crate: string; rev: string }[] = [];
  for (const sourceRepo of input.source) {
    const baseRepo = input.base.find(item => item.repo === sourceRepo.repo);
    if (!baseRepo) fail(`${sourceRepo.repo}: missing base pin snapshot`);
    const basePins: Record<string, string> = {};
    const sourcePins: Record<string, string> = {};
    for (const pin of baseRepo.pins) basePins[pin.crate] = pin.rev;
    for (const pin of sourceRepo.pins) sourcePins[pin.crate] = pin.rev;
    for (const [crate, rev] of Object.entries(sourcePins)) {
      if (!SHA.test(rev)) fail(`${sourceRepo.repo}:${crate} is not a full SHA`);
      if (basePins[crate] === rev) {
        if (topic[rev]) fail(`${sourceRepo.repo}:${crate} retains topic-only node pin ${rev}. ${TWO_PASS}`);
        unchanged.push({ repo: sourceRepo.repo, crate, rev });
        continue;
      }
      if (!input.isOnNodeOrigin(rev)) fail(`${sourceRepo.repo}:${crate} introduces unpublished pin ${rev}. ${TWO_PASS}`);
    }
  }
  return { unchanged };
}

export function inconsistent(report: ReleaseReport): boolean {
  const revs = report.cargo.flatMap(item => item.revs);
  const account = report.consumers.find(item => item.path.endsWith("apps/account/package.json"));
  const paired = account ? Object.values(account.specs) : [];
  return report.cargo.some(item => item.revs.length !== 1) || new Set(revs).size !== 1
    || report.packages.some(item => !VERSION.test(item.version)) || new Set(report.packages.map(item => item.version)).size !== 1
    || report.consumers.some(item => Object.values(item.specs).some(value => !VERSION.test(value)))
    || new Set(paired).size > 1
    || report.discrepancies.length > 0
    || report.tools.some(item => item.error);
}

