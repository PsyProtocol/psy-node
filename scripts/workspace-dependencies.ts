import { readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

type Table = Record<string, any>;
const nodeUrl = (url: unknown): boolean => typeof url === "string" && /^https:\/\/github\.com\/PsyProtocol\/psy-node(?:\.git)?\/?$/i.test(url);
const localNode = (path: unknown): boolean => typeof path === "string" && /(?:^|[/\\])psy-node(?:[/\\]|$)/.test(path);
const sections = ["dependencies", "dev-dependencies", "build-dependencies"];
export type NodeDependency = { table: string; key: string; package: string; value: Table };

export function nodeDependencies(text: string): NodeDependency[] {
  const manifest = Bun.TOML.parse(text) as Table;
  const found: NodeDependency[] = [];
  const visit = (value: Table, path: string[]): void => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return;
    if (path[0] === "patch") return;
    if (nodeUrl(value.git) || localNode(value.path)) {
      const table = path.slice(0, -1).join(".");
      if (!(sections.includes(table) || table === "workspace.dependencies")) throw new Error(`unsupported node dependency location ${path.join(".")}`);
      const key = path.at(-1)!;
      found.push({ table, key, package: value.package ?? key, value });
      return;
    }
    for (const [key, child] of Object.entries(value)) visit(child as Table, [...path, key]);
  };
  visit(manifest, []);
  return found;
}

export function nodeCratePaths(node: string, read: (path: string, encoding: "utf8") => string = readFileSync, real: (path: string) => string = realpathSync): Map<string, string> {
  const manifest = Bun.TOML.parse(read(join(node, "Cargo.toml"), "utf8")) as Table;
  const directories = new Set<string>(manifest.workspace?.members ?? []);
  for (const value of Object.values(manifest.workspace?.dependencies ?? {}) as Table[]) if (typeof value.path === "string") directories.add(value.path);
  const packages = new Map<string, string>();
  for (const directory of directories) {
    const path = real(resolve(node, directory));
    if (relative(real(node), path).startsWith("..")) throw new Error(`crate escapes sibling node: ${directory}`);
    const crate = Bun.TOML.parse(read(join(path, "Cargo.toml"), "utf8")) as Table;
    if (typeof crate.package?.name !== "string") throw new Error(`${directory}: not a concrete crate`);
    const prior = packages.get(crate.package.name);
    if (prior && prior !== path) throw new Error(`duplicate crate ${crate.package.name}`);
    packages.set(crate.package.name, path);
  }
  return packages;
}

export function rewriteNodeDependencies(text: string, repo: string, crates: Map<string, string>, revision?: string): string {
  if (revision && !/^[0-9a-f]{40}$/.test(revision)) throw new Error("revision must be a full SHA");
  const dependencies = nodeDependencies(text);
  if (!dependencies.length) throw new Error(`${repo}: no node dependencies`);
  const sources = new Set(dependencies.map(dep => dep.value.path ? "local" : dep.value.rev));
  if (sources.size !== 1) throw new Error(`${repo}: mixed node dependency graph`);
  let next = text;
  for (const dep of dependencies) {
    const crate = crates.get(dep.package);
    if (!crate) throw new Error(`${dep.package}: no concrete sibling crate`);
    if (dep.value.path && realpathSync(resolve(repo, dep.value.path)) !== crate) throw new Error(`${dep.key}: local path is not its sibling package`);
    if (dep.value.branch || dep.value.tag || (!dep.value.path && !/^[0-9a-f]{40}$/.test(dep.value.rev))) throw new Error(`${dep.key}: a full node revision is required`);
    const escaped = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`(^\\[${escaped(dep.table)}\\][\\s\\S]*?^\\s*${escaped(dep.key)}\\s*=\\s*\\{)([^}\\n]*)(\\})`, "m");
    const match = pattern.exec(next);
    if (!match) throw new Error(`${dep.key}: unsupported dependency formatting`);
    const properties = match[2].split(/,(?=(?:[^"\[\]]|"[^"]*"|\[[^\]]*\])*$)/).filter(part => !/^\s*(git|rev|path)\s*=/.test(part)).map(part => part.trim()).filter(Boolean);
    const url = dep.value.git ?? (repo.endsWith("psy-compiler") ? "https://github.com/PsyProtocol/psy-node.git" : "https://github.com/PsyProtocol/psy-node");
    const source = revision ? `git = ${JSON.stringify(url)}, rev = "${revision}"` : `path = ${JSON.stringify(relative(repo, crate))}`;
    next = next.replace(pattern, (_all, start, _body, end) => `${start} ${[source, ...properties].join(", ")} ${end}`);
  }
  const after = nodeDependencies(next);
  if (after.length !== dependencies.length) throw new Error("node dependency set changed");
  for (let i = 0; i < after.length; i++) {
    const strip = (value: Table): Table => Object.fromEntries(Object.entries(value).filter(([key]) => !["git", "rev", "path"].includes(key)));
    if (JSON.stringify(strip(after[i].value)) !== JSON.stringify(strip(dependencies[i].value))) throw new Error("node dependency options changed");
  }
  return next;
}

export function assertLocalCargoGraph(metadataText: string, lockText: string, crates: Map<string, string>, expected: string[], local: boolean): string[] {
  const metadata = JSON.parse(metadataText) as Table;
  const nodes = new Set((metadata.resolve?.nodes ?? []).map((node: Table) => node.id));
  if (!nodes.size || !Array.isArray(metadata.packages)) throw new Error("Cargo metadata has no resolved graph");
  for (const node of metadata.resolve.nodes) for (const edge of node.deps ?? []) if (!nodes.has(edge.pkg)) throw new Error("Cargo resolve edge missing");
  const found = new Set<string>();
  for (const pkg of metadata.packages) {
    if (!crates.has(pkg.name)) continue;
    if (!nodes.has(pkg.id)) throw new Error(`${pkg.name}: package missing from resolve graph`);
    if (local) {
      if (pkg.source || realpathSync(dirname(pkg.manifest_path)) !== crates.get(pkg.name)) throw new Error(`${pkg.name}: mixed local/remote node graph`);
    } else if (!pkg.source || !nodeUrl(String(pkg.source).replace(/^git\+/, "").split("?")[0].split("#")[0])) throw new Error(`${pkg.name}: mixed local/remote node graph`);
    found.add(pkg.name);
  }
  for (const name of expected) if (!found.has(name)) throw new Error(`${name}: expected node package missing`);
  const lock = Bun.TOML.parse(lockText) as Table;
  for (const pkg of lock.package ?? []) {
    if (local && typeof pkg.source === "string" && /github\.com\/PsyProtocol\/psy-node/i.test(pkg.source)) throw new Error("Cargo.lock retains a remote node package");
    if (crates.has(pkg.name) && local && pkg.source) throw new Error(`${pkg.name}: lock retains nonlocal node package`);
    if (crates.has(pkg.name) && !local && !pkg.source) throw new Error(`${pkg.name}: lock retains local node package`);
  }
  return [...found].sort();
}

// Bun 1.3.14 exposes JSON5.parse; fail explicitly on older runtimes rather than
// stripping comments/commas with a regex that can corrupt string contents.
export function parseBunLock(text: string): Table {
  if (!("JSON5" in Bun) || !Bun.JSON5 || typeof Bun.JSON5 !== "object" || !("parse" in Bun.JSON5) || typeof Bun.JSON5.parse !== "function") throw new Error("Bun.JSON5.parse is required for bun.lock (use Bun 1.3.14 or newer)");
  return Bun.JSON5.parse(text) as Table;
}

export type CargoGuardContext = { nodePackages: readonly string[]; consumerPackages: readonly string[] };

export function assertNoLocalDependencies(repoName: string, path: string, text: string, cargo?: CargoGuardContext): void {
  const cargoConsumer = ["psy-compiler", "psy-sdk", "psy-services"].includes(repoName);
  if (cargoConsumer && /(?:^|\/)Cargo\.lock$/.test(path)) {
    if (!cargo) throw new Error(`${repoName}/${path}: node and consumer package identities are required to inspect Cargo.lock`);
    const lock = Bun.TOML.parse(text) as Table;
    if (!Array.isArray(lock.package)) throw new Error(`${repoName}/${path}: Cargo.lock has no package records`);
    for (const pkg of lock.package) {
      if (!pkg || typeof pkg !== "object" || typeof pkg.name !== "string") throw new Error(`${repoName}/${path}: invalid Cargo package record`);
      if (pkg.source == null && cargo.nodePackages.includes(pkg.name) && !cargo.consumerPackages.includes(pkg.name)) throw new Error(`${repoName}/${path}: local node lock package ${pkg.name}; resolve a published revision before publication`);
    }
    return;
  }
  if (cargoConsumer && /(?:^|\/)Cargo\.toml$/.test(path)) {
    const manifest = Bun.TOML.parse(text) as Table;
    const containsLocal = (value: unknown): boolean => {
      if (!value || typeof value !== "object") return false;
      if ("path" in value && localNode(value.path)) return true;
      return Object.values(value).some(containsLocal);
    };
    if (containsLocal(manifest)) throw new Error(`${repoName}/${path}: local node dependency; run node-rev with a published revision before publication`);
    return;
  }
  if (!["psy-wallet", "psy-dapp"].includes(repoName)) return;
  if (!/(?:^|\/)(?:package\.json|pnpm-lock\.yaml|bun\.lock)$/.test(path)) return;
  const document = path.endsWith(".yaml") ? Bun.YAML.parse(text) : path.endsWith("bun.lock") ? parseBunLock(text) : JSON.parse(text);
  const visit = (value: unknown, key = ""): void => {
    if (typeof value === "string" && ((key.startsWith("@psy-protocol/") && /^(file:|link:|workspace:)/.test(value)) || /(?:file:|link:).*psy-sdk\/psy-ts-sdk/.test(value))) throw new Error(`${repoName}/${path}: local SDK dependency; run consumers with a published version before publication`);
    if (key.startsWith("@psy-protocol/") && /(?:file:|link:)/.test(key)) throw new Error(`${repoName}/${path}: local SDK lock entry`);
    if (Array.isArray(value)) value.forEach(child => visit(child, key));
    else if (value && typeof value === "object") for (const [childKey, child] of Object.entries(value)) visit(child, childKey.startsWith("@psy-protocol/") ? childKey : key);
  };
  visit(document);
}
