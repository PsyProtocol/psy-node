import { afterEach, describe, expect, it } from "bun:test";
import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WORKSPACE_REPOS } from "./workspace-create";
import { applyPreparation, type PreparePlan, type PrepareResult, type Runner, type RunResult } from "./workspace-operations";

const script = join(import.meta.dir, "workspace.ts");
const identity = ["-c", "user.name=Workspace Test", "-c", "user.email=workspace@example.invalid"];
const disposables: string[] = [];
function disposable(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  disposables.push(dir);
  return dir;
}
afterEach(() => { while (disposables.length) rmSync(disposables.pop()!, { recursive: true, force: true }); });

// Fixture setup is local-only; publication uses the deny-by-default simulator below.
const realGit = Bun.which("git")!;
function localEnvironment(home: string): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0", GIT_ALLOW_PROTOCOL: "file", GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.hooksPath", GIT_CONFIG_VALUE_0: "/dev/null" };
}
function git(repo: string, args: string[]): string {
  if (args.includes("push") || args.includes("ls-remote")) throw new Error("Real publication/remote queries are forbidden in fixtures");
  const result = spawnSync(realGit, ["-C", repo, ...args], { encoding: "utf8", env: localEnvironment(repo) });
  if (result.status !== 0) throw new Error(`${args.join(" ")}\n${result.stderr}`);
  return result.stdout.trim();
}

function commit(repo: string, message: string): string {
  git(repo, [...identity, "commit", "--allow-empty", "-m", message]);
  return git(repo, ["rev-parse", "HEAD"]);
}

function pin(repo: string, path: string, sha: string, gitmodules: string): void {
  writeFileSync(join(repo, ".gitmodules"), gitmodules);
  git(repo, ["add", ".gitmodules"]);
  git(repo, ["update-index", "--add", "--cacheinfo", `160000,${sha},${path}`]);
  git(repo, [...identity, "commit", "-m", `pin ${path}`]);
}

function cohort(root: string): Record<string, string> {
  const repos: Record<string, string> = {};
  for (const name of WORKSPACE_REPOS) {
    const repo = join(root, name);
    mkdirSync(repo);
    git(repo, ["init", "-q", "-b", "mainnet-beta"]);
    repos[name] = repo;
  }
  return repos;
}

function workspace(command: string[], env = localEnvironment(tmpdir())): SpawnSyncReturns<string> {
  const result = spawnSync(process.execPath, [script, ...command], { encoding: "utf8", env });
  return result;
}

describe("nested gitlink sync", () => {
  it("rejects a drifted nested HEAD before writing any index", () => {
    const root = disposable("workspace-sync-");
    const repos = cohort(root);
    const base = commit(repos["psy-genesis"], "genesis base");
    git(repos["psy-genesis"], ["switch", "-c", "feature/demo"]);
    const next = commit(repos["psy-genesis"], "genesis topic");
    for (const name of WORKSPACE_REPOS) {
      if (name === "psy-genesis") continue;
      commit(repos[name], `${name} base`);
      git(repos[name], ["switch", "-c", "feature/demo"]);
    }
    pin(repos["psy-node"], "psy-genesis", base, '[submodule "psy-genesis"]\n\tpath = psy-genesis\n\turl = https://example.invalid/psy-genesis.git\n');
    const recorded = git(repos["psy-node"], ["rev-parse", "HEAD"]);
    git(repos["psy-node"], ["clone", "-q", repos["psy-genesis"], "psy-genesis"]);
    git(join(repos["psy-node"], "psy-genesis"), ["checkout", "-q", next]);
    const checkouts = [...Object.values(repos), join(repos["psy-node"], "psy-genesis")];
    const indexesBefore = checkouts.map(repo => git(repo, ["ls-files", "-s"]));

    const result = workspace(["gitlinks", "sync", "--source", root]);

    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("differs from recorded gitlink");
    expect(checkouts.map(repo => git(repo, ["ls-files", "-s"]))).toEqual(indexesBefore);
    expect(git(repos["psy-node"], ["rev-parse", "HEAD"])).toBe(recorded);

  });

  it("stages the parent and materializes its recorded child without moving an external gitlink", () => {
    const root = disposable("workspace-sync-");
    const repos = cohort(root);
    commit(repos["psy-genesis"], "genesis base");
    const forge = disposable("workspace-forge-");
    git(forge, ["init", "-q", "-b", "main"]);
    const forgeBase = commit(forge, "forge base");
    pin(repos["psy-contracts"], "lib/forge-std", forgeBase, '[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://example.invalid/forge-std\n');
    mkdirSync(join(repos["psy-contracts"], "lib"), { recursive: true });
    git(repos["psy-contracts"], ["clone", "-q", forge, "lib/forge-std"]);
    const contractsBase = git(repos["psy-contracts"], ["rev-parse", "HEAD"]);
    pin(repos["psy-dapp"], "psy-contracts", contractsBase, '[submodule "psy-contracts"]\n\tpath = psy-contracts\n\turl = https://example.invalid/psy-contracts.git\n');
    const dappBase = git(repos["psy-dapp"], ["rev-parse", "HEAD"]);
    for (const name of WORKSPACE_REPOS) {
      if (["psy-genesis", "psy-contracts", "psy-dapp"].includes(name)) continue;
      commit(repos[name], `${name} base`);
    }
    pin(repos["psy-node"], "psy-dapp", dappBase, '[submodule "psy-dapp"]\n\tpath = psy-dapp\n\turl = https://example.invalid/psy-dapp.git\n\tupdate = none\n');
    for (const name of WORKSPACE_REPOS) git(repos[name], ["switch", "-c", "feature/demo"]);
    commit(repos["psy-genesis"], "genesis topic");
    writeFileSync(join(repos["psy-contracts"], "topic.txt"), "topic");
    git(repos["psy-contracts"], ["add", "topic.txt"]);
    git(repos["psy-contracts"], [...identity, "commit", "-m", "contracts topic"]);
    const contractsNext = git(repos["psy-contracts"], ["rev-parse", "HEAD"]);
    git(repos["psy-dapp"], ["update-index", "--cacheinfo", `160000,${contractsNext},psy-contracts`]);
    git(repos["psy-dapp"], [...identity, "commit", "-m", "dapp topic"]);
    const dappNext = git(repos["psy-dapp"], ["rev-parse", "HEAD"]);
    git(repos["psy-dapp"], ["clone", "-q", repos["psy-contracts"], "psy-contracts"]);
    git(join(repos["psy-dapp"], "psy-contracts"), ["checkout", "-q", contractsNext]);
    mkdirSync(join(repos["psy-dapp"], "psy-contracts/lib"), { recursive: true });
    git(join(repos["psy-dapp"], "psy-contracts"), ["clone", "-q", forge, "lib/forge-std"]);
    git(join(repos["psy-dapp"], "psy-contracts/lib/forge-std"), ["checkout", "-q", forgeBase]);
    git(repos["psy-node"], ["clone", "-q", repos["psy-dapp"], "psy-dapp"]);
    git(join(repos["psy-node"], "psy-dapp"), ["checkout", "-q", dappBase]);
    git(join(repos["psy-node"], "psy-dapp"), ["clone", "-q", repos["psy-contracts"], "psy-contracts"]);
    git(join(repos["psy-node"], "psy-dapp/psy-contracts"), ["checkout", "-q", contractsBase]);
    mkdirSync(join(repos["psy-node"], "psy-dapp/psy-contracts/lib"), { recursive: true });
    git(join(repos["psy-node"], "psy-dapp/psy-contracts"), ["clone", "-q", forge, "lib/forge-std"]);
    git(join(repos["psy-node"], "psy-dapp/psy-contracts/lib/forge-std"), ["checkout", "-q", forgeBase]);
    for (const repo of [repos["psy-contracts"], repos["psy-dapp"], repos["psy-node"], join(repos["psy-dapp"], "psy-contracts"), join(repos["psy-node"], "psy-dapp"), join(repos["psy-node"], "psy-dapp/psy-contracts")]) git(repo, ["submodule", "init"]);

    const result = workspace(["gitlinks", "sync", "--source", root]);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(git(repos["psy-node"], ["rev-parse", ":psy-dapp"])).toBe(dappNext);
    expect(git(join(repos["psy-node"], "psy-dapp"), ["rev-parse", "HEAD"])).toBe(dappNext);
    expect(git(join(repos["psy-node"], "psy-dapp/psy-contracts"), ["rev-parse", "HEAD"])).toBe(contractsNext);
    expect(git(join(repos["psy-node"], "psy-dapp/psy-contracts/lib/forge-std"), ["rev-parse", "HEAD"])).toBe(forgeBase);
    expect(git(join(repos["psy-node"], "psy-dapp"), ["status", "--porcelain", "--ignore-submodules=none"])).toBe("");
    for (const name of ["psy-contracts", "psy-dapp"]) expect(git(repos[name], ["status", "--porcelain", "--ignore-submodules=none"])).toBe("");

  });

  it("rejects a direct target external gitlink change before any index write", () => {
    const root = disposable("workspace-sync-");
    const repos = cohort(root);
    const forge = disposable("workspace-forge-");
    git(forge, ["init", "-q", "-b", "main"]);
    const forgeBase = commit(forge, "forge base");
    pin(repos["psy-contracts"], "lib/forge-std", forgeBase, '[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://example.invalid/forge-std\n');
    const contractsBase = git(repos["psy-contracts"], ["rev-parse", "HEAD"]);
    for (const name of WORKSPACE_REPOS) if (name !== "psy-contracts") commit(repos[name], `${name} base`);
    pin(repos["psy-dapp"], "psy-contracts", contractsBase, '[submodule "psy-contracts"]\n\tpath = psy-contracts\n\turl = https://example.invalid/psy-contracts.git\n');
    for (const name of WORKSPACE_REPOS) git(repos[name], ["switch", "-c", "feature/demo"]);
    git(repos["psy-dapp"], ["clone", "-q", repos["psy-contracts"], "psy-contracts"]);
    const nested = join(repos["psy-dapp"], "psy-contracts");
    for (const repo of [repos["psy-contracts"], nested]) {
      mkdirSync(join(repo, "lib"), { recursive: true });
      git(repo, ["clone", "-q", forge, "lib/forge-std"]);
      git(repo, ["submodule", "init"]);
    }
    git(repos["psy-dapp"], ["submodule", "init"]);
    const forgeNext = commit(forge, "forge topic");
    git(join(repos["psy-contracts"], "lib/forge-std"), ["fetch", "--no-recurse-submodules", forge, forgeNext]);
    git(join(repos["psy-contracts"], "lib/forge-std"), ["checkout", "-q", forgeNext]);
    git(repos["psy-contracts"], ["add", "lib/forge-std"]);
    commit(repos["psy-contracts"], "advance forge");
    const checkouts = [...Object.values(repos), nested, join(nested, "lib/forge-std"), join(repos["psy-contracts"], "lib/forge-std")];
    const indexesBefore = checkouts.map(repo => git(repo, ["ls-files", "-s"]));
    const result = workspace(["gitlinks", "sync", "--source", root]);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("external gitlink");
    expect(checkouts.map(repo => git(repo, ["ls-files", "-s"]))).toEqual(indexesBefore);
    expect(git(nested, ["rev-parse", "HEAD"])).toBe(contractsBase);
    expect(git(join(nested, "lib/forge-std"), ["rev-parse", "HEAD"])).toBe(forgeBase);
  });

  it("rejects a changed external child gitlink before writing an index", () => {
    const root = disposable("workspace-sync-");
    const repos = cohort(root);
    commit(repos["psy-genesis"], "genesis base");
    const forge = disposable("workspace-forge-");
    git(forge, ["init", "-q", "-b", "main"]);
    const forgeBase = commit(forge, "forge base");
    pin(repos["psy-contracts"], "lib/forge-std", forgeBase, '[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://example.invalid/forge-std\n');
    const contractsBase = git(repos["psy-contracts"], ["rev-parse", "HEAD"]);
    pin(repos["psy-dapp"], "psy-contracts", contractsBase, '[submodule "psy-contracts"]\n\tpath = psy-contracts\n\turl = https://example.invalid/psy-contracts.git\n');
    const dappBase = git(repos["psy-dapp"], ["rev-parse", "HEAD"]);
    for (const name of WORKSPACE_REPOS) if (!["psy-genesis", "psy-contracts", "psy-dapp"].includes(name)) commit(repos[name], `${name} base`);
    pin(repos["psy-node"], "psy-dapp", dappBase, '[submodule "psy-dapp"]\n\tpath = psy-dapp\n\turl = https://example.invalid/psy-dapp.git\n');
    for (const name of WORKSPACE_REPOS) git(repos[name], ["switch", "-c", "feature/demo"]);
    const forgeNext = commit(forge, "forge topic");
    git(repos["psy-contracts"], ["update-index", "--cacheinfo", `160000,${forgeNext},lib/forge-std`]);
    git(repos["psy-contracts"], [...identity, "commit", "-m", "advance forge"]);
    const contractsNext = git(repos["psy-contracts"], ["rev-parse", "HEAD"]);
    mkdirSync(join(repos["psy-contracts"], "lib"), { recursive: true });
    git(repos["psy-contracts"], ["clone", "-q", forge, "lib/forge-std"]);
    git(repos["psy-dapp"], ["update-index", "--cacheinfo", `160000,${contractsNext},psy-contracts`]);
    git(repos["psy-dapp"], [...identity, "commit", "-m", "dapp topic"]);
    git(repos["psy-dapp"], ["clone", "-q", repos["psy-contracts"], "psy-contracts"]);
    git(join(repos["psy-dapp"], "psy-contracts"), ["checkout", "-q", contractsNext]);
    mkdirSync(join(repos["psy-dapp"], "psy-contracts/lib"), { recursive: true });
    git(join(repos["psy-dapp"], "psy-contracts"), ["clone", "-q", forge, "lib/forge-std"]);
    git(join(repos["psy-dapp"], "psy-contracts/lib/forge-std"), ["checkout", "-q", forgeNext]);
    git(repos["psy-node"], ["clone", "-q", repos["psy-dapp"], "psy-dapp"]);
    git(join(repos["psy-node"], "psy-dapp"), ["checkout", "-q", dappBase]);
    git(join(repos["psy-node"], "psy-dapp"), ["clone", "-q", repos["psy-contracts"], "psy-contracts"]);
    git(join(repos["psy-node"], "psy-dapp/psy-contracts"), ["checkout", "-q", contractsBase]);
    mkdirSync(join(repos["psy-node"], "psy-dapp/psy-contracts/lib"), { recursive: true });
    git(join(repos["psy-node"], "psy-dapp/psy-contracts"), ["clone", "-q", forge, "lib/forge-std"]);
    git(join(repos["psy-node"], "psy-dapp/psy-contracts/lib/forge-std"), ["checkout", "-q", forgeBase]);
    for (const repo of [repos["psy-contracts"], repos["psy-dapp"], repos["psy-node"], join(repos["psy-dapp"], "psy-contracts"), join(repos["psy-node"], "psy-dapp"), join(repos["psy-node"], "psy-dapp/psy-contracts")]) git(repo, ["submodule", "init"]);
    const checkouts = [...Object.values(repos), join(repos["psy-dapp"], "psy-contracts"), join(repos["psy-dapp"], "psy-contracts/lib/forge-std"), join(repos["psy-node"], "psy-dapp"), join(repos["psy-node"], "psy-dapp/psy-contracts"), join(repos["psy-node"], "psy-dapp/psy-contracts/lib/forge-std"), join(repos["psy-contracts"], "lib/forge-std")];
    const indexesBefore = checkouts.map(repo => git(repo, ["ls-files", "-s"]));
    const result = workspace(["gitlinks", "sync", "--source", root]);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("external gitlink");
    expect(checkouts.map(repo => git(repo, ["ls-files", "-s"]))).toEqual(indexesBefore);
    expect(git(join(repos["psy-node"], "psy-dapp/psy-contracts/lib/forge-std"), ["rev-parse", "HEAD"])).toBe(forgeBase);
  });
});

describe("workspace creation", () => {
  it("keeps dirty source content unstaged and out of the destination", () => {
    const root = disposable("workspace-create-");
    const source = join(root, "source");
    mkdirSync(source);
    for (const name of WORKSPACE_REPOS) {
      const repo = join(source, name);
      mkdirSync(repo);
      git(repo, ["init", "-q", "-b", "mainnet-beta"]);
      commit(repo, `${name} base`);
    }
    writeFileSync(join(source, "psy-sdk/dirty.txt"), "not committed");
    const destination = join(root, "destination");

    const result = workspace(["create", "--source", source, "--destination", destination, "--branch", "feature/demo"]);

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(git(join(destination, "psy-sdk"), ["status", "--porcelain"])).toBe("");
    expect(git(join(destination, "psy-sdk"), ["branch", "--show-current"])).toBe("feature/demo");
    expect(readFileSync(join(source, "psy-sdk/dirty.txt"), "utf8")).toBe("not committed");
    expect(existsSync(join(destination, "psy-sdk/dirty.txt"))).toBe(false);

  });
});

describe("workspace command parsing", () => {
  it("prints git, dependency, and package commands from one entrypoint", () => {
    const result = workspace(["--help"]);
    expect(result.status).toBe(0);
    for (const command of ["status", "create", "gitlinks sync", "commit", "push", "prepare-merge", "deps show", "deps check", "deps use-local", "deps use-node-commit", "deps use-npm-version", "packages set-version", "packages pack", "packages publish"]) {
      expect(result.stdout).toContain(command);
    }
    expect(result.stdout).toContain("--install requires --apply");
    expect(result.stdout).not.toContain("workspace-release.ts");
  });

  it("rejects unknown commands and cross-group options before touching a workspace", () => {
    for (const command of [["release"], ["sync"], ["merge"], ["deps"], ["gitlinks"], ["deps pinned"], ["packages"], ["deps use-local", "--rev", "abc"], ["deps use-node-commit", "--version", "1.2.3"], ["packages set-version", "--rev", "abc"], ["status", "--apply"], ["deps use-local", "--source", "unused", "--source", "again"]]) {
      const result = workspace(command);
      expect(result.status, command.join(" ")).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`, command.join(" ")).toMatch(/Unknown command|Unexpected or duplicate option/);
    }
  });

  it("requires --source and command values without resolving a workspace", () => {
    for (const command of [["deps check"], ["deps use-local"], ["deps use-node-commit", "--source", "unused"], ["deps use-npm-version", "--source", "unused"], ["packages set-version", "--source", "unused"], ["packages pack", "--source", "unused", "--version", "1.2.3"], ["packages publish", "--source", "unused", "--out", "unused", "--version", "1.2.3"]]) {
      const result = workspace(command);
      expect(result.status, command.join(" ")).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`, command.join(" ")).toContain("is required");
    }
  });

  it("rejects dependency install without apply before reading repositories", () => {
    for (const command of [["deps", "use-local", "--source", "unused", "--install"], ["deps", "use-npm-version", "--source", "unused", "--version", "1.2.3", "--install"]]) {
      const result = workspace(command);
      expect(result.status, command.join(" ")).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`, command.join(" ")).toContain("--install requires --apply");
    }
  });
});

type PublicationEvent = { kind: "READ" | "SIMULATED" | "DENIED"; name: string; args: string[] };

// No transport exists in this fixture. Only enumerated local read-only queries may
// reach real Git; remote reads and publication are state-file simulations.
function publicationFixture() {
  const root = disposable("workspace-reviewed-");
  const repos = cohort(root);
  const expected: Record<string, string> = {};
  const reviewed: Record<string, string> = {};
  for (const name of WORKSPACE_REPOS) {
    expected[name] = commit(repos[name], `${name} expected`);
    reviewed[name] = commit(repos[name], `${name} reviewed`);
  }
  const bin = join(root, "bin");
  mkdirSync(bin);
  const statePath = join(root, "simulation.json");
  const logPath = join(root, "commands.jsonl");
  const executable = join(bin, "git");
  let fixtureAllowed: Record<string, string[][]> = {};
  const state = {
    tips: { ...expected },
    reads: {} as Record<string, number>,
    drift: {} as Record<string, { at: number; sha: string }>,
    failures: {} as Record<string, true>,
    afterPush: {} as Record<string, string>,
    urls: {} as Record<string, string>,
  };
  function install() {
    const previous = fixtureAllowed;
    const allowed: Record<string, string[][]> = {};
    fixtureAllowed = allowed;
    for (const name of WORKSPACE_REPOS) {
      const headSha = git(repos[name], ["rev-parse", "HEAD"]);
      const shas = [...new Set([expected[name], reviewed[name], headSha, ...(previous[repos[name]] || []).flatMap(args => args.filter(arg => /^[0-9a-f]{40}/.test(arg)).map(arg => arg.slice(0, 40)))])];
      const generated = [
        ["rev-parse", "--show-toplevel"],
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        ["check-ref-format", "refs/heads/mainnet-beta"],
        ["rev-parse", "--verify", "HEAD^{commit}"],
        ["rev-parse", "--verify", `${headSha}^{commit}`],
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"],
        ["ls-tree", "-r", "-z", "--name-only", headSha],
        ...shas.flatMap(sha => [
          ["rev-parse", "--verify", `${sha}^{commit}`],
          ["cat-file", "-e", `${sha}^{commit}`],
          ["ls-tree", "-r", "-z", sha],
          ["ls-tree", "-r", "-z", "--name-only", sha],
          ["config", "--blob", `${sha}:.gitmodules`, "--get-regexp", "^submodule\\..*\\.path$"],
          ...[...WORKSPACE_REPOS, "forge-std"].map(child => ["config", "--blob", `${sha}:.gitmodules`, "--get", `submodule.${child}.url`]),
          ...shas.map(other => ["merge-base", "--is-ancestor", sha, other]),
        ]),
      ];
      allowed[repos[name]] = [...generated, ...(previous[repos[name]] || []).filter(extra => !generated.some(args => JSON.stringify(args) === JSON.stringify(extra)))];
    }
    writeFileSync(statePath, JSON.stringify(state));
    writeFileSync(logPath, "");
    writeFileSync(executable, `#!${process.execPath}
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const repos = ${JSON.stringify(repos)};
const allowed = ${JSON.stringify(allowed)};
const targets = ${JSON.stringify(reviewed)};
const heads = ${JSON.stringify(Object.fromEntries(WORKSPACE_REPOS.map(name => [name, git(repos[name], ["rev-parse", "HEAD"])])))};
const statePath = ${JSON.stringify(statePath)};
const logPath = ${JSON.stringify(logPath)};
const argv = process.argv.slice(2);
const repo = argv[1];
const args = argv.slice(2);
const name = Object.keys(repos).find(name => repos[name] === repo) || "UNKNOWN";
const equal = expected => JSON.stringify(args) === JSON.stringify(expected);
const record = kind => appendFileSync(logPath, JSON.stringify({ kind, name, args }) + "\\n");
const deny = () => { record("DENIED"); console.error("DENIED fixture git invocation"); process.exit(97); };
if (argv[0] !== "-C" || name === "UNKNOWN") deny();
const state = JSON.parse(readFileSync(statePath, "utf8"));
const save = () => writeFileSync(statePath, JSON.stringify(state));
if (equal(["remote"])) { record("READ"); console.log("origin"); process.exit(0); }
if (equal(["remote", "get-url", "--all", "origin"]) || equal(["remote", "get-url", "--push", "--all", "origin"])) {
  record("READ"); console.log(state.urls[name] || "git@github.com:PsyProtocol/" + name + ".git"); process.exit(0);
}
if (equal(["ls-remote", "--refs", "origin", "refs/heads/mainnet-beta"])) {
  record("READ");
  state.reads[name] = (state.reads[name] || 0) + 1;
  if (state.drift[name] && state.reads[name] >= state.drift[name].at) state.tips[name] = state.drift[name].sha;
  save(); console.log(state.tips[name] + "\\trefs/heads/mainnet-beta"); process.exit(0);
}
if (args[0] === "-c" && args[1] === "push.followTags=false" && args[2] === "push" && args[3] === "--no-follow-tags" && args[4] === "--recurse-submodules=no" && args[5] === "origin" && (args[6] === targets[name] + ":refs/heads/mainnet-beta" || args[6] === heads[name] + ":refs/heads/mainnet-beta") && args.length === 7) {
  record("SIMULATED");
  if (state.failures[name]) { console.error("simulated publication failure"); process.exit(1); }
  state.tips[name] = state.afterPush[name] || args[6].slice(0, 40); save(); process.exit(0);
}
if (!allowed[repo].some(equal)) deny();
record("READ");
const result = spawnSync(${JSON.stringify(realGit)}, ["-C", repo, ...args], { env: ${JSON.stringify(localEnvironment(root))}, encoding: "utf8" });
process.stdout.write(result.stdout || ""); process.stderr.write(result.stderr || ""); process.exit(result.status ?? 98);
`);
    chmodSync(executable, 0o755);
  }
  const env = { ...localEnvironment(root), PATH: bin };
  function run(names: string[], publish = true, mappings: string[] | null = names) {
    install();
    return workspace([
      "push", "--source", root,
      ...names.flatMap(name => ["--repo", name]),
      ...(mappings === null ? [] : mappings.flatMap(name => ["--reviewed", `${name}=${reviewed[name]}`, "--expected", `${name}=${expected[name]}`])),
      ...(publish ? ["--push"] : []),
    ], env);
  }
  function events(): PublicationEvent[] {
    return readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
  }
  function pushes() { return events().filter(event => event.kind === "SIMULATED"); }
  function tips(): Record<string, string> { return JSON.parse(readFileSync(statePath, "utf8")).tips; }
  function snapshot() {
    return Object.fromEntries(WORKSPACE_REPOS.map(name => [name, {
      head: git(repos[name], ["rev-parse", "HEAD"]),
      refs: git(repos[name], ["show-ref"]),
      index: readFileSync(join(repos[name], ".git/index")),
      status: git(repos[name], ["status", "--porcelain=v1"]),
      staged: git(repos[name], ["diff", "--cached", "--binary"]),
      unstaged: git(repos[name], ["diff", "--binary"]),
      dirty: existsSync(join(repos[name], "dirty.txt")) ? readFileSync(join(repos[name], "dirty.txt"), "utf8") : "",
    }]));
  }
  return { root, repos, expected, reviewed, state, env, install, run, events, pushes, tips, snapshot, executable, allowed: () => fixtureAllowed };
}

describe("reviewed workspace publication (simulated transport only)", () => {
  it("maps distinct frozen commits, completes every preflight, and preserves dirty state", () => {
    const fixture = publicationFixture();
    const names = ["psy-sdk", "psy-compiler"];
    for (const name of WORKSPACE_REPOS) {
      writeFileSync(join(fixture.repos[name], "dirty.txt"), "staged\n");
      git(fixture.repos[name], ["add", "dirty.txt"]);
      writeFileSync(join(fixture.repos[name], "dirty.txt"), "unstaged\n");
      commit(fixture.repos[name], "later unreviewed HEAD");
      git(fixture.repos[name], ["add", "dirty.txt"]);
      writeFileSync(join(fixture.repos[name], "dirty.txt"), "kept\n");
    }
    const before = fixture.snapshot();
    const result = fixture.run(names, true, [...names].reverse());
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(fixture.pushes().map(event => event.name)).toEqual(names);
    for (const event of fixture.pushes()) expect(event.args.at(-1)).toBe(`${fixture.reviewed[event.name]}:refs/heads/mainnet-beta`);
    const events = fixture.events();
    const preflight = events.slice(0, events.findIndex(event => event.kind === "SIMULATED"));
    for (const name of names) expect(preflight.filter(event => event.name === name && event.args[0] === "ls-remote").length).toBeGreaterThanOrEqual(2);
    expect(fixture.snapshot()).toEqual(before);
    expect(events.filter(event => event.kind === "DENIED")).toEqual([]);
  });

  it("orders children before parents and skips an already published child", () => {
    const fixture = publicationFixture();
    const child = "psy-genesis", parent = "psy-node";
    pin(fixture.repos[parent], child, fixture.reviewed[child], `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
    fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
    const result = fixture.run([parent, child]);
    expect(result.status, result.stderr).toBe(0);
    expect(fixture.pushes().map(event => event.name)).toEqual([child, parent]);
    fixture.state.tips[child] = fixture.reviewed[child];
    const skipped = fixture.run([parent, child]);
    expect(skipped.status, skipped.stderr).toBe(0);
    expect(skipped.stdout).toContain(`${child}: target already on remote; nothing to push`);
    expect(fixture.pushes().map(event => event.name)).toEqual([parent]);
  });

  it("preflights unpublished selected pins without fetching or changing dirty state", () => {
    const fixture = publicationFixture();
    const child = "psy-genesis", parent = "psy-node";
    pin(fixture.repos[parent], child, fixture.reviewed[child], `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
    fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
    for (const name of [child, parent]) {
      writeFileSync(join(fixture.repos[name], "dirty.txt"), "staged\n");
      git(fixture.repos[name], ["add", "dirty.txt"]);
      writeFileSync(join(fixture.repos[name], "dirty.txt"), "unstaged\n");
    }
    const before = fixture.snapshot();
    const preview = fixture.run([parent, child], false);
    expect(preview.status, preview.stderr).toBe(0);
    for (const name of [child, parent]) expect(preview.stdout).toContain(`READY[${name}] ${fixture.reviewed[name]}`);
    expect(fixture.pushes()).toEqual([]);
    expect(fixture.tips()).toEqual(fixture.expected);
    expect(fixture.events().filter(event => event.kind === "DENIED" || event.args.includes("fetch"))).toEqual([]);
    expect(fixture.snapshot()).toEqual(before);
    const published = fixture.run([parent, child]);
    expect(published.status, published.stderr).toBe(0);
    expect(fixture.pushes().map(event => event.name)).toEqual([child, parent]);
    const events = fixture.events();
    const preflight = events.slice(0, events.findIndex(event => event.kind === "SIMULATED"));
    for (const name of [parent, child]) expect(preflight.filter(event => event.name === name && event.args[0] === "ls-remote").length).toBeGreaterThanOrEqual(2);
    const childPush = events.findIndex(event => event.kind === "SIMULATED" && event.name === child);
    const parentPush = events.findIndex(event => event.kind === "SIMULATED" && event.name === parent);
    expect(events.slice(childPush + 1, parentPush).some(event => event.name === child && event.args[0] === "ls-remote")).toBe(true);
    expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
    expect(fixture.snapshot()).toEqual(before);
  });

  it("stops before the parent when the selected child fails publication or drifts afterward", () => {
    for (const failure of [true, false]) {
      const fixture = publicationFixture();
      const child = "psy-genesis", parent = "psy-node";
      pin(fixture.repos[parent], child, fixture.reviewed[child], `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
      fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
      if (failure) fixture.state.failures[child] = true;
      else fixture.state.afterPush[child] = fixture.expected[child];
      const before = fixture.snapshot();
      const result = fixture.run([parent, child]);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(failure ? "simulated publication failure" : "child remote changed; publication stopped");
      expect(fixture.pushes().map(event => event.name)).toEqual([child]);
      expect(fixture.tips()[parent]).toBe(fixture.expected[parent]);
      expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
      expect(fixture.snapshot()).toEqual(before);
    }
  });

  it("rejects selected pins beyond the reviewed child and dependency cycles before publication", () => {
    for (const cycle of [false, true]) {
      const fixture = publicationFixture();
      const child = "psy-genesis", parent = "psy-node";
      const childPin = cycle ? fixture.reviewed[child] : commit(fixture.repos[child], "unreviewed child commit");
      pin(fixture.repos[parent], child, childPin, `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
      fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
      if (cycle) {
        pin(fixture.repos[child], parent, fixture.expected[parent], `[submodule "${parent}"]\n\tpath = ${parent}\n\turl = git@github.com:PsyProtocol/${parent}.git\n`);
        fixture.reviewed[child] = git(fixture.repos[child], ["rev-parse", "HEAD"]);
      }
      const result = fixture.run([parent, child]);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(cycle ? "Gitlink dependency cycle" : "not reachable from reviewed child commit");
      expect(fixture.pushes()).toEqual([]);
      expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
    }
  });

  it("accepts a historical pin contained in the selected child's reviewed commit", () => {
    const fixture = publicationFixture();
    const child = "psy-genesis", parent = "psy-node";
    pin(fixture.repos[parent], child, fixture.expected[child], `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
    fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
    const result = fixture.run([parent, child]);
    expect(result.status, result.stderr).toBe(0);
    expect(fixture.pushes().map(event => event.name)).toEqual([child, parent]);
    expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
  });

  it("rejects a selected child downgrade before any simulated publication", () => {
    const fixture = publicationFixture();
    const child = "psy-genesis", parent = "psy-node";
    pin(fixture.repos[parent], child, fixture.reviewed[child], `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
    fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
    fixture.expected[child] = commit(fixture.repos[child], "newer published child");
    fixture.state.tips[child] = fixture.expected[child];
    const result = fixture.run([parent, child]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("expected remote commit is not an ancestor of the reviewed commit");
    expect(fixture.pushes()).toEqual([]);
    expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
  });

  it("rechecks an unselected child's actual published tip before the parent", () => {
    const fixture = publicationFixture();
    const child = "psy-genesis", parent = "psy-node";
    pin(fixture.repos[parent], child, fixture.reviewed[child], `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
    fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
    fixture.state.tips[child] = fixture.reviewed[child];
    fixture.state.drift[child] = { at: 2, sha: fixture.expected[child] };
    const result = fixture.run([parent]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("not reachable from published head");
    expect(fixture.pushes()).toEqual([]);
    expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
  });

  it("previews without publication and leaves dirty files, refs, and indexes unchanged", () => {
    const fixture = publicationFixture();
    for (const name of WORKSPACE_REPOS) {
      writeFileSync(join(fixture.repos[name], "dirty.txt"), "kept");
      git(fixture.repos[name], ["add", "dirty.txt"]);
    }
    const before = fixture.snapshot();
    const result = fixture.run(["psy-sdk", "psy-node"], false);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`READY[psy-sdk] ${fixture.reviewed["psy-sdk"]}`);
    expect(fixture.pushes()).toEqual([]);
    expect(fixture.tips()).toEqual(fixture.expected);
    expect(fixture.snapshot()).toEqual(before);
  });

  it("rejects remote drift in the last repository before any simulated publication", () => {
    for (const at of [1, 3]) {
      const fixture = publicationFixture();
      fixture.state.drift["psy-sdk"] = { at, sha: "f".repeat(40) };
      const result = fixture.run(["psy-compiler", "psy-sdk"]);
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`).toContain(at === 1 ? "live remote head is neither" : "state changed since preflight");
      expect(fixture.pushes()).toEqual([]);
    }
  });

  it("stops later publication when a remote changes during publication", () => {
    const fixture = publicationFixture();
    fixture.state.drift["psy-sdk"] = { at: 4, sha: "f".repeat(40) };
    const result = fixture.run(["psy-compiler", "psy-sdk"]);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("remote topic changed; publication stopped");
    expect(fixture.pushes().map(event => event.name)).toEqual(["psy-compiler"]);
    expect(fixture.tips()["psy-sdk"]).toBe("f".repeat(40));
  });

  it("rejects effective URL rewrites before any simulated publication", () => {
    const fixture = publicationFixture();
    fixture.state.urls["psy-sdk"] = "https://example.invalid/rewritten.git";
    const result = fixture.run(["psy-compiler", "psy-sdk"]);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("remote is not the documented origin");
    expect(fixture.pushes()).toEqual([]);
  });

  it("accepts only unchanged external pins from the published expected parent tree", () => {
    for (const alreadyPublished of [false, true]) {
      const fixture = publicationFixture();
      const parent = "psy-contracts";
      pin(fixture.repos[parent], "lib/forge-std", "a".repeat(40), '[submodule "forge-std"]\n\tpath = lib/forge-std\n\turl = https://github.com/foundry-rs/forge-std.git\n');
      fixture.expected[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
      fixture.reviewed[parent] = commit(fixture.repos[parent], "preserve published external pin");
      fixture.state.tips[parent] = alreadyPublished ? fixture.reviewed[parent] : fixture.expected[parent];
      const before = fixture.snapshot();
      const result = fixture.run([parent]);
      expect(result.status, result.stderr).toBe(0);
      expect(fixture.pushes().map(event => event.name)).toEqual(alreadyPublished ? [] : [parent]);
      expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
      const events = fixture.events();
      expect(events.every(event => WORKSPACE_REPOS.includes(event.name))).toBe(true);
      expect(events.filter(event => event.kind === "SIMULATED" || event.args[0] === "ls-remote" || event.args.includes("fetch")).every(event => event.name === parent)).toBe(true);
      expect(fixture.snapshot()).toEqual(before);
    }
  });

  it("rejects changed external SHAs, URLs, and paths or new pins before any simulated publication", 60000, () => {
    for (const change of ["sha", "url", "path", "new"]) {
      const fixture = publicationFixture();
      const parent = "psy-contracts";
      const url = "https://github.com/foundry-rs/forge-std.git";
      if (change !== "new") {
        pin(fixture.repos[parent], "lib/forge-std", "a".repeat(40), `[submodule "forge-std"]\n\tpath = lib/forge-std\n\turl = ${url}\n`);
        fixture.expected[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
      }
      fixture.state.tips[parent] = fixture.expected[parent];
      const path = change === "path" ? "vendor/forge-std" : "lib/forge-std";
      pin(fixture.repos[parent], path, (change === "sha" ? "b" : "a").repeat(40), `[submodule "forge-std"]\n\tpath = ${path}\n\turl = ${change === "url" ? "https://example.invalid/forge-std.git" : url}\n`);
      fixture.reviewed[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
      const result = fixture.run(["psy-compiler", parent]);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("not an unchanged published external pin");
      expect(fixture.pushes()).toEqual([]);
      expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
    }
  });

  it("requires the external pin's parent remote to remain at the expected or reviewed commit", () => {
    for (const at of [1, 4]) {
      const fixture = publicationFixture();
      const parent = "psy-contracts";
      pin(fixture.repos[parent], "lib/forge-std", "a".repeat(40), '[submodule "forge-std"]\n\tpath = lib/forge-std\n\turl = https://github.com/foundry-rs/forge-std.git\n');
      fixture.expected[parent] = git(fixture.repos[parent], ["rev-parse", "HEAD"]);
      fixture.reviewed[parent] = commit(fixture.repos[parent], "preserve published external pin");
      fixture.state.tips[parent] = fixture.expected[parent];
      fixture.state.drift[parent] = { at, sha: "f".repeat(40) };
      const result = fixture.run([parent]);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(at === 1 ? "live remote head is neither the expected nor the reviewed commit" : "state changed since preflight");
      expect(fixture.pushes()).toEqual([]);
      expect(fixture.events().filter(event => event.kind === "DENIED")).toEqual([]);
    }
  });

  it("rejects unknown gitlinks and unpublished child pins before any simulated publication", () => {
    for (const unknown of [true, false]) {
      const fixture = publicationFixture();
      const path = unknown ? "lib/forge-std" : "psy-genesis";
      const child = unknown ? "forge-std" : "psy-genesis";
      pin(fixture.repos["psy-node"], path, fixture.reviewed["psy-genesis"], `[submodule "${child}"]\n\tpath = ${path}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
      fixture.reviewed["psy-node"] = git(fixture.repos["psy-node"], ["rev-parse", "HEAD"]);
      const result = fixture.run(["psy-compiler", "psy-node"]);
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`).toContain(unknown ? "gitlink lib/forge-std has no workspace mapping" : "not reachable from published head");
      expect(fixture.pushes()).toEqual([]);
    }
  });

  it("rejects empty and one-sided mappings rather than entering ordinary publication", () => {
    const fixture = publicationFixture();
    for (const options of [["--reviewed", ",", "--expected", ","], ["--reviewed", ","], ["--expected", ","]]) {
      fixture.install();
      const result = workspace(["push", "--source", fixture.root, "--repo", "psy-sdk", ...options], fixture.env);
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`).toMatch(/reviewed|expected|mapping/i);
      expect(fixture.events()).toEqual([]);
      expect(fixture.pushes()).toEqual([]);
    }
  });

  it("rejects missing, duplicate, and mismatched repository mappings without publication", () => {
    const fixture = publicationFixture();
    for (const mappings of [["psy-sdk"], ["psy-sdk", "psy-sdk"], ["psy-sdk", "psy-node"]]) {
      const result = fixture.run(["psy-sdk", "psy-compiler"], true, mappings);
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`).toMatch(/mapping|Invalid reviewed/);
      expect(fixture.pushes()).toEqual([]);
    }
    fixture.install();
    const result = workspace(["push", "--source", fixture.root, "--reviewed", `psy-sdk=${fixture.reviewed["psy-sdk"]}`, "--expected", `psy-sdk=${fixture.expected["psy-sdk"]}`, "--push"], fixture.env);
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("single reviewed pair requires --repo");
    expect(fixture.pushes()).toEqual([]);
  });

  it("denies transport, arbitrary options, writes, and nonfixture paths with no fallback", () => {
    const fixture = publicationFixture();
    fixture.install();
    for (const args of [
      ["-C", fixture.repos["psy-sdk"], "push", "origin", "mainnet-beta"],
      ["-C", fixture.repos["psy-sdk"], "fetch", "origin"],
      ["-C", fixture.repos["psy-sdk"], "-c", "alias.probe=!false", "probe"],
      ["-C", fixture.repos["psy-sdk"], "update-ref", "refs/heads/mainnet-beta", fixture.expected["psy-sdk"]],
      ["-C", fixture.repos["psy-sdk"], "ls-remote", "https://example.invalid/repo", "HEAD"],
      ["-C", tmpdir(), "rev-parse", "--show-toplevel"],
    ]) {
      const result = spawnSync(fixture.executable, args, { encoding: "utf8", env: fixture.env });
      expect(result.status).toBe(97);
      expect(result.stderr).toContain("DENIED fixture git invocation");
    }
    expect(fixture.events().every(event => event.kind === "DENIED")).toBe(true);
    expect(fixture.pushes()).toEqual([]);
    expect(fixture.tips()).toEqual(fixture.expected);
  });

  it("publishes frozen HEADs through the same pipeline, including a new child pin, only with --push", () => {
    const fixture = publicationFixture();
    const child = "psy-genesis", parent = "psy-node";
    pin(fixture.repos[parent], child, git(fixture.repos[child], ["rev-parse", "HEAD"]), `[submodule "${child}"]\n\tpath = ${child}\n\turl = git@github.com:PsyProtocol/${child}.git\n`);
    for (const name of [child, parent]) {
      writeFileSync(join(fixture.repos[name], "dirty.txt"), "kept\n");
      git(fixture.repos[name], ["add", "dirty.txt"]);
    }
    const heads = Object.fromEntries([child, parent].map(name => [name, git(fixture.repos[name], ["rev-parse", "HEAD"])]));
    const before = fixture.snapshot();
    const preview = fixture.run([parent, child], false, null);
    expect(preview.status, preview.stderr).toBe(0);
    expect(preview.stdout).toContain(`${parent}: dirty files are not included:`);
    expect(preview.stdout).toContain(`READY[${child}] ${heads[child]}`);
    expect(preview.stdout).toContain(`READY[${parent}] ${heads[parent]}`);
    expect(fixture.pushes()).toEqual([]);
    expect(fixture.snapshot()).toEqual(before);
    const published = fixture.run([parent, child], true, null);
    expect(published.status, published.stderr).toBe(0);
    expect(fixture.pushes().map(event => event.name)).toEqual([child, parent]);
    for (const event of fixture.pushes()) expect(event.args.at(-1)).toBe(`${heads[event.name]}:refs/heads/mainnet-beta`);
    expect(fixture.events().some(event => event.args.includes("fetch"))).toBe(false);
    expect(fixture.snapshot()).toEqual(before);
  });

  it("rejects a selected HEAD that is behind the live origin tip before publication", () => {
    const fixture = publicationFixture();
    const repo = fixture.repos["psy-sdk"];
    const headSha = git(repo, ["rev-parse", "HEAD"]);
    const newer = commit(repo, "newer origin tip");
    git(repo, ["update-ref", "HEAD", headSha]);
    (fixture.allowed()[repo] ??= []).push(["rev-parse", "--verify", `${newer}^{commit}`], ["merge-base", "--is-ancestor", newer, headSha]);
    fixture.state.tips["psy-sdk"] = newer;
    const result = fixture.run(["psy-sdk"], true, null);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("expected remote commit is not an ancestor of the reviewed commit");
    expect(fixture.pushes()).toEqual([]);
    expect(git(repo, ["rev-parse", "HEAD"])).toBe(headSha);
  });
});


const NODE_REV = "7d6815d22728debbc71f6a928f85aa4b209ebf4f";
const CARGO_NODE = `[dependencies]\npsy_vm = { git = "https://github.com/PsyProtocol/psy-node.git", rev = "${NODE_REV}" }\n`;
const NODE_CRATE = `[package]\nname = "psy_vm"\nversion = "0.0.0"\n`;

function seedNode(repo: string): void {
  writeFileSync(join(repo, "Cargo.toml"), `[workspace]\nmembers = ["psy_vm"]\n`);
  mkdirSync(join(repo, "psy_vm/src"), { recursive: true });
  writeFileSync(join(repo, "psy_vm/src/lib.rs"), "");
  writeFileSync(join(repo, "psy_vm/Cargo.toml"), NODE_CRATE);
  git(repo, ["add", "Cargo.toml", "psy_vm"]);
}

function prepareWorkspace(): { root: string; repos: Record<string, string> } {
  const root = disposable("workspace-prepare-");
  const repos = cohort(root);
  for (const name of WORKSPACE_REPOS) commit(repos[name], `${name} base`);
  seedNode(repos["psy-node"]);
  commit(repos["psy-node"], "node crates");
  return { root, repos };
}


function prepareSnapshot(root: string): Record<string, { head: string; refs: string; index: string; status: string }> {
  return Object.fromEntries(WORKSPACE_REPOS.flatMap(name => {
    const repo = join(root, name);
    const nested = WORKSPACE_REPOS.filter(child => existsSync(join(repo, child, ".git"))).map(child => join(repo, child));
    return [[name, repo], ...nested.map(path => [path, path] as [string, string])].map(([label, path]) => [label, {
      head: git(path, ["rev-parse", "HEAD"]),
      refs: git(path, ["show-ref"]),
      index: readFileSync(join(path, ".git/index")).toString("base64"),
      status: git(path, ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"]),
    }]);
  }));
}

// P1: workspace.ts captures its Git environment at module init, so every planner
// invocation runs in a child process whose sanitized fixture environment exists
// before the planner import; the test process never imports it.
function planProcess(root: string, mode: "build" | "assert", payload: string): SpawnSyncReturns<string> {
  const child = join(root, "plan-child.mjs");
  writeFileSync(child, `const planner = await import(${JSON.stringify(script)});
const [mode, payload] = process.argv.slice(2);
if (mode === "build") {
  const { root, args } = JSON.parse(payload);
  const parsed = planner.parseInvocation(["prepare", ...args]);
  const plan = planner.buildPreparePlan(root, parsed.options.get("repo").split(","), parsed.commitPaths, parsed.options.get("message"));
  planner.printPreparePlan(plan);
  console.log("PLANJSON" + JSON.stringify(plan));
} else {
  try { planner.assertPreparePlanUnchanged(JSON.parse(payload)); console.log("PLANUNCHANGED"); }
  catch (error) { console.log("PLANREJECTED " + (error instanceof Error ? error.message : String(error))); }
}
`);
  return spawnSync(process.execPath, [child, mode, payload], { encoding: "utf8", env: localEnvironment(root) });
}

function buildPlan(root: string, args: string[]): PreparePlan {
  const result = planProcess(root, "build", JSON.stringify({ root, args }));
  expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
  return JSON.parse(result.stdout.split("\n").find(line => line.startsWith("PLANJSON"))!.slice("PLANJSON".length)) as PreparePlan;
}

describe("local preparation (subprocess planner, no publication)", () => {
  it("previews without index, ref, or file mutations", () => {
    const { root, repos } = prepareWorkspace();
    writeFileSync(join(repos["psy-sdk"], "owned.txt"), "owned\n");
    const before = prepareSnapshot(root);
    const result = workspace(["prepare", "--source", root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "prepare sdk"], localEnvironment(root));
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain("prepare: psy-sdk");
    expect(result.stdout).toContain('"owned.txt"');
    expect(result.stdout).toContain("Preview performs no writes, fetches or Cargo resolution");
    expect(result.stdout).toContain("No push or npm version change.");
    expect(prepareSnapshot(root)).toEqual(before);
  });

  it("keeps a comma inside an explicit owned path", () => {
    const { root, repos } = prepareWorkspace();
    const name = "notes,draft.txt";
    writeFileSync(join(repos["psy-wallet"], name), "kept\n");
    const result = workspace(["prepare", "--source", root, "--repo", "psy-sdk,psy-wallet", "--commit-path", `psy-wallet=${name}`, "--message", "keep comma"], localEnvironment(root));
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain("prepare: psy-sdk -> psy-wallet");
    expect(result.stdout).toContain('"notes,draft.txt"');
  });

  it("rejects owning a repository root or directory, a symlink, and a dirty index", () => {
    const { root, repos } = prepareWorkspace();
    mkdirSync(join(repos["psy-sdk"], "dir"));
    writeFileSync(join(repos["psy-sdk"], "dir/file.txt"), "inside\n");
    symlinkSync("dir/file.txt", join(repos["psy-sdk"], "linked.txt"));
    for (const [owned, message] of [[".", /literal relative file path|individual file/], ["dir", /individual file, not a directory/], ["linked.txt", /symlink traversal is not owned/]] as const) {
      const result = workspace(["prepare", "--source", root, "--repo", "psy-sdk", "--commit-path", `psy-sdk=${owned}`, "--message", "reject"], localEnvironment(root));
      expect(result.status, owned).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`, owned).toMatch(message);
    }
    expect(lstatSync(join(repos["psy-sdk"], "linked.txt")).isSymbolicLink()).toBe(true);
    writeFileSync(join(repos["psy-wallet"], "staged.txt"), "staged\n");
    git(repos["psy-wallet"], ["add", "staged.txt"]);
    const staged = workspace(["prepare", "--source", root, "--repo", "psy-wallet", "--commit-path", "psy-wallet=staged.txt", "--message", "reject"], localEnvironment(root));
    expect(staged.status).not.toBe(0);
    expect(`${staged.stdout}${staged.stderr}`).toContain("empty index without conflicts");
    expect(git(repos["psy-wallet"], ["diff", "--cached", "--name-only"])).toBe("staged.txt");
  });

  it("orders a gitlink child before its parent and rejects a Cargo edge cycle", () => {
    const { root, repos } = prepareWorkspace();
    const child = git(repos["psy-genesis"], ["rev-parse", "HEAD"]);
    pin(repos["psy-dapp"], "psy-genesis", child, '[submodule "psy-genesis"]\n\tpath = psy-genesis\n\turl = git@github.com:PsyProtocol/psy-genesis.git\n');
    mkdirSync(join(repos["psy-dapp"], "psy-genesis"), { recursive: true });
    git(repos["psy-dapp"], ["clone", "-q", repos["psy-genesis"], "psy-genesis"]);
    git(join(repos["psy-dapp"], "psy-genesis"), ["checkout", "-q", child]);
    git(repos["psy-dapp"], ["submodule", "init"]);
    const result = workspace(["prepare", "--source", root, "--repo", "psy-dapp,psy-genesis", "--message", "order children first"], localEnvironment(root));
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain("prepare: psy-genesis -> psy-dapp");
    expect(result.stdout).toContain('gitlink "psy-genesis"');
    writeFileSync(join(repos["psy-compiler"], "Cargo.toml"), CARGO_NODE);
    git(repos["psy-compiler"], ["add", "Cargo.toml"]);
    commit(repos["psy-compiler"], "compiler depends on node");
    pin(repos["psy-node"], "psy-compiler", git(repos["psy-compiler"], ["rev-parse", "HEAD"]), '[submodule "psy-compiler"]\n\tpath = psy-compiler\n\turl = git@github.com:PsyProtocol/psy-compiler.git\n');
    mkdirSync(join(repos["psy-node"], "psy-compiler"), { recursive: true });
    git(repos["psy-node"], ["clone", "-q", repos["psy-compiler"], "psy-compiler"]);
    git(join(repos["psy-node"], "psy-compiler"), ["checkout", "-q", git(repos["psy-compiler"], ["rev-parse", "HEAD"])]);
    git(repos["psy-node"], ["submodule", "init"]);
    const cycle = workspace(["prepare", "--source", root, "--repo", "psy-node,psy-compiler", "--message", "cycle"], localEnvironment(root));
    expect(cycle.status).not.toBe(0);
    expect(`${cycle.stdout}${cycle.stderr}`).toMatch(/Preparation dependency cycle \(gitlink\/Cargo\)[\s\S]*psy-compiler \(gitlink\)[\s\S]*psy-node \(Cargo\)/);
  });

  it("leaves unrelated dirty files unstaged and unowned", () => {
    const { root, repos } = prepareWorkspace();
    writeFileSync(join(repos["psy-sdk"], "owned.txt"), "owned\n");
    writeFileSync(join(repos["psy-sdk"], "aside.txt"), "staged\n");
    git(repos["psy-sdk"], ["add", "aside.txt"]);
    writeFileSync(join(repos["psy-sdk"], "aside.txt"), "unstaged\n");
    writeFileSync(join(repos["psy-wallet"], "other.txt"), "untouched\n");
    const blocked = workspace(["prepare", "--source", root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "keep unrelated"], localEnvironment(root));
    expect(blocked.status).not.toBe(0);
    expect(`${blocked.stdout}${blocked.stderr}`).toContain("empty index without conflicts");
    git(repos["psy-sdk"], ["reset", "-q"]);
    const result = workspace(["prepare", "--source", root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "keep unrelated"], localEnvironment(root));
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain('"owned.txt"');
    expect(result.stdout).toContain("Outside preparation (untouched, not automatically updated):");
    expect(result.stdout).toContain("psy-wallet");
    expect(readFileSync(join(repos["psy-sdk"], "aside.txt"), "utf8")).toBe("unstaged\n");
    expect(readFileSync(join(repos["psy-wallet"], "other.txt"), "utf8")).toBe("untouched\n");
    expect(git(repos["psy-sdk"], ["diff", "--cached", "--name-only"])).toBe("");
  });

  it("refuses a stale HEAD or owned-file snapshot before any commit", () => {
    const { root, repos } = prepareWorkspace();
    writeFileSync(join(repos["psy-sdk"], "owned.txt"), "owned\n");
    const plan = buildPlan(root, ["--source", root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "frozen"]);
    expect(plan.repositories[0].ownedPaths).toEqual(["owned.txt"]);
    const assertPlan = (): string => planProcess(root, "assert", JSON.stringify(plan)).stdout;
    expect(assertPlan()).toContain("PLANUNCHANGED");
    const headBefore = git(repos["psy-sdk"], ["rev-parse", "HEAD"]);
    commit(repos["psy-sdk"], "moved after preview");
    expect(assertPlan()).toContain("HEAD changed since preparation preview");
    git(repos["psy-sdk"], ["update-ref", "HEAD", headBefore]);
    writeFileSync(join(repos["psy-sdk"], "owned.txt"), "changed after preview\n");
    expect(assertPlan()).toContain("owned.txt: owned file changed since preparation preview");
    writeFileSync(join(repos["psy-sdk"], "owned.txt"), "owned\n");
    expect(assertPlan()).toContain("PLANUNCHANGED");
    expect(git(repos["psy-sdk"], ["rev-parse", "HEAD"])).toBe(headBefore);
    expect(git(repos["psy-sdk"], ["diff", "--cached", "--name-only"])).toBe("");
  });

  it("does not treat an npm manifest as a preparation dependency or owned path", () => {
    const { root, repos } = prepareWorkspace();
    writeFileSync(join(repos["psy-dapp"], "package.json"), JSON.stringify({ dependencies: { "@psy-protocol/psy-sdk": "1.0.0" } }));
    writeFileSync(join(repos["psy-sdk"], "package.json"), JSON.stringify({ name: "@psy-protocol/psy-sdk", version: "1.0.0" }));
    const before = [repos["psy-dapp"], repos["psy-sdk"]].map(repo => readFileSync(join(repo, "package.json"), "utf8"));
    const result = workspace(["prepare", "--source", root, "--repo", "psy-dapp,psy-sdk", "--message", "npm stays"], localEnvironment(root));
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain("prepare: psy-dapp -> psy-sdk");
    expect(result.stdout).not.toContain("package.json");
    expect(result.stdout).toContain("(none; skip empty commit)");
    expect([repos["psy-dapp"], repos["psy-sdk"]].map(repo => readFileSync(join(repo, "package.json"), "utf8"))).toEqual(before);
  });
});

describe("local preparation apply (existing runner, fake commands, no publication)", () => {
  it("commits the child, pins the parent, resolves Cargo locally, and leaves npm untouched", () => {
    const { root, repos } = prepareWorkspace();
    const genesis = git(repos["psy-genesis"], ["rev-parse", "HEAD"]);
    pin(repos["psy-node"], "psy-genesis", genesis, '[submodule "psy-genesis"]\n\tpath = psy-genesis\n\turl = git@github.com:PsyProtocol/psy-genesis.git\n');
    mkdirSync(join(repos["psy-node"], "psy-genesis"), { recursive: true });
    git(repos["psy-node"], ["clone", "-q", repos["psy-genesis"], "psy-genesis"]);
    git(join(repos["psy-node"], "psy-genesis"), ["checkout", "-q", genesis]);
    git(repos["psy-node"], ["submodule", "init"]);
    writeFileSync(join(repos["psy-compiler"], "Cargo.toml"), CARGO_NODE);
    writeFileSync(join(repos["psy-compiler"], "Cargo.lock"), `[[package]]\nname = "psy_vm"\nversion = "0.0.0"\nsource = "git+https://github.com/PsyProtocol/psy-node.git?rev=${NODE_REV}#${NODE_REV}"\n`);
    git(repos["psy-compiler"], ["add", "Cargo.toml", "Cargo.lock"]);
    commit(repos["psy-compiler"], "compiler pins node");
    writeFileSync(join(repos["psy-genesis"], "owned.txt"), "child change\n");
    writeFileSync(join(repos["psy-compiler"], "package.json"), "{\"name\":\"unchanged\"}\n");
    const plan = buildPlan(root, ["--source", root, "--repo", "psy-genesis,psy-node,psy-compiler", "--commit-path", "psy-genesis=owned.txt", "--message", "prepare cohort"]);
    expect(plan.repositories.map(repo => repo.name)).toEqual(["psy-genesis", "psy-node", "psy-compiler"]);
    const commands: string[][] = [];
    const runner: Runner = (command): RunResult => {
      commands.push(command);
      const destination = command[1] === "-C" ? command[2] : "";
      const fetchArgs = command[1] === "-C" ? command.slice(3) : [];
      const source = fetchArgs.at(-2) || "";
      const refspec = fetchArgs.at(-1) || "";
      const local = (path: string) => path.startsWith(`${root}/`) || path.startsWith(`${tmpdir()}/`);
      const cacheSeed = JSON.stringify(fetchArgs.slice(0, -2)) === JSON.stringify(["fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "--recurse-submodules=no"])
        && local(destination) && local(source) && !source.includes("://") && !source.startsWith("git@")
        && /^[0-9a-f]{40}:refs\/(heads\/prepare|prefetch\/workspace\/[0-9a-f]{40})$/.test(refspec);
      if (command.includes("push") || command.includes("ls-remote") || command[0] === "npm" || (command.includes("fetch") && !cacheSeed)) return { code: 97, out: "", err: "publication denied" };
      if (command[0] === "git") {
        const repo = command[1] === "-C" ? command[2] : undefined;
        const args = command[1] === "-C" ? command.slice(3) : command.slice(1);
        const result = spawnSync(realGit, [...(repo ? ["-C", repo] : []), ...identity, ...args], { encoding: "utf8", env: localEnvironment(root) });
        return { code: result.status ?? 1, out: result.stdout, err: result.stderr };
      }
      if (command[0] === "cargo" && command[1] === "metadata") {
        const rev = git(repos["psy-node"], ["rev-parse", "HEAD"]);
        const source = `git+https://github.com/PsyProtocol/psy-node.git?rev=${rev}#${rev}`;
        writeFileSync(join(repos["psy-compiler"], "Cargo.lock"), `[[package]]\nname = "psy_vm"\nversion = "0.0.0"\nsource = "${source}"\n`);
        return { code: 0, out: JSON.stringify({ packages: [{ name: "app", id: "app", source: null }, { name: "psy_vm", id: "psy_vm", source, manifest_path: join(repos["psy-node"], "psy_vm/Cargo.toml") }], resolve: { nodes: [{ id: "app", deps: [{ pkg: "psy_vm" }] }, { id: "psy_vm", deps: [] }] } }), err: "" };
      }
      return { code: 1, out: "", err: `unexpected ${command.join(" ")}` };
    };
    const result: PrepareResult = applyPreparation(plan, runner);
    const nodeCommit = result.commits.find(commit => commit.name === "psy-node")!;
    expect(result.commits.map(commit => commit.name)).toEqual(["psy-genesis", "psy-node", "psy-compiler"]);
    expect(git(repos["psy-node"], ["rev-parse", ":psy-genesis"])).toBe(result.commits[0].to);
    expect(readFileSync(join(repos["psy-compiler"], "Cargo.toml"), "utf8")).toContain(nodeCommit.to);
    expect(readFileSync(join(repos["psy-compiler"], "package.json"), "utf8")).toBe("{\"name\":\"unchanged\"}\n");
    expect(commands.some(command => command.includes("push") || command.includes("ls-remote") || command[0] === "npm")).toBe(false);
    expect(commands.filter(command => command.includes("commit")).every(command => command.includes("--no-verify"))).toBe(true);
    expect(commands.some(command => command.includes("fetch") && command.at(-1)?.endsWith(":refs/heads/prepare"))).toBe(true);
  });
});

describe("prepare apply CLI (subprocess, deny-by-default git)", () => {
  function applyFixture(mode: "skip" | "apply" | "stale"): { root: string; bin: string; log: string } {
    const root = disposable("workspace-prepare-cli-");
    const repos = cohort(root);
    for (const name of WORKSPACE_REPOS) commit(repos[name], `${name} base`);
    writeFileSync(join(repos["psy-sdk"], "owned.txt"), "base\n");
    git(repos["psy-sdk"], ["add", "owned.txt"]);
    git(repos["psy-sdk"], [...identity, "commit", "-m", "record owned"]);
    if (mode !== "skip") writeFileSync(join(repos["psy-sdk"], "owned.txt"), "owned\n");
    const log = join(root, "git-calls.log");
    const bin = join(root, "bin");
    mkdirSync(bin);
    const gitShim = join(bin, "git");
    const sdk = join(repos["psy-sdk"]);
    const count = join(root, "symbolic-ref.count");
    writeFileSync(gitShim, `#!${process.execPath}
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const log = ${JSON.stringify(log)};
const sdk = ${JSON.stringify(sdk)};
const count = ${JSON.stringify(count)};
const mutate = ${mode === "stale" ? "true" : "false"};
const argv = process.argv.slice(2);
appendFileSync(log, argv.join(" ") + "\\n");
const deny = () => { console.error("DENIED fixture git invocation: " + argv.join(" ")); process.exit(97); };
if (argv[0] !== "-C" || argv[1] !== sdk) deny();
const args = argv.slice(2);
const text = args.join(" ");
const sha = value => /^[0-9a-f]{40}$/.test(value);
const allowed = (args[0] === "rev-parse" && args[1] === "--show-toplevel" && args.length === 2)
  || text === "rev-parse HEAD"
  || text === "symbolic-ref --quiet --short HEAD"
  || text === "diff --cached --name-only -z"
  || text === "ls-files --unmerged -z"
  || (args[0] === "rev-parse" && args[1] === "--verify" && args.length === 3 && args[2].endsWith("^{commit}") && (args[2] === "HEAD^{commit}" || sha(args[2].slice(0, 40))))
  || (args[0] === "ls-tree" && args[1] === "-r" && args[2] === "-z" && args.length === 4 && sha(args[3]))
  || text === "--literal-pathspecs ls-files -z -- owned.txt"
  || text === "--literal-pathspecs add -- owned.txt"
  || text === "commit --no-verify -m prepare sdk"
  || (args[0] === "merge-base" && args[1] === "--is-ancestor" && args.length === 4 && sha(args[2]) && sha(args[3]));
if (!allowed || args.includes("fetch") || args.includes("push") || args.includes("ls-remote")) deny();
if (mutate && text === "symbolic-ref --quiet --short HEAD") {
  let seen = 0;
  try { seen = readFileSync(count, "utf8").split("\\n").filter(Boolean).length; } catch {}
  appendFileSync(count, "x\\n");
  if (seen === 2) writeFileSync(sdk + "/owned.txt", "changed after preview\\n");
}
const result = spawnSync(${JSON.stringify(realGit)}, argv, { encoding: "utf8" });
process.stdout.write(result.stdout || "");
process.stderr.write(result.stderr || "");
process.exit(result.status ?? 98);
`);
    chmodSync(gitShim, 0o755);
    return { root, bin, log };
  }
  function applyEnv(root: string, bin: string): NodeJS.ProcessEnv {
    return { ...localEnvironment(root), PATH: `${bin}:${process.env.PATH}`, GIT_AUTHOR_NAME: "Workspace Test", GIT_AUTHOR_EMAIL: "workspace@example.invalid", GIT_COMMITTER_NAME: "Workspace Test", GIT_COMMITTER_EMAIL: "workspace@example.invalid" };
  }

  it("rechecks the frozen plan, skips an unchanged repository, and commits through the CLI with hooks disabled", () => {
    const skipped = applyFixture("skip");
    const preview = workspace(["prepare", "--source", skipped.root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "prepare sdk"], applyEnv(skipped.root, skipped.bin));
    expect(preview.status, `${preview.stdout}${preview.stderr}`).toBe(0);
    expect(preview.stdout).toContain('owned paths: "owned.txt"');
    const skip = workspace(["prepare", "--source", skipped.root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "prepare sdk", "--apply"], applyEnv(skipped.root, skipped.bin));
    expect(skip.status, `${skip.stdout}${skip.stderr}`).toBe(0);
    expect(skip.stdout).toContain("psy-sdk: unchanged; no commit");
    expect(readFileSync(skipped.log, "utf8")).not.toMatch(/(^|\s)commit(\s|$)|(^|\s)push(\s|$)/m);

    const applied = applyFixture("apply");
    const head = git(join(applied.root, "psy-sdk"), ["rev-parse", "HEAD"]);
    const result = workspace(["prepare", "--source", applied.root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "prepare sdk", "--apply"], applyEnv(applied.root, applied.bin));
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain(`psy-sdk: prepared ${head} -> `);
    const calls = readFileSync(applied.log, "utf8");
    expect(calls.match(/commit --no-verify -m prepare sdk/g)).toEqual(["commit --no-verify -m prepare sdk"]);
    expect(calls).not.toMatch(/\bpush\b/);
    expect(git(join(applied.root, "psy-sdk"), ["rev-parse", "HEAD^{commit}"])).not.toBe(head);

    const stale = applyFixture("stale");
    const before = git(join(stale.root, "psy-sdk"), ["rev-parse", "HEAD"]);
    const rejected = workspace(["prepare", "--source", stale.root, "--repo", "psy-sdk", "--commit-path", "psy-sdk=owned.txt", "--message", "prepare sdk", "--apply"], applyEnv(stale.root, stale.bin));
    expect(rejected.status).not.toBe(0);
    expect(`${rejected.stdout}${rejected.stderr}`).toContain("owned.txt: owned file changed since preparation preview");
    expect(git(join(stale.root, "psy-sdk"), ["rev-parse", "HEAD"])).toBe(before);
    expect(readFileSync(stale.log, "utf8")).not.toMatch(/(^|\s)commit(\s|$)/m);
  });

  it("rejects a cohort-named gitlink whose URL is not the canonical origin", () => {
    const { root, repos } = prepareWorkspace();
    const child = git(repos["psy-genesis"], ["rev-parse", "HEAD"]);
    pin(repos["psy-dapp"], "psy-genesis", child, '[submodule "psy-genesis"]\n\tpath = psy-genesis\n\turl = https://evil.example/psy-genesis\n');
    const before = { head: git(repos["psy-dapp"], ["rev-parse", "HEAD"]), index: git(repos["psy-dapp"], ["ls-files", "-s"]), status: git(repos["psy-dapp"], ["status", "--porcelain"]) };
    const result = workspace(["prepare", "--source", root, "--repo", "psy-dapp,psy-genesis", "--message", "reject foreign origin"], localEnvironment(root));
    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("gitlink psy-genesis URL is not the canonical psy-genesis origin");
    expect({ head: git(repos["psy-dapp"], ["rev-parse", "HEAD"]), index: git(repos["psy-dapp"], ["ls-files", "-s"]), status: git(repos["psy-dapp"], ["status", "--porcelain"]) }).toEqual(before);
  });
});
