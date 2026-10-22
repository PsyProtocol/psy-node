import { afterEach, describe, expect, it } from "bun:test";
import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WORKSPACE_REPOS } from "./workspace-create";

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

  it("rejects changed external SHAs, URLs, and paths or new pins before any simulated publication", () => {
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
