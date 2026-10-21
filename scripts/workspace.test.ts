import { afterEach, describe, expect, it } from "bun:test";
import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

function git(repo: string, args: string[]): string {
  const result = spawnSync("git", ["-C", repo, ...args], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr);
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

function workspace(command: string[]): SpawnSyncReturns<string> {
  return spawnSync("bun", [script, ...command], { encoding: "utf8" });
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
