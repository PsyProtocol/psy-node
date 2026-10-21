// Creates a new multi-repo workspace mirroring an existing one: per repo, a
// NEW topic branch of the same name based on the base tip frozen to a SHA at
// preflight, via `git worktree add` from local source repos. A missing source
// repo may be cloned from its documented origin; that clone is the only
// network read. A present local base is frozen from refs/heads or the
// existing origin tracking ref and is never fetched. Recorded submodules are
// initialized at their gitlink SHAs. No push, prune, force, or branch
// deletion; no staging of dirty content; no config/secret copies; no builds.
// Failures never delete what was created.

import { existsSync, mkdirSync, realpathSync } from "node:fs";
import * as path from "node:path";

/** Canonical workspace repos in dependency order (leaf first; merge order). */
export const WORKSPACE_REPOS = [
  "psy-compiler",
  "psy-contracts",
  "psy-genesis",
  "psy-sdk",
  "psy-services",
  "psy-wallet",
  "psy-dapp",
  "psy-node",
] as const;

export type WorkspaceRepo = (typeof WORKSPACE_REPOS)[number];

/** Documented official origins (docs/src/dev/worktree-cohort.md §2). Only used when the source workspace lacks a repo directory. */
export const WORKSPACE_ORIGIN_URLS: Record<WorkspaceRepo, string> = {
  "psy-compiler": "https://github.com/PsyProtocol/psy-compiler.git",
  "psy-contracts": "https://github.com/PsyProtocol/psy-contracts.git",
  "psy-genesis": "https://github.com/PsyProtocol/psy-genesis.git",
  "psy-sdk": "https://github.com/PsyProtocol/psy-sdk.git",
  "psy-services": "https://github.com/PsyProtocol/psy-services.git",
  "psy-wallet": "https://github.com/PsyProtocol/psy-wallet.git",
  "psy-dapp": "https://github.com/PsyProtocol/psy-dapp.git",
  "psy-node": "https://github.com/PsyProtocol/psy-node.git",
};

export const DEFAULT_BASE_BRANCH = "mainnet-beta";

export interface CreateWorkspaceOptions {
  source: string;
  destination: string;
  branch: string;
  base: string;
}

export interface RepoOutcome {
  repo: WorkspaceRepo;
  path: string;
  mode: "worktree" | "clone";
  /** Base commit SHA the topic branch was frozen to at preflight. */
  baseSha: string;
}

export interface CreateWorkspaceResult {
  workspace: string;
  branch: string;
  base: string;
  repos: RepoOutcome[];
}

const GIT_ENV = (() => {
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  env.GIT_TERMINAL_PROMPT = "0";
  if (!env.GIT_SSH_COMMAND) env.GIT_SSH_COMMAND = "ssh -oBatchMode=yes";
  return env;
})();

function redactCredentials(text: string): string {
  return text.replace(/(https?:\/\/)[^@/\s]+@/g, "$1***@");
}

async function git(args: string[], cwd?: string): Promise<string> {
  const proc = Bun.spawn(["git", ...args], { cwd, env: GIT_ENV, stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) {
    throw new Error(
      redactCredentials(`git ${args.join(" ")} (cwd: ${cwd ?? process.cwd()}) exited ${code}: ${(err || out).trim()}`),
    );
  }
  return out.trim();
}

/** Exit-code variant for checks that are allowed to fail (nonzero = false). */
async function gitOk(args: string[], cwd?: string): Promise<boolean> {
  const proc = Bun.spawn(["git", ...args], { cwd, env: GIT_ENV, stdout: "ignore", stderr: "ignore" });
  return (await proc.exited) === 0;
}

function isInside(child: string, parent: string): boolean {
  return child === parent || child.startsWith(parent + path.sep);
}

/** Freeze the base tip to a commit SHA: local branch first, then origin tracking ref. */
async function resolveBaseSha(repo: string, base: string): Promise<string | null> {
  for (const ref of [`refs/heads/${base}`, `refs/remotes/origin/${base}`]) {
    if (await gitOk(["show-ref", "--verify", "--quiet", ref], repo)) {
      return await git(["rev-parse", "--verify", `${ref}^{commit}`], repo);
    }
  }
  return null;
}

/** Remote counterpart of resolveBaseSha for clone plans: freeze via ls-remote before any write. */
async function remoteBaseSha(url: string, base: string): Promise<string | null> {
  const out = await git(["ls-remote", url, `refs/heads/${base}`]).catch(() => null);
  if (!out) return null;
  const sha = out.split("\n")[0]?.split("\t")[0];
  return /^[0-9a-f]{40}$/.test(sha ?? "") ? sha! : null;
}

/**
 * Update=none entries in .gitmodules are skipped by plain `git submodule
 * update`; re-run them under a per-name config override so every recorded
 * gitlink is materialized at its exact SHA.
 */
async function submoduleUpdateArgs(repo: string): Promise<string[]> {
  const proc = Bun.spawn(
    ["git", "config", "--file", ".gitmodules", "--get-regexp", "^submodule\..+\.update$"],
    { cwd: repo, env: GIT_ENV, stdout: "pipe", stderr: "ignore" },
  );
  const out = await new Response(proc.stdout).text();
  if ((await proc.exited) !== 0) return [];
  const overrides: string[] = [];
  for (const line of out.split("\n")) {
    const [key, value] = line.trim().split(/\s+/);
    if (value === "none") {
      overrides.push(
        "-c",
        `submodule.${key.replace(/^submodule\./, "").replace(/\.update$/, "")}.update=checkout`,
      );
    }
  }
  return overrides;
}

export async function createWorkspace(options: CreateWorkspaceOptions): Promise<CreateWorkspaceResult> {
  const branch = options.branch;
  const base = options.base || DEFAULT_BASE_BRANCH;
  const errors: string[] = [];
  const fail = (msg: string) => errors.push(msg);

  if (!options.source) fail("source workspace is required");
  if (!branch) fail("topic branch is required");
  if (!options.destination) fail("destination is required");

  let srcRoot = "";
  if (options.source && existsSync(options.source)) {
    srcRoot = realpathSync(options.source);
  } else if (options.source) {
    fail(`source workspace does not exist: ${options.source}`);
  }

  let destAbs = "";
  if (options.destination) {
    const destResolved = path.resolve(options.destination);
    const destParent = path.dirname(destResolved);
    if (!existsSync(destParent)) {
      fail(`destination parent does not exist: ${destParent}`);
    } else {
      destAbs = path.join(realpathSync(destParent), path.basename(destResolved));
      if (existsSync(destAbs)) {
        fail(`destination already exists: ${destAbs}`);
      } else if (srcRoot) {
        if (isInside(destAbs, srcRoot)) fail(`destination is inside source workspace: ${destAbs}`);
        for (const repo of WORKSPACE_REPOS) {
          const srcRepo = path.join(srcRoot, repo);
          if (existsSync(srcRepo) && isInside(destAbs, realpathSync(srcRepo))) {
            fail(`destination is inside ${repo}: ${destAbs}`);
          }
        }
      }
    }
  }

  if (branch && !(await gitOk(["check-ref-format", "--branch", branch]))) {
    fail(`invalid branch name: ${branch}`);
  }

  interface Plan {
    repo: WorkspaceRepo;
    mode: "worktree" | "clone";
    srcRepo?: string;
    cloneUrl?: string;
    baseSha?: string;
  }
  const plans: Plan[] = [];

  for (const repo of WORKSPACE_REPOS) {
    const srcRepo = srcRoot ? path.join(srcRoot, repo) : "";
    if (!srcRepo || !existsSync(srcRepo)) {
      const url = WORKSPACE_ORIGIN_URLS[repo];
      if (!url) {
        fail(`source repo missing and no documented origin for: ${repo}`);
        continue;
      }
      const sha = await remoteBaseSha(url, base);
      if (!sha) {
        fail(`base branch not found on documented origin for ${repo}: refs/heads/${base} at ${redactCredentials(url)}`);
        continue;
      }
      plans.push({ repo, mode: "clone", cloneUrl: url, baseSha: sha });
      continue;
    }
    const top = await git(["rev-parse", "--show-toplevel"], srcRepo).catch(() => null);
    if (!top || realpathSync(top) !== realpathSync(srcRepo)) {
      fail(`source repo is not a repository root: ${srcRepo}`);
      continue;
    }
    const baseSha = await resolveBaseSha(srcRepo, base);
    if (!baseSha) {
      fail(
        `base branch not found in ${repo}: ${base} (no refs/heads/${base} or refs/remotes/origin/${base})`,
      );
      continue;
    }
    if (branch && (await gitOk(["show-ref", "--verify", "--quiet", `refs/heads/${branch}`], srcRepo))) {
      fail(`topic branch already exists in ${repo}: ${branch}`);
      continue;
    }
    plans.push({ repo, mode: "worktree", srcRepo, baseSha });
  }

  if (errors.length > 0) {
    throw new Error(`preflight failed, nothing created:\n${errors.map((e) => `  - ${e}`).join("\n")}`);
  }

  mkdirSync(destAbs);
  const created: string[] = [destAbs];

  try {
    const outcomes: RepoOutcome[] = [];
    for (const plan of plans) {
      const destRepo = path.join(destAbs, plan.repo);
      if (plan.mode === "clone") {
        console.log(`[${plan.repo}] cloning from documented origin: ${redactCredentials(plan.cloneUrl!)}`);
        await git(["clone", plan.cloneUrl!, destRepo]);
        created.push(destRepo);
        await git(["switch", "-c", branch, plan.baseSha!], destRepo);
      } else {
        console.log(`[${plan.repo}] worktree add -b ${branch} ${destRepo} ${plan.baseSha}`);
        await git(["worktree", "add", "-b", branch, destRepo, plan.baseSha!], plan.srcRepo);
        created.push(destRepo);
      }
      if (existsSync(path.join(destRepo, ".gitmodules"))) {
        const overrides = await submoduleUpdateArgs(destRepo);
        console.log(`[${plan.repo}] initializing submodules at recorded gitlinks`);
        await git([...overrides, "submodule", "update", "--init", "--recursive"], destRepo);
      }
      outcomes.push({ repo: plan.repo, path: destRepo, mode: plan.mode, baseSha: plan.baseSha! });
    }
    return { workspace: destAbs, branch, base, repos: outcomes };
  } catch (err) {
    throw new Error(
      `${err instanceof Error ? err.message : String(err)}\ncreated so far (no cleanup performed):\n${created.map((p) => `  - ${p}`).join("\n")}`,
    );
  }
}
