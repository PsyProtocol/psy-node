import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { Signals } from "node:child_process";

/** Approved `psy_cli/psy_relayer_cli/indexer/envio/pnpm-lock.yaml`. */
export const APPROVED_INDEXER_LOCK_SHA256 =
    "a8d7c31d095d02a300d6e8649c657ddb498d4034b6f6ffd8af89259dd8e631d4";

// Envio v2.32.10 writes this public template during codegen (84 bytes).
// https://raw.githubusercontent.com/enviodev/hyperindex/v2.32.10/codegenerator/cli/templates/static/codegen/.npmrc
const GENERATED_NPMRC_SHA256 = "02226d294c37bddb02089899f4c98732100cb7e382c87822815e20c661cf077d";

const CACHED_PNPM_SUFFIX = `${path.sep}pnpm${path.sep}10.33.0${path.sep}bin${path.sep}pnpm.cjs`;
const CHILD_ENV_KEYS = ["PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "TEMP", "TMP"] as const;

const ROOT_DEPENDENCIES: Readonly<Record<string, string>> = {
    "@envio-dev/hypersync-client": "1.3.0",
    "poseidon-goldilocks-lite": "^0.2.3",
};
const ROOT_DEV_DEPENDENCIES: Readonly<Record<string, string>> = {
    envio: "2.32.10",
    typescript: "5.6.3",
};
const GENERATED_DEPENDENCIES: Readonly<Record<string, string>> = {
    "@rescript/react": "0.12.1",
    "bignumber.js": "9.1.2",
    "date-fns": "3.3.1",
    dotenv: "16.4.5",
    envio: "2.32.10",
    ethers: "6.8.0",
    express: "4.19.2",
    ink: "3.2.0",
    "ink-big-text": "1.2.0",
    "ink-spinner": "4.0.3",
    "js-sdsl": "4.4.2",
    pino: "8.16.1",
    postgres: "3.4.1",
    "prom-client": "15.0.0",
    react: "18.2.0",
    rescript: "11.1.3",
    "rescript-envsafe": "5.0.0",
    "rescript-schema": "9.3.0",
    "ts-node": "10.9.1",
    viem: "2.21.0",
    yargs: "17.7.2",
};

export type FrozenDepsChildStatus = {
    code: number | null;
    signal: Signals | null;
};

export type FrozenDepsRunner = (
    command: string,
    args: readonly string[],
    options: { cwd: string; env: NodeJS.ProcessEnv },
) => Promise<FrozenDepsChildStatus>;

export type FrozenDepsCodegenContext = {
    environment: NodeJS.ProcessEnv;
    dispatch: (argv: readonly string[], cwd: string) => Promise<number>;
};

export type FrozenDepsInput = {
    root: string;
    cachedPnpm: string;
    store: string;
    environment: NodeJS.ProcessEnv;
    runner: FrozenDepsRunner;
};

type Isolation = {
    directory: string;
    home: string;
    xdg: string;
    userconfig: string;
    globalconfig: string;
    marker: string;
    bin: string;
};

type PreparedChild =
    | { kind: "spawn"; command: string; args: string[]; cwd: string; env: NodeJS.ProcessEnv }
    | { kind: "reject"; reason: string };

/** Exact `PSY_FROZEN_DEPS=1`. Unset, empty, and every other value stay off. */
export function frozenDepsEnabled(value: string | undefined = process.env.PSY_FROZEN_DEPS): boolean {
    return value === "1";
}

export function frozenDepsCommandRunner(
    command: string,
    args: readonly string[],
    options: { cwd: string; env: NodeJS.ProcessEnv },
): Promise<FrozenDepsChildStatus> {
    const { promise, resolve, reject } = Promise.withResolvers<FrozenDepsChildStatus>();
    const child = spawn(command, args, {
        cwd: options.cwd,
        env: options.env,
        shell: false,
        stdio: "inherit",
    });
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
    return promise;
}

/**
 * Parent for one Envio codegen. `context.environment.PATH` starts with temporary
 * `pnpm` and `npm` executables. Spawn the real envio shim directly; the installed
 * `.bin/envio` is `#!/bin/sh`, so neither `node` nor `process.execPath` can run it.
 * Pass `context.environment` unchanged. Acceptance requires codegen status 0 and
 * an empty failure marker, because upstream discards child statuses and can exit 0.
 */
export async function guardedEnvioCodegen(
    input: FrozenDepsInput & {
        codegen: (context: FrozenDepsCodegenContext) => Promise<FrozenDepsChildStatus>;
    },
): Promise<void> {
    const isolation = createIsolation();
    const prepared = { ...input, root: path.resolve(input.root) };
    try {
        assertFrozenDepsInputs(prepared);
        assertConfigAbsent(prepared.root);
        assertFrozenManifests(prepared.root);
        writeWrappers(isolation);
        const status = await input.codegen({
            environment: codegenEnvironment(prepared, isolation),
            dispatch: (argv, cwd) => dispatchChild(argv, cwd, prepared, isolation),
        });
        let marker = "";
        try {
            marker = readFileSync(isolation.marker, "utf8");
        } catch {
            throw new Error("frozen deps failure marker is missing or unreadable");
        }
        if (marker.length !== 0) throw new Error(`frozen deps child failed: ${marker.trim()}`);
        if (status.signal || status.code !== 0) {
            throw new Error(`envio codegen failed code=${status.code ?? ""} signal=${status.signal ?? ""}`);
        }
    } finally {
        rmSync(isolation.directory, { recursive: true, force: true });
    }
}

/** Entry used by the temporary pnpm/npm wrappers. Not a general policy hook. */
export async function dispatchFrozenDepsProcess(): Promise<number> {
    const input: FrozenDepsInput = {
        root: requiredEnv("PSY_FROZEN_DEPS_ROOT"),
        cachedPnpm: requiredEnv("PSY_FROZEN_DEPS_PNPM"),
        store: requiredEnv("PSY_FROZEN_DEPS_STORE"),
        environment: process.env,
        runner: frozenDepsCommandRunner,
    };
    const isolation: Isolation = {
        directory: requiredEnv("PSY_FROZEN_DEPS_DIR"),
        home: requiredEnv("PSY_FROZEN_DEPS_HOME"),
        xdg: requiredEnv("PSY_FROZEN_DEPS_XDG"),
        userconfig: requiredEnv("PSY_FROZEN_DEPS_USERCONFIG"),
        globalconfig: requiredEnv("PSY_FROZEN_DEPS_GLOBALCONFIG"),
        marker: requiredEnv("PSY_FROZEN_DEPS_MARKER"),
        bin: path.dirname(process.argv[1] ?? ""),
    };
    const name = path.basename(process.argv[1] ?? "");
    return dispatchChild([name, ...process.argv.slice(2)], process.cwd(), input, isolation);
}

async function dispatchChild(
    argv: readonly string[],
    cwd: string,
    input: FrozenDepsInput,
    isolation: Isolation,
): Promise<number> {
    let prepared: PreparedChild;
    try {
        assertConfigAbsent(input.root);
        assertFrozenManifests(input.root);
        prepared = prepareChild(argv, cwd, input, isolation);
    } catch (error) {
        rememberFailure(isolation.marker, error instanceof Error ? error.message : "unknown failure");
        return 1;
    }
    if (prepared.kind === "reject") {
        rememberFailure(isolation.marker, prepared.reason);
        return 1;
    }
    if (readFileSync(isolation.marker).length !== 0) return 1;
    let status: FrozenDepsChildStatus;
    try {
        status = await input.runner(prepared.command, prepared.args, {
            cwd: prepared.cwd,
            env: prepared.env,
        });
    } catch (error) {
        rememberFailure(isolation.marker, `spawn failed: ${error instanceof Error ? error.message : "unknown failure"}`);
        return 1;
    }
    if (status.signal || status.code !== 0) {
        rememberFailure(isolation.marker, `child failed code=${status.code ?? ""} signal=${status.signal ?? ""}`);
        return status.code && status.code > 0 ? status.code : 1;
    }
    return 0;
}

function prepareChild(
    argv: readonly string[],
    cwd: string,
    input: FrozenDepsInput,
    isolation: Isolation,
): PreparedChild {
    const [command, ...args] = argv;
    if (command !== "pnpm") return { kind: "reject", reason: `rejected command: ${command ?? ""}` };
    const here = canonicalDir(cwd);
    const root = canonicalDir(input.root);
    const generated = canonicalDir(path.join(input.root, "generated"));
    const env: NodeJS.ProcessEnv = {
        HOME: isolation.home,
        XDG_CONFIG_HOME: isolation.xdg,
        XDG_DATA_HOME: path.join(isolation.directory, "data"),
        XDG_CACHE_HOME: path.join(isolation.directory, "cache"),
        XDG_STATE_HOME: path.join(isolation.directory, "state"),
        NPM_CONFIG_USERCONFIG: isolation.userconfig,
        NPM_CONFIG_GLOBALCONFIG: isolation.globalconfig,
        COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
        COREPACK_ENABLE_NETWORK: "0",
    };
    for (const key of CHILD_ENV_KEYS) {
        const value = input.environment[key];
        if (value != null) env[key] = value;
    }
    const common = [
        input.cachedPnpm,
        `--dir=${here}`,
        `--config.userconfig=${isolation.userconfig}`,
        `--config.globalconfig=${isolation.globalconfig}`,
        "--config.ignore-pnpmfile=true",
        "--config.manage-package-manager-versions=false",
    ];
    if (sameArgs(args, ["--version"]) && here === generated) {
        return { kind: "spawn", command: process.execPath, args: [...common, "--version"], cwd: here, env };
    }
    if (sameArgs(args, ["rescript"]) && here === generated) {
        return { kind: "spawn", command: process.execPath, args: [...common, "rescript"], cwd: here, env };
    }
    const generatedInstall = sameArgs(args, ["install", "--no-lockfile", "--prefer-offline"]) && here === generated;
    const rootInstall = sameArgs(args, ["install", "--prefer-offline"]) && here === root;
    if (!generatedInstall && !rootInstall) return { kind: "reject", reason: `rejected pnpm argv: ${args.join(" ")}` };
    return {
        kind: "spawn",
        command: process.execPath,
        cwd: here,
        env,
        args: [
            ...common,
            "install",
            "--offline",
            "--frozen-lockfile",
            "--ignore-scripts",
            `--lockfile-dir=${root}`,
            `--store-dir=${canonicalDir(input.store)}`,
            "--verify-store-integrity=true",
            "--registry=https://registry.npmjs.org/",
        ],
    };
}

function assertFrozenDepsInputs(input: FrozenDepsInput): void {
    for (const [label, value] of [
        ["root", input.root],
        ["cachedPnpm", input.cachedPnpm],
        ["store", input.store],
    ] as const) {
        if (!path.isAbsolute(value)) throw new Error(`${label} must be absolute`);
    }
    const cached = realpathSync(input.cachedPnpm);
    const cachedStat = lstatSync(cached);
    if (!cachedStat.isFile() || !cached.endsWith(CACHED_PNPM_SUFFIX)) {
        throw new Error("cached pnpm must be the reviewed pnpm 10.33.0 script");
    }
    canonicalDir(input.store);
}

function assertFrozenManifests(root: string): void {
    assertDependencies(readManifest(path.join(root, "package.json")), ROOT_DEPENDENCIES, ROOT_DEV_DEPENDENCIES, "root");
    assertDependencies(readManifest(path.join(root, "generated", "package.json")), GENERATED_DEPENDENCIES, {}, "generated");
    const lockPath = path.join(root, "pnpm-lock.yaml");
    if (!lstatSync(lockPath).isFile()) throw new Error("indexer lock is not a regular file");
    const digest = createHash("sha256").update(readFileSync(lockPath)).digest("hex");
    if (digest !== APPROVED_INDEXER_LOCK_SHA256) {
        throw new Error("indexer lock does not match the approved frozen dependency lock");
    }
    lstatSync(path.join(root, "pnpm-workspace.yaml"));
}

function assertConfigAbsent(root: string): void {
    for (const start of [root, path.join(root, "generated")]) {
        let dir = path.resolve(start);
        while (true) {
            const npmrc = path.join(dir, ".npmrc");
            if (exists(npmrc)) {
                const importer = dir === path.resolve(root) || dir === path.resolve(root, "generated");
                const project = exists(path.join(dir, "package.json")) || exists(path.join(dir, "pnpm-workspace.yaml"));
                if ((importer || project)
                    && !(dir === path.resolve(root, "generated") && isApprovedGeneratedConfig(npmrc))) {
                    throw new Error(`frozen deps refuse project config at ${npmrc}`);
                }
            }
            const parent = path.dirname(dir);
            if (parent === dir) break;
            dir = parent;
        }
    }
}

/** Only the generator-owned path may contain the exact published template. */
function isApprovedGeneratedConfig(file: string): boolean {
    const stat = lstatSync(file);
    if (!stat.isFile() || stat.size !== 84) return false;
    const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
        const opened = fstatSync(fd);
        if (!opened.isFile() || opened.size !== 84) return false;
        // Bound the read even if the file changes after stat; reject extra bytes.
        const bytes = Buffer.alloc(85);
        const length = readSync(fd, bytes, 0, bytes.length, 0);
        return length === 84
            && createHash("sha256").update(bytes.subarray(0, length)).digest("hex") === GENERATED_NPMRC_SHA256;
    } finally {
        closeSync(fd);
    }
}

function assertDependencies(
    manifest: Record<string, unknown>,
    dependencies: Readonly<Record<string, string>>,
    devDependencies: Readonly<Record<string, string>>,
    label: string,
): void {
    if (manifest.pnpm != null || manifest.workspaces != null) {
        throw new Error(`${label} manifest changes pnpm dependency policy`);
    }
    sameDependencyMap(manifest.dependencies, dependencies, `${label} dependencies`);
    sameDependencyMap(manifest.devDependencies, devDependencies, `${label} devDependencies`);
    sameDependencyMap(manifest.optionalDependencies, {}, `${label} optionalDependencies`);
    sameDependencyMap(manifest.peerDependencies, {}, `${label} peerDependencies`);
}

function sameDependencyMap(actual: unknown, expected: Readonly<Record<string, string>>, label: string): void {
    if (actual == null) {
        if (Object.keys(expected).length === 0) return;
        throw new Error(`${label} are missing`);
    }
    if (typeof actual !== "object" || Array.isArray(actual)) throw new Error(`${label} are malformed`);
    const entries = Object.entries(actual);
    if (entries.length !== Object.keys(expected).length) throw new Error(`${label} do not match the reviewed manifest`);
    for (const [name, spec] of entries) {
        if (typeof spec !== "string" || expected[name] !== spec) {
            throw new Error(`${label} do not match the reviewed manifest`);
        }
    }
}

function readManifest(file: string): Record<string, unknown> {
    let parsed: unknown;
    try {
        parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch {
        throw new Error(`malformed manifest: ${path.basename(file)}`);
    }
    if (typeof parsed !== "object" || parsed == null || Array.isArray(parsed)) {
        throw new Error(`malformed manifest: ${path.basename(file)}`);
    }
    return parsed as Record<string, unknown>;
}

function codegenEnvironment(input: FrozenDepsInput, isolation: Isolation): NodeJS.ProcessEnv {
    return {
        ...input.environment,
        PATH: `${isolation.bin}${path.delimiter}${input.environment.PATH ?? ""}`,
        PSY_FROZEN_DEPS_ROOT: input.root,
        PSY_FROZEN_DEPS_PNPM: input.cachedPnpm,
        PSY_FROZEN_DEPS_STORE: input.store,
        PSY_FROZEN_DEPS_MARKER: isolation.marker,
        PSY_FROZEN_DEPS_HOME: isolation.home,
        PSY_FROZEN_DEPS_XDG: isolation.xdg,
        PSY_FROZEN_DEPS_USERCONFIG: isolation.userconfig,
        PSY_FROZEN_DEPS_GLOBALCONFIG: isolation.globalconfig,
        PSY_FROZEN_DEPS_DIR: isolation.directory,
    };
}

function createIsolation(): Isolation {
    const directory = mkdtempSync(path.join(tmpdir(), "psy-frozen-deps-"));
    const isolation: Isolation = {
        directory,
        home: path.join(directory, "home"),
        xdg: path.join(directory, "xdg"),
        userconfig: path.join(directory, "empty.npmrc"),
        globalconfig: path.join(directory, "empty-global.npmrc"),
        marker: path.join(directory, "failure"),
        bin: path.join(directory, "bin"),
    };
    for (const dir of [
        isolation.home,
        isolation.xdg,
        isolation.bin,
        path.join(directory, "data"),
        path.join(directory, "cache"),
        path.join(directory, "state"),
    ]) mkdirSync(dir);
    writeFileSync(isolation.userconfig, "");
    writeFileSync(isolation.globalconfig, "");
    writeFileSync(isolation.marker, "");
    return isolation;
}

function writeWrappers(isolation: Isolation): void {
    const moduleUrl = pathToFileURL(path.join(path.dirname(new URL(import.meta.url).pathname), "frozenDeps.ts")).href;
    const source = `#!/usr/bin/env bun\nimport { dispatchFrozenDepsProcess } from ${JSON.stringify(moduleUrl)};\nprocess.exit(await dispatchFrozenDepsProcess());\n`;
    for (const name of ["pnpm", "npm"]) writeFileSync(path.join(isolation.bin, name), source, { mode: 0o755 });
}

function rememberFailure(marker: string, reason: string): void {
    writeFileSync(marker, `${reason}\n`, { flag: "a" });
}

function canonicalDir(dir: string): string {
    const stat = lstatSync(dir);
    if (!stat.isDirectory()) throw new Error(`not a directory: ${dir}`);
    return realpathSync(dir);
}

function exists(file: string): boolean {
    try {
        lstatSync(file);
        return true;
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
        throw error;
    }
}

function sameArgs(actual: readonly string[], expected: readonly string[]): boolean {
    return actual.length === expected.length && actual.every((arg, index) => arg === expected[index]);
}

function requiredEnv(name: string): string {
    const value = process.env[name];
    if (!value) throw new Error(`missing ${name}`);
    return value;
}
