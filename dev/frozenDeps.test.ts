import { mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "bun:test";
import {
    frozenDepsEnabled,
    guardedEnvioCodegen,
    type FrozenDepsChildStatus,
    type FrozenDepsRunner,
} from "./frozenDeps";

const approvedLock = readFileSync(new URL("../psy_cli/psy_relayer_cli/indexer/envio/pnpm-lock.yaml", import.meta.url));
// Exact public Envio v2.32.10 template, including its final LF.
const generatedNpmrc = "save-exact=true # Since we want specific versions of envio to be completely stable.\n";
const ROOT_MANIFEST = {
    name: "psy-relayer-envio",
    dependencies: {
        "@envio-dev/hypersync-client": "1.3.0",
        "poseidon-goldilocks-lite": "^0.2.3",
    },
    devDependencies: { envio: "2.32.10", typescript: "5.6.3" },
};
const GENERATED_MANIFEST = {
    name: "generated",
    dependencies: {
        "ts-node": "10.9.1",
        "@rescript/react": "0.12.1",
        "bignumber.js": "9.1.2",
        "date-fns": "3.3.1",
        dotenv: "16.4.5",
        ethers: "6.8.0",
        express: "4.19.2",
        ink: "3.2.0",
        "ink-big-text": "1.2.0",
        "ink-spinner": "4.0.3",
        "js-sdsl": "4.4.2",
        pino: "8.16.1",
        postgres: "3.4.1",
        react: "18.2.0",
        rescript: "11.1.3",
        "rescript-envsafe": "5.0.0",
        "rescript-schema": "9.3.0",
        envio: "2.32.10",
        viem: "2.21.0",
        yargs: "17.7.2",
        "prom-client": "15.0.0",
    },
};

type Fixture = { base: string; root: string; pnpm: string; store: string; calls: string[][] };

function fixture(lock: Buffer = approvedLock): Fixture {
    const base = mkdtempSync(path.join(tmpdir(), "psy-frozen-fixture-"));
    const root = path.join(base, "envio");
    const cache = path.join(base, "cache", "node", "corepack", "v1", "pnpm", "10.33.0", "bin");
    mkdirSync(path.join(root, "generated"), { recursive: true });
    mkdirSync(cache, { recursive: true });
    mkdirSync(path.join(base, "store"));
    writeFileSync(path.join(root, "package.json"), `${JSON.stringify(ROOT_MANIFEST)}\n`);
    writeFileSync(path.join(root, "generated", "package.json"), `${JSON.stringify(GENERATED_MANIFEST)}\n`);
    writeFileSync(path.join(root, "pnpm-lock.yaml"), lock);
    writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages:\n  - generated\n");
    const pnpm = path.join(cache, "pnpm.cjs");
    writeFileSync(pnpm, "");
    return {
        base,
        root: realpathSync(root),
        pnpm: realpathSync(pnpm),
        store: realpathSync(path.join(base, "store")),
        calls: [],
    };
}

async function drive(
    tree: Fixture,
    script: readonly (readonly [string[], string])[],
    codegenStatus: FrozenDepsChildStatus = { code: 0, signal: null },
    runner?: FrozenDepsRunner,
): Promise<void> {
    await guardedEnvioCodegen({
        root: tree.root,
        cachedPnpm: tree.pnpm,
        store: tree.store,
        environment: { PATH: "/usr/bin", HOME: tree.root, npm_config_registry: "https://evil.example" },
        runner: runner ?? (async (_command, args) => {
            tree.calls.push([...args]);
            return { code: 0, signal: null };
        }),
        codegen: async (context) => {
            expect(context.environment.PATH?.split(path.delimiter)[0]).toMatch(/psy-frozen-deps-.+\/bin$/);
            expect(context.environment.PSY_FROZEN_DEPS_PNPM).toBe(tree.pnpm);
            expect(context.environment.PSY_FROZEN_DEPS_STORE).toBe(tree.store);
            for (const [argv, cwd] of script) await context.dispatch(argv, cwd);
            return codegenStatus;
        },
    });
}

describe("PSY_FROZEN_DEPS", () => {
    it("accepts only the exact value 1", () => {
        expect(frozenDepsEnabled("1")).toBe(true);
        for (const value of [undefined, "", "0", "true", " 1", "1\n"]) expect(frozenDepsEnabled(value)).toBe(false);
    });
});

describe("guarded Envio codegen", () => {
    it("rewrites the reviewed installs and keeps optional packages", async () => {
        const tree = fixture();
        try {
            const generated = realpathSync(path.join(tree.root, "generated"));
            await drive(tree, [
                [["pnpm", "--version"], generated],
                [["pnpm", "install", "--no-lockfile", "--prefer-offline"], generated],
                [["pnpm", "install", "--prefer-offline"], tree.root],
                [["pnpm", "rescript"], generated],
            ]);
            const frozenInstall = [
                "install", "--offline", "--frozen-lockfile", "--ignore-scripts",
                `--lockfile-dir=${tree.root}`, `--store-dir=${tree.store}`,
                "--verify-store-integrity=true", "--registry=https://registry.npmjs.org/",
            ];
            expect(tree.calls.map((args) => args.slice(-1)[0] === "--version" || args.at(-1) === "rescript" ? args.at(-1) : args.slice(-8))).toEqual([
                "--version",
                frozenInstall,
                frozenInstall,
                "rescript",
            ]);
            for (const args of tree.calls) {
                expect(args[0]).toBe(tree.pnpm);
                expect(args).toContain("--config.ignore-pnpmfile=true");
                expect(args).toContain("--config.manage-package-manager-versions=false");
                expect(args).not.toContain("--manage-package-manager-versions=false");
                const userconfig = args.find((arg) => arg.startsWith("--config.userconfig="))?.slice("--config.userconfig=".length);
                const globalconfig = args.find((arg) => arg.startsWith("--config.globalconfig="))?.slice("--config.globalconfig=".length);
                expect(userconfig).toMatch(/^\/.*\/psy-frozen-deps-[^/]+\/empty\.npmrc$/);
                expect(globalconfig).toMatch(/^\/.*\/psy-frozen-deps-[^/]+\/empty-global\.npmrc$/);
                expect(path.dirname(userconfig ?? "")).toBe(path.dirname(globalconfig ?? ""));
                expect(args.join(" ")).not.toContain("--no-optional");
                expect(args.join(" ")).not.toContain("--no-lockfile");
                expect(args.join(" ")).not.toContain("--prefer-offline");
            }
        } finally {
            rmSync(tree.base, { recursive: true, force: true });
        }
    });

    it("records malformed argv and does not spawn", async () => {
        const tree = fixture();
        try {
            const generated = path.join(tree.root, "generated");
            await expect(drive(tree, [[["pnpm", "install", "--no-frozen-lockfile"], tree.root]])).rejects.toThrow(/rejected pnpm argv/);
            await expect(drive(tree, [[["pnpm", "--version"], tree.root]])).rejects.toThrow(/rejected pnpm argv/);
            await expect(drive(tree, [[["pnpm", "install", "--prefer-offline", "--ignore-scripts"], tree.root]])).rejects.toThrow(/rejected pnpm argv/);
            await expect(drive(tree, [[["npm", "install", "--global", "pnpm"], generated]])).rejects.toThrow(/rejected command: npm/);
            expect(tree.calls).toEqual([]);
        } finally {
            rmSync(tree.base, { recursive: true, force: true });
        }
    });

    it("rejects malformed or changed manifests and a different lock", async () => {
        const changed = fixture();
        const manifest = { ...GENERATED_MANIFEST, dependencies: { ...GENERATED_MANIFEST.dependencies, envio: "2.32.11" } };
        writeFileSync(path.join(changed.root, "generated", "package.json"), JSON.stringify(manifest));
        const broken = fixture();
        writeFileSync(path.join(broken.root, "package.json"), "{]");
        const unlocked = fixture(Buffer.from("not-the-approved-lock\n"));
        const policy = fixture();
        writeFileSync(path.join(policy.root, "package.json"), JSON.stringify({ ...ROOT_MANIFEST, pnpm: { neverBuiltDependencies: [] } }));
        try {
            await expect(drive(changed, [])).rejects.toThrow(/generated dependencies/);
            await expect(drive(broken, [])).rejects.toThrow(/malformed manifest/);
            await expect(drive(unlocked, [])).rejects.toThrow(/approved frozen dependency lock/);
            await expect(drive(policy, [])).rejects.toThrow(/pnpm dependency policy/);
        } finally {
            for (const tree of [changed, broken, unlocked, policy]) rmSync(tree.base, { recursive: true, force: true });
        }
    });

    it("accepts the exact generated template created by codegen without modifying it", async () => {
        const tree = fixture();
        const generated = path.join(tree.root, "generated");
        const config = path.join(generated, ".npmrc");
        try {
            await guardedEnvioCodegen({
                root: tree.root, cachedPnpm: tree.pnpm, store: tree.store, environment: {},
                runner: async (_command, args) => {
                    tree.calls.push([...args]);
                    return { code: 0, signal: null };
                },
                codegen: async ({ dispatch }) => {
                    writeFileSync(config, generatedNpmrc);
                    expect(await dispatch(["pnpm", "--version"], generated)).toBe(0);
                    expect(await dispatch(["pnpm", "install", "--no-lockfile", "--prefer-offline"], generated)).toBe(0);
                    expect(await dispatch(["pnpm", "install", "--prefer-offline"], tree.root)).toBe(0);
                    expect(await dispatch(["pnpm", "rescript"], generated)).toBe(0);
                    return { code: 0, signal: null };
                },
            });
            expect(tree.calls).toHaveLength(4);
            expect(readFileSync(config, "utf8")).toBe(generatedNpmrc);
            await drive(tree, [[["pnpm", "--version"], generated]]);
        } finally {
            rmSync(tree.base, { recursive: true, force: true });
        }
    });

    it("rejects altered, oversized, nonregular, symlinked, or misplaced templates", async () => {
        for (const variant of ["changed", "oversized", "directory", "symlink", "root", "ancestor"]) {
            const tree = fixture();
            const config = path.join(tree.root, "generated", ".npmrc");
            try {
                switch (variant) {
                    case "changed": writeFileSync(config, generatedNpmrc.replace("true", "True")); break;
                    case "oversized": writeFileSync(config, generatedNpmrc + "\n"); break;
                    case "directory": mkdirSync(config); break;
                    case "symlink": {
                        const target = path.join(tree.base, "public-template");
                        writeFileSync(target, generatedNpmrc);
                        symlinkSync(target, config);
                        break;
                    }
                    case "root": writeFileSync(path.join(tree.root, ".npmrc"), generatedNpmrc); break;
                    case "ancestor":
                        writeFileSync(path.join(tree.base, "package.json"), "{}");
                        writeFileSync(path.join(tree.base, ".npmrc"), generatedNpmrc);
                        break;
                }
                await expect(drive(tree, [])).rejects.toThrow(/refuse project config/);
                expect(tree.calls).toEqual([]);
            } finally {
                rmSync(tree.base, { recursive: true, force: true });
            }
        }
    });

    it("refuses project config by existence and allows a manifest-free ancestor", async () => {
        const project = fixture();
        writeFileSync(path.join(project.root, ".npmrc"), "//secret\n");
        const generated = fixture();
        writeFileSync(path.join(generated.root, "generated", ".npmrc"), "//secret\n");
        const ancestor = fixture();
        const parent = mkdtempSync(path.join(tmpdir(), "psy-frozen-ancestor-"));
        writeFileSync(path.join(parent, "package.json"), "{}");
        writeFileSync(path.join(parent, ".npmrc"), "//secret\n");
        const moved = path.join(parent, "envio");
        renameSync(ancestor.root, moved);
        ancestor.root = moved;
        const userOnly = fixture();
        writeFileSync(path.join(userOnly.base, ".npmrc"), "//secret\n");
        try {
            await expect(drive(project, [])).rejects.toThrow(/refuse project config/);
            await expect(drive(generated, [])).rejects.toThrow(/refuse project config/);
            await expect(drive(ancestor, [])).rejects.toThrow(/refuse project config/);
            await drive(userOnly, []);
        } finally {
            rmSync(parent, { recursive: true, force: true });
            for (const tree of [project, generated, ancestor, userOnly]) rmSync(tree.base, { recursive: true, force: true });
        }
    });

    it("records child failure and blocks the later rescript", async () => {
        const tree = fixture();
        const runner: FrozenDepsRunner = async (_command, args) => {
            tree.calls.push([...args]);
            return args.includes("install") ? { code: 3, signal: null } : { code: 0, signal: null };
        };
        try {
            await expect(drive(tree, [
                [["pnpm", "install", "--no-lockfile", "--prefer-offline"], path.join(tree.root, "generated")],
                [["pnpm", "rescript"], path.join(tree.root, "generated")],
            ], { code: 0, signal: null }, runner)).rejects.toThrow(/child failed code=3/);
            expect(tree.calls).toHaveLength(1);
        } finally {
            rmSync(tree.base, { recursive: true, force: true });
        }
    });

    it("rejects a zero codegen exit after a signaled or unlaunched child", async () => {
        const tree = fixture();
        const signaled: FrozenDepsRunner = async () => ({ code: null, signal: "SIGTERM" });
        const launch: FrozenDepsRunner = async () => {
            throw new Error("ENOENT cached pnpm");
        };
        try {
            await expect(drive(tree, [[["pnpm", "--version"], path.join(tree.root, "generated")]], { code: 0, signal: null }, signaled))
                .rejects.toThrow(/signal=SIGTERM/);
            await expect(drive(tree, [], { code: 2, signal: null })).rejects.toThrow(/envio codegen failed code=2/);
            await expect(drive(tree, [[["pnpm", "rescript"], path.join(tree.root, "generated")]], { code: 0, signal: null }, launch))
                .rejects.toThrow(/spawn failed: ENOENT cached pnpm/);
        } finally {
            rmSync(tree.base, { recursive: true, force: true });
        }
    });
});
