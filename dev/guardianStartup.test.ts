import { describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { planGuardianStartup, prepareGuardianStartup } from "./guardianStartup";

async function fixture(run: (cwd: string, env: NodeJS.ProcessEnv) => Promise<void>) {
    const cwd = await fs.mkdtemp(path.join(os.tmpdir(), "psy-guardian-startup-"));
    try {
        await fs.writeFile(path.join(cwd, "genesis.json"), "verified fixture");
        await run(cwd, { PSY_GUARDIAN_AUTO_PREPARE: "1", PSY_DEVNET_DIR: path.join(cwd, "operator") });
    } finally { await fs.rm(cwd, { recursive: true, force: true }); }
}

describe("Guardian startup preparation", () => {
    test("is opt-in and leaves existing daemon provisioning to strict preflight", async () => {
        await fixture(async (cwd, env) => {
            expect(await planGuardianStartup(cwd, {}, true)).toBeUndefined();
            await fs.mkdir(env.PSY_DEVNET_DIR!);
            await fs.writeFile(path.join(env.PSY_DEVNET_DIR!, "daemon.toml"), "existing");
            expect(await planGuardianStartup(cwd, env, false)).toBeUndefined();
        });
    });
    test("rejects remote/component-only mode, stale overrides, absent Genesis and partial roots", async () => {
        await fixture(async (cwd, env) => {
            await expect(planGuardianStartup(cwd, env, false)).rejects.toThrow("localhost");
            await expect(planGuardianStartup(cwd, { ...env, PSY_GUARDIAN_CONFIG: "/tmp/v6/config.json" }, true)).rejects.toThrow("stale overrides");
            await expect(planGuardianStartup(cwd, { ...env, PSY_GUARDIANS_ROOT: "/tmp/v6" }, true)).rejects.toThrow("explicit Guardian provisioning");
            await fs.mkdir(path.join(env.PSY_DEVNET_DIR!, "guardians"), { recursive: true });
            await expect(planGuardianStartup(cwd, env, true)).rejects.toThrow("Partial Guardian root");
            await fs.unlink(path.join(cwd, "genesis.json"));
            await expect(planGuardianStartup(cwd, env, true)).rejects.toThrow("existing verified genesis.json");
        });
    });
    test("prepares approvals then root then daemon without generating Genesis or calling shutdown", async () => {
        await fixture(async (cwd, env) => {
            const startup = (await planGuardianStartup(cwd, env, true))!;
            const calls: string[][] = [];
            await prepareGuardianStartup(cwd, startup, async (args) => { calls.push(args); });
            expect(calls).toHaveLength(3);
            expect(calls[0]).toContain(path.join(cwd, "dev/guardianInputs.ts"));
            expect(calls[1]).toContain("--guardians-root");
            expect(calls[1]).toContain("WALLET_PASSWORD");
            expect(calls[2]).toContain(path.join(cwd, "dev/guardianConfig.ts"));
            expect(await fs.readFile(path.join(cwd, "genesis.json"), "utf8")).toBe("verified fixture");
        });
    });
    test("reuses a retained root without discovering or regenerating approvals", async () => {
        await fixture(async (cwd, env) => {
            const startup = (await planGuardianStartup(cwd, env, true))!;
            await fs.mkdir(path.dirname(startup.guardianPath), { recursive: true });
            await fs.writeFile(startup.guardianPath, "retained config");
            const calls: string[][] = [];
            await prepareGuardianStartup(cwd, startup, async (args) => { calls.push(args); });
            expect(calls).toHaveLength(1);
            expect(calls[0]).toContain(path.join(cwd, "dev/guardianConfig.ts"));
            expect(await fs.readFile(startup.guardianPath, "utf8")).toBe("retained config");
        });
    });
    test("stops at the first failure without resetting or retrying", async () => {
        await fixture(async (cwd, env) => {
            const startup = (await planGuardianStartup(cwd, env, true))!;
            let calls = 0;
            await expect(prepareGuardianStartup(cwd, startup, async () => { calls++; throw new Error("artifact mismatch"); })).rejects.toThrow("artifact mismatch");
            expect(calls).toBe(1);
        });
    });
});
