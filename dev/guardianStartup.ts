import { promises as fs } from "node:fs";
import path from "node:path";
import { homedir } from "node:os";

export type GuardianStartup = { directory: string; guardianPath: string; daemonPath: string };

export async function planGuardianStartup(cwd: string, env: NodeJS.ProcessEnv, localFullStack: boolean): Promise<GuardianStartup | undefined> {
    if (env.PSY_GUARDIAN_AUTO_PREPARE !== "1") return;
    const directory = path.resolve(env.PSY_DEVNET_DIR || path.join(homedir(), ".psy/devnet/local"));
    const guardianPath = path.join(directory, "guardians/config.json");
    const daemonPath = path.join(directory, "daemon.toml");
    const present = async (file: string) => {
        try { await fs.lstat(file); return true; } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
            throw error;
        }
    };
    if (await present(path.resolve(cwd, env.PSY_BRIDGE_DAEMON_CONFIG || daemonPath))) return;
    if (await present(guardianPath)) throw new Error("Existing Guardian configuration has no daemon.toml; restore its daemon configuration before startup (authorization and journal are unchanged)");
    if (!localFullStack) throw new Error("Automatic Guardian preparation requires the foreground localhost non-fork L1/L2 stack; provision other deployments explicitly");
    for (const [name, expected] of Object.entries({
        PSY_GUARDIAN_CONFIG: guardianPath, PSY_BRIDGE_DAEMON_CONFIG: daemonPath,
        PSY_RELAYER_MULTISIG_ACCOUNT: path.join(directory, "relayer-multisig-account.json"),
        PSY_MULTISIG_POLICY_ARTIFACT: path.join(directory, "inputs/multisig_policy.json"),
    })) {
        if (env[name] && path.resolve(cwd, env[name]!) !== expected) throw new Error(`${name} overrides the local Guardian preparation paths; remove stale overrides or provision explicitly`);
    }
    for (const name of ["PSY_GUARDIANS_ROOT", "PSY_GUARDIAN_CHAINS", "PSY_GUARDIAN_L1_ENDPOINTS", "PSY_GUARDIAN_APPROVED_CONTRACTS"]) {
        if (env[name]) throw new Error(`${name} requires explicit Guardian provisioning, not automatic preparation`);
    }
    if (!(await present(path.join(cwd, "genesis.json")))) throw new Error("Guardian preparation requires an existing verified genesis.json; explicit Genesis generation is required before startup");
    if (await present(path.dirname(guardianPath)) && !(await present(guardianPath))) throw new Error("Partial Guardian root exists; preserve it and diagnose the failed generation instead of replacing it");
    return { directory, guardianPath, daemonPath };
}

export async function prepareGuardianStartup(
    cwd: string, startup: GuardianStartup, run: (args: string[]) => Promise<void>,
): Promise<void> {
    try {
        await fs.lstat(startup.guardianPath);
        throw new Error("Guardian configuration appeared during startup; preserve authorization and journal, then restart with the existing configuration");
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await run(["bun", "run", path.join(cwd, "dev/guardianInputs.ts"), "--output", path.join(startup.directory, "inputs"),
        ...(process.env.PSY_COMPILER_ARTIFACTS_DIR ? ["--compiler-artifacts", process.env.PSY_COMPILER_ARTIFACTS_DIR] : [])]);
    await run(["env", "-u", "PRIVATE_KEY", "-u", "BRIDGE_RELAYER_L2_PRIVATE_KEY", "-u", "KEYSTORE_PATH",
        "-u", "PSY_BRIDGE_RELAYER_KEYSTORE_PATH", "-u", "BRIDGE_RELAYER_KEYSTORE_PATH", "-u", "WALLET_PASSWORD",
        path.join(cwd, "target/release/psy_dev_cli"), "generate-genesis-data", "--repo-root", cwd,
        "--relayer-multisig-account", path.join(startup.directory, "relayer-multisig-account.json"),
        "--multisig-policy-artifact", path.join(startup.directory, "inputs/multisig_policy.json"),
        "--guardians-root", path.dirname(startup.guardianPath),
        "--chains", path.join(startup.directory, "inputs/chains.json"),
        "--l1-endpoints", path.join(startup.directory, "inputs/l1-endpoints.json"),
        "--approved-contracts", path.join(startup.directory, "inputs/approved-contracts.json")]);
    await run(["bun", "run", path.join(cwd, "dev/guardianConfig.ts"), startup.guardianPath, startup.daemonPath]);
}
