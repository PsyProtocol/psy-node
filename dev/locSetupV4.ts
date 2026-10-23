import { parseArgs, isDeepStrictEqual } from "util";
import { rm, exists, mkdir, writeFile } from "fs/promises";
import fs from "fs";
import path from "path";
import net from "node:net";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { availableParallelism } from "node:os";
import { execFile, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { frozenDepsEnabled, frozenDepsCommandRunner, guardedEnvioCodegen } from "./frozenDeps";
import allConfig from "../psy-genesis/config.json";
import { protocolConfig } from "../psy-contracts/protocol-config";
import {
    COORDINATOR_PROCESSOR_READY_MARKER,
    DEFAULT_WORKER_BATCH_SIZE,
    FAUCET_ENV_KEYS,
    PSY_DAPP_NESTED_PAYLOADS,
    PSY_DAPP_NESTED_SUBMODULES,
    PSY_SDK_GENESIS_CONFIG_REL,
    PSY_SDK_GENESIS_SUBMODULE,
    REALM_PROCESSOR_READY_MARKER,
    SUPERVISOR_RESTART_LIMIT_TAG,
    applyEnvioCpuSetToCompose,
    applyEnvioNetworkName,
    classifySupervisedExit,
    emptyRestartStreak,
    failureSignature,
    formatBridgeRelayerKeystoreDecryptError,
    formatPsyDappNestedSubmoduleRemedy,
    hasFaucetOperatorConfig,
    hasZstdMagic,
    parseCpuSet,
    isExactProcessorReadyLine,
    isTransientScyllaSchemaFailure,
    nextSpawnRetryDelayMs,
    parseFatalProcessorErrorMarker,
    parseRealmProcessorFailureLine,
    parseLscpuTopology,
    planSupervisedRestart,
    shouldScheduleSupervisedRestart,
    resolveCpuPartition,
    parseEnvAssignments,
    resolveCpuPartitionForAffinity,
    resolvePositiveIntegerSetting,
    resolveRayonThreadCount,
    resolveRealmWorkerCount,
    resolveWalletPasswordPolicy,
    resolveScyllaMemory,
    selectNonEmptyEnv,
    shouldSkipBranchSync,
    psySdkGenesisSubmoduleNeedsInit,
    planPsyDappNestedSubmoduleInit,
    isCompilerFingerprintSource,
    r2CurlArgs,
    psyServicesDatabaseCommands,
    pinFaucetPerClaimAmount,
    DEVNET_NAMESPACE_ENV,
    resolveDevnetDbNamesFromEnv,
    resolveDevnetDbNames,
    devnetDbContainerNames,
    devnetDbVolumeNames,
    devnetIsolationResources,
    envioPostgresReadinessCommand,
    envioServicesDatabaseProbeCommand,
    envioComposeCommand,
} from "./locSetupPolicy";
import type {
    DevnetDbNames,
    FatalProcessorErrorMarker,
    PsyDappNestedInitPlan,
    PsyDappNestedSubmodule,
    RestartStreak,
} from "./locSetupPolicy";

/**
 * Retry processor creation only for the known transient Scylla schema family.
 * The caller must return only after the full processor marker, so no failed
 * pre-ready child is ever exposed to supervisor tracking.
 */
export async function retryProcessorStartup<T>(
    name: string,
    startAttempt: (attempt: number, totalAttempts: number) => Promise<T>,
    opts?: { maxRetries?: number; retryDelayMs?: number },
): Promise<T> {
    const maxRetries = opts?.maxRetries ?? 3;
    const retryDelayMs = opts?.retryDelayMs ?? 2000;
    if (!Number.isInteger(maxRetries) || maxRetries < 0) {
        throw new Error(`Processor readiness maxRetries must be a non-negative integer, received ${maxRetries}`);
    }
    if (!Number.isFinite(retryDelayMs) || retryDelayMs < 0) {
        throw new Error(`Processor readiness retryDelayMs must be non-negative, received ${retryDelayMs}`);
    }
    const totalAttempts = maxRetries + 1;
    const attemptErrors: string[] = [];
    let sawTransientScyllaFailure = false;
    for (let attempt = 1; attempt <= totalAttempts; attempt += 1) {
        console.log(`[DevNet] Starting ${name} readiness attempt ${attempt}/${totalAttempts}`);
        try {
            return await startAttempt(attempt, totalAttempts);
        } catch (error) {
            const context = error instanceof Error ? error.message : String(error);
            attemptErrors.push(`Attempt ${attempt}/${totalAttempts}: ${context}`);
            const isTransientScyllaFailure = isTransientScyllaSchemaFailure(context);
            const isPostScyllaReadinessTimeout = sawTransientScyllaFailure
                && context.includes("did not reach its initialization marker within");
            if (!isTransientScyllaFailure && !isPostScyllaReadinessTimeout) {
                throw new Error(`${name} exited before full readiness.\n${attemptErrors.join("\n\n")}`);
            }
            sawTransientScyllaFailure ||= isTransientScyllaFailure;
            if (attempt === totalAttempts) {
                throw new Error(
                    `${name} exhausted ${totalAttempts} readiness attempts after transient Scylla startup failures.\n`
                    + attemptErrors.join("\n\n"),
                );
            }
            console.warn(
                `[DevNet] ${name} readiness attempt ${attempt}/${totalAttempts} hit a transient Scylla startup failure; `
                + `retrying the whole process in ${retryDelayMs}ms`,
            );
            if (retryDelayMs > 0) {
                const { promise, resolve } = Promise.withResolvers<void>();
                setTimeout(resolve, retryDelayMs);
                await promise;
            }
        }
    }

    throw new Error(`${name} processor readiness loop ended unexpectedly`);
}

type ProcessLineVisitor = (line: string, process: RunningProcess) => void;
// this is an insecure, obviously fake private key for local devnet use only
const FAKE_MINER_PRIVATE_KEY = "691337BADFACE067320cb499a730fa6c81a756ed912f181f0f20a6b1fa5c1337";
export const DEVNET_NAMESPACE_BINDING = path.join("local_checkpoints", "devnet-namespace");

export async function resolveBoundDevnetNames(repoRoot: string, env: NodeJS.ProcessEnv = process.env): Promise<DevnetDbNames> {
    const bindingPath = path.join(repoRoot, DEVNET_NAMESPACE_BINDING);
    let stored: string | null = null;
    try { stored = (await fs.promises.readFile(bindingPath, "utf8")).trim(); }
    catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const explicit = env[DEVNET_NAMESPACE_ENV];
    const explicitSet = explicit != null && explicit !== "";
    if (stored !== null) {
        const bound = resolveDevnetDbNames(stored === "" ? null : stored);
        if (explicitSet && bound.namespace !== resolveDevnetDbNames(explicit).namespace) {
            throw new Error(`[DevNet] ${DEVNET_NAMESPACE_ENV} does not match the worktree binding`);
        }
        return bound;
    }
    if (explicitSet) throw new Error(`[DevNet] ${DEVNET_NAMESPACE_ENV} has no committed worktree binding`);
    return resolveDevnetDbNames(null);
}

export async function commitDevnetNamespaceBinding(repoRoot: string, names: DevnetDbNames): Promise<void> {
    const bindingPath = path.join(repoRoot, DEVNET_NAMESPACE_BINDING);
    const bindingDir = path.dirname(bindingPath);
    // New trees get an owner-only directory; a pre-existing directory is only
    // validated, never chmod'ed (it may hold operator-managed checkpoints).
    await mkdir(bindingDir, { recursive: true, mode: 0o700 });
    if ((await fs.promises.stat(bindingDir)).mode & 0o22) {
        throw new Error(`[DevNet] binding directory ${bindingDir} must not be group/other-writable`);
    }
    const pendingPath = `${bindingPath}.pending-${process.pid}`;
    // Explicit 0600: bare "wx" inherits the umask (0664 under umask 002), which
    // the fresh-state helper rejects for owner-controlled files.
    const handle = await fs.promises.open(pendingPath, "wx", 0o600);
    try {
        await handle.writeFile(`${names.namespace ?? ""}\n`);
        await handle.sync();
    } finally { await handle.close(); }
    try {
        // link is exclusive: never replace a binding published by another owner.
        await fs.promises.link(pendingPath, bindingPath);
    } finally { await fs.promises.unlink(pendingPath); }
    const directory = await fs.promises.open(path.dirname(bindingPath), "r");
    try { await directory.sync(); } finally { await directory.close(); }
}

export async function reserveDevnetNamespace(repoRoot: string, env: NodeJS.ProcessEnv = process.env): Promise<DevnetDbNames> {
    const bindingPath = path.join(repoRoot, DEVNET_NAMESPACE_BINDING);
    if (await exists(bindingPath)) return resolveBoundDevnetNames(repoRoot, env);
    const names = resolveDevnetDbNamesFromEnv(env);
    await assertFreshDevnetNamespace(names);
    await commitDevnetNamespaceBinding(repoRoot, names);
    return names;
}
async function assertFreshDevnetNamespace(names: DevnetDbNames): Promise<void> {
    const wanted = devnetIsolationResources(names);
    wanted.containers.push(`${names.envioComposeProject}-graphql-engine-1`);
    wanted.networks.push(names.namespace === null ? "psy-devnet" : `${names.namespace}-psy-devnet`);
    const checks: Array<[string, string[], string[]]> = [
        ["container", ["docker", "ps", "-a", "--format", "{{.Names}}"], wanted.containers],
        ["volume", ["docker", "volume", "ls", "--format", "{{.Name}}"], wanted.volumes],
        ["network", ["docker", "network", "ls", "--format", "{{.Name}}"], wanted.networks],
    ];
    for (const [kind, argv, expected] of checks) {
        const listed = await runTeardownCommand(argv, undefined, PURGE_DOCKER_TIMEOUT_MS);
        if (listed.timedOut || listed.code !== 0 || !listed.stdoutComplete) {
            throw new Error(`[DevNet] cannot prove ${kind} absence for namespace ${names.namespace}`);
        }
        const present = exactSnapshotNames(listed.stdout);
        const collision = expected.filter((name) => present.has(name));
        if (collision.length > 0) throw new Error(`[DevNet] namespace ${names.namespace} already owns ${kind}: ${collision.join(", ")}`);
    }
    for (const port of [6379, 4222, 9042, 8081, 5433, 8080, 8545, 9545, 10545]) {
        if (await tcpPortOpen(port)) throw new Error(`[DevNet] namespace ${names.namespace} requires free port ${port}`);
    }
}

async function runIgnoreErrors(cmd: string[], cwd?: string): Promise<void> {
    try {
        await runAndCapture(cmd, cwd);
    } catch {
        // best-effort teardown helper
    }
}

function isTruthyEnv(value: string | undefined): boolean {
    if (!value) return false;
    return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}

type RuntimeResourceSettings = {
    workerBatchSize: string;
    runtimeCpuSet?: string;
    scyllaCpuSet?: string;
    scyllaSmp: string;
    env: { [key: string]: string };
};

async function resolveRuntimeResourceSettings(
    env: { [key: string]: string },
    provingProcessCount: number,
    shouldPartitionCpus: boolean,
): Promise<RuntimeResourceSettings> {
    const workerBatchSize = resolvePositiveIntegerSetting(
        env.PSY_WORKER_BATCH_SIZE,
        DEFAULT_WORKER_BATCH_SIZE,
        "PSY_WORKER_BATCH_SIZE",
    );
    let runtimeCpuSet: string | undefined;
    let scyllaCpuSet: string | undefined;
    let runtimePhysicalCoreCount = availableParallelism();
    let detectedScyllaSmp: number | undefined;

    const requestedRuntimeCpuSet = env.PSY_RUNTIME_CPUSET?.trim() || undefined;
    const requestedScyllaCpuSet = env.SCYLLA_CPUSET?.trim() || undefined;
    if (process.platform !== "linux" && (requestedRuntimeCpuSet || requestedScyllaCpuSet)) {
        throw new Error("PSY_RUNTIME_CPUSET and SCYLLA_CPUSET are supported only on Linux");
    }
    if (process.platform === "linux" && !shouldPartitionCpus && (requestedRuntimeCpuSet || requestedScyllaCpuSet)) {
        throw new Error("CPU set overrides require a launch that manages Scylla (--db or full devnet)");
    }
    if (process.platform === "darwin") {
        const physicalCpuResult = await runAndCapture(["sysctl", "-n", "hw.physicalcpu"]);
        const physicalCpuCount = Number(physicalCpuResult.stdout.trim());
        if (physicalCpuResult.code === 0 && Number.isSafeInteger(physicalCpuCount) && physicalCpuCount > 0) {
            runtimePhysicalCoreCount = physicalCpuCount;
        }
    }
    if (process.platform === "linux" && (shouldPartitionCpus || provingProcessCount > 0)) {
        await checkToolAvailable("lscpu", "install the util-linux package");
        const topology = await runAndCapture(["lscpu", "--parse=CPU,CORE,SOCKET"]);
        if (topology.code !== 0) {
            throw new Error(`Failed to inspect Linux CPU topology: ${topology.stderr || topology.stdout}`);
        }
        let allowedCpus: Set<number> | undefined;
        try {
            const status = fs.readFileSync("/proc/self/status", "utf8");
            const allowedList = /^Cpus_allowed_list:\s*(.+)$/m.exec(status)?.[1]?.trim();
            if (allowedList) allowedCpus = parseCpuSet(allowedList);
        } catch {
            allowedCpus = undefined;
        }
        const physicalCoreGroups = parseLscpuTopology(topology.stdout);
        const allowedPhysicalCoreGroups = allowedCpus
            ? parseLscpuTopology(topology.stdout, allowedCpus)
            : physicalCoreGroups;
        if (allowedPhysicalCoreGroups.length > 0) {
            runtimePhysicalCoreCount = allowedPhysicalCoreGroups.length;
        }
        if (shouldPartitionCpus) {
            const partition = resolveCpuPartitionForAffinity(
                physicalCoreGroups,
                allowedCpus,
                requestedScyllaCpuSet,
                requestedRuntimeCpuSet,
            );
            if (partition) {
                runtimeCpuSet = partition.runtimeCpuSet;
                scyllaCpuSet = partition.scyllaCpuSet;
                runtimePhysicalCoreCount = partition.runtimePhysicalCoreCount;
                detectedScyllaSmp = partition.scyllaLogicalCpuCount;
            }
        }
    }

    const rayonThreads = resolvePositiveIntegerSetting(
        env.RAYON_NUM_THREADS,
        resolveRayonThreadCount(runtimePhysicalCoreCount, provingProcessCount),
        "RAYON_NUM_THREADS",
    );
    const scyllaSmp = resolvePositiveIntegerSetting(
        env.SCYLLA_SMP,
        detectedScyllaSmp ?? Math.max(1, Math.min(2, availableParallelism())),
        "SCYLLA_SMP",
    );
    const resourceEnv: { [key: string]: string } = {
        RAYON_NUM_THREADS: rayonThreads.toString(),
        PSY_WORKER_BATCH_SIZE: workerBatchSize.toString(),
        SCYLLA_SMP: scyllaSmp.toString(),
    };
    if (runtimeCpuSet) resourceEnv.PSY_RUNTIME_CPUSET = runtimeCpuSet;
    if (scyllaCpuSet) resourceEnv.SCYLLA_CPUSET = scyllaCpuSet;

    return {
        workerBatchSize: workerBatchSize.toString(),
        runtimeCpuSet,
        scyllaCpuSet,
        scyllaSmp: scyllaSmp.toString(),
        env: resourceEnv,
    };
}

let runtimeCpuSetForChildren: string | undefined;

type L1SignerInfo = {
    address: string;
    keystorePath: string;
};

type L1NetworkName = "localhost" | "sepolia" | "ethereum";
type L1DeploymentNetwork = L1NetworkName | "localhostBsc" | "localhostBase" | "bscTestnet" | "baseSepolia";
type ActiveL1Chain = {
    chainIndex: number;
    prefix: string;
    networkId: L1DeploymentNetwork;
    deploymentsNetwork: L1DeploymentNetwork;
    rpcUrl: string;
};

export function resolveActiveL1Chains(l1Network: L1NetworkName, l1Fork: boolean, l1RpcUrl: string): ActiveL1Chain[] {
    const primary = l1Fork ? "localhost" : l1Network;
    const chains: ActiveL1Chain[] = [{ chainIndex: 0, prefix: "ETH", networkId: primary, deploymentsNetwork: primary, rpcUrl: l1RpcUrl }];
    if (!l1Fork && l1Network !== "ethereum") {
        const local = l1Network === "localhost";
        chains.push(
            { chainIndex: 1, prefix: "BSC", networkId: local ? "localhostBsc" : "bscTestnet", deploymentsNetwork: local ? "localhostBsc" : "bscTestnet", rpcUrl: local ? process.env.LOCALHOST_BSC_RPC_URL || resolveLocalL1RpcUrl(9545) : process.env.BSC_TESTNET_RPC_URL || protocolConfig.chains.bscTestnet.defaultRpcUrl },
            { chainIndex: 2, prefix: "BASE", networkId: local ? "localhostBase" : "baseSepolia", deploymentsNetwork: local ? "localhostBase" : "baseSepolia", rpcUrl: local ? process.env.LOCALHOST_BASE_RPC_URL || resolveLocalL1RpcUrl(10545) : process.env.BASE_SEPOLIA_RPC_URL || protocolConfig.chains.baseSepolia.defaultRpcUrl },
        );
    }
    return chains;
}

/**
 * Post-deploy deployment document of each selected chain, as repeatable
 * `--l1-config PATH` pairs. Exactly the selected chains, one existing document
 * each; the documents stay where deployment wrote them — nothing is copied and
 * no config is written.
 */
export async function resolveL1ConfigArgs(cwd: string, chains: readonly ActiveL1Chain[]): Promise<string[]> {
    const args: string[] = [];
    for (const chain of chains) {
        const documentPath = path.join(cwd, "psy-contracts", "deployments", chain.deploymentsNetwork, "deployed-contracts.json");
        const stat = await fs.promises.lstat(documentPath).catch(() => null);
        if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
            throw new Error(`[DevNet] selected L1 chain ${chain.networkId} has no deployment document at ${documentPath}`);
        }
        args.push("--l1-config", documentPath);
    }
    return args;
}
type ConfigNetworkEntry = {
    l1_rpc_urls?: string[];
    anvilForkSourceUrlEnv?: string;
};

// The Psy stage (genesis config block, VITE_PSY_STAGE) and the L1 target
// network (anvil vs external RPC, psy-contracts/deployments/<name>,
// VITE_NETWORK) are separate namespaces after the stage rename. A stage
// picks the genesis config; an L1 network name picks the chain/deployments
// directory. STAGE_DEFAULT_L1 is the default L1 for a stage when
// VITE_NETWORK is not set explicitly.
type PsyStage = "localhost" | "testnet" | "mainnet";
const STAGE_DEFAULT_L1: Record<PsyStage, L1NetworkName> = {
    localhost: "localhost",
    testnet: "sepolia",
    mainnet: "ethereum",
};
// Reverse map: only the L1 networks that are a stage's default L1 have a
// corresponding genesis config block. bscTestnet/baseSepolia/localhostBsc/
// localhostBase are L1-only names with no genesis stage of their own.
const L1_TO_STAGE: Partial<Record<L1DeploymentNetwork, PsyStage>> = Object.fromEntries(
    (Object.entries(STAGE_DEFAULT_L1) as [PsyStage, L1NetworkName][]).map(([stage, l1]) => [l1, stage]),
);

// The env var that holds the RPC URL to fork/connect to a given L1 network
// is a property of the L1 network, not of the Psy stage: you can run
// VITE_PSY_STAGE=localhost (a local Psy chain / genesis block) while
// VITE_NETWORK=sepolia VITE_FORK=true forks public Sepolia underneath it,
// and that combination must not require picking a non-local stage just to
// name an L1 RPC source — that would recouple the two namespaces this
// rename is meant to separate. The genesis config's per-stage
// anvilForkSourceUrlEnv (when the selected stage happens to define one)
// stays authoritative as an override; this table is the L1-owned fallback.
// Phase 2 moves this table into psy-contracts' protocol config, which is
// the real L1-owned home for it.
const L1_FORK_RPC_ENV: Partial<Record<L1NetworkName, string>> = {
    sepolia: "SEPOLIA_RPC_URL",
    ethereum: "ETH_RPC_URL",
};

function resolveStage(): PsyStage {
    const value = (process.env.VITE_PSY_STAGE || "localhost").trim().toLowerCase();
    if (value === "localhost" || value === "testnet" || value === "mainnet") return value;
    throw new Error(`[DevNet] unsupported VITE_PSY_STAGE=${value}; expected localhost, testnet, or mainnet`);
}
const DEV_TEST_ADDRESSES = [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
] as const;

function resolveL1Selection(): { stage: PsyStage; l1Network: L1NetworkName; l1Fork: boolean; cfgEntry: ConfigNetworkEntry } {
    const stage = resolveStage();
    const l1Network = resolveL1Network(stage);
    const l1Fork = isTruthyEnv(process.env.VITE_FORK);
    if (l1Network === "localhost" && l1Fork) {
        throw new Error("[DevNet] VITE_FORK=true requires VITE_NETWORK=sepolia or ethereum");
    }
    const cfgEntry = (allConfig as any)?.networks?.[stage] as ConfigNetworkEntry | undefined;
    if (!cfgEntry) {
        throw new Error(`[DevNet] config.json networks.${stage} missing`);
    }
    return { stage, l1Network, l1Fork, cfgEntry };
}

let cachedWalletPassword: string | null = null;
/** True when auto-setup generated the bridge-relayer keystore during this process. */
let bridgeRelayerKeystoreGeneratedThisRun = false;

function setBridgeRelayerKeystoreAlias(): { name: string; path: string } | null {
    for (const name of [
        "PSY_BRIDGE_RELAYER_KEYSTORE_PATH",
        "BRIDGE_RELAYER_KEYSTORE_PATH",
        "KEYSTORE_PATH",
    ] as const) {
        const raw = process.env[name];
        if (raw && raw.trim() !== "") {
            return { name, path: raw.trim() };
        }
    }
    return null;
}

function resolveBridgeRelayerKeystorePath(): string {
    const setAlias = setBridgeRelayerKeystoreAlias();
    if (setAlias) {
        return setAlias.path;
    }
    const homeDir = process.env.HOME;
    if (!homeDir) {
        throw new Error("[DevNet] HOME is not set and KEYSTORE_PATH was not provided");
    }
    return path.join(homeDir, ".psy", "keystore", "bridge-relayer");
}

async function resolveWalletPassword(): Promise<string> {
    const keystorePath = resolveBridgeRelayerKeystorePath();
    const keystoreExists = await exists(keystorePath);
    const policy = resolveWalletPasswordPolicy({
        envPassword: process.env.WALLET_PASSWORD,
        cachedPassword: cachedWalletPassword,
        isTty: !!process.stdin.isTTY,
        keystoreExists,
        keystoreGeneratedThisRun: bridgeRelayerKeystoreGeneratedThisRun,
    });

    if (policy.password) {
        if (policy.source === "env" || policy.source === "default-devnet") {
            // Keep process env aligned so child deploy/relayer processes see the same secret.
            process.env.WALLET_PASSWORD = policy.password;
        }
        if (policy.source === "cached" || policy.source === "default-devnet" || policy.source === "env") {
            cachedWalletPassword = policy.password;
        }
        return policy.password;
    }

    if (policy.error) {
        throw new Error(`[DevNet] ${policy.error}`);
    }

    // Interactive path: existing keystore or first-run without env password.
    const { createInterface } = await import("node:readline/promises");
    const rl = createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    try {
        const password = (await rl.question("Enter WALLET_PASSWORD for bridge-relayer keystore: ")).trim();
        if (!password) {
            throw new Error(
                keystoreExists && !bridgeRelayerKeystoreGeneratedThisRun
                    ? "WALLET_PASSWORD is required when using an existing bridge-relayer keystore"
                    : "WALLET_PASSWORD is required when using bridge-relayer keystore",
            );
        }
        cachedWalletPassword = password;
        process.env.WALLET_PASSWORD = password;
        return password;
    } finally {
        rl.close();
    }
}

async function loadBridgeRelayerSigner(repoCwd: string): Promise<L1SignerInfo> {
    const keystorePath = resolveBridgeRelayerKeystorePath();
    if (!(await exists(keystorePath))) {
        throw new Error(`[DevNet] bridge relayer keystore not found: ${keystorePath}`);
    }
    const password = await resolveWalletPassword();
    const contractsDir = path.join(repoCwd, "psy-contracts");
    const decodeScript = `
const { Wallet } = require("ethers");
const fs = require("fs");
(async () => {
  const json = fs.readFileSync(process.argv[1], "utf8");
  const password = (process.env.WALLET_PASSWORD || "").trim();
  if (!password) {
        throw new Error("WALLET_PASSWORD is required to decrypt bridge-relayer keystore");
  }
  const wallet = await Wallet.fromEncryptedJson(json, password);
  process.stdout.write(JSON.stringify({ address: wallet.address }));
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`.trim();
    const proc = Bun.spawnSync(["node", "-e", decodeScript, keystorePath], {
        cwd: contractsDir,
        env: {
            ...process.env,
            WALLET_PASSWORD: password,
        },
        stdout: "pipe",
        stderr: "pipe",
    });
    const code = proc.exitCode;
    const stdout = proc.stdout ? new TextDecoder().decode(proc.stdout) : "";
    const stderr = proc.stderr ? new TextDecoder().decode(proc.stderr) : "";
    if (code !== 0) {
        throw new Error(formatBridgeRelayerKeystoreDecryptError({
            keystorePath,
            detail: stderr || stdout,
        }));
    }
    const parsed = JSON.parse(stdout) as { address: string };
    return {
        address: parsed.address,
        keystorePath,
    };
}

async function setLocalAnvilBalance(rpcUrl: string, address: string, balanceHex = "0x3635C9ADC5DEA00000"): Promise<void> {
    const response = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "anvil_setBalance",
            params: [address, balanceHex],
        }),
    });
    if (!response.ok) {
        throw new Error(`[DevNet] anvil_setBalance failed with HTTP ${response.status}`);
    }
    const body = await response.json() as { error?: { message?: string } };
    if (body.error) {
        throw new Error(`[DevNet] anvil_setBalance failed: ${body.error.message || "unknown error"}`);
    }
}

async function anvilRpc(
    rpcUrl: string,
    method: string,
    params: unknown[],
): Promise<unknown> {
    const response = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            jsonrpc: "2.0",
            id: Date.now(),
            method,
            params,
        }),
    });
    if (!response.ok) {
        throw new Error(`[DevNet] ${method} failed with HTTP ${response.status}`);
    }
    let body: { error?: { message?: string }; result?: unknown };
    try {
        body = await response.json() as { error?: { message?: string }; result?: unknown };
    } catch (error) {
        const endpoint = new URL(rpcUrl);
        const contentLength = response.headers.get("content-length");
        const category = error instanceof SyntaxError ? "invalid JSON" : "response parse failed";
        throw new Error(`[DevNet] ${method} response from ${endpoint.origin} HTTP ${response.status}${contentLength === null ? "" : ` content-length ${contentLength}`} ${category}`);
    }
    if (body.error) {
        throw new Error(`[DevNet] ${method} failed: ${body.error.message || "unknown error"}`);
    }
    return body.result;
}
/** One-second interval mining for a launcher-managed Anvil. Not for an external RPC. */
export async function setLocalAnvilIntervalMining(rpcUrl: string): Promise<void> {
    await anvilRpc(rpcUrl, "anvil_setIntervalMining", [1]);
    console.log(`[DevNet] set anvil interval mining to 1 second on ${rpcUrl}`);
}

async function sendTokenTransfer(
    rpcUrl: string,
    from: string,
    token: string,
    to: string,
    amountHex: string,
): Promise<void> {
    const toWord = to.replace(/^0x/i, "").padStart(64, "0");
    const amountWord = amountHex.replace(/^0x/i, "").padStart(64, "0");
    const data = `0xa9059cbb${toWord}${amountWord}`;
    await anvilRpc(rpcUrl, "eth_sendTransaction", [{
        from,
        to: token,
        data,
        gas: "0x100000",
    }]);
}

async function fundDevTestAccounts(
    rpcUrl: string,
    deployer: L1SignerInfo,
    deploymentSummaryPath: string,
): Promise<void> {
    if (!(await exists(deploymentSummaryPath))) {
        console.log(`[DevNet] skipping fundDevTestAccounts: missing deployment summary at ${deploymentSummaryPath}`);
        return;
    }
    const summary = await Bun.file(deploymentSummaryPath).json() as any;
    const usdt = summary?.protocol?.tokens?.USDT?.l1Address as string | undefined;
    const psy = summary?.protocol?.tokens?.PSY?.l1Address as string | undefined;
    const psySource = (process.env.DEV_PSY_SOURCE_ADDRESS
        ?? summary?.verify?.PsyToken?.constructorArgs?.[0]
        ?? deployer.address) as string;
    if (!usdt || !psy) {
        console.log("[DevNet] skipping fundDevTestAccounts: USDT/PSY address missing");
        return;
    }
    const extra = (process.env.DEV_FUND_EXTRA_ADDRESSES ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    const targets = [...DEV_TEST_ADDRESSES, ...extra];
    const hundredEthHex = "0x56BC75E2D63100000";
    const sources = [...new Set([deployer.address, psySource])];
    for (const addr of targets) {
        await anvilRpc(rpcUrl, "anvil_setBalance", [addr, hundredEthHex]);
    }
    for (const source of sources) {
        await anvilRpc(rpcUrl, "anvil_setBalance", [source, hundredEthHex]);
    }
    for (const source of sources) {
        await anvilRpc(rpcUrl, "anvil_impersonateAccount", [source]);
    }
    try {
        const usdtAmtHex = `0x${(1_000_000n * 1_000_000n).toString(16)}`;
        const psyAmtHex = `0x${(1_000_000n * 1_000_000_000n).toString(16)}`;
        for (const addr of targets) {
            await sendTokenTransfer(rpcUrl, deployer.address, usdt, addr, usdtAmtHex);
            await sendTokenTransfer(rpcUrl, psySource, psy, addr, psyAmtHex);
        }
    } finally {
        for (const source of sources) {
            await anvilRpc(rpcUrl, "anvil_stopImpersonatingAccount", [source]);
        }
    }
    console.log(`[DevNet] funded ${targets.length} dev test accounts with ETH+USDT+PSY`);
}

function resolveL1Network(stage: PsyStage): L1NetworkName {
    const raw = (process.env.VITE_NETWORK || STAGE_DEFAULT_L1[stage]).trim().toLowerCase();
    if (raw === "localhost" || raw === "sepolia" || raw === "ethereum") {
        return raw;
    }
    throw new Error(`[DevNet] unsupported VITE_NETWORK=${raw}; expected localhost, sepolia, or ethereum`);
}

function resolveLocalL1RpcUrl(port: number): string {
    const rpcHost = process.env.L1_RPC_HOST || "127.0.0.1";
    return `http://${rpcHost}:${port}`;
}

// The genesis config's per-stage anvilForkSourceUrlEnv is only authoritative
// when the requested L1 network is that stage's own default L1 (see
// STAGE_DEFAULT_L1) — it names the fork source for the stage's usual L1,
// not for whichever L1 happens to be requested. Otherwise fall back to the
// L1-owned L1_FORK_RPC_ENV table so forking a public L1
// (VITE_NETWORK=sepolia VITE_FORK=true) works regardless of which Psy
// stage (VITE_PSY_STAGE) is selected, and so a mismatched pair like
// VITE_PSY_STAGE=testnet VITE_NETWORK=ethereum does not silently borrow
// testnet's Sepolia fork source for an Ethereum fork. Shared by every
// caller that needs the fork/external RPC source env-var name for an L1
// network, so the two knobs stay named consistently in every error message.
export function resolveForkRpcEnvKey(l1Network: L1NetworkName, cfgEntry: ConfigNetworkEntry | undefined, stage: PsyStage): string {
    const cfgEnvKey = STAGE_DEFAULT_L1[stage] === l1Network ? cfgEntry?.anvilForkSourceUrlEnv : undefined;
    const envKey = cfgEnvKey ?? L1_FORK_RPC_ENV[l1Network];
    if (!envKey) {
        throw new Error(
            `[DevNet] no fork RPC env is known for VITE_NETWORK=${l1Network}; ` +
            `VITE_NETWORK must be one of the L1 names with a known fork source (${Object.keys(L1_FORK_RPC_ENV).join(", ")})`,
        );
    }
    return envKey;
}

function resolveExternalL1RpcUrl(network: Exclude<L1NetworkName, "localhost">, cfgEntry: ConfigNetworkEntry | undefined, stage: PsyStage): string {
    const envKey = resolveForkRpcEnvKey(network, cfgEntry, stage);
    const rpcUrl = process.env[envKey];
    if (!rpcUrl || rpcUrl.trim().length === 0) {
        throw new Error(`[DevNet] ${envKey} is required when VITE_NETWORK=${network}`);
    }
    return rpcUrl.trim();
}

function shouldRedeployL1(): boolean {
    const value = process.env.REDEPLOY_L1?.trim().toLowerCase();
    if (!value) return true;
    if (["0", "false", "no", "off"].includes(value)) return false;
    return true;
}

async function readRequiredDeploymentTokenGaps(deploymentSummaryPath: string): Promise<string[]> {
    if (!(await exists(deploymentSummaryPath))) {
        return ["PSY", "USDT"];
    }
    const raw = await Bun.file(deploymentSummaryPath).text();
    const summary = JSON.parse(raw) as {
        protocol?: {
            tokens?: Record<string, { l1Address?: string | null } | undefined>;
        };
    };
    const tokens = summary.protocol?.tokens ?? {};
    const requiredTokens = ["PSY", "USDT"];
    return requiredTokens.filter((token) => {
        const addr = tokens[token]?.l1Address?.trim();
        return !addr;
    });
}

export class RunningProcess {
    pid: number;
    proc: Bun.Subprocess;
    stdOutLines: string[] = [];
    stdErrLines: string[] = [];
    lineBufferStdOut: string = '';
    lineBufferStdErr: string = '';
    linesToKeepStdOut: number = 5000;
    linesToKeepStdErr: number = 5000;
    stdOutVisitor: ProcessLineVisitor = () => { };
    stdErrVisitor: ProcessLineVisitor = () => { };
    allOutputVisitor: ProcessLineVisitor = () => { };
    onExit: (code: number | null, signal: string | null) => void = () => { };

    /** Stable service name for supervisor logs (e.g. prove_proxy_0, bridge_relayer). */
    name: string = '';
    cmds: string[] = [];
    guardianListener?: { host: string; port: number };
    spawnOptions: {
        cwd?: string;
        stdOutVisitor?: ProcessLineVisitor;
        stdErrVisitor?: ProcessLineVisitor;
        allOutputVisitor?: ProcessLineVisitor;
        stdoutLogFile?: string;
        stderrLogFile?: string;
        initializationTimeoutMs?: number;
        env?: { [key: string]: string };
        appendLogs?: boolean;
    } = {};
    hintDetector?: (line: string) => boolean;
    useInitHint: boolean = false;
    initializationReady: boolean = false;
    initMaxRetries: number = 3;
    initRetryDelayMs: number = 2000;
    restartCount: number = 0;
    startedAtMs: number = 0;
    /** 0 until ready. Circuit build must not count as a healthy run. */
    healthySinceMs: number = 0;
    restartStreak: RestartStreak = emptyRestartStreak();
    hasExited: boolean = false;
    exitCode: number | null = null;
    exitSignal: string | null = null;
    supervisorObservedExit: boolean = false;
    intentionalStop: boolean = false;
    dependencyRestartRequested: boolean = false;
    fatalProcessorErrorMarker: FatalProcessorErrorMarker | null = null;
    firstCausalStderr: string | null = null;
    fatalWitnessWrite: Promise<void> | null = null;

    constructor(proc: Bun.Subprocess, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor) {
        this.proc = proc;
        this.pid = proc.pid;
        if (stdOutVisitor) this.stdOutVisitor = stdOutVisitor;
        if (stdErrVisitor) this.stdErrVisitor = stdErrVisitor;
        if (allOutputVisitor) this.allOutputVisitor = allOutputVisitor;
    }

    injestStdOut(data: string): void {
        this.lineBufferStdOut += data;
        let lines = this.lineBufferStdOut.split('\n');
        this.lineBufferStdOut = lines.pop() || '';
        lines.forEach(line => {
            this.stdOutVisitor(line, this);
            this.allOutputVisitor(line, this);
        });
        this.stdOutLines.push(...lines);
        if (this.stdOutLines.length > this.linesToKeepStdOut) {
            this.stdOutLines.splice(0, this.stdOutLines.length - this.linesToKeepStdOut);
        }
    }

    injestStdErr(data: string): void {
        this.lineBufferStdErr += data;
        let lines = this.lineBufferStdErr.split('\n');
        this.lineBufferStdErr = lines.pop() || '';
        lines.forEach(line => {
            if (!this.firstCausalStderr) {
                const causal = parseRealmProcessorFailureLine(line);
                if (causal) this.firstCausalStderr = causal;
            }
            this.stdErrVisitor(line, this);
            this.allOutputVisitor(line, this);
        });
        this.stdErrLines.push(...lines);
        if (this.stdErrLines.length > this.linesToKeepStdErr) {
            this.stdErrLines.splice(0, this.stdErrLines.length - this.linesToKeepStdErr);
        }
    }

    kill(): void {
        this.killWithSignal("SIGTERM");
    }

    isRunning(): boolean {
        return !this.hasExited && this.proc.killed === false;
    }

    signalProcessGroup(signal: number | NodeJS.Signals): void {
        try {
            process.kill(-this.pid, signal);
        } catch {
            if (!this.hasExited) this.proc.kill(signal);
        }
    }

    killWithSignal(signal: number | NodeJS.Signals): void {
        this.intentionalStop = true;
        this.signalProcessGroup(signal);
    }

    static async appendLogBanner(filePath: string | undefined, banner: string): Promise<void> {
        if (!filePath) return;
        await fs.promises.mkdir(path.dirname(filePath), { recursive: true }).catch(() => undefined);
        await fs.promises.appendFile(filePath, banner.endsWith('\n') ? banner : banner + '\n', 'utf8');
    }

    static async spawn(cmds: string[], options: {
        cwd?: string,
        stdOutVisitor?: ProcessLineVisitor,
        stdErrVisitor?: ProcessLineVisitor,
        allOutputVisitor?: ProcessLineVisitor,
        stdoutLogFile?: string,
        stderrLogFile?: string,
        initializationTimeoutMs?: number,
        env?: { [key: string]: string },
        appendLogs?: boolean,
        logBanner?: string,
    }): Promise<RunningProcess> {
        if (cmds.some((cmd) => path.basename(cmd) === "psy_relayer_cli")) {
            options = { ...options, cwd: path.resolve(options.cwd || process.cwd()), env: options.env ?? { ...process.env } as Record<string, string> };
        }
        await validateRelayerTemplate(cmds, options);
        const guardianListener = cmds.includes("guardian-service")
            ? await prepareGuardianService(cmds, options.cwd || process.cwd(), options.env ?? process.env)
            : undefined;
        const prepareLog = async (filePath: string | undefined) => {
            if (!filePath) return;
            if (options.appendLogs) {
                if (options.logBanner) await RunningProcess.appendLogBanner(filePath, options.logBanner);
            } else {
                await Bun.write(filePath, options.logBanner || "");
            }
        };
        await prepareLog(options.stdoutLogFile);
        await prepareLog(options.stderrLogFile);

        const launchCmds = runtimeCpuSetForChildren
            ? ["taskset", "--cpu-list", runtimeCpuSetForChildren, ...cmds]
            : cmds;
        const proc = Bun.spawn(launchCmds, {
            cwd: options.cwd || undefined,
            stdout: "pipe",
            stderr: "pipe",
            env: cmds.some((cmd) => path.basename(cmd) === "psy_relayer_cli") ? options.env : options.env ? { ...process.env, ...options.env } : undefined,
            detached: true,
        });

        const runningProcess = new RunningProcess(proc, options.stdOutVisitor, options.stdErrVisitor, options.allOutputVisitor);
        runningProcess.cmds = cmds.slice();
        runningProcess.guardianListener = guardianListener;
        runningProcess.startedAtMs = Date.now();
        runningProcess.healthySinceMs = runningProcess.startedAtMs;
        runningProcess.spawnOptions = {
            cwd: options.cwd,
            stdOutVisitor: options.stdOutVisitor,
            stdErrVisitor: options.stdErrVisitor,
            allOutputVisitor: options.allOutputVisitor,
            stdoutLogFile: options.stdoutLogFile,
            stderrLogFile: options.stderrLogFile,
            initializationTimeoutMs: options.initializationTimeoutMs,
            env: options.env,
            appendLogs: options.appendLogs,
        };
        const outputPumps: Promise<void>[] = [];
        const pumpOutput = async (
            readableStream: AsyncIterable<Uint8Array>,
            logFile: string | undefined,
            ingest: (data: string) => void,
            hasBufferedLine: () => boolean,
        ): Promise<void> => {
            const decoder = new TextDecoder();
            const logStream = logFile
                ? fs.createWriteStream(logFile, { flags: "a" })
                : undefined;
            let logWriteError: unknown;
            logStream?.on("error", (error) => {
                if (logWriteError) return;
                logWriteError = error;
                console.error(`[DevNet] failed to append process log ${logFile}:`, error);
            });

            for await (const chunk of readableStream) {
                if (logStream && !logWriteError && !logStream.write(chunk)) {
                    try {
                        await once(logStream, "drain");
                    } catch (error) {
                        logWriteError = error;
                        logStream.destroy();
                        console.error(`[DevNet] failed to append process log ${logFile}:`, error);
                    }
                }
                const decoded = decoder.decode(chunk, { stream: true });
                if (decoded) ingest(decoded);
            }

            const tail = decoder.decode();
            if (tail) ingest(tail);
            if (hasBufferedLine()) ingest('\n');

            if (logStream && !logWriteError) {
                logStream.end();
                try {
                    await once(logStream, "finish");
                } catch (error) {
                    console.error(`[DevNet] failed to close process log ${logFile}:`, error);
                }
            } else {
                logStream?.destroy();
            }
        };

        if (proc.stdout) {
            outputPumps.push(pumpOutput(
                proc.stdout,
                options.stdoutLogFile,
                (data) => runningProcess.injestStdOut(data),
                () => runningProcess.lineBufferStdOut.length > 0,
            ));
        }

        if (proc.stderr) {
            outputPumps.push(pumpOutput(
                proc.stderr,
                options.stderrLogFile,
                (data) => runningProcess.injestStdErr(data),
                () => runningProcess.lineBufferStdErr.length > 0,
            ));
        }

        (async () => {
            const code = await proc.exited;
            await Promise.allSettled(outputPumps);
            const exitSignal = proc.signalCode ?? null;
            runningProcess.exitCode = code;
            runningProcess.exitSignal = exitSignal;
            runningProcess.hasExited = true;
            runningProcess.onExit(code, exitSignal);
        })();
        if (guardianListener) {
            runningProcess.healthySinceMs = 0;
            // Cold circuit build measured ~5min. Prove-proxy uses the same 600s listen budget
            // (600 attempts × 1s). 120 × 500ms is only ~60s when each probe is connection-refused.
            const readinessDeadlineMs = 600_000;
            const readinessStartedMs = performance.now();
            try {
                for (;;) {
                    if (proc.exitCode !== null) throw new Error("[DevNet] guardian-service exited before readiness");
                    const remainingMs = readinessDeadlineMs - (performance.now() - readinessStartedMs);
                    if (remainingMs <= 0) {
                        throw new Error(`[DevNet] guardian-service port ${guardianListener.port} not ready within ${readinessDeadlineMs}ms`);
                    }
                    try {
                        const host = guardianListener.host.includes(":") ? `[${guardianListener.host}]` : guardianListener.host;
                        await waitForHttpUrl(`http://${host}:${guardianListener.port}/v1/ready`, {
                            // One account read; it does not share the observer lock or session page.
                            // No fallback to an older binary: the devnet shares one source tree, so a
                            // guardian built from a different revision is a setup error, not a retry.
                            attempts: 1, timeoutMs: Math.min(1_500, remainingMs), name: "guardian-service ready",
                            validateResponse: guardianServiceReady,
                        });
                        if (performance.now() - readinessStartedMs >= readinessDeadlineMs) {
                            throw new Error(`[DevNet] guardian-service port ${guardianListener.port} not ready within ${readinessDeadlineMs}ms`);
                        }
                        break;
                    } catch (error) {
                        const afterMs = readinessDeadlineMs - (performance.now() - readinessStartedMs);
                        if (afterMs <= 0) {
                            throw new Error(`[DevNet] guardian-service port ${guardianListener.port} not ready within ${readinessDeadlineMs}ms`);
                        }
                        await Bun.sleep(Math.min(500, Math.max(0, afterMs)));
                    }
                }
                if (runningProcess.hasExited || proc.exitCode !== null) throw new Error("[DevNet] guardian-service exited before readiness");
                runningProcess.initializationReady = true;
                runningProcess.healthySinceMs = Date.now();
            } catch (error) {
                runningProcess.kill();
                await waitForProcessExit(runningProcess);
                throw error;
            }
        }

        return runningProcess;
    }


    static async spawnWithInitializationHint(cmds: string[], hintDetector: (line: string) => boolean, options: {
        cwd?: string,
        stdOutVisitor?: ProcessLineVisitor,
        stdErrVisitor?: ProcessLineVisitor,
        allOutputVisitor?: ProcessLineVisitor,
        stdoutLogFile?: string,
        stderrLogFile?: string,
        env?: { [key: string]: string },
        appendLogs?: boolean,
        logBanner?: string,
        initializationTimeoutMs?: number,
    }): Promise<RunningProcess> {
        const { promise, resolve, reject } = Promise.withResolvers<RunningProcess>();
        let initialized = false;
        let settled = false;
        let timeout: Timer | undefined;
        const finishReady = (process: RunningProcess) => {
            if (settled) return;
            settled = true;
            initialized = true;
            clearTimeout(timeout);
            process.initializationReady = true;
            process.healthySinceMs = Date.now();
            resolve(process);
        };
        const allOutputVisitor: ProcessLineVisitor = (line: string, process: RunningProcess) => {
            const normalizedLine = line.replace(/\u001b\[[0-9;]*m/g, '');
            if (!initialized && hintDetector(normalizedLine)) finishReady(process);
            options.allOutputVisitor?.(line, process);
        };
        const proc = await RunningProcess.spawn(cmds, {
            cwd: options.cwd,
            stdOutVisitor: options.stdOutVisitor,
            stdErrVisitor: options.stdErrVisitor,
            allOutputVisitor,
            stdoutLogFile: options.stdoutLogFile,
            stderrLogFile: options.stderrLogFile,
            initializationTimeoutMs: options.initializationTimeoutMs,
            env: options.env,
            appendLogs: options.appendLogs,
            logBanner: options.logBanner,
        });
        // Keep the ORIGINAL visitor for supervisor restarts (not the init-hint wrapper).
        proc.spawnOptions.allOutputVisitor = options.allOutputVisitor;
        proc.hintDetector = hintDetector;
        if (!proc.initializationReady) proc.healthySinceMs = 0;
        proc.useInitHint = true;
        const prevOnExit = proc.onExit.bind(proc);
        proc.onExit = (code: number | null, signal: string | null) => {
            if (!settled) {
                settled = true;
                clearTimeout(timeout);
                proc.supervisorObservedExit = true;
                const fullOut = proc.stdOutLines.join("\n");
                const fullErr = proc.stdErrLines.join("\n");
                reject(new Error(`Process exited before initialization hint was found.\n` +
                    `Command: ${cmds.join(" ")}\n` +
                    `Exit Code: ${code}, Signal: ${signal}\n\n` +
                    `--- Full StdOut ---\n${fullOut}\n\n` +
                    `--- Full StdErr ---\n${fullErr}\n\n` +
                    `Please check the log files in the 'logs/' directory for more details.`));
            }
            // Pre-ready exits are owned by the startup retry loop. After the
            // full marker, chain so an already-wired supervisor still sees
            // every later exit.
            if (proc.initializationReady) prevOnExit(code, signal);
        };
        if (options.initializationTimeoutMs !== undefined) {
            timeout = setTimeout(() => {
                if (settled) return;
                settled = true;
                proc.supervisorObservedExit = true;
                proc.kill();
                void proc.proc.exited.then(async () => {
                    await Promise.resolve();
                    reject(new Error(
                        `Process did not reach its initialization marker within ${options.initializationTimeoutMs}ms.\n`
                        + `Command: ${cmds.join(" ")}\n\n`
                        + `--- Full StdOut ---\n${proc.stdOutLines.join("\n")}\n\n`
                        + `--- Full StdErr ---\n${proc.stdErrLines.join("\n")}`,
                    ));
                });
            }, options.initializationTimeoutMs);
        }
        return promise;
    }

    static spawnWithInitializationHintWithRetry(
        cmds: string[],
        hintDetector: (line: string) => boolean,
        options: {
            cwd?: string,
            stdOutVisitor?: ProcessLineVisitor,
            stdErrVisitor?: ProcessLineVisitor,
            allOutputVisitor?: ProcessLineVisitor,
            stdoutLogFile?: string,
            stderrLogFile?: string,
            initializationTimeoutMs?: number,
            maxRetries?: number,
            retryDelayMs?: number,
            env?: { [key: string]: string },
            appendLogs?: boolean,
            logBanner?: string,
        }
    ): Promise<RunningProcess> {
        const { promise, resolve, reject } = Promise.withResolvers<RunningProcess>();
        const maxRetries = options.maxRetries ?? 3;
        const retryDelayMs = options.retryDelayMs ?? 2000;
        let attempt = 0;

        const trySpawn = async () => {
            attempt++;
            console.log(`[DevNet] Starting process (attempt ${attempt}/${maxRetries + 1}): ${cmds.join(" ")}`);

            try {
                const proc = await this.spawnWithInitializationHint(cmds, hintDetector, {
                    cwd: options.cwd,
                    stdOutVisitor: options.stdOutVisitor,
                    stdErrVisitor: options.stdErrVisitor,
                    allOutputVisitor: options.allOutputVisitor,
                    stdoutLogFile: options.stdoutLogFile,
                    stderrLogFile: options.stderrLogFile,
                    initializationTimeoutMs: options.initializationTimeoutMs,
                    env: options.env,
                    appendLogs: options.appendLogs,
                    logBanner: options.logBanner,
                });
                proc.initMaxRetries = maxRetries;
                proc.initRetryDelayMs = retryDelayMs;
                console.log(`[DevNet] Process initialized successfully`);
                resolve(proc);
            } catch (error) {
                if (attempt <= maxRetries) {
                    console.warn(`[DevNet] Process failed (attempt ${attempt}/${maxRetries + 1}), retrying in ${retryDelayMs}ms...`);
                    setTimeout(trySpawn, retryDelayMs);
                } else {
                    reject(error);
                }
            }
        };

        void trySpawn();
        return promise;
    }
}

export async function startRealmProcessorBatchSequentially<T>(
    realmIds: readonly number[],
    startProcessor: (realmId: number) => Promise<T>,
): Promise<T[]> {
    const processes: T[] = [];
    for (const realmId of realmIds) {
        processes.push(await startProcessor(realmId));
    }
    return processes;
}

export async function startAfterPrerequisite<T>(
    prerequisite: Promise<unknown>,
    startServices: () => Promise<T>,
): Promise<T> {
    await prerequisite;
    return startServices();
}


// --- Log Detectors ---
function dbStartedDetector(line: string): boolean {
    return line.includes('All services are running.')
}
function coordinatorEdgeProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_COORDINATOR_EDGE_RPC_STARTED]')
        || line.includes('Coordinator edge starting with proving backend:')
}
function workerStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_PROOF_MINER_WORKER_STARTED]'); }
function realmEdgeProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_REALM_EDGE_RPC_STARTED]')
        || line.includes('Realm edge starting...')
}
function dummyProverStartedDetector(line: string): boolean { return line.startsWith('[CFLI:DUMMY_END_CAP_PROVER_STARTED]'); }
function proveProxyStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_PROVE_PROXY_STARTED]')
        || line.includes('new zk sign circuit - build inner circuit')
        || line.includes('adding user {')
        || line.includes('Listening on')
}
function faucetServerStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_FAUCET_SERVER_STARTED]')
        || line.includes('Starting psy faucet server')
        || line.includes('psy faucet server mode enabled');
}
function l1StartedDetector(line: string): boolean {
    return line.includes('Listening on');
}


const REALM_P2P_OUT_DIR = "./local_checkpoints/realm_p2p";
export const REALM_P2P_SUB_IDS = [1, 2] as const;
/** Local-devnet genesis pre-places ZK validators only for realms `[0, count)`. */
export const LOCAL_DEVNET_VALIDATOR_REALM_COUNT = 2;
export const LOCAL_DEVNET_VALIDATORS_PER_REALM = REALM_P2P_SUB_IDS.length;
/** Local-devnet ZK fingerprint constant from `local_devnet.rs`. */
export const LOCAL_DEVNET_ZK_FINGERPRINT = "65e0169bfffd55f1c0ea9f76c111a5b15e652322ee253c1a9604a10d59066b50";

/** Local-devnet bridge relayer stays at registration 2 (Strategy5 user_id 524288). */
export const LOCAL_DEVNET_RELAYER_REGISTRATION_ID = 2;
export const LOCAL_DEVNET_RELAYER_USER_ID = 524288;
/** Anvil account #0. Seeds the auto-generated encrypted L1 sender keystore. Bridge identity is the preprovisioned multisig account, not a generated L2 key. */
export const LOCAL_DEVNET_RELAYER_ZK_PRIVATE_KEY =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/** Canonical reserved leaf: `realm_id * 2^h + (sub_id - 1)`. */
export function realmValidatorUserId(realmId: number, subId: number, height: number = 20): number {
    if (!Number.isInteger(realmId) || realmId < 0) throw new Error(`Invalid realm id ${realmId}`);
    if (!Number.isInteger(subId) || subId < 1) throw new Error(`Invalid validator sub id ${subId}`);
    if (!Number.isInteger(height) || height < 1 || height >= 53) throw new Error(`Invalid realm user tree height ${height}`);
    return realmId * (2 ** height) + (subId - 1);
}

/**
 * Dense Strategy5 registration reserved for a local-devnet validator.
 * Registration 2 is reserved for the bridge relayer (user_id 524288), so
 * validators use: (0,1)->0, (1,1)->1, (1,2)->3, (0,2)->4.
 */
export function reservedValidatorRegistrationId(realmId: number, subId: number): number {
    if (!Number.isInteger(realmId) || realmId < 0 || realmId >= LOCAL_DEVNET_VALIDATOR_REALM_COUNT) {
        throw new Error(
            `Local-devnet genesis only pre-places validators for realms 0..${LOCAL_DEVNET_VALIDATOR_REALM_COUNT - 1}, got ${realmId}`,
        );
    }
    if (!Number.isInteger(subId) || subId < 1 || subId > LOCAL_DEVNET_VALIDATORS_PER_REALM) {
        throw new Error(`Validator sub id must be in 1..${LOCAL_DEVNET_VALIDATORS_PER_REALM}, got ${subId}`);
    }
    if (subId === 1) return realmId;
    return 4 - realmId;
}

/** Strategy5 user id for a local-devnet registration id. */
export function strategy5UserIdFromRegistrationId(registrationId: number): number {
    if (!Number.isInteger(registrationId) || registrationId < 0 || registrationId >= 2 ** 32) {
        throw new Error(`Invalid genesis registration id ${registrationId}`);
    }
    const usersPerRealm = 2 ** 20;
    const realmId = Math.floor(registrationId / (2 * usersPerRealm)) * 2 + registrationId % 2;
    let userIndex = Math.floor(registrationId / 2) % usersPerRealm;
    let leafIndex = 0;
    for (let bit = 0; bit < 20; bit++) {
        leafIndex = leafIndex * 2 + userIndex % 2;
        userIndex = Math.floor(userIndex / 2);
    }
    return realmId * usersPerRealm + leafIndex;
}

export function reservedValidatorUserId(realmId: number, subId: number): number {
    return strategy5UserIdFromRegistrationId(reservedValidatorRegistrationId(realmId, subId));
}

export async function genesisValidatorUserIds(
    cwd: string,
    realmIds: readonly number[],
    validatorsPerRealm: number = REALM_P2P_SUB_IDS.length,
): Promise<number[]> {
    if (!Number.isInteger(validatorsPerRealm) || validatorsPerRealm !== LOCAL_DEVNET_VALIDATORS_PER_REALM) {
        throw new Error(`Local-devnet reserved validators require exactly ${LOCAL_DEVNET_VALIDATORS_PER_REALM} per realm`);
    }
    const genesis = JSON.parse(await fs.promises.readFile(path.join(cwd, "genesis.json"), "utf-8")) as {
        users: Array<{ public_key_info: { fingerprint: string } }>;
    };
    const config = JSON.parse(await fs.promises.readFile(path.join(cwd, "psy-genesis/config.json"), "utf-8")) as FullNetworkConfig;
    const network = config.networks.localhost;
    if (network?.global_user_tree_height !== 32 || network.realm_user_tree_height !== 20 || network.group_realm_height !== 1) {
        throw new Error("Genesis validator mapping requires Strategy5 COORD=12, REALM=20, GROUP=1");
    }
    return realmIds.flatMap((realmId) => {
        if (!Number.isInteger(realmId) || realmId < 0 || realmId >= 2 ** 12) throw new Error(`Invalid genesis Realm ${realmId}`);
        return Array.from({ length: validatorsPerRealm }, (_, index) => {
            const subId = index + 1;
            const registrationId = reservedValidatorRegistrationId(realmId, subId);
            if (registrationId >= genesis.users.length) {
                throw new Error(`Genesis missing reserved validator registration ${registrationId} for realm ${realmId} sub ${subId}`);
            }
            if (registrationId === LOCAL_DEVNET_RELAYER_REGISTRATION_ID) {
                throw new Error(`Genesis registration ${registrationId} is reserved for the bridge relayer`);
            }
            if (genesis.users[registrationId].public_key_info.fingerprint !== LOCAL_DEVNET_ZK_FINGERPRINT) {
                throw new Error(`Genesis registration ${registrationId} is not a reserved ZK validator account`);
            }
            const userId = reservedValidatorUserId(realmId, subId);
            const realmStart = realmId * 2 ** 20;
            const realmEnd = (realmId + 1) * 2 ** 20;
            if (userId < realmStart || userId >= realmEnd) {
                throw new Error(`Reserved validator user id ${userId} is outside Realm ${realmId} range`);
            }
            return userId;
        });
    });
}

type PublicNode = { node_id: string; addresses: string[] };
type GenesisValidator = {
    validator_user_id: number;
    processor_node_id: string;
    bls_public_key: string;
    processor_addresses: string[];
    edge_nodes: PublicNode[];
};
type RealmNetworkConfig = { id: number; rpc_url: string[]; validators: GenesisValidator[] };
type NetworkConfigEntry = {
    realm_configs: RealmNetworkConfig[];
    p2p: { checkpoints_per_epoch: number };
    realm_user_tree_height?: number;
    [key: string]: unknown;
};
type FullNetworkConfig = { defaultNetwork: string; networks: Record<string, NetworkConfigEntry>; genesisConfigHash?: string };

export function realmP2pProcessorPort(realmId: number, subId: number): number { return 41000 + realmId * 20 + subId; }
export function realmP2pEdgePort(realmId: number, subId: number, edgeIndex: number, edgeCount: number): number {
    const realmStride = Math.max(20, REALM_P2P_SUB_IDS.length * edgeCount);
    return 41100 + realmId * realmStride + (subId - 1) * edgeCount + edgeIndex + 1;
}
function realmDbNamespace(realmId: number, subId: number): string {
    return `realm_${realmId}_${subId}`;
}
function multiaddrHost(host: string): string {
    return net.isIPv4(host) ? `ip4/${host}` : net.isIPv6(host) ? `ip6/${host}` : `dns4/${host}`;
}
function realmP2pListen(host: string, port: number): string { return `/${multiaddrHost(host)}/tcp/${port}`; }
export function realmP2pHttpPort(realmId: number, subId: number, edgeIndex: number, realmEdgeCount: number): number {
    const realmStride = Math.max(10, REALM_P2P_SUB_IDS.length * realmEdgeCount);
    return 13380 + realmId * realmStride + (subId - 1) * realmEdgeCount + edgeIndex;
}
type RealmPortRequest = { family: "processor P2P" | "edge P2P" | "Realm HTTP"; realmId: number; subId: number; edgeIndex?: number; port: number };

export function requestedRealmPorts(startRealmId: number, realmsCount: number, edgeCount: number): RealmPortRequest[] {
    const ports: RealmPortRequest[] = [];
    for (let realmId = startRealmId; realmId < startRealmId + realmsCount; realmId++) {
        for (const subId of REALM_P2P_SUB_IDS) {
            ports.push({ family: "processor P2P", realmId, subId, port: realmP2pProcessorPort(realmId, subId) });
            for (let edgeIndex = 0; edgeIndex < edgeCount; edgeIndex++) {
                ports.push({ family: "edge P2P", realmId, subId, edgeIndex, port: realmP2pEdgePort(realmId, subId, edgeIndex, edgeCount) });
                ports.push({ family: "Realm HTTP", realmId, subId, edgeIndex, port: realmP2pHttpPort(realmId, subId, edgeIndex, edgeCount) });
            }
        }
    }
    return ports;
}

function describeRealmPort(request: RealmPortRequest): string {
    const edge = request.edgeIndex === undefined ? "" : ` edge ${request.edgeIndex}`;
    return `${request.family} Realm ${request.realmId} validator ${request.subId}${edge}`;
}

export function validateRealmP2pPorts(startRealmId: number, realmsCount: number, edgeCount: number): void {
    if (!Number.isInteger(startRealmId) || startRealmId < 0) throw new Error("--start-realm-id must be a non-negative integer");
    if (!Number.isInteger(realmsCount) || realmsCount < 1) throw new Error("--realms-count must be a positive integer");
    if (!Number.isInteger(edgeCount) || edgeCount < 1 || edgeCount > 255) throw new Error("--realm-edge-nodes must be in 1..=255");
    const ownerByPort = new Map<number, RealmPortRequest>();
    for (const request of requestedRealmPorts(startRealmId, realmsCount, edgeCount)) {
        if (!Number.isSafeInteger(request.port) || request.port > 65535) throw new Error("Requested Realm P2P topology exceeds TCP port 65535");
        const previous = ownerByPort.get(request.port);
        if (previous) {
            throw new Error(`Requested Realm topology assigns TCP port ${request.port} to both ${describeRealmPort(previous)} and ${describeRealmPort(request)}`);
        }
        ownerByPort.set(request.port, request);
    }
}

export function shouldPrepareRealmP2p(startCoordinatorProcessor: boolean, startRealmProcessor: boolean): boolean {
    return startCoordinatorProcessor || startRealmProcessor;
}
function realmP2pEdgeIdentityPath(realmId: number, subId: number, edgeIndex: number): string {
    const suffix = edgeIndex === 0 ? "edge_identity.key" : `edge_${edgeIndex}_identity.key`;
    return `${REALM_P2P_OUT_DIR}/realm_${realmId}_sub_${subId}_${suffix}`;
}

export function selectedRuntimeConfigKey(nodeNetwork: string): string {
    return nodeNetwork === "local-devnet" ? "localhost" : nodeNetwork;
}

export type RealmP2pConfigPlan = { reuse: boolean; args: string[]; env: Record<string, string> };

export function realmP2pSecretPaths(realmIds: readonly number[], edgeCount: number): string[] {
    return realmIds.flatMap((realmId) => REALM_P2P_SUB_IDS.flatMap((subId) => [
        `${REALM_P2P_OUT_DIR}/realm_${realmId}_sub_${subId}_processor_identity.key`,
        `${REALM_P2P_OUT_DIR}/realm_${realmId}_sub_${subId}_bls.key`,
        `${REALM_P2P_OUT_DIR}/realm_${realmId}_sub_${subId}_zk.key`,
        ...Array.from({ length: edgeCount }, (_, edgeIndex) => realmP2pEdgeIdentityPath(realmId, subId, edgeIndex)),
    ]));
}

export function planRealmP2pConfig(
    config: FullNetworkConfig | null,
    realmIds: readonly number[],
    edgeCount: number,
    publicHost: string,
    validatorUserIds: readonly number[],
    _genesisConfigHash: string,
    nodeNetwork: string = "local-devnet",
    sourceConfig: FullNetworkConfig = allConfig as FullNetworkConfig,
): RealmP2pConfigPlan {
    if (validatorUserIds.length !== realmIds.length * REALM_P2P_SUB_IDS.length) throw new Error("Expected one genesis user id per validator");
    validatorUserIds.forEach((userId, index) => {
        const realmId = realmIds[Math.floor(index / REALM_P2P_SUB_IDS.length)];
        if (!Number.isSafeInteger(userId) || userId < realmId * 2 ** 20 || userId >= (realmId + 1) * 2 ** 20) {
            throw new Error(`Validator user id ${userId} is outside Realm ${realmId} user range`);
        }
    });
    const configKey = selectedRuntimeConfigKey(nodeNetwork);
    const sourceNetwork = sourceConfig.networks[configKey];
    if (!sourceNetwork) throw new Error(`Genesis config has no network ${configKey}`);
    const networkConfig = config?.networks?.[configKey];
    const activeRealmIds = new Set(realmIds);
    const consensusFields = ["p2p", "magic", "users_per_realm", "global_user_tree_height", "realm_user_tree_height", "group_realm_height"] as const;
    if (config && (!networkConfig || consensusFields.some((field) => !isDeepStrictEqual(networkConfig[field], sourceNetwork[field])))) {
        throw new Error("Existing Realm P2P consensus configuration differs from source; refusing identity regeneration");
    }
    const reusable = !!networkConfig
        && Array.isArray(networkConfig.realm_configs)
        && realmIds.every((realmId, realmIndex) => {
            const matches = networkConfig.realm_configs.filter((value) => value.id === realmId);
            if (matches.length !== 1) return false;
            const realm = matches[0];
            return Array.isArray(realm.validators)
                && realm.validators.length === REALM_P2P_SUB_IDS.length
                && realm.validators.every((validator, validatorIndex) => {
                    const subId = validatorIndex + 1;
                    return typeof validator.processor_node_id === "string" && validator.processor_node_id.length > 0
                        && validator.validator_user_id === validatorUserIds[realmIndex * REALM_P2P_SUB_IDS.length + validatorIndex]
                        && typeof validator.bls_public_key === "string" && validator.bls_public_key.length > 0
                        && Array.isArray(validator.processor_addresses)
                        && validator.processor_addresses.some((address) => address.startsWith(`${realmP2pListen(publicHost, realmP2pProcessorPort(realmId, subId))}/p2p/`))
                        && Array.isArray(validator.edge_nodes)
                        && validator.edge_nodes.length === edgeCount
                        && validator.edge_nodes.every((edge, edgeIndex) => typeof edge.node_id === "string" && edge.node_id.length > 0
                            && Array.isArray(edge.addresses)
                            && edge.addresses.some((address) => address.startsWith(`${realmP2pListen(publicHost, realmP2pEdgePort(realmId, subId, edgeIndex, edgeCount))}/p2p/`)));
                });
        })
        && networkConfig.realm_configs.every((realm) => activeRealmIds.has(realm.id)
            || Array.isArray(realm.validators) && realm.validators.length === 0);
    if (config && !reusable) throw new Error("Existing Realm P2P topology is incompatible; refusing identity regeneration");
    return {
        reuse: reusable,
        args: ["--out-dir", REALM_P2P_OUT_DIR, "--realm-ids", realmIds.join(","), "--validators-per-realm", REALM_P2P_SUB_IDS.length.toString(), "--validator-user-ids", validatorUserIds.join(","), "--edges-per-validator", edgeCount.toString()],
        env: { PSY_CONFIG_PATH: "psy-genesis/config.json", PSY_NETWORK: configKey, PSY_REALM_P2P_PUBLIC_HOST: publicHost },
    };
}

export function daemonRealmP2pConfig(config: FullNetworkConfig, realmIds: readonly number[], edgeCount: number): FullNetworkConfig {
    const copy = structuredClone(config);
    const networkConfig = copy.networks[copy.defaultNetwork];
    for (const realmId of realmIds) {
        const realm = networkConfig.realm_configs.find((value) => value.id === realmId);
        if (!realm) throw new Error(`Runtime network config has no Realm ${realmId}`);
        realm.validators.forEach((validator, validatorIndex) => {
            const subId = validatorIndex + 1;
            const processorPeerId = validator.processor_addresses[0]?.split("/p2p/")[1];
            if (!processorPeerId) throw new Error(`Realm ${realmId} validator ${subId} has no processor peer id`);
            const processorName = `realm-${realmId}-sub-${subId}-processor`;
            validator.processor_addresses = [`${realmP2pListen(processorName, realmP2pProcessorPort(realmId, subId))}/p2p/${processorPeerId}`];
            validator.edge_nodes.forEach((edge, edgeIndex) => {
                const edgePeerId = edge.addresses[0]?.split("/p2p/")[1];
                if (!edgePeerId) throw new Error(`Realm ${realmId} validator ${subId} edge ${edgeIndex} has no peer id`);
                const edgeName = `realm-${realmId}-sub-${subId}-edge-${edgeIndex}`;
                edge.addresses = [`${realmP2pListen(edgeName, realmP2pEdgePort(realmId, subId, edgeIndex, edgeCount))}/p2p/${edgePeerId}`];
            });
        });
    }
    return copy;
}

type GenesisMembership = Array<{ realm_id: number; validator_user_id: number; node_id: string; bls_public_key: string }>;

function realmGenesisValidators(config: FullNetworkConfig): GenesisMembership {
    return config.networks[config.defaultNetwork].realm_configs.flatMap((realm) => realm.validators.map((validator) => ({
        realm_id: realm.id,
        validator_user_id: validator.validator_user_id,
        node_id: validator.processor_node_id,
        bls_public_key: validator.bls_public_key,
    })));
}

function validateGenesisValidators(validators: unknown, expected: GenesisMembership): void {
    if (validators === undefined) return;
    if (!Array.isArray(validators)) throw new Error("Malformed Genesis validator membership");
    if (validators.length === 0) return;
    const canonical = (members: GenesisMembership) => [...members].sort((a, b) => a.realm_id - b.realm_id || a.validator_user_id - b.validator_user_id);
    if (!isDeepStrictEqual(canonical(validators), canonical(expected))) {
        throw new Error("Existing Genesis validator membership conflicts with Realm P2P config; refusing overwrite");
    }
}

export async function injectGenesisValidators(genesisPath: string, config: FullNetworkConfig): Promise<void> {
    const genesis = JSON.parse(await fs.promises.readFile(genesisPath, "utf-8")) as { validators?: GenesisMembership };
    const validators = realmGenesisValidators(config);
    validateGenesisValidators(genesis.validators, validators);
    if (genesis.validators?.length) return;
    genesis.validators = validators;
    await fs.promises.writeFile(genesisPath, JSON.stringify(genesis, null, 2), "utf-8");
}

export async function ensureRealmP2pConfig(
    nodeCli: string,
    cwd: string,
    realmIds: number[],
    edgeCount: number,
    publicHost: string,
    genesisPath: string = path.join(cwd, "genesis.json"),
): Promise<FullNetworkConfig> {
    const runtimeDir = path.join(cwd, REALM_P2P_OUT_DIR);
    const configPath = path.join(runtimeDir, "config.json");
    const sourceBytes = await fs.promises.readFile(path.join(cwd, "psy-genesis/config.json"));
    const sourceConfig = JSON.parse(sourceBytes.toString()) as FullNetworkConfig;
    const genesisConfigHash = createHash("sha256").update(sourceBytes).digest("hex");
    const entries = await fs.promises.readdir(runtimeDir, { withFileTypes: true }).catch((error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return [];
        throw error;
    });
    const secretNames = realmP2pSecretPaths(realmIds, edgeCount).map((secretPath) => path.basename(secretPath));
    const allowedNames = new Set(["config.json", "daemon-config.json", ...secretNames]);
    if (entries.some((entry) => !entry.isFile() || !allowedNames.has(entry.name))) {
        throw new Error("Unexpected Realm P2P runtime artifacts; refusing identity regeneration");
    }
    const names = new Set(entries.map((entry) => entry.name));
    if (entries.length && (!names.has("config.json") || secretNames.some((name) => !names.has(name)))) {
        throw new Error("Incomplete Realm P2P config or keys; refusing identity regeneration");
    }
    let config: FullNetworkConfig | null = null;
    if (names.has("config.json")) {
        config = JSON.parse(await fs.promises.readFile(configPath, "utf-8")) as FullNetworkConfig;
        if (!config || !config.networks) throw new Error("Malformed Realm P2P config; refusing identity regeneration");
    }
    const genesis = JSON.parse(await fs.promises.readFile(genesisPath, "utf-8")) as { validators?: GenesisMembership };
    const validatorUserIds = await genesisValidatorUserIds(cwd, realmIds);
    const plan = planRealmP2pConfig(config, realmIds, edgeCount, publicHost, validatorUserIds, genesisConfigHash, "local-devnet", sourceConfig);
    const configKey = selectedRuntimeConfigKey("local-devnet");
    if (config && plan.reuse) {
        validateGenesisValidators(genesis.validators, realmGenesisValidators({ ...config, defaultNetwork: configKey }));
        const projected = structuredClone(config);
        const network = projected.networks[configKey];
        for (const field of ["prove_proxy_url", "system_prove_proxy_url", "guardian_initial_member_hashes", "fees"] as const) {
            const source = sourceConfig.networks[configKey][field];
            if (source === undefined) delete network[field];
            else network[field] = structuredClone(source);
        }
        delete network.guardian_authorization;
        delete network.guardian_max_fee;
        projected.defaultNetwork = configKey;
        return projected;
    }
    validateGenesisValidators(genesis.validators, []);
    const privateKeys = JSON.parse(await fs.promises.readFile(path.join(cwd, "private_keys.json"), "utf-8")) as string[];
    const validatorKeys = validatorUserIds.map((userId, index) => {
        const realmId = realmIds[Math.floor(index / REALM_P2P_SUB_IDS.length)];
        const subId = (index % REALM_P2P_SUB_IDS.length) + 1;
        const registrationId = reservedValidatorRegistrationId(realmId, subId);
        const expectedUserId = reservedValidatorUserId(realmId, subId);
        if (userId !== expectedUserId) {
            throw new Error(`Validator user id ${userId} does not match reserved id ${expectedUserId} for realm ${realmId} sub ${subId}`);
        }
        const key = privateKeys[registrationId];
        if (typeof key !== "string" || !/^[0-9a-fA-F]{64}$/.test(key)) throw new Error(`Missing or invalid genesis private key for validator user ${userId}`);
        return key;
    });
    const proc = Bun.spawn([nodeCli, "init-realm-p2p-keys", ...plan.args], {
        cwd,
        stdout: "pipe",
        stderr: "pipe",
        env: { ...process.env, ...plan.env },
    });
    const exit = await proc.exited;
    if (exit !== 0) throw new Error(`init-realm-p2p-keys failed (${exit}): ${await new Response(proc.stderr).text()}`);
    config = JSON.parse(await fs.promises.readFile(configPath, "utf-8")) as FullNetworkConfig;
    planRealmP2pConfig(config, realmIds, edgeCount, publicHost, validatorUserIds, genesisConfigHash, "local-devnet", sourceConfig);
    const generated = config.networks[configKey];
    for (const field of ["guardian_initial_member_hashes", "fees"] as const) {
        const source = sourceConfig.networks[configKey][field];
        if (source === undefined) delete generated[field];
        else generated[field] = structuredClone(source);
    }
    delete generated.guardian_authorization;
    config.genesisConfigHash = genesisConfigHash;
    await fs.promises.writeFile(configPath, JSON.stringify(config, null, 2), "utf-8");
    for (let index = 0; index < validatorKeys.length; index++) {
        const realmId = realmIds[Math.floor(index / REALM_P2P_SUB_IDS.length)];
        const subId = index % REALM_P2P_SUB_IDS.length + 1;
        const keyPath = path.join(cwd, REALM_P2P_OUT_DIR, `realm_${realmId}_sub_${subId}_zk.key`);
        await fs.promises.writeFile(keyPath, validatorKeys[index], { encoding: "utf-8", mode: 0o600 });
    }
    config.defaultNetwork = selectedRuntimeConfigKey("local-devnet");
    return config;
}

function selectedRealm(config: FullNetworkConfig, realmId: number): RealmNetworkConfig {
    const realm = config.networks[config.defaultNetwork].realm_configs.find((value) => value.id === realmId);
    if (!realm) throw new Error(`Runtime network config has no Realm ${realmId}`);
    return realm;
}
export function realmP2pProcessorExtraArgs(host: string, realmId: number, subId: number): string[] {
    return [
        "--p2p-identity-key", `${REALM_P2P_OUT_DIR}/realm_${realmId}_sub_${subId}_processor_identity.key`,
        "--p2p-bls-key", `${REALM_P2P_OUT_DIR}/realm_${realmId}_sub_${subId}_bls.key`,
        "--p2p-zk-key", `${REALM_P2P_OUT_DIR}/realm_${realmId}_sub_${subId}_zk.key`,
        "--p2p-listen", realmP2pListen(host, realmP2pProcessorPort(realmId, subId)),
    ];
}
export function realmP2pEdgeExtraArgs(host: string, realmId: number, subId: number, edgeIndex: number, edgeCount: number): string[] {
    return ["--p2p-identity-key", realmP2pEdgeIdentityPath(realmId, subId, edgeIndex), "--p2p-listen", realmP2pListen(host, realmP2pEdgePort(realmId, subId, edgeIndex, edgeCount))];
}
export function relayerStartedDetector(line: string): boolean {
    return /(?:^|\s)(?<!aggregate )(?:multichain bridge relayer started|bridge relayer started)(?!\w)/.test(line);
}
function psyServicesStartedDetector(line: string): boolean {
    return line.includes('Starting API server on')
        || line.includes('API server listening on')
        || line.includes('Server running on');
}
function psyIndexerStartedDetector(line: string): boolean {
    return line.includes('Starting PSY Indexer');
}
function uiStartedDetector(line: string): boolean { return line.includes('ready in'); }

/**
 * Grant public select permissions on all Envio-indexed tables so the frontend
 * (which never sends X-Hasura-Admin-Secret) can query them. This must be called
 * AFTER envio has created the tables (i.e. after Hasura health check passes).
 */
async function ensureEnvioHasuraPublicAccess(): Promise<void> {
    const hasuraUrl = 'http://127.0.0.1:8080';
    const adminSecret = 'testing';
    const tables = ['Deposit', 'DepositTreeMeta', 'DepositTreeNode', 'FinalizedBatch', 'WithdrawalClaim'];
    type HasuraMetadataExport = {
        sources?: Array<{
            name?: string;
            tables?: Array<{
                table?: { name?: string; schema?: string };
                select_permissions?: Array<{
                    role?: string;
                    permission?: { allow_aggregations?: boolean };
                }>;
            }>;
        }>;
    };

    async function hasuraMetadata(type: string, args: Record<string, unknown>): Promise<{ ok: boolean; msg?: string }> {
        try {
            const resp = await fetch(`${hasuraUrl}/v1/metadata`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Hasura-Admin-Secret': adminSecret },
                body: JSON.stringify({ type, args }),
            });
            const body = await resp.json() as { error?: string; message?: string; code?: string };
            if (body.message === 'success') return { ok: true };
            if (body.error?.includes('already-tracked')) {
                return { ok: true, msg: body.error };
            }
            return { ok: false, msg: body.error };
        } catch {
            return { ok: false };
        }
    }

    async function hasuraSql(sql: string): Promise<{ ok: boolean; rows?: string[][]; msg?: string }> {
        try {
            const resp = await fetch(`${hasuraUrl}/v2/query`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Hasura-Admin-Secret': adminSecret },
                body: JSON.stringify({
                    type: 'run_sql',
                    args: {
                        source: 'default',
                        sql,
                        read_only: true,
                    },
                }),
            });
            const body = await resp.json() as { result?: string[][]; error?: string; message?: string };
            if (resp.ok && Array.isArray(body.result)) return { ok: true, rows: body.result };
            return { ok: false, msg: body.error || body.message };
        } catch {
            return { ok: false };
        }
    }

    async function hasuraExportMetadata(): Promise<HasuraMetadataExport | null> {
        try {
            const resp = await fetch(`${hasuraUrl}/v1/metadata`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Hasura-Admin-Secret': adminSecret },
                body: JSON.stringify({ type: 'export_metadata', args: {} }),
            });
            if (!resp.ok) return null;
            return await resp.json() as HasuraMetadataExport;
        } catch {
            return null;
        }
    }

    async function hasuraTableExists(table: string): Promise<boolean> {
        const sql = `select to_regclass('public."${table}"') is not null as exists;`;
        const result = await hasuraSql(sql);
        return result.ok && result.rows?.[1]?.[0] === 't';
    }

    function metadataHasPublicSelect(
        metadata: HasuraMetadataExport | null,
        table: string,
        opts?: { requireAggregations?: boolean }
    ): boolean {
        if (!metadata?.sources) return false;
        const requireAggregations = opts?.requireAggregations ?? false;
        for (const source of metadata.sources) {
            if (source.name !== 'default') continue;
            for (const trackedTable of source.tables || []) {
                if (trackedTable.table?.schema !== 'public' || trackedTable.table?.name !== table) continue;
                for (const permission of trackedTable.select_permissions || []) {
                    if (permission.role !== 'public') continue;
                    if (!requireAggregations || permission.permission?.allow_aggregations === true) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    async function anonymousAggregateAvailable(table: string): Promise<boolean> {
        try {
            const resp = await fetch(`${hasuraUrl}/v1/graphql`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: `query { ${table}_aggregate { aggregate { count } } }`,
                }),
            });
            const body = await resp.json() as { data?: unknown; errors?: unknown };
            return resp.ok && body.data != null && body.errors == null;
        } catch {
            return false;
        }
    }

    async function ensurePublicSelectPermission(table: string): Promise<boolean> {
        const permission = { filter: {}, columns: '*', allow_aggregations: true };
        const args = {
            table: { name: table, schema: 'public' },
            source: 'default',
            role: 'public',
            permission,
        };

        const create = await hasuraMetadata('pg_create_select_permission', args);
        if (create.ok) return true;

        if (!create.msg?.includes('already defined') && !create.msg?.includes('already-exists')) {
            return false;
        }

        if (await anonymousAggregateAvailable(table)) {
            return true;
        }

        const metadata = await hasuraExportMetadata();
        if (metadataHasPublicSelect(metadata, table, { requireAggregations: true })) {
            return true;
        }

        // Older devnets created select permissions without allow_aggregations,
        // which hides *_aggregate fields from the anonymous GraphQL schema.
        const drop = await hasuraMetadata('pg_drop_select_permission', {
            table: { name: table, schema: 'public' },
            source: 'default',
            role: 'public',
        });
        if (!drop.ok) return false;
        const recreate = await hasuraMetadata('pg_create_select_permission', args);
        return recreate.ok;
    }

    async function anonymousAggregatesAvailable(): Promise<boolean> {
        try {
            const resp = await fetch(`${hasuraUrl}/v1/graphql`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: '{ Deposit_aggregate { aggregate { count } } DepositTreeNode_aggregate { aggregate { count } } }',
                }),
            });
            const body = await resp.json() as { data?: unknown; errors?: unknown };
            return resp.ok && body.data != null && body.errors == null;
        } catch {
            return false;
        }
    }

    // Envio opens its API before Hasura has necessarily tracked and exposed the
    // generated tables. Wait for the postgres tables to exist before applying
    // metadata to avoid false warnings on fresh devnet boots.
    for (let attempt = 0; attempt < 90; attempt++) {
        const missingTables: string[] = [];
        for (const table of tables) {
            if (!(await hasuraTableExists(table))) missingTables.push(table);
        }
        if (missingTables.length === 0) {
            break;
        }
        if (attempt === 89) {
            console.warn('[DevNet] Envio tables did not appear in Hasura postgres within timeout:', missingTables);
            return;
        }
        await new Promise(r => setTimeout(r, 2000));
    }

    for (let attempt = 0; attempt < 60; attempt++) {
        const remaining: string[] = [];
        for (const table of tables) {
            // Step 1: track the table in Hasura metadata (idempotent)
            const track = await hasuraMetadata('pg_track_table', {
                table: { name: table, schema: 'public' },
                source: 'default',
            });
            // Step 2: grant public select permission (idempotent)
            const permOk = await ensurePublicSelectPermission(table);
            if (!track.ok || !permOk) {
                remaining.push(table);
            }
        }
        if (remaining.length === 0) {
            if (!(await anonymousAggregatesAvailable())) {
                await new Promise(r => setTimeout(r, 2000));
                if (!(await anonymousAggregatesAvailable())) {
                    const metadata = await hasuraExportMetadata();
                    const stillMissing = tables.filter((table) => !metadataHasPublicSelect(metadata, table, { requireAggregations: true }));
                    if (stillMissing.length === 0) {
                        console.log('[DevNet] Envio Hasura public permissions set');
                        return;
                    }
                    console.warn('[DevNet] Envio Hasura public aggregate fields are not visible yet');
                    continue;
                }
            }
            console.log('[DevNet] Envio Hasura public permissions set');
            return;
        }
        await new Promise(r => setTimeout(r, 2000));
    }
    const metadata = await hasuraExportMetadata();
    const missingPermissions = tables.filter((table) => !metadataHasPublicSelect(metadata, table, { requireAggregations: true }));
    if (missingPermissions.length === 0) {
        console.log('[DevNet] Envio Hasura public permissions set');
        return;
    }
    console.warn('[DevNet] Failed to set Envio Hasura public permissions for:', missingPermissions);
}

export async function guardianSessionsReady(response: Response): Promise<boolean> {
    if (response.status !== 200) return false;
    const page = await response.json();
    return !!page && Array.isArray(page.sessions) && page.sessions.length <= 1
        && typeof page.next_after_nonce === "number" && Number.isFinite(page.next_after_nonce)
        && Number.isInteger(page.next_after_nonce) && page.next_after_nonce >= 0
        && typeof page.has_more === "boolean";
}
/** HTTP 200 only when the runtime account is initialized and not halted. `network_magic` is a configured u64; JSON number parsing loses precision, so this check is status only and must not compare identity. */
export async function guardianServiceReady(response: Response): Promise<boolean> {
    if (response.status !== 200) return false;
    const body = await response.json();
    return !!body && body.schema_version === 3 && body.runtime_initialized === true && body.halted === false
        && typeof body.user_id === "number" && Number.isSafeInteger(body.user_id) && body.user_id >= 0
        && typeof body.network_magic === "number" && Number.isInteger(body.network_magic) && body.network_magic > 0;
}


async function waitForHttpUrl(
    url: string,
    opts?: { attempts?: number; delayMs?: number; timeoutMs?: number; name?: string; validateResponse?: (response: Response) => Promise<boolean> }
): Promise<void> {
    const attempts = opts?.attempts ?? 20;
    const delayMs = opts?.delayMs ?? 1000;
    const timeoutMs = opts?.timeoutMs ?? 1500;
    const name = opts?.name ?? url;
    for (let i = 1; i <= attempts; i++) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), timeoutMs);
        try {
            const res = await fetch(url, { method: "GET", signal: ctrl.signal, redirect: opts?.validateResponse ? "error" : "follow" });
            if (opts?.validateResponse ? await opts.validateResponse(res) : res.ok || res.status < 500) {
                return;
            }
        } catch {
            // retry
        } finally {
            clearTimeout(timer);
        }
        if (i < attempts) {
            await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
    }
    throw new Error(`[DevNet] Timed out waiting for ${name}: ${url}`);
}

async function waitForTcpPort(
    host: string,
    port: number,
    opts?: { attempts?: number; delayMs?: number; timeoutMs?: number; name?: string }
): Promise<void> {
    const attempts = opts?.attempts ?? 30;
    const delayMs = opts?.delayMs ?? 1000;
    const timeoutMs = opts?.timeoutMs ?? 1500;
    const name = opts?.name ?? `${host}:${port}`;

    for (let i = 1; i <= attempts; i++) {
        try {
            await new Promise<void>((resolve, reject) => {
                const socket = net.createConnection({ host, port });
                const timer = setTimeout(() => {
                    socket.destroy();
                    reject(new Error(`timeout waiting for ${name}`));
                }, timeoutMs);

                socket.once("connect", () => {
                    clearTimeout(timer);
                    socket.end();
                    resolve();
                });
                socket.once("error", (err) => {
                    clearTimeout(timer);
                    socket.destroy();
                    reject(err);
                });
            });
            return;
        } catch {
            // retry
        }
        if (i < attempts) {
            await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
    }

    throw new Error(`[DevNet] Timed out waiting for TCP service ${name}`);
}


async function waitForLogPattern(
    filePath: string,
    pattern: RegExp,
    opts?: { attempts?: number; delayMs?: number; name?: string }
): Promise<void> {
    const attempts = opts?.attempts ?? 60;
    const delayMs = opts?.delayMs ?? 1000;
    const name = opts?.name ?? filePath;

    for (let i = 1; i <= attempts; i++) {
        try {
            if (await exists(filePath)) {
                const raw = await Bun.file(filePath).text();
                if (pattern.test(raw)) {
                    return;
                }
            }
        } catch {
            // retry
        }

        if (i < attempts) {
            await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
    }

    throw new Error(`[DevNet] Timed out waiting for log pattern in ${name}`);
}

// --- Auto setup: clone repos, build binaries, install deps, download keystore ---

const REPO_CONFIGS = [
    { name: "psy-services", url: "https://github.com/PsyProtocol/psy-services.git", branch: "mainnet-beta" },
    { name: "psy-wallet", url: "https://github.com/PsyProtocol/psy-wallet.git", branch: "mainnet-beta" },
    { name: "psy-sdk", url: "https://github.com/PsyProtocol/psy-sdk.git", branch: "mainnet-beta" },
    { name: "psy-compiler", url: "https://github.com/PsyProtocol/psy-compiler.git", branch: "mainnet-beta" },
] as const;

// Resolve the psy-node repository root from the script location so the
// script works regardless of the caller's cwd.
const REPO_ROOT = path.resolve(import.meta.dir, "..");
const GIT_NO_LFS_CONFIG_ARGS = [
    "-c", "filter.lfs.process=",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.required=false",
] as const;

function gitWithoutLfs(...args: string[]): string[] {
    return ["git", ...GIT_NO_LFS_CONFIG_ARGS, ...args];
}

export function resolveProjectsDir(): string {
    const configuredProjectsDir = process.env.PSY_PROJECTS_DIR?.trim();
    if (configuredProjectsDir) return path.resolve(configuredProjectsDir);
    return path.resolve(REPO_ROOT, "..");
}

function normalizeGitRemoteUrl(url: string): string {
    const trimmed = url.trim().replace(/\/+$/, "").replace(/\.git$/, "");
    const sshMatch = trimmed.match(/^git@([^:]+):(.+)$/);
    if (sshMatch) {
        return `${sshMatch[1].toLowerCase()}/${sshMatch[2]}`;
    }
    const httpsMatch = trimmed.match(/^(?:https?:\/\/)?([^/]+)\/(.+)$/);
    if (httpsMatch) {
        return `${httpsMatch[1].toLowerCase()}/${httpsMatch[2]}`;
    }
    return trimmed;
}


async function gitRef(repoPath: string, ref: string): Promise<string | null> {
    const result = await runAndCapture(["git", "rev-parse", "--verify", ref], repoPath);
    if (result.code !== 0) return null;
    return result.stdout.trim();
}


async function stashDirtyWorktree(repoName: string, repoPath: string, reason: string): Promise<void> {
    const statusResult = await runAndCapture(["git", "status", "--porcelain"], repoPath);
    if (statusResult.code !== 0) {
        throw new Error(`[AutoSetup] Failed to inspect ${repoName} worktree at ${repoPath}: ${statusResult.stderr || statusResult.stdout}`);
    }
    if (statusResult.stdout.trim().length === 0) return;

    const stashResult = await runAndCapture(
        ["git", "stash", "push", "--include-untracked", "-m", `auto-setup ${repoName} ${reason} ${new Date().toISOString()}`],
        repoPath,
    );
    if (stashResult.code !== 0) {
        throw new Error(`[AutoSetup] ${repoName} worktree is dirty and git stash failed: ${stashResult.stderr || stashResult.stdout}`);
    }
    console.log(`[AutoSetup] ${repoName}: local changes detected — stashing before ${reason}.`);
    console.log(`[AutoSetup] Recover with: cd ${repoPath} && git stash pop   (or: git stash list)`);
}

async function syncRepoToRemoteBranch(repoName: string, repoPath: string, branch: string): Promise<void> {
    const remoteRef = `origin/${branch}`;
    if (shouldSkipBranchSync(process.env.PSY_SKIP_BRANCH_CHECK)) {
        console.warn(`[AutoSetup] ${repoName}: branch sync disabled by default — leaving current HEAD untouched (expected ${remoteRef}); set PSY_SKIP_BRANCH_CHECK=0 to sync`);
        return;
    }
    const fetchResult = await runAndCapture(gitWithoutLfs("fetch", "origin", branch), repoPath);
    if (fetchResult.code !== 0) {
        throw new Error(`[AutoSetup] Failed to fetch ${remoteRef} for ${repoName}: ${fetchResult.stderr || fetchResult.stdout}`);
    }

    // Sync behind, ahead, and diverged HEADs uniformly: local commits stay on
    // their branch ref, while uncommitted work is recoverable from the stash.
    const head = await gitRef(repoPath, "HEAD");
    const remoteHead = await gitRef(repoPath, remoteRef);
    if (!head || !remoteHead) {
        throw new Error(`[AutoSetup] Failed to resolve HEAD or ${remoteRef} for ${repoName}`);
    }
    if (head === remoteHead) {
        console.log(`[AutoSetup] ${repoName} already at ${remoteRef}`);
        return;
    }

    await stashDirtyWorktree(repoName, repoPath, `syncing to ${remoteRef}`);
    const checkoutResult = await runAndCapture(gitWithoutLfs("checkout", remoteRef), repoPath);
    if (checkoutResult.code !== 0) {
        throw new Error(`[AutoSetup] Failed to checkout ${repoName} at ${remoteRef}: ${checkoutResult.stderr || checkoutResult.stdout}`);
    }
    const syncedHead = await gitRef(repoPath, "HEAD");
    if (syncedHead !== remoteHead) {
        throw new Error(`[AutoSetup] ${repoName} checkout of ${remoteRef} did not land at expected commit (got ${syncedHead}, expected ${remoteHead})`);
    }
    console.log(`[AutoSetup] ${repoName} synced to ${remoteRef} (detached HEAD)`);
}

async function ensureRepoCloned(repoName: string, repoUrl: string, branch: string): Promise<string> {
    const projectsDir = resolveProjectsDir();
    const repoPath = path.join(projectsDir, repoName);
    if (await exists(path.join(repoPath, ".git"))) {
        const remoteResult = await runAndCapture(["git", "remote", "-v"], repoPath);
        if (remoteResult.code !== 0) {
            throw new Error(`[AutoSetup] Failed to inspect ${repoName} remotes at ${repoPath}: ${remoteResult.stderr || remoteResult.stdout}`);
        }
        const expectedOrigin = normalizeGitRemoteUrl(repoUrl);
        // Accept the canonical URL on ANY remote (not just origin): source
        // checkouts keep their historical origin (e.g. psy-services origin is
        // QEDProtocol) with the PsyProtocol canonical remote added separately.
        const remotes = remoteResult.stdout
            .split("\n")
            .map((line) => line.split(/\s+/)[1])
            .filter((url): url is string => Boolean(url))
            .map(normalizeGitRemoteUrl);
        if (!remotes.includes(expectedOrigin)) {
            throw new Error(`[AutoSetup] ${repoName} already exists at ${repoPath} but no remote matches '${expectedOrigin}'. Fix the remote or remove the repo to let auto-setup reclone it.`);
        }
        if (shouldSkipBranchSync(process.env.PSY_SKIP_BRANCH_CHECK)) {
            console.log(`[AutoSetup] Branch sync disabled by default — leaving ${repoName} HEAD untouched; set PSY_SKIP_BRANCH_CHECK=0 to sync`);
        } else {
            await syncRepoToRemoteBranch(repoName, repoPath, branch);
        }
        return repoPath;
    }
    console.log(`[AutoSetup] Cloning ${repoName} from ${repoUrl} (branch: ${branch})...`);
    await mkdir(projectsDir, { recursive: true });
    const result = await runAndCapture(gitWithoutLfs("clone", "-b", branch, repoUrl, repoPath));
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to clone ${repoName} branch '${branch}': ${result.stderr || result.stdout}`);
    }
    console.log(`[AutoSetup] ${repoName} cloned to ${repoPath}`);
    return repoPath;
}

async function ensureRequiredSubmodules(cwd: string): Promise<void> {
    const requiredSubmodules = ["psy-genesis", "psy-contracts", "psy-dapp"];
    const missingSubmodules: string[] = [];
    for (const submodule of requiredSubmodules) {
        if (!(await exists(path.join(cwd, submodule, ".git")))) {
            missingSubmodules.push(submodule);
        }
    }
    if (missingSubmodules.length === 0) return;

    throw new Error(
        `[AutoSetup] Required submodules are not initialized: ${missingSubmodules.join(", ")}. ` +
        "Run `git submodule update --init --recursive` from the psy-node repository.",
    );
}

async function ensurePsySdkGenesisSubmodule(sdkRoot: string): Promise<void> {
    if (!(await exists(path.join(sdkRoot, ".git")))) {
        throw new Error(`[AutoSetup] psy-sdk repository is missing under the projects directory: ${sdkRoot}`);
    }
    const gitMetadataPresent = await exists(path.join(sdkRoot, PSY_SDK_GENESIS_SUBMODULE, ".git"));
    const configPresent = await exists(path.join(sdkRoot, PSY_SDK_GENESIS_CONFIG_REL));
    if (!psySdkGenesisSubmoduleNeedsInit({ gitMetadataPresent, configPresent })) {
        return;
    }

    console.log(`[AutoSetup] psy-sdk: initializing ${PSY_SDK_GENESIS_SUBMODULE} submodule...`);
    const result = await runAndCapture(
        gitWithoutLfs("submodule", "update", "--init", "--", PSY_SDK_GENESIS_SUBMODULE),
        sdkRoot,
    );
    if (result.code !== 0) {
        throw new Error(
            `[AutoSetup] Failed to initialize psy-sdk ${PSY_SDK_GENESIS_SUBMODULE} submodule: ` +
            `${result.stderr || result.stdout}. ` +
            `Run \`git submodule update --init -- ${PSY_SDK_GENESIS_SUBMODULE}\` from ${sdkRoot}.`,
        );
    }

    const readyGit = await exists(path.join(sdkRoot, PSY_SDK_GENESIS_SUBMODULE, ".git"));
    const readyConfig = await exists(path.join(sdkRoot, PSY_SDK_GENESIS_CONFIG_REL));
    if (psySdkGenesisSubmoduleNeedsInit({ gitMetadataPresent: readyGit, configPresent: readyConfig })) {
        throw new Error(
            `[AutoSetup] psy-sdk still missing ${PSY_SDK_GENESIS_CONFIG_REL} after submodule init. ` +
            `Run \`git submodule update --init -- ${PSY_SDK_GENESIS_SUBMODULE}\` from ${sdkRoot}.`,
        );
    }
    console.log(`[AutoSetup] psy-sdk: ${PSY_SDK_GENESIS_CONFIG_REL} ready`);
}

/**
 * Gather disk facts for the nested psy-dapp gitlinks: which gitlinks lack
 * their .git gitlink metadata and which payload files are missing. Pure
 * planning happens in planPsyDappNestedSubmoduleInit; this only touches the
 * filesystem, never git or the network.
 */
export async function planPsyDappNestedSubmodulesFromDisk(dappRoot: string): Promise<PsyDappNestedInitPlan> {
    const uninitialized: PsyDappNestedSubmodule[] = [];
    const missingPayloads: Partial<Record<PsyDappNestedSubmodule, string[]>> = {};
    for (const name of PSY_DAPP_NESTED_SUBMODULES) {
        if (!(await exists(path.join(dappRoot, name, ".git")))) {
            uninitialized.push(name);
            continue;
        }
        const missing: string[] = [];
        for (const rel of PSY_DAPP_NESTED_PAYLOADS[name]) {
            if (!(await exists(path.join(dappRoot, name, rel)))) missing.push(rel);
        }
        if (missing.length > 0) missingPayloads[name] = missing;
    }
    return planPsyDappNestedSubmoduleInit({ uninitialized, missingPayloads });
}

/**
 * Ensure the nested psy-dapp gitlinks (psy-genesis, psy-contracts) are
 * initialized before any UI dependency install or dev-server startup reads
 * their payloads (config.json, protocol-config, deployments). Existing
 * initialized checkouts are a no-op; failures throw with repository-relative
 * commands and never silently continue.
 */
async function ensurePsyDappNestedSubmodules(dappRoot: string): Promise<void> {
    if (!(await exists(path.join(dappRoot, ".git")))) {
        throw new Error(
            `[AutoSetup] psy-dapp checkout is missing at ${dappRoot}. ` +
            "Run `git submodule update --init -- psy-dapp` from the psy-node repository.",
        );
    }
    const dappRelPath = path.relative(REPO_ROOT, dappRoot) || "psy-dapp";

    const plan = await planPsyDappNestedSubmodulesFromDisk(dappRoot);
    if (plan.ready) return;

    console.log(`[AutoSetup] psy-dapp: initializing nested gitlinks ${plan.pending.join(", ")}...`);
    const result = await runAndCapture(gitWithoutLfs(...plan.updateArgs), dappRoot);
    if (result.code !== 0) {
        throw new Error(
            `[AutoSetup] Failed to initialize psy-dapp nested gitlinks (${plan.pending.join(", ")}): ` +
            `${result.stderr || result.stdout}. ` +
            formatPsyDappNestedSubmoduleRemedy(dappRelPath, plan),
        );
    }

    const afterPlan = await planPsyDappNestedSubmodulesFromDisk(dappRoot);
    if (!afterPlan.ready) {
        throw new Error(
            `[AutoSetup] psy-dapp nested gitlinks still incomplete after init (${afterPlan.pending.join(", ")}). ` +
            formatPsyDappNestedSubmoduleRemedy(dappRelPath, afterPlan),
        );
    }
    console.log(`[AutoSetup] psy-dapp: nested gitlinks ${PSY_DAPP_NESTED_SUBMODULES.join(", ")} ready`);
}

async function ensureAllReposCloned(): Promise<void> {
    for (const repo of REPO_CONFIGS) {
        const repoPath = await ensureRepoCloned(repo.name, repo.url, repo.branch);
        if (repo.name === "psy-sdk") {
            await ensurePsySdkGenesisSubmodule(repoPath);
        }
    }
}

async function ensureBinaryBuilt(binaryPath: string, buildArgs: string[], cwd: string, name: string): Promise<void> {
    if (await exists(binaryPath)) {
        console.log(`[AutoSetup] ${name} binary already exists`);
        return;
    }
    console.log(`[AutoSetup] Building ${name}...`);
    const result = await runAndCapture(buildArgs, cwd);
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to build ${name}: ${result.stderr || result.stdout}`);
    }
    console.log(`[AutoSetup] ${name} built successfully`);
}

function skipBuildEnabled(): boolean {
    return shouldSkipBranchSync(process.env.PSY_SKIP_BUILD);
}

async function requireReleaseBinaries(binaries: Array<{ name: string; path: string }>): Promise<void> {
    const missing: string[] = [];
    for (const binary of binaries) {
        if (!(await exists(binary.path))) {
            missing.push(`${binary.name} (${binary.path})`);
        }
    }
    if (missing.length > 0) {
        throw new Error(
            `[AutoSetup] Skipping build requires existing release binaries. Missing: ${missing.join(", ")}. ` +
            `Set PSY_SKIP_BUILD=0 to build them.`,
        );
    }
}

async function ensureAllBinariesBuilt(cwd: string): Promise<void> {
    const nodeBinaries = [
        { name: "psy_node_cli", path: path.join(cwd, "target", "release", "psy_node_cli") },
        { name: "psy_worker_cli", path: path.join(cwd, "target", "release", "psy_worker_cli") },
        { name: "psy_relayer_cli", path: path.join(cwd, "target", "release", "psy_relayer_cli") },
        { name: "psy_user_cli", path: path.join(cwd, "target", "release", "psy_user_cli") },
        { name: "psy_dev_cli", path: path.join(cwd, "target", "release", "psy_dev_cli") },
    ];
    const psyServicesPath = path.resolve(resolveProjectsDir(), "psy-services");
    const psyServicesBinaries = [
        { name: "psy-services", path: path.join(psyServicesPath, "target", "release", "psy-services") },
        { name: "psy-indexer", path: path.join(psyServicesPath, "target", "release", "psy-indexer") },
    ];

    if (skipBuildEnabled()) {
        await requireReleaseBinaries([...nodeBinaries, ...psyServicesBinaries]);
        console.warn("[AutoSetup] build skipped unless PSY_SKIP_BUILD=0 -- using existing release binaries without running Cargo");
        return;
    }

    // Always run cargo build --release for psy-node. Cargo's incremental
    // compilation skips unchanged crates while still picking up source changes.
    console.log("[AutoSetup] Building psy-node binaries (incremental)...");
    const nodeCode = await runStreaming(
        ["cargo", "build", "--release", "--locked",
         "--bin", "psy_node_cli",
         "--bin", "psy_worker_cli",
         "--bin", "psy_relayer_cli",
         "--bin", "psy_user_cli",
         "--bin", "psy_dev_cli"],
        cwd,
    );
    if (nodeCode !== 0) {
        throw new Error(`[AutoSetup] Failed to build psy-node binaries (exit ${nodeCode})`);
    }
    console.log("[AutoSetup] psy-node binaries ready");

    // Always run cargo build --release for psy-services too.
    if (await exists(path.join(psyServicesPath, "Cargo.toml"))) {
        console.log("[AutoSetup] Building psy-services binaries (incremental)...");
        const psCode = await runStreaming(
            ["cargo", "build", "--release", "--locked", "--bin", "psy-services", "--bin", "psy-indexer"],
            psyServicesPath,
        );
        if (psCode !== 0) {
            throw new Error(`[AutoSetup] Failed to build psy-services (exit ${psCode})`);
        }
        console.log("[AutoSetup] psy-services binaries ready");
    }
}

async function shouldUseFrozenPnpmLock(dir: string): Promise<boolean> {
    const npmConfigPath = path.join(dir, ".npmrc");
    if (!await exists(npmConfigPath)) return false;
    const npmConfig = await Bun.file(npmConfigPath).text();
    return npmConfig
        .split(/\r?\n/)
        .some((line) => line.trim() === "lockfile=true");
}

async function ensureNpmDeps(dir: string, name: string, opts?: { force?: boolean }): Promise<void> {
    const nodeModules = path.join(dir, "node_modules");
    if (frozenDepsEnabled()) {
        if (!(await exists(nodeModules))) throw new Error(`[DevNet] PSY_FROZEN_DEPS requires preinstalled ${name} dependencies`);
        return;
    }
    if (!opts?.force && await exists(nodeModules)) {
        console.log(`[AutoSetup] ${name} deps already installed`);
        return;
    }
    console.log(`[AutoSetup] ${opts?.force ? "Refreshing" : "Installing"} ${name} deps...`);
    const hasPnpmLock = await exists(path.join(dir, "pnpm-lock.yaml"));
    const hasBunLock = await exists(path.join(dir, "bun.lock"));
    const hasPackageLock = await exists(path.join(dir, "package-lock.json"));
    let result: { code: number; stdout: string; stderr: string };
    if (hasPnpmLock) {
        await ensurePnpmBuildScriptsApproved(dir, ["esbuild"]);
        const installMode = await shouldUseFrozenPnpmLock(dir) ? "--frozen-lockfile" : "--no-frozen-lockfile";
        result = await runAndCapture(["pnpm", "install", installMode], dir);
    } else if (hasBunLock || !hasPackageLock) {
        result = await runAndCapture(["bun", "install"], dir);
    } else {
        result = await runAndCapture(["npm", "install"], dir);
    }
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to install ${name} deps: ${result.stderr || result.stdout}`);
    }
    console.log(`[AutoSetup] ${name} deps installed`);
}

async function ensureAllUiDeps(cwd: string, opts?: { force?: boolean }): Promise<void> {
    const uiDirs = [
        { dir: path.join(cwd, "psy-dapp"), name: "psy-dapp" },
        { dir: path.join(cwd, "psy-contracts"), name: "psy-contracts" },
    ];
    for (const { dir, name } of uiDirs) {
        if (await exists(path.join(dir, "package.json"))) {
            await ensureNpmDeps(dir, name, opts);
        }
    }
}

export type CompilerArtifactFingerprint = {
    compilerRevision: string;
    compilerSourcesHash: string;
};

export type GenesisContractsArtifactFingerprint = CompilerArtifactFingerprint & {
    artifactSha256: string;
    artifactByteSize: number;
    tokenArtifactSha256: string;
    tokenArtifactByteSize: number;
    tokenUpdateArtifactSha256: string;
    tokenUpdateArtifactByteSize: number;
};

export type CompilerArtifactStampMatch = "match" | "missing" | "mismatch";

export function evaluateCompilerArtifactStamp(
    actual: GenesisContractsArtifactFingerprint | null,
    expected: GenesisContractsArtifactFingerprint,
): CompilerArtifactStampMatch {
    if (!actual) return "missing";
    if (actual.compilerRevision !== expected.compilerRevision
        || actual.compilerSourcesHash !== expected.compilerSourcesHash
        || actual.artifactSha256 !== expected.artifactSha256
        || actual.artifactByteSize !== expected.artifactByteSize
        || actual.tokenArtifactSha256 !== expected.tokenArtifactSha256
        || actual.tokenArtifactByteSize !== expected.tokenArtifactByteSize
        || actual.tokenUpdateArtifactSha256 !== expected.tokenUpdateArtifactSha256
        || actual.tokenUpdateArtifactByteSize !== expected.tokenUpdateArtifactByteSize) {
        return "mismatch";
    }
    return "match";
}

export async function writeCompilerArtifactStamp(
    stampPath: string,
    fingerprint: GenesisContractsArtifactFingerprint,
): Promise<void> {
    const tmpPath = `${stampPath}.tmp`;
    try {
        await fs.promises.writeFile(tmpPath, `${JSON.stringify(fingerprint, null, 2)}\n`, "utf8");
        await fs.promises.rename(tmpPath, stampPath);
    } catch (error) {
        await fs.promises.rm(tmpPath, { force: true }).catch(() => undefined);
        throw error;
    }
}



async function resolveCompilerArtifactFingerprint(compilerDir: string): Promise<CompilerArtifactFingerprint> {
    const revision = await runAndCapture(["git", "rev-parse", "HEAD"], compilerDir);
    if (revision.code !== 0) {
        throw new Error(`[AutoSetup] Failed to resolve standalone compiler revision: ${revision.stderr || revision.stdout}`);
    }
    const sourceList = await runAndCapture(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        compilerDir,
    );
    if (sourceList.code !== 0) {
        throw new Error(`[AutoSetup] Failed to list standalone compiler sources: ${sourceList.stderr || sourceList.stdout}`);
    }
    const sourcePaths = sourceList.stdout
        .split("\0")
        .filter(Boolean)
        .filter(isCompilerFingerprintSource)
        .sort((left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
    const hash = createHash("sha256");
    for (const sourcePath of sourcePaths) {
        const absoluteSourcePath = path.join(compilerDir, sourcePath);
        const stat = await fs.promises.lstat(absoluteSourcePath);
        const sourceBytes = stat.isFile()
            ? await fs.promises.readFile(absoluteSourcePath)
            : stat.isSymbolicLink()
                ? Buffer.from(await fs.promises.readlink(absoluteSourcePath), "utf8")
                : undefined;
        if (!sourceBytes) continue;
        hash.update(Buffer.from(sourcePath, "utf8"));
        hash.update(Buffer.from([0]));
        hash.update(sourceBytes);
        hash.update(Buffer.from([0]));
    }
    return {
        compilerRevision: revision.stdout.trim(),
        compilerSourcesHash: hash.digest("hex"),
    };
}

async function readCompilerArtifactFingerprint(stampPath: string): Promise<CompilerArtifactFingerprint | null> {
    try {
        const parsed = JSON.parse(await fs.promises.readFile(stampPath, "utf8")) as Partial<CompilerArtifactFingerprint>;
        if (typeof parsed.compilerRevision !== "string" || typeof parsed.compilerSourcesHash !== "string") {
            return null;
        }
        return {
            compilerRevision: parsed.compilerRevision,
            compilerSourcesHash: parsed.compilerSourcesHash,
        };
    } catch {
        return null;
    }
}

export async function readGenesisContractsArtifactStamp(
    stampPath: string,
): Promise<GenesisContractsArtifactFingerprint | null> {
    try {
        const parsed = JSON.parse(await fs.promises.readFile(stampPath, "utf8")) as Partial<GenesisContractsArtifactFingerprint>;
        if (typeof parsed.compilerRevision !== "string"
            || typeof parsed.compilerSourcesHash !== "string"
            || typeof parsed.artifactSha256 !== "string"
            || typeof parsed.artifactByteSize !== "number"
            || typeof parsed.tokenArtifactSha256 !== "string"
            || typeof parsed.tokenArtifactByteSize !== "number"
            || typeof parsed.tokenUpdateArtifactSha256 !== "string"
            || typeof parsed.tokenUpdateArtifactByteSize !== "number") {
            return null;
        }
        return {
            compilerRevision: parsed.compilerRevision,
            compilerSourcesHash: parsed.compilerSourcesHash,
            artifactSha256: parsed.artifactSha256,
            artifactByteSize: parsed.artifactByteSize,
            tokenArtifactSha256: parsed.tokenArtifactSha256,
            tokenArtifactByteSize: parsed.tokenArtifactByteSize,
            tokenUpdateArtifactSha256: parsed.tokenUpdateArtifactSha256,
            tokenUpdateArtifactByteSize: parsed.tokenUpdateArtifactByteSize,
        };
    } catch {
        return null;
    }
}


async function assemblePsySdkCompilerSidecar(sdkDir: string, workspaceDir: string): Promise<void> {
    const compilerDistDir = path.join(sdkDir, "dist", "local-web-compiler");
    const sidecarDir = path.join(workspaceDir, "target", "release", "psy-sdk-compiler");
    const artifacts = [
        [path.join(compilerDistDir, "psy_compiler.mjs"), "psy_compiler.mjs"],
        [path.join(compilerDistDir, "wasm-binary.mjs"), "wasm-binary.mjs"],
        [path.join(sdkDir, ".compiler-artifact.json"), ".compiler-artifact.json"],
    ] as const;

    await rm(sidecarDir, { recursive: true, force: true });
    await mkdir(sidecarDir, { recursive: true });
    for (const [sourcePath, fileName] of artifacts) {
        if (!(await exists(sourcePath))) {
            throw new Error(`[AutoSetup] psy-sdk compiler sidecar artifact is missing: ${path.relative(sdkDir, sourcePath)}`);
        }
        await fs.promises.copyFile(sourcePath, path.join(sidecarDir, fileName));
    }
    console.log(`[AutoSetup] assembled native compiler sidecar at ${path.relative(workspaceDir, sidecarDir)}`);
}

async function ensurePsySdkArtifacts(workspaceDir: string): Promise<{ rebuilt: boolean }> {
    const projectsDir = resolveProjectsDir();
    const compilerDir = path.resolve(projectsDir, "psy-compiler");
    const sdkRoot = path.resolve(projectsDir, "psy-sdk");
    const sdkDir = path.resolve(sdkRoot, "psy-ts-sdk", "packages", "psy-sdk");
    if (!(await exists(path.join(compilerDir, "Cargo.toml")))) {
        throw new Error(`[AutoSetup] standalone psy-compiler repository is missing under the projects directory`);
    }
    if (!(await exists(path.join(sdkDir, "package.json")))) {
        throw new Error(`[AutoSetup] psy-sdk package not found under the projects directory`);
    }
    // prepare:wasm copies ../../../psy-genesis/config.json; init before any build/read.
    await ensurePsySdkGenesisSubmodule(sdkRoot);
    const requiredArtifacts = [
        path.join(sdkDir, "dist", "index.mjs"),
        path.join(sdkDir, "dist", "index.d.ts"),
        path.join(sdkDir, "dist", "local-web-prover", "index.mjs"),
        path.join(sdkDir, "dist", "local-web-compiler", "index.mjs"),
        path.join(sdkDir, "src", "local-web-prover", "psy_prover_bg.wasm"),
        path.join(sdkDir, "src", "local-prover", "psy_prover_bg.wasm"),
        path.join(sdkDir, "src", "local-web-compiler", "psy_compiler_bg.wasm"),
        path.join(sdkDir, "dist", "local-web-compiler", "psy_compiler.mjs"),
        path.join(sdkDir, "dist", "local-web-compiler", "wasm-binary.mjs"),
    ];
    const staleReasons: string[] = [];
    for (const artifact of requiredArtifacts) {
        if (!(await exists(artifact))) staleReasons.push(`missing ${path.relative(sdkDir, artifact)}`);
    }
    const expectedFingerprint = await resolveCompilerArtifactFingerprint(compilerDir);
    const stampPath = path.join(sdkDir, ".compiler-artifact.json");
    const actualFingerprint = await readCompilerArtifactFingerprint(stampPath);
    if (!actualFingerprint) {
        staleReasons.push("missing or invalid .compiler-artifact.json");
    } else {
        if (actualFingerprint.compilerRevision !== expectedFingerprint.compilerRevision) {
            staleReasons.push("compiler revision changed");
        }
        if (actualFingerprint.compilerSourcesHash !== expectedFingerprint.compilerSourcesHash) {
            staleReasons.push("compiler sources changed");
        }
    }
    if (staleReasons.length === 0) {
        console.log("[AutoSetup] psy-sdk dist + compiler WASM match the standalone compiler sources");
        await assemblePsySdkCompilerSidecar(sdkDir, workspaceDir);
        return { rebuilt: false };
    }
    if (skipBuildEnabled() || frozenDepsEnabled()) {
        throw new Error(
            `[AutoSetup] Skipping build requires current psy-sdk compiler artifacts. ` +
            `Rebuild psy-sdk first (${staleReasons.join(", ")}).`,
        );
    }

    await checkToolAvailable("pnpm", "npm i -g pnpm");
    await checkToolAvailable("wasm-pack", "cargo install wasm-pack");
    await ensureNpmDeps(sdkDir, "psy-sdk");

    console.log(`[AutoSetup] Building psy-sdk (${staleReasons.join(", ")})...`);
    const result = await runAndCapture(["pnpm", "build"], sdkDir);
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to build psy-sdk: ${result.stderr || result.stdout}`);
    }

    const stillMissing: string[] = [];
    for (const artifact of requiredArtifacts) {
        if (!(await exists(artifact))) stillMissing.push(path.relative(sdkDir, artifact));
    }
    if (stillMissing.length > 0) {
        throw new Error(`[AutoSetup] psy-sdk build completed but artifacts are still missing: ${stillMissing.join(", ")}`);
    }
    const rebuiltFingerprint = await readCompilerArtifactFingerprint(stampPath);
    const currentFingerprint = await resolveCompilerArtifactFingerprint(compilerDir);
    if (!rebuiltFingerprint
        || rebuiltFingerprint.compilerRevision !== currentFingerprint.compilerRevision
        || rebuiltFingerprint.compilerSourcesHash !== currentFingerprint.compilerSourcesHash) {
        throw new Error("[AutoSetup] psy-sdk build completed without a matching standalone compiler artifact stamp");
    }

    console.log("[AutoSetup] psy-sdk dist + compiler WASM rebuilt from standalone compiler sources");
    await assemblePsySdkCompilerSidecar(sdkDir, workspaceDir);
    return { rebuilt: true };
}

export async function downloadKeystoreObject(key: string, destPath: string, resume = false): Promise<void> {
    const args = r2CurlArgs(process.env.PSY_KEYSTORE_R2_PREFIX, key, destPath);
    // Part downloads resume; a finished part is skipped by the caller, a short one continues.
    if (resume) args.splice(args.length - 1, 0, "-C", "-");
    const object = args[args.length - 1];
    console.log(`[AutoSetup] Downloading ${object}...`);
    let code: number;
    try {
        // Public HTTPS needs no Wrangler or login. Keep raw subprocess output
        // and spawn errors out of launcher diagnostics.
        const proc = Bun.spawn(args, { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
        code = await proc.exited;
    } catch {
        throw new Error(`[AutoSetup] Failed to download ${object} (exit unavailable)`);
    }
    if (code !== 0) {
        throw new Error(`[AutoSetup] Failed to download ${object} (exit ${code})`);
    }
}

// The four large official objects ship as <object>.part-NN: 256MiB each, zero-based,
// last part holding the remainder. Count is ceil(manifest size / part bytes).
export const TRUST_SETUP_PART_BYTES = 268435456;

export function trustSetupPartKeys(key: string, size: number, partBytes = TRUST_SETUP_PART_BYTES): string[] {
    if (!Number.isSafeInteger(size) || size <= 0 || !Number.isSafeInteger(partBytes) || partBytes <= 0) {
        throw new Error(`[AutoSetup] ${key}: invalid compressed object size`);
    }
    const count = Math.ceil(size / partBytes);
    return Array.from({ length: count }, (_, index) => `${key}.part-${String(index).padStart(2, "0")}`);
}

async function assembleChunkedObject(
    key: string,
    destPath: string,
    expected: { sha256: string; size: number },
    partBytes: number,
): Promise<void> {
    const partKeys = trustSetupPartKeys(key, expected.size, partBytes);
    const partDir = path.dirname(destPath);
    const partPaths: string[] = [];
    for (let index = 0; index < partKeys.length; index++) {
        const partKey = partKeys[index];
        const partPath = path.join(partDir, partKey);
        const partSize = index === partKeys.length - 1
            ? expected.size - partBytes * (partKeys.length - 1)
            : partBytes;
        let stat: { size: number } | null = await fs.promises.stat(partPath).catch(() => null);
        if (stat && stat.size > partSize) {
            await rm(partPath).catch(() => undefined);
            stat = null;
        }
        if (!stat || stat.size !== partSize) {
            try {
                await downloadKeystoreObject(partKey, partPath, true);
            } catch (err) {
                throw new Error(`[AutoSetup] ${key}: missing part ${partKey} (${(err as Error).message})`);
            }
            stat = await fs.promises.stat(partPath).catch(() => null);
            if (!stat || stat.size !== partSize) {
                throw new Error(`[AutoSetup] ${key}: missing or empty part ${partKey}`);
            }
        }
        partPaths.push(partPath);
    }
    const out = await fs.promises.open(destPath, "w");
    try {
        const buf = Buffer.alloc(1024 * 1024);
        for (const partPath of partPaths) {
            const input = await fs.promises.open(partPath, "r");
            try {
                let position = 0;
                for (;;) {
                    const { bytesRead } = await input.read(buf, 0, buf.length, position);
                    if (bytesRead <= 0) break;
                    await out.write(buf.subarray(0, bytesRead));
                    position += bytesRead;
                }
            } finally {
                await input.close();
            }
        }
    } finally {
        await out.close();
    }
    const actual = await digestFile(destPath);
    if (actual.size !== expected.size || actual.sha256 !== expected.sha256) {
        await rm(destPath).catch(() => undefined);
        await Promise.all(partPaths.map((partPath) => rm(partPath).catch(() => undefined)));
        throw new Error(`[AutoSetup] ${key}: sha256/size mismatch vs sha256sums.json`);
    }
    await Promise.all(partPaths.map((partPath) => rm(partPath).catch(() => undefined)));
}

export async function downloadTrustSetupObject(
    group: KeystoreGroup,
    destPath: string,
    manifest: KeystoreManifest,
    partBytes = TRUST_SETUP_PART_BYTES,
): Promise<void> {
    if (!group.chunked) {
        await downloadKeystoreObject(group.key, destPath);
        return;
    }
    const expected = manifest.files[group.key];
    if (!expected || typeof expected.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(expected.sha256)
        || !Number.isSafeInteger(expected.size) || expected.size <= 0) {
        throw new Error(`[AutoSetup] ${group.key}: sha256sums.json has no size/sha256 entry for the compressed object`);
    }
    await assembleChunkedObject(group.key, destPath, expected, partBytes);
}

async function downloadAndExtractTar(group: KeystoreGroup, destDir: string, manifest: KeystoreManifest): Promise<void> {
    const tmpFile = path.join(destDir, path.basename(group.key) + ".tmp");
    await downloadTrustSetupObject(group, tmpFile, manifest);
    console.log(`[AutoSetup] Extracting ${group.key}...`);
    // Use zstd + tar pipe for cross-platform compat (macOS BSD tar doesn't support --zstd)
    const result = await runAndCapture(["bash", "-c", `zstd -d < "${tmpFile}" | tar xf - -C "${destDir}"`]);
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to extract ${group.key}: ${result.stderr}`);
    }
    await rm(tmpFile).catch(() => undefined);
}

async function checkToolAvailable(tool: string, installHint: string): Promise<void> {
    const result = await runAndCapture(["which", tool]);
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Required tool '${tool}' not found. Install: ${installHint}`);
    }
}

async function checkDockerComposeAvailable(): Promise<void> {
    const result = await runAndCapture(["docker", "compose", "version"]);
    if (result.code !== 0) {
        throw new Error("[AutoSetup] Required tool 'docker compose' not found. Install Docker Compose v2 or enable the compose plugin.");
    }
}

/**
 * Fail early when an existing bridge-relayer keystore cannot be decrypted with
 * the resolved password. Avoids long tool/binary startup before a password
 * mismatch is discovered at deploy/relayer time. Never logs the password.
 */
async function assertExistingBridgeRelayerKeystorePassword(
    keystorePath: string,
    contractsDir: string,
): Promise<void> {
    // resolveWalletPassword already refuses silent "devnet" for preserved keystores.
    const password = await resolveWalletPassword();
    const decodeScript = `
const { Wallet } = require("ethers");
const fs = require("fs");
(async () => {
  const json = fs.readFileSync(process.argv[1], "utf8");
  const password = (process.env.WALLET_PASSWORD || "").trim();
  if (!password) {
    throw new Error("WALLET_PASSWORD is required to decrypt bridge-relayer keystore");
  }
  await Wallet.fromEncryptedJson(json, password);
  process.stdout.write("ok");
})().catch((err) => {
  console.error(err && err.message ? err.message : err);
  process.exit(1);
});
`.trim();
    const proc = Bun.spawnSync(["node", "-e", decodeScript, keystorePath], {
        cwd: contractsDir,
        env: {
            ...process.env,
            WALLET_PASSWORD: password,
        },
        stdout: "pipe",
        stderr: "pipe",
    });
    if ((proc.exitCode ?? 1) === 0) return;
    const stdout = proc.stdout ? new TextDecoder().decode(proc.stdout) : "";
    const stderr = proc.stderr ? new TextDecoder().decode(proc.stderr) : "";
    throw new Error(formatBridgeRelayerKeystoreDecryptError({
        keystorePath,
        detail: stderr || stdout,
    }));
}

async function autoGenerateBridgeRelayerKeystore(keystorePath: string, contractsDir: string): Promise<void> {
    console.log("[AutoSetup] Auto-generating bridge-relayer keystore...");
    const devPrivateKey = `0x${LOCAL_DEVNET_RELAYER_ZK_PRIVATE_KEY}`;
    const devPassword = process.env.WALLET_PASSWORD || "devnet";
    const script = `
const { Wallet } = require("ethers");
(async () => {
  const wallet = new Wallet("${devPrivateKey}");
  const json = await wallet.encrypt("${devPassword}");
  require("fs").writeFileSync(process.argv[1], json);
})().catch(e => { console.error(e); process.exit(1); });
    `.trim();
    // Run from psy-contracts dir where ethers is installed as a dependency
    const result = await runAndCapture(["node", "-e", script, keystorePath], contractsDir);
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to generate keystore: ${result.stderr || result.stdout}`);
    }
    console.log(`[AutoSetup] bridge-relayer keystore generated at ${keystorePath}`);
}

type KeystoreManifestFile = { sha256: string; size: number };
type KeystoreManifest = { version: number; files: Record<string, KeystoreManifestFile> };
type KeystoreGroup = { type: "zst" | "tar"; key: string; entries: string[]; chunked: boolean };

export const trustSetupGroups: readonly KeystoreGroup[] = [
    { type: "zst", key: "circuit_groth16.bin.zst", entries: ["circuit_groth16.bin"], chunked: false },
    { type: "zst", key: "pk_groth16.bin.zst", entries: ["pk_groth16.bin"], chunked: true },
    { type: "zst", key: "vk_groth16.bin.zst", entries: ["vk_groth16.bin"], chunked: false },
    {
        type: "tar",
        key: "deposit_append.tar.zst",
        entries: [
            "deposit_append/circuit_groth16.bin",
            "deposit_append/pk_groth16.bin",
            "deposit_append/vk_groth16.bin",
        ],
        chunked: true,
    },
    {
        type: "tar",
        key: "withdrawal_claim.tar.zst",
        entries: [
            "withdrawal_claim/circuit_groth16.bin",
            "withdrawal_claim/pk_groth16.bin",
            "withdrawal_claim/vk_groth16.bin",
        ],
        chunked: true,
    },
    {
        type: "tar",
        key: "reward_claim.tar.zst",
        entries: [
            "reward_claim/circuit_groth16.bin",
            "reward_claim/pk_groth16.bin",
            "reward_claim/vk_groth16.bin",
        ],
        chunked: true,
    },
];

export async function fetchKeystoreManifest(manifestPath: string): Promise<KeystoreManifest> {
    await downloadKeystoreObject("sha256sums.json", manifestPath);
    try {
        const parsed = JSON.parse(await fs.promises.readFile(manifestPath, "utf8"));
        if (parsed?.version !== 1 || !parsed.files || typeof parsed.files !== "object" || Array.isArray(parsed.files)) {
            throw new Error("invalid manifest");
        }
        for (const dir of ["", "deposit_append/", "withdrawal_claim/", "reward_claim/"]) {
            for (const name of ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"]) {
                const entry = parsed.files[dir + name];
                if (!entry || typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(entry.sha256)
                    || !Number.isSafeInteger(entry.size) || entry.size <= 0) {
                    throw new Error("invalid manifest entry");
                }
            }
        }
        return parsed;
    } catch {
        throw new Error("[AutoSetup] Invalid sha256sums.json: require version 1 and size/sha256 entries for all twelve trust-setup files");
    }
}

async function digestFile(filePath: string): Promise<{ sha256: string; size: number }> {
    const handle = await fs.promises.open(filePath, "r");
    try {
        const { size } = await handle.stat();
        const hash = createHash("sha256");
        const chunk = Buffer.alloc(256 * 1024);
        let position = 0;
        while (position < size) {
            const { bytesRead } = await handle.read(chunk, 0, chunk.length, position);
            if (bytesRead <= 0) break;
            hash.update(chunk.subarray(0, bytesRead));
            position += bytesRead;
        }
        return { sha256: hash.digest("hex"), size };
    } finally {
        await handle.close();
    }
}

async function sha256File(filePath: string): Promise<string> {
    return (await digestFile(filePath)).sha256;
}

// Returns true iff the local file at keystoreDir/relPath exists and its
// size + sha256 match the manifest entry. Streaming hash keeps memory flat
// even for the ~770MB pk files.
async function verifyKeystoreEntry(
    manifest: KeystoreManifest,
    keystoreDir: string,
    relPath: string,
): Promise<boolean> {
    const expected = manifest.files[relPath];
    if (!expected) throw new Error(`[AutoSetup] sha256sums.json has no entry for ${relPath}`);
    const filePath = path.join(keystoreDir, relPath);
    try {
        const stat = await fs.promises.stat(filePath);
        if (stat.size !== expected.size) return false;
        return (await sha256File(filePath)) === expected.sha256;
    } catch {
        return false;
    }
}
export async function groupVerifies(manifest: KeystoreManifest, keystoreDir: string, entries: readonly string[]): Promise<boolean> {
    for (const entry of entries) {
        if (!(await verifyKeystoreEntry(manifest, keystoreDir, entry))) return false;
    }
    return true;
}

async function missingOrEmptyKeystoreEntries(
    keystoreDir: string,
    entries: readonly string[],
): Promise<string[]> {
    const invalid: string[] = [];
    for (const entry of entries) {
        try {
            const stat = await fs.promises.stat(path.join(keystoreDir, entry));
            if (!stat.isFile() || stat.size === 0) invalid.push(entry);
        } catch {
            invalid.push(entry);
        }
    }
    return invalid;
}

async function ensureKeystoreFiles(contractsDir: string): Promise<{ generated: boolean }> {
    const homeDir = process.env.HOME;
    if (!homeDir) throw new Error("[AutoSetup] HOME is not set");
    const keystoreDir = path.join(homeDir, ".psy", "keystore");
    await mkdir(keystoreDir, { recursive: true });
    const setAlias = setBridgeRelayerKeystoreAlias();
    const bridgeRelayerPath = resolveBridgeRelayerKeystorePath();
    if (setAlias && !(await exists(setAlias.path))) {
        throw new Error(
            `[AutoSetup] ${setAlias.name} is set to ${setAlias.path} but that file does not exist`,
        );
    }
    await mkdir(path.dirname(bridgeRelayerPath), { recursive: true });
    let generated = false;

    // Local mode is the default. Exact PSY_SKIP_KEYSTORE=0 selects remote refresh.
    // A remote failure never selects local mode; this predicate is the only selector.
    if (shouldSkipBranchSync(process.env.PSY_SKIP_KEYSTORE)) {
        console.warn("[AutoSetup] keystore refresh skipped unless PSY_SKIP_KEYSTORE=0 -- keeping local ~/.psy/keystore as-is");
        const requiredTrustSetupEntries = [
            "circuit_groth16.bin",
            "pk_groth16.bin",
            "vk_groth16.bin",
            "deposit_append/circuit_groth16.bin",
            "deposit_append/pk_groth16.bin",
            "deposit_append/vk_groth16.bin",
            "withdrawal_claim/circuit_groth16.bin",
            "withdrawal_claim/pk_groth16.bin",
            "withdrawal_claim/vk_groth16.bin",
            "reward_claim/circuit_groth16.bin",
            "reward_claim/pk_groth16.bin",
            "reward_claim/vk_groth16.bin",
        ];
        const invalidEntries = await missingOrEmptyKeystoreEntries(
            keystoreDir,
            requiredTrustSetupEntries,
        );
        if (invalidEntries.length > 0) {
            throw new Error(
                `[AutoSetup] Skipping keystore refresh requires a complete local trust setup. ` +
                `Missing or empty files under ${keystoreDir}: ${invalidEntries.join(", ")}. ` +
                `Generate them first or set PSY_SKIP_KEYSTORE=0 to download the published setup.`,
            );
        }
        // PSY_BRIDGE_RELAYER_KEYSTORE_PATH / BRIDGE_RELAYER_KEYSTORE_PATH / KEYSTORE_PATH override the encrypted UTC JSON used by L1 [finalize] and [[chains]]; trust setup remains under ~/.psy/keystore.
        if (!(await exists(bridgeRelayerPath))) {
            await ensurePsyContractsDependencies(contractsDir);
            await autoGenerateBridgeRelayerKeystore(bridgeRelayerPath, contractsDir);
            generated = true;
            bridgeRelayerKeystoreGeneratedThisRun = true;
        } else {
            console.log("[AutoSetup] bridge-relayer keystore present, keeping");
            await assertExistingBridgeRelayerKeystorePassword(bridgeRelayerPath, contractsDir);
        }
        return { generated };
    }

    // 1. bridge-relayer keystore: auto-generate only when missing.
    //    It is a dev key and never needs refreshing on its own; no interactive prompt.
    // PSY_BRIDGE_RELAYER_KEYSTORE_PATH / BRIDGE_RELAYER_KEYSTORE_PATH / KEYSTORE_PATH override the encrypted UTC JSON used by L1 [finalize] and [[chains]]; trust setup remains under ~/.psy/keystore.
    if (!(await exists(bridgeRelayerPath))) {
        await ensurePsyContractsDependencies(contractsDir);
        await rm(bridgeRelayerPath).catch(() => undefined);
        await autoGenerateBridgeRelayerKeystore(bridgeRelayerPath, contractsDir);
        generated = true;
        bridgeRelayerKeystoreGeneratedThisRun = true;
    } else {
        console.log("[AutoSetup] bridge-relayer keystore present, keeping");
        await assertExistingBridgeRelayerKeystorePassword(bridgeRelayerPath, contractsDir);
    }

    // 2. Remote mode requires a valid manifest, even for a complete local setup.
    const manifestPath = path.join(keystoreDir, "sha256sums.json");
    const manifest = await fetchKeystoreManifest(manifestPath);

    // 3. Trust-setup groups. Each group is fetched from one public R2 object;
    //    every member file is hash-verified against the manifest before and after.
    const groups = trustSetupGroups;

    for (const group of groups) {
        if (await groupVerifies(manifest, keystoreDir, group.entries)) {
            console.log(`[AutoSetup] ${group.key}: up to date, skipping`);
            continue;
        }
        console.log(`[AutoSetup] ${group.key}: downloading (missing or hash mismatch)...`);
        if (group.type === "zst") {
            const destPath = path.join(keystoreDir, group.entries[0]);
            const tmpPath = path.join(keystoreDir, group.key + ".downloading");
            await rm(destPath).catch(() => undefined);
            await downloadTrustSetupObject(group, tmpPath, manifest);
            console.log(`[AutoSetup] Decompressing ${group.key}...`);
            const decompressedTmp = destPath + ".decompressing";
            const result = await runAndCapture(["zstd", "-d", tmpPath, "-o", decompressedTmp, "--force"]);
            if (result.code !== 0) {
                await rm(decompressedTmp).catch(() => undefined);
                throw new Error(`[AutoSetup] Failed to decompress ${group.key}: ${result.stderr}`);
            }
            await rm(tmpPath).catch(() => undefined);
            fs.renameSync(decompressedTmp, destPath);
        } else {
            // Extract the whole tar into keystoreDir; the archive carries the top-level dir.

            const dirPath = path.join(keystoreDir, path.dirname(group.entries[0]));
            await rm(dirPath, { recursive: true }).catch(() => undefined);
            await downloadAndExtractTar(group, keystoreDir, manifest);
        }

        if (!(await groupVerifies(manifest, keystoreDir, group.entries))) {
            throw new Error(
                `[AutoSetup] ${group.key}: post-download verification failed ` +
                `(size/sha256 mismatch vs sha256sums.json).`,
            );
        }
        console.log(`[AutoSetup] ${group.key}: verified OK`);
    }

    return { generated };
}
const GENESIS_BLOCK_TIME_SECONDS = 1_764_248_609;
const GENESIS_INSPECT_SUFFIX_BYTES = 64 * 1024;

export async function isUsableGenesisData(filePath: string): Promise<boolean> {
    try {
        const { size } = await fs.promises.stat(filePath);
        const len = Math.min(size, GENESIS_INSPECT_SUFFIX_BYTES);
        if (len <= 0) return false;
        const buf = Buffer.alloc(len);
        const handle = await fs.promises.open(filePath, "r");
        try {
            const { bytesRead } = await handle.read(buf, 0, len, size - len);
            const suffix = buf.subarray(0, bytesRead).toString("utf8");
            const statsIdx = suffix.indexOf("\"checkpoint_stats\"");
            if (statsIdx < 0) return false;
            const keyIdx = suffix.indexOf("\"block_time\"", statsIdx);
            if (keyIdx < 0) return false;
            const after = suffix.slice(keyIdx + "\"block_time\"".length);
            const match = after.match(/^\s*:\s*(\d+)/);
            if (!match) return false;
            const value = Number(match[1]);
            return Number.isSafeInteger(value) && value === GENESIS_BLOCK_TIME_SECONDS;
        } finally {
            await handle.close();
        }
    } catch {
        return false;
    }
}

async function isUsableGenesisContracts(filePath: string): Promise<boolean> {
    try {
        const handle = await fs.promises.open(filePath, "r");
        try {
            const magic = Buffer.alloc(4);
            await handle.read(magic, 0, magic.length, 0);
            return hasZstdMagic(magic);
        } finally {
            await handle.close();
        }
    } catch {
        return false;
    }
}

const GOLDILOCKS_MODULUS = 0xffffffff00000001n;
const GUARDIAN_MEMBER_FIELD = "guardian_initial_member_hashes";

/** QHashOut JSON is up to 64 hex digits, big-endian, reversed into four little-endian Goldilocks limbs. */
function guardianMemberLimbs(hash: unknown): bigint[] | null {
    if (typeof hash !== "string" || !/^(?:[0-9a-fA-F]{2}){0,32}$/.test(hash)) return null;
    const padded = hash.padStart(64, "0");
    return [3, 2, 1, 0].map((limb) => BigInt(`0x${padded.slice(limb * 16, limb * 16 + 16)}`) % GOLDILOCKS_MODULUS);
}



/**
 * Read-only membership preflight. The selected network already carries three member
 * hashes; genesis consumes them and never writes config.
 */
export async function planGenesisGeneration(cwd: string, env: NodeJS.ProcessEnv): Promise<{ args: string[]; env: NodeJS.ProcessEnv }> {
    const networkKey = env.PSY_NETWORK?.trim();
    const memberField = `networks.${networkKey || "CURRENT_NETWORK"}.${GUARDIAN_MEMBER_FIELD}`;
    try {
        if (!networkKey) throw new Error("missing selected network");
        const configPath = path.resolve(cwd, "psy-genesis/config.json");
        const stat = await fs.promises.lstat(configPath);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024 * 1024) throw new Error("invalid canonical config");
        const config = JSON.parse(await fs.promises.readFile(configPath, "utf8"));
        const network = config?.networks?.[networkKey];
        const hashes = network?.[GUARDIAN_MEMBER_FIELD];
        if (!Array.isArray(hashes) || hashes.length !== 3) throw new Error("expected three member hashes");
        const members = new Set<string>();
        for (const hash of hashes) {
            const limbs = guardianMemberLimbs(hash);
            if (!limbs || limbs.every((limb) => limb === 0n)) throw new Error("invalid member hash");
            const member = limbs.join(",");
            if (members.has(member)) throw new Error("duplicate member");
            members.add(member);
        }
    } catch {
        throw new Error(`psy-genesis/config.json ${memberField} must contain three distinct nonzero public member hashes`);
    }
    const childEnv: NodeJS.ProcessEnv = { ...env, PWD: cwd };
    for (const key of ["PRIVATE_KEY", "BRIDGE_RELAYER_L2_PRIVATE_KEY", "KEYSTORE_PATH", "PSY_BRIDGE_RELAYER_KEYSTORE_PATH", "BRIDGE_RELAYER_KEYSTORE_PATH", "WALLET_PASSWORD"]) delete childEnv[key];
    return { args: [path.resolve(cwd, "target", "release", "psy_dev_cli"), "generate-genesis-data", "--repo-root", path.resolve(cwd)], env: childEnv };
}

export async function ensureGenesisFiles(cwd: string, env: NodeJS.ProcessEnv = process.env, preflight = false): Promise<void> {
    const genesisPath = path.join(cwd, "genesis.json");
    const genesisContractsPath = path.join(cwd, "psy-genesis", "genesis_contracts.json");
    const genesisContractsStampPath = path.join(cwd, "psy-genesis", ".genesis_contracts.compiler-artifact.json");
    const tokenArtifactPath = path.join(cwd, "psy-genesis", "token.json");
    const tokenUpdateArtifactPath = path.join(cwd, "psy-genesis", "token.update.json");

    // The canonical zstd-compressed genesis contracts artifact is owned by
    // the psy-genesis submodule. Plain JSON and Git LFS pointers are invalid.
    if (!(await isUsableGenesisContracts(genesisContractsPath))) {
        throw new Error(
            "[AutoSetup] psy-genesis/genesis_contracts.json is missing or invalid. " +
            "Initialize the psy-genesis submodule before starting the devnet.",
        );
    }

    // The psy-genesis submodule commit remains the packaging authority. When a
    // compiler provenance sidecar is present beside the payload, additionally
    // verify that it certifies these exact bytes and, when available, the
    // checked-out standalone compiler identity. Never synthesize a stamp for a
    // committed payload that was not generated in this setup run.
    if (await exists(genesisContractsStampPath)) {
        const stamp = await readGenesisContractsArtifactStamp(genesisContractsStampPath);
        if (!stamp) {
            throw new Error("[AutoSetup] psy-genesis compiler artifact stamp is malformed or legacy");
        }
        const artifactDigest = await digestFile(genesisContractsPath);
        const tokenDigest = await digestFile(tokenArtifactPath);
        const tokenUpdateDigest = await digestFile(tokenUpdateArtifactPath);
        let expected: GenesisContractsArtifactFingerprint = {
            compilerRevision: stamp.compilerRevision,
            compilerSourcesHash: stamp.compilerSourcesHash,
            artifactSha256: artifactDigest.sha256,
            artifactByteSize: artifactDigest.size,
            tokenArtifactSha256: tokenDigest.sha256,
            tokenArtifactByteSize: tokenDigest.size,
            tokenUpdateArtifactSha256: tokenUpdateDigest.sha256,
            tokenUpdateArtifactByteSize: tokenUpdateDigest.size,
        };
        const compilerPath = path.resolve(resolveProjectsDir(), "psy-compiler");
        if (await exists(path.join(compilerPath, "Makefile"))) {
            expected = {
                ...(await resolveCompilerArtifactFingerprint(compilerPath)),
                artifactSha256: artifactDigest.sha256,
                artifactByteSize: artifactDigest.size,
                tokenArtifactSha256: tokenDigest.sha256,
                tokenArtifactByteSize: tokenDigest.size,
                tokenUpdateArtifactSha256: tokenUpdateDigest.sha256,
                tokenUpdateArtifactByteSize: tokenUpdateDigest.size,
            };
        }
        if (evaluateCompilerArtifactStamp(stamp, expected) !== "match") {
            throw new Error(
                "[AutoSetup] psy-genesis compiler artifact stamp does not match the compiler identity or genesis_contracts.json bytes",
            );
        }
    }
    if (preflight) {
        await fs.promises.access(path.join(cwd, "target/release/psy_dev_cli"), fs.constants.X_OK);
        await planGenesisGeneration(cwd, env);
        return;
    }

    if (await exists(genesisPath)) {
        if (await isUsableGenesisData(genesisPath)) {
            console.log("[AutoSetup] genesis artifacts already exist");
            return;
        }
        throw new Error("[AutoSetup] Existing genesis.json is invalid; explicit authorized regeneration is required");
    }

    const cli = path.join(cwd, "target", "release", "psy_dev_cli");
    if (!(await exists(cli))) {
        throw new Error(
            `[AutoSetup] ${cli} is missing; build it with cargo build --release --bin psy_dev_cli ` +
            `or set PSY_SKIP_BUILD=0.`,
        );
    }
    const generation = await planGenesisGeneration(cwd, env);
    console.log("[AutoSetup] Generating genesis.json via psy_dev_cli generate-genesis-data...");
    const result = await runAndCapture(generation.args, cwd, generation.env);
    if (result.code !== 0 || !(await isUsableGenesisData(genesisPath))) {
        throw new Error(`[AutoSetup] Failed to generate genesis.json (exit ${result.code})`);
    }
    console.log("[AutoSetup] genesis.json generated");
}

/** Component selection contract: core-only launchers have no SDK sidecar consumer. */
export function selectedUiDependencies(startAll: boolean, options: { psyPrivacyBridge?: boolean; ide?: boolean; explorer?: boolean; modeAWebWalletBridge?: boolean }): boolean {
    return startAll || !!options.psyPrivacyBridge || !!options.ide || !!options.explorer || !!options.modeAWebWalletBridge;
}

async function ensureDevEnvironment(
    cwd: string,
    opts?: {
        requireDocker?: boolean;
        requireAnvil?: boolean;
        requireBun?: boolean;
        selectedUi?: boolean;
        env?: NodeJS.ProcessEnv;
    },
): Promise<void> {
    if (opts?.env?.PSY_FROZEN_DEPS !== undefined) process.env.PSY_FROZEN_DEPS = opts.env.PSY_FROZEN_DEPS;
    console.log("[AutoSetup] Checking dev environment...");
    // Preflight: check required tools with actionable install hints
    await checkToolAvailable("git", "https://git-scm.com/");
    await checkToolAvailable("cargo", "https://rustup.rs/");
    await checkToolAvailable("curl", "usually pre-installed");
    await checkToolAvailable("zstd", "brew install zstd (macOS) or apt install zstd (Linux)");
    await checkToolAvailable("node", "https://nodejs.org/ or use fnm/nvm");
    await checkToolAvailable("npm", "https://nodejs.org/ or use fnm/nvm");
    await checkToolAvailable("pnpm", "npm i -g pnpm");
    await checkToolAvailable("make", "brew install make (macOS) or build-essential (Linux)");
    await checkToolAvailable("bash", "usually pre-installed");
    if (opts?.requireBun) {
        await checkToolAvailable("bun", "curl -fsSL https://bun.sh/install | bash");
    }
    if (opts?.requireDocker) {
        await checkToolAvailable("docker", "https://docs.docker.com/engine/install/");
        await checkDockerComposeAvailable();
    }
    if (opts?.requireAnvil) {
        await checkToolAvailable("anvil", "foundryup");
    }

    await ensureRequiredSubmodules(cwd);
    if (opts?.selectedUi && !(await exists(path.join(cwd, "psy-dapp", "apps", "account", "package.json")))) {
        throw new Error("[DevNet] Mode A web wallet bridge package is missing at psy-dapp/apps/account/package.json");
    }
    // psy-dapp ships nested psy-genesis/psy-contracts gitlinks that the UI
    // apps alias into (config.json, protocol-config, deployments); initialize
    // them before any UI dependency install or dev-server startup.
    if (opts?.selectedUi) await ensurePsyDappNestedSubmodules(path.join(cwd, "psy-dapp"));
    // Proven order from parth-generic-v1: clone/find siblings (and init
    // psy-sdk's psy-genesis) before ensurePsySdkArtifacts reads config.json.
    await ensureAllReposCloned();
    const contractsDir = path.join(cwd, "psy-contracts");
    if (opts?.selectedUi) {
        const sdk = await ensurePsySdkArtifacts(cwd);
        await ensureAllUiDeps(cwd, { force: sdk.rebuilt });
    }
    const { generated } = await ensureKeystoreFiles(contractsDir);
    // Only set default WALLET_PASSWORD when we generated the L1 keystore this run.
    if (generated && !process.env.WALLET_PASSWORD) {
        process.env.WALLET_PASSWORD = "devnet";
        bridgeRelayerKeystoreGeneratedThisRun = true;
        console.warn("[AutoSetup] WALLET_PASSWORD not set, using default 'devnet' for auto-generated keystore.");
    }
    await ensureAllBinariesBuilt(cwd);
    console.log("[AutoSetup] Dev environment ready.");
}

async function buildProject(cwd?: string) {
    console.log("Building project...");
    const root = cwd || ".";
    const stage = resolveStage();
    const env = {
        ...process.env,
        PSY_CONFIG_PATH: path.join(root, "psy-genesis", "config.json"),
        PSY_NETWORK: stage,
    };
    const proc = Bun.spawn([
        "cargo",
        "build",
        "--release",
        "--locked",
        "--bin",
        "psy_node_cli",
        "--bin",
        "psy_worker_cli",
        "--bin",
        "psy_relayer_cli",
    ], {
        cwd,
        stdout: "inherit",
        stderr: "inherit",
        env,
    });
    if (await proc.exited !== 0) throw new Error(`Build failed`);
}

async function ensureUiDependencies(uiDir: string) {
    if (frozenDepsEnabled()) {
        const workspaceDir = path.resolve(uiDir, "..", "..");
        if (!(await exists(path.join(uiDir, "node_modules"))) && !(await exists(path.join(workspaceDir, "node_modules")))) {
            throw new Error("[DevNet] PSY_FROZEN_DEPS requires preinstalled UI dependencies");
        }
        return;
    }
    // Some apps ship their own pnpm-workspace.yaml (e.g. apps/account)
    // even though they live under a parent workspace. Install them in-place so
    // pnpm can resolve their `link:` deps correctly.
    if (await exists(path.join(uiDir, "pnpm-workspace.yaml"))) {
        console.log(`[DevNet] Installing UI deps in standalone pnpm workspace ${uiDir}...`);
        await ensurePnpmBuildScriptsApproved(uiDir, ["esbuild"]);
        const result = await runAndCapture(["pnpm", "install"], uiDir);
        if (result.code !== 0) {
            throw new Error(`pnpm install failed in ${uiDir}: ${result.stderr || result.stdout}`);
        }
        console.log(`[DevNet] UI deps installed in ${uiDir}`);
        return;
    }

    const workspaceDir = path.resolve(uiDir, "..", "..");
    if (await exists(path.join(workspaceDir, "pnpm-workspace.yaml"))) {
        await ensureNpmDeps(workspaceDir, "psy-dapp");
        return;
    }

    console.log(`[DevNet] Installing UI deps in ${uiDir}...`);
    const pnpmLock = path.join(uiDir, "pnpm-lock.yaml");
    const bunLock = path.join(uiDir, "bun.lock");
    const hasPnpmLock = await exists(pnpmLock);
    const useFrozenPnpmLock = hasPnpmLock && await shouldUseFrozenPnpmLock(uiDir);
    if (hasPnpmLock) {
        await ensurePnpmBuildScriptsApproved(uiDir, ["esbuild"]);
    }
    const installCmd =
        hasPnpmLock ? ["pnpm", "install", useFrozenPnpmLock ? "--frozen-lockfile" : "--no-frozen-lockfile"] :
        (await exists(bunLock)) ? ["bun", "install", "--frozen-lockfile"] :
        ["bun", "install"];
    if (hasPnpmLock) {
        await pnpmInstallWithAutoApprove(uiDir, [useFrozenPnpmLock ? "--frozen-lockfile" : "--no-frozen-lockfile"]);
    } else {
        const proc = Bun.spawn(installCmd, {
            cwd: uiDir,
            stdout: "inherit",
            stderr: "inherit",
            env: {
                ...process.env,
                // Avoid failing on husky prepare hooks in non-standard/devnet worktrees.
                HUSKY: "0",
            },
        });
        const code = await proc.exited;
        if (code !== 0) {
            throw new Error(`${installCmd.join(" ")} failed in ${uiDir} (exit=${code})`);
        }
    }
}

async function ensurePnpmBuildScriptsApproved(cwd: string, deps: string[] = ["esbuild"]): Promise<void> {
    if (deps.length === 0) return;
    const cmd = ["pnpm", "approve-builds", ...deps];
    const result = await runAndCapture(cmd, cwd);
    if (result.code !== 0) {
        const output = `${result.stderr}\n${result.stdout}`;
        // pnpm returns a non-zero code when package scripts are already approved.
        if (output.includes("ERR_PNPM_APPROVE_BUILDS_UNKNOWN_PACKAGES")
            || output.includes("not awaiting approval")) {
            return;
        }
        throw new Error(`[DevNet] ${cmd.join(" ")} failed in ${cwd}: ${result.stderr || result.stdout}`);
    }
}

async function pnpmInstallWithAutoApprove(cwd: string, extraArgs: string[] = []): Promise<void> {
    const installCmd = ["pnpm", "install", "--registry=https://registry.npmjs.org", ...extraArgs];
    for (let i = 0; i < 3; i++) {
        const install = await runAndCapture(installCmd, cwd);
        if (install.code === 0) {
            return;
        }
        const output = `${install.stderr}\n${install.stdout}`;
        if (!output.includes("ERR_PNPM_IGNORED_BUILDS")) {
            throw new Error(`${installCmd.join(" ")} failed in ${cwd}: ${install.stderr || install.stdout}`);
        }
        const approveAll = await runAndCapture(["pnpm", "approve-builds", "--all"], cwd);
        if (approveAll.code !== 0) {
            throw new Error(`[DevNet] pnpm approve-builds --all failed in ${cwd}: ${approveAll.stderr || approveAll.stdout}`);
        }
    }
    throw new Error(`${installCmd.join(" ")} failed in ${cwd}: exceeded auto-approve retries`);
}

export async function ensurePsyContractsDependencies(contractsDir: string) {
    if (frozenDepsEnabled() && !(await exists(path.join(contractsDir, "node_modules/.bin/hardhat")))) {
        throw new Error("[DevNet] PSY_FROZEN_DEPS requires preinstalled psy-contracts dependencies; refusing install");
    }
    const hardhatBin = path.join(contractsDir, "node_modules/.bin/hardhat");
    if (await exists(hardhatBin)) return;

    console.log(`[DevNet] Installing psy-contracts deps in ${contractsDir}...`);

    const lockfile = path.join(contractsDir, "package-lock.json");
    const installCmd = (await exists(lockfile)) ? ["npm", "ci"] : ["npm", "install"];
    const proc = Bun.spawn(installCmd, {
        cwd: contractsDir,
        stdout: "inherit",
        stderr: "inherit",
    });
    const code = await proc.exited;
    if (code !== 0) {
        throw new Error(`${installCmd.join(" ")} failed in ${contractsDir} (exit=${code})`);
    }
}

export const ANVIL_STATE_PATH = path.join("db", "anvil", "state.json");
export function localAnvilStatePath(repoCwd: string, network: L1DeploymentNetwork = "localhost"): string {
    return path.join(repoCwd, network === "localhost" ? ANVIL_STATE_PATH : path.join("db", "anvil", network, "state.json"));
}


export interface PreservedAnvilGenesis {
    timestamp: string;
    header: Record<string, string>;
    block1ParentHash?: string;
}

export interface LocalAnvilStatePlan {
    statePath: string;
    hasState: false;
    shouldResetEnvio: true;
}

function canonicalAnvilHeader(block: unknown, source: string): Record<string, string> {
    if (typeof block !== "object" || block === null || !("header" in block)) {
        throw new Error(`[DevNet] Anvil state ${source} has a block without a header object`);
    }
    const raw = block.header;
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
        throw new Error(`[DevNet] Anvil state ${source} block header is not an object`);
    }
    const header: Record<string, string> = {};
    for (const [key, value] of Object.entries(raw)) {
        if (typeof value !== "string") {
            throw new Error(`[DevNet] Anvil state ${source} header.${key} is not a string. Refusing a partial genesis identity.`);
        }
        header[key] = value;
    }
    if (header.number === undefined || header.timestamp === undefined) {
        throw new Error(`[DevNet] Anvil state ${source} header is missing number or timestamp`);
    }
    return header;
}

function requireBlockHash(value: unknown, source: string): string {
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
        throw new Error(`[DevNet] ${source} is ${JSON.stringify(value)}; expected a 32-byte hash`);
    }
    return value.toLowerCase();
}

/** Anvil mints a fresh genesis before loading --state, then the last serialized block 0 replaces it. */
export function preservedAnvilGenesis(state: unknown, source: string): PreservedAnvilGenesis {
    const blocks = typeof state === "object" && state !== null && "blocks" in state ? state.blocks : undefined;
    if (!Array.isArray(blocks)) {
        throw new Error(`[DevNet] Anvil state ${source} has no blocks array. Refusing to start a preserved chain without a genesis header to pin.`);
    }
    const genesisHeaders: Record<string, string>[] = [];
    const block1Parents: string[] = [];
    for (const block of blocks) {
        const header = canonicalAnvilHeader(block, source);
        const number = hexQuantityToBigInt(header.number, `Anvil state ${source} block number`);
        if (number === 0n) genesisHeaders.push(header);
        else if (number === 1n) block1Parents.push(requireBlockHash(header.parentHash, `Anvil state ${source} block 1 parentHash`));
    }
    if (genesisHeaders.length !== 1) {
        const stamps = genesisHeaders.map((header) => header.timestamp).join(", ");
        throw new Error(
            `[DevNet] Anvil state ${source} has ${genesisHeaders.length} block 0 headers` +
            `${stamps ? ` (timestamps ${stamps})` : ""}. Anvil keeps the last block 0 and that changes the genesis hash. ` +
            "Refusing to select or drop one. Match block 1 parentHash to a trusted RPC block hash before replacing this snapshot.",
        );
    }
    const header = genesisHeaders[0];
    const timestamp = hexQuantityToBigInt(header.timestamp, `Anvil state ${source} genesis timestamp`);
    if (timestamp > (1n << 64n) - 1n) {
        throw new Error(`[DevNet] Anvil state ${source} genesis timestamp does not fit Anvil --timestamp`);
    }
    const parents = [...new Set(block1Parents)];
    if (parents.length > 1) {
        throw new Error(`[DevNet] Anvil state ${source} has conflicting block 1 parentHash values. Refusing to bind genesis.`);
    }
    return {
        timestamp: timestamp.toString(),
        header,
        ...(parents.length === 1 ? { block1ParentHash: parents[0] } : {}),
    };
}

export function localAnvilLaunchArgs(
    port: number,
    chainId: string,
    statePath: string,
    genesis?: PreservedAnvilGenesis,
): string[] {
    const intervalEnv = process.env.ANVIL_STATE_INTERVAL;
    const interval = intervalEnv === undefined || intervalEnv.length === 0
        ? 900
        : resolvePositiveIntegerSetting(/^\d+$/.test(intervalEnv) ? intervalEnv : "0", 900, "ANVIL_STATE_INTERVAL");
    const args = [
        "anvil", "--host", "0.0.0.0", "--port", String(port),
        "--chain-id", chainId,
        "--state", statePath, "--state-interval", String(interval), "-vvvv",
    ];
    if (genesis) args.push("--timestamp", genesis.timestamp);
    return args;
}

function assertSavedGenesisFields(
    actual: Record<string, unknown>,
    expected: Record<string, string>,
    source: string,
): void {
    const mismatches = Object.entries(expected).filter(([key, value]) => {
        const got = actual[key];
        return typeof got !== "string" || got.toLowerCase() !== value.toLowerCase();
    }).map(([key]) => key);
    if (mismatches.length > 0) {
        throw new Error(`[DevNet] ${source} does not match the saved genesis header fields: ${mismatches.join(", ")}`);
    }
}

async function anvilRpcHeader(
    rpc: (rpcUrl: string, method: string, params: unknown[]) => Promise<unknown>,
    rpcUrl: string,
    tag: string,
    source: string,
): Promise<{ hash: string; parentHash: string; fields: Record<string, unknown> }> {
    const block = await rpc(rpcUrl, "eth_getBlockByNumber", [tag, false]);
    if (typeof block !== "object" || block === null) {
        throw new Error(`[DevNet] ${source} returned ${JSON.stringify(block)}; expected a block header`);
    }
    const fields = block as Record<string, unknown>;
    return {
        hash: requireBlockHash(fields.hash, `${source} hash`),
        parentHash: requireBlockHash(fields.parentHash, `${source} parentHash`),
        fields,
    };
}

/** Fail closed before deployment reuse. The hash is the RPC value, not a locally computed header hash. */
export async function assertPreservedAnvilGenesis(
    rpcUrl: string,
    genesis: PreservedAnvilGenesis,
    source: string,
    rpc: (rpcUrl: string, method: string, params: unknown[]) => Promise<unknown> = anvilRpc,
): Promise<void> {
    const block0 = await anvilRpcHeader(rpc, rpcUrl, "0x0", `${source} block 0`);
    const earliest = await anvilRpcHeader(rpc, rpcUrl, "earliest", `${source} earliest`);
    if (block0.hash !== earliest.hash) {
        throw new Error(`[DevNet] ${source} earliest hash ${earliest.hash} does not match block 0 hash ${block0.hash}`);
    }
    assertSavedGenesisFields(block0.fields, genesis.header, `${source} block 0`);
    assertSavedGenesisFields(earliest.fields, genesis.header, `${source} earliest`);
    if (genesis.block1ParentHash === undefined) return;
    const expected = requireBlockHash(genesis.block1ParentHash, `${source} saved block 1 parentHash`);
    if (block0.hash !== expected) {
        throw new Error(`[DevNet] ${source} block 0 hash ${block0.hash} does not match saved block 1 parentHash ${expected}. Refusing the drifted genesis.`);
    }
    const block1 = await anvilRpcHeader(rpc, rpcUrl, "0x1", `${source} block 1`);
    if (block1.parentHash !== expected) {
        throw new Error(`[DevNet] ${source} block 1 parentHash ${block1.parentHash} does not match saved block 1 parentHash ${expected}`);
    }
}

/** The release CLI streams the complete document; stdout contains only bounded header metadata. */
export async function inspectLocalAnvilState(statePath: string, fork: boolean): Promise<PreservedAnvilGenesis | undefined> {
    const cli = path.resolve(import.meta.dir, "../target/release/psy_dev_cli");
    const args = ["inspect-anvil-state", "--state", statePath, ...(fork ? ["--fork"] : [])];
    const stdout = await new Promise<string>((resolve, reject) => {
        execFile(cli, args, { encoding: "utf8", maxBuffer: 512 * 1024 }, (error, stdout, stderr) => {
            if (error) {
                reject(new Error(`[DevNet] Anvil state ${statePath} validation failed: ${stderr.trim() || error.message}. ` +
                    "If psy_dev_cli is missing or stale, rebuild with cargo build --release --bin psy_dev_cli."));
            } else resolve(stdout);
        });
    });
    const result = JSON.parse(stdout) as PreservedAnvilGenesis | null;
    if (fork ? result !== null : result === null || typeof result !== "object" || typeof result.timestamp !== "string" || typeof result.header !== "object" || result.header === null) {
        throw new Error(`[DevNet] Invalid inspect-anvil-state metadata for ${statePath}; rebuild psy_dev_cli`);
    }
    return result ?? undefined;
}

/** Local startup never loads a snapshot. The state path is where the new Anvil will write. */
export async function resolveLocalAnvilStatePlan(
    repoCwd: string, network: L1DeploymentNetwork = "localhost", _fork = false,
    control: Pick<GracefulStopControl, "listenerOwner"> & { rpcUrl?: string } = {},
): Promise<LocalAnvilStatePlan> {
    const statePath = localAnvilStatePath(repoCwd, network);
    const chain = LOCAL_ANVIL_RPCS.find((entry) => entry.network === network);
    if (chain) {
        const rpcUrl = control.rpcUrl ?? `http://127.0.0.1:${chain.port}`;
        const endpoint = new URL(rpcUrl);
        if (!["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname) || Number(endpoint.port) !== chain.port) {
            throw new Error(`[DevNet] ${network} RPC must use the configured local Anvil port ${chain.port}`);
        }
        const pid = await (control.listenerOwner ?? tcpListenerOwner)(chain.port);
        if (pid !== null) {
            throw new Error(`[DevNet] occupied ${network} listener is not available for a fresh Anvil; refusing to reuse or kill a foreign owner`);
        }
    }
    if (await exists(statePath)) {
        throw new Error(`[DevNet] fresh startup left ${statePath}; refusing to load an existing Anvil snapshot`);
    }
    return { statePath, hasState: false, shouldResetEnvio: true };
}

async function deployPsyContracts(
    repoCwd: string,
    l1RpcUrl: string,
    deploymentsNetwork: L1DeploymentNetwork,
    opts?: { fundDevAccounts?: boolean; localAnvilRpcUrl?: string },
) {
    const contractsDir = path.join(repoCwd, "psy-contracts");
    if (!(await exists(contractsDir))) {
        throw new Error(`psy-contracts directory not found: ${contractsDir}`);
    }
    const homeDir = process.env.HOME;
    if (!homeDir) {
        throw new Error("HOME is required to resolve Groth16 keystore paths");
    }
    const deploymentSummaryPath = path.join(
        repoCwd,
        "psy-contracts",
        "deployments",
        deploymentsNetwork,
        "deployed-contracts.json",
    );
    const forceRedeploy = shouldRedeployL1();
    const hasExistingDeployment = await exists(deploymentSummaryPath);
    if (deploymentsNetwork.startsWith("localhost")) {
        if (hasExistingDeployment) {
            throw new Error(`[DevNet] fresh startup left ${deploymentSummaryPath}; refusing to reuse a localhost deployment`);
        }
    } else if (!forceRedeploy) {
        if (!hasExistingDeployment) {
            throw new Error(
                `[DevNet] Missing ${deploymentsNetwork} deployment at ${deploymentSummaryPath}. ` +
                `Unset REDEPLOY_L1=false to deploy a fresh ${deploymentsNetwork} stack.`,
            );
        }
        const missingTokens = await readRequiredDeploymentTokenGaps(deploymentSummaryPath);
        if (missingTokens.length > 0) {
            throw new Error(
                `[DevNet] Existing ${deploymentsNetwork} deployment is incomplete: missing tokens ${missingTokens.join(", ")}. ` +
                `Unset REDEPLOY_L1=false to redeploy.`,
            );
        }
        console.log(`[DevNet] Reusing existing ${deploymentsNetwork} deployment at ${deploymentSummaryPath}`);
        return;
    }
    await ensurePsyContractsDependencies(contractsDir);
    const bridgeRelayerSigner = await loadBridgeRelayerSigner(repoCwd);
    if (deploymentsNetwork.startsWith("localhost")) {
        await setLocalAnvilBalance(l1RpcUrl, bridgeRelayerSigner.address);
        console.log(`[DevNet] funded bridge relayer deployer ${bridgeRelayerSigner.address} on local anvil`);
    }
    console.log(`[DevNet] Deploying psy-contracts to ${deploymentsNetwork}...`);
    // deploymentsNetwork is an L1 name (sepolia/bscTestnet/...), not a Psy
    // stage, so it cannot index the genesis config's networks block
    // directly. Only L1 names that are a stage's default L1 (see
    // STAGE_DEFAULT_L1) have a corresponding genesis block; reverse-map
    // through L1_TO_STAGE to find it. bscTestnet/baseSepolia/localhostBsc/
    // localhostBase have no genesis stage of their own, so deploymentCfg
    // stays undefined for them and the RPC env key falls through below.
    const deploymentStage = L1_TO_STAGE[deploymentsNetwork];
    const deploymentCfg = deploymentStage
        ? ((allConfig as any)?.networks?.[deploymentStage] as ConfigNetworkEntry | undefined)
        : undefined;
    const localRpcEnvKeys: Partial<Record<L1DeploymentNetwork, string>> = {
        localhost: "LOCALHOST_RPC_URL",
        localhostBsc: "LOCALHOST_BSC_RPC_URL",
        localhostBase: "LOCALHOST_BASE_RPC_URL",
    };
    const networkEnvKey = localRpcEnvKeys[deploymentsNetwork]
        ?? deploymentCfg?.anvilForkSourceUrlEnv
        ?? "LOCALHOST_RPC_URL";
    const walletPassword = await resolveWalletPassword();
    const deployArgs = ["node", "scripts/deploy-with-keystore.mjs", "deploy", "--network", deploymentsNetwork];
    if (deploymentsNetwork.startsWith("localhost") || forceRedeploy) {
        deployArgs.push("--reset");
    }
    const proc = Bun.spawn(deployArgs, {
        cwd: contractsDir,
        stdout: "inherit",
        stderr: "inherit",
        env: {
            ...process.env,
            [networkEnvKey]: l1RpcUrl,
            KEYSTORE_PATH: bridgeRelayerSigner.keystorePath,
            WALLET_PASSWORD: walletPassword,
        },
    });
    const code = await proc.exited;
    if (code !== 0) {
        throw new Error(`psy-contracts deploy failed (exit=${code})`);
    }
    if (opts?.fundDevAccounts && opts.localAnvilRpcUrl) {
        await fundDevTestAccounts(opts.localAnvilRpcUrl, bridgeRelayerSigner, deploymentSummaryPath);
    }
    console.log("[DevNet] psy-contracts deployed");
}

async function readDeploymentAddress(repoCwd: string, deploymentsNetwork: string, contractName: string): Promise<string | null> {
    const deploymentPath = path.join(repoCwd, "psy-contracts", "deployments", deploymentsNetwork, "deployed-contracts.json");
    if (!(await exists(deploymentPath))) {
        return null;
    }
    const deployments = await Bun.file(deploymentPath).json() as any;
    return deployments?.core?.[contractName] || deployments?.contracts?.[contractName] || null;
}

async function readDeploymentChainId(repoCwd: string, network: L1DeploymentNetwork): Promise<number> {
    const deploymentPath = path.join(repoCwd, "psy-contracts", "deployments", network, "deployed-contracts.json");
    const deployed = await Bun.file(deploymentPath).json();
    const chainId = Number(deployed?.chainId ?? deployed?.protocol?.chain?.l1ChainId);
    const expected = protocolConfig.chains[network].l1ChainId;
    if (!Number.isSafeInteger(chainId) || chainId <= 0 || chainId !== expected) {
        throw new Error(`invalid chainId in ${deploymentPath}: expected ${expected}, got ${chainId}`);
    }
    return chainId;
}

async function runAndCapture(cmd: string[], cwd?: string, env?: NodeJS.ProcessEnv): Promise<{ code: number; stdout: string; stderr: string }> {
    const proc = Bun.spawn(cmd, {
        cwd,
        env: env ?? (cwd ? { ...process.env, PWD: cwd } : undefined),
        stdout: "pipe",
        stderr: "pipe",
    });
    const stdout = proc.stdout ? await new Response(proc.stdout).text() : "";
    const stderr = proc.stderr ? await new Response(proc.stderr).text() : "";
    const code = await proc.exited;
    return { code, stdout, stderr };
}

async function runStreaming(cmd: string[], cwd?: string): Promise<number> {
    const proc = Bun.spawn(cmd, {
        cwd,
        env: cwd ? { ...process.env, PWD: cwd } : undefined,
        stdout: "inherit",
        stderr: "inherit",
    });
    return await proc.exited;
}

/**
 * Run a command with stdout inherited and stderr piped, teeing each stderr
 * chunk to the terminal (visible progress) while accumulating it into a string
 * (captured diagnostics for fail-closed error messages). Mirrors the env/PWD
 * propagation of runAndCapture/runStreaming. No shell is involved: the argv is
 * passed straight to Bun.spawn. `stderrSink` is overridable for tests so the
 * terminal is not polluted when the captured text is asserted directly.
 */
export async function runStreamingCaptureStderr(
    cmd: string[],
    cwd?: string,
    opts?: { stderrSink?: (chunk: Uint8Array) => void },
): Promise<{ code: number; stderr: string }> {
    const proc = Bun.spawn(cmd, {
        cwd,
        env: cwd ? { ...process.env, PWD: cwd } : undefined,
        stdout: "inherit",
        stderr: "pipe",
    });
    const sink = opts?.stderrSink ?? ((chunk: Uint8Array) => { process.stderr.write(chunk); });
    let stderr = "";
    if (proc.stderr) {
        const reader = proc.stderr.getReader();
        const decoder = new TextDecoder();
        try {
            for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                if (value) {
                    sink(value);
                    stderr += decoder.decode(value, { stream: true });
                }
            }
            stderr += decoder.decode();
        } finally {
            reader.releaseLock();
        }
    }
    const code = await proc.exited;
    return { code, stderr };
}

async function waitForCommandSuccess(
    cmd: string[],
    opts?: { cwd?: string; attempts?: number; delayMs?: number; name?: string }
): Promise<void> {
    const attempts = opts?.attempts ?? 30;
    const delayMs = opts?.delayMs ?? 1000;
    const name = opts?.name ?? cmd.join(" ");

    for (let i = 1; i <= attempts; i++) {
        const result = await runAndCapture(cmd, opts?.cwd);
        if (result.code === 0) {
            return;
        }
        if (i < attempts) {
            await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
    }

    throw new Error(`[DevNet] Timed out waiting for command success: ${name}`);
}

function parseTomlScalar(raw: string, key: string): string | undefined {
    const m = raw.match(new RegExp(`(?:^|\\n)\\s*${key}\\s*=\\s*"([^"]+)"`));
    return m?.[1];
}




function isHttpOrigin(value: unknown): value is string {
    if (typeof value !== "string" || !value) return false;
    try {
        const url = new URL(value);
        return url.protocol === "http:" && !!url.hostname && !isWildcardHost(url.hostname.replace(/^\[|\]$/g, "")) && url.port !== "0"
            && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash;
    } catch { return false; }
}

function isSocketAddress(value: unknown, history: boolean): boolean {
    if (typeof value !== "string" || !value.trim() || value.includes("\0")) return false;
    const ipv6 = value.startsWith("[") ? value.match(/^\[([^\]]+)\]:(\d+)$/) : null;
    const host = ipv6 ? ipv6[1] : value.slice(0, value.lastIndexOf(":"));
    const portText = ipv6 ? ipv6[2] : value.slice(value.lastIndexOf(":") + 1);
    const port = Number(portText);
    if (!host || !ipv6 && host.includes(":") || !/^\d+$/.test(portText) || !Number.isInteger(port) || port <= 0 || port > 65535) return false;
    if (net.isIP(host) === 0) return false;
    return !history || port !== 0 && host !== "0.0.0.0" && host !== "::";
}





const GUARDIAN_RPC_CONTEXT = "[DevNet] Bridge relayer requires the daemon rpc_config psy-genesis network to carry guardian public endpoints";
const GUARDIAN_RPC_FIELDS = "expected canonical guardian public fields: three distinct nonzero guardian_initial_member_hashes, distinct guardian_configs ids 1..3 and advertised origins, and guardian_history";

function guardianRpcError(detail: string): Error {
    return new Error(`${GUARDIAN_RPC_CONTEXT}; ${detail}`);
}

function exactFields(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
    const keys = Object.keys(value);
    return required.every((field) => keys.includes(field))
        && keys.every((field) => required.includes(field) || optional.includes(field));
}

function isWildcardHost(host: string): boolean {
    return host === "0.0.0.0" || host === "::";
}

function socketHost(value: string): string | null {
    const ipv6 = value.startsWith("[") ? value.match(/^\[([^\]]+)\]:\d+$/) : null;
    const host = ipv6 ? ipv6[1] : value.slice(0, value.lastIndexOf(":"));
    return host || null;
}

function advertisedOrigin(listenAddress: string, rpcUrl: unknown): boolean {
    if (rpcUrl === undefined) {
        const host = socketHost(listenAddress);
        return !!host && !isWildcardHost(host);
    }
    return isHttpOrigin(rpcUrl);
}

function isGuardianPublicConfig(value: unknown): value is { id: number; listen_address: string; rpc_url?: string } {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const entry = value as Record<string, unknown>;
    return exactFields(entry, ["id", "listen_address"], ["rpc_url"])
        && Number.isInteger(entry.id) && (entry.id as number) >= 1 && (entry.id as number) <= 3
        && isSocketAddress(entry.listen_address, false)
        && advertisedOrigin(entry.listen_address as string, entry.rpc_url);
}

function isGuardianHistoryConfig(value: unknown): boolean {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const entry = value as Record<string, unknown>;
    return exactFields(entry, ["listen_address"], ["rpc_url"])
        && isSocketAddress(entry.listen_address, true)
        && advertisedOrigin(entry.listen_address as string, entry.rpc_url);
}

export async function validateGuardianRpcConfig(cwd: string, configuredPath: string, env: NodeJS.ProcessEnv = process.env): Promise<Record<string, unknown>> {
    const networkKey = env.PSY_NETWORK?.trim();
    if (!networkKey) throw guardianRpcError("PSY_NETWORK must name the compiled canonical network");
    const configPath = path.resolve(cwd, configuredPath);
    let config: Record<string, unknown>;
    try {
        const stat = await fs.promises.lstat(configPath);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 64 * 1024 * 1024) throw new Error("not a regular bounded file");
        config = JSON.parse(await fs.promises.readFile(configPath, "utf8"));
    } catch {
        throw guardianRpcError("the selected rpc_config must be a readable, non-symlink regular file containing valid JSON (at most 64 MiB).");
    }
    const networks = config.networks;
    const network = networks && typeof networks === "object" && !Array.isArray(networks)
        ? (networks as Record<string, unknown>)[networkKey]
        : undefined;
    if (!network || typeof network !== "object" || Array.isArray(network)) {
        throw guardianRpcError(`the ${networkKey} network must exist`);
    }
    const selected = network as Record<string, unknown>;
    const guardians = selected.guardian_configs;
    const members = Array.isArray(selected.guardian_initial_member_hashes)
        ? selected.guardian_initial_member_hashes.map((hash) => guardianMemberLimbs(hash)?.join(",") ?? "")
        : [];
    const guardianValid = Array.isArray(guardians) && guardians.length === 3 && guardians.every(isGuardianPublicConfig)
        && [1, 2, 3].every((id) => guardians.filter((entry) => (entry as { id: number }).id === id).length === 1);
    const guardianOrigins = guardianValid
        ? guardians.map((entry) => new URL(entry.rpc_url ?? `http://${entry.listen_address}`).origin)
        : [];
    if (Object.hasOwn(selected, "guardian_authorization") || Object.hasOwn(selected, "guardian_max_fee") || Object.hasOwn(selected, "guardian_root") || !guardianValid
        || members.length !== 3 || members.some((member) => !member || member === "0,0,0,0") || new Set(members).size !== 3
        || new Set(guardianOrigins).size !== 3 || !isGuardianHistoryConfig(selected.guardian_history)) {
        throw guardianRpcError(GUARDIAN_RPC_FIELDS);
    }
    return selected;
}

export async function resolveGuardianRoot(cwd: string, configuredRoot: string | undefined): Promise<string> {
    const context = "[DevNet] Bridge relayer requires PSY_GUARDIAN_ROOT pointing at the guardians-root runtime directory";
    if (!configuredRoot?.trim()) {
        throw new Error(`${context}; supply it in the environment or --env. Guardian credentials, registration and bootstrap are operator prerequisites; no L2 wallet fallback is available.`);
    }
    const root = path.resolve(cwd, configuredRoot);
    let stat: fs.Stats;
    try { stat = await fs.promises.lstat(root); }
    catch { throw new Error(`${context}; the selected path must be an existing non-symlink directory.`); }
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${context}; the selected path must be an existing non-symlink directory.`);
    if (await fs.promises.realpath(root) !== root) throw new Error(`${context}; symlink ancestors are not allowed.`);
    return root;
}

async function validateGuardianRuntimeRoot(root: string, purgeTargets: readonly string[], generated: boolean): Promise<void> {
    await validateDaemonPath(path.resolve(root, "db"), generated ? "directory" : "output-directory", purgeTargets, "guardian root db metadata");
}
const GUARDIAN_PASSWORD_ENV = ["GUARDIAN_1_KEYSTORE_PASSWORD", "GUARDIAN_2_KEYSTORE_PASSWORD", "GUARDIAN_3_KEYSTORE_PASSWORD"] as const;

/** Metadata only: three existing owner-only keystores. Passwords stay in the inherited env and are never written or logged. */
export async function assertGuardianKeystoresPresent(env: NodeJS.ProcessEnv = process.env): Promise<void> {
    const homeDir = env.HOME;
    if (!homeDir) throw new Error("[DevNet] HOME is required to locate guardian keystores");
    const checks = await Promise.allSettled(GUARDIAN_PASSWORD_ENV.map(async (name, index) => {
        if (!env[name]) throw new Error(`[DevNet] ${name} is required; passwords are not read from files`);
        const keystore = path.join(homeDir, ".psy", "keystore", `guardian-${index + 1}.keystore.json`);
        const stat = await fs.promises.lstat(keystore);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (process.getuid && stat.uid !== process.getuid())) {
            throw new Error(`[DevNet] guardian-${index + 1} keystore must be an existing owner-only regular file`);
        }
    }));
    const failure = checks.find((result): result is PromiseRejectedResult => result.status === "rejected");
    if (failure) throw failure.reason;
}

// Member hashes and Guardian endpoints come from the selected network; chain identity comes from the selected deployment documents.
export async function prepareGuardianService(cmds: readonly string[], cwd: string, env: NodeJS.ProcessEnv = process.env): Promise<{ host: string; port: number }> {
    const idIndex = cmds.indexOf("--guardian-id");
    const rpcIndex = cmds.indexOf("--rpc-config");
    const rootIndex = cmds.indexOf("--guardian-root");
    const id = cmds[idIndex + 1];
    if (!["1", "2", "3"].includes(id) || rpcIndex < 0 || rootIndex < 0 || idIndex !== cmds.length - 2) {
        throw new Error("[DevNet] Invalid guardian-service template");
    }
    const network = await validateGuardianRpcConfig(cwd, cmds[rpcIndex + 1], env);
    const entry = (network.guardian_configs as Array<{ id: number; listen_address: string }>).find((guardian) => guardian.id === Number(id));
    if (!entry) throw new Error("[DevNet] Invalid guardian-service template");
    const address = entry.listen_address;
    const port = Number(address.slice(address.lastIndexOf(":") + 1));
    const host = address.slice(0, address.lastIndexOf(":")).replace(/^\[|\]$/g, "");
    if (port === 0) throw new Error("[DevNet] guardian-service requires a fixed listen port");
    await new Promise<void>((resolve, reject) => {
        const server = net.createServer();
        server.once("error", reject);
        server.listen({ host, port, exclusive: true }, () => server.close((error) => error ? reject(error) : resolve()));
    });
    const root = path.resolve(cwd, cmds[rootIndex + 1]);
    const databaseDir = path.join(root, "db");
    await validateDaemonPath(databaseDir, "directory", DEVNET_PURGE_PATHS.map((target) => path.resolve(cwd, target)), "guardian db metadata");
    const stat = await fs.promises.lstat(databaseDir);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())) {
        throw new Error("[DevNet] guardian db directory must be an existing owner-only directory");
    }
    await assertGuardianKeystoresPresent(env);
    return { host: host === "0.0.0.0" ? "127.0.0.1" : host === "::" ? "::1" : host, port };
}

const DEVNET_PURGE_PATHS = [
    "local_checkpoints", "db/anvil", "logs",
    ...["localhost", "localhostBsc", "localhostBase", "sepolia", "ethereum"].map((network) => `psy-contracts/deployments/${network}`),
];

export interface FreshDevnetState {
    abort(): Promise<void>;
    reset(): Promise<void>;
    finish(): Promise<void>;
}

export interface ScopedDevnetReset {
    volumes: string[];
    containers: string[];
}

/** EOF grace before SIGTERM: enough for a clean helper exit that drops its dirty-DB mark. */
const FRESH_HELPER_ABORT_GRACE_MS = 5_000;
/** Bounded waits between SIGTERM and SIGKILL in the abort ladder. */
const FRESH_HELPER_TERM_GRACE_MS = 2_000;
const FRESH_HELPER_KILL_GRACE_MS = 2_000;

/** ANSI CSI/escape sequences stripped before any stderr line becomes a diagnostic. */
const ANSI_ESCAPE_PATTERN = /\u001b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g;
/** Words that disqualify a stderr line from display, whatever their case. */
const FRESH_HELPER_SECRET_PATTERN = /password|private[\s_-]*key|mnemonic|secret|token/i;
const FRESH_HELPER_STDERR_TAIL_BYTES = 2048;
const FRESH_HELPER_DIAGNOSTIC_MAX_CHARS = 200;

/** Last `Error:` line of the helper's stderr, made safe for display; null when absent or unsafe. */
function freshHelperSafeError(stderrTail: Buffer): string | null {
    const last = stderrTail.toString("utf8").replace(ANSI_ESCAPE_PATTERN, "")
        .split("\n").filter((line) => /^Error:/.test(line)).at(-1);
    if (last === undefined) return null;
    const clipped = last.slice(0, FRESH_HELPER_DIAGNOSTIC_MAX_CHARS);
    if (clipped.includes("=") || FRESH_HELPER_SECRET_PATTERN.test(clipped)) return null;
    return clipped;
}

/** Suffixes the failure's message with the helper's safe stderr line; never replaces the error. */
function appendFreshHelperDiagnostic(error: unknown, stderrTail: Buffer): unknown {
    const diagnostic = freshHelperSafeError(stderrTail);
    if (diagnostic === null || !(error instanceof Error)) return error;
    error.message += `\n[DevNet] fresh helper stderr: ${diagnostic}`;
    return error;
}

/** One helper owns every database inode from prepare through finish. Config is read-only and is not snapshotted. */
export async function prepareFreshDevnetState(cwd: string, guardianRoot: string, env: NodeJS.ProcessEnv): Promise<FreshDevnetState> {
    const generation = await planGenesisGeneration(cwd, env);
    const child = spawn(generation.args[0], ["fresh-devnet-state", "--repo-root", path.resolve(cwd),
        "--guardians-root", guardianRoot],
        { cwd, env: generation.env, stdio: ["pipe", "pipe", "pipe"] });
    const lines = createInterface({ input: child.stdout });
    const iterator = lines[Symbol.asyncIterator]();
    // Exit fact vs error event: a spawn failure has no pid and is done; an
    // error on a live process (e.g. a failed kill) must never fake an exit.
    const exited = new Promise<number | null>((resolve) => {
        child.once("exit", (code) => resolve(code));
        child.once("error", () => { if (child.pid === undefined) resolve(null); });
    });
    const waitExited = (ms: number) => {
        let timer: NodeJS.Timeout | undefined;
        const deadline = new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), ms); });
        return Promise.race([exited.then(() => true), deadline]).finally(() => clearTimeout(timer!));
    };
    // Bounded stderr tail: the pipe must never fill while the handshake runs,
    // and only the exit-time anyhow line is needed for diagnostics.
    let stderrTail = Buffer.alloc(0);
    child.stderr?.on("data", (chunk: Buffer) => {
        stderrTail = Buffer.concat([stderrTail, chunk]);
        if (stderrTail.length > FRESH_HELPER_STDERR_TAIL_BYTES) {
            stderrTail = stderrTail.subarray(stderrTail.length - FRESH_HELPER_STDERR_TAIL_BYTES);
        }
    });
    const receive = async (phase: string) => {
        try {
            const line = await iterator.next();
            if (line.done || line.value !== JSON.stringify({ phase })) {
                throw new Error(`[DevNet] fresh state helper failed before ${phase}; database locks were not released for the next stage`);
            }
        } catch (error) {
            // Abort first so the exit-time anyhow line is fully written, then
            // surface it as display-only context; the original error is kept.
            try { await abort(); }
            catch (abortError) {
                // A final abort error (helper refusing to die) must not swallow
                // the phase failure that triggered it.
                throw new Error((abortError as Error).message, { cause: error });
            }
            throw appendFreshHelperDiagnostic(error, stderrTail);
        }
    };
    // Singleflight: concurrent aborts share one ladder. It ends only on a real
    // exit (or a spawn failure, which has no process to wait for) and throws
    // a final error when the helper survives every stage, never claiming stop.
    let abortPromise: Promise<void> | null = null;
    const abort = (): Promise<void> => abortPromise ??= (async () => {
        try {
            child.stdin.end();
            // Graceful EOF first: a clean helper exit after stdin close drops
            // its dirty-DB mark, so the next fresh run finds a clean redb.
            if (!await waitExited(FRESH_HELPER_ABORT_GRACE_MS)) {
                child.kill("SIGTERM");
                if (!await waitExited(FRESH_HELPER_TERM_GRACE_MS)) {
                    child.kill("SIGKILL");
                    if (!await waitExited(FRESH_HELPER_KILL_GRACE_MS)) {
                        throw new Error("[DevNet] fresh state helper survived EOF, SIGTERM, and SIGKILL; it may still hold its redb lock");
                    }
                }
            }
        } finally { lines.close(); }
    })();
    // receive aborts and annotates its own failures; after it the helper
    // reached "prepared" and remains alive for reset/finish phases.
    await receive("prepared");
    return {
        abort,
        async reset() { child.stdin.write("reset\n"); await receive("reset"); },
        async finish() {
            child.stdin.end("finish\n");
            await receive("finished");
            if (await exited !== 0) throw appendFreshHelperDiagnostic(
                new Error("[DevNet] fresh state helper failed to finish"), stderrTail);
            lines.close();
        },
    };
}

export async function planScopedDevnetReset(names: DevnetDbNames): Promise<ScopedDevnetReset> {
    const failures: string[] = [];
    const listed = await runBoundedTeardown("fresh-volume-ls", ["docker", "volume", "ls", "--format", "{{.Name}}"], undefined, failures);
    const containers = await runBoundedTeardown("fresh-docker-ps", ["docker", "ps", "-a", "--format", "{{.Names}}"], undefined, failures);
    if (failures.length > 0) throw new Error(`[DevNet] fresh startup cannot prove namespace resources: ${failures.join(" | ")}`);
    return {
        volumes: [...devnetDbVolumeNames(names), names.envioDataVolume].filter((name) => exactSnapshotNames(listed.stdout).has(name)),
        containers: [...devnetDbContainerNames(names), names.envioPostgresContainer, `${names.envioComposeProject}-graphql-engine-1`].filter((name) => exactSnapshotNames(containers.stdout).has(name)),
    };
}

async function resetScopedDevnetState(cwd: string, targets: ScopedDevnetReset): Promise<void> {
    await stopRepoAnvilsForPurge(cwd);
    const failures: string[] = [];
    if (targets.containers.length > 0) {
        await removeOwnedContainersForPurge(targets.containers, failures, "fresh-docker");
        if (failures.length > 0) throw new Error(`[DevNet] could not remove owned containers: ${failures.join(" | ")}`);
    }
    if (targets.volumes.length > 0) await runBoundedTeardown("fresh-volume-rm", ["docker", "volume", "rm", "-f", ...targets.volumes], undefined, failures);
    if (failures.length > 0) throw new Error(`[DevNet] fresh startup namespace cleanup failed: ${failures.join(" | ")}`);
}
/** Supplied path must already be a non-symlink regular file; the returned path is canonical. */
export async function resolveScyllaIoProperties(value: string | undefined): Promise<string | undefined> {
    const supplied = value?.trim();
    if (!supplied) return undefined;
    let suppliedStat: fs.Stats;
    try {
        suppliedStat = await fs.promises.lstat(supplied);
    } catch {
        throw new Error(`[DevNet] SCYLLA_IO_PROPERTIES must be an existing non-symlink regular file, received '${supplied}'`);
    }
    if (!suppliedStat.isFile() || suppliedStat.isSymbolicLink()) {
        throw new Error(`[DevNet] SCYLLA_IO_PROPERTIES must be an existing non-symlink regular file, received '${supplied}'`);
    }
    let canonical: string;
    try {
        canonical = await fs.promises.realpath(path.resolve(supplied));
    } catch {
        throw new Error(`[DevNet] SCYLLA_IO_PROPERTIES must be an existing non-symlink regular file, received '${supplied}'`);
    }
    if (canonical.includes(":")) {
        throw new Error(`[DevNet] SCYLLA_IO_PROPERTIES absolute path must not contain ':', received '${supplied}'`);
    }
    return canonical;
}


function daemonConfigError(field: string): Error {
    return new Error(`[DevNet] PSY_BRIDGE_DAEMON_CONFIG: invalid or unavailable ${field}; operator provisioning required`);
}

async function validateDaemonPath(file: string, kind: "file" | "directory" | "output" | "output-directory", purgeTargets: readonly string[], field: string): Promise<void> {
    const contains = (parent: string, child: string) => {
        const relative = path.relative(parent, child);
        return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
    };
    const realPath = async (target: string): Promise<string> => {
        try { return await fs.promises.realpath(target); }
        catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
            // A dangling symlink is not an absent output directory.
            try { await fs.promises.lstat(target); throw daemonConfigError(field); }
            catch (missing) { if ((missing as NodeJS.ErrnoException).code !== "ENOENT") throw missing; }
            const parent = path.dirname(target);
            if (parent === target) throw error;
            return path.join(await realPath(parent), path.basename(target));
        }
    };
    try {
        const resolved = await realPath(file);
        for (const target of purgeTargets) {
            if (contains(target, file) || contains(await realPath(target), resolved)) throw daemonConfigError(field);
        }
        try {
            const stat = await fs.promises.stat(file);
            if ((kind === "directory" || kind === "output-directory") ? !stat.isDirectory() : !stat.isFile()) throw daemonConfigError(field);
        } catch (error) {
            if ((kind !== "output" && kind !== "output-directory") || (error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
    } catch { throw daemonConfigError(field); }
}

export async function resolveBridgeDaemonConfigPath(
    cwd: string,
    env: NodeJS.ProcessEnv,
    purge: boolean = false,
    parse: ((text: string) => unknown) | undefined = Bun.TOML?.parse,
): Promise<string> {
    if (typeof parse !== "function") throw daemonConfigError("Bun.TOML.parse capability");
    const textField = (value: unknown, field: string): string => {
        if (typeof value !== "string" || !value.trim() || value.includes("\0")) throw daemonConfigError(field);
        return value;
    };
    const table = (value: unknown, field: string): Record<string, unknown> => {
        if (!value || typeof value !== "object" || Array.isArray(value) || value instanceof Date) throw daemonConfigError(field);
        return value as Record<string, unknown>;
    };
    const integer = (value: unknown, bits: number, field: string): void => {
        if (typeof value !== "bigint" && (typeof value !== "number" || !Number.isSafeInteger(value))) throw daemonConfigError(field);
        const n = BigInt(value as number | bigint);
        if (n < 0n || n >= (1n << BigInt(bits))) throw daemonConfigError(field);
    };
    const configPath = path.resolve(cwd, textField(env.PSY_BRIDGE_DAEMON_CONFIG, "config path"));
    const purgeTargets = purge ? DEVNET_PURGE_PATHS.map((target) => path.resolve(cwd, target)) : [];
    await validateDaemonPath(configPath, "file", purgeTargets, "config path metadata");
    let config: Record<string, unknown>;
    try {
        if ((await fs.promises.stat(configPath)).size > 64 * 1024 * 1024) throw daemonConfigError("config size");
        config = table(parse(await fs.promises.readFile(configPath, "utf8")), "config table");
    } catch { throw daemonConfigError("TOML document (details withheld)"); }
    const inspectCredentials = async (value: unknown): Promise<void> => {
        if (!value || typeof value !== "object") return;
        for (const [field, child] of Object.entries(value)) {
            if (field === "private_key" && child !== "") throw daemonConfigError("inline private_key");
            if (field === "keystore_path") {
                await validateDaemonPath(path.resolve(cwd, textField(child, "keystore_path")), "file", purgeTargets, "keystore_path metadata");
            } else if (child && typeof child === "object") await inspectCredentials(child);
        }
    };
    await inspectCredentials(config);
    await validateDaemonPath(path.resolve(cwd, textField(config.rpc_config, "rpc_config")), "file", purgeTargets, "rpc_config metadata");
    textField(config.services_url, "services_url");
    integer(config.withdraw_method_id, 64, "withdraw_method_id");
    for (const field of ["proof_dir", "poll_interval_secs", "confirmation_lag_checkpoints", "max_checkpoint_batch", "max_concurrent_l2_batches"]) {
        if (!Object.hasOwn(config, field) || config[field] == null) continue;
        if (field === "proof_dir") textField(config[field], field);
        else integer(config[field], 64, field);
    }
    if (Object.hasOwn(config, "finalize") && config.finalize != null) table(config.finalize, "finalize");
    if (Object.hasOwn(config, "chains")) {
        if (!Array.isArray(config.chains)) throw daemonConfigError("chains");
        for (const value of config.chains) {
            const chain = table(value, "chains");
            integer(chain.chain_index, 8, "chains.chain_index");
            for (const field of ["network_id", "deployments_network"]) textField(chain[field], `chains.${field}`);
            if (Object.hasOwn(chain, "family") && chain.family != null) textField(chain.family, "chains.family");
        }
    }
    const configuredRoot = textField(config.guardian_root, "guardian_root");
    const envRoot = env.PSY_GUARDIAN_ROOT?.trim();
    if (envRoot && path.resolve(cwd, envRoot) !== path.resolve(cwd, configuredRoot)) {
        throw daemonConfigError("PSY_GUARDIAN_ROOT disagrees with guardian_root");
    }
    const guardianRoot = await resolveGuardianRoot(cwd, configuredRoot);
    await validateGuardianRuntimeRoot(guardianRoot, purgeTargets, false);
    try { await validateGuardianRpcConfig(cwd, config.rpc_config as string, env); }
    catch (error) { throw daemonConfigError(error instanceof Error ? error.message : "rpc_config guardian public endpoints"); }
    return configPath;
}

export async function validateRelayerTemplate(cmds: readonly string[], options: RunningProcess["spawnOptions"] = {}): Promise<void> {
    if (!cmds.includes("guardian-service") && !cmds.some((cmd) => path.basename(cmd) === "psy_relayer_cli")) return;
    const cwd = options.cwd || process.cwd();
    const env = options.env ?? process.env;
    if (cmds.includes("guardian-service")) {
        const rpcIndex = cmds.indexOf("--rpc-config");
        if (rpcIndex < 0 || !cmds[rpcIndex + 1]) throw guardianRpcError("missing --rpc-config");
        await validateGuardianRpcConfig(cwd, cmds[rpcIndex + 1], env);
        return;
    }
    if (!cmds.some((cmd) => path.basename(cmd) === "psy_relayer_cli")) return;
    const configPath = await resolveBridgeDaemonConfigPath(cwd, env);
    const index = cmds.indexOf("--config");
    if (index < 0 || !cmds[index + 1] || path.resolve(cwd, cmds[index + 1]) !== configPath) throw daemonConfigError("saved --config coherence");
    const config = Bun.TOML.parse(await fs.promises.readFile(configPath, "utf8"));
    await validateGuardianRpcConfig(cwd, config.rpc_config as string, env);
}

const ENVIO_NPM_VERSION = "2.32.10";
const ENVIO_HASURA_IMAGE = "hasura/graphql-engine:v2.43.0";
const ENVIO_POSTGRES_IMAGE = "postgres:17.5";

async function configureEnvioDockerCompose(composePath: string, runtimeCpuSet: string | undefined, networkName: string): Promise<void> {
    if (!(await exists(composePath))) {
        throw new Error(`Envio codegen did not create ${composePath}`);
    }
    const original = await Bun.file(composePath).text();
    const pinnedImages = original
        .replace(/image:\s*hasura\/graphql-engine:[^\s]+/g, `image: ${ENVIO_HASURA_IMAGE}`)
        .replace(/image:\s*postgres:[^\s]+/g, `image: ${ENVIO_POSTGRES_IMAGE}`);
    const configured = applyEnvioNetworkName(applyEnvioCpuSetToCompose(pinnedImages, runtimeCpuSet), networkName);
    if (configured !== original) {
        await Bun.write(composePath, configured);
    }
}

function stringRecord(value: unknown): Record<string, string> {
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return Object.fromEntries(
        Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
    );
}

export async function runFrozenEnvioCodegen(envioDir: string, environment: NodeJS.ProcessEnv): Promise<void> {
    const root = path.resolve(envioDir);
    const cachedPnpm = environment.PSY_FROZEN_DEPS_PNPM;
    const store = environment.PSY_FROZEN_DEPS_STORE;
    if (!cachedPnpm || !store) throw new Error("[DevNet] PSY_FROZEN_DEPS requires PSY_FROZEN_DEPS_PNPM and PSY_FROZEN_DEPS_STORE");
    const executable = path.join(root, "node_modules/.bin/envio");
    if (!(await exists(executable))) throw new Error("[DevNet] PSY_FROZEN_DEPS requires preinstalled Envio executable");
    await guardedEnvioCodegen({
        root, cachedPnpm, store, environment, runner: frozenDepsCommandRunner,
        codegen: ({ environment: guardedEnvironment }) => frozenDepsCommandRunner(executable, ["codegen", "--directory", root, "--config", "./config.yaml"], { cwd: root, env: guardedEnvironment }),
    });
}

export async function frozenEnvioStartCommand(envioDir: string): Promise<{ command: string[]; cwd: string }> {
    const generated = path.resolve(envioDir, "generated");
    const manifest: unknown = JSON.parse(await fs.promises.readFile(path.join(generated, "package.json"), "utf8"));
    if (!manifest || typeof manifest !== "object" || !("scripts" in manifest)
        || !manifest.scripts || typeof manifest.scripts !== "object"
        || !("start" in manifest.scripts) || manifest.scripts.start !== "ts-node src/Index.res.js") {
        throw new Error("[DevNet] frozen Envio runtime requires the reviewed generated start script");
    }
    const executable = path.join(generated, "node_modules/.bin/ts-node");
    if (!(await exists(executable)) || !(await exists(path.join(generated, "src/Index.res.js")))) {
        throw new Error("[DevNet] frozen Envio runtime requires compiled indexer and preinstalled ts-node");
    }
    // Envio 2.32.10 start without --restart/--bench only runs this script in
    // generated/. Mandatory guarded codegen already parsed the configuration.
    return { command: [executable, "src/Index.res.js"], cwd: generated };
}

async function startEnvioIndexerForRelayer(
    repoCwd: string,
    relayerConfigPath: string,
    cohort: readonly ActiveL1Chain[],
    env?: { [key: string]: string },
    resetStorage: boolean = false,
    runtimeCpuSet?: string,
): Promise<RunningProcess | null> {
    const cfgPath = path.isAbsolute(relayerConfigPath) ? relayerConfigPath : path.join(repoCwd, relayerConfigPath);
    if (!(await exists(cfgPath))) return null;
    const relayerRaw = await Bun.file(cfgPath).text();
    const databaseUrl =
        parseTomlScalar(relayerRaw, "database_url") ||
        "postgres://postgres:testing@127.0.0.1:5433/envio-dev";

    const readArtifactBlockNumber = async (network: string, artifactName: string): Promise<number | undefined> => {
        const artifactPath = path.join(
            repoCwd,
            "psy-contracts",
            "deployments",
            network,
            `${artifactName}.json`,
        );
        if (!(await exists(artifactPath))) return undefined;
        try {
            const artifact = JSON.parse(await Bun.file(artifactPath).text()) as any;
            const raw = artifact?.receipt?.blockNumber;
            if (typeof raw === "number" && Number.isFinite(raw)) return raw;
            if (typeof raw === "string" && raw.trim()) {
                const n = Number(raw);
                if (Number.isFinite(n)) return n;
            }
        } catch {
            return undefined;
        }
        return undefined;
    };
    const targets = await Promise.all(cohort.map(async (target) => {
        const deployedPath = path.join(repoCwd, "psy-contracts", "deployments", target.deploymentsNetwork, "deployed-contracts.json");
        if (!(await exists(deployedPath))) throw new Error(`missing deployed contracts summary: ${deployedPath}`);
        const deployed = JSON.parse(await Bun.file(deployedPath).text()) as any;
        const chainId = await readDeploymentChainId(repoCwd, target.deploymentsNetwork);
        const bridge = deployed?.core?.Bridge || deployed?.contracts?.Bridge;
        const stateManager = deployed?.core?.StateManager || deployed?.contracts?.StateManager;
        if (!bridge || !stateManager) throw new Error(`missing Bridge/StateManager in ${deployedPath}`);
        const blocks = await Promise.all([
            readArtifactBlockNumber(target.deploymentsNetwork, "Bridge_Proxy"),
            readArtifactBlockNumber(target.deploymentsNetwork, "StateManager_Proxy"),
        ]);
        const startBlock = blocks.filter((v): v is number => v != null && v > 0)
            .reduce<number | undefined>((min, value) => min == null ? value : Math.min(min, value), undefined) ?? 1;
        return { ...target, chainId, bridge, stateManager, startBlock };
    }));

    const envioDir = path.join(repoCwd, "psy_cli", "psy_relayer_cli", "indexer", "envio");
    const templatePath = path.join(envioDir, "config.template.yaml");
    const configPath = path.join(envioDir, "config.yaml");
    const envPath = path.join(envioDir, ".env");
    if (!(await exists(templatePath))) {
        throw new Error(`missing envio config template: ${templatePath}`);
    }
    const template = await Bun.file(templatePath).text();
    const prefixes = new Set(targets.map((target) => target.prefix));
    let config = template.replace(/^  - id: \$\{([A-Z]+)_CHAIN_ID\}[\s\S]*?(?=^  - id:|$(?![\s\S]))/gm, (block, prefix: string) => prefixes.has(prefix) ? block : "");
    for (const target of targets) {
        const values: Record<string, string> = {
            [`${target.prefix}_CHAIN_ID`]: String(target.chainId),
            [`${target.prefix}_START_BLOCK`]: String(target.startBlock),
            [`${target.prefix}_RPC_URL`]: target.rpcUrl,
            [`${target.prefix}_BRIDGE_ADDRESS`]: target.bridge,
            [`${target.prefix}_STATE_MANAGER_ADDRESS`]: target.stateManager,
        };
        for (const [key, value] of Object.entries(values)) config = config.replaceAll(`\${${key}}`, value);
    }
    if (/\$\{[A-Z0-9_]+\}/.test(config)) throw new Error("unresolved variable in generated Envio config");
    await Bun.write(configPath, config);
    await Bun.write(
        envPath,
        [
            ...targets.flatMap((target) => [
                `${target.prefix}_CHAIN_ID=${target.chainId}`,
                `${target.prefix}_RPC_URL=${target.rpcUrl}`,
                `${target.prefix}_BRIDGE_ADDRESS=${target.bridge}`,
                `${target.prefix}_STATE_MANAGER_ADDRESS=${target.stateManager}`,
            ]),
            `DATABASE_URL=${databaseUrl}`,
            `LOG_LEVEL=info`,
        ].join("\n") + "\n",
    );
    const frozen = frozenDepsEnabled((env ?? process.env).PSY_FROZEN_DEPS);
    if (frozen) {
        // Always run real codegen; its guarded children install/build from the
        // reviewed lock. Do not rewrite manifests or trust a config hash.
        await runFrozenEnvioCodegen(envioDir, env ?? process.env);
    } else {
        const pkgPath = path.join(envioDir, "package.json");
        let existingPackage: Record<string, unknown> = {};
        if (await exists(pkgPath)) {
            try {
                const parsedPackage: unknown = JSON.parse(await Bun.file(pkgPath).text());
                if (parsedPackage && typeof parsedPackage === "object" && !Array.isArray(parsedPackage)) {
                    existingPackage = parsedPackage as Record<string, unknown>;
                }
            } catch {
                // fall back to defaults below
            }
        }
        const envioPkg = {
            ...existingPackage,
            name: typeof existingPackage.name === "string" ? existingPackage.name : "psy-relayer-envio",
            private: true,
            version: typeof existingPackage.version === "string" ? existingPackage.version : "0.1.0",
            scripts: {
                ...stringRecord(existingPackage.scripts),
                codegen: "envio codegen --config ./config.yaml",
                start: "envio start --config ./config.yaml",
            },
            devDependencies: {
                ...stringRecord(existingPackage.devDependencies),
                envio: ENVIO_NPM_VERSION,
            },
        };
        await Bun.write(pkgPath, JSON.stringify(envioPkg, null, 2) + "\n");
        console.log("[DevNet] Installing Envio indexer dependencies...");
        await ensurePnpmBuildScriptsApproved(envioDir, ["esbuild"]);
        await pnpmInstallWithAutoApprove(envioDir);
        console.log("[DevNet] Generating Envio indexer...");
        const codegen = await runAndCapture(["pnpm", "codegen"], envioDir);
        if (codegen.code !== 0) {
            throw new Error(`envio codegen failed: ${codegen.stderr || codegen.stdout}`);
        }
    }
    const envioGeneratedDir = path.join(envioDir, "generated");
    const envioComposeFile = path.join(envioGeneratedDir, "docker-compose.yaml");
    const names = resolveDevnetDbNamesFromEnv(env ?? process.env);
    await configureEnvioDockerCompose(envioComposeFile, runtimeCpuSet, names.envioNetwork);

    if (resetStorage) {
        console.log("[DevNet] Resetting Envio storage for ephemeral Anvil chain...");
        const reset = await runAndCapture(
            envioComposeCommand(envioComposeFile, names.envioComposeProject, ["down", "--remove-orphans", "-v"]),
            repoCwd,
        );
        if (reset.code !== 0) {
            throw new Error(`[DevNet] Failed to reset Envio storage (exit ${reset.code}): ${reset.stderr || reset.stdout}`);
        }
    }

    console.log("[DevNet] Starting Envio docker services...");
    const composeStart = await runAndCapture(
        envioComposeCommand(envioComposeFile, names.envioComposeProject, ["up", "-d"]),
        repoCwd,
    );
    if (composeStart.code !== 0) {
        throw new Error(`[DevNet] Failed to start Envio docker services: ${composeStart.stderr || composeStart.stdout}`);
    }
    await waitForTcpPort("127.0.0.1", 5433, {
        attempts: 600,
        delayMs: 1000,
        timeoutMs: 1500,
        name: "Envio Postgres",
    });
    await waitForCommandSuccess(
        envioPostgresReadinessCommand(names.envioPostgresContainer),
        { attempts: 600, delayMs: 1000, name: "Envio Postgres SQL readiness" },
    );
    await waitForHttpUrl("http://127.0.0.1:8080/healthz", {
        attempts: 600,
        delayMs: 1000,
        timeoutMs: 1500,
        name: "Envio GraphQL",
    });

    if (!frozen) {
        await ensurePnpmBuildScriptsApproved(envioGeneratedDir, ["rescript"]);
        await pnpmInstallWithAutoApprove(envioGeneratedDir);
        const buildGenerated = await runAndCapture(["pnpm", "build"], envioGeneratedDir);
        if (buildGenerated.code !== 0) {
            throw new Error(`envio generated build failed: ${buildGenerated.stderr || buildGenerated.stdout}`);
        }
    }

    console.log("[DevNet] Starting Envio indexer...");
    const start = frozen ? await frozenEnvioStartCommand(envioDir) : { command: ["pnpm", "start"], cwd: envioDir };
    const envioProcess = await RunningProcess.spawn(start.command, {
        cwd: start.cwd,
        stdoutLogFile: path.join(repoCwd, "logs", "envio_logs.txt"),
        stderrLogFile: path.join(repoCwd, "logs", "envio_errs.txt"),
        env: {
            ...(env || {}),
            TUI_OFF: "true",
            LOG_LEVEL: "info",
            FILE_LOG_LEVEL: "trace",
            HASURA_GRAPHQL_ENDPOINT: "http://localhost:8080/v1/metadata",
        },
    });
    return envioProcess;
}

const PURGE_DOCKER_TIMEOUT_MS = 15_000;
/** Seconds Docker may wait for a container's own stop handler before purge escalates. */
const PURGE_DOCKER_STOP_GRACE_SECONDS = 10;

const PURGE_ANVIL_SIGNAL_WAIT_MS = 5_000;

export interface TeardownCommandResult {
    argv0: string;
    code: number | null;
    timedOut: boolean;
    /** False when the deadline fired and the client was not reaped inside the extra second. */
    reaped: boolean;
    stderrCategory: "empty" | "present";
    stdout: string;
    stdoutComplete: boolean;
}

async function readPipeBounded(stream: ReadableStream<Uint8Array> | null | undefined, limit: number, cancel: { run?: () => void }): Promise<{ text: string; complete: boolean }> {
    if (!stream) return { text: "", complete: false };
    const reader = stream.getReader();
    let complete = true;
    cancel.run = () => { complete = false; void reader.cancel().catch(() => {}); };
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value) continue;
            if (value.byteLength > limit - size) complete = false;
            const slice = value.subarray(0, Math.min(value.byteLength, limit - size));
            if (slice.byteLength > 0) chunks.push(slice);
            size += slice.byteLength;
        }
    } catch {
        complete = false;
    } finally {
        reader.releaseLock();
    }
    return { text: Buffer.concat(chunks).toString("utf8"), complete };
}

export async function runTeardownCommand(argv: string[], cwd: string | undefined, timeoutMs: number): Promise<TeardownCommandResult> {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error(`[DevNet] teardown command timeout must be positive, received ${timeoutMs}`);
    const proc = Bun.spawn(["setsid", "--wait", ...argv], { cwd, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    const stdoutCancel: { run?: () => void } = {};
    const stderrCancel: { run?: () => void } = {};
    const stdoutTask = readPipeBounded(proc.stdout, 65_536, stdoutCancel);
    const stderrTask = readPipeBounded(proc.stderr, 65_536, stderrCancel);
    const completed = Promise.all([proc.exited, stdoutTask, stderrTask]);
    const { promise, resolve } = Promise.withResolvers<boolean>();
    const timer = setTimeout(() => resolve(true), timeoutMs);
    completed.then(() => resolve(false), () => resolve(true));
    const timedOut = await promise;
    clearTimeout(timer);
    if (timedOut && proc.pid > 0 && proc.pid !== process.pid) {
        // The leader may already have exited while descendants still hold its pipes.
        try { process.kill(-proc.pid, "SIGKILL"); } catch { /* group already gone */ }
        try { proc.kill("SIGKILL"); } catch { /* leader already reaped */ }
        stdoutCancel.run?.();
        stderrCancel.run?.();
    }
    const reap = Promise.withResolvers<Awaited<typeof completed> | null>();
    const reapTimer = setTimeout(() => reap.resolve(null), 1_000);
    completed.then(reap.resolve, () => reap.resolve(null));
    const result = await reap.promise;
    clearTimeout(reapTimer);
    return {
        argv0: argv[0] ?? "",
        code: timedOut || !result ? null : result[0],
        timedOut,
        reaped: !!result,
        stderrCategory: !result || result[2].text.trim() ? "present" : "empty",
        stdout: result?.[1].text.trim() ?? "",
        stdoutComplete: !timedOut && !!result?.[1].complete,
    };
}

function formatTeardownFailure(phase: string, result: TeardownCommandResult): string {
    const status = result.timedOut ? "timed out after bounded wait" : `exit ${result.code}`;
    return `${phase} ${result.argv0} ${status} stdout=${result.stdoutComplete ? "complete" : "incomplete"} stderr=${result.stderrCategory}`;
}

export interface AnvilProcessIdentity {
    exe: string;
    cwd: string;
    cmdline: string;
    starttime: string;
}

const LOCAL_ANVIL_RPCS: ReadonlyArray<{ network: L1DeploymentNetwork; relative: string; port: number }> = [
    { network: "localhost", relative: "db/anvil/state.json", port: 8545 },
    { network: "localhostBsc", relative: "db/anvil/localhostBsc/state.json", port: 9545 },
    { network: "localhostBase", relative: "db/anvil/localhostBase/state.json", port: 10545 },
];

async function tcpPortOpen(port: number): Promise<boolean> {
    const { promise, resolve } = Promise.withResolvers<boolean>();
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const done = (open: boolean) => { socket.destroy(); resolve(open); };
    socket.setTimeout(300);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    return promise;
}

function anvilFlagValues(args: readonly string[], name: string): string[] | null {
    const values: string[] = [];
    const prefix = `${name}=`;
    for (let index = 0; index < args.length; index += 1) {
        const token = args[index];
        if (token === name) {
            const value = args[index + 1];
            if (value === undefined || value.startsWith("--")) return null;
            values.push(value);
            index += 1;
        } else if (token.startsWith(prefix)) {
            values.push(token.slice(prefix.length));
        }
    }
    return values;
}

async function canonicalExistingAncestor(target: string): Promise<string | null> {
    const missing: string[] = [];
    let cursor = path.resolve(target);
    while (!(await exists(cursor))) {
        const parent = path.dirname(cursor);
        if (parent === cursor) return null;
        missing.push(cursor);
        cursor = parent;
    }
    let canonical: string;
    try { canonical = await fs.promises.realpath(cursor); }
    catch { return null; }
    for (const segment of missing.reverse()) canonical = path.join(canonical, path.basename(segment));
    return canonical;
}

/** Pure identity predicate: basename anvil, this checkout, one expected state, matching port. */
export async function isRepoAnvilProcess(processInfo: AnvilProcessIdentity, canonicalRepoRoot: string): Promise<boolean> {
    if (path.basename(processInfo.exe) !== "anvil") return false;
    let cwdReal: string;
    let exeReal: string;
    try {
        cwdReal = await fs.promises.realpath(processInfo.cwd);
        exeReal = await fs.promises.realpath(processInfo.exe);
    } catch {
        return false;
    }
    if (path.basename(exeReal) !== "anvil" || cwdReal !== canonicalRepoRoot) return false;
    const args = processInfo.cmdline.split("\0").filter((token) => token.length > 0);
    if (args.length === 0 || path.basename(args[0]) !== "anvil") return false;
    const states = anvilFlagValues(args, "--state");
    const ports = anvilFlagValues(args, "--port");
    if (!states || states.length !== 1 || !ports || ports.length !== 1) return false;
    const port = Number(ports[0]);
    const expected = LOCAL_ANVIL_RPCS.find((entry) => entry.port === port);
    if (!expected || !Number.isInteger(port)) return false;
    const stateReal = await canonicalExistingAncestor(path.resolve(canonicalRepoRoot, states[0]));
    const allowed = await canonicalExistingAncestor(path.resolve(canonicalRepoRoot, expected.relative));
    if (!stateReal || !allowed || stateReal !== allowed) return false;
    let cursor = path.resolve(canonicalRepoRoot, states[0]);
    while (true) {
        let link: fs.Stats;
        try { link = await fs.promises.lstat(cursor); }
        catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") {
                const parent = path.dirname(cursor);
                if (parent === cursor) break;
                cursor = parent;
                continue;
            }
            return false;
        }
        if (link.isSymbolicLink()) {
            let followed: string;
            try { followed = await fs.promises.realpath(cursor); }
            catch { return false; }
            const inside = followed === canonicalRepoRoot || followed.startsWith(`${canonicalRepoRoot}${path.sep}`);
            if (!inside) return false;
        }
        const parent = path.dirname(cursor);
        if (parent === cursor) break;
        cursor = parent;
    }
    return true;
}

async function readAnvilProcessIdentity(pid: number): Promise<AnvilProcessIdentity | null> {
    const base = `/proc/${pid}`;
    try {
        const [exe, cwd, cmdline, stat] = await Promise.all([
            fs.promises.readlink(`${base}/exe`),
            fs.promises.readlink(`${base}/cwd`),
            fs.promises.readFile(`${base}/cmdline`),
            fs.promises.readFile(`${base}/stat`, "utf8"),
        ]);
        const close = stat.lastIndexOf(")");
        const starttime = close >= 0 ? stat.slice(close + 2).split(" ")[19] : "";
        if (!starttime) return null;
        return { exe, cwd, cmdline: cmdline.toString("utf8"), starttime };
    } catch {
        return null;
    }
}

function processAncestors(pid: number): Set<number> {
    const ancestors = new Set<number>([pid]);
    let cursor = pid;
    for (let depth = 0; depth < 64; depth += 1) {
        let status = "";
        try { status = fs.readFileSync(`/proc/${cursor}/status`, "utf8"); }
        catch { break; }
        const match = /^PPid:\s+(\d+)$/m.exec(status);
        const parent = match ? Number(match[1]) : 0;
        if (!parent || ancestors.has(parent)) break;
        ancestors.add(parent);
        cursor = parent;
    }
    return ancestors;
}

async function listPids(): Promise<number[]> {
    const entries = await fs.promises.readdir("/proc");
    return entries.filter((entry) => /^\d+$/.test(entry)).map((entry) => Number(entry));
}

export interface PurgeAnvilControl {
    listPids?: () => Promise<number[]>;
    readIdentity?: (pid: number) => Promise<AnvilProcessIdentity | null>;
    signal?: (pid: number, signal: "SIGTERM" | "SIGKILL") => void;
    alive?: (pid: number) => boolean;
    portOpen?: (port: number) => Promise<boolean>;
}

export async function stopRepoAnvilsForPurge(repoRoot: string, control: PurgeAnvilControl = {}): Promise<void> {
    const canonicalRepoRoot = await fs.promises.realpath(repoRoot);
    const list = control.listPids ?? listPids;
    const readIdentity = control.readIdentity ?? readAnvilProcessIdentity;
    const signal = control.signal ?? ((pid, sig) => process.kill(pid, sig));
    const alive = control.alive ?? ((pid) => { try { process.kill(pid, 0); return true; } catch { return false; } });
    const portOpen = control.portOpen ?? tcpPortOpen;
    const protectedPids = processAncestors(process.pid);
    const owned: Array<{ pid: number; starttime: string }> = [];
    const failures: string[] = [];
    for (const pid of await list()) {
        if (protectedPids.has(pid)) continue;
        const identity = await readIdentity(pid);
        if (!identity || !(await isRepoAnvilProcess(identity, canonicalRepoRoot))) continue;
        const again = await readIdentity(pid);
        if (!again || again.starttime !== identity.starttime || again.exe !== identity.exe || again.cwd !== identity.cwd || again.cmdline !== identity.cmdline) {
            failures.push(`pid ${pid} identity changed before signal`);
            continue;
        }
        owned.push({ pid, starttime: again.starttime });
    }
    if (failures.length > 0) throw new Error(`[DevNet] Anvil identity preflight failed: ${failures.join("; ")}`);
    if (!control.portOpen) await discoverRepoAnvils(repoRoot);
    const stopOwned = async (sig: "SIGTERM" | "SIGKILL") => {
        for (const entry of owned) {
            const current = await readIdentity(entry.pid);
            if (!current) continue;
            if (current.starttime !== entry.starttime || !(await isRepoAnvilProcess(current, canonicalRepoRoot))) {
                failures.push(`pid ${entry.pid} reused before ${sig}`);
                continue;
            }
            try { signal(entry.pid, sig); }
            catch (error) {
                if (alive(entry.pid)) failures.push(`pid ${entry.pid} ${sig} failed: ${error instanceof Error ? error.message : String(error)}`);
            }
        }
    };
    await stopOwned("SIGTERM");
    const deadline = Date.now() + PURGE_ANVIL_SIGNAL_WAIT_MS;
    while (owned.some((entry) => alive(entry.pid)) && Date.now() < deadline) await Bun.sleep(50);
    if (owned.some((entry) => alive(entry.pid))) await stopOwned("SIGKILL");
    const killDeadline = Date.now() + PURGE_ANVIL_SIGNAL_WAIT_MS;
    while (owned.some((entry) => alive(entry.pid)) && Date.now() < killDeadline) await Bun.sleep(50);
    const residual: string[] = [];
    for (const entry of owned) {
        const current = await readIdentity(entry.pid);
        if (alive(entry.pid) && current?.starttime === entry.starttime) residual.push(String(entry.pid));
    }
    for (const chain of LOCAL_ANVIL_RPCS) {
        if (await portOpen(chain.port)) residual.push(`port ${chain.port}`);
    }
    if (failures.length > 0 || residual.length > 0) {
        throw new Error(`[DevNet] purge Anvil cleanup failed: ${[...failures, ...residual.map((item) => `still live ${item}`)].join("; ")}`);
    }
}

async function runBoundedTeardown(phase: string, argv: string[], cwd: string | undefined, failures: string[]): Promise<TeardownCommandResult> {
    try {
        const result = await runTeardownCommand(argv, cwd, PURGE_DOCKER_TIMEOUT_MS);
        if (result.timedOut || result.code !== 0 || !result.stdoutComplete) failures.push(formatTeardownFailure(phase, result));
        return result;
    } catch (error) {
        failures.push(`${phase} ${argv[0] ?? ""} spawn failed: ${error instanceof Error ? error.message : String(error)}`);
        return { argv0: argv[0] ?? "", code: null, timedOut: false, reaped: false, stderrCategory: "present", stdout: "", stdoutComplete: false };
    }
}
/** Explicit purge/fresh only: bounded stop, then force-remove the exact owned names.
 * A stop timeout is ignored only when that stop client was reaped and `docker rm -f` succeeded.
 * An unreaped stop client is fatal even if force-remove reports success. */
export async function removeOwnedContainersForPurge(
    containers: readonly string[],
    failures: string[],
    phase: string,
    run: (argv: string[], cwd: string | undefined, timeoutMs: number) => Promise<TeardownCommandResult> = runTeardownCommand,
): Promise<void> {
    if (containers.length === 0) return;
    const before = failures.length;
    const stop = await run(
        ["docker", "stop", "-t", String(PURGE_DOCKER_STOP_GRACE_SECONDS), ...containers],
        undefined,
        (PURGE_DOCKER_STOP_GRACE_SECONDS * 1_000) + 1_000,
    );
    try {
        const removed = await run(["docker", "rm", "-f", ...containers], undefined, PURGE_DOCKER_TIMEOUT_MS);
        if (removed.timedOut || removed.code !== 0 || !removed.stdoutComplete) failures.push(formatTeardownFailure(`${phase}-rm`, removed));
    } catch (error) {
        failures.push(`${phase}-rm docker spawn failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!stop.reaped || (failures.length > before && (stop.timedOut || stop.code !== 0))) failures.push(formatTeardownFailure(`${phase}-stop`, stop));
}


export function exactSnapshotNames(stdout: string): Set<string> {
    return new Set(stdout.split("\n").map((line) => line.trim()).filter((line) => line.length > 0));
}
async function purgeDockerCleanup(cwd: string, failures: string[]): Promise<boolean> {
    const containers = await runBoundedTeardown("docker-ps", ["docker", "ps", "-a", "--format", "{{.Names}}"], undefined, failures);
    const volumes = await runBoundedTeardown("volume-ls", ["docker", "volume", "ls", "--format", "{{.Name}}"], undefined, failures);
    if (containers.timedOut || containers.code !== 0 || !containers.stdoutComplete || volumes.timedOut || volumes.code !== 0 || !volumes.stdoutComplete) {
        return false;
    }
    const names = await resolveBoundDevnetNames(cwd);
    const containerTargets = [...devnetDbContainerNames(names), names.envioPostgresContainer, `${names.envioComposeProject}-graphql-engine-1`];
    const volumeTargets = [...devnetDbVolumeNames(names), names.envioDataVolume];
    const containerNames = exactSnapshotNames(containers.stdout);
    const volumeNames = exactSnapshotNames(volumes.stdout);
    const composeFile = path.join(cwd, "psy_cli", "psy_relayer_cli", "indexer", "envio", "generated", "docker-compose.yaml");
    const expected = new Set<string>(containerTargets);
    const liveContainers = containerTargets.filter((name) => containerNames.has(name));
    const liveVolumes = volumeTargets.filter((name) => volumeNames.has(name));
    if (liveContainers.length > 0) {
        await removeOwnedContainersForPurge(liveContainers, failures, "docker");
    }
    if (liveVolumes.length > 0) await runBoundedTeardown("volume-rm", ["docker", "volume", "rm", "-f", ...liveVolumes], undefined, failures);
    if (await exists(composeFile)) {
        await runBoundedTeardown("compose-down", envioComposeCommand(composeFile, names.envioComposeProject, ["down", "--remove-orphans", "-v"]), cwd, failures);
    }
    const containersAfter = await runBoundedTeardown("docker-ps-after", ["docker", "ps", "-a", "--format", "{{.Names}}"], undefined, failures);
    const volumesAfter = await runBoundedTeardown("volume-ls-after", ["docker", "volume", "ls", "--format", "{{.Name}}"], undefined, failures);
    if (containersAfter.timedOut || containersAfter.code !== 0 || !containersAfter.stdoutComplete || volumesAfter.timedOut || volumesAfter.code !== 0 || !volumesAfter.stdoutComplete) {
        return false;
    }
    const leftContainers = exactSnapshotNames(containersAfter.stdout);
    const leftVolumes = exactSnapshotNames(volumesAfter.stdout);
    for (const name of expected) if (leftContainers.has(name)) failures.push(`container ${name} still present`);
    for (const name of volumeTargets) if (leftVolumes.has(name)) failures.push(`volume ${name} still present`);
    return failures.length === 0;
}

async function knownApplicationsGone(failures: string[]): Promise<boolean> {
    const patterns = ["psy_node_cli", "psy_worker_cli", "psy_relayer_cli", "psy_user_cli prove-proxy", "psy_user_cli faucet-server", "psy-services", "psy-indexer", "hardhat node", "vite.js --host 0.0.0.0 --port 5179", "envio/bin.js"];
    const listed = await runBoundedTeardown("application-ps", ["ps", "-eo", "args="], undefined, failures);
    if (listed.timedOut || listed.code !== 0 || !listed.stdoutComplete) {
        return false;
    }
    const lines = listed.stdout.split("\n");
    const residual = patterns.filter((pattern) => lines.some((line) => line.includes(pattern)));
    const ports = [3000, 5433, 8080, 8081, 9898, 9998, 5174, 5175, 5176, 5177, 5178, 5179];
    for (let port = 1337; port <= 1346; port += 1) ports.push(port);
    for (const port of ports) if (await tcpPortOpen(port)) residual.push(`port ${port}`);
    if (residual.length > 0) failures.push(`applications still present: ${residual.join(", ")}`);
    return residual.length === 0;
}

async function purgeDevnet(cwd: string): Promise<void> {
    const failures: string[] = [];
    let anvilStopped = true;
    try { await stopRepoAnvilsForPurge(cwd); }
    catch (error) {
        anvilStopped = false;
        failures.push(error instanceof Error ? error.message : String(error));
    }
    const dockerClean = await purgeDockerCleanup(cwd, failures);
    const applicationsGone = await knownApplicationsGone(failures);
    console.log("[DevNet] Purging local checkpoints, Anvil state, logs, deployments, and Docker volumes...");
    const purgePaths = ["./local_checkpoints", "./db/anvil", "./logs", ...DEVNET_PURGE_PATHS.filter((entry) => entry.startsWith("psy-contracts/"))];
    if (anvilStopped && dockerClean && applicationsGone) {
        const root = await fs.promises.realpath(cwd);
        for (const relative of purgePaths) {
            const target = path.resolve(root, relative);
            try {
                const parent = await canonicalExistingAncestor(path.dirname(target));
                if (!parent || (parent !== root && !parent.startsWith(`${root}${path.sep}`))) {
                    throw new Error("parent resolves outside checkout");
                }
                await rm(target, { recursive: true, force: true });
            } catch (error) {
                failures.push(`delete ${relative}: ${error instanceof Error ? error.message : String(error)}`);
            }
        }
    } else failures.push("skipped deleting purge paths: cleanup was not proven");
    for (const chain of LOCAL_ANVIL_RPCS) {
        if (await tcpPortOpen(chain.port)) failures.push(`residual port ${chain.port}`);
    }
    for (const relative of purgePaths) {
        try {
            await fs.promises.lstat(path.resolve(cwd, relative));
            failures.push(`residual path ${relative}`);
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") failures.push(`cannot inspect residual path ${relative}`);
        }
    }
    if (failures.length > 0) throw new Error(`[DevNet] purge failed without startup: ${failures.join(" | ")}`);
}


async function killKnownProcesses(): Promise<void> {
    const patterns = [
        "bash dev/start_db.sh",
        "bun run dev/locSetupV4.ts",
        "psy_node_cli",
        "psy_worker_cli",
        "psy_relayer_cli",
        "psy_user_cli prove-proxy",
        "psy_user_cli faucet-server",
        "psy-services/target/release/psy-services",
        "psy-services/target/release/psy-indexer",
        "cargo run --release --bin psy-services",
        "cargo run --release --bin psy-indexer",

        "hardhat node",
        "dummy_prover.sh prove_random",
        "client_prover/psy_bridge",
        "client_prover/psy_privacy",
        "psy-dapp/apps/bridge",
        "psy-dapp/apps/ide",
        "psy-dapp/apps/explorer",
        "psy-dapp/apps/account",
        "vite.js --host 0.0.0.0 --port 5179",
        "pnpm dev",
        "envio/bin.js",
        "envio-linux",
        "generated/src/Index.res.js",
    ];
    for (const pattern of patterns) {
        await runIgnoreErrors([
            "bash",
            "-lc",
            `pgrep -f "${pattern}" 2>/dev/null | grep -vw $$ | grep -vw $PPID | xargs -r kill -9 2>/dev/null || true`,
        ]);
    }
}
const DEVNET_UI_LISTENER_APPS: Record<number, string> = { 5176: "ide", 5177: "bridge", 5178: "explorer", 5179: "account" };

export interface DevnetUiListenerControl {
    portOpen?: (port: number) => Promise<boolean>;
    listenerOwner?: (port: number) => Promise<number | null>;
    readIdentity?: (pid: number) => Promise<AnvilProcessIdentity | null>;
    readUid?: (pid: number) => Promise<number | null>;
    readPgrp?: (pid: number) => Promise<number | null>;
    signalGroup?: (pgrp: number, signal: "SIGTERM" | "SIGKILL") => void;
    leaderAlive?: (pgrp: number) => boolean;
    sleep?: (ms: number) => Promise<void>;
}
/** Node listener sharing this app cwd, led by that same node or the exact `bun run dev` wrapper. */
function ownedDevnetUiLeader(leader: AnvilProcessIdentity, listener: AnvilProcessIdentity, port: number): boolean {
    if (leader.cwd !== listener.cwd || path.basename(listener.exe) !== "node") return false;
    if (leader.exe === listener.exe) return true;
    if (path.basename(leader.exe) !== "bun") return false;
    const args = leader.cmdline.split("\0");
    if (args.at(-1) === "") args.pop();
    return args.length === 9
        && path.basename(args[0] ?? "") === "bun"
        && args[1] === "run" && args[2] === "dev" && args[3] === "--"
        && args[4] === "--host" && args[5] === "0.0.0.0"
        && args[6] === "--port" && args[7] === String(port)
        && args[8] === "--strictPort";
}


/** SIGTERM then SIGKILL only an owned node listener whose group leader is that node or the exact bun dev wrapper. */
export async function stopOwnedDevnetUiListeners(repoRoot: string, control: DevnetUiListenerControl = {}): Promise<void> {
    const canonical = await fs.promises.realpath(repoRoot);
    const appsRoot = `${canonical}${path.sep}psy-dapp${path.sep}apps${path.sep}`;
    const self = process.getuid?.() ?? null;
    const portOpen = control.portOpen ?? tcpPortOpen;
    const ownerOf = control.listenerOwner ?? tcpListenerOwner;
    const readIdentity = control.readIdentity ?? readAnvilProcessIdentity;
    const readUid = control.readUid ?? (async (pid: number) => {
        try {
            const status = await fs.promises.readFile(`/proc/${pid}/status`, "utf8");
            const uid = Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]);
            return Number.isInteger(uid) ? uid : null;
        } catch { return null; }
    });
    const readPgrp = control.readPgrp ?? (async (pid: number) => {
        try {
            const stat = await fs.promises.readFile(`/proc/${pid}/stat`, "utf8");
            const close = stat.lastIndexOf(")");
            const pgrp = Number(close >= 0 ? stat.slice(close + 2).split(" ")[2] : "");
            return Number.isInteger(pgrp) && pgrp > 1 ? pgrp : null;
        } catch { return null; }
    });
    const signalGroup = control.signalGroup ?? ((pgrp: number, signal: "SIGTERM" | "SIGKILL") => process.kill(-pgrp, signal));
    const leaderAlive = control.leaderAlive ?? ((pgrp: number) => { try { process.kill(pgrp, 0); return true; } catch { return false; } });
    const sleep = control.sleep ?? ((ms: number) => Bun.sleep(ms));
    const protectedPids = processAncestors(process.pid);
    const groups = new Map<number, { starttime: string; exe: string; cwd: string; uid: number }>();
    for (const [portText, app] of Object.entries(DEVNET_UI_LISTENER_APPS)) {
        const port = Number(portText);
        const appCwd = `${appsRoot}${app}`;
        if (!(await portOpen(port))) continue;
        let owner: number | null = null;
        try { owner = await ownerOf(port); }
        catch { throw new Error(`[DevNet] port ${port} listener owner is not attributable`); }
        if (owner === null || protectedPids.has(owner)) {
            throw new Error(`[DevNet] port ${port} listener is not an owned devnet UI process`);
        }
        const identity = await readIdentity(owner);
        const uid = await readUid(owner);
        const cwd = identity?.cwd ?? "";
        const owned = identity !== null && uid !== null && uid === self
            && path.basename(identity.exe) === "node"
            && (cwd === appCwd || cwd.startsWith(`${appCwd}${path.sep}`));
        if (!owned || identity === null) throw new Error(`[DevNet] port ${port} listener is not an owned devnet UI process`);
        const again = await readIdentity(owner);
        const uidAgain = await readUid(owner);
        if (!again || uidAgain !== uid || again.starttime !== identity.starttime || again.exe !== identity.exe || again.cwd !== identity.cwd) {
            throw new Error(`[DevNet] port ${port} owner changed before signal`);
        }
        const pgrp = await readPgrp(owner);
        if (pgrp === null || protectedPids.has(pgrp)) throw new Error(`[DevNet] port ${port} process group is not an owned devnet UI process`);
        const leader = await readIdentity(pgrp);
        const leaderUid = await readUid(pgrp);
        if (!leader || leaderUid !== uid || !ownedDevnetUiLeader(leader, identity, port)) {
            throw new Error(`[DevNet] port ${port} process group leader is not the owned listener context`);
        }
        const leaderAgain = await readIdentity(pgrp);
        if (!leaderAgain || leaderAgain.starttime !== leader.starttime || leaderAgain.exe !== leader.exe || leaderAgain.cwd !== leader.cwd) {
            throw new Error(`[DevNet] port ${port} process group leader changed before signal`);
        }
        const recorded = groups.get(pgrp);
        if (recorded && (recorded.starttime !== leader.starttime || recorded.exe !== leader.exe || recorded.cwd !== leader.cwd || recorded.uid !== uid)) {
            throw new Error(`[DevNet] devnet UI process group ${pgrp} has conflicting listeners`);
        }
        groups.set(pgrp, { starttime: leader.starttime, exe: leader.exe, cwd: leader.cwd, uid });
    }
    for (const [pgrp, expected] of groups) {
        const leader = await readIdentity(pgrp);
        const leaderUid = await readUid(pgrp);
        if (!leader || leaderUid !== expected.uid || leader.starttime !== expected.starttime || leader.exe !== expected.exe || leader.cwd !== expected.cwd) {
            throw new Error(`[DevNet] devnet UI process group ${pgrp} was reused before SIGTERM`);
        }
        try { signalGroup(pgrp, "SIGTERM"); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
    }
    const deadline = Date.now() + PURGE_ANVIL_SIGNAL_WAIT_MS;
    while (Date.now() < deadline && [...groups.keys()].some(leaderAlive)) await sleep(50);
    for (const [pgrp, expected] of groups) {
        if (!leaderAlive(pgrp)) continue;
        const leader = await readIdentity(pgrp);
        const leaderUid = await readUid(pgrp);
        if (!leader || leaderUid !== expected.uid || leader.starttime !== expected.starttime || leader.exe !== expected.exe || leader.cwd !== expected.cwd) {
            throw new Error(`[DevNet] devnet UI process group ${pgrp} was reused before SIGKILL`);
        }
        try { signalGroup(pgrp, "SIGKILL"); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
    }
}




async function teardownDevnet(cwd: string = ".", purge: boolean = false): Promise<void> {
    if (!purge) {
        await gracefulDevnetStop(cwd);
        return;
    }
    console.log(`
[DevNet] Tearing down... (purge)`);
    await stopOwnedDevnetUiListeners(cwd);
    await killKnownProcesses();
    await purgeDevnet(cwd);
}


function hexQuantityToBigInt(value: unknown, source: string): bigint {
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
        throw new Error(`[DevNet] ${source} returned ${JSON.stringify(value)}; expected a hex quantity`);
    }
    return BigInt(value);
}

interface GracefulStopControl {
    listPids?: () => Promise<number[]>;
    readIdentity?: (pid: number) => Promise<AnvilProcessIdentity | null>;
    signal?: (pid: number, signal: "SIGTERM") => void;
    alive?: (pid: number) => boolean;
    listenerOwner?: (port: number) => Promise<number | null>;
    listCheckoutProcesses?: (repoRoot: string) => Promise<string[]>;
    stopDocker?: (names: readonly string[]) => Promise<void>;
}

function anvilChainOf(identity: AnvilProcessIdentity): (typeof LOCAL_ANVIL_RPCS)[number] {
    const port = Number(anvilFlagValues(identity.cmdline.split("\0"), "--port")?.[0]);
    const chain = LOCAL_ANVIL_RPCS.find((entry) => entry.port === port);
    if (!chain) throw new Error(`[DevNet] discovered Anvil has no configured chain for port ${port}`);
    return chain;
}

function anvilIdentityMatches(current: AnvilProcessIdentity | null, expected: AnvilProcessIdentity): boolean {
    return current !== null && current.exe === expected.exe && current.cwd === expected.cwd
        && current.cmdline === expected.cmdline && current.starttime === expected.starttime;
}

async function tcpListenerOwner(port: number): Promise<number | null> {
    const hex = port.toString(16).padStart(4, "0").toUpperCase();
    const sockets = new Map<string, number>();
    for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
        let text = "";
        try { text = await fs.promises.readFile(table, "utf8"); }
        catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
            continue;
        }
        for (const line of text.split("\n").slice(1)) {
            const fields = line.trim().split(/\s+/);
            if (fields.length < 10 || fields[3] !== "0A") continue;
            const local = fields[1].split(":");
            if (local[1] !== hex) continue;
            sockets.set(fields[9], Number.parseInt(fields[7], 16));
        }
    }
    if (sockets.size === 0) return null;
    const owners = new Set<number>();
    for (const pid of await listPids()) {
        let fds: string[] = [];
        try { fds = await fs.promises.readdir(`/proc/${pid}/fd`); }
        catch { continue; }
        for (const fd of fds) {
            let link = "";
            try { link = await fs.promises.readlink(`/proc/${pid}/fd/${fd}`); }
            catch { continue; }
            const match = /^socket:\[(\d+)\]$/.exec(link);
            if (match && sockets.has(match[1])) owners.add(pid);
        }
    }
    if (owners.size !== 1) {
        throw new Error(`[DevNet] listener on port ${port} has ${owners.size === 0 ? "no attributable" : "ambiguous"} owner`);
    }
    return [...owners][0];
}

const CHECKOUT_PRODUCER_BASENAMES: Record<string, true> = {
    psy_node_cli: true, psy_worker_cli: true, psy_relayer_cli: true, psy_user_cli: true,
    "psy-services": true, "psy-indexer": true, node: true, bun: true, envio: true, "envio-linux": true,
};

/** Only the same-user, same-runtime CLI waiting for non-purge shutdown is not a producer. */
export function isGracefulShutdownControlClient(repoRoot: string, exe: string, cwd: string, argv: readonly string[], uid: number): boolean {
    if (exe !== process.execPath || cwd !== repoRoot || uid !== process.getuid?.()) return false;
    const args = argv.at(-1) === "" ? argv.slice(0, -1) : argv;
    const scriptIndex = args[1] === "run" ? 2 : 1;
    return args.length === scriptIndex + 2
        && path.resolve(cwd, args[scriptIndex] ?? "") === path.join(repoRoot, "dev/locSetupV4.ts")
        && args[scriptIndex + 1] === "--teardown";
}

async function listCheckoutProducerLines(repoRoot: string): Promise<string[]> {
    const found: string[] = [];
    const protectedPids = processAncestors(process.pid);
    const servicesRoot = await fs.promises.realpath(path.resolve(repoRoot, "../psy-services")).catch(() => null);
    for (const pid of await listPids()) {
        if (protectedPids.has(pid)) continue;
        let exe: string;
        let cwd: string;
        let argv: string[];
        let uid: number;
        try {
            const status = await fs.promises.readFile(`/proc/${pid}/status`, "utf8");
            uid = Number(/^Uid:\s+(\d+)/m.exec(status)?.[1] ?? NaN);
            const command = /^Name:\s+(.+)$/m.exec(status)?.[1] ?? "";
            // Linux comm is truncated; known runtime/interpreter candidates
            // must be attributable, unrelated system processes need not be.
            if (!Object.keys(CHECKOUT_PRODUCER_BASENAMES).some((name) => name.slice(0, 15) === command)
                && !["MainThread", "nodejs"].includes(command)) continue;
            [exe, cwd] = await Promise.all([
                fs.promises.readlink(`/proc/${pid}/exe`),
                fs.promises.readlink(`/proc/${pid}/cwd`),
            ]);
            argv = (await fs.promises.readFile(`/proc/${pid}/cmdline`, "utf8")).split("\0");
            if (isGracefulShutdownControlClient(repoRoot, exe, cwd, argv, uid)) continue;
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT" || (error as NodeJS.ErrnoException).code === "ESRCH") continue;
            throw new Error(`[DevNet] cannot attribute candidate process ${pid}; refusing non-purge shutdown`);
        }
        const basename = path.basename(exe).replace(/ \(deleted\)$/, "");
        const inside = cwd === repoRoot || cwd.startsWith(`${repoRoot}${path.sep}`);
        const sibling = servicesRoot !== null && (cwd === servicesRoot || cwd.startsWith(`${servicesRoot}${path.sep}`));
        const referencesCheckout = argv.some((arg) => arg === repoRoot || arg.startsWith(`${repoRoot}${path.sep}`));
        let mountedCheckout = false;
        if (CHECKOUT_PRODUCER_BASENAMES[basename] && cwd.startsWith("/app/")) {
            try {
                const [host, mounted] = await Promise.all([
                    fs.promises.stat(repoRoot), fs.promises.stat(`/proc/${pid}/root/app/workspace`),
                ]);
                mountedCheckout = host.dev === mounted.dev && host.ino === mounted.ino;
            } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
            }
        }
        if (((inside || mountedCheckout) && CHECKOUT_PRODUCER_BASENAMES[basename])
            || (sibling && ["psy-services", "psy-indexer"].includes(basename)
                && (referencesCheckout || await tcpListenerOwner(3000) === pid))) {
            found.push(`${pid} ${basename}`);
        }
    }
    return found;
}

async function assertCheckoutProducersStopped(repoRoot: string, control: GracefulStopControl): Promise<void> {
    const canonical = await fs.promises.realpath(repoRoot);
    const producers = await (control.listCheckoutProcesses ?? listCheckoutProducerLines)(canonical);
    if (producers.length > 0) throw new Error("[DevNet] checkout producers remain or cannot be safely attributed; refusing non-purge shutdown");
}

export async function discoverRepoAnvils(repoRoot: string, control: GracefulStopControl = {}): Promise<Array<{ pid: number; identity: AnvilProcessIdentity; chain: (typeof LOCAL_ANVIL_RPCS)[number] }>> {
    const canonicalRepoRoot = await fs.promises.realpath(repoRoot).catch(() => path.resolve(repoRoot));
    const list = control.listPids ?? listPids;
    const readIdentity = control.readIdentity ?? readAnvilProcessIdentity;
    const listenerOwner = control.listenerOwner ?? tcpListenerOwner;
    const found: Array<{ pid: number; identity: AnvilProcessIdentity; chain: (typeof LOCAL_ANVIL_RPCS)[number] }> = [];
    for (const pid of await list()) {
        if (processAncestors(process.pid).has(pid)) continue;
        const identity = await readIdentity(pid);
        if (!identity || !(await isRepoAnvilProcess(identity, canonicalRepoRoot))) continue;
        const chain = anvilChainOf(identity);
        if (found.some((entry) => entry.chain.port === chain.port)) {
            throw new Error(`[DevNet] more than one repo Anvil matches ${chain.network}`);
        }
        const owner = await listenerOwner(chain.port);
        if (owner !== pid) throw new Error(`[DevNet] ${chain.network} listener is not owned by discovered Anvil ${pid}`);
        found.push({ pid, identity, chain });
    }
    for (const chain of LOCAL_ANVIL_RPCS) {
        const owner = await listenerOwner(chain.port);
        if (owner === null) continue;
        if (!found.some((entry) => entry.pid === owner && entry.chain.port === chain.port)) {
            throw new Error(`[DevNet] occupied ${chain.network} listener is not the matching repo Anvil`);
        }
    }
    return found;
}

async function stopNamedDocker(names: readonly string[]): Promise<void> {
    const listed = await runTeardownCommand(["docker", "ps", "-a", "--format", "{{.Names}}"], undefined, PURGE_DOCKER_TIMEOUT_MS);
    if (listed.timedOut || listed.code !== 0 || !listed.stdoutComplete) throw new Error("[DevNet] cannot list containers before graceful stop");
    const present = exactSnapshotNames(listed.stdout);
    const live = names.filter((name) => present.has(name));
    if (live.length === 0) return;
    const proc = Bun.spawn(["docker", "stop", "-t", "-1", ...live], { stdin: "ignore", stdout: "ignore", stderr: "inherit" });
    const code = await proc.exited;
    if (code !== 0) throw new Error(`[DevNet] graceful docker stop failed with exit ${code}`);
}

/** Stop checkout producers, SIGTERM each exact repo Anvil, then stop namespace databases.
 * Anvil's own --state exit dump is the only retained L1 evidence. */
export async function gracefulDevnetStop(cwd: string, control: GracefulStopControl = {}): Promise<void> {
    const names = await resolveBoundDevnetNames(cwd);
    await assertCheckoutProducersStopped(cwd, control);
    const discovered = await discoverRepoAnvils(cwd, control);
    const readIdentity = control.readIdentity ?? readAnvilProcessIdentity;
    const listenerOwner = control.listenerOwner ?? tcpListenerOwner;
    const signal = control.signal ?? ((pid: number) => process.kill(pid, "SIGTERM"));
    const alive = control.alive ?? ((pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } });
    for (const entry of discovered) {
        const current = await readIdentity(entry.pid);
        if (!anvilIdentityMatches(current, entry.identity) || await listenerOwner(entry.chain.port) !== entry.pid) {
            throw new Error(`[DevNet] ${entry.chain.network} identity changed before SIGTERM`);
        }
        signal(entry.pid, "SIGTERM");
        while (alive(entry.pid)) {
            const again = await readIdentity(entry.pid);
            if (again && !anvilIdentityMatches(again, entry.identity)) {
                throw new Error(`[DevNet] ${entry.chain.network} pid was reused during shutdown`);
            }
            await Bun.sleep(50);
        }
        if (await listenerOwner(entry.chain.port) !== null) {
            throw new Error(`[DevNet] ${entry.chain.network} listener remained open after exit`);
        }
    }
    await (control.stopDocker ?? stopNamedDocker)([...devnetDbContainerNames(names), names.envioPostgresContainer, `${names.envioComposeProject}-graphql-engine-1`]);
}

export async function requestOwnedAnvilShutdown(repoRoot: string, purge: boolean): Promise<"owned" | "absent"> {
    const socketPath = devnetControlSocketPath(repoRoot);
    let stat: fs.Stats;
    try { stat = await fs.promises.stat(socketPath); }
    catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return "absent";
        throw error;
    }
    if (!stat.isSocket()) return "absent";
    try {
        await sendDevnetControlCommand(repoRoot, purge ? "shutdown-purge" : "shutdown");
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes("ECONNREFUSED") || message.includes("ENOENT")) return "absent";
        if (message.includes("unsupported command")) {
            throw new Error(`[DevNet] running supervisor at ${socketPath} does not support shutdown; restart it before PURGE=0 shutdown. Refusing to kill a live owner that cannot stop Anvil.`);
        }
        throw error;
    }
    return "owned";
}


interface ProcessOptions {
    all?: boolean;
    purge?: boolean;
    cwd?: string;
    jtmb?: boolean;
    l1Port?: number;
    workerRealmCount: number;
    realmEdgeCount: number;
    coordinatorEdgeCount: number;
    coordinatorWorkersCount: number;
    disableWorkerEdgeLogs?: boolean;
    startRealmId?: number;
    realmsCount?: number;
    coordinator?: boolean;
    db?: boolean;
    dummyProvers?: number;
    genesisDataPath?: string;
    proveProxyCount?: number;
    faucetServer?: boolean;
    l1?: boolean;
    relayer?: boolean;
    relayerConfig?: string;
    bridgeProposerDaemon?: boolean;
    bridgeUi?: boolean;
    privacyUi?: boolean;
    psyPrivacyBridge?: boolean;
    ide?: boolean;
    explorer?: boolean;
    modeAWebWalletBridge?: boolean;
    daemonlize?: boolean;
}
export const ROLLBACK_STOP_SENTINEL_CONTENT =
    "rollback offline: all processors and relayer stopped; Scylla Redis NATS and checkpoints retained";
export const ROLLBACK_STOP_SENTINEL_PATH = path.join("local_checkpoints", "rollback-stop.sentinel");

type ApplicationLifecycleState = "running" | "stopping" | "stopped" | "starting";

export function splitDevnetProcesses(processes: RunningProcess[]): { persistent: RunningProcess[]; applications: RunningProcess[] } {
    const persistent: RunningProcess[] = [];
    const applications: RunningProcess[] = [];
    for (const process of processes) {
        if (process.name === "db" || ["l1_anvil", "l1_anvil_bsc", "l1_anvil_base"].includes(process.name)) persistent.push(process);
        else applications.push(process);
    }
    return { persistent, applications };
}
function applicationStartRank(process: RunningProcess): number {
    const command = process.cmds.join(" ");
    if (command.includes("start-coordinator-processor")) return 0;
    if (command.includes("start-coordinator-edge")) return 1;
    if (command.includes("start-realm-processor")) return 2;
    if (command.includes("start-realm-edge")) return 3;
    if (command.includes("psy_worker_cli") || command.includes("dummy_prover")) return 4;
    if (command.includes("prove-proxy")) return 5;
    if (process.name.startsWith("envio")) return 6;
    if (process.name === "psy_services") return 7;
    if (process.name.startsWith("psy_indexer")) return 8;
    if (command.includes("faucet-server")) return 9;
    if (command.includes("guardian-service")) return 10;
    if (command.includes("psy_relayer_cli")) return 11;
    return 12;
}

function sortedApplicationProcesses(processes: RunningProcess[]): RunningProcess[] {
    return processes
        .map((process, index) => ({ process, index }))
        .sort((left, right) => applicationStartRank(left.process) - applicationStartRank(right.process) || left.index - right.index)
        .map(({ process }) => process);
}

export function applicationStartOrder(processes: RunningProcess[]): string[] {
    return sortedApplicationProcesses(processes).map((process) => process.name);
}
export function applicationListenerPorts(processes: RunningProcess[]): number[] {
    const ports = new Set<number>();
    for (const process of processes) {
        const command = process.cmds;
        if (process.guardianListener) ports.add(process.guardianListener.port);
        for (let index = 0; index < command.length - 1; index += 1) {
            if (command[index] === "--port") {
                const port = Number(command[index + 1]);
                if (Number.isInteger(port)) ports.add(port);
            }
            if (command[index] === "--listen-addr") {
                const port = Number(command[index + 1].split(":").at(-1));
                if (Number.isInteger(port)) ports.add(port);
            }
        }
        if (process.name === "psy_services") ports.add(3000);
        if (process.name.startsWith("envio")) ports.add(9898);
    }
    return [...ports].sort((left, right) => left - right);
}

async function waitForTcpPortsClosed(host: string, ports: number[], timeoutMs: number = 15_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    const openPorts = new Set(ports);
    while (openPorts.size > 0 && Date.now() < deadline) {
        for (const port of openPorts) {
            const connected = Promise.withResolvers<boolean>();
            const socket = net.createConnection({ host, port });
            const timeout = setTimeout(() => {
                socket.destroy();
                connected.resolve(false);
            }, 250);
            socket.once("connect", () => {
                clearTimeout(timeout);
                socket.end();
                connected.resolve(true);
            });
            socket.once("error", () => {
                clearTimeout(timeout);
                socket.destroy();
                connected.resolve(false);
            });
            if (!(await connected.promise)) openPorts.delete(port);
        }
        if (openPorts.size > 0) await Bun.sleep(100);
    }
    if (openPorts.size > 0) {
        throw new Error(`[DevNet][control] application ports remained open after stop: ${[...openPorts].join(", ")}`);
    }
}

export async function writeRollbackStopSentinel(cwd: string): Promise<string> {
    const sentinelPath = path.join(cwd, ROLLBACK_STOP_SENTINEL_PATH);
    await mkdir(path.dirname(sentinelPath), { recursive: true });
    await writeFile(sentinelPath, `${ROLLBACK_STOP_SENTINEL_CONTENT}\n`, "utf8");
    return sentinelPath;
}
async function stopEnvioIndexerProcess(): Promise<void> {
    await runIgnoreErrors([
        "bash",
        "-lc",
        "if command -v lsof >/dev/null 2>&1; then lsof -tiTCP:9898 -sTCP:LISTEN 2>/dev/null | xargs -r kill -TERM; elif command -v fuser >/dev/null 2>&1; then fuser -k 9898/tcp >/dev/null 2>&1 || true; fi",
    ]);
}

async function waitForProcessExit(process: RunningProcess): Promise<void> {
    if (process.hasExited) return;
    await process.proc.exited;
}
export class DevNetProcessManager {
    spawnedProcesses: RunningProcess[] = [];
    needsStartDb: boolean = false;
    private admittedNames: DevnetDbNames | null = null;
    private namespaceLock: DevnetLock | null = null;
    /** When true, exited children must not be auto-restarted (teardown/Ctrl+C). */
    private stopping: boolean = false;
    private applicationLifecycleState: ApplicationLifecycleState = "running";
    private pausedApplicationProcesses: RunningProcess[] = [];
    private freshState: FreshDevnetState | undefined;

    private async admitNamespace(cwd: string): Promise<DevnetDbNames> {
        // All local deployments share host ports. Hold this host-wide lock
        // through startup and supervision, not just the absence check.
        this.namespaceLock = await acquireDevnetLock("psy-devnet-host-resources");
        try {
            const names = await reserveDevnetNamespace(cwd, this.getEnv());
            this.envVars = { ...(this.envVars || {}), [DEVNET_NAMESPACE_ENV]: names.namespace ?? "" };
            this.admittedNames = names;
            return names;
        } catch (error) {
            this.namespaceLock.release();
            this.namespaceLock = null;
            throw error;
        }
    }

    async cleanupFailedSetup(cwd: string): Promise<void> {
        this.stopping = true;
        if (this.freshState) {
            await this.freshState.abort();
            this.freshState = undefined;
        }
        // Preflight/auto-setup failures confer no authority over any resources.
        // Leave artifacts for explicit recovery rather than discovering/killing
        // processes or containers that this invocation never started.
        if (!this.admittedNames) return;
        if (this.applicationLifecycleState === "running" || this.applicationLifecycleState === "stopping") {
            await this.stopApplications(cwd, false);
        }
        this.namespaceLock?.release();
        this.namespaceLock = null;
    }

    // Shared Config Constants
    private readonly NETWORK = "local-devnet";
    private readonly host: string;
    private readonly SCYLLA_URL: string;
    private readonly NATS_URL: string;
    private readonly REDIS_URL: string;
    private readonly COORD_API_URL: string;
    private genesisDataPath: string = "genesis.json";
    private envVars: { [key: string]: string } | undefined;
    private provingBackend: string | undefined;

    constructor(host: string = "127.0.0.1", envVars?: { [key: string]: string }, provingBackend?: string) {
        this.host = host;
        this.SCYLLA_URL = `${host}:9042`;
        this.NATS_URL = `nats://${host}:4222`;
        this.REDIS_URL = `redis://${host}:6379`;
        this.COORD_API_URL = `http://${host}:1337`;
        this.envVars = envVars;
        this.provingBackend = provingBackend;
    }

    private autoRestartEnabled(): boolean {
        return process.env.PSY_NO_AUTO_RESTART !== "1";
    }

    private isProcessorProcess(p: RunningProcess): boolean {
        return p.cmds.includes("start-coordinator-processor")
            || p.cmds.includes("start-realm-processor");
    }

    private restartProcessorsAfterDbRecovery(): void {
        for (const process of this.spawnedProcesses) {
            if (
                this.stopping
                || !this.autoRestartEnabled()
                || !this.isProcessorProcess(process)
                || process.dependencyRestartRequested
                || !process.isRunning()
            ) {
                continue;
            }
            process.dependencyRestartRequested = true;
            console.warn(
                `[DevNet][supervisor] DB recovered; restarting dependent processor '${process.name}' ` +
                `(pid=${process.pid}) to rebuild infrastructure connections`
            );
            process.signalProcessGroup("SIGTERM");
        }
    }

    private serviceNameFromCmds(cmds: string[], logFile?: string): string {
        if (logFile) {
            const base = path.basename(logFile).replace(/_logs\.txt$/i, "").replace(/\.txt$/i, "");
            if (base) return base;
        }
        const joined = cmds.join(" ");
        if (joined.includes("prove-proxy")) return "prove_proxy";
        if (joined.includes("faucet-server")) return "faucet_server";
        if (joined.includes("psy_relayer_cli")) return "bridge_relayer";
        if (joined.includes("start-coordinator-processor")) return "coordinator_processor";
        if (joined.includes("start-coordinator-edge")) return "coordinator_edge";
        if (joined.includes("start-realm-processor")) return "realm_processor";
        if (joined.includes("start-realm-edge")) return "realm_edge";
        if (joined.includes("psy_worker_cli")) return "worker";
        if (joined.includes("anvil")) return "l1_anvil";
        if (joined.includes("psy-services")) return "psy_services";
        if (joined.includes("psy-indexer")) return "psy_indexer";
        if (joined.includes("start_db")) return "db";
        return cmds[cmds.length - 1] || "process";
    }

    private track(p: RunningProcess, explicitName?: string): RunningProcess {
        const name = explicitName
            || p.name
            || this.serviceNameFromCmds(p.cmds, p.spawnOptions.stdoutLogFile);
        p.name = name;
        this.spawnedProcesses.push(p);
        this.wireAutoRestart(p);
        this.wireFatalProcessorSupervision(p);
        return p;
    }

    private wireAutoRestart(p: RunningProcess): void {
        if (!this.autoRestartEnabled()) return;
        if (!p.cmds.length) {
            console.warn(`[DevNet][supervisor] skip auto-restart wiring for unnamed process pid=${p.pid} (no cmds recorded)`);
            return;
        }
        const prevOnExit = p.onExit.bind(p);
        p.onExit = (code, signal) => {
            prevOnExit(code, signal);
            void this.handleSupervisedExit(p, code, signal);
        };
    }

    private wireFatalProcessorSupervision(p: RunningProcess): void {
        if (!this.autoRestartEnabled() || !this.isProcessorProcess(p)) return;
        const originalVisitor = p.allOutputVisitor;
        p.allOutputVisitor = (line: string, process: RunningProcess) => {
            const marker = parseFatalProcessorErrorMarker(line);
            if (marker !== null && process.fatalProcessorErrorMarker === null) {
                process.fatalProcessorErrorMarker = marker;
                process.fatalWitnessWrite = this.writeFatalWitnessThenTerminate(process, marker);
            }
            originalVisitor(line, process);
        };
    }

    private async writeFatalWitnessThenTerminate(
        process: RunningProcess,
        marker: FatalProcessorErrorMarker,
    ): Promise<void> {
        const witness =
            `[DevNet][supervisor][restart-failure] service=${process.name} ` +
            `cause=${failureSignature({ kind: "fatal-processor-error", marker })} ` +
            `marker=${marker} pid=${process.pid}`;
        console.warn(witness);
        try {
            await RunningProcess.appendLogBanner(process.spawnOptions.stdoutLogFile, witness);
            await RunningProcess.appendLogBanner(process.spawnOptions.stderrLogFile, witness);
        } catch (err) {
            console.warn(`[DevNet][supervisor] failed to write fatal witness for '${process.name}': ${err}`);
        }
        if (this.stopping || process.intentionalStop || process.hasExited) return;
        try {
            process.signalProcessGroup("SIGTERM");
        } catch (err) {
            console.warn(`[DevNet][supervisor] failed to signal fatal processor '${process.name}': ${err}`);
        }
    }

    private async handleSupervisedExit(
        previous: RunningProcess,
        code: number | null,
        signal: string | null,
        spawnFailed: boolean = false,
    ): Promise<void> {
        const name = previous.name || "process";
        if (this.stopping || previous.intentionalStop) {
            console.log(`[DevNet][supervisor] process '${name}' stopped intentionally (code=${code}, signal=${signal}, pid=${previous.pid})`);
            return;
        }
        if (!this.autoRestartEnabled()) {
            console.warn(`[DevNet][supervisor] process '${name}' exited (code=${code}, signal=${signal}); auto-restart disabled via PSY_NO_AUTO_RESTART=1`);
            return;
        }
        if (previous.fatalWitnessWrite) {
            try {
                await previous.fatalWitnessWrite;
            } catch (err) {
                console.warn(`[DevNet][supervisor] fatal witness write failed for '${name}': ${err}`);
            }
        }

        const nowMs = Date.now();
        const observedAtIso = new Date(nowMs).toISOString();
        const cause = classifySupervisedExit({
            spawnFailed,
            fatalProcessorErrorMarker: previous.fatalProcessorErrorMarker,
            dependencyRestartRequested: previous.dependencyRestartRequested,
            signalCode: signal,
            exitCode: code,
        });
        const plan = planSupervisedRestart({
            restartCount: previous.restartCount,
            streak: previous.restartStreak,
            cause,
            firstCause: previous.firstCausalStderr,
            healthySinceMs: spawnFailed ? 0 : previous.healthySinceMs,
            nowMs,
            observedAtIso,
        });
        previous.restartCount = plan.restartCount;
        previous.restartStreak = plan.streak;

        if (plan.action === "limit") {
            const first = plan.streak;
            const summary =
                `${SUPERVISOR_RESTART_LIMIT_TAG} service=${name} cause=${failureSignature(cause)} ` +
                `attempts=${first.identicalRepeats} first-observed-at=${first.firstObservedAtIso ?? ""}` +
                (first.firstCause ? ` first-cause=${first.firstCause}` : "");
            console.error(summary);
            try {
                await RunningProcess.appendLogBanner(previous.spawnOptions.stdoutLogFile, summary);
                await RunningProcess.appendLogBanner(previous.spawnOptions.stderrLogFile, summary);
            } catch (err) {
                console.warn(`[DevNet][supervisor] failed to write restart-limit summary for '${name}': ${err}`);
            }
            return;
        }

        console.warn(
            `[DevNet][supervisor] process '${name}' EXITED (code=${code}, signal=${signal}, pid=${previous.pid}); ` +
            `will RESTART in ${plan.delayMs}ms (restart #${plan.restartCount})`,
        );

        const delay = Promise.withResolvers<void>();
        setTimeout(delay.resolve, plan.delayMs);
        await delay.promise;
        if (!shouldScheduleSupervisedRestart(this.stopping, previous.intentionalStop)) {
            console.log(`[DevNet][supervisor] process '${name}' restart aborted (intentional stop or teardown)`);
            return;
        }

        const first = plan.streak;
        const firstPart = first.cause && first.firstObservedAtIso
            ? ` first-failure=${failureSignature(first.cause)}@${first.firstObservedAtIso}`
            : "";
        const firstCause = first.firstCause ? ` first-cause=${first.firstCause}` : "";
        const banner =
            `\n===== [DevNet supervisor] RESTART #${plan.restartCount} at ${observedAtIso} ` +
            `(previous exit code=${code}, signal=${signal}, previous pid=${previous.pid}) =====\n` +
            `===== service: ${name} =====\n` +
            `=====${firstPart}${firstCause} =====\n`;

        try {
            const restarted = await this.spawnFromTemplate(previous, banner, false);
            const idx = this.spawnedProcesses.indexOf(previous);
            if (idx >= 0) this.spawnedProcesses[idx] = restarted;
            else this.spawnedProcesses.push(restarted);
            this.wireAutoRestart(restarted);
            this.wireFatalProcessorSupervision(restarted);

            console.log(
                `[DevNet][supervisor] process '${name}' RESTARTED successfully ` +
                `(new pid=${restarted.pid}, restart #${plan.restartCount})`,
            );
            await RunningProcess.appendLogBanner(
                restarted.spawnOptions.stdoutLogFile,
                `[DevNet][supervisor] process '${name}' is UP again pid=${restarted.pid} restart #${plan.restartCount}\n`,
            );
            await RunningProcess.appendLogBanner(
                restarted.spawnOptions.stderrLogFile,
                `[DevNet][supervisor] process '${name}' is UP again pid=${restarted.pid} restart #${plan.restartCount}\n`,
            );
            if (name === "db") {
                this.restartProcessorsAfterDbRecovery();
            }
        } catch (err) {
            console.error(
                `[DevNet][supervisor] process '${name}' restart #${plan.restartCount} FAILED: ${err}`,
            );
            if (shouldScheduleSupervisedRestart(this.stopping, previous.intentionalStop)) {
                const retryDelay = nextSpawnRetryDelayMs(plan.delayMs);
                console.warn(
                    `[DevNet][supervisor] will retry '${name}' again in ${retryDelay}ms (still counting as restart #${plan.restartCount})`,
                );
                const spawnRetry = Promise.withResolvers<void>();
                setTimeout(spawnRetry.resolve, retryDelay);
                await spawnRetry.promise;
                if (!shouldScheduleSupervisedRestart(this.stopping, previous.intentionalStop)) {
                    console.log(`[DevNet][supervisor] process '${name}' spawn-retry aborted (intentional stop or teardown)`);
                    return;
                }
                previous.hasExited = true;
                previous.healthySinceMs = 0;
                void this.handleSupervisedExit(previous, code, signal, true);
            }
        }
    }

    private async spawnFromTemplate(
        template: RunningProcess,
        banner: string = `\n===== [DevNet supervisor] CONTROLLED START at ${new Date().toISOString()} =====\n`,
        track: boolean = true,
    ): Promise<RunningProcess> {
        await validateRelayerTemplate(template.cmds, template.spawnOptions);
        const options = { ...template.spawnOptions, appendLogs: true, logBanner: banner };
        const process = template.useInitHint && template.hintDetector
            ? await RunningProcess.spawnWithInitializationHintWithRetry(
                template.cmds,
                template.hintDetector,
                { ...options, maxRetries: template.initMaxRetries, retryDelayMs: template.initRetryDelayMs },
            )
            : await RunningProcess.spawn(template.cmds, options);
        process.name = template.name;
        process.restartCount = template.restartCount;
        process.restartStreak = template.restartStreak;
        process.hintDetector = template.hintDetector;
        process.useInitHint = template.useInitHint;
        process.initMaxRetries = template.initMaxRetries;
        process.initRetryDelayMs = template.initRetryDelayMs;
        if (!process.useInitHint) process.healthySinceMs = process.startedAtMs;
        return track ? this.track(process, template.name) : process;
    }
    private async waitForControlledStartDependency(process: RunningProcess): Promise<void> {
        if (process.name.startsWith("prove_proxy")) {
            const addressIndex = process.cmds.indexOf("--listen-addr");
            const port = Number(process.cmds[addressIndex + 1]?.split(":").at(-1));
            if (!Number.isInteger(port)) throw new Error(`[DevNet][control] ${process.name} has no valid listen port`);
            await waitForTcpPort(this.host, port, { attempts: 600, delayMs: 1000, timeoutMs: 1500, name: process.name });
        }
        if (process.name === "psy_services") {
            await waitForHttpUrl(`http://${this.host}:3000/health`, { attempts: 30, delayMs: 1000, timeoutMs: 1500, name: "psy-services health" });
        }
        if (process.name.startsWith("envio")) {
            await waitForTcpPort(this.host, 9898, { attempts: 600, delayMs: 1000, timeoutMs: 1500, name: "Envio Indexer API" });
        }
    }


    async stopApplications(cwd: string = ".", writeRollbackSentinel: boolean = false): Promise<void> {
        if (this.applicationLifecycleState !== "running" && this.applicationLifecycleState !== "stopping") {
            throw new Error(`[DevNet][control] cannot stop applications while state=${this.applicationLifecycleState}`);
        }
        const wasRunning = this.applicationLifecycleState === "running";
        this.applicationLifecycleState = "stopping";
        const { persistent, applications } = wasRunning
            ? splitDevnetProcesses(this.spawnedProcesses)
            : { persistent: this.spawnedProcesses, applications: this.pausedApplicationProcesses };
        this.pausedApplicationProcesses = applications;
        this.spawnedProcesses = persistent;
        try {
            if (wasRunning) {
                for (const process of applications) {
                    process.killWithSignal("SIGTERM");
                }
                await Promise.all(applications.map((process) => waitForProcessExit(process)));
            }
            await waitForTcpPortsClosed(this.host, applicationListenerPorts(applications));
            for (const process of applications) {
                if (process.guardianListener && process.guardianListener.host !== this.host) {
                    await waitForTcpPortsClosed(process.guardianListener.host, [process.guardianListener.port]);
                }
            }
            this.applicationLifecycleState = "stopped";
        } catch (error) {
            this.applicationLifecycleState = "stopping";
            throw error;
        }
        if (writeRollbackSentinel) {
            const sentinelPath = await writeRollbackStopSentinel(cwd);
            console.log(`[DevNet][control] rollback stop sentinel written to ${sentinelPath}`);
        }
        console.log(`[DevNet][control] stopped ${applications.length} application processes; DB and Anvil retained`);
    }

    async startApplications(cwd: string = "."): Promise<void> {
        if (this.applicationLifecycleState !== "stopped") {
            throw new Error(`[DevNet][control] cannot start applications while state=${this.applicationLifecycleState}`);
        }
        for (const template of this.pausedApplicationProcesses) await validateRelayerTemplate(template.cmds, template.spawnOptions);
        this.applicationLifecycleState = "starting";
        const templates = sortedApplicationProcesses(this.pausedApplicationProcesses);
        const started: RunningProcess[] = [];
        try {
            for (const template of templates) {
                template.restartCount = 0;
                template.restartStreak = emptyRestartStreak();
                template.fatalProcessorErrorMarker = null;
                template.firstCausalStderr = null;
                const process = await this.spawnFromTemplate(template);
                started.push(process);
                await this.waitForControlledStartDependency(process);
            }
            this.pausedApplicationProcesses = [];
            this.applicationLifecycleState = "running";
            await rm(path.join(cwd, ROLLBACK_STOP_SENTINEL_PATH), { force: true });
            console.log(`[DevNet][control] restarted ${templates.length} application processes; DB and Anvil unchanged`);
        } catch (error) {
            for (const process of started) {
                process.killWithSignal("SIGTERM");
            }
            await Promise.all(started.map((process) => waitForProcessExit(process)));
            this.spawnedProcesses = this.spawnedProcesses.filter((process) => !started.includes(process));
            this.applicationLifecycleState = "stopped";
            throw error;
        }
    }

    async restartApplications(cwd: string = "."): Promise<void> {
        const { persistent, applications } = splitDevnetProcesses(this.spawnedProcesses);
        const required = ["db", "l1_anvil", "l1_anvil_bsc", "l1_anvil_base"];
        const missing = required.filter((name) => !persistent.some((process) => process.name === name && process.isRunning()));
        if (missing.length > 0) {
            throw new Error(`[DevNet][control] restart requires running infrastructure; missing ${missing.join(", ")}`);
        }
        for (const template of applications) await validateRelayerTemplate(template.cmds, template.spawnOptions);
        await this.stopApplications(cwd, false);
        await this.startApplications(cwd);
    }

    private getEnv(): { [key: string]: string } {
        const namespace = process.env[DEVNET_NAMESPACE_ENV];
        return { ...process.env, ...this.envVars, PSY_NETWORK: selectedRuntimeConfigKey(this.NETWORK), ...(namespace ? { [DEVNET_NAMESPACE_ENV]: namespace } : {}) } as { [key: string]: string };
    }
    private getEnvWithRustLogDirective(directive: string): { [key: string]: string } {
        const env = this.getEnv() || { ...process.env } as { [key: string]: string };
        const current = env["RUST_LOG"]?.trim();
        if (!current) return { ...env, RUST_LOG: directive };
        const directives = current.split(",").map((value) => value.trim()).filter(Boolean);
        if (directives.some((value) => value === directive || value.startsWith(`${directive.split("=")[0]}=`) || value === directive.split("=")[0])) return env;
        return { ...env, RUST_LOG: `${current},${directive}` };
    }


    async startGuardianServices(cwd: string, daemonConfigPath: string, l1ConfigArgs: readonly string[]): Promise<void> {
        const config = Bun.TOML.parse(await fs.promises.readFile(daemonConfigPath, "utf8"));
        const rpcConfig = path.resolve(cwd, config.rpc_config as string);
        const guardianRoot = await resolveGuardianRoot(cwd, String(config.guardian_root ?? ""));
        const guardianEnv = this.getEnvWithRustLogDirective('psy_relayer_cli=info');
        await assertGuardianKeystoresPresent(guardianEnv);
        // All three guardians launch concurrently; each spawn blocks on its own 600s
        // HTTP readiness budget and kills its own child when readiness fails. Every
        // successful child is tracked immediately so a failing sibling cannot orphan
        // it; on any failure the still-running children are killed and awaited before
        // startup fails. The relayer therefore starts only after all three are ready.
        const started: RunningProcess[] = [];
        const results = await Promise.allSettled([1, 2, 3].map((id) => (async () => {
            const name = `guardian_${id}`;
            const process = await RunningProcess.spawn([
                './target/release/psy_relayer_cli', 'guardian-service',
                '--rpc-config', rpcConfig, '--guardian-root', guardianRoot,
                ...l1ConfigArgs, '--guardian-id', String(id),
            ], {
                cwd,
                stdoutLogFile: path.join(cwd, 'logs', `${name}_logs.txt`),
                stderrLogFile: path.join(cwd, 'logs', `${name}_errs.txt`),
                env: guardianEnv,
            });
            started.push(process);
            return this.track(process, name);
        })()));
        const failure = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
        if (failure) {
            for (const process of started) process.killWithSignal("SIGTERM");
            await Promise.all(started.map((process) => waitForProcessExit(process)));
            this.spawnedProcesses = this.spawnedProcesses.filter((process) => !started.includes(process));
            throw failure.reason;
        }
    }

    async setupProcesses(options: ProcessOptions): Promise<void> {

        const cwd = options?.cwd || ".";
        const relayer = !!options.relayer || !!options.bridgeProposerDaemon;
        const hasOnlyOptions = !!options.db || !!options.coordinator || (options.proveProxyCount || 0) > 0 || !!options.faucetServer || (options.dummyProvers || 0) > 0 || !!options.l1 || relayer || !!options.bridgeUi || !!options.privacyUi || !!options.psyPrivacyBridge || !!options.ide || !!options.explorer || !!options.modeAWebWalletBridge;
        const startAll = options.all ?? !hasOnlyOptions;
        const jtmb = !!options?.jtmb;
        const l1Port = options.l1Port ?? 8545;
        const { stage, l1Network, l1Fork, cfgEntry } = resolveL1Selection();
        const deploymentsNetwork: L1NetworkName = l1Fork ? "localhost" : l1Network;
        const localL1RpcUrl = resolveLocalL1RpcUrl(l1Port);
        const l1RpcUrl = (l1Network === "localhost" || l1Fork) ? localL1RpcUrl : resolveExternalL1RpcUrl(l1Network, cfgEntry, stage);
        const relayerChains = resolveActiveL1Chains(l1Network, l1Fork, l1RpcUrl);
        const workerRealmCount = options.workerRealmCount;
        const realmEdgeCount = options.realmEdgeCount;
        const coordinatorEdgeCount = options.coordinatorEdgeCount;
        const coordinatorWorkersCount = options.coordinatorWorkersCount;
        this.genesisDataPath = options.genesisDataPath || "genesis.json";
        const skipBuild = skipBuildEnabled();
        const disableWorkerEdgeLogs = !!options.disableWorkerEdgeLogs;
        const startBridgeProposerDaemon = shouldRequireGuardianRoot(startAll, options);
        const daemonConfigPath = startBridgeProposerDaemon
            ? await resolveBridgeDaemonConfigPath(cwd, this.getEnv(), startAll || !!options.purge)
            : undefined;

        const startCoordinatorProcessor = startAll || !!options.coordinator;
        const startCoordinatorWorkers = coordinatorWorkersCount > 0;
        const startRealmProcessor = startAll || !!options.coordinator;
        const startRealmWorkers = workerRealmCount > 0;

        const needsStartDb = startAll || !!options.db;
        const startRealmId = options.startRealmId || 0;
        const realmsCount = options.realmsCount !== undefined ? options.realmsCount : (startAll ? 1 : 1);
        const prepareRealmP2p = shouldPrepareRealmP2p(startCoordinatorProcessor, startRealmProcessor);
        if (prepareRealmP2p) validateRealmP2pPorts(startRealmId, realmsCount, realmEdgeCount);
        const endRealmId = startRealmId + realmsCount - 1;
        const provingProcessCount = coordinatorWorkersCount
            + workerRealmCount
            + (options.dummyProvers || 0)
            + (options.proveProxyCount ?? (startAll ? 1 : 0));
        const runtimeResources = await resolveRuntimeResourceSettings(
            this.getEnv() || { ...process.env } as { [key: string]: string },
            provingProcessCount,
            needsStartDb,
        );
        this.envVars = { ...(this.envVars || {}), ...runtimeResources.env };
        runtimeCpuSetForChildren = runtimeResources.runtimeCpuSet;
        if (runtimeResources.runtimeCpuSet) {
            await checkToolAvailable("taskset", "install the util-linux package");
            console.log(
                `[DevNet] CPU partition: Scylla=${runtimeResources.scyllaCpuSet}, ` +
                `runtime=${runtimeResources.runtimeCpuSet}, Scylla SMP=${runtimeResources.scyllaSmp}, ` +
                `Rayon threads=${runtimeResources.env.RAYON_NUM_THREADS}`,
            );
        } else {
            console.log(
                `[DevNet] CPU affinity unavailable or not requested on ${process.platform}; ` +
                `using concurrency limits only (Rayon threads=${runtimeResources.env.RAYON_NUM_THREADS})`,
            );
        }

        this.needsStartDb = needsStartDb;

        const logsDir = path.join(cwd, "logs");
        await mkdir(logsDir, { recursive: true });

        const getLogPaths = (baseName: string, isWorkerOrEdge: boolean) => {
            if (isWorkerOrEdge && disableWorkerEdgeLogs) return {};
            return {
                stdoutLogFile: path.join(logsDir, `${baseName}_logs.txt`),
                stderrLogFile: path.join(logsDir, `${baseName}_errs.txt`),
            };
        };

        const backend = this.provingBackend || (jtmb ? 'jtmb-poseidon-goldilocks' : 'plonky2-poseidon-goldilocks');

        // 1. Build (skip if binaries exist)
        const psyNodeCliPath = path.join(cwd || '.', 'target/release/psy_node_cli');
        const psyWorkerCliPath = path.join(cwd || '.', 'target/release/psy_worker_cli');
        const psyRelayerCliPath = path.join(cwd || '.', 'target/release/psy_relayer_cli');
        const parthRuntimeBinaries = [
            { name: "psy_node_cli", path: psyNodeCliPath },
            { name: "psy_worker_cli", path: psyWorkerCliPath },
            { name: "psy_relayer_cli", path: psyRelayerCliPath },
        ];
        const missingParthRuntimeBinary = (
            !(await exists(psyNodeCliPath))
            || !(await exists(psyWorkerCliPath))
            || !(await exists(psyRelayerCliPath))
        );
        if (missingParthRuntimeBinary) {
            if (skipBuild) {
                await requireReleaseBinaries(parthRuntimeBinaries);
            } else {
                await buildProject(cwd);
            }
        } else {
            console.log("Binaries already exist, skipping build...");
        }
        if (startAll) {
            if (stage !== "localhost" || l1Network !== "localhost" || l1Fork || options.daemonlize
                || path.resolve(cwd, this.genesisDataPath) !== path.resolve(cwd, "genesis.json")) {
                throw new Error("[DevNet] full fresh startup requires foreground localhost, no fork, and the canonical genesis.json");
            }
            await ensureGenesisFiles(cwd, this.getEnv(), true);
            await ensurePsyContractsDependencies(path.join(cwd, "psy-contracts"));
            await assertCheckoutProducersStopped(cwd, {});
            await discoverRepoAnvils(cwd);
            await loadBridgeRelayerSigner(cwd);
        }
        const names = await this.admitNamespace(cwd);
        if (this.needsStartDb) await resolveScyllaIoProperties(this.getEnv().SCYLLA_IO_PROPERTIES);
        if (startAll && daemonConfigPath) {
            const daemon = Bun.TOML.parse(await fs.promises.readFile(daemonConfigPath, "utf8"));
            const guardianRoot = await resolveGuardianRoot(cwd, daemon.guardian_root as string);
            const reset = await planScopedDevnetReset(names);
            this.freshState = await prepareFreshDevnetState(cwd, guardianRoot, this.getEnv());
            await resetScopedDevnetState(cwd, reset);
            await this.freshState.reset();
            await ensureGenesisFiles(cwd, this.getEnv());
        }

        if (this.needsStartDb) {
            const startDbCmd = ['./dev/start_db.sh', '--fresh'];
            await this.track(
                await RunningProcess.spawnWithInitializationHint(
                    startDbCmd, dbStartedDetector, { cwd, ...getLogPaths("db", false), env: this.getEnv() }
                ),
                "db"
            );
            console.log("[DevNet] Waiting for infrastructure ports to accept connections...");
            await waitForTcpPort(this.host, 6379, { attempts: 30, delayMs: 500, timeoutMs: 1500, name: "Valkey/Redis" });
            await waitForTcpPort(this.host, 4222, { attempts: 30, delayMs: 500, timeoutMs: 1500, name: "NATS" });
            await waitForTcpPort(this.host, 9042, { attempts: 30, delayMs: 500, timeoutMs: 1500, name: "Scylla" });
            console.log("[DevNet] Infrastructure is ready.");
        }

        const nodeCli = './target/release/psy_node_cli';
        const workerCli = './target/release/psy_worker_cli';
        const realmP2pSubIds: readonly number[] = REALM_P2P_SUB_IDS;
        let realmP2pConfig: FullNetworkConfig | null = null;
        if (prepareRealmP2p) {
            const allRealmIds = Array.from({ length: realmsCount }, (_, i) => startRealmId + i);
            realmP2pConfig = await ensureRealmP2pConfig(nodeCli, cwd, allRealmIds, realmEdgeCount, this.host, path.join(cwd, this.genesisDataPath));
            this.envVars = { ...this.envVars, PSY_CONFIG_PATH: `${REALM_P2P_OUT_DIR}/config.json`, PSY_NETWORK: realmP2pConfig.defaultNetwork };
            await injectGenesisValidators(path.join(cwd, this.genesisDataPath), realmP2pConfig);
        }

        // Prove proxy Groth16 preload is independent of Coordinator RPC.
        // Spawn immediately after realm/genesis prep, then wait for :9999
        // before core so processor startup is not concurrent with preload.
        const proveProxyReady: Promise<void>[] = [];
        const proveProxyCount = options.proveProxyCount ?? (startAll ? 1 : 0);
        if (proveProxyCount > 0) {
            const count = proveProxyCount;
            for (let i = 0; i < count; i++) {
                const port = 9999 + i;
                const proveProxyProc = await RunningProcess.spawnWithInitializationHintWithRetry(
                    [
                        './target/release/psy_user_cli',
                        'prove-proxy',
                        '--listen-addr',
                        `0.0.0.0:${port}`,
                        '--rpc-config',
                        'psy-genesis/config.json',
                        '--role',
                        'all',
                    ],
                    proveProxyStartedDetector,
                    { cwd, ...getLogPaths(`prove_proxy_${i}`, false), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                );
                this.track(proveProxyProc);
                proveProxyReady.push(
                    waitForTcpPort('127.0.0.1', port, {
                        attempts: 600,
                        delayMs: 1000,
                        timeoutMs: 1500,
                        name: `Prove proxy ${i}`,
                    }).then(() => {
                        console.log(`[DevNet] Prove proxy instance ${i} started on port ${port}`);
                    }),
                );
                console.log(`[DevNet] Prove proxy instance ${i} process started; continuing while Groth16 warms on port ${port}`);
            }
        }
        const waitForProveProxy = async (reason: string): Promise<void> => {
            if (proveProxyReady.length === 0) return;
            console.log(`[DevNet] Waiting for prove-proxy listen before ${reason}...`);
            await Promise.all(proveProxyReady);
        };
        await waitForProveProxy("coordinator processor");



        // 3. Coordinator Processor
        if (startCoordinatorProcessor) {
            const coordinatorLogPaths = getLogPaths("coordinator_processor", false);
            const coordinatorProcessor = await retryProcessorStartup(
                "coordinator processor",
                (attempt, totalAttempts) => RunningProcess.spawnWithInitializationHint(
                    [
                        nodeCli, 'start-coordinator-processor',
                        '--coordinator-id', '0',
                        '--coordinator-sub-id', '0',
                        '--network', this.NETWORK,
                        '--db-namespace', 'coordinator',
                        '--scylla-db-url', this.SCYLLA_URL,
                        '--nats-jetstream-url', this.NATS_URL,
                        '--redis-url', this.REDIS_URL,
                        '--genesis-data-path', this.genesisDataPath,
                        '--checkpoint-backup-path', './local_checkpoints',
                        '--proving-backend', backend,
                        '--verbose'
                    ],
                    (line) => isExactProcessorReadyLine(line, COORDINATOR_PROCESSOR_READY_MARKER),
                    {
                        cwd,
                        ...coordinatorLogPaths,
                        initializationTimeoutMs: 120_000,
                        env: this.getEnv(),
                        appendLogs: attempt > 1,
                        logBanner: `===== coordinator processor readiness attempt ${attempt}/${totalAttempts} =====`,
                    },
                ),
                { maxRetries: 3, retryDelayMs: 2000 },
            );
            this.track(coordinatorProcessor);

            // 4. Coordinator Edges (Scalable)
            const coordEdgePromises: Promise<RunningProcess>[] = [];
            for (let j = 0; j < coordinatorEdgeCount; j++) {
                const port = 1337 + j;
                const edgePromise = RunningProcess.spawnWithInitializationHintWithRetry(
                    [
                        nodeCli, 'start-coordinator-edge',
                        '--coordinator-id', '0',
                        '--coordinator-sub-id', '0',
                        '--network', this.NETWORK,
                        '--db-namespace', 'coordinator',
                        '--scylla-db-url', this.SCYLLA_URL,
                        '--nats-jetstream-url', this.NATS_URL,
                        '--redis-url', this.REDIS_URL,
                        '--port', port.toString(),
                        '--listen', '0.0.0.0',
                        '--proving-backend', backend,
                        '--verbose',
                    ],
                    coordinatorEdgeProcessorStartedDetector,
                    { cwd, ...getLogPaths(`coordinator_edge_${j}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                ).then(proc => this.track(proc));
                coordEdgePromises.push(edgePromise);
            }
            await Promise.all(coordEdgePromises);
        }
        const startCoordinatorWorkerProcesses = async (): Promise<void> => {
            if (!startCoordinatorWorkers || coordinatorWorkersCount === 0) return;

            for (let i = 0; i < coordinatorWorkersCount; i++) {
                const coordinatorUrls: string[] = [];
                for (let edgeIndex = 0; edgeIndex < coordinatorEdgeCount; edgeIndex++) {
                    coordinatorUrls.push(`http://${this.host}:${1337 + edgeIndex}`);
                }

                const workerArgs = [
                    workerCli, 'worker',
                    '--user', '0',
                    '--network', this.NETWORK,
                    '--proving-backend', backend,
                    '--completed-jobs-log-file', `./local_checkpoints/coordinator_worker_${i}.backup`,
                    '--batch-size', runtimeResources.workerBatchSize,
                ];
                for (const coordinatorUrl of coordinatorUrls) {
                    workerArgs.push('--coordinator-api-url', coordinatorUrl);
                }
                workerArgs.push('--private-key', FAKE_MINER_PRIVATE_KEY);

                await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                    workerArgs,
                    workerStartedDetector,
                    { cwd, ...getLogPaths(`coordinator_worker_${i}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                ));
            }
        };
        await startCoordinatorWorkerProcesses();

        let processorReadiness: Promise<void> = Promise.resolve();

        if (startRealmProcessor) {
            const activeRealmP2pConfig = realmP2pConfig;
            if (!activeRealmP2pConfig) throw new Error("Realm P2P config was not prepared for Realm startup");
            processorReadiness = (async () => {
                console.log(`[DevNet] Starting ${realmsCount} realms with two validators each...`);
                for (let b = 0; b < realmsCount; b += 4) {
                    const batchSize = Math.min(4, realmsCount - b);
                    const realmIds = Array.from(
                        { length: batchSize },
                        (_, i) => startRealmId + b + i,
                    );

                    for (const subId of realmP2pSubIds) {
                        await startRealmProcessorBatchSequentially(
                            realmIds,
                            async (realmId) => {
                                const logName = `realm_${realmId}_sub_${subId}_processor`;
                                const realmLogPaths = getLogPaths(logName, false);
                                selectedRealm(activeRealmP2pConfig, realmId).validators[subId - 1];
                                const extra = realmP2pProcessorExtraArgs(this.host, realmId, subId);
                                const proc = await retryProcessorStartup(
                                    `realm ${realmId} sub ${subId} processor`,
                                    (attempt, totalAttempts) => RunningProcess.spawnWithInitializationHint(
                                        [
                                            nodeCli, 'start-realm-processor',
                                            '--realm-id', realmId.toString(),
                                            '--network', this.NETWORK,
                                            '--db-namespace', realmDbNamespace(realmId, subId),
                                            '--scylla-db-url', this.SCYLLA_URL,
                                            '--nats-jetstream-url', this.NATS_URL,
                                            '--redis-url', this.REDIS_URL,
                                            '--genesis-data-path', this.genesisDataPath,
                                            '--checkpoint-backup-path', './local_checkpoints',
                                            '--coordinator-api-urls', this.COORD_API_URL,
                                            '--proving-backend', backend,
                                            '--verbose',
                                            ...extra,
                                        ],
                                        (line) => isExactProcessorReadyLine(line, REALM_PROCESSOR_READY_MARKER),
                                        {
                                            cwd,
                                            ...realmLogPaths,
                                            initializationTimeoutMs: 180_000,
                                            env: this.getEnv(),
                                            appendLogs: attempt > 1,
                                            logBanner: `===== realm ${realmId} sub ${subId} processor readiness attempt ${attempt}/${totalAttempts} =====`,
                                        },
                                    ),
                                    { maxRetries: 3, retryDelayMs: 2000 },
                                );
                                this.track(proc);
                                return proc;
                            },
                        );
                    }
                    console.log(`[DevNet] Batch ${b/4 + 1} realm processors finished genesis initialization.`);

                    const realmEdgesPromises: Promise<RunningProcess>[] = [];
                    for (let i = 0; i < batchSize; i++) {
                        const realmId = startRealmId + b + i;
                        for (const subId of realmP2pSubIds) {
                            for (let j = 0; j < realmEdgeCount; j++) {
                                const port = realmP2pHttpPort(realmId, subId, j, realmEdgeCount);
                                selectedRealm(activeRealmP2pConfig, realmId).validators[subId - 1];
                                const extra = realmP2pEdgeExtraArgs(this.host, realmId, subId, j, realmEdgeCount);
                                const logName = `realm_${realmId}_sub_${subId}_edge_${j}`;
                                const edgePromise = RunningProcess.spawnWithInitializationHintWithRetry(
                                    [
                                        nodeCli, 'start-realm-edge',
                                        '--realm-id', realmId.toString(),
                                        '--network', this.NETWORK,
                                        '--db-namespace', realmDbNamespace(realmId, subId),
                                        '--scylla-db-url', this.SCYLLA_URL,
                                        '--nats-jetstream-url', this.NATS_URL,
                                        '--redis-url', this.REDIS_URL,
                                        '--port', port.toString(),
                                        '--listen', '0.0.0.0',
                                        '--proving-backend', backend,
                                        '--verbose',
                                        ...extra,
                                    ],
                                    realmEdgeProcessorStartedDetector,
                                    { cwd, ...getLogPaths(logName, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                                ).then(proc => this.track(proc));
                                realmEdgesPromises.push(edgePromise);
                            }
                        }
                    }
                    await Promise.all(realmEdgesPromises);
                    console.log(`[DevNet] Batch ${b/4 + 1} realm edges started. Waiting 2 seconds before starting next batch...`);
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
                console.log(`[DevNet] All realm processors and edges started`);
            })();
        }

        await processorReadiness;

        if (startRealmWorkers) {
            const workerPromises: Promise<RunningProcess>[] = [];

            if (workerRealmCount <= realmsCount) {
                // Workers <= realms: distribute realms across workers using ranges
                const realmsPerWorker = Math.ceil(realmsCount / workerRealmCount);
                console.log(`[DevNet] Starting ${workerRealmCount} workers, ${realmsPerWorker} realms per each worker (${realmsCount} total realms)...`);

                for (let workerId = 0; workerId < workerRealmCount; workerId++) {
                    const startRealmForWorker = workerId * realmsPerWorker;
                    const endRealmForWorker = Math.min((workerId + 1) * realmsPerWorker, realmsCount);

                    const realmUrls: string[] = [];
                    for (let realmIndex = startRealmForWorker; realmIndex < endRealmForWorker; realmIndex++) {
                        const realmId = startRealmId + realmIndex;
                        for (const subId of realmP2pSubIds) {
                            for (let edgeIndex = 0; edgeIndex < realmEdgeCount; edgeIndex++) {
                                realmUrls.push(`http://${this.host}:${realmP2pHttpPort(realmId, subId, edgeIndex, realmEdgeCount)}`);
                            }
                        }
                    }

                    const workerArgs = [
                        workerCli, 'worker',
                        '--user', '0',  // shared user id
                        '--network', this.NETWORK,
                        '--proving-backend', backend,
                        '--completed-jobs-log-file', `./local_checkpoints/realm_worker_${workerId}.backup`,
                        '--batch-size', runtimeResources.workerBatchSize,
                    ];

                    for (const realmUrl of realmUrls) {
                        workerArgs.push('--realm-api-url', realmUrl);
                    }

                    workerArgs.push('--private-key', FAKE_MINER_PRIVATE_KEY);

                    const workerPromise = RunningProcess.spawnWithInitializationHintWithRetry(
                        workerArgs,
                        workerStartedDetector,
                        { cwd, ...getLogPaths(`worker_${workerId}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                    ).then(proc => this.track(proc));
                    workerPromises.push(workerPromise);
                }
            } else {
                // Workers > realms: distribute workers across realms, outer loop realm, inner loop worker
                const workersPerRealm = Math.floor(workerRealmCount / realmsCount);
                const extraWorkers = workerRealmCount % realmsCount;
                console.log(`[DevNet] Starting ${workerRealmCount} workers distributed across ${realmsCount} realms (${workersPerRealm}-${workersPerRealm + 1} workers per realm)...`);

                let workerId = 0;
                for (let realmIndex = 0; realmIndex < realmsCount; realmIndex++) {
                    const realmId = startRealmId + realmIndex;
                    const realmUrls: string[] = [];
                    for (const subId of realmP2pSubIds) {
                        for (let edgeIndex = 0; edgeIndex < realmEdgeCount; edgeIndex++) {
                            realmUrls.push(`http://${this.host}:${realmP2pHttpPort(realmId, subId, edgeIndex, realmEdgeCount)}`);
                        }
                    }

                    const numWorkersForRealm = workersPerRealm + (realmIndex < extraWorkers ? 1 : 0);
                    for (let i = 0; i < numWorkersForRealm; i++) {
                        const workerArgs = [
                            workerCli, 'worker',
                            '--user', '0',  // shared user id
                            '--network', this.NETWORK,
                            '--proving-backend', backend,
                            '--completed-jobs-log-file', `./local_checkpoints/realm_worker_${workerId}.backup`,
                            '--batch-size', runtimeResources.workerBatchSize,
                        ];

                        for (const realmUrl of realmUrls) {
                            workerArgs.push('--realm-api-url', realmUrl);
                        }

                        workerArgs.push('--private-key', FAKE_MINER_PRIVATE_KEY);

                        const workerPromise = RunningProcess.spawnWithInitializationHintWithRetry(
                            workerArgs,
                            workerStartedDetector,
                            { cwd, ...getLogPaths(`worker_${workerId}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                        ).then(proc => this.track(proc));
                        workerPromises.push(workerPromise);
                        workerId++;
                    }
                }
            }

            // Wait for all worker processes to start
            await Promise.all(workerPromises);
            console.log(`[DevNet] All ${workerRealmCount} shared workers started (${workerPromises.length} connections total)`);
        }

        // 8. Dummy Provers
        const dummyProvers = options.dummyProvers || 0;
        if (dummyProvers > 0) {
            const dummyPromises: Promise<RunningProcess>[] = [];
            for (let i = 0; i < dummyProvers; i++) {
                const dummyPromise = RunningProcess.spawnWithInitializationHintWithRetry(
                    [
                        './dev/dummy_prover.sh', 'prove_random', '-p', backend, '-H', this.host,
                        '--start-realm-id', startRealmId.toString(), '--end-realm-id', endRealmId.toString(),
                    ],
                    dummyProverStartedDetector,
                    { cwd, ...getLogPaths(`dummy_prover_${i}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                ).then(proc => this.track(proc));
                dummyPromises.push(dummyPromise);
            }
            await Promise.all(dummyPromises);
            console.log(`[DevNet] All ${dummyProvers} dummy provers started`);
        }


        // 10. L1 (Anvil). Local chains always start empty and deploy fresh.
        let resetEnvioStorage = false;
        if (options.l1 || startAll) {
            const local = l1Network === "localhost" || l1Fork;
            const statePlans = local
                ? await Promise.all(relayerChains.map((chain) => resolveLocalAnvilStatePlan(cwd, chain.deploymentsNetwork, l1Fork, { rpcUrl: chain.rpcUrl })))
                : [];
            resetEnvioStorage = statePlans.length > 0;
            const contractsDir = path.join(cwd, "psy-contracts");
            const deploys = relayerChains.some((chain) => chain.deploymentsNetwork.startsWith("localhost") || shouldRedeployL1());
            if (deploys) {
                await ensurePsyContractsDependencies(contractsDir);
                const compile = Bun.spawn(["npx", "hardhat", "compile"], { cwd: contractsDir, stdout: "inherit", stderr: "inherit" });
                const compileCode = await compile.exited;
                if (compileCode !== 0) throw new Error(`[DevNet] psy-contracts compile failed (exit=${compileCode})`);
            }
            const l1Deployments = await Promise.allSettled(relayerChains.map(async (chain, index) => {
                const chainMeta = protocolConfig.chains[chain.deploymentsNetwork];
                const statePlan = statePlans[index];
                const logName = chain.chainIndex === 0 ? "l1_anvil" : `l1_anvil_${chain.prefix.toLowerCase()}`;
                if (statePlan) {
                    await mkdir(path.dirname(statePlan.statePath), { recursive: true });
                    const rpc = new URL(chain.rpcUrl);
                    const port = Number(rpc.port || (rpc.protocol === "https:" ? 443 : 80));
                    const args = localAnvilLaunchArgs(port, String(chainMeta.l1ChainId), statePlan.statePath);
                    if (l1Fork) {
                        const forkEnvKey = resolveForkRpcEnvKey(l1Network, cfgEntry, stage);
                        const forkRpcUrl = process.env[forkEnvKey];
                        if (!forkRpcUrl) throw new Error(`[DevNet] VITE_FORK=true requires env ${forkEnvKey}`);
                        args.push("--fork-url", forkRpcUrl);
                        const forkBlock = process.env.VITE_FORK_BLOCK_NUMBER;
                        if (forkBlock?.trim()) args.push("--fork-block-number", forkBlock.trim());
                    }
                    this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                        args, l1StartedDetector,
                        { cwd, ...getLogPaths(logName, false), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() },
                    ), logName);
                } else {
                    console.log(`[DevNet] Using external L1 network ${chain.networkId} via ${chain.rpcUrl}`);
                }
                await waitForHttpUrl(chain.rpcUrl, {
                    attempts: 30, delayMs: local ? 500 : 1000, timeoutMs: local ? 1500 : 3000, name: `${chainMeta.name} RPC`,
                });
                if (statePlan) await setLocalAnvilIntervalMining(chain.rpcUrl);
                await deployPsyContracts(cwd, chain.rpcUrl, chain.deploymentsNetwork, {
                    fundDevAccounts: local,
                    localAnvilRpcUrl: local ? chain.rpcUrl : undefined,
                });
            }));
            const l1Failure = l1Deployments.find((result): result is PromiseRejectedResult => result.status === "rejected");
            if (l1Failure) throw l1Failure.reason;
        }
        if (this.freshState) {
            await this.freshState.finish();
            this.freshState = undefined;
        }
        // Deployment documents of exactly the selected chains, passed as repeatable
        // --l1-config paths. The documents stay where deployment wrote them.
        const l1ConfigArgs = startBridgeProposerDaemon ? await resolveL1ConfigArgs(cwd, relayerChains) : [];
        // 11. Bridge dependencies (Envio + psy-services)
        if (relayer || options.bridgeUi || options.psyPrivacyBridge || startAll) {
            const relayerConfig = options.relayerConfig || './psy_cli/psy_relayer_cli/config/local.toml';
            const relayerCfgPath = path.isAbsolute(relayerConfig) ? relayerConfig : path.join(cwd, relayerConfig);
            const relayerRaw = await Bun.file(relayerCfgPath).text();
            const coordinatorRpcUrl = parseTomlScalar(relayerRaw, "coordinator_rpc_url") || "http://127.0.0.1:1337";
            const relayerL1RpcUrl = l1RpcUrl;

            // Ensure relayer dependencies are up before spawning it.
            await waitForHttpUrl(relayerL1RpcUrl, { attempts: 30, delayMs: 1000, timeoutMs: 1500, name: "L1 RPC" });
            await waitForHttpUrl(coordinatorRpcUrl, { attempts: 30, delayMs: 1000, timeoutMs: 1500, name: "Coordinator RPC" });

            const envioProc = await startEnvioIndexerForRelayer(
                cwd,
                relayerConfig,
                relayerChains,
                this.getEnv(),
                resetEnvioStorage,
                runtimeResources.runtimeCpuSet,
            );
            if (envioProc) {
                this.track(envioProc);
                console.log('[DevNet] Envio indexer started');
            }

            await waitForTcpPort('127.0.0.1', 9898, {
                attempts: 600,
                delayMs: 1000,
                timeoutMs: 1500,
                name: 'Envio Indexer API',
            });

            // Grant public select permissions on all Envio-indexed tables so the
            // frontend (which never sends X-Hasura-Admin-Secret) can query them.
            await ensureEnvioHasuraPublicAccess();

            const psyServicesCwd = path.resolve(cwd, '../psy-services');
            const psyServicesBin = path.join(psyServicesCwd, 'target', 'release', 'psy-services');
            const psyServicesGenesisAbi = path.join(path.resolve(cwd), 'psy-genesis', 'genesis_contracts.json');
            const psyServicesGenesisUser = path.join(psyServicesCwd, 'genesis_users.bin');
            const psyIndexerBin = path.join(psyServicesCwd, 'target', 'release', 'psy-indexer');
            const psyServicesCargoToml = path.join(psyServicesCwd, 'Cargo.toml');
            if (skipBuild) {
                await requireReleaseBinaries([
                    { name: "psy-services", path: psyServicesBin },
                    { name: "psy-indexer", path: psyIndexerBin },
                ]);
                console.log('[DevNet] build skipped unless PSY_SKIP_BUILD=0 -- using existing psy-services release binaries');
            } else if (await exists(psyServicesCargoToml)) {
                console.log('[DevNet] Building psy-services release binaries...');
                const buildPsyServices = await runStreaming([
                    'cargo', 'build', '--release', '--bin', 'psy-services', '--bin', 'psy-indexer'
                ], psyServicesCwd);
                if (buildPsyServices !== 0) {
                    throw new Error(`[DevNet] psy-services release build failed (exit ${buildPsyServices})`);
                }
            }
            const psyServicesCmd = skipBuild
                ? [psyServicesBin, '--disable-auth']
                : await exists(psyServicesBin)
                    ? [psyServicesBin, '--disable-auth']
                    : ['cargo', 'run', '--release', '--bin', 'psy-services', '--', '--disable-auth'];
            if (await exists(psyServicesGenesisAbi)) {
                psyServicesCmd.push('--genesis-path', psyServicesGenesisAbi);
            }
            if (await exists(psyServicesGenesisUser)) {
                psyServicesCmd.push('--genesis-users-path', psyServicesGenesisUser);
            }
            const psyIndexerCmdBase = skipBuild
                ? [psyIndexerBin]
                : await exists(psyIndexerBin)
                    ? [psyIndexerBin]
                    : ['cargo', 'run', '--release', '--bin', 'psy-indexer', '--'];
            const stateManagerAddress = await readDeploymentAddress(cwd, deploymentsNetwork, 'StateManager');
            if (!stateManagerAddress) {
                throw new Error(`[DevNet] Failed to resolve StateManager address from ${deploymentsNetwork} deployments`);
            }
            const bridgeAddress = await readDeploymentAddress(cwd, deploymentsNetwork, 'Bridge');
            if (!bridgeAddress) {
                throw new Error(`[DevNet] Failed to resolve Bridge address from ${deploymentsNetwork} deployments`);
            }
            const bridgeL1Chains = await Promise.all(relayerChains.map(async (chain) => {
                const address = await readDeploymentAddress(cwd, chain.deploymentsNetwork, 'StateManager');
                if (!address) {
                    throw new Error(
                        `[DevNet] Failed to resolve StateManager address from ${chain.deploymentsNetwork} deployments`,
                    );
                }
                const chainId = await readDeploymentChainId(cwd, chain.deploymentsNetwork);
                return {
                    chain_index: chain.chainIndex,
                    chain_id: chainId,
                    name: chain.networkId,
                    rpc_url: chain.rpcUrl,
                    state_manager_address: address,
                };
            }));

            const names = resolveDevnetDbNamesFromEnv(this.getEnv());
            for (const command of psyServicesDatabaseCommands(true, false, names.envioPostgresContainer)) {
                const code = await Bun.spawn(command, { stdio: ['ignore', 'ignore', 'inherit'] }).exited;
                if (code !== 0) throw new Error(`[DevNet] psy_services database setup failed: ${command[3]}`);
            }
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                psyServicesCmd,
                psyServicesStartedDetector,
                {
                    cwd: psyServicesCwd,
                    ...getLogPaths('psy_services', false),
                    env: {
                        ...this.getEnvWithRustLogDirective('psy_services=info'),
                        DATABASE_URL: 'postgres://postgres:testing@127.0.0.1:5433/psy_services',
                        REDIS_URL: 'redis://localhost:6379',
                        INDEXER_GRAPHQL_URL: 'http://127.0.0.1:8080/v1/graphql',
                        PSY_NODE_URL: 'http://127.0.0.1:1337',
                        PSY_NOSTR_ENABLED: 'true',
                        PSY_NOSTR_RELAY_URL: 'ws://127.0.0.1:8081',
                        L1_RPC_URL: relayerL1RpcUrl,
                        BRIDGE_L1_CHAINS_JSON: JSON.stringify(bridgeL1Chains),
                        BRIDGE_ADDRESS: bridgeAddress,
                        STATE_MANAGER_ADDRESS: stateManagerAddress,
                        API_LISTEN: '0.0.0.0:3000',
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] psy-services started on port 3000');
            await waitForHttpUrl('http://127.0.0.1:3000/health', {
                attempts: 30,
                delayMs: 1000,
                timeoutMs: 1500,
                name: 'psy-services health',
            });

            const backupDir = path.resolve(cwd, 'local_checkpoints');
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                [
                    ...psyIndexerCmdBase,
                    '--edge-url', 'http://127.0.0.1:1337',
                    '--psy-services-url', 'http://127.0.0.1:3000',
                    '--jwt-secret', 'dev-secret-key',
                    '--backup-dir', backupDir,
                    '--poll-interval-ms', '5000',
                    'coordinator',
                ],
                psyIndexerStartedDetector,
                {
                    cwd: psyServicesCwd,
                    ...getLogPaths('psy_indexer_coordinator', false),
                    env: {
                        ...this.getEnvWithRustLogDirective('psy_services=info'),
                        PSY_LOG_LEVEL: 'info',
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] psy-indexer coordinator started');

            for (let realmId = startRealmId; realmId <= endRealmId; realmId++) {
                for (const realmSubId of realmP2pSubIds) {
                    const edgePort = realmP2pHttpPort(realmId, realmSubId, 0, realmEdgeCount);
                    await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                        [
                            ...psyIndexerCmdBase,
                            '--edge-url', `http://127.0.0.1:${edgePort}`,
                            '--psy-services-url', 'http://127.0.0.1:3000',
                            '--jwt-secret', 'dev-secret-key',
                            '--backup-dir', backupDir,
                            '--poll-interval-ms', '5000',
                            'realm',
                            '--realm-id', realmId.toString(),
                            '--realm-sub-id', realmSubId.toString(),
                        ],
                        psyIndexerStartedDetector,
                        {
                            cwd: psyServicesCwd,
                            ...getLogPaths(`psy_indexer_realm_${realmId}_${realmSubId}`, false),
                            env: {
                                ...this.getEnvWithRustLogDirective('psy_services=info'),
                                PSY_LOG_LEVEL: 'info',
                            },
                            maxRetries: 3,
                            retryDelayMs: 2000
                        }
                    ));
                    console.log(`[DevNet] psy-indexer realm ${realmId}/${realmSubId} started`);
                }
            }
        }

        // Faucet refuses to start unless prove-proxy is already reachable.
        if (options.faucetServer || startAll) {
            await waitForProveProxy("faucet-server");
            const faucetPort = 9998;
            const faucetProc = await RunningProcess.spawnWithInitializationHintWithRetry(
                [
                    './target/release/psy_user_cli',
                    'faucet-server',
                    '--listen-addr',
                    `0.0.0.0:${faucetPort}`,
                    '--rpc-config',
                    'psy-genesis/config.json',
                ],
                faucetServerStartedDetector,
                { cwd, ...getLogPaths('faucet_server', false), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
            );
            this.track(faucetProc);
            void waitForTcpPort('127.0.0.1', faucetPort, {
                attempts: 600,
                delayMs: 1000,
                timeoutMs: 1500,
                name: 'Faucet server',
            }).then(() => {
                console.log(`[DevNet] Faucet server started on port ${faucetPort}`);
            }).catch((error) => {
                console.warn(`[DevNet] Faucet server has not opened port ${faucetPort} yet: ${error}`);
            });
            console.log(`[DevNet] Faucet server process started; continuing while it warms on port ${faucetPort}`);
        }

        // Relayer immediately requests Groth16 proofs; wait for listen first.
        if (startBridgeProposerDaemon) {
            await waitForProveProxy("bridge relayer");
            await this.startGuardianServices(cwd, daemonConfigPath!, l1ConfigArgs);

            // Forward the whole operator config unchanged; the daemon owns protocol and credential validation.

            this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                ['./target/release/psy_relayer_cli', '--config', daemonConfigPath!, ...l1ConfigArgs],
                relayerStartedDetector,
                {
                    cwd,
                    ...getLogPaths('bridge_relayer', false),
                    env: this.getEnvWithRustLogDirective('psy_relayer_cli=info'),
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] Bridge relayer started');
        }

        // 11.5 Nostr relay readiness
        if (options.psyPrivacyBridge || startAll) {
            await waitForTcpPort(this.host, 8081, {
                attempts: 30,
                delayMs: 500,
                timeoutMs: 1500,
                name: "Nostr relay",
            });
        }

        // 12. Privacy Bridge shell
        if (options.psyPrivacyBridge || startAll) {
            const privacyBridgeDir = path.join(cwd, 'psy-dapp', 'apps', 'bridge');
            await ensureUiDependencies(privacyBridgeDir);
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                ['bun', 'run', 'dev', '--', '--host', '0.0.0.0', '--port', '5177', '--strictPort'],
                uiStartedDetector,
                {
                    cwd: privacyBridgeDir,
                    ...getLogPaths('psy_privacy_bridge', false),
                    env: {
                        ...this.getEnv(),
                        VITE_PSY_STAGE: stage,
                        VITE_NETWORK: l1Network,
                        VITE_FORK: String(l1Fork),
                        // Point @deployments at the root psy-contracts deployments the
                        // L1 deploy flow actually writes; the nested psy-dapp copy is
                        // only for standalone dapp runs and is not synced by devnet.
                        PSY_DEPLOYMENTS_DIR: path.resolve(cwd, 'psy-contracts', 'deployments'),
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] Privacy Bridge UI started on port 5177');
        }

        // 16. IDE
        if (options.ide || startAll) {
            const ideDir = path.join(cwd, 'psy-dapp', 'apps', 'ide');
            await ensureUiDependencies(ideDir);
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                ['bun', 'run', 'dev', '--', '--host', '0.0.0.0', '--port', '5176', '--strictPort'],
                uiStartedDetector,
                {
                    cwd: ideDir,
                    ...getLogPaths('ide', false),
                    env: {
                        ...this.getEnv(),
                        VITE_PSY_STAGE: stage,
                        VITE_NETWORK: l1Network,
                        VITE_FORK: String(l1Fork),
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] IDE started on port 5176');
        }

        // 17. Explorer
        if (options.explorer || startAll) {
            const explorerDir = path.join(cwd, 'psy-dapp', 'apps', 'explorer');
            await ensureUiDependencies(explorerDir);
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                ['pnpm', 'exec', 'vite', '--host', '0.0.0.0', '--port', '5178', '--strictPort'],
                uiStartedDetector,
                {
                    cwd: explorerDir,
                    ...getLogPaths('explorer', false),
                    env: {
                        ...this.getEnv(),
                        VITE_PSY_STAGE: stage,
                        VITE_NETWORK: l1Network,
                        VITE_FORK: String(l1Fork),
                        // Same as the bridge shell: read the root psy-contracts
                        // deployments the L1 deploy flow writes, not the
                        // unsynced nested psy-dapp copy.
                        PSY_DEPLOYMENTS_DIR: path.resolve(cwd, 'psy-contracts', 'deployments'),
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] Explorer started on port 5178');
        }

        // 18. Mode A Web Wallet Bridge
        if (options.modeAWebWalletBridge || startAll) {
            const modeAWebWalletBridgeDir = path.join(cwd, 'psy-dapp', 'apps', 'account');
            // The app uses `link:` deps to `@psy-protocol/psy-sdk` and `@psy-protocol/evm-wallet`.
            // Those packages are not part of this repo (client_prover/psy_sdk only has generated
            // types), so we can only start the dev server if the linked workspace is present.
            const modeAPackageJson = await (async (): Promise<Record<string, unknown> | null> => {
                try {
                    return await Bun.file(path.join(modeAWebWalletBridgeDir, 'package.json')).json();
                } catch {
                    return null;
                }
            })();
            const linkedDeps: string[] = [];
            if (modeAPackageJson && typeof modeAPackageJson.dependencies === 'object' && modeAPackageJson.dependencies !== null) {
                for (const [name, spec] of Object.entries(modeAPackageJson.dependencies as Record<string, string>)) {
                    if (typeof spec === 'string' && spec.startsWith('link:')) {
                        linkedDeps.push(name);
                        const resolved = path.resolve(modeAWebWalletBridgeDir, spec.slice(5));
                        if (!(await exists(path.join(resolved, 'package.json')))) {
                            console.warn(
                                `[DevNet] Skipping Mode A Web Wallet Bridge: linked dependency ${name}@${spec} does not resolve to a valid package (${resolved}).\n`
                                + `[DevNet] Make sure the psy-sdk workspace is checked out at the path expected by psy-dapp/apps/account/package.json.`,
                            );
                            return;
                        }
                    }
                }
            }
            if (linkedDeps.length > 0) {
                console.log(`[DevNet] Mode A Web Wallet Bridge linked dependencies resolved: ${linkedDeps.join(', ')}`);
            }
            await ensureUiDependencies(modeAWebWalletBridgeDir);
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                ['node', 'node_modules/vite/bin/vite.js', '--host', '0.0.0.0', '--port', '5179', '--strictPort'],
                uiStartedDetector,
                {
                    cwd: modeAWebWalletBridgeDir,
                    ...getLogPaths('mode_a_web_wallet_bridge', false),
                    env: {
                        ...this.getEnv(),
                        VITE_PSY_STAGE: stage,
                        VITE_NETWORK: l1Network,
                        VITE_FORK: String(l1Fork),
                        PSY_DEPLOYMENTS_DIR: path.resolve(cwd, 'psy-contracts', 'deployments'),
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] Mode A Web Wallet Bridge started on port 5179');
        }
    }

    async setupDaemonized(options: ProcessOptions): Promise<void> {
        const cwd = options?.cwd || ".";
        const jtmb = !!options?.jtmb;
        const workerRealmCount = options.workerRealmCount;
        const realmEdgeCount = options.realmEdgeCount;
        const coordinatorEdgeCount = options.coordinatorEdgeCount;
        const coordinatorWorkersCount = options.coordinatorWorkersCount;
        this.genesisDataPath = options.genesisDataPath || "genesis.json";

        const relayer = !!options.relayer || !!options.bridgeProposerDaemon;
        const hasOnlyOptions = !!options.db || !!options.coordinator || (options.proveProxyCount || 0) > 0 || !!options.faucetServer || (options.dummyProvers || 0) > 0 || !!options.l1 || relayer || !!options.bridgeUi || !!options.privacyUi || !!options.psyPrivacyBridge || !!options.ide || !!options.explorer || !!options.modeAWebWalletBridge;
        const startAll = options.all ?? !hasOnlyOptions;

        const startCoordinatorProcessor = startAll || !!options.coordinator;
        const startCoordinatorWorkers = coordinatorWorkersCount > 0;
        const startRealmProcessor = startAll || !!options.coordinator;
        const startRealmWorkers = workerRealmCount > 0;

        const needsStartDb = !hasOnlyOptions || !!options.db;
        const startRealmId = options.startRealmId || 0;
        const realmsCount = options.realmsCount !== undefined ? options.realmsCount : (startAll ? 1 : 1);
        const prepareRealmP2p = shouldPrepareRealmP2p(startCoordinatorProcessor, startRealmProcessor);
        if (prepareRealmP2p) validateRealmP2pPorts(startRealmId, realmsCount, realmEdgeCount);

        const backend = this.provingBackend || (jtmb ? 'jtmb-poseidon-goldilocks' : 'plonky2-poseidon-goldilocks');
        const realmP2pSubIds: readonly number[] = REALM_P2P_SUB_IDS;
        let realmP2pConfig: FullNetworkConfig | null = null;
        if (prepareRealmP2p) {
            const allRealmIds = Array.from({ length: realmsCount }, (_, i) => startRealmId + i);
            const foregroundP2pConfig = await ensureRealmP2pConfig("./target/release/psy_node_cli", cwd, allRealmIds, realmEdgeCount, this.host, path.join(cwd, this.genesisDataPath));
            realmP2pConfig = daemonRealmP2pConfig(foregroundP2pConfig, allRealmIds, realmEdgeCount);
            const daemonConfigPath = path.join(cwd, REALM_P2P_OUT_DIR, "daemon-config.json");
            await fs.promises.writeFile(daemonConfigPath, JSON.stringify(realmP2pConfig, null, 2), "utf-8");
            await injectGenesisValidators(path.join(cwd, this.genesisDataPath), realmP2pConfig);
        }


        const services: any = {};
        const names = await this.admitNamespace(cwd);
        const daemonName = names.namespace === null ? "psy-devnet" : `${names.namespace}-psy-devnet`;
        const networkName = daemonName;

        const runtimeResources = await resolveRuntimeResourceSettings(
            this.getEnv() || { ...process.env } as { [key: string]: string },
            coordinatorWorkersCount + workerRealmCount + (options.dummyProvers || 0) + (options.proveProxyCount || 0),
            needsStartDb,
        );
        const env = { ...(this.getEnv() || {}), ...runtimeResources.env };
        const scyllaSmp = runtimeResources.scyllaSmp;
        const scyllaCasTimeout = resolvePositiveIntegerSetting(
            env.SCYLLA_CAS_CONTENTION_TIMEOUT_MS,
            10_000,
            "SCYLLA_CAS_CONTENTION_TIMEOUT_MS",
        ).toString();
        const scyllaWriteTimeout = resolvePositiveIntegerSetting(
            env.SCYLLA_WRITE_REQUEST_TIMEOUT_MS,
            10_000,
            "SCYLLA_WRITE_REQUEST_TIMEOUT_MS",
        ).toString();
        const scyllaCommand = [
            "--smp", scyllaSmp,
            "--developer-mode", "1",
            "--experimental-features=lwt",
            "--cas-contention-timeout-in-ms", scyllaCasTimeout,
            "--write-request-timeout-in-ms", scyllaWriteTimeout,
            "--memory", resolveScyllaMemory(env.SCYLLA_MEMORY),
        ];
        const scyllaIoProperties = await resolveScyllaIoProperties(env.SCYLLA_IO_PROPERTIES);
        if (scyllaIoProperties) scyllaCommand.push("--io-properties-file", "/etc/scylla.d/io_properties.yaml");
        if (!runtimeResources.scyllaCpuSet) {
            scyllaCommand.push("--overprovisioned", "1");
        }
        const filteredEnv: Record<string, string> = {
            "RUST_LOG": env["RUST_LOG"] || "info",
            "RUST_BACKTRACE": "1",
            "RAYON_NUM_THREADS": runtimeResources.env.RAYON_NUM_THREADS,
            "PSY_WORKER_BATCH_SIZE": runtimeResources.env.PSY_WORKER_BATCH_SIZE,
        };
        if (realmP2pConfig) {
            filteredEnv["PSY_CONFIG_PATH"] = `${REALM_P2P_OUT_DIR}/daemon-config.json`;
            filteredEnv["PSY_NETWORK"] = realmP2pConfig.defaultNetwork;
        }
        Object.assign(filteredEnv, selectNonEmptyEnv(env, FAUCET_ENV_KEYS));
        const envList = Object.entries(filteredEnv).map(([k, v]) => `${k}=${v}`);

        // Infrastructure
        if (needsStartDb) {
            const occupied = await planScopedDevnetReset(names);
            const owned = [...devnetDbContainerNames(names), ...devnetDbVolumeNames(names)];
            const collision = [...occupied.containers, ...occupied.volumes].filter((name) => owned.includes(name));
            if (collision.length > 0) {
                throw new Error(`[DevNet] database startup refuses existing resources: ${collision.join(", ")}`);
            }
            services["valkey-server"] = {
                image: "valkey/valkey",
                container_name: names.containers.valkey,
                ports: ["6379:6379"],
                volumes: [`${names.volumes.valkey}:/data`],
                command: [
                    "valkey-server",
                    "--dir", "/data",
                    "--dbfilename", "dump.rdb",
                    "--appendonly", "yes",
                    "--save", "60", "1"
                ],
                ...(runtimeResources.runtimeCpuSet ? { cpuset: runtimeResources.runtimeCpuSet } : {}),
            };

            services["nats-server"] = {
                image: "nats",
                container_name: names.containers.nats,
                ports: ["4222:4222"],
                volumes: [`${names.volumes.nats}:/data`],
                ...(runtimeResources.runtimeCpuSet ? { cpuset: runtimeResources.runtimeCpuSet } : {}),
                command: ["-js", "-sd", "/data"]
            };

            services["scylla-server"] = {
                image: "scylladb/scylla@sha256:43a600f5291e55f1239dd94680c95d2b8a8be11bc0d73ced062031c978c155ca",
                container_name: names.containers.scylla,
                ports: ["9042:9042"],
                cap_add: ["PERFMON"],
                ...(runtimeResources.scyllaCpuSet ? { cpuset: runtimeResources.scyllaCpuSet } : {}),
                volumes: [
                    `${names.volumes.scylla}:/var/lib/scylla`,
                    `${names.volumes.scyllaData}:/run/udev/data`,
                    ...(scyllaIoProperties ? [`${scyllaIoProperties}:/etc/scylla.d/io_properties.yaml:ro`] : []),
                ],
                command: scyllaCommand,
                healthcheck: {
                    test: ["CMD", "nodetool", "status"],
                    interval: "10s",
                    timeout: "5s",
                    retries: 5
                }
            };
        }

        const commonVolumes = [
            ".:/app/workspace",
            "./target/release:/app/bin",
            "./logs:/app/logs",
            "./local_checkpoints:/app/local_checkpoints"
        ];
        const nodeImage = "ubuntu:24.04";
        const nodeDeps = needsStartDb ? {
            depends_on: {
                "scylla-server": { condition: "service_healthy" },
                "nats-server": { condition: "service_started" },
                "valkey-server": { condition: "service_started" }
            }
        } : {};

        const uid = process.getuid?.() ?? 1000;
        const gid = process.getgid?.() ?? 1000;

        const getServiceEntry = (name: string, cmd: string[], useHostUser: boolean = true) => ({
            image: nodeImage,
            container_name: names.namespace === null ? name : `${names.namespace}-${name}`,
            ...(useHostUser ? { user: `${uid}:${gid}` } : {}),
            working_dir: "/app/workspace",
            environment: envList,
            volumes: commonVolumes,
            entrypoint: cmd,
            ...nodeDeps
        });
        const getRuntimeServiceEntry = (name: string, cmd: string[], useHostUser: boolean = true) => ({
            ...getServiceEntry(name, cmd, useHostUser),
            ...(runtimeResources.runtimeCpuSet ? { cpuset: runtimeResources.runtimeCpuSet } : {}),
        });

        if (startCoordinatorProcessor) {
            services["coordinator-processor"] = getRuntimeServiceEntry("coordinator-processor", [
                "/app/bin/psy_node_cli", "start-coordinator-processor",
                "--coordinator-id", "0",
                "--coordinator-sub-id", "0",
                "--network", this.NETWORK,
                "--db-namespace", "coordinator",
                "--scylla-db-url", "scylla-server:9042",
                "--nats-jetstream-url", "nats://nats-server:4222",
                "--redis-url", "redis://valkey-server:6379",
                "--genesis-data-path", this.genesisDataPath,
                "--checkpoint-backup-path", "/app/local_checkpoints",
                "--proving-backend", backend,
                "--verbose"
            ]);

            for (let j = 0; j < coordinatorEdgeCount; j++) {
                const port = 1337 + j;
                services[`coordinator-edge-${j}`] = {
                    ...getRuntimeServiceEntry(`coordinator-edge-${j}`, [
                        "/app/bin/psy_node_cli", "start-coordinator-edge",
                        "--coordinator-id", "0",
                        "--coordinator-sub-id", "0",
                        "--network", this.NETWORK,
                        "--db-namespace", "coordinator",
                        "--scylla-db-url", "scylla-server:9042",
                        "--nats-jetstream-url", "nats://nats-server:4222",
                        "--redis-url", "redis://valkey-server:6379",
                        "--port", port.toString(),
                        "--listen", "0.0.0.0",
                        "--proving-backend", backend,
                        "--verbose",
                    ]),
                    ports: [`${port}:${port}`]
                };
            }
        }

        if (startCoordinatorWorkers) {
            for (let i = 0; i < coordinatorWorkersCount; i++) {
                const workerArgs = [
                    "/app/bin/psy_worker_cli", "worker",
                    "--user", "0",
                    "--network", this.NETWORK,
                    "--proving-backend", backend,
                    "--completed-jobs-log-file", `/app/local_checkpoints/coordinator_worker_${i}.backup`,
                    "--batch-size", runtimeResources.workerBatchSize,
                ];
                for (let j = 0; j < coordinatorEdgeCount; j++) {
                    workerArgs.push("--coordinator-api-url", `http://coordinator-edge-${j}:${1337 + j}`);
                }
                workerArgs.push("--private-key", FAKE_MINER_PRIVATE_KEY);
                services[`coordinator-worker-${i}`] = getRuntimeServiceEntry(`coordinator-worker-${i}`, workerArgs);
            }
        }

        if (startRealmProcessor) {
            const activeRealmP2pConfig = realmP2pConfig;
            if (!activeRealmP2pConfig) throw new Error("Realm P2P config was not prepared for Realm startup");
            for (let i = 0; i < realmsCount; i++) {
                const realmId = startRealmId + i;
                for (const subId of realmP2pSubIds) {
                    selectedRealm(activeRealmP2pConfig, realmId).validators[subId - 1];
                    const extra = realmP2pProcessorExtraArgs("0.0.0.0", realmId, subId);
                    const serviceName = `realm-${realmId}-sub-${subId}-processor`;
                    services[serviceName] = getRuntimeServiceEntry(serviceName, [
                        "/app/bin/psy_node_cli", "start-realm-processor",
                        "--realm-id", realmId.toString(),
                        "--network", this.NETWORK,
                        "--db-namespace", realmDbNamespace(realmId, subId),
                        "--scylla-db-url", "scylla-server:9042",
                        "--nats-jetstream-url", "nats://nats-server:4222",
                        "--redis-url", "redis://valkey-server:6379",
                        "--genesis-data-path", this.genesisDataPath,
                        "--checkpoint-backup-path", "/app/local_checkpoints",
                        "--coordinator-api-urls", `http://coordinator-edge-0:1337`,
                        "--proving-backend", backend,
                        "--verbose",
                        ...extra,
                    ]);
                    for (let j = 0; j < realmEdgeCount; j++) {
                        const port = realmP2pHttpPort(realmId, subId, j, realmEdgeCount);
                        const edgeExtra = realmP2pEdgeExtraArgs("0.0.0.0", realmId, subId, j, realmEdgeCount);
                        const edgeName = `realm-${realmId}-sub-${subId}-edge-${j}`;
                        services[edgeName] = {
                            ...getRuntimeServiceEntry(edgeName, [
                                "/app/bin/psy_node_cli", "start-realm-edge",
                                "--realm-id", realmId.toString(),
                                "--network", this.NETWORK,
                                "--db-namespace", realmDbNamespace(realmId, subId),
                                "--scylla-db-url", "scylla-server:9042",
                                "--nats-jetstream-url", "nats://nats-server:4222",
                                "--redis-url", "redis://valkey-server:6379",
                                "--port", port.toString(),
                                "--listen", "0.0.0.0",
                                "--proving-backend", backend,
                                "--verbose",
                                ...edgeExtra,
                            ]),
                            ports: [`${port}:${port}`]
                        };
                    }
                }
            }
        }

        // Simplification for workers distribution in daemonized mode
        if (startRealmWorkers) {
             for (let workerId = 0; workerId < workerRealmCount; workerId++) {
                 const workerArgs = [
                    "/app/bin/psy_worker_cli", "worker",
                    "--user", "0",
                    "--network", this.NETWORK,
                    "--proving-backend", backend,
                    "--completed-jobs-log-file", `/app/local_checkpoints/realm_worker_${workerId}.backup`,
                    "--batch-size", runtimeResources.workerBatchSize,
                ];
                // Connect to all realm edges
                for (let i = 0; i < realmsCount; i++) {
                    const realmId = startRealmId + i;
                    for (const subId of realmP2pSubIds) {
                        for (let j = 0; j < realmEdgeCount; j++) {
                            const port = realmP2pHttpPort(realmId, subId, j, realmEdgeCount);
                            const edgeName = `realm-${realmId}-sub-${subId}-edge-${j}`;
                            workerArgs.push("--realm-api-url", `http://${edgeName}:${port}`);
                        }
                    }
                }
                workerArgs.push("--private-key", FAKE_MINER_PRIVATE_KEY);
                services[`realm-worker-${workerId}`] = getRuntimeServiceEntry(`realm-worker-${workerId}`, workerArgs);
             }
        }

        const proveProxyCountD = options.proveProxyCount || 0;
        if (proveProxyCountD > 0) {
            const count = proveProxyCountD;
            const basePort = 9999;
            for (let i = 0; i < count; i++) {
                const port = basePort + i;
                services[`prove-proxy-${i}`] = {
                    ...getRuntimeServiceEntry(`prove-proxy-${i}`, [
                        "/app/bin/psy_user_cli", "prove-proxy",
                        "--listen-addr", `0.0.0.0:${port}`,
                        "--rpc-config", "/app/workspace/psy-genesis/config.json"
                    ]),
                    ports: [`${port}:${port}`]
                };
            }
        }
        if (options.faucetServer || !hasOnlyOptions) {
            services["faucet-server"] = {
                ...getRuntimeServiceEntry("faucet-server", [
                    "/app/bin/psy_user_cli", "faucet-server",
                    "--listen-addr", "0.0.0.0:9998",
                    "--rpc-config", "/app/workspace/psy-genesis/config.json"
                ]),
                ports: ["9998:9998"]
            };
        }

        const compose: any = {
            services,
            networks: {
                default: {
                    name: networkName
                }
            }
        };

        compose.volumes = {
            [names.volumes.valkey]: { name: names.volumes.valkey },
            [names.volumes.scylla]: { name: names.volumes.scylla },
            [names.volumes.scyllaData]: { name: names.volumes.scyllaData },
            [names.volumes.nats]: { name: names.volumes.nats },
        };

        // Helper to stringify Docker Compose YAML with explicit quoting for all string values
        const stringifyYaml = (obj: any, indent: number = 0): string => {
            const spaces = " ".repeat(indent);
            if (Array.isArray(obj)) {
                return obj.map(item => `${spaces}- ${JSON.stringify(String(item))}`).join("\n") + "\n";
            } else if (typeof obj === "object" && obj !== null) {
                let result = "";
                for (const [key, value] of Object.entries(obj)) {
                    if (Array.isArray(value)) {
                        result += `${spaces}${key}:\n${stringifyYaml(value, indent + 2)}`;
                    } else if (typeof value === "object" && value !== null) {
                        result += `${spaces}${key}:\n${stringifyYaml(value, indent + 2)}`;
                    } else {
                        // Quote everything that isn't a plain number for safety
                        const valStr = (typeof value === "string" || typeof value === "boolean") 
                            ? JSON.stringify(value) 
                            : value;
                        result += `${spaces}${key}: ${valStr}\n`;
                    }
                }
                return result;
            }
            return String(obj);
        };

        const yamlString = stringifyYaml({ services, networks: { default: { name: networkName } } });
        let fullYaml = yamlString + `\nvolumes:\n  ${names.volumes.valkey}:\n    name: ${names.volumes.valkey}\n  ${names.volumes.scylla}:\n    name: ${names.volumes.scylla}\n  ${names.volumes.scyllaData}:\n    name: ${names.volumes.scyllaData}\n  ${names.volumes.nats}:\n    name: ${names.volumes.nats}\n`;
        
        await writeFile("docker-compose.yml", fullYaml);
        console.log("[DevNet] Generated docker-compose.yml (Clean YAML)");
        
        console.log("[DevNet] Starting via docker-compose...");
        const proc = Bun.spawn(["docker", "compose", "-p", daemonName, "up", "-d", "--remove-orphans"], {
            stdout: "inherit",
            stderr: "inherit"
        });
        await proc.exited;
        console.log("[DevNet] Services started in background.");
    }

    async teardown(cwd: string = ".", purge: boolean = false): Promise<void> {
        this.stopping = true;
        if (this.freshState) {
            await this.freshState.abort();
            this.freshState = undefined;
        }
        if (!this.admittedNames) return;
        console.log("[DevNet][supervisor] teardown: auto-restart disabled, stopping all children");
        if (!purge) {
            await this.stopOwnedAnvilState(cwd);
            await gracefulDevnetStop(cwd);
            return;
        }
        for (const child of this.spawnedProcesses) {
            if (child?.isRunning()) child.kill();
        }
        await teardownDevnet(cwd, true);
    }

    /** Stop tracked producers. Anvil stays up until gracefulDevnetStop signals it. */
    async stopOwnedAnvilState(cwd: string): Promise<void> {
        await resolveBoundDevnetNames(cwd, this.getEnv());
        if (!this.admittedNames) throw new Error("[DevNet] supervisor has not admitted resource ownership");
        this.stopping = true;
        if (this.applicationLifecycleState === "running" || this.applicationLifecycleState === "stopping") {
            await this.stopApplications(cwd, false);
        }
        const tracked = splitDevnetProcesses(this.spawnedProcesses).applications.filter((process) => process.isRunning());
        for (const process of tracked) process.killWithSignal("SIGTERM");
        for (const process of tracked) await process.proc.exited;
    }

    static create(host?: string, envVars?: { [key: string]: string }, provingBackend?: string): DevNetProcessManager { return new DevNetProcessManager(host, envVars, provingBackend); }
}
export function shouldRequireGuardianRoot(startAll: boolean, options: Pick<ProcessOptions, "relayer" | "bridgeProposerDaemon" | "bridgeUi">): boolean {
    return startAll || !!options.relayer || !!options.bridgeProposerDaemon || !!options.bridgeUi;
}

// --- Race-safe per-repository devnet startup lock -----------------------------
// Prevents two concurrent devnet startups for the same repo root from racing
// into destructive Docker/process teardown. The lock lives in tmpdir (never in
// the worktree, so it leaves no git artifact) and is keyed by the canonical
// repo root. Teardown and --help intentionally do NOT acquire it: --teardown is
// the sanctioned destruction entry point and must be able to run even when a
// (possibly stale) lock is present.

function devnetLockPath(repoRoot: string): string {
    const tmpBase = repoRoot === "psy-devnet-host-resources" ? "/tmp" : process.env.TMPDIR || "/tmp";
    const key = createHash("sha256").update(repoRoot).digest("hex").slice(0, 32);
    return path.join(tmpBase, `psy-devnet-${key}.lock`);
}

class DevnetLock {
    private released = false;

    constructor(private readonly holder: Bun.Subprocess) {}

    release(): void {
        if (this.released) return;
        this.released = true;
        try {
            this.holder.kill();
        } catch {
            // Already exited: the kernel lock is already released.
        }
    }
}

async function acquireDevnetLock(repoRoot: string): Promise<DevnetLock> {
    const lockPath = devnetLockPath(repoRoot);
    const ourPid = process.pid;
    let previousPid: number | null = null;
    try {
        const parsed = parseInt(fs.readFileSync(lockPath, "utf8").trim(), 10);
        if (Number.isFinite(parsed)) previousPid = parsed;
    } catch {
        // First run: the lock file does not exist yet.
    }

    // Hold a kernel advisory lock for this process lifetime. `cat` blocks on a
    // pipe owned by the Bun parent; if Bun exits or is killed, the pipe closes,
    // `cat` exits, and the kernel releases flock automatically. The lock file
    // may remain, but its contents are diagnostic only — exclusivity comes
    // from flock, so stale-file deletion and its ABA race are eliminated.
    const holder = Bun.spawn([
        "flock", "-n", "-o", "-E", "73", lockPath,
        "bash", "-c",
        'printf "%s\\n" "$1" > "$2"; printf "LOCKED\\n"; cat >/dev/null',
        "_", String(ourPid), lockPath,
    ], {
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
    });

    const reader = holder.stdout.getReader();
    const first = await reader.read();
    reader.releaseLock();
    const marker = first.value ? new TextDecoder().decode(first.value) : "";
    if (!marker.includes("LOCKED")) {
        const code = await holder.exited;
        if (code === 73) {
            let holderPid = previousPid;
            try {
                const parsed = parseInt(fs.readFileSync(lockPath, "utf8").trim(), 10);
                if (Number.isFinite(parsed)) holderPid = parsed;
            } catch {
                // Keep the pre-acquire diagnostic PID if the file is unreadable.
            }
            console.error(
                `[DevNet] Another devnet is already running for this repository${holderPid !== null ? ` (pid=${holderPid})` : ""}.\n` +
                `Lock file: ${lockPath}\n` +
                `To stop it: bun run dev/locSetupV4.ts --teardown`
            );
            process.exit(1);
        }
        const stderr = holder.stderr ? await new Response(holder.stderr).text() : "";
        throw new Error(`[DevNet] Failed to acquire devnet lock via flock (exit ${code}): ${stderr.trim()}`);
    }

    if (previousPid !== null && previousPid !== ourPid) {
        console.log(`[DevNet] Acquired released devnet lock (previous pid=${previousPid}) at ${lockPath}`);
    }
    return new DevnetLock(holder);
}
export type DevnetControlCommand = "restart" | "rollback-stop" | "rollback-resume" | "shutdown" | "shutdown-purge";

interface DevnetControlResponse {
    ok: boolean;
    message: string;
}

interface DevnetControlServer {
    close(): Promise<void>;
}

export function devnetControlSocketPath(repoRoot: string): string {
    return devnetLockPath(repoRoot).replace(/\.lock$/, ".control.sock");
}

function parseDevnetControlCommand(value: string): DevnetControlCommand {
    if (value === "restart" || value === "rollback-stop" || value === "rollback-resume" || value === "shutdown" || value === "shutdown-purge") return value;
    throw new Error(`[DevNet][control] unsupported command ${value}`);
}

export async function sendDevnetControlCommand(repoRoot: string, command: DevnetControlCommand): Promise<string> {
    const socketPath = devnetControlSocketPath(repoRoot);
    const response = Promise.withResolvers<string>();
    const socket = net.createConnection(socketPath);
    const timeout = setTimeout(() => {
        socket.destroy();
        response.reject(new Error(`[DevNet][control] timed out waiting for ${command}`));
    }, 900_000);
    let received = "";
    socket.setEncoding("utf8");
    socket.once("connect", () => socket.write(`${command}\n`));
    socket.on("data", (chunk) => {
        received += chunk;
        const newline = received.indexOf("\n");
        if (newline < 0) return;
        socket.end();
        try {
            const result = JSON.parse(received.slice(0, newline)) as DevnetControlResponse;
            if (result.ok) response.resolve(result.message);
            else response.reject(new Error(result.message));
        } catch (error) {
            response.reject(new Error(`[DevNet][control] invalid supervisor response: ${error}`));
        }
    });
    socket.once("error", (error) => response.reject(
        new Error(`[DevNet][control] cannot reach the running supervisor at ${socketPath}: ${error.message}`),
    ));
    socket.once("close", () => {
        if (!received.includes("\n")) response.reject(new Error("[DevNet][control] supervisor disconnected without a completion acknowledgment"));
    });
    try {
        return await response.promise;
    } finally {
        clearTimeout(timeout);
        socket.destroy();
    }
}

export async function startDevnetControlServer(
    repoRoot: string,
    handle: (command: DevnetControlCommand) => Promise<string | { message: string; afterAck?: () => void }>,
): Promise<DevnetControlServer> {
    const socketPath = devnetControlSocketPath(repoRoot);
    try {
        const stat = await fs.promises.stat(socketPath);
        if (stat.isSocket()) {
            const probe = net.createConnection(socketPath);
            const connected = Promise.withResolvers<boolean>();
            probe.once("connect", () => connected.resolve(true));
            probe.once("error", () => connected.resolve(false));
            const timeout = setTimeout(() => connected.resolve(false), 500);
            const isLive = await connected.promise;
            clearTimeout(timeout);
            probe.destroy();
            if (isLive) throw new Error(`[DevNet][control] supervisor socket already active at ${socketPath}`);
        }
        await rm(socketPath, { force: true });
    } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "ENOENT") throw error;
    }
    let commandQueue = Promise.resolve();
    const server = net.createServer((socket) => {
        socket.setEncoding("utf8");
        let received = "";
        socket.on("data", (chunk) => {
            received += chunk;
            const newline = received.indexOf("\n");
            if (newline < 0) return;
            socket.removeAllListeners("data");
            commandQueue = commandQueue.then(async () => {
                let response: DevnetControlResponse;
                let afterAck: (() => void) | undefined;
                try {
                    const command = parseDevnetControlCommand(received.slice(0, newline).trim());
                    const result = await handle(command);
                    if (typeof result === "string") response = { ok: true, message: result };
                    else {
                        response = { ok: true, message: result.message };
                        afterAck = result.afterAck;
                    }
                } catch (error) {
                    response = { ok: false, message: error instanceof Error ? error.message : String(error) };
                }
                socket.end(`${JSON.stringify(response)}\n`, () => afterAck?.());
            }).catch((error) => {
                console.error(`[DevNet][control] failed to ack ${received.trim()}: ${error}`);
            });
        });
    });
    const listening = Promise.withResolvers<void>();
    const listeningError = (error: Error) => listening.reject(error);
    server.once("error", listeningError);
    server.listen(socketPath, listening.resolve);
    await listening.promise;
    server.off("error", listeningError);
    server.on("error", (error) => console.error(`[DevNet][control] server error: ${error.message}`));
    await fs.promises.chmod(socketPath, 0o600);
    return {
        async close(): Promise<void> {
            const closed = Promise.withResolvers<void>();
            server.close(closed.resolve);
            await closed.promise;
            await rm(socketPath, { force: true });
        },
    };
}
let globalManager: DevNetProcessManager | null = null;

async function runMain() {

    const { values } = parseArgs({
        args: Bun.argv,
        options: {
            all: { type: "boolean" },
            jtmb: { type: "boolean" },
            "proving-backend": { type: "string" },
            "disable-worker-edge-logs": { type: "boolean" },
            "realm-workers": { type: "string" },
            "realm-edge-nodes": { type: "string", default: "1" },
            "coordinator-edge-nodes": { type: "string", default: "1" },
            "coordinator-workers": { type: "string" },
            "start-realm-id": { type: "string", default: "0" },
            "realms-count": { type: "string", default: "1" },
            "host": { type: "string", default: "127.0.0.1" },

            "genesis-data-path": { type: "string", default: "genesis.json" },
            "coordinator": { type: "boolean" },
            "db": { type: "boolean" },
            "dummy-provers": { type: "string" },
            "prove-proxy": { type: "string" },
            "faucet-server": { type: "boolean" },
            "l1": { type: "boolean" },
            "relayer": { type: "boolean" },
            "relayer-config": { type: "string", default: "./psy_cli/psy_relayer_cli/config/local.toml" },
            "bridge-proposer-daemon": { type: "boolean" },
            "psy-privacy-bridge": { type: "boolean" },
            "ide": { type: "boolean" },
            "explorer": { type: "boolean" },
            "mode-a-web-wallet-bridge": { type: "boolean" },
            "daemonlize": { type: "boolean" },
            "teardown": { type: "boolean" },
            "purge": { type: "boolean" },
            control: { type: "string" },
            env: { type: "string" },
            "help": { type: "boolean", short: "h" },
        },
        allowPositionals: true,
    });



    const proveProxyCount = values["prove-proxy"] !== undefined ? parseInt(values["prove-proxy"], 10) : undefined;
    const hasOnlyOptions = !values.all && (!!values["db"] || !!values["coordinator"] || (proveProxyCount !== undefined && proveProxyCount !== 0) || !!values["faucet-server"] || !!values["dummy-provers"] || !!values["l1"] || !!values["relayer"] || !!values["bridge-proposer-daemon"] || !!values["psy-privacy-bridge"] || !!values["ide"] || !!values["explorer"] || !!values["mode-a-web-wallet-bridge"]);
    const workerRealmCount = resolveRealmWorkerCount(
        values["realm-workers"],
        hasOnlyOptions,
    );
    const realmEdgeCount = parseInt(values["realm-edge-nodes"] || "1", 10);
    const coordinatorEdgeCount = parseInt(values["coordinator-edge-nodes"] || "1", 10);
    const coordinatorWorkersCount = values["coordinator-workers"] ? parseInt(values["coordinator-workers"], 10) : (!hasOnlyOptions ? 1 : 0);
    const startRealmId = parseInt(values["start-realm-id"] || "0", 10);
    const realmsCount = parseInt(values["realms-count"] || "1", 10);
    if (!hasOnlyOptions || !!values["coordinator"]) validateRealmP2pPorts(startRealmId, realmsCount, realmEdgeCount);
    const host = values["host"] || "127.0.0.1";
    const genesisDataPath = values["genesis-data-path"] || "genesis.json";
    const coordinator = !!values["coordinator"];
    const db = !!values["db"];
    const faucetServer = !!values["faucet-server"];
    const dummyProvers = values["dummy-provers"] ? parseInt(values["dummy-provers"], 10) : 0;
    const l1 = !!values["l1"];
    const relayer = !!values["relayer"] || !!values["bridge-proposer-daemon"];
    const bridgeProposerDaemon = relayer;
    const relayerConfig = values["relayer-config"] as string;
    const psyPrivacyBridge = !!values["psy-privacy-bridge"];
    const ide = !!values["ide"];
    const explorer = !!values["explorer"];
    const modeAWebWalletBridge = !!values["mode-a-web-wallet-bridge"];
    const daemonlize = !!values["daemonlize"];
    const teardown = !!values["teardown"];
    const purge = !!values["purge"];
    const control = values["control"] as string | undefined;

    const provingBackend = values["proving-backend"];
    const envString = values["env"];
    const help = !!values["help"];
    if (control) {
        const command = parseDevnetControlCommand(control);
        console.log(await sendDevnetControlCommand(REPO_ROOT, command));
        process.exit(0);
    }
    const l1Port = values["l1-port"] ? parseInt(values["l1-port"] as string, 10) : 8545;
    const { stage, l1Network, l1Fork, cfgEntry } = resolveL1Selection();
    const localL1RpcUrl = resolveLocalL1RpcUrl(l1Port);
    const l1RpcUrl = (l1Network === "localhost" || l1Fork) ? localL1RpcUrl : resolveExternalL1RpcUrl(l1Network, cfgEntry, stage);

    const envVars: { [key: string]: string } = envString ? parseEnvAssignments(envString) : {};

    // Load faucet operators for prove-proxy (localhost devnet)
    // NOTE: this is done BEFORE auto-setup. If genesis generation creates the
    // file, it will be reloaded after ensureDevEnvironment() below.
    if (!hasFaucetOperatorConfig(envVars, process.env)) {
        try {
            const faucetOpsPath = path.join(REPO_ROOT, "psy-dapp", "apps", "bridge", "src", "config", "faucetOperators.json");
            if (fs.existsSync(faucetOpsPath)) {
                envVars["PSY_FAUCET_OPERATORS_JSON"] = pinFaucetPerClaimAmount(fs.readFileSync(faucetOpsPath, "utf-8"));
                console.log(`[DevNet] Loaded faucet operators from ${faucetOpsPath}`);
            }
        } catch (err) {
            console.warn(`[DevNet] Failed to load faucet operators: ${err}`);
        }
    }

    // Show help if requested
    if (help) {
        console.log(`
Psy Network DevNet Setup Tool

Usage: bun run dev/locSetupV4.ts [options]

 Options:
    --all                          Full fresh local startup (component counts remain configurable)
    --control <command>             Send restart, rollback-stop, rollback-resume, shutdown, or shutdown-purge to the running supervisor
    --host <ip>                     Target host IP (default: 127.0.0.1)
    --genesis-data-path <path>      Path to genesis data JSON file for processor nodes (default: genesis.json)
    --proving-backend <backend>     Proving backend to use (default: plonky2-poseidon-goldilocks)
    --env <vars>                    Environment variables to pass to processes (format: KEY1=VALUE1,KEY2=VALUE2)
    --jtmb                          Use JTMB proving backend instead of Plonky2
   --disable-worker-edge-logs      Disable logging for worker and edge processes
   --realm-workers <count>         Number of shared workers distributed across all realms (default: 2 when starting full system, 0 in component-only modes)
   --realm-edge-nodes <count>      Number of edge nodes per realm (default: 1)
   --coordinator-edge-nodes <count> Number of edge nodes for coordinator (default: 1)
   --coordinator-workers <count>   Number of coordinator workers (default: 1 when starting coordinator, 0 in only modes)
   --start-realm-id <id>           Starting realm ID (default: 0)
   --realms-count <n>              Number of realms to start (default: 1)
   --coordinator                   Start coordinator + realm processors and edges (requires database to be running)
   --db                            Start only database services
   --workers                       Start only workers (requires database to be running)
   --dummy-provers <n>             Start N dummy provers (requires coordinator and realms running)
   --prove-proxy <n>               Start N prove proxy instances (port 9999+)
   --faucet-server                 Start psy faucet server (port 9998)
   --l1                            Start L1 chain (anvil, default port 8545)
   --l1-port <port>                Port for anvil L1 node (default: 8545)
   VITE_PSY_STAGE=localhost|testnet|mainnet   Select the Psy stage (default: localhost)
   VITE_NETWORK=localhost|sepolia|ethereum   Select L1 target network (default: the stage's default L1, see VITE_PSY_STAGE)
   --relayer                       Start bridge relayer from PSY_BRIDGE_DAEMON_CONFIG (no subcommand: psy_relayer_cli --config <path>)
   --relayer-config <path>         Legacy relayer/envio config path (default: ./psy_cli/psy_relayer_cli/config/local.toml)
   --bridge-proposer-daemon        Same component selection and bridge dependencies as --relayer
   --psy-privacy-bridge           Start integrated privacy+bridge shell (psy-dapp/apps/bridge, port 5177)
   --ide                          Start IDE dev server (psy-dapp/apps/ide, port 5176)
   --explorer                     Start blockchain explorer dev server (psy-dapp/apps/explorer, port 5178)
   --mode-a-web-wallet-bridge     Start Mode A web wallet bridge dev server (psy-dapp/apps/account, port 5179)
   --daemonlize                    Generate docker-compose.yml and start in background
   --teardown                      Stop local devnet processes/containers and exit
   --purge                         With --teardown (or startup), also remove local_checkpoints, logs, deployments, and devnet Docker volumes
   --help, -h                      Show this help message

  Examples:
    # Start full system (default when no options specified)
    bun run dev/locSetupV4.ts  # starts all components with realms 0-127

    # Start full system with multiple realms
    bun run dev/locSetupV4.ts --realms-count 4  # realms 0,1,2,3

    # Start with custom genesis data
    bun run dev/locSetupV4.ts --genesis-data-path ./my-genesis.json  # use custom genesis file

    # Start in background using docker-compose
    bun run dev/locSetupV4.ts --daemonlize --realms-count 4

    # Start with specific proving backend
    bun run dev/locSetupV4.ts --proving-backend jtmb-sha256-u64  # use JTMB SHA256 backend

   # Start with workers
   bun run dev/locSetupV4.ts --coordinator-workers 2 --realm-workers 1  # coordinator + realms with workers

   # Start components separately
   bun run dev/locSetupV4.ts --db
   bun run dev/locSetupV4.ts --coordinator
   bun run dev/locSetupV4.ts --coordinator --realm  # coordinator + realms
   bun run dev/locSetupV4.ts --workers --coordinator-workers 3 --realm-workers 2  # only workers
   bun run dev/locSetupV4.ts --dummy-provers 4 --start-realm-id 1 --realms-count 2  # start 4 dummy provers in realms 1-2
   bun run dev/locSetupV4.ts --l1                  # start anvil L1 only
   bun run dev/locSetupV4.ts --relayer             # start unified bridge relayer only
   bun run dev/locSetupV4.ts --bridge-proposer-daemon  # alias for unified bridge relayer
   bun run dev/locSetupV4.ts --psy-privacy-bridge  # start integrated privacy+bridge shell on port 5177
   bun run dev/locSetupV4.ts --explorer            # start blockchain explorer on port 5178
   bun run dev/locSetupV4.ts --mode-a-web-wallet-bridge  # start Mode A web wallet bridge (psy-dapp/apps/account, port 5179)
   bun run dev/locSetupV4.ts --l1 --relayer --psy-privacy-bridge  # full bridge stack

 Notes:
   - Database services are automatically started in full system mode or when --db is specified
   - Flags can be combined (e.g., --db --coordinator)
   - Workers are started when --*-workers options are specified
   - No options specified starts the full system (all components)
   - Set VITE_PSY_STAGE=localhost|testnet|mainnet to choose the Psy stage (genesis config block)
   - Set VITE_NETWORK=localhost|sepolia|ethereum to choose the L1 target network (defaults to the stage's default L1)
   - Set VITE_NETWORK=<sepolia|ethereum> and VITE_FORK=true to run anvil in fork mode; this forks the L1 named by VITE_NETWORK regardless of VITE_PSY_STAGE (VITE_PSY_STAGE picks the Psy genesis block, VITE_NETWORK+VITE_FORK pick the L1 to fork — e.g. VITE_PSY_STAGE=localhost VITE_NETWORK=sepolia VITE_FORK=true runs a local Psy chain forking public Sepolia); requires SEPOLIA_RPC_URL or ETH_RPC_URL to be set
   - Optionally set VITE_FORK_BLOCK_NUMBER=<block> to pin the fork block
   - PSY_SKIP_BRANCH_CHECK=0  explicitly enable repo fetch/checkout (default: leave every HEAD untouched)
   - PSY_SKIP_KEYSTORE=0      explicitly download/hash-refresh trust setup (default: keep local ~/.psy/keystore)
   - PSY_KEYSTORE_R2_PREFIX   required when PSY_SKIP_KEYSTORE=0: single segment localhost-<digest> in psy-proving-keystores
   - PSY_SKIP_BUILD=0         explicitly build Rust release binaries (default: use existing; fail if any are missing)
   - PSY_NO_AUTO_RESTART=1    disable supervised child-process auto-restart
   - SCYLLA_SMP=<n>           Scylla shard count (default: auto from reserved CPUs)
   - SCYLLA_CPUSET=<cpus>      Linux override for dedicated Scylla physical cores
   - PSY_RUNTIME_CPUSET=<cpus> Linux override for all non-Scylla child processes
   - SCYLLA_MEMORY=<size>      Scylla Seastar memory budget, for example 8G
   - SCYLLA_CAS_CONTENTION_TIMEOUT_MS=<ms>  LWT contention timeout (default: 10000)
   - SCYLLA_WRITE_REQUEST_TIMEOUT_MS=<ms>   write timeout (default: 10000)
   - SCYLLA_IO_PROPERTIES=<file> optional regular file; resolved to an absolute path before launch and mounted read-only at /etc/scylla.d/io_properties.yaml (unset: unchanged; ':' rejected)
   - PSY_WORKER_BATCH_SIZE=<n> Concurrent jobs per worker (default: 2)
   - RAYON_NUM_THREADS=<n>     Rayon threads per proving process (default: auto, max 4)
   - Linux full-devnet/--db launches auto-partition complete physical cores; macOS uses concurrency limits without affinity
   - Child auto-restart is ON by default; restart banners are appended to per-service logs
        `);
        process.exit(0);
    }
    if (!teardown && daemonlize && (values.all || !hasOnlyOptions)) throw new Error("[DevNet] full fresh startup requires the foreground launcher");

    if (!teardown && !daemonlize && shouldRequireGuardianRoot(!hasOnlyOptions, { relayer, bridgeProposerDaemon })) {
        envVars.PSY_BRIDGE_DAEMON_CONFIG = await resolveBridgeDaemonConfigPath(process.cwd(), { ...process.env, ...envVars }, purge);
    }


    // Acquire a race-safe per-repository kernel lock BEFORE auto-setup or any
    // Docker/process destruction. A live holder blocks this startup; an
    // unlocked file left by a dead holder is reused safely. Teardown and
    // --help intentionally skip the lock: --teardown is the sanctioned
    // destruction entry point.
    let devnetLock: DevnetLock | null = null;
    if (!teardown) {
        devnetLock = await acquireDevnetLock(REPO_ROOT);
    }
    const releaseDevnetLock = () => {
        devnetLock?.release();
        devnetLock = null;
    };
    // Safety net: release only our own PID's lock on any process exit path.
    process.on('exit', () => {
        devnetLock?.release();
    });

    globalManager = DevNetProcessManager.create(host, envVars, provingBackend);
    let controlServer: DevnetControlServer | null = null;
    const closeControlServer = async () => {
        if (!controlServer) return;
        await controlServer.close();
        controlServer = null;
    };


    // Control shutdown acks first, then exits. A duplicate signal is ignored.
    let shuttingDown = false;
    const shutdown = async (failed = false) => {
        if (shuttingDown) return;
        shuttingDown = true;
        try {
            await closeControlServer();
            if (globalManager) await globalManager.teardown(".", false);
        } catch (e) {
            failed = true;
            console.error('[DevNet] error during teardown:', e);
        } finally {
            releaseDevnetLock();
            process.exit(failed ? 1 : 0);
        }
    };

    process.on('SIGINT', () => void shutdown());
    process.on('SIGTERM', () => void shutdown());
    try {
    if (!teardown) {
        await ensureDevEnvironment(REPO_ROOT, {
            requireDocker: !hasOnlyOptions || db || relayer || bridgeProposerDaemon,
            requireAnvil: !hasOnlyOptions || l1,
            requireBun: !hasOnlyOptions || psyPrivacyBridge || ide || modeAWebWalletBridge,
            selectedUi: selectedUiDependencies(!hasOnlyOptions, { psyPrivacyBridge, ide, explorer, modeAWebWalletBridge }),
            env: envVars,
        });
    }

    // (Re)load faucet operators AFTER auto-setup so genesis-generated files exist.
    // Explicit JSON or B64 from either the CLI or parent environment remains authoritative.
    if (!hasFaucetOperatorConfig(envVars, process.env)) {
        try {
            const faucetOpsPath = path.join(REPO_ROOT, "psy-dapp", "apps", "bridge", "src", "config", "faucetOperators.json");
            if (fs.existsSync(faucetOpsPath)) {
                envVars["PSY_FAUCET_OPERATORS_JSON"] = pinFaucetPerClaimAmount(fs.readFileSync(faucetOpsPath, "utf-8"));
                console.log(`[DevNet] Loaded faucet operators from ${faucetOpsPath}`);
            }
        } catch (err) {
            console.warn(`[DevNet] Failed to load faucet operators: ${err}`);
        }
    }

    if (teardown) {
        try {
            if (!purge) {
                const owner = await requestOwnedAnvilShutdown(REPO_ROOT, false);
                if (owner === "owned") process.exit(0);
                await gracefulDevnetStop(".");
            } else {
                await teardownDevnet(".", true);
            }
            process.exit(0);
        } catch (error) {
            console.error(`[DevNet] teardown failed without broad cleanup: ${error}`);
            process.exit(1);
        }
    }

        const options: ProcessOptions = {
            all: !hasOnlyOptions,
            purge,
            jtmb: !!values.jtmb,
            l1Port,
            workerRealmCount,
            realmEdgeCount,
            coordinatorEdgeCount,
            coordinatorWorkersCount,
            disableWorkerEdgeLogs: !!values["disable-worker-edge-logs"],
            startRealmId,
            realmsCount,
            coordinator,
            db,
            dummyProvers,
            genesisDataPath,
            proveProxyCount,
            faucetServer,
            l1,

            relayer,
            relayerConfig,
            bridgeProposerDaemon,
            psyPrivacyBridge,
            ide,
            explorer,
            modeAWebWalletBridge,
            daemonlize: !!values.daemonlize,
        };

        if (daemonlize) {
            await globalManager.setupDaemonized(options);
            releaseDevnetLock();
            process.exit(0);
        } else {
            await globalManager.setupProcesses(options);
            controlServer = await startDevnetControlServer(REPO_ROOT, async (command) => {
                if (!globalManager) throw new Error("[DevNet][control] process manager unavailable");
                if (command === "shutdown" || command === "shutdown-purge") {
                    const purgeRequested = command === "shutdown-purge";
                    if (!purgeRequested) {
                        await globalManager.stopOwnedAnvilState(REPO_ROOT);
                        await gracefulDevnetStop(REPO_ROOT);
                    } else {
                        globalManager.stopping = true;
                        await teardownDevnet(REPO_ROOT, true);
                    }
                    return {
                        message: purgeRequested ? "shutdown purge completed" : "shutdown completed",
                        afterAck: () => queueMicrotask(() => {
                            releaseDevnetLock();
                            void closeControlServer().finally(() => process.exit(0));
                        }),
                    };
                }
                if (command === "restart") {
                    await globalManager.restartApplications(REPO_ROOT);
                    return "Devnet application processes restarted; DB and Anvil retained";
                }
                if (command === "rollback-stop") {
                    await globalManager.stopApplications(REPO_ROOT, true);
                    return `Devnet applications stopped; rollback sentinel: ${ROLLBACK_STOP_SENTINEL_PATH}`;
                }
                await globalManager.startApplications(REPO_ROOT);
                return "Devnet applications resumed; DB and Anvil retained";
            });
            console.log(`[DevNet][control] listening at ${devnetControlSocketPath(REPO_ROOT)}`);
            console.log('DevNet started. Press Ctrl+C to stop.');
            if (process.env.PSY_NO_AUTO_RESTART === "1") {
                console.log('[DevNet][supervisor] auto-restart DISABLED (PSY_NO_AUTO_RESTART=1)');
            } else {
                console.log('[DevNet][supervisor] auto-restart ENABLED for supervised child processes (set PSY_NO_AUTO_RESTART=1 to disable)');
            }
            setInterval(() => { }, 1000 * 60);
        }
    } catch (e) {
        console.error("Setup failed:", e);
        try {
            await closeControlServer();
            if (globalManager) await globalManager.cleanupFailedSetup(".");
        } catch (te) {
            console.error("[DevNet] error during teardown after setup failure:", te);
        }
        releaseDevnetLock();
        process.exit(1);
    }
}

if (import.meta.main) runMain();
