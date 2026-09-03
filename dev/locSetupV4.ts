import { parseArgs } from "util";
import { rmdir, rm, exists, mkdir, writeFile } from "fs/promises";
import fs from "fs";
import path from "path";
import net from "node:net";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { availableParallelism } from "node:os";
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
    applyEnvioCpuSetToCompose,
    formatBridgeRelayerKeystoreDecryptError,
    formatPsyDappNestedSubmoduleRemedy,
    hasFaucetOperatorConfig,
    hasZstdMagic,
    parseCpuSet,
    isExactProcessorReadyLine,
    isTransientScyllaSchemaFailure,
    parseLscpuTopology,
    resolveCpuPartition,
    parseEnvAssignments,
    resolveCpuPartitionForAffinity,
    resolvePositiveIntegerSetting,
    resolveRayonThreadCount,
    resolveRealmWorkerCount,
    resolveWalletPasswordPolicy,
    shouldFatalRestartProcessor,
    resolveScyllaMemory,
    selectNonEmptyEnv,
    shouldSkipBranchSync,
    psySdkGenesisSubmoduleNeedsInit,
    planPsyDappNestedSubmoduleInit,
    isCompilerFingerprintSource,
    s3CurlArgs,
} from "./locSetupDefaults";
import type { PsyDappNestedInitPlan, PsyDappNestedSubmodule } from "./locSetupDefaults";

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
async function killDocker() {
    try {
        const proc = Bun.spawn(['docker', 'stop', 'valkey-server', 'scylla-server', 'nats-server'], {
            stderr: "ignore",
            stdout: "ignore"
        });
        await proc.exited;
    } catch (e) {
        console.log("[DevNet] Failed to kill docker", e);
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
type ConfigNetworkEntry = {
    l1_rpc_urls?: string[];
    anvilForkSourceUrlEnv?: string;
};
const DEV_TEST_ADDRESSES = [
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
] as const;

function resolveL1Selection(): { l1Network: L1NetworkName; l1Fork: boolean; cfgEntry: ConfigNetworkEntry } {
    const l1Network = resolveL1Network();
    const l1Fork = isTruthyEnv(process.env.VITE_FORK);
    if (l1Network === "localhost" && l1Fork) {
        throw new Error("[DevNet] VITE_FORK=true requires VITE_NETWORK=sepolia or ethereum");
    }
    const cfgEntry = (allConfig as any)?.networks?.[l1Network] as ConfigNetworkEntry | undefined;
    if (!cfgEntry) {
        throw new Error(`[DevNet] config.json networks.${l1Network} missing`);
    }
    return { l1Network, l1Fork, cfgEntry };
}

let cachedWalletPassword: string | null = null;
/** True when auto-setup generated the bridge-relayer keystore during this process. */
let bridgeRelayerKeystoreGeneratedThisRun = false;

function resolveBridgeRelayerKeystorePath(): string {
    const homeDir = process.env.HOME;
    if (process.env.KEYSTORE_PATH) return process.env.KEYSTORE_PATH;
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
    const body = await response.json() as { error?: { message?: string }; result?: unknown };
    if (body.error) {
        throw new Error(`[DevNet] ${method} failed: ${body.error.message || "unknown error"}`);
    }
    return body.result;
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

function resolveL1Network(): L1NetworkName {
    const value = (process.env.VITE_NETWORK || "localhost").trim().toLowerCase();
    if (value === "localhost" || value === "sepolia" || value === "ethereum") {
        return value;
    }
    throw new Error(`[DevNet] unsupported VITE_NETWORK=${value}; expected localhost, sepolia, or ethereum`);
}

function resolveLocalL1RpcUrl(port: number): string {
    const rpcHost = process.env.L1_RPC_HOST || "127.0.0.1";
    return `http://${rpcHost}:${port}`;
}

function resolveExternalL1RpcUrl(network: Exclude<L1NetworkName, "localhost">): string {
    const cfgEntry = (allConfig as any)?.networks?.[network] as ConfigNetworkEntry | undefined;
    const envKey = cfgEntry?.anvilForkSourceUrlEnv;
    const rpcUrl = envKey ? process.env[envKey] : undefined;
    if (!rpcUrl || rpcUrl.trim().length === 0) {
        throw new Error(`[DevNet] ${envKey ?? "RPC URL env"} is required when VITE_NETWORK=${network}`);
    }
    const trimmed = rpcUrl.trim();
    return trimmed;
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
    onExit: (code: number | null, signal: number | null) => void = () => { };

    /** Stable service name for supervisor logs (e.g. prove_proxy_0, bridge_relayer). */
    name: string = '';
    cmds: string[] = [];
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
    hasExited: boolean = false;
    exitCode: number | null = null;
    exitSignal: number | null = null;
    supervisorObservedExit: boolean = false;
    intentionalStop: boolean = false;
    dependencyRestartRequested: boolean = false;
    /** Fatal processor error already observed and signaled for supervised restart. */
    fatalRestartRequested: boolean = false;

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
            this.stdErrVisitor(line, this);
            this.allOutputVisitor(line, this);
        });
        this.stdErrLines.push(...lines);
        if (this.stdErrLines.length > this.linesToKeepStdErr) {
            this.stdErrLines.splice(0, this.stdErrLines.length - this.linesToKeepStdErr);
        }
    }

    kill(): void {
        this.intentionalStop = true;
        if (this.isRunning()) {
            this.proc.kill();
        }
    }

    isRunning(): boolean {
        return !this.hasExited && this.proc.killed === false;
    }

    killWithSignal(signal: number | NodeJS.Signals): void {
        this.intentionalStop = true;
        this.proc.kill(signal);
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
            env: options.env ? { ...process.env, ...options.env } : undefined
        });

        const runningProcess = new RunningProcess(proc, options.stdOutVisitor, options.stdErrVisitor, options.allOutputVisitor);
        runningProcess.cmds = cmds.slice();
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
            runningProcess.exitCode = code;
            runningProcess.exitSignal = null;
            runningProcess.hasExited = true;
            runningProcess.onExit(code, null);
        })();

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
        proc.useInitHint = true;
        const prevOnExit = proc.onExit.bind(proc);
        proc.onExit = (code: number | null, signal: number | null) => {
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
function l1StartedDetector(line: string): boolean { return line.includes('Listening on'); }
function relayerStartedDetector(line: string): boolean {
    return line.includes("connected to indexer postgres")
        || line.includes("envio schema is ready")
        || line.includes("indexer deposit sync window")
        || line.includes("bridge relayer started");
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

async function waitForHttpUrl(
    url: string,
    opts?: { attempts?: number; delayMs?: number; timeoutMs?: number; name?: string }
): Promise<void> {
    const attempts = opts?.attempts ?? 20;
    const delayMs = opts?.delayMs ?? 1000;
    const timeoutMs = opts?.timeoutMs ?? 1500;
    const name = opts?.name ?? url;
    for (let i = 1; i <= attempts; i++) {
        try {
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), timeoutMs);
            const res = await fetch(url, { method: "GET", signal: ctrl.signal });
            clearTimeout(timer);
            if (res.ok || res.status < 500) {
                return;
            }
        } catch {
            // retry
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

const S3_BASE_URL = (
    process.env.PSY_KEYSTORE_S3_BASE_URL
    || "https://psy-protocol-devnet.s3.ap-southeast-1.amazonaws.com/assets/keystore"
).replace(/\/+$/, "");

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
    return process.env.PSY_SKIP_BUILD === "1";
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
            `[AutoSetup] PSY_SKIP_BUILD=1 requires existing release binaries. Missing: ${missing.join(", ")}. ` +
            `Run once without PSY_SKIP_BUILD=1 to build them.`,
        );
    }
}

async function ensureAllBinariesBuilt(cwd: string): Promise<void> {
    const nodeBinaries = [
        { name: "psy_node_cli", path: path.join(cwd, "target", "release", "psy_node_cli") },
        { name: "psy_worker_cli", path: path.join(cwd, "target", "release", "psy_worker_cli") },
        { name: "psy_relayer_cli", path: path.join(cwd, "target", "release", "psy_relayer_cli") },
        { name: "psy_user_cli", path: path.join(cwd, "target", "release", "psy_user_cli") },
    ];
    const psyServicesPath = path.resolve(resolveProjectsDir(), "psy-services");
    const psyServicesBinaries = [
        { name: "psy-services", path: path.join(psyServicesPath, "target", "release", "psy-services") },
        { name: "psy-indexer", path: path.join(psyServicesPath, "target", "release", "psy-indexer") },
    ];

    if (skipBuildEnabled()) {
        await requireReleaseBinaries([...nodeBinaries, ...psyServicesBinaries]);
        console.warn("[AutoSetup] PSY_SKIP_BUILD=1 — using existing release binaries without running Cargo");
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
         "--bin", "psy_user_cli"],
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
        || actual.artifactByteSize !== expected.artifactByteSize) {
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
            || typeof parsed.artifactByteSize !== "number") {
            return null;
        }
        return {
            compilerRevision: parsed.compilerRevision,
            compilerSourcesHash: parsed.compilerSourcesHash,
            artifactSha256: parsed.artifactSha256,
            artifactByteSize: parsed.artifactByteSize,
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
    if (skipBuildEnabled()) {
        throw new Error(
            `[AutoSetup] PSY_SKIP_BUILD=1 requires current psy-sdk compiler artifacts. ` +
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

async function downloadS3File(key: string, destPath: string): Promise<void> {
    const url = `${S3_BASE_URL}/${key}`;
    console.log(`[AutoSetup] Downloading ${key}...`);
    // Stream curl's stderr (progress meter + error messages) to the terminal so
    // large keystore downloads show live progress, while still capturing it for
    // the fail-closed diagnostic below. -f keeps non-2xx fatal, --progress-bar
    // forces the meter even though stderr is piped, and the body still goes to
    // the temp file via -o (atomic temp/extract flow handled by the caller).
    const result = await runStreamingCaptureStderr(s3CurlArgs(url, destPath));
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to download ${key} from ${url} to ${destPath}.\nManual recovery: download from ${url} and place at ${destPath}.\n${result.stderr}`);
    }
}

async function downloadAndExtractTar(key: string, destDir: string): Promise<void> {
    const tmpFile = path.join(destDir, path.basename(key) + ".tmp");
    await downloadS3File(key, tmpFile);
    console.log(`[AutoSetup] Extracting ${key}...`);
    // Use zstd + tar pipe for cross-platform compat (macOS BSD tar doesn't support --zstd)
    const result = await runAndCapture(["bash", "-c", `zstd -d < "${tmpFile}" | tar xf - -C "${destDir}"`]);
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to extract ${key}: ${result.stderr}`);
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
    const devPrivateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
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
type KeystoreGroup = { type: "zst" | "tar"; key: string; entries: string[] };

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
// Preserve offline restarts by falling back to existence checks when the manifest is unavailable.
async function entryOk(
    manifest: KeystoreManifest | null,
    keystoreDir: string,
    relPath: string,
): Promise<boolean> {
    if (manifest) return verifyKeystoreEntry(manifest, keystoreDir, relPath);
    return exists(path.join(keystoreDir, relPath));
}

async function groupIsCurrent(manifest: KeystoreManifest | null, keystoreDir: string, entries: readonly string[]): Promise<boolean> {
    for (const entry of entries) {
        if (!(await entryOk(manifest, keystoreDir, entry))) return false;
    }
    return true;
}

async function groupVerifies(manifest: KeystoreManifest, keystoreDir: string, entries: readonly string[]): Promise<boolean> {
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
    const bridgeRelayerPath = resolveBridgeRelayerKeystorePath();
    await mkdir(path.dirname(bridgeRelayerPath), { recursive: true });
    let generated = false;

    // Skip S3 download/hash verification when local keystores are intentionally managed
    // (e.g. regenerated after circuit changes). Existence-only checks still apply below
    // for the bridge-relayer wallet keystore.
    if (process.env.PSY_SKIP_KEYSTORE === "1") {
        console.warn("[AutoSetup] PSY_SKIP_KEYSTORE=1 — skipping trust-setup download/hash verification; keeping local ~/.psy/keystore as-is");
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
        ];
        const invalidEntries = await missingOrEmptyKeystoreEntries(
            keystoreDir,
            requiredTrustSetupEntries,
        );
        if (invalidEntries.length > 0) {
            throw new Error(
                `[AutoSetup] PSY_SKIP_KEYSTORE=1 requires a complete local trust setup. ` +
                `Missing or empty files under ${keystoreDir}: ${invalidEntries.join(", ")}. ` +
                `Generate them first or run without PSY_SKIP_KEYSTORE=1 to download the published setup.`,
            );
        }
        // KEYSTORE_PATH overrides only the relayer wallet; trust setup remains under ~/.psy/keystore.
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
    // KEYSTORE_PATH overrides only the relayer wallet; trust setup remains under ~/.psy/keystore.
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

    // 2. Fetch the sha256sums.json manifest (tiny) that pins every trust-setup artifact.
    //    If S3 is unreachable, degrade to existence-check only (no hash verification)
    //    so an offline restart with a complete keystore still works.
    const manifestPath = path.join(keystoreDir, "sha256sums.json");
    let manifest: KeystoreManifest | null = null;
    try {
        await downloadS3File("sha256sums.json", manifestPath);
        const parsed = JSON.parse(await fs.promises.readFile(manifestPath, "utf8")) as KeystoreManifest;
        if (parsed.version !== 1) {
            throw new Error(`unsupported version ${parsed.version} (expected 1)`);
        }
        manifest = parsed;
    } catch (error) {
        console.warn(`[AutoSetup] Could not fetch/parse sha256sums.json (${error}). Falling back to existence-check only.`);
    }

    // 3. Trust-setup groups. Each group is fetched atomically from one S3 object;
    //    every member file is hash-verified against the manifest before and after.
    const groups: KeystoreGroup[] = [
        { type: "zst", key: "circuit_groth16.bin.zst", entries: ["circuit_groth16.bin"] },
        { type: "zst", key: "pk_groth16.bin.zst", entries: ["pk_groth16.bin"] },
        { type: "zst", key: "vk_groth16.bin.zst", entries: ["vk_groth16.bin"] },
        {
            type: "tar",
            key: "deposit_append.tar.zst",
            entries: [
                "deposit_append/circuit_groth16.bin",
                "deposit_append/pk_groth16.bin",
                "deposit_append/vk_groth16.bin",
            ],
        },
        {
            type: "tar",
            key: "withdrawal_claim.tar.zst",
            entries: [
                "withdrawal_claim/circuit_groth16.bin",
                "withdrawal_claim/pk_groth16.bin",
                "withdrawal_claim/vk_groth16.bin",
            ],
        },
    ];

    for (const group of groups) {
        if (await groupIsCurrent(manifest, keystoreDir, group.entries)) {
            console.log(`[AutoSetup] ${group.key}: up to date, skipping`);
            continue;
        }
        console.log(`[AutoSetup] ${group.key}: downloading (missing or hash mismatch)...`);
        if (group.type === "zst") {
            const destPath = path.join(keystoreDir, group.entries[0]);
            const tmpPath = path.join(keystoreDir, group.key + ".downloading");
            await rm(destPath).catch(() => undefined);
            await downloadS3File(group.key, tmpPath);
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
            await downloadAndExtractTar(group.key, keystoreDir);
        }

        // A manifest makes post-download verification mandatory; without one,
        // successful download/extraction remains the only available signal.
        if (manifest) {
            if (!(await groupVerifies(manifest, keystoreDir, group.entries))) {
                throw new Error(
                    `[AutoSetup] ${group.key}: post-download verification failed ` +
                    `(size/sha256 mismatch vs sha256sums.json).`,
                );
            }
            console.log(`[AutoSetup] ${group.key}: verified OK`);
        }
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

async function ensureGenesisFiles(cwd: string): Promise<void> {
    const genesisPath = path.join(cwd, "genesis.json");
    const genesisContractsPath = path.join(cwd, "psy-genesis", "genesis_contracts.json");
    const genesisContractsStampPath = path.join(cwd, "psy-genesis", ".genesis_contracts.compiler-artifact.json");

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
        let expected: GenesisContractsArtifactFingerprint = {
            compilerRevision: stamp.compilerRevision,
            compilerSourcesHash: stamp.compilerSourcesHash,
            artifactSha256: artifactDigest.sha256,
            artifactByteSize: artifactDigest.size,
        };
        const compilerPath = path.resolve(resolveProjectsDir(), "psy-compiler");
        if (await exists(path.join(compilerPath, "Makefile"))) {
            expected = {
                ...(await resolveCompilerArtifactFingerprint(compilerPath)),
                artifactSha256: artifactDigest.sha256,
                artifactByteSize: artifactDigest.size,
            };
        }
        if (evaluateCompilerArtifactStamp(stamp, expected) !== "match") {
            throw new Error(
                "[AutoSetup] psy-genesis compiler artifact stamp does not match the compiler identity or genesis_contracts.json bytes",
            );
        }
    }

    if (await exists(genesisPath)) {
        if (await isUsableGenesisData(genesisPath)) {
            console.log("[AutoSetup] genesis artifacts already exist");
            return;
        }
        console.log("[AutoSetup] genesis.json present but not strict Unix-seconds genesis; regenerating");
    }

    // genesis.json: generated by cargo test in psy_plonky2_circuits
    console.log("[AutoSetup] Generating genesis.json (this may take a few minutes)...");
    const result = await runAndCapture([
        "cargo", "test", "--release", "--package", "psy_plonky2_circuits", "--lib",
        "--", "node::config::networks::local_devnet::tests", "--nocapture",
    ], cwd);
    if (result.code !== 0) {
        throw new Error(`[AutoSetup] Failed to generate genesis.json: ${result.stderr || result.stdout}`);
    }
    console.log("[AutoSetup] genesis.json generated");
}

async function ensureDevEnvironment(
    cwd: string,
    opts?: {
        requireDocker?: boolean;
        requireAnvil?: boolean;
        requireBun?: boolean;
    },
): Promise<void> {
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
    // psy-dapp ships nested psy-genesis/psy-contracts gitlinks that the UI
    // apps alias into (config.json, protocol-config, deployments); initialize
    // them before any UI dependency install or dev-server startup.
    await ensurePsyDappNestedSubmodules(path.join(cwd, "psy-dapp"));
    // Proven order from parth-generic-v1: clone/find siblings (and init
    // psy-sdk's psy-genesis) before ensurePsySdkArtifacts reads config.json.
    await ensureAllReposCloned();
    const contractsDir = path.join(cwd, "psy-contracts");
    const sdk = await ensurePsySdkArtifacts(cwd);
    await ensureAllUiDeps(cwd, { force: sdk.rebuilt });
    const { generated } = await ensureKeystoreFiles(contractsDir);
    await ensureGenesisFiles(cwd);
    await ensureAllBinariesBuilt(cwd);
    // Only set default WALLET_PASSWORD when we generated the keystore this run.
    // For an existing keystore, leave it unset so the prompt/decryption flow still works.
    if (generated && !process.env.WALLET_PASSWORD) {
        process.env.WALLET_PASSWORD = "devnet";
        bridgeRelayerKeystoreGeneratedThisRun = true;
        console.warn("[AutoSetup] WALLET_PASSWORD not set, using default 'devnet' for auto-generated keystore.");
    }
    console.log("[AutoSetup] Dev environment ready.");
}

async function buildProject(cwd?: string) {
    console.log("Building project...");
    const root = cwd || ".";
    const env = {
        ...process.env,
        PSY_CONFIG_PATH: path.join(root, "psy-genesis", "config.json"),
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
    // Some apps ship their own pnpm-workspace.yaml (e.g. mode-a-web-wallet-bridge)
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

async function ensurePsyContractsDependencies(contractsDir: string) {
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
    if (deploymentsNetwork !== "localhost") {
        const hasExistingDeployment = await exists(deploymentSummaryPath);
        if (!forceRedeploy) {
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
            console.log(
                `[DevNet] Reusing existing ${deploymentsNetwork} deployment at ${deploymentSummaryPath} ` +
                `(set REDEPLOY_L1=false to reuse intentionally)`,
            );
            return;
        }
    }
    await ensurePsyContractsDependencies(contractsDir);
    const bridgeRelayerSigner = await loadBridgeRelayerSigner(repoCwd);
    if (deploymentsNetwork.startsWith("localhost")) {
        await setLocalAnvilBalance(l1RpcUrl, bridgeRelayerSigner.address);
        console.log(`[DevNet] funded bridge relayer deployer ${bridgeRelayerSigner.address} on local anvil`);
    }
    console.log(`[DevNet] Deploying psy-contracts to ${deploymentsNetwork}...`);
    const deploymentCfg = (allConfig as any)?.networks?.[deploymentsNetwork] as ConfigNetworkEntry | undefined;
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

async function runAndCapture(cmd: string[], cwd?: string): Promise<{ code: number; stdout: string; stderr: string }> {
    const proc = Bun.spawn(cmd, {
        cwd,
        env: cwd ? { ...process.env, PWD: cwd } : undefined,
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

const ENVIO_NPM_VERSION = "2.32.10";
const ENVIO_HASURA_IMAGE = "hasura/graphql-engine:v2.43.0";
const ENVIO_POSTGRES_IMAGE = "postgres:17.5";

async function configureEnvioDockerCompose(composePath: string, runtimeCpuSet: string | undefined): Promise<void> {
    if (!(await exists(composePath))) {
        throw new Error(`Envio codegen did not create ${composePath}`);
    }
    const original = await Bun.file(composePath).text();
    const pinnedImages = original
        .replace(/image:\s*hasura\/graphql-engine:[^\s]+/g, `image: ${ENVIO_HASURA_IMAGE}`)
        .replace(/image:\s*postgres:[^\s]+/g, `image: ${ENVIO_POSTGRES_IMAGE}`);
    const configured = applyEnvioCpuSetToCompose(pinnedImages, runtimeCpuSet);
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

async function startEnvioIndexerForRelayer(
    repoCwd: string,
    relayerConfigPath: string,
    l1RpcUrlOverride?: string,
    deploymentsNetworkOverride?: string,
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
    const deploymentsNetwork =
        deploymentsNetworkOverride || parseTomlScalar(relayerRaw, "deployments_network") || "localhost";
    const primaryRpcUrl =
        l1RpcUrlOverride ||
        parseTomlScalar(relayerRaw, "rpc_url") ||
        parseTomlScalar(relayerRaw, "l1_rpc_url") ||
        "http://127.0.0.1:8545";
    const localCohort = deploymentsNetwork.startsWith("localhost");
    const cohort = localCohort
        ? [
            { prefix: "ETH", network: "localhost", rpcUrl: primaryRpcUrl },
            { prefix: "BSC", network: "localhostBsc", rpcUrl: process.env.LOCALHOST_BSC_RPC_URL || "http://127.0.0.1:9545" },
            { prefix: "BASE", network: "localhostBase", rpcUrl: process.env.LOCALHOST_BASE_RPC_URL || "http://127.0.0.1:10545" },
        ]
        : [
            { prefix: "ETH", network: "sepolia", rpcUrl: process.env.SEPOLIA_RPC_URL || protocolConfig.chains.sepolia.defaultRpcUrl || "" },
            { prefix: "BSC", network: "bscTestnet", rpcUrl: process.env.BSC_TESTNET_RPC_URL || protocolConfig.chains.bscTestnet.defaultRpcUrl || "" },
            { prefix: "BASE", network: "baseSepolia", rpcUrl: process.env.BASE_SEPOLIA_RPC_URL || protocolConfig.chains.baseSepolia.defaultRpcUrl || "" },
        ];

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
        const deployedPath = path.join(repoCwd, "psy-contracts", "deployments", target.network, "deployed-contracts.json");
        if (!(await exists(deployedPath))) throw new Error(`missing deployed contracts summary: ${deployedPath}`);
        const deployed = JSON.parse(await Bun.file(deployedPath).text()) as any;
        const chainId = Number(deployed?.chainId ?? deployed?.protocol?.chain?.l1ChainId);
        const expected = (protocolConfig.chains as any)[target.network];
        if (!Number.isFinite(chainId) || chainId !== expected?.l1ChainId) {
            throw new Error(`invalid chainId in ${deployedPath}: expected ${expected?.l1ChainId}, got ${chainId}`);
        }
        const bridge = deployed?.core?.Bridge || deployed?.contracts?.Bridge;
        const stateManager = deployed?.core?.StateManager || deployed?.contracts?.StateManager;
        if (!bridge || !stateManager) throw new Error(`missing Bridge/StateManager in ${deployedPath}`);
        const blocks = await Promise.all([
            readArtifactBlockNumber(target.network, "Bridge_Proxy"),
            readArtifactBlockNumber(target.network, "StateManager_Proxy"),
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
    let config = template;
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
    const envioGeneratedDir = path.join(envioDir, "generated");
    const envioComposeFile = path.join(envioGeneratedDir, "docker-compose.yaml");
    await configureEnvioDockerCompose(envioComposeFile, runtimeCpuSet);

    if (resetStorage) {
        console.log("[DevNet] Resetting Envio storage for ephemeral Anvil chain...");
        const reset = await runAndCapture(
            ["docker", "compose", "-f", envioComposeFile, "down", "--remove-orphans", "-v"],
            repoCwd,
        );
        if (reset.code !== 0) {
            throw new Error(`[DevNet] Failed to reset Envio storage (exit ${reset.code}): ${reset.stderr || reset.stdout}`);
        }
    }

    console.log("[DevNet] Starting Envio docker services...");
    const composeStart = await runAndCapture(
        ["docker", "compose", "-f", envioComposeFile, "up", "-d"],
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
        ["docker", "exec", "generated-envio-postgres-1", "psql", "-U", "postgres", "-d", "postgres", "-c", "select 1"],
        { attempts: 600, delayMs: 1000, name: "Envio Postgres SQL readiness" },
    );
    await waitForHttpUrl("http://127.0.0.1:8080/healthz", {
        attempts: 600,
        delayMs: 1000,
        timeoutMs: 1500,
        name: "Envio GraphQL",
    });

    await ensurePnpmBuildScriptsApproved(envioGeneratedDir, ["rescript"]);
    await pnpmInstallWithAutoApprove(envioGeneratedDir);
    const buildGenerated = await runAndCapture(["pnpm", "build"], envioGeneratedDir);
    if (buildGenerated.code !== 0) {
        throw new Error(`envio generated build failed: ${buildGenerated.stderr || buildGenerated.stdout}`);
    }

    console.log("[DevNet] Starting Envio indexer (pnpm start)...");
    const envioProcess = await RunningProcess.spawn(["pnpm", "start"], {
        cwd: envioDir,
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

async function cleanCheckpoint(checkpointPath: string, cwd: string = '.') {
    const fullPath = path.resolve(cwd, checkpointPath);
    if (await exists(fullPath)) {
        await rmdir(fullPath, { recursive: true });
    }
}

async function runIgnoreErrors(cmd: string[], cwd?: string): Promise<void> {
    try {
        await runAndCapture(cmd, cwd);
    } catch {
        // best-effort teardown helper
    }
}

async function killGeneratedEnvioStack(cwd: string, purge: boolean): Promise<void> {
    const composeFile = path.join(cwd, "psy_cli", "psy_relayer_cli", "indexer", "envio", "generated", "docker-compose.yaml");
    if (!(await exists(composeFile))) return;
    const args = ["docker", "compose", "-f", composeFile, "down", "--remove-orphans"];
    if (purge) args.push("-v");
    await runIgnoreErrors(args, cwd);
}

async function killKnownProcesses(): Promise<void> {
    const patterns = [
        "bash dev/start_db.sh",
        "bun run dev/locSetupV4.ts",
        "psy_node_cli",
        "psy_worker_cli",
        "psy_user_cli prove-proxy",
        "psy_user_cli faucet-server",
        "psy-services/target/release/psy-services",
        "psy-services/target/release/psy-indexer",
        "cargo run --release --bin psy-services",
        "cargo run --release --bin psy-indexer",
        "anvil --port 8545",
        "anvil --port 9545",
        "anvil --port 10545",
        "hardhat node",
        "dummy_prover.sh prove_random",
        "client_prover/psy_bridge",
        "client_prover/psy_privacy",
        "psy-dapp/apps/bridge",
        "psy-dapp/apps/ide",
        "psy-dapp/apps/explorer",
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

async function killKnownPorts(): Promise<void> {
    const ports: number[] = [3000, 5433, 8080, 8081, 8545, 9545, 10545, 9898, 9998, 5174, 5175, 5176, 5177, 5178];
    for (let p = 1337; p <= 1346; p++) ports.push(p);
    for (let p = 9999; p <= 10008; p++) ports.push(p);
    for (let p = 13380; p <= 14670; p += 10) ports.push(p);
    for (const port of ports) {
        await runIgnoreErrors([
            "bash",
            "-lc",
            `if command -v lsof >/dev/null 2>&1; then lsof -tiTCP:${port} -sTCP:LISTEN 2>/dev/null | xargs -r kill -9 2>/dev/null || true; elif command -v fuser >/dev/null 2>&1; then fuser -k ${port}/tcp >/dev/null 2>&1 || true; fi`,
        ]);
    }
}

async function teardownDevnet(cwd: string = ".", purge: boolean = false): Promise<void> {
    console.log(`
[DevNet] Tearing down...${purge ? " (purge)" : ""}`);
    await killKnownProcesses();
    await killDocker();
    await runIgnoreErrors(["docker", "rm", "-f", "valkey-server", "nats-server", "scylla-server", "nostr-relay"]);
    await killGeneratedEnvioStack(cwd, purge);
    await killKnownPorts();
    if (purge) {
        console.log("[DevNet] Purging local checkpoints, logs, deployments, and Docker volumes...");
        await cleanCheckpoint("./local_checkpoints", cwd);
        await cleanCheckpoint("./logs", cwd);
        await cleanCheckpoint("./psy-contracts/deployments/localhost", cwd);
        await cleanCheckpoint("./psy-contracts/deployments/sepolia", cwd);
        await cleanCheckpoint("./psy-contracts/deployments/ethereum", cwd);
        await runIgnoreErrors(["docker", "volume", "rm", "-f", "psy-devnet-redis", "psy-devnet-scylla", "psy-devnet-scylla-data", "psy-devnet-nats"]);
    }
}

interface ProcessOptions {
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
    cleanState?: boolean;
}

class DevNetProcessManager {
    spawnedProcesses: RunningProcess[] = [];
    needsStartDb: boolean = false;
    /** When true, exited children must not be auto-restarted (teardown/Ctrl+C). */
    private stopping: boolean = false;

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
            // Deliberately do not set intentionalStop: this is supervised
            // dependency recovery, so handleSupervisedExit must respawn it.
            process.proc.kill("SIGTERM");
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

    /**
     * Processor binaries emit a fatal CFLI error marker but may keep running
     * while producing empty blocks. Detect that marker in their output and
     * terminate the process without marking the stop intentional, so the
     * existing auto-restart path recreates it. `fatalRestartRequested` guards
     * against repeated kills for duplicate log lines. DB-recovery restarts
     * (dependencyRestartRequested) are independent and remain unchanged.
     */
    private wireFatalProcessorSupervision(p: RunningProcess): void {
        if (!this.autoRestartEnabled() || !this.isProcessorProcess(p)) return;
        const originalVisitor = p.allOutputVisitor;
        p.allOutputVisitor = (line: string, process: RunningProcess) => {
            if (shouldFatalRestartProcessor(line, process.fatalRestartRequested)) {
                process.fatalRestartRequested = true;
                console.warn(
                    `[DevNet][supervisor] fatal processor error detected for '${process.name}' ` +
                    `(pid=${process.pid}); terminating for supervised restart`
                );
                // Deliberately do not set intentionalStop: handleSupervisedExit
                // must respawn the processor after it exits.
                try {
                    process.proc.kill("SIGTERM");
                } catch (err) {
                    console.warn(`[DevNet][supervisor] failed to signal fatal processor '${process.name}': ${err}`);
                }
            }
            originalVisitor(line, process);
        };
    }

    private async handleSupervisedExit(
        previous: RunningProcess,
        code: number | null,
        signal: number | null,
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

        previous.restartCount += 1;
        const attempt = previous.restartCount;
        const delayMs = Math.min(30_000, 1_000 * Math.pow(2, Math.min(attempt - 1, 5)));
        const cmdStr = previous.cmds.join(" ");
        const ts = new Date().toISOString();
        console.warn(
            `[DevNet][supervisor] process '${name}' EXITED (code=${code}, signal=${signal}, pid=${previous.pid}); ` +
            `will RESTART in ${delayMs}ms (restart #${attempt}) cmd=${cmdStr}`
        );

        await new Promise((r) => setTimeout(r, delayMs));
        if (this.stopping) {
            console.log(`[DevNet][supervisor] process '${name}' restart aborted (teardown in progress)`);
            return;
        }

        const banner =
            `\n===== [DevNet supervisor] RESTART #${attempt} at ${ts} ` +
            `(previous exit code=${code}, signal=${signal}, previous pid=${previous.pid}) =====\n` +
            `===== service: ${name} =====\n` +
            `===== cmd: ${cmdStr} =====\n`;

        try {
            const opts = {
                ...previous.spawnOptions,
                appendLogs: true,
                logBanner: banner,
            };
            let restarted: RunningProcess;
            if (previous.useInitHint && previous.hintDetector) {
                restarted = await RunningProcess.spawnWithInitializationHintWithRetry(
                    previous.cmds,
                    previous.hintDetector,
                    {
                        ...opts,
                        maxRetries: previous.initMaxRetries,
                        retryDelayMs: previous.initRetryDelayMs,
                    },
                );
            } else {
                restarted = await RunningProcess.spawn(previous.cmds, opts);
            }

            restarted.name = name;
            restarted.restartCount = previous.restartCount;
            restarted.cmds = previous.cmds.slice();
            restarted.spawnOptions = {
                ...previous.spawnOptions,
                appendLogs: true,
            };
            restarted.hintDetector = previous.hintDetector;
            restarted.useInitHint = previous.useInitHint;
            restarted.initMaxRetries = previous.initMaxRetries;
            restarted.initRetryDelayMs = previous.initRetryDelayMs;

            const idx = this.spawnedProcesses.indexOf(previous);
            if (idx >= 0) this.spawnedProcesses[idx] = restarted;
            else this.spawnedProcesses.push(restarted);
            this.wireAutoRestart(restarted);
            this.wireFatalProcessorSupervision(restarted);

            console.log(
                `[DevNet][supervisor] process '${name}' RESTARTED successfully ` +
                `(new pid=${restarted.pid}, restart #${attempt})`
            );
            await RunningProcess.appendLogBanner(
                restarted.spawnOptions.stdoutLogFile,
                `[DevNet][supervisor] process '${name}' is UP again pid=${restarted.pid} restart #${attempt}\n`,
            );
            await RunningProcess.appendLogBanner(
                restarted.spawnOptions.stderrLogFile,
                `[DevNet][supervisor] process '${name}' is UP again pid=${restarted.pid} restart #${attempt}\n`,
            );
            if (name === "db") {
                this.restartProcessorsAfterDbRecovery();
            }
        } catch (err) {
            console.error(
                `[DevNet][supervisor] process '${name}' restart #${attempt} FAILED: ${err}`
            );
            if (!this.stopping) {
                const retryDelay = Math.min(60_000, delayMs * 2);
                console.warn(
                    `[DevNet][supervisor] will retry '${name}' again in ${retryDelay}ms (still counting as restart #${attempt})`
                );
                await new Promise((r) => setTimeout(r, retryDelay));
                // Decrement so the next handleSupervisedExit increments back to the same attempt number + 1
                // Actually we want attempt to keep growing: leave restartCount as-is and call again with synthetic exit.
                previous.hasExited = true;
                previous.intentionalStop = false;
                // Call again — restartCount will go to attempt+1
                void this.handleSupervisedExit(previous, code, signal);
            }
        }
    }

    private getEnv(): { [key: string]: string } | undefined {
        if (this.envVars) {
            return { ...process.env, ...this.envVars };
        }
        return undefined;
    }

    private getEnvWithRustLogDirective(directive: string): { [key: string]: string } {
        const env = this.getEnv() || { ...process.env } as { [key: string]: string };
        const current = env["RUST_LOG"]?.trim();
        if (!current) {
            return { ...env, RUST_LOG: directive };
        }
        const directives = current.split(",").map((s) => s.trim()).filter(Boolean);
        if (directives.some((d) => d === directive || d.startsWith(`${directive.split("=")[0]}=`) || d === directive.split("=")[0])) {
            return env;
        }
        return { ...env, RUST_LOG: `${current},${directive}` };
    }

    async setupProcesses(options: ProcessOptions): Promise<void> {
        const cwd = options?.cwd || ".";
        const jtmb = !!options?.jtmb;
        const l1Port = options.l1Port ?? 8545;
        const { l1Network, l1Fork, cfgEntry } = resolveL1Selection();
        const deploymentsNetwork: L1NetworkName = l1Fork ? "localhost" : l1Network;
        const localL1RpcUrl = resolveLocalL1RpcUrl(l1Port);
        const l1RpcUrl = (l1Network === "localhost" || l1Fork) ? localL1RpcUrl : resolveExternalL1RpcUrl(l1Network);
        const relayerChains = deploymentsNetwork.startsWith('localhost')
            ? [
                { chainIndex: 0, networkId: 'localhost', deploymentsNetwork: 'localhost', rpcUrl: l1RpcUrl },
                { chainIndex: 1, networkId: 'localhostBsc', deploymentsNetwork: 'localhostBsc', rpcUrl: process.env.LOCALHOST_BSC_RPC_URL || 'http://127.0.0.1:9545' },
                { chainIndex: 2, networkId: 'localhostBase', deploymentsNetwork: 'localhostBase', rpcUrl: process.env.LOCALHOST_BASE_RPC_URL || 'http://127.0.0.1:10545' },
            ]
            : [
                { chainIndex: 0, networkId: 'sepolia', deploymentsNetwork: 'sepolia', rpcUrl: process.env.SEPOLIA_RPC_URL || protocolConfig.chains.sepolia.defaultRpcUrl },
                { chainIndex: 1, networkId: 'bscTestnet', deploymentsNetwork: 'bscTestnet', rpcUrl: process.env.BSC_TESTNET_RPC_URL || protocolConfig.chains.bscTestnet.defaultRpcUrl },
                { chainIndex: 2, networkId: 'baseSepolia', deploymentsNetwork: 'baseSepolia', rpcUrl: process.env.BASE_SEPOLIA_RPC_URL || protocolConfig.chains.baseSepolia.defaultRpcUrl },
            ];
        const workerRealmCount = options.workerRealmCount;
        const realmEdgeCount = options.realmEdgeCount;
        const coordinatorEdgeCount = options.coordinatorEdgeCount;
        const coordinatorWorkersCount = options.coordinatorWorkersCount;
        this.genesisDataPath = options.genesisDataPath || "genesis.json";
        const cleanState = !!options.cleanState;
        const skipBuild = skipBuildEnabled();


        const disableWorkerEdgeLogs = !!options.disableWorkerEdgeLogs;
        // Determine what components to start
        const hasOnlyOptions = !!options.db || !!options.coordinator || (options.proveProxyCount || 0) > 0 || !!options.faucetServer || (options.dummyProvers || 0) > 0 || !!options.l1 || !!options.relayer || !!options.bridgeUi || !!options.privacyUi || !!options.psyPrivacyBridge || !!options.ide || !!options.explorer || !!options.modeAWebWalletBridge;
        const startAll = !hasOnlyOptions;
        const startBridgeProposerDaemon = startAll || !!options.bridgeProposerDaemon || !!options.relayer || !!options.bridgeUi;

        const startCoordinatorProcessor = startAll || !!options.coordinator;
        const startCoordinatorWorkers = coordinatorWorkersCount > 0;
        const startRealmProcessor = startAll || !!options.coordinator;
        const startRealmWorkers = workerRealmCount > 0;

        const needsStartDb = !hasOnlyOptions || !!options.db;
        const startRealmId = options.startRealmId || 0;
        const realmsCount = options.realmsCount !== undefined ? options.realmsCount : (startAll ? 1 : 1);
        const endRealmId = startRealmId + realmsCount - 1;
        const provingProcessCount = coordinatorWorkersCount
            + workerRealmCount
            + (options.dummyProvers || 0)
            + ((options.proveProxyCount || 0) > 0 ? options.proveProxyCount || 0 : (startAll ? 1 : 0));
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

        // 2. Start Database
        if (this.needsStartDb) {
            if (cleanState) {
                console.log("[DevNet] Cleaning local checkpoints...");
                await cleanCheckpoint('./local_checkpoints', cwd);
                console.log("[DevNet] Removing persisted devnet Docker volumes...");
                await runAndCapture(["docker", "volume", "rm", "-f", "psy-devnet-redis", "psy-devnet-scylla", "psy-devnet-scylla-data", "psy-devnet-nats"]);
            }

            console.log("[DevNet] Killing existing docker containers...");
            await killDocker();
            const startDbCmd = ['./dev/start_db.sh', '--persist'];
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
                        '--verbose'
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

        let processorReadiness: Promise<void> = Promise.resolve();

        if (startRealmProcessor) {
            processorReadiness = (async () => {
                console.log(`[DevNet] Starting ${realmsCount} realm processors and edges sequentially...`);
                for (let b = 0; b < realmsCount; b += 4) {
                    const batchSize = Math.min(4, realmsCount - b);
                    const realmIds = Array.from(
                        { length: batchSize },
                        (_, i) => startRealmId + b + i,
                    );

                    await startRealmProcessorBatchSequentially(
                        realmIds,
                        async (realmId) => {
                            const realmLogPaths = getLogPaths(`realm_${realmId}_processor`, false);
                            const proc = await retryProcessorStartup(
                                `realm ${realmId} processor`,
                                (attempt, totalAttempts) => RunningProcess.spawnWithInitializationHint(
                                    [
                                        nodeCli, 'start-realm-processor',
                                        '--realm-id', realmId.toString(),
                                        '--realm-sub-id', '1',
                                        '--network', this.NETWORK,
                                        '--db-namespace', 'realm_' + realmId,
                                        '--scylla-db-url', this.SCYLLA_URL,
                                        '--nats-jetstream-url', this.NATS_URL,
                                        '--redis-url', this.REDIS_URL,
                                        '--genesis-data-path', this.genesisDataPath,
                                        '--checkpoint-backup-path', './local_checkpoints',
                                        '--coordinator-api-urls', this.COORD_API_URL,
                                        '--proving-backend', backend,
                                        '--verbose'
                                    ],
                                    (line) => isExactProcessorReadyLine(line, REALM_PROCESSOR_READY_MARKER),
                                    {
                                        cwd,
                                        ...realmLogPaths,
                                        initializationTimeoutMs: 180_000,
                                        env: this.getEnv(),
                                        appendLogs: attempt > 1,
                                        logBanner: `===== realm ${realmId} processor readiness attempt ${attempt}/${totalAttempts} =====`,
                                    },
                                ),
                                { maxRetries: 3, retryDelayMs: 2000 },
                            );
                            this.track(proc);
                            return proc;
                        },
                    );
                    console.log(`[DevNet] Batch ${b/4 + 1} realm processors finished genesis initialization.`);

                    const realmEdgesPromises: Promise<RunningProcess>[] = [];
                    for (let i = 0; i < batchSize; i++) {
                        const realmId = startRealmId + b + i;
                        const realmEdgeStartPort = 13380 + realmId * 10;
                        for (let j = 0; j < realmEdgeCount; j++) {
                            const port = realmEdgeStartPort + j;
                            const edgePromise = RunningProcess.spawnWithInitializationHintWithRetry(
                                [
                                    nodeCli, 'start-realm-edge',
                                    '--realm-id', realmId.toString(),
                                    '--realm-sub-id', '1',
                                    '--network', this.NETWORK,
                                    '--db-namespace', 'realm_' + realmId,
                                    '--scylla-db-url', this.SCYLLA_URL,
                                    '--nats-jetstream-url', this.NATS_URL,
                                    '--redis-url', this.REDIS_URL,
                                    '--port', port.toString(),
                                    '--listen', '0.0.0.0',
                                    '--proving-backend', backend,
                                    '--verbose'
                                ],
                                realmEdgeProcessorStartedDetector,
                                { cwd, ...getLogPaths(`realm_edge_${realmId}_${j}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                            ).then(proc => this.track(proc));
                            realmEdgesPromises.push(edgePromise);
                        }
                    }
                    await Promise.all(realmEdgesPromises);
                    console.log(`[DevNet] Batch ${b/4 + 1} realm edges started. Waiting 2 seconds before starting next batch...`);
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
                console.log(`[DevNet] All realm processors and edges started`);
            })();
        }

        await startAfterPrerequisite(processorReadiness, startCoordinatorWorkerProcesses);

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
                        const realmEdgeStartPort = 13380 + realmId * 10;

                        // Connect to all edges of this realm for better load distribution
                        for (let edgeIndex = 0; edgeIndex < realmEdgeCount; edgeIndex++) {
                            const edgePort = realmEdgeStartPort + edgeIndex;
                            const realmUrl = `http://${this.host}:${edgePort}`;
                            realmUrls.push(realmUrl);
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
                    const realmEdgeStartPort = 13380 + realmId * 10;

                    const realmUrls: string[] = [];
                    // Connect to all edges of this realm
                    for (let edgeIndex = 0; edgeIndex < realmEdgeCount; edgeIndex++) {
                        const edgePort = realmEdgeStartPort + edgeIndex;
                        const realmUrl = `http://${this.host}:${edgePort}`;
                        realmUrls.push(realmUrl);
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

        // 9. Prove Proxy
        // Groth16 preload is 3–4 minutes and does not depend on Anvil/Envio.
        // Spawn now, keep warming in the background, and only wait for :9999
        // before the proof-consuming relayer (and before setupProcesses returns).
        const proveProxyReady: Promise<void>[] = [];
        const proveProxyCount = options.proveProxyCount || 0;
        if (proveProxyCount > 0 || startAll) {
            const count = proveProxyCount || 1;
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

        // 10. L1 (Anvil)
        if (options.l1 || startAll) {
            if (l1Network === "localhost" && !l1Fork) {
                const localChains = [
                    { network: "localhost" as const, port: l1Port, logName: "l1_anvil" },
                    { network: "localhostBsc" as const, port: 9545, logName: "l1_anvil_bsc" },
                    { network: "localhostBase" as const, port: 10545, logName: "l1_anvil_base" },
                ];
                for (const localChain of localChains) {
                    const chainMeta = protocolConfig.chains[localChain.network];
                    const rpcUrl = resolveLocalL1RpcUrl(localChain.port);
                    const args = [
                        'anvil', '--host', '0.0.0.0', '--port', String(localChain.port),
                        '--chain-id', String(chainMeta.l1ChainId), '--steps-tracing', '-vvvv',
                    ];
                    await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                        args,
                        l1StartedDetector,
                        { cwd, ...getLogPaths(localChain.logName, false), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() },
                    ));
                    await waitForHttpUrl(rpcUrl, {
                        attempts: 30, delayMs: 500, timeoutMs: 1500, name: `${chainMeta.name} RPC`,
                    });
                    await deployPsyContracts(cwd, rpcUrl, localChain.network, {
                        fundDevAccounts: true,
                        localAnvilRpcUrl: rpcUrl,
                    });
                    console.log(`[DevNet] ${chainMeta.name} started and deployed on ${rpcUrl}`);
                }
            } else if (l1Fork) {
                const chainMeta = protocolConfig.chains[l1Network];
                if (!chainMeta) throw new Error(`[DevNet] protocolConfig.chains.${l1Network} missing`);
                const effectiveL1ChainId = protocolConfig.chains.localhost.l1ChainId;
                const l1ForkArgs = ['anvil', '--host', '0.0.0.0', '--port', String(l1Port), '--chain-id', String(effectiveL1ChainId), '--steps-tracing', '-vvvv'];
                if (l1Fork) {
                    const forkEnvKey = cfgEntry.anvilForkSourceUrlEnv;
                    if (!forkEnvKey) throw new Error(`[DevNet] cannot fork ${l1Network}: missing anvilForkSourceUrlEnv in config.json`);
                    const forkRpcUrl = process.env[forkEnvKey];
                    if (!forkRpcUrl) {
                        throw new Error(`[DevNet] VITE_FORK=true requires env ${forkEnvKey}`);
                    }
                    l1ForkArgs.push('--fork-url', forkRpcUrl);
                    const forkBlock = process.env.VITE_FORK_BLOCK_NUMBER;
                    if (forkBlock && forkBlock.trim().length > 0) {
                        l1ForkArgs.push('--fork-block-number', forkBlock.trim());
                    }
                    console.log(`[DevNet] Starting L1 anvil in ${l1Network} fork mode`);
                }
                await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                    l1ForkArgs,
                    l1StartedDetector,
                    { cwd, ...getLogPaths('l1_anvil', false), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                ));
                console.log(`[DevNet] L1 (anvil${l1Fork ? ` ${l1Network}-fork` : ''}) started on ${localL1RpcUrl}`);
                await waitForHttpUrl(localL1RpcUrl, {
                    attempts: 30,
                    delayMs: 500,
                    timeoutMs: 1500,
                    name: "L1 RPC"
                });
                await deployPsyContracts(cwd, l1RpcUrl, deploymentsNetwork, {
                    fundDevAccounts: true,
                    localAnvilRpcUrl: localL1RpcUrl,
                });
            } else {
                console.log(`[DevNet] Using external L1 network ${l1Network} via ${l1RpcUrl}`);
                await waitForHttpUrl(l1RpcUrl, {
                    attempts: 30,
                    delayMs: 1000,
                    timeoutMs: 3000,
                    name: `${l1Network} RPC`
                });
                await deployPsyContracts(cwd, l1RpcUrl, deploymentsNetwork, {
                    fundDevAccounts: false,
                    localAnvilRpcUrl: localL1RpcUrl,
                });
            }
        }

        // 11. Bridge dependencies (Envio + psy-services)
        if (options.relayer || options.bridgeUi || startAll) {
            const relayerConfig = options.relayerConfig || './psy_cli/psy_relayer_cli/config/local.toml';
            const relayerCfgPath = path.isAbsolute(relayerConfig) ? relayerConfig : path.join(cwd, relayerConfig);
            const relayerRaw = await Bun.file(relayerCfgPath).text();
            const coordinatorRpcUrl = parseTomlScalar(relayerRaw, "coordinator_rpc_url") || "http://127.0.0.1:1337";
            const relayerL1RpcUrl = (l1Network === "localhost" || l1Fork)
                ? (parseTomlScalar(relayerRaw, "rpc_url") || l1RpcUrl)
                : l1RpcUrl;

            // Ensure relayer dependencies are up before spawning it.
            await waitForHttpUrl(relayerL1RpcUrl, { attempts: 30, delayMs: 1000, timeoutMs: 1500, name: "L1 RPC" });
            await waitForHttpUrl(coordinatorRpcUrl, { attempts: 30, delayMs: 1000, timeoutMs: 1500, name: "Coordinator RPC" });

            const envioProc = await startEnvioIndexerForRelayer(
                cwd,
                relayerConfig,
                (l1Network === "localhost" || l1Fork) ? undefined : l1RpcUrl,
                deploymentsNetwork,
                this.getEnv(),
                (options.l1 || startAll) && (l1Network === "localhost" || l1Fork),
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
                console.log('[DevNet] PSY_SKIP_BUILD=1 — using existing psy-services release binaries');
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
                return {
                    chain_index: chain.chainIndex,
                    rpc_url: chain.rpcUrl,
                    state_manager_address: address,
                };
            }));

            await Bun.spawn(['docker', 'exec', 'generated-envio-postgres-1', 'dropdb', '-U', 'postgres', '--if-exists', 'psy_services'], {
                stdio: ['ignore', 'ignore', 'ignore'],
            }).exited;
            await Bun.spawn(['docker', 'exec', 'generated-envio-postgres-1', 'createdb', '-U', 'postgres', 'psy_services'], {
                stdio: ['ignore', 'ignore', 'ignore'],
            }).exited;
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
                const edgePort = 13380 + (realmId * 10);
                const realmSubId = 1;
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

            // 11.5 Unified bridge relayer
            const proofDir = path.resolve(cwd, 'local_checkpoints', 'bridge_proposer');
            await mkdir(proofDir, { recursive: true });
            const daemonConfigPath = path.join(proofDir, 'daemon.toml');
            const daemonConfig = [
                `rpc_config = "psy-genesis/config.json"`,
                `services_url = "http://127.0.0.1:3000"`,
                `withdraw_method_id = 4159421846`,
                `proof_dir = "${proofDir.replaceAll('\\', '\\\\')}"`,
                `poll_interval_secs = 15`,
                `confirmation_lag_checkpoints = 3`,
                ``,
                `[relayer_wallet]`,
                `sign_type = "ZKSign"`,
                `keystore_path = "${resolveBridgeRelayerKeystorePath().replaceAll('\\', '\\\\')}"`,
                ``,
                `[finalize]`,
                `l1_rpc_url = "${l1RpcUrl}"`,
                `deployments_network = "${deploymentsNetwork}"`,
                `keystore_path = "${resolveBridgeRelayerKeystorePath().replaceAll('\\', '\\\\')}"`,
                `password_env = "WALLET_PASSWORD"`,
                ``,
                ...relayerChains.flatMap((chain) => [
                    `[[chains]]`,
                    `family = "evm"`,
                    `chain_index = ${chain.chainIndex}`,
                    `network_id = "${chain.networkId}"`,
                    `rpc_urls = ["${chain.rpcUrl}"]`,
                    `deployments_network = "${chain.deploymentsNetwork}"`,
                    `keystore_path = "${resolveBridgeRelayerKeystorePath().replaceAll('\\', '\\\\')}"`,
                    `password_env = "WALLET_PASSWORD"`,
                    ``,
                ]),
            ].join('\n');
            await writeFile(daemonConfigPath, daemonConfig, 'utf8');

            this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                ['./target/release/psy_relayer_cli', '--config', daemonConfigPath],
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
            const modeAWebWalletBridgeDir = path.join(cwd, 'psy-dapp', 'mode-a-web-wallet-bridge');
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
                                + `[DevNet] Make sure the psy-sdk workspace is checked out at the path expected by psy-dapp/mode-a-web-wallet-bridge/package.json.`,
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
                ['bun', 'run', 'dev', '--', '--host', '0.0.0.0', '--port', '5179', '--strictPort'],
                uiStartedDetector,
                {
                    cwd: modeAWebWalletBridgeDir,
                    ...getLogPaths('mode_a_web_wallet_bridge', false),
                    env: {
                        ...this.getEnv(),
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

        const hasOnlyOptions = !!options.db || !!options.coordinator || (options.proveProxyCount || 0) > 0 || !!options.faucetServer || (options.dummyProvers || 0) > 0 || !!options.l1 || !!options.relayer || !!options.bridgeUi || !!options.privacyUi || !!options.psyPrivacyBridge || !!options.ide || !!options.explorer || !!options.modeAWebWalletBridge;
        const startAll = !hasOnlyOptions;

        const startCoordinatorProcessor = startAll || !!options.coordinator;
        const startCoordinatorWorkers = coordinatorWorkersCount > 0;
        const startRealmProcessor = startAll || !!options.coordinator;
        const startRealmWorkers = workerRealmCount > 0;

        const needsStartDb = !hasOnlyOptions || !!options.db;
        const startRealmId = options.startRealmId || 0;
        const realmsCount = options.realmsCount !== undefined ? options.realmsCount : (startAll ? 1 : 1);
        const endRealmId = startRealmId + realmsCount - 1;

        const backend = this.provingBackend || (jtmb ? 'jtmb-poseidon-goldilocks' : 'plonky2-poseidon-goldilocks');

        const services: any = {};
        const networkName = "psy-devnet";

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
        if (!runtimeResources.scyllaCpuSet) {
            scyllaCommand.push("--overprovisioned", "1");
        }
        const filteredEnv: Record<string, string> = {
            "RUST_LOG": env["RUST_LOG"] || "info",
            "RUST_BACKTRACE": "1",
            "RAYON_NUM_THREADS": runtimeResources.env.RAYON_NUM_THREADS,
            "PSY_WORKER_BATCH_SIZE": runtimeResources.env.PSY_WORKER_BATCH_SIZE,
        };
        Object.assign(filteredEnv, selectNonEmptyEnv(env, FAUCET_ENV_KEYS));
        const envList = Object.entries(filteredEnv).map(([k, v]) => `${k}=${v}`);

        // Infrastructure
        if (needsStartDb) {
            services["valkey-server"] = {
                image: "valkey/valkey",
                container_name: "valkey-server",
                ports: ["6379:6379"],
                volumes: ["psy-devnet-redis:/data"],
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
                container_name: "nats-server",
                ports: ["4222:4222"],
                volumes: ["psy-devnet-nats:/data"],
                ...(runtimeResources.runtimeCpuSet ? { cpuset: runtimeResources.runtimeCpuSet } : {}),
                command: ["-js", "-sd", "/data"]
            };

            services["scylla-server"] = {
                image: "scylladb/scylla:latest",
                container_name: "scylla-server",
                ports: ["9042:9042"],
                cap_add: ["PERFMON"],
                ...(runtimeResources.scyllaCpuSet ? { cpuset: runtimeResources.scyllaCpuSet } : {}),
                volumes: [
                    "psy-devnet-scylla:/var/lib/scylla",
                    "psy-devnet-scylla-data:/run/udev/data"
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
            container_name: name,
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
                        "--verbose"
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
            for (let i = 0; i < realmsCount; i++) {
                const realmId = startRealmId + i;
                services[`realm-${realmId}-processor`] = getRuntimeServiceEntry(`realm-${realmId}-processor`, [
                    "/app/bin/psy_node_cli", "start-realm-processor",
                    "--realm-id", realmId.toString(),
                    "--realm-sub-id", "1",
                    "--network", this.NETWORK,
                    "--db-namespace", `realm_${realmId}`,
                    "--scylla-db-url", "scylla-server:9042",
                    "--nats-jetstream-url", "nats://nats-server:4222",
                    "--redis-url", "redis://valkey-server:6379",
                    "--genesis-data-path", this.genesisDataPath,
                    "--checkpoint-backup-path", "/app/local_checkpoints",
                    "--coordinator-api-urls", `http://coordinator-edge-0:1337`,
                    "--proving-backend", backend,
                    "--verbose"
                ]);

                for (let j = 0; j < realmEdgeCount; j++) {
                    const port = 13380 + realmId * 10 + j;
                    services[`realm-${realmId}-edge-${j}`] = {
                        ...getRuntimeServiceEntry(`realm-${realmId}-edge-${j}`, [
                            "/app/bin/psy_node_cli", "start-realm-edge",
                            "--realm-id", realmId.toString(),
                            "--realm-sub-id", "1",
                            "--network", this.NETWORK,
                            "--db-namespace", `realm_${realmId}`,
                            "--scylla-db-url", "scylla-server:9042",
                            "--nats-jetstream-url", "nats://nats-server:4222",
                            "--redis-url", "redis://valkey-server:6379",
                            "--port", port.toString(),
                            "--listen", "0.0.0.0",
                            "--proving-backend", backend,
                            "--verbose"
                        ]),
                        ports: [`${port}:${port}`]
                    };
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
                    for (let j = 0; j < realmEdgeCount; j++) {
                         const port = 13380 + realmId * 10 + j;
                         workerArgs.push("--realm-api-url", `http://realm-${realmId}-edge-${j}:${port}`);
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
            "psy-devnet-redis": { name: "psy-devnet-redis" },
            "psy-devnet-scylla": { name: "psy-devnet-scylla" },
            "psy-devnet-scylla-data": { name: "psy-devnet-scylla-data" },
            "psy-devnet-nats": { name: "psy-devnet-nats" }
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
        let fullYaml = yamlString + "\nvolumes:\n  psy-devnet-redis: {}\n  psy-devnet-scylla: {}\n  psy-devnet-scylla-data: {}\n  psy-devnet-nats: {}\n";
        
        await writeFile("docker-compose.yml", fullYaml);
        console.log("[DevNet] Generated docker-compose.yml (Clean YAML)");
        
        console.log("[DevNet] Starting via docker-compose...");
        const proc = Bun.spawn(["docker", "compose", "up", "-d", "--remove-orphans"], {
            stdout: "inherit",
            stderr: "inherit"
        });
        await proc.exited;
        console.log("[DevNet] Services started in background.");
    }

    async teardown(cwd: string = ".", purge: boolean = false): Promise<void> {
        this.stopping = true;
        console.log("[DevNet][supervisor] teardown: auto-restart disabled, stopping all children");
        for (const process of this.spawnedProcesses) {
            if (process?.isRunning()) process.kill();
        }
        await teardownDevnet(cwd, purge);
    }

    static create(host?: string, envVars?: { [key: string]: string }, provingBackend?: string): DevNetProcessManager { return new DevNetProcessManager(host, envVars, provingBackend); }
}

// --- Race-safe per-repository devnet startup lock -----------------------------
// Prevents two concurrent devnet startups for the same repo root from racing
// into destructive Docker/process teardown. The lock lives in tmpdir (never in
// the worktree, so it leaves no git artifact) and is keyed by the canonical
// repo root. Teardown and --help intentionally do NOT acquire it: --teardown is
// the sanctioned destruction entry point and must be able to run even when a
// (possibly stale) lock is present.

function devnetLockPath(repoRoot: string): string {
    const tmpBase = process.env.TMPDIR || "/tmp";
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
let globalManager: DevNetProcessManager | null = null;

async function runMain() {

    const { values } = parseArgs({
        args: Bun.argv,
        options: {
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
            "clean-state": { type: "boolean" }, // deprecated alias
            "teardown": { type: "boolean" },
            "purge": { type: "boolean" },
            env: { type: "string" },
            "help": { type: "boolean", short: "h" },
        },
        allowPositionals: true,
    });



    const hasOnlyOptions = !!values["db"] || !!values["coordinator"] || !!values["prove-proxy"] || !!values["faucet-server"] || !!values["dummy-provers"] || !!values["l1"] || !!values["relayer"] || !!values["bridge-proposer-daemon"] || !!values["psy-privacy-bridge"] || !!values["ide"] || !!values["explorer"] || !!values["mode-a-web-wallet-bridge"];
    const workerRealmCount = resolveRealmWorkerCount(
        values["realm-workers"],
        hasOnlyOptions,
    );
    const realmEdgeCount = parseInt(values["realm-edge-nodes"] || "1", 10);
    const coordinatorEdgeCount = parseInt(values["coordinator-edge-nodes"] || "1", 10);
    const coordinatorWorkersCount = values["coordinator-workers"] ? parseInt(values["coordinator-workers"], 10) : (!hasOnlyOptions ? 1 : 0);
    const startRealmId = parseInt(values["start-realm-id"] || "0", 10);
    const realmsCount = parseInt(values["realms-count"] || "1", 10);
    const host = values["host"] || "127.0.0.1";
    const genesisDataPath = values["genesis-data-path"] || "genesis.json";
    const coordinator = !!values["coordinator"];
    const db = !!values["db"];
    const proveProxyCount = values["prove-proxy"] ? parseInt(values["prove-proxy"], 10) : 0;
    const faucetServer = !!values["faucet-server"];
    const dummyProvers = values["dummy-provers"] ? parseInt(values["dummy-provers"], 10) : 0;
    const l1 = !!values["l1"];
    const relayer = !!values["relayer"];
    const relayerConfig = values["relayer-config"] as string;
    const bridgeProposerDaemon = !!values["bridge-proposer-daemon"];
    const psyPrivacyBridge = !!values["psy-privacy-bridge"];
    const ide = !!values["ide"];
    const explorer = !!values["explorer"];
    const modeAWebWalletBridge = !!values["mode-a-web-wallet-bridge"];
    const daemonlize = !!values["daemonlize"];
    const teardown = !!values["teardown"];
    const purge = !!values["purge"];
    const cleanState = !!values["clean-state"] || purge;
    const provingBackend = values["proving-backend"];
    const envString = values["env"];
    const help = !!values["help"];
    const l1Port = values["l1-port"] ? parseInt(values["l1-port"] as string, 10) : 8545;
    const { l1Network, l1Fork } = resolveL1Selection();
    const localL1RpcUrl = resolveLocalL1RpcUrl(l1Port);
    const l1RpcUrl = (l1Network === "localhost" || l1Fork) ? localL1RpcUrl : resolveExternalL1RpcUrl(l1Network);

    const envVars: { [key: string]: string } = envString ? parseEnvAssignments(envString) : {};

    // Load faucet operators for prove-proxy (localhost devnet)
    // NOTE: this is done BEFORE auto-setup. If genesis generation creates the
    // file, it will be reloaded after ensureDevEnvironment() below.
    if (!hasFaucetOperatorConfig(envVars, process.env)) {
        try {
            const faucetOpsPath = path.join(REPO_ROOT, "psy-dapp", "apps", "bridge", "src", "config", "faucetOperators.json");
            if (fs.existsSync(faucetOpsPath)) {
                envVars["PSY_FAUCET_OPERATORS_JSON"] = fs.readFileSync(faucetOpsPath, "utf-8");
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
   VITE_NETWORK=localhost|sepolia|ethereum   Select L1 target network (default: localhost)
   --relayer                       Start unified bridge relayer (psy_relayer_cli --config <daemon.toml>)
   --relayer-config <path>         Legacy relayer/envio config path (default: ./psy_cli/psy_relayer_cli/config/local.toml)
   --bridge-proposer-daemon        Alias for --relayer
   --psy-privacy-bridge           Start integrated privacy+bridge shell (psy-dapp/apps/bridge, port 5177)
   --ide                          Start IDE dev server (psy-dapp/apps/ide, port 5176)
   --explorer                     Start blockchain explorer dev server (psy-dapp/apps/explorer, port 5178)
   --mode-a-web-wallet-bridge     Start Mode A web wallet bridge dev server (psy-dapp/mode-a-web-wallet-bridge, port 5179)
   --daemonlize                    Generate docker-compose.yml and start in background
   --teardown                      Stop local devnet processes/containers and exit
   --purge                         With --teardown (or startup), also remove local_checkpoints, logs, deployments, and devnet Docker volumes
   --clean-state                   Deprecated alias for --purge during startup
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
   bun run dev/locSetupV4.ts --mode-a-web-wallet-bridge  # start Mode A web wallet bridge on port 5179
   bun run dev/locSetupV4.ts --l1 --relayer --psy-privacy-bridge  # full bridge stack

 Notes:
   - Database services are automatically started in full system mode or when --db is specified
   - Flags can be combined (e.g., --db --coordinator)
   - Workers are started when --*-workers options are specified
   - No options specified starts the full system (all components)
   - Set VITE_NETWORK=localhost|sepolia|ethereum to choose the L1 target network
   - Set VITE_NETWORK=<sepolia|ethereum> and VITE_FORK=true to run anvil in fork mode
   - Optionally set VITE_FORK_BLOCK_NUMBER=<block> to pin the fork block
   - PSY_SKIP_BRANCH_CHECK=0  explicitly enable repo fetch/checkout (default: leave every HEAD untouched)
   - PSY_SKIP_KEYSTORE=1      keep local ~/.psy/keystore (skip S3 download/hash refresh)
   - PSY_SKIP_BUILD=1         use existing Rust release binaries; fail if any are missing
   - PSY_NO_AUTO_RESTART=1    disable supervised child-process auto-restart
   - SCYLLA_SMP=<n>           Scylla shard count (default: auto from reserved CPUs)
   - SCYLLA_CPUSET=<cpus>      Linux override for dedicated Scylla physical cores
   - PSY_RUNTIME_CPUSET=<cpus> Linux override for all non-Scylla child processes
   - SCYLLA_MEMORY=<size>      Scylla Seastar memory budget, for example 8G
   - SCYLLA_CAS_CONTENTION_TIMEOUT_MS=<ms>  LWT contention timeout (default: 10000)
   - SCYLLA_WRITE_REQUEST_TIMEOUT_MS=<ms>   write timeout (default: 10000)
   - PSY_WORKER_BATCH_SIZE=<n> Concurrent jobs per worker (default: 2)
   - RAYON_NUM_THREADS=<n>     Rayon threads per proving process (default: auto, max 4)
   - Linux full-devnet/--db launches auto-partition complete physical cores; macOS uses concurrency limits without affinity
   - Child auto-restart is ON by default; restart banners are appended to per-service logs
        `);
        process.exit(0);
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

    // SIGINT/SIGTERM: await teardown, then release the lock before exit. A
    // duplicate signal while already shutting down is ignored.
    let shuttingDown = false;
    const shutdown = async () => {
        if (shuttingDown) {
            console.log('[DevNet] shutdown already in progress; ignoring duplicate signal');
            return;
        }
        shuttingDown = true;
        try {
            if (globalManager) await globalManager.teardown(".", false);
        } catch (e) {
            console.error('[DevNet] error during teardown:', e);
        } finally {
            releaseDevnetLock();
            process.exit(0);
        }
    };

    process.on('SIGINT', () => void shutdown());
    process.on('SIGTERM', () => void shutdown());

    try {
    // Auto-setup: clone repos, install deps, download keystore, build binaries
    // Skip for teardown so it works even on a partially configured machine
    if (!teardown) {
        await ensureDevEnvironment(REPO_ROOT, {
            requireDocker: !hasOnlyOptions || db || relayer || bridgeProposerDaemon,
            requireAnvil: !hasOnlyOptions || l1,
            requireBun: !hasOnlyOptions || psyPrivacyBridge || ide || modeAWebWalletBridge,
        });
    }

    // (Re)load faucet operators AFTER auto-setup so genesis-generated files exist.
    // Explicit JSON or B64 from either the CLI or parent environment remains authoritative.
    if (!hasFaucetOperatorConfig(envVars, process.env)) {
        try {
            const faucetOpsPath = path.join(REPO_ROOT, "psy-dapp", "apps", "bridge", "src", "config", "faucetOperators.json");
            if (fs.existsSync(faucetOpsPath)) {
                envVars["PSY_FAUCET_OPERATORS_JSON"] = fs.readFileSync(faucetOpsPath, "utf-8");
                console.log(`[DevNet] Loaded faucet operators from ${faucetOpsPath}`);
            }
        } catch (err) {
            console.warn(`[DevNet] Failed to load faucet operators: ${err}`);
        }
    }

    if (teardown) {
        await teardownDevnet(".", purge);
        process.exit(0);
    }

        const options: ProcessOptions = {
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
            cleanState,
        };

        if (daemonlize) {
            await globalManager.setupDaemonized(options);
            releaseDevnetLock();
            process.exit(0);
        } else {
            await globalManager.setupProcesses(options);
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
            if (globalManager) await globalManager.teardown(".", false);
        } catch (te) {
            console.error("[DevNet] error during teardown after setup failure:", te);
        }
        releaseDevnetLock();
        process.exit(1);
    }
}

if (import.meta.main) runMain();
