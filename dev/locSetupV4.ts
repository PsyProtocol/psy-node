import { parseArgs } from "util";
import { rmdir, exists, mkdir, writeFile } from "fs/promises";
import path from "path";
import net from "node:net";
import allConfig from "../psy-genesis/config.json";
import { protocolConfig } from "../psy-contracts/protocol-config";

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

type L1SignerInfo = {
    address: string;
    keystorePath: string;
};

type L1NetworkName = "localhost" | "sepolia" | "ethereum" | "bsc";
type ConfigNetworkEntry = {
    l1_rpc_urls?: string[];
    anvilForkSourceUrlEnv?: string;
};
const LOCALHOST_CHAIN_ID = protocolConfig.chains.localhost.l1ChainId;
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
        throw new Error("[DevNet] VITE_FORK=true requires VITE_NETWORK=sepolia, ethereum, or bsc");
    }
    const cfgEntry = (allConfig as any)?.networks?.[l1Network] as ConfigNetworkEntry | undefined;
    if (!cfgEntry) {
        throw new Error(`[DevNet] config.json networks.${l1Network} missing`);
    }
    return { l1Network, l1Fork, cfgEntry };
}

let cachedWalletPassword: string | null = null;

function resolveBridgeRelayerKeystorePath(): string {
    const homeDir = process.env.HOME;
    if (process.env.KEYSTORE_PATH) return process.env.KEYSTORE_PATH;
    if (!homeDir) {
        throw new Error("[DevNet] HOME is not set and KEYSTORE_PATH was not provided");
    }
    return path.join(homeDir, ".psy", "keystore", "bridge-relayer");
}

async function resolveWalletPassword(): Promise<string> {
    if (process.env.WALLET_PASSWORD && process.env.WALLET_PASSWORD.length > 0) {
        return process.env.WALLET_PASSWORD;
    }
    if (cachedWalletPassword) {
        return cachedWalletPassword;
    }
    const { createInterface } = await import("node:readline/promises");
    const rl = createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    try {
        const password = (await rl.question("Enter WALLET_PASSWORD for bridge-relayer keystore: ")).trim();
        if (!password) {
            throw new Error("WALLET_PASSWORD is required when using bridge-relayer keystore");
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
        throw new Error(`[DevNet] failed to decrypt bridge relayer keystore: ${stderr || stdout}`);
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
    for (const addr of targets) {
        await anvilRpc(rpcUrl, "anvil_setBalance", [addr, hundredEthHex]);
    }
    await anvilRpc(rpcUrl, "anvil_impersonateAccount", [deployer.address]);
    try {
        const usdtAmtHex = `0x${(1_000_000n * 1_000_000n).toString(16)}`;
        const psyAmtHex = `0x${(1_000_000n * 1_000_000_000n).toString(16)}`;
        for (const addr of targets) {
            await sendTokenTransfer(rpcUrl, deployer.address, usdt, addr, usdtAmtHex);
            await sendTokenTransfer(rpcUrl, deployer.address, psy, addr, psyAmtHex);
        }
    } finally {
        await anvilRpc(rpcUrl, "anvil_stopImpersonatingAccount", [deployer.address]);
    }
    console.log(`[DevNet] funded ${targets.length} dev test accounts with ETH+USDT+PSY`);
}

function resolveL1Network(): L1NetworkName {
    const value = (process.env.VITE_NETWORK || "localhost").trim().toLowerCase();
    if (value === "localhost" || value === "sepolia" || value === "ethereum" || value === "bsc") {
        return value;
    }
    throw new Error(`[DevNet] unsupported VITE_NETWORK=${value}; expected localhost, sepolia, ethereum, or bsc`);
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

class RunningProcess {
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
        if (this.isRunning()) {
            this.proc.kill();
        }
    }

    isRunning(): boolean {
        return this.proc.killed === false;
    }

    killWithSignal(signal: number | NodeJS.Signals): void {
        this.proc.kill(signal);
    }

    static async spawn(cmds: string[], options: { cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor, stdoutLogFile?: string, stderrLogFile?: string, env?: { [key: string]: string } }): Promise<RunningProcess> {
        if (options.stdoutLogFile) await Bun.write(options.stdoutLogFile, "");
        if (options.stderrLogFile) await Bun.write(options.stderrLogFile, "");

        const proc = Bun.spawn(cmds, {
            cwd: options.cwd || undefined,
            stdout: "pipe",
            stderr: "pipe",
            env: options.env ? { ...process.env, ...options.env } : undefined
        });

        const runningProcess = new RunningProcess(proc, options.stdOutVisitor, options.stdErrVisitor, options.allOutputVisitor);

        if (proc.stdout) {
            let readableStream = proc.stdout;
            if (options.stdoutLogFile) {
                const [fileBranch, logicBranch] = proc.stdout.tee();
                readableStream = logicBranch as any;
                (async () => {
                    const sink = Bun.file(options.stdoutLogFile!).writer();
                    for await (const chunk of fileBranch) { sink.write(chunk); }
                    sink.end();
                })();
            }
            (async () => {
                const decoder = new TextDecoder();
                for await (const chunk of readableStream) {
                    runningProcess.injestStdOut(decoder.decode(chunk));
                }
                if (runningProcess.lineBufferStdOut.length > 0) {
                    runningProcess.injestStdOut('\n');
                }
            })();
        }

        if (proc.stderr) {
            let readableStream = proc.stderr;
            if (options.stderrLogFile) {
                const [fileBranch, logicBranch] = readableStream.tee();
                readableStream = logicBranch as any;
                (async () => {
                    const sink = Bun.file(options.stderrLogFile!).writer();
                    for await (const chunk of fileBranch) {
                        sink.write(chunk);
                    }
                    sink.end();
                })();
            }
            (async () => {
                const decoder = new TextDecoder();
                for await (const chunk of readableStream) {
                    runningProcess.injestStdErr(decoder.decode(chunk));
                }
                if (runningProcess.lineBufferStdErr.length > 0) {
                    runningProcess.injestStdErr('\n');
                }
            })();
        }

        (async () => {
            const code = await proc.exited;
            runningProcess.onExit(code, null);
        })();

        return runningProcess;
    }


    static spawnWithInitializationHint(cmds: string[], hintDetector: (line: string) => boolean, options: { cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor, stdoutLogFile?: string, stderrLogFile?: string, env?: { [key: string]: string } }): Promise<RunningProcess> {
        return new Promise<RunningProcess>(async (resolve, reject) => {
            let initialized = false;
            const allOutputVisitor: ProcessLineVisitor = (line: string, process: RunningProcess) => {
                if (!initialized && hintDetector(line)) {
                    initialized = true;
                    resolve(process as RunningProcess);
                }
                if (options.allOutputVisitor) {
                    options.allOutputVisitor(line, process);
                }
            };
            const proc = await RunningProcess.spawn(cmds, {
                cwd: options.cwd,
                stdOutVisitor: options.stdOutVisitor,
                stdErrVisitor: options.stdErrVisitor,
                allOutputVisitor: allOutputVisitor,
                stdoutLogFile: options.stdoutLogFile,
                stderrLogFile: options.stderrLogFile,
                env: options.env
            });
            proc.onExit = (code: number | null, signal: number | null) => {
                if (!initialized) {
                    const fullOut = proc.stdOutLines.join("\n");
                    const fullErr = proc.stdErrLines.join("\n");
                    reject(new Error(`Process exited before initialization hint was found.\n` +
                        `Command: ${cmds.join(" ")}\n` +
                        `Exit Code: ${code}, Signal: ${signal}\n\n` +
                        `--- Full StdOut ---\n${fullOut}\n\n` +
                        `--- Full StdErr ---\n${fullErr}\n\n` +
                        `Please check the log files in the 'logs/' directory for more details.`));
                }
            };
        });
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
            maxRetries?: number,
            retryDelayMs?: number,
            env?: { [key: string]: string }
        }
    ): Promise<RunningProcess> {
        return new Promise<RunningProcess>(async (resolve, reject) => {
            let attempt = 0;
            const maxRetries = options.maxRetries || 3;
            const retryDelayMs = options.retryDelayMs || 2000;

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
                        env: options.env
                    });
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

            trySpawn();
        });
    }
}

// --- Log Detectors ---
function dbStartedDetector(line: string): boolean {
    return line.includes('All services are running.')
}
function coordinatorProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_COORDINATOR_PROCESSOR_STARTED]')
        || line.includes('Using network:')
}
function coordinatorEdgeProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_COORDINATOR_EDGE_RPC_STARTED]')
        || line.includes('Coordinator edge starting with proving backend:')
}
function workerStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_PROOF_MINER_WORKER_STARTED]'); }
function realmProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_REALM_PROCESSOR_STARTED]')
        || line.includes('Using network:')
        || line.includes('[REALM_CREATE] setup_for_realm start')
        || line.includes('[REALM_CREATE] create_and_run start')
        || line.includes('creating keyspaces:')
}
function realmEdgeProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_REALM_EDGE_RPC_STARTED]')
        || line.includes('Realm edge starting...')
}
function dummyProverStartedDetector(line: string): boolean { return line.startsWith('[CFLI:DUMMY_END_CAP_PROVER_STARTED]'); }
function proveProxyStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_PROVE_PROXY_STARTED]');
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
    const tables = ['Deposit', 'DepositBatchAppend', 'DepositTreeNode', 'FinalizedBatch'];

    async function hasuraMetadata(type: string, args: Record<string, unknown>): Promise<{ ok: boolean; msg?: string }> {
        try {
            const resp = await fetch(`${hasuraUrl}/v1/metadata`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Hasura-Admin-Secret': adminSecret },
                body: JSON.stringify({ type, args }),
            });
            const body = await resp.json() as { error?: string; message?: string };
            if (body.message === 'success') return { ok: true };
            if (body.error?.includes('already-tracked') || body.error?.includes('already-exists')) {
                return { ok: true, msg: body.error };
            }
            return { ok: false, msg: body.error };
        } catch {
            return { ok: false };
        }
    }

    // Retry loop: tables may not exist yet if envio hasn't finished initialising
    for (let attempt = 0; attempt < 30; attempt++) {
        const remaining: string[] = [];
        for (const table of tables) {
            // Step 1: track the table in Hasura metadata (idempotent)
            const track = await hasuraMetadata('pg_track_table', {
                table: { name: table, schema: 'public' },
                source: 'default',
            });
            // Step 2: grant public select permission (idempotent)
            const perm = await hasuraMetadata('pg_create_select_permission', {
                table: { name: table, schema: 'public' },
                role: 'public',
                permission: { filter: {}, columns: '*', allow_aggregations: true },
            });
            if (!track.ok || !perm.ok) {
                remaining.push(table);
            }
        }
        if (remaining.length === 0) {
            console.log('[DevNet] Envio Hasura public permissions set');
            return;
        }
        await new Promise(r => setTimeout(r, 2000));
    }
    console.warn('[DevNet] Failed to set Envio Hasura public permissions for:', tables);
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
    console.log(`[DevNet] Installing UI deps in ${uiDir}...`);
    const pnpmLock = path.join(uiDir, "pnpm-lock.yaml");
    const bunLock = path.join(uiDir, "bun.lock");
    const hasPnpmLock = await exists(pnpmLock);
    if (hasPnpmLock) {
        await ensurePnpmBuildScriptsApproved(uiDir, ["esbuild"]);
    }
    const installCmd =
        hasPnpmLock ? ["pnpm", "install", "--no-frozen-lockfile"] :
        (await exists(bunLock)) ? ["bun", "install", "--no-frozen-lockfile"] :
        ["bun", "install"];
    if (hasPnpmLock) {
        await pnpmInstallWithAutoApprove(uiDir, ["--no-frozen-lockfile"]);
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
    deploymentsNetwork: L1NetworkName,
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
    if (deploymentsNetwork === "localhost") {
        await setLocalAnvilBalance(l1RpcUrl, bridgeRelayerSigner.address);
        console.log(`[DevNet] funded bridge relayer deployer ${bridgeRelayerSigner.address} on local anvil`);
    }
    console.log(`[DevNet] Deploying psy-contracts to ${deploymentsNetwork}...`);
    const deploymentCfg = (allConfig as any)?.networks?.[deploymentsNetwork] as ConfigNetworkEntry | undefined;
    const networkEnvKey = deploymentCfg?.anvilForkSourceUrlEnv ?? "LOCALHOST_RPC_URL";
    const walletPassword = await resolveWalletPassword();
    const deployArgs = ["node", "scripts/deploy-with-keystore.mjs", "deploy", "--network", deploymentsNetwork];
    if (deploymentsNetwork === "localhost" || forceRedeploy) {
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
    const proc = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe" });
    const stdout = proc.stdout ? await new Response(proc.stdout).text() : "";
    const stderr = proc.stderr ? await new Response(proc.stderr).text() : "";
    const code = await proc.exited;
    return { code, stdout, stderr };
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

function parseTomlInt(raw: string, key: string): number | undefined {
    const m = raw.match(new RegExp(`(?:^|\\n)\\s*${key}\\s*=\\s*(\\d+)`));
    if (!m?.[1]) return undefined;
    const n = Number(m[1]);
    return Number.isFinite(n) ? n : undefined;
}

async function startEnvioIndexerForRelayer(
    repoCwd: string,
    relayerConfigPath: string,
    l1RpcUrlOverride?: string,
    deploymentsNetworkOverride?: string,
    env?: { [key: string]: string },
): Promise<RunningProcess | null> {
    const cfgPath = path.isAbsolute(relayerConfigPath) ? relayerConfigPath : path.join(repoCwd, relayerConfigPath);
    if (!(await exists(cfgPath))) return null;
    const relayerRaw = await Bun.file(cfgPath).text();
    const databaseUrl =
        parseTomlScalar(relayerRaw, "database_url") ||
        "postgres://postgres:testing@127.0.0.1:5433/envio-dev";
    const rpcUrl =
        l1RpcUrlOverride ||
        parseTomlScalar(relayerRaw, "rpc_url") ||
        parseTomlScalar(relayerRaw, "l1_rpc_url") ||
        "http://127.0.0.1:8545";
    const configuredChainId = parseTomlInt(relayerRaw, "chain_id");
    const deploymentsNetwork =
        deploymentsNetworkOverride || parseTomlScalar(relayerRaw, "deployments_network") || "localhost";

    const deployedPath = path.join(
        repoCwd,
        "psy-contracts",
        "deployments",
        deploymentsNetwork,
        "deployed-contracts.json",
    );
    if (!(await exists(deployedPath))) {
        throw new Error(`missing deployed contracts summary: ${deployedPath}`);
    }
    const deployedRaw = await Bun.file(deployedPath).text();
    const deployed = JSON.parse(deployedRaw) as any;
    const deployedChainId = Number(
        deployed?.chainId ?? deployed?.protocol?.chain?.l1ChainId ?? configuredChainId ?? LOCALHOST_CHAIN_ID
    );
    const chainId = Number.isFinite(deployedChainId) ? deployedChainId : LOCALHOST_CHAIN_ID;
    const bridge = deployed?.core?.Bridge || deployed?.contracts?.Bridge;
    const stateManager = deployed?.core?.StateManager || deployed?.contracts?.StateManager;
    if (!bridge || !stateManager) {
        throw new Error(`missing Bridge/StateManager in ${deployedPath}`);
    }

    const readArtifactBlockNumber = async (artifactName: string): Promise<number | undefined> => {
        const artifactPath = path.join(
            repoCwd,
            "psy-contracts",
            "deployments",
            deploymentsNetwork,
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

    const bridgeDeployBlock = await readArtifactBlockNumber("Bridge_Proxy");
    const stateManagerDeployBlock = await readArtifactBlockNumber("StateManager_Proxy");
    const startBlock = [bridgeDeployBlock, stateManagerDeployBlock]
        .filter((v): v is number => Number.isFinite(v as number) && (v as number) > 0)
        .reduce<number | undefined>((min, v) => (min === undefined ? v : Math.min(min, v)), undefined) ?? 1;

    const envioDir = path.join(repoCwd, "psy_cli", "psy_relayer_cli", "indexer", "envio");
    const templatePath = path.join(envioDir, "config.template.yaml");
    const configPath = path.join(envioDir, "config.yaml");
    const envPath = path.join(envioDir, ".env");
    if (!(await exists(templatePath))) {
        throw new Error(`missing envio config template: ${templatePath}`);
    }
    const template = await Bun.file(templatePath).text();
    const config = template
        .replace("${ETH_RPC_URL}", rpcUrl)
        .replace(`id: ${LOCALHOST_CHAIN_ID}`, `id: ${chainId}`)
        .replace("start_block: 1", `start_block: ${startBlock}`)
        .replace("${BRIDGE_ADDRESS}", bridge)
        .replace("${STATE_MANAGER_ADDRESS}", stateManager);
    await Bun.write(configPath, config);
    await Bun.write(
        envPath,
        [
            `ETH_RPC_URL=${rpcUrl}`,
            `BRIDGE_ADDRESS=${bridge}`,
            `STATE_MANAGER_ADDRESS=${stateManager}`,
            `DATABASE_URL=${databaseUrl}`,
            `LOG_LEVEL=info`,
            `FILE_LOG_LEVEL=trace`,
            "",
        ].join("\n"),
    );

    // Clean up old Envio containers and start fresh.
    // (Containers and volumes are cleaned by make shutdown / clean-db before this runs.)
    const envioComposeFile = path.join(envioDir, "generated", "docker-compose.yaml");
    if (await exists(envioComposeFile)) {
        console.log("[DevNet] Starting Envio docker services...");
        await runAndCapture(["docker", "compose", "-f", envioComposeFile, "up", "-d"]);

        await waitForTcpPort('127.0.0.1', 5433, {
            attempts: 300,
            delayMs: 1000,
            timeoutMs: 1500,
            name: 'Envio Postgres',
        });
        await waitForCommandSuccess(
            ['docker', 'exec', 'generated-envio-postgres-1', 'psql', '-U', 'postgres', '-d', 'postgres', '-c', 'select 1'],
            { attempts: 300, delayMs: 1000, name: 'Envio Postgres SQL readiness' }
        );
        await waitForHttpUrl('http://127.0.0.1:8080/healthz', {
            attempts: 300,
            delayMs: 1000,
            timeoutMs: 1500,
            name: 'Envio GraphQL',
        });
    }

    const pkgPath = path.join(envioDir, "package.json");
    if (!(await exists(pkgPath))) {
        await Bun.write(
            pkgPath,
            JSON.stringify(
                {
                    name: "psy-relayer-envio",
                    private: true,
                    version: "0.1.0",
                    scripts: {
                        dev: "envio dev --config ./config.yaml",
                    },
                    devDependencies: {
                        envio: "^2.32.10",
                    },
                },
                null,
                2,
            ) + "\n",
        );
    }

    console.log("[DevNet] Installing Envio indexer dependencies...");
    await ensurePnpmBuildScriptsApproved(envioDir, ["esbuild"]);
    await pnpmInstallWithAutoApprove(envioDir);
    const envioGeneratedDir = path.join(envioDir, "generated");
    if (await exists(path.join(envioGeneratedDir, "package.json"))) {
        await ensurePnpmBuildScriptsApproved(envioGeneratedDir, ["rescript"]);
        await pnpmInstallWithAutoApprove(envioGeneratedDir);
        const buildGenerated = await runAndCapture(["pnpm", "build"], envioGeneratedDir);
        if (buildGenerated.code !== 0) {
            throw new Error(`envio generated build failed: ${buildGenerated.stderr || buildGenerated.stdout}`);
        }
    }

    console.log("[DevNet] Starting Envio indexer (pnpm dev)...");
    return RunningProcess.spawn(["pnpm", "dev"], {
        cwd: envioDir,
        stdoutLogFile: path.join(repoCwd, "logs", "envio_logs.txt"),
        stderrLogFile: path.join(repoCwd, "logs", "envio_errs.txt"),
        env: {
            ...(env || {}),
            TUI_OFF: "true",
            LOG_LEVEL: "info",
            FILE_LOG_LEVEL: "trace",
            HASURA_GRAPHQL_ENDPOINT: "http://localhost:8090/v1/metadata",
        },
    });
}

async function cleanCheckpoint(checkpointPath: string, cwd: string = '.') {
    const fullPath = path.resolve(cwd, checkpointPath);
    if (await exists(fullPath)) {
        await rmdir(fullPath, { recursive: true });
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
    l1?: boolean;
    relayer?: boolean;
    relayerConfig?: string;
    bridgeProposerDaemon?: boolean;
    bridgeUi?: boolean;
    privacyUi?: boolean;
    psyPrivacyBridge?: boolean;
    ide?: boolean;
    explorer?: boolean;
    daemonlize?: boolean;
    cleanState?: boolean;
}

class DevNetProcessManager {
    spawnedProcesses: RunningProcess[] = [];
    needsStartDb: boolean = false;

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

    private track(p: RunningProcess): RunningProcess {
        this.spawnedProcesses.push(p);
        return p;
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
        const workerRealmCount = options.workerRealmCount;
        const realmEdgeCount = options.realmEdgeCount;
        const coordinatorEdgeCount = options.coordinatorEdgeCount;
        const coordinatorWorkersCount = options.coordinatorWorkersCount;
        this.genesisDataPath = options.genesisDataPath || "genesis.json";
        const cleanState = !!options.cleanState;


        const disableWorkerEdgeLogs = !!options.disableWorkerEdgeLogs;
        // Determine what components to start
        const hasOnlyOptions = !!options.db || !!options.coordinator || (options.proveProxyCount || 0) > 0 || (options.dummyProvers || 0) > 0 || !!options.l1 || !!options.relayer || !!options.bridgeUi || !!options.privacyUi || !!options.psyPrivacyBridge || !!options.ide || !!options.explorer;
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
        if (
            !(await exists(psyNodeCliPath))
            || !(await exists(psyWorkerCliPath))
            || !(await exists(psyRelayerCliPath))
        ) {
            await buildProject(cwd);
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
            await this.track(await RunningProcess.spawnWithInitializationHint(
                startDbCmd, dbStartedDetector, { cwd, ...getLogPaths("scylla", false) }
            ));
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
            // await cleanCheckpoint('./local_checkpoints/coordinator_0_0', cwd);
            const coordinatorProcessorLogPath = path.join(logsDir, "coordinator_processor_logs.txt");
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
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
                coordinatorProcessorStartedDetector,
                { cwd, ...getLogPaths("coordinator_processor", false), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
            ));
            console.log("[DevNet] Waiting for coordinator processor to finish genesis initialization...");
            await waitForLogPattern(
                coordinatorProcessorLogPath,
                /\[COORD_CREATE\] processor new done/,
                { attempts: 120, delayMs: 1000, name: "coordinator processor readiness" }
            );

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

        // 5. Coordinator Workers
        if (startCoordinatorWorkers && coordinatorWorkersCount > 0) {
            for (let i = 0; i < coordinatorWorkersCount; i++) {
                const coordUrls: string[] = [];

                // Connect to all coordinator edges for better load distribution
                for (let edgeIndex = 0; edgeIndex < coordinatorEdgeCount; edgeIndex++) {
                    const coordEdgePort = 1337 + edgeIndex;
                    const coordUrl = `http://${this.host}:${coordEdgePort}`;
                    coordUrls.push(coordUrl);
                }

                const workerArgs = [
                    workerCli, 'worker',
                    '--user', '0',
                    '--network', this.NETWORK,
                    '--proving-backend', backend,
                    '--completed-jobs-log-file', `./local_checkpoints/coordinator_worker_${i}.backup`,
                ];

                for (const coordUrl of coordUrls) {
                    workerArgs.push('--coordinator-api-url', coordUrl);
                }

                workerArgs.push('--private-key', FAKE_MINER_PRIVATE_KEY);

                await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                    workerArgs,
                    workerStartedDetector,
                    { cwd, ...getLogPaths(`coordinator_worker_${i}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                ));
            }
        }

        if (startRealmProcessor) {
            console.log(`[DevNet] Starting ${realmsCount} realm processors and edges in parallel...`);

            // Clean all checkpoints first
            // console.log(`[DevNet] Cleaning checkpoints for ${realmsCount} realms...`);
            // for (let i = 0; i < realmsCount; i++) {
            //     const realmId = startRealmId + i;
            //     await cleanCheckpoint('./local_checkpoints/realm_' + realmId + '_1', cwd);
            // }

            // Start realm processors first, then edges
            for (let b = 0; b < realmsCount; b += 4) {
                const realmProcessorPromises: Promise<RunningProcess>[] = [];
                const batchSize = Math.min(4, realmsCount - b);

                // First, start all processors in this batch
                for (let i = 0; i < batchSize; i++) {
                    const realmId = startRealmId + b + i;
                    const realmProcessorLogPath = path.join(logsDir, `realm_${realmId}_processor_logs.txt`);

                    // Start realm processor
                    const processorPromise = RunningProcess.spawnWithInitializationHintWithRetry(
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
                        realmProcessorStartedDetector,
                        { cwd, ...getLogPaths(`realm_${realmId}_processor`, false), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                    ).then(async (proc) => {
                        this.track(proc);
                        await waitForLogPattern(
                            realmProcessorLogPath,
                            /\[REALM_CREATE\] processor new done/,
                            { attempts: 180, delayMs: 1000, name: `realm ${realmId} processor readiness` }
                        );
                        return proc;
                    });
                    realmProcessorPromises.push(processorPromise);
                }

                // Wait for all realm processors in this batch to start
                await Promise.all(realmProcessorPromises);
                console.log(`[DevNet] Batch ${b/4 + 1} realm processors finished genesis initialization.`);

                // Now start the edges for this batch
                const realmEdgesPromises: Promise<RunningProcess>[] = [];
                for (let i = 0; i < batchSize; i++) {
                    const realmId = startRealmId + b + i;
                    const realmEdgeStartPort = 13380 + realmId * 10;

                    // Start realm edges
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

                // Wait for all realm edges in this batch to start
                await Promise.all(realmEdgesPromises);
                console.log(`[DevNet] Batch ${b/4 + 1} realm edges started. Waiting 2 seconds before starting next batch...`);
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
            console.log(`[DevNet] All realm processors and edges started`);
        }

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
                    ['./dev/dummy_prover.sh', 'prove_random', '-p', backend, '-H', this.host,
                     '--start-realm-id', startRealmId.toString(), '--end-realm-id', endRealmId.toString()],
                    dummyProverStartedDetector,
                    { cwd, ...getLogPaths(`dummy_prover_${i}`, true), maxRetries: 3, retryDelayMs: 2000, env: this.getEnv() }
                ).then(proc => this.track(proc));
                dummyPromises.push(dummyPromise);
            }
            await Promise.all(dummyPromises);
            console.log(`[DevNet] All ${dummyProvers} dummy provers started`);
        }

        // 9. Prove Proxy
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
                await waitForTcpPort('127.0.0.1', port, {
                    attempts: 300,
                    delayMs: 1000,
                    timeoutMs: 1500,
                    name: `Prove proxy ${i}`,
                });
                console.log(`[DevNet] Prove proxy instance ${i} started on port ${port}`);
            }
        }

        // 10. L1 (Anvil)
        if (options.l1 || startAll) {
            if (l1Network === "localhost" || l1Fork) {
                const chainMeta = protocolConfig.chains[l1Network];
                if (!chainMeta) throw new Error(`[DevNet] protocolConfig.chains.${l1Network} missing`);
                const effectiveL1ChainId = l1Fork ? protocolConfig.chains.localhost.l1ChainId : chainMeta.l1ChainId;
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

                // Warm up precompile addresses (0x01-0x08) by sending ETH to them
                // This creates local account entries so anvil doesn't try to look them up from fork
                if (l1Fork) {
                    console.log(`[DevNet] Warming up precompile addresses on forked anvil...`);
                    const fromAddr = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
                    const precompileAddrs = ['0x01','0x02','0x03','0x04','0x05','0x06','0x07','0x08'];
                    for (const addr of precompileAddrs) {
                        try {
                            const paddedAddr = ('0x' + addr.slice(2).padStart(40, '0'));
                            const resp = await fetch(localL1RpcUrl, {
                                method: 'POST',
                                headers: { 'content-type': 'application/json' },
                                body: JSON.stringify({
                                    jsonrpc: '2.0',
                                    id: 1,
                                    method: 'eth_sendTransaction',
                                    params: [{
                                        from: fromAddr,
                                        to: paddedAddr,
                                        value: '0x1',
                                    }],
                                }),
                            });
                            const body = await resp.json();
                            if (body.error) {
                                console.log(`  precompile ${addr} warmup skipped: ${body.error.message}`);
                            } else {
                                console.log(`  precompile ${addr} warmed up`);
                            }
                        } catch (e) {
                            console.log(`  precompile ${addr} warmup error: ${e}`);
                        }
                    }
                    console.log(`[DevNet] Precompile warmup complete`);
                }
            } else {
                console.log(`[DevNet] Using external L1 network ${l1Network} via ${l1RpcUrl}`);
                await waitForHttpUrl(l1RpcUrl, {
                    attempts: 30,
                    delayMs: 1000,
                    timeoutMs: 3000,
                    name: `${l1Network} RPC`
                });
            }
            await deployPsyContracts(cwd, l1RpcUrl, deploymentsNetwork, {
                fundDevAccounts: l1Network === "localhost" || l1Fork,
                localAnvilRpcUrl: localL1RpcUrl,
            });
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
            );
            if (envioProc) {
                this.track(envioProc);
                console.log('[DevNet] Envio indexer started');
            }

            await waitForTcpPort('127.0.0.1', 9898, {
                attempts: 300,
                delayMs: 1000,
                timeoutMs: 1500,
                name: 'Envio Indexer API',
            });

            // Grant public select permissions on all Envio-indexed tables so the
            // frontend (which never sends X-Hasura-Admin-Secret) can query them.
            await ensureEnvioHasuraPublicAccess();

            const psyServicesCwd = path.resolve(cwd, '../psy-services');
            const psyServicesBin = path.join(psyServicesCwd, 'target', 'release', 'psy-services');
            const psyServicesGenesisAbi = path.join(psyServicesCwd, 'genesis_contracts', 'genesis.json');
            const psyServicesGenesisUser = path.join(psyServicesCwd, 'genesis_users.bin');
            const psyIndexerBin = path.join(psyServicesCwd, 'target', 'release', 'psy-indexer');
            const psyServicesCmd = await exists(psyServicesBin)
                ? [psyServicesBin, '--disable-auth']
                : ['cargo', 'run', '--release', '--bin', 'psy-services', '--', '--disable-auth'];
            if (await exists(psyServicesGenesisAbi)) {
                psyServicesCmd.push('--genesis-path', psyServicesGenesisAbi);
            }
            if (await exists(psyServicesGenesisUser)) {
                psyServicesCmd.push('--genesis-users-path', psyServicesGenesisUser);
            }
            const psyIndexerCmdBase = await exists(psyIndexerBin)
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
                        L1_RPC_URL: relayerL1RpcUrl,
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

        // 11.5 Unified bridge relayer
        if (startBridgeProposerDaemon) {
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
            const privacyBridgeDir = path.join(cwd, 'psy-dapp/apps/bridge');
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
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] Privacy Bridge UI started on port 5177');
        }

        // 16. IDE
        if (options.ide || startAll) {
            await ensureUiDependencies(path.join(cwd, 'psy-dapp/apps/ide'));
            await this.track(await RunningProcess.spawnWithInitializationHintWithRetry(
                ['bun', 'run', 'dev', '--', '--host', '0.0.0.0', '--port', '5176', '--strictPort'],
                uiStartedDetector,
                {
                    cwd: path.join(cwd, 'psy-dapp/apps/ide'),
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
            const explorerDir = path.join(cwd, 'psy-dapp/apps/explorer');
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
                    },
                    maxRetries: 3,
                    retryDelayMs: 2000
                }
            ));
            console.log('[DevNet] Explorer started on port 5178');
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

        const hasOnlyOptions = !!options.db || !!options.coordinator || (options.proveProxyCount || 0) > 0 || (options.dummyProvers || 0) > 0 || !!options.l1 || !!options.relayer || !!options.bridgeUi || !!options.privacyUi || !!options.psyPrivacyBridge || !!options.ide || !!options.explorer;
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

        const env = this.getEnv() || {};
        // Only pass relevant environment variables to the container to avoid bloating the file and leaking host secrets
        const filteredEnv = {
            "RUST_LOG": env["RUST_LOG"] || "info",
            "RUST_BACKTRACE": "1"
        };
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
                ]
            };

            services["nats-server"] = {
                image: "nats",
                container_name: "nats-server",
                ports: ["4222:4222"],
                volumes: ["psy-devnet-nats:/data"],
                command: ["-js", "-sd", "/data"]
            };

            services["scylla-server"] = {
                image: "scylladb/scylla:latest",
                container_name: "scylla-server",
                ports: ["9042:9042"],
                cap_add: ["PERFMON"],
                volumes: [
                    "psy-devnet-scylla:/var/lib/scylla",
                    "psy-devnet-scylla-data:/run/udev/data"
                ],
                command: [
                    "--smp", "2", "--developer-mode", "1", "--overprovisioned", "1",
                    "--experimental-features=lwt"
                ],
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

        if (startCoordinatorProcessor) {
            services["coordinator-processor"] = getServiceEntry("coordinator-processor", [
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
                    ...getServiceEntry(`coordinator-edge-${j}`, [
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
                ];
                for (let j = 0; j < coordinatorEdgeCount; j++) {
                    workerArgs.push("--coordinator-api-url", `http://coordinator-edge-${j}:${1337 + j}`);
                }
                workerArgs.push("--private-key", FAKE_MINER_PRIVATE_KEY);
                services[`coordinator-worker-${i}`] = getServiceEntry(`coordinator-worker-${i}`, workerArgs);
            }
        }

        if (startRealmProcessor) {
            for (let i = 0; i < realmsCount; i++) {
                const realmId = startRealmId + i;
                services[`realm-${realmId}-processor`] = getServiceEntry(`realm-${realmId}-processor`, [
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
                        ...getServiceEntry(`realm-${realmId}-edge-${j}`, [
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
                services[`realm-worker-${workerId}`] = getServiceEntry(`realm-worker-${workerId}`, workerArgs);
             }
        }

        const proveProxyCountD = options.proveProxyCount || 0;
        if (proveProxyCountD > 0) {
            const count = proveProxyCountD;
            const basePort = 9999;
            for (let i = 0; i < count; i++) {
                const port = basePort + i;
                services[`prove-proxy-${i}`] = {
                    ...getServiceEntry(`prove-proxy-${i}`, [
                        "/app/bin/psy_user_cli", "prove-proxy",
                        "--listen-addr", `0.0.0.0:${port}`,
                        "--rpc-config", "/app/workspace/psy-genesis/config.json"
                    ]),
                    ports: [`${port}:${port}`]
                };
            }
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

    teardown(): void {

        console.log("\n[DevNet] Tearing down...");
        for (const process of this.spawnedProcesses) {
            if (process?.isRunning()) process.kill();
        }
        if (this.needsStartDb) {
            killDocker();
        }
    }

    static create(host?: string, envVars?: { [key: string]: string }, provingBackend?: string): DevNetProcessManager { return new DevNetProcessManager(host, envVars, provingBackend); }
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
            "l1": { type: "boolean" },
            "relayer": { type: "boolean" },
            "relayer-config": { type: "string", default: "./psy_cli/psy_relayer_cli/config/local.toml" },
            "bridge-proposer-daemon": { type: "boolean" },
            "psy-privacy-bridge": { type: "boolean" },
            "ide": { type: "boolean" },
            "explorer": { type: "boolean" },
            "daemonlize": { type: "boolean" },
            "clean-state": { type: "boolean" },
            env: { type: "string" },
            "help": { type: "boolean", short: "h" },
        },
        allowPositionals: true,
    });



    const hasOnlyOptions = !!values["db"] || !!values["coordinator"] || !!values["prove-proxy"] || !!values["dummy-provers"] || !!values["l1"] || !!values["relayer"] || !!values["bridge-proposer-daemon"] || !!values["psy-privacy-bridge"] || !!values["ide"] || !!values["explorer"];
    const workerRealmCount = values["realm-workers"] ? parseInt(values["realm-workers"], 10) : 0;
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
    const dummyProvers = values["dummy-provers"] ? parseInt(values["dummy-provers"], 10) : 0;
    const l1 = !!values["l1"];
    const relayer = !!values["relayer"];
    const relayerConfig = values["relayer-config"] as string;
    const bridgeProposerDaemon = !!values["bridge-proposer-daemon"];
    const psyPrivacyBridge = !!values["psy-privacy-bridge"];
    const ide = !!values["ide"];
    const explorer = !!values["explorer"];
    const daemonlize = !!values["daemonlize"];
    const cleanState = !!values["clean-state"];
    const provingBackend = values["proving-backend"];
    const envString = values["env"];
    const help = !!values["help"];
    const l1Port = values["l1-port"] ? parseInt(values["l1-port"] as string, 10) : 8545;
    const { l1Network, l1Fork } = resolveL1Selection();
    const localL1RpcUrl = resolveLocalL1RpcUrl(l1Port);
    const l1RpcUrl = (l1Network === "localhost" || l1Fork) ? localL1RpcUrl : resolveExternalL1RpcUrl(l1Network);

    // Parse environment variables
    let envVars: { [key: string]: string } | undefined;
    if (envString) {
        envVars = {};
        const pairs = envString.split(',');
        for (const pair of pairs) {
            const [key, value] = pair.split('=');
            if (key && value) {
                envVars[key.trim()] = value.trim();
            }
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
   --realm-workers <count>         Number of shared workers distributed across all realms (default: 1 when starting full system)
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
   --l1                            Start L1 chain (anvil, default port 8545)
   --l1-port <port>                Port for anvil L1 node (default: 8545)
   VITE_NETWORK=localhost|sepolia|ethereum   Select L1 target network (default: localhost)
   --relayer                       Start unified bridge relayer (psy_relayer_cli --config <daemon.toml>)
   --relayer-config <path>         Legacy relayer/envio config path (default: ./psy_cli/psy_relayer_cli/config/local.toml)
   --bridge-proposer-daemon        Alias for --relayer
   --psy-privacy-bridge           Start integrated privacy+bridge shell (psy-dapp/apps/bridge, port 5177)
   --ide                           Start IDE dev server (psy-dapp/apps/ide, port 5176)
   --explorer                      Start blockchain explorer dev server (psy-dapp/apps/explorer, port 5178)
   --daemonlize                    Generate docker-compose.yml and start in background
   --clean-state                   Remove local_checkpoints and devnet Docker volumes before boot
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
   bun run dev/locSetupV4.ts --l1 --relayer --psy-privacy-bridge  # full bridge stack

 Notes:
   - Database services are automatically started in full system mode or when --db is specified
   - Flags can be combined (e.g., --db --coordinator)
   - Workers are started when --*-workers options are specified
   - No options specified starts the full system (all components)
   - Set VITE_NETWORK=localhost|sepolia|ethereum to choose the L1 target network
   - Set VITE_NETWORK=<sepolia|ethereum> and VITE_FORK=true to run anvil in fork mode
   - Optionally set VITE_FORK_BLOCK_NUMBER=<block> to pin the fork block
        `);
        process.exit(0);
    }


    globalManager = DevNetProcessManager.create(host, envVars, provingBackend);

    const shutdown = () => {
        if (globalManager) globalManager.teardown();
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    try {
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
            l1,

            relayer,
            relayerConfig,
            bridgeProposerDaemon,
            psyPrivacyBridge,
            ide,
            explorer,
            daemonlize: !!values.daemonlize,
            cleanState,
        };

        if (daemonlize) {
            await globalManager.setupDaemonized(options);
            process.exit(0);
        } else {
            await globalManager.setupProcesses(options);
            console.log('DevNet started. Press Ctrl+C to stop.');
            setInterval(() => { }, 1000 * 60);
        }
    } catch (e) {
        console.error("Setup failed:", e);
        if (globalManager) globalManager.teardown();
        process.exit(1);
    }
}

runMain();
