import { parseArgs } from "util";
import { rmdir, exists, mkdir } from "fs/promises";
import path from "path";

type ProcessLineVisitor = (line: string, process: RunningProcess) => void;
// this is an insecure, obviously fake private key for local devnet use only
const FAKE_MINER_PRIVATE_KEY = "691337BADFACE067320cb499a730fa6c81a756ed912f181f0f20a6b1fa5c1337";
async function killDocker() {
    try {
        const proc = Bun.spawn(['docker', 'kill', 'valkey-server', 'scylla-server', 'nats-server'], {
            stderr: "ignore",
            stdout: "ignore"
        });
        await proc.exited;
    } catch (e) { }
}

class RunningProcess {
    pid: number;
    proc: Bun.Subprocess;
    stdOutLines: string[] = [];
    stdErrLines: string[] = [];
    lineBufferStdOut: string = '';
    lineBufferStdErr: string = '';
    linesToKeepStdOut: number = 1000;
    linesToKeepStdErr: number = 1000;
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

    static async spawn(cmds: string[], options: { cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor, stdoutLogFile?: string, stderrLogFile?: string }): Promise<RunningProcess> {
        if (options.stdoutLogFile) await Bun.write(options.stdoutLogFile, "");
        if (options.stderrLogFile) await Bun.write(options.stderrLogFile, "");

        const proc = Bun.spawn(cmds, {
            cwd: options.cwd || undefined,
            stdout: "pipe",
            stderr: "pipe"
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
                const [fileBranch, logicBranch] = proc.stderr.tee();
                readableStream = logicBranch as any;
                (async () => {
                    const sink = Bun.file(options.stderrLogFile!).writer();
                    for await (const chunk of fileBranch) { sink.write(chunk); }
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


    static spawnWithInitializationHint(cmds: string[], hintDetector: (line: string) => boolean, options: { cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor, stdoutLogFile?: string, stderrLogFile?: string }): Promise<RunningProcess> {
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
                stderrLogFile: options.stderrLogFile
            });
            proc.onExit = (code: number | null, signal: number | null) => {
                if (!initialized) {
                    reject(new Error(`Process exited before initialization hint was found. Exit code: ${code}, signal: ${signal}\nCommand: ${cmds.join(" ")}`));
                }
            };
        });
    }
}

// --- Log Detectors ---
function scyllaStartedDetector(line: string): boolean { return line.includes('init - Scylla version') && line.includes('initialization completed'); }
function coordinatorProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_COORDINATOR_PROCESSOR_STARTED]'); }
function coordinatorEdgeProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_COORDINATOR_EDGE_RPC_STARTED]'); }
function workerStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_PROOF_MINER_WORKER_STARTED]'); }
function realmProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_REALM_PROCESSOR_STARTED]'); }
function realmEdgeProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_REALM_EDGE_RPC_STARTED]'); }

async function buildProject(cwd?: string) {
    console.log("Building project...");
    const proc = Bun.spawn(["cargo", "build", "--release"], { cwd, stdout: "inherit", stderr: "inherit" });
    if (await proc.exited !== 0) throw new Error(`Build failed`);
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
    workerRealmCount: number;
    workerEdgeCount: number;
    disableWorkerEdgeLogs?: boolean;
    realmId?: number;
    realmOnly?: boolean;
    coordinatorOnly?: boolean;
}

class DevNetProcessManager {
    spawnedProcesses: RunningProcess[] = [];
    needsStartDb: boolean = false;

    // Shared Config Constants
    private readonly NETWORK = "local-devnet";
    private readonly SCYLLA_URL = "127.0.0.1:9042";
    private readonly NATS_URL = "nats://127.0.0.1:4222";
    private readonly REDIS_URL = "redis://127.0.0.1:6379";
    private readonly COORD_API_URL = "http://127.0.0.1:1337";
    private REALM_EDGE_START_PORT: number = 13370;

    private track(p: RunningProcess): RunningProcess {
        this.spawnedProcesses.push(p);
        return p;
    }

    async setupProcesses(options: ProcessOptions): Promise<void> {
        const cwd = options?.cwd || ".";
        const jtmb = !!options?.jtmb;
        const workerRealmCount = options.workerRealmCount;
        const workerEdgeCount = options.workerEdgeCount;
        const disableWorkerEdgeLogs = !!options.disableWorkerEdgeLogs;
        const needsCoordinator = !options.realmOnly;
        const needsRealm = !options.coordinatorOnly;
        const needsStartDb = !options.realmOnly && !options.coordinatorOnly;
        const realmId = parseInt(options?.realmId ? (options.realmId + "") : "0", 10);
        this.REALM_EDGE_START_PORT = 13370 + realmId * 100;





        this.needsStartDb = needsStartDb;
        if (needsStartDb) {
            console.log("[DevNet] Killing existing docker containers...");
            await killDocker();
        }



        const logsDir = path.join(cwd, "logs");
        await mkdir(logsDir, { recursive: true });

        const getLogPaths = (baseName: string, isWorkerOrEdge: boolean) => {
            if (isWorkerOrEdge && disableWorkerEdgeLogs) return {};
            return {
                stdoutLogFile: path.join(logsDir, `${baseName}_logs.txt`),
                stderrLogFile: path.join(logsDir, `${baseName}_errs.txt`),
            };
        };

        const backend = jtmb ? 'jtmb-poseidon-goldilocks' : 'plonky2-poseidon-goldilocks';

        // 1. Start Database
        if (this.needsStartDb) {
            await this.track(await RunningProcess.spawnWithInitializationHint(
                ['./dev/start_db.sh'], scyllaStartedDetector, { cwd, ...getLogPaths("scylla", false) }
            ));
        }
        // 2. Build
        await buildProject(cwd);

        const nodeCli = './target/release/psy_node_cli';
        const workerCli = './target/release/psy_worker_cli';

        // 3. Coordinator Processor
        if (needsCoordinator) {
            await cleanCheckpoint('./local_checkpoints/coordinator_0_0', cwd);
            await this.track(await RunningProcess.spawnWithInitializationHint(
                [
                    nodeCli, 'start-coordinator-processor',
                    '--coordinator-id', '0',
                    '--coordinator-sub-id', '0',
                    '--network', this.NETWORK,
                    '--db-namespace', 'coordinator',
                    '--scylla-db-url', this.SCYLLA_URL,
                    '--nats-jetstream-url', this.NATS_URL,
                    '--redis-url', this.REDIS_URL,
                    '--checkpoint-backup-path', './local_checkpoints',
                    '--proving-backend', backend,
                    '--verbose'
                ],
                coordinatorProcessorStartedDetector,
                { cwd, ...getLogPaths("coordinator_processor", false) }
            ));

            // 4. Coordinator Edge
            await this.track(await RunningProcess.spawnWithInitializationHint(
                [
                    nodeCli, 'start-coordinator-edge',
                    '--coordinator-id', '0',
                    '--coordinator-sub-id', '0',
                    '--network', this.NETWORK,
                    '--db-namespace', 'coordinator',
                    '--scylla-db-url', this.SCYLLA_URL,
                    '--nats-jetstream-url', this.NATS_URL,
                    '--redis-url', this.REDIS_URL,
                    '--port', '1337',
                    '--listen', '127.0.0.1',
                    '--proving-backend', backend,
                    '--verbose'
                ],
                coordinatorEdgeProcessorStartedDetector,
                { cwd, ...getLogPaths("coordinator_edge_0", true) }
            ));

            // 5. Coordinator Worker
            await this.track(await RunningProcess.spawnWithInitializationHint(
                [
                    workerCli, 'worker',
                    '--user', '0',
                    '--network', this.NETWORK,
                    '--proving-backend', backend,
                    '--coordinator-api-url', this.COORD_API_URL,
                    '--private-key', FAKE_MINER_PRIVATE_KEY,
                ],
                workerStartedDetector,
                { cwd, ...getLogPaths("coordinator_worker_0", true) }
            ));
        }

        if (needsRealm) {
            // 6. Realm Processor
            await cleanCheckpoint('./local_checkpoints/realm_' + realmId + '_1', cwd);
            await this.track(await RunningProcess.spawnWithInitializationHint(
                [
                    nodeCli, 'start-realm-processor',
                    '--realm-id', realmId + "",
                    '--realm-sub-id', '1',
                    '--network', this.NETWORK,
                    '--db-namespace', 'realm_' + realmId,
                    '--scylla-db-url', this.SCYLLA_URL,
                    '--nats-jetstream-url', this.NATS_URL,
                    '--redis-url', this.REDIS_URL,
                    '--checkpoint-backup-path', './local_checkpoints',
                    '--coordinator-api-urls', this.COORD_API_URL,
                    '--proving-backend', backend,
                    '--verbose'
                ],
                realmProcessorStartedDetector,
                { cwd, ...getLogPaths(`realm_${realmId}_processor`, false) }
            ));

            // 7. Realm Edges (Scalable)
            for (let i = 0; i < workerEdgeCount; i++) {
                const port = this.REALM_EDGE_START_PORT + i;
                await this.track(await RunningProcess.spawnWithInitializationHint(
                    [
                        nodeCli, 'start-realm-edge',
                        '--realm-id', realmId + "",
                        '--realm-sub-id', '1',
                        '--network', this.NETWORK,
                        '--db-namespace', 'realm_' + realmId,
                        '--scylla-db-url', this.SCYLLA_URL,
                        '--nats-jetstream-url', this.NATS_URL,
                        '--redis-url', this.REDIS_URL,
                        '--port', port.toString(),
                        '--listen', '127.0.0.1',
                        '--proving-backend', backend,
                        '--verbose'
                    ],
                    realmEdgeProcessorStartedDetector,
                    { cwd, ...getLogPaths(`realm_edge_${realmId}_${i}`, true) }
                ));
            }

            // 8. Realm Workers (Load Balanced)
            for (let i = 0; i < workerRealmCount; i++) {
                // Round robin selection of edge port
                const edgePort = this.REALM_EDGE_START_PORT + (i % workerEdgeCount);
                const realmUrl = `http://127.0.0.1:${edgePort}`;

                await this.track(await RunningProcess.spawnWithInitializationHint(
                    [
                        workerCli, 'worker',
                        '--user', '0',
                        '--network', this.NETWORK,
                        '--proving-backend', backend,
                        '--realm-api-url', realmUrl,
                        '--private-key', FAKE_MINER_PRIVATE_KEY,
                    ],
                    workerStartedDetector,
                    { cwd, ...getLogPaths(`realm_worker_${i}`, true) }
                ));
            }
        }
    }

    teardown(): void {
        console.log("\n[DevNet] Tearing down...");
        for (const process of this.spawnedProcesses) {
            if (process?.isRunning()) process.kill();
        }
        if (this.needsStartDb) {
            killDocker().catch(() => { });
        }
    }

    static create(): DevNetProcessManager { return new DevNetProcessManager(); }
}

let globalManager: DevNetProcessManager | null = null;

async function runMain() {
    const { values } = parseArgs({
        args: Bun.argv,
        options: {
            jtmb: { type: "boolean" },
            "disable-worker-edge-logs": { type: "boolean" },
            "realm-workers": { type: "string", default: "1" },
            "realm-edge-nodes": { type: "string", default: "1" },
            "realm-id": { type: "string", default: "0" },
            "realm-only": { type: "boolean" },
            "coordinator-only": { type: "boolean" },
        },
        allowPositionals: true,
    });

    const workerRealmCount = parseInt(values["realm-workers"] || "1", 10);
    const workerEdgeCount = parseInt(values["realm-edge-nodes"] || "1", 10);
    const realmId = parseInt(values["realm-id"] || "0", 10);
    const realmOnly = !!values["realm-only"];
    const coordinatorOnly = !!values["coordinator-only"];

    globalManager = DevNetProcessManager.create();

    const shutdown = () => {
        if (globalManager) globalManager.teardown();
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    try {
        await globalManager.setupProcesses({
            jtmb: !!values.jtmb,
            workerRealmCount,
            workerEdgeCount,
            disableWorkerEdgeLogs: !!values["disable-worker-edge-logs"],
            realmId,
            realmOnly,
            coordinatorOnly,
        });
        console.log('DevNet started. Press Ctrl+C to stop.');
        setInterval(() => { }, 1000 * 60);
    } catch (e) {
        console.error("Setup failed:", e);
        if (globalManager) globalManager.teardown();
        process.exit(1);
    }
}

runMain();