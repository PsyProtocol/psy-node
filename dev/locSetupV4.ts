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
}

// --- Log Detectors ---
function scyllaStartedDetector(line: string): boolean {
    return line.includes('init - Scylla version') && line.includes('initialization completed');
}
function coordinatorProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_COORDINATOR_PROCESSOR_STARTED]'); }
function coordinatorEdgeProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_COORDINATOR_EDGE_RPC_STARTED]'); }
function workerStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_PROOF_MINER_WORKER_STARTED]'); }
function realmProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_REALM_PROCESSOR_STARTED]'); }
function realmEdgeProcessorStartedDetector(line: string): boolean { return line.startsWith('[CFLI:PSY_REALM_EDGE_RPC_STARTED]'); }

async function buildProject(cwd?: string) {
    console.log("Building project...");
    const proc = Bun.spawn(["cargo", "build", "--release", "--bin", "psy_node_cli", "--bin", "psy_worker_cli"], { cwd, stdout: "inherit", stderr: "inherit" });
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
    coordinatorWorkersCount: number;
    disableWorkerEdgeLogs?: boolean;
    startRealmId?: number;
    endRealmId?: number;
    realmOnly?: boolean;
    coordinatorOnly?: boolean;
    dbOnly?: boolean;
    workersOnly?: boolean;
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

    constructor(host: string = "127.0.0.1") {
        this.host = host;
        this.SCYLLA_URL = `${host}:9042`;
        this.NATS_URL = `nats://${host}:4222`;
        this.REDIS_URL = `redis://${host}:6379`;
        this.COORD_API_URL = `http://${host}:1337`;
    }

    private track(p: RunningProcess): RunningProcess {
        this.spawnedProcesses.push(p);
        return p;
    }

    async setupProcesses(options: ProcessOptions): Promise<void> {
        const cwd = options?.cwd || ".";
        const jtmb = !!options?.jtmb;
        const workerRealmCount = options.workerRealmCount;
        const workerEdgeCount = options.workerEdgeCount;
        const coordinatorWorkersCount = options.coordinatorWorkersCount;


        const disableWorkerEdgeLogs = !!options.disableWorkerEdgeLogs;
        // Determine what components to start
        const hasOnlyOptions = !!options.dbOnly || !!options.coordinatorOnly || !!options.realmOnly || !!options.workersOnly;
        const startAll = !hasOnlyOptions;

        const startCoordinatorProcessor = startAll || !!options.coordinatorOnly;
        const startCoordinatorWorkers = (coordinatorWorkersCount > 0) || !!options.coordinatorOnly || !!options.workersOnly;
        const startRealmProcessor = startAll || !!options.realmOnly;
        const startRealmWorkers = (workerRealmCount > 0) || !!options.realmOnly || !!options.workersOnly;

        const needsStartDb = !hasOnlyOptions || !!options.dbOnly;
        const startRealmId = options.startRealmId || 0;
        const endRealmId = options.endRealmId !== undefined ? options.endRealmId : (startAll ? 3 : startRealmId);
        const realmsCount = Math.max(0, endRealmId - startRealmId + 1);

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

        const backend = jtmb ? 'jtmb-poseidon-goldilocks' : 'plonky2-poseidon-goldilocks';

        // 1. Build (skip if binaries exist)
        const psyNodeCliPath = path.join(cwd || '.', 'target/release/psy_node_cli');
        const psyWorkerCliPath = path.join(cwd || '.', 'target/release/psy_worker_cli');
        if (!(await exists(psyNodeCliPath)) || !(await exists(psyWorkerCliPath))) {
            await buildProject(cwd);
        } else {
            console.log("Binaries already exist, skipping build...");
        }

        // 2. Start Database
        if (this.needsStartDb) {
            console.log("[DevNet] Killing existing docker containers...");
            await killDocker();
            await this.track(await RunningProcess.spawnWithInitializationHint(
                ['./dev/start_db.sh'], scyllaStartedDetector, { cwd, ...getLogPaths("scylla", false) }
            ));
            console.log("[DevNet] Waiting additional 1 second for ScyllaDB to be fully ready...");
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        const nodeCli = './target/release/psy_node_cli';
        const workerCli = './target/release/psy_worker_cli';

        // 3. Coordinator Processor
        if (startCoordinatorProcessor) {
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
                    '--listen', '0.0.0.0',
                    '--proving-backend', backend,
                    '--verbose'
                ],
                coordinatorEdgeProcessorStartedDetector,
                { cwd, ...getLogPaths("coordinator_edge_0", true) }
            ));
        }

        // 5. Coordinator Workers
        if (startCoordinatorWorkers && coordinatorWorkersCount > 0) {
            for (let i = 0; i < coordinatorWorkersCount; i++) {
                await this.track(await RunningProcess.spawnWithInitializationHint(
                    [
                        workerCli, 'worker',
                        '--user', i.toString(),
                        '--network', this.NETWORK,
                        '--proving-backend', backend,
                        '--coordinator-api-url', this.COORD_API_URL,
                        '--private-key', FAKE_MINER_PRIVATE_KEY,
                    ],
                    workerStartedDetector,
                    { cwd, ...getLogPaths(`coordinator_worker_${i}`, true) }
                ));
            }
        }

        if (startRealmProcessor) {
            // 6. Realm Processor
            for (let i = 0; i < realmsCount; i++) {
                const realmId = startRealmId + i;
                const realmEdgeStartPort = 13380 + realmId * 10;

                // Add a small delay between starting realms to prevent DB connection storms
                if (i > 0) {
                    console.log(`[DevNet] Waiting for 0.5 seconds before starting next realm...`);
                    await new Promise(resolve => setTimeout(resolve, 500));
                }

                console.log(`[DevNet] Starting Realm Processor ${realmId}...`);

                await cleanCheckpoint('./local_checkpoints/realm_' + realmId + '_1', cwd);
                await this.track(await RunningProcess.spawnWithInitializationHint(
                    [
                        nodeCli, 'start-realm-processor',
                        '--realm-id', realmId.toString(),
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
                for (let j = 0; j < workerEdgeCount; j++) {
                    const port = realmEdgeStartPort + j;
                    await this.track(await RunningProcess.spawnWithInitializationHint(
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
                        { cwd, ...getLogPaths(`realm_edge_${realmId}_${j}`, true) }
                    ));
                }
            }
        }

        if (startRealmWorkers) {
            for (let i = 0; i < realmsCount; i++) {
                const realmId = startRealmId + i;
                const realmEdgeStartPort = 13380 + realmId * 10;

                // Add a small delay between starting realms to prevent DB connection storms
                if (i > 0) {
                    console.log(`[DevNet] Waiting for 0.5 seconds before starting next realm workers...`);
                    await new Promise(resolve => setTimeout(resolve, 500));
                }

                // 8. Realm Workers (Load Balanced)
                for (let k = 0; k < workerRealmCount; k++) {
                    // Round robin selection of edge port
                    const edgePort = realmEdgeStartPort + (k % workerEdgeCount);
                    const realmUrl = `http://${this.host}:${edgePort}`;

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
                        { cwd, ...getLogPaths(`realm_worker_${realmId}_${k}`, true) }
                    ));
                }
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

    static create(host?: string): DevNetProcessManager { return new DevNetProcessManager(host); }
}

let globalManager: DevNetProcessManager | null = null;

async function runMain() {
    const { values } = parseArgs({
        args: Bun.argv,
        options: {
            jtmb: { type: "boolean" },
            "disable-worker-edge-logs": { type: "boolean" },
            "realm-workers": { type: "string" },
            "realm-edge-nodes": { type: "string", default: "1" },
            "coordinator-workers": { type: "string" },
            "start-realm-id": { type: "string", default: "0" },
            "end-realm-id": { type: "string" },
            "host": { type: "string", default: "127.0.0.1" },
            "coordinator-only": { type: "boolean" },
            "db-only": { type: "boolean" },
            "realm-only": { type: "boolean" },
            "workers-only": { type: "boolean" },
            "help": { type: "boolean", short: "h" },
        },
        allowPositionals: true,
    });

    const hasOnlyOptions = !!values["db-only"] || !!values["coordinator-only"] || !!values["realm-only"] || !!values["workers-only"];
    const workerRealmCount = values["realm-workers"] ? parseInt(values["realm-workers"], 10) : 0;
    const workerEdgeCount = parseInt(values["realm-edge-nodes"] || "1", 10);
    const coordinatorWorkersCount = values["coordinator-workers"] ? parseInt(values["coordinator-workers"], 10) : (!hasOnlyOptions ? 1 : 0);
    const startRealmId = parseInt(values["start-realm-id"] || "0", 10);
    const endRealmId = values["end-realm-id"] ? parseInt(values["end-realm-id"], 10) : startRealmId;
    const host = values["host"] || "127.0.0.1";
    const realmOnly = !!values["realm-only"];
    const coordinatorOnly = !!values["coordinator-only"];
    const dbOnly = !!values["db-only"];
    const workersOnly = !!values["workers-only"];
    const help = !!values["help"];

    // Show help if requested
    if (help) {
        console.log(`
Psy Network DevNet Setup Tool

Usage: bun run dev/locSetupV4.ts [options]

 Options:
   --host <ip>                     Target host IP (default: 127.0.0.1)
   --jtmb                          Use JTMB proving backend instead of Plonky2
   --disable-worker-edge-logs      Disable logging for worker and edge processes
   --realm-workers <count>         Number of workers per realm (default: 1 when starting realms, 0 in only modes)
   --realm-edge-nodes <count>      Number of edge nodes per realm (default: 1)
   --coordinator-workers <count>   Number of coordinator workers (default: 1 when starting coordinator, 0 in only modes)
   --start-realm-id <id>           Starting realm ID (default: 0)
   --end-realm-id <id>             Ending realm ID (inclusive, default: 127 when starting full system)
   --realm-only                    Start only realms (requires database and coordinator to be running)
   --coordinator-only              Start only coordinator (requires database to be running)
   --db-only                       Start only database services
   --workers-only                  Start only workers (requires database to be running)
   --help, -h                      Show this help message

Examples:
   # Start full system (default when no options specified)
   bun run dev/locSetupV4.ts  # starts all components with realms 0-127

   # Start full system with specific realm range
   bun run dev/locSetupV4.ts --end-realm-id 3  # realms 0,1,2,3

   # Start with workers
   bun run dev/locSetupV4.ts --coordinator-workers 2 --realm-workers 1  # coordinator + realms with workers

   # Start components separately
   bun run dev/locSetupV4.ts --db-only
   bun run dev/locSetupV4.ts --coordinator-only
   bun run dev/locSetupV4.ts --coordinator-only --realm-only  # coordinator + realms
   bun run dev/locSetupV4.ts --workers-only --coordinator-workers 3 --realm-workers 2  # only workers

Notes:
   - Database services are automatically started in full system mode or when --db-only is specified
   - Only modes can be combined (e.g., --coordinator-only --realm-only)
   - Workers are started when --*-workers options are specified
   - No options specified starts the full system (all components)
        `);
        process.exit(0);
    }

    globalManager = DevNetProcessManager.create(host);

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
            coordinatorWorkersCount,
            disableWorkerEdgeLogs: !!values["disable-worker-edge-logs"],
            startRealmId,
            endRealmId,
            realmOnly,
            coordinatorOnly,
            dbOnly,
            workersOnly,
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
