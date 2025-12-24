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
function dummyProverStartedDetector(line: string): boolean { return line.startsWith('[CFLI:DUMMY_END_CAP_PROVER_STARTED]'); }

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
    realmEdgeCount: number;
    coordinatorEdgeCount: number;
    coordinatorWorkersCount: number;
    disableWorkerEdgeLogs?: boolean;
    startRealmId?: number;
    endRealmId?: number;
    realmOnly?: boolean;
    coordinatorOnly?: boolean;
    dbOnly?: boolean;
    workersOnly?: boolean;
    dummyProversCount?: number;
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
        const realmEdgeCount = options.realmEdgeCount;
        const coordinatorEdgeCount = options.coordinatorEdgeCount;
        const coordinatorWorkersCount = options.coordinatorWorkersCount;


        const disableWorkerEdgeLogs = !!options.disableWorkerEdgeLogs;
        // Determine what components to start
        const hasOnlyOptions = !!options.dbOnly || !!options.coordinatorOnly || !!options.realmOnly || !!options.workersOnly || (options.dummyProversCount || 0) > 0;
        const startAll = !hasOnlyOptions;

        const startCoordinatorProcessor = startAll || !!options.coordinatorOnly;
        const startCoordinatorWorkers = (coordinatorWorkersCount > 0) || !!options.workersOnly;
        const startRealmProcessor = startAll || !!options.realmOnly;
        const startRealmWorkers = (workerRealmCount > 0) || !!options.workersOnly;

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

            // Clean checkpoints when resetting database
            console.log("[DevNet] Cleaning local checkpoints...");
            await cleanCheckpoint('./local_checkpoints', cwd);

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

            // 4. Coordinator Edges (Scalable)
            const coordEdgePromises: Promise<RunningProcess>[] = [];
            for (let j = 0; j < coordinatorEdgeCount; j++) {
                const port = 1337 + j;
                const edgePromise = RunningProcess.spawnWithInitializationHint(
                    [
                        nodeCli, 'start-coordinator-edge',
                        '--coordinator-id', '0',
                        '--coordinator-sub-id', j.toString(),
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
                    { cwd, ...getLogPaths(`coordinator_edge_${j}`, true) }
                ).then(proc => this.track(proc));
                coordEdgePromises.push(edgePromise);
            }
            await Promise.all(coordEdgePromises);
        }

        // 5. Coordinator Workers
        if (startCoordinatorWorkers && coordinatorWorkersCount > 0) {
            for (let i = 0; i < coordinatorWorkersCount; i++) {
                // Round robin selection of coordinator edge port
                const coordEdgePort = 1337 + (i % coordinatorEdgeCount);
                const coordUrl = `http://${this.host}:${coordEdgePort}`;

                await this.track(await RunningProcess.spawnWithInitializationHint(
                    [
                        workerCli, 'worker',
                        '--user', i.toString(),
                        '--network', this.NETWORK,
                        '--proving-backend', backend,
                        '--coordinator-api-url', coordUrl,
                        '--private-key', FAKE_MINER_PRIVATE_KEY,
                    ],
                    workerStartedDetector,
                    { cwd, ...getLogPaths(`coordinator_worker_${i}`, true) }
                ));
            }
        }

        if (startRealmProcessor) {
            console.log(`[DevNet] Starting ${realmsCount} realm processors and edges in parallel...`);

            // Clean all checkpoints first
            console.log(`[DevNet] Cleaning checkpoints for ${realmsCount} realms...`);
            for (let i = 0; i < realmsCount; i++) {
                const realmId = startRealmId + i;
                await cleanCheckpoint('./local_checkpoints/realm_' + realmId + '_1', cwd);
            }

            // Start all realm processors and edges in parallel
            const numBatches = Math.floor(realmsCount / 4);
            for (let b = 0; b < numBatches; b++) {
                const realmPromises: Promise<RunningProcess>[] = [];

                for (let i = 0; i < 4; i++) {
                    const realmId = startRealmId + 4 * b + i;
                    const realmEdgeStartPort = 13380 + realmId * 10;

                    // Start realm processor
                    const processorPromise = RunningProcess.spawnWithInitializationHint(
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
                    ).then(proc => this.track(proc));
                    realmPromises.push(processorPromise);

                    // Start realm edges
                    for (let j = 0; j < realmEdgeCount; j++) {
                        const port = realmEdgeStartPort + j;
                        const edgePromise = RunningProcess.spawnWithInitializationHint(
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
                        ).then(proc => this.track(proc));
                        realmPromises.push(edgePromise);
                    }
                }

                // Wait for all realm processes to start
                await Promise.all(realmPromises);
            }
            console.log(`[DevNet] All realm processors and edges started`);
        }

        if (startRealmWorkers) {
            const realmsPerWorker = Math.ceil(realmsCount / workerRealmCount);
            console.log(`[DevNet] Starting ${workerRealmCount} workers, ${realmsPerWorker} realms per each worker (${realmsCount} total realms)...`);

            const workerPromises: Promise<RunningProcess>[] = [];

            for (let workerId = 0; workerId < workerRealmCount; workerId++) {
                const startRealmForWorker = workerId * realmsPerWorker;
                const endRealmForWorker = Math.min((workerId + 1) * realmsPerWorker, realmsCount);

                const realmUrls: string[] = [];
                for (let realmIndex = startRealmForWorker; realmIndex < endRealmForWorker; realmIndex++) {
                    const realmId = startRealmId + realmIndex;
                    const realmEdgeStartPort = 13380 + realmId * 10;
                    const edgePort = realmEdgeStartPort + workerId % realmEdgeCount;
                    const realmUrl = `http://${this.host}:${edgePort}`;
                    realmUrls.push(realmUrl);
                }

                const workerArgs = [
                    workerCli, 'worker',
                    '--user', `${workerId}`,
                    '--network', this.NETWORK,
                    '--proving-backend', backend,
                ];

                for (const realmUrl of realmUrls) {
                    workerArgs.push('--realm-api-url', realmUrl);
                }

                workerArgs.push('--private-key', FAKE_MINER_PRIVATE_KEY);

                const workerPromise = RunningProcess.spawnWithInitializationHint(
                    workerArgs,
                    workerStartedDetector,
                    { cwd, ...getLogPaths(`worker_${workerId}`, true) }
                ).then(proc => this.track(proc));
                workerPromises.push(workerPromise);
            }

            // Wait for all worker processes to start
            await Promise.all(workerPromises);
            console.log(`[DevNet] All ${workerRealmCount} shared workers started (${workerPromises.length} connections total)`);
        }

        // 8. Dummy Provers (if requested)
        const dummyProversCount = options.dummyProversCount || 0;
        if (dummyProversCount > 0) {
            console.log(`[DevNet] Starting ${dummyProversCount} dummy provers (realms ${startRealmId}-${endRealmId})...`);

            const dummyPromises: Promise<RunningProcess>[] = [];
            for (let i = 0; i < dummyProversCount; i++) {
                const dummyPromise = RunningProcess.spawnWithInitializationHint(
                    [
                        './dev/dummy_prover.sh', 'prove_random',
                        '-p', backend,
                        '-H', this.host,
                        '--start-realm-id', startRealmId.toString(),
                        '--end-realm-id', endRealmId.toString()
                    ],
                    dummyProverStartedDetector,
                    { cwd, ...getLogPaths(`dummy_prover_${i}`, true) }
                ).then(proc => this.track(proc));
                dummyPromises.push(dummyPromise);
            }

            // Wait for all dummy provers to start
            await Promise.all(dummyPromises);
            console.log(`[DevNet] All ${dummyProversCount} dummy provers started`);
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
            "coordinator-edge-nodes": { type: "string", default: "1" },
            "coordinator-workers": { type: "string" },
            "start-realm-id": { type: "string", default: "0" },
            "end-realm-id": { type: "string" },
            "host": { type: "string", default: "127.0.0.1" },
            "coordinator-only": { type: "boolean" },
            "db-only": { type: "boolean" },
            "realm-only": { type: "boolean" },
            "workers-only": { type: "boolean" },
            "dummy-provers-only": { type: "string" },
            "help": { type: "boolean", short: "h" },
        },
        allowPositionals: true,
    });

    const hasOnlyOptions = !!values["db-only"] || !!values["coordinator-only"] || !!values["realm-only"] || !!values["workers-only"] || !!values["dummy-provers-only"];
    const workerRealmCount = values["realm-workers"] ? parseInt(values["realm-workers"], 10) : 0;
    const realmEdgeCount = parseInt(values["realm-edge-nodes"] || "1", 10);
    const coordinatorEdgeCount = parseInt(values["coordinator-edge-nodes"] || "1", 10);
    const coordinatorWorkersCount = values["coordinator-workers"] ? parseInt(values["coordinator-workers"], 10) : (!hasOnlyOptions ? 1 : 0);
    const startRealmId = parseInt(values["start-realm-id"] || "0", 10);
    const endRealmId = values["end-realm-id"] ? parseInt(values["end-realm-id"], 10) : startRealmId;
    const host = values["host"] || "127.0.0.1";
    const realmOnly = !!values["realm-only"];
    const coordinatorOnly = !!values["coordinator-only"];
    const dbOnly = !!values["db-only"];
    const workersOnly = !!values["workers-only"];
    const dummyProversCount = values["dummy-provers-only"] ? parseInt(values["dummy-provers-only"], 10) : 0;
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
   --realm-workers <count>         Number of shared workers distributed across all realms (default: 1 when starting full system)
   --realm-edge-nodes <count>      Number of edge nodes per realm (default: 1)
   --coordinator-edge-nodes <count> Number of edge nodes for coordinator (default: 1)
   --coordinator-workers <count>   Number of coordinator workers (default: 1 when starting coordinator, 0 in only modes)
   --start-realm-id <id>           Starting realm ID (default: 0)
   --end-realm-id <id>             Ending realm ID (inclusive, default: 127 when starting full system)
   --realm-only                    Start only realm processors and edges (requires database and coordinator to be running)
   --coordinator-only              Start only coordinator (requires database to be running)
   --db-only                       Start only database services
   --workers-only                  Start only workers (requires database to be running)
   --dummy-provers-only <count>    Start only dummy provers within the specified realm range (requires database, coordinator, and realms to be running)
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
   bun run dev/locSetupV4.ts --dummy-provers-only 4 --start-realm-id 1 --end-realm-id 2  # start 4 dummy provers in realms 1-2

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
            realmEdgeCount,
            coordinatorEdgeCount,
            coordinatorWorkersCount,
            disableWorkerEdgeLogs: !!values["disable-worker-edge-logs"],
            startRealmId,
            endRealmId,
            realmOnly,
            coordinatorOnly,
            dbOnly,
            workersOnly,
            dummyProversCount,
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
