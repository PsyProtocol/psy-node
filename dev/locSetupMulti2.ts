import { parseArgs } from "util";
import { rmdir, exists, mkdir } from "fs/promises";
import path from "path";

type ProcessLineVisitor = (line: string, process: RunningProcess) => void;

async function killDocker() {
    try {
        const proc = Bun.spawn(['docker', 'kill', 'valkey-server', 'scylla-server', 'nats-server'], {
            stderr: "ignore", 
            stdout: "ignore"
        });
        await proc.exited;
    } catch (e) {}
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
    stdOutVisitor: ProcessLineVisitor = () => {};
    stdErrVisitor: ProcessLineVisitor = () => {};
    allOutputVisitor: ProcessLineVisitor = () => {};
    onExit: (code: number | null, signal: number | null) => void = () => {};

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

    static async spawn(cmds: string[], options: {cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor, stdoutLogFile?: string, stderrLogFile?: string}): Promise<RunningProcess> {
        // Clear log files if they exist and are requested
        if (options.stdoutLogFile) await Bun.write(options.stdoutLogFile, "");
        if (options.stderrLogFile) await Bun.write(options.stderrLogFile, "");

        const proc = Bun.spawn(cmds, {
            cwd: options.cwd || undefined,
            stdout: "pipe",
            stderr: "pipe"
        });

        const runningProcess = new RunningProcess(proc, options.stdOutVisitor, options.stdErrVisitor, options.allOutputVisitor);

        // --- Handle StdOut ---
        if (proc.stdout) {
            let readableStream = proc.stdout;
            
            // If logging to file, tee the stream: one branch for file, one for logic
            if (options.stdoutLogFile) {
                const [fileBranch, logicBranch] = proc.stdout.tee();
                readableStream = logicBranch as any; 

                // File Writer Loop (Background)
                (async () => {
                    const sink = Bun.file(options.stdoutLogFile!).writer();
                    for await (const chunk of fileBranch) {
                        sink.write(chunk);
                    }
                    sink.end();
                })();
            }

            // Internal Logic Loop (Startup Detection)
            (async () => {
                const decoder = new TextDecoder();
                for await (const chunk of readableStream) {
                    // Logic for detection is kept
                    runningProcess.injestStdOut(decoder.decode(chunk));
                }
                if (runningProcess.lineBufferStdOut.length > 0) {
                    runningProcess.injestStdOut('\n');
                }
            })();
        }

        // --- Handle StdErr ---
        if (proc.stderr) {
            let readableStream = proc.stderr;

            if (options.stderrLogFile) {
                const [fileBranch, logicBranch] = proc.stderr.tee();
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

        // --- Exit Handler ---
        (async () => {
            const code = await proc.exited;
            runningProcess.onExit(code, null);
        })();

        return runningProcess;
    }


    static spawnWithInitializationHint(cmds: string[], hintDetector: (line: string) => boolean, options: {cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor, stdoutLogFile?: string, stderrLogFile?: string}): Promise<RunningProcess> {
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

function scyllaStartedDetector(line: string): boolean {
    return line.includes('init - Scylla version') && line.includes('initialization completed');
}
function coordinatorProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_COORDINATOR_PROCESSOR_STARTED]');
}
function coordinatorEdgeProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_COORDINATOR_EDGE_RPC_STARTED]');
}
function workerStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_PROOF_MINER_WORKER_STARTED]');
}
function realmProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_REALM_PROCESSOR_STARTED]');
}
function realmEdgeProcessorStartedDetector(line: string): boolean {
    return line.startsWith('[CFLI:PSY_REALM_EDGE_RPC_STARTED]');
}

// --- Helpers ---

async function buildProject(cwd?: string) {
    console.log("Building project with 'cargo build --release'...");
    const proc = Bun.spawn(["cargo", "build", "--release"], {
        cwd,
        stdout: "inherit",
        stderr: "inherit"
    });
    const exitCode = await proc.exited;
    if (exitCode !== 0) {
        throw new Error(`Build failed with exit code ${exitCode}`);
    }
    console.log("Build successful.");
}

async function cleanCheckpoint(checkpointPath: string, cwd: string = '.') {
    const fullPath = path.resolve(cwd, checkpointPath);
    if (await exists(fullPath)) {
        console.log(`Cleaning checkpoint: ${fullPath}`);
        await rmdir(fullPath, { recursive: true });
    }
}

interface ProcessOptions {
    cwd?: string;
    jtmb?: boolean;
    workerRealmCount: number;
    workerEdgeCount: number;
    disableWorkerEdgeLogs?: boolean;
}

class DevNetProcessManager {
    spawnedProcesses: RunningProcess[] = [];
    scyllaProcess: RunningProcess | null = null;
    coordinatorProcessor: RunningProcess | null = null;
    coordinatorEdge: RunningProcess | null = null;
    coordinatorWorker: RunningProcess | null = null;
    realmProcessor: RunningProcess | null = null;
    realmEdges: RunningProcess[] = [];
    realmWorkers: RunningProcess[] = [];

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
        
        const logsDir = path.join(cwd, "logs");
        await mkdir(logsDir, { recursive: true });

        // Helper to conditionally generate log paths
        const getLogPaths = (baseName: string, isWorkerOrEdge: boolean) => {
            if (isWorkerOrEdge && disableWorkerEdgeLogs) {
                return {};
            }
            return {
                stdoutLogFile: path.join(logsDir, `${baseName}_logs.txt`),
                stderrLogFile: path.join(logsDir, `${baseName}_errs.txt`),
            };
        };

        // 1. Start Database
        this.scyllaProcess = this.track(await RunningProcess.spawnWithInitializationHint(
            ['./dev/start_db.sh'],
            scyllaStartedDetector,
            { 
                cwd,
                ...getLogPaths("scylla", false)
            },
        ));
        console.log(`ScyllaDB started with PID: ${this.scyllaProcess.pid}`);

        // 2. Build Project
        await buildProject(cwd);

        // Define Binary Paths
        const nodeCli = './target/release/psy_node_cli';
        const workerCli = './target/release/psy_worker_cli';
        const backendArgs = jtmb ? ['--proving-backend', 'jtmb-poseidon-goldilocks'] : [];

        // 3. Coordinator Processor
        await cleanCheckpoint('./local_checkpoints/coordinator_0_0', cwd);
        this.coordinatorProcessor = this.track(await RunningProcess.spawnWithInitializationHint(
            [
                nodeCli, 
                'start-coordinator-processor', 
                ...backendArgs,
                '--config', './psy_cli/example_node_configs/coordinator_processor_1.yaml'
            ],
            coordinatorProcessorStartedDetector,
            { 
                cwd,
                ...getLogPaths("coordinator_processor_1", false)
            },
        ));
        console.log(`Coordinator Processor started with PID: ${this.coordinatorProcessor.pid}`);

        // 4. Coordinator Edge
        this.coordinatorEdge = this.track(await RunningProcess.spawnWithInitializationHint(
            [
                nodeCli,
                'start-coordinator-edge',
                ...backendArgs,
                '--config', './psy_cli/example_node_configs/coordinator_edge_1.yaml'
            ],
            coordinatorEdgeProcessorStartedDetector,
            { 
                cwd,
                ...getLogPaths("coordinator_edge_1", true)
            },
        ));
        console.log(`Coordinator Edge RPC started with PID: ${this.coordinatorEdge.pid}`);

        // 5. Coordinator Worker
        this.coordinatorWorker = this.track(await RunningProcess.spawnWithInitializationHint(
            [
                workerCli,
                'worker',
                '--user', '0',
                '--network', 'local-devnet',
                ...backendArgs,
                '--config', './psy_cli/example_node_configs/worker_1.yml'
            ],
            workerStartedDetector,
            { 
                cwd,
                ...getLogPaths("worker_1", true)
            },
        ));
        console.log(`Coordinator Worker started with PID: ${this.coordinatorWorker.pid}`);

        // 6. Realm Processor
        await cleanCheckpoint('./local_checkpoints/realm_0_1', cwd);
        this.realmProcessor = this.track(await RunningProcess.spawnWithInitializationHint(
            [
                nodeCli,
                'start-realm-processor',
                ...backendArgs,
                '--config', './psy_cli/example_node_configs/realm_processor_1.yaml'
            ],
            realmProcessorStartedDetector,
            { 
                cwd,
                ...getLogPaths("realm_processor_1", false)
            },
        ));
        console.log(`Realm Processor started with PID: ${this.realmProcessor.pid}`);

        // 7. Realm Edges (Scalable)
        for (let i = 0; i < workerEdgeCount; i++) {
            let configPath = '';
            if (i === 0) {
                 configPath = './psy_cli/example_node_configs/realm_edge_1.yaml';
            } else {
                 configPath = `./psy_cli/example_node_configs/perf_test/realm_0_edge_${i}.yaml`;
            }

            const logPrefix = `realm_edge_${i}`;
            console.log(`Starting Realm Edge ${i} using config ${configPath}...`);
            const p = this.track(await RunningProcess.spawnWithInitializationHint(
                [
                    nodeCli,
                    'start-realm-edge',
                    ...backendArgs,
                    '--config', configPath
                ],
                realmEdgeProcessorStartedDetector,
                { 
                    cwd,
                    ...getLogPaths(logPrefix, true)
                },
            ));
            this.realmEdges.push(p);
            console.log(`Realm Edge ${i} started with PID: ${p.pid}`);
        }

        // 8. Realm Workers (Scalable)
        for (let i = 0; i < workerRealmCount; i++) {
            let configPath = '';
            if (i === 0) {
                 configPath = './psy_cli/example_node_configs/worker_realm_1.yml';
            } else {
                 configPath = `./psy_cli/example_node_configs/perf_test/realm_0_worker_${i}.yml`;
            }

            const logPrefix = `realm_worker_${i}`;
            console.log(`Starting Realm Worker ${i} using config ${configPath}...`);
            const p = this.track(await RunningProcess.spawnWithInitializationHint(
                [
                    workerCli,
                    'worker',
                    '--user', '0',
                    '--network', 'local-devnet',
                    ...backendArgs,
                    '--config', configPath
                ],
                workerStartedDetector,
                { 
                    cwd,
                    ...getLogPaths(logPrefix, true)
                },
            ));
            this.realmWorkers.push(p);
            console.log(`Realm Worker ${i} started with PID: ${p.pid}`);
        }
    }

    teardown(): void {
        console.log("\n[DevNet] Tearing down all processes...");
        for (const process of this.spawnedProcesses) {
            if (process && process.isRunning()) {
                try {
                    console.log(`[DevNet] Killing PID: ${process.pid}`);
                    process.kill();
                } catch (e) {
                    console.error(`[DevNet] Failed to kill PID ${process.pid}:`, e);
                }
            }
        }
        if (this.scyllaProcess && this.scyllaProcess.isRunning()) {
            try {
                this.scyllaProcess.killWithSignal('SIGINT');
            } catch (e) {}
        }
        killDocker().then(() => {
            console.log("[DevNet] Docker containers killed.");
        }).catch((e) => {
            console.error("[DevNet] Failed to kill Docker containers:", e);
        });
    }

    static create(): DevNetProcessManager {
        return new DevNetProcessManager();
    }
}

// Global reference for the emergency exit hooks
let globalManager: DevNetProcessManager | null = null;

async function runMain() {
    const { values } = parseArgs({
        args: Bun.argv,
        options: {
            jtmb: { type: "boolean" },
            "disable-worker-edge-logs": { type: "boolean" },
            "worker-realm-count": { type: "string", default: "1" },
            "worker-edge-count": { type: "string", default: "1" }
        },
        allowPositionals: true,
    });
    
    const jtmbEnabled = !!values.jtmb;
    const disableWorkerEdgeLogs = !!values["disable-worker-edge-logs"];
    const workerRealmCount = parseInt(values["worker-realm-count"] || "1", 10) || 1;
    const workerEdgeCount = parseInt(values["worker-edge-count"] || "1", 10) || 1;

    const mode = jtmbEnabled ? 'JTMB DevNet' : 'Standard Plonky2';

    console.log("Starting Local DevNet in mode:", mode);
    console.log(`Configuration: ${workerRealmCount} Realm Workers, ${workerEdgeCount} Realm Edges.`);
    if (disableWorkerEdgeLogs) {
        console.log("Worker and Edge logs are disabled.");
    }

    // Initialize Manager
    globalManager = DevNetProcessManager.create();

    // Hook up signal listeners
    const shutdown = (signal: string) => {
        console.log(`\nReceived ${signal}.`);
        if (globalManager) {
            globalManager.teardown();
        }
        process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

    // Hook up Exception listeners to ensure cleanup on crashes
    process.on('uncaughtException', (err) => {
        console.error('Uncaught Exception:', err);
        if (globalManager) globalManager.teardown();
        process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
        console.error('Unhandled Rejection at:', promise, 'reason:', reason);
        if (globalManager) globalManager.teardown();
        process.exit(1);
    });

    // Start Processes
    try {
        await globalManager.setupProcesses({ 
            jtmb: jtmbEnabled,
            workerRealmCount,
            workerEdgeCount,
            disableWorkerEdgeLogs
        });
        
        console.log('DevNet started successfully. Press Ctrl+C to stop.');
        
        // Keep alive
        setInterval(() => {}, 1000 * 60 * 60); 

    } catch (e) {
        console.error("Setup failed:", e);
        if (globalManager) globalManager.teardown();
        process.exit(1);
    }
}

// Final safety net: synchronized exit hook
process.on('exit', () => {
    if (globalManager) {
        globalManager.teardown();
    }
});

runMain().catch(err => {
    console.error('Error in main execution:', err);
    process.exit(1);
});