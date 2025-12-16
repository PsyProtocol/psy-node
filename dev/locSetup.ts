import { parseArgs } from "util";



type ProcessLineVisitor = (line: string, process: RunningProcess) => void;


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

    async kill(): Promise<void> {
        this.proc.kill()
    }
    
    isRunning(): boolean {
        return this.proc.killed === false;
    }
    static async spawn(cmds: string[], options: {cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor}): Promise<RunningProcess> {
        const proc = Bun.spawn(cmds, {cwd: options.cwd || undefined, stdout: "pipe", stderr: "pipe"});
        const runningProcess = new RunningProcess(proc, options.stdOutVisitor, options.stdErrVisitor, options.allOutputVisitor);

        (async () => {
            for await (const chunk of proc.stdout) {
                runningProcess.injestStdOut(new TextDecoder().decode(chunk));
            }
            // Handle any remaining buffered data
            if (runningProcess.lineBufferStdOut.length > 0) {
                runningProcess.injestStdOut('\n');
            }
        })();

        (async () => {
            for await (const chunk of proc.stderr) {
                runningProcess.injestStdErr(new TextDecoder().decode(chunk));
            }
            // Handle any remaining buffered data
            if (runningProcess.lineBufferStdErr.length > 0) {
                runningProcess.injestStdErr('\n');
            }
        })();

        (async () => {
            const code = await proc.exited;
            runningProcess.onExit(code, null);
        })();

        return runningProcess;
    }
    killWithSignal(signal: number | NodeJS.Signals): void {
        this.proc.kill(signal);
    }
    static spawnWithInitializationHint(cmds: string[], hintDetector: (line: string) => boolean, options: {cwd?: string, stdOutVisitor?: ProcessLineVisitor, stdErrVisitor?: ProcessLineVisitor, allOutputVisitor?: ProcessLineVisitor}): Promise<RunningProcess> {

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
                allOutputVisitor: allOutputVisitor
            });
            // In case the process exits before initialization
            proc.onExit = (code: number | null, signal: number | null) => {
                if (!initialized) {
                    reject(new Error(`Process exited before initialization hint was found. Exit code: ${code}, signal: ${signal}`));
                }
            };
        });
    }
}



// [SCYLLA] INFO  2025-12-15 09:24:01,862 [shard  0:main] init - Scylla version 2025.3.1-0.20250907.2bbf3cf669bb initialization completed.

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


class DevNetProcessManager {
    scyllaProcess: RunningProcess | null = null;
    coordinatorProcessor: RunningProcess | null = null
    coordinatorEdge: RunningProcess | null = null
    coordinatorWorker: RunningProcess | null = null
    realmProcessor: RunningProcess | null = null
    realmEdge: RunningProcess | null = null
    realmWorker: RunningProcess | null = null

    async setupProcesses(options?: {cwd?: string, jtmb?: boolean}): Promise<void> {
        const psyDevScript = options?.jtmb ? './dev/j.sh' : './dev/d.sh';
        const cmdOptions = options?.cwd ? {cwd: options.cwd} : {};

        this.scyllaProcess = await RunningProcess.spawnWithInitializationHint(
            ['./dev/start_db.sh'],
            scyllaStartedDetector,
            cmdOptions,
        );
        
        console.log(`ScyllaDB started with PID: ${this.scyllaProcess.pid}`);

        this.coordinatorProcessor = await RunningProcess.spawnWithInitializationHint(
            [psyDevScript, 'p', '-g'],
            coordinatorProcessorStartedDetector,
            cmdOptions,
        );
        console.log(`Coordinator Processor started with PID: ${this.coordinatorProcessor.pid}`);
        this.coordinatorEdge = await RunningProcess.spawnWithInitializationHint(
            [psyDevScript, 'edge'],
            coordinatorEdgeProcessorStartedDetector,
            cmdOptions,
        );
        console.log(`Coordinator Edge RPC started with PID: ${this.coordinatorEdge.pid}`);
        this.coordinatorWorker = await RunningProcess.spawnWithInitializationHint(
            [psyDevScript, 'w'],
            workerStartedDetector,
            cmdOptions,
        );
        console.log(`Coordinator Worker started with PID: ${this.coordinatorWorker.pid}`);

        this.realmProcessor = await RunningProcess.spawnWithInitializationHint(
            [psyDevScript, 'rp', '-g'],
            realmProcessorStartedDetector,
            cmdOptions,
        );
        console.log(`Realm Processor started with PID: ${this.realmProcessor.pid}`);

        this.realmEdge = await RunningProcess.spawnWithInitializationHint(
            [psyDevScript, 're'],
            realmEdgeProcessorStartedDetector,
            cmdOptions,
        );
        console.log(`Realm Edge RPC started with PID: ${this.realmEdge.pid}`);

        this.realmWorker = await RunningProcess.spawnWithInitializationHint(
            [psyDevScript, 'rw'],
            workerStartedDetector,
            cmdOptions,
        );
        console.log(`Realm Worker started with PID: ${this.realmWorker.pid}`);
    }

    async teardown(): Promise<void> {
        const processes = [
            this.realmProcessor,
            this.coordinatorProcessor,
            this.coordinatorWorker,
            this.realmWorker,
            this.realmEdge,
            this.coordinatorEdge,
        ];
        for (const process of processes) {
            if (process && process.isRunning()) {
                console.log(`Killing process with PID: ${process.pid}`);
                await process.kill();
            }
        }
        if (this.scyllaProcess && this.scyllaProcess.isRunning()) {
            console.log(`Killing ScyllaDB process with PID: ${this.scyllaProcess.pid}`);
            this.scyllaProcess.killWithSignal('SIGINT');
        }
    }
    static async create(options?: {cwd?: string, jtmb?: boolean}): Promise<DevNetProcessManager> {
        const manager = new DevNetProcessManager();
        await manager.setupProcesses(options);
        return manager;
    }
}

async function runSetupLocalDevnet(options?: {cwd?: string, jtmb?: boolean}) {
    const manager = await DevNetProcessManager.create(options);
    process.on('SIGINT', async () => {
        console.log('Received SIGINT, tearing down processes...');
        await manager.teardown();
        process.exit(0);
    });
    return manager;
}


async function runMain() {

    const { values, positionals } = parseArgs({
        args: Bun.argv,
        options: {
            jtmb: {
                type: "boolean",
            },
        },
        allowPositionals: true,
    });
    const jtmbEnabled = !!values.jtmb;


    const mode = jtmbEnabled ? 'JTMB DevNet' : 'Standard Plonky2';

    console.log("Starting Local DevNet in mode:", mode);
    const manager = await runSetupLocalDevnet({jtmb: jtmbEnabled});
}

runMain().then(()=>{
    console.log('DevNet started.');
}).catch(err => {
    console.error('Error in main execution:', err);
});


