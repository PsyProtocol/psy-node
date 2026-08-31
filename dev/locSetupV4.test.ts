import { describe, expect, it } from "bun:test";
import path from "node:path";
import {
    COORDINATOR_PROCESSOR_READY_MARKER,
    REALM_PROCESSOR_READY_MARKER,
    isExactProcessorReadyLine,
    s3CurlArgs,
} from "./locSetupPolicy";
import {
    ANVIL_STATE_PATH,
    ROLLBACK_STOP_SENTINEL_CONTENT,
    ROLLBACK_STOP_SENTINEL_PATH,
    applicationListenerPorts,
    applicationStartOrder,
    devnetControlSocketPath,
    sendDevnetControlCommand,
    evaluateCompilerArtifactStamp,
    isUsableGenesisData,
    planPsyDappNestedSubmodulesFromDisk,
    readGenesisContractsArtifactStamp,
    resolveLocalAnvilStatePlan,
    resolveProjectsDir,
    RunningProcess,
    runStreamingCaptureStderr,
    retryProcessorStartup,
    splitDevnetProcesses,
    startAfterPrerequisite,
    startDevnetControlServer,
    startRealmProcessorBatchSequentially,
    writeCompilerArtifactStamp,
    writeRollbackStopSentinel,
} from "./locSetupV4";
import type { GenesisContractsArtifactFingerprint } from "./locSetupV4";

describe("s3CurlArgs", () => {
    it("builds a shell-free curl argv that is fail-closed, follows redirects, and shows progress", () => {
        const args = s3CurlArgs("https://psy-protocol-devnet.s3.example/key.bin.zst", "/tmp/key.bin.zst.tmp");

        // No shell: the binary is invoked directly.
        expect(args[0]).toBe("curl");
        expect(args).not.toContain("bash");
        expect(args).not.toContain("-c");

        // Fail-closed: HTTP 4xx/5xx must produce a non-zero exit.
        expect(args).toContain("-f");

        // Errors still surface on piped (non-TTY) stderr.
        expect(args).toContain("-S");

        // Follow S3/CDN redirects.
        expect(args).toContain("-L");

        // Visible progress forced even though stderr is piped.
        expect(args).toContain("--progress-bar");

        // Progress is never silenced.
        expect(args).not.toContain("-s");
        expect(args).not.toContain("--silent");
        expect(args).not.toContain("--no-progress-meter");

        // Body is written to the destination temp file (atomic temp/extract flow
        // is the caller's responsibility); the URL is the final positional arg.
        const oIdx = args.indexOf("-o");
        expect(oIdx).toBeGreaterThan(-1);
        expect(args[oIdx + 1]).toBe("/tmp/key.bin.zst.tmp");
        expect(args[args.length - 1]).toBe("https://psy-protocol-devnet.s3.example/key.bin.zst");
    });

    it("preserves the destination and url verbatim for arbitrary paths", () => {
        const weird = "<workspace>/keystore/sub dir/circuit.bin.zst";
        const args = s3CurlArgs("https://x.example/a/b/c", weird);
        const oIdx = args.indexOf("-o");
        expect(args[oIdx + 1]).toBe(weird);
        expect(args[args.length - 1]).toBe("https://x.example/a/b/c");
    });
});

describe("runStreamingCaptureStderr", () => {
    it("captures stderr and propagates a non-zero exit code (fail-closed signal preserved)", async () => {
        const chunks: Uint8Array[] = [];
        const result = await runStreamingCaptureStderr(
            [process.execPath, "-e", "process.stderr.write('boom-diagnostic\\n'); process.exit(4)"],
            undefined,
            { stderrSink: (c) => chunks.push(c) },
        );

        // The exit code reaches the caller, so downloadS3File can fail-closed.
        expect(result.code).toBe(4);

        // Diagnostics are captured for the error message...
        expect(result.stderr).toContain("boom-diagnostic");

        // ...and the same bytes were streamed (teed) to the sink, i.e. visible
        // progress would reach the terminal in real use.
        const streamed = chunks.map((c) => new TextDecoder().decode(c)).join("");
        expect(streamed).toContain("boom-diagnostic");
    });

    it("returns code 0 on success and an empty captured stderr", async () => {
        const result = await runStreamingCaptureStderr(
            [process.execPath, "-e", "process.exit(0)"],
            undefined,
            { stderrSink: () => undefined },
        );
        expect(result.code).toBe(0);
        expect(result.stderr).toBe("");
    });

    it("propagates PWD via the cwd option (env.PWD equals cwd)", async () => {
        const cwd = process.cwd();
        const result = await runStreamingCaptureStderr(
            [process.execPath, "-e", `process.stderr.write(process.env.PWD + "\\n"); process.exit(0)`],
            cwd,
            { stderrSink: () => undefined },
        );
        expect(result.code).toBe(0);
        expect(result.stderr.trim()).toBe(cwd);
    });
});

describe("processor full-readiness startup", () => {
    it("accepts only exact processor completion markers", () => {
        expect(isExactProcessorReadyLine(COORDINATOR_PROCESSOR_READY_MARKER, COORDINATOR_PROCESSOR_READY_MARKER)).toBe(true);
        expect(isExactProcessorReadyLine(`INFO ${REALM_PROCESSOR_READY_MARKER}`, REALM_PROCESSOR_READY_MARKER)).toBe(true);
        expect(isExactProcessorReadyLine("[COORD_CREATE] processor new start", COORDINATOR_PROCESSOR_READY_MARKER)).toBe(false);
        expect(isExactProcessorReadyLine(`${COORDINATOR_PROCESSOR_READY_MARKER} trailing`, COORDINATOR_PROCESSOR_READY_MARKER)).toBe(false);
    });

    it("rejects non-transient pre-ready exits without retry", async () => {
        let attempts = 0;
        const startup = retryProcessorStartup("coordinator processor", async () => {
            attempts += 1;
            throw new Error("Process exited before initialization hint was found.\nfatal config error");
        }, { maxRetries: 3, retryDelayMs: 0 });
        await expect(startup).rejects.toThrow("fatal config error");
        expect(attempts).toBe(1);
    });

    it("retries transient Scylla raft add_entry failures", async () => {
        const attempts: number[] = [];
        const result = await retryProcessorStartup("realm 7 processor", async (attempt) => {
            attempts.push(attempt);
            if (attempt === 1) throw new Error("Scylla group 0 add_entry schema operation timed out");
            return "ready";
        }, { maxRetries: 2, retryDelayMs: 0 });
        expect(result).toBe("ready");
        expect(attempts).toEqual([1, 2]);
    });

    it("retries a readiness timeout after a transient Scylla failure", async () => {
        const attempts: number[] = [];
        const result = await retryProcessorStartup("realm 1 processor", async (attempt) => {
            attempts.push(attempt);
            if (attempt === 1) throw new Error("Scylla group 0 add_entry schema operation timed out");
            if (attempt === 2) throw new Error("Process did not reach its initialization marker within 180000ms");
            return "ready";
        }, { maxRetries: 3, retryDelayMs: 0 });
        expect(result).toBe("ready");
        expect(attempts).toEqual([1, 2, 3]);
    });

    it("resolves from the exact marker and rejects exit before it", async () => {
        const proc = await RunningProcess.spawnWithInitializationHint(
            [process.execPath, "-e", `process.stderr.write("${COORDINATOR_PROCESSOR_READY_MARKER}\\n", () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0))`],
            (line) => isExactProcessorReadyLine(line, COORDINATOR_PROCESSOR_READY_MARKER),
            { initializationTimeoutMs: 500 },
        );
        expect(proc.isRunning()).toBe(true);
        proc.kill();
        await proc.proc.exited;

        const failed = RunningProcess.spawnWithInitializationHint(
            [process.execPath, "-e", "process.stderr.write('schema bootstrap failed\\n'); process.exit(7)"],
            (line) => isExactProcessorReadyLine(line, REALM_PROCESSOR_READY_MARKER),
            { initializationTimeoutMs: 500 },
        );
        await expect(failed).rejects.toThrow("Exit Code: 7");
        await expect(failed).rejects.toThrow("schema bootstrap failed");
    });
});

describe("startRealmProcessorBatchSequentially", () => {
    it("starts realms in readiness order and stops at the first failure", async () => {
        const started: number[] = [];
        const startup = startRealmProcessorBatchSequentially([4, 5, 6], async (realmId) => {
            started.push(realmId);
            if (realmId === 5) throw new Error("realm 5 failed readiness");
            return realmId;
        });
        await expect(startup).rejects.toThrow("realm 5 failed readiness");
        expect(started).toEqual([4, 5]);
    });
});

function processTemplate(name: string, commands: string[]): RunningProcess {
    const process = Object.create(RunningProcess.prototype) as RunningProcess;
    process.name = name;
    process.cmds = commands;
    return process;
}

describe("devnet application lifecycle", () => {
    it("keeps only the database launcher and Anvil alive", () => {
        const processes = [
            processTemplate("db", ["./dev/start_db.sh", "--persist"]),
            processTemplate("l1_anvil", ["anvil", "--port", "8545"]),
            processTemplate("coordinator_processor", ["psy_node_cli", "start-coordinator-processor"]),
            processTemplate("bridge_relayer", ["psy_relayer_cli", "--config", "daemon.toml"]),
        ];

        const { persistent, applications } = splitDevnetProcesses(processes);
        expect(persistent.map((process) => process.name)).toEqual(["db", "l1_anvil"]);
        expect(applications.map((process) => process.name)).toEqual(["coordinator_processor", "bridge_relayer"]);
    });

    it("orders node core before services, indexers, and relayer", () => {
        const processes = [
            processTemplate("bridge_relayer", ["psy_relayer_cli"]),
            processTemplate("psy_indexer_coordinator", ["psy-indexer"]),
            processTemplate("psy_services", ["psy-services"]),
            processTemplate("envio", ["pnpm", "start"]),
            processTemplate("prove_proxy_0", ["psy_user_cli", "prove-proxy"]),
            processTemplate("worker_0", ["psy_worker_cli", "worker"]),
            processTemplate("realm_edge_0_0", ["psy_node_cli", "start-realm-edge"]),
            processTemplate("realm_0_processor", ["psy_node_cli", "start-realm-processor"]),
            processTemplate("coordinator_edge_0", ["psy_node_cli", "start-coordinator-edge"]),
            processTemplate("coordinator_processor", ["psy_node_cli", "start-coordinator-processor"]),
        ];

        expect(applicationStartOrder(processes)).toEqual([
            "coordinator_processor",
            "coordinator_edge_0",
            "realm_0_processor",
            "realm_edge_0_0",
            "worker_0",
            "prove_proxy_0",
            "envio",
            "psy_services",
            "psy_indexer_coordinator",
            "bridge_relayer",
        ]);
    });

    it("derives every application listener that must close before rollback", () => {
        const processes = [
            processTemplate("coordinator_edge_0", ["psy_node_cli", "start-coordinator-edge", "--port", "1337"]),
            processTemplate("realm_edge_0_0", ["psy_node_cli", "start-realm-edge", "--port", "13380"]),
            processTemplate("prove_proxy_0", ["psy_user_cli", "prove-proxy", "--listen-addr", "0.0.0.0:9999"]),
            processTemplate("faucet_server", ["psy_user_cli", "faucet-server", "--listen-addr", "0.0.0.0:9998"]),
            processTemplate("psy_services", ["psy-services"]),
            processTemplate("envio", ["pnpm", "start"]),
        ];

        expect(applicationListenerPorts(processes)).toEqual([1337, 3000, 9898, 9998, 9999, 13380]);
    });

    it("uses a stable repo-specific control socket path", () => {
        const first = devnetControlSocketPath("<workspace>/psy-node");
        const second = devnetControlSocketPath("<workspace>/psy-node");
        expect(first).toBe(second);
        expect(first).toEndWith(".control.sock");
        expect(first).not.toBe(devnetControlSocketPath("<workspace>/other-node"));
    });


    it("delivers serialized commands through the repo control socket", async () => {
        const repoRoot = `${(await Bun.$`mktemp -d`.text()).trim()}/repo`;
        await Bun.$`mkdir -p ${repoRoot}`.quiet();
        const received: string[] = [];
        const server = await startDevnetControlServer(repoRoot, async (command) => {
            received.push(command);
            return `${command} complete`;
        });
        try {
            expect(await sendDevnetControlCommand(repoRoot, "restart")).toBe("restart complete");
            expect(await sendDevnetControlCommand(repoRoot, "rollback-stop")).toBe("rollback-stop complete");
            expect(await sendDevnetControlCommand(repoRoot, "rollback-resume")).toBe("rollback-resume complete");
            expect(received).toEqual(["restart", "rollback-stop", "rollback-resume"]);
        } finally {
            await server.close();
            await Bun.$`rm -rf ${path.dirname(repoRoot)}`.quiet();
        }
    });
    it("writes the exact rollback attestation", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const sentinelPath = await writeRollbackStopSentinel(dir);
            expect(sentinelPath).toBe(path.join(dir, ROLLBACK_STOP_SENTINEL_PATH));
            expect((await Bun.file(sentinelPath).text()).trim()).toBe(ROLLBACK_STOP_SENTINEL_CONTENT);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});

describe("local Anvil persistence", () => {
    it("uses the ignored db/anvil state path for a new chain", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const plan = await resolveLocalAnvilStatePlan(dir);
            expect(plan.statePath).toBe(path.join(dir, ANVIL_STATE_PATH));
            expect(plan.hasState).toBe(false);
            expect(plan.shouldResetEnvio).toBe(true);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("reuses Anvil and localhost deployments only when both exist", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.$`mkdir -p ${dir}/db/anvil ${dir}/psy-contracts/deployments/localhost`.quiet();
            await Bun.write(`${dir}/db/anvil/state.json`, "{}");
            await Bun.write(`${dir}/psy-contracts/deployments/localhost/deployed-contracts.json`, "{}");
            const plan = await resolveLocalAnvilStatePlan(dir);
            expect(plan.hasState).toBe(true);
            expect(plan.shouldResetEnvio).toBe(false);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects state and deployment drift", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.$`mkdir -p ${dir}/db/anvil`.quiet();
            await Bun.write(`${dir}/db/anvil/state.json`, "{}");
            await expect(resolveLocalAnvilStatePlan(dir)).rejects.toThrow("must exist together");
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects deployment without Anvil state", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.$`mkdir -p ${dir}/psy-contracts/deployments/localhost`.quiet();
            await Bun.write(`${dir}/psy-contracts/deployments/localhost/deployed-contracts.json`, "{}");
            await expect(resolveLocalAnvilStatePlan(dir)).rejects.toThrow("must exist together");
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});

describe("startAfterPrerequisite", () => {
    it("does not start workers until every processor reaches readiness", async () => {
        const order: string[] = [];
        const { promise: readiness, resolve } = Promise.withResolvers<void>();
        const { promise: workersStarted, resolve: resolveWorkersStarted } = Promise.withResolvers<void>();
        const startup = startAfterPrerequisite(readiness, async () => {
            order.push("workers");
            resolveWorkersStarted();
        });

        expect(order).toEqual([]);
        order.push("processors");
        resolve();
        await workersStarted;
        await startup;
        expect(order).toEqual(["processors", "workers"]);
    });

    it("does not start workers when processor readiness fails", async () => {
        let workersStarted = false;
        const startup = startAfterPrerequisite(
            Promise.reject(new Error("realm readiness failed")),
            async () => {
                workersStarted = true;
            },
        );

        await expect(startup).rejects.toThrow("realm readiness failed");
        expect(workersStarted).toBe(false);
    });
});

describe("isUsableGenesisData", () => {
    it("accepts canonical seconds and rejects milliseconds", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const prefix = "x".repeat(70 * 1024);
            const milliseconds = `${dir}/milliseconds.json`;
            const seconds = `${dir}/seconds.json`;
            await Bun.write(milliseconds, `${prefix}\n{"checkpoint_stats":{"block_time":1764248609000}}`);
            await Bun.write(seconds, `${prefix}\n{"checkpoint_stats":{"block_time":1764248609}}`);
            expect(await isUsableGenesisData(seconds)).toBe(true);
            expect(await isUsableGenesisData(milliseconds)).toBe(false);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});

describe("resolveProjectsDir", () => {
    it("uses the explicit cohort directory when configured", () => {
        const originalProjectsDir = process.env.PSY_PROJECTS_DIR;
        try {
            process.env.PSY_PROJECTS_DIR = "<workspace>/mainnet-beta";
            expect(resolveProjectsDir()).toEndWith("<workspace>/mainnet-beta");
        } finally {
            if (originalProjectsDir === undefined) delete process.env.PSY_PROJECTS_DIR;
            else process.env.PSY_PROJECTS_DIR = originalProjectsDir;
        }
    });

    it("defaults to the sibling of the psy-node repo, not HOME/Projects", () => {
        const originalProjectsDir = process.env.PSY_PROJECTS_DIR;
        try {
            delete process.env.PSY_PROJECTS_DIR;
            expect(resolveProjectsDir()).toBe(path.resolve(import.meta.dir, "..", ".."));
        } finally {
            if (originalProjectsDir === undefined) delete process.env.PSY_PROJECTS_DIR;
            else process.env.PSY_PROJECTS_DIR = originalProjectsDir;
        }
    });
});

describe("compiler/genesis artifact stamps", () => {
    const expected: GenesisContractsArtifactFingerprint = {
        compilerRevision: "rev",
        compilerSourcesHash: "sources",
        artifactSha256: "aa".repeat(32),
        artifactByteSize: 42,
    };

    it("matches only the exact compiler identity and artifact bytes", () => {
        expect(evaluateCompilerArtifactStamp({ ...expected }, expected)).toBe("match");
        expect(evaluateCompilerArtifactStamp(null, expected)).toBe("missing");
        expect(evaluateCompilerArtifactStamp({ ...expected, artifactByteSize: 43 }, expected)).toBe("mismatch");
        expect(evaluateCompilerArtifactStamp({ ...expected, artifactSha256: "bb".repeat(32) }, expected)).toBe("mismatch");
    });

    it("strictly reads and atomically replaces complete stamps", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const stampPath = `${dir}/.genesis_contracts.compiler-artifact.json`;
            await Bun.write(stampPath, JSON.stringify({ compilerRevision: "rev", compilerSourcesHash: "sources" }));
            expect(await readGenesisContractsArtifactStamp(stampPath)).toBeNull();
            await writeCompilerArtifactStamp(stampPath, expected);
            expect(await readGenesisContractsArtifactStamp(stampPath)).toEqual(expected);
            expect(await Bun.file(`${stampPath}.tmp`).exists()).toBe(false);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});

describe("planPsyDappNestedSubmodulesFromDisk", () => {
    it("plans a fully present psy-dapp checkout as ready without git or network", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.write(`${dir}/psy-genesis/.git`, "gitdir: gitlink");
            await Bun.write(`${dir}/psy-genesis/config.json`, "{}");
            await Bun.write(`${dir}/psy-contracts/.git`, "gitdir: gitlink");
            await Bun.write(`${dir}/psy-contracts/protocol-config/index.ts`, "export {}");
            await Bun.write(`${dir}/psy-contracts/deployments/index.ts`, "export {}");
            const plan = await planPsyDappNestedSubmodulesFromDisk(dir);
            expect(plan.ready).toBe(true);
            expect(plan.pending).toEqual([]);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("flags a fresh clone with missing git metadata and payloads as pending", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.write(`${dir}/psy-genesis/.git`, "gitdir: gitlink");
            await Bun.write(`${dir}/psy-genesis/config.json`, "{}");
            // psy-contracts is an empty gitlink directory: no .git, no payloads.
            await Bun.$`mkdir -p ${dir}/psy-contracts`.quiet();
            const plan = await planPsyDappNestedSubmodulesFromDisk(dir);
            expect(plan.ready).toBe(false);
            expect(plan.pending).toEqual(["psy-contracts"]);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("flags a checked-out gitlink missing payload files", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.write(`${dir}/psy-genesis/.git`, "gitdir: gitlink");
            // config.json absent -> payload missing.
            await Bun.write(`${dir}/psy-contracts/.git`, "gitdir: gitlink");
            await Bun.write(`${dir}/psy-contracts/protocol-config/index.ts`, "export {}");
            await Bun.write(`${dir}/psy-contracts/deployments/index.ts`, "export {}");
            const plan = await planPsyDappNestedSubmodulesFromDisk(dir);
            expect(plan.ready).toBe(false);
            expect(plan.pending).toEqual(["psy-genesis"]);
            expect(plan.missingPayloads["psy-genesis"]).toEqual(["config.json"]);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});