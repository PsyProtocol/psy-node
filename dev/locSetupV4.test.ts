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
    injectGenesisValidators,
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
    realmP2pHttpPort,
    realmP2pEdgePort,
    realmP2pSecretPaths,
    realmP2pEdgeExtraArgs,
    realmP2pProcessorExtraArgs,
    realmValidatorUserId,
    reservedValidatorRegistrationId,
    reservedValidatorUserId,
    strategy5UserIdFromRegistrationId,
    LOCAL_DEVNET_RELAYER_REGISTRATION_ID,
    LOCAL_DEVNET_RELAYER_USER_ID,
    planRealmP2pConfig,
    daemonRealmP2pConfig,
    realmP2pProcessorPort,
    requestedRealmPorts,
    shouldPrepareRealmP2p,
    validateRealmP2pPorts,
    selectedRuntimeConfigKey,
    REALM_P2P_SUB_IDS,
} from "./locSetupV4";
import allConfig from "../psy-genesis/config.json";
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
            processTemplate("realm_0_sub_1_edge_0", ["psy_node_cli", "start-realm-edge"]),
            processTemplate("realm_0_sub_1_processor", ["psy_node_cli", "start-realm-processor"]),
            processTemplate("coordinator_edge_0", ["psy_node_cli", "start-coordinator-edge"]),
            processTemplate("coordinator_processor", ["psy_node_cli", "start-coordinator-processor"]),
        ];

        expect(applicationStartOrder(processes)).toEqual([
            "coordinator_processor",
            "coordinator_edge_0",
            "realm_0_sub_1_processor",
            "realm_0_sub_1_edge_0",
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
            processTemplate("realm_0_sub_1_edge_0", ["psy_node_cli", "start-realm-edge", "--port", "13380"]),
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
        tokenArtifactSha256: "bb".repeat(32),
        tokenArtifactByteSize: 43,
        tokenUpdateArtifactSha256: "cc".repeat(32),
        tokenUpdateArtifactByteSize: 44,
    };

    it("matches only the exact compiler identity and artifact bytes", () => {
        expect(evaluateCompilerArtifactStamp({ ...expected }, expected)).toBe("match");
        expect(evaluateCompilerArtifactStamp(null, expected)).toBe("missing");
        expect(evaluateCompilerArtifactStamp({ ...expected, artifactByteSize: 43 }, expected)).toBe("mismatch");
        expect(evaluateCompilerArtifactStamp({ ...expected, artifactSha256: "bb".repeat(32) }, expected)).toBe("mismatch");
        expect(evaluateCompilerArtifactStamp({ ...expected, tokenArtifactSha256: "dd".repeat(32) }, expected)).toBe("mismatch");
        expect(evaluateCompilerArtifactStamp({ ...expected, tokenUpdateArtifactByteSize: 45 }, expected)).toBe("mismatch");
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

describe("realm P2P HTTP ports", () => {
    it("uses subs 1 and 2 only", () => {
        expect([...REALM_P2P_SUB_IDS]).toEqual([1, 2]);
    });

    it("matches psy-genesis localhost realm RPC URLs at default edge count", () => {
        const localhost = allConfig.networks.localhost;
        const realmEdgeCount = 1;
        for (const realm of localhost.realm_configs) {
            const expected = REALM_P2P_SUB_IDS.map((subId) =>
                `http://127.0.0.1:${realmP2pHttpPort(realm.id, subId, 0, realmEdgeCount)}`,
            );
            expect(realm.rpc_url).toEqual(expected);
        }
    });

    it("keeps large multi-edge Realm HTTP ranges disjoint", () => {
        const realmZeroLast = realmP2pHttpPort(0, 2, 5, 6);
        const realmOneFirst = realmP2pHttpPort(1, 1, 0, 6);
        expect(realmZeroLast).toBeLessThan(realmOneFirst);
    });
    it("rejects topologies whose HTTP or P2P ports exceed u16", () => {
        expect(() => validateRealmP2pPorts(0, 1, 1)).not.toThrow();
        expect(() => validateRealmP2pPorts(127, 1, 255)).toThrow("TCP port 65535");
    });

    it("accepts the normal Realm 0..1 topology", () => {
        expect(() => validateRealmP2pPorts(0, 2, 1)).not.toThrow();
    });

    it("rejects the Realm 0..5 processor-to-edge collision", () => {
        expect(() => validateRealmP2pPorts(0, 6, 1)).toThrow("TCP port 41101");
    });

    it("detects duplicates across processor, edge, and HTTP families", () => {
        const ports = requestedRealmPorts(0, 2, 3);
        expect(new Set(ports.map(({ port }) => port)).size).toBe(ports.length);
        expect(ports.some(({ family }) => family === "processor P2P")).toBe(true);
        expect(ports.some(({ family }) => family === "edge P2P")).toBe(true);
        expect(ports.some(({ family }) => family === "Realm HTTP")).toBe(true);
        expect(realmP2pProcessorPort(5, 1)).toBe(realmP2pEdgePort(0, 1, 0, 1));
    });
});

describe("Realm P2P component selection", () => {
    it("plans no P2P config or Genesis mutation for DB/UI-only modes", () => {
        expect(shouldPrepareRealmP2p(false, false)).toBe(false);
    });

    it("plans P2P mutation whenever Coordinator or Realm core starts", () => {
        expect(shouldPrepareRealmP2p(true, false)).toBe(true);
        expect(shouldPrepareRealmP2p(false, true)).toBe(true);
    });
});

describe("realm P2P launch planning", () => {
    const validator = (userId: number, subId: number, edges: number) => ({
        validator_user_id: userId,
        processor_node_id: `processor-${subId}`,
        bls_public_key: `bls-${subId}`,
        processor_addresses: [`/ip4/192.0.2.8/tcp/${41000 + subId}/p2p/processor-peer-${subId}`],
        edge_nodes: Array.from({ length: edges }, (_, edgeIndex) => ({
            node_id: `edge-${subId}-${edgeIndex}`,
            addresses: [`/ip4/192.0.2.8/tcp/${realmP2pEdgePort(0, subId, edgeIndex, edges)}/p2p/edge-peer-${subId}-${edgeIndex}`],
        })),
    });
    const realm0ValidatorIds = [reservedValidatorUserId(0, 1), reservedValidatorUserId(0, 2)];
    const config = (edges: number) => ({
        defaultNetwork: "localhost",
        networks: {
            localhost: {
                realm_user_tree_height: 20,
                p2p: { checkpoints_per_epoch: 10 },
                realm_configs: [{
                    id: 0,
                    rpc_url: [],
                    validators: [
                        validator(realm0ValidatorIds[0], 1, edges),
                        validator(realm0ValidatorIds[1], 2, edges),
                    ],
                }],
            },
        },
    });

    it("reuses only a complete config for the selected host and edge count", () => {
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.8", realm0ValidatorIds).reuse).toBe(true);
        expect(planRealmP2pConfig(config(1), [0], 2, "192.0.2.8", realm0ValidatorIds).reuse).toBe(false);
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.9", realm0ValidatorIds).reuse).toBe(false);
    });

    it("regenerates when an unselected Realm still has validators", () => {
        const stale = config(1);
        stale.networks.localhost.realm_configs.push({
            id: 1,
            rpc_url: [],
            validators: [
                validator(reservedValidatorUserId(1, 1), 1, 1),
                validator(reservedValidatorUserId(1, 2), 2, 1),
            ],
        });
        expect(planRealmP2pConfig(stale, [0], 1, "192.0.2.8", realm0ValidatorIds).reuse).toBe(false);
        stale.networks.localhost.realm_configs[1].validators = [];
        expect(planRealmP2pConfig(stale, [0], 1, "192.0.2.8", realm0ValidatorIds).reuse).toBe(true);
    });

    it("pins generator network selection and edge count", () => {
        const placeholderIds = [3 * (1 << 20), 3 * (1 << 20) + 1, 4 * (1 << 20), 4 * (1 << 20) + 1];
        const plan = planRealmP2pConfig(null, [3, 4], 3, "devnet.example", placeholderIds);
        expect(plan.env).toEqual({ PSY_CONFIG_PATH: "psy-genesis/config.json", PSY_NETWORK: "localhost", PSY_REALM_P2P_PUBLIC_HOST: "devnet.example" });
        expect(plan.args).toContain("--edges-per-validator");
        expect(plan.args.at(-1)).toBe("3");
        expect(selectedRuntimeConfigKey("local-devnet")).toBe("localhost");
        expect(realmP2pSecretPaths([0], 2)).toEqual([
            "./local_checkpoints/realm_p2p/realm_0_sub_1_processor_identity.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_1_bls.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_1_zk.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_1_edge_identity.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_1_edge_1_identity.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_2_processor_identity.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_2_bls.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_2_zk.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_2_edge_identity.key",
            "./local_checkpoints/realm_p2p/realm_0_sub_2_edge_1_identity.key",
        ]);
    });

    it("assigns every foreground edge a distinct key and P2P listen port", () => {
        const launches = [0, 1, 2].map((edgeIndex) => realmP2pEdgeExtraArgs("192.0.2.8", 2, 1, edgeIndex, 3));
        expect(new Set(launches.map((args) => args[1])).size).toBe(3);
        expect(new Set(launches.map((args) => args[3])).size).toBe(3);
        expect(launches[0][1]).toEndWith("edge_identity.key");
        expect(realmP2pProcessorExtraArgs("devnet.example", 2, 1)[7]).toBe("/dns4/devnet.example/tcp/41041");
    });

    it("rewrites daemon public addresses to Compose DNS while listeners stay wildcard", () => {
        const daemon = daemonRealmP2pConfig(config(2), [0], 2);
        const first = daemon.networks.localhost.realm_configs[0].validators[0];
        expect(first.processor_addresses[0]).toBe("/dns4/realm-0-sub-1-processor/tcp/41001/p2p/processor-peer-1");
        expect(first.edge_nodes[1].addresses[0]).toBe("/dns4/realm-0-sub-1-edge-1/tcp/41102/p2p/edge-peer-1-1");
        expect(realmP2pProcessorExtraArgs("0.0.0.0", 0, 1)[7]).toBe("/ip4/0.0.0.0/tcp/41001");
        expect(realmP2pEdgeExtraArgs("0.0.0.0", 0, 1, 1, 2)[3]).toBe("/ip4/0.0.0.0/tcp/41102");
    });

    it("keeps validator ids inside the selected Realm user range", () => {
        const height = 17;
        const userId = realmValidatorUserId(9, 2, height);
        expect(userId).toBe(9 * (2 ** height) + 1);
        expect(userId).toBeGreaterThanOrEqual(9 * (2 ** height));
        expect(userId).toBeLessThan(10 * (2 ** height));
    });

    it("uses reserved Strategy5 registrations for local-devnet validators", () => {
        expect(reservedValidatorRegistrationId(0, 1)).toBe(0);
        expect(reservedValidatorRegistrationId(1, 1)).toBe(1);
        expect(reservedValidatorRegistrationId(0, 2)).toBe(4);
        expect(reservedValidatorRegistrationId(1, 2)).toBe(3);
        expect(reservedValidatorUserId(0, 1)).toBe(0);
        expect(reservedValidatorUserId(1, 1)).toBe(1 << 20);
        expect(reservedValidatorUserId(0, 2)).toBe(1 << 18);
        expect(reservedValidatorUserId(1, 2)).toBe((1 << 20) + (1 << 19));
        expect(LOCAL_DEVNET_RELAYER_REGISTRATION_ID).toBe(2);
        expect(strategy5UserIdFromRegistrationId(LOCAL_DEVNET_RELAYER_REGISTRATION_ID)).toBe(LOCAL_DEVNET_RELAYER_USER_ID);
        expect(() => reservedValidatorRegistrationId(2, 1)).toThrow(/realms 0\.\.1/);
    });
});

describe("injectGenesisValidators", () => {
    it("writes ordered network validators without storing sub ids", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const genesisPath = `${dir}/genesis.json`;
            await Bun.write(genesisPath, JSON.stringify({ checkpoint_stats: { block_time: 1764248609 } }));
            const validator = (validator_user_id: number, processor_node_id: string, bls_public_key: string) => ({
                validator_user_id,
                processor_node_id,
                bls_public_key,
                processor_addresses: [],
                edge_nodes: [],
            });
            await injectGenesisValidators(genesisPath, {
                defaultNetwork: "localhost",
                networks: {
                    localhost: {
                        p2p: { checkpoints_per_epoch: 10 },
                        realm_configs: [
                            { id: 0, rpc_url: [], validators: [validator(1, "aa".repeat(38), "11".repeat(48)), validator(2, "bb".repeat(38), "22".repeat(48))] },
                            { id: 1, rpc_url: [], validators: [validator((1 << 20) + 1, "cc".repeat(38), "33".repeat(48))] },
                        ],
                    },
                },
            });
            const written = JSON.parse(await Bun.file(genesisPath).text());
            expect(written.checkpoint_stats).toEqual({ block_time: 1764248609 });
            expect(written.validators).toEqual([
                { realm_id: 0, validator_user_id: 1, node_id: "aa".repeat(38), bls_public_key: "11".repeat(48) },
                { realm_id: 0, validator_user_id: 2, node_id: "bb".repeat(38), bls_public_key: "22".repeat(48) },
                { realm_id: 1, validator_user_id: (1 << 20) + 1, node_id: "cc".repeat(38), bls_public_key: "33".repeat(48) },
            ]);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});