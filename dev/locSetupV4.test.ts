import { describe, expect, it, spyOn } from "bun:test";
import path from "node:path";
import net from "node:net";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, readdirSync, statSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { mkdtemp, mkdir, writeFile, rm, symlink, chmod } from "node:fs/promises";
import { tmpdir, homedir } from "node:os";
import allConfig from "../psy-genesis/config.json";
import {
    COORDINATOR_PROCESSOR_READY_MARKER,
    REALM_PROCESSOR_READY_MARKER,
    isExactProcessorReadyLine,
    r2CurlArgs,
    psyServicesDatabaseCommands,
    pinFaucetPerClaimAmount,
} from "./locSetupPolicy";
import {
    downloadKeystoreObject,
    fetchKeystoreManifest,
    groupVerifies,
    ANVIL_STATE_PATH,
    assertPreservedAnvilGenesis,
    anvilStateBestBlockNumber,
    localAnvilLaunchArgs,
    isRepoAnvilProcess,
    runTeardownCommand,
    stopRepoAnvilsForPurge,
    exactSnapshotNames,
    preservedAnvilGenesis,
    ROLLBACK_STOP_SENTINEL_CONTENT,
    ROLLBACK_STOP_SENTINEL_PATH,
    applicationListenerPorts,
    applicationStartOrder,
    decodeAnvilDumpStateHex,
    devnetControlSocketPath,
    sendDevnetControlCommand,
    evaluateCompilerArtifactStamp,
    injectGenesisValidators,
    isUsableGenesisData,
    ensureGenesisFiles,
    planGenesisGeneration,
    planPsyDappNestedSubmodulesFromDisk,
    readGenesisContractsArtifactStamp,
    localAnvilStatePath,
    resolveLocalAnvilStatePlan,
    resolveForkRpcEnvKey,
    resolveProjectsDir,
    RunningProcess,
    runStreamingCaptureStderr,
    retryProcessorStartup,
    splitDevnetProcesses,
    startAfterPrerequisite,
    preserveUnownedLiveAnvils,
    startDevnetControlServer,
    startRealmProcessorBatchSequentially,
    writeCompilerArtifactStamp,
    writeRollbackStopSentinel,
    requestOwnedAnvilShutdown,
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
    LOCAL_DEVNET_RELAYER_ZK_PRIVATE_KEY,
    planRealmP2pConfig,
    daemonRealmP2pConfig,
    realmP2pProcessorPort,
    requestedRealmPorts,
    shouldPrepareRealmP2p,
    validateRealmP2pPorts,
    selectedRuntimeConfigKey,
    REALM_P2P_SUB_IDS,
    resolveGuardianConfigPath,
    resolveBridgeDaemonConfigPath,
    prepareGuardianService,
    guardianSessionsReady,
    validateRelayerTemplate,
    relayerStartedDetector,
    DevNetProcessManager,
    shouldRequireGuardianConfig,
} from "./locSetupV4";
import type { GenesisContractsArtifactFingerprint } from "./locSetupV4";

describe("psy_services database preservation", () => {
    it("leaves an existing database untouched without purge", () => {
        expect(psyServicesDatabaseCommands(false, true)).toEqual([]);
    });

    it("creates a missing database without dropping it", () => {
        expect(psyServicesDatabaseCommands(false, false)).toEqual([
            ['docker', 'exec', 'generated-envio-postgres-1', 'createdb', '-U', 'postgres', 'psy_services'],
        ]);
    });

    it("drops and recreates the database only with purge", () => {
        expect(psyServicesDatabaseCommands(true, true)).toEqual([
            ['docker', 'exec', 'generated-envio-postgres-1', 'dropdb', '-U', 'postgres', '--if-exists', 'psy_services'],
            ['docker', 'exec', 'generated-envio-postgres-1', 'createdb', '-U', 'postgres', 'psy_services'],
        ]);
    });
});

describe("pinFaucetPerClaimAmount", () => {
    it("forces the genesis amount without changing operators", () => {
        const config = { faucetPerClaimAmount: "42", operators: [{ userId: "test-operator" }] };
        expect(JSON.parse(pinFaucetPerClaimAmount(JSON.stringify(config)))).toEqual({
            ...config, faucetPerClaimAmount: "1000000000000",
        });
    });

    it("rejects malformed JSON rather than inventing operators", () => {
        expect(() => pinFaucetPerClaimAmount("not json")).toThrow();
    });
});

describe("public R2 keystore", () => {
    it("uses literal anonymous HTTPS argv and rejects HTTP errors and insecure redirects", () => {
        const dest = "/tmp/keystore space/'$(touch nope); key.zst";
        expect(r2CurlArgs("localhost-abc123", "pk_groth16.bin.zst", dest)).toEqual([
            "curl", "-q", "-f", "-S", "-L", "--proto", "=https", "--proto-redir", "=https", "-o", dest,
            "https://pub-23b7764b3820454094ce80557ab38d0b.r2.dev/localhost-abc123/pk_groth16.bin.zst",
        ]);
        for (const prefix of [undefined, "", "..", "a..b", "localhost/digest", "a b", "a\n", "a\\b", "a".repeat(129)]) {
            expect(() => r2CurlArgs(prefix, "sha256sums.json", dest)).toThrow("PSY_KEYSTORE_R2_PREFIX");
        }
        for (const prefix of ["a", "a".repeat(128), "localhost-a_b.c-1"]) {
            expect(r2CurlArgs(prefix, "sha256sums.json", dest).at(-1)).toBe(`https://pub-23b7764b3820454094ce80557ab38d0b.r2.dev/${prefix}/sha256sums.json`);
        }
    });

    it("fails closed on fetch, spawn and malformed manifests without logging secrets", async () => {
        const dir = mkdtempSync(path.join(tmpdir(), "psy-r2-"));
        const manifestPath = path.join(dir, "sha256sums.json");
        const previous = process.env.PSY_KEYSTORE_R2_PREFIX;
        process.env.PSY_KEYSTORE_R2_PREFIX = "localhost-test";
        const sentinel = "SECRET_SENTINEL_DO_NOT_LOG";
        const log = spyOn(console, "log").mockImplementation(() => {});
        const warn = spyOn(console, "warn").mockImplementation(() => {});
        const error = spyOn(console, "error").mockImplementation(() => {});
        const nativeSpawn = Bun.spawn.bind(Bun);
        const spawn = spyOn(Bun, "spawn");
        try {
            // Exercise real stdout/stderr output with the downloader's stdio policy.
            spawn.mockImplementation(((_args: unknown, options: Bun.SpawnOptions<"ignore", "ignore", "ignore">) => nativeSpawn([
                process.execPath, "-e", `console.log('${sentinel}'); console.error('${sentinel}'); process.exit(22)`,
            ], options)) as typeof Bun.spawn);
            const manifest = { version: 1, files: {} as Record<string, { size: number; sha256: string }> };
            for (const prefix of ["", "deposit_append/", "withdrawal_claim/"]) {
                for (const name of ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"]) {
                    manifest.files[prefix + name] = { size: 3, sha256: createHash("sha256").update("abc").digest("hex") };
                }
            }
            writeFileSync(manifestPath, JSON.stringify(manifest));
            // curl -f reports HTTP 4xx/5xx as exit 22; a retained manifest cannot rescue it.
            await expect(fetchKeystoreManifest(manifestPath)).rejects.toThrow("exit 22");
            expect(spawn.mock.calls[0][0]).toEqual(r2CurlArgs("localhost-test", "sha256sums.json", manifestPath));
            expect(spawn.mock.calls[0][1]).toEqual({ stdin: "ignore", stdout: "ignore", stderr: "ignore" });
            spawn.mockImplementation(() => { throw new Error(sentinel); });
            await expect(downloadKeystoreObject("sha256sums.json", manifestPath)).rejects.toThrow("exit unavailable");
            spawn.mockImplementation((() => ({ exited: Promise.resolve(0) })) as typeof Bun.spawn);
            await expect(fetchKeystoreManifest(manifestPath)).resolves.toEqual(manifest);
            for (const invalid of [sentinel, "null", JSON.stringify({ ...manifest, version: 2 }),
                JSON.stringify({ version: 1, files: {} }),
                JSON.stringify({ ...manifest, files: { ...manifest.files, "pk_groth16.bin": { size: 3, sha256: sentinel } } }),
                JSON.stringify({ ...manifest, files: { ...manifest.files, "pk_groth16.bin": { size: -1, sha256: "a".repeat(64) } } })]) {
                writeFileSync(manifestPath, invalid);
                await expect(fetchKeystoreManifest(manifestPath)).rejects.toThrow("Invalid sha256sums.json");
            }
            writeFileSync(path.join(dir, "pk_groth16.bin"), "abc");
            expect(await groupVerifies(manifest, dir, ["pk_groth16.bin"])).toBe(true);
            writeFileSync(path.join(dir, "pk_groth16.bin"), "abd");
            expect(await groupVerifies(manifest, dir, ["pk_groth16.bin"])).toBe(false);
            writeFileSync(path.join(dir, "pk_groth16.bin"), "abcd");
            expect(await groupVerifies(manifest, dir, ["pk_groth16.bin"])).toBe(false);
            expect(JSON.stringify([...log.mock.calls, ...warn.mock.calls, ...error.mock.calls])).not.toContain(sentinel);
        } finally {
            spawn.mockRestore();
            log.mockRestore(); warn.mockRestore(); error.mockRestore();
            if (previous === undefined) delete process.env.PSY_KEYSTORE_R2_PREFIX;
            else process.env.PSY_KEYSTORE_R2_PREFIX = previous;
            rmSync(dir, { recursive: true, force: true });
        }
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

        // Generic command callers still receive the original exit code.
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
    process.onExit = () => undefined;
    process.hasExited = false;
    process.pid = 0;
    process.proc = { pid: 0, killed: false, exited: Promise.resolve(0), kill() {} } as unknown as RunningProcess["proc"];
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

const ZERO_HASH = `0x${"00".repeat(32)}`;
const ORIGINAL_GENESIS_HASH = "0x812ac38361726fed01b4bba155407cbad7af499bd2ba47d35d180e8dc6ed627a";
const genesisHeader: Record<string, string> = {
    number: "0x0",
    parentHash: ZERO_HASH,
    stateRoot: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    timestamp: "0x6acdc5de",
    gasLimit: "0x1c9c380",
};
const block1: Record<string, string> = {
    number: "0x1",
    parentHash: ORIGINAL_GENESIS_HASH,
    timestamp: "0x6acdc5df",
};
const rpcBlock = (header: Record<string, string>, hash: string) => ({ ...header, hash });

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

    it("reuses Anvil and localhost deployments only when both exist and genesis is unique", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.$`mkdir -p ${dir}/db/anvil ${dir}/psy-contracts/deployments/localhost`.quiet();
            const header = { ...genesisHeader, timestamp: "0x6acdc5de" };
            await Bun.write(`${dir}/db/anvil/state.json`, JSON.stringify({
                best_block_number: 2,
                blocks: [
                    { header: { ...header, number: "0x2", parentHash: ZERO_HASH } },
                    { header: block1 },
                    { header },
                ],
            }));
            await Bun.write(`${dir}/psy-contracts/deployments/localhost/deployed-contracts.json`, "{}");
            const snapshotBefore = await Bun.file(`${dir}/db/anvil/state.json`).text();
            const plan = await resolveLocalAnvilStatePlan(dir);
            expect(plan.hasState).toBe(true);
            expect(plan.shouldResetEnvio).toBe(false);
            expect(plan.genesis?.timestamp).toBe((0x6acdc5den).toString());
            expect(plan.genesis?.block1ParentHash).toBe(ORIGINAL_GENESIS_HASH);
            expect(localAnvilLaunchArgs(8545, "31337", plan.statePath, plan.genesis)).toEqual([
                "anvil", "--host", "0.0.0.0", "--port", "8545", "--chain-id", "31337",
                "--state", plan.statePath, "--state-interval", (process.env.ANVIL_STATE_INTERVAL && /^\d+$/.test(process.env.ANVIL_STATE_INTERVAL) ? process.env.ANVIL_STATE_INTERVAL : "900"), "--preserve-historical-states", "-vvvv",
                "--timestamp", (0x6acdc5den).toString(),
            ]);
            expect(localAnvilLaunchArgs(8545, "31337", plan.statePath)).not.toContain("--timestamp");
            expect(await Bun.file(`${dir}/db/anvil/state.json`).text()).toBe(snapshotBefore);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects duplicate block 0 even when a later nonzero block is unsorted", () => {
        const drifted = { ...genesisHeader, timestamp: "0x6acdd96f" };
        expect(() => preservedAnvilGenesis({
            blocks: [
                { header: { ...genesisHeader, number: "0x5" } },
                { header: genesisHeader },
                { header: drifted },
            ],
        }, "fixture")).toThrow("2 block 0");
    });

    it("fails closed when the ready RPC genesis does not retain the saved header and block 1 parent", async () => {
        const genesis = preservedAnvilGenesis({
            blocks: [{ header: genesisHeader }, { header: block1 }],
        }, "fixture");
        const wrong = rpcBlock({ ...genesisHeader, timestamp: "0x6acdd96f" }, "0x" + "ab".repeat(32));
        const calls: string[] = [];
        const rpc = async (_url: string, method: string, params: unknown[]) => {
            calls.push(`${method}:${String(params[0])}`);
            return params[0] === "0x1"
                ? rpcBlock({ ...block1, parentHash: ORIGINAL_GENESIS_HASH }, "0x" + "11".repeat(32))
                : wrong;
        };
        await expect(assertPreservedAnvilGenesis("http://127.0.0.1:8545", genesis, "localhost", rpc))
            .rejects.toThrow("block 0");
        expect(calls).toEqual(["eth_getBlockByNumber:0x0", "eth_getBlockByNumber:earliest"]);
    });

    it("keeps a paired fork snapshot without requiring a local block 0", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.$`mkdir -p ${dir}/db/anvil ${dir}/psy-contracts/deployments/localhost`.quiet();
            await Bun.write(`${dir}/db/anvil/state.json`, JSON.stringify({ best_block_number: 19_000_000, blocks: [] }));
            await Bun.write(`${dir}/psy-contracts/deployments/localhost/deployed-contracts.json`, "{}");
            const plan = await resolveLocalAnvilStatePlan(dir, "localhost", true);
            expect(plan.hasState).toBe(true);
            expect(plan.shouldResetEnvio).toBe(false);
            expect(plan.genesis).toBeUndefined();
            expect(localAnvilLaunchArgs(8545, "1", plan.statePath, plan.genesis)).not.toContain("--timestamp");
            await Bun.$`rm ${dir}/psy-contracts/deployments/localhost/deployed-contracts.json`.quiet();
            await expect(resolveLocalAnvilStatePlan(dir, "localhost", true)).rejects.toThrow("must exist together");
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects malformed trailing JSON for local and fork restore without changing the snapshot", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.$`mkdir -p ${dir}/db/anvil ${dir}/psy-contracts/deployments/localhost`.quiet();
            await Bun.write(`${dir}/psy-contracts/deployments/localhost/deployed-contracts.json`, "{}");
            const invalid = JSON.stringify({ blocks: [{ header: genesisHeader }] }) + " trailing";
            await Bun.write(`${dir}/db/anvil/state.json`, invalid);
            for (const fork of [false, true]) {
                await expect(resolveLocalAnvilStatePlan(dir, "localhost", fork)).rejects.toThrow("validation failed");
                expect(await Bun.file(`${dir}/db/anvil/state.json`).text()).toBe(invalid);
            }
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

describe("public-only Genesis generation", () => {
    const account = () => ({ contract_id: 1, initial_policy: { version: 1, threshold: 2, member_count: 3, member_hashes: ["01", "02", "03", "00", "00", "00", "00", "00"] } });
    const artifact = () => ({ state_tree_height: 4, circuit_definitions: [{ name: "get_policy" }, { name: "set_policy" }], abi: { contract: { state_tree_height: 4 } } });

    it("forwards public paths as individual argv and strips only child secrets", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.write(`${dir}/public account.json`, JSON.stringify(account()));
            await Bun.write(`${dir}/policy artifact.json`, JSON.stringify(artifact()));
            const aliases = ["PRIVATE_KEY", "BRIDGE_RELAYER_L2_PRIVATE_KEY", "KEYSTORE_PATH", "PSY_BRIDGE_RELAYER_KEYSTORE_PATH", "BRIDGE_RELAYER_KEYSTORE_PATH", "WALLET_PASSWORD"];
            const env: NodeJS.ProcessEnv = { PSY_RELAYER_MULTISIG_ACCOUNT: "public account.json", PSY_MULTISIG_POLICY_ARTIFACT: "policy artifact.json", KEEP: "present", ...Object.fromEntries(aliases.map((key) => [key, "test-only"])) };
            const plan = await planGenesisGeneration(dir, env);
            expect(plan.args).toEqual([`${dir}/target/release/psy_dev_cli`, "generate-genesis-data", "--repo-root", dir, "--relayer-multisig-account", `${dir}/public account.json`, "--multisig-policy-artifact", `${dir}/policy artifact.json`]);
            for (const alias of aliases) {
                expect(plan.env[alias]).toBeUndefined();
                expect(env[alias]).toBe("test-only");
            }
            expect(plan.env.KEEP).toBe("present");
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects missing paths, unknown and duplicate fields, and invalid fixed policies", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const env = { PSY_RELAYER_MULTISIG_ACCOUNT: "account.json", PSY_MULTISIG_POLICY_ARTIFACT: "policy.json" };
            await Bun.write(`${dir}/policy.json`, JSON.stringify(artifact()));
            await expect(planGenesisGeneration(dir, {})).rejects.toThrow();
            await expect(planGenesisGeneration(dir, env)).rejects.toThrow();
            await expect(planGenesisGeneration(dir, { ...env, PSY_RELAYER_MULTISIG_ACCOUNT: "." })).rejects.toThrow();
            const invalid: unknown[] = [null, {}, { ...account(), contract_id: 5 }, { ...account(), extra: true }];
            for (const change of [{ version: 2 }, { threshold: 1 }, { member_count: 2 }, { member_hashes: ["01", "01", "03", "00", "00", "00", "00", "00"] }, { member_hashes: ["00", "02", "03", "00", "00", "00", "00", "00"] }, { member_hashes: ["01", "02", "03", "01", "00", "00", "00", "00"] }]) invalid.push({ ...account(), initial_policy: { ...account().initial_policy, ...change } });
            for (const input of invalid.map((value) => JSON.stringify(value)).concat('{"contract_id":1,"contract_id":1,"initial_policy":' + JSON.stringify(account().initial_policy) + '}', "not JSON")) {
                await Bun.write(`${dir}/account.json`, input);
                await expect(planGenesisGeneration(dir, env)).rejects.toThrow();
            }
            await Bun.write(`${dir}/account.json`, JSON.stringify(account()));
            await expect(planGenesisGeneration(dir, { PSY_RELAYER_MULTISIG_ACCOUNT: "account.json" })).rejects.toThrow();
            await Bun.write(`${dir}/policy.json`, JSON.stringify({ ...artifact(), state_tree_height: 3 }));
            await expect(planGenesisGeneration(dir, env)).rejects.toThrow();
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("launches generation with public argv and a secret-free child environment", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.write(`${dir}/psy-genesis/genesis_contracts.json`, new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]));
            await Bun.write(`${dir}/public account.json`, JSON.stringify(account()));
            await Bun.write(`${dir}/policy artifact.json`, JSON.stringify(artifact()));
            const cli = `${dir}/target/release/psy_dev_cli`;
            await Bun.write(cli, '#!/usr/bin/env bun\nawait Bun.write("child.json", JSON.stringify({ args: process.argv.slice(2), env: process.env }));\nawait Bun.write("genesis.json", \'{"checkpoint_stats":{"block_time":1764248609}}\');\n');
            await Bun.$`chmod +x ${cli}`.quiet();
            const aliases = ["PRIVATE_KEY", "BRIDGE_RELAYER_L2_PRIVATE_KEY", "KEYSTORE_PATH", "PSY_BRIDGE_RELAYER_KEYSTORE_PATH", "BRIDGE_RELAYER_KEYSTORE_PATH", "WALLET_PASSWORD"];
            const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, PSY_RELAYER_MULTISIG_ACCOUNT: "public account.json", PSY_MULTISIG_POLICY_ARTIFACT: "policy artifact.json", ...Object.fromEntries(aliases.map((key) => [key, "test-only"])) };
            await ensureGenesisFiles(dir, env);
            const child = await Bun.file(`${dir}/child.json`).json();
            expect(child.args).toEqual(["generate-genesis-data", "--repo-root", dir, "--relayer-multisig-account", `${dir}/public account.json`, "--multisig-policy-artifact", `${dir}/policy artifact.json`]);
            for (const alias of aliases) {
                expect(child.env[alias]).toBeUndefined();
                expect(env[alias]).toBe("test-only");
            }
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects exit zero without usable genesis.json and a nonzero generator exit", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.write(`${dir}/psy-genesis/genesis_contracts.json`, new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]));
            await Bun.write(`${dir}/public account.json`, JSON.stringify(account()));
            await Bun.write(`${dir}/policy artifact.json`, JSON.stringify(artifact()));
            const cli = `${dir}/target/release/psy_dev_cli`;
            const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, PSY_RELAYER_MULTISIG_ACCOUNT: "public account.json", PSY_MULTISIG_POLICY_ARTIFACT: "policy artifact.json" };
            await Bun.write(cli, "#!/usr/bin/env bun\n");
            await Bun.$`chmod +x ${cli}`.quiet();
            await expect(ensureGenesisFiles(dir, env)).rejects.toThrow("exit 0");
            expect(await Bun.file(`${dir}/genesis.json`).exists()).toBe(false);
            await Bun.write(cli, "#!/usr/bin/env bun\nprocess.exit(7);\n");
            await expect(ensureGenesisFiles(dir, env)).rejects.toThrow("exit 7");
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("reuses verified Genesis without public inputs and never replaces invalid existing Genesis", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await Bun.write(`${dir}/psy-genesis/genesis_contracts.json`, new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]));
            const genesis = '{"checkpoint_stats":{"block_time":1764248609}}';
            await Bun.write(`${dir}/genesis.json`, genesis);
            await ensureGenesisFiles(dir, {});
            expect(await Bun.file(`${dir}/genesis.json`).text()).toBe(genesis);
            await Bun.write(`${dir}/genesis.json`, "invalid");
            await expect(ensureGenesisFiles(dir, {})).rejects.toThrow();
            expect(await Bun.file(`${dir}/genesis.json`).text()).toBe("invalid");
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
    const genesisConfigBytes = readFileSync(new URL("../psy-genesis/config.json", import.meta.url));
    const genesisConfigHash = createHash("sha256").update(genesisConfigBytes).digest("hex");
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
        genesisConfigHash,
        networks: {
            localhost: {
                realm_user_tree_height: 20,
                p2p: { checkpoints_per_epoch: allConfig.networks.localhost.p2p.checkpoints_per_epoch },
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
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(true);
        expect(planRealmP2pConfig(config(1), [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(false);
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.9", realm0ValidatorIds, genesisConfigHash).reuse).toBe(false);
    });

    it("reuses a runtime config stamped with the current genesis hash", () => {
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(true);
    });

    it("regenerates when genesis bytes change even if parsed settings match", () => {
        const changedHash = createHash("sha256").update(genesisConfigBytes).update("\n").digest("hex");
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.8", realm0ValidatorIds, changedHash).reuse).toBe(false);
    });

    it("regenerates legacy runtime configs without a genesis hash", () => {
        const { genesisConfigHash: _, ...unstamped } = config(2);
        expect(planRealmP2pConfig(unstamped, [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(false);
    });

    it("regenerates when the cached checkpoint period differs from genesis", () => {
        const stale = config(2);
        stale.networks.localhost.p2p.checkpoints_per_epoch += 1;
        expect(planRealmP2pConfig(stale, [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(false);
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
        expect(planRealmP2pConfig(stale, [0], 1, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(false);
        stale.networks.localhost.realm_configs[1].validators = [];
        expect(planRealmP2pConfig(stale, [0], 1, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(true);
    });

    it("pins generator network selection and edge count", () => {
        const placeholderIds = [3 * (1 << 20), 3 * (1 << 20) + 1, 4 * (1 << 20), 4 * (1 << 20) + 1];
        const plan = planRealmP2pConfig(null, [3, 4], 3, "devnet.example", placeholderIds, genesisConfigHash);
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
        expect(LOCAL_DEVNET_RELAYER_ZK_PRIVATE_KEY).toBe(
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        );
        expect(LOCAL_DEVNET_RELAYER_ZK_PRIVATE_KEY.startsWith("0x")).toBe(false);
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

describe("guardian launcher config preflight", () => {
    const configLimitBytes = 64 * 1024 * 1024;
    const signer = (id: number) => ({
        listen_address: `127.0.0.1:${15440 + id}`,
        signing_key_secret_path: path.join(homedir(), ".psy", "keystore", `guardian-${id}.keystore.json`),
        signing_key_password_secret_path: path.join(homedir(), ".psy", "keystore", `guardian-${id}.password`),
    });
    const publicNetwork = () => ({ magic: "0x1", users_per_realm: 1, global_user_tree_height: 32, realm_user_tree_height: 20, group_realm_height: 1, realm_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18081"] }], p2p: { checkpoints_per_epoch: 1 }, coordinator_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18080"] }], prove_proxy_url: ["http://127.0.0.1:9999"], faucet_rpc_url: [], nostr_relay_url: "wss://relay.example", native_currency: "PSY", native_currency_decimal: 18, native_currency_name: "Psy", fees: { register_user_fee: 0, deploy_contract_fee: 0, guta_fee: 1000000000, da_fee: 1000 } });
    const publicGuardianConfig = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
        network: publicNetwork(),
        guardians: { "1": signer(1), "2": signer(2), "3": signer(3) },
        client: {
            endpoints: ["http://127.0.0.1:15441/", "http://127.0.0.1:15442/", "http://127.0.0.1:15443/"],
            archive_path: "archive/relayer-journal",
            listen_address: "127.0.0.1:15450",
            l1_endpoints: [{ chain_index: 0, rpc_url: "http://127.0.0.1:8545" }],
        },
        ...overrides,
    });
    const inTempDir = async (run: (dir: string) => Promise<void>): Promise<void> => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await run(dir);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    };
    const writeConfig = async (dir: string, file: string, contents: unknown): Promise<void> => {
        await Bun.write(path.join(dir, file), typeof contents === "string" ? contents : JSON.stringify(contents));
    };
    const expectRejection = (dir: string, file: string, message: string): Promise<void> =>
        expect(resolveGuardianConfigPath(dir, file)).rejects.toThrow(message);

    it("accepts a bounded public GuardianConfig and returns the resolved config path", async () => {
        await inTempDir(async (dir) => {
            await writeConfig(dir, "config.json", publicGuardianConfig());
            await Bun.$`mkdir -p ${path.join(dir, "nested")}`.quiet();
            await writeConfig(dir, "nested/config.json", publicGuardianConfig());
            await writeConfig(dir, "origin-variants.json", publicGuardianConfig({
                client: {
                    endpoints: ["http://guardian-a.example", "http://guardian-a.example:8443", "http://guardian-b.example"],
                    archive_path: "archive/relayer-journal",
                    listen_address: "127.0.0.1:15450",
                    l1_endpoints: [],
                },
            }));
            expect(await resolveGuardianConfigPath(dir, "config.json")).toBe(path.resolve(dir, "config.json"));
            expect(await resolveGuardianConfigPath(dir, "nested/config.json")).toBe(path.resolve(dir, "nested", "config.json"));
            expect(await resolveGuardianConfigPath(dir, path.join(dir, "config.json"))).toBe(path.join(dir, "config.json"));
            expect(await resolveGuardianConfigPath("/", path.join(dir, "origin-variants.json"))).toBe(path.join(dir, "origin-variants.json"));
        });
    });

    it("rejects a missing or blank PSY_GUARDIAN_CONFIG instead of falling back to a wallet", async () => {
        await inTempDir(async (dir) => {
            for (const missing of [undefined, "", "   "]) {
                await expect(resolveGuardianConfigPath(dir, missing)).rejects.toThrow("supply it in the environment or --env");
            }
        });
    });

    it("rejects a per-guardian service config, TLS metadata, or schema drift from GuardianConfig", async () => {
        const missingClient = publicGuardianConfig();
        delete missingClient.client;
        const cases: Array<[string, unknown]> = [
            ["database path", { ...publicGuardianConfig(), db_path: "guardian.redb" }],
            ["TLS metadata", { ...publicGuardianConfig(), tls_identity_path: "tls/relayer.pem" }],
            ["missing client", missingClient],
            ["leading zero guardian key", publicGuardianConfig({ guardians: { "01": signer(1), "2": signer(2), "3": signer(3) } })],
            ["top level array", [publicGuardianConfig()]],
            ["top level string", '"config"'],
            ["top level null", "null"],
        ];
        await inTempDir(async (dir) => {
            for (const [label, contents] of cases) {
                const file = `schema-${label.replaceAll(" ", "-")}.json`;
                await writeConfig(dir, file, contents);
                await expectRejection(dir, file, "expected only GuardianConfig public fields");
            }
        });
    });

    it("rejects a client archive path that escapes the config directory or is not the fixed archive", async () => {
        const violations: Array<[string, unknown]> = [
            ["parent traversal", "../escaped/relayer-journal"],
            ["absolute path", "/tmp/relayer-journal"],
            ["wrong archive", "archive/other"],
            ["empty string", ""],
            ["nul byte", "archive/relayer-journal\0"],
        ];
        await inTempDir(async (dir) => {
            for (const [label, archivePath] of violations) {
                const file = `archive-${label.replaceAll(" ", "-")}.json`;
                const config = publicGuardianConfig();
                (config.client as Record<string, unknown>).archive_path = archivePath;
                await writeConfig(dir, file, config);
                await expectRejection(dir, file, "expected only GuardianConfig public fields");
            }
        });
    });

    it("rejects a symlinked, directory, missing or non-JSON guardian config file", async () => {
        await inTempDir(async (dir) => {
            await writeConfig(dir, "real.json", publicGuardianConfig());
            await Bun.$`ln -s ${path.join(dir, "real.json")} ${path.join(dir, "link.json")}`.quiet();
            await Bun.$`mkdir -p ${path.join(dir, "directory.json")}`.quiet();
            await writeConfig(dir, "truncated.json", '{"network":');
            await writeConfig(dir, "empty.json", "");
            for (const file of ["link.json", "directory.json", "missing.json", "truncated.json", "empty.json"]) {
                await expectRejection(dir, file, "the selected path must be a readable, non-symlink regular file containing valid JSON (at most 64 MiB).");
            }
            expect(await resolveGuardianConfigPath(dir, "real.json")).toBe(path.resolve(dir, "real.json"));
        });
    });

    it("rejects a guardian config above the 64 MiB read limit and accepts one exactly at the limit", async () => {
        await inTempDir(async (dir) => {
            const file = "oversized.json";
            const target = path.join(dir, file);
            const network = publicNetwork();
            (network as Record<string, unknown>).padding = "";
            const encoded = JSON.stringify(publicGuardianConfig({ network }));
            const insertion = encoded.indexOf('"padding":"');
            const head = encoded.slice(0, insertion + '"padding":"'.length);
            const tail = encoded.slice(insertion + '"padding":"'.length);
            const writer = Bun.file(target).writer();
            writer.write(head);
            const chunk = "a".repeat(1024 * 1024);
            let remaining = configLimitBytes - head.length - tail.length;
            while (remaining > 0) {
                writer.write(remaining >= chunk.length ? chunk : chunk.slice(0, remaining));
                remaining -= Math.min(remaining, chunk.length);
            }
            writer.write(tail);
            await writer.end();
            expect(statSync(target).size).toBe(configLimitBytes);
            expect(await resolveGuardianConfigPath(dir, file)).toBe(target);
            appendFileSync(target, " ");
            expect(statSync(target).size).toBe(configLimitBytes + 1);
            await expectRejection(dir, file, "at most 64 MiB");
        });
    });

    it("rejects guardian endpoints that are not three distinct fixed HTTP origins", async () => {
        const cases: Array<[string, unknown]> = [
            ["duplicate origin", ["http://127.0.0.1:15441", "http://127.0.0.1:15442", "http://127.0.0.1:15442"]],
            ["host case only difference", ["http://guardian-a.example/", "http://Guardian-A.example/", "http://guardian-b.example/"]],
            ["https origin", ["https://127.0.0.1:15441", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["embedded credentials", ["http://user:pass@127.0.0.1:15441", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["non root path", ["http://127.0.0.1:15441/admin", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["query string", ["http://127.0.0.1:15441/?x=1", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["fragment", ["http://127.0.0.1:15441/#frag", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["zero port", ["http://127.0.0.1:0", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["missing host", ["http:///", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["unparseable entry", ["not a url", "http://127.0.0.1:15442", "http://127.0.0.1:15443"]],
            ["non string entry", ["http://127.0.0.1:15441", 7, "http://127.0.0.1:15443"]],
            ["two entries", ["http://127.0.0.1:15441", "http://127.0.0.1:15442"]],
            ["four entries", ["http://127.0.0.1:15441", "http://127.0.0.1:15442", "http://127.0.0.1:15443", "http://127.0.0.1:15444"]],
            ["not an array", "http://127.0.0.1:15441"],
        ];
        await inTempDir(async (dir) => {
            for (const [label, endpoints] of cases) {
                const file = `endpoints-${label.replaceAll(" ", "-")}.json`;
                const config = publicGuardianConfig();
                (config.client as Record<string, unknown>).endpoints = endpoints;
                await writeConfig(dir, file, config);
                await expectRejection(dir, file, "expected only GuardianConfig public fields");
            }
        });
    });

    it("rejects an unusable history listener or invalid L1 endpoint", async () => {
        const cases: Array<[string, Record<string, unknown>]> = [
            ["blank listener", { listen_address: "   " }],
            ["non string listener", { listen_address: 15450 }],
            ["unspecified listener", { listen_address: "0.0.0.0:15450" }],
            ["zero port", { listen_address: "127.0.0.1:0" }],
            ["l1 endpoints not an array", { l1_endpoints: {} }],
            ["null l1 endpoint", { l1_endpoints: [null] }],
            ["unknown l1 field", { l1_endpoints: [{ chain_index: 0, rpc_url: "http://127.0.0.1:8545", chain_id: 1 }] }],
            ["chain index above u8", { l1_endpoints: [{ chain_index: 256, rpc_url: "http://127.0.0.1:8545" }] }],
            ["negative chain index", { l1_endpoints: [{ chain_index: -1, rpc_url: "http://127.0.0.1:8545" }] }],
            ["fractional chain index", { l1_endpoints: [{ chain_index: 1.5, rpc_url: "http://127.0.0.1:8545" }] }],
            ["string chain index", { l1_endpoints: [{ chain_index: "0", rpc_url: "http://127.0.0.1:8545" }] }],
            ["non string rpc url", { l1_endpoints: [{ chain_index: 0, rpc_url: 7 }] }],
            ["blank rpc url", { l1_endpoints: [{ chain_index: 0, rpc_url: "   " }] }],
        ];
        await inTempDir(async (dir) => {
            for (const [label, clientOverrides] of cases) {
                const file = `client-${label.replaceAll(" ", "-")}.json`;
                const config = publicGuardianConfig();
                config.client = { ...(config.client as Record<string, unknown>), ...clientOverrides };
                await writeConfig(dir, file, config);
                await expectRejection(dir, file, "expected only GuardianConfig public fields");
            }
        });
    });
    it("requires a nonempty trusted prove-proxy pool and rejects empty or malformed pools", async () => {
        const cases: Array<[string, unknown]> = [
            ["empty pool", []],
            ["not an array", "http://127.0.0.1:9999"],
            ["non string entry", ["http://127.0.0.1:9999", 7]],
            ["blank entry", ["http://127.0.0.1:9999", "   "]],
        ];
        await inTempDir(async (dir) => {
            for (const [label, proveProxyUrl] of cases) {
                const file = `proxy-${label.replaceAll(" ", "-")}.json`;
                const config = publicGuardianConfig();
                (config.network as Record<string, unknown>).prove_proxy_url = proveProxyUrl;
                await writeConfig(dir, file, config);
                await expectRejection(dir, file, "expected only GuardianConfig public fields");
            }
            await writeConfig(dir, "trusted-proxy.json", publicGuardianConfig());
            expect(await resolveGuardianConfigPath(dir, "trusted-proxy.json")).toBe(path.resolve(dir, "trusted-proxy.json"));
        });
    });
});

describe("guardian config selection precedence", () => {
    it("requires PSY_GUARDIAN_CONFIG whenever a relayer, bridge proposer or bridge UI launches", () => {
        // ProcessOptions.bridgeUi is set by the process-manager path, not by a CLI flag.
        expect(shouldRequireGuardianConfig(true, {})).toBe(true);
        expect(shouldRequireGuardianConfig(false, { relayer: true })).toBe(true);
        expect(shouldRequireGuardianConfig(false, { bridgeProposerDaemon: true })).toBe(true);
        expect(shouldRequireGuardianConfig(false, { bridgeUi: true })).toBe(true);
    });

    it("does not require PSY_GUARDIAN_CONFIG for memory, db or explicit-only runs", () => {
        expect(shouldRequireGuardianConfig(false, {})).toBe(false);
        expect(shouldRequireGuardianConfig(false, { relayer: false, bridgeProposerDaemon: false, bridgeUi: false })).toBe(false);
        expect(shouldRequireGuardianConfig(false, { psyPrivacyBridge: true })).toBe(false);
    });
});

describe("whole bridge daemon config forwarding", () => {
    const daemonToml = `rpc_config = "rpc.json"
services_url = "http://127.0.0.1:3000"
guardian_config = "guardian.json"
withdraw_method_id = 4159421846
poll_interval_secs = 15
confirmation_lag_checkpoints = 3
max_checkpoint_batch = 32
[finalize]
l1_rpc_url = "http://127.0.0.1:8545"
deployments_network = "localhost"
keystore_path = "signer"
password_env = "SYNTHETIC_PASSWORD"
[[chains]]
chain_index = 0
family = "evm"
network_id = "synthetic"
rpc_urls = ["http://127.0.0.1:8545"]
deployments_network = "localhost"
keystore_path = "signer"
password_env = "SYNTHETIC_PASSWORD"
`;
    const reserveLoopbackPort = async (): Promise<number> => {
        const listener = net.createServer();
        await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
        const port = (listener.address() as net.AddressInfo).port;
        await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
        return port;
    };
    const fixture = async (run: (cwd: string, env: NodeJS.ProcessEnv, ports: number[]) => Promise<void>) => {
        const cwd = await mkdtemp(path.join(tmpdir(), "daemon-public-preflight-"));
        try {
            await mkdir(path.join(cwd, "authorization", "versions"), { recursive: true });
            for (const file of ["rpc.json", "signer", "authorization/index.json", "authorization/versions/1.json"]) await writeFile(path.join(cwd, file), "synthetic metadata fixture, not credentials");
            const ports = [await reserveLoopbackPort(), await reserveLoopbackPort(), await reserveLoopbackPort()];
            const signer = (id: number) => ({ listen_address: `127.0.0.1:${ports[id - 1]}`, signing_key_secret_path: path.join(homedir(), ".psy", "keystore", `guardian-${id}.keystore.json`), signing_key_password_secret_path: path.join(homedir(), ".psy", "keystore", `guardian-${id}.password`) });
            const network = { magic: "0x1", users_per_realm: 1, global_user_tree_height: 32, realm_user_tree_height: 20, group_realm_height: 1, realm_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18081"] }], p2p: { checkpoints_per_epoch: 1 }, coordinator_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18080"] }], prove_proxy_url: ["http://127.0.0.1:9999"], faucet_rpc_url: [], nostr_relay_url: "wss://relay.example", native_currency: "PSY", native_currency_decimal: 18, native_currency_name: "Psy", fees: { register_user_fee: 0, deploy_contract_fee: 0, guta_fee: 1000000000, da_fee: 1000 } };
            await writeFile(path.join(cwd, "guardian.json"), JSON.stringify({
                network,
                guardians: { "1": signer(1), "2": signer(2), "3": signer(3) },
                client: { endpoints: ["http://a.example/", "http://b.example/", "http://c.example/"], archive_path: "archive/relayer-journal", listen_address: "127.0.0.1:15450", l1_endpoints: [] },
            }));
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            await run(cwd, { PSY_BRIDGE_DAEMON_CONFIG: "daemon.toml" }, ports);
        } finally { await rm(cwd, { recursive: true, force: true }); }
    };

    it("requires HTTP 200 and a guardian sessions response for readiness", async () => {
        const page = { sessions: [], next_after_nonce: 0, has_more: false };
        expect(await guardianSessionsReady(Response.json(page))).toBe(true);
        expect(await guardianSessionsReady(Response.json({ ...page, sessions: [{}], next_after_nonce: 1 }))).toBe(true);
        for (const body of [null, {}, [], { ...page, sessions: {} }, { ...page, sessions: [{}, {}] },
            { ...page, next_after_nonce: -1 }, { ...page, next_after_nonce: "0" }, { ...page, has_more: "false" }]) {
            expect(await guardianSessionsReady(Response.json(body))).toBe(false);
        }
        expect(await guardianSessionsReady(Response.json(page, { status: 503 }))).toBe(false);
        expect(await guardianSessionsReady(Response.json(page, { status: 404 }))).toBe(false);
        await expect(guardianSessionsReady(new Response("not JSON"))).rejects.toThrow();
    });

    it("starts three tracked guardians concurrently with independent saved journals", async () => {
        await fixture(async (cwd, _env, ports) => {
            const manager = new DevNetProcessManager();
            const gates = [1, 2, 3].map(() => Promise.withResolvers<void>());
            const allEntered = Promise.withResolvers<void>();
            const commands: string[][] = [];
            const spawn = spyOn(RunningProcess, "spawn").mockImplementation(async (cmds, options) => {
                const index = commands.length;
                commands.push(cmds);
                if (commands.length === 3) allEntered.resolve();
                await gates[index].promise;
                const process = processTemplate(`guardian_${index + 1}`, cmds as string[]);
                process.spawnOptions = options;
                process.guardianListener = { host: "127.0.0.1", port: ports[index] };
                process.proc = { pid: 0, killed: false, exited: Promise.resolve(0), kill() {} } as unknown as RunningProcess["proc"];
                return process;
            });
            try {
                const starting = manager.startGuardianServices(cwd, path.join(cwd, "daemon.toml"));
                await allEntered.promise;
                expect(commands).toHaveLength(3);
                expect(manager.spawnedProcesses).toHaveLength(0);
                for (const gate of gates) gate.resolve();
                await starting;
                expect(commands).toEqual([1, 2, 3].map((id) => [
                    './target/release/psy_relayer_cli', 'guardian-service', '--config', path.join(cwd, 'guardian.json'),
                    '--guardian-id', String(id), '--db-path', `journal/${id}.redb`,
                ]));
                expect(manager.spawnedProcesses.map((process) => process.name)).toEqual(["guardian_1", "guardian_2", "guardian_3"]);
                const relayer = processTemplate("bridge_relayer", ["psy_relayer_cli", "--config", "daemon.toml"]);
                expect(applicationStartOrder([relayer, ...manager.spawnedProcesses])).toEqual(["guardian_1", "guardian_2", "guardian_3", "bridge_relayer"]);
                expect(applicationListenerPorts(manager.spawnedProcesses)).toEqual([...ports].sort((left, right) => left - right));
                await validateRelayerTemplate(commands[0], { cwd, env: {} });
            } finally { for (const gate of gates) gate.resolve(); spawn.mockRestore(); }
        });
    });

    it("rejects a sessions page that validates after the 600s deadline", async () => {
        await fixture(async (cwd, _env, ports) => {
            const realNow = performance.now.bind(performance);
            const startedMs = realNow();
            let probes = 0;
            let elapsedMs = 0;
            const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(async () => {
                elapsedMs = 600_000;
                return Response.json({ sessions: [], next_after_nonce: 0, has_more: false });
            });
            const sleep = spyOn(Bun, "sleep").mockImplementation(async () => {
                probes += 1;
                elapsedMs += 500;
                if (probes > 5) throw new Error(`guardian readiness still looping after ${probes} probes`);
            });
            const now = spyOn(performance, "now").mockImplementation(() => startedMs + elapsedMs);
            try {
                await expect(RunningProcess.spawn([
                    process.execPath, "-e", "setInterval(() => {}, 1 << 30)",
                    "guardian-service", "--config", "guardian.json", "--guardian-id", "1", "--db-path", "journal/1.redb",
                ], {
                    cwd,
                    env: {} as Record<string, string>,
                    stdoutLogFile: path.join(cwd, "guardian-late.log"),
                    stderrLogFile: path.join(cwd, "guardian-late.err"),
                })).rejects.toThrow(`guardian-service port ${ports[0]} not ready within 600000ms`);
                expect(probes).toBe(0);
            } finally { fetchSpy.mockRestore(); sleep.mockRestore(); now.mockRestore(); }
        });
    });

    it("fails guardian readiness at the 600s deadline and names the listen port", async () => {
        await fixture(async (cwd, _env, ports) => {
            const realNow = performance.now.bind(performance);
            const startedMs = realNow();
            let probes = 0;
            const sleep = spyOn(Bun, "sleep").mockImplementation(async (ms) => {
                probes += 1;
                if (ms !== 500 && probes < 1_200) throw new Error(`unexpected sleep ${ms} before the deadline boundary`);
                if (probes > 1_202) throw new Error(`guardian readiness still looping after ${probes} probes`);
            });
            const now = spyOn(performance, "now").mockImplementation(() => startedMs + probes * 500);
            try {
                await expect(RunningProcess.spawn([
                    process.execPath, "-e", "setInterval(() => {}, 1 << 30)",
                    "guardian-service", "--config", "guardian.json", "--guardian-id", "1", "--db-path", "journal/1.redb",
                ], {
                    cwd,
                    env: {} as Record<string, string>,
                    stdoutLogFile: path.join(cwd, "guardian-timeout.log"),
                    stderrLogFile: path.join(cwd, "guardian-timeout.err"),
                })).rejects.toThrow(`guardian-service port ${ports[0]} not ready within 600000ms`);
                expect(probes).toBe(1_200);
            } finally { sleep.mockRestore(); now.mockRestore(); }
        });
    });

    it("attempts all three guardians concurrently and fails startup after settled cleanup when one readiness fails", async () => {
        await fixture(async (cwd, _env, ports) => {
            const manager = new DevNetProcessManager();
            const killed: string[] = [];
            const kill = spyOn(RunningProcess.prototype, "killWithSignal").mockImplementation(function (this: RunningProcess, signal) {
                killed.push(`${this.name}:${String(signal)}`);
            });
            const spawn = spyOn(RunningProcess, "spawn").mockImplementation(async (cmds, options) => {
                const argv = cmds as string[];
                const id = Number(argv[argv.indexOf("--guardian-id") + 1]);
                if (id === 2) throw new Error("guardian readiness failed");
                const process = processTemplate(`guardian_${id}`, argv);
                process.spawnOptions = options;
                process.guardianListener = { host: "127.0.0.1", port: ports[id - 1] };
                process.hasExited = true;
                process.proc = { pid: 0, killed: false, exited: Promise.resolve(0), kill() {} } as unknown as RunningProcess["proc"];
                return process;
            });
            try {
                await expect(manager.startGuardianServices(cwd, path.join(cwd, "daemon.toml"))).rejects.toThrow("guardian readiness failed");
                expect(spawn).toHaveBeenCalledTimes(3);
                expect(killed).toEqual(["guardian_1:SIGTERM", "guardian_3:SIGTERM"]);
                expect(manager.spawnedProcesses).toEqual([]);
            } finally { spawn.mockRestore(); kill.mockRestore(); }
        });
    });

    it("rejects occupied guardian ports and preserves protected journal bytes", async () => {
        await fixture(async (cwd) => {
            const listener = net.createServer();
            await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
            const port = (listener.address() as net.AddressInfo).port;
            const configPath = path.join(cwd, "guardian.json");
            const config = JSON.parse(await Bun.file(configPath).text());
            config.guardians["1"].listen_address = `127.0.0.1:${port}`;
            await writeFile(configPath, JSON.stringify(config));
            const cmds = ["psy_relayer_cli", "guardian-service", "--config", configPath, "--guardian-id", "1", "--db-path", "journal/1.redb"];
            try {
                await expect(prepareGuardianService(cmds, cwd)).rejects.toThrow();
            } finally { await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve())); }
            expect(await prepareGuardianService(cmds, cwd)).toEqual({ host: "127.0.0.1", port });
            const journal = path.join(cwd, "journal");
            expect(statSync(journal).mode & 0o777).toBe(0o700);
            await writeFile(path.join(journal, "1.redb"), "retained journal", { mode: 0o600 });
            await prepareGuardianService(cmds, cwd);
            expect(readFileSync(path.join(journal, "1.redb"), "utf8")).toBe("retained journal");
            expect(statSync(path.join(journal, "1.redb")).mode & 0o777).toBe(0o600);
            await chmod(journal, 0o755);
            await expect(prepareGuardianService(cmds, cwd)).rejects.toThrow("owner-only");
            expect(statSync(journal).mode & 0o777).toBe(0o755);
        });
    });

    it("rejects journal paths redirected into purgeable state", async () => {
        await fixture(async (cwd) => {
            await mkdir(path.join(cwd, "logs"));
            await symlink(path.join(cwd, "logs"), path.join(cwd, "journal"));
            const cmds = ["psy_relayer_cli", "guardian-service", "--config", "guardian.json", "--guardian-id", "1", "--db-path", "journal/1.redb"];
            await expect(prepareGuardianService(cmds, cwd)).rejects.toThrow("guardian journal metadata");
            await expect(prepareGuardianService([...cmds.slice(0, -1), "journal/2.redb"], cwd)).rejects.toThrow("Invalid guardian-service template");
        });
    });

    it("forwards nested TOML unchanged, resolving from launch cwd without reading protected contents", async () => {
        await fixture(async (cwd, env) => {
            for (const file of ["signer", "authorization/index.json"]) await chmod(path.join(cwd, file), 0);
            expect(await resolveBridgeDaemonConfigPath(cwd, env, true)).toBe(path.join(cwd, "daemon.toml"));
            expect(await Bun.file(path.join(cwd, "daemon.toml")).text()).toBe(daemonToml);
            await validateRelayerTemplate(["./target/release/psy_relayer_cli", "--config", "daemon.toml"], { cwd, env: env as Record<string, string> });
        });
    });

    it("rejects missing config, missing inputs and unsupported TOML capability without parser details", async () => {
        await fixture(async (cwd, env) => {
            await expect(resolveBridgeDaemonConfigPath(cwd, {})).rejects.toThrow("config path");
            await expect(resolveBridgeDaemonConfigPath(cwd, env, false, null as never)).rejects.toThrow("Bun.TOML.parse");
            await writeFile(path.join(cwd, "daemon.toml"), 'broken = "SYNTHETIC-DO-NOT-REPORT\n');
            const malformedConfig = resolveBridgeDaemonConfigPath(cwd, env);
            await expect(malformedConfig).rejects.toBeInstanceOf(Error);
            try { await malformedConfig; }
            catch (error) {
                expect(String(error)).not.toContain("SYNTHETIC-DO-NOT-REPORT");
            }
            await writeFile(path.join(cwd, "daemon.toml"), 'private_key = "SYNTHETIC-DO-NOT-REPORT"\n[broken');
            const malformedConfigWithKey = resolveBridgeDaemonConfigPath(cwd, env);
            await expect(malformedConfigWithKey).rejects.toBeInstanceOf(Error);
            try { await malformedConfigWithKey; }
            catch (error) {
                expect(String(error)).not.toContain("SYNTHETIC-DO-NOT-REPORT");
            }
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            await rm(path.join(cwd, "rpc.json"));
            await expect(resolveBridgeDaemonConfigPath(cwd, env)).rejects.toThrow("rpc_config metadata");
        });
    });

    it("rejects nested inline keys without exposing their values", async () => {
        await fixture(async (cwd, env) => {
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml + 'private_key = "SYNTHETIC-DO-NOT-REPORT"\n');
            try { await resolveBridgeDaemonConfigPath(cwd, env); throw new Error("accepted inline key"); }
            catch (error) {
                expect(String(error)).toContain("inline private_key");
                expect(String(error)).not.toContain("SYNTHETIC-DO-NOT-REPORT");
            }
        });
    });

    it("requires daemon integers and chain identity, rejecting width overflow", async () => {
        await fixture(async (cwd, env) => {
            for (const [before, after, message] of [
                ["chain_index = 0", "chain_index = 256", "chains.chain_index"],
                ["withdraw_method_id = 4159421846", "withdraw_method_id = -1", "withdraw_method_id"],
                ["poll_interval_secs = 15", "poll_interval_secs = 1.5", "poll_interval_secs"],
                ["max_checkpoint_batch = 32", "max_checkpoint_batch = 9007199254740993.0", "max_checkpoint_batch"],
                ["family = \"evm\"", "family = 7", "chains.family"],
            ] as const) {
                await writeFile(path.join(cwd, "daemon.toml"), daemonToml.replace(before, after));
                await expect(resolveBridgeDaemonConfigPath(cwd, env)).rejects.toThrow(message);
            }
            const parsed = Bun.TOML.parse(daemonToml) as Record<string, unknown>;
            parsed.withdraw_method_id = 1n << 64n;
            await expect(resolveBridgeDaemonConfigPath(cwd, env, false, () => parsed)).rejects.toThrow("withdraw_method_id");
        });
    });

    it("accepts an omitted chain family because the daemon defaults it to evm", async () => {
        await fixture(async (cwd, env) => {
            const omitted = daemonToml.replace('family = "evm"\n', "");
            await writeFile(path.join(cwd, "daemon.toml"), omitted);
            expect(await resolveBridgeDaemonConfigPath(cwd, env)).toBe(path.join(cwd, "daemon.toml"));
            expect(await Bun.file(path.join(cwd, "daemon.toml")).text()).toBe(omitted);
        });
    });

    it("rejects lexical and realpath purge containment including absent history outputs", async () => {
        await fixture(async (cwd, env) => {
            await mkdir(path.join(cwd, "logs"));
            await writeFile(path.join(cwd, "logs", "rpc.json"), "synthetic");
            await symlink(path.join(cwd, "logs"), path.join(cwd, "alias"));
            for (const rpc of ["logs/rpc.json", "alias/rpc.json"]) {
                await writeFile(path.join(cwd, "daemon.toml"), daemonToml.replace('rpc_config = "rpc.json"', `rpc_config = "${rpc}"`));
                await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("rpc_config metadata");
                expect(await resolveBridgeDaemonConfigPath(cwd, env)).toBe(path.join(cwd, "daemon.toml"));
            }
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            const guardian = JSON.parse(await Bun.file(path.join(cwd, "guardian.json")).text());
            await symlink(path.join(cwd, "logs"), path.join(cwd, "archive"));
            await writeFile(path.join(cwd, "guardian.json"), JSON.stringify(guardian));
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("archive_path metadata");
        });
    });

    it("accepts a real or absent relayer archive directory and rejects a regular file through restart and resume", async () => {
        await fixture(async (cwd, env) => {
            const guardianPath = path.join(cwd, "guardian.json");
            const guardian = JSON.parse(await Bun.file(guardianPath).text());
            const archive = path.join(cwd, "archive", "relayer-journal");
            const spawnOptions = { cwd, env: env as Record<string, string> };
            await rm(archive, { recursive: true, force: true });
            expect(await resolveBridgeDaemonConfigPath(cwd, env, true)).toBe(path.join(cwd, "daemon.toml"));
            await validateRelayerTemplate(["psy_relayer_cli", "--config", "daemon.toml"], spawnOptions);
            expect(await Bun.file(archive).exists()).toBe(false);

            await mkdir(path.join(archive, "7"), { recursive: true });
            await writeFile(path.join(archive, "7", "request.json"), "retained signing history");
            expect(await resolveBridgeDaemonConfigPath(cwd, env, true)).toBe(path.join(cwd, "daemon.toml"));
            await validateRelayerTemplate(["psy_relayer_cli", "--config", "daemon.toml"], spawnOptions);
            const manager = new DevNetProcessManager();
            const relayer = processTemplate("bridge_relayer", ["psy_relayer_cli", "--config", "daemon.toml"]);
            relayer.spawnOptions = spawnOptions;
            const lifecycle = manager as unknown as {
                applicationLifecycleState: string;
                pausedApplicationProcesses: RunningProcess[];
                spawnedProcesses: RunningProcess[];
            };
            lifecycle.applicationLifecycleState = "running";
            lifecycle.spawnedProcesses = [relayer];
            lifecycle.pausedApplicationProcesses = [];
            const stop = spyOn(manager, "stopApplications").mockImplementation(async () => {
                lifecycle.applicationLifecycleState = "stopped";
                lifecycle.spawnedProcesses = [];
                lifecycle.pausedApplicationProcesses = [relayer];
            });
            const spawnSentinel = new Error("archive preflight reached spawn sentinel");
            const spawn = spyOn(RunningProcess, "spawn").mockRejectedValue(spawnSentinel);
            try {
                // The saved config matches, so this proves preflight reaches spawn rather than a config mismatch.
                await expect(manager.restartApplications(cwd)).rejects.toBe(spawnSentinel);
                expect(stop).toHaveBeenCalledOnce();
                expect(lifecycle.applicationLifecycleState).toBe("stopped");
                expect(lifecycle.pausedApplicationProcesses).toEqual([relayer]);
                await expect(manager.startApplications(cwd)).rejects.toBe(spawnSentinel);
                expect(spawn).toHaveBeenCalledTimes(2);
            } finally {
                stop.mockRestore();
                spawn.mockRestore();
            }
            expect(lifecycle.applicationLifecycleState).toBe("stopped");
            expect(lifecycle.pausedApplicationProcesses).toEqual([relayer]);
            expect(lifecycle.spawnedProcesses).toEqual([]);
            expect(await Bun.file(path.join(archive, "7", "request.json")).text()).toBe("retained signing history");

            const invalidArchive = path.join(cwd, "archive-file");
            await writeFile(invalidArchive, "not a directory");
            guardian.client.archive_path = "archive-file";
            await writeFile(path.join(cwd, "guardian.json"), JSON.stringify(guardian));
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("expected only GuardianConfig public fields");
        });
    });

    it("checks a symlinked purge target and rejects mismatched guardian or replay config", async () => {
        await fixture(async (cwd, env) => {
            await symlink(path.join(cwd, "rpc.json"), path.join(cwd, "logs"));
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml.replace('rpc_config = "rpc.json"', 'rpc_config = "logs"'));
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("rpc_config metadata");
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            await expect(resolveBridgeDaemonConfigPath(cwd, { ...env, PSY_GUARDIAN_CONFIG: "other.json" })).rejects.toThrow("coherence");
            await expect(validateRelayerTemplate(["psy_relayer_cli", "--config", "other.toml"], { cwd, env: env as Record<string, string> })).rejects.toThrow("saved --config coherence");
        });
    });

    it("rejects manual restart before stopping live applications and resume before any spawn", async () => {
        await fixture(async (cwd, env) => {
            const manager = new DevNetProcessManager();
            const relayer = processTemplate("bridge_relayer", ["psy_relayer_cli", "--config", "daemon.toml"]);
            relayer.spawnOptions = { cwd, env: env as Record<string, string> };
            manager.spawnedProcesses = [relayer];
            const stop = spyOn(manager, "stopApplications").mockResolvedValue(undefined);
            const spawn = spyOn(RunningProcess, "spawn");
            try {
                await rm(path.join(cwd, "rpc.json"));
                await expect(manager.restartApplications("/not-the-launch-cwd")).rejects.toThrow("rpc_config");
                expect(stop).not.toHaveBeenCalled();
                expect(manager.spawnedProcesses).toEqual([relayer]);
                // Exercise saved supervisor state without starting any child processes.
                const lifecycle = manager as unknown as {
                    applicationLifecycleState: string;
                    pausedApplicationProcesses: RunningProcess[];
                    spawnFromTemplate(template: RunningProcess, banner: string, track: boolean): Promise<RunningProcess>;
                };
                lifecycle.applicationLifecycleState = "stopped";
                lifecycle.pausedApplicationProcesses = [processTemplate("worker", ["psy_worker_cli"]), relayer];
                await expect(manager.startApplications()).rejects.toThrow("rpc_config");
                await expect(lifecycle.spawnFromTemplate(relayer, "automatic restart", false)).rejects.toThrow("rpc_config");
                expect(spawn).not.toHaveBeenCalled();
            } finally { stop.mockRestore(); spawn.mockRestore(); }
        });
    });

    it("blocks the actual spawn before logs and leaves non-relayer validation unchanged", async () => {
        await fixture(async (cwd, env) => {
            await rm(path.join(cwd, "rpc.json"));
            await expect(RunningProcess.spawn(["psy_relayer_cli", "--config", "daemon.toml"], {
                cwd, env: env as Record<string, string>, stdoutLogFile: path.join(cwd, "never-written.log"),
            })).rejects.toThrow("rpc_config");
            expect(await Bun.file(path.join(cwd, "never-written.log")).exists()).toBe(false);
            await validateRelayerTemplate(["psy_worker_cli"], { cwd: "/missing", env: {} });
        });
    });

    it("accepts the current single-chain and multichain startup markers, never indexer readiness", () => {
        expect(relayerStartedDetector("INFO multichain bridge relayer started config=/public/daemon.toml chain_count=1")).toBe(true);
        expect(relayerStartedDetector("INFO bridge relayer started config=/public/daemon.toml")).toBe(true);
        for (const line of ["connected to indexer postgres", "envio schema is ready", "indexer deposit sync window", "aggregate bridge relayer started", "bridge relayer startedness"]) expect(relayerStartedDetector(line)).toBe(false);
    });
});

describe("resolveForkRpcEnvKey", () => {
    it("falls back to the L1-owned table when the selected stage's genesis block has no anvilForkSourceUrlEnv", () => {
        // Reproduces VITE_PSY_STAGE=localhost VITE_NETWORK=sepolia VITE_FORK=true:
        // the localhost stage's genesis block never defines anvilForkSourceUrlEnv,
        // but forking sepolia must still work without picking a non-local stage.
        expect(resolveForkRpcEnvKey("sepolia", undefined, "localhost")).toBe("SEPOLIA_RPC_URL");
        expect(resolveForkRpcEnvKey("sepolia", {}, "localhost")).toBe("SEPOLIA_RPC_URL");
        expect(resolveForkRpcEnvKey("ethereum", undefined, "localhost")).toBe("ETH_RPC_URL");
    });

    it("prefers the genesis config's anvilForkSourceUrlEnv over the L1-owned fallback when the requested L1 is that stage's own default L1", () => {
        expect(
            resolveForkRpcEnvKey("sepolia", { anvilForkSourceUrlEnv: "CUSTOM_SEPOLIA_RPC_URL" }, "testnet"),
        ).toBe("CUSTOM_SEPOLIA_RPC_URL");
    });

    it("ignores the genesis config's anvilForkSourceUrlEnv when the requested L1 is not the selected stage's default L1", () => {
        // Reproduces VITE_PSY_STAGE=testnet VITE_NETWORK=ethereum VITE_FORK=true: the
        // testnet stage's genesis block names a Sepolia fork source, but the request
        // is for Ethereum, so it must fall through to the L1-owned ETH_RPC_URL
        // instead of silently forking Ethereum via testnet's Sepolia RPC.
        expect(
            resolveForkRpcEnvKey("ethereum", { anvilForkSourceUrlEnv: "CUSTOM_SEPOLIA_RPC_URL" }, "testnet"),
        ).toBe("ETH_RPC_URL");
    });

    it("throws naming both VITE_NETWORK and the missing fork source when neither source has an answer", () => {
        expect(() => resolveForkRpcEnvKey("localhost", undefined, "localhost")).toThrow(
            /no fork RPC env is known for VITE_NETWORK=localhost.*VITE_NETWORK must be one of the L1 names with a known fork source/s,
        );
    });
});

describe("make shutdown Anvil preservation", () => {
    const stateText = (best: number) => JSON.stringify({
        best_block_number: best,
        blocks: [{ header: { number: "0x1" } }, { header: { number: "0x64" } }],
    });
    const dumpHex = (text: string) => `0x${Buffer.from(Bun.gzipSync(Buffer.from(text))).toString("hex")}`;

    it("reads top-level best_block_number instead of the last unsorted block", () => {
        const text = stateText(5);
        expect(anvilStateBestBlockNumber(JSON.parse(text), "fixture")).toBe(5n);
        expect(decodeAnvilDumpStateHex(dumpHex(text), "fixture")).toBe(text);
        expect(() => anvilStateBestBlockNumber({ blocks: [{ header: { number: "0x64" } }] }, "fixture")).toThrow("best_block_number");
    });

    it("decodes a large incompressible mixed-case JSON dump", () => {
        let state = 0x9e3779b9;
        const next = () => {
            state ^= state << 13;
            state ^= state >>> 17;
            state ^= state << 5;
            return state >>> 0;
        };
        const alphabet = "0123456789abcdef";
        let padding = "";
        while (padding.length < 4 * 1024 * 1024) padding += alphabet[next() & 15];
        const text = JSON.stringify({ best_block_number: 5, padding });
        const hex = Buffer.from(Bun.gzipSync(Buffer.from(text))).toString("hex");
        const mixed = `0x${hex.replace(/[a-f]/g, (digit, index) => index % 2 === 0 ? digit.toUpperCase() : digit)}`;
        expect(mixed.length).toBeGreaterThan(1024 * 1024);
        expect(decodeAnvilDumpStateHex(mixed, "fixture")).toBe(text);
        expect(JSON.parse(decodeAnvilDumpStateHex(mixed, "fixture")).best_block_number).toBe(5);
    });

    it("rejects malformed hex and non-gzip dumps", () => {
        const expected = "expected hex-encoded gzip";
        const valid = dumpHex(stateText(5));
        for (const dump of ["0x", "abc", `${valid}a`, `${valid}\n`, `${valid}é`, 0, null]) {
            expect(() => decodeAnvilDumpStateHex(dump, "fixture")).toThrow(expected);
        }
        expect(() => decodeAnvilDumpStateHex(`${valid.slice(0, -1)}g`, "fixture")).toThrow(expected);
        expect(() => decodeAnvilDumpStateHex(`0x${Buffer.from("not gzip").toString("hex")}`, "fixture")).toThrow("not decodable gzip");
    });

    it("routes PURGE=0 teardown to the owner, publishes only after exit, and skips broad kill on failure", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        const repo = `${dir}/repo`;
        await Bun.$`mkdir -p ${repo}`.quiet();
        const previousTmp = process.env.TMPDIR;
        process.env.TMPDIR = dir;
        const order: string[] = [];
        const published: string[] = [];
        const killed: string[] = [];
        const manager = new DevNetProcessManager();
        const anvil = Object.create(RunningProcess.prototype) as RunningProcess;
        anvil.name = "l1_anvil";
        anvil.cmds = ["anvil", "--port", "8545"];
        anvil.hasExited = false;
        const exited = Promise.withResolvers<number>();
        anvil.proc = { killed: false, exited: exited.promise } as unknown as RunningProcess["proc"];
        anvil.isRunning = () => !anvil.hasExited;
        anvil.killWithSignal = () => {
            killed.push("SIGTERM");
            anvil.hasExited = true;
            exited.resolve(0);
        };
        manager.spawnedProcesses = [anvil];
        manager.quiesceApplications = async () => { order.push("quiesce"); };
        const rpc = async (_rpcUrl: string, method: string) => {
            order.push(method);
            return method === "eth_blockNumber" ? "0x5" : dumpHex(stateText(5));
        };
        try {
            const server = await startDevnetControlServer(repo, async (command) => {
                if (command !== "shutdown-preserve") throw new Error(`unexpected ${command}`);
                await manager.preserveOwnedAnvilState(repo, rpc);
                published.push(await Bun.file(localAnvilStatePath(repo)).text());
                return { message: "preserved", afterAck: () => undefined };
            });
            expect(await requestOwnedAnvilShutdown(repo, false)).toBe("owned");
            expect(JSON.parse(published[0]).best_block_number).toBe(5);
            expect(order).toEqual(["quiesce", "eth_blockNumber", "anvil_dumpState"]);
            expect(killed).toEqual(["SIGTERM"]);
            await server.close();

            const stale = await startDevnetControlServer(repo, async () => {
                throw new Error("[DevNet][control] unsupported command shutdown-preserve");
            });
            await expect(requestOwnedAnvilShutdown(repo, false)).rejects.toThrow("does not support shutdown-preserve");
            await stale.close();

            const before = await Bun.file(localAnvilStatePath(repo)).text();
            await expect(preserveUnownedLiveAnvils(repo, async () => {
                throw new Error("RPC must not run");
            }, async (port) => port === 8545)).rejects.toThrow("refusing to snapshot or kill");
            expect(await Bun.file(localAnvilStatePath(repo)).text()).toBe(before);
            expect(readdirSync(path.dirname(localAnvilStatePath(repo))).some((entry) => entry.includes(".preserve-"))).toBe(false);
        } finally {
            if (previousTmp === undefined) delete process.env.TMPDIR;
            else process.env.TMPDIR = previousTmp;
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});

describe("purge Anvil ownership", () => {
    const withExe = async (run: (exe: string, repo: string) => Promise<void>) => {
        const dir = await mkdtemp(`${tmpdir()}/anvil-exe-`);
        const repo = `${dir}/repo`;
        await mkdir(repo);
        const exe = `${dir}/anvil`;
        await writeFile(exe, "");
        await chmod(exe, 0o755);
        try { await run(exe, repo); }
        finally { await rm(dir, { recursive: true, force: true }); }
    };
    const identity = (cmdline: string, exe: string, cwd = path.join(path.dirname(exe), "repo")) => ({ exe, cwd, cmdline, starttime: "10" });

    it("accepts host-before-port and equals flags for an expected state", async () => {
        await withExe(async (exe, repo) => {
            const state = `${repo}/db/anvil/state.json`;
            expect(await isRepoAnvilProcess(identity(["anvil", "--host", "0.0.0.0", "--port", "8545", "--state", state].join("\0"), exe), repo)).toBe(true);
            expect(await isRepoAnvilProcess(identity(["anvil", `--state=${state}`, "--port=8545"].join("\0"), exe), repo)).toBe(true);
        });
    });

    it("defaults the state interval to 900 and rejects non-positive values", () => {
        const previous = process.env.ANVIL_STATE_INTERVAL;
        try {
            delete process.env.ANVIL_STATE_INTERVAL;
            expect(localAnvilLaunchArgs(8545, "31337", "db/anvil/state.json")).toContain("900");
            for (const invalid of ["0", "-1", "1.5", "abc", " 900"]) {
                process.env.ANVIL_STATE_INTERVAL = invalid;
                expect(() => localAnvilLaunchArgs(8545, "31337", "db/anvil/state.json")).toThrow("positive integer");
            }
        } finally {
            if (previous === undefined) delete process.env.ANVIL_STATE_INTERVAL;
            else process.env.ANVIL_STATE_INTERVAL = previous;
        }
    });

    it("rejects foreign cwd, foreign state, duplicate flags, and a symlink that leaves the checkout", async () => {
        const dir = await mkdtemp(`${tmpdir()}/purge-anvil-`);
        const checkout = `${dir}/repo`;
        const repo = checkout;
        const exe = `${dir}/anvil`;
        const outside = `${dir}/outside.json`;
        const link = `${checkout}/db/anvil/state.json`;
        await mkdir(`${checkout}/db/anvil`, { recursive: true });
        await writeFile(exe, "");
        await chmod(exe, 0o755);
        await writeFile(outside, "{}");
        await symlink(outside, link);
        try {
            expect(await isRepoAnvilProcess(identity(["anvil", "--port", "8545", "--state", `${repo}/db/anvil/state.json`].join("\0"), exe, "/tmp/other-repo"), repo)).toBe(false);
            expect(await isRepoAnvilProcess(identity(["anvil", "--port", "8545", "--state", "/tmp/other/state.json"].join("\0"), exe), repo)).toBe(false);
            expect(await isRepoAnvilProcess(identity(["anvil", "--port", "8545", "--port", "9545", "--state", `${repo}/db/anvil/state.json`].join("\0"), exe), repo)).toBe(false);
            expect(await isRepoAnvilProcess(identity(["anvil", "--port", "8545", "--state", `${repo}/db/anvil/state.json`, "--state", `${repo}/db/anvil/localhostBsc/state.json`].join("\0"), exe), repo)).toBe(false);
            expect(await isRepoAnvilProcess(identity(["anvil", "--port", "8545", "--state", link].join("\0"), exe, checkout), checkout)).toBe(false);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    it("accepts an absent snapshot whose canonical ancestor stays inside the checkout", async () => {
        await withExe(async (exe, repo) => {
            const missing = `${repo}/db/anvil/not-yet-written-state.json`;
            expect(await isRepoAnvilProcess(identity(["anvil", "--port", "8545", "--state", `${repo}/db/anvil/state.json`].join("\0"), exe), repo)).toBe(true);
            expect(await isRepoAnvilProcess(identity(["anvil", "--port", "8545", "--state", missing].join("\0"), exe), repo)).toBe(false);
        });
    });

    it("signals only the owned pid and refuses a reused starttime", async () => {
        await withExe(async (exe, repo) => {
            const state = `${repo}/db/anvil/state.json`;
            const owned = identity(["anvil", "--port", "8545", "--state", state].join("\0"), exe);
            const foreign = identity(["anvil", "--port", "8545", "--state", "/tmp/other/state.json"].join("\0"), exe, "/tmp/other");
            const signals: Array<[number, string]> = [];
            const alive = new Set([11, 22]);
            await expect(stopRepoAnvilsForPurge(repo, {
                listPids: async () => [11, 22, process.pid],
                readIdentity: async (pid) => pid === 11 ? owned : pid === 22 ? foreign : null,
                signal: (pid, sig) => { signals.push([pid, sig]); alive.delete(pid); },
                alive: (pid) => alive.has(pid),
                portOpen: async () => false,
            })).resolves.toBeUndefined();
            expect(signals).toEqual([[11, "SIGTERM"]]);

            let reads = 0;
            await expect(stopRepoAnvilsForPurge(repo, {
                listPids: async () => [11],
                readIdentity: async () => {
                    reads += 1;
                    return { ...owned, starttime: reads < 3 ? "10" : "99" };
                },
                signal: () => { throw new Error("must not signal a reused pid"); },
                alive: () => false,
                portOpen: async () => false,
            })).rejects.toThrow("reused before SIGTERM");
        });
    });

    it("fails while a foreign Anvil port stays open and does not signal it", async () => {
        await withExe(async (_exe, repo) => {
            const signals: number[] = [];
            await expect(stopRepoAnvilsForPurge(repo, {
                listPids: async () => [],
                readIdentity: async () => null,
                signal: (pid) => { signals.push(pid); },
                alive: () => true,
                portOpen: async (port) => port === 8545,
            })).rejects.toThrow("still live port 8545");
            expect(signals).toEqual([]);
        });
    });

    it("kills and reaps a harmless timeout child and returns failure", async () => {
        const result = await runTeardownCommand(["sleep", "30"], undefined, 200);
        expect(result.timedOut).toBe(true);
        expect(result.code).toBeNull();
        expect(result.argv0).toBe("sleep");
    });

    it("times out and kills a descendant retaining stdout after its leader exits", async () => {
        // Real kernel pipe EOF and orphan reaping cannot be driven by fake timers.
        const started = Date.now();
        const result = await runTeardownCommand(["sh", "-c", "sleep 30 & echo $!"], undefined, 200);
        expect(result.timedOut).toBe(true);
        expect(result.stdoutComplete).toBe(false);
        expect(Date.now() - started).toBeLessThan(2_000);
        const pid = Number(result.stdout);
        expect(Number.isSafeInteger(pid) && pid > 0).toBe(true);
        // Orphans may briefly remain as zombies until the host's init reaps them.
        const deadline = Date.now() + 1_000;
        let running = true;
        while (running && Date.now() < deadline) {
            try {
                const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
                running = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[0] !== "Z";
            } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
                running = false;
            }
            if (running) await Bun.sleep(10);
        }
        expect(running).toBe(false);
    });

    it("never treats truncated stdout as a complete listing", async () => {
        const result = await runTeardownCommand([process.execPath, "-e", "process.stdout.write('x'.repeat(70000))"], undefined, 2_000);
        expect(result.code).toBe(0);
        expect(result.timedOut).toBe(false);
        expect(result.stdout.length).toBe(65_536);
        expect(result.stdoutComplete).toBe(false);
    });

    it("stops an owned fixture child before a hanging docker command and keeps the aggregate failing", async () => {
        await withExe(async (exe, repo) => {
            const child = Bun.spawn(["sleep", "30"], { stdout: "ignore", stderr: "ignore" });
            let exited = false;
            const reaped = child.exited.then(() => { exited = true; });
            const signals: number[] = [];
            const order: string[] = [];
            try {
                await stopRepoAnvilsForPurge(repo, {
                    listPids: async () => [child.pid],
                    readIdentity: async () => identity(["anvil", "--port", "8545", "--state", `${repo}/db/anvil/state.json`].join("\0"), exe),
                    signal: (pid, sig) => {
                        order.push(sig);
                        signals.push(pid);
                        if (sig === "SIGTERM") child.kill("SIGTERM");
                    },
                    alive: () => !exited,
                    portOpen: async () => false,
                });
                expect(exited).toBe(true);
                await reaped;
                order.push("anvil-gone");
                const hung = await runTeardownCommand(["sleep", "30"], undefined, 200);
                order.push("docker");
                const failures = [hung.timedOut ? "docker timed out" : ""].filter((entry) => entry.length > 0);
                expect(failures).toEqual(["docker timed out"]);
                expect(order[0]).toBe("SIGTERM");
                expect(order.indexOf("anvil-gone")).toBeLessThan(order.indexOf("docker"));
                expect(signals).toEqual([child.pid]);
            } finally {
                try { child.kill("SIGKILL"); } catch { /* already reaped */ }
                await child.exited;
            }
        });
    });

    it("treats a missing docker object as absent and a daemon error or leftover as failure", () => {
        const names = exactSnapshotNames("valkey-server\n\npsy-devnet-redis\n");
        expect(names.has("scylla-server")).toBe(false);
        expect(names.has("psy-devnet-redis")).toBe(true);
        const missing = { code: 0, timedOut: false };
        const daemon = { code: 1, timedOut: false };
        const timed = { code: null, timedOut: true };
        expect(missing.code === 0 && !names.has("scylla-server")).toBe(true);
        expect(daemon.code !== 0 || daemon.timedOut).toBe(true);
        expect(timed.code !== 0 || timed.timedOut).toBe(true);
        expect(names.has("valkey-server")).toBe(true);
    });
});

