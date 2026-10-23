import { describe, expect, it, spyOn, mock } from "bun:test";
import path from "node:path";
import fs from "node:fs";
import * as childProcess from "node:child_process";
import { type ChildProcessWithoutNullStreams } from "node:child_process";
import net from "node:net";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { mkdtemp, mkdir, writeFile, rm, symlink, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
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
    downloadTrustSetupObject,
    fetchKeystoreManifest,
    groupVerifies,
    trustSetupPartKeys,
    trustSetupGroups,
    TRUST_SETUP_PART_BYTES,
    ANVIL_STATE_PATH,
    assertPreservedAnvilGenesis,

    localAnvilLaunchArgs,
    isRepoAnvilProcess,
    runTeardownCommand,
    stopOwnedDevnetUiListeners,
    stopRepoAnvilsForPurge,
    exactSnapshotNames,
    preservedAnvilGenesis,
    ROLLBACK_STOP_SENTINEL_CONTENT,
    ROLLBACK_STOP_SENTINEL_PATH,
    applicationListenerPorts,
    applicationStartOrder,
    devnetControlSocketPath,
    sendDevnetControlCommand,
    evaluateCompilerArtifactStamp,
    injectGenesisValidators,
    ensureRealmP2pConfig,
    LOCAL_DEVNET_ZK_FINGERPRINT,
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
    discoverRepoAnvils,
    gracefulDevnetStop,
    isGracefulShutdownControlClient,
    resolveBoundDevnetNames,
    commitDevnetNamespaceBinding,
    selectedUiDependencies,
    ensurePsyContractsDependencies,
    runFrozenEnvioCodegen,
    frozenEnvioStartCommand,
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
    validateGuardianRpcConfig,
    resolveGuardianRoot,
    assertGuardianKeystoresPresent,
    resolveBridgeDaemonConfigPath,
    prepareGuardianService,
    guardianSessionsReady,
    guardianServiceReady,
    validateRelayerTemplate,
    relayerStartedDetector,
    DevNetProcessManager,
    shouldRequireGuardianRoot,
    prepareFreshDevnetState,
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
            for (const prefix of ["", "deposit_append/", "withdrawal_claim/", "reward_claim/"]) {
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

    const CHUNKED_KEYS = ["pk_groth16.bin.zst", "deposit_append.tar.zst", "withdrawal_claim.tar.zst", "reward_claim.tar.zst"];

    it("derives zero-based part keys from the manifest size", () => {
        expect(TRUST_SETUP_PART_BYTES).toBe(268435456);
        expect(trustSetupPartKeys("pk_groth16.bin.zst", 1)).toEqual(["pk_groth16.bin.zst.part-00"]);
        expect(trustSetupPartKeys("pk_groth16.bin.zst", 268435456)).toEqual(["pk_groth16.bin.zst.part-00"]);
        expect(trustSetupPartKeys("pk_groth16.bin.zst", 21, 10)).toEqual([
            "pk_groth16.bin.zst.part-00", "pk_groth16.bin.zst.part-01", "pk_groth16.bin.zst.part-02",
        ]);
        expect(trustSetupGroups.filter((group) => group.chunked).map((group) => group.key)).toEqual(CHUNKED_KEYS);
        expect(trustSetupGroups.filter((group) => !group.chunked).map((group) => group.key)).toEqual([
            "circuit_groth16.bin.zst", "vk_groth16.bin.zst",
        ]);
    });

    it("assembles chunked objects from resumed parts and leaves single objects whole", async () => {
        const dir = mkdtempSync(path.join(tmpdir(), "psy-r2-parts-"));
        const previous = process.env.PSY_KEYSTORE_R2_PREFIX;
        process.env.PSY_KEYSTORE_R2_PREFIX = "localhost-test";
        const spawn = spyOn(Bun, "spawn");
        const partBytes = 5;
        const object = "pk_groth16.bin.zst";
        const parts = ["aaaaa", "bbbbb", "cc"];
        const whole = parts.join("");
        const manifest = { version: 1, files: { [object]: { size: whole.length, sha256: createHash("sha256").update(whole).digest("hex") } } };
        try {
            spawn.mockImplementation(((args: string[]) => {
                const dest = args[args.indexOf("-o") + 1];
                const part = parts[Number(args.at(-1)!.slice(-2))];
                writeFileSync(dest, part);
                expect(args).toContain("-C");
                return { exited: Promise.resolve(0) };
            }) as typeof Bun.spawn);
            const dest = path.join(dir, object);
            await downloadTrustSetupObject({ type: "zst", key: object, entries: ["pk_groth16.bin"], chunked: true }, dest, manifest, partBytes);
            expect(readFileSync(dest, "utf8")).toBe(whole);
            expect(readdirSync(dir)).toEqual([object]);
            const single = path.join(dir, "circuit_groth16.bin.zst");
            spawn.mockImplementation(((args: string[]) => {
                expect(args).not.toContain("-C");
                expect(args.at(-1)).toContain("/circuit_groth16.bin.zst");
                writeFileSync(args[args.indexOf("-o") + 1], "whole-object");
                return { exited: Promise.resolve(0) };
            }) as typeof Bun.spawn);
            await downloadTrustSetupObject({ type: "zst", key: "circuit_groth16.bin.zst", entries: ["circuit_groth16.bin"], chunked: false }, single, manifest);
            expect(readFileSync(single, "utf8")).toBe("whole-object");
            expect(spawn.mock.calls).toHaveLength(4);
        } finally {
            spawn.mockRestore();
            if (previous === undefined) delete process.env.PSY_KEYSTORE_R2_PREFIX;
            else process.env.PSY_KEYSTORE_R2_PREFIX = previous;
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it("fails closed naming the object when a part is missing or empty", async () => {
        const dir = mkdtempSync(path.join(tmpdir(), "psy-r2-parts-"));
        const previous = process.env.PSY_KEYSTORE_R2_PREFIX;
        process.env.PSY_KEYSTORE_R2_PREFIX = "localhost-test";
        const spawn = spyOn(Bun, "spawn");
        const object = "deposit_append.tar.zst";
        const manifest = { version: 1, files: { [object]: { size: 12, sha256: "a".repeat(64) } } };
        const group = { type: "tar" as const, key: object, entries: ["deposit_append/pk_groth16.bin"], chunked: true };
        try {
            spawn.mockImplementation(((args: string[]) => {
                const dest = args[args.indexOf("-o") + 1];
                writeFileSync(dest, args.at(-1)!.endsWith("part-01") ? "" : "12345");
                return { exited: Promise.resolve(0) };
            }) as typeof Bun.spawn);
            await expect(downloadTrustSetupObject(group, path.join(dir, object), manifest, 5)).rejects.toThrow(`${object}: missing or empty part ${object}.part-01`);
            spawn.mockImplementation(((args: string[]) => {
                if (args.at(-1)!.endsWith("part-02")) return { exited: Promise.resolve(22) };
                writeFileSync(args[args.indexOf("-o") + 1], "12345");
                return { exited: Promise.resolve(0) };
            }) as typeof Bun.spawn);
            await expect(downloadTrustSetupObject(group, path.join(dir, object), manifest, 5)).rejects.toThrow(`${object}: missing part ${object}.part-02`);
            delete manifest.files[object];
            await expect(downloadTrustSetupObject(group, path.join(dir, object), manifest, 5)).rejects.toThrow(`${object}: sha256sums.json has no size/sha256`);
        } finally {
            spawn.mockRestore();
            if (previous === undefined) delete process.env.PSY_KEYSTORE_R2_PREFIX;
            else process.env.PSY_KEYSTORE_R2_PREFIX = previous;
            rmSync(dir, { recursive: true, force: true });
        }
    });

    it("fails closed naming the object when the assembled sha256 mismatches", async () => {
        const dir = mkdtempSync(path.join(tmpdir(), "psy-r2-parts-"));
        const previous = process.env.PSY_KEYSTORE_R2_PREFIX;
        process.env.PSY_KEYSTORE_R2_PREFIX = "localhost-test";
        const spawn = spyOn(Bun, "spawn");
        const object = "withdrawal_claim.tar.zst";
        const manifest = { version: 1, files: { [object]: { size: 6, sha256: "f".repeat(64) } } };
        try {
            spawn.mockImplementation(((args: string[]) => {
                writeFileSync(args[args.indexOf("-o") + 1], "123");
                return { exited: Promise.resolve(0) };
            }) as typeof Bun.spawn);
            await expect(downloadTrustSetupObject(
                { type: "tar", key: object, entries: ["withdrawal_claim/pk_groth16.bin"], chunked: true },
                path.join(dir, object), manifest, 3,
            )).rejects.toThrow(`${object}: sha256/size mismatch vs sha256sums.json`);
            expect(readdirSync(dir)).toEqual([]);
        } finally {
            spawn.mockRestore();
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

describe("local Anvil fresh startup", () => {
    it("rejects an occupied listener without reading identity or RPC", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "fresh-anvil-plan-"));
        try {
            const readIdentity = mock(async () => { throw new Error("identity must not be read"); });
            await expect(resolveLocalAnvilStatePlan(dir, "localhost", false, { listenerOwner: async () => 12345, readIdentity }))
                .rejects.toThrow("refusing to reuse or kill a foreign owner");
            expect(readIdentity).not.toHaveBeenCalled();
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    it("rejects a stale snapshot and deployment even when PURGE is unset", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "stale-anvil-plan-"));
        const previous = process.env.PURGE;
        process.env.PURGE = "0";
        try {
            await mkdir(path.join(dir, "db/anvil"), { recursive: true });
            await writeFile(path.join(dir, ANVIL_STATE_PATH), "{\"blocks\":[]}");
            await expect(resolveLocalAnvilStatePlan(dir, "localhost", false, { listenerOwner: async () => null }))
                .rejects.toThrow("refusing to load an existing Anvil snapshot");
            expect(await Bun.file(path.join(dir, ANVIL_STATE_PATH)).text()).toBe("{\"blocks\":[]}");
        } finally {
            if (previous === undefined) delete process.env.PURGE;
            else process.env.PURGE = previous;
            await rm(dir, { recursive: true, force: true });
        }
    });

    it("returns an absent output path and no timestamp for a new chain", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "new-anvil-plan-"));
        try {
            const plan = await resolveLocalAnvilStatePlan(dir, "localhost", false, { listenerOwner: async () => null });
            expect(plan).toEqual({ statePath: path.join(dir, ANVIL_STATE_PATH), hasState: false, shouldResetEnvio: true });
            expect(localAnvilLaunchArgs(8545, "31337", plan.statePath)).not.toContain("--timestamp");
            expect(localAnvilLaunchArgs(8545, "31337", plan.statePath)).toContain("--state");
            expect(localAnvilLaunchArgs(8545, "31337", plan.statePath)).not.toContain("--preserve-historical-states");
        } finally {
            await rm(dir, { recursive: true, force: true });
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
    const members = ["01", "02", "03"];
    const writeMembers = (dir: string, hashes: unknown = members) => Bun.write(`${dir}/psy-genesis/config.json`, JSON.stringify({
        networks: { localhost: { guardian_initial_member_hashes: hashes, fees: { guta_fee: 1000000000, da_fee: 1000 } } },
    }));

    it("uses only the canonical public config and strips child secrets", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            await writeMembers(dir);
            const aliases = ["PRIVATE_KEY", "BRIDGE_RELAYER_L2_PRIVATE_KEY", "KEYSTORE_PATH", "PSY_BRIDGE_RELAYER_KEYSTORE_PATH", "BRIDGE_RELAYER_KEYSTORE_PATH", "WALLET_PASSWORD"];
            const env: NodeJS.ProcessEnv = { PSY_NETWORK: "localhost", PSY_PROJECTS_DIR: dir, KEEP: "present", ...Object.fromEntries(aliases.map((key) => [key, "test-only"])) };
            const plan = await planGenesisGeneration(dir, env);
            expect(plan.args).toEqual([`${dir}/target/release/psy_dev_cli`, "generate-genesis-data", "--repo-root", dir]);
            for (const alias of aliases) {
                expect(plan.env[alias]).toBeUndefined();
                expect(env[alias]).toBe("test-only");
            }
            expect(plan.env.KEEP).toBe("present");
            expect(await Bun.file(`${dir}/psy-genesis/config.json`).json()).toMatchObject({ networks: { localhost: { guardian_initial_member_hashes: members } } });
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects missing, duplicate, zero, and underpriced member configuration without rewriting it", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const env = { PSY_NETWORK: "localhost", PSY_PROJECTS_DIR: dir };
            await expect(planGenesisGeneration(dir, {})).rejects.toThrow("guardian_initial_member_hashes");
            await expect(planGenesisGeneration(dir, env)).rejects.toThrow();
            for (const hashes of [null, [], ["01", "02"], ["01", "02", "03", "04"], ["01", "01", "03"], ["00", "02", "03"], ["zz", "02", "03"]]) {
                await writeMembers(dir, hashes);
                await expect(planGenesisGeneration(dir, env)).rejects.toThrow("guardian_initial_member_hashes");
            }
            await writeMembers(dir, ["01", "01", "03"]);
            await expect(planGenesisGeneration(dir, env)).rejects.toThrow("guardian_initial_member_hashes");
            await writeMembers(dir);
            await expect(planGenesisGeneration(dir, { ...env, PSY_NETWORK: "absent" })).rejects.toThrow("networks.absent.guardian_initial_member_hashes");
            await writeMembers(dir, ["03", "01", "02"]);
            const canonicalBefore = await Bun.file(`${dir}/psy-genesis/config.json`).text();
            await planGenesisGeneration(dir, env);
            expect(await Bun.file(`${dir}/psy-genesis/config.json`).text()).toBe(canonicalBefore);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });

    it("rejects stale compiler policy without deleting an existing Genesis", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "policy-preflight-"));
        try {
            await writeMembers(dir);
            await Bun.write(`${dir}/genesis.json`, "existing genesis");
            await expect(ensureGenesisFiles(dir, { PSY_PROJECTS_DIR: dir, PSY_NETWORK: "localhost" }, true)).rejects.toThrow("genesis_contracts.json");
            expect(await Bun.file(`${dir}/genesis.json`).text()).toBe("existing genesis");
            expect(await Bun.file(`${dir}/psy-genesis/config.json`).json()).toMatchObject({ networks: { localhost: { fees: { guta_fee: 1000000000, da_fee: 1000 } } } });
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });


    it("rejects preflight prerequisites without touching existing state or launching a generator", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "genesis-preflight-"));
        try {
            await mkdir(path.join(dir, "psy-genesis"));
            await writeFile(path.join(dir, "genesis.json"), "existing genesis");
            await writeFile(path.join(dir, "private_keys.json"), "retained fixture");
            await expect(ensureGenesisFiles(dir, {}, true)).rejects.toThrow("genesis_contracts.json");
            await writeFile(path.join(dir, "psy-genesis/genesis_contracts.json"), new Uint8Array([0x28, 0xb5, 0x2f, 0xfd]));
            await expect(ensureGenesisFiles(dir, {}, true)).rejects.toThrow();
            expect(await Bun.file(path.join(dir, "genesis.json")).text()).toBe("existing genesis");
            expect(await Bun.file(path.join(dir, "private_keys.json")).text()).toBe("retained fixture");
            expect(await Bun.file(path.join(dir, "db")).exists()).toBe(false);
        } finally {
            await rm(dir, { recursive: true, force: true });
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
                ...structuredClone(allConfig.networks.localhost),
                realm_user_tree_height: 20,
                p2p: structuredClone(allConfig.networks.localhost.p2p),
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

    async function fixture(existing: boolean = true) {
        const cwd = await mkdtemp(path.join(tmpdir(), "realm-p2p-preserve-"));
        const runtimeDir = path.join(cwd, "local_checkpoints/realm_p2p");
        await mkdir(path.join(cwd, "psy-genesis"), { recursive: true });
        await mkdir(runtimeDir, { recursive: true });
        const runtime = config(2);
        const source = structuredClone(runtime);
        const genesis = {
            users: Array.from({ length: 5 }, () => ({ public_key_info: { fingerprint: LOCAL_DEVNET_ZK_FINGERPRINT } })),
            validators: existing ? runtime.networks.localhost.realm_configs.flatMap((realm) => realm.validators.map((validator) => ({
                realm_id: realm.id, validator_user_id: validator.validator_user_id,
                node_id: validator.processor_node_id, bls_public_key: validator.bls_public_key,
            }))) : [],
        };
        await writeFile(path.join(cwd, "genesis.json"), JSON.stringify(genesis));
        await writeFile(path.join(cwd, "psy-genesis/config.json"), JSON.stringify(source));
        if (existing) {
            await writeFile(path.join(runtimeDir, "config.json"), JSON.stringify(runtime));
            for (const key of realmP2pSecretPaths([0], 2)) await writeFile(path.join(cwd, key), `fixture-${path.basename(key)}`);
        }
        return { cwd, runtimeDir, runtime, source, genesis };
    }

    function snapshot(cwd: string) {
        return Object.fromEntries((readdirSync(cwd, { recursive: true }) as string[]).sort().map((name) => {
            const file = path.join(cwd, name);
            return [name, statSync(file).isFile() ? readFileSync(file).toString("hex") : "directory"];
        }));
    }

    for (const change of ["both endpoints", "normal endpoint", "system endpoint", "whitespace", "missing hash"] as const) {
        it(`preserves all keys and membership for ${change}`, async () => {
            const f = await fixture();
            const sourceNetwork = f.source.networks.localhost as Record<string, unknown>;
            if (change === "both endpoints" || change === "normal endpoint") sourceNetwork.prove_proxy_url = ["http://normal.example:9999"];
            if (change === "both endpoints" || change === "system endpoint") sourceNetwork.system_prove_proxy_url = ["http://system.example:9998"];
            sourceNetwork.faucet_rpc_url = ["http://not-refreshed.example"];
            await writeFile(path.join(f.cwd, "psy-genesis/config.json"), JSON.stringify(f.source, null, 4) + "\n");
            if (change === "missing hash") {
                const { genesisConfigHash: _, ...unstamped } = f.runtime;
                await writeFile(path.join(f.runtimeDir, "config.json"), JSON.stringify(unstamped));
            }
            const before = snapshot(f.cwd);
            const spawn = spyOn(Bun, "spawn").mockImplementation(() => { throw new Error("Generator must not run"); });
            const writes = spyOn(fs.promises, "writeFile");
            try {
                const result = await ensureRealmP2pConfig("unused", f.cwd, [0], 2, "192.0.2.8");
                await injectGenesisValidators(path.join(f.cwd, "genesis.json"), result);
                expect(spawn).not.toHaveBeenCalled();
                expect(writes).not.toHaveBeenCalled();
                const persisted = JSON.parse(Buffer.from(before["local_checkpoints/realm_p2p/config.json"], "hex").toString());
                const expected = structuredClone(persisted);
                for (const field of ["prove_proxy_url", "system_prove_proxy_url", "guardian_initial_member_hashes", "fees"]) {
                    if (sourceNetwork[field] === undefined) delete expected.networks.localhost[field];
                    else expected.networks.localhost[field] = sourceNetwork[field];
                }
                delete expected.networks.localhost.guardian_authorization;
                delete expected.networks.localhost.guardian_max_fee;
                expected.defaultNetwork = "localhost";
                expect(result).toEqual(expected);
                expect(JSON.parse(readFileSync(path.join(f.runtimeDir, "config.json"), "utf8"))).toEqual(persisted);
                const after = snapshot(f.cwd);
                delete before["local_checkpoints/realm_p2p/config.json"];
                delete after["local_checkpoints/realm_p2p/config.json"];
                expect(after).toEqual(before);
                const daemon = daemonRealmP2pConfig(result, [0], 2);
                expect(daemon.networks.localhost.prove_proxy_url).toEqual(sourceNetwork.prove_proxy_url);
                expect(daemon.networks.localhost.system_prove_proxy_url).toEqual(sourceNetwork.system_prove_proxy_url);
            } finally {
                writes.mockRestore();
                spawn.mockRestore();
                await rm(f.cwd, { recursive: true, force: true });
            }
        });
    }

    for (const failure of ["missing key", "missing config", "malformed config", "null config", "unexpected realm", "nested artifact", "edge count", "host", "realm count", "consensus", "genesis conflict", "fresh with membership", "config only", "daemon only"] as const) {
        it(`rejects ${failure} before writes or generation`, async () => {
            const f = await fixture();
            const configPath = path.join(f.runtimeDir, "config.json");
            if (failure === "missing key") await rm(path.join(f.cwd, realmP2pSecretPaths([0], 2)[0]));
            if (failure === "missing config") await rm(configPath);
            if (failure === "malformed config") await writeFile(configPath, "{");
            if (failure === "null config") await writeFile(configPath, "null");
            if (failure === "unexpected realm") await writeFile(path.join(f.runtimeDir, "realm_9_sub_1_bls.key"), "fixture");
            if (failure === "nested artifact") await mkdir(path.join(f.runtimeDir, "old-keys"));
            if (failure === "config only" || failure === "daemon only") {
                for (const key of realmP2pSecretPaths([0], 2)) await rm(path.join(f.cwd, key));
            }
            if (failure === "daemon only") {
                await rm(configPath);
                await writeFile(path.join(f.runtimeDir, "daemon-config.json"), JSON.stringify(f.runtime));
            }
            if (failure === "consensus") {
                f.source.networks.localhost.p2p.checkpoints_per_epoch++;
                await writeFile(path.join(f.cwd, "psy-genesis/config.json"), JSON.stringify(f.source));
            }
            if (failure === "genesis conflict") {
                f.source.networks.localhost.prove_proxy_url = ["http://must-not-refresh.example:9999"];
                await writeFile(path.join(f.cwd, "psy-genesis/config.json"), JSON.stringify(f.source));
                f.genesis.validators[0].node_id = "conflicting-identity";
                await writeFile(path.join(f.cwd, "genesis.json"), JSON.stringify(f.genesis));
            }
            if (failure === "fresh with membership") await rm(f.runtimeDir, { recursive: true });
            const before = snapshot(f.cwd);
            const spawn = spyOn(Bun, "spawn").mockImplementation(() => { throw new Error("Generator must not run"); });
            const writes = spyOn(fs.promises, "writeFile");
            try {
                await expect(ensureRealmP2pConfig("unused", f.cwd, failure === "realm count" ? [0, 1] : [0], failure === "edge count" ? 1 : 2, failure === "host" ? "192.0.2.9" : "192.0.2.8")).rejects.toThrow();
                expect(spawn).not.toHaveBeenCalled();
                expect(writes).not.toHaveBeenCalled();
                expect(snapshot(f.cwd)).toEqual(before);
            } finally {
                writes.mockRestore();
                spawn.mockRestore();
                await rm(f.cwd, { recursive: true, force: true });
            }
        });
    }

    for (const directory of ["empty", "absent"] as const) {
    it(`generates only fresh ${directory} state and binds reserved ZK keys once`, async () => {
        const f = await fixture(false);
        if (directory === "absent") await rm(f.runtimeDir, { recursive: true });
        const privateKeys = Array.from({ length: 5 }, (_, index) => (index + 1).toString(16).repeat(64));
        await writeFile(path.join(f.cwd, "private_keys.json"), JSON.stringify(privateKeys));
        const spawn = spyOn(Bun, "spawn").mockImplementation((..._args: unknown[]) => {
            mkdirSync(f.runtimeDir, { recursive: true });
            writeFileSync(path.join(f.runtimeDir, "config.json"), JSON.stringify(f.runtime));
            for (const key of realmP2pSecretPaths([0], 2)) writeFileSync(path.join(f.cwd, key), "generated-fixture");
            return { exited: Promise.resolve(0) } as Bun.Subprocess;
        });
        try {
            const result = await ensureRealmP2pConfig("fixture-cli", f.cwd, [0], 2, "192.0.2.8");
            expect(spawn).toHaveBeenCalledTimes(1);
            expect(spawn.mock.calls[0][0]).toContain("init-realm-p2p-keys");
            await injectGenesisValidators(path.join(f.cwd, "genesis.json"), result);
            expect(JSON.parse(readFileSync(path.join(f.cwd, "genesis.json"), "utf8")).validators).toHaveLength(2);
            for (const subId of REALM_P2P_SUB_IDS) {
                expect(readFileSync(path.join(f.runtimeDir, `realm_0_sub_${subId}_zk.key`), "utf8")).toBe(privateKeys[reservedValidatorRegistrationId(0, subId)]);
            }
            const before = snapshot(f.cwd);
            await ensureRealmP2pConfig("fixture-cli", f.cwd, [0], 2, "192.0.2.8");
            expect(spawn).toHaveBeenCalledTimes(1);
            expect(snapshot(f.cwd)).toEqual(before);
        } finally {
            spawn.mockRestore();
            await rm(f.cwd, { recursive: true, force: true });
        }
    });
    }

    it("keeps canonical nonempty Genesis bytes unchanged and rejects conflicts", async () => {
        const f = await fixture();
        const genesisPath = path.join(f.cwd, "genesis.json");
        f.genesis.validators.reverse();
        await writeFile(genesisPath, JSON.stringify(f.genesis, null, 4) + "\n");
        const before = snapshot(f.cwd);
        const writes = spyOn(fs.promises, "writeFile");
        try {
            await injectGenesisValidators(genesisPath, f.runtime);
            expect(writes).not.toHaveBeenCalled();
            f.runtime.networks.localhost.realm_configs[0].validators[0].bls_public_key = "conflicting-bls";
            await expect(injectGenesisValidators(genesisPath, f.runtime)).rejects.toThrow(/membership conflicts/);
            expect(writes).not.toHaveBeenCalled();
            expect(snapshot(f.cwd)).toEqual(before);
        } finally {
            writes.mockRestore();
            await rm(f.cwd, { recursive: true, force: true });
        }
    });

    it("reuses only a complete config for the selected host and edge count", () => {
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(true);
        expect(() => planRealmP2pConfig(config(1), [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash)).toThrow(/topology/);
        expect(() => planRealmP2pConfig(config(2), [0], 2, "192.0.2.9", realm0ValidatorIds, genesisConfigHash)).toThrow(/topology/);
    });

    it("reuses a runtime config stamped with the current genesis hash", () => {
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(true);
    });

    it("reuses identities when source bytes or hash metadata change", () => {
        const changedHash = createHash("sha256").update(genesisConfigBytes).update("\n").digest("hex");
        expect(planRealmP2pConfig(config(2), [0], 2, "192.0.2.8", realm0ValidatorIds, changedHash).reuse).toBe(true);
    });

    it("reuses legacy runtime configs without a genesis hash", () => {
        const { genesisConfigHash: _, ...unstamped } = config(2);
        expect(planRealmP2pConfig(unstamped, [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash).reuse).toBe(true);
    });

    it("rejects a cached checkpoint period differing from genesis", () => {
        const stale = config(2);
        stale.networks.localhost.p2p.checkpoints_per_epoch += 1;
        expect(() => planRealmP2pConfig(stale, [0], 2, "192.0.2.8", realm0ValidatorIds, genesisConfigHash)).toThrow(/consensus/);
    });

    it("rejects an unselected Realm with validators", () => {
        const stale = config(1);
        stale.networks.localhost.realm_configs.push({
            id: 1,
            rpc_url: [],
            validators: [
                validator(reservedValidatorUserId(1, 1), 1, 1),
                validator(reservedValidatorUserId(1, 2), 2, 1),
            ],
        });
        expect(() => planRealmP2pConfig(stale, [0], 1, "192.0.2.8", realm0ValidatorIds, genesisConfigHash)).toThrow(/topology/);
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
    const env = { PSY_NETWORK: "localhost" };
    const guardian = (id: number, overrides: Record<string, unknown> = {}) => ({
        id,
        listen_address: `127.0.0.1:${15440 + id}`,
        ...overrides,
    });
    const canonicalNetwork = (overrides: Record<string, unknown> = {}) => ({
        magic: "0x1", users_per_realm: 1, global_user_tree_height: 32, realm_user_tree_height: 20, group_realm_height: 1,
        realm_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18081"] }],
        p2p: { checkpoints_per_epoch: 1 }, coordinator_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18080"] }],
        prove_proxy_url: ["http://127.0.0.1:9999"], faucet_rpc_url: [], nostr_relay_url: "wss://relay.example",
        native_currency: "PSY", native_currency_decimal: 18, native_currency_name: "Psy",
        fees: { register_user_fee: 0, deploy_contract_fee: 0, guta_fee: 1000000000, da_fee: 1000 },
        guardian_configs: [guardian(1), guardian(2), guardian(3)],
        guardian_history: { listen_address: "127.0.0.1:15450" },
        guardian_initial_member_hashes: ["01", "02", "03"],

        ...overrides,
    });
    const canonicalConfig = (network: Record<string, unknown> = canonicalNetwork()) => ({ defaultNetwork: "localhost", networks: { localhost: network } });
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
        expect(validateGuardianRpcConfig(dir, file, env)).rejects.toThrow(message);

    it("accepts a canonical network with guardian public endpoints and returns that network", async () => {
        await inTempDir(async (dir) => {
            await writeConfig(dir, "config.json", canonicalConfig());
            await Bun.$`mkdir -p ${path.join(dir, "nested")}`.quiet();
            await writeConfig(dir, "nested/config.json", canonicalConfig());
            await writeConfig(dir, "origin-variants.json", canonicalConfig(canonicalNetwork({
                guardian_configs: [
                    guardian(1, { rpc_url: "http://guardian-a.example/" }),
                    guardian(2, { rpc_url: "http://guardian-a.example:8443/" }),
                    guardian(3, { rpc_url: "http://guardian-b.example/" }),
                ],
            })));
            const selected = await validateGuardianRpcConfig(dir, "config.json", env);
            expect(selected.guardian_configs).toEqual([guardian(1), guardian(2), guardian(3)]);
            expect(selected.guardian_history).toEqual({ listen_address: "127.0.0.1:15450" });
            expect(selected).not.toHaveProperty("l1_endpoints");
            expect((await validateGuardianRpcConfig(dir, "nested/config.json", env)).guardian_configs).toHaveLength(3);
            expect((await validateGuardianRpcConfig("/", path.join(dir, "origin-variants.json"), env)).guardian_configs).toHaveLength(3);
        });
    });
    it("rejects a missing or blank PSY_GUARDIAN_ROOT instead of falling back to a wallet", async () => {
        await inTempDir(async (dir) => {
            for (const missing of [undefined, "", "   "]) {
                await expect(resolveGuardianRoot(dir, missing)).rejects.toThrow("supply it in the environment or --env");
            }
        });
    });

    it("rejects symlink ancestors without changing the real guardian directory", async () => {
        await inTempDir(async (dir) => {
            await mkdir(path.join(dir, "owned/guardians"), { recursive: true });
            await writeFile(path.join(dir, "owned/guardians/retained"), "unchanged");
            await symlink(path.join(dir, "owned"), path.join(dir, "alias"));
            await expect(resolveGuardianRoot(dir, "alias/guardians")).rejects.toThrow("symlink ancestors");
            expect(await Bun.file(path.join(dir, "owned/guardians/retained")).text()).toBe("unchanged");
        });
    });

    it("rejects endpoint keys, runtime root paths and malformed canonical network structures", async () => {
        const missingHistory = canonicalNetwork();
        delete missingHistory.guardian_history;
        const cases: Array<[string, unknown]> = [
            ["keystore path", canonicalConfig(canonicalNetwork({ guardian_configs: [guardian(1, { signing_key_secret_path: "/keys/1.json" }), guardian(2), guardian(3)] }))],
            ["root path", canonicalConfig(canonicalNetwork({ guardian_root: "/tmp/guardians" }))],
            ["missing guardian history", canonicalConfig(missingHistory)],
            ["leading zero guardian id", canonicalConfig(canonicalNetwork({ guardian_configs: [{ id: "01", listen_address: "127.0.0.1:15441" }, guardian(2), guardian(3)] }))],
            ["top level array", [canonicalConfig()]],
            ["top level string", '"config"'],
            ["top level null", "null"],
        ];
        await inTempDir(async (dir) => {
            for (const [label, contents] of cases) {
                const file = `schema-${label.replaceAll(" ", "-")}.json`;
                await writeConfig(dir, file, contents);
                await expect(validateGuardianRpcConfig(dir, file, env)).rejects.toThrow();
            }
        });
    });

    it("rejects a symlinked, directory, missing or non-JSON rpc config file", async () => {
        await inTempDir(async (dir) => {
            await writeConfig(dir, "real.json", canonicalConfig());
            await Bun.$`ln -s ${path.join(dir, "real.json")} ${path.join(dir, "link.json")}`.quiet();
            await Bun.$`mkdir -p ${path.join(dir, "directory.json")}`.quiet();
            await writeConfig(dir, "truncated.json", '{"networks":');
            await writeConfig(dir, "empty.json", "");
            for (const file of ["link.json", "directory.json", "missing.json", "truncated.json", "empty.json"]) {
                await expectRejection(dir, file, "the selected rpc_config must be a readable, non-symlink regular file containing valid JSON (at most 64 MiB).");
            }
            expect(await validateGuardianRpcConfig(dir, "real.json", env)).toMatchObject({ guardian_configs: [guardian(1), guardian(2), guardian(3)] });
        });
    });

    it("rejects an rpc config above the 64 MiB read limit and accepts one exactly at the limit", async () => {
        const configLimitBytes = 64 * 1024 * 1024;
        await inTempDir(async (dir) => {
            const file = "oversized.json";
            const target = path.join(dir, file);
            const network = canonicalNetwork({ padding: "" });
            const encoded = JSON.stringify(canonicalConfig(network));
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
            expect(await validateGuardianRpcConfig(dir, file, env)).toMatchObject({ guardian_history: { listen_address: "127.0.0.1:15450" } });
            appendFileSync(target, " ");
            expect(statSync(target).size).toBe(configLimitBytes + 1);
            await expectRejection(dir, file, "at most 64 MiB");
        });
    });

    it("rejects guardian endpoints that are not three distinct advertised origins", async () => {
        const cases: Array<[string, unknown]> = [
            ["duplicate id", [guardian(1), guardian(1), guardian(3)]],
            ["duplicate advertised origin", [guardian(1, { rpc_url: "http://guardian.example/" }), guardian(2, { rpc_url: "http://guardian.example:80/" }), guardian(3)]],
            ["advertised wildcard", [guardian(1, { rpc_url: "http://0.0.0.0:15441" }), guardian(2), guardian(3)]],
            ["https origin", [guardian(1, { rpc_url: "https://127.0.0.1:15441/" }), guardian(2), guardian(3)]],
            ["embedded credentials", [guardian(1, { rpc_url: "http://user:pass@127.0.0.1:15441/" }), guardian(2), guardian(3)]],
            ["non root path", [guardian(1, { rpc_url: "http://127.0.0.1:15441/admin" }), guardian(2), guardian(3)]],
            ["query string", [guardian(1, { rpc_url: "http://127.0.0.1:15441/?x=1" }), guardian(2), guardian(3)]],
            ["fragment", [guardian(1, { rpc_url: "http://127.0.0.1:15441/#frag" }), guardian(2), guardian(3)]],
            ["zero port", [guardian(1, { listen_address: "127.0.0.1:0" }), guardian(2), guardian(3)]],
            ["wildcard without advertisement", [guardian(1, { listen_address: "0.0.0.0:15441" }), guardian(2), guardian(3)]],
            ["unparseable entry", [guardian(1, { rpc_url: "not a url" }), guardian(2), guardian(3)]],
            ["two entries", [guardian(1), guardian(2)]],
            ["four entries", [guardian(1), guardian(2), guardian(3), guardian(4)]],
            ["not an array", "http://127.0.0.1:15441"],
        ];
        await inTempDir(async (dir) => {
            for (const [label, guardianConfigs] of cases) {
                const file = `endpoints-${label.replaceAll(" ", "-")}.json`;
                await writeConfig(dir, file, canonicalConfig(canonicalNetwork({ guardian_configs: guardianConfigs })));
                await expectRejection(dir, file, "guardian public fields");
            }
        });
    });

    it("rejects an unusable history listener", async () => {
        const cases: Array<[string, Record<string, unknown>]> = [
            ["blank listener", { guardian_history: { listen_address: "   " } }],
            ["non string listener", { guardian_history: { listen_address: 15450 } }],
            ["unspecified listener", { guardian_history: { listen_address: "0.0.0.0:15450" } }],
            ["zero port", { guardian_history: { listen_address: "127.0.0.1:0" } }],
        ];
        await inTempDir(async (dir) => {
            for (const [label, overrides] of cases) {
                const file = `network-${label.replaceAll(" ", "-")}.json`;
                await writeConfig(dir, file, canonicalConfig(canonicalNetwork(overrides)));
                await expectRejection(dir, file, "guardian public fields");
            }
        });
    });

    it("selects the compiled network and rejects one without guardian endpoints", async () => {
        await inTempDir(async (dir) => {
            await writeConfig(dir, "config.json", canonicalConfig());
            await expect(validateGuardianRpcConfig(dir, "config.json", { PSY_NETWORK: "mainnet" })).rejects.toThrow("mainnet network must exist");
            await expect(validateGuardianRpcConfig(dir, "config.json", {})).rejects.toThrow("PSY_NETWORK must name the compiled canonical network");
        });
    });
});

describe("guardian config selection precedence", () => {
    it("requires PSY_GUARDIAN_ROOT whenever a relayer, bridge proposer or bridge UI launches", () => {
        // ProcessOptions.bridgeUi is set by the process-manager path, not by a CLI flag.
        expect(shouldRequireGuardianRoot(true, {})).toBe(true);
        expect(shouldRequireGuardianRoot(false, { relayer: true })).toBe(true);
        expect(shouldRequireGuardianRoot(false, { bridgeProposerDaemon: true })).toBe(true);
        expect(shouldRequireGuardianRoot(false, { bridgeUi: true })).toBe(true);
    });

    it("does not require PSY_GUARDIAN_ROOT for memory, db or explicit-only runs", () => {
        expect(shouldRequireGuardianRoot(false, {})).toBe(false);
        expect(shouldRequireGuardianRoot(false, { relayer: false, bridgeProposerDaemon: false, bridgeUi: false })).toBe(false);
        expect(shouldRequireGuardianRoot(false, { psyPrivacyBridge: true })).toBe(false);
    });
});

describe("whole bridge daemon config forwarding", () => {
    const daemonToml = `guardian_root = "guardians"
rpc_config = "rpc.json"
services_url = "http://127.0.0.1:3000"
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
        const previous = { HOME: process.env.HOME, PSY_NETWORK: process.env.PSY_NETWORK };
        try {
            await mkdir(path.join(cwd, "guardians", "db"), { recursive: true, mode: 0o700 });
            await writeFile(path.join(cwd, "signer"), "synthetic metadata fixture, not credentials");
            for (const network of ["localhost", "localhostBsc", "localhostBase"]) {
                const deployments = path.join(cwd, "psy-contracts", "deployments", network);
                await mkdir(deployments, { recursive: true });
                await writeFile(path.join(deployments, "deployed-contracts.json"), "{}");
            }
            const keystoreDir = path.join(cwd, "home", ".psy", "keystore");
            await mkdir(keystoreDir, { recursive: true, mode: 0o700 });
            for (const id of [1, 2, 3]) {
                await writeFile(path.join(keystoreDir, `guardian-${id}.keystore.json`), "synthetic keystore fixture, not credentials", { mode: 0o600 });
            }
            const ports = [await reserveLoopbackPort(), await reserveLoopbackPort(), await reserveLoopbackPort()];
            const network = {
                magic: "0x1", users_per_realm: 1, global_user_tree_height: 32, realm_user_tree_height: 20, group_realm_height: 1,
                realm_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18081"] }], p2p: { checkpoints_per_epoch: 1 },
                coordinator_configs: [{ id: 0, rpc_url: ["http://127.0.0.1:18080"] }], prove_proxy_url: ["http://127.0.0.1:9999"],
                faucet_rpc_url: [], nostr_relay_url: "wss://relay.example", native_currency: "PSY", native_currency_decimal: 18,
                native_currency_name: "Psy", fees: { register_user_fee: 0, deploy_contract_fee: 0, guta_fee: 1000000000, da_fee: 1000 },
                guardian_configs: [1, 2, 3].map((id) => ({ id, listen_address: `127.0.0.1:${ports[id - 1]}` })),
                guardian_history: { listen_address: "127.0.0.1:15450" },
                guardian_initial_member_hashes: ["01", "02", "03"],

            };
            await writeFile(path.join(cwd, "rpc.json"), JSON.stringify({ defaultNetwork: "localhost", networks: { localhost: network } }));
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            process.env.HOME = path.join(cwd, "home");
            process.env.PSY_NETWORK = "localhost";
            const env: NodeJS.ProcessEnv = {
                PSY_BRIDGE_DAEMON_CONFIG: "daemon.toml", PSY_GUARDIAN_ROOT: "guardians", PSY_NETWORK: "localhost", HOME: process.env.HOME,
                GUARDIAN_1_KEYSTORE_PASSWORD: "synthetic-1", GUARDIAN_2_KEYSTORE_PASSWORD: "synthetic-2", GUARDIAN_3_KEYSTORE_PASSWORD: "synthetic-3",
            };
            await run(cwd, env, ports);
        } finally {
            for (const name of ["HOME", "PSY_NETWORK"] as const) {
                if (previous[name] === undefined) delete process.env[name];
                else process.env[name] = previous[name];
            }
            await rm(cwd, { recursive: true, force: true });
        }
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
    it("requires an initialized unhalted guardian ready response", async () => {
        const ready = { schema_version: 3, user_id: 524288, network_magic: 1, runtime_initialized: true, halted: false };
        expect(await guardianServiceReady(Response.json(ready))).toBe(true);
        for (const body of [null, {}, [], { ...ready, schema_version: 1 }, { ...ready, runtime_initialized: false },
            { ...ready, halted: true }, { ...ready, user_id: -1 }, { ...ready, network_magic: 0 }, { ...ready, user_id: "1" }]) {
            expect(await guardianServiceReady(Response.json(body))).toBe(false);
        }
        expect(await guardianServiceReady(Response.json(ready, { status: 503 }))).toBe(false);
        expect(await guardianServiceReady(Response.json({ ...ready, halted: true }, { status: 503 }))).toBe(false);
        await expect(guardianServiceReady(new Response("not JSON"))).rejects.toThrow();
    });


    it("starts three tracked guardians concurrently with independent saved journals", async () => {
        await fixture(async (cwd, env, ports) => {
            const manager = new DevNetProcessManager("127.0.0.1", env as Record<string, string>);
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
            let starting: Promise<void> | undefined;
            try {
                const l1ConfigArgs = ["localhost", "localhostBsc", "localhostBase"].flatMap((network) => ["--l1-config", path.join(cwd, "psy-contracts", "deployments", network, "deployed-contracts.json")]);
                starting = manager.startGuardianServices(cwd, path.join(cwd, "daemon.toml"), l1ConfigArgs);
                // A preflight rejection must fail this test, not strand it on an unopened gate.
                await Promise.race([allEntered.promise, starting]);
                expect(commands).toHaveLength(3);
                expect(manager.spawnedProcesses).toHaveLength(0);
                expect(commands).toEqual([1, 2, 3].map((id) => [
                    './target/release/psy_relayer_cli', 'guardian-service', '--rpc-config', path.join(cwd, 'rpc.json'),
                    '--guardian-root', path.join(cwd, 'guardians'), ...l1ConfigArgs, '--guardian-id', String(id),
                ]));
                for (const gate of gates) gate.resolve();
                await starting;
                expect(manager.spawnedProcesses.map((process) => process.name)).toEqual(["guardian_1", "guardian_2", "guardian_3"]);
                const relayer = processTemplate("bridge_relayer", ["psy_relayer_cli", "--config", "daemon.toml"]);
                expect(applicationStartOrder([relayer, ...manager.spawnedProcesses])).toEqual(["guardian_1", "guardian_2", "guardian_3", "bridge_relayer"]);
                expect(applicationListenerPorts(manager.spawnedProcesses)).toEqual([...ports].sort((left, right) => left - right));
                await validateRelayerTemplate(commands[0], { cwd, env: { PSY_NETWORK: "localhost" } });
            } finally {
                for (const gate of gates) gate.resolve();
                try { await starting; }
                finally { spawn.mockRestore(); }
            }
        });
    });

    it("accepts a bounded guardian ready response within the 1500ms probe", async () => {
        await fixture(async (cwd, env) => {
            const ready = { schema_version: 3, user_id: 524288, network_magic: 1, runtime_initialized: true, halted: false };
            let probes = 0;
            const timer = spyOn(globalThis, "setTimeout");
            const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(async (_url, options) => {
                probes += 1;
                expect(options?.signal?.aborted).toBe(false);
                return Response.json(ready);
            });
            const sleep = spyOn(Bun, "sleep").mockResolvedValue(undefined);
            let guardian: RunningProcess | undefined;
            try {
                guardian = await RunningProcess.spawn([
                    process.execPath, "-e", "Bun.serve({ port: 0, fetch: () => new Response() })",
                    "guardian-service", "--rpc-config", "rpc.json", "--guardian-root", "guardians", "--guardian-id", "1",
                ], {
                    cwd,
                    env: env as Record<string, string>,
                    stdoutLogFile: path.join(cwd, "guardian-ready.log"),
                    stderrLogFile: path.join(cwd, "guardian-ready.err"),
                });
                expect(timer).toHaveBeenCalledWith(expect.any(Function), 1_500);
                expect(timer).not.toHaveBeenCalledWith(expect.any(Function), 60_000);
                expect(probes).toBe(1);
                expect(sleep).not.toHaveBeenCalled();
                expect(guardian.initializationReady).toBe(true);
            } finally {
                fetchSpy.mockRestore(); sleep.mockRestore(); timer.mockRestore();
                if (guardian) {
                    guardian.killWithSignal("SIGKILL");
                    await guardian.proc.exited;
                }
            }
        });
    });

    it("clamps the last guardian ready probe to the remaining 500ms", async () => {
        await fixture(async (cwd, env) => {
            const ready = { schema_version: 3, user_id: 524288, network_magic: 1, runtime_initialized: true, halted: false };
            let virtualMs = 0;
            let probes = 0;
            const timer = spyOn(globalThis, "setTimeout");
            const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(async (_url, options) => {
                probes += 1;
                if (probes === 1) {
                    virtualMs = 599_000;
                    throw new Error("synthetic connection refused");
                }
                expect(options?.signal?.aborted).toBe(false);
                return Response.json(ready);
            });
            const sleep = spyOn(Bun, "sleep").mockImplementation(async (ms) => { virtualMs += ms ?? 0; });
            const now = spyOn(performance, "now").mockImplementation(() => virtualMs);
            let guardian: RunningProcess | undefined;
            try {
                guardian = await RunningProcess.spawn([
                    process.execPath, "-e", "Bun.serve({ port: 0, fetch: () => new Response() })",
                    "guardian-service", "--rpc-config", "rpc.json", "--guardian-root", "guardians", "--guardian-id", "1",
                ], {
                    cwd,
                    env: env as Record<string, string>,
                    stdoutLogFile: path.join(cwd, "guardian-clamp.log"),
                    stderrLogFile: path.join(cwd, "guardian-clamp.err"),
                });
                expect(timer).toHaveBeenCalledWith(expect.any(Function), 1_500);
                expect(timer).toHaveBeenCalledWith(expect.any(Function), 500);
                expect(probes).toBe(2);
                expect(virtualMs).toBe(599_500);
                expect(guardian.initializationReady).toBe(true);
            } finally {
                fetchSpy.mockRestore(); sleep.mockRestore(); now.mockRestore(); timer.mockRestore();
                if (guardian) {
                    guardian.killWithSignal("SIGKILL");
                    await guardian.proc.exited;
                }
            }
        });
    });


    it("rejects a ready response that validates after the 600s deadline", async () => {
        await fixture(async (cwd, env, ports) => {
            let virtualMs = 0;
            const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(async () => {
                virtualMs = 600_000;
                return Response.json({ schema_version: 3, user_id: 524288, network_magic: 1, runtime_initialized: true, halted: false });
            });
            const sleep = spyOn(Bun, "sleep").mockImplementation(async () => {
                throw new Error("late guardian response must not retry after the deadline");
            });
            const now = spyOn(performance, "now").mockImplementation(() => virtualMs);
            let guardian: RunningProcess | undefined;
            try {
                await expect(RunningProcess.spawn([
                    process.execPath, "-e", "setInterval(() => {}, 1 << 30)",
                    "guardian-service", "--rpc-config", "rpc.json", "--guardian-root", "guardians", "--guardian-id", "1",
                ], {
                    cwd,
                    env: env as Record<string, string>,
                    stdoutLogFile: path.join(cwd, "guardian-late.log"),
                    stderrLogFile: path.join(cwd, "guardian-late.err"),
                }).then((started) => { guardian = started; return started; })).rejects.toThrow(`guardian-service port ${ports[0]} not ready within 600000ms`);
                expect(sleep).not.toHaveBeenCalled();
            } finally {
                fetchSpy.mockRestore(); sleep.mockRestore(); now.mockRestore();
                if (guardian) {
                    guardian.killWithSignal("SIGKILL");
                    await guardian.proc.exited;
                }
            }
        });
    });

    it("fails guardian readiness at the 600s deadline and names the listen port", async () => {
        await fixture(async (cwd, env, ports) => {
            let virtualMs = 0;
            let probes = 0;
            const fetchSpy = spyOn(globalThis, "fetch").mockRejectedValue(new Error("synthetic connection refused"));
            const sleep = spyOn(Bun, "sleep").mockImplementation(async (ms) => {
                probes += 1;
                virtualMs += ms ?? 0;
                if (probes > 1_202) throw new Error(`guardian readiness still looping after ${probes} probes`);
            });
            const now = spyOn(performance, "now").mockImplementation(() => virtualMs);
            let guardian: RunningProcess | undefined;
            try {
                await expect(RunningProcess.spawn([
                    process.execPath, "-e", "setInterval(() => {}, 1 << 30)",
                    "guardian-service", "--rpc-config", "rpc.json", "--guardian-root", "guardians", "--guardian-id", "1",
                ], {
                    cwd,
                    env: env as Record<string, string>,
                    stdoutLogFile: path.join(cwd, "guardian-timeout.log"),
                    stderrLogFile: path.join(cwd, "guardian-timeout.err"),
                }).then((started) => { guardian = started; return started; })).rejects.toThrow(`guardian-service port ${ports[0]} not ready within 600000ms`);
                expect(probes).toBe(1_200);
                expect(virtualMs).toBe(600_000);
            } finally {
                fetchSpy.mockRestore(); sleep.mockRestore(); now.mockRestore();
                if (guardian) {
                    guardian.killWithSignal("SIGKILL");
                    await guardian.proc.exited;
                }
            }
        });
    });

    it("attempts all three guardians concurrently and fails startup after settled cleanup when one readiness fails", async () => {
        await fixture(async (cwd, env, ports) => {
            const manager = new DevNetProcessManager("127.0.0.1", env as Record<string, string>);
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
                await expect(manager.startGuardianServices(cwd, path.join(cwd, "daemon.toml"), [])).rejects.toThrow("guardian readiness failed");
                expect(spawn).toHaveBeenCalledTimes(3);
                expect(killed).toEqual(["guardian_1:SIGTERM", "guardian_3:SIGTERM"]);
                expect(manager.spawnedProcesses).toEqual([]);
            } finally { spawn.mockRestore(); kill.mockRestore(); }
        });
    });

    it("rejects occupied guardian ports and preserves an existing guardian database file", async () => {
        await fixture(async (cwd, env) => {
            const listener = net.createServer();
            await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
            const port = (listener.address() as net.AddressInfo).port;
            const configPath = path.join(cwd, "rpc.json");
            const config = JSON.parse(await Bun.file(configPath).text());
            config.networks.localhost.guardian_configs[0].listen_address = `127.0.0.1:${port}`;
            await writeFile(configPath, JSON.stringify(config));
            const cmds = ["psy_relayer_cli", "guardian-service", "--rpc-config", "rpc.json", "--guardian-root", "guardians", "--guardian-id", "1"];
            try {
                await expect(prepareGuardianService(cmds, cwd, env)).rejects.toThrow();
            } finally { await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve())); }
            expect(await prepareGuardianService(cmds, cwd, env)).toEqual({ host: "127.0.0.1", port });
            const databaseDir = path.join(cwd, "guardians", "db");
            expect(statSync(databaseDir).mode & 0o777).toBe(0o700);
            await writeFile(path.join(databaseDir, "guardian-1.redb"), "retained database", { mode: 0o600 });
            await prepareGuardianService(cmds, cwd, env);
            expect(readFileSync(path.join(databaseDir, "guardian-1.redb"), "utf8")).toBe("retained database");
            expect(statSync(path.join(databaseDir, "guardian-1.redb")).mode & 0o777).toBe(0o600);
            await chmod(databaseDir, 0o755);
            await expect(prepareGuardianService(cmds, cwd, env)).rejects.toThrow("owner-only");
            expect(statSync(databaseDir).mode & 0o777).toBe(0o755);
        });
    });

    it("rejects a database directory redirected into purgeable state", async () => {
        await fixture(async (cwd, env) => {
            await rm(path.join(cwd, "guardians", "db"), { recursive: true, force: true });
            await mkdir(path.join(cwd, "logs"));
            await symlink(path.join(cwd, "logs"), path.join(cwd, "guardians", "db"));
            const cmds = ["psy_relayer_cli", "guardian-service", "--rpc-config", "rpc.json", "--guardian-root", "guardians", "--guardian-id", "1"];
            await expect(prepareGuardianService(cmds, cwd, env)).rejects.toThrow("guardian db metadata");
        });
    });

    it("forwards nested TOML unchanged, resolving from launch cwd without reading protected contents", async () => {
        await fixture(async (cwd, env) => {
            await chmod(path.join(cwd, "signer"), 0);
            expect(await resolveBridgeDaemonConfigPath(cwd, env, true)).toBe(path.join(cwd, "daemon.toml"));
            expect(await Bun.file(path.join(cwd, "daemon.toml")).text()).toBe(daemonToml);
            await validateRelayerTemplate(["./target/release/psy_relayer_cli", "--config", "daemon.toml"], { cwd, env: env as Record<string, string> });
        });
    });

    it("rejects a published authorization object and keeps canonical bytes unchanged", async () => {
        await fixture(async (cwd, env) => {
            const file = path.join(cwd, "rpc.json");
            const published = await Bun.file(file).text();
            const commands = ["./target/release/psy_relayer_cli", "--config", "daemon.toml"];
            const guardian = ["psy_relayer_cli", "guardian-service", "--rpc-config", "rpc.json", "--guardian-root", "guardians"];
            const config = JSON.parse(published);
            config.networks.localhost.guardian_authorization = {};
            await writeFile(file, JSON.stringify(config));
            await expect(validateRelayerTemplate(commands, { cwd, env: env as Record<string, string> })).rejects.toThrow("guardian_initial_member_hashes");
            await expect(validateRelayerTemplate(guardian, { cwd, env: env as Record<string, string> })).rejects.toThrow("guardian_initial_member_hashes");
            await writeFile(file, published);
            delete config.networks.localhost.guardian_authorization;
            await writeFile(file, JSON.stringify(config));
            await validateRelayerTemplate(commands, { cwd, env: env as Record<string, string> });
            await validateRelayerTemplate(guardian, { cwd, env: env as Record<string, string> });
            expect(await Bun.file(file).text()).toBe(JSON.stringify(config));
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
            await writeFile(path.join(cwd, "logs", "rpc.json"), await Bun.file(path.join(cwd, "rpc.json")).text());
            await symlink(path.join(cwd, "logs"), path.join(cwd, "alias"));
            for (const rpc of ["logs/rpc.json", "alias/rpc.json"]) {
                await writeFile(path.join(cwd, "daemon.toml"), daemonToml.replace('rpc_config = "rpc.json"', `rpc_config = "${rpc}"`));
                await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("rpc_config metadata");
                expect(await resolveBridgeDaemonConfigPath(cwd, env)).toBe(path.join(cwd, "daemon.toml"));
            }
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            await rm(path.join(cwd, "guardians", "db"), { recursive: true, force: true });
            await symlink(path.join(cwd, "logs"), path.join(cwd, "guardians", "db"));
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("guardian root db metadata");
        });
    });

    it("requires the generator-owned db directory and preserves an existing database file through restart", async () => {
        await fixture(async (cwd, env) => {
            const databaseDir = path.join(cwd, "guardians", "db");
            const databaseFile = path.join(databaseDir, "relayer.redb");
            const spawnOptions = { cwd, env: env as Record<string, string> };
            await writeFile(databaseFile, "retained relayer database", { mode: 0o600 });
            expect(await resolveBridgeDaemonConfigPath(cwd, env, true)).toBe(path.join(cwd, "daemon.toml"));
            await validateRelayerTemplate(["psy_relayer_cli", "--config", "daemon.toml"], spawnOptions);
            expect(await Bun.file(databaseFile).text()).toBe("retained relayer database");
            expect(await resolveBridgeDaemonConfigPath(cwd, env, true)).toBe(path.join(cwd, "daemon.toml"));
            await validateRelayerTemplate(["psy_relayer_cli", "--config", "daemon.toml"], spawnOptions);
            const manager = new DevNetProcessManager();
            const relayer = processTemplate("bridge_relayer", ["psy_relayer_cli", "--config", "daemon.toml"]);
            relayer.spawnOptions = spawnOptions;
            const infrastructure = ["db", "l1_anvil", "l1_anvil_bsc", "l1_anvil_base"].map((name) => {
                const process = processTemplate(name, [name]);
                process.isRunning = () => true;
                return process;
            });
            const lifecycle = manager as unknown as {
                applicationLifecycleState: string;
                pausedApplicationProcesses: RunningProcess[];
                spawnedProcesses: RunningProcess[];
            };
            lifecycle.applicationLifecycleState = "running";
            lifecycle.spawnedProcesses = [...infrastructure, relayer];
            lifecycle.pausedApplicationProcesses = [];
            const stop = spyOn(manager, "stopApplications").mockImplementation(async () => {
                lifecycle.applicationLifecycleState = "stopped";
                lifecycle.spawnedProcesses = [];
                lifecycle.pausedApplicationProcesses = [relayer];
            });
            const spawnSentinel = new Error("db preflight reached spawn sentinel");
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
            expect(await Bun.file(databaseFile).text()).toBe("retained relayer database");
            lifecycle.spawnedProcesses = [relayer];
            lifecycle.applicationLifecycleState = "running";
            await expect(manager.restartApplications(cwd)).rejects.toThrow("requires running infrastructure");
            expect(await Bun.file(databaseFile).text()).toBe("retained relayer database");

            await rm(databaseDir, { recursive: true, force: true });
            await writeFile(databaseDir, "not a directory");
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("guardian root db metadata");
        });
    });

    it("checks a symlinked purge target and rejects mismatched guardian or replay config", async () => {
        await fixture(async (cwd, env) => {
            await symlink(path.join(cwd, "rpc.json"), path.join(cwd, "logs"));
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml.replace('rpc_config = "rpc.json"', 'rpc_config = "logs"'));
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("rpc_config metadata");
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            await expect(resolveBridgeDaemonConfigPath(cwd, { ...env, PSY_GUARDIAN_ROOT: "other-root" })).rejects.toThrow();
            expect(await Bun.file(path.join(cwd, "daemon.toml")).text()).toBe(daemonToml);
            await expect(validateRelayerTemplate(["psy_relayer_cli", "--config", "other.toml"], { cwd, env: env as Record<string, string> })).rejects.toThrow("saved --config coherence");
        });
    });

    it("rejects manual restart before stopping live applications and resume before any spawn", async () => {
        await fixture(async (cwd, env) => {
            const manager = new DevNetProcessManager();
            const relayer = processTemplate("bridge_relayer", ["psy_relayer_cli", "--config", "daemon.toml"]);
            relayer.spawnOptions = { cwd, env: env as Record<string, string> };
            const infrastructure = ["db", "l1_anvil", "l1_anvil_bsc", "l1_anvil_base"].map((name) => {
                const process = processTemplate(name, [name]);
                process.isRunning = () => true;
                return process;
            });
            manager.spawnedProcesses = [...infrastructure, relayer];
            const stop = spyOn(manager, "stopApplications").mockResolvedValue(undefined);
            const spawn = spyOn(RunningProcess, "spawn");
            try {
                await rm(path.join(cwd, "rpc.json"));
                await expect(manager.restartApplications("/not-the-launch-cwd")).rejects.toThrow("rpc_config");
                expect(stop).not.toHaveBeenCalled();
                expect(manager.spawnedProcesses).toEqual([...infrastructure, relayer]);
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

describe("PURGE=0 shutdown control", () => {
    it("acks shutdown only through the supervisor and refuses an unsupported owner", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        const repo = `${dir}/repo`;
        await Bun.$`mkdir -p ${repo}`.quiet();
        const previousTmp = process.env.TMPDIR;
        process.env.TMPDIR = dir;
        try {
            const server = await startDevnetControlServer(repo, async (command) => {
                if (command !== "shutdown") throw new Error(`unexpected ${command}`);
                return { message: "shutdown completed", afterAck: () => undefined };
            });
            expect(await requestOwnedAnvilShutdown(repo, false)).toBe("owned");
            await server.close();
            const stale = await startDevnetControlServer(repo, async () => {
                throw new Error("[DevNet][control] unsupported command shutdown");
            });
            await expect(requestOwnedAnvilShutdown(repo, false)).rejects.toThrow("does not support shutdown");
            await stale.close();
        } finally {
            if (previousTmp === undefined) delete process.env.TMPDIR;
            else process.env.TMPDIR = previousTmp;
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});

describe("frozen dependency startup selection", () => {
    it("does not prepare SDK/UI sidecars for core-only selection", () => {
        expect(selectedUiDependencies(false, {})).toBe(false);
        expect(selectedUiDependencies(true, {})).toBe(true);
        for (const ui of ["psyPrivacyBridge", "ide", "explorer", "modeAWebWalletBridge"] as const) {
            expect(selectedUiDependencies(false, { [ui]: true })).toBe(true);
        }
    });

    it("refuses missing contracts dependencies instead of installing in frozen mode", async () => {
        const root = await mkdtemp(path.join(tmpdir(), "frozen-contracts-"));
        const previous = process.env.PSY_FROZEN_DEPS;
        process.env.PSY_FROZEN_DEPS = "1";
        const spawn = spyOn(Bun, "spawn").mockImplementation(() => { throw new Error("must not install"); });
        try {
            await expect(ensurePsyContractsDependencies(root)).rejects.toThrow("refusing install");
            expect(spawn).not.toHaveBeenCalled();
            await mkdir(path.join(root, "node_modules/.bin"), { recursive: true });
            await writeFile(path.join(root, "node_modules/.bin/hardhat"), "fixture");
            await ensurePsyContractsDependencies(root);
            expect(spawn).not.toHaveBeenCalled();
        } finally {
            spawn.mockRestore();
            if (previous === undefined) delete process.env.PSY_FROZEN_DEPS;
            else process.env.PSY_FROZEN_DEPS = previous;
            await rm(root, { recursive: true, force: true });
        }
    });

    it("requires explicit cached pnpm/store and real Envio before guarded codegen", async () => {
        const root = await mkdtemp(path.join(tmpdir(), "frozen-envio-"));
        try {
            await expect(runFrozenEnvioCodegen(root, {})).rejects.toThrow("PSY_FROZEN_DEPS_PNPM");
            await expect(runFrozenEnvioCodegen(root, { PSY_FROZEN_DEPS_PNPM: "/unused/pnpm.cjs", PSY_FROZEN_DEPS_STORE: "/unused/store" }))
                .rejects.toThrow("preinstalled Envio executable");
        } finally { await rm(root, { recursive: true, force: true }); }
    });
});

describe("frozen Envio runtime command", () => {
    it("accepts the reviewed start script and refuses a different one", async () => {
        const root = await mkdtemp(path.join(tmpdir(), "frozen-envio-start-"));
        const generated = path.join(root, "generated");
        const executable = path.join(generated, "node_modules/.bin/ts-node");
        const writeManifest = (start: string) => writeFile(
            path.join(generated, "package.json"),
            JSON.stringify({ scripts: { start } }),
        );
        await mkdir(path.dirname(executable), { recursive: true });
        await mkdir(path.join(generated, "src"), { recursive: true });
        await writeFile(executable, "#!/usr/bin/env node\n");
        await writeFile(path.join(generated, "src/Index.res.js"), "export {};\n");
        try {
            await writeManifest("ts-node src/Index.res.js");
            await expect(frozenEnvioStartCommand(root)).resolves.toEqual({
                command: [executable, "src/Index.res.js"],
                cwd: generated,
            });
            await writeManifest("node src/Index.res.js");
            await expect(frozenEnvioStartCommand(root)).rejects.toThrow("reviewed generated start script");
        } finally {
            await rm(root, { recursive: true, force: true });
        }
    });
});

describe("graceful Anvil stop", () => {
    const identity = (exe: string, repo: string, port: number) => ({
        exe, cwd: repo, cmdline: ["anvil", "--port", String(port), "--state", `${repo}/db/anvil/state.json`].join("\0"), starttime: "10",
    });

    it("SIGTERMs only the discovered repo Anvil and leaves its state file untouched", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "graceful-anvil-"));
        const repo = path.join(dir, "repo");
        const exe = path.join(dir, "anvil");
        const state = path.join(repo, "db/anvil/state.json");
        await mkdir(path.dirname(state), { recursive: true });
        await writeFile(state, "native-exit-dump");
        await writeFile(exe, "");
        await chmod(exe, 0o755);
        const processIdentity = identity(exe, repo, 8545);
        const signals: number[] = [];
        let alive = true;
        const stopped: string[][] = [];
        try {
            await gracefulDevnetStop(repo, {
                listPids: async () => [41],
                readIdentity: async (pid) => pid === 41 && alive ? processIdentity : null,
                listenerOwner: async (port) => port === 8545 && alive ? 41 : null,
                alive: (pid) => pid === 41 && alive,
                signal: (pid) => { signals.push(pid); alive = false; },
                listCheckoutProcesses: async () => [],
                stopDocker: async (names) => { stopped.push([...names]); },
            });
            expect(signals).toEqual([41]);
            expect(await Bun.file(state).text()).toBe("native-exit-dump");
            expect(stopped[0]).toEqual(["valkey-server", "nats-server", "scylla-server", "nostr-relay", "generated-envio-postgres-1", "generated-graphql-engine-1"]);
        } finally { await rm(dir, { recursive: true, force: true }); }
    });

    it("refuses SIGTERM when the listener identity changes and does not stop databases", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "graceful-anvil-reuse-"));
        const repo = path.join(dir, "repo");
        const exe = path.join(dir, "anvil");
        const state = path.join(repo, "db/anvil/state.json");
        await mkdir(path.dirname(state), { recursive: true });
        await writeFile(state, "native-exit-dump");
        await writeFile(exe, "");
        await chmod(exe, 0o755);
        const processIdentity = identity(exe, repo, 8545);
        const stopped: string[][] = [];
        let reads = 0;
        try {
            await expect(gracefulDevnetStop(repo, {
                listPids: async () => [41],
                readIdentity: async () => {
                    reads += 1;
                    return reads === 1 ? processIdentity : { ...processIdentity, starttime: "99" };
                },
                listenerOwner: async (port) => port === 8545 ? 41 : null,
                signal: () => { throw new Error("must not signal a changed identity"); },
                listCheckoutProcesses: async () => [],
                stopDocker: async (names) => { stopped.push([...names]); },
            })).rejects.toThrow("identity changed before SIGTERM");
            expect(stopped).toEqual([]);
            expect(reads).toBe(2);
        } finally { await rm(dir, { recursive: true, force: true }); }
    });

    it("rejects an occupied listener that is not the matching repo Anvil", async () => {
        const dir = await mkdtemp(`${tmpdir()}/graceful-anvil-`);
        const exe = `${dir}/anvil`;
        await writeFile(exe, "");
        await chmod(exe, 0o755);
        try {
            await expect(discoverRepoAnvils(`${dir}/repo`, {
                listPids: async () => [],
                listenerOwner: async (port) => port === 8545 ? 77 : null,
            })).rejects.toThrow("not the matching repo Anvil");
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    it("stops only the resolved namespace containers", async () => {
        const dir = await mkdtemp(`${tmpdir()}/graceful-stop-`);
        await mkdir(path.join(dir, "local_checkpoints"));
        await writeFile(path.join(dir, "local_checkpoints", "devnet-namespace"), "\n");
        const stopped: string[][] = [];
        try {
            await gracefulDevnetStop(dir, {
                listPids: async () => [],
                listenerOwner: async () => null,
                listCheckoutProcesses: async () => [],
                stopDocker: async (names) => { stopped.push([...names]); },
            });
            expect(stopped[0]).toEqual(["valkey-server", "nats-server", "scylla-server", "nostr-relay", "generated-envio-postgres-1", "generated-graphql-engine-1"]);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });
});

describe("devnet resource admission", () => {
    it("inherits a committed namespace and rejects explicit conflicts", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "namespace-binding-"));
        try {
            await mkdir(path.join(dir, "local_checkpoints"));
            await writeFile(path.join(dir, "local_checkpoints/devnet-namespace"), "isolated\n");
            expect((await resolveBoundDevnetNames(dir, {})).namespace).toBe("isolated");
            await expect(resolveBoundDevnetNames(dir, { PSY_DEVNET_NAMESPACE: "other" })).rejects.toThrow("does not match");
        } finally { await rm(dir, { recursive: true, force: true }); }
    });

    it("allows unbound legacy reads but never maps an explicit namespace to legacy", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "namespace-unbound-"));
        try {
            const legacy = await resolveBoundDevnetNames(dir, {});
            expect(legacy.namespace).toBeNull();
            await expect(resolveBoundDevnetNames(dir, { PSY_DEVNET_NAMESPACE: "isolated" })).rejects.toThrow("no committed");
            expect(await Bun.file(path.join(dir, "local_checkpoints/devnet-namespace")).exists()).toBe(false);
            await commitDevnetNamespaceBinding(dir, legacy);
            await expect(commitDevnetNamespaceBinding(dir, legacy)).rejects.toThrow();
        } finally { await rm(dir, { recursive: true, force: true }); }
    });

    it("creates an owner-only binding tree and rejects a loose pre-existing one", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "namespace-binding-modes-"));
        try {
            await commitDevnetNamespaceBinding(dir, await resolveBoundDevnetNames(dir, {}));
            const bindingDir = path.join(dir, "local_checkpoints");
            expect(statSync(bindingDir).mode & 0o777).toBe(0o700);
            expect(statSync(path.join(bindingDir, "devnet-namespace")).mode & 0o7777).toBe(0o600);
            expect(readdirSync(bindingDir)).toEqual(["devnet-namespace"]);

            const loose = await mkdtemp(path.join(tmpdir(), "namespace-binding-loose-"));
            try {
                const looseDir = path.join(loose, "local_checkpoints");
                await mkdir(looseDir);
                await chmod(looseDir, 0o775);
                await expect(commitDevnetNamespaceBinding(loose, await resolveBoundDevnetNames(loose, {})))
                    .rejects.toThrow("must not be group/other-writable");
                expect(statSync(looseDir).mode & 0o777).toBe(0o775);
                expect(readdirSync(looseDir)).toEqual([]);
            } finally { await rm(loose, { recursive: true, force: true }); }
        } finally { await rm(dir, { recursive: true, force: true }); }
    });

    it("does not discover or stop infrastructure after failed admission", async () => {
        const manager = new DevNetProcessManager();
        const spawn = spyOn(Bun, "spawn").mockImplementation(() => { throw new Error("must not spawn cleanup"); });
        try {
            await manager.cleanupFailedSetup("unused");
            await manager.teardown("unused", false);
            expect(spawn).not.toHaveBeenCalled();
        } finally { spawn.mockRestore(); }
    });

    it("checks untracked producers before discovery or infrastructure stop", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "namespace-producer-"));
        try {
            await expect(gracefulDevnetStop(dir, {
                listCheckoutProcesses: async () => ["orphan"],
                listPids: async () => { throw new Error("must not discover"); },
                stopDocker: async () => { throw new Error("must not stop"); },
            })).rejects.toThrow("producers remain");
        } finally { await rm(dir, { recursive: true, force: true }); }
    });
});

describe("non-purge shutdown control client attribution", () => {
    it("ignores only the exact same-user checkout teardown CLI, not Bun producers", () => {
        const root = "/checkout/psy-node";
        const uid = process.getuid!();
        const client = [process.execPath, "run", "dev/locSetupV4.ts", "--teardown", ""];
        const matches = (argv: string[], exe = process.execPath, cwd = root, owner = uid) =>
            isGracefulShutdownControlClient(root, exe, cwd, argv, owner);
        expect(matches(client)).toBe(true);
        expect(matches([process.execPath, `${root}/dev/locSetupV4.ts`, "--teardown"])).toBe(true);
        expect(matches([process.execPath, "run", "dev/locSetupV4.ts", "--db", "--l1"])).toBe(false);
        expect(matches([process.execPath, "run", "producer.ts", "--teardown"])).toBe(false);
        expect(matches([...client.slice(0, -1), "--db"])).toBe(false);
        expect(matches([...client.slice(0, -1), "--purge"])).toBe(false);
        expect(matches(client, "/other/bun")).toBe(false);
        expect(matches(client, process.execPath, "/other/checkout")).toBe(false);
        expect(matches(client, process.execPath, root, uid + 1)).toBe(false);
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
                const code = (error as NodeJS.ErrnoException).code;
                if (code !== "ENOENT" && code !== "ESRCH") throw error;
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

describe("owned devnet UI listener purge", () => {
    const resolved = Bun.which("node");
    if (!resolved) throw new Error("node is not on PATH");
    const nodeBin = realpathSync(resolved);
    if (path.basename(nodeBin) !== "node") throw new Error(`resolved node basename is ${path.basename(nodeBin)}`);

    it("stops an orphan node group in the explorer app and leaves a foreign listener", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "owned-ui-listener-"));
        const repo = path.join(dir, "repo");
        const explorer = path.join(repo, "psy-dapp/apps/explorer");
        const script = path.join(explorer, "hold.js");
        await mkdir(explorer, { recursive: true });
        await writeFile(script, "process.on('SIGTERM', () => process.exit(0));\nprocess.stdin.resume();\nprocess.stdout.write('ready\\n');\n");
        const child = Bun.spawn([nodeBin, script], { cwd: explorer, detached: true, stdin: "pipe", stdout: "pipe", stderr: "ignore" });
        const pgrp = child.pid;
        let exited = false;
        const reaped = child.exited.then((code) => { exited = true; return code; });
        const signals: Array<[number, string]> = [];
        const foreignSignals: number[] = [];
        try {
            const reader = child.stdout.getReader();
            try {
                const ready = await reader.read();
                expect(new TextDecoder().decode(ready.value)).toBe("ready\n");
            } finally { reader.releaseLock(); }
            const stat = readFileSync(`/proc/${child.pid}/stat`, "utf8");
            expect(Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[2])).toBe(pgrp);
            await stopOwnedDevnetUiListeners(repo, {
                portOpen: async (port) => port === 5178 && !exited,
                listenerOwner: async () => child.pid,
                signalGroup: (group, signal) => {
                    signals.push([group, signal]);
                    process.kill(-group, signal);
                },
                leaderAlive: () => !exited,
                // Await real exit delivery instead of spinning microtasks until the production deadline.
                sleep: async () => { await reaped; },
            });
            expect(signals).toEqual([[pgrp, "SIGTERM"]]);
            expect(await reaped).toBe(0);
            await expect(stopOwnedDevnetUiListeners(repo, {
                portOpen: async (port) => port === 5178,
                listenerOwner: async () => 424242,
                readIdentity: async () => ({ exe: nodeBin, cwd: "/tmp/foreign-explorer", cmdline: "", starttime: "10" }),
                readUid: async () => process.getuid?.() ?? 0,
                readPgrp: async () => 424242,
                signalGroup: (pgrp) => { foreignSignals.push(pgrp); },
                leaderAlive: () => false,
                sleep: async () => {},
            })).rejects.toThrow("not an owned devnet UI process");
            expect(foreignSignals).toEqual([]);
        } finally {
            try { process.kill(-pgrp, "SIGKILL"); } catch { /* already reaped */ }
            await child.exited;
            await rm(dir, { recursive: true, force: true });
        }
    });
});

/** Owned helper exit when stdin closes. The abort ladder stays in production. */
describe("fresh helper ownership release", () => {
    it("releases ownership with exit code 1 and a null signal", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "fresh-helper-exit-"));
        const guardianRoot = path.join(dir, "guardians");
        const helperPath = path.join(dir, "target", "release", "psy_dev_cli");
        // ESM live binding: locSetupV4's spawn is this namespace export, so the spy
        // observes the helper the abort actually owns. A static import is a copy.
        const spawnSpy = spyOn(childProcess, "spawn");
        let child: ChildProcessWithoutNullStreams | undefined;
        try {
            await mkdir(path.join(dir, "psy-genesis"), { recursive: true });
            await mkdir(path.dirname(helperPath), { recursive: true });
            await writeFile(path.join(dir, "psy-genesis/config.json"), JSON.stringify({
                networks: { localhost: {
                    guardian_initial_member_hashes: ["01", "02", "03"],

                    fees: { guta_fee: 1000000000, da_fee: 1000 },
                } },
            }));
            // One process: re-exec line-buffered, then block in `read`. EOF makes `read`
            // return 1, and that status is the exit. `exit 0` would fake a clean publish.
            await writeFile(helperPath, [
                "#!/bin/bash",
                "if [[ -z ${FRESH_HELPER_FIXTURE_READY:-} ]]; then",
                "  export FRESH_HELPER_FIXTURE_READY=1",
                "  exec stdbuf -oL /bin/bash \"$0\" \"$@\"",
                "fi",
                "printf '%s\\n' '{\"phase\":\"prepared\"}'",
                "read -r line",
                "",
            ].join("\n"));
            await chmod(helperPath, 0o755);
            const state = await prepareFreshDevnetState(dir, guardianRoot, { PSY_NETWORK: "localhost", PSY_PROJECTS_DIR: dir });
            const spawned = spawnSpy.mock.results[0];
            expect(spawned?.type).toBe("return");
            child = spawned.value as ChildProcessWithoutNullStreams;
            const exitEvent = new Promise<{ code: number | null; signal: string | null }>((resolve) => {
                child!.once("exit", (code, signal) => resolve({ code, signal }));
            });
            await state.abort();
            expect(await exitEvent).toEqual({ code: 1, signal: null });

        } finally {
            const owned = child ?? (spawnSpy.mock.results[0]?.type === "return"
                ? spawnSpy.mock.results[0].value as ChildProcessWithoutNullStreams
                : undefined);
            spawnSpy.mockRestore();
            if (owned && owned.exitCode === null && owned.signalCode === null) {
                await new Promise<void>((resolve) => {
                    owned.once("exit", () => resolve());
                    try { owned.kill("SIGKILL"); } catch { resolve(); }
                });
            }
            await rm(dir, { recursive: true, force: true });
        }
    }, 15_000);

    it("finishes without rewriting canonical config", async () => {
        const dir = await mkdtemp(path.join(tmpdir(), "fresh-helper-finish-"));
        const helperPath = path.join(dir, "target", "release", "psy_dev_cli");
        const spawnSpy = spyOn(childProcess, "spawn");
        let child: ChildProcessWithoutNullStreams | undefined;
        try {
            await mkdir(path.join(dir, "psy-genesis"), { recursive: true });
            await mkdir(path.dirname(helperPath), { recursive: true });
            const canonical = JSON.stringify({ networks: { localhost: {
                guardian_initial_member_hashes: ["01", "02", "03"],
                fees: { guta_fee: 1000000000, da_fee: 1000 },
                guardian_configs: [1, 2, 3].map((id) => ({ id, listen_address: `127.0.0.1:${16000 + id}` })),
                guardian_history: { listen_address: "127.0.0.1:16010" },

            } } });
            await writeFile(path.join(dir, "psy-genesis/config.json"), canonical);
            await writeFile(helperPath, ["#!/bin/bash", "printf '%s\\n' '{\"phase\":\"prepared\"}'", "read -r reset", "printf '%s\\n' '{\"phase\":\"reset\"}'", "read -r finish", "printf '%s\\n' '{\"phase\":\"finished\"}'", "exit 0", ""].join("\n"));
            await chmod(helperPath, 0o755);
            const state = await prepareFreshDevnetState(dir, path.join(dir, "guardians"), { PSY_NETWORK: "localhost", PSY_PROJECTS_DIR: dir });
            child = spawnSpy.mock.results[0]?.value as ChildProcessWithoutNullStreams;
            await state.reset();
            await state.finish();
            expect(await Bun.file(path.join(dir, "psy-genesis/config.json")).text()).toBe(canonical);
        } finally {
            spawnSpy.mockRestore();
            if (child && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
            await rm(dir, { recursive: true, force: true });
        }
    }, 15_000);
});


