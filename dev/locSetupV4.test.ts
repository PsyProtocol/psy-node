import { describe, expect, it, spyOn } from "bun:test";
import path from "node:path";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, statSync } from "node:fs";
import { mkdtemp, mkdir, writeFile, rm, symlink, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import allConfig from "../psy-genesis/config.json";
import {
    COORDINATOR_PROCESSOR_READY_MARKER,
    REALM_PROCESSOR_READY_MARKER,
    isExactProcessorReadyLine,
    s3CurlArgs,
    psyServicesDatabaseCommands,
    pinFaucetPerClaimAmount,
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
    ensureGenesisFiles,
    planGenesisGeneration,
    planPsyDappNestedSubmodulesFromDisk,
    readGenesisContractsArtifactStamp,
    resolveLocalAnvilStatePlan,
    resolveForkRpcEnvKey,
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
    resolveGuardianConfigPath,
    resolveBridgeDaemonConfigPath,
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

describe("public-only Genesis generation", () => {
    const account = () => ({ contract_id: 6, initial_policy: { version: 1, threshold: 2, member_count: 3, member_hashes: ["01", "02", "03", "00", "00", "00", "00", "00"] } });
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
            for (const input of invalid.map((value) => JSON.stringify(value)).concat('{"contract_id":6,"contract_id":6,"initial_policy":' + JSON.stringify(account().initial_policy) + '}', "not JSON")) {
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
            await Bun.write(cli, '#!/usr/bin/env bun\nawait Bun.write("child.json", JSON.stringify({ args: process.argv.slice(2), env: process.env }));\n');
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
    const configPathFields = [
        "authorization_path",
        "archive_path",
        "tls_identity_path",
        "server_ca_path",
        "authorization_archive_path",
        "authorization_index_path",
        "history_tls_certificate_path",
        "history_tls_private_key_path",
        "history_client_ca_path",
    ];
    const publicGuardianConfig = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
        authorization_path: "authorization.json",
        archive_path: "archive/relayer-journal.json",
        tls_identity_path: "tls/relayer.pem",
        server_ca_path: "tls/guardian-ca.pem",
        authorization_archive_path: "authorization/versions",
        authorization_index_path: "authorization/index.json",
        history_tls_certificate_path: "tls/history.pem",
        history_tls_private_key_path: "tls/history-key.pem",
        history_client_ca_path: "tls/history-client-ca.pem",
        endpoints: ["https://guardian-a.example/", "https://guardian-b.example/", "https://guardian-c.example/"],
        l1_endpoints: [{ chain_index: 0, rpc_url: "https://l1-a.example" }],
        listen_address: "127.0.0.1:9443",
        allowed_client_certificate_sha256: [`0x${"ab".repeat(32)}`],
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

    it("accepts a bounded public GuardianClientConfig and returns the resolved config path", async () => {
        await inTempDir(async (dir) => {
            await writeConfig(dir, "guardian-client.json", publicGuardianConfig());
            await Bun.$`mkdir -p ${path.join(dir, "nested")}`.quiet();
            await writeConfig(dir, "nested/guardian-client.json", publicGuardianConfig());
            await writeConfig(dir, "origin-variants.json", publicGuardianConfig({
                endpoints: ["https://guardian-a.example", "https://guardian-a.example:8443", "https://guardian-b.example"],
                allowed_client_certificate_sha256: [],
                l1_endpoints: [],
            }));
            expect(await resolveGuardianConfigPath(dir, "guardian-client.json")).toBe(path.resolve(dir, "guardian-client.json"));
            expect(await resolveGuardianConfigPath(dir, "nested/guardian-client.json")).toBe(path.resolve(dir, "nested", "guardian-client.json"));
            expect(await resolveGuardianConfigPath(dir, path.join(dir, "guardian-client.json"))).toBe(path.join(dir, "guardian-client.json"));
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

    it("rejects a guardian service config or any schema drift from GuardianClientConfig", async () => {
        const missingField = publicGuardianConfig();
        delete missingField.history_client_ca_path;
        const cases: Array<[string, unknown]> = [
            ["guardian service config", { ...publicGuardianConfig(), db_path: "guardian.redb", signing_key_secret_path: "key.json", signing_authorization_path: "signing-authorization.json" }],
            ["embedded signing key material", { ...publicGuardianConfig(), signing_key_secret_path: "key.json" }],
            ["missing field", missingField],
            ["top level array", [publicGuardianConfig()]],
            ["top level string", '"guardian-client"'],
            ["top level null", "null"],
        ];
        await inTempDir(async (dir) => {
            for (const [label, contents] of cases) {
                const file = `schema-${label.replaceAll(" ", "-")}.json`;
                await writeConfig(dir, file, contents);
                await expectRejection(dir, file, "expected only GuardianClientConfig public fields");
            }
        });
    });

    it("rejects config-relative path fields that escape the config directory", async () => {
        const violations: Array<[string, unknown]> = [
            ["parent traversal", "../escaped/relayer.json"],
            ["nested parent traversal", "authorization/../../escaped.json"],
            ["absolute path", "/etc/passwd"],
            ["current directory component", "./authorization.json"],
            ["empty component", "authorization//index.json"],
            ["trailing separator", "authorization/"],
            ["empty string", ""],
            ["non string", 7],
            ["nul byte", "authorization\0.json"],
        ];
        await inTempDir(async (dir) => {
            for (const field of configPathFields) {
                for (const [label, value] of violations) {
                    const file = `${field}-${label.replaceAll(" ", "-")}.json`;
                    await writeConfig(dir, file, publicGuardianConfig({ [field]: value }));
                    await expectRejection(dir, file, `${field} must be a nonempty config-relative path without traversal`);
                }
            }
        });
    });

    it("rejects a symlinked, directory, missing or non-JSON guardian config file", async () => {
        await inTempDir(async (dir) => {
            await writeConfig(dir, "real.json", publicGuardianConfig());
            await Bun.$`ln -s ${path.join(dir, "real.json")} ${path.join(dir, "link.json")}`.quiet();
            await Bun.$`mkdir -p ${path.join(dir, "directory.json")}`.quiet();
            await writeConfig(dir, "truncated.json", '{"authorization_path":');
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
            const head = '{"authorization_path":"';
            const tail = `","archive_path":"archive/relayer-journal.json","endpoints":["https://guardian-a.example/","https://guardian-b.example/","https://guardian-c.example/"],"tls_identity_path":"tls/relayer.pem","server_ca_path":"tls/guardian-ca.pem","authorization_archive_path":"authorization/versions","authorization_index_path":"authorization/index.json","history_tls_certificate_path":"tls/history.pem","history_tls_private_key_path":"tls/history-key.pem","history_client_ca_path":"tls/history-client-ca.pem","l1_endpoints":[{"chain_index":0,"rpc_url":"https://l1-a.example"}],"listen_address":"127.0.0.1:9443","allowed_client_certificate_sha256":["0x${"ab".repeat(32)}"]}`;
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

    it("rejects guardian endpoints that are not three distinct fixed HTTPS origins", async () => {
        const cases: Array<[string, unknown]> = [
            ["duplicate origin", ["https://guardian-a.example/", "https://guardian-b.example/", "https://guardian-b.example/"]],
            ["host case only difference", ["https://guardian-a.example/", "https://Guardian-A.example/", "https://guardian-b.example/"]],
            ["plain HTTP origin", ["http://guardian-a.example/", "https://guardian-b.example/", "https://guardian-c.example/"]],
            ["embedded credentials", ["https://user:pass@guardian-a.example/", "https://guardian-b.example/", "https://guardian-c.example/"]],
            ["non root path", ["https://guardian-a.example/admin", "https://guardian-b.example/", "https://guardian-c.example/"]],
            ["query string", ["https://guardian-a.example/?x=1", "https://guardian-b.example/", "https://guardian-c.example/"]],
            ["fragment", ["https://guardian-a.example/#frag", "https://guardian-b.example/", "https://guardian-c.example/"]],
            ["missing host", ["https:///", "https://guardian-b.example/", "https://guardian-c.example/"]],
            ["unparseable entry", ["not a url", "https://guardian-b.example/", "https://guardian-c.example/"]],
            ["non string entry", ["https://guardian-a.example/", 7, "https://guardian-c.example/"]],
            ["two entries", ["https://guardian-a.example/", "https://guardian-b.example/"]],
            ["four entries", ["https://guardian-a.example/", "https://guardian-b.example/", "https://guardian-c.example/", "https://guardian-d.example/"]],
            ["not an array", "https://guardian-a.example/"],
        ];
        await inTempDir(async (dir) => {
            for (const [label, endpoints] of cases) {
                const file = `endpoints-${label.replaceAll(" ", "-")}.json`;
                await writeConfig(dir, file, publicGuardianConfig({ endpoints }));
                await expectRejection(dir, file, "endpoints must name three distinct fixed HTTPS origins");
            }
        });
    });

    it("rejects invalid history listener, client certificate pins or L1 endpoint fields", async () => {
        const cases: Array<[string, unknown]> = [
            ["blank listen address", { listen_address: "   " }],
            ["non string listen address", { listen_address: 9443 }],
            ["pins not an array", { allowed_client_certificate_sha256: `0x${"ab".repeat(32)}` }],
            ["uppercase digest", { allowed_client_certificate_sha256: [`0x${"AB".repeat(32)}`] }],
            ["digest without prefix", { allowed_client_certificate_sha256: ["ab".repeat(32)] }],
            ["short digest", { allowed_client_certificate_sha256: [`0x${"ab".repeat(31)}`] }],
            ["l1 endpoints not an array", { l1_endpoints: {} }],
            ["null l1 endpoint", { l1_endpoints: [null] }],
            ["unknown l1 endpoint field", { l1_endpoints: [{ chain_index: 0, rpc_url: "https://l1-a.example", chain_id: 1 }] }],
            ["chain index above u8", { l1_endpoints: [{ chain_index: 256, rpc_url: "https://l1-a.example" }] }],
            ["negative chain index", { l1_endpoints: [{ chain_index: -1, rpc_url: "https://l1-a.example" }] }],
            ["fractional chain index", { l1_endpoints: [{ chain_index: 1.5, rpc_url: "https://l1-a.example" }] }],
            ["string chain index", { l1_endpoints: [{ chain_index: "0", rpc_url: "https://l1-a.example" }] }],
            ["non string rpc url", { l1_endpoints: [{ chain_index: 0, rpc_url: 7 }] }],
        ];
        await inTempDir(async (dir) => {
            for (const [label, overrides] of cases) {
                const file = `tail-${label.replaceAll(" ", "-")}.json`;
                await writeConfig(dir, file, publicGuardianConfig(overrides as Record<string, unknown>));
                await expectRejection(dir, file, "invalid history listener, client certificate pins or L1 endpoint fields");
            }
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
    });
});

describe("whole bridge daemon config forwarding", () => {
    const daemonToml = `rpc_config = "rpc.json"
services_url = "http://127.0.0.1:3000"
guardian_config = "guardian.json"
aggregate_setup_config = "setup.json"
aggregate_artifact_dir = "artifacts"
aggregation_token_file = "token"
withdraw_method_id = 4159421846
[aggregate_limits]
max_deposits = 1
reserved_withdrawals = 1
reserved_rewards = 0
max_window_calldata_bytes = 4096
[[aggregate_limits.chains]]
chain_index = 0
max_deposits = 1
reserved_withdrawals = 1
tx_gas_limit = 5000000
block_gas_reserve = 100000
[[chains]]
chain_index = 0
family = "evm"
network_id = "synthetic"
rpc_urls = ["http://127.0.0.1:8545"]
deployments_network = "localhost"
keystore_path = "signer"
password_env = "SYNTHETIC_PASSWORD"
`;
    const fixture = async (run: (cwd: string, env: NodeJS.ProcessEnv) => Promise<void>) => {
        const cwd = await mkdtemp(path.join(tmpdir(), "daemon-public-preflight-"));
        try {
            await mkdir(path.join(cwd, "artifacts"));
            await mkdir(path.join(cwd, "authorization"));
            for (const file of ["rpc.json", "setup.json", "token", "signer", "public-reference"]) await writeFile(path.join(cwd, file), "synthetic metadata fixture, not credentials");
            await writeFile(path.join(cwd, "guardian.json"), JSON.stringify({
                authorization_path: "public-reference", archive_path: "new-history/journal.json",
                tls_identity_path: "public-reference", server_ca_path: "public-reference",
                authorization_archive_path: "authorization", authorization_index_path: "public-reference",
                history_tls_certificate_path: "public-reference", history_tls_private_key_path: "public-reference",
                history_client_ca_path: "public-reference",
                endpoints: ["https://a.example", "https://b.example", "https://c.example"],
                l1_endpoints: [], listen_address: "127.0.0.1:9443", allowed_client_certificate_sha256: [],
            }));
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            await run(cwd, { PSY_BRIDGE_DAEMON_CONFIG: "daemon.toml" });
        } finally { await rm(cwd, { recursive: true, force: true }); }
    };

    it("forwards nested TOML unchanged, resolving from launch cwd without reading protected contents", async () => {
        await fixture(async (cwd, env) => {
            for (const file of ["token", "signer", "public-reference"]) await chmod(path.join(cwd, file), 0);
            expect(await resolveBridgeDaemonConfigPath(cwd, env, true)).toBe(path.join(cwd, "daemon.toml"));
            expect(await Bun.file(path.join(cwd, "daemon.toml")).text()).toBe(daemonToml);
            await validateRelayerTemplate(["./target/release/psy_relayer_cli", "--config", "daemon.toml"], { cwd, env: env as Record<string, string> });
        });
    });

    it("rejects missing config, missing inputs and unsupported TOML capability without parser details", async () => {
        await fixture(async (cwd, env) => {
            await expect(resolveBridgeDaemonConfigPath(cwd, {})).rejects.toThrow("config path");
            await expect(resolveBridgeDaemonConfigPath(cwd, env, false, null as never)).rejects.toThrow("Bun.TOML.parse");
            await writeFile(path.join(cwd, "daemon.toml"), 'private_key = "SYNTHETIC-DO-NOT-REPORT"\n[broken');
            try { await resolveBridgeDaemonConfigPath(cwd, env); throw new Error("accepted malformed TOML"); }
            catch (error) {
                expect(String(error)).toContain("TOML document");
                expect(String(error)).not.toContain("SYNTHETIC-DO-NOT-REPORT");
            }
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            await rm(path.join(cwd, "token"));
            await expect(resolveBridgeDaemonConfigPath(cwd, env)).rejects.toThrow("aggregation_token_file metadata");
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

    it("requires integer fields and rejects width overflow, fractional and rounded unsafe numbers", async () => {
        await fixture(async (cwd, env) => {
            for (const [before, after] of [
                ["chain_index = 0", "chain_index = 256"],
                ["max_deposits = 1", "max_deposits = 4294967296"],
                ["reserved_rewards = 0", "reserved_rewards = -1"],
                ["tx_gas_limit = 5000000", "tx_gas_limit = 1.5"],
                ["block_gas_reserve = 100000", "block_gas_reserve = 9007199254740993.0"],
                ["max_window_calldata_bytes = 4096", "# absent byte budget"],
                ["max_window_calldata_bytes = 4096", "max_window_calldata_bytes = 0"],
                ["[aggregate_limits]", "[aggregate_limits]\nmax_a_calldata_bytes = 4096"],
                ["[aggregate_limits]", "[aggregate_limits]\nmax_b_calldata_bytes = 4096"],
            ]) {
                await writeFile(path.join(cwd, "daemon.toml"), daemonToml.replace(before, after));
                await expect(resolveBridgeDaemonConfigPath(cwd, env)).rejects.toThrow("aggregate_limits");
            }
            const parsed = Bun.TOML.parse(daemonToml) as Record<string, unknown>;
            parsed.withdraw_method_id = 1n << 64n;
            await expect(resolveBridgeDaemonConfigPath(cwd, env, false, () => parsed)).rejects.toThrow("withdraw_method_id");
        });
    });

    it("rejects lexical and realpath purge containment including absent history outputs", async () => {
        await fixture(async (cwd, env) => {
            await mkdir(path.join(cwd, "logs"));
            await writeFile(path.join(cwd, "logs", "token"), "synthetic");
            await symlink(path.join(cwd, "logs"), path.join(cwd, "alias"));
            for (const token of ["logs/token", "alias/token"]) {
                await writeFile(path.join(cwd, "daemon.toml"), daemonToml.replace('aggregation_token_file = "token"', `aggregation_token_file = "${token}"`));
                await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("aggregation_token_file metadata");
                expect(await resolveBridgeDaemonConfigPath(cwd, env)).toBe(path.join(cwd, "daemon.toml"));
            }
            await writeFile(path.join(cwd, "daemon.toml"), daemonToml);
            const guardian = JSON.parse(await Bun.file(path.join(cwd, "guardian.json")).text());
            guardian.archive_path = "alias/absent/journal.json";
            await writeFile(path.join(cwd, "guardian.json"), JSON.stringify(guardian));
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("archive_path metadata");
        });
    });

    it("checks a symlinked purge target and rejects mismatched guardian or replay config", async () => {
        await fixture(async (cwd, env) => {
            await symlink(path.join(cwd, "artifacts"), path.join(cwd, "logs"));
            await expect(resolveBridgeDaemonConfigPath(cwd, env, true)).rejects.toThrow("aggregate_artifact_dir metadata");
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
                await rm(path.join(cwd, "token"));
                await expect(manager.restartApplications("/not-the-launch-cwd")).rejects.toThrow("aggregation_token_file");
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
                await expect(manager.startApplications()).rejects.toThrow("aggregation_token_file");
                await expect(lifecycle.spawnFromTemplate(relayer, "automatic restart", false)).rejects.toThrow("aggregation_token_file");
                expect(spawn).not.toHaveBeenCalled();
            } finally { stop.mockRestore(); spawn.mockRestore(); }
        });
    });

    it("blocks the actual spawn before logs and leaves non-relayer validation unchanged", async () => {
        await fixture(async (cwd, env) => {
            await rm(path.join(cwd, "token"));
            await expect(RunningProcess.spawn(["psy_relayer_cli", "--config", "daemon.toml"], {
                cwd, env: env as Record<string, string>, stdoutLogFile: path.join(cwd, "never-written.log"),
            })).rejects.toThrow("aggregation_token_file");
            expect(await Bun.file(path.join(cwd, "never-written.log")).exists()).toBe(false);
            await validateRelayerTemplate(["psy_worker_cli"], { cwd: "/missing", env: {} });
        });
    });

    it("requires the aggregate daemon marker, never indexer or legacy readiness", () => {
        expect(relayerStartedDetector("INFO aggregate bridge relayer started config=/public/daemon.toml chain_count=1")).toBe(true);
        for (const line of ["connected to indexer postgres", "envio schema is ready", "indexer deposit sync window", "bridge relayer started", "aggregate bridge relayer startedness"]) expect(relayerStartedDetector(line)).toBe(false);
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