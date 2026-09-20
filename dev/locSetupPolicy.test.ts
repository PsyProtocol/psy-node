import { describe, expect, it } from "bun:test";
import {
    applyEnvioCpuSetToCompose,
    classifySupervisedExit,
    DEFAULT_PROVING_RAYON_THREADS,
    DEFAULT_WORKER_BATCH_SIZE,
    emptyRestartStreak,
    FAUCET_ENV_KEYS,
    failureSignature,
    findCpuSetOverlap,
    formatBridgeRelayerKeystoreDecryptError,
    formatCpuSet,
    hasFaucetOperatorConfig,
    COORDINATOR_PROCESSOR_READY_MARKER,
    REALM_PROCESSOR_READY_MARKER,
    hasZstdMagic,
    isCompilerFingerprintSource,
    isExactProcessorReadyLine,
    isLikelyWrongKeystorePassword,
    isTransientScyllaSchemaFailure,
    MAX_IDENTICAL_FAILURE_RESTARTS,
    nextRestartDelayMs,
    nextSpawnRetryDelayMs,
    shouldScheduleSupervisedRestart,
    parseCpuSet,
    parseEnvAssignments,
    parseFatalProcessorErrorMarker,
    parseLscpuTopology,
    parseRealmProcessorFailureLine,
    planSupervisedRestart,
    PSY_DAPP_NESTED_PAYLOADS,
    PSY_DAPP_NESTED_SUBMODULES,
    PSY_SDK_GENESIS_CONFIG_REL,
    PSY_SDK_GENESIS_SUBMODULE,
    formatPsyDappNestedSubmoduleRemedy,
    psySdkGenesisSubmoduleNeedsInit,
    planPsyDappNestedSubmoduleInit,
    resolveCpuPartition,
    resolveCpuPartitionForAffinity,
    resolvePositiveIntegerSetting,
    resolveRayonThreadCount,
    resolveScyllaMemory,
    resolveWalletPasswordPolicy,
    selectNonEmptyEnv,
    resolveRealmWorkerCount,
    shouldSkipBranchSync,
} from "./locSetupPolicy";
import type { RestartPlan, RestartStreak, SupervisedFailureCause } from "./locSetupPolicy";

describe("resolveRealmWorkerCount", () => {
    it("starts two realm workers for a full devnet by default", () => {
        expect(resolveRealmWorkerCount(undefined, false)).toBe(2);
    });

    it("keeps component-only launches worker-free by default", () => {
        expect(resolveRealmWorkerCount(undefined, true)).toBe(0);
    });

    it("honors an explicit realm worker count", () => {
        expect(resolveRealmWorkerCount("3", false)).toBe(3);
        expect(resolveRealmWorkerCount("0", false)).toBe(0);
    });
});

describe("resource settings", () => {
    it("uses bounded proving defaults", () => {
        expect(resolvePositiveIntegerSetting(undefined, DEFAULT_WORKER_BATCH_SIZE, "batch")).toBe(2);
        expect(resolvePositiveIntegerSetting(undefined, DEFAULT_PROVING_RAYON_THREADS, "rayon")).toBe(4);
    });

    it("rejects invalid positive integer settings", () => {
        expect(() => resolvePositiveIntegerSetting("0", 2, "batch")).toThrow();
        expect(() => resolvePositiveIntegerSetting("1.5", 2, "batch")).toThrow();
        expect(() => resolvePositiveIntegerSetting("many", 2, "batch")).toThrow();
    });

    it("expands CPU ranges and detects overlap", () => {
        expect([...parseCpuSet("0-2,16")]).toEqual([0, 1, 2, 16]);
        expect(findCpuSetOverlap("0,1,16,17", "2-15,18-31")).toEqual([]);
        expect(findCpuSetOverlap("0-3", "2-5")).toEqual([2, 3]);
    });

    it("rejects malformed CPU sets", () => {
        expect(() => parseCpuSet("")).toThrow();
        expect(() => parseCpuSet("4-2")).toThrow();
        expect(() => parseCpuSet("0,a")).toThrow();
    });
});

describe("portable CPU partitioning", () => {
    const topology = (physicalCores: number, threadsPerCore: number): string => {
        const rows: string[] = [];
        for (let core = 0; core < physicalCores; core += 1) {
            for (let thread = 0; thread < threadsPerCore; thread += 1) {
                rows.push(`${core + thread * physicalCores},${core},0`);
            }
        }
        return rows.join("\n");
    };

    it("reserves two complete cores on a 16-core SMT host", () => {
        const partition = resolveCpuPartition(parseLscpuTopology(topology(16, 2)));
        expect(partition).toEqual({
            scyllaCpuSet: "0-1,16-17",
            runtimeCpuSet: "2-15,18-31",
            scyllaLogicalCpuCount: 2,
            runtimePhysicalCoreCount: 14,
        });
    });

    it("adapts to 8-core hosts with and without SMT", () => {
        expect(resolveCpuPartition(parseLscpuTopology(topology(8, 2)))?.scyllaLogicalCpuCount).toBe(2);
        expect(resolveCpuPartition(parseLscpuTopology(topology(8, 1)))?.scyllaLogicalCpuCount).toBe(2);
    });

    it("drops partially allowed SMT cores", () => {
        const groups = parseLscpuTopology(topology(4, 2), new Set([0, 1, 2, 3, 4, 5, 7]));
        expect(groups).toEqual([[0, 4], [1, 5], [3, 7]]);
    });

    it("rejects overrides when fewer than two complete cores are available", () => {
        expect(() => resolveCpuPartition([[0, 4]], "0,4", "1,5")).toThrow();
    });

    it("requires explicit overrides to preserve whole physical cores", () => {
        const groups = parseLscpuTopology(topology(8, 2));
        expect(() => resolveCpuPartition(groups, "0", "1-15")).toThrow();
        expect(() => resolveCpuPartition(groups, "0,8", "1-7,9-15")).not.toThrow();
    });

    it("treats an outer launcher affinity as the existing runtime partition", () => {
        const groups = parseLscpuTopology(topology(16, 2));
        const allowed = parseCpuSet("2-15,18-31");
        expect(resolveCpuPartitionForAffinity(groups, allowed)).toEqual({
            scyllaCpuSet: "0-1,16-17",
            runtimeCpuSet: "2-15,18-31",
            scyllaLogicalCpuCount: 2,
            runtimePhysicalCoreCount: 14,
        });
        expect(resolveCpuPartitionForAffinity(groups, allowed, "0-1,16-17", "2-15,18-31")).not.toBeNull();
    });

    it("rejects partial-core or conflicting launcher affinity overrides", () => {
        const groups = parseLscpuTopology(topology(8, 2));
        expect(() => resolveCpuPartitionForAffinity(groups, parseCpuSet("1-7,8-15"))).toThrow();
        expect(() => resolveCpuPartitionForAffinity(groups, parseCpuSet("2-7,10-15"), undefined, "1-7,9-15")).toThrow();
    });

    it("formats compact ranges and budgets Rayon per proving process", () => {
        expect(formatCpuSet([0, 1, 2, 4, 8, 9])).toBe("0-2,4,8-9");
        expect(resolveRayonThreadCount(14, 3)).toBe(4);
        expect(resolveRayonThreadCount(6, 3)).toBe(2);
        expect(resolveRayonThreadCount(3, 4)).toBe(1);
    });
});

describe("runtime infrastructure settings", () => {
    it("defaults Scylla memory to 8G and preserves an explicit budget", () => {
        expect(resolveScyllaMemory(undefined)).toBe("8G");
        expect(resolveScyllaMemory(" ")).toBe("8G");
        expect(resolveScyllaMemory("12G")).toBe("12G");
    });

    it("injects both Envio services into the generated base compose idempotently", () => {
        const compose = [
            "services:",
            "  envio-postgres:",
            "    image: postgres:17.5",
            "  graphql-engine:",
            "    image: hasura/graphql-engine:v2.43.0",
            "volumes:",
            "  db_data:",
            "",
        ].join("\n");
        const configured = applyEnvioCpuSetToCompose(compose, "2-15,18-31");
        expect(configured.match(/cpuset: "2-15,18-31"/g)?.length).toBe(2);
        expect(applyEnvioCpuSetToCompose(configured, "2-15,18-31")).toBe(configured);
        expect(applyEnvioCpuSetToCompose(compose, undefined)).toBe(compose);
        expect(() => applyEnvioCpuSetToCompose("services:\n  envio-postgres:\n", "2-3")).toThrow();
    });

    it("parses comma-bearing environment values without corrupting assignments", () => {
        expect(parseEnvAssignments("SCYLLA_CPUSET=0-1,16-17,PSY_RUNTIME_CPUSET=2-15,18-31")).toEqual({
            SCYLLA_CPUSET: "0-1,16-17",
            PSY_RUNTIME_CPUSET: "2-15,18-31",
        });
        expect(parseEnvAssignments('PSY_FAUCET_OPERATORS_JSON={"operators":[1,2]},PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES=localhost,dev.example')).toEqual({
            PSY_FAUCET_OPERATORS_JSON: '{"operators":[1,2]}',
            PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES: "localhost,dev.example",
        });
        expect(parseEnvAssignments("TOKEN=a=b=c")).toEqual({ TOKEN: "a=b=c" });
        expect(() => parseEnvAssignments("BROKEN")).toThrow();
    });

    it("preserves configured faucet operators and Turnstile values", () => {
        const parentEnv = { PSY_FAUCET_OPERATORS_JSON_B64: "parent-encoded" };
        expect(hasFaucetOperatorConfig({}, parentEnv)).toBe(true);
        expect(hasFaucetOperatorConfig({ PSY_FAUCET_OPERATORS_JSON: '{"operators":[]}' }, {})).toBe(true);
        expect(hasFaucetOperatorConfig({}, {})).toBe(false);
        const selected = selectNonEmptyEnv({
            PSY_FAUCET_OPERATORS_JSON: '{"operators":[]}',
            PSY_FAUCET_OPERATORS_JSON_B64: "encoded",
            PSY_FAUCET_TURNSTILE_SECRET: "secret-value",
            PSY_FAUCET_REQUIRE_TURNSTILE: "1",
            PSY_FAUCET_TURNSTILE_ACTION: "psy_faucet",
            PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES: "localhost",
            PSY_FAUCET_WINDOW_CHECKPOINTS: "120",
            UNRELATED: "drop-me",
        }, FAUCET_ENV_KEYS);
        expect(Object.keys(selected).sort()).toEqual([...FAUCET_ENV_KEYS].sort());
        expect(selected.UNRELATED).toBeUndefined();
    });
});


describe("isCompilerFingerprintSource", () => {
    it("includes compiler source and manifest files", () => {
        expect(isCompilerFingerprintSource("Cargo.toml")).toBe(true);
        expect(isCompilerFingerprintSource("psy-wasm/src/lib.rs")).toBe(true);
        expect(isCompilerFingerprintSource("psy-std/storage.psy")).toBe(true);
        expect(isCompilerFingerprintSource("psy-precompiles/build.rs")).toBe(true);
    });

    it("excludes secrets and unrelated artifacts", () => {
        expect(isCompilerFingerprintSource(".env")).toBe(false);
        expect(isCompilerFingerprintSource("config/auth.toml")).toBe(false);
        expect(isCompilerFingerprintSource("fixtures/private.key")).toBe(false);
        expect(isCompilerFingerprintSource("target/release/compiler")).toBe(false);
    });
});


describe("hasZstdMagic", () => {
    it("accepts the zstd frame magic", () => {
        expect(hasZstdMagic(Uint8Array.from([0x28, 0xb5, 0x2f, 0xfd]))).toBe(true);
    });

    it("rejects plain JSON, LFS pointers, and truncated input", () => {
        expect(hasZstdMagic(new TextEncoder().encode("[{}]"))).toBe(false);
        expect(hasZstdMagic(new TextEncoder().encode("version https://git-lfs.github.com/spec/v1"))).toBe(false);
        expect(hasZstdMagic(Uint8Array.from([0x28, 0xb5, 0x2f]))).toBe(false);
    });
});

describe("shouldSkipBranchSync", () => {
    it("skips branch sync by default", () => {
        expect(shouldSkipBranchSync(undefined)).toBe(true);
        expect(shouldSkipBranchSync("")).toBe(true);
        expect(shouldSkipBranchSync("1")).toBe(true);
    });

    it("requires an explicit zero to enable branch sync", () => {
        expect(shouldSkipBranchSync("0")).toBe(false);
        expect(shouldSkipBranchSync(" 0 ")).toBe(false);
        expect(shouldSkipBranchSync("false")).toBe(true);
    });
});

describe("parseFatalProcessorErrorMarker", () => {
    it("parses exact CFLI tokens and ignores other lines", () => {
        expect(parseFatalProcessorErrorMarker("[CFLI:PSY_REALM_PROCESSOR_ERROR] coordinator halted")).toBe("PSY_REALM_PROCESSOR_ERROR");
        expect(parseFatalProcessorErrorMarker("2026-07-29 [CFLI:PSY_COORDINATOR_PROCESSOR_ERROR] boom")).toBe("PSY_COORDINATOR_PROCESSOR_ERROR");
        expect(parseFatalProcessorErrorMarker("[CFLI:PSY_REALM_PROCESSOR_STARTED] up")).toBeNull();
        expect(parseFatalProcessorErrorMarker("realm_processor_failure realm_id=0 realm_sub_id=1 error=x")).toBeNull();
    });
});

describe("parseRealmProcessorFailureLine", () => {
    it("captures the structured stderr event and ignores CFLI", () => {
        const line = "realm_processor_failure realm_id=0 realm_sub_id=1 error=leaf-mismatch";
        expect(parseRealmProcessorFailureLine(line)).toBe(line);
        expect(parseRealmProcessorFailureLine("[CFLI:PSY_REALM_PROCESSOR_ERROR] x")).toBeNull();
        expect(parseRealmProcessorFailureLine("Error: channel closed")).toBeNull();
        expect(parseRealmProcessorFailureLine("realm_processor_failureevil")).toBeNull();
        expect(parseRealmProcessorFailureLine("\u001b[0m\u001b[31m" + line + "\u001b[0m")).toBe(line);
    });
});

describe("supervised retry policy", () => {
    const fatal: SupervisedFailureCause = { kind: "fatal-processor-error", marker: "PSY_REALM_PROCESSOR_ERROR" };
    const firstCause = "realm_processor_failure realm_id=0 realm_sub_id=1 error=leaf-mismatch";
    const firstIso = "2026-01-01T00:00:00.000Z";

    function plan(overrides: {
        restartCount?: number;
        streak?: RestartStreak;
        cause?: SupervisedFailureCause;
        firstCause?: string | null;
        healthySinceMs?: number;
        nowMs?: number;
        observedAtIso?: string;
    } = {}): RestartPlan {
        return planSupervisedRestart({
            restartCount: 0,
            streak: emptyRestartStreak(),
            cause: fatal,
            firstCause,
            healthySinceMs: 0,
            nowMs: 1_000,
            observedAtIso: firstIso,
            ...overrides,
        });
    }

    function repeat(count: number, cause: SupervisedFailureCause = fatal): RestartPlan {
        let streak = emptyRestartStreak();
        let restartCount = 0;
        let last = plan({ streak, restartCount, cause });
        for (let i = 0; i < count; i += 1) {
            last = plan({ streak, restartCount, cause, observedAtIso: `2026-01-01T00:00:0${i}.000Z` });
            streak = last.streak;
            restartCount = last.restartCount;
        }
        return last;
    }

    it("keeps the existing 1s exponential backoff capped at 30s", () => {
        expect([1, 2, 3, 4, 5, 6, 7].map(nextRestartDelayMs)).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000]);
        expect(nextSpawnRetryDelayMs(30000)).toBe(60000);
    });

    it("classifies from typed marker, signal, and exit code", () => {
        expect(classifySupervisedExit({
            fatalProcessorErrorMarker: "PSY_REALM_PROCESSOR_ERROR",
            dependencyRestartRequested: false,
            signalCode: "SIGTERM",
            exitCode: 143,
        })).toEqual({ kind: "fatal-processor-error", marker: "PSY_REALM_PROCESSOR_ERROR" });
        expect(classifySupervisedExit({
            fatalProcessorErrorMarker: null,
            dependencyRestartRequested: false,
            signalCode: "SIGTERM",
            exitCode: null,
        })).toEqual({ kind: "signaled", signal: "SIGTERM" });
        expect(classifySupervisedExit({
            fatalProcessorErrorMarker: null,
            dependencyRestartRequested: false,
            signalCode: null,
            exitCode: 1,
        })).toEqual({ kind: "exited", code: 1 });
    });

    it("restarts the first identical typed failure on the 1s backoff", () => {
        const first = plan();
        expect(first.action).toBe("restart");
        expect(first.restartCount).toBe(1);
        expect(first.delayMs).toBe(1000);
        expect(first.streak.identicalRepeats).toBe(1);
        expect(first.streak.firstCause).toBe(firstCause);
        expect(failureSignature(first.streak.cause!)).toBe(failureSignature(fatal));
    });

    it("stops automatic restarts on the fifth identical typed failure", () => {
        expect(MAX_IDENTICAL_FAILURE_RESTARTS).toBe(4);
        const last = repeat(MAX_IDENTICAL_FAILURE_RESTARTS + 1);
        expect(last.action).toBe("limit");
        expect(last.delayMs).toBe(0);
        expect(last.restartCount).toBe(4);
        expect(last.streak.identicalRepeats).toBe(5);
        expect(last.streak.firstCause).toBe(firstCause);
        expect(last.streak.firstObservedAtIso).toBe("2026-01-01T00:00:00.000Z");
    });

    it("still restarts before the identical-failure cap", () => {
        const last = repeat(MAX_IDENTICAL_FAILURE_RESTARTS);
        expect(last.action).toBe("restart");
        expect(last.restartCount).toBe(4);
        expect(last.streak.identicalRepeats).toBe(4);
    });

    it("resets identical repeats when the typed cause changes but keeps the first causal stderr", () => {
        const afterFatal = repeat(2);
        const afterExit = plan({
            streak: afterFatal.streak,
            restartCount: afterFatal.restartCount,
            cause: { kind: "exited", code: 1 },
            firstCause: "realm_processor_failure realm_id=0 realm_sub_id=1 error=other",
        });
        expect(afterExit.action).toBe("restart");
        expect(afterExit.streak.identicalRepeats).toBe(1);
        expect(afterExit.streak.cause).toEqual({ kind: "exited", code: 1 });
        expect(afterExit.streak.firstCause).toBe(firstCause);
        expect(afterExit.streak.firstObservedAtIso).toBe("2026-01-01T00:00:00.000Z");
    });

    it("keeps the first causal stderr for the life of the streak", () => {
        const first = plan({ observedAtIso: firstIso });
        const later = plan({
            streak: first.streak,
            restartCount: first.restartCount,
            firstCause: "realm_processor_failure realm_id=0 realm_sub_id=1 error=later-symptom",
            observedAtIso: "2026-01-01T00:00:10.000Z",
        });
        expect(later.streak.firstCause).toBe(firstCause);
        expect(later.streak.firstObservedAtIso).toBe(firstIso);
        expect(later.streak.identicalRepeats).toBe(2);
    });

    it("does not treat a long unready launch as a stable run", () => {
        const longUnready = plan({
            restartCount: 4,
            healthySinceMs: 0,
            nowMs: 120_000,
        });
        expect(longUnready.action).toBe("restart");
        expect(longUnready.restartCount).toBe(5);
        expect(longUnready.delayMs).toBe(16_000);
        expect(longUnready.streak.identicalRepeats).toBe(1);
    });

    it("resets backoff and streak after a ready run of at least 60s", () => {
        const healthy = plan({
            restartCount: 4,
            healthySinceMs: 1,
            nowMs: 60_001,
        });
        expect(healthy.action).toBe("restart");
        expect(healthy.restartCount).toBe(1);
        expect(healthy.delayMs).toBe(1000);
        expect(healthy.streak.identicalRepeats).toBe(1);
        expect(healthy.streak.firstCause).toBe(firstCause);
    });

    it("uses the current spawn cause after a healthy reset, not the previous epoch", () => {
        const causeA = "realm_processor_failure realm_id=0 realm_sub_id=1 error=A";
        const causeB = "realm_processor_failure realm_id=0 realm_sub_id=1 error=B";
        const epochA = plan({ firstCause: causeA, observedAtIso: firstIso });
        const afterHealthy = plan({
            streak: epochA.streak,
            restartCount: epochA.restartCount,
            firstCause: causeB,
            healthySinceMs: 1,
            nowMs: 60_001,
            observedAtIso: "2026-01-01T00:02:00.000Z",
        });
        expect(afterHealthy.action).toBe("restart");
        expect(afterHealthy.restartCount).toBe(1);
        expect(afterHealthy.streak.identicalRepeats).toBe(1);
        expect(afterHealthy.streak.firstCause).toBe(causeB);
        expect(afterHealthy.streak.firstObservedAtIso).toBe("2026-01-01T00:02:00.000Z");
    });

    it("does not treat later spawn-failure waits as a second healthy reset", () => {
        const spawnFailed: SupervisedFailureCause = { kind: "spawn-failed" };
        const afterHealthyChild = plan({
            restartCount: 0,
            healthySinceMs: 1,
            nowMs: 60_001,
            cause: spawnFailed,
            firstCause: null,
        });
        expect(afterHealthyChild.action).toBe("restart");
        expect(afterHealthyChild.restartCount).toBe(1);
        let last = afterHealthyChild;
        let nowMs = 60_001;
        const failedSpawnMs = 20_000;
        for (let i = 0; i < MAX_IDENTICAL_FAILURE_RESTARTS; i += 1) {
            nowMs += failedSpawnMs + nextSpawnRetryDelayMs(last.delayMs);
            last = plan({
                streak: last.streak,
                restartCount: last.restartCount,
                cause: spawnFailed,
                firstCause: null,
                healthySinceMs: 0,
                nowMs,
            });
        }
        expect(nowMs - 60_001).toBeGreaterThan(60_000);
        expect(last.action).toBe("limit");
        expect(last.streak.identicalRepeats).toBe(5);
        expect(last.restartCount).toBe(4);
    });

    it("does not schedule a restart after intentional stop or teardown", () => {
        expect(shouldScheduleSupervisedRestart(false, false)).toBe(true);
        expect(shouldScheduleSupervisedRestart(true, false)).toBe(false);
        expect(shouldScheduleSupervisedRestart(false, true)).toBe(false);
        expect(shouldScheduleSupervisedRestart(true, true)).toBe(false);
    });
});


describe("processor readiness helpers", () => {
    it("accepts only complete readiness markers", () => {
        expect(isExactProcessorReadyLine(COORDINATOR_PROCESSOR_READY_MARKER, COORDINATOR_PROCESSOR_READY_MARKER)).toBe(true);
        expect(isExactProcessorReadyLine(`INFO ${REALM_PROCESSOR_READY_MARKER}`, REALM_PROCESSOR_READY_MARKER)).toBe(true);
        expect(isExactProcessorReadyLine("[COORD_CREATE] processor new start", COORDINATOR_PROCESSOR_READY_MARKER)).toBe(false);
        expect(isExactProcessorReadyLine(`${COORDINATOR_PROCESSOR_READY_MARKER} trailing`, COORDINATOR_PROCESSOR_READY_MARKER)).toBe(false);
        expect(isExactProcessorReadyLine(`prefix${COORDINATOR_PROCESSOR_READY_MARKER}`, COORDINATOR_PROCESSOR_READY_MARKER)).toBe(false);
    });

    it("recognizes only transient Scylla schema timeout evidence", () => {
        expect(isTransientScyllaSchemaFailure("Scylla schema configuration failed\nunrelated coordinator request timeout")).toBe(false);
        expect(isTransientScyllaSchemaFailure("Scylla schema operation timed out while applying migration")).toBe(true);
        expect(isTransientScyllaSchemaFailure("raft group-0 add_entry: operation timeout")).toBe(true);
        expect(isTransientScyllaSchemaFailure("group [ec259ee0] raft operation [add_entry] timed out")).toBe(true);
    });
});

describe("psySdkGenesisSubmoduleNeedsInit", () => {
    it("requires init when git metadata or config.json is missing", () => {
        expect(psySdkGenesisSubmoduleNeedsInit({ gitMetadataPresent: false, configPresent: false })).toBe(true);
        expect(psySdkGenesisSubmoduleNeedsInit({ gitMetadataPresent: true, configPresent: false })).toBe(true);
        expect(psySdkGenesisSubmoduleNeedsInit({ gitMetadataPresent: false, configPresent: true })).toBe(true);
    });

    it("skips init when psy-genesis is fully present for prepare:wasm", () => {
        expect(psySdkGenesisSubmoduleNeedsInit({ gitMetadataPresent: true, configPresent: true })).toBe(false);
        expect(PSY_SDK_GENESIS_SUBMODULE).toBe("psy-genesis");
        expect(PSY_SDK_GENESIS_CONFIG_REL).toBe("psy-genesis/config.json");
    });
});

describe("planPsyDappNestedSubmoduleInit", () => {
    it("plans init for every nested gitlink missing git metadata", () => {
        const plan = planPsyDappNestedSubmoduleInit({
            uninitialized: ["psy-genesis", "psy-contracts"],
        });
        expect(plan.ready).toBe(false);
        expect(plan.pending).toEqual(["psy-genesis", "psy-contracts"]);
        expect(plan.updateArgs).toEqual([
            "submodule", "update", "--init", "--", "psy-genesis", "psy-contracts",
        ]);
    });

    it("treats a checked-out gitlink with missing payloads as pending", () => {
        const plan = planPsyDappNestedSubmoduleInit({
            uninitialized: [],
            missingPayloads: { "psy-contracts": ["protocol-config/index.ts", "deployments/index.ts"] },
        });
        expect(plan.ready).toBe(false);
        expect(plan.pending).toEqual(["psy-contracts"]);
        expect(plan.updateArgs).toEqual([
            "submodule", "update", "--init", "--", "psy-contracts",
        ]);
        expect(plan.missingPayloads["psy-contracts"]).toEqual([
            "protocol-config/index.ts", "deployments/index.ts",
        ]);
    });

    it("is a no-op when every nested gitlink is fully present", () => {
        const plan = planPsyDappNestedSubmoduleInit({ uninitialized: [], missingPayloads: {} });
        expect(plan.ready).toBe(true);
        expect(plan.pending).toEqual([]);
        expect(plan.missingPayloads).toEqual({});
    });

    it("declares exactly the gitlinks and payloads the psy-dapp UI aliases into", () => {
        expect(PSY_DAPP_NESTED_SUBMODULES).toEqual(["psy-genesis", "psy-contracts"]);
        expect(PSY_DAPP_NESTED_PAYLOADS["psy-genesis"]).toEqual(["config.json"]);
        expect(PSY_DAPP_NESTED_PAYLOADS["psy-contracts"]).toEqual([
            "protocol-config/index.ts", "deployments/index.ts",
        ]);
    });
});

describe("formatPsyDappNestedSubmoduleRemedy", () => {
    it("renders a repository-relative command for pending gitlinks", () => {
        const plan = planPsyDappNestedSubmoduleInit({ uninitialized: ["psy-contracts"] });
        const remedy = formatPsyDappNestedSubmoduleRemedy("psy-dapp", plan);
        expect(remedy).toContain("cd psy-dapp && git submodule update --init -- psy-contracts");
        expect(remedy).toContain("from the psy-node repository root");
    });

    it("lists payload files that remain missing after an init attempt", () => {
        const plan = planPsyDappNestedSubmoduleInit({
            uninitialized: [],
            missingPayloads: { "psy-genesis": ["config.json"] },
        });
        const remedy = formatPsyDappNestedSubmoduleRemedy("psy-dapp", plan);
        expect(remedy).toContain("cd psy-dapp && git submodule update --init -- psy-genesis");
        expect(remedy).toContain("psy-dapp/psy-genesis/config.json");
    });

    it("renders nothing for a ready plan", () => {
        const plan = planPsyDappNestedSubmoduleInit({ uninitialized: [], missingPayloads: {} });
        expect(formatPsyDappNestedSubmoduleRemedy("psy-dapp", plan)).toBe("");
    });
});

describe("resolveWalletPasswordPolicy", () => {
    it("prefers explicit env password over every other source", () => {
        expect(resolveWalletPasswordPolicy({
            envPassword: "from-env",
            cachedPassword: "cached",
            isTty: false,
            keystoreExists: true,
            keystoreGeneratedThisRun: false,
        })).toEqual({ source: "env", password: "from-env" });
    });

    it("preserves leading and trailing password whitespace", () => {
        expect(resolveWalletPasswordPolicy({
            envPassword: "  exact secret  ",
            cachedPassword: null,
            isTty: false,
            keystoreExists: true,
            keystoreGeneratedThisRun: false,
        })).toEqual({ source: "env", password: "  exact secret  " });
    });

    it("uses the cached password when env is empty", () => {
        expect(resolveWalletPasswordPolicy({
            envPassword: undefined,
            cachedPassword: "cached",
            isTty: true,
            keystoreExists: true,
            keystoreGeneratedThisRun: false,
        })).toEqual({ source: "cached", password: "cached" });
    });

    it("defaults to devnet only for generated/missing keystores in non-TTY sessions", () => {
        expect(resolveWalletPasswordPolicy({
            envPassword: "",
            cachedPassword: null,
            isTty: false,
            keystoreExists: false,
            keystoreGeneratedThisRun: false,
        })).toEqual({ source: "default-devnet", password: "devnet" });

        expect(resolveWalletPasswordPolicy({
            envPassword: undefined,
            cachedPassword: null,
            isTty: false,
            keystoreExists: true,
            keystoreGeneratedThisRun: true,
        })).toEqual({ source: "default-devnet", password: "devnet" });
    });

    it("never silently defaults an existing preserved keystore to devnet", () => {
        const nonTty = resolveWalletPasswordPolicy({
            envPassword: undefined,
            cachedPassword: null,
            isTty: false,
            keystoreExists: true,
            keystoreGeneratedThisRun: false,
        });
        expect(nonTty.source).toBe("prompt-required");
        expect(nonTty.password).toBeUndefined();
        expect(nonTty.error).toContain("WALLET_PASSWORD is required");
        expect(nonTty.error).toContain("existing bridge-relayer keystore");

        const tty = resolveWalletPasswordPolicy({
            envPassword: "   ",
            cachedPassword: null,
            isTty: true,
            keystoreExists: true,
            keystoreGeneratedThisRun: false,
        });
        expect(tty).toEqual({ source: "prompt-required" });
    });

    it("still prompts on TTY when generating a new keystore without env/cache", () => {
        expect(resolveWalletPasswordPolicy({
            envPassword: undefined,
            cachedPassword: null,
            isTty: true,
            keystoreExists: false,
            keystoreGeneratedThisRun: false,
        })).toEqual({ source: "prompt-required" });
    });
});

describe("bridge-relayer keystore decrypt errors", () => {
    it("classifies common wrong-password diagnostics", () => {
        expect(isLikelyWrongKeystorePassword("Error: invalid password")).toBe(true);
        expect(isLikelyWrongKeystorePassword("bad MAC")).toBe(true);
        expect(isLikelyWrongKeystorePassword("could not decrypt data")).toBe(true);
        expect(isLikelyWrongKeystorePassword("ethers is not installed")).toBe(false);
    });

    it("formats an actionable recovery path without echoing credentials", () => {
        const message = formatBridgeRelayerKeystoreDecryptError({
            keystorePath: "<workspace>/.psy/keystore/bridge-relayer",
            detail: "invalid password",
        });
        expect(message).toContain("<workspace>/.psy/keystore/bridge-relayer");
        expect(message).toContain("WALLET_PASSWORD does not match the existing keystore");
        expect(message).toContain("rm -f <workspace>/.psy/keystore/bridge-relayer");
        expect(message).toContain("Detail: invalid password");
        expect(message).not.toMatch(/password\s*=/i);
    });
});