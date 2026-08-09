import { describe, expect, it } from "bun:test";
import {
    applyEnvioCpuSetToCompose,
    DEFAULT_PROVING_RAYON_THREADS,
    DEFAULT_WORKER_BATCH_SIZE,
    FATAL_PROCESSOR_ERROR_MARKERS,
    FAUCET_ENV_KEYS,
    findCpuSetOverlap,
    formatCpuSet,
    hasFaucetOperatorConfig,
    COORDINATOR_PROCESSOR_READY_MARKER,
    REALM_PROCESSOR_READY_MARKER,
    hasZstdMagic,
    isFatalProcessorErrorLine,
    isCompilerFingerprintSource,
    isExactProcessorReadyLine,
    isTransientScyllaSchemaFailure,
    parseCpuSet,
    parseEnvAssignments,
    parseLscpuTopology,
    resolveCpuPartition,
    resolveCpuPartitionForAffinity,
    resolvePositiveIntegerSetting,
    resolveRayonThreadCount,
    resolveScyllaMemory,
    selectNonEmptyEnv,
    resolveRealmWorkerCount,
    shouldFatalRestartProcessor,
    shouldSkipBranchSync,
} from "./locSetupDefaults";

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

describe("isFatalProcessorErrorLine", () => {
    it("detects the realm processor fatal marker", () => {
        expect(isFatalProcessorErrorLine("[CFLI:PSY_REALM_PROCESSOR_ERROR] coordinator halted")).toBe(true);
    });

    it("detects the coordinator processor fatal marker", () => {
        expect(isFatalProcessorErrorLine("2026-07-29 [CFLI:PSY_COORDINATOR_PROCESSOR_ERROR] boom")).toBe(true);
    });

    it("ignores ordinary processor log lines", () => {
        expect(isFatalProcessorErrorLine("[CFLI:PSY_REALM_PROCESSOR_STARTED] up")).toBe(false);
        expect(isFatalProcessorErrorLine("[REALM_CREATE] processor new done")).toBe(false);
        expect(isFatalProcessorErrorLine("")).toBe(false);
    });

    it("matches every advertised marker", () => {
        for (const marker of FATAL_PROCESSOR_ERROR_MARKERS) {
            expect(isFatalProcessorErrorLine(`prefix ${marker} suffix`)).toBe(true);
        }
    });
});

describe("shouldFatalRestartProcessor", () => {
    it("requests a restart the first time a fatal marker appears", () => {
        expect(shouldFatalRestartProcessor("[CFLI:PSY_REALM_PROCESSOR_ERROR] x", false)).toBe(true);
        expect(shouldFatalRestartProcessor("[CFLI:PSY_COORDINATOR_PROCESSOR_ERROR] x", false)).toBe(true);
    });

    it("does not request a restart for non-fatal lines", () => {
        expect(shouldFatalRestartProcessor("[REALM_CREATE] processor new done", false)).toBe(false);
        expect(shouldFatalRestartProcessor("ordinary stdout", false)).toBe(false);
    });

    it("suppresses repeated kills once one has already been requested", () => {
        const line = "[CFLI:PSY_REALM_PROCESSOR_ERROR] duplicated";
        expect(shouldFatalRestartProcessor(line, false)).toBe(true);
        expect(shouldFatalRestartProcessor(line, true)).toBe(false);
        expect(shouldFatalRestartProcessor("[CFLI:PSY_COORDINATOR_PROCESSOR_ERROR] other", true)).toBe(false);
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