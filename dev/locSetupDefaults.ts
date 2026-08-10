export const DEFAULT_WORKER_BATCH_SIZE = 2;
export const DEFAULT_PROVING_RAYON_THREADS = 4;
export const DEFAULT_SCYLLA_MEMORY = "8G";
export const FAUCET_ENV_KEYS = [
    "PSY_FAUCET_OPERATORS_JSON",
    "PSY_FAUCET_OPERATORS_JSON_B64",
    "PSY_FAUCET_TURNSTILE_SECRET",
    "PSY_FAUCET_REQUIRE_TURNSTILE",
    "PSY_FAUCET_TURNSTILE_ACTION",
    "PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES",
    "PSY_FAUCET_WINDOW_CHECKPOINTS",
] as const;

export function resolveScyllaMemory(value: string | undefined): string {
    return value?.trim() || DEFAULT_SCYLLA_MEMORY;
}

export function applyEnvioCpuSetToCompose(composeYaml: string, runtimeCpuSet: string | undefined): string {
    if (!runtimeCpuSet) return composeYaml;
    const lines = composeYaml.split("\n");
    for (const serviceName of ["envio-postgres", "graphql-engine"]) {
        const serviceLine = `  ${serviceName}:`;
        const serviceIndex = lines.indexOf(serviceLine);
        if (serviceIndex < 0) {
            throw new Error(`Envio compose is missing service '${serviceName}'`);
        }
        let serviceEnd = serviceIndex + 1;
        while (serviceEnd < lines.length && !/^(?:\S|  \S).*:\s*$/.test(lines[serviceEnd])) {
            serviceEnd += 1;
        }
        const cpuSetIndex = lines.findIndex((line, index) => index > serviceIndex && index < serviceEnd && /^    cpuset:/.test(line));
        const cpuSetLine = `    cpuset: ${JSON.stringify(runtimeCpuSet)}`;
        if (cpuSetIndex >= 0) {
            lines[cpuSetIndex] = cpuSetLine;
        } else {
            lines.splice(serviceIndex + 1, 0, cpuSetLine);
        }
    }
    return lines.join("\n");
}

export function parseEnvAssignments(value: string): Record<string, string> {
    const assignments: Record<string, string> = {};
    for (const pair of value.split(/,(?=[A-Za-z_][A-Za-z0-9_]*=)/)) {
        const separatorIndex = pair.indexOf("=");
        if (separatorIndex <= 0) {
            throw new Error(`Invalid environment assignment '${pair}'`);
        }
        const key = pair.slice(0, separatorIndex).trim();
        const assignmentValue = pair.slice(separatorIndex + 1).trim();
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || assignmentValue.length === 0) {
            throw new Error(`Invalid environment assignment '${pair}'`);
        }
        assignments[key] = assignmentValue;
    }
    return assignments;
}

export function hasFaucetOperatorConfig(...sources: Readonly<Record<string, string | undefined>>[]): boolean {
    return sources.some((source) => source.PSY_FAUCET_OPERATORS_JSON?.trim() || source.PSY_FAUCET_OPERATORS_JSON_B64?.trim());
}

export function selectNonEmptyEnv(
    source: Readonly<Record<string, string | undefined>>,
    keys: readonly string[],
): Record<string, string> {
    const selected: Record<string, string> = {};
    for (const key of keys) {
        const value = source[key];
        if (value?.trim()) selected[key] = value;
    }
    return selected;
}

export type CpuPartition = {
    scyllaCpuSet: string;
    runtimeCpuSet: string;
    scyllaLogicalCpuCount: number;
    runtimePhysicalCoreCount: number;
};

export function parseLscpuTopology(output: string, allowedCpus?: ReadonlySet<number>): number[][] {
    const groups = new Map<string, number[]>();
    for (const rawLine of output.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        const columns = line.split(",");
        if (columns.length !== 3) {
            throw new Error(`Unexpected lscpu topology row '${line}'`);
        }
        const [cpuText, coreText, socketText] = columns;
        const cpu = Number(cpuText);
        const core = Number(coreText);
        const socket = Number(socketText);
        if (![cpu, core, socket].every(Number.isSafeInteger) || cpu < 0 || core < 0 || socket < 0) {
            throw new Error(`Invalid lscpu topology row '${line}'`);
        }
        const key = `${socket}:${core}`;
        const siblings = groups.get(key) ?? [];
        siblings.push(cpu);
        groups.set(key, siblings);
    }
    return [...groups.values()]
        .filter((siblings) => !allowedCpus || siblings.every((cpu) => allowedCpus.has(cpu)))
        .map((siblings) => siblings.sort((left, right) => left - right))
        .sort((left, right) => left[0] - right[0]);
}

export function formatCpuSet(cpus: readonly number[]): string {
    const sorted = [...new Set(cpus)].sort((left, right) => left - right);
    if (sorted.length === 0) throw new Error("CPU set must contain at least one CPU");
    const ranges: string[] = [];
    let rangeStart = sorted[0];
    let rangeEnd = sorted[0];
    for (const cpu of sorted.slice(1)) {
        if (cpu === rangeEnd + 1) {
            rangeEnd = cpu;
            continue;
        }
        ranges.push(rangeStart === rangeEnd ? `${rangeStart}` : `${rangeStart}-${rangeEnd}`);
        rangeStart = cpu;
        rangeEnd = cpu;
    }
    ranges.push(rangeStart === rangeEnd ? `${rangeStart}` : `${rangeStart}-${rangeEnd}`);
    return ranges.join(",");
}

export function resolveCpuPartition(
    physicalCoreGroups: readonly (readonly number[])[],
    scyllaOverride?: string,
    runtimeOverride?: string,
): CpuPartition | null {
    if (physicalCoreGroups.length < 2) {
        if (scyllaOverride || runtimeOverride) {
            throw new Error("CPU set overrides require at least two complete physical cores");
        }
        return null;
    }
    const allCpus = new Set(physicalCoreGroups.flat());
    const scyllaCpus = scyllaOverride ? parseCpuSet(scyllaOverride) : undefined;
    const runtimeCpus = runtimeOverride ? parseCpuSet(runtimeOverride) : undefined;

    for (const [name, selected] of [["SCYLLA_CPUSET", scyllaCpus], ["PSY_RUNTIME_CPUSET", runtimeCpus]] as const) {
        if (!selected) continue;
        for (const cpu of selected) {
            if (!allCpus.has(cpu)) throw new Error(`${name} contains unavailable CPU ${cpu}`);
        }
        for (const siblings of physicalCoreGroups) {
            const selectedSiblingCount = siblings.filter((cpu) => selected.has(cpu)).length;
            if (selectedSiblingCount !== 0 && selectedSiblingCount !== siblings.length) {
                throw new Error(`${name} must include the complete physical core sibling group ${siblings.join(",")}`);
            }
        }
    }

    const defaultScyllaCoreCount = physicalCoreGroups.length >= 8 ? 2 : 1;
    const resolvedScylla = scyllaCpus ?? new Set(
        runtimeCpus
            ? [...allCpus].filter((cpu) => !runtimeCpus.has(cpu))
            : physicalCoreGroups.slice(0, defaultScyllaCoreCount).flat(),
    );
    const resolvedRuntime = runtimeCpus ?? new Set([...allCpus].filter((cpu) => !resolvedScylla.has(cpu)));
    const overlap = [...resolvedScylla].filter((cpu) => resolvedRuntime.has(cpu));
    if (overlap.length > 0) {
        throw new Error(`Runtime and Scylla CPU sets overlap on CPUs: ${overlap.sort((a, b) => a - b).join(",")}`);
    }
    const covered = new Set([...resolvedScylla, ...resolvedRuntime]);
    if (covered.size !== allCpus.size || [...allCpus].some((cpu) => !covered.has(cpu))) {
        throw new Error("Runtime and Scylla CPU sets must partition every available CPU");
    }
    if (resolvedScylla.size === 0 || resolvedRuntime.size === 0) {
        throw new Error("Runtime and Scylla CPU sets must both contain at least one CPU");
    }

    return {
        scyllaCpuSet: formatCpuSet([...resolvedScylla]),
        runtimeCpuSet: formatCpuSet([...resolvedRuntime]),
        scyllaLogicalCpuCount: physicalCoreGroups.filter((siblings) => siblings.every((cpu) => resolvedScylla.has(cpu))).length,
        runtimePhysicalCoreCount: physicalCoreGroups.filter((siblings) => siblings.every((cpu) => resolvedRuntime.has(cpu))).length,
    };
}

export function resolveCpuPartitionForAffinity(
    physicalCoreGroups: readonly (readonly number[])[],
    allowedCpus: ReadonlySet<number> | undefined,
    scyllaOverride?: string,
    runtimeOverride?: string,
): CpuPartition | null {
    if (!allowedCpus) return resolveCpuPartition(physicalCoreGroups, scyllaOverride, runtimeOverride);

    const onlineCpus = new Set(physicalCoreGroups.flat());
    const allowedOnlineCpus = new Set([...allowedCpus].filter((cpu) => onlineCpus.has(cpu)));
    if (allowedOnlineCpus.size === onlineCpus.size) {
        return resolveCpuPartition(physicalCoreGroups, scyllaOverride, runtimeOverride);
    }
    for (const siblings of physicalCoreGroups) {
        const selectedSiblingCount = siblings.filter((cpu) => allowedOnlineCpus.has(cpu)).length;
        if (selectedSiblingCount !== 0 && selectedSiblingCount !== siblings.length) {
            throw new Error(`Launcher CPU affinity must include the complete physical core sibling group ${siblings.join(",")}`);
        }
    }
    if (allowedOnlineCpus.size === 0) {
        throw new Error("Launcher CPU affinity contains no online CPUs");
    }

    const affinityRuntimeCpuSet = formatCpuSet([...allowedOnlineCpus]);
    if (runtimeOverride) {
        const requestedRuntimeCpus = parseCpuSet(runtimeOverride);
        const differsFromAffinity = requestedRuntimeCpus.size !== allowedOnlineCpus.size
            || [...requestedRuntimeCpus].some((cpu) => !allowedOnlineCpus.has(cpu));
        if (differsFromAffinity) {
            throw new Error(`PSY_RUNTIME_CPUSET must match the launcher CPU affinity ${affinityRuntimeCpuSet}`);
        }
    }
    return resolveCpuPartition(physicalCoreGroups, scyllaOverride, affinityRuntimeCpuSet);
}

export function resolveRayonThreadCount(availablePhysicalCores: number, provingProcessCount: number): number {
    const coresPerProcess = Math.floor(availablePhysicalCores / Math.max(1, provingProcessCount));
    return Math.max(1, Math.min(DEFAULT_PROVING_RAYON_THREADS, coresPerProcess));
}

export function resolvePositiveIntegerSetting(
    value: string | undefined,
    fallback: number,
    settingName: string,
): number {
    const resolved = value === undefined ? fallback : Number(value);
    if (!Number.isSafeInteger(resolved) || resolved < 1) {
        throw new Error(`${settingName} must be a positive integer, received '${value ?? ""}'`);
    }
    return resolved;
}

export function parseCpuSet(value: string): Set<number> {
    const cpuSet = new Set<number>();
    for (const rawRange of value.split(",")) {
        const range = rawRange.trim();
        const match = /^(\d+)(?:-(\d+))?$/.exec(range);
        if (!match) {
            throw new Error(`Invalid CPU set segment '${range}' in '${value}'`);
        }
        const firstCpu = Number(match[1]);
        const lastCpu = match[2] === undefined ? firstCpu : Number(match[2]);
        if (lastCpu < firstCpu || lastCpu > 4095) {
            throw new Error(`Invalid CPU set range '${range}' in '${value}'`);
        }
        for (let cpu = firstCpu; cpu <= lastCpu; cpu += 1) {
            cpuSet.add(cpu);
        }
    }
    if (cpuSet.size === 0) {
        throw new Error("CPU set must contain at least one CPU");
    }
    return cpuSet;
}

export function findCpuSetOverlap(left: string, right: string): number[] {
    const leftCpus = parseCpuSet(left);
    const rightCpus = parseCpuSet(right);
    return [...leftCpus].filter((cpu) => rightCpus.has(cpu)).sort((a, b) => a - b);
}

export function isCompilerFingerprintSource(sourcePath: string): boolean {
    const normalized = sourcePath.replaceAll("\\", "/");
    const lower = normalized.toLowerCase();
    const basename = lower.split("/").at(-1) ?? lower;
    const containsSensitiveName = ["credential", "credentials", "secret", "secrets", "auth"]
        .some((name) => lower.includes(name));
    if (basename.startsWith(".env")
        || containsSensitiveName
        || lower.endsWith(".pem")
        || lower.endsWith(".key")
        || normalized === ".compiler-artifact.json") {
        return false;
    }
    return normalized === "Cargo.toml"
        || normalized === "Cargo.lock"
        || normalized === "rust-toolchain.toml"
        || normalized === "Makefile"
        || basename === "build.rs"
        || basename === "precompiles.json"
        || basename === "package.json"
        || lower.endsWith(".rs")
        || lower.endsWith(".psy")
        || lower.endsWith(".toml")
        || lower.endsWith(".lock");
}

export function hasZstdMagic(bytes: Uint8Array): boolean {
    return bytes.length >= 4
        && bytes[0] === 0x28
        && bytes[1] === 0xb5
        && bytes[2] === 0x2f
        && bytes[3] === 0xfd;
}


export function shouldSkipBranchSync(value: string | undefined): boolean {
    return value?.trim() !== "0";
}

export function resolveRealmWorkerCount(
    explicitCount: string | undefined,
    hasOnlyOptions: boolean,
): number {
    if (explicitCount !== undefined) {
        return parseInt(explicitCount, 10);
    }

    // A full devnet needs a realm worker to prove its first non-empty GUTA
    // block. Without one, realms appear healthy while producing empty blocks,
    // then stall forever as soon as a real user end-cap arrives. Component-only
    // launches remain opt-in so `--db`, `--coordinator`, UI-only, etc. do not
    // unexpectedly start workers.
    return hasOnlyOptions ? 0 : 2;
}

export const COORDINATOR_PROCESSOR_READY_MARKER = "[COORD_CREATE] processor new done";
export const REALM_PROCESSOR_READY_MARKER = "[REALM_CREATE] processor new done";

/**
 * Processor readiness is announced by these complete marker messages. The
 * surrounding line may contain tracing metadata, but partial lifecycle
 * messages must never make the devnet advance to dependent services.
 */
export function isExactProcessorReadyLine(line: string, marker: string): boolean {
    const normalizedLine = line.replace(/\u001b\[[0-9;]*m/g, "").trimEnd();
    const markerIndex = normalizedLine.lastIndexOf(marker);
    const startsAtBoundary = markerIndex === 0 || /\s/.test(normalizedLine[markerIndex - 1] || "");
    return startsAtBoundary && markerIndex + marker.length === normalizedLine.length;
}

/**
 * Group-0 schema mutations can time out transiently on a busy single-node
 * Scylla instance. Only that narrow failure family is safe to retry during
 * initial processor creation; unrelated early exits must surface immediately.
 */
export function isTransientScyllaSchemaFailure(errorText: string): boolean {
    return errorText.split(/\r?\n/).some((line) => {
        const normalized = line.toLowerCase();
        const timedOut = /\b(?:timed out|timeout)\b/.test(normalized);
        const groupZeroAddEntry = normalized.includes("add_entry")
            && /\bgroup[ _-]?0\b/.test(normalized);
        const raftAddEntry = normalized.includes("raft operation")
            && normalized.includes("add_entry");
        const scyllaSchemaOperation = normalized.includes("schema")
            && (normalized.includes("scylla") || normalized.includes("cassandra"));
        return timedOut && (groupZeroAddEntry || raftAddEntry || scyllaSchemaOperation);
    });
}

// Log markers the processor binaries emit when they hit a fatal, unrecoverable
// error. Such a processor may keep running while producing empty blocks, so the
// devnet supervisor must terminate it and let auto-restart recreate it.
export const FATAL_PROCESSOR_ERROR_MARKERS: readonly string[] = [
    "[CFLI:PSY_REALM_PROCESSOR_ERROR]",
    "[CFLI:PSY_COORDINATOR_PROCESSOR_ERROR]",
];

/** True when a processor log line announces a fatal, unrecoverable error. */
export function isFatalProcessorErrorLine(line: string): boolean {
    return FATAL_PROCESSOR_ERROR_MARKERS.some((marker) => line.includes(marker));
}

/**
 * Decide whether a processor process emitting `line` should be terminated for
 * a supervised restart. Returns false once a kill has already been requested
 * (`alreadyRequested`), so duplicate log lines do not trigger repeated kills.
 */
export function shouldFatalRestartProcessor(line: string, alreadyRequested: boolean): boolean {
    return !alreadyRequested && isFatalProcessorErrorLine(line);
}

/**
 * Build the argv for a shell-free S3 (or any HTTP) fetch with curl, used by the
 * keystore trust-setup downloader. Pure so it can be unit-tested directly.
 *
 *   -f              fail-closed: non-zero exit on HTTP 4xx/5xx, so a truncated
 *                   or partial download never silently becomes the keystore.
 *   -S              still print error messages when stderr is not a TTY.
 *   -L              follow redirects (S3 presigned/CDN redirects).
 *   --progress-bar  force a visible progress meter even though stderr is piped
 *                   (curl suppresses its meter for non-TTY stderr by default),
 *                   so the ~hundreds-of-MB keystore downloads show live progress.
 *   -o <destPath>   write the body to the destination temp file; the atomic
 *                   temp/extract flow is handled by the caller.
 *
 * No --silent/--no-progress-meter: progress must stay visible. The argv is
 * passed straight to Bun.spawn (no shell).
 */
export function s3CurlArgs(url: string, destPath: string): string[] {
    return ["curl", "-f", "-S", "-L", "--progress-bar", "-o", destPath, url];
}
