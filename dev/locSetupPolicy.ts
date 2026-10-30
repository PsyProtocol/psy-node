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

/** Unset or empty keeps the checkout's existing Docker identities. */
export const DEVNET_NAMESPACE_ENV = "PSY_DEVNET_NAMESPACE";

const DEVNET_NAMESPACE_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
const DOCKER_OBJECT_NAME_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,62}$/;

export const LEGACY_ENVIO_COMPOSE_PROJECT = "generated";
export const LEGACY_ENVIO_NETWORK = "local_test_network";
export const ENVIO_POSTGRES_SERVICE = "envio-postgres";
export const ENVIO_DATA_VOLUME = "db_data";

const DB_CONTAINER_SUFFIX = {
    valkey: "valkey-server",
    nats: "nats-server",
    scylla: "scylla-server",
    nostr: "nostr-relay",
} as const;

const DB_VOLUME_SUFFIX = {
    valkey: "psy-devnet-redis",
    scylla: "psy-devnet-scylla",
    scyllaData: "psy-devnet-scylla-data",
    nats: "psy-devnet-nats",
} as const;

export type DevnetDbContainers = { [Key in keyof typeof DB_CONTAINER_SUFFIX]: string };
export type DevnetDbVolumes = { [Key in keyof typeof DB_VOLUME_SUFFIX]: string };

export type DevnetDbNames = {
    namespace: string | null;
    containers: DevnetDbContainers;
    volumes: DevnetDbVolumes;
    envioComposeProject: string;
    envioNetwork: string;
    envioPostgresContainer: string;
    envioDataVolume: string;
};

export type DevnetIsolationResources = {
    containers: string[];
    volumes: string[];
    networks: string[];
};

function assertDockerObjectName(value: string, label: string): void {
    if (!DOCKER_OBJECT_NAME_PATTERN.test(value)) {
        throw new Error(`${label} is not a usable Docker object name`);
    }
}

function prefixDevnetName(namespace: string | null, legacyName: string): string {
    return namespace == null ? legacyName : `${namespace}-${legacyName}`;
}

function devnetDbNames(namespace: string | null): DevnetDbNames {
    const containers = {
        valkey: prefixDevnetName(namespace, DB_CONTAINER_SUFFIX.valkey),
        nats: prefixDevnetName(namespace, DB_CONTAINER_SUFFIX.nats),
        scylla: prefixDevnetName(namespace, DB_CONTAINER_SUFFIX.scylla),
        nostr: prefixDevnetName(namespace, DB_CONTAINER_SUFFIX.nostr),
    };
    const volumes = {
        valkey: prefixDevnetName(namespace, DB_VOLUME_SUFFIX.valkey),
        scylla: prefixDevnetName(namespace, DB_VOLUME_SUFFIX.scylla),
        scyllaData: prefixDevnetName(namespace, DB_VOLUME_SUFFIX.scyllaData),
        nats: prefixDevnetName(namespace, DB_VOLUME_SUFFIX.nats),
    };
    const envioComposeProject = prefixDevnetName(namespace, LEGACY_ENVIO_COMPOSE_PROJECT);
    const envioNetwork = namespace == null ? LEGACY_ENVIO_NETWORK : `${namespace}-${LEGACY_ENVIO_NETWORK}`;
    const names = {
        namespace,
        containers,
        volumes,
        envioComposeProject,
        envioNetwork,
        envioPostgresContainer: `${envioComposeProject}-${ENVIO_POSTGRES_SERVICE}-1`,
        envioDataVolume: `${envioComposeProject}_${ENVIO_DATA_VOLUME}`,
    };
    for (const name of [...Object.values(containers), ...Object.values(volumes), envioComposeProject, envioNetwork, names.envioPostgresContainer, names.envioDataVolume]) {
        assertDockerObjectName(name, "Resolved devnet resource");
    }
    return names;
}

export const LEGACY_DEVNET_DB_NAMES: DevnetDbNames = devnetDbNames(null);

/**
 * One resolved identity for the four DB containers and volumes, the Envio
 * Compose project, its explicit network, and the Postgres service container.
 * Null, undefined, and "" keep legacy names. Any other value must match
 * `^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`; namespaced results never equal a
 * legacy identity. `dev/start_db.sh` applies the same container and volume rule.
 */
export function resolveDevnetDbNames(namespace: string | null | undefined): DevnetDbNames {
    if (namespace == null || namespace === "") return LEGACY_DEVNET_DB_NAMES;
    if (!DEVNET_NAMESPACE_PATTERN.test(namespace)) {
        throw new Error(`${DEVNET_NAMESPACE_ENV} is invalid`);
    }
    return devnetDbNames(namespace);
}

export function resolveDevnetDbNamesFromEnv(
    env: Readonly<Record<string, string | undefined>>,
): DevnetDbNames {
    return resolveDevnetDbNames(env[DEVNET_NAMESPACE_ENV]);
}

export function devnetDbContainerNames(names: DevnetDbNames): string[] {
    return [names.containers.valkey, names.containers.nats, names.containers.scylla, names.containers.nostr];
}

export function devnetDbVolumeNames(names: DevnetDbNames): string[] {
    return [names.volumes.valkey, names.volumes.scylla, names.volumes.scyllaData, names.volumes.nats];
}

/** Containers, volumes, and network a selected namespace must not already own. */
export function devnetIsolationResources(names: DevnetDbNames): DevnetIsolationResources {
    return {
        containers: [...devnetDbContainerNames(names), names.envioPostgresContainer],
        volumes: [...devnetDbVolumeNames(names), names.envioDataVolume],
        networks: [names.envioNetwork],
    };
}

function envioPostgresExec(postgresContainer: string, command: readonly string[]): string[] {
    assertDockerObjectName(postgresContainer, "Envio Postgres container");
    return ["docker", "exec", postgresContainer, ...command];
}

export function psyServicesDatabaseCommands(
    purge: boolean,
    databaseExists: boolean,
    postgresContainer: string = LEGACY_DEVNET_DB_NAMES.envioPostgresContainer,
): string[][] {
    const drop = envioPostgresExec(postgresContainer, ["dropdb", "-U", "postgres", "--if-exists", "psy_services"]);
    const create = envioPostgresExec(postgresContainer, ["createdb", "-U", "postgres", "psy_services"]);
    if (purge) return [drop, create];
    return databaseExists ? [] : [create];
}
/** Resume probes an existing services database and never creates or drops one. */
export function retainedServicesDatabaseCommands(
    databaseExists: boolean,
    postgresContainer: string = LEGACY_DEVNET_DB_NAMES.envioPostgresContainer,
): string[][] {
    if (!databaseExists) throw new Error("[DevNet] retained resume requires the existing psy_services database");
    return psyServicesDatabaseCommands(false, true, postgresContainer);
}

export function envioPostgresReadinessCommand(
    postgresContainer: string = LEGACY_DEVNET_DB_NAMES.envioPostgresContainer,
): string[] {
    return envioPostgresExec(postgresContainer, ["psql", "-U", "postgres", "-d", "postgres", "-c", "select 1"]);
}

export function envioServicesDatabaseProbeCommand(
    postgresContainer: string = LEGACY_DEVNET_DB_NAMES.envioPostgresContainer,
): string[] {
    return envioPostgresExec(postgresContainer, [
        "psql", "-U", "postgres", "-d", "postgres", "-tAc",
        "SELECT 1 FROM pg_database WHERE datname = 'psy_services'",
    ]);
}

export function envioComposeCommand(
    composeFile: string,
    project: string,
    args: readonly string[],
): string[] {
    assertDockerObjectName(project, "Envio Compose project");
    if (composeFile.trim() === "" || args.length === 0 || args.some((arg) => arg === "")) {
        throw new Error("Envio Compose command is incomplete");
    }
    return ["docker", "compose", "-p", project, "-f", composeFile, ...args];
}

const ENVIO_NETWORK_NAME_LINE = /^([ \t]*)name:[ \t]*["']?([A-Za-z0-9][A-Za-z0-9_.-]*)["']?[ \t]*$/;

/**
 * Rewrites the generated Compose network's explicit `local_test_network` name.
 * Other `name:` entries are left alone. A namespaced run must find that line;
 * repeating the rewrite is a no-op.
 */
export function applyEnvioNetworkName(composeYaml: string, networkName: string): string {
    assertDockerObjectName(networkName, "Envio network");
    const lines = composeYaml.split("\n");
    let matches = 0;
    for (let index = 0; index < lines.length; index += 1) {
        const match = lines[index].match(ENVIO_NETWORK_NAME_LINE);
        if (!match) continue;
        const current = match[2];
        if (current !== LEGACY_ENVIO_NETWORK && current !== networkName) continue;
        matches += 1;
        if (current !== networkName) lines[index] = `${match[1]}name: ${networkName}`;
    }
    if (matches !== 1) {
        throw new Error(`Envio compose must contain exactly one explicit ${LEGACY_ENVIO_NETWORK} network name`);
    }
    return lines.join("\n");
}

export function pinFaucetPerClaimAmount(json: string): string {
    const config = JSON.parse(json);
    config.faucetPerClaimAmount = "1000000000000";
    return JSON.stringify(config);
}

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

    const defaultScyllaCoreCount = physicalCoreGroups.length >= 16 ? 4 : physicalCoreGroups.length >= 8 ? 2 : 1;
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

// Processor binaries emit these CFLI tokens on a fatal, unrecoverable error.
export const FATAL_PROCESSOR_ERROR_MARKERS = [
    "PSY_REALM_PROCESSOR_ERROR",
    "PSY_COORDINATOR_PROCESSOR_ERROR",
] as const;
export type FatalProcessorErrorMarker = (typeof FATAL_PROCESSOR_ERROR_MARKERS)[number];

/** Existing backoff: 1s exponential, cap 30s. Spawn-retry delay doubles, cap 60s. */
export const RESTART_BACKOFF_CAP_MS = 30_000;
export const RESTART_SPAWN_RETRY_CAP_MS = 60_000;
/** Ready/healthy interval that resets backoff. Circuit-build time is not healthy. */
export const RESTART_STABLE_RUN_MS = 60_000;
/** Consecutive identical typed failures that still auto-restart. The next identical failure stops. */
export const MAX_IDENTICAL_FAILURE_RESTARTS = 4;
export const SUPERVISOR_RESTART_LIMIT_TAG = "[DevNet][supervisor][restart-limit]";

export type SupervisedFailureCause =
    | { kind: "fatal-processor-error"; marker: FatalProcessorErrorMarker }
    | { kind: "signaled"; signal: string }
    | { kind: "exited"; code: number }
    | { kind: "spawn-failed" }
    | { kind: "dependency-restart" };

/** One retry record. First causal stderr is kept; kind is derived from cause. */
export type RestartStreak = {
    cause: SupervisedFailureCause | null;
    firstCause: string | null;
    firstObservedAtIso: string | null;
    identicalRepeats: number;
};

export type RestartPlan = {
    action: "restart" | "limit";
    restartCount: number;
    delayMs: number;
    streak: RestartStreak;
};

export function emptyRestartStreak(): RestartStreak {
    return { cause: null, firstCause: null, firstObservedAtIso: null, identicalRepeats: 0 };
}

/** Recheck after every backoff/spawn-retry sleep. Never clear intentionalStop to force a retry. */
export function shouldScheduleSupervisedRestart(stopping: boolean, intentionalStop: boolean): boolean {
    return !stopping && !intentionalStop;
}

/** Single prose boundary: exact `[CFLI:<token>]` → closed marker. */
export function parseFatalProcessorErrorMarker(line: string): FatalProcessorErrorMarker | null {
    for (const marker of FATAL_PROCESSOR_ERROR_MARKERS) {
        if (line.includes(`[CFLI:${marker}]`)) return marker;
    }
    return null;
}

/** Structured stderr event; never treat CFLI as the causal error. */
export function parseRealmProcessorFailureLine(line: string): string | null {
    const normalized = line.replace(/\u001b\[[0-9;]*m/g, "").trim();
    return normalized.startsWith("realm_processor_failure ") ? normalized : null;
}

export function classifySupervisedExit(opts: {
    spawnFailed?: boolean;
    fatalProcessorErrorMarker: FatalProcessorErrorMarker | null;
    dependencyRestartRequested: boolean;
    signalCode: string | null;
    exitCode: number | null;
}): SupervisedFailureCause {
    if (opts.spawnFailed) return { kind: "spawn-failed" };
    if (opts.fatalProcessorErrorMarker !== null) {
        return { kind: "fatal-processor-error", marker: opts.fatalProcessorErrorMarker };
    }
    if (opts.dependencyRestartRequested) return { kind: "dependency-restart" };
    if (opts.signalCode) return { kind: "signaled", signal: opts.signalCode };
    return { kind: "exited", code: opts.exitCode ?? 0 };
}

export function failureSignature(cause: SupervisedFailureCause): string {
    switch (cause.kind) {
        case "fatal-processor-error": return `fatal-processor-error:${cause.marker}`;
        case "signaled": return `signaled:${cause.signal}`;
        case "exited": return `exited:${cause.code}`;
        default: return cause.kind;
    }
}

export function nextRestartDelayMs(attempt: number): number {
    return Math.min(RESTART_BACKOFF_CAP_MS, 1_000 * Math.pow(2, Math.min(attempt - 1, 5)));
}

export function nextSpawnRetryDelayMs(restartDelayMs: number): number {
    return Math.min(RESTART_SPAWN_RETRY_CAP_MS, restartDelayMs * 2);
}

export function planSupervisedRestart(opts: {
    restartCount: number;
    streak: RestartStreak;
    cause: SupervisedFailureCause;
    firstCause: string | null;
    healthySinceMs: number;
    nowMs: number;
    observedAtIso: string;
}): RestartPlan {
    const stable = opts.healthySinceMs > 0 && opts.nowMs - opts.healthySinceMs >= RESTART_STABLE_RUN_MS;
    const restartCount = stable ? 0 : opts.restartCount;
    const streak = stable ? emptyRestartStreak() : opts.streak;
    const firstCause = stable ? opts.firstCause : (streak.firstCause ?? opts.firstCause);
    if (opts.cause.kind === "dependency-restart") {
        return { action: "restart", restartCount: restartCount + 1, delayMs: nextRestartDelayMs(restartCount + 1), streak };
    }
    const signature = failureSignature(opts.cause);
    const same = streak.cause !== null && failureSignature(streak.cause) === signature;
    const nextStreak: RestartStreak = same
        ? { ...streak, firstCause: streak.firstCause ?? firstCause, identicalRepeats: streak.identicalRepeats + 1 }
        : {
            cause: opts.cause,
            firstCause,
            firstObservedAtIso: streak.firstObservedAtIso ?? opts.observedAtIso,
            identicalRepeats: 1,
        };
    if (nextStreak.identicalRepeats > MAX_IDENTICAL_FAILURE_RESTARTS) {
        return { action: "limit", restartCount, delayMs: 0, streak: nextStreak };
    }
    return { action: "restart", restartCount: restartCount + 1, delayMs: nextRestartDelayMs(restartCount + 1), streak: nextStreak };
}

/** Anonymous public R2 reads; no shell, curl config, or authentication required. */
export function r2CurlArgs(prefix: string | undefined, key: string, destPath: string): string[] {
    if (!prefix || !/^[A-Za-z0-9._-]{1,128}$/.test(prefix) || prefix.includes("..")) {
        throw new Error("[AutoSetup] PSY_KEYSTORE_R2_PREFIX is required: one 1–128 character segment using letters, digits, '.', '_' or '-', without '..' (use localhost-<digest>)");
    }
    const url = `https://pub-23b7764b3820454094ce80557ab38d0b.r2.dev/${prefix}/${key}`;
    return ["curl", "-q", "-f", "-S", "-L", "--proto", "=https", "--proto-redir", "=https", "-o", destPath, url];
}

/**
 * psy-sdk declares psy-genesis as a submodule; prepare:wasm copies
 * ../../../psy-genesis/config.json into packages/psy-sdk before build.
 */
export const PSY_SDK_GENESIS_SUBMODULE = "psy-genesis";
export const PSY_SDK_GENESIS_CONFIG_REL = "psy-genesis/config.json";

/**
 * True when psy-sdk still needs `git submodule update --init` for psy-genesis
 * before consumers can read config.json.
 */
export function psySdkGenesisSubmoduleNeedsInit(opts: {
    gitMetadataPresent: boolean;
    configPresent: boolean;
}): boolean {
    return !opts.gitMetadataPresent || !opts.configPresent;
}

/**
 * psy-dapp ships nested gitlinks (psy-dapp/.gitmodules) for psy-genesis and
 * psy-contracts. The UI apps alias directly into them — @chain-config ->
 * psy-genesis/config.json, @protocol-config and @deployments ->
 * psy-contracts/protocol-config|deployments — so both gitlinks must be
 * initialized before UI dependency install or dev-server startup. A plain
 * `git submodule update --init --recursive` at the psy-node root never
 * reaches them when psy-dapp is pinned `update = none`; the nested gitlinks
 * must be initialized from inside the psy-dapp checkout.
 */
export const PSY_DAPP_NESTED_SUBMODULES = ["psy-genesis", "psy-contracts"] as const;
export type PsyDappNestedSubmodule = (typeof PSY_DAPP_NESTED_SUBMODULES)[number];

/**
 * Payload files (relative to each nested gitlink root) that the psy-dapp UI
 * reads at dev/build time. A gitlink is ready only when its git metadata AND
 * every payload file are present on disk.
 */
export const PSY_DAPP_NESTED_PAYLOADS: Readonly<Record<PsyDappNestedSubmodule, readonly string[]>> = {
    "psy-genesis": ["config.json"],
    "psy-contracts": ["protocol-config/index.ts", "deployments/index.ts"],
};

export type PsyDappNestedMissingPayloads = Readonly<Partial<Record<PsyDappNestedSubmodule, readonly string[]>>>;

export type PsyDappNestedInitPlan = {
    /** Nested gitlinks that still need `git submodule update --init`. */
    pending: PsyDappNestedSubmodule[];
    ready: boolean;
    /** Payload files (submodule-relative) missing on disk, per gitlink. */
    missingPayloads: PsyDappNestedMissingPayloads;
    /** `submodule update --init -- <pending...>` args to run from the psy-dapp checkout root. */
    updateArgs: string[];
};

/**
 * Pure readiness decision + path planning for the nested psy-dapp gitlinks.
 * Facts are gathered by the caller from the filesystem; this function never
 * touches the network or the filesystem, so it is unit-testable in isolation.
 */
export function planPsyDappNestedSubmoduleInit(opts: {
    /** Nested gitlinks whose .git gitlink metadata is absent on disk. */
    uninitialized: readonly PsyDappNestedSubmodule[];
    /** Payload files (submodule-relative) missing on disk. */
    missingPayloads?: PsyDappNestedMissingPayloads;
}): PsyDappNestedInitPlan {
    const missingPayloads: PsyDappNestedMissingPayloads = {};
    const pending: PsyDappNestedSubmodule[] = [];
    for (const name of PSY_DAPP_NESTED_SUBMODULES) {
        const payloads = opts.missingPayloads?.[name] ?? [];
        if (payloads.length > 0) missingPayloads[name] = payloads;
        if (opts.uninitialized.includes(name) || payloads.length > 0) {
            pending.push(name);
        }
    }
    const updateArgs = ["submodule", "update", "--init", "--", ...pending];
    return { pending, ready: pending.length === 0, missingPayloads, updateArgs };
}

/**
 * Repository-relative remedy for a plan that is not ready: the exact
 * `git submodule update --init` command (relative to the psy-node repo root,
 * `dappRelPath` is the psy-dapp checkout path, e.g. "psy-dapp") plus the
 * payload files that remain missing on disk.
 */
export function formatPsyDappNestedSubmoduleRemedy(
    dappRelPath: string,
    plan: PsyDappNestedInitPlan,
): string {
    if (plan.ready) return "";
    const command = `cd ${dappRelPath} && git submodule update --init -- ${plan.pending.join(" ")}`;
    const missingFiles = plan.pending.flatMap((name) =>
        (plan.missingPayloads[name] ?? []).map((rel) => `${dappRelPath}/${name}/${rel}`),
    );
    const payloadNote = missingFiles.length > 0
        ? ` Required payloads still missing on disk: ${missingFiles.join(", ")}.`
        : "";
    return `Run \`${command}\` from the psy-node repository root.${payloadNote}`;
}

export type WalletPasswordSource = "env" | "cached" | "default-devnet" | "prompt-required";

export type WalletPasswordPolicy = {
    source: WalletPasswordSource;
    password?: string;
    error?: string;
};

/**
 * Pure password resolution for the bridge-relayer keystore.
 *
 * Existing keystores must never silently invent the "devnet" default: a wrong
 * assumption only fails much later during decrypt/deploy. Auto-generated
 * keystores may still use the devnet default in non-interactive sessions.
 * Interactive sessions still prompt; non-TTY with an existing keystore requires
 * an explicit WALLET_PASSWORD.
 */
export function resolveWalletPasswordPolicy(opts: {
    envPassword: string | undefined;
    cachedPassword: string | null | undefined;
    isTty: boolean;
    keystoreExists: boolean;
    keystoreGeneratedThisRun: boolean;
}): WalletPasswordPolicy {
    const envPassword = opts.envPassword ?? "";
    if (envPassword.trim().length > 0) {
        return { source: "env", password: envPassword };
    }
    if (opts.cachedPassword && opts.cachedPassword.length > 0) {
        return { source: "cached", password: opts.cachedPassword };
    }

    const existingPreservedKeystore = opts.keystoreExists && !opts.keystoreGeneratedThisRun;
    if (existingPreservedKeystore) {
        if (!opts.isTty) {
            return {
                source: "prompt-required",
                error:
                    "WALLET_PASSWORD is required for an existing bridge-relayer keystore in a non-interactive session. " +
                    "Set WALLET_PASSWORD to the keystore password, or remove ~/.psy/keystore/bridge-relayer to regenerate a dev key encrypted with 'devnet'.",
            };
        }
        return { source: "prompt-required" };
    }

    if (!opts.isTty) {
        return { source: "default-devnet", password: "devnet" };
    }
    return { source: "prompt-required" };
}

/** True when decrypt stderr/stdout looks like a wrong keystore password (not a missing tool). */
export function isLikelyWrongKeystorePassword(errorText: string): boolean {
    const normalized = errorText.toLowerCase();
    return normalized.includes("invalid password")
        || normalized.includes("incorrect password")
        || normalized.includes("bad mac")
        || normalized.includes("could not decrypt")
        || normalized.includes("unable to decrypt")
        || normalized.includes("unsupported state or unable to authenticate data")
        || (normalized.includes("decrypt") && normalized.includes("password"));
}

/**
 * Actionable error when an existing bridge-relayer keystore cannot be decrypted.
 * Never echoes the password or keystore contents.
 */
export function formatBridgeRelayerKeystoreDecryptError(opts: {
    keystorePath: string;
    detail: string;
}): string {
    const detail = opts.detail.trim() || "unknown decrypt failure";
    const wrongPasswordHint = isLikelyWrongKeystorePassword(detail)
        ? "WALLET_PASSWORD does not match the existing keystore. "
        : "Could not decrypt the existing keystore (wrong WALLET_PASSWORD or corrupt file). ";
    return (
        `[DevNet] failed to decrypt bridge relayer keystore at ${opts.keystorePath}. ` +
        wrongPasswordHint +
        `Set the correct WALLET_PASSWORD, or remove the keystore to regenerate a dev key: rm -f ${opts.keystorePath}. ` +
        `Detail: ${detail}`
    );
}
