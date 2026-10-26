import fs from "node:fs/promises";
import path from "node:path";

type EnvioNames = {
    namespace: string | null;
    envioComposeProject: string;
    envioNetwork: string;
    envioPostgresContainer: string;
    envioDataVolume: string;
};
type Volume = { type: string; source?: string };
type Service = {
    container_name?: string;
    network_mode?: string;
    ports?: unknown[];
    volumes?: Volume[];
    [field: string]: unknown;
};
type Resource = { name?: string; external?: unknown; driver_opts?: unknown };
type EnvioCompose = {
    name?: string;
    services: Record<string, Service>;
    volumes?: Record<string, Resource | null>;
    networks?: Record<string, Resource | null>;
    [field: string]: unknown;
};

function validateEnvioNames(names: EnvioNames): void {
    if (!names.namespace || !/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(names.namespace)) {
        throw new Error("Envio requires an explicit devnet namespace");
    }
    // These are the existing native namespace resolver's names. Readiness and
    // teardown must retain exactly the same resource inventory as startup.
    const project = `${names.namespace}-generated`;
    if (names.envioComposeProject !== project
        || names.envioNetwork !== `${names.namespace}-local_test_network`
        || names.envioPostgresContainer !== `${project}-envio-postgres-1`
        || names.envioDataVolume !== `${project}_db_data`) {
        throw new Error("Envio resource names disagree with the native namespace");
    }
}

export function envioEnvironment(input: Record<string, string>): Record<string, string> {
    return {
        ...input,
        DATABASE_URL: "postgres://postgres:testing@127.0.0.1:15433/envio-dev",
        ENVIO_PG_HOST: "127.0.0.1",
        ENVIO_PG_PORT: "15433",
        ENVIO_PG_DATABASE: "envio-dev",
        ENVIO_PG_USER: "postgres",
        ENVIO_PG_PASSWORD: "testing",
        HASURA_GRAPHQL_ENDPOINT: "http://127.0.0.1:9080/v1/metadata",
    };
}

export function configureEnvio(input: EnvioCompose, names: EnvioNames): EnvioCompose {
    validateEnvioNames(names);
    const compose = structuredClone(input);
    if (!compose.services?.["envio-postgres"] || !compose.services?.["graphql-engine"]
        || Object.keys(compose.services).length !== 2) {
        throw new Error("Envio must contain exactly Postgres and GraphQL services");
    }
    if (!compose.volumes || Object.keys(compose.volumes).length !== 1 || !("db_data" in compose.volumes)) {
        throw new Error("Envio must use only the native db_data volume");
    }
    if (!compose.networks || Object.keys(compose.networks).length !== 1) {
        throw new Error("Envio must use one native network");
    }
    compose.name = names.envioComposeProject;
    for (const [name, service] of Object.entries(compose.services)) {
        if (service.network_mode) throw new Error("Envio network_mode bypasses the native network");
        if (service.volumes?.some(volume => volume.type !== "volume" || volume.source !== "db_data")) {
            throw new Error("Envio host mounts and unowned volumes are forbidden");
        }
        delete service.container_name;
        const postgres = name === "envio-postgres";
        service.ports = [{
            target: postgres ? 5432 : 8080,
            published: String(postgres ? 15433 : 9080),
            host_ip: "127.0.0.1",
            protocol: "tcp",
        }];
    }
    const volume = compose.volumes.db_data ?? {};
    if (volume.external || volume.driver_opts) throw new Error("External Envio storage is forbidden");
    volume.name = names.envioDataVolume;
    compose.volumes.db_data = volume;
    for (const [key, value] of Object.entries(compose.networks)) {
        const network = value ?? {};
        if (network.external) throw new Error("External Envio networks are forbidden");
        network.name = names.envioNetwork;
        compose.networks[key] = network;
    }
    return compose;
}

export async function configureEnvioFile(file: string, names: EnvioNames): Promise<void> {
    validateEnvioNames(names);
    file = path.resolve(file);
    if (path.basename(file) !== "docker-compose.yaml" || path.basename(path.dirname(file)) !== "generated") {
        throw new Error("Envio may rewrite only its generated Compose file");
    }
    const metadata = await fs.lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || await fs.realpath(file) !== file) {
        throw new Error("Envio generated Compose path must be a regular file without symlink ancestors");
    }
    const child = Bun.spawn([
        "docker", "compose", "-p", names.envioComposeProject,
        "-f", file, "config", "--format", "json",
    ], { cwd: path.dirname(file), stdout: "pipe", stderr: "pipe" });
    const [output, , code] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
    ]);
    if (code !== 0) throw new Error(`Envio Compose configuration failed (exit ${code})`);
    const configured = configureEnvio(JSON.parse(output), names);
    await fs.writeFile(file, JSON.stringify(configured, null, 2) + "\n");
}
