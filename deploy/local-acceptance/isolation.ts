import fs from "node:fs/promises";
import path from "node:path";

// This module is imported only by the deployment-owned local launcher overlay.
// A missing scope must fail before the launcher's cleanup or auto-setup runs.
if (process.env.PSY_ACCEPTANCE !== "1") throw new Error("PSY_ACCEPTANCE=1 is required");
const project = process.env.COMPOSE_PROJECT_NAME || "";
if (!/^psy-accept-[a-z0-9-]+-envio$/.test(project)) throw new Error("Invalid acceptance Compose project");

function port(name: string): number {
    const value = Number(process.env[name]);
    if (!Number.isInteger(value) || value < 1024 || value > 65535) throw new Error(`Invalid ${name}`);
    return value;
}

const postgresPort = port("ENVIO_PG_PORT");
const hasuraPort = port("HASURA_EXTERNAL_PORT");
if ([5432, 5433, 5434, 55432].includes(postgresPort) || hasuraPort === 8080) {
    throw new Error("Acceptance must not use shared database/Hasura ports");
}
export const acceptance = {
    project,
    postgresPort,
    hasuraUrl: `http://127.0.0.1:${hasuraPort}`,
    databaseUrl: `postgres://postgres:testing@127.0.0.1:${postgresPort}/envio-dev`,
};

export async function configureAcceptanceCompose(file: string): Promise<void> {
    const proc = Bun.spawn(["docker", "compose", "-f", file, "config", "--format", "json"], {
        cwd: path.dirname(file), stdout: "pipe", stderr: "pipe",
    });
    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();
    if (await proc.exited !== 0) throw new Error(`Compose config failed: ${error}`);
    const config = isolateCompose(JSON.parse(output));
    // JSON is valid Compose YAML and avoids rewriting YAML with text substitutions.
    await fs.writeFile(file, JSON.stringify(config, null, 2) + "\n");
}

export function isolateCompose(input: any): any {
    const config = structuredClone(input);
    config.name = project;
    if (!config.services?.["envio-postgres"] || !config.services?.["graphql-engine"]) {
        throw new Error("Unexpected Envio Compose service layout");
    }
    for (const [name, service] of Object.entries<any>(config.services)) {
        if (!["envio-postgres", "graphql-engine"].includes(name)) throw new Error(`Unexpected service ${name}`);
        delete service.container_name;
        service.restart = "no";
        const isPostgres = name === "envio-postgres";
        service.ports = [{target: isPostgres ? 5432 : 8080,
            published: String(isPostgres ? postgresPort : hasuraPort), host_ip: "127.0.0.1", protocol: "tcp"}];
        for (const volume of service.volumes || []) {
            if (volume.type !== "volume") throw new Error("Unexpected Envio host bind mount");
        }
    }
    for (const section of ["volumes", "networks"]) {
        for (const [name, value] of Object.entries<any>(config[section] || {})) {
            if (value.external) throw new Error(`External ${section} not allowed`);
            value.name = `${project}_${name}`;
        }
    }
    return config;
}
