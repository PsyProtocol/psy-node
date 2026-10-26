import { describe, expect, test } from "bun:test";
import { linkSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { configureEnvio, configureEnvioFile, envioEnvironment } from "./fresh-envio";

const names = {
    namespace: "psy-fixture",
    envioComposeProject: "psy-fixture-generated",
    envioNetwork: "psy-fixture-local_test_network",
    envioPostgresContainer: "psy-fixture-generated-envio-postgres-1",
    envioDataVolume: "psy-fixture-generated_db_data",
};

function compose() {
    return {
        name: "generated",
        services: {
            "envio-postgres": {
                image: "postgres:17.5", container_name: "shared-postgres",
                ports: ["5433:5432"],
                volumes: [{ type: "volume", source: "db_data", target: "/var/lib/postgresql/data" }],
                networks: { "my-proxy-net": null },
            },
            "graphql-engine": {
                image: "hasura/graphql-engine:v2.43.0", container_name: "shared-hasura",
                ports: ["8080:8080"], networks: { "my-proxy-net": null },
                environment: {
                    HASURA_GRAPHQL_DATABASE_URL: "postgres://postgres:testing@envio-postgres:5432/envio-dev",
                    PORT: "8080",
                },
                healthcheck: { test: ["CMD-SHELL", "test -n 8080"] },
            },
        },
        volumes: { db_data: { name: "shared-data", external: false } },
        networks: { "my-proxy-net": { name: "shared-network", external: false } },
    };
}

describe("fresh local Envio isolation", () => {
    test("uses the native resource inventory and loopback host ports without mutating input", () => {
        const input = compose();
        const before = JSON.stringify(input);
        const configured = configureEnvio(input, names);
        expect(JSON.stringify(input)).toBe(before);
        expect(configured.name).toBe(names.envioComposeProject);
        expect(configured.volumes?.db_data?.name).toBe(names.envioDataVolume);
        expect(configured.networks?.["my-proxy-net"]?.name).toBe(names.envioNetwork);
        expect(configured.services["envio-postgres"].container_name).toBeUndefined();
        expect(configured.services["graphql-engine"].container_name).toBeUndefined();
        expect(configured.services["envio-postgres"].ports).toEqual([
            { target: 5432, published: "15433", host_ip: "127.0.0.1", protocol: "tcp" },
        ]);
        expect(configured.services["graphql-engine"].ports).toEqual([
            { target: 8080, published: "9080", host_ip: "127.0.0.1", protocol: "tcp" },
        ]);
        expect(configured.services["graphql-engine"].environment).toEqual(input.services["graphql-engine"].environment);
        expect(configured.services["graphql-engine"].healthcheck).toEqual(input.services["graphql-engine"].healthcheck);
        expect(configureEnvio(configured, names)).toEqual(configured);
    });

    test("requires an explicit namespace matching native readiness and teardown names", () => {
        expect(() => configureEnvio(compose(), { ...names, namespace: null })).toThrow("explicit devnet namespace");
        expect(() => configureEnvio(compose(), { ...names, envioDataVolume: "shared-db" })).toThrow("native namespace");
        expect(() => configureEnvio(compose(), { ...names, envioNetwork: "foreign-network" })).toThrow("native namespace");
    });

    test("rejects external storage and networks", () => {
        const volume = compose();
        volume.volumes.db_data.external = true;
        expect(() => configureEnvio(volume, names)).toThrow("External Envio storage");
        const network = compose();
        network.networks["my-proxy-net"].external = true;
        expect(() => configureEnvio(network, names)).toThrow("External Envio networks");
        const driver = compose();
        Object.assign(driver.volumes.db_data, { driver_opts: { type: "none", device: "/foreign", o: "bind" } });
        expect(() => configureEnvio(driver, names)).toThrow("External Envio storage");
    });

    test("rejects host mounts, unowned volumes and host networking", () => {
        const bind = compose();
        Object.assign(bind.services["envio-postgres"].volumes[0], { type: "bind", source: "/foreign" });
        expect(() => configureEnvio(bind, names)).toThrow("host mounts");
        const volume = compose();
        volume.services["envio-postgres"].volumes[0].source = "foreign-db";
        expect(() => configureEnvio(volume, names)).toThrow("unowned volumes");
        const network = compose();
        Object.assign(network.services["envio-postgres"], { network_mode: "host" });
        expect(() => configureEnvio(network, names)).toThrow("network_mode");
    });

    test("does not add resources outside the native cleanup inventory", () => {
        const service = compose();
        Object.assign(service.services, { foreign: { image: "postgres:17.5" } });
        expect(() => configureEnvio(service, names)).toThrow("exactly Postgres and GraphQL");
        const volume = compose();
        Object.assign(volume.volumes, { extra: {} });
        expect(() => configureEnvio(volume, names)).toThrow("only the native db_data");
        const network = compose();
        Object.assign(network.networks, { extra: {} });
        expect(() => configureEnvio(network, names)).toThrow("one native network");
    });

    test("explicit PG settings override inherited defaults independently of DATABASE_URL", () => {
        const inherited = { DATABASE_URL: "postgres://foreign", ENVIO_PG_HOST: "foreign", ENVIO_PG_PORT: "5433", KEEP: "yes" };
        const configured = envioEnvironment(inherited);
        expect(inherited.ENVIO_PG_PORT).toBe("5433");
        expect(configured).toMatchObject({
            DATABASE_URL: "postgres://postgres:testing@127.0.0.1:15433/envio-dev",
            ENVIO_PG_HOST: "127.0.0.1", ENVIO_PG_PORT: "15433", ENVIO_PG_DATABASE: "envio-dev",
            ENVIO_PG_USER: "postgres", ENVIO_PG_PASSWORD: "testing",
            HASURA_GRAPHQL_ENDPOINT: "http://127.0.0.1:9080/v1/metadata", KEEP: "yes",
        });
    });

    test("rewrites only generated Compose while preserving source artifact bytes", async () => {
        const directory = mkdtempSync(path.join(tmpdir(), "fresh-envio-"));
        try {
            const generated = path.join(directory, "generated");
            mkdirSync(generated);
            const file = path.join(generated, "docker-compose.yaml");
            const artifact = path.join(directory, "genesis_contracts.json");
            const stamp = path.join(directory, ".genesis_contracts.compiler-artifact.json");
            writeFileSync(file, JSON.stringify(compose()));
            writeFileSync(artifact, "unchanged artifact\n");
            writeFileSync(stamp, "unchanged stamp\n");
            await configureEnvioFile(path.relative(process.cwd(), file), names);
            const configured = JSON.parse(readFileSync(file, "utf8"));
            expect(configured.services["envio-postgres"].ports[0].published).toBe("15433");
            expect(configured.services["graphql-engine"].ports[0].published).toBe("9080");
            await expect(configureEnvioFile(artifact, names)).rejects.toThrow("only its generated Compose");
            expect(readFileSync(artifact, "utf8")).toBe("unchanged artifact\n");
            expect(readFileSync(stamp, "utf8")).toBe("unchanged stamp\n");
        } finally {
            rmSync(directory, { recursive: true, force: true });
        }
    });

    test("refuses a generated Compose symlink without changing its target", async () => {
        const directory = mkdtempSync(path.join(tmpdir(), "fresh-envio-link-"));
        try {
            const generated = path.join(directory, "generated");
            mkdirSync(generated);
            const target = path.join(directory, "source.json");
            const original = JSON.stringify(compose());
            writeFileSync(target, original);
            symlinkSync(target, path.join(generated, "docker-compose.yaml"));
            await expect(configureEnvioFile(path.join(generated, "docker-compose.yaml"), names)).rejects.toThrow("regular file");
            expect(readFileSync(target, "utf8")).toBe(original);
        } finally {
            rmSync(directory, { recursive: true, force: true });
        }
    });

    test("refuses a generated Compose hardlink to a source artifact", async () => {
        const directory = mkdtempSync(path.join(tmpdir(), "fresh-envio-hardlink-"));
        try {
            const generated = path.join(directory, "generated");
            mkdirSync(generated);
            const artifact = path.join(directory, "genesis_contracts.json");
            const original = JSON.stringify(compose());
            writeFileSync(artifact, original);
            linkSync(artifact, path.join(generated, "docker-compose.yaml"));
            await expect(configureEnvioFile(path.join(generated, "docker-compose.yaml"), names)).rejects.toThrow("regular file");
            expect(readFileSync(artifact, "utf8")).toBe(original);
        } finally {
            rmSync(directory, { recursive: true, force: true });
        }
    });
});
