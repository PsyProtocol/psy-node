import {describe, expect, test} from "bun:test";
import {isolateCompose} from "./isolation";

const fixture = () => ({services: {
    "envio-postgres": {container_name: "shared-postgres", restart: "always", ports: ["5433:5432"],
        volumes: [{type: "volume", source: "db_data", target: "/data"}]},
    "graphql-engine": {ports: ["8080:8080"]},
}, networks: {shared: {name: "local_test_network"}}, volumes: {db_data: {name: "shared_data"}}});

describe("acceptance Compose isolation", () => {
    test("scopes containers, networks and volumes without modifying input", () => {
        const original = fixture();
        const out = isolateCompose(original);
        expect(out.name).toBe(process.env.COMPOSE_PROJECT_NAME);
        expect(out.services["envio-postgres"].container_name).toBeUndefined();
        expect(out.services["envio-postgres"].restart).toBe("no");
        expect(out.networks.shared.name).toBe(`${out.name}_shared`);
        expect(out.volumes.db_data.name).toBe(`${out.name}_db_data`);
        expect(original.networks.shared.name).toBe("local_test_network");
    });
    test("publishes only chosen loopback ports", () => {
        const out = isolateCompose(fixture());
        expect(out.services["envio-postgres"].ports).toEqual([
            {target:5432, published:"15433", host_ip:"127.0.0.1", protocol:"tcp"},
        ]);
        expect(out.services["graphql-engine"].ports[0].published).toBe("9080");
    });
    test("rejects foreign services", () => {
        const data: any = fixture(); data.services.other = {};
        expect(() => isolateCompose(data)).toThrow("Unexpected service");
    });
    test("rejects missing services", () => {
        expect(() => isolateCompose({services: {}})).toThrow("layout");
    });
    test("rejects host bind mounts", () => {
        const data: any = fixture(); data.services["envio-postgres"].volumes[0].type = "bind";
        expect(() => isolateCompose(data)).toThrow("host bind");
    });
    for (const section of ["networks", "volumes"]) {
        test(`rejects external ${section}`, () => {
            const data: any = fixture(); Object.values<any>(data[section])[0].external = true;
            expect(() => isolateCompose(data)).toThrow("External");
        });
    }
});
