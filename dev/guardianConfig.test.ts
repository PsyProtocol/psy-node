import { describe, expect, it } from "bun:test";
import { buildGuardianDaemonConfig } from "./guardianConfig";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

describe("Guardian daemon config", () => {
    it("uses the selected Guardian root and keeps destination chain indices", () => {
        const text = buildGuardianDaemonConfig("/operator/guardians/config.json", { client: { l1_endpoints: [
            { chain_index: 1, rpc_url: "http://127.0.0.1:9545" },
            { chain_index: 0, rpc_url: "http://127.0.0.1:8545" },
        ] } }, "/repo", "/operator");
        const config = Bun.TOML.parse(text);
        expect(config.guardian_config).toBe("/operator/guardians/config.json");
        expect(config.rpc_config).toBe("/repo/psy-genesis/config.json");
        expect(config.withdraw_method_id).toBe(3055054724);
        expect(config.chains.map((chain: any) => [chain.chain_index, chain.network_id, chain.rpc_urls])).toEqual([
            [0, "localhost", ["http://127.0.0.1:8545"]], [1, "localhostBsc", ["http://127.0.0.1:9545"]],
        ]);
    });

    it("uses the withdraw method ID from the current token ABI", async () => {
        const abi = JSON.parse(await fs.readFile(path.join(import.meta.dir, "../psy-genesis/genesis_abi/PsyTokenContract.json"), "utf8"));
        const withdraw = abi.contract.methods.find((method: { name: string }) => method.name === "withdraw");
        const text = buildGuardianDaemonConfig("/operator/guardians/config.json", { client: { l1_endpoints: [
            { chain_index: 0, rpc_url: "http://127.0.0.1:8545" },
        ] } }, "/repo", "/operator");
        expect(Bun.TOML.parse(text).withdraw_method_id).toBe(withdraw.method_id);
        const template = await fs.readFile(path.join(import.meta.dir, "../psy_cli/psy_relayer_cli/config/local.toml"), "utf8");
        expect(Bun.TOML.parse(template).withdraw_method_id).toBe(withdraw.method_id);
    });

    it("rejects missing indices and non-local endpoints", () => {
        for (const endpoints of [[], [{ chain_index: 1, rpc_url: "http://127.0.0.1:9545" }], [{ chain_index: 0, rpc_url: "https://example.com" }]]) {
            expect(() => buildGuardianDaemonConfig("/config.json", { client: { l1_endpoints: endpoints } }, "/repo", "/operator")).toThrow();
        }
    });

    it("creates private config, reuses it, and refuses to replace different contents", async () => {
        const directory = await fs.mkdtemp(path.join(os.tmpdir(), "psy-guardian-config-"));
        try {
            const guardian = path.join(directory, "config.json");
            const output = path.join(directory, "daemon.toml");
            await fs.writeFile(guardian, JSON.stringify({ client: { l1_endpoints: [{ chain_index: 0, rpc_url: "http://127.0.0.1:8545" }] } }));
            const run = async () => {
                const proc = Bun.spawn([process.execPath, path.join(import.meta.dir, "guardianConfig.ts"), guardian, output], { stdout: "pipe", stderr: "pipe" });
                await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
                return proc.exited;
            };
            expect(await run()).toBe(0);
            const before = await fs.readFile(output, "utf8");
            expect((await fs.stat(output)).mode & 0o777).toBe(0o600);
            expect(await run()).toBe(0);
            expect(await fs.readFile(output, "utf8")).toBe(before);
            await fs.writeFile(output, "retained operator config");
            expect(await run()).not.toBe(0);
            expect(await fs.readFile(output, "utf8")).toBe("retained operator config");
        } finally {
            await fs.rm(directory, { recursive: true, force: true });
        }
    });
});
