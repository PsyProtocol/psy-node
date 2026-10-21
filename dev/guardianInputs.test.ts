import { describe, expect, it } from "bun:test";
import { promises as fs } from "node:fs";
import path from "node:path";
import { buildChainAuthorization, checkGenesisContracts, readGenesisContracts, validateLocalEndpoint } from "./guardianInputs";

describe("Local Guardian input discovery", () => {
    const address = (byte: string) => `0x${byte.repeat(40)}`;
    const hash = (byte: string) => `0x${byte.repeat(64)}`;
    const summary = () => ({ chainId: 31337, core: { Bridge: address("1"), StateManager: address("2"), PsyToken: address("5"), USDTToken: address("6"), PsyAddressesProvider: address("7") },
        implementations: { Bridge_Implementation: address("3"), StateManager_Implementation: address("4") },
        protocol: { chain: { l1ChainIndex: 0, l1ChainId: 31337 }, tokens: {
            PSY: { l1Address: address("5"), l2TokenContractId: "0x0" }, USDT: { l1Address: address("6"), l2TokenContractId: "0x4" },
        } } });
    const deployment = { address: address("1"), transactionHash: hash("a"), receipt: { blockNumber: 5, contractAddress: address("1") } };
    const calls: [string, unknown[]][] = [];
    const rpc = async (method: string, params: unknown[]) => {
        calls.push([method, params]);
        if (method === "eth_chainId") return "0x7a69";
        if (method === "eth_getBlockByNumber") {
            if (params[0] === "0x0") return { hash: hash("f"), number: "0x0" };
            if (params[0] === "0x5") return { hash: hash("d"), number: "0x5" };
            return { hash: hash("e"), number: "0x10" };
        }
        if (method === "eth_getTransactionReceipt") return { status: "0x1", blockNumber: "0x5", blockHash: hash("d"), transactionHash: hash("a"), contractAddress: address("1") };
        if (method === "eth_getStorageAt") return `0x${"0".repeat(24)}${(params[0] === address("1") ? address("3") : address("4")).slice(2)}`;
        if (method === "eth_getCode") return "0x6000";
        if (method === "eth_call") {
            const data = (params[0] as any).data;
            if (data === "0xcae81d60") return `0x${"0".repeat(64)}`;
            return `0x${"0".repeat(24)}${(data === "0xc72c4d10" ? address("7") : address("2")).slice(2)}`;
        }
        throw new Error(`Unexpected method ${method}`);
    };

    it("discovers a canonical deployment, pins code reads, and preserves token IDs", async () => {
        calls.length = 0;
        const result = await buildChainAuthorization(summary(), deployment, rpc, async () => hash("b"));
        expect(result.chain_index).toBe(0);
        expect(result.chain_id).toBe("0x7a69");
        expect(result.genesis_hash).toBe(hash("f"));
        expect(result.deployment_block).toBe(5);
        expect(result.bridge_implementation).toBe(address("3"));
        expect(result.token_mappings).toEqual([{ token: address("5"), l2_contract_id: 0 }, { token: address("6"), l2_contract_id: 4 }]);
        for (const [method, params] of calls.filter(([method]) => ["eth_getCode", "eth_getStorageAt", "eth_call"].includes(method))) {
            expect(params[method === "eth_getStorageAt" ? 2 : 1]).toEqual({ blockHash: hash("e"), requireCanonical: true });
        }
    });

    it("rejects chain, implementation, and receipt conflicts", async () => {
        const wrongChain = summary(); wrongChain.chainId = 1;
        await expect(buildChainAuthorization(wrongChain, deployment, rpc, async () => hash("b"))).rejects.toThrow("chain ID");
        const wrongImplementation = summary(); wrongImplementation.implementations.Bridge_Implementation = address("7");
        await expect(buildChainAuthorization(wrongImplementation, deployment, rpc, async () => hash("b"))).rejects.toThrow("implementation differs");
        await expect(buildChainAuthorization(summary(), deployment, async (method, params) => method === "eth_getTransactionReceipt" ? null : rpc(method, params), async () => hash("b"))).rejects.toThrow("receipt");
        await expect(buildChainAuthorization(summary(), deployment, async (method, params) => method === "eth_getTransactionReceipt" ? { ...await rpc(method, params), contractAddress: address("2") } : rpc(method, params), async () => hash("b"))).rejects.toThrow("created another contract");
        await expect(buildChainAuthorization(summary(), deployment, async (method, params) => method === "eth_call" ? `0x${"0".repeat(63)}1` : rpc(method, params), async () => hash("b"))).rejects.toThrow("chain index");
        await expect(buildChainAuthorization(summary(), deployment, async (method, params) => method === "eth_getBlockByNumber" && params[0] === "0x10" ? { number: "0x10", hash: hash("c") } : rpc(method, params), async () => hash("b"))).rejects.toThrow("L1 head changed");
    });

    it("restricts discovery to local credential-free endpoints", () => {
        for (const endpoint of ["http://127.0.0.1:8545", "http://localhost:9545", "http://[::1]:8545"]) expect(() => validateLocalEndpoint(endpoint)).not.toThrow();
        for (const endpoint of ["https://example.com", "http://user:secret@127.0.0.1:8545", "http://example.com"]) expect(() => validateLocalEndpoint(endpoint)).toThrow();
    });

    it("checks Genesis contracts against the adopted Genesis bundle", async () => {
        const directory = await fs.mkdtemp("/tmp/psy-guardian-genesis-contracts-");
        try {
            const contract = { deployer: 1, code_root: [1, 2, 3, 4], code_definition: { state_tree_height: 4, functions: [] } };
            const genesis = `${directory}/genesis.json`;
            const bundle = `${directory}/genesis_contracts.json`;
            await fs.writeFile(genesis, JSON.stringify({ contracts: [contract] }));
            await fs.writeFile(bundle, JSON.stringify([{ name: "multisig_policy", ...contract }]));
            await expect(checkGenesisContracts(genesis, bundle)).resolves.toBeUndefined();
            await fs.writeFile(bundle, JSON.stringify([{ name: "multisig_policy", ...contract, deployer: 2 }]));
            await expect(checkGenesisContracts(genesis, bundle)).rejects.toThrow("contracts differ");
        } finally {
            await fs.rm(directory, { recursive: true, force: true });
        }
    });

    it("keeps every Guardian ABI method aligned with the Genesis contract code", async () => {
        const root = path.resolve(import.meta.dir, "../psy-genesis");
        const contracts = await readGenesisContracts(path.join(root, "genesis_contracts.json")) as any[];
        for (const [id, name] of ["PsyTokenContract", "MultisigPolicyContract", "PsyDepositTreeContract", "PsyWithdrawalTreeContract", "USDTTokenContract"].entries()) {
            const abi = JSON.parse(await fs.readFile(path.join(root, "genesis_abi", `${name}.json`), "utf8"));
            const codeMethods = contracts[id].code_definition.functions.map((method: any) => method.method_id).sort((a: number, b: number) => a - b);
            const abiMethods = abi.contract.methods.map((method: any) => method.method_id).sort((a: number, b: number) => a - b);
            expect(abiMethods).toEqual(codeMethods);
        }
    });
});
