import { promises as fs } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

type Rpc = (method: string, params: unknown[]) => Promise<any>;
const implementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

async function command(args: string[]): Promise<string> {
    const proc = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
    const [output, error, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
    if (code !== 0) throw new Error(`${args[0]} ${args[1]} failed: ${error || output}`);
    return output.trim();
}

async function readGenesisContracts(file: string): Promise<unknown[]> {
    const bytes = await fs.readFile(file);
    const text = bytes.subarray(0, 4).equals(Buffer.from([0x28, 0xb5, 0x2f, 0xfd]))
        ? await command(["zstd", "-dc", file])
        : bytes.toString("utf8");
    const contracts = JSON.parse(text);
    if (!Array.isArray(contracts)) throw new Error("psy-genesis/genesis_contracts.json must contain an array");
    return contracts;
}

export async function checkGenesisContracts(genesisData: string, genesisContracts: string): Promise<void> {
    const genesis = JSON.parse(await fs.readFile(genesisData, "utf8"));
    if (!Array.isArray(genesis.contracts)) throw new Error("genesis.json must contain a contracts array");
    const named = await readGenesisContracts(genesisContracts);
    const contracts = named.map((entry, index) => {
        if (entry === null || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`Genesis contract ${index} must be an object`);
        const { name, ...contract } = entry as Record<string, unknown>;
        if (typeof name !== "string" || name.trim() === "") throw new Error(`Genesis contract ${index} has no name`);
        return contract;
    });
    if (JSON.stringify(stableJson(genesis.contracts)) !== JSON.stringify(stableJson(contracts))) {
        throw new Error("genesis.json contracts differ from psy-genesis/genesis_contracts.json");
    }
}

function address(value: unknown): string {
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/.test(value)) throw new Error("Missing or invalid deployment address");
    return value.toLowerCase();
}

export function validateLocalEndpoint(endpoint: string): void {
    const url = new URL(endpoint);
    if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || url.username || url.password) {
        throw new Error("Guardian input discovery is restricted to credential-free localhost L1 RPCs");
    }
}

export async function buildChainAuthorization(summary: any, deployment: any, rpc: Rpc, hashCode: (code: string) => Promise<string>): Promise<any> {
    const chainIndex = summary.protocol.chain.l1ChainIndex;
    if (!Number.isSafeInteger(chainIndex) || chainIndex < 0 || chainIndex > 2) throw new Error("Invalid localhost chain index");
    const chainId = await rpc("eth_chainId", []);
    if (BigInt(chainId) !== BigInt(summary.chainId) || BigInt(chainId) !== BigInt(summary.protocol.chain.l1ChainId)) throw new Error("L1 chain ID differs from the deployment record");
    const genesis = await rpc("eth_getBlockByNumber", ["0x0", false]);
    const head = await rpc("eth_getBlockByNumber", ["latest", false]);
    if (!/^0x[0-9a-fA-F]{64}$/.test(genesis.hash) || !/^0x[0-9a-fA-F]{64}$/.test(head.hash)) throw new Error("Invalid L1 block hash");
    const block = { blockHash: head.hash, requireCanonical: true };
    const bridge = address(summary.core.Bridge);
    const stateManager = address(summary.core.StateManager);
    const call = async (to: string, data: string) => {
        const word = await rpc("eth_call", [{ to, data }, block]);
        if (typeof word !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(word)) throw new Error("Invalid L1 contract response");
        return word;
    };
    // ABI selectors for l1ChainIndex(), addressesProvider(), and getAddress(bytes32).
    if (BigInt(await call(stateManager, "0xcae81d60")) !== BigInt(chainIndex)) throw new Error("StateManager chain index differs from the deployment record");
    const providerWord = await call(bridge, "0xc72c4d10");
    if (!/^0x0{24}/.test(providerWord)) throw new Error("Invalid Bridge addresses provider");
    const provider = address(`0x${providerWord.slice(-40)}`);
    if (provider !== address(summary.core.PsyAddressesProvider)) throw new Error("Bridge addresses provider differs from the deployment record");
    const managerWord = await call(provider, "0x21f8a7217c0c08811839d3a8bfad3f26fd05feea7daf5d75bf9d6f3fe140cd8f62b7af38");
    if (!/^0x0{24}/.test(managerWord) || address(`0x${managerWord.slice(-40)}`) !== stateManager) throw new Error("Bridge registry points to another StateManager");
    if (address(deployment.address) !== bridge) throw new Error("Bridge deployment file differs from the summary");
    const receipt = await rpc("eth_getTransactionReceipt", [deployment.transactionHash]);
    if (!receipt || BigInt(receipt.status) !== 1n || receipt.transactionHash.toLowerCase() !== deployment.transactionHash.toLowerCase()
        || BigInt(receipt.blockNumber) !== BigInt(deployment.receipt.blockNumber) || BigInt(receipt.blockNumber) > BigInt(head.number)) throw new Error("Bridge deployment receipt is unavailable or inconsistent");
    if (address(receipt.contractAddress) !== bridge || address(deployment.receipt.contractAddress) !== bridge) throw new Error("Deployment receipt created another contract instead of Bridge");
    const receiptBlock = await rpc("eth_getBlockByNumber", [receipt.blockNumber, false]);
    if (receiptBlock.hash !== receipt.blockHash) throw new Error("Bridge deployment receipt is not canonical");
    const deploymentBlock = Number(BigInt(receipt.blockNumber));
    if (!Number.isSafeInteger(deploymentBlock)) throw new Error("Deployment block exceeds the supported integer range");
    const codeHash = async (target: string) => {
        const code = await rpc("eth_getCode", [target, block]);
        if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(code)) throw new Error(`No deployed code at ${target}`);
        const hash = await hashCode(code);
        if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error("Invalid deployed code hash");
        return hash;
    };
    const implementation = async (proxy: string, name: string) => {
        const storage = await rpc("eth_getStorageAt", [proxy, implementationSlot, block]);
        if (typeof storage !== "string" || !/^0x0{24}[0-9a-fA-F]{40}$/.test(storage)) throw new Error(`Invalid ${name} implementation slot`);
        const target = address(`0x${storage.slice(-40)}`);
        if (target !== address(summary.implementations[`${name}_Implementation`])) throw new Error(`${name} implementation differs from the deployment record`);
        return target;
    };
    const bridgeImplementation = await implementation(bridge, "Bridge");
    const managerImplementation = await implementation(stateManager, "StateManager");
    const tokens = Object.values(summary.protocol.tokens) as any[];
    const tokenMappings = tokens.map((token) => {
        const id = BigInt(token.l2TokenContractId);
        if (id !== 0n && id !== 4n) throw new Error("Local approval supports only the Genesis PSY and USDT token contracts");
        const tokenAddress = address(token.l1Address);
        const name = id === 0n ? "PsyToken" : "USDTToken";
        if (tokenAddress !== address(summary.core[name])) throw new Error("Token mapping differs from the deployment record");
        return { token: tokenAddress, l2_contract_id: Number(id) };
    }).sort((a, b) => a.l2_contract_id - b.l2_contract_id);
    if (tokenMappings.length !== 2 || tokenMappings[0].l2_contract_id !== 0 || tokenMappings[1].l2_contract_id !== 4) throw new Error("Local deployment must contain exactly PSY and USDT token mappings");
    const result = {
        chain_index: chainIndex, chain_id: chainId, genesis_hash: genesis.hash, bridge, state_manager: stateManager,
        bridge_code_hash: await codeHash(bridge), bridge_implementation: bridgeImplementation,
        bridge_implementation_code_hash: await codeHash(bridgeImplementation),
        state_manager_code_hash: await codeHash(stateManager), state_manager_implementation: managerImplementation,
        state_manager_implementation_code_hash: await codeHash(managerImplementation), deployment_block: deploymentBlock, token_mappings: tokenMappings,
    };
    // Recheck the pinned head after all contract/code reads.
    const canonical = await rpc("eth_getBlockByNumber", [head.number, false]);
    if (canonical.hash !== head.hash) throw new Error("L1 head changed during discovery");
    return result;
}

async function writePublic(output: string, bytes: string | Uint8Array): Promise<void> {
    await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
    try {
        const file = await fs.open(output, "wx", 0o600);
        try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
        const parent = await fs.open(path.dirname(output), "r");
        try { await parent.sync(); } finally { await parent.close(); }
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (!(await existingPublicMatches(output, bytes))) throw new Error(`Input differs: ${output}; use a new PSY_DEVNET_DIR`);
    }
}

function stableJson(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(stableJson);
    if (value !== null && typeof value === "object") {
        return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, item]) => [key, stableJson(item)]));
    }
    return value;
}

async function existingPublicMatches(output: string, expected: string | Uint8Array): Promise<boolean> {
    let metadata: Awaited<ReturnType<typeof fs.lstat>>;
    try { metadata = await fs.lstat(output); }
    catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
        throw error;
    }
    if (!metadata.isFile() || metadata.uid !== process.getuid?.() || (metadata.mode & 0o7777) !== 0o600) throw new Error(`Unsafe existing input: ${output}`);
    const current = Buffer.from(await fs.readFile(output));
    const next = Buffer.from(expected);
    try { return JSON.stringify(stableJson(JSON.parse(current.toString("utf8")))) === JSON.stringify(stableJson(JSON.parse(next.toString("utf8")))); }
    catch { return current.equals(next); }
}

async function findArtifacts(repoRoot: string, selected: string | undefined): Promise<Record<string, string>> {
    const names = ["token", "multisig_policy", "deposit_tree", "withdrawal_tree", "usdt_token"];
    const root = selected ? path.resolve(selected) : path.resolve(repoRoot, "../psy-compiler/psy-precompiles");
    const artifacts = Object.fromEntries(names.map((name) => [name, selected
        ? path.join(root, `${name}.json`)
        : path.join(root, name, "target", `${name}.json`)]));
    for (const [name, artifact] of Object.entries(artifacts)) {
        try {
            if (!(await fs.stat(artifact)).isFile()) throw new Error();
        } catch {
            throw new Error(`Missing canonical ${name} compiler artifact at ${artifact}; build the matching sibling psy-compiler first`);
        }
    }
    return artifacts;
}

if (import.meta.main) {
    const { values } = parseArgs({ args: process.argv.slice(2), options: {
        output: { type: "string" }, "policy-only": { type: "boolean" }, "compiler-artifacts": { type: "string" },
        "check-genesis-contracts-only": { type: "boolean" },
    } });
    if (!values.output && !values["check-genesis-contracts-only"]) throw new Error("--output is required");
    const repoRoot = path.resolve(import.meta.dir, "..");
    if (values["check-genesis-contracts-only"]) {
        await checkGenesisContracts(path.join(repoRoot, "genesis.json"), path.join(repoRoot, "psy-genesis/genesis_contracts.json"));
        console.log("genesis.json contracts match psy-genesis/genesis_contracts.json.");
        process.exit(0);
    }
    const artifacts = await findArtifacts(repoRoot, values["compiler-artifacts"]);
    console.log(`Compiler artifacts selected: ${Object.values(artifacts).join(", ")}`);
    const output = path.resolve(values.output!);
    await writePublic(path.join(output, "multisig_policy.json"), await fs.readFile(artifacts.multisig_policy));
    if (!values["policy-only"]) {
        const chains = [];
        const endpoints = [];
        for (const [chainIndex, network] of ["localhost", "localhostBsc", "localhostBase"].entries()) {
            const directory = path.join(repoRoot, "psy-contracts", "deployments", network);
            const summary = JSON.parse(await fs.readFile(path.join(directory, "deployed-contracts.json"), "utf8"));
            if (summary.network !== network || summary.protocol.chain.l1ChainIndex !== chainIndex) throw new Error("Deployment network or chain index differs");
            const endpoint = summary.protocol.chain.defaultRpcUrl;
            validateLocalEndpoint(endpoint);
            const rpc: Rpc = async (method, params) => {
                const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" },
                    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(15000), redirect: "error" });
                if (!response.ok) throw new Error(`L1 RPC HTTP ${response.status}`);
                const body = await response.json() as any;
                if (body.id !== 1 || body.error || body.result == null) throw new Error(`L1 RPC ${method} failed`);
                return body.result;
            };
            const deployment = JSON.parse(await fs.readFile(path.join(directory, "Bridge.json"), "utf8"));
            chains.push(await buildChainAuthorization(summary, deployment, rpc, (code) => command(["cast", "keccak", code])));
            endpoints.push({ chain_index: chainIndex, rpc_url: endpoint });
        }
        await fs.mkdir(output, { recursive: true, mode: 0o700 });
        const stage = await fs.mkdtemp(path.join(output, ".approved-contracts-"));
        try {
            const approved = path.join(stage, "approved-contracts.json");
            await command([path.join(repoRoot, "target/release/psy_relayer_cli"), "guardian-prepare-approved-contracts", "--genesis-data", path.join(repoRoot, "genesis.json"),
                ...Object.values(artifacts).flatMap((artifact) => ["--artifact", artifact]), "--output", approved]);
            await writePublic(path.join(output, "approved-contracts.json"), await fs.readFile(approved));
        } finally { await fs.rm(stage, { recursive: true, force: true }); }
        await writePublic(path.join(output, "chains.json"), JSON.stringify(chains));
        await writePublic(path.join(output, "l1-endpoints.json"), JSON.stringify(endpoints));
    }
    console.log(`Guardian public inputs ready: ${output}`);
}
