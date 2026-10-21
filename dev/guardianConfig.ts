import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

export function buildGuardianDaemonConfig(guardianPath: string, config: { client: { l1_endpoints: { chain_index: number; rpc_url: string }[] } }, repoRoot: string, homeDir: string): string {
    const networks = ["localhost", "localhostBsc", "localhostBase"];
    const endpoints = [...config.client.l1_endpoints].sort((a, b) => a.chain_index - b.chain_index);
    if (!endpoints.length || endpoints.some((endpoint, index) => endpoint.chain_index !== index || index >= networks.length)) {
        throw new Error("Local Guardian config requires contiguous chain indices starting at zero, with at most three chains");
    }
    for (const endpoint of endpoints) {
        const url = new URL(endpoint.rpc_url);
        if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || url.username || url.password) {
            throw new Error("Local Guardian daemon config requires credential-free localhost L1 RPC endpoints");
        }
    }
    const quote = JSON.stringify;
    const custody = `keystore_path = ${quote(path.join(homeDir, ".psy", "keystore", "bridge-relayer"))}\npassword_env = "WALLET_PASSWORD"`;
    return `guardian_config = ${quote(path.resolve(guardianPath))}
rpc_config = ${quote(path.join(repoRoot, "psy-genesis", "config.json"))}
services_url = "http://127.0.0.1:3000"
withdraw_method_id = 3055054724
proof_dir = ${quote(path.join(repoRoot, "local_checkpoints", "bridge_proposer"))}
poll_interval_secs = 15
confirmation_lag_checkpoints = 3

[finalize]
l1_rpc_url = ${quote(endpoints[0].rpc_url)}
deployments_network = "localhost"
${custody}
${endpoints.map((endpoint) => `
[[chains]]
family = "evm"
chain_index = ${endpoint.chain_index}
network_id = ${quote(networks[endpoint.chain_index])}
rpc_urls = [${quote(endpoint.rpc_url)}]
deployments_network = ${quote(networks[endpoint.chain_index])}
${custody}
`).join("")}`;
}

if (import.meta.main) {
    const [guardianPath, output] = process.argv.slice(2);
    if (!guardianPath || !output) throw new Error("Usage: guardianConfig.ts <guardian-config> <daemon-config-output>");
    const config = JSON.parse(await fs.readFile(guardianPath, "utf8"));
    const text = buildGuardianDaemonConfig(guardianPath, config, path.resolve(import.meta.dir, ".."), os.homedir());
    await fs.mkdir(path.dirname(path.resolve(output)), { recursive: true, mode: 0o700 });
    try {
        const file = await fs.open(output, "wx", 0o600);
        try { await file.writeFile(text); await file.sync(); } finally { await file.close(); }
        const parent = await fs.open(path.dirname(path.resolve(output)), "r");
        try { await parent.sync(); } finally { await parent.close(); }
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const metadata = await fs.lstat(output);
        if (!metadata.isFile() || metadata.uid !== process.getuid?.() || (metadata.mode & 0o7777) !== 0o600) {
            throw new Error("Existing daemon config must be an operator-owned regular file with mode 0600");
        }
        if (await fs.readFile(output, "utf8") !== text) throw new Error("Existing daemon config differs; select a new PSY_DEVNET_DIR instead of overwriting it");
    }
    console.log(`Guardian daemon config ready: ${output}`);
}
