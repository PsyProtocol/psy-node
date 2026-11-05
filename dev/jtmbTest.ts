/** Isolated JTMB core tests. Lifecycle stays in locSetupV4.ts. */
import { parseArgs } from "node:util";
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { realmP2pHttpPort, strategy5UserIdFromRegistrationId } from "./locSetupV4";

const ROOT = path.resolve(import.meta.dir, "..");
const BACKEND = "jtmb-poseidon-goldilocks";
const readJson = (file: string) => JSON.parse(readFileSync(file, "utf8"));
const saveJson = (file: string, value: unknown) => writeFileSync(file, JSON.stringify(value, null, 2), { mode: 0o600 });
const binding = () => existsSync(path.join(ROOT, "local_checkpoints/devnet-namespace"))
    ? readFileSync(path.join(ROOT, "local_checkpoints/devnet-namespace"), "utf8").trim() : "";

export function validateNamespace(namespace: string, current: string): void {
    if (!/^jtmb[-a-z0-9]*$/.test(namespace) || (current !== "" && current !== namespace)) {
        throw new Error("Use a dedicated jtmb-prefixed namespace; existing binding must match");
    }
}

function requireJTMB(allowStopped = false): void {
    validateNamespace(binding(), binding());
    const processList = Bun.spawnSync(["ps", "-axo", "pid,args"]);
    if (processList.exitCode !== 0) throw new Error("Cannot inspect node proving backends");
    let found = 0;
    for (const line of processList.stdout.toString().split("\n")) {
        const match = line.match(/^\s*(\d+)\s+(\S+)(?:\s+(.*))?$/);
        if (!match || !["psy_node_cli", "psy_worker_cli"].includes(path.basename(match[2]))) continue;
        const [, pid, executable, args = ""] = match;
        let belongs = path.isAbsolute(executable) && path.dirname(executable) === path.join(ROOT, "target/release");
        if (!path.isAbsolute(executable)) {
            try { belongs = realpathSync(`/proc/${pid}/cwd`) === ROOT; }
            catch {
                const cwd = Bun.spawnSync(["lsof", "-a", "-p", pid, "-d", "cwd", "-Fn"]);
                belongs = cwd.exitCode === 0 && cwd.stdout.toString().split("\n").includes(`n${ROOT}`);
            }
        }
        if (!belongs) continue;
        if (args.match(/--proving-backend(?:=|\s+)(\S+)/)?.[1] !== BACKEND) {
            throw new Error("This checkout contains a non-JTMB node/worker");
        }
        found++;
    }
    if (found === 0 && !allowStopped) throw new Error("No running JTMB nodes found for this checkout");
}

async function rpc(url: string, method: string, params: unknown[]): Promise<any> {
    const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: `psy_${method}`, params }), signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
    const body = await response.json() as any;
    if (body.error) throw new Error(JSON.stringify(body.error));
    return body.result;
}

export function getRealmRpcUrls(realm: any): string[] {
    return realm.validators.flatMap((validator: any, index: number) => validator.edge_nodes.map((_: unknown, edgeIndex: number) => {
        const url = new URL(realm.rpc_url[0]);
        url.port = String(realmP2pHttpPort(realm.id, index + 1, edgeIndex, validator.edge_nodes.length));
        return url.toString();
    }));
}

function getNetwork() {
    const config = path.join(ROOT, "local_checkpoints/realm_p2p/config.json");
    const network = readJson(config).networks.localhost;
    const coordinator: string = network.coordinator_configs[0].rpc_url[0];
    const realms = new Map<number, string[]>(network.realm_configs.map((realm: any) => [realm.id, getRealmRpcUrls(realm)]));
    const urls = [...new Set([coordinator, ...[...realms.values()].flat()])];
    if (urls.some(url => !["127.0.0.1", "localhost", "[::1]"].includes(new URL(url).hostname))) {
        throw new Error("JTMB tests require local RPC endpoints");
    }
    return { config, network, coordinator, realms, urls };
}

type Network = ReturnType<typeof getNetwork>;

export async function getCommonCheckpoint(urls: string[]): Promise<number> {
    const checkpoint = Math.min(...await Promise.all(urls.map(url => rpc(url, "get_latest_checkpoint_id", []))));
    const roots = await Promise.all(urls.map(url => rpc(url, "get_checkpoint_global_state_roots", [checkpoint])));
    if (roots.some(root => JSON.stringify(root) !== JSON.stringify(roots[0]))) throw new Error(`State roots differ at checkpoint ${checkpoint}`);
    return checkpoint;
}

async function waitFor<T>(check: () => Promise<T | undefined>, seconds: number): Promise<T> {
    const deadline = Date.now() + seconds * 1000;
    while (true) {
        const result = await check();
        if (result !== undefined) return result;
        if (Date.now() >= deadline) throw new Error("Timed out waiting for confirmed test state");
        await Bun.sleep(2000);
    }
}

async function mapConcurrent<T, R>(items: T[], concurrency: number, run: (item: T, index: number) => Promise<R>): Promise<R[]> {
    const results = new Array<R>(items.length);
    let next = 0;
    const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (next < items.length) {
            const index = next++;
            results[index] = await run(items[index], index);
        }
    });
    const completed = await Promise.allSettled(workers);
    const failure = completed.find(result => result.status === "rejected");
    if (failure?.status === "rejected") throw failure.reason;
    return results;
}

async function runCli(binary: string, args: string[], log: string, timeout: number, key?: string): Promise<void> {
    const env = { ...process.env };
    for (const name of ["PRIVATE_KEY", "KEYSTORE_PATH", "WALLET_PASSWORD"]) delete env[name];
    if (key !== undefined) env.PRIVATE_KEY = key;
    const fd = openSync(log, "w", 0o600);
    try {
        const child = Bun.spawn([path.join(ROOT, "target/release", binary), ...args], { cwd: ROOT, env, stdout: fd, stderr: fd });
        const timer = setTimeout(() => child.kill(), timeout * 1000);
        try {
            if (await child.exited !== 0) throw new Error(`Client failed; inspect ${log}`);
        } finally { clearTimeout(timer); }
    } finally { closeSync(fd); }
}

export function selectOrdinaryAccounts(total: number, users: number, validators: number[], realms: Map<number, string[]>): Array<{ uid: number; url: string }> {
    const accounts: Array<{ uid: number; url: string }> = [];
    for (let registration = 0; registration < total && accounts.length < users; registration++) {
        const uid = strategy5UserIdFromRegistrationId(registration);
        if (uid === 0 || validators.includes(uid) || registration === 2) continue;
        const urls = realms.get(Math.floor(uid / 2 ** 20));
        if (urls?.length) accounts.push({ uid, url: urls[accounts.length % urls.length] });
    }
    if (accounts.length !== users) throw new Error(`Only ${accounts.length} ordinary accounts available; run make jtmb-register first`);
    return accounts;
}

async function runBatch(net: Network, output: string, users: number, rounds: number, concurrency: number, timeout: number): Promise<void> {
    if (net.network.global_user_tree_height !== 32 || net.network.realm_user_tree_height !== 20 || net.network.group_realm_height !== 1) {
        throw new Error("Account selection requires Strategy5 COORD=12, REALM=20, GROUP=1");
    }
    const validators = net.network.realm_configs.flatMap((realm: any) => realm.validators.map((v: any) => v.user_id ?? v.validator_user_id));
    const total = (await rpc(net.coordinator, "get_latest_l2_block_state", [])).next_user_id;
    const accounts = selectOrdinaryAccounts(total, users, validators, net.realms);
    const results: unknown[] = [];
    for (let round = 1; round <= rounds; round++) {
        const checkpoint = await getCommonCheckpoint(net.urls);
        const before = await Promise.all(accounts.map(({ uid, url }) => rpc(url, "get_user_leaf_data", [checkpoint, uid])));
        await mapConcurrent(accounts, concurrency, async ({ uid, url }) => runCli("psy_worker_cli", [
            "dummy-end-cap-prover-lite", "--realm-api-url", url, "--coordinator-url", net.coordinator,
            "--network", "local-devnet", "--proving-backend", BACKEND, "--start-user-id", String(uid), "--count", "1", "--batches", "1",
            "--min-state-updates", "1", "--max-state-updates", "2", "--max-contract-calls", "1",
        ], path.join(output, `round${round}-user${uid}.log`), timeout));
        const confirmed = await waitFor(async () => {
            const checkpoint = await getCommonCheckpoint(net.urls);
            const leaves = await Promise.all(accounts.map(({ uid, url }) => rpc(url, "get_user_leaf_data", [checkpoint, uid])));
            if (leaves.some((leaf, index) => leaf.nonce !== before[index].nonce + 1)) return undefined;
            for (let index = 0; index < accounts.length; index++) {
                const { uid } = accounts[index];
                const replicas = await Promise.all(net.realms.get(Math.floor(uid / 2 ** 20))!.map(url => rpc(url, "get_user_leaf_data", [checkpoint, uid])));
                if (replicas.some(leaf => JSON.stringify(leaf) !== JSON.stringify(leaves[index]))) throw new Error(`Replica leaf mismatch for ${uid}`);
            }
            return { round, checkpoint, nonces: Object.fromEntries(accounts.map(({ uid }, index) => [uid, leaves[index].nonce])) };
        }, timeout);
        results.push(confirmed);
        saveJson(path.join(output, "results.json"), results);
        console.log(`round ${round}/${rounds}: ${accounts.length} EndCaps confirmed at checkpoint ${confirmed.checkpoint}`);
    }
}

async function registerUsers(net: Network, output: string, count: number, concurrency: number, timeout: number): Promise<void> {
    const modulus = (1n << 64n) - (1n << 32n) + 1n;
    const keys = Array.from({ length: count }, () => Array.from({ length: 4 }, () => (randomBytes(8).readBigUInt64BE() % modulus).toString(16).padStart(16, "0")).join(""));
    saveJson(path.join(output, "private_keys.json"), keys);
    const publicKeys = await mapConcurrent(keys, concurrency, async (key, index) => {
        const result = path.join(output, `register-${index}.json`);
        await runCli("psy_user_cli", ["--result-file", result, "register-user", "--rpc-config", net.config], path.join(output, `register-${index}.log`), timeout, key);
        const registration = readJson(result);
        if (registration.status !== "pending") throw new Error("Expected a fresh registration");
        return registration.public_key_hash as string;
    });
    const users = await waitFor(async () => {
        const ids = await Promise.all(publicKeys.map(key => rpc(net.coordinator, "get_user_ids_for_public_key", [key, 0, 64])));
        return ids.every(values => values.length) ? ids.map(values => values[0] as number) : undefined;
    }, timeout);
    if (new Set(users).size !== count) throw new Error("Registered user IDs are not distinct");
    const total = (await rpc(net.coordinator, "get_latest_l2_block_state", [])).next_user_id;
    const indices = new Map(Array.from({ length: total }, (_, index) => [strategy5UserIdFromRegistrationId(index), index]));
    const checkpoint = await waitFor(async () => {
        const checkpoint = await getCommonCheckpoint(net.urls);
        const leaves = await Promise.all(users.map(uid => rpc(net.coordinator, "get_user_registration_tree_leaf_hash", [checkpoint, indices.get(uid)])));
        return leaves.every((leaf, index) => leaf === publicKeys[index]) ? checkpoint : undefined;
    }, timeout);
    saveJson(path.join(output, "results.json"), { checkpoint, user_ids: users, public_keys: publicKeys });
    console.log(`${users.length} new accounts registered and included at checkpoint ${checkpoint}`);
}

async function deployContract(net: Network, output: string, contract: string, timeout: number): Promise<void> {
    let key = process.env.PRIVATE_KEY;
    if (!key) {
        const tests = path.join(ROOT, "local_checkpoints/jtmb_tests");
        const registration = readdirSync(tests).sort().reverse().find(name => name.includes("-register-")
            && existsSync(path.join(tests, name, "results.json")) && existsSync(path.join(tests, name, "private_keys.json")));
        if (!registration) throw new Error("Run make jtmb-register first, or supply an already registered PRIVATE_KEY through the environment");
        key = readJson(path.join(tests, registration, "private_keys.json"))[0];
    }
    const command = path.join(output, "deploy-command.json");
    await runCli("psy_user_cli", ["deploy-contract", "--rpc-config", net.config, "--contract-path", path.resolve(contract), "--output-path", command],
        path.join(output, "prepare-deploy.log"), Math.max(timeout, 600), key);
    const payload = readJson(command);
    const contractId = (await rpc(net.coordinator, "get_latest_l2_block_state", [])).next_contract_id;
    // Core RPC test: no ABI upload service or external L1 deployment is involved.
    const transaction = await rpc(net.coordinator, "deploy_contract", [payload]);
    const checkpoint = await waitFor(async () => {
        const checkpoint = await getCommonCheckpoint(net.urls);
        const leaf = await rpc(net.coordinator, "get_contract_tree_leaf_hash", [checkpoint, contractId]);
        return /^0+$/.test(leaf) ? undefined : checkpoint;
    }, timeout);
    const expected = payload.deploy_contract;
    const leaf = await rpc(net.coordinator, "get_contract_leaf_data", [contractId]);
    const code = await rpc(net.coordinator, "get_contract_code_definition", [contractId]);
    if (leaf.deployer !== expected.deployer || JSON.stringify(code) !== JSON.stringify(expected.code_definition)) throw new Error("Deployed contract differs from prepared command");
    saveJson(path.join(output, "results.json"), { checkpoint, contract_id: contractId, transaction, leaf });
    console.log(`L2 contract ${contractId} deployed and included at checkpoint ${checkpoint}`);
}

async function deployContracts(net: Network, output: string, contract: string, count: number, concurrency: number, timeout: number): Promise<void> {
    const tests = path.join(ROOT, "local_checkpoints/jtmb_tests");
    const registration = readdirSync(tests).sort().reverse().find(name => name.includes("-register-")
        && existsSync(path.join(tests, name, "results.json")) && existsSync(path.join(tests, name, "private_keys.json")));
    if (!registration) throw new Error("Run make jtmb-register first");
    const keys: string[] = readJson(path.join(tests, registration, "private_keys.json"));
    const registered: number[] = readJson(path.join(tests, registration, "results.json")).user_ids;
    if (count > keys.length || count > registered.length) throw new Error(`Batch count exceeds available registered keys (${keys.length})`);
    if (new Set(keys.slice(0, count)).size !== count) throw new Error("Registered deployer keys are not distinct");
    const startCheckpoint = await getCommonCheckpoint(net.urls);
    const firstContractId = Number((await rpc(net.coordinator, "get_latest_l2_block_state", [])).next_contract_id);
    const prepared = await mapConcurrent(keys.slice(0, count), concurrency, async (key, index) => {
        const command = path.join(output, `deploy-command-${index}.json`);
        await runCli("psy_user_cli", ["deploy-contract", "--rpc-config", net.config, "--contract-path", path.resolve(contract), "--output-path", command],
            path.join(output, `prepare-deploy-${index}.log`), Math.max(timeout, 600), key);
        const payload = readJson(command);
        if (Number(payload.deploy_contract.deployer) !== Number(registered[index])) throw new Error(`Prepared deployer mismatch at item ${index}`);
        return { index, payload };
    });
    const submissions = await Promise.all(prepared.map(async ({ index, payload }) => ({ index, result: await rpc(net.coordinator, "deploy_contract", [payload]) })));
    saveJson(path.join(output, "submitted.json"), { start_checkpoint: startCheckpoint,
        contract_ids: Array.from({ length: count }, (_, index) => firstContractId + index), submissions });
    const inclusion = await waitFor(async () => {
        const checkpoint = await getCommonCheckpoint(net.urls);
        const hashes = await Promise.all(Array.from({ length: count }, (_, index) => rpc(net.coordinator,
            "get_contract_tree_leaf_hash", [checkpoint, firstContractId + index])));
        return hashes.every(hash => !/^0+$/.test(hash)) ? checkpoint : undefined;
    }, timeout);
    const inclusionCheckpoints = await Promise.all(Array.from({ length: count }, async (_, index) => {
        const contractId = firstContractId + index;
        for (let checkpoint = startCheckpoint + 1; checkpoint <= inclusion; checkpoint++) {
            const hash = await rpc(net.coordinator, "get_contract_tree_leaf_hash", [checkpoint, contractId]);
            if (!/^0+$/.test(hash)) return checkpoint;
        }
        throw new Error(`Contract ${contractId} has no inclusion checkpoint in the observed range`);
    }));
    const contracts = await Promise.all(Array.from({ length: count }, async (_, index) => {
        const contractId = firstContractId + index;
        const [leaf, code] = await Promise.all([rpc(net.coordinator, "get_contract_leaf_data", [contractId]),
            rpc(net.coordinator, "get_contract_code_definition", [contractId])]);
        const expected = prepared[index].payload.deploy_contract;
        if (Number(leaf.deployer) !== Number(expected.deployer) || JSON.stringify(code) !== JSON.stringify(expected.code_definition)) {
            throw new Error(`Deployed contract ${contractId} differs from its prepared command`);
        }
        return { contract_id: contractId, checkpoint: inclusionCheckpoints[index], leaf };
    }));
    const sameCheckpoint = new Set(inclusionCheckpoints).size === 1;
    saveJson(path.join(output, "results.json"), { start_checkpoint: startCheckpoint, final_checkpoint: inclusion,
        same_checkpoint: sameCheckpoint, inclusion_checkpoints: inclusionCheckpoints, contracts });
    console.log(`${count} contracts included; first inclusion checkpoints ${[...new Set(inclusionCheckpoints)].join(", ")}; same checkpoint: ${sameCheckpoint}`);
    if (!sameCheckpoint) throw new Error("Batch contracts were split across checkpoints; see results.json");
}

async function main(): Promise<void> {
    const { positionals, values } = parseArgs({ args: process.argv.slice(2), allowPositionals: true, options: {
        namespace: { type: "string", default: "jtmb-test" }, users: { type: "string", default: "10" }, rounds: { type: "string", default: "10" },
        count: { type: "string", default: "10" }, concurrency: { type: "string", default: "10" }, timeout: { type: "string", default: "180" },
        contract: { type: "string", default: "psy-genesis/token.json" },
    } });
    const command = positionals[0];
    process.chdir(ROOT);
    if (command === "check-start") {
        validateNamespace(values.namespace, binding());
        if (!existsSync("genesis.json")) throw new Error("Existing verified genesis.json required; this target does not regenerate Genesis");
        return;
    }
    if (command === "check-stop") { requireJTMB(true); return; }
    requireJTMB();
    const net = getNetwork();
    if (command === "status") { console.log(JSON.stringify({ backend: BACKEND, checkpoint: await getCommonCheckpoint(net.urls), rpc_endpoints: net.urls }, null, 2)); return; }
    if (!["batch", "register", "deploy", "deploy-batch"].includes(command)) throw new Error("Expected batch, register, deploy, deploy-batch, status, check-start, or check-stop");
    const numbers = [values.users, values.rounds, values.count, values.concurrency, values.timeout].map(Number);
    if (numbers.some(value => !Number.isSafeInteger(value) || value < 1)) throw new Error("Counts and timeout must be positive integers");
    const [users, rounds, count, concurrency, timeout] = numbers;
    const output = path.join(ROOT, "local_checkpoints/jtmb_tests", `${Date.now()}-${command}-${randomBytes(3).toString("hex")}`);
    mkdirSync(output, { recursive: true, mode: 0o700 });
    console.log(`evidence: ${output}`);
    if (command === "batch") await runBatch(net, output, users, rounds, concurrency, timeout);
    else if (command === "register") await registerUsers(net, output, count, concurrency, timeout);
    else if (command === "deploy") await deployContract(net, output, values.contract, timeout);
    else await deployContracts(net, output, values.contract, count, concurrency, timeout);
}

if (import.meta.main) main().catch(error => { console.error(error.message); process.exitCode = 1; });
