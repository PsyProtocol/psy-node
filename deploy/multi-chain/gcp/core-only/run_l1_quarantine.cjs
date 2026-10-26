#!/usr/bin/env node
"use strict";
// Called by run_l1_quarantine.py; passwords enter over stdin only.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const http = require("node:http");
const { createRequire } = require("node:module");
const PIN = Object.freeze({
  plan: "cb29a265a72c7c0ae320119e2c652ca3ee86aceca8536117ce42eb3114771598",
  originalSnapshot: "6fb3706bd2752d9201054c02e0eeb9b6b4587ec6a47dd66a39f05b5f9e547b38",
  snapshot: "4e09d0ea5845a863bd0ff88742f787e589fda744fdb1b9e21f72d561acb0abc8",
  collector: "0aacb78d196d17b19289193e9bd9f3c6376482c34ef37a285e95440508ab68ba",
  planner: "77bf8d9b60f5d352b305b9d3891b88058d10b1e60a452b8b23185bc679ee3128",
  custody: "2a100a28748685bcba8a9abf8dd6c4e15361d6e5ec306b72b6a32e45d838c184",
  unlock: "0ec0d2c2efaeccf407c2c83379506f017f5da0f1002006836ed55372fdc77a61",
});
const BUDGET = Object.freeze({
  sepolia: "66eba88dcb5b97422306a5014670931892fbbdcd3256a271af9020a2a1c838cb",
  bscTestnet: "692846a796c5b4d984e0f824e47178532d8c5bd23c18e6e679df734130cf991a",
  baseSepolia: "17bff1de7f02f7c05bda79d6a5b261959a05af8b2e9a0d2edc080087ff92dd82",
});
const ATTEMPT = "/var/lib/psy-l1-quarantine-20261026";
const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const sha = data => crypto.createHash("sha256").update(data).digest("hex");
const hex = n => "0x" + BigInt(n).toString(16);
const clean = x => x?._isBigNumber ? x.toString() : Array.isArray(x) ? x.map(clean) : x;
const equalAddress = (a, b) => assert.equal(a.toLowerCase(), b.toLowerCase());
let currentStage = "input";

function bytes(file, pin) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    assert(fs.fstatSync(fd).isFile());
    const data = fs.readFileSync(fd);
    assert.equal(sha(data), pin);
    return data;
  } finally { fs.closeSync(fd); }
}

function save(dir, name, value) {
  const s = fs.lstatSync(dir);
  assert(s.isDirectory() && !s.isSymbolicLink() && !(s.mode & 0o077));
  assert.match(name, /^[a-zA-Z0-9-]+\.json$/);
  const fd = fs.openSync(path.join(dir, name), fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2) + "\n"); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  const parent = fs.openSync(dir, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}

// A single HTTP request, no redirects, proxy environment, fallback or retry.
function rpcClient(url, execute) {
  const u = new URL(url);
  assert(u.protocol === "http:" && !u.username && !u.password && !u.search && !u.hash && u.pathname === "/");
  const allowed = new Set(["eth_chainId", "eth_getBlockByNumber", "eth_syncing", "eth_getTransactionCount",
    "eth_getCode", "eth_getStorageAt", "eth_call", "eth_getLogs", "eth_estimateGas", "eth_gasPrice",
    "eth_getBalance", "eth_getTransactionReceipt", "eth_getTransactionByHash"]);
  return async requests => {
    assert(requests.length > 0 && requests.length <= 32);
    for (const [m] of requests) assert(allowed.has(m) || (execute && requests.length === 1 && m === "eth_sendRawTransaction"));
    const body = JSON.stringify(requests.map(([method, params], id) => ({ jsonrpc: "2.0", id, method, params })));
    return new Promise((resolve, reject) => {
      const req = http.request(u, { method: "POST", agent: false, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } }, res => {
        let data = "";
        res.on("data", chunk => { data += chunk; if (data.length > 16 * 1024 * 1024) req.destroy(new Error("rpc-size")); });
        res.on("error", () => reject(new Error("rpc-response")));
        res.on("end", () => {
          try {
            assert.equal(res.statusCode, 200);
            const rows = JSON.parse(data);
            assert(Array.isArray(rows) && rows.length === requests.length);
            assert.equal(new Set(rows.map(r => r.id)).size, rows.length);
            resolve(requests.map((_, id) => {
              const row = rows.find(r => r.id === id);
              assert(row && !row.error && Object.hasOwn(row, "result"));
              return row.result;
            }));
          } catch { reject(new Error("rpc-result")); }
        });
      });
      req.setTimeout(30000, () => req.destroy(new Error("rpc-timeout")));
      req.on("error", () => reject(new Error("rpc-transport")));
      req.end(body);
    });
  };
}

function load(request) {
  bytes(path.join(__dirname, "prepare_l1_reset.cjs"), PIN.planner);
  bytes(path.join(__dirname, "fresh_l1.cjs"), PIN.unlock);
  bytes(request.collector, PIN.collector);
  const planner = require("./prepare_l1_reset.cjs");
  const contracts = path.resolve(request.bundle, "contracts");
  const ctx = planner.context(contracts, request.evidence);
  const plan = planner.pinnedJson(request.plan, PIN.plan);
  const snapshot = planner.pinnedJson(request.snapshot, PIN.snapshot);
  assert.equal(plan.tool_sha256, PIN.planner);
  assert.equal(plan.input_sha256.snapshot, PIN.originalSnapshot);
  assert.equal(plan.before.collector_sha256, PIN.collector);
  assert.equal(snapshot.collector_sha256, PIN.collector);
  const expected = planner.prepare("quarantine", plan.before, ctx);
  for (const k of Object.keys(expected)) assert.deepEqual(plan[k], expected[k]);
  planner.validateSnapshot(snapshot, ctx);
  for (const row of snapshot.chains) {
    const old = plan.before.chains.find(c => c.network === row.network);
    assert(row.block >= old.block);
    for (const k of ["state", "nonces", "events", "unparsed_logs", "finalized", "root_registry", "contracts", "bytecode_matches"]) assert.deepEqual(row[k], old[k]);
    assert.equal(row.state["StateManager.checkpointTreeRootsClean"], true);
    for (const token of ["native", "PSY", "USDT"]) assert.deepEqual(row.state["pause." + token], [1, 0, 1]);
  }
  const localRequire = createRequire(path.join(contracts, "package.json"));
  const proxyCode = localRequire("hardhat-deploy/extendedArtifacts/TransparentUpgradeableProxy.json").deployedBytecode;
  const artifacts = {};
  for (const name of ["StateManager", "Bridge", "PsyACLManager", "PsyAddressesProvider", "PsyToken", "TokenFaucetManager"]) {
    artifacts[name] = JSON.parse(fs.readFileSync(path.join(contracts, `artifacts/hardhat/src/${name}.sol/${name}.json`)));
    ctx.abis[name] = new ctx.ethers.utils.Interface(artifacts[name].abi);
  }
  const budgets = Object.fromEntries(Object.entries(BUDGET).map(([network, pin]) => [network, planner.pinnedJson(path.join(request.budgets, network + ".json"), pin)]));
  assert.equal(plan.chains.length, 3);
  assert(plan.chains.every(c => c.transactions.length === 2));
  return { ...ctx, planner, plan, snapshot, budgets, artifacts, proxyCode };
}

function stateJobs(ctx, row, completed) {
  const jobs = [];
  const add = (name, field, args, expected, to = row.contracts[name], abi = ctx.abis[name]) =>
    jobs.push({ to, field, abi, expected, data: abi.encodeFunctionData(field, args) });
  const erc = new ctx.ethers.utils.Interface(["function balanceOf(address) view returns(uint256)"]);
  const s = row.state;
  for (const [label, expected] of Object.entries(s)) {
    const [name, field] = label.split(".");
    switch (name) {
      case "provider": add("PsyAddressesProvider", "getAddress", [ctx.ethers.utils.id(field)], expected); break;
      case "pause": case "withdrawalTotal": case "custody": {
        const token = field === "native" ? ctx.ethers.constants.AddressZero : row.contracts[field === "PSY" ? "PsyToken" : "USDTToken"];
        if (name === "pause") add("Bridge", "getPauseFlags", [token], completed === 2 ? [7, 0, 7] : expected);
        else if (name === "withdrawalTotal") add("Bridge", "totalWithdrawalAmount", [token], expected);
        else add("Bridge", "balanceOf", [row.contracts.Bridge], expected, field === "native" ? row.contracts.WETH9 : token, erc);
        break;
      }
      case "PsyACLManager": add(name, field, [ctx.planner.SIGNER], expected); break;
      case "StateManager": case "Bridge": case "PsyToken": case "PsyAddressesProvider": case "TokenFaucetManager":
        add(name, field, [], label === "StateManager.checkpointTreeRootsClean" && completed > 0 ? false : expected); break;
      default: throw new Error("unknown-state-field");
    }
  }
  add("PsyAddressesProvider", "getAddress", [ctx.ethers.utils.id("ACL_MANAGER")], row.contracts.PsyACLManager);
  add("Bridge", "addressesProvider", [], row.contracts.PsyAddressesProvider);
  for (const root of row.root_registry) add("StateManager", root.field, [root.root], root.value);
  return jobs;
}

const logIdentity = log => ({ address: log.address.toLowerCase(), topics: log.topics, data: log.data,
  blockHash: log.blockHash, transactionHash: log.transactionHash, logIndex: log.logIndex });

async function preflight(ctx, row, rpc, receipts) {
  currentStage = row.network + ":chain-nonce-pending";
  const completed = receipts.length;
  assert(completed <= 2);
  const expectedNonce = row.nonces.snapshot + completed;
  const [chain, block, sync, latest, pending, pool, original] = await rpc([
    ["eth_chainId", []], ["eth_getBlockByNumber", ["latest", false]], ["eth_syncing", []],
    ["eth_getTransactionCount", [row.signer, "latest"]], ["eth_getTransactionCount", [row.signer, "pending"]],
    ["eth_getBlockByNumber", ["pending", true]], ["eth_getBlockByNumber", [hex(row.block), false]],
  ]);
  assert.equal(Number(chain), row.chain_id);
  assert.equal(sync, false);
  assert.equal(Number(latest), expectedNonce); assert.equal(Number(pending), expectedNonce);
  const age = Date.now() / 1000 - Number(block.timestamp);
  assert(age >= -30 && age <= 180);
  assert.equal(original.hash, row.block_hash);
  const watched = new Set(Object.values(row.contracts).map(a => a.toLowerCase()));
  assert(pool && Array.isArray(pool.transactions));
  for (const tx of pool.transactions) {
    assert(tx && typeof tx === "object" && typeof tx.from === "string" && typeof tx.hash === "string");
    assert(tx.from.toLowerCase() !== row.signer.toLowerCase() && !watched.has(tx.to?.toLowerCase()));
  }
  const blockTag = block.number;
  for (const name of ["StateManager", "Bridge", "PsyACLManager", "PsyAddressesProvider"]) {
    currentStage = row.network + ":code:" + name;
    const implementation = ctx.docs[row.network].implementations[name + "_Implementation"];
    const [slot, admin, code, proxy] = await rpc([
      ["eth_getStorageAt", [row.contracts[name], IMPL_SLOT, blockTag]],
      ["eth_getStorageAt", [row.contracts[name], ADMIN_SLOT, blockTag]],
      ["eth_getCode", [implementation, blockTag]], ["eth_getCode", [row.contracts[name], blockTag]],
    ]);
    equalAddress("0x" + slot.slice(-40), implementation);
    equalAddress("0x" + admin.slice(-40), row.contracts.DefaultProxyAdmin);
    assert.equal(code.toLowerCase(), ctx.artifacts[name].deployedBytecode.toLowerCase());
    assert.equal(proxy.toLowerCase(), ctx.proxyCode.toLowerCase());
  }
  const jobs = stateJobs(ctx, row, completed);
  currentStage = row.network + ":state-roles-roots";
  for (let i = 0; i < jobs.length; i += 24) {
    const batch = jobs.slice(i, i + 24);
    const results = await rpc(batch.map(j => ["eth_call", [{ to: j.to, data: j.data }, blockTag]]));
    results.forEach((result, n) => {
      const j = batch[n], decoded = j.abi.decodeFunctionResult(j.field, result);
      assert.deepEqual(clean(decoded.length === 1 ? decoded[0] : decoded), j.expected);
    });
  }
  // Every intervening event must belong to our already retained receipts.
  const height = Number(block.number);
  currentStage = row.network + ":event-history";
  assert(height >= row.block && height - row.block <= 100000);
  const queries = [];
  for (let from = row.block + 1; from <= height; from += 1024) queries.push(["eth_getLogs", [{
    address: Object.keys(ctx.artifacts).map(n => row.contracts[n]), fromBlock: hex(from), toBlock: hex(Math.min(height, from + 1023)),
  }]]);
  const logs = [];
  for (let i = 0; i < queries.length; i += 16) logs.push(...(await rpc(queries.slice(i, i + 16))).flat());
  assert(logs.every(l => !l.removed));
  const order = (a, b) => Number(BigInt(a.blockNumber) - BigInt(b.blockNumber)) || Number(BigInt(a.logIndex) - BigInt(b.logIndex));
  assert.deepEqual(logs.sort(order).map(logIdentity), receipts.flatMap(r => r.logs).sort(order).map(logIdentity));
  const [again, last, pend] = await rpc([["eth_getBlockByNumber", [blockTag, false]],
    ["eth_getTransactionCount", [row.signer, "latest"]], ["eth_getTransactionCount", [row.signer, "pending"]]]);
  assert.equal(again.hash, block.hash); assert.equal(Number(last), expectedNonce); assert.equal(Number(pend), expectedNonce);
  return { chain_id: row.chain_id, block: height, block_hash: block.hash, nonce: expectedNonce, completed };
}

function reserve(budget, estimate, price, used = { gas: 0n, wei: 0n }) {
  const gas = (BigInt(estimate) * 120n + 99n) / 100n;
  const suggested = BigInt(price);
  const cap = BigInt(budget.maxGasPriceWei);
  assert(suggested > 0n && suggested <= cap);
  const fee = suggested * 2n < cap ? suggested * 2n : cap;
  assert(gas > 0n && gas <= BigInt(budget.maxGasPerTransaction));
  assert(fee > 0n && fee <= BigInt(budget.maxGasPriceWei));
  const cost = gas * fee + BigInt(budget.l1FeeReserveWeiPerTransaction);
  const next = { gas: used.gas + gas, wei: used.wei + cost };
  assert(next.gas <= BigInt(budget.maxTotalGas) && next.wei <= BigInt(budget.maxNativeSpendWei));
  return { gas, fee, cost, next };
}

async function quote(ctx, row, operation, rpc, used) {
  currentStage = row.network + ":quote:" + operation.method;
  const call = { from: operation.from, to: operation.to, data: operation.data, value: "0x0" };
  const [result, estimate, price, balance] = await rpc([["eth_call", [call, "latest"]],
    ["eth_estimateGas", [call]], ["eth_gasPrice", []], ["eth_getBalance", [row.signer, "latest"]]]);
  assert.equal(result, "0x");
  const reserved = reserve(ctx.budgets[row.network], estimate, price, used);
  assert(BigInt(balance) >= reserved.cost);
  return reserved;
}

function signedIntent(ethers, raw, operation, nonce, quote) {
  const tx = ethers.utils.parseTransaction(raw);
  equalAddress(tx.from, operation.from); equalAddress(tx.to, operation.to);
  assert.equal(tx.chainId, operation.chainId); assert.equal(tx.nonce, nonce);
  assert.equal(tx.data, operation.data); assert.equal(tx.value.toString(), "0");
  assert.equal(tx.gasPrice.toString(), quote.fee.toString()); assert.equal(tx.gasLimit.toString(), quote.gas.toString());
  assert(tx.type === null || tx.type === 0);
  return ethers.utils.keccak256(raw);
}

async function receipt(ctx, rpc, hash, operation, nonce, quote, retain, wait = ms => new Promise(r => setTimeout(r, ms))) {
  for (let i = 0; i < 180; i++) {
    currentStage = "receipt-poll";
    let r;
    try { [r] = await rpc([["eth_getTransactionReceipt", [hash]]]); }
    catch { await wait(5000); continue; }
    if (!r) { await wait(5000); continue; }
    // Save even a failed or nonconforming receipt before rejecting it.
    retain(r);
    currentStage = "receipt-identity";
    assert.equal(r.transactionHash, hash); assert.equal(Number(r.status), 1);
    equalAddress(r.from, operation.from); equalAddress(r.to, operation.to);
    assert(BigInt(r.gasUsed) <= quote.gas && BigInt(r.effectiveGasPrice) <= quote.fee);
    const l1Fee = BigInt(r.l1Fee || "0x0");
    assert(l1Fee <= BigInt(ctx.budgets[Object.keys(ctx.planner.CHAINS).find(n => ctx.planner.CHAINS[n][0] === operation.chainId)].l1FeeReserveWeiPerTransaction));
    let confirmed = false;
    for (let j = 0; j < 60; j++) {
      const [head] = await rpc([["eth_getBlockByNumber", ["latest", false]]]);
      if (BigInt(head.number) >= BigInt(r.blockNumber) + 1n) { confirmed = true; break; }
      await wait(5000);
    }
    assert(confirmed, "confirmation-depth-timeout");
    const [block, tx] = await rpc([["eth_getBlockByNumber", [r.blockNumber, false]], ["eth_getTransactionByHash", [hash]]]);
    assert.equal(block.hash, r.blockHash); assert.equal(tx.blockHash, r.blockHash); assert.equal(tx.hash, hash);
    equalAddress(tx.from, operation.from); equalAddress(tx.to, operation.to);
    assert.equal(Number(tx.chainId), operation.chainId); assert.equal(Number(tx.nonce), nonce);
    assert.equal(tx.input, operation.data); assert.equal(BigInt(tx.value), 0n);
    assert.equal(BigInt(tx.gas), quote.gas); assert.equal(BigInt(tx.gasPrice), quote.fee);
    if (operation.contract === "StateManager") assert.deepEqual(r.logs, []);
    else {
      assert.equal(r.logs.length, 1); equalAddress(r.logs[0].address, operation.to);
      const event = ctx.abis.Bridge.parseLog(r.logs[0]);
      assert.equal(event.name, "GlobalPauseFlagsUpdated");
      assert.deepEqual(clean(event.args), [1, 7]);
    }
    return r;
  }
  throw new Error("receipt-timeout-no-retry");
}

async function run(request) {
  const ctx = load(request);
  assert.equal(typeof request.execute, "boolean");
  assert.deepEqual(Object.keys(request.rpcs).sort(), Object.keys(BUDGET).sort());
  const clients = Object.fromEntries(Object.keys(BUDGET).map(n => [n, rpcClient(request.rpcs[n], request.execute)]));
  const report = { ok: true, execute: request.execute, plan_sha256: PIN.plan, snapshot_sha256: PIN.snapshot,
    collector_sha256: PIN.collector, planner_sha256: PIN.planner, runner_sha256: sha(fs.readFileSync(__filename)),
    gas_budget_sha256: BUDGET, release_approved: false, cleanup_reopen_allowed: false, chains: [] };
  for (const row of ctx.snapshot.chains) {
    const rpc = clients[row.network];
    const checked = await preflight(ctx, row, rpc, []);
    let used = { gas: 0n, wei: 0n };
    const quotes = [];
    for (const op of ctx.plan.chains.find(c => c.network === row.network).transactions) {
      const q = await quote(ctx, row, op, rpc, used); used = q.next;
      quotes.push({ gas_limit: q.gas.toString(), gas_price_wei: q.fee.toString(), reserved_wei: q.cost.toString() });
    }
    const [balance] = await rpc([["eth_getBalance", [row.signer, "latest"]]]);
    assert(BigInt(balance) >= used.wei);
    report.chains.push({ network: row.network, ...checked, quotes });
  }
  save(request.output, request.execute ? "execute-preflight.json" : "check.json", report);
  if (!request.execute) return report;
  assert.equal(process.getuid(), 0);
  const claim = JSON.parse(fs.readFileSync(path.join(ATTEMPT, "attempt.json")));
  assert.equal(claim.plan_sha256, PIN.plan); assert.equal(claim.output, request.output);
  assert.equal(claim.runner_js_sha256, report.runner_sha256);
  currentStage = "custody-unlock";
  assert.equal(request.keystore, "/var/lib/parth/.psy/keystore/bridge-relayer-dev");
  const encrypted = bytes(request.keystore, PIN.custody).toString();
  const { unlock } = require("./fresh_l1.cjs");
  const wallet = await unlock(ctx.ethers, encrypted, request.password, ctx.planner.SIGNER);
  delete request.password;
  save(ATTEMPT, "execution-start.json", report);
  const total = await execute(ctx, clients, wallet, (name, value) => save(ATTEMPT, name, value));
  const result = { ...report, transactions_completed: total, next: "collect-real-quarantine-snapshot-before-reset" };
  save(ATTEMPT, "complete.json", result);
  return result;
}

async function execute(ctx, clients, wallet, audit) {
  let total = 0;
  for (const row of ctx.snapshot.chains) {
    const rpc = clients[row.network], receipts = [];
    let used = { gas: 0n, wei: 0n };
    const operations = ctx.plan.chains.find(c => c.network === row.network).transactions;
    for (const operation of operations) {
      assert(total < 6);
      // Re-derive calldata immediately before signing, never trust argv data.
      assert.equal(operation.data, ctx.abis[operation.contract].encodeFunctionData(operation.method, operation.args));
      const q = await quote(ctx, row, operation, rpc, used);
      const checked = await preflight(ctx, row, rpc, receipts);
      const tx = { chainId: operation.chainId, nonce: checked.nonce, to: operation.to, data: operation.data,
        value: 0, type: 0, gasLimit: hex(q.gas), gasPrice: hex(q.fee) };
      const raw = await wallet.signTransaction(tx);
      const hash = signedIntent(ctx.ethers, raw, operation, checked.nonce, q);
      // Reserve before the single send. A timeout never releases this intent.
      used = q.next;
      const prefix = String(++total).padStart(2, "0") + "-" + row.network;
      audit(prefix + "-intent.json", { plan_sha256: PIN.plan, collector_sha256: PIN.collector,
        checked, transaction: tx, hash, max_reserved_wei: q.cost.toString() });
      currentStage = row.network + ":single-send:" + operation.method;
      const [sent] = await rpc([["eth_sendRawTransaction", [raw]]]);
      assert.equal(sent, hash);
      const r = await receipt(ctx, rpc, hash, operation, checked.nonce, q,
        value => audit(prefix + "-receipt.json", value));
      receipts.push(r);
      const after = await preflight(ctx, row, rpc, receipts);
      audit(prefix + "-readback.json", after);
    }
  }
  assert.equal(total, 6);
  return total;
}

if (require.main === module) {
  let request;
  (async () => {
    let input = "";
    for await (const chunk of process.stdin) { input += chunk; assert(input.length < 1024 * 1024); }
    request = JSON.parse(input);
    return run(request);
  })().then(result => console.log(JSON.stringify(result)), error => {
    const report = { ok: false, stage: currentStage, error: "gate-failed-no-retry" };
    if (request?.execute === false && error.code === "ERR_ASSERTION") report.assertion = error.message.slice(0, 512);
    try { save(request.output, request.execute ? "execute-failed.json" : "check-failed.json", report); } catch {}
    console.log(JSON.stringify({ ok: false, stage: currentStage })); process.exitCode = 1;
  });
}
module.exports = { PIN, BUDGET, load, bytes, save, rpcClient, stateJobs, preflight, reserve, signedIntent, receipt, run, execute };
