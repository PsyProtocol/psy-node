"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const tool = require("./run_l1_quarantine.cjs");
const keys = ["bundle", "evidence", "plan", "snapshot", "collector", "budgets"];
const request = Object.fromEntries(keys.map((key, i) => [key, process.argv[i + 2]]));
const ctx = tool.load(request);
const hex = n => "0x" + BigInt(n).toString(16);
const blockHash = "0x" + "ab".repeat(32);

function fixture(context, row, audit = new Map()) {
  let sent = 0;
  const txs = new Map(), receipts = [];
  const rpc = async requests => requests.map(([method, params]) => {
    const height = row.block + 10 + sent;
    const block = { number: hex(height), hash: blockHash, timestamp: hex(Math.floor(Date.now() / 1000)), transactions: [] };
    switch (method) {
      case "eth_chainId": return hex(row.chain_id);
      case "eth_syncing": return false;
      case "eth_getBlockByNumber": return params[0] === hex(row.block) ? { ...block, hash: row.block_hash } : { ...block, number: hex(height + 1) };
      case "eth_getTransactionCount": return hex(row.nonces.snapshot + sent);
      case "eth_getStorageAt": {
        const name = Object.keys(context.artifacts).find(n => row.contracts[n] === params[0]);
        const addr = params[1].startsWith("0x3608") ? context.docs[row.network].implementations[name + "_Implementation"] : row.contracts.DefaultProxyAdmin;
        return "0x" + "0".repeat(24) + addr.slice(2);
      }
      case "eth_getCode": {
        const name = Object.keys(context.artifacts).find(n => context.docs[row.network].implementations[n + "_Implementation"] === params[0]);
        return name ? context.artifacts[name].deployedBytecode : context.proxyCode;
      }
      case "eth_call": {
        const j = tool.stateJobs(context, row, sent).find(j => j.to === params[0].to && j.data === params[0].data);
        if (!j) return "0x";
        const outputs = j.abi.getFunction(j.field).outputs;
        return j.abi.encodeFunctionResult(j.field, outputs.length === 1 ? [j.expected] : j.expected);
      }
      case "eth_getLogs": return receipts.flatMap(r => r.logs).filter(l => BigInt(l.blockNumber) >= BigInt(params[0].fromBlock) && BigInt(l.blockNumber) <= BigInt(params[0].toBlock));
      case "eth_estimateGas": return "0xc350";
      case "eth_gasPrice": return "0xf4240";
      case "eth_getBalance": return "0xde0b6b3a7640000";
      case "eth_sendRawTransaction": {
        const tx = context.ethers.utils.parseTransaction(params[0]);
        const hash = context.ethers.utils.keccak256(params[0]);
        assert([...audit.values()].some(v => v.hash === hash), "intent must be saved before send");
        assert(sent < 2);
        const operation = context.plan.chains.find(c => c.network === row.network).transactions[sent++];
        assert.equal(tx.data, operation.data);
        const logs = [];
        if (sent === 2) {
          const event = context.abis.Bridge.encodeEventLog(context.abis.Bridge.getEvent("GlobalPauseFlagsUpdated"), [1, 7]);
          logs.push({ ...event, address: operation.to, blockHash, blockNumber: hex(row.block + 10 + sent), transactionHash: hash, logIndex: "0x0", removed: false });
        }
        const r = { transactionHash: hash, blockHash, blockNumber: hex(row.block + 10 + sent), from: tx.from, to: tx.to,
          status: "0x1", gasUsed: "0xc350", effectiveGasPrice: hex(tx.gasPrice), logs };
        receipts.push(r);
        txs.set(hash, { ...tx, hash, blockHash, chainId: hex(tx.chainId), nonce: hex(tx.nonce), input: tx.data,
          value: hex(tx.value), gas: hex(tx.gasLimit), gasPrice: hex(tx.gasPrice) });
        return hash;
      }
      case "eth_getTransactionReceipt": return receipts.find(r => r.transactionHash === params[0]);
      case "eth_getTransactionByHash": return txs.get(params[0]);
      default: throw new Error("unexpected fixture method");
    }
  });
  return { rpc, receipts, sent: () => sent };
}

test("exact real plan, fresh snapshot, collector and original budgets bind six operations", () => {
  assert.equal(ctx.plan.chains.flatMap(c => c.transactions).length, 6);
  assert.equal(ctx.snapshot.collector_sha256, tool.PIN.collector);
  assert.equal(ctx.plan.broadcast_allowed, false);
  assert.throws(() => tool.load({ ...request, snapshot: request.plan }));
  for (const row of ctx.snapshot.chains) assert.equal(tool.stateJobs(ctx, row, 0).length, Object.keys(row.state).length + row.root_registry.length + 2);
});

test("all three complete real snapshot fixtures pass live preflight", async () => {
  for (const row of ctx.snapshot.chains) {
    const checked = await tool.preflight(ctx, row, fixture(ctx, row).rpc, []);
    assert.equal(checked.nonce, row.nonces.snapshot);
  }
});

test("wrong chain, nonce, implementation, proxy, roles, roots and foreign logs fail closed", async () => {
  const row = ctx.snapshot.chains[0];
  const replacements = [
    ["eth_chainId", () => true, "0x1"],
    ["eth_getTransactionCount", () => true, "0x1"],
    ["eth_getStorageAt", () => true, "0x" + "0".repeat(64)],
    ["eth_getCode", () => true, "0x00"],
    ["eth_getLogs", () => true, [{ address: row.contracts.Bridge, topics: [], data: "0x", blockNumber: hex(row.block + 1), logIndex: "0x0" }]],
    ["eth_call", p => p[0].data === ctx.abis.PsyACLManager.encodeFunctionData("isBridgeAdmin", [row.signer]), ctx.abis.PsyACLManager.encodeFunctionResult("isBridgeAdmin", [false])],
    ["eth_call", p => p[0].data === ctx.abis.StateManager.encodeFunctionData("checkpointTreeRootCheckpointId", [row.checkpoint_roots[0]]), ctx.abis.StateManager.encodeFunctionResult("checkpointTreeRootCheckpointId", [0])],
  ];
  for (const [method, predicate, value] of replacements) {
    const base = fixture(ctx, row).rpc;
    const bad = async requests => (await base(requests)).map((result, i) => requests[i][0] === method && predicate(requests[i][1]) ? value : result);
    await assert.rejects(tool.preflight(ctx, row, bad, []));
  }
});

test("pending signer or contract transactions and unavailable pending view reject", async () => {
  const row = ctx.snapshot.chains[0];
  for (const pool of [null, { transactions: ["0xhash"] }, { transactions: [{ from: row.signer, hash: blockHash }] },
    { transactions: [{ from: row.contracts.USDTToken, to: row.contracts.Bridge, hash: blockHash }] }]) {
    const base = fixture(ctx, row).rpc;
    const bad = async reqs => (await base(reqs)).map((r, i) => reqs[i][0] === "eth_getBlockByNumber" && reqs[i][1][0] === "pending" ? pool : r);
    await assert.rejects(tool.preflight(ctx, row, bad, []));
  }
});

test("gas reservations include Base L1 reserve, never exceed original limits", () => {
  const budget = ctx.budgets.baseSepolia;
  const q = tool.reserve(budget, 50000n, 1000000n);
  assert.equal(q.cost, 60000n * 2000000n + BigInt(budget.l1FeeReserveWeiPerTransaction));
  assert.throws(() => tool.reserve(budget, 12000000n, 1n));
  assert.throws(() => tool.reserve(budget, 50000n, BigInt(budget.maxGasPriceWei) + 1n));
  assert.throws(() => tool.reserve(budget, 50000n, 1n, { gas: 0n, wei: BigInt(budget.maxNativeSpendWei) }));
});

test("exclusive durable audit refuses overwrite and symlink", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "quarantine-test-"));
  try {
    tool.save(dir, "intent.json", { hash: blockHash });
    assert.equal(fs.statSync(path.join(dir, "intent.json")).mode & 0o777, 0o600);
    assert.throws(() => tool.save(dir, "intent.json", {}));
    fs.symlinkSync(path.join(dir, "intent.json"), path.join(dir, "link.json"));
    assert.throws(() => tool.save(dir, "link.json", {}));
    assert.throws(() => tool.bytes(path.join(dir, "link.json"), tool.PIN.plan));
  } finally { fs.rmSync(dir, { recursive: true }); }
});

function executionFixture() {
  // Fixed, public test vector only; never production custody or key generation.
  const wallet = new ctx.ethers.Wallet("0x" + "11".repeat(32));
  const snapshot = structuredClone(ctx.snapshot), plan = structuredClone(ctx.plan);
  for (const row of snapshot.chains) row.signer = wallet.address;
  for (const chain of plan.chains) for (const op of chain.transactions) op.from = wallet.address;
  const local = { ...ctx, snapshot, plan, planner: { ...ctx.planner, SIGNER: wallet.address } };
  const audit = new Map();
  const hosts = Object.fromEntries(snapshot.chains.map(row => [row.network, fixture(local, row, audit)]));
  return { local, wallet, audit, hosts, clients: Object.fromEntries(Object.entries(hosts).map(([n, h]) => [n, h.rpc])),
    save: (name, value) => { assert(!audit.has(name)); audit.set(name, value); } };
}

test("six exact sends, every intent precedes send, receipts and readbacks retained", async () => {
  const f = executionFixture();
  assert.equal(await tool.execute(f.local, f.clients, f.wallet, f.save), 6);
  assert.equal(f.audit.size, 18);
  assert(Object.values(f.hosts).every(h => h.sent() === 2));
  await assert.rejects(tool.execute(f.local, f.clients, f.wallet, f.save));
  assert(Object.values(f.hosts).every(h => h.sent() === 2));
});

test("lost send response and failed receipt are terminal; never resubmit", async () => {
  for (const fail of ["send", "receipt"]) {
    const f = executionFixture(), original = f.clients.sepolia;
    let sends = 0;
    f.clients.sepolia = async requests => {
      if (requests.some(r => r[0] === "eth_sendRawTransaction")) sends++;
      const out = await original(requests);
      if (fail === "send" && requests[0][0] === "eth_sendRawTransaction") throw new Error("lost response");
      return out.map((r, i) => fail === "receipt" && requests[i][0] === "eth_getTransactionReceipt" ? { ...r, status: "0x0" } : r);
    };
    await assert.rejects(tool.execute(f.local, f.clients, f.wallet, f.save));
    assert.equal(sends, 1);
    assert.equal(f.hosts.bscTestnet.sent(), 0);
    assert(f.audit.has("01-sepolia-intent.json"));
    assert.equal(f.audit.has("01-sepolia-receipt.json"), fail === "receipt");
  }
});

test("signed transaction identity rejects altered calldata, nonce or fees", async () => {
  const f = executionFixture();
  const op = f.local.plan.chains[0].transactions[0];
  const q = tool.reserve(ctx.budgets.sepolia, 50000n, 1000000n);
  const tx = { chainId: op.chainId, nonce: 1, to: op.to, data: op.data, value: 0, type: 0, gasLimit: hex(q.gas), gasPrice: hex(q.fee) };
  const raw = await f.wallet.signTransaction(tx);
  assert.match(tool.signedIntent(ctx.ethers, raw, op, 1, q), /^0x[0-9a-f]{64}$/);
  assert.throws(() => tool.signedIntent(ctx.ethers, raw, { ...op, data: "0x" }, 1, q));
  assert.throws(() => tool.signedIntent(ctx.ethers, raw, op, 2, q));
  assert.throws(() => tool.signedIntent(ctx.ethers, raw, op, 1, { ...q, fee: 1n }));
});
