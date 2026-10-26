#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const sha = data => crypto.createHash("sha256").update(data).digest("hex");
assert.equal(sha(fs.readFileSync(path.join(__dirname, "run_l1_quarantine.cjs"))), "51e94ca832838bba79ace121d59fa723a0f2a2445b9fee6ac9df3c0a2169858f");
const q = require("./run_l1_quarantine.cjs");
const ATTEMPT = "/var/lib/psy-l1-reset-20261027";
const hex = n => "0x" + BigInt(n).toString(16);
let stage = "input";

function load(request) {
  // Reuse the frozen quarantine context and real pre-quarantine lineage.
  const ctx = q.load({ ...request, plan: request.quarantine_plan, snapshot: request.baseline_snapshot });
  const snapshot = ctx.planner.pinnedJson(request.snapshot, request.snapshot_sha256);
  assert.equal(snapshot.collector_sha256, q.PIN.collector, "collector hash mismatch");
  ctx.planner.verifyReadback(ctx.plan, snapshot, ctx);
  for (const row of snapshot.chains) assert(row.block > ctx.snapshot.chains.find(c => c.network === row.network).block,
    "snapshot must follow the pinned prebroadcast baseline");
  const fence = ctx.planner.pinnedJson(request.fence, request.fence_sha256);
  assert.equal(fence.snapshot_sha256, request.snapshot_sha256, "fence snapshot binding mismatch");
  const plan = ctx.planner.pinnedJson(request.plan, request.plan_sha256);
  const expected = ctx.planner.prepare("reset", snapshot, ctx, fence);
  expected.input_sha256 = { snapshot: request.snapshot_sha256, fence: request.fence_sha256 };
  expected.tool_sha256 = q.PIN.planner;
  assert.deepEqual(plan, expected, "reset plan must equal complete reviewed planner output");
  return { ...ctx, snapshot, plan, planSha: request.plan_sha256, snapshotSha: request.snapshot_sha256, fenceSha: request.fence_sha256 };
}

function expectedRow(ctx, before, completed) {
  assert([0, 1, 2].includes(completed));
  const row = structuredClone(before);
  if (completed > 0) {
    ctx.planner.FIELDS.forEach((f, i) => { row.state["StateManager." + f] = i === 0 ? "0" : ctx.planner.ZERO; });
  }
  if (completed === 2) {
    for (const entry of row.root_registry) if (entry.field === "checkpointTreeRootCheckpointId") entry.value = "0";
  }
  // This is an in-memory expected delta, never a generated snapshot/evidence.
  // Quarantine's checker still reads ALL fields/roots/events from the live RPC.
  return row;
}

function stateHash(ctx, tuple) {
  return ctx.ethers.utils.keccak256(ctx.ethers.utils.defaultAbiCoder.encode(
    ["bytes32", "uint64", "bytes32", "bytes32", "bytes32", "bytes32"],
    [ctx.ethers.utils.id("PSY_STATE_MANAGER_FORCE_SET_STATE_V1"), ...tuple]));
}

function verifyReceipt(ctx, r, hash, operation, nonce, quote, block, tx) {
  assert.equal(r.transactionHash, hash); assert.equal(Number(r.status), 1);
  for (const data of [r, tx]) {
    assert.equal(data.from.toLowerCase(), operation.from.toLowerCase());
    assert.equal(data.to.toLowerCase(), operation.to.toLowerCase());
  }
  assert.equal(block.hash, r.blockHash); assert.equal(tx.blockHash, r.blockHash); assert.equal(tx.hash, hash);
  assert.equal(Number(tx.chainId), operation.chainId); assert.equal(Number(tx.nonce), nonce);
  assert.equal(tx.input, operation.data); assert.equal(BigInt(tx.value), 0n);
  assert.equal(BigInt(tx.gas), quote.gas); assert.equal(BigInt(tx.gasPrice), quote.fee);
  assert(BigInt(r.gasUsed) <= quote.gas && BigInt(r.effectiveGasPrice) <= quote.fee);
  const network = Object.keys(ctx.planner.CHAINS).find(n => ctx.planner.CHAINS[n][0] === operation.chainId);
  assert(BigInt(r.l1Fee || "0x0") <= BigInt(ctx.budgets[network].l1FeeReserveWeiPerTransaction));
  if (operation.method === "revokeCheckpointTreeRoots") assert.deepEqual(r.logs, []);
  else {
    assert.equal(operation.method, "forceSetState");
    assert.equal(r.logs.length, 1);
    assert.equal(r.logs[0].address.toLowerCase(), operation.to.toLowerCase());
    const event = ctx.abis.StateManager.parseLog(r.logs[0]);
    assert.equal(event.name, "ForceSetState");
    const args = [...event.args].map(a => a?._isBigNumber ? a.toString() : a);
    assert.deepEqual(args, [stateHash(ctx, operation.args[0]), stateHash(ctx, operation.args[1]), ...operation.args[1]]);
  }
}

async function receipt(ctx, rpc, hash, op, nonce, quote, retain) {
  const wait = () => new Promise(r => setTimeout(r, 5000));
  for (let i = 0; i < 180; i++) {
    let r;
    try { [r] = await rpc([["eth_getTransactionReceipt", [hash]]]); } catch { await wait(); continue; }
    if (!r) { await wait(); continue; }
    retain(r);
    assert.equal(Number(r.status), 1);
    let confirmed = false;
    for (let j = 0; j < 60; j++) {
      const [head] = await rpc([["eth_getBlockByNumber", ["latest", false]]]);
      if (BigInt(head.number) >= BigInt(r.blockNumber) + 1n) { confirmed = true; break; }
      await wait();
    }
    assert(confirmed, "confirmation-depth-timeout");
    const [block, tx] = await rpc([["eth_getBlockByNumber", [r.blockNumber, false]], ["eth_getTransactionByHash", [hash]]]);
    verifyReceipt(ctx, r, hash, op, nonce, quote, block, tx);
    return r;
  }
  throw new Error("receipt-timeout-no-retry");
}

async function quote(ctx, row, operation, rpc, used) {
  const call = { from: operation.from, to: operation.to, data: operation.data, value: "0x0" };
  const [result, gas, price, balance] = await rpc([["eth_call", [call, "latest"]], ["eth_estimateGas", [call]],
    ["eth_gasPrice", []], ["eth_getBalance", [row.signer, "latest"]]]);
  assert.equal(result, "0x");
  const reserved = q.reserve(ctx.budgets[row.network], gas, price, used);
  assert(BigInt(balance) >= reserved.cost);
  return reserved;
}

async function run(request) {
  const ctx = load(request);
  assert.equal(typeof request.execute, "boolean");
  assert.deepEqual(Object.keys(request.rpcs).sort(), Object.keys(q.BUDGET).sort());
  const clients = Object.fromEntries(Object.entries(request.rpcs).map(([n, u]) => [n, q.rpcClient(u, request.execute)]));
  const report = { ok: true, execute: request.execute, phase: "reset", plan_sha256: ctx.planSha, snapshot_sha256: ctx.snapshotSha,
    fence_sha256: ctx.fenceSha, collector_sha256: q.PIN.collector, planner_sha256: q.PIN.planner,
    runner_sha256: sha(fs.readFileSync(__filename)), gas_budget_sha256: q.BUDGET, release_approved: false, cleanup_reopen_allowed: false, chains: [] };
  for (const row of ctx.snapshot.chains) {
    stage = row.network + ":public-preflight";
    const rpc = clients[row.network], checked = await q.preflight(ctx, expectedRow(ctx, row, 0), rpc, []);
    let used = { gas: 0n, wei: 0n };
    const quotes = [];
    for (const op of ctx.plan.chains.find(c => c.network === row.network).transactions) {
      const quoted = await quote(ctx, row, op, rpc, used); used = quoted.next;
      quotes.push({ method: op.method, gas_limit: quoted.gas.toString(), gas_price_wei: quoted.fee.toString(), reserved_wei: quoted.cost.toString() });
    }
    const [balance] = await rpc([["eth_getBalance", [row.signer, "latest"]]]);
    assert(BigInt(balance) >= used.wei);
    report.chains.push({ network: row.network, ...checked, quotes });
  }
  q.save(request.output, request.execute ? "execute-preflight.json" : "check.json", report);
  if (!request.execute) return report;
  assert.equal(process.getuid(), 0);
  const attempt = JSON.parse(fs.readFileSync(path.join(ATTEMPT, "attempt.json")));
  assert.equal(attempt.plan_sha256, ctx.planSha); assert.equal(attempt.output, request.output);
  assert.equal(attempt.runner_js_sha256, report.runner_sha256);
  assert.equal(request.keystore, "/var/lib/parth/.psy/keystore/bridge-relayer-dev");
  stage = "custody-unlock";
  const encrypted = q.bytes(request.keystore, q.PIN.custody).toString();
  const wallet = await require("./fresh_l1.cjs").unlock(ctx.ethers, encrypted, request.password, ctx.planner.SIGNER);
  delete request.password;
  q.save(ATTEMPT, "execution-start.json", report);
  let total = 0;
  for (const row of ctx.snapshot.chains) {
    const rpc = clients[row.network], receipts = [];
    let used = { gas: 0n, wei: 0n };
    for (const op of ctx.plan.chains.find(c => c.network === row.network).transactions) {
      stage = row.network + ":preflight:" + op.method;
      assert(total < 6);
      assert.equal(op.data, ctx.abis.StateManager.encodeFunctionData(op.method, op.args));
      const price = await quote(ctx, row, op, rpc, used);
      const checked = await q.preflight(ctx, expectedRow(ctx, row, receipts.length), rpc, receipts);
      const tx = { chainId: op.chainId, nonce: checked.nonce, to: op.to, data: op.data, value: 0, type: 0, gasLimit: hex(price.gas), gasPrice: hex(price.fee) };
      const raw = await wallet.signTransaction(tx);
      const hash = q.signedIntent(ctx.ethers, raw, op, checked.nonce, price);
      used = price.next;
      const prefix = String(++total).padStart(2, "0") + "-" + row.network;
      q.save(ATTEMPT, prefix + "-intent.json", { plan_sha256: ctx.planSha, collector_sha256: q.PIN.collector,
        checked, transaction: tx, hash, max_reserved_wei: price.cost.toString() });
      stage = row.network + ":single-send:" + op.method;
      const [sent] = await rpc([["eth_sendRawTransaction", [raw]]]);
      assert.equal(sent, hash);
      stage = row.network + ":receipt:" + op.method;
      receipts.push(await receipt(ctx, rpc, hash, op, checked.nonce, price, r => q.save(ATTEMPT, prefix + "-receipt.json", r)));
      stage = row.network + ":readback:" + op.method;
      q.save(ATTEMPT, prefix + "-readback.json", await q.preflight(ctx, expectedRow(ctx, row, receipts.length), rpc, receipts));
    }
  }
  assert.equal(total, 6);
  const result = { ...report, transactions_completed: total, next: "real-reset-readback-then-fork-new-proof-gate" };
  q.save(ATTEMPT, "complete.json", result);
  return result;
}

if (require.main === module) {
  let request;
  (async () => {
    let input = "";
    for await (const c of process.stdin) { input += c; assert(input.length < 1024 * 1024); }
    request = JSON.parse(input);
    return run(request);
  })().then(r => console.log(JSON.stringify(r)), error => {
    const report = { ok: false, stage, error: "reset-gate-failed-no-retry" };
    if (request?.execute === false && error.code === "ERR_ASSERTION") report.assertion = error.message.slice(0, 512);
    try { q.save(request.output, request.execute ? "execute-failed.json" : "check-failed.json", report); } catch {}
    console.log(JSON.stringify({ ok: false, stage })); process.exitCode = 1;
  });
}
module.exports = { load, expectedRow, stateHash, verifyReceipt, quote, run };
