#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const sha = data => crypto.createHash("sha256").update(data).digest("hex");
const PIN = Object.freeze({
  quarantine: "51e94ca832838bba79ace121d59fa723a0f2a2445b9fee6ac9df3c0a2169858f",
  reset: "b4a1e1e8e02e70ba0eddb624f2e33e7c52bcda2a4a93bed27a920d2e02f3c114",
  proof: "1e983a884fa01e8f8cc4d5faf908d203b56d5ce5c068997b4339d878727a4988",
  runtime: "5d38eefc07b0925ed9875b74805d9c3fea73d998",
  genesis: "a5465bd712ceb66585660fddb4ac233afb747938395adaa200a63ead2f25f2c8",
});
const ATTEMPT = "/var/lib/psy-l1-clean-20261027";
const NETWORKS = ["sepolia", "bscTestnet", "baseSepolia"];
let stage = "input";
let saveAudit;

function pinned(file, expected) {
  assert.match(expected, /^[0-9a-f]{64}$/);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { assert(fs.fstatSync(fd).isFile()); const raw = fs.readFileSync(fd); assert.equal(sha(raw), expected); return raw; }
  finally { fs.closeSync(fd); }
}

function validateFork(report, row, input) {
  assert.equal(report.version, 2); assert.equal(report.result, "PASS");
  assert.equal(report.network, row.network); assert.equal(report.l1_chain_id, row.chain_id);
  assert.equal(report.baseline_block, row.block); assert.equal(report.baseline_block_hash, row.block_hash);
  assert(Number.isSafeInteger(report.block) && report.block >= row.block && report.block - row.block <= 100000);
  assert.match(report.block_hash, /^0x[0-9a-fA-F]{64}$/); assert(BigInt(report.block_hash) !== 0n);
  if (report.block === row.block) assert.equal(report.block_hash, row.block_hash);
  assert.equal(report.no_contract_events_since_baseline, true);
  assert.equal(report.actual_state_matches_approved_snapshot, true);
  assert.equal(report.execution_model, "real RPC eth_call at a fixed actual block with only StateManager slot8 stateDiff");
  assert.equal(report.snapshot_sha256, input.post_snapshot_sha256);
  assert.equal(report.proof_sha256, PIN.proof); assert.equal(report.attestation_sha256, input.attestation_sha256);
  assert.equal(report.tool_sha256, input.fork_tool_sha256);
  assert.equal(report.runtime_commit, PIN.runtime); assert.equal(report.genesis_sha256, PIN.genesis);
  assert.equal(report.verifier, row.state["provider.ZK_VERIFIER"]);
  assert.equal(report.valid_finalize, "accepted");
  assert.deepEqual(report.negative_controls, ["clean_false", "changed_proof", "changed_public_input", "wrong_chain_index"]);
  for (const field of ["native_zero_root_path_normalization", "proof_file_unchanged"]) assert.equal(report[field], true);
  for (const field of ["broadcast", "live_writes", "real_clean_enable_authorized"]) assert.equal(report[field], false);
  assert.equal(report.simulated_clean_bit.slot, "0x8");
  assert.match(report.simulated_clean_bit.before, /^0x[0-9a-fA-F]{64}$/);
  assert.match(report.simulated_clean_bit.after, /^0x[0-9a-fA-F]{64}$/);
  const before = BigInt(report.simulated_clean_bit.before), after = BigInt(report.simulated_clean_bit.after);
  assert.equal(before & 255n, 0n); assert.equal(after, before | 1n);
}

function load(request) {
  for (const [name, pin] of [["run_l1_quarantine.cjs", PIN.quarantine], ["run_l1_reset.cjs", PIN.reset]])
    pinned(path.join(request.helpers, name), pin);
  const q = require(path.join(request.helpers, "run_l1_quarantine.cjs"));
  saveAudit = q.save;
  const reset = require(path.join(request.helpers, "run_l1_reset.cjs"));
  const input = JSON.parse(pinned(request.inputs, request.inputs_sha256));
  const ctx = reset.load(input.reset);
  const snapshot = JSON.parse(pinned(input.post_snapshot, input.post_snapshot_sha256));
  assert.equal(snapshot.collector_sha256, q.PIN.collector);
  ctx.planner.verifyReadback(ctx.plan, snapshot, ctx);
  pinned(input.fork_tool, input.fork_tool_sha256);
  pinned(input.proof, PIN.proof);
  const attestation = JSON.parse(pinned(input.attestation, input.attestation_sha256));
  assert.equal(attestation.proof_sha256, PIN.proof);
  assert.equal(attestation.source_commit, PIN.runtime); assert.equal(attestation.genesis_sha256, PIN.genesis);
  assert.equal(attestation.local_proof_passed, true); assert.equal(attestation.setup_unchanged, true);
  assert.equal(attestation.broadcast, false);
  assert.deepEqual(Object.keys(input.fork_reports).sort(), [...NETWORKS].sort());
  for (const row of snapshot.chains) {
    assert.equal(row.state["StateManager.checkpointTreeRootsClean"], false);
    for (const token of ["native", "PSY", "USDT"]) assert.deepEqual(row.state["pause." + token], [7, 0, 7]);
    const entry = input.fork_reports[row.network];
    validateFork(JSON.parse(pinned(entry.path, entry.sha256)), row, input);
  }
  return { ...ctx, snapshot, q, reset, input };
}

function operation(ctx, row) {
  return { contract: "StateManager", method: "setCheckpointTreeRootsClean", args: [true],
    chainId: row.chain_id, from: row.signer, to: row.contracts.StateManager,
    data: ctx.abis.StateManager.encodeFunctionData("setCheckpointTreeRootsClean", [true]) };
}

function expectedRow(row, completed) {
  assert(completed === 0 || completed === 1);
  const expected = structuredClone(row);
  if (completed) {
    expected.state["StateManager.checkpointTreeRootsClean"] = true;
    for (const field of Object.keys(expected.nonces)) expected.nonces[field] += 1;
  }
  // No event is emitted by this setter. Give the frozen checker the expected
  // nonce/clean delta with zero quarantine operations, retaining every other field.
  return expected;
}

async function execute(ctx, clients, wallet, audit) {
  const { q, reset } = ctx;
  let total = 0;
  for (const row of ctx.snapshot.chains) {
    const rpc = clients[row.network], op = operation(ctx, row);
    stage = row.network + ":preflight-clean";
    const quote = await reset.quote(ctx, row, op, rpc, { gas: 0n, wei: 0n });
    const checked = await q.preflight(ctx, expectedRow(row, 0), rpc, []);
    const tx = { chainId: op.chainId, nonce: checked.nonce, to: op.to, data: op.data, value: 0, type: 0,
      gasLimit: "0x" + quote.gas.toString(16), gasPrice: "0x" + quote.fee.toString(16) };
    const raw = await wallet.signTransaction(tx);
    const hash = q.signedIntent(ctx.ethers, raw, op, checked.nonce, quote);
    const prefix = String(++total).padStart(2, "0") + "-" + row.network;
    assert(total <= 3);
    audit(prefix + "-intent.json", { checked, transaction: tx, hash, max_reserved_wei: quote.cost.toString() });
    stage = row.network + ":single-send-clean";
    const [sent] = await rpc([["eth_sendRawTransaction", [raw]]]);
    assert.equal(sent, hash);
    await q.receipt(ctx, rpc, hash, op, checked.nonce, quote, r => audit(prefix + "-receipt.json", r));
    stage = row.network + ":readback-clean";
    audit(prefix + "-readback.json", await q.preflight(ctx, expectedRow(row, 1), rpc, []));
  }
  assert.equal(total, 3);
  return total;
}

async function run(request) {
  assert.equal(typeof request.execute, "boolean");
  const ctx = load(request), { q, reset, input } = ctx;
  assert.deepEqual(Object.keys(request.rpcs).sort(), [...NETWORKS].sort());
  const clients = Object.fromEntries(NETWORKS.map(n => [n, q.rpcClient(request.rpcs[n], request.execute)]));
  const report = { ok: true, execute: request.execute, phase: "clean", inputs_sha256: request.inputs_sha256,
    snapshot_sha256: input.post_snapshot_sha256, proof_sha256: PIN.proof,
    fork_report_sha256: Object.fromEntries(NETWORKS.map(n => [n, input.fork_reports[n].sha256])),
    collector_sha256: q.PIN.collector, runner_sha256: sha(fs.readFileSync(__filename)),
    bridge_pause_unchanged: 7, public_deposits_authorized: false, service_changes: false, chains: [] };
  for (const row of ctx.snapshot.chains) {
    stage = row.network + ":all-chain-preflight";
    const rpc = clients[row.network], op = operation(ctx, row);
    const checked = await q.preflight(ctx, expectedRow(row, 0), rpc, []);
    const quote = await reset.quote(ctx, row, op, rpc, { gas: 0n, wei: 0n });
    report.chains.push({ network: row.network, ...checked, operation: op,
      gas_limit: quote.gas.toString(), gas_price_wei: quote.fee.toString(), max_reserved_wei: quote.cost.toString() });
  }
  q.save(request.output, request.execute ? "execute-preflight.json" : "check.json", report);
  if (!request.execute) return report;
  assert.equal(process.getuid(), 0);
  const claim = JSON.parse(fs.readFileSync(path.join(ATTEMPT, "attempt.json")));
  assert.equal(claim.inputs_sha256, request.inputs_sha256); assert.equal(claim.output, request.output);
  assert.equal(claim.runner_js_sha256, report.runner_sha256);
  assert.equal(request.keystore, "/var/lib/parth/.psy/keystore/bridge-relayer-dev");
  stage = "custody-unlock";
  const wallet = await require(path.join(request.helpers, "fresh_l1.cjs")).unlock(ctx.ethers,
    q.bytes(request.keystore, q.PIN.custody).toString(), request.password, ctx.planner.SIGNER);
  delete request.password;
  q.save(ATTEMPT, "execution-start.json", report);
  const total = await execute(ctx, clients, wallet, (name, value) => q.save(ATTEMPT, name, value));
  const result = { ...report, transactions_completed: total, next: "collect-real-clean-readback-main-owned-relayer-gate" };
  q.save(ATTEMPT, "complete.json", result);
  return result;
}

if (require.main === module) {
  let request;
  (async () => {
    let raw = "";
    for await (const chunk of process.stdin) { raw += chunk; assert(raw.length < 1024 * 1024); }
    request = JSON.parse(raw);
    return run(request);
  })().then(report => console.log(JSON.stringify(report)), () => {
    try {
      if (saveAudit) saveAudit(request.output, request.execute ? "execute-failed.json" : "check-failed.json", { ok: false, stage });
    } catch {}
    console.log(JSON.stringify({ ok: false, stage, error: "clean-gate-failed-no-retry" })); process.exitCode = 1;
  });
}
module.exports = { PIN, NETWORKS, pinned, validateFork, load, operation, expectedRow, execute, run };
