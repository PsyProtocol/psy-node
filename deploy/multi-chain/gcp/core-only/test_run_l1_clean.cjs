"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { createRequire } = require("node:module");
const clean = require("./run_l1_clean.cjs");
const local = createRequire(path.resolve(process.argv[2], "package.json"));
const { ethers } = local("ethers");
const abi = new ethers.utils.Interface(["function setCheckpointTreeRootsClean(bool)"]);

function fixture() {
  const input = { post_snapshot_sha256: "a".repeat(64), attestation_sha256: "b".repeat(64), fork_tool_sha256: "c".repeat(64) };
  const row = { network: "sepolia", chain_id: 11155111, block: 42, block_hash: "0x" + "1".repeat(64),
    signer: "0x" + "1".repeat(40), contracts: { StateManager: "0x" + "2".repeat(40) },
    nonces: { snapshot: 9, latest: 9, pending: 9, latest_after: 9, pending_after: 9 },
    state: { "provider.ZK_VERIFIER": "0x" + "3".repeat(40), "StateManager.checkpointTreeRootsClean": false,
      "pause.native": [7, 0, 7], "pause.PSY": [7, 0, 7], "pause.USDT": [7, 0, 7], "Bridge.depositRoot": "retained-empty-root" },
    root_registry: [{ field: "checkpointTreeRootCheckpointId", root: "old", value: "0" }] };
  const report = { version: 2, result: "PASS", network: row.network, l1_chain_id: row.chain_id,
    baseline_block: row.block, baseline_block_hash: row.block_hash,
    block: row.block + 3, block_hash: "0x" + "4".repeat(64), snapshot_sha256: input.post_snapshot_sha256,
    no_contract_events_since_baseline: true, actual_state_matches_approved_snapshot: true,
    execution_model: "real RPC eth_call at a fixed actual block with only StateManager slot8 stateDiff",
    proof_sha256: clean.PIN.proof, attestation_sha256: input.attestation_sha256, tool_sha256: input.fork_tool_sha256,
    runtime_commit: clean.PIN.runtime, genesis_sha256: clean.PIN.genesis, verifier: row.state["provider.ZK_VERIFIER"],
    valid_finalize: "accepted", negative_controls: ["clean_false", "changed_proof", "changed_public_input", "wrong_chain_index"],
    native_zero_root_path_normalization: true, proof_file_unchanged: true, broadcast: false, live_writes: false,
    real_clean_enable_authorized: false, simulated_clean_bit: { slot: "0x8", before: "0x" + "0".repeat(61) + "100", after: "0x" + "0".repeat(61) + "101" } };
  return { input, row, report };
}

test("fork gate requires exact real snapshot, proof, runtime, chain and negative controls", () => {
  const { input, row, report } = fixture();
  clean.validateFork(report, row, input);
  for (const field of ["version", "result", "network", "l1_chain_id", "block", "block_hash", "baseline_block", "baseline_block_hash",
    "no_contract_events_since_baseline", "actual_state_matches_approved_snapshot", "execution_model", "snapshot_sha256", "proof_sha256",
    "attestation_sha256", "tool_sha256", "runtime_commit", "genesis_sha256", "verifier", "valid_finalize",
    "negative_controls", "native_zero_root_path_normalization", "proof_file_unchanged", "broadcast", "live_writes", "real_clean_enable_authorized"]) {
    assert.throws(() => clean.validateFork({ ...report, [field]: null }, row, input), { code: "ERR_ASSERTION" }, field);
  }
  for (const bit of [{ ...report.simulated_clean_bit, slot: "0x9" }, { ...report.simulated_clean_bit, after: "0x" + "f".repeat(64) }])
    assert.throws(() => clean.validateFork({ ...report, simulated_clean_bit: bit }, row, input));
});

test("v2 distinguishes approved baseline from bounded actual execution anchor", () => {
  const { input, row, report } = fixture();
  clean.validateFork(report, row, input);
  clean.validateFork({ ...report, block: row.block, block_hash: row.block_hash }, row, input);
  for (const patch of [{ version: 1 }, { baseline_block: row.block + 1 }, { baseline_block_hash: report.block_hash },
    { block: row.block - 1 }, { block: row.block + 100001 }, { block: 42.5 }, { block: "45" },
    { block_hash: "0x123" }, { block_hash: "0x" + "0".repeat(64) },
    { block: row.block }, { no_contract_events_since_baseline: false }, { actual_state_matches_approved_snapshot: false }])
    assert.throws(() => clean.validateFork({ ...report, ...patch }, row, input));
  const legacy = { ...report, fork_clean_bit: report.simulated_clean_bit };
  delete legacy.simulated_clean_bit;
  assert.throws(() => clean.validateFork(legacy, row, input));
});

test("fixed operation is only StateManager clean=true and readback retains pause and old roots", () => {
  const { row } = fixture(), original = structuredClone(row), ctx = { abis: { StateManager: abi } };
  const op = clean.operation(ctx, row);
  assert.equal(op.method, "setCheckpointTreeRootsClean"); assert.deepEqual(op.args, [true]);
  assert.equal(op.data, abi.encodeFunctionData("setCheckpointTreeRootsClean", [true]));
  assert.equal(op.to, row.contracts.StateManager);
  const after = clean.expectedRow(row, 1);
  assert.equal(after.state["StateManager.checkpointTreeRootsClean"], true);
  assert.deepEqual(after.root_registry, row.root_registry);
  for (const token of ["native", "PSY", "USDT"]) assert.deepEqual(after.state["pause." + token], [7, 0, 7]);
  assert(Object.values(after.nonces).every(n => n === 10));
  assert.deepEqual(row, original); assert.deepEqual(clean.expectedRow(row, 0), row);
  assert.throws(() => clean.expectedRow(row, 2));
});

function executionFixture(failSend = false) {
  const rows = clean.NETWORKS.map((network, i) => ({ ...fixture().row, network, chain_id: [11155111, 97, 84532][i] }));
  const calls = [], audit = [], signed = [];
  const wallet = { signTransaction: async tx => { signed.push(tx); return "raw-" + tx.chainId; } };
  const q = {
    preflight: async (ctx, row, rpc, receipts) => {
      assert.deepEqual(receipts, []);
      assert.equal(row.state["Bridge.depositRoot"], "retained-empty-root");
      calls.push(row.state["StateManager.checkpointTreeRootsClean"] ? "after" : "before");
      return { nonce: row.nonces.snapshot };
    },
    signedIntent: (e, raw, op, nonce) => { assert.equal(nonce, 9); assert.deepEqual(op.args, [true]); return "hash-" + op.chainId; },
    receipt: async (ctx, rpc, hash, op, nonce, quote, retain) => { calls.push("receipt"); retain({ transactionHash: hash }); },
  };
  const ctx = { snapshot: { chains: rows }, q, ethers, abis: { StateManager: abi }, reset: {
    quote: async () => ({ gas: 50000n, fee: 10n, cost: 500000n }),
  } };
  const clients = Object.fromEntries(rows.map(row => [row.network, async requests => {
    assert.equal(audit.at(-1)[0], String(signed.length).padStart(2, "0") + "-" + row.network + "-intent.json");
    assert.equal(requests.length, 1); assert.equal(requests[0][0], "eth_sendRawTransaction");
    calls.push("send"); if (failSend) throw new Error("uncertain transport");
    return ["hash-" + row.chain_id];
  }]));
  return { ctx, clients, wallet, calls, signed, audit, retain: (name, value) => audit.push([name, value]) };
}

test("exactly three fixed sends, intent before each send, readback after receipt", async () => {
  const f = executionFixture();
  assert.equal(await clean.execute(f.ctx, f.clients, f.wallet, f.retain), 3);
  assert.deepEqual(f.calls, Array(3).fill(["before", "send", "receipt", "after"]).flat());
  assert.equal(f.signed.length, 3); assert.equal(f.audit.length, 9);
  for (const tx of f.signed) { assert.equal(tx.value, 0); assert.equal(tx.data, abi.encodeFunctionData("setCheckpointTreeRootsClean", [true])); }
});

test("uncertain send retains intent and never retries or advances another chain", async () => {
  const f = executionFixture(true);
  await assert.rejects(clean.execute(f.ctx, f.clients, f.wallet, f.retain), /uncertain transport/);
  assert.equal(f.signed.length, 1); assert.equal(f.audit.length, 1);
  assert.deepEqual(f.calls, ["before", "send"]);
});
