"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const tool = require("./prepare_l1_reset.cjs");
assert(process.env.L1_RESET_CONTRACTS_DIR, "set L1_RESET_CONTRACTS_DIR to the pinned contracts bundle");
const { ethers } = createRequire(path.resolve(process.env.L1_RESET_CONTRACTS_DIR, "package.json"))("ethers");
const { ZERO, FIRST_OLD_ROOT, EMPTY, SOURCE, SIGNER, CODE, FIELDS, CHAINS } = tool;
const address = n => "0x" + n.toString(16).padStart(40, "0");
const root = n => "0x" + n.toString(16).padStart(64, "0");
const sha = data => crypto.createHash("sha256").update(data).digest("hex");
const artifact = n => JSON.parse(fs.readFileSync(path.join(process.env.L1_RESET_CONTRACTS_DIR, `artifacts/hardhat/src/${n}.sol/${n}.json`)));

function fixture(quarantined = false) {
  const ctx = { ethers, docs: {}, abis: Object.fromEntries(["StateManager", "Bridge"].map(n => [n, new ethers.utils.Interface(artifact(n).abi)])) };
  const snapshot = { complete: true, readonly: true, source: SOURCE, collector_sha256: "a".repeat(64), chains: [] };
  for (const [i, network] of Object.keys(CHAINS).entries()) {
    const core = { StateManager: address(1 + i * 10), Bridge: address(2 + i * 10), PsyAddressesProvider: address(3 + i * 10), PsyToken: address(4 + i * 10) };
    const implementations = { StateManager_Implementation: address(5 + i * 10), Bridge_Implementation: address(6 + i * 10) };
    ctx.docs[network] = { core, implementations, deploymentBlock: 10 };
    const state = {
      "StateManager.lastFinalizedCheckpointId": "1216", "StateManager.lastVerifiedCheckpointRoot": root(19),
      "StateManager.lastVerifiedDepositTreeRoot": ZERO, "StateManager.lastVerifiedWithdrawalTreeRoot": ZERO,
      "StateManager.withdrawalSubtreeRoot": ZERO, "StateManager.checkpointTreeRootsClean": !quarantined,
      "StateManager.l1ChainIndex": i, "StateManager.addressesProvider": core.PsyAddressesProvider,
      "Bridge.provedDepositCount": "0", "Bridge.pendingDepositCount": "0", "Bridge.depositRoot": EMPTY,
      "Bridge.getDepositFrontier": Array(32).fill(ZERO), "PsyToken.totalSupply": "1000000000000000000",
      "custody.PSY": "1000000000000000000", "custody.native": "0", "custody.USDT": "0",
      "PsyToken.owner": core.Bridge, "PsyToken.addressesProvider": core.PsyAddressesProvider,
      "provider.STATE_MANAGER": core.StateManager, "provider.BRIDGE": core.Bridge,
    };
    for (const r of ["isBridgeAdmin", "isStateManagerAdmin", "isProposer"]) state[`PsyACLManager.${r}`] = true;
    for (const t of ["native", "PSY", "USDT"]) { state[`pause.${t}`] = quarantined ? [7, 0, 7] : [1, 0, 1]; state[`withdrawalTotal.${t}`] = "0"; }
    const finalized = Array.from({ length: 19 }, (_, j) => ({ tx: root(j + 50), block: 20 + j, log_index: 0, old_checkpoint_root: j === 0 ? FIRST_OLD_ROOT : root(j), args: [String(64 * (j + 1)), root(j + 1), ZERO, ZERO] }));
    snapshot.chains.push({ network, chain_id: CHAINS[network][0], signer: SIGNER, contracts: core,
      start_block: 1, block: 100, block_timestamp: 1000, block_hash: root(90),
      pending_block_available: true, pending_transactions: [], nonces: { snapshot: 40, latest: 40, pending: 40, latest_after: 40, pending_after: 40 },
      quiescent_observed: true, end_tip: { checkpoint: "1216", root: root(19) }, state,
      bytecode_matches: Object.fromEntries(Object.keys(CODE).map(n => [n, { keccak256: CODE[n], implementation: implementations[`${n}_Implementation`] }])),
      events: { "StateManager.Finalized": 19, "PsyToken.Transfer": 1 }, unparsed_logs: [], finalized,
      checkpoint_roots: finalized.map(e => e.args[1]), deposit_subtree_roots: [ZERO], withdrawal_subtree_roots: [ZERO],
      root_registry: [...finalized.map(e => ({ field: "checkpointTreeRootCheckpointId", root: e.args[1], value: e.args[0] })),
        { field: "knownDepositSubtreeRoots", root: ZERO, value: true }, { field: "knownWithdrawalSubtreeRoots", root: ZERO, value: true }],
      force_states: [], withdrawal_nonces: [], reward_claims: [], deposit_indexes: [] });
  }
  const fence = { relayer_stopped: true, guardians_stopped: true, pending_l1_transactions_drained: true,
    snapshot_finality_accepted: true, stopped_at_unix: 900, new_genesis_sha256: "b".repeat(64), new_runtime_commit: "c".repeat(40), snapshot_sha256: "d".repeat(64) };
  return { ctx, snapshot, fence };
}

test("quarantine encodes only clean=false then full pause, for exactly three chains", () => {
  const { ctx, snapshot } = fixture(); const p = tool.prepare("quarantine", snapshot, ctx);
  for (const c of p.chains) {
    assert.deepEqual(c.transactions.map(t => t.method), ["setCheckpointTreeRootsClean", "setGlobalPauseFlags"]);
    assert.deepEqual(c.transactions.map(t => t.args), [[false], [7]]);
    assert.equal(ctx.abis.StateManager.decodeFunctionData("setCheckpointTreeRootsClean", c.transactions[0].data)[0], false);
  }
  assert.equal(p.broadcast_allowed, false); assert.equal(p.release_approved, false);
  assert.equal(p.cleanup_reopen_allowed, false);
  assert.throws(() => tool.prepare("broadcast", snapshot, ctx));
});

test("reset requires quiescent fenced quarantine and contains all roots and exact five-field CAS", () => {
  const { ctx, snapshot, fence } = fixture(true); const p = tool.prepare("reset", snapshot, ctx, fence);
  for (let i = 0; i < 3; i++) {
    const txs = p.chains[i].transactions;
    assert.deepEqual(txs.map(t => t.contract), ["StateManager", "StateManager"]);
    assert.deepEqual(txs[0].args[0], FIELDS.map(f => snapshot.chains[i].state[`StateManager.${f}`]));
    assert.deepEqual(txs[0].args[1], ["0", ZERO, ZERO, ZERO, ZERO]);
    assert.deepEqual(Array.from(ctx.abis.StateManager.decodeFunctionData("revokeCheckpointTreeRoots", txs[1].data)[0]), snapshot.chains[i].checkpoint_roots);
  }
});

test("unfenced, unpaused, stale nonce, pending tx and predating snapshots fail closed", () => {
  for (const mutate of [
    f => { f.fence.relayer_stopped = false; }, f => { f.fence.guardians_stopped = false; },
    f => { f.fence.pending_l1_transactions_drained = false; }, f => { f.fence.snapshot_finality_accepted = false; },
    f => { f.fence.stopped_at_unix = 1001; }, f => { f.snapshot.chains[0].state["StateManager.checkpointTreeRootsClean"] = true; },
    f => { f.snapshot.chains[0].state["pause.native"] = [1, 0, 1]; }, f => { f.snapshot.chains[0].nonces.pending++; },
    f => { f.snapshot.chains[0].pending_transactions.push({ hash: root(20) }); }, f => { f.snapshot.chains[0].pending_block_available = false; },
    f => { f.snapshot.chains[0].end_tip.checkpoint = "1280"; },
  ]) { const f = fixture(true); mutate(f); assert.throws(() => tool.prepare("reset", f.snapshot, f.ctx, f.fence)); }
});

test("partial history, missing chain/root, root-value drift and implementation drift fail closed", () => {
  for (const mutate of [
    f => { f.snapshot.complete = false; }, f => { f.snapshot.chains.pop(); },
    f => { f.snapshot.chains[0].checkpoint_roots.pop(); }, f => { f.snapshot.chains[0].root_registry.pop(); },
    f => { f.snapshot.chains[0].root_registry[0].value = "0"; },
    f => { f.snapshot.chains[0].finalized[0].old_checkpoint_root = ZERO; },
    f => { f.snapshot.chains[0].bytecode_matches.Bridge.keccak256 = root(30); },
    f => { const c = f.snapshot.chains[0]; c.finalized.splice(1, 1); c.checkpoint_roots.splice(1, 1); c.root_registry.splice(1, 1); c.events["StateManager.Finalized"]--; },
    f => { f.snapshot.chains[0].contracts.Bridge = address(999); },
  ]) { const f = fixture(true); mutate(f); assert.throws(() => tool.prepare("reset", f.snapshot, f.ctx, f.fence)); }
});

test("nonuniform final batches are accepted only with an unbroken predecessor root chain", () => {
  const f = fixture(true);
  for (const c of f.snapshot.chains) {
    c.finalized.at(-1).args[0] = "1159";
    c.root_registry[18].value = "1159";
    c.state["StateManager.lastFinalizedCheckpointId"] = "1159";
    c.end_tip.checkpoint = "1159";
  }
  assert.doesNotThrow(() => tool.prepare("reset", f.snapshot, f.ctx, f.fence));
  f.snapshot.chains[0].finalized[7].old_checkpoint_root = root(999);
  assert.throws(() => tool.prepare("reset", f.snapshot, f.ctx, f.fence));
});

test("any deposit/claim/reward/transfer/withdrawal-total/reserve change blocks narrow reset", () => {
  for (const mutate of [
    f => { f.snapshot.chains[0].events["PsyToken.RewardClaimed"] = 1; },
    f => { f.snapshot.chains[0].events["Bridge.WithdrawalPendingCreated"] = 1; },
    f => { f.snapshot.chains[0].events["Bridge.DepositRecorded"] = 1; },
    f => { f.snapshot.chains[0].events["PsyToken.Transfer"]++; },
    f => { f.snapshot.chains[0].state["withdrawalTotal.PSY"] = "1"; },
    f => { f.snapshot.chains[0].state["custody.PSY"] = "0"; },
    f => { f.snapshot.chains[0].state["Bridge.getDepositFrontier"][0] = root(1); },
    f => { f.snapshot.chains[0].withdrawal_subtree_roots.push(root(55)); },
  ]) { const f = fixture(true); mutate(f); assert.throws(() => tool.prepare("reset", f.snapshot, f.ctx, f.fence)); }
});

function resetReadback(f) {
  const after = structuredClone(f.snapshot);
  for (const c of after.chains) {
    c.block++; c.block_hash = root(99);
    for (const k of Object.keys(c.nonces)) c.nonces[k] += 2;
    const tuple = FIELDS.map(k => c.state[`StateManager.${k}`]);
    const next = ["0", ZERO, ZERO, ZERO, ZERO];
    const digest = t => ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["bytes32", "uint64", "bytes32", "bytes32", "bytes32", "bytes32"], [ethers.utils.id("PSY_STATE_MANAGER_FORCE_SET_STATE_V1"), ...t]));
    FIELDS.forEach((k, i) => { c.state[`StateManager.${k}`] = next[i]; });
    c.end_tip = { checkpoint: "0", root: ZERO };
    c.root_registry.forEach(r => { if (r.field === "checkpointTreeRootCheckpointId") r.value = "0"; });
    c.events["StateManager.ForceSetState"] = 1;
    c.force_states = [{ contract: "StateManager", block: c.block, args: [digest(tuple), digest(next), ...next] }];
  }
  return after;
}

test("reset readback verifies exact event hashes, all roots revoked, unchanged custody and clean remains false", () => {
  const f = fixture(true), p = tool.prepare("reset", f.snapshot, f.ctx, f.fence), after = resetReadback(f);
  p.input_sha256 = { snapshot: f.fence.snapshot_sha256 };
  assert.equal(tool.verifyReadback(p, after, f.ctx).verified, true);
  for (const mutate of [
    a => { a.chains[0].root_registry[0].value = "64"; },
    a => { a.chains[0].state["StateManager.checkpointTreeRootsClean"] = true; },
    a => { a.chains[0].force_states[0].args[0] = root(100); },
    a => { a.chains[0].state["Bridge.depositBatchVerifier"] = address(100); },
    a => { a.chains[0].state["custody.PSY"] = "0"; },
    a => { a.chains[0].events["PsyACLManager.RoleGranted"] = 1; },
    a => { a.chains[0].events["Bridge.TokenFlowConfigUpdated"] = 1; },
    a => { a.chains[0].unparsed_logs.push({ topic: root(3) }); },
    a => { for (const k of Object.keys(a.chains[0].nonces)) a.chains[0].nonces[k]++; },
  ]) { const a = structuredClone(after); mutate(a); assert.throws(() => tool.verifyReadback(p, a, f.ctx)); }
  const changed = structuredClone(p); changed.chains[0].transactions[0].data = "0x";
  assert.throws(() => tool.verifyReadback(changed, after, f.ctx));
  const binding = structuredClone(p); binding.input_sha256.snapshot = "e".repeat(64);
  assert.throws(() => tool.verifyReadback(binding, after, f.ctx));
});

test("quarantine readback accepts only pause/clean changes and cannot report reset complete", () => {
  const f = fixture(), p = tool.prepare("quarantine", f.snapshot, f.ctx), a = structuredClone(f.snapshot);
  for (const c of a.chains) { c.block++; for (const k of Object.keys(c.nonces)) c.nonces[k] += 2; c.events["Bridge.GlobalPauseFlagsUpdated"] = 1; c.state["StateManager.checkpointTreeRootsClean"] = false; for (const t of ["native", "PSY", "USDT"]) c.state[`pause.${t}`] = [7, 0, 7]; }
  const r = tool.verifyReadback(p, a, f.ctx); assert.equal(r.phase, "quarantine"); assert.equal(r.release_approved, false);
  a.chains[0].state["StateManager.lastFinalizedCheckpointId"] = "0";
  assert.throws(() => tool.verifyReadback(p, a, f.ctx));
});

test("input pin, symlink rejection, create-only output and private modes", t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "l1-reset-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "out.json"); tool.writeNew(file, { safe: true });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.throws(() => tool.writeNew(file, {}));
  const raw = fs.readFileSync(file); assert.deepEqual(tool.pinnedJson(file, sha(raw)), { safe: true });
  assert.throws(() => tool.pinnedJson(file, "0".repeat(64)));
  const link = path.join(dir, "link"); fs.symlinkSync(file, link);
  assert.throws(() => tool.pinnedJson(link, sha(raw)));
  fs.chmodSync(dir, 0o755); assert.throws(() => tool.writeNew(path.join(dir, "other"), {}));
});
