#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");

const SOURCE = "5ba12a360c29243b687076997f97e80c2050895b";
const SIGNER = "0x490f8192725255C2C3dE0CbCE66312335Ca019Ad";
const ZERO = "0x" + "0".repeat(64);
const FIRST_OLD_ROOT = "0x3c7aaf1cffb4affc4d0d470bb7ea832be303a399bb3b70674f01d0c0eac28e2f";
const EMPTY = "0xd65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43";
const CHAINS = {
  sepolia: [11155111, "01bf0faf41dddcdc856e8e471b09a61ee1bdf405f33be8caa40882422cfc0c0b"],
  bscTestnet: [97, "9e1df0ce526897f17999bdbc20550f50131df026bdbd477ff714d4b72f7cc19f"],
  baseSepolia: [84532, "9d95d2cf55a561d4bc3d715398c5448ecd3e452e1ee2d198d64c6a07a995143d"],
};
const CODE = { StateManager: "0xdd1f31296ef896e63be489edbabb105040487a2ea241455b0b97b1c887519d68", Bridge: "0xe9a32d7f2165d3a1070f98bca218ff1cb88e51fc8a368125d005990916f11d78" };
const ABI_PINS = { StateManager: "0dfbcd26f1cf02436a92de49686c0f932fce5b07dc638d0975c083b4a318644b", Bridge: "1daaf26d7c088f864774810d81f2bdd39d1ef39b4f4f761160027dd8e50b4891" };
const FIELDS = ["lastFinalizedCheckpointId", "lastVerifiedCheckpointRoot", "lastVerifiedDepositTreeRoot", "lastVerifiedWithdrawalTreeRoot", "withdrawalSubtreeRoot"];
const USER_EVENTS = ["Bridge.DepositRecorded", "Bridge.DepositBatchAppended", "Bridge.WithdrawalPendingCreated", "Bridge.WithdrawalClaimed", "Bridge.WithdrawalForceClaimed", "Bridge.WithdrawalClaimBatchResult", "Bridge.WithdrawalClaimItemFailed", "PsyToken.RewardClaimed", "TokenFaucetManager.Claimed"];
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const hash = value => assert.match(value, /^[0-9a-f]{64}$/);
const word = value => assert.match(value, /^0x[0-9a-f]{64}$/);
const tuple = row => FIELDS.map(f => row.state[`StateManager.${f}`]);
const target = () => ["0", ZERO, ZERO, ZERO, ZERO];

function pinnedJson(file, pin) {
  hash(pin);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    assert(fs.fstatSync(fd).isFile());
    const raw = fs.readFileSync(fd);
    assert.equal(sha(raw), pin, "input hash mismatch");
    return JSON.parse(raw);
  } finally { fs.closeSync(fd); }
}

function context(contracts, evidence) {
  const localRequire = createRequire(path.resolve(contracts, "package.json"));
  const { ethers } = localRequire("ethers");
  const abis = {};
  for (const [name, pin] of Object.entries(ABI_PINS)) {
    abis[name] = new ethers.utils.Interface(pinnedJson(path.join(contracts, `artifacts/hardhat/src/${name}.sol/${name}.json`), pin).abi);
  }
  const docs = Object.fromEntries(Object.entries(CHAINS).map(([n, [, pin]]) => [n, pinnedJson(path.join(evidence, n, "deployed-contracts.json"), pin)]));
  return { ethers, abis, docs };
}

function validateSnapshot(snapshot, ctx, afterReset = false) {
  assert.equal(snapshot.complete, true, "incomplete snapshot");
  assert.equal(snapshot.readonly, true);
  assert.equal(snapshot.source, SOURCE);
  hash(snapshot.collector_sha256);
  assert.deepEqual(snapshot.chains.map(c => c.network).sort(), Object.keys(CHAINS).sort());
  for (const row of snapshot.chains) {
    const doc = ctx.docs[row.network];
    assert.equal(row.chain_id, CHAINS[row.network][0]);
    assert.deepEqual(row.contracts, doc.core, "deployment address mismatch");
    assert.equal(row.signer, SIGNER);
    word(row.block_hash);
    assert(Number.isSafeInteger(row.start_block) && row.start_block > 0 && row.start_block <= doc.deploymentBlock);
    assert(Number.isSafeInteger(row.block) && row.block >= row.start_block);
    assert(Number.isSafeInteger(row.block_timestamp) && row.block_timestamp > 0);
    assert.equal(row.pending_block_available, true, "pending block unavailable");
    assert.deepEqual(row.pending_transactions, [], "pending contract/signer transaction");
    assert.deepEqual(Object.keys(row.nonces).sort(), ["snapshot", "latest", "pending", "latest_after", "pending_after"].sort());
    const nonces = Object.values(row.nonces);
    assert(nonces.every(n => Number.isSafeInteger(n) && n >= 0) && new Set(nonces).size === 1, "nonce not quiescent");
    assert.equal(row.quiescent_observed, true);
    assert(Array.isArray(row.unparsed_logs), "unparsed-log inventory required");
    for (const count of Object.values(row.events)) assert(Number.isSafeInteger(count) && count >= 0);
    const s = row.state;
    assert.equal(row.end_tip.checkpoint, s["StateManager.lastFinalizedCheckpointId"]);
    assert.equal(row.end_tip.root, s["StateManager.lastVerifiedCheckpointRoot"]);
    for (const name of Object.keys(CODE)) {
      assert.equal(row.bytecode_matches[name].keccak256, CODE[name]);
      assert.equal(row.bytecode_matches[name].implementation, doc.implementations[`${name}_Implementation`]);
    }
    for (const field of ["isStateManagerAdmin", "isBridgeAdmin", "isProposer"]) assert.equal(s[`PsyACLManager.${field}`], true);
    assert.equal(s["provider.STATE_MANAGER"], doc.core.StateManager);
    assert.equal(s["provider.BRIDGE"], doc.core.Bridge);
    assert.equal(s["StateManager.addressesProvider"], doc.core.PsyAddressesProvider);
    assert.equal(s["PsyToken.addressesProvider"], doc.core.PsyAddressesProvider);
    assert.equal(s["StateManager.l1ChainIndex"], Object.keys(CHAINS).indexOf(row.network));
    for (const event of USER_EVENTS) assert.equal(row.events[event] || 0, 0, `nonempty ${event}`);
    for (const field of ["withdrawal_nonces", "reward_claims", "deposit_indexes"]) assert.deepEqual(row[field], []);
    assert.equal(row.events["PsyToken.Transfer"], 1, "token transfer history changed");
    for (const f of ["provedDepositCount", "pendingDepositCount"]) assert.equal(s[`Bridge.${f}`], "0");
    assert.equal(s["Bridge.depositRoot"], EMPTY);
    assert.deepEqual(s["Bridge.getDepositFrontier"], Array(32).fill(ZERO));
    assert.equal(s["PsyToken.totalSupply"], "1000000000000000000");
    assert.equal(s["custody.PSY"], s["PsyToken.totalSupply"]);
    assert.equal(s["PsyToken.owner"], doc.core.Bridge);
    for (const t of ["native", "PSY", "USDT"]) {
      assert.equal(s[`withdrawalTotal.${t}`], "0");
      const flags = s[`pause.${t}`];
      assert(Array.isArray(flags) && flags.length === 3 && [1, 7].includes(flags[0]) && flags[1] === 0 && flags[2] === flags[0]);
    }
    for (const t of ["native", "USDT"]) assert.equal(s[`custody.${t}`], "0");
    for (const f of FIELDS.slice(2)) assert.equal(s[`StateManager.${f}`], ZERO, "nonempty bridge tree requires separate review");
    assert.equal(typeof s["StateManager.checkpointTreeRootsClean"], "boolean");
    assert.deepEqual(row.deposit_subtree_roots, [ZERO]);
    assert.deepEqual(row.withdrawal_subtree_roots, [ZERO]);
    const finalized = row.finalized;
    assert(finalized.length >= 19 && finalized.length <= 64 && finalized.length === row.events["StateManager.Finalized"], "bounded complete settlement cohort required");
    assert.deepEqual(row.checkpoint_roots, finalized.map(e => e.args[1]), "incomplete root inventory");
    assert.equal(new Set(row.checkpoint_roots).size, finalized.length);
    let previous = 0n;
    let previousRoot;
    for (const event of finalized) {
      assert(event.block >= row.start_block && event.block <= row.block);
      word(event.tx); word(event.args[1]);
      assert.notEqual(event.args[1], ZERO);
      assert(BigInt(event.args[0]) > previous && BigInt(event.args[0]) < 2n ** 64n);
      word(event.old_checkpoint_root);
      if (previousRoot) assert.equal(event.old_checkpoint_root, previousRoot, "missing settlement predecessor");
      else {
        assert.equal(event.args[0], "64", "missing first settlement");
        assert.equal(event.old_checkpoint_root, FIRST_OLD_ROOT, "wrong first-proof lineage");
      }
      previous = BigInt(event.args[0]);
      previousRoot = event.args[1];
      assert.equal(event.args[2], ZERO); assert.equal(event.args[3], ZERO);
    }
    const entries = row.root_registry.map(r => `${r.field}:${r.root}`);
    assert.equal(new Set(entries).size, entries.length);
    const expected = finalized.map(e => ({ field: "checkpointTreeRootCheckpointId", root: e.args[1], value: afterReset ? "0" : e.args[0] }));
    expected.push({ field: "knownDepositSubtreeRoots", root: ZERO, value: true }, { field: "knownWithdrawalSubtreeRoots", root: ZERO, value: true });
    assert.deepEqual(row.root_registry, expected, "root registry mismatch");
    if (afterReset) assert.deepEqual(tuple(row), target());
    else {
      assert.equal(s["StateManager.lastFinalizedCheckpointId"], finalized.at(-1).args[0]);
      assert.equal(s["StateManager.lastVerifiedCheckpointRoot"], finalized.at(-1).args[1]);
      assert.deepEqual(row.force_states, [], "prior force-set requires separate review");
      assert.equal(row.events["StateManager.ForceSetState"] || 0, 0);
      assert.equal(row.events["Bridge.ForceSetState"] || 0, 0);
    }
  }
}

function requireQuarantine(row) {
  assert.equal(row.state["StateManager.checkpointTreeRootsClean"], false, "quarantine readback required");
  for (const token of ["native", "PSY", "USDT"]) assert.deepEqual(row.state[`pause.${token}`], [7, 0, 7]);
}

function prepare(phase, snapshot, ctx, fence) {
  assert(["quarantine", "reset"].includes(phase));
  validateSnapshot(snapshot, ctx);
  if (phase === "reset") {
    for (const k of ["relayer_stopped", "guardians_stopped", "pending_l1_transactions_drained", "snapshot_finality_accepted"]) assert.equal(fence[k], true, `missing ${k}`);
    hash(fence.new_genesis_sha256);
    hash(fence.snapshot_sha256);
    assert.match(fence.new_runtime_commit, /^[0-9a-f]{40}$/);
    assert(Number.isSafeInteger(fence.stopped_at_unix) && fence.stopped_at_unix > 0);
    for (const row of snapshot.chains) {
      requireQuarantine(row);
      assert(row.block_timestamp >= fence.stopped_at_unix, "snapshot predates fencing");
    }
  }
  const chains = snapshot.chains.map(row => {
    const operations = phase === "quarantine"
      ? [["StateManager", "setCheckpointTreeRootsClean", [false]], ["Bridge", "setGlobalPauseFlags", [7]]]
      : [["StateManager", "forceSetState", [tuple(row), target()]], ["StateManager", "revokeCheckpointTreeRoots", [row.checkpoint_roots]]];
    return { network: row.network, transactions: operations.map(([contract, method, args]) => ({
      chainId: row.chain_id, from: SIGNER, to: row.contracts[contract], value: "0", contract, method,
      args, data: ctx.abis[contract].encodeFunctionData(method, args),
    })) };
  });
  return { version: 1, phase, broadcast_allowed: false, release_approved: false, cleanup_reopen_allowed: false,
    dry_run_kind: "offline-calldata-only", fresh_prebroadcast_readback_required: true,
    fence: fence || null, before: snapshot, chains };
}

function verifyReadback(plan, snapshot, ctx) {
  const expectedPlan = prepare(plan.phase, plan.before, ctx, plan.fence);
  for (const k of Object.keys(expectedPlan)) assert.deepEqual(plan[k], expectedPlan[k], `changed plan ${k}`);
  validateSnapshot(snapshot, ctx, plan.phase === "reset");
  if (plan.phase === "reset") assert.equal(plan.input_sha256?.snapshot, plan.fence.snapshot_sha256, "fence/plan snapshot binding mismatch");
  for (const after of snapshot.chains) {
    const before = plan.before.chains.find(c => c.network === after.network);
    assert(after.block > before.block, "new post-transaction snapshot required");
    assert.equal(after.nonces.snapshot, before.nonces.snapshot + 2, "unexpected signer activity or incomplete phase");
    const changedEvent = plan.phase === "quarantine" ? "Bridge.GlobalPauseFlagsUpdated" : "StateManager.ForceSetState";
    const keys = new Set([...Object.keys(before.events), ...Object.keys(after.events), changedEvent]);
    for (const key of keys) assert.equal((after.events[key] || 0) - (before.events[key] || 0), key === changedEvent ? 1 : 0, `unexpected event delta ${key}`);
    assert.deepEqual(after.unparsed_logs, before.unparsed_logs, "unexpected unparsed event during phase");
    assert.deepEqual(after.finalized, before.finalized, "unexpected settlement during quarantine");
    assert.deepEqual(after.checkpoint_roots, before.checkpoint_roots);
    requireQuarantine(after);
    const state = structuredClone(before.state);
    state["StateManager.checkpointTreeRootsClean"] = false;
    for (const token of ["native", "PSY", "USDT"]) state[`pause.${token}`] = [7, 0, 7];
    if (plan.phase === "reset") {
      FIELDS.forEach((f, i) => { state[`StateManager.${f}`] = target()[i]; });
      assert.equal(after.force_states.length, 1);
      assert.equal(after.events["StateManager.ForceSetState"], 1);
      assert.equal(after.events["Bridge.ForceSetState"] || 0, 0);
      const event = after.force_states[0];
      const stateHash = t => ctx.ethers.utils.keccak256(ctx.ethers.utils.defaultAbiCoder.encode(
        ["bytes32", "uint64", "bytes32", "bytes32", "bytes32", "bytes32"],
        [ctx.ethers.utils.id("PSY_STATE_MANAGER_FORCE_SET_STATE_V1"), ...t]));
      assert.equal(event.contract, "StateManager");
      assert(event.block > before.block && event.block <= after.block);
      assert.deepEqual(event.args, [stateHash(tuple(before)), stateHash(target()), ...target()]);
    }
    assert.deepEqual(after.state, state, "state outside planned SM/pause delta changed");
  }
  return { verified: true, phase: plan.phase, broadcast_allowed: false, release_approved: false, cleanup_reopen_allowed: false };
}

function writeNew(file, report) {
  const parent = fs.lstatSync(path.dirname(path.resolve(file)));
  assert(parent.isDirectory() && !parent.isSymbolicLink() && (parent.mode & 0o077) === 0, "private output parent required");
  fs.writeFileSync(file, JSON.stringify(report, null, 2) + "\n", { flag: "wx", mode: 0o600 });
}

function main(argv) {
  const [phase, contracts, evidence, ...args] = argv;
  assert(["quarantine", "reset", "readback"].includes(phase), "phase must be quarantine, reset or readback; no broadcast mode exists");
  assert.equal(args.length, phase === "quarantine" ? 3 : 5, "Usage: PHASE CONTRACTS EVIDENCE SNAPSHOT SHA [FENCE SHA] OUTPUT; readback uses PLAN SHA SNAPSHOT SHA OUTPUT");
  const ctx = context(contracts, evidence);
  let result;
  if (phase === "readback") result = verifyReadback(pinnedJson(args[0], args[1]), pinnedJson(args[2], args[3]), ctx);
  else {
    const fence = phase === "reset" ? pinnedJson(args[2], args[3]) : null;
    if (fence) assert.equal(fence.snapshot_sha256, args[1], "fence refers to another snapshot");
    result = prepare(phase, pinnedJson(args[0], args[1]), ctx, fence);
  }
  result.input_sha256 = phase === "readback" ? { plan: args[1], snapshot: args[3] } : { snapshot: args[1], ...(phase === "reset" ? { fence: args[3] } : {}) };
  result.tool_sha256 = sha(fs.readFileSync(__filename));
  writeNew(args.at(-1), result);
  console.log(JSON.stringify({ phase, sha256: sha(fs.readFileSync(args.at(-1))), broadcast_allowed: false, release_approved: false }));
}
if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { prepare, verifyReadback, validateSnapshot, context, pinnedJson, writeNew, SOURCE, SIGNER, ZERO, FIRST_OLD_ROOT, EMPTY, CODE, FIELDS, CHAINS };
