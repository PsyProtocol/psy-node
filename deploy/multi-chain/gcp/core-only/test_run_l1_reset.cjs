"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const q = require("./run_l1_quarantine.cjs");
const reset = require("./run_l1_reset.cjs");
const names = ["bundle", "evidence", "plan", "snapshot", "collector", "budgets"];
const input = Object.fromEntries(names.map((name, i) => [name, process.argv[i + 2]]));
const original = q.load(input);
const sha = data => crypto.createHash("sha256").update(data).digest("hex");

function fixture() {
  // Unit-test simulation only, owned temporary files removed by every test.
  // Never stage these files or present them as real post-quarantine evidence.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "reset-unit-fixture-"));
  const snapshot = structuredClone(original.snapshot);
  snapshot.simulated_unit_test = true;
  for (const row of snapshot.chains) {
    row.block += 10;
    row.state["StateManager.checkpointTreeRootsClean"] = false;
    for (const t of ["native", "PSY", "USDT"]) row.state["pause." + t] = [7, 0, 7];
    for (const n of Object.keys(row.nonces)) row.nonces[n] += 2;
    row.events["Bridge.GlobalPauseFlagsUpdated"] = (row.events["Bridge.GlobalPauseFlagsUpdated"] || 0) + 1;
  }
  const write = (name, value) => {
    const bytes = JSON.stringify(value);
    const file = path.join(dir, name + ".json");
    fs.writeFileSync(file, bytes, { flag: "wx", mode: 0o600 });
    return [file, sha(bytes)];
  };
  const [snapshotFile, snapshotSHA] = write("unit-snapshot", snapshot);
  const fence = { relayer_stopped: true, guardians_stopped: true, pending_l1_transactions_drained: true,
    snapshot_finality_accepted: true, stopped_at_unix: 1, new_genesis_sha256: "a".repeat(64),
    new_runtime_commit: "b".repeat(40), snapshot_sha256: snapshotSHA };
  const [fenceFile, fenceSHA] = write("unit-fence", fence);
  const plan = original.planner.prepare("reset", snapshot, original, fence);
  plan.input_sha256 = { snapshot: snapshotSHA, fence: fenceSHA }; plan.tool_sha256 = q.PIN.planner;
  const [planFile, planSHA] = write("unit-plan", plan);
  const request = { ...input, quarantine_plan: input.plan, baseline_snapshot: input.snapshot,
    snapshot: snapshotFile, snapshot_sha256: snapshotSHA, fence: fenceFile, fence_sha256: fenceSHA, plan: planFile, plan_sha256: planSHA };
  return { dir, request, plan, snapshot, fence, write };
}

test("reset plan binds collector, real-lineage predicate, fence and exact six reconstructed operations", () => {
  const f = fixture();
  try {
    const ctx = reset.load(f.request);
    assert.equal(ctx.plan.phase, "reset");
    assert.equal(ctx.plan.chains.flatMap(c => c.transactions).length, 6);
    assert(ctx.plan.chains.every(c => c.transactions.every(t => t.contract === "StateManager")));
    assert.throws(() => reset.load({ ...f.request, plan_sha256: "0".repeat(64) }), /input hash mismatch/);
    assert.throws(() => reset.load({ ...f.request, snapshot: input.snapshot, snapshot_sha256: q.PIN.snapshot }), /unexpected signer activity or incomplete phase/);
  } finally { fs.rmSync(f.dir, { recursive: true }); }
});

test("changed calldata, omitted roots, unknown metadata and clean/unpause substitution reject even with updated SHA", () => {
  const f = fixture();
  try {
    const mutations = [p => { p.chains[0].transactions[0].data = "0x"; },
      p => { p.chains[0].transactions[1].args[0].pop(); },
      p => { p.extra = true; }, p => { p.chains[0].transactions[0].method = "setCheckpointTreeRootsClean"; }];
    mutations.forEach((change, i) => {
      const plan = structuredClone(f.plan); change(plan);
      const [file, pin] = f.write("bad-plan-" + i, plan);
      assert.throws(() => reset.load({ ...f.request, plan: file, plan_sha256: pin }), /reset plan must equal complete reviewed planner output/);
    });
  } finally { fs.rmSync(f.dir, { recursive: true }); }
});

test("collector, fence snapshot and malformed fence hash have precise rejection gates", () => {
  const f = fixture();
  try {
    const badSnapshot = structuredClone(f.snapshot); badSnapshot.collector_sha256 = "0".repeat(64);
    const [s, sh] = f.write("wrong-collector", badSnapshot);
    assert.throws(() => reset.load({ ...f.request, snapshot: s, snapshot_sha256: sh }), /collector hash mismatch/);
    const [ff, fh] = f.write("wrong-fence", { ...f.fence, snapshot_sha256: "0".repeat(64) });
    assert.throws(() => reset.load({ ...f.request, fence: ff, fence_sha256: fh }), /fence snapshot binding mismatch/);
    assert.throws(() => reset.load({ ...f.request, fence_sha256: "abc" }), { code: "ERR_ASSERTION" });
  } finally { fs.rmSync(f.dir, { recursive: true }); }
});

test("expected reset deltas preserve history and pause7, old root registrations only clear after revoke", () => {
  const f = fixture();
  try {
    const ctx = reset.load(f.request), row = ctx.snapshot.chains[0];
    const before = structuredClone(row);
    const one = reset.expectedRow(ctx, row, 1), two = reset.expectedRow(ctx, row, 2);
    assert.deepEqual(row, before);
    assert.equal(one.state["StateManager.lastFinalizedCheckpointId"], "0");
    assert.deepEqual(one.root_registry, row.root_registry);
    assert(two.root_registry.filter(r => r.field === "checkpointTreeRootCheckpointId").every(r => r.value === "0"));
    assert(two.root_registry.filter(r => r.field !== "checkpointTreeRootCheckpointId").every(r => r.value === true));
    assert.deepEqual(two.finalized, row.finalized);
    assert.equal(two.state["StateManager.checkpointTreeRootsClean"], false);
    for (const token of ["native", "PSY", "USDT"]) assert.deepEqual(two.state["pause." + token], [7, 0, 7]);
  } finally { fs.rmSync(f.dir, { recursive: true }); }
});

test("real in-process EVM: CAS zero then revoke all roots with exact receipts and unchanged pause", async () => {
  const f = fixture();
  try {
    const ctx = reset.load(f.request), { ethers } = ctx;
    const local = createRequire(path.resolve(input.bundle, "contracts/package.json"));
    const { createHardhatNetworkProvider } = local("hardhat/internal/hardhat-network/provider/provider");
    const proxy = local("hardhat-deploy/extendedArtifacts/TransparentUpgradeableProxy.json");
    const provider = await createHardhatNetworkProvider({ hardfork: "cancun", chainId: 31337, networkId: 31337,
      blockGasLimit: 30000000, minGasPrice: 0n, automine: true, intervalMining: 0, mempoolOrder: "priority",
      chains: new Map(), genesisAccounts: [], allowUnlimitedContractSize: false, throwOnTransactionFailures: true,
      throwOnCallFailures: true, allowBlocksWithSameTimestamp: false, initialBaseFeePerGas: 1,
      enableTransientStorage: true, enableRip7212: false }, { enabled: false });
    const rpc = (method, params) => provider.request({ method, params });
    await rpc("hardhat_impersonateAccount", [ctx.planner.SIGNER]);
    await rpc("hardhat_setBalance", [ctx.planner.SIGNER, "0xde0b6b3a7640000"]);
    const source = path.resolve(input.bundle, "contracts/artifacts/hardhat/src/StateManager.sol");
    const debug = JSON.parse(fs.readFileSync(path.join(source, "StateManager.dbg.json")));
    const build = JSON.parse(fs.readFileSync(path.resolve(source, debug.buildInfo)));
    const layout = build.output.contracts["src/StateManager.sol"].StateManager.storageLayout.storage;
    const slot = layout.find(s => s.label === "checkpointTreeRootCheckpointId").slot;
    let tested = 0;
    for (const row of ctx.snapshot.chains) {
      const doc = ctx.docs[row.network];
      for (const name of ["StateManager", "Bridge", "PsyACLManager", "PsyAddressesProvider"]) {
        const impl = doc.implementations[name + "_Implementation"];
        await rpc("hardhat_setCode", [impl, ctx.artifacts[name].deployedBytecode]);
        await rpc("hardhat_setCode", [doc.core[name], proxy.deployedBytecode]);
        await rpc("hardhat_setStorageAt", [doc.core[name], "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", ethers.utils.hexZeroPad(impl, 32)]);
        await rpc("hardhat_setStorageAt", [doc.core[name], "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", ethers.utils.hexZeroPad(doc.core.DefaultProxyAdmin, 32)]);
      }
      const send = async (name, field, args) => {
        const hash = await rpc("eth_sendTransaction", [{ from: ctx.planner.SIGNER, to: doc.core[name],
          data: ctx.abis[name].encodeFunctionData(field, args), gas: "0x100000", gasPrice: "0x3b9aca00" }]);
        const r = await rpc("eth_getTransactionReceipt", [hash]); assert.equal(r.status, "0x1"); return r;
      };
      const read = async (name, field, args = []) => ctx.abis[name].decodeFunctionResult(field,
        await rpc("eth_call", [{ to: doc.core[name], data: ctx.abis[name].encodeFunctionData(field, args) }, "latest"]));
      await send("PsyAddressesProvider", "initialize", [ctx.planner.SIGNER]);
      await send("PsyACLManager", "initialize", Array(5).fill(ctx.planner.SIGNER));
      await send("PsyAddressesProvider", "setAddress", [ethers.utils.id("ACL_MANAGER"), doc.core.PsyACLManager]);
      for (const id of ["STATE_MANAGER", "BRIDGE", "ZK_VERIFIER", "REWARD_CLAIM_VERIFIER"]) {
        await send("PsyAddressesProvider", "setAddress", [ethers.utils.id(id), row.state["provider." + id]]);
      }
      await send("StateManager", "initialize", [ctx.planner.SIGNER, doc.core.PsyAddressesProvider, row.state["StateManager.l1ChainIndex"]]);
      await send("Bridge", "initialize", [ctx.planner.SIGNER, doc.core.PsyAddressesProvider, doc.core.DepositBatchVerifier, doc.core.WithdrawalClaimVerifier]);
      await send("Bridge", "setGlobalPauseFlags", [7]);
      // These unrelated retained Bridge fields are fixture storage, not reset
      // operations. Hydrate them from the baseline using compiler slot data.
      const bridgeLayout = build.output.contracts["src/Bridge.sol"].Bridge.storageLayout.storage;
      for (const name of ["withdrawalForceClaimExecutor", "withdrawalTotalsTokenSetHash"]) {
        const field = bridgeLayout.find(s => s.label === name);
        const key = ethers.utils.hexValue(BigInt(field.slot));
        const old = BigInt(await rpc("eth_getStorageAt", [doc.core.Bridge, key, "latest"]));
        const bits = name === "withdrawalForceClaimExecutor" ? 160n : 256n;
        const shift = BigInt(field.offset) * 8n, mask = ((1n << bits) - 1n) << shift;
        const value = (old & ~mask) | (BigInt(row.state["Bridge." + name]) << shift);
        await rpc("hardhat_setStorageAt", [doc.core.Bridge, key, ethers.utils.hexZeroPad(ethers.utils.hexValue(value), 32)]);
      }
      const operations = ctx.plan.chains.find(c => c.network === row.network).transactions;
      // Build simulated old state directly in this non-fork local VM. The
      // production setter deliberately forbids increasing checkpoint height.
      for (const [i, name] of ctx.planner.FIELDS.entries()) {
        const field = layout.find(s => s.label === name);
        const key = ethers.utils.hexValue(BigInt(field.slot));
        const old = BigInt(await rpc("eth_getStorageAt", [doc.core.StateManager, key, "latest"]));
        const bits = i === 0 ? 64n : 256n, shift = BigInt(field.offset) * 8n;
        const mask = ((1n << bits) - 1n) << shift;
        const value = (old & ~mask) | (BigInt(operations[0].args[0][i]) << shift);
        await rpc("hardhat_setStorageAt", [doc.core.StateManager, key, ethers.utils.hexZeroPad(ethers.utils.hexValue(value), 32)]);
      }
      await send("StateManager", "setCheckpointTreeRootsClean", [false]);
      for (const entry of row.root_registry.filter(r => r.field === "checkpointTreeRootCheckpointId")) {
        const key = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(["bytes32", "uint256"], [entry.root, slot]));
        await rpc("hardhat_setStorageAt", [doc.core.StateManager, key, ethers.utils.hexZeroPad(ethers.utils.hexValue(BigInt(entry.value)), 32)]);
        assert.equal((await read("StateManager", entry.field, [entry.root]))[0].toString(), entry.value);
      }
      let reserved = { gas: 0n, wei: 0n };
      for (const op of operations) {
        const call = { from: op.from, to: op.to, data: op.data };
        assert.equal(await rpc("eth_call", [call, "latest"]), "0x");
        const estimate = await rpc("eth_estimateGas", [call]);
        const quoted = q.reserve(ctx.budgets[row.network], estimate, BigInt(ctx.budgets[row.network].maxGasPriceWei) / 2n, reserved);
        reserved = quoted.next;
        assert(quoted.gas <= BigInt(ctx.budgets[row.network].maxGasPerTransaction));
      }
      assert(reserved.gas <= BigInt(ctx.budgets[row.network].maxTotalGas));
      let completed = 0;
      for (const op of operations) {
        const r = await send("StateManager", op.method, op.args);
        const tx = await rpc("eth_getTransactionByHash", [r.transactionHash]);
        // EDR's impersonated transactions are unprotected and omit chainId.
        // Supply local VM metadata only here; production signs EIP-155 and
        // still requires the actual RPC transaction's chainId to match.
        tx.chainId = await rpc("eth_chainId", []);
        // Local VM chain is deliberately not a public testnet.
        const localOp = { ...op, chainId: 31337 };
        const localCtx = { ...ctx, planner: { ...ctx.planner, CHAINS: { [row.network]: [31337] } } };
        reset.verifyReceipt(localCtx, r, r.transactionHash, localOp, Number(tx.nonce),
          { gas: 0x100000n, fee: 1000000000n }, { hash: r.blockHash }, tx);
        completed++;
        const names = ["StateManager", "Bridge", "PsyAddressesProvider", "PsyACLManager"];
        for (const name of names) assert.equal(row.contracts[name].toLowerCase(), doc.core[name].toLowerCase());
        const deployed = new Set(names.map(n => doc.core[n].toLowerCase()));
        const jobs = q.stateJobs(ctx, reset.expectedRow(ctx, row, completed), completed).filter(j => deployed.has(j.to.toLowerCase()));
        assert(jobs.length > 0, "post-op stateJobs must be nonempty");
        assert.deepEqual(new Set(jobs.map(j => j.to.toLowerCase())), deployed, "post-op stateJobs must cover all four contracts");
        for (const job of jobs) {
          const raw = await rpc("eth_call", [{ to: job.to, data: job.data }, "latest"]);
          const decoded = job.abi.decodeFunctionResult(job.field, raw);
          const clean = v => v?._isBigNumber ? v.toString() : Array.isArray(v) ? v.map(clean) : v;
          assert.deepEqual(clean(decoded.length === 1 ? decoded[0] : decoded), job.expected, job.field);
        }
        const wrong = structuredClone(r); wrong.logs = op.method === "forceSetState" ? [] : [{ address: op.to }];
        assert.throws(() => reset.verifyReceipt(localCtx, wrong, r.transactionHash, localOp, Number(tx.nonce),
          { gas: 0x100000n, fee: 1000000000n }, { hash: r.blockHash }, tx));
        assert.equal((await read("StateManager", "checkpointTreeRootsClean"))[0], false);
        for (const [i, field] of ctx.planner.FIELDS.entries()) assert.equal((await read("StateManager", field))[0].toString(), i === 0 ? "0" : ctx.planner.ZERO);
        for (const token of [ethers.constants.AddressZero, doc.core.PsyToken, doc.core.USDTToken]) assert.deepEqual([...(await read("Bridge", "getPauseFlags", [token]))], [7, 0, 7]);
        for (const entry of row.root_registry.filter(r => r.field === "checkpointTreeRootCheckpointId")) {
          assert.equal((await read("StateManager", entry.field, [entry.root]))[0].toString(), op.method === "forceSetState" ? entry.value : "0");
        }
        assert.equal((await read("StateManager", "knownDepositSubtreeRoots", [ctx.planner.ZERO]))[0], true);
        assert.equal((await read("StateManager", "knownWithdrawalSubtreeRoots", [ctx.planner.ZERO]))[0], true);
        tested++;
      }
    }
    assert.equal(tested, 6);
  } finally { fs.rmSync(f.dir, { recursive: true }); }
});
