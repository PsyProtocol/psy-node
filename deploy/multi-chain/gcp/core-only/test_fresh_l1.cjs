"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createRequire } = require("node:module");
const runner = require("./fresh_l1.cjs");
const approved = require("./fresh_l1_policy.candidate.json");
const SIGNER = "0x490f8192725255C2C3dE0CbCE66312335Ca019Ad";
const ZERO = "0x" + "0".repeat(40);
const HASHZERO = "0x" + "0".repeat(64);
const address = n => "0x" + n.toString(16).padStart(40, "0");
const tokens = { native: ZERO, PSY: address(2), pUSDT: address(3) };

function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fresh-l1-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function fixture(network = "sepolia") {
  const events = [];
  const configs = structuredClone(approved.networks[network]);
  let flags = [1, 0, 1];
  const contracts = {
    PsyACLManager: { isBridgeAdmin: async () => true, isProposer: async () => true, isGuardian: async () => false },
    Bridge: { owner: async () => SIGNER,
      getTokenFlowConfig: async token => configs[Object.keys(tokens).find(n => tokens[n] === token)],
      getPauseFlags: async () => flags, totalWithdrawalAmount: async () => 0n,
      pendingDepositCount: async () => 0n, provedDepositCount: async () => 0n,
      depositRoot: async () => "0xd65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43" },
    StateManager: { lastFinalizedCheckpointId: async () => 0n, checkpointTreeRootsClean: async () => true },
    DefaultProxyAdmin: { owner: async () => address(9) },
    Router: {
      l1ToL2Token: async token => token === tokens.pUSDT ? "0x" + "0".repeat(63) + "4" : HASHZERO,
      l2ToL1Token: async id => id === HASHZERO ? tokens.PSY : tokens.pUSDT,
      isTokenMapped: async token => token !== ZERO,
    },
  };
  for (const method of ["lastVerifiedCheckpointRoot", "lastVerifiedDepositTreeRoot", "lastVerifiedWithdrawalTreeRoot", "withdrawalSubtreeRoot"]) {
    contracts.StateManager[method] = async () => HASHZERO;
  }
  const hre = {
    artifacts: { readArtifact: async () => ({ abi: [
      ["l1ToL2Token", "address", "bytes32"], ["l2ToL1Token", "bytes32", "address"],
      ["isTokenMapped", "address", "bool"],
    ].map(([name, input, output]) => ({ type: "function", name, stateMutability: "view",
      inputs: [{ type: input }], outputs: [{ type: output }] })) }) },
    ethers: { constants: { AddressZero: ZERO, HashZero: HASHZERO }, getContractAt: async name => contracts[name],
      provider: { getBlockNumber: async () => 123 } },
    run: async (task, args) => { events.push(args.tags || "full"); },
    deployments: {
      get: async name => ({ address: ({ PsyToken: tokens.PSY, USDTToken: tokens.pUSDT, ExecutorWithTimelock: address(9) })[name] || address(1) }),
      execute: async (name, opts, method, ...args) => { events.push(method); if (method === "setGlobalPauseFlags") assert.equal(args[0], 1); },
      read: async (name, method) => method === "ACL_MANAGER_ID" ? HASHZERO : method === "owner" ? address(9) : flags,
    },
  };
  return { hre, events, configs, contracts, setFlags: value => { flags = value; } };
}

test("approved policy pauses deposits but not registration/claims", () => {
  assert.equal(approved.pause_deposits, true);
  for (const chain of Object.values(approved.networks)) {
    for (const cfg of Object.values(chain)) {
      assert.equal(cfg.depositCap, ((1n << 128n) - 1n).toString());
      assert.equal(cfg.smallWithdrawalDelay, "0");
      assert.equal(cfg.mediumWithdrawalDelay, "0");
      assert.equal(cfg.largeWithdrawalDelay, "0");
    }
  }
});

test("bridge then ACL/pause/readback precedes any gateways and full wiring", async t => {
  const f = fixture();
  const output = temporary(t);
  await runner.deployPhases(f.hre, { pause_deposits: true, policy: approved.networks.sepolia }, output, "sepolia");
  assert.deepEqual(f.events, ["bridge", "setAddress", "setGlobalPauseFlags", "gateways", "full"]);
  const flow = JSON.parse(fs.readFileSync(path.join(output, "flow-sepolia.json")));
  assert.deepEqual(flow.tokens, [ZERO, tokens.PSY, tokens.pUSDT]);
  assert.deepEqual(flow.historicalWithdrawalTotals, ["0", "0", "0"]);
  const readback = JSON.parse(fs.readFileSync(path.join(output, "readback-sepolia.json")));
  assert.equal(readback.l1_acl_guardian, false);
  assert.equal(readback.tokens.native.effective_flags, 1);
});

test("pause readback failure stops before gateways", async t => {
  const f = fixture();
  f.setFlags([0, 0, 0]);
  await assert.rejects(runner.deployPhases(f.hre, { pause_deposits: true, policy: approved.networks.sepolia }, temporary(t), "sepolia"));
  assert.ok(!f.events.includes("gateways"));
});

test("deposit token policy rejects native admission", async () => {
  const f = fixture();
  f.contracts.Router.isTokenMapped = async () => true;
  await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens), /native deposits must remain unmapped/);
});

test("deposit token policy rejects a hidden native forward mapping", async () => {
  const f = fixture();
  const original = f.contracts.Router.l1ToL2Token;
  f.contracts.Router.l1ToL2Token = async token => token === ZERO ? "0x" + "0".repeat(63) + "5" : original(token);
  await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens), /native token has an unexpected L2 mapping/);
});

test("deposit token policy rejects an unset PSY reverse mapping", async () => {
  const f = fixture();
  f.contracts.Router.l2ToL1Token = async () => ZERO;
  await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens), /PSY reverse mapping/);
});

test("deposit token policy rejects wrong forward mappings and RPC failures", async () => {
  const f = fixture();
  f.contracts.Router.l1ToL2Token = async () => HASHZERO;
  await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens), /pUSDT forward mapping/);
  f.contracts.Router.l1ToL2Token = async () => { throw new Error("synthetic unavailable RPC"); };
  await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens), /synthetic unavailable RPC/);
});

test("deposit token policy rejects disabled tokens and a wrong nonzero pUSDT id", async () => {
  for (const name of ["PSY", "pUSDT"]) {
    const f = fixture();
    f.contracts.Router.isTokenMapped = async token => token !== ZERO && token !== tokens[name];
    await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens), new RegExp(`${name} deposits are not mapped`));
  }
  const f = fixture();
  f.contracts.Router.l1ToL2Token = async token => token === tokens.pUSDT ? "0x" + "0".repeat(63) + "5" : HASHZERO;
  await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens), /pUSDT forward mapping/);
});

test("deposit token policy rejects missing Router ABI before deployment", async t => {
  for (const missing of ["l1ToL2Token", "l2ToL1Token", "isTokenMapped"]) {
    const f = fixture();
    const artifact = await f.hre.artifacts.readArtifact();
    f.hre.artifacts.readArtifact = async () => ({ abi: artifact.abi.filter(item => item.name !== missing) });
    await assert.rejects(runner.deployPhases(f.hre, { pause_deposits: true }, temporary(t), "sepolia"), new RegExp(`Router ABI missing ${missing}`));
    assert.deepEqual(f.events, []);
  }
});

test("deposit token policy checks all mappings at one block on every chain", async t => {
  for (const network of ["sepolia", "bscTestnet", "baseSepolia"]) {
    const f = fixture(network);
    const calls = [];
    let blockReads = 0;
    f.hre.ethers.provider.getBlockNumber = async () => 123 + blockReads++;
    for (const method of ["l1ToL2Token", "l2ToL1Token", "isTokenMapped"]) {
      const original = f.contracts.Router[method];
      f.contracts.Router[method] = async (argument, block) => {
        calls.push(block);
        return original(argument);
      };
    }
    const output = temporary(t);
    await runner.deployPhases(f.hre, { pause_deposits: true, policy: approved.networks[network] }, output, network);
    assert.equal(calls.length, 8);
    assert.equal(blockReads, 1);
    assert.ok(calls.every(block => block.blockTag === 123));
    const readback = JSON.parse(fs.readFileSync(path.join(output, `readback-${network}.json`)));
    assert.equal(readback.deposit_mapping.native_allowed, false);
    assert.equal(readback.deposit_mapping.block_number, 123);
    assert.equal(readback.deposit_mapping.tokens.PSY.l2_contract_id, HASHZERO);
  }
});

test("missing Bridge-admin prevents pause and all gateways", async t => {
  const f = fixture();
  f.contracts.PsyACLManager.isBridgeAdmin = async () => false;
  await assert.rejects(runner.deployPhases(f.hre, { pause_deposits: true, policy: approved.networks.sepolia }, temporary(t), "sepolia"));
  assert.deepEqual(f.events, ["bridge"]);
});

test("each flow field and each pause bit are checked", async () => {
  for (const token of Object.keys(tokens)) {
    for (const field of Object.keys(approved.networks.sepolia[token])) {
      const f = fixture();
      f.configs[token][field] = field === "configured" ? false : "999";
      await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens));
    }
  }
  for (const flags of [[0, 0, 0], [3, 0, 3], [5, 0, 5], [1, 2, 3]]) {
    const f = fixture(); f.setFlags(flags);
    await assert.rejects(runner.verifyReadback(f.hre, approved.networks.sepolia, tokens));
  }
  await assert.rejects(runner.verifyReadback(fixture().hre, approved.networks.sepolia, { ...tokens, native: address(7) }));
});

test("gas bounds cover request and legacy send, reserve unknown submissions", async () => {
  const sent = [];
  const p = { request: async payload => { sent.push(payload); return "0x1"; } };
  runner.budgetGuard(p, {}, { maxGasPriceWei: "5", maxGasPerTransaction: "100", maxTotalGas: "150", maxNativeSpendWei: "500", l1FeeReserveWeiPerTransaction: "0" });
  const tx = { from: SIGNER, gas: "0x64", gasPrice: "0x5" };
  await p.send("eth_sendTransaction", [tx]);
  await assert.rejects(p.request({ method: "eth_sendTransaction", params: [tx] }));
  await assert.rejects(p.send("eth_sendTransaction", [{ ...tx, gas: "0x65" }]));
  await assert.rejects(p.send("eth_sendTransaction", [{ ...tx, gasPrice: "0x6" }]));
  assert.equal(sent.length, 1);
});

test("public receipt allowlist excludes arbitrary result fields", async t => {
  const h = "0x" + "1".repeat(64);
  const hre = { deployments: { deploy: async () => ({ receipt: { transactionHash: h, status: 1, secret: "NEVER" } }),
    execute: async () => ({ transactionHash: h, status: 1, rpc: "NEVER" }) } };
  const output = temporary(t);
  runner.retainReceipts(hre, output, "sepolia");
  await hre.deployments.deploy(); await hre.deployments.execute();
  const raw = fs.readFileSync(path.join(output, "receipts/sepolia", h + ".json"), "utf8");
  assert.equal(raw.includes("NEVER"), false);
});

const contractsDir = process.env.L1_TEST_CONTRACTS;
test("real ethers decrypts Psy-format JSON without address", { skip: !contractsDir }, async () => {
  const ethers = createRequire(path.join(contractsDir, "package.json"))("ethers");
  const wallet = ethers.Wallet.createRandom();
  const encrypted = JSON.parse(await wallet.encrypt("synthetic-test-only", { scrypt: { N: 1024 } }));
  delete encrypted.address;
  const loaded = await runner.unlock(ethers, JSON.stringify(encrypted), "synthetic-test-only", wallet.address);
  assert.equal(loaded.address, wallet.address);
  await assert.rejects(runner.unlock(ethers, JSON.stringify(encrypted), "wrong", wallet.address));
});

test("real in-process Hardhat full fresh DAG, fixture account only", { skip: !contractsDir, timeout: 180000 }, async t => {
  const output = temporary(t);
  const cwd = process.cwd();
  const saved = { ...process.env };
  t.after(() => { process.chdir(cwd); process.env = saved; });
  for (const key of ["PRIVATE_KEY", "PSY_RELAYER_PRIVKEY", "PSY_INTERNAL_DEPLOY_PRIVATE_KEY", "PSY_INTERNAL_DEPLOY_FROM_KEYSTORE",
    "WALLET_PASSWORD", "KEYSTORE_PATH", "VITE_FORK", "GRANT_TIMELOCK_ROLES", "REVOKE_REPLACED_ADMIN_ROLES", "TRANSFER_PROTOCOL_OWNERSHIP_TO_TIMELOCK"]) delete process.env[key];
  process.env.HOME = output;
  process.env.TS_NODE_PROJECT = path.join(contractsDir, "tsconfig.json");
  process.env.HARDHAT_NETWORK = "hardhat";
  process.env.TRANSFER_PROXY_ADMIN_TO_TIMELOCK = "1";
  delete process.env.TIMELOCK_ADMIN;
  const config = path.join(output, "hardhat.config.cjs");
  fs.writeFileSync(config, runner.configuration(contractsDir, output));
  process.env.HARDHAT_CONFIG = config;
  process.chdir(output);
  const r = createRequire(path.join(contractsDir, "package.json"));
  r("ts-node/register/transpile-only");
  const hre = r("hardhat");
  assert.equal(hre.network.name, "hardhat");
  const fixtureSigner = await (await hre.ethers.getSigners())[0].getAddress();
  assert.notEqual(fixtureSigner.toLowerCase(), SIGNER.toLowerCase());
  runner.retainReceipts(hre, output, "hardhat");
  await runner.deployPhases(hre, { pause_deposits: true, policy: approved.networks.sepolia }, output, "hardhat", fixtureSigner);
  const exported = JSON.parse(fs.readFileSync(path.join(output, "deployments/hardhat/deployed-contracts.json")));
  assert.equal(exported.protocol.chain.l1ChainIndex, 0);
  assert.equal(Number(exported.chainId), 31337);
  for (const name of ["Bridge", "StateManager", "PsyToken", "USDTToken", "DefaultProxyAdmin", "ExecutorWithTimelock"]) assert.ok(exported.core[name]);
  assert.ok(exported.deploymentBlock > 0);
  const readback = JSON.parse(fs.readFileSync(path.join(output, "readback-hardhat.json")));
  assert.equal(readback.bridge_admin, true);
  assert.equal(readback.deposits_paused, true);
  assert.equal(readback.tokens.native.address, ZERO);
  assert.equal(readback.tokens.PSY.address, exported.core.PsyToken);
  assert.equal(readback.tokens.pUSDT.address, exported.core.USDTToken);
  assert.equal(readback.withdrawal_registration_paused, false);
  assert.equal(readback.pending_claims_paused, false);
  assert.ok(fs.readdirSync(path.join(output, "receipts/hardhat")).length > 10);
});
