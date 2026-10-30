#!/usr/bin/env node
"use strict";

// Invoked by fresh_l1.py only. Secrets arrive over stdin, never argv or disk.
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const assert = require("node:assert/strict");
const SIGNER = "0x490f8192725255C2C3dE0CbCE66312335Ca019Ad";
const NETWORKS = { sepolia: [11155111, 0, "SEPOLIA_RPC_URL"],
  bscTestnet: [97, 1, "BSC_TESTNET_RPC_URL"], baseSepolia: [84532, 2, "BASE_SEPOLIA_RPC_URL"] };
let currentStage = "input";
let stageJournal;

function stage(name, status = "entered") {
  currentStage = name;
  if (stageJournal) fs.appendFileSync(stageJournal,
    JSON.stringify({ stage: name, status, time: new Date().toISOString() }) + "\n", { mode: 0o600 });
}

function budgetGuard(provider, ethers, budget) {
  const request = provider.request.bind(provider);
  let reservedGas = 0n;
  let reservedWei = 0n;
  provider.request = async function (payload) {
    if (!["eth_sendTransaction", "eth_sendRawTransaction"].includes(payload.method)) return request(payload);
    let gas, fee;
    if (payload.method === "eth_sendRawTransaction") {
      const tx = ethers.utils.parseTransaction(payload.params[0]);
      assert.equal(tx.from.toLowerCase(), SIGNER.toLowerCase());
      gas = BigInt(tx.gasLimit.toString());
      fee = BigInt((tx.maxFeePerGas || tx.gasPrice).toString());
    } else {
      const tx = { ...payload.params[0] };
      assert.equal(tx.from.toLowerCase(), SIGNER.toLowerCase());
      if (!tx.gas) {
        const estimate = BigInt(await request({ method: "eth_estimateGas", params: [tx] }));
        tx.gas = "0x" + ((estimate * 120n + 99n) / 100n).toString(16);
      }
      if (!tx.maxFeePerGas && !tx.gasPrice) tx.gasPrice = await request({ method: "eth_gasPrice", params: [] });
      gas = BigInt(tx.gas);
      fee = BigInt(tx.maxFeePerGas || tx.gasPrice);
      payload = { ...payload, params: [tx] };
    }
    assert.ok(gas > 0n && gas <= BigInt(budget.maxGasPerTransaction));
    assert.ok(fee <= BigInt(budget.maxGasPriceWei));
    const cost = gas * fee + BigInt(budget.l1FeeReserveWeiPerTransaction);
    assert.ok(reservedGas + gas <= BigInt(budget.maxTotalGas));
    assert.ok(reservedWei + cost <= BigInt(budget.maxNativeSpendWei));
    // Reserve before send: an unknown submission outcome never restores budget.
    reservedGas += gas;
    reservedWei += cost;
    return request(payload);
  };
  // ethers' Hardhat adapter uses send(), which otherwise bypasses request().
  provider.send = (method, params) => provider.request({ method, params });
  provider.sendAsync = (payload, callback) => provider.request(payload).then(
    result => callback(null, { jsonrpc: "2.0", id: payload.id, result }), error => callback(error));
}

function retainReceipts(hre, output, network) {
  const directory = path.join(output, "receipts", network);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  for (const method of ["deploy", "execute"]) {
    const original = hre.deployments[method].bind(hre.deployments);
    hre.deployments[method] = async (...args) => {
      const result = await original(...args);
      const receipt = result.receipt || result;
      if (/^0x[0-9a-fA-F]{64}$/.test(receipt.transactionHash || "")) {
        const safe = {};
        for (const key of ["transactionHash", "blockHash", "blockNumber", "status", "from", "to",
          "contractAddress", "gasUsed", "cumulativeGasUsed", "effectiveGasPrice", "logs"]) {
          if (receipt[key] !== undefined) safe[key] = receipt[key];
        }
        const file = path.join(directory, receipt.transactionHash + ".json");
        if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(safe, null, 2) + "\n", { flag: "wx", mode: 0o600 });
      }
      return result;
    };
  }
}

async function unlock(ethers, encrypted, password, expected = SIGNER) {
  // Psy's eth-keystore JSON can omit address; ethers derives it after MAC validation.
  const wallet = await ethers.Wallet.fromEncryptedJson(encrypted, password);
  assert.equal(wallet.address.toLowerCase(), expected.toLowerCase());
  return wallet;
}

function flowManifest(policy, tokens) {
  const names = ["native", "PSY", "pUSDT"];
  return { tokens: names.map(n => tokens[n]), configs: names.map(n => policy[n]),
    historicalWithdrawalTotals: names.map(() => "0") };
}

function configuration(contracts, output) {
  return `const base = require(${JSON.stringify(path.join(contracts, "hardhat.config.ts"))}).default;\n` +
    `module.exports = {...base, paths: {...base.paths, root: ${JSON.stringify(contracts)}, ` +
    `deployments: ${JSON.stringify(path.join(output, "deployments"))}, ` +
    `cache: ${JSON.stringify(path.join(output, "cache"))}}};\n`;
}

async function pauseBridge(hre, signer = SIGNER) {
  const aclAddress = (await hre.deployments.get("PsyACLManager")).address;
  const acl = await hre.ethers.getContractAt("PsyACLManager", aclAddress);
  assert.equal(await acl.isBridgeAdmin(signer), true);
  const id = await hre.deployments.read("PsyAddressesProvider", "ACL_MANAGER_ID");
  await hre.deployments.execute("PsyAddressesProvider", { from: signer, log: false }, "setAddress", id, aclAddress);
  await hre.deployments.execute("Bridge", { from: signer, log: false }, "setGlobalPauseFlags", 1);
  const flags = await hre.deployments.read("Bridge", "getPauseFlags", hre.ethers.constants.AddressZero);
  assert.deepEqual(Array.from(flags).map(v => v.toString()), ["1", "0", "1"]);
}

async function verifyReadback(hre, policy, tokens, signer = SIGNER) {
  assert.equal(tokens.native, hre.ethers.constants.AddressZero);
  assert.equal(new Set(Object.values(tokens).map(a => a.toLowerCase())).size, 3);
  const contract = async name => hre.ethers.getContractAt(name, (await hre.deployments.get(name)).address);
  const acl = await contract("PsyACLManager");
  assert.equal(await acl.isProposer(signer), true);
  assert.equal(await acl.isBridgeAdmin(signer), true);
  // L1 ACL Guardian is distinct from the retained L2 multisig Guardians.
  // Record its actual status; this runner does not grant an unrequested new role.
  const guardian = await acl.isGuardian(signer);
  const bridge = await contract("Bridge");
  assert.equal((await bridge.owner()).toLowerCase(), signer.toLowerCase());
  const router = await contract("Router");
  const block = { blockTag: await hre.ethers.provider.getBlockNumber() };
  const depositMapping = { block_number: block.blockTag, native_allowed: false, tokens: {} };
  assert.equal(await router.isTokenMapped(tokens.native, block), false, "native deposits must remain unmapped");
  assert.equal(await router.l1ToL2Token(tokens.native, block), hre.ethers.constants.HashZero,
    "native token has an unexpected L2 mapping");
  for (const [name, id] of [["PSY", hre.ethers.constants.HashZero], ["pUSDT", "0x" + "0".repeat(63) + "4"]]) {
    assert.equal(await router.isTokenMapped(tokens[name], block), true, `${name} deposits are not mapped`);
    assert.equal((await router.l1ToL2Token(tokens[name], block)).toLowerCase(), id,
      `${name} forward mapping does not match its L2 contract`);
    assert.equal((await router.l2ToL1Token(id, block)).toLowerCase(), tokens[name].toLowerCase(),
      `${name} reverse mapping does not match its L1 token`);
    depositMapping.tokens[name] = { l1_address: tokens[name], l2_contract_id: id };
  }
  const checked = {};
  for (const name of ["native", "PSY", "pUSDT"]) {
    const actual = await bridge.getTokenFlowConfig(tokens[name]);
    for (const [field, value] of Object.entries(policy[name])) {
      assert.equal(field === "configured" ? actual[field] : actual[field].toString(), value);
    }
    const flags = Array.from(await bridge.getPauseFlags(tokens[name])).map(v => v.toString());
    assert.deepEqual(flags, ["1", "0", "1"]);
    assert.equal((await bridge.totalWithdrawalAmount(tokens[name])).toString(), "0");
    checked[name] = { address: tokens[name], config: policy[name], global_flags: 1, token_flags: 0, effective_flags: 1 };
  }
  const sm = await contract("StateManager");
  assert.equal((await sm.lastFinalizedCheckpointId()).toString(), "0");
  for (const method of ["lastVerifiedCheckpointRoot", "lastVerifiedDepositTreeRoot", "lastVerifiedWithdrawalTreeRoot", "withdrawalSubtreeRoot"]) {
    assert.equal(await sm[method](), hre.ethers.constants.HashZero);
  }
  assert.equal(await sm.checkpointTreeRootsClean(), true);
  assert.equal((await bridge.provedDepositCount()).toString(), "0");
  assert.equal((await bridge.pendingDepositCount()).toString(), "0");
  assert.equal(await bridge.depositRoot(), "0xd65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43");
  // DefaultProxyAdmin is a hardhat-deploy builtin, not a compiled source artifact.
  assert.equal((await hre.deployments.read("DefaultProxyAdmin", "owner")).toLowerCase(),
    (await hre.deployments.get("ExecutorWithTimelock")).address.toLowerCase());
  return { signer, proposer: true, bridge_admin: true, l1_acl_guardian: guardian,
    deposits_paused: true, withdrawal_registration_paused: false, pending_claims_paused: false,
    deposit_mapping: depositMapping, tokens: checked };
}

async function deployPhases(hre, request, output, network, signer = SIGNER) {
  assert.equal(request.pause_deposits, true);
  stage("runtime");
  const { abi } = await hre.artifacts.readArtifact("Router");
  for (const [name, input, outputType] of [
    ["l1ToL2Token", "address", "bytes32"], ["l2ToL1Token", "bytes32", "address"],
    ["isTokenMapped", "address", "bool"],
  ]) {
    assert.ok(abi.some(item => item.type === "function" && item.name === name && item.stateMutability === "view"
      && item.inputs.length === 1 && item.inputs[0].type === input
      && item.outputs.length === 1 && item.outputs[0].type === outputType), `Router ABI missing ${name}`);
  }
  stage("bridge");
  await hre.run("deploy", { tags: "bridge", noCompile: true, write: true });
  stage("pause");
  await pauseBridge(hre, signer);
  stage("gateways");
  await hre.run("deploy", { tags: "gateways", noCompile: true, write: true });
  const tokens = { native: hre.ethers.constants.AddressZero,
    PSY: (await hre.deployments.get("PsyToken")).address,
    pUSDT: (await hre.deployments.get("USDTToken")).address };
  stage("flow");
  const manifest = path.join(output, `flow-${network}.json`);
  fs.writeFileSync(manifest, JSON.stringify(flowManifest(request.policy, tokens), null, 2) + "\n", { flag: "wx", mode: 0o600 });
  process.env.BRIDGE_FLOW_LIMITS_FILE = manifest;
  stage("complete");
  await hre.run("deploy", { noCompile: true, write: true });
  stage("readback");
  const readback = await verifyReadback(hre, request.policy, tokens, signer);
  fs.writeFileSync(path.join(output, `readback-${network}.json`), JSON.stringify(readback, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  stage("readback", "passed");
}

async function run() {
  const [contracts, output, network] = process.argv.slice(2);
  assert.equal(process.argv.length, 5);
  assert.ok(Object.hasOwn(NETWORKS, network));
  assert.ok(Number(process.versions.node.split(".")[0]) >= 18);
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  assert.equal(typeof request.execute, "boolean");
  if (request.execute) {
    stageJournal = path.join(output, `stages-${network}.jsonl`);
    fs.writeFileSync(stageJournal, "", { flag: "wx", mode: 0o600 });
  }
  stage("wallet");
  const localRequire = createRequire(path.join(contracts, "package.json"));
  const ethers = localRequire("ethers");
  const wallet = await unlock(ethers, fs.readFileSync(request.keystore, "utf8"), request.password);
  if (!request.execute) return;
  stage("runtime");
  // Both the pinned exporter and verification registry write relative to cwd.
  // Keep every generated file in the fresh output, never in the frozen bundle.
  process.chdir(output);
  process.env.TS_NODE_PROJECT = path.join(contracts, "tsconfig.json");
  process.env.HARDHAT_NETWORK = network;
  const configPath = path.join(output, `hardhat-${network}.config.cjs`);
  fs.writeFileSync(configPath, configuration(contracts, output), { flag: "wx", mode: 0o600 });
  process.env.HARDHAT_CONFIG = configPath;
  process.env.PSY_INTERNAL_DEPLOY_PRIVATE_KEY = wallet.privateKey;
  process.env.PSY_INTERNAL_DEPLOY_FROM_KEYSTORE = "1";
  process.env[NETWORKS[network][2]] = request.rpc;
  process.env.TRANSFER_PROXY_ADMIN_TO_TIMELOCK = "1";
  process.env.TIMELOCK_ADMIN = SIGNER;
  // Explicit bootstrap ownership: no unreviewed governance cutover or revocations.
  for (const name of ["GRANT_TIMELOCK_ROLES", "TRANSFER_PROTOCOL_OWNERSHIP_TO_TIMELOCK",
    "REVOKE_REPLACED_ADMIN_ROLES", "PRIVATE_KEY", "PSY_RELAYER_PRIVKEY", "VITE_FORK"]) delete process.env[name];
  localRequire("ts-node/register/transpile-only");
  const hre = localRequire("hardhat");
  budgetGuard(hre.network.provider, ethers, request.budget);
  retainReceipts(hre, output, network);
  assert.equal(Number(await hre.getChainId()), NETWORKS[network][0]);
  // The exporter must never save an authenticated backup RPC URL into public metadata.
  const protocol = localRequire("./protocol-config").protocolConfig;
  protocol.chains[network].defaultRpcUrl = request.public_rpc;
  assert.equal(protocol.chains[network].l1ChainIndex, NETWORKS[network][1]);
  await deployPhases(hre, request, output, network);
  delete process.env.PSY_INTERNAL_DEPLOY_PRIVATE_KEY;
}

if (require.main === module) {
  const emit = process.stdout.write.bind(process.stdout);
  process.stdout.write = () => true;
  process.stderr.write = () => true;
  run().then(() => {
    emit(JSON.stringify({ ok: true, address: SIGNER, network: process.argv[4] }) + "\n");
    process.exit(0);
  }).catch(() => {
    try { stage(currentStage, "failed"); } catch (_) { /* Keep the original safe stage. */ }
    emit(JSON.stringify({ ok: false, stage: currentStage }) + "\n");
    process.exit(1);
  });
}
module.exports = { unlock, flowManifest, configuration, pauseBridge, verifyReadback, deployPhases, budgetGuard, retainReceipts };
