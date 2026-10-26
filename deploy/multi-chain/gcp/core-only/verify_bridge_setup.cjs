#!/usr/bin/env node
"use strict";

// Offline EVM acceptance of the real setup fixtures, never a public RPC.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { createRequire } = require("node:module");
const assert = require("node:assert/strict");

const cohorts = {
  bridge_agg: "GnarkGroth16Verifier.sol",
  deposit_append: "DepositBatchVerifier.sol",
  withdrawal_claim: "WithdrawalClaimVerifier.sol",
  reward_claim: "RewardClaimVerifier.sol",
};

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function parseProof(log) {
  const lines = log.split(/\r?\n/).filter(line => line.startsWith("proofString "));
  assert.equal(lines.length, 1, "Expected exactly one generated proof per cohort");
  const proof = JSON.parse(lines[0].slice("proofString ".length));
  for (const [name, length] of [["pi_a", 2], ["pi_b", 2], ["pi_c", 2], ["public_inputs", 2]]) {
    assert.ok(Array.isArray(proof[name]) && proof[name].length === length, `Invalid ${name}`);
  }
  assert.ok(proof.pi_b.every(row => Array.isArray(row) && row.length === 2), "Invalid pi_b");
  function hex(word) {
    assert.match(word, /^[0-9a-fA-F]{64}$/);
    return "0x" + word;
  }
  // Match psy_relayer_cli's EIP-197 conversion, not gnark's JSON Fp2 order.
  return {
    words: [proof.pi_a[0], proof.pi_a[1], proof.pi_b[0][1], proof.pi_b[0][0],
      proof.pi_b[1][1], proof.pi_b[1][0], proof.pi_c[0], proof.pi_c[1]].map(hex),
    inputs: proof.public_inputs.map(hex),
  };
}

async function assertProofInvalid(call, message) {
  await assert.rejects(call, { code: "CALL_EXCEPTION", errorName: "ProofInvalid" }, message);
}

async function main() {
  assert.equal(process.argv.length, 4, "Usage: verify_bridge_setup.cjs CONTRACTS_DIR SETUP_DIR");
  const contracts = fs.realpathSync(process.argv[2]);
  const setup = fs.realpathSync(process.argv[3]);
  const fixtures = Object.entries(cohorts).map(([cohort, file]) => {
    const exported = fs.readFileSync(path.join(setup, file));
    assert.ok(exported.equals(fs.readFileSync(path.join(contracts, "src", file))),
      `${cohort}: exported verifier differs from contract source`);
    const log = fs.readFileSync(path.join(setup, `${cohort}.log`), "utf8");
    assert.ok(log.includes("[prove] groth16.Verify took "), `${cohort}: native verification missing`);
    return { cohort, file, sha256: sha256(exported), proof: parseProof(log) };
  });
  process.chdir(contracts);
  process.env.HARDHAT_NETWORK = "hardhat";
  process.env.HARDHAT_CONFIG = path.join(contracts, "hardhat.config.ts");
  const localRequire = createRequire(path.join(contracts, "package.json"));
  localRequire("ts-node/register/transpile-only");
  const hre = localRequire("hardhat");
  assert.equal(hre.network.name, "hardhat");
  assert.equal(Number((await hre.ethers.provider.getNetwork()).chainId), 31337);
  await hre.run("compile");
  const results = [];
  for (const item of fixtures) {
    const factory = await hre.ethers.getContractFactory(`src/${item.file}:Verifier`);
    const verifier = await factory.deploy();
    await verifier.deployed();
    await verifier.callStatic.verifyProof(item.proof.words, item.proof.inputs);
    const changed = [...item.proof.inputs];
    changed[0] = "0x" + (BigInt(changed[0]) ^ 1n).toString(16);
    await assertProofInvalid(verifier.callStatic.verifyProof(item.proof.words, changed),
      `${item.cohort}: modified public input accepted`);
    const badProof = [...item.proof.words];
    badProof[0] = "0x" + (BigInt(badProof[0]) ^ 1n).toString(16);
    await assertProofInvalid(verifier.callStatic.verifyProof(badProof, item.proof.inputs),
      `${item.cohort}: modified proof accepted`);
    results.push({ cohort: item.cohort, solidity_sha256: item.sha256,
      valid_proof: "accepted", changed_input: "rejected", changed_proof: "rejected" });
  }
  console.log(JSON.stringify({ network: "offline-hardhat", results }, null, 2));
}

if (require.main === module) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = { parseProof, assertProofInvalid };
