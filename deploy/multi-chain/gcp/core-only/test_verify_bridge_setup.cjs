"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseProof, assertProofInvalid } = require("./verify_bridge_setup.cjs");
const word = value => value.toString(16).padStart(64, "0");
function fixture() {
  return { pi_a: [word(1), word(2)], pi_b: [[word(3), word(4)], [word(5), word(6)]],
    pi_c: [word(7), word(8)], public_inputs: [word(9), word(10)] };
}
const line = value => "proofString " + JSON.stringify(value);

test("maps gnark Fp2 words to the Relayer EIP-197 encoding", () => {
  const proof = parseProof("diagnostic\n" + line(fixture()) + "\n");
  assert.deepEqual(proof.words.map(BigInt), [1n, 2n, 4n, 3n, 6n, 5n, 7n, 8n]);
  assert.deepEqual(proof.inputs.map(BigInt), [9n, 10n]);
});
test("rejects missing or multiple proof records", () => {
  assert.throws(() => parseProof("no proof"));
  assert.throws(() => parseProof(line(fixture()) + "\n" + line(fixture())));
});
test("rejects missing and oversized scalar arrays", () => {
  const missing = fixture();
  delete missing.pi_c;
  assert.throws(() => parseProof(line(missing)));
  const oversized = fixture();
  oversized.public_inputs.push(word(11));
  assert.throws(() => parseProof(line(oversized)));
});
test("rejects malformed Fp2 coordinates", () => {
  const proof = fixture();
  proof.pi_b[1] = [word(5)];
  assert.throws(() => parseProof(line(proof)));
});
test("rejects nonhex and noncanonical-width words", () => {
  for (const invalid of ["z".repeat(64), "1", "0x" + word(1), 1]) {
    const proof = fixture();
    proof.pi_a[0] = invalid;
    assert.throws(() => parseProof(line(proof)));
  }
});
test("accepts CRLF logs without consuming verification-key records", () => {
  assert.deepEqual(parseProof("vkString {}\r\n" + line(fixture()) + "\r\n"),
    parseProof(line(fixture())));
});

test("negative control requires the decoded ProofInvalid call exception", async () => {
  const error = Object.assign(new Error("reverted"), {
    code: "CALL_EXCEPTION", errorName: "ProofInvalid",
  });
  await assertProofInvalid(Promise.reject(error), "modified proof accepted");
});
test("negative control fails on successful void verification", async () => {
  await assert.rejects(assertProofInvalid(Promise.resolve(), "modified proof accepted"));
});
test("negative control does not accept transport, ABI, or unrelated revert errors", async () => {
  for (const fields of [
    {},
    { code: "NETWORK_ERROR", errorName: "ProofInvalid" },
    { code: "INVALID_ARGUMENT" },
    { code: "CALL_EXCEPTION" },
    { code: "CALL_EXCEPTION", errorName: "PublicInputNotInField" },
  ]) {
    const error = Object.assign(new Error("failure"), fields);
    await assert.rejects(assertProofInvalid(Promise.reject(error), "modified proof accepted"));
  }
});
