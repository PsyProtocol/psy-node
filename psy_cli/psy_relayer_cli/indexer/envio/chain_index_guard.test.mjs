import assert from "node:assert/strict";
import test from "node:test";
import { assertChainIndexOwner } from "./chain_index_guard.mjs";

test("first write is allowed", () => {
  assert.doesNotThrow(() => assertChainIndexOwner(null, 0, 11155111));
});

test("legacy meta without chain_id is claimed by the next event", () => {
  assert.doesNotThrow(() =>
    assertChainIndexOwner({ last_count: 3 }, 0, 11155111),
  );
});

test("same EVM owner may keep appending", () => {
  assert.doesNotThrow(() =>
    assertChainIndexOwner({ chain_id: 11155111, last_count: 3 }, 0, 11155111),
  );
});

test("a second EVM network reusing chain_index is rejected", () => {
  assert.throws(
    () => assertChainIndexOwner({ chain_id: 11155111, last_count: 3 }, 0, 97),
    /owned by EVM chain_id=11155111.*chain_id=97/,
  );
});
