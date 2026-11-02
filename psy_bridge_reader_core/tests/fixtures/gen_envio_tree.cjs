// Generates envio_tree_2100.json from the real Envio DepositRecorded handler.
//
// Run from the psy-node root after `pnpm install` in
// psy_cli/psy_relayer_cli/indexer/envio:
//   node psy_bridge_reader_core/tests/fixtures/gen_envio_tree.cjs
//
// The output holds the Poseidon leaf hash of every deposit by index and the
// deposit tree root Envio stored after each deposit. 2100 deposits cross the
// 1024 and 2048 leaf boundaries and end inside a partial third block.
const assert = require('node:assert/strict');
const { writeFileSync } = require('node:fs');
const path = require('node:path');
const { loadHandlers, makeContext, depositEvent } = require(
  '../../../psy_cli/psy_relayer_cli/indexer/envio/tests/lib/handler-harness.cjs',
);

const OUTPUT_PATH = path.join(__dirname, 'envio_tree_2100.json');
const DEPOSIT_COUNT = 2100;
const SEPOLIA = { chainId: 11155111, chainIndex: 0 };
const GOLDEN_ROOT = '0x1227beae8ca7cb5e5f1b72673239885cff16a7d0b45d33bb47700082df261019';
const SHIELD_ADDRESS_COUNT = 7;

const { handlers } = loadHandlers();
const deposit = (context, fields) => handlers.DepositRecorded({ event: depositEvent(fields), context });
const shieldAddress = (n) => '0x' + n.toString(16).padStart(64, '0');

async function assertGoldenRoot() {
  // Same events as the golden case in tests/deposit-read-model.test.cjs.
  const context = makeContext();
  for (let index = 0; index < 5; index++) {
    await deposit(context, { ...SEPOLIA, index, blockNumber: 100 + index });
  }
  const meta = context.DepositTreeMeta.rows.get('0');
  assert.equal(meta.last_count, 5);
  assert.equal(meta.poseidon_deposit_tree_root, GOLDEN_ROOT);
}

async function main() {
  await assertGoldenRoot();

  const context = makeContext();
  const leaves = [];
  const rootsAfter = [];
  for (let index = 0; index < DEPOSIT_COUNT; index++) {
    await deposit(context, {
      ...SEPOLIA,
      index,
      blockNumber: 100 + index,
      shieldAddress: shieldAddress((index % SHIELD_ADDRESS_COUNT) + 1),
      amount: 1000n + BigInt(index),
    });
    const meta = context.DepositTreeMeta.rows.get('0');
    assert.equal(meta.last_count, index + 1);
    rootsAfter.push(meta.poseidon_deposit_tree_root);
  }
  for (let index = 0; index < DEPOSIT_COUNT; index++) {
    leaves.push(context.DepositLeaf.rows.get(`0-${index}`).poseidon_leaf_hash);
  }
  assert.equal(new Set(leaves).size, DEPOSIT_COUNT, 'every leaf hash must be distinct');
  assert.equal(new Set(rootsAfter).size, DEPOSIT_COUNT, 'every root must be distinct');

  writeFileSync(OUTPUT_PATH, JSON.stringify({ leaves, roots_after: rootsAfter }, null, 2) + '\n');
  console.log(`golden root ok; wrote ${leaves.length} leaves and ${rootsAfter.length} roots to ${OUTPUT_PATH}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
