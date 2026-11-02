const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadHandlers, makeContext, snapshot, depositEvent, claimEvent } = require('./lib/handler-harness.cjs');

const { handlers, exports: lib } = loadHandlers();
const deposit = (context, fields) => handlers.DepositRecorded({ event: depositEvent(fields), context });
const claim = (context, fields) => handlers.WithdrawalClaimed({ event: claimEvent(fields), context });

const SEPOLIA = { chainId: 11155111, chainIndex: 0 };
const BSC = { chainId: 97, chainIndex: 1 };
const BASE = { chainId: 84532, chainIndex: 2 };
const shield = (n) => '0x' + n.toString(16).padStart(64, '0');

async function assertRejectedWithoutWrites(context, run, pattern) {
  const before = snapshot(context);
  await assert.rejects(run, pattern);
  assert.deepEqual(snapshot(context), before, 'a rejected event must not write any entity');
}

test('a deposit writes its leaf and account stats next to Deposit and the tree', async () => {
  const context = makeContext();
  await deposit(context, { ...SEPOLIA, index: 0, blockNumber: 42, blockTimestamp: 1716601728, shieldAddress: shield(1) });

  assert.deepEqual(context.DepositLeaf.rows.get('0-0'), {
    id: '0-0',
    chain_index: 0,
    chain_local_deposit_index: 0,
    deposit_index: 0,
    chain_id: 11155111,
    poseidon_leaf_hash: context.DepositTreeNode.rows.get('0:0:0').hash,
    block_number: 42,
  });
  assert.deepEqual(context.AccountDepositStats.rows.get(`0-${shield(1)}`), {
    id: `0-${shield(1)}`,
    shield_address: shield(1),
    chain_index: 0,
    chain_id: 11155111,
    deposit_count: 1,
    last_chain_local_deposit_index: 0,
    last_block_number: 42,
  });
  const row = context.Deposit.rows.get('11155111-0');
  assert.equal(row.chain_local_deposit_index, 0);
  assert.equal(row.block_timestamp, 1716601728n);
  assert.equal(context.DepositTreeMeta.rows.get('0').last_count, 1);
});

test('the tree, its root and Deposit rows are unchanged by the read model', async () => {
  const context = makeContext();
  for (let index = 0; index < 5; index++) {
    await deposit(context, { ...SEPOLIA, index, blockNumber: 100 + index });
  }
  // Golden values produced by the handler before the read model was added.
  const meta = context.DepositTreeMeta.rows.get('0');
  assert.equal(meta.last_count, 5);
  assert.equal(meta.poseidon_deposit_tree_root, '0x1227beae8ca7cb5e5f1b72673239885cff16a7d0b45d33bb47700082df261019');
  assert.equal(meta.deposit_tree_root, meta.poseidon_deposit_tree_root);
  assert.equal(context.DepositTreeNode.rows.get('0:0:4').hash,
    '0xca9068f9c7b0ed3e1fcc28906a0014e659bfb77625aadff2122103ab02c84d92');
  assert.equal(context.DepositLeaf.rows.get('0-4').poseidon_leaf_hash, context.DepositTreeNode.rows.get('0:0:4').hash);
  assert.equal(context.Deposit.rows.size, 5);
  assert.deepEqual({ ...context.Deposit.rows.get('11155111-4') }, {
    id: '11155111-4',
    chain_id: 11155111,
    deposit_index: 4,
    chain_local_deposit_index: 4,
    shield_address: '0x' + '11'.repeat(32),
    token: '0x' + '22'.repeat(20),
    l2_token_contract_id: '0x' + '4'.padStart(64, '0'),
    amount: 1000n,
    note_commitment: '0x' + '5'.padStart(64, '0'),
    chain_index: 0,
    leaf_hash: '0x' + '44'.repeat(32),
    block_number: 104,
    block_timestamp: 1716601728n,
    tx_hash: '0x' + 'ab'.repeat(32),
  });
});

test('stats count deposits per (chain_index, shield_address) across interleaved chains', async () => {
  const context = makeContext();
  const next = new Map();
  const expected = new Map();
  const plan = [
    [SEPOLIA, 1], [SEPOLIA, 2], [BSC, 1], [SEPOLIA, 1], [BASE, 3],
    [BSC, 1], [SEPOLIA, 1], [BASE, 3], [BASE, 1], [SEPOLIA, 2],
  ];
  for (const [step, [chain, account]] of plan.entries()) {
    const local = next.get(chain.chainIndex) ?? 0;
    next.set(chain.chainIndex, local + 1);
    const blockNumber = 1000 + step;
    await deposit(context, { ...chain, index: local, blockNumber, shieldAddress: shield(account) });
    const key = `${chain.chainIndex}-${shield(account)}`;
    const previous = expected.get(key);
    expected.set(key, {
      deposit_count: (previous?.deposit_count ?? 0) + 1,
      last_chain_local_deposit_index: local,
      last_block_number: blockNumber,
      chain_id: chain.chainId,
    });
  }

  assert.equal(context.AccountDepositStats.rows.size, expected.size);
  for (const [key, want] of expected) {
    const row = context.AccountDepositStats.rows.get(key);
    assert.ok(row, `missing stats ${key}`);
    assert.deepEqual(
      {
        deposit_count: row.deposit_count,
        last_chain_local_deposit_index: row.last_chain_local_deposit_index,
        last_block_number: row.last_block_number,
        chain_id: row.chain_id,
      },
      want,
      key,
    );
  }
  // Leaves are dense from 0 per chain_index and mirror Deposit.
  for (const [chainIndex, count] of next) {
    for (let local = 0; local < count; local++) {
      const leaf = context.DepositLeaf.rows.get(`${chainIndex}-${local}`);
      assert.ok(leaf, `missing leaf ${chainIndex}-${local}`);
      const row = context.Deposit.rows.get(`${leaf.chain_id}-${leaf.deposit_index}`);
      assert.equal(row.chain_local_deposit_index, local);
      assert.equal(row.chain_index, chainIndex);
      assert.equal(context.DepositTreeNode.rows.get(`${chainIndex}:0:${local}`).hash, leaf.poseidon_leaf_hash);
    }
    assert.equal(context.DepositTreeMeta.rows.get(`${chainIndex}`).last_count, count);
  }
});

test('a chain starts at deposit_index 0 and continues without gaps', async () => {
  const context = makeContext();
  await assertRejectedWithoutWrites(context, deposit(context, { ...SEPOLIA, index: 7 }),
    /deposit read model invariant violated: first deposit of chain_index 0 is not deposit_index 0/);
  await deposit(context, { ...SEPOLIA, index: 0 });
  await deposit(context, { ...SEPOLIA, index: 1 });
  assert.equal(context.DepositLeaf.rows.get('0-1').deposit_index, 1);
  await assertRejectedWithoutWrites(context, deposit(context, { ...SEPOLIA, index: 3 }),
    /deposit read model invariant violated: deposit_index does not follow previous deposit_index 1/);
  await assertRejectedWithoutWrites(context, deposit(context, { ...SEPOLIA, index: 1 }),
    /Deposit 11155111-1 already exists/);
});

test('a duplicate Deposit id is rejected instead of desynchronizing Deposit and the tree', async () => {
  const context = makeContext();
  await deposit(context, { ...SEPOLIA, index: 0 });
  // A second chain_index on the same chain_id reuses deposit ids from 0.
  await assertRejectedWithoutWrites(context, deposit(context, { chainId: SEPOLIA.chainId, chainIndex: 5, index: 0 }),
    /Deposit 11155111-0 already exists/);
});

test('leaf density is checked against DepositTreeMeta', async () => {
  const context = makeContext();
  await deposit(context, { ...SEPOLIA, index: 0 });
  await deposit(context, { ...SEPOLIA, index: 1 });

  const ahead = makeContext();
  for (const [name, store] of Object.entries(context)) {
    for (const row of store.rows.values()) ahead[name].set(row);
  }
  ahead.DepositTreeMeta.set({ ...ahead.DepositTreeMeta.rows.get('0'), last_count: 3 });
  await assertRejectedWithoutWrites(ahead, deposit(ahead, { ...SEPOLIA, index: 2 }),
    /DepositLeaf 0-2 is missing/);

  const behind = makeContext();
  for (const [name, store] of Object.entries(context)) {
    for (const row of store.rows.values()) behind[name].set(row);
  }
  behind.DepositTreeMeta.set({ ...behind.DepositTreeMeta.rows.get('0'), last_count: 1 });
  await assertRejectedWithoutWrites(behind, deposit(behind, { ...SEPOLIA, index: 2 }),
    /DepositLeaf 0-1 already exists/);
});

test('a chain_index cannot move to another chain_id', async () => {
  const context = makeContext();
  await deposit(context, { ...SEPOLIA, index: 0 });
  await assertRejectedWithoutWrites(context, deposit(context, { chainId: 1, chainIndex: 0, index: 1 }),
    /chain_index 0 already belongs to chain_id 11155111/);
});

test('stats arithmetic rejects inconsistent existing rows', () => {
  const base = { shieldAddress: shield(1), chainIndex: 0, chainId: 11155111, chainLocalDepositIndex: 10, blockNumber: 50 };
  const row = (fields) => ({
    id: `0-${shield(1)}`,
    shield_address: shield(1),
    chain_index: 0,
    chain_id: 11155111,
    deposit_count: 3,
    last_chain_local_deposit_index: 6,
    last_block_number: 40,
    ...fields,
  });

  // Spread: the handler module runs in its own realm (different Object prototype).
  assert.deepEqual({ ...lib.nextAccountDepositStats(undefined, base) }, {
    id: `0-${shield(1)}`,
    shield_address: shield(1),
    chain_index: 0,
    chain_id: 11155111,
    deposit_count: 1,
    last_chain_local_deposit_index: 10,
    last_block_number: 50,
  });
  const next = lib.nextAccountDepositStats(row({}), base);
  assert.equal(next.deposit_count, 4);
  assert.equal(next.last_chain_local_deposit_index, 10);
  assert.equal(next.last_block_number, 50);
  // Same block as the previous deposit of the account is fine.
  assert.equal(lib.nextAccountDepositStats(row({ last_block_number: 50 }), base).deposit_count, 4);

  assert.throws(() => lib.nextAccountDepositStats(row({ deposit_count: 8 }), base), /count 8 is inconsistent with last index 6/);
  assert.throws(() => lib.nextAccountDepositStats(row({ deposit_count: 0 }), base), /count 0 is inconsistent/);
  assert.throws(() => lib.nextAccountDepositStats(row({ last_chain_local_deposit_index: 10 }), base), /last index 10 is not below 10/);
  assert.throws(() => lib.nextAccountDepositStats(row({ last_block_number: 51 }), base), /last block 51 is after 50/);
  assert.throws(() => lib.nextAccountDepositStats(row({ chain_id: 97 }), base), /belongs to chain_id 97, not 11155111/);
});

test('ids are chain-first and stable', () => {
  assert.equal(lib.depositLeafId(2, 1023), '2-1023');
  assert.equal(lib.accountDepositStatsId(1, shield(9)), `1-${shield(9)}`);
});

test('withdrawal claims are unique per (chain_id, nullifier)', async () => {
  const context = makeContext();
  const nullifier = '0x' + 'aa'.repeat(32);
  await claim(context, { nullifier, blockNumber: 10 });
  await claim(context, { chainId: 97, nullifier, blockNumber: 11 });
  assert.equal(context.WithdrawalClaim.rows.get(`11155111-${nullifier}`).block_number, 10);
  assert.equal(context.WithdrawalClaim.rows.get(`97-${nullifier}`).chain_id, 97);

  await assertRejectedWithoutWrites(context, claim(context, { nullifier, blockNumber: 12, txHash: '0x' + 'ee'.repeat(32) }),
    /withdrawal claim invariant violated: WithdrawalClaim 11155111-0xa+ already exists/);
  assert.equal(context.WithdrawalClaim.rows.get(`11155111-${nullifier}`).block_number, 10);
});
