const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const ts = require('typescript');

// Execute the real handlers with only Envio's registration/storage replaced.
// Hashing stays real, so this also exercises the existing deposit-tree update.
function loadHandler() {
  let handler;
  const ignored = { handler() {} };
  const generated = {
    Bridge: { DepositRecorded: { handler(fn) { handler = fn; } }, WithdrawalClaimed: ignored },
    StateManager: { Finalized: ignored },
  };
  const source = readFileSync(path.join(__dirname, '../handlers.ts'), 'utf8');
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  });
  vm.runInNewContext(outputText, {
    exports: {},
    require(name) {
      return name === './generated/index.js' ? generated : require(name);
    },
  });
  assert.equal(typeof handler, 'function');
  return handler;
}

function store() {
  const rows = new Map();
  return { rows, async get(id) { return rows.get(id); }, set(row) { rows.set(row.id, row); } };
}

test('Deposit schema adds a nullable Unix timestamp for existing rows', () => {
  const schema = readFileSync(path.join(__dirname, '../schema.graphql'), 'utf8');
  const deposit = schema.match(/type Deposit @entity \{([^}]+)\}/)[1];
  assert.match(deposit, /block_timestamp: BigInt\s/);
  assert.doesNotMatch(deposit, /block_timestamp: BigInt!/);
});

test('all three chains persist the supplied timestamp without fetching it', async () => {
  const handler = loadHandler();
  const context = { Deposit: store(), DepositTreeMeta: store(), DepositTreeNode: store() };
  const chains = [11155111, 97, 84532];
  for (const [chainIndex, chainId] of chains.entries()) {
    const event = {
      chainId,
      block: { number: 42, timestamp: 1716601728 + chainIndex },
      transaction: { hash: '0xabc' },
      params: {
        index: 7, chainIndex, leafHash: '0x44', shieldAddress: '0x11', token: '0x22',
        l2TokenContractId: '0x04', amount: 1n, noteCommitment: '0x33',
      },
    };
    await handler({ event, context });
    const row = context.Deposit.rows.get(`${chainId}-7`);
    assert.equal(row.block_timestamp, BigInt(event.block.timestamp));
    assert.equal(row.block_number, 42);
    assert.equal(row.chain_local_deposit_index, 0);
    assert.equal(context.DepositTreeMeta.rows.get(`${chainIndex}`).last_count, 1);
    assert.equal(context.DepositTreeNode.rows.has(`${chainIndex}:32:0`), true);
    // Replay against fresh pre-event storage: the replacement block's time wins.
    const replay = { Deposit: store(), DepositTreeMeta: store(), DepositTreeNode: store() };
    event.block.timestamp += 12;
    await handler({ event, context: replay });
    assert.equal(replay.Deposit.rows.get(`${chainId}-7`).block_timestamp, BigInt(event.block.timestamp));
  }
  assert.equal(context.Deposit.rows.size, 3);
});
