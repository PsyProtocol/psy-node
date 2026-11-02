// Runs the real handlers.ts with only Envio's registration and storage
// replaced. Poseidon hashing stays real, so tree nodes and roots are the ones
// Envio would write.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

const HANDLERS_PATH = path.join(__dirname, '../../handlers.ts');

function loadHandlers(source = readFileSync(HANDLERS_PATH, 'utf8')) {
  const registered = {};
  const register = (name) => ({ handler(fn) { registered[name] = fn; } });
  const generated = {
    Bridge: {
      DepositRecorded: register('DepositRecorded'),
      WithdrawalClaimed: register('WithdrawalClaimed'),
    },
    StateManager: { Finalized: register('Finalized') },
  };
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
  });
  const moduleExports = {};
  vm.runInNewContext(outputText, {
    exports: moduleExports,
    require(name) {
      return name === './generated/index.js' ? generated : require(name);
    },
  });
  for (const name of ['DepositRecorded', 'WithdrawalClaimed', 'Finalized']) {
    assert.equal(typeof registered[name], 'function', `${name} handler not registered`);
  }
  return { handlers: registered, exports: moduleExports };
}

const ENTITIES = [
  'Deposit',
  'DepositLeaf',
  'AccountDepositStats',
  'DepositTreeMeta',
  'DepositTreeNode',
  'WithdrawalClaim',
  'FinalizedBatch',
];

// In-memory stand-in for Envio's handler context. Rows are frozen like
// Envio's, so a handler that mutates a loaded entity fails here too.
function makeContext() {
  const context = {};
  for (const name of ENTITIES) {
    const rows = new Map();
    context[name] = {
      rows,
      async get(id) { return rows.get(id); },
      set(row) { rows.set(row.id, Object.freeze({ ...row })); },
    };
  }
  return context;
}

function snapshot(context) {
  const out = {};
  for (const name of ENTITIES) {
    out[name] = new Map(context[name].rows);
  }
  return out;
}

function depositEvent({
  chainId = 11155111,
  chainIndex = 0,
  index,
  blockNumber = 100,
  blockTimestamp = 1716601728,
  txHash = '0x' + 'ab'.repeat(32),
  shieldAddress = '0x' + '11'.repeat(32),
  token = '0x' + '22'.repeat(20),
  l2TokenContractId = '0x' + '04'.padStart(64, '0'),
  amount = 1000n,
  noteCommitment,
  leafHash = '0x' + '44'.repeat(32),
}) {
  return {
    chainId,
    block: { number: blockNumber, timestamp: blockTimestamp },
    transaction: { hash: txHash },
    params: {
      index,
      chainIndex,
      leafHash,
      shieldAddress,
      token,
      l2TokenContractId,
      amount,
      noteCommitment: noteCommitment ?? '0x' + (index + 1).toString(16).padStart(64, '0'),
    },
  };
}

function claimEvent({
  chainId = 11155111,
  nullifier,
  blockNumber = 200,
  txHash = '0x' + 'cd'.repeat(32),
  recipient = '0x' + '55'.repeat(20),
  token = '0x' + '22'.repeat(20),
  amount = 7n,
}) {
  return {
    chainId,
    block: { number: blockNumber, timestamp: 1716601728 },
    transaction: { hash: txHash },
    params: { nullifier, recipient, token, amount },
  };
}

module.exports = { loadHandlers, makeContext, snapshot, depositEvent, claimEvent, ENTITIES };
