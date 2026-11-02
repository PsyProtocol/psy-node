#!/usr/bin/env node
// Reorg rollback test for the deposit read model, against real Envio 2.32.10.
//
// It starts a private Anvil chain whose Bridge address carries a tiny log
// emitter, runs `envio start` with config.reorg-test.yaml (rollback_on_reorg at
// its default, true) on a throwaway database, emits deposits and claims, and
// replaces the last blocks with a different fork (evm_snapshot / evm_revert).
//
// Scenario 1 (gate): Envio is stopped across the reorg and restarted, detects
// it from its stored checkpoint hashes and rolls back. Every entity table must
// then equal a replay of the canonical chain through the same handlers.ts
// (tests/lib/handler-harness.cjs); stale DepositLeaf or AccountDepositStats
// rows would also make the handler's invariants stop Envio.
// Scenario 2: the reorg happens while Envio runs, and the discarded deposit is
// re-included in a later block. Upstream Envio 2.32.10's RPC source answers its
// parent-hash check from a block cache keyed by number, so it misses this
// reorg: the handler invariant must stop Envio instead of appending the deposit
// twice, and a restart must roll the fork back. With the fresh-reorg-parent
// patch enabled (patches/fresh-reorg-parent.py, PSY_ENVIO_FRESH_REORG_PARENT=1)
// Envio must roll back live, without a restart.
// Scenario 3 uses confirmed_block_threshold 8, the live release's value. It is
// a reorg window, not a confirmation delay: a reorg is rolled back live while
// the parent block is within 8 blocks of the head (3a) and missed for good,
// even after a restart, once the head is further away (3c). The confirmation
// delay is ENVIO_INDEXING_BLOCK_LAG: blocks within it never reach the handlers,
// so a reorg within it needs no rollback (3b).
//
// Requirements: anvil and cast (Foundry), psql, a PostgreSQL server reachable
// through ENVIO_PG_HOST / ENVIO_PG_PORT / ENVIO_PG_USER / ENVIO_PG_PASSWORD
// (never point it at a shared server: the test creates and drops its own
// database), and `pnpm install` done in this directory (it applies the patch):
//
//   ENVIO_PG_HOST=127.0.0.1 ENVIO_PG_PORT=5544 ENVIO_PG_USER=postgres \
//     ENVIO_PG_PASSWORD=... node tests/reorg/run-reorg-test.cjs
//
// Envio bakes the RPC URL and the threshold into generated/ at codegen time, so
// the test runs codegen for config.reorg-test.yaml once per threshold. Run
// `pnpm codegen` again before using the regular config. Envio 2.32.10 runs on
// Node <= 22 (on Node >= 23 its yargs dependency fails to load);
// REORG_TEST_NODE_BIN_DIR, when set, is put first on PATH for the Envio
// process only.
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { loadHandlers, makeContext, ENTITIES } = require('../lib/handler-harness.cjs');
const readerCheck = require('./reader-check.cjs');

// Opt-in: --with-reader <path-to-psy-bridge-reader> also runs the Reader on the
// test database and checks its roots and reads (see
// psy_bridge_reader_core/tests/e2e/README.md). Checked before anything starts.
const readerFlag = process.argv.indexOf('--with-reader');
const readerBin = readerFlag === -1 ? undefined : process.argv[readerFlag + 1];
if (readerFlag !== -1) {
  try {
    if (!readerBin || readerBin.startsWith('--')) throw new Error('reader binary not found: --with-reader needs a path');
    readerCheck.assertReaderBinary(readerBin);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

// Opt-in: --hold-reader <dir> pauses before each reorg and before a Reader is
// stopped, so an external load generator can attach to the running Reader.
const holdFlag = process.argv.indexOf('--hold-reader');
const holdDir = holdFlag === -1 ? undefined : process.argv[holdFlag + 1];
if (holdFlag !== -1 && (!readerBin || !holdDir || !fs.existsSync(holdDir) || !fs.statSync(holdDir).isDirectory())) {
  console.error('--hold-reader needs --with-reader and an existing directory');
  process.exit(1);
}
const staleHolds = holdDir ? fs.readdirSync(holdDir).filter((name) => /^\d+-.*\.(json|json\.tmp|go)$/.test(name)) : [];
if (staleHolds.length > 0) {
  console.error(`--hold-reader directory ${holdDir} has leftover hold files: ${staleHolds.join(', ')}`);
  process.exit(1);
}

const ENVIO_DIR = path.join(__dirname, '../..');
const CHAIN_ID = 31337;
const BRIDGE = '0x00000000000000000000000000000000000b1d9e';
const SENDER = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266'; // Anvil default account 0
const TIMEOUT_MS = Number(process.env.REORG_TEST_TIMEOUT_MS || 120000);

// Runtime code: calldata = [topicCount][t0][t1][t2][t3][data...]; emits LOG3
// when topicCount == 3, otherwise LOG4, with `data` as the log data.
const EMITTER_RUNTIME = '0x'
  + '60a03603' + '60a0' + '6000' + '37'       // CALLDATACOPY(0, 160, size - 160)
  + '600035' + '600314' + '6026' + '57'        // if calldata[0] == 3 goto LOG3
  + '608035' + '606035' + '604035' + '602035' // t3 t2 t1 t0
  + '60a03603' + '6000' + 'a4' + '00'         // LOG4(0, size - 160, ...) STOP
  + '5b'                                       // LOG3:
  + '606035' + '604035' + '602035'
  + '60a03603' + '6000' + 'a3' + '00';

const env = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const PG = {
  host: env('ENVIO_PG_HOST'),
  port: env('ENVIO_PG_PORT'),
  user: env('ENVIO_PG_USER'),
  password: env('ENVIO_PG_PASSWORD'),
};
const FRESH_PARENT_ENV = 'PSY_ENVIO_FRESH_REORG_PARENT';
const DEFAULT_REORG_DEPTH = 200; // Envio's confirmed_block_threshold default
const LIVE_RELEASE_REORG_DEPTH = 8;
const INDEXING_BLOCK_LAG = 4;
const createdDatabases = [];
let database;
let reorgDepth;
let reader;
let readerDir;
const orphanedHashes = new Set();
const orphanedNullifiers = new Set();

const word = (value) => BigInt(value).toString(16).padStart(64, '0');
const hex32 = (value) => '0x' + word(value);
const keccak = (text) => execFileSync('cast', ['keccak', text], { encoding: 'utf8' }).trim();
const DEPOSIT_TOPIC = keccak('DepositRecorded(uint32,bytes32,address,bytes32,uint256,uint8,bytes32,bytes32)');
const CLAIM_TOPIC = keccak('WithdrawalClaimed(bytes32,address,address,uint256)');
// Digit-only addresses: Envio's checksum formatting leaves them unchanged.
const TOKEN = '0x2222222222222222222222222222222222222222';
const RECIPIENT = '0x5555555555555555555555555555555555555555';
const L2_TOKEN = hex32(4);

function psql(sql, target = database) {
  return execFileSync('psql', ['-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', '-d', target, '-c', sql], {
    encoding: 'utf8',
    env: { ...process.env, PGHOST: PG.host, PGPORT: PG.port, PGUSER: PG.user, PGPASSWORD: PG.password },
  }).trim();
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(label, predicate) {
  const deadline = Date.now() + TIMEOUT_MS;
  let lastError;
  while (Date.now() < deadline) {
    try {
      if (await predicate()) return;
    } catch (error) {
      lastError = error;
    }
    if (envio?.exitCode != null) {
      throw new Error(`Envio exited with code ${envio.exitCode} while waiting for ${label}\n${tail(envioLog)}`);
    }
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${label}${lastError ? `: ${lastError.message}` : ''}\n${tail(envioLog)}`);
}

let rpcUrl;
let rpcId = 0;
async function rpc(method, params = []) {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

// Sends one log-emitting transaction (one block, automine) and returns the
// event as Envio will hand it to the handler.
async function emit(topics, dataWords, params, kind) {
  const padded = [...topics, ...Array(4 - topics.length).fill(0n)];
  const calldata = '0x' + word(topics.length) + padded.map(word).join('') + dataWords.map(word).join('');
  const txHash = await rpc('eth_sendTransaction', [{ from: SENDER, to: BRIDGE, data: calldata, gas: '0x100000' }]);
  let receipt = await rpc('eth_getTransactionReceipt', [txHash]);
  for (let attempt = 0; receipt == null && attempt < 50; attempt++) {
    await sleep(100); // Anvil can answer the send before the automined block is visible
    receipt = await rpc('eth_getTransactionReceipt', [txHash]);
  }
  assert.ok(receipt, `no receipt for ${txHash}`);
  assert.equal(receipt.status, '0x1');
  assert.equal(receipt.logs.length, 1);
  const block = await rpc('eth_getBlockByNumber', [receipt.blockNumber, false]);
  return {
    kind,
    event: {
      chainId: CHAIN_ID,
      block: { number: Number(receipt.blockNumber), timestamp: Number(block.timestamp) },
      transaction: { hash: txHash },
      params,
    },
  };
}

function emitDeposit({ index, shield, amount }) {
  const noteCommitment = hex32(0x1000n + BigInt(index) * 7n + amount);
  const leafHash = hex32(0x2000n + BigInt(index) * 13n + amount);
  return emit(
    [BigInt(DEPOSIT_TOPIC), BigInt(index), BigInt(TOKEN)],
    [BigInt(shield), BigInt(L2_TOKEN), amount, 0n, BigInt(noteCommitment), BigInt(leafHash)],
    {
      index,
      chainIndex: 0,
      shieldAddress: shield,
      token: TOKEN,
      l2TokenContractId: L2_TOKEN,
      amount,
      noteCommitment,
      leafHash,
    },
    'DepositRecorded',
  );
}

function emitClaim({ nullifier, amount }) {
  return emit(
    [BigInt(CLAIM_TOPIC), BigInt(nullifier), BigInt(RECIPIENT), BigInt(TOKEN)],
    [amount],
    { nullifier, recipient: RECIPIENT, token: TOKEN, amount },
    'WithdrawalClaimed',
  );
}

// All values as strings, so PostgreSQL numerics and handler bigints compare.
const normalizeRow = (row) => Object.fromEntries(
  Object.entries(row).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => [key, String(value)]),
);
const normalizeTable = (rows) => rows.map(normalizeRow).sort((a, b) => a.id.localeCompare(b.id));

function dbState() {
  const state = {};
  for (const table of ENTITIES) {
    const json = psql(`SELECT coalesce(json_agg(to_jsonb(t)), '[]') FROM "${table}" t`);
    state[table] = normalizeTable(JSON.parse(json));
  }
  return state;
}

async function expectedState(events) {
  const { handlers } = loadHandlers();
  const context = makeContext();
  for (const { kind, event } of events) {
    await handlers[kind]({ event, context });
  }
  const state = {};
  for (const table of ENTITIES) {
    state[table] = normalizeTable([...context[table].rows.values()]);
  }
  return state;
}

function historyRowCounts() {
  const counts = {};
  for (const table of ['Deposit', 'DepositLeaf', 'AccountDepositStats']) {
    counts[table] = Number(psql(`SELECT count(*) FROM "envio_history_${table}"`));
  }
  return counts;
}

let anvil;
let envio;
let envioLog = '';
const tail = (text) => text.split('\n').slice(-40).join('\n');

function stop(child) {
  if (!child || child.exitCode != null) return;
  try {
    process.kill(-child.pid, 'SIGTERM'); // own process group only
  } catch {
    // already gone
  }
}

function signalEnvio(signal) {
  process.kill(-envio.pid, signal); // own process group only
}

function codegen(depth) {
  reorgDepth = depth;
  execFileSync('pnpm', ['exec', 'envio', 'codegen', '--config', './config.reorg-test.yaml'], {
    cwd: ENVIO_DIR,
    env: {
      ...process.env,
      REORG_TEST_RPC_URL: rpcUrl,
      REORG_TEST_CONFIRMED_BLOCK_THRESHOLD: String(reorgDepth),
    },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
}

// Writes <dir>/<n>-<point>.json (the Reader's address and the events about to
// be orphaned) and waits for <dir>/<n>-<point>.go.
const HOLD_TIMEOUT_MS = 600000;
let holdCount = 0;
async function holdReader(point, pending = []) {
  if (!holdDir || !reader) return;
  const name = `${String(++holdCount).padStart(2, '0')}-${point}`;
  const hold = {
    point,
    database,
    atUnixMs: Date.now(),
    readerPid: reader.child.pid,
    readerUrl: reader.base,
    tokenFile: reader.tokenFile,
    pending: pending.map(({ kind, event }) => ({
      kind,
      txHash: event.transaction.hash,
      blockNumber: event.block.number,
      index: event.params.index ?? null,
      shieldAddress: event.params.shieldAddress ?? null,
      nullifier: event.params.nullifier ?? null,
    })),
  };
  fs.writeFileSync(path.join(holdDir, `${name}.json.tmp`), JSON.stringify(hold));
  fs.renameSync(path.join(holdDir, `${name}.json.tmp`), path.join(holdDir, `${name}.json`));
  const deadline = Date.now() + HOLD_TIMEOUT_MS;
  while (!fs.existsSync(path.join(holdDir, `${name}.go`))) {
    if (Date.now() > deadline) throw new Error(`hold ${name} was not released in ${HOLD_TIMEOUT_MS} ms`);
    await sleep(100);
  }
}

async function createDatabase() {
  const previous = reader; // the Reader follows one database; the next one gets its own
  await holdReader('reader-stop');
  reader = undefined;
  previous?.stop();
  database = `envio_reorg_test_${process.pid}_depth_${reorgDepth}`;
  psql(`CREATE DATABASE "${database}"`, 'postgres');
  createdDatabases.push(database);
}

const orphan = (events) => events.forEach((e) => {
  orphanedHashes.add(e.event.transaction.hash);
  if (e.kind === 'WithdrawalClaimed') orphanedNullifiers.add(e.event.params.nullifier);
});

// Starts the Reader for the current database if it is not running, waits until
// it has caught up with Envio's watermark, and returns its revision epoch.
async function readerBaseline(label) {
  if (!readerBin) return undefined;
  if (!reader) {
    readerDir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'reorg-reader-'));
    reader = new readerCheck.Reader({
      bin: readerBin, pg: PG, database, schema: 'public', port: await freePort(), dir: readerDir,
    });
  }
  const lastCount = Number(psql('SELECT last_count FROM "DepositTreeMeta" WHERE chain_index = 0'));
  const { epoch } = (await reader.waitSynced(0, lastCount, label)).revision;
  console.log(`${label}: reader synced at ${lastCount} deposits in ${reader.lastSyncMs} ms (epoch ${epoch})`);
  return epoch;
}

async function readerVerify(label, canonical, epochBefore) {
  if (!readerBin) return;
  const hashes = new Set(canonical.map((e) => e.event.transaction.hash));
  const removed = [...orphanedHashes].filter((hash) => !hashes.has(hash));
  const nullifiers = new Set(canonical.filter((e) => e.kind === 'WithdrawalClaimed').map((e) => e.event.params.nullifier));
  const result = await readerCheck.verify(reader, {
    label,
    chainId: CHAIN_ID,
    chainIndex: 0,
    psqlJson: psql,
    events: canonical,
    expectedState,
    removed,
    removedNullifiers: [...orphanedNullifiers].filter((n) => !nullifiers.has(n)),
    epochBefore,
  });
  console.log(`${label}: reader equals the replay and the registered SQL at ${result.lastCount} deposits `
    + `(epoch ${epochBefore ?? 'n/a'} -> ${result.epoch}, ${removed.length} discarded tx hashes not served, `
    + `synced in ${result.syncMs} ms)`);
}

function startEnvio({ isFreshParent, indexingBlockLag }) {
  const { [FRESH_PARENT_ENV]: _fresh, ENVIO_INDEXING_BLOCK_LAG: _lag, ...inheritedEnv } = process.env;
  const child = spawn('pnpm', ['exec', 'envio', 'start', '--config', './config.reorg-test.yaml'], {
    cwd: ENVIO_DIR,
    detached: true,
    env: {
      ...inheritedEnv,
      ...(process.env.REORG_TEST_NODE_BIN_DIR
        ? { PATH: `${process.env.REORG_TEST_NODE_BIN_DIR}${path.delimiter}${process.env.PATH}` }
        : {}),
      ...(isFreshParent ? { [FRESH_PARENT_ENV]: '1' } : {}),
      ...(indexingBlockLag ? { ENVIO_INDEXING_BLOCK_LAG: String(indexingBlockLag) } : {}),
      ENVIO_PG_DATABASE: database,
      ENVIO_PG_PUBLIC_SCHEMA: 'public',
      ENVIO_HASURA: 'false',
      REORG_TEST_RPC_URL: rpcUrl,
      REORG_TEST_CONFIRMED_BLOCK_THRESHOLD: String(reorgDepth),
      LOG_LEVEL: 'info',
      TUI_OFF: 'true',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (chunk) => { envioLog += chunk; });
  child.stderr.on('data', (chunk) => { envioLog += chunk; });
  return child;
}

async function stopAndWait(child) {
  if (!child || child.exitCode != null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  stop(child);
  await Promise.race([exited, sleep(15000)]);
}

const progress = () => Number(psql(
  `SELECT coalesce(max(progress_block), -1) FROM envio_chains WHERE id = ${CHAIN_ID}`) || -1);
const depositRow = (index) => JSON.parse(psql(
  `SELECT coalesce(json_agg(to_jsonb(t)), '[]') FROM "Deposit" t WHERE id = '${CHAIN_ID}-${index}'`))[0];
const reorgLogCount = (fromOffset = 0) => (envioLog.slice(fromOffset).match(/Blockchain reorg detected/g) || []).length;
const invariantMessage = (fromOffset) =>
  (envioLog.slice(fromOffset).match(/deposit read model invariant violated: [^\n"]*/) || [])[0];

// With Envio running and caught up, replaces the block holding a new deposit
// with a fork that re-includes the same deposit `blocksBefore` blocks later and
// ends `blocksAfter` blocks after it. Envio is paused while the fork is built,
// so it first sees the finished fork.
const waitForDepositIndexed = (index, orphaned) => waitFor(`deposit ${index} to be indexed`,
  () => progress() >= orphaned.event.block.number && depositRow(index) != null);

async function replaceDepositBlock({
  index, shield, amount, blocksBefore = 2, blocksAfter, beforeReorg = waitForDepositIndexed,
}) {
  const point = await rpc('evm_snapshot');
  const orphaned = await emitDeposit({ index, shield, amount });
  await beforeReorg(index, orphaned);
  await holdReader(`reorg-deposit-${index}`, [orphaned]);
  const logOffset = envioLog.length;
  signalEnvio('SIGSTOP');
  try {
    assert.equal(await rpc('evm_revert', [point]), true);
    if (blocksBefore > 0) await rpc('anvil_mine', [`0x${blocksBefore.toString(16)}`]);
    const reincluded = await emitDeposit({ index, shield, amount });
    await rpc('anvil_mine', [`0x${blocksAfter.toString(16)}`]);
    const head = Number(await rpc('eth_blockNumber'));
    return { orphaned, reincluded, head, logOffset };
  } finally {
    signalEnvio('SIGCONT');
  }
}

// Waits until Envio has either rolled the fork back and indexed the deposit at
// its new block, or stopped.
async function waitForReorgOutcome({ index, reincluded, head, logOffset }) {
  const deadline = Date.now() + 30000;
  const isRolledBack = () => reorgLogCount(logOffset) > 0 && progress() >= head
    && depositRow(index)?.block_number === reincluded.event.block.number;
  while (Date.now() < deadline && envio.exitCode == null && !isRolledBack()) await sleep(500);
  await sleep(2000); // let the batch after the rollback commit, or the process exit
  return {
    isDetected: reorgLogCount(logOffset) > 0,
    isHalted: envio.exitCode != null,
    invariant: invariantMessage(logOffset),
  };
}

// The re-included deposit must stop Envio instead of appending a second leaf.
function assertMissedAndHalted(outcome, index) {
  assert.ok(!outcome.isDetected && outcome.isHalted
    && new RegExp(`Deposit ${CHAIN_ID}-${index} already exists`).test(outcome.invariant || ''),
  `missed reorg was neither rolled back nor stopped by the invariant: ${JSON.stringify(outcome)}\n${tail(envioLog)}`);
}

async function assertRolledBackLive(outcome, canonical, label) {
  assert.ok(outcome.isDetected && !outcome.isHalted,
    `${label}: live reorg not rolled back: ${JSON.stringify(outcome)}\n${tail(envioLog)}`);
  assert.deepEqual(dbState(), await expectedState(canonical), `${label}: state after the live rollback differs from a replay`);
}

const describeFork = ({ index, orphaned, reincluded, head }) => `deposit ${index} orphaned at block `
  + `${orphaned.event.block.number}, re-included at block ${reincluded.event.block.number}, head ${head}`;

async function main() {
  const port = await freePort();
  rpcUrl = `http://127.0.0.1:${port}`;
  anvil = spawn('anvil', ['--port', String(port), '--chain-id', String(CHAIN_ID), '--silent'], {
    detached: true,
    stdio: 'ignore',
  });
  await waitFor('anvil', async () => (await rpc('eth_chainId')) === '0x7a69');
  await rpc('anvil_setCode', [BRIDGE, EMITTER_RUNTIME]);

  codegen(DEFAULT_REORG_DEPTH);
  await createDatabase();

  const S1 = hex32(0x51n);
  const S2 = hex32(0x52n);
  const S3 = hex32(0x53n);

  // ── Scenario 1 (gate): reorg rolled back by Envio ────────────────────────
  // Stopping Envio before the reorg and restarting it after makes Envio
  // compare the stored checkpoint hashes with the new chain (its block cache
  // starts empty) and run its real rollback path.
  const common = [
    await emitDeposit({ index: 0, shield: S1, amount: 100n }),
    await emitDeposit({ index: 1, shield: S1, amount: 101n }),
    await emitClaim({ nullifier: hex32(0xa0n), amount: 5n }),
  ];
  const forkPoint = await rpc('evm_snapshot');
  const forkA = [
    await emitDeposit({ index: 2, shield: S1, amount: 102n }),
    await emitDeposit({ index: 3, shield: S2, amount: 103n }),
    await emitClaim({ nullifier: hex32(0xa1n), amount: 6n }),
  ];
  const headA = Number(await rpc('eth_blockNumber'));

  envio = startEnvio({ isFreshParent: false });
  await waitFor('fork A to be indexed', () => progress() >= headA);
  const stateA = dbState();
  assert.deepEqual(stateA, await expectedState([...common, ...forkA]), 'fork A state differs from replay');
  const historyA = historyRowCounts();
  for (const [table, count] of Object.entries(historyA)) {
    assert.ok(count > 0, `no ${table} history rows: rollback would have nothing to restore`);
  }
  console.log(`fork A indexed to block ${headA}: ${stateA.Deposit.length} deposits, `
    + `${stateA.DepositLeaf.length} leaves, history rows ${JSON.stringify(historyA)}`);
  orphan(forkA);
  const epoch1 = await readerBaseline('scenario 1 baseline');
  await holdReader('reorg-scenario-1', forkA);
  await stopAndWait(envio);

  assert.equal(await rpc('evm_revert', [forkPoint]), true);
  const forkB = [
    await emitDeposit({ index: 2, shield: S3, amount: 902n }),
    await emitClaim({ nullifier: hex32(0xb2n), amount: 9n }),
  ];
  for (let i = 0; i < 3; i++) await rpc('evm_mine');
  const headB = Number(await rpc('eth_blockNumber'));
  assert.ok(headB > headA, 'fork B must be longer than fork A');
  let canonical = [...common, ...forkB];

  envio = startEnvio({ isFreshParent: false });
  await waitFor('fork B to replace fork A', () => progress() >= headB && depositRow(2)?.shield_address === S3);
  await sleep(2000); // let the batch after the rollback commit
  assert.equal(envio.exitCode, null, `Envio stopped after the reorg\n${tail(envioLog)}`);
  assert.ok(reorgLogCount() >= 1, `Envio did not log a reorg\n${tail(envioLog)}`);
  const stateB = dbState();
  assert.deepEqual(stateB, await expectedState(canonical),
    'state after the rollback differs from a replay of the canonical chain');
  assert.equal(stateB.AccountDepositStats.find((row) => row.shield_address === S2), undefined,
    'stats of an account that only deposited on the discarded fork must be gone');
  console.log(`scenario 1 passed: Envio rolled back to the fork point and indexed fork B to block ${headB}; `
    + `${stateB.Deposit.length} deposits, ${stateB.DepositLeaf.length} leaves, `
    + `${stateB.AccountDepositStats.length} stats rows, ${stateB.WithdrawalClaim.length} claims; `
    + `all ${ENTITIES.length} entity tables equal the replay`);
  await readerVerify('scenario 1', canonical, epoch1);

  // ── Scenario 2a: live reorg, upstream RPC source (patch not enabled) ─────
  const unpatched = await replaceDepositBlock({ index: 3, shield: S1, amount: 103n, blocksAfter: 2 });
  orphan([unpatched.orphaned]);
  const unpatchedOutcome = await waitForReorgOutcome({ index: 3, ...unpatched });
  console.log(`scenario 2a (${FRESH_PARENT_ENV} unset, threshold ${DEFAULT_REORG_DEPTH}): `
    + `${describeFork({ index: 3, ...unpatched })}; ${JSON.stringify(unpatchedOutcome)}`);
  assertMissedAndHalted(unpatchedOutcome, 3);
  canonical = [...canonical, unpatched.reincluded];
  // Recovery: a restart starts with an empty block cache, so Envio compares
  // the stored checkpoint hashes with the chain and rolls the fork back.
  envio = startEnvio({ isFreshParent: false });
  await waitFor('restart to roll back the missed reorg', () => reorgLogCount(unpatched.logOffset) > 0
    && progress() >= unpatched.head && depositRow(3)?.block_number === unpatched.reincluded.event.block.number);
  await sleep(2000);
  assert.equal(envio.exitCode, null, `Envio stopped after the restart\n${tail(envioLog)}`);
  assert.deepEqual(dbState(), await expectedState(canonical),
    'state after the restart differs from a replay of the canonical chain');
  console.log('scenario 2a passed: upstream Envio missed the live reorg, the invariant stopped it, '
    + 'and a restart rolled back to a state equal to the replay');
  await stopAndWait(envio);

  // ── Scenario 2b: live reorg with the fresh reorg parent enabled ─────────
  const epoch2 = await readerBaseline('scenario 2 baseline'); // Reader caught up, Envio stopped
  envio = startEnvio({ isFreshParent: true });
  const patched = await replaceDepositBlock({ index: 4, shield: S2, amount: 104n, blocksAfter: 2 });
  const patchedOutcome = await waitForReorgOutcome({ index: 4, ...patched });
  console.log(`scenario 2b (${FRESH_PARENT_ENV}=1, threshold ${DEFAULT_REORG_DEPTH}): `
    + `${describeFork({ index: 4, ...patched })}; ${JSON.stringify(patchedOutcome)}`);
  orphan([patched.orphaned]);
  canonical = [...canonical, patched.reincluded];
  await assertRolledBackLive(patchedOutcome, canonical, 'scenario 2b');
  console.log('scenario 2b passed: Envio rolled the live reorg back without a restart; '
    + `all ${ENTITIES.length} entity tables equal the replay`);
  await readerVerify('scenario 2', canonical, epoch2);
  await stopAndWait(envio);

  // ── Scenario 3: the live release's confirmed_block_threshold ────────────
  // Envio checks the parent hash only while the parent is within the threshold
  // of the head the fetch saw; an older parent is skipped.
  codegen(LIVE_RELEASE_REORG_DEPTH);
  await createDatabase();
  envio = startEnvio({ isFreshParent: true });
  const headBefore = Number(await rpc('eth_blockNumber'));
  await waitFor('the chain to be indexed again', () => progress() >= headBefore);
  assert.deepEqual(dbState(), await expectedState(canonical), 'threshold 8: initial sync differs from a replay');
  const epoch3 = await readerBaseline('scenario 3 baseline');

  const within = await replaceDepositBlock({ index: 5, shield: S3, amount: 105n, blocksAfter: 2 });
  const withinOutcome = await waitForReorgOutcome({ index: 5, ...within });
  console.log(`scenario 3a (${FRESH_PARENT_ENV}=1, threshold ${LIVE_RELEASE_REORG_DEPTH}): `
    + `${describeFork({ index: 5, ...within })}; ${JSON.stringify(withinOutcome)}`);
  orphan([within.orphaned]);
  canonical = [...canonical, within.reincluded];
  await assertRolledBackLive(withinOutcome, canonical, 'scenario 3a');
  console.log('scenario 3a passed: parent within the threshold, rolled back live');
  await readerVerify('scenario 3a', canonical, epoch3);

  await stopAndWait(envio);
  envio = startEnvio({ isFreshParent: false, indexingBlockLag: INDEXING_BLOCK_LAG });
  await rpc('anvil_mine', [`0x${(INDEXING_BLOCK_LAG + 2).toString(16)}`]);
  const laggedHead = Number(await rpc('eth_blockNumber'));
  await waitFor('Envio to index up to the lagged head', () => progress() >= laggedHead - INDEXING_BLOCK_LAG);
  const lagged = await replaceDepositBlock({
    index: 6,
    shield: S2,
    amount: 106n,
    blocksAfter: INDEXING_BLOCK_LAG + 1,
    beforeReorg: async (index, orphaned) => {
      await sleep(3000); // several polls with the deposit block at the head
      assert.ok(progress() < orphaned.event.block.number && depositRow(index) == null,
        `ENVIO_INDEXING_BLOCK_LAG=${INDEXING_BLOCK_LAG} let the head block reach the handlers`);
    },
  });
  await waitFor('the re-included deposit to be indexed',
    () => depositRow(6)?.block_number === lagged.reincluded.event.block.number);
  await sleep(2000);
  const laggedOutcome = { isDetected: reorgLogCount(lagged.logOffset) > 0, isHalted: envio.exitCode != null };
  console.log(`scenario 3b (${FRESH_PARENT_ENV} unset, ENVIO_INDEXING_BLOCK_LAG=${INDEXING_BLOCK_LAG}): `
    + `${describeFork({ index: 6, ...lagged })}; ${JSON.stringify(laggedOutcome)}`);
  assert.ok(!laggedOutcome.isDetected && !laggedOutcome.isHalted, `${JSON.stringify(laggedOutcome)}\n${tail(envioLog)}`);
  orphan([lagged.orphaned]);
  canonical = [...canonical, lagged.reincluded];
  assert.deepEqual(dbState(), await expectedState(canonical), 'scenario 3b: state differs from a replay');
  await readerVerify('scenario 3b', canonical, undefined);
  console.log('scenario 3b passed: the orphaned head block never reached the handlers; no rollback was needed');
  await stopAndWait(envio);

  envio = startEnvio({ isFreshParent: true });
  const beyond = await replaceDepositBlock({
    index: 7, shield: S1, amount: 107n, blocksAfter: LIVE_RELEASE_REORG_DEPTH + 4,
  });
  const beyondOutcome = await waitForReorgOutcome({ index: 7, ...beyond });
  console.log(`scenario 3c (${FRESH_PARENT_ENV}=1, threshold ${LIVE_RELEASE_REORG_DEPTH}): `
    + `${describeFork({ index: 7, ...beyond })}; ${JSON.stringify(beyondOutcome)}`);
  assertMissedAndHalted(beyondOutcome, 7);
  const restartOffset = envioLog.length;
  envio = startEnvio({ isFreshParent: true });
  await waitFor('the restart to stop again', () => envio.exitCode != null || reorgLogCount(restartOffset) > 0);
  assertMissedAndHalted({
    isDetected: reorgLogCount(restartOffset) > 0,
    isHalted: envio.exitCode != null,
    invariant: invariantMessage(restartOffset),
  }, 7);
  console.log('scenario 3c passed (documents a limit): with the parent more than '
    + `${LIVE_RELEASE_REORG_DEPTH} blocks below the head, neither the patched live guard nor a restart `
    + 'detects the reorg; the invariant stops Envio on every start');
  console.log('reorg rollback test passed');
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (!process.exitCode) await holdReader('reader-stop').catch((error) => console.error(error.message));
    await reader?.stop();
    const keepDir = process.env.REORG_TEST_KEEP_LOGS; // opt-in: keep the Envio and Reader logs
    if (keepDir) {
      fs.mkdirSync(keepDir, { recursive: true });
      fs.writeFileSync(path.join(keepDir, 'envio.log'), envioLog);
      for (const name of readerDir ? fs.readdirSync(readerDir) : []) {
        if (name.endsWith('.log')) fs.copyFileSync(path.join(readerDir, name), path.join(keepDir, name));
      }
    }
    if (readerDir) fs.rmSync(readerDir, { recursive: true, force: true }); // holds the token file
    stop(envio);
    stop(anvil);
    await sleep(1500);
    for (const name of createdDatabases) {
      try {
        psql(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`, 'postgres');
      } catch (error) {
        console.error(`could not drop ${name}: ${error.message}`);
      }
    }
  });
