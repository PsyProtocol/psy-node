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
// re-included in a later block. Envio 2.32.10's RPC source answers its
// parent-hash check from a block cache keyed by number, so it misses this
// reorg. The test then requires the handler invariant to stop Envio instead of
// appending the deposit twice, and a restart to roll the fork back to a state
// equal to the replay (or, if Envio detects the reorg live, a correct
// rollback). Set REORG_TEST_REQUIRE_LIVE_DETECTION=1 to require detection.
//
// Requirements: anvil and cast (Foundry), psql, a PostgreSQL server reachable
// through ENVIO_PG_HOST / ENVIO_PG_PORT / ENVIO_PG_USER / ENVIO_PG_PASSWORD
// (never point it at a shared server: the test creates and drops its own
// database), and `pnpm install` done in this directory:
//
//   ENVIO_PG_HOST=127.0.0.1 ENVIO_PG_PORT=5544 ENVIO_PG_USER=postgres \
//     ENVIO_PG_PASSWORD=... node tests/reorg/run-reorg-test.cjs
//
// Envio bakes the RPC URL into generated/ at codegen time, so the test runs
// codegen for config.reorg-test.yaml after it has picked the Anvil port. Run
// `pnpm codegen` again before using the regular config. Envio 2.32.10 runs on
// Node <= 22 (on Node >= 23 its yargs dependency fails to load);
// REORG_TEST_NODE_BIN_DIR, when set, is put first on PATH for the Envio
// process only.
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');
const { loadHandlers, makeContext, ENTITIES } = require('../lib/handler-harness.cjs');

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
const DATABASE = `envio_reorg_test_${process.pid}`;

const word = (value) => BigInt(value).toString(16).padStart(64, '0');
const hex32 = (value) => '0x' + word(value);
const keccak = (text) => execFileSync('cast', ['keccak', text], { encoding: 'utf8' }).trim();
const DEPOSIT_TOPIC = keccak('DepositRecorded(uint32,bytes32,address,bytes32,uint256,uint8,bytes32,bytes32)');
const CLAIM_TOPIC = keccak('WithdrawalClaimed(bytes32,address,address,uint256)');
// Digit-only addresses: Envio's checksum formatting leaves them unchanged.
const TOKEN = '0x2222222222222222222222222222222222222222';
const RECIPIENT = '0x5555555555555555555555555555555555555555';
const L2_TOKEN = hex32(4);

function psql(sql, database = DATABASE) {
  return execFileSync('psql', ['-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', sql], {
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
  const receipt = await rpc('eth_getTransactionReceipt', [txHash]);
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

function startEnvio() {
  const child = spawn('pnpm', ['exec', 'envio', 'start', '--config', './config.reorg-test.yaml'], {
    cwd: ENVIO_DIR,
    detached: true,
    env: {
      ...process.env,
      ...(process.env.REORG_TEST_NODE_BIN_DIR
        ? { PATH: `${process.env.REORG_TEST_NODE_BIN_DIR}${path.delimiter}${process.env.PATH}` }
        : {}),
      ENVIO_PG_DATABASE: DATABASE,
      ENVIO_PG_PUBLIC_SCHEMA: 'public',
      ENVIO_HASURA: 'false',
      REORG_TEST_RPC_URL: rpcUrl,
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
const reorgLogCount = () => (envioLog.match(/Blockchain reorg detected/g) || []).length;

async function main() {
  const port = await freePort();
  rpcUrl = `http://127.0.0.1:${port}`;
  anvil = spawn('anvil', ['--port', String(port), '--chain-id', String(CHAIN_ID), '--silent'], {
    detached: true,
    stdio: 'ignore',
  });
  await waitFor('anvil', async () => (await rpc('eth_chainId')) === '0x7a69');
  await rpc('anvil_setCode', [BRIDGE, EMITTER_RUNTIME]);

  execFileSync('pnpm', ['exec', 'envio', 'codegen', '--config', './config.reorg-test.yaml'], {
    cwd: ENVIO_DIR,
    env: { ...process.env, REORG_TEST_RPC_URL: rpcUrl },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  psql(`CREATE DATABASE "${DATABASE}"`, 'postgres');

  const S1 = hex32(0x51n);
  const S2 = hex32(0x52n);
  const S3 = hex32(0x53n);

  // ── Scenario 1 (gate): reorg rolled back by Envio ────────────────────────
  // Envio 2.32.10's RPC source caches blocks by number, so its parent-hash
  // guard only sees a reorg when the cache is fresh. Stopping Envio before the
  // reorg and restarting it after makes Envio compare the stored checkpoint
  // hashes with the new chain and run its real rollback path.
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

  envio = startEnvio();
  await waitFor('fork A to be indexed', () => progress() >= headA);
  const stateA = dbState();
  assert.deepEqual(stateA, await expectedState([...common, ...forkA]), 'fork A state differs from replay');
  const historyA = historyRowCounts();
  for (const [table, count] of Object.entries(historyA)) {
    assert.ok(count > 0, `no ${table} history rows: rollback would have nothing to restore`);
  }
  console.log(`fork A indexed to block ${headA}: ${stateA.Deposit.length} deposits, `
    + `${stateA.DepositLeaf.length} leaves, history rows ${JSON.stringify(historyA)}`);
  await stopAndWait(envio);

  assert.equal(await rpc('evm_revert', [forkPoint]), true);
  const forkB = [
    await emitDeposit({ index: 2, shield: S3, amount: 902n }),
    await emitClaim({ nullifier: hex32(0xb2n), amount: 9n }),
  ];
  for (let i = 0; i < 3; i++) await rpc('evm_mine');
  const headB = Number(await rpc('eth_blockNumber'));
  assert.ok(headB > headA, 'fork B must be longer than fork A');
  const canonicalB = [...common, ...forkB];

  envio = startEnvio();
  await waitFor('fork B to replace fork A', () => progress() >= headB && depositRow(2)?.shield_address === S3);
  await sleep(2000); // let the batch after the rollback commit
  assert.equal(envio.exitCode, null, `Envio stopped after the reorg\n${tail(envioLog)}`);
  assert.ok(reorgLogCount() >= 1, `Envio did not log a reorg\n${tail(envioLog)}`);
  const stateB = dbState();
  assert.deepEqual(stateB, await expectedState(canonicalB),
    'state after the rollback differs from a replay of the canonical chain');
  assert.equal(stateB.AccountDepositStats.find((row) => row.shield_address === S2), undefined,
    'stats of an account that only deposited on the discarded fork must be gone');
  console.log(`scenario 1 passed: Envio rolled back to the fork point and indexed fork B to block ${headB}; `
    + `${stateB.Deposit.length} deposits, ${stateB.DepositLeaf.length} leaves, `
    + `${stateB.AccountDepositStats.length} stats rows, ${stateB.WithdrawalClaim.length} claims; `
    + `all ${ENTITIES.length} entity tables equal the replay`);

  // ── Scenario 2: reorg while Envio keeps running ──────────────────────────
  const reorgsBefore = reorgLogCount();
  const livePoint = await rpc('evm_snapshot');
  const forkC = [await emitDeposit({ index: 3, shield: S1, amount: 103n })];
  const headC = Number(await rpc('eth_blockNumber'));
  await waitFor('fork C to be indexed', () => progress() >= headC && depositRow(3) != null);
  assert.equal(await rpc('evm_revert', [livePoint]), true);
  for (let i = 0; i < 2; i++) await rpc('evm_mine');
  // The same deposit, re-included in a later block of the new chain.
  const forkD = [await emitDeposit({ index: 3, shield: S1, amount: 103n })];
  for (let i = 0; i < 2; i++) await rpc('evm_mine');
  const headD = Number(await rpc('eth_blockNumber'));
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline && envio.exitCode == null) {
    if (reorgLogCount() > reorgsBefore && progress() >= headD) break;
    await sleep(500);
  }
  await sleep(2000);
  const detected = reorgLogCount() > reorgsBefore;
  const halted = envio.exitCode != null;
  const invariant = (envioLog.match(/deposit read model invariant violated: [^\n"]*/) || [])[0];
  if (detected && !halted) {
    assert.deepEqual(dbState(), await expectedState([...canonicalB, ...forkD]),
      'state after the live rollback differs from a replay');
    console.log('scenario 2: Envio detected the live reorg and rolled back');
  } else {
    console.log(`scenario 2: live reorg detected=${detected}; Envio halted=${halted}`
      + `${invariant ? `; ${invariant}` : ''}; DB Deposit 3 block=${depositRow(3)?.block_number}, `
      + `canonical block=${forkD[0].event.block.number} (orphaned fork C block ${forkC[0].event.block.number})`);
    // Without a rollback, the re-included deposit must stop Envio instead of
    // appending a second leaf for it.
    assert.ok(!detected && halted && /Deposit 31337-3 already exists/.test(invariant || ''),
      `missed reorg was neither rolled back nor stopped by the invariant\n${tail(envioLog)}`);
    // Recovery: a restart starts with an empty block cache, so Envio compares
    // the stored checkpoint hashes with the chain and rolls the fork back.
    envio = startEnvio();
    await waitFor('restart to roll back the missed reorg',
      () => reorgLogCount() > reorgsBefore && progress() >= headD && depositRow(3)?.block_number === forkD[0].event.block.number);
    await sleep(2000);
    assert.equal(envio.exitCode, null, `Envio stopped after the restart\n${tail(envioLog)}`);
    assert.deepEqual(dbState(), await expectedState([...canonicalB, ...forkD]),
      'state after the restart differs from a replay of the canonical chain');
    console.log('scenario 2: a restart detected the missed reorg, rolled back and matches the replay');
    if (process.env.REORG_TEST_REQUIRE_LIVE_DETECTION === '1') {
      throw new Error('live reorg was not rolled back');
    }
  }
  console.log('reorg rollback test passed');
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    stop(envio);
    stop(anvil);
    await sleep(1500);
    try {
      psql(`DROP DATABASE IF EXISTS "${DATABASE}" WITH (FORCE)`, 'postgres');
    } catch (error) {
      console.error(`could not drop ${DATABASE}: ${error.message}`);
    }
  });
