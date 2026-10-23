// Reader half of the live reorg test (run-reorg-test.cjs --with-reader <path>).
// Starts psy-bridge-reader against the test's database and compares its HTTP
// answers with the registered SQL (psy_bridge_reader_api/sql/queries.sql) run
// with psql, and its tree roots with a replay of the canonical chain.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const QUERIES_SQL = path.join(__dirname, '../../../../../../psy_bridge_reader_api/sql/queries.sql');
const SYNC_TIMEOUT_MS = 30000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tail = (text) => text.split('\n').slice(-40).join('\n');

function assertReaderBinary(bin) {
  try {
    fs.accessSync(bin, fs.constants.X_OK);
    if (!fs.statSync(bin).isFile()) throw new Error('not a file');
  } catch {
    throw new Error(`reader binary not found: ${bin}`);
  }
}

// name -> { params: [type...], body }
function loadQueries() {
  const queries = {};
  let current;
  for (const line of fs.readFileSync(QUERIES_SQL, 'utf8').split('\n')) {
    const name = /^-- name:\s*(\S+)/.exec(line);
    if (name) {
      current = { params: [], body: [] };
      queries[name[1]] = current;
    } else if (current && /^-- params:/.test(line)) {
      current.params = line.replace(/^-- params:/, '').split(',').map((s) => s.trim()).filter(Boolean);
    } else if (current && !line.startsWith('--') && line.trim()) {
      current.body.push(line);
    }
  }
  for (const query of Object.values(queries)) query.body = query.body.join('\n').replace(/;\s*$/, '');
  return queries;
}

const literal = (type, value) => {
  if (type === 'text') return `'${String(value).replace(/'/g, "''")}'::text`;
  if (type === 'text[]') return `ARRAY[${value.map((v) => `'${String(v).replace(/'/g, "''")}'`).join(',')}]::text[]`;
  assert.ok(['int4', 'int8'].includes(type) && Number.isSafeInteger(Number(value)), `bad parameter ${type} ${value}`);
  return `${Number(value)}::${type}`;
};

class Reader {
  constructor({ bin, pg, database, schema, port, dir }) {
    this.queries = loadQueries();
    this.base = `http://127.0.0.1:${port}`;
    this.token = `reorg-test-${process.pid}-${Date.now()}`;
    this.tokenFile = path.join(dir, `reader-token-${database}`);
    fs.writeFileSync(this.tokenFile, this.token + '\n', { mode: 0o600 });
    this.logFile = path.join(dir, `reader-${database}.log`);
    this.log = '';
    const logFd = fs.openSync(this.logFile, 'a');
    const url = `postgres://${encodeURIComponent(pg.user)}:${encodeURIComponent(pg.password)}@${pg.host}:${pg.port}/${database}`;
    this.child = spawn(bin, [], {
      stdio: ['ignore', 'ignore', logFd],
      env: {
        ...process.env,
        PSY_BRIDGE_READER_LISTEN: `127.0.0.1:${port}`,
        PSY_BRIDGE_READER_TOKEN_FILE: this.tokenFile,
        PSY_BRIDGE_READER_DATABASE_URL: url,
        PSY_BRIDGE_READER_DB_SCHEMA: schema,
        PSY_BRIDGE_READER_TICK_MS: '200',
      },
    });
    fs.closeSync(logFd);
    this.seen = []; // raw text of every response since the last resetSeen()
  }

  logTail() {
    try { return tail(fs.readFileSync(this.logFile, 'utf8')); } catch { return '(no log)'; }
  }

  stop() {
    if (this.child.exitCode == null && this.child.signalCode == null) this.child.kill('SIGTERM'); // this child only
  }

  async call(method, route, body) {
    const response = await fetch(this.base + route, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        'x-psy-lane': 'interactive',
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    this.seen.push(text);
    let json;
    try { json = JSON.parse(text); } catch { json = undefined; }
    return { status: response.status, json, text };
  }

  async get(route) {
    const { status, json, text } = await this.call('GET', route);
    assert.equal(status, 200, `GET ${route} answered ${status}: ${text}\nreader log:\n${this.logTail()}`);
    return json;
  }

  async epoch() {
    return (await this.get('/v1/status')).revision.epoch;
  }

  // Waits until chain `chainIndex` is ready with the deposit count of the
  // Envio watermark.
  async waitSynced(chainIndex, lastCount, label) {
    const deadline = Date.now() + SYNC_TIMEOUT_MS;
    let last = 'no answer';
    while (Date.now() < deadline) {
      if (this.child.exitCode != null) {
        throw new Error(`${label}: reader exited with code ${this.child.exitCode}\n${this.logTail()}`);
      }
      try {
        const { status, json } = await this.call('GET', '/v1/status');
        const chain = json?.chains?.find((c) => c.chain_index === chainIndex);
        last = `http ${status}, ready ${json?.ready}, chain ${JSON.stringify(chain)}`;
        if (status === 200 && json.ready && chain?.ready && chain.deposit_count === lastCount) return json;
      } catch (error) {
        last = error.message;
      }
      await sleep(200);
    }
    throw new Error(`${label}: reader did not reach deposit_count ${lastCount} and ready in ${SYNC_TIMEOUT_MS} ms (${last})\n${this.logTail()}`);
  }

  // The registered SQL, with literals bound, run on the test database.
  sql(name, args, psqlJson) {
    const query = this.queries[name];
    assert.ok(query, `query ${name} is not registered`);
    assert.equal(args.length, query.params.length, `${name}: parameter count`);
    const bound = query.body.replace(/\$(\d+)/g, (_, n) => literal(query.params[n - 1], args[n - 1]));
    return JSON.parse(psqlJson(`SELECT coalesce(json_agg(q), '[]') FROM (${bound}) q`));
  }
}

// Every field the SQL row carries must equal the Reader's field as a string
// (amount and block_timestamp are text on the SQL side, numbers on the wire).
function assertRowMatches(label, readerRow, sqlRow) {
  assert.ok(readerRow, `${label}: the Reader returned no row, SQL returned ${JSON.stringify(sqlRow)}`);
  for (const [key, value] of Object.entries(sqlRow)) {
    if (key === 'chain_local_count') continue;
    assert.equal(String(readerRow[key]), String(value), `${label}: field ${key}: reader ${JSON.stringify(readerRow)} vs SQL ${JSON.stringify(sqlRow)}`);
  }
}

function assertRowsMatch(label, readerRows, sqlRows, keyOf) {
  assert.deepEqual(readerRows.map(keyOf).sort(), sqlRows.map(keyOf).sort(), `${label}: row sets differ`);
  for (const sqlRow of sqlRows) {
    assertRowMatches(`${label} ${keyOf(sqlRow)}`, readerRows.find((r) => keyOf(r) === keyOf(sqlRow)), sqlRow);
  }
}

// events: canonical events of the chain; expectedState: the test's replay;
// removed: tx hashes that were on discarded forks only.
async function verify(reader, {
  label, chainId, chainIndex, psqlJson, events, expectedState, removed, removedNullifiers = [], epochBefore,
}) {
  const meta = JSON.parse(psqlJson(`SELECT coalesce(json_agg(to_jsonb(t)), '[]') FROM "DepositTreeMeta" t WHERE chain_index = ${chainIndex}`))[0];
  assert.ok(meta, `${label}: no DepositTreeMeta row`);
  const lastCount = Number(meta.last_count);
  const status = await reader.waitSynced(chainIndex, lastCount, label);
  reader.seen.length = 0; // only responses after the final state are scanned for removed hashes
  if (epochBefore != null) {
    assert.ok(status.revision.epoch > epochBefore, `${label}: revision.epoch did not increase across the reorg (${epochBefore} -> ${status.revision.epoch})`);
  }

  // Roots: at last_count against the Envio watermark, at every count against the replay.
  const rootAt = async (count) => (await reader.get(`/v1/tree/root?chain_index=${chainIndex}&count=${count}`)).root;
  assert.equal(await rootAt(lastCount), meta.poseidon_deposit_tree_root, `${label}: root at last_count differs from DepositTreeMeta`);
  const chainStatus = status.chains.find((c) => c.chain_index === chainIndex);
  assert.equal(chainStatus.tree_root, meta.poseidon_deposit_tree_root, `${label}: status tree_root differs from DepositTreeMeta`);
  const deposits = events.filter((e) => e.kind === 'DepositRecorded');
  assert.equal(deposits.length, lastCount, `${label}: canonical deposit count`);
  for (let count = 1; count <= lastCount; count++) {
    const replay = await expectedState(deposits.slice(0, count));
    const expected = replay.DepositTreeMeta.find((row) => row.chain_index === String(chainIndex)).poseidon_deposit_tree_root;
    assert.equal(await rootAt(count), expected, `${label}: root at count ${count} differs from the replay`);
  }

  // Reads against the registered SQL.
  const sql = (name, ...args) => reader.sql(name, args, psqlJson);
  const depositRows = JSON.parse(psqlJson(`SELECT coalesce(json_agg(to_jsonb(t)), '[]') FROM "Deposit" t WHERE chain_index = ${chainIndex}`));
  const shields = [...new Set(depositRows.map((r) => r.shield_address))];
  for (const shield of [...shields, '0x' + '99'.repeat(32)]) {
    for (const offset of [0, 1]) {
      const sqlRows = sql('deposit_list_offset_page', shield, chainIndex, chainId, offset);
      const got = await reader.get(`/v1/deposits/by-address?shield_address=${shield}&chain_id=${chainId}&chain_index=${chainIndex}&limit=100&offset=${offset}`);
      const total = Number(psqlJson(`SELECT count(*) FROM "Deposit" WHERE shield_address = '${shield}' AND chain_index = ${chainIndex} AND chain_id = ${chainId}`));
      assert.equal(got.total, total, `${label}: by-address total for ${shield}`);
      assert.deepEqual(got.rows.map((r) => r.chain_local_deposit_index), sqlRows.map((r) => Number(r.chain_local_deposit_index)), `${label}: by-address order for ${shield}`);
      assertRowsMatch(`${label} by-address ${shield}`, got.rows, sqlRows, (r) => String(r.deposit_index));
    }
  }
  for (let index = 0; index <= lastCount; index++) { // one past the end must be null
    const sqlRows = sql('deposit_by_deposit_index', chainIndex, chainId, index);
    const got = await reader.get(`/v1/deposits/by-index?chain_index=${chainIndex}&chain_id=${chainId}&deposit_index=${index}`);
    if (sqlRows.length === 0) assert.equal(got.deposit, null, `${label}: by-index ${index} should be null`);
    else assertRowMatches(`${label} by-index ${index}`, got.deposit, sqlRows[0]);
  }
  for (const hash of [...new Set(depositRows.map((r) => r.tx_hash)), ...removed]) {
    const sqlRows = sql('deposit_by_tx_hash', hash, chainIndex);
    const got = await reader.get(`/v1/deposits/by-tx?tx_hash=${hash}&chain_index=${chainIndex}`);
    assertRowsMatch(`${label} by-tx ${hash}`, got.rows, sqlRows, (r) => String(r.deposit_index));
    if (removed.includes(hash)) assert.equal(got.rows.length, 0, `${label}: removed tx ${hash} is still served`);
  }
  for (let target = 0; target <= lastCount; target++) {
    const probe = sql('global_to_local_probe', chainIndex, chainId, target);
    const foreign = sql('foreign_prefix_probe', chainIndex, chainId, target)[0].has_foreign_deposits;
    const got = await reader.get(`/v1/deposits/prefix?chain_index=${chainIndex}&chain_id=${chainId}&target_deposit_count=${target}`);
    assert.equal(got.chain_local_count, probe.length ? Number(probe[0].chain_local_count) : 0, `${label}: prefix local count at ${target}`);
    assert.equal(got.has_foreign_deposits, foreign, `${label}: prefix foreign flag at ${target}`);
  }
  const claimRows = JSON.parse(psqlJson(`SELECT coalesce(json_agg(to_jsonb(t)), '[]') FROM "WithdrawalClaim" t WHERE chain_id = ${chainId}`));
  const nullifiers = [...claimRows.map((r) => r.nullifier), '0x' + 'ee'.repeat(32)];
  const claims = await reader.call('POST', '/v1/withdrawal-claims', { chain_id: chainId, nullifiers });
  assert.equal(claims.status, 200, `${label}: withdrawal-claims answered ${claims.status}: ${claims.text}`);
  assertRowsMatch(`${label} claims`, claims.json.claims, sql('withdrawal_claims_by_nullifier', chainId, nullifiers), (r) => r.nullifier);
  const discarded = await reader.call('POST', '/v1/withdrawal-claims', { chain_id: chainId, nullifiers: removedNullifiers });
  assert.equal(discarded.status, 200, `${label}: withdrawal-claims (discarded) answered ${discarded.status}`);
  assert.equal(discarded.json.claims.length, 0, `${label}: a discarded claim is still served`);

  // Explorer: the SQL orders by deposit_index desc within a chain_index, the
  // Reader by (block_number desc, id desc); compare as sets, then check the
  // Reader's own order rule.
  const explorer = await reader.get(`/v1/explorer?chain_id=${chainId}`);
  assertRowsMatch(`${label} explorer`, explorer.deposits, sql('explorer_latest_deposits', chainIndex), (r) => String(r.deposit_index));
  for (let i = 1; i < explorer.deposits.length; i++) {
    const a = explorer.deposits[i - 1];
    const b = explorer.deposits[i];
    assert.ok(a.block_number > b.block_number || (a.block_number === b.block_number && a.id > b.id),
      `${label}: explorer order (block_number desc, id desc) broken at ${i}`);
  }
  const batchCount = Number(psqlJson(`SELECT count(*) FROM "FinalizedBatch" WHERE chain_id = ${chainId}`));
  assert.equal(explorer.batches.length, Math.min(batchCount, 100), `${label}: explorer batch count`);

  // Nothing served after the final state may mention a discarded transaction.
  // The by-tx and claims probes above asked about them on purpose; the
  // responses to those carry only the empty result, not the hash.
  const everything = reader.seen.join('\n');
  for (const hash of removed) assert.ok(!everything.includes(hash), `${label}: a response contains removed tx_hash ${hash}`);
  return { lastCount, epoch: (await reader.get('/v1/status')).revision.epoch };
}

module.exports = { assertReaderBinary, Reader, verify };
