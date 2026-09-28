// Only a disposable, local PostgreSQL container with password local-test-only.
// HISTORY_TEST_PORT=<published port> node tests/history-backfill.integration.cjs
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const generatedRequire = createRequire(path.resolve(__dirname, '../generated/package.json'));
const postgres = generatedRequire('postgres');
const history = require('envio/src/db/EntityHistory.res.js');
const { Deposit } = require('../generated/src/db/Entities.res.js');
const port = Number(process.env.HISTORY_TEST_PORT);
assert(Number.isSafeInteger(port) && port > 1024 && port < 65536, 'explicit local test port required');
const sql = postgres({ host: '127.0.0.1', port, database: 'postgres', username: 'postgres',
  password: 'local-test-only', max: 1, onnotice: () => {}, connect_timeout: 5,
  debug: process.env.HISTORY_TEST_DEBUG ? console.log : undefined });
const quote = s => '"' + s.replace(/"/g, '""') + '"';
const schemas = [];
let checks = 0;

async function check(label, fn) {
  await fn();
  console.log('PASS ' + label);
  checks++;
}

async function fixture(schema) {
  await sql.unsafe(`CREATE SCHEMA ${quote(schema)}`);
  schemas.push(schema);
  const s = quote(schema);
  await sql.unsafe(`CREATE TYPE ${s}.envio_history_change AS ENUM ('SET', 'DELETE');
    CREATE TABLE ${s}."Deposit" (
      amount NUMERIC NOT NULL, block_number INTEGER NOT NULL, chain_id INTEGER NOT NULL,
      chain_index INTEGER NOT NULL, chain_local_deposit_index INTEGER NOT NULL,
      deposit_index INTEGER NOT NULL, id TEXT PRIMARY KEY,
      l2_token_contract_id TEXT NOT NULL, leaf_hash TEXT NOT NULL, note_commitment TEXT NOT NULL,
      shield_address TEXT NOT NULL, token TEXT NOT NULL, tx_hash TEXT NOT NULL);
    CREATE TABLE ${s}."envio_history_Deposit" (LIKE ${s}."Deposit");
    ALTER TABLE ${s}."envio_history_Deposit" ADD COLUMN checkpoint_id INTEGER,
      ADD COLUMN envio_change ${s}.envio_history_change,
      ADD PRIMARY KEY (id, checkpoint_id);
    ALTER TABLE ${s}."Deposit" ADD COLUMN block_timestamp NUMERIC;
    ALTER TABLE ${s}."envio_history_Deposit" ADD COLUMN block_timestamp NUMERIC;
    INSERT INTO ${s}."Deposit" VALUES
      (123456789012345678901234567890123456789,42,97,1,0,0,'populated','1','leaf','note','shield','token','tx',1789999999),
      (987654321098765432109876543210,41,11155111,0,0,0,'legacy','1','leaf2','note2','shield2','token2','tx2',NULL);`);
}

async function main() {
  const schema = 'psy_history_test_' + process.pid;
  await fixture(schema);
  const s = quote(schema);
  await check('reproduce legacy positional SQL error on actual migrated column order', async () => {
    await assert.rejects(async () => await sql.unsafe(`INSERT INTO ${s}."envio_history_Deposit"
      SELECT *, 0 AS checkpoint_id, 'SET' AS envio_change FROM ${s}."Deposit"`, [], { simple: false, prepare: true }),
      e => e.code === '42804' && e.message.includes('envio_change'));
  });
  if (process.env.HISTORY_EXPECT_UNPATCHED === '1') {
    await check('unpatched Envio runtime backfillHistory reproduces production error', async () => {
      await assert.rejects(async () => await history.backfillHistory(sql, schema, 'Deposit', 0, ['populated']),
        e => e.code === '42804' && e.message.includes('envio_change'));
    });
    return;
  }
  await check('actual Envio backfill preserves every field, NULL and exact large NUMERIC', async () => {
    await history.backfillHistory(sql, schema, 'Deposit', 0, ['populated', 'legacy']);
    const [row] = await sql.unsafe(`SELECT count(*)::int AS n,
      bool_and(to_jsonb(h) - 'checkpoint_id' - 'envio_change' = to_jsonb(d)) AS equal,
      bool_and(h.checkpoint_id = 0 AND h.envio_change = 'SET') AS baseline
      FROM ${s}."envio_history_Deposit" h JOIN ${s}."Deposit" d USING (id)`);
    assert.deepEqual(row, { n: 2, equal: true, baseline: true });
  });
  await check('repeated, duplicate, absent and empty IDs neither duplicate nor overwrite history', async () => {
    await sql.unsafe(`UPDATE ${s}."Deposit" SET block_timestamp=1800000000 WHERE id='populated'`);
    await history.backfillHistory(sql, schema, 'Deposit', 0, ['populated', 'populated', 'absent']);
    await history.backfillHistory(sql, schema, 'Deposit', 0, []);
    const [row] = await sql.unsafe(`SELECT count(*)::int AS n,
      max(block_timestamp)::text AS ts FROM ${s}."envio_history_Deposit"`);
    assert.deepEqual(row, { n: 2, ts: '1789999999' });
  });
  await check('generated rollback query selects original baseline; real rollback prunes later history', async () => {
    await sql.unsafe(`INSERT INTO ${s}."envio_history_Deposit"
      SELECT (jsonb_populate_record(NULL::${s}."envio_history_Deposit",
        to_jsonb(h) || '{"checkpoint_id":5,"block_timestamp":1800000000}'::jsonb)).*
      FROM ${s}."envio_history_Deposit" h WHERE id='populated'`);
    const rows = await sql.unsafe(Deposit.entityHistory.makeGetRollbackRestoredEntitiesQuery(schema), [0]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].block_timestamp, '1789999999');
    assert.equal(rows[0].amount, '123456789012345678901234567890123456789');
    await history.rollback(sql, schema, 'Deposit', 0, 0);
    const [row] = await sql.unsafe(`SELECT count(*)::int AS n FROM ${s}."envio_history_Deposit"`);
    assert.equal(row.n, 2);
  });
  await check('enclosing transaction rollback also rolls back inserted baseline', async () => {
    await sql.unsafe(`DELETE FROM ${s}."envio_history_Deposit" WHERE id='legacy'`);
    await assert.rejects(sql.begin(async tx => {
      await history.backfillHistory(tx, schema, 'Deposit', 0, ['legacy']);
      throw new Error('intentional abort');
    }), /intentional abort/);
    const [row] = await sql.unsafe(`SELECT count(*)::int AS n FROM ${s}."envio_history_Deposit" WHERE id='legacy'`);
    assert.equal(row.n, 0);
  });
  await check('other entities, quoted names, arrays, duplicate IDs and arbitrary history order', async () => {
    const other = schema + '"quoted';
    await sql.unsafe(`CREATE SCHEMA ${quote(other)}`);
    schemas.push(other);
    const entity = 'other"entity';
    const ref = quote(other) + '.' + quote(entity);
    const href = quote(other) + '.' + quote(history.historyTableName(entity, 1));
    await sql.unsafe(`CREATE TABLE ${ref} (id TEXT PRIMARY KEY, value NUMERIC, tags TEXT[]);
      CREATE TABLE ${href} (envio_change ${s}.envio_history_change, tags TEXT[], checkpoint_id INTEGER,
        value NUMERIC, id TEXT, PRIMARY KEY(id,checkpoint_id));
      INSERT INTO ${ref} VALUES ('a',123456789012345678901234567890,ARRAY['a','b']),('b',NULL,NULL);`);
    await history.backfillHistory(sql, other, entity, 1, ['a', 'a', 'b']);
    const [row] = await sql.unsafe(`SELECT count(*)::int AS n,
      bool_and(to_jsonb(h)-'checkpoint_id'-'envio_change'=to_jsonb(e)) AS equal
      FROM ${href} h JOIN ${ref} e USING (id)`);
    assert.deepEqual(row, { n: 2, equal: true });
  });
  await check('fresh, unmigrated tables remain compatible, including long history names', async () => {
    const name = 'AnEntityWithAVeryLongName'.repeat(3);
    // PostgreSQL limits entity names as well; choose one <=63, history prefix overflows.
    const entity = name.slice(0, 60);
    const ref = s + '.' + quote(entity);
    const href = s + '.' + quote(history.historyTableName(entity, 7));
    await sql.unsafe(`CREATE TABLE ${ref} (id TEXT PRIMARY KEY, value INTEGER);
      CREATE TABLE ${href} (id TEXT, value INTEGER, checkpoint_id INTEGER,
        envio_change ${s}.envio_history_change, PRIMARY KEY(id,checkpoint_id));
      INSERT INTO ${ref} VALUES ('fresh',1)`);
    await history.backfillHistory(sql, schema, entity, 7, ['fresh']);
    const [row] = await sql.unsafe(`SELECT * FROM ${href}`);
    assert.deepEqual(row, { id: 'fresh', value: 1, checkpoint_id: 0, envio_change: 'SET' });
  });
}
main().then(() => console.log(`${checks} checks passed`)).catch(e => {
  console.error(e);
  process.exitCode = 1;
}).finally(async () => {
  for (const schema of schemas.reverse()) await sql.unsafe(`DROP SCHEMA ${quote(schema)} CASCADE`);
  await sql.end();
});
