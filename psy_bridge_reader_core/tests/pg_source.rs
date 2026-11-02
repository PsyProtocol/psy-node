//! PgSource against Envio's own DDL.
//!
//! `PSY_BRIDGE_READER_TEST_PG` is the URL of a throwaway database on which
//! Envio's migrations ran (`tests/pg/start-envio-pg.sh` starts one), and
//! `PSY_BRIDGE_READER_TEST_PG_SCHEMA` its Envio schema (default `public`). Each
//! test clones that database (`CREATE DATABASE .. TEMPLATE ..`, through the
//! `postgres` maintenance database) and works on its clone only, so the tests
//! can run in parallel and the given database stays pristine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use psy_bridge_reader_api::{DepositRow, FinalizedBatchRow, WithdrawalClaimRow};
use psy_bridge_reader_core::model::{ChainProgress, Cursors, DepositCursor, DepositWithLeaf, TreeMetaRow};
use psy_bridge_reader_core::source::{EnvioSource, PgConfig, PgSource, SourceError};
use psy_bridge_reader_core::tree::hash::{to_display_hex, zero, Hash};
use tokio_postgres::{Client, NoTls};

const CHAIN_ID: u64 = 11155111;
const AMOUNT: &str = "123456789012345678901234567890";

fn test_url() -> String {
    std::env::var("PSY_BRIDGE_READER_TEST_PG").unwrap_or_else(|_| {
        panic!(
            "PSY_BRIDGE_READER_TEST_PG is not set: start a throwaway Envio database with \
             `PSY_BRIDGE_READER_TEST_PG=$(tests/pg/start-envio-pg.sh)` (see that script)"
        )
    })
}

fn test_schema() -> String {
    std::env::var("PSY_BRIDGE_READER_TEST_PG_SCHEMA").unwrap_or_else(|_| "public".to_owned())
}

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.expect("connect");
    tokio::spawn(connection);
    client
}

/// A clone of the test database, dropped by `drop_db`.
struct ClonedDb {
    name: String,
    url: String,
}

fn with_dbname(url: &str, db: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, format!("?{q}")),
        None => (url, String::new()),
    };
    let slash = base.rfind('/').expect("URL has a database path");
    assert!(slash > base.find("://").map_or(0, |i| i + 2), "URL {url} names no database");
    format!("{}/{db}{query}", &base[..slash])
}

async fn clone_db() -> ClonedDb {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let url = test_url();
    let template: tokio_postgres::Config = url.parse().expect("PSY_BRIDGE_READER_TEST_PG is a URL");
    let template_db = template.get_dbname().expect("URL names a database").to_owned();
    assert_ne!(template_db, "postgres", "the test database must not be the maintenance database");
    let name = format!("reader_test_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
    let admin = connect(&with_dbname(&url, "postgres")).await;
    admin
        .batch_execute(&format!("CREATE DATABASE \"{name}\" TEMPLATE \"{template_db}\""))
        .await
        .expect("clone the test database");
    ClonedDb { url: with_dbname(&url, &name), name }
}

async fn drop_db(db: ClonedDb) {
    let admin = connect(&with_dbname(&test_url(), "postgres")).await;
    admin
        .batch_execute(&format!("DROP DATABASE \"{}\" WITH (FORCE)", db.name))
        .await
        .expect("drop the cloned database");
}

fn cfg(url: &str) -> PgConfig {
    PgConfig {
        url: url.to_owned(),
        schema: test_schema(),
        statement_timeout_ms: 5000,
        application_name: "psy-bridge-reader".to_owned(),
    }
}

async fn seeded(db: &ClonedDb) -> Client {
    let c = connect(&db.url).await;
    c.batch_execute(&format!("SET search_path TO \"{}\"", test_schema())).await.unwrap();
    c.batch_execute(&format!(
        "DELETE FROM envio_chains;
         INSERT INTO envio_chains (id, start_block, end_block, max_reorg_depth, buffer_block, source_block,
             first_event_block, ready_at, events_processed, _is_hyper_sync, progress_block, _num_batches_fetched)
         VALUES ({CHAIN_ID}, 1, NULL, 8, 130, 140, 90, NULL, 5, false, 120, 3);"
    ))
    .await
    .unwrap();
    for (local, deposit_index, block) in [(0u64, 5u64, 91u64), (1, 7, 95), (2, 9, 95)] {
        c.batch_execute(&format!(
            "INSERT INTO \"Deposit\" (id, chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
                 l2_token_contract_id, amount, note_commitment, chain_index, leaf_hash, block_number, block_timestamp,
                 tx_hash)
             VALUES ('{CHAIN_ID}-{deposit_index}', {CHAIN_ID}, {deposit_index}, {local}, '0xshield{local}',
                 '0xtoken', '0xl2token', {AMOUNT}, '0xnote{local}', 0, '0xleafhash{local}', {block}, 1700000000{local},
                 '0xtx{local}');
             INSERT INTO \"DepositLeaf\" (id, chain_index, chain_local_deposit_index, deposit_index, chain_id,
                 poseidon_leaf_hash, block_number)
             VALUES ('0-{local}', 0, {local}, {deposit_index}, {CHAIN_ID}, '{}', {block});",
            to_display_hex(&leaf(local))
        ))
        .await
        .unwrap();
    }
    c.batch_execute(&format!(
        "INSERT INTO \"DepositTreeMeta\" (id, chain_index, last_count, poseidon_deposit_tree_root, deposit_tree_root,
             finalized_keccak_deposit_tree_root, last_finalized_checkpoint_id, block_number, tx_hash)
         VALUES ('0', 0, 3, '{root}', '{root}', '0xkeccak', 4, 95, '0xtx2');
         INSERT INTO \"WithdrawalClaim\" (id, chain_id, nullifier, recipient, token, amount, block_number, tx_hash)
         VALUES ('{CHAIN_ID}-0xnull', {CHAIN_ID}, '0xnull', '0xrecipient', '0xtoken', {AMOUNT}, 100, '0xclaimtx');
         INSERT INTO \"FinalizedBatch\" (id, chain_id, finalized_checkpoint_id, deposit_tree_root,
             withdrawal_tree_root, block_number, tx_hash)
         VALUES ('batch-1', {CHAIN_ID}, 18446744073709551615, '0xdroot', '0xwroot', 110, '0xbatchtx');",
        root = to_display_hex(&tree_root())
    ))
    .await
    .unwrap();
    c
}

fn leaf(local: u64) -> Hash {
    zero(local as u8 + 1)
}

fn tree_root() -> Hash {
    zero(20)
}

fn deposit(local: u64) -> DepositWithLeaf {
    let (deposit_index, block) = [(5, 91), (7, 95), (9, 95)][local as usize];
    DepositWithLeaf {
        row: DepositRow {
            id: format!("{CHAIN_ID}-{deposit_index}"),
            chain_id: CHAIN_ID,
            chain_index: 0,
            deposit_index,
            chain_local_deposit_index: local,
            shield_address: format!("0xshield{local}"),
            token: "0xtoken".to_owned(),
            l2_token_contract_id: "0xl2token".to_owned(),
            amount: AMOUNT.to_owned(),
            note_commitment: format!("0xnote{local}"),
            leaf_hash: format!("0xleafhash{local}"),
            block_number: block,
            block_timestamp: format!("1700000000{local}").parse().unwrap(),
            tx_hash: format!("0xtx{local}"),
        },
        leaf: leaf(local),
        leaf_deposit_index: deposit_index,
        leaf_chain_id: CHAIN_ID,
        leaf_block_number: block,
    }
}

fn claim() -> WithdrawalClaimRow {
    WithdrawalClaimRow {
        id: format!("{CHAIN_ID}-0xnull"),
        chain_id: CHAIN_ID,
        nullifier: "0xnull".to_owned(),
        recipient: "0xrecipient".to_owned(),
        token: "0xtoken".to_owned(),
        amount: AMOUNT.to_owned(),
        block_number: 100,
        tx_hash: "0xclaimtx".to_owned(),
    }
}

fn batch() -> FinalizedBatchRow {
    FinalizedBatchRow {
        id: "batch-1".to_owned(),
        chain_id: CHAIN_ID,
        finalized_checkpoint_id: "18446744073709551615".to_owned(),
        deposit_tree_root: "0xdroot".to_owned(),
        withdrawal_tree_root: "0xwroot".to_owned(),
        block_number: 110,
        tx_hash: "0xbatchtx".to_owned(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

#[tokio::test]
#[ignore]
async fn reads_a_tick_from_envio_ddl() {
    let db = clone_db().await;
    let seed = seeded(&db).await;
    let ids = seed
        .query_one("SELECT 'envio_chains'::regclass::oid::int8, '\"Deposit\"'::regclass::oid::int8", &[])
        .await
        .unwrap();
    let (chains_oid, deposit_oid): (i64, i64) = (ids.get(0), ids.get(1));

    let mut source = PgSource::connect(&cfg(&db.url)).await.expect("connect");

    // From the start: everything, nothing truncated.
    let before = now_ms();
    let tick = source.read_tick(&Cursors::default(), 10).await.expect("first tick");
    assert!(tick.started_unix_ms >= before && tick.started_unix_ms <= now_ms());
    assert_eq!((tick.identity.chains_oid, tick.identity.deposit_oid), (chains_oid, deposit_oid));
    assert_eq!(tick.progress, vec![ChainProgress { chain_id: CHAIN_ID, progress_block: 120, max_reorg_depth: 8 }]);
    assert_eq!(tick.metas, vec![TreeMetaRow { chain_index: 0, last_count: 3, root: tree_root() }]);
    assert_eq!(tick.deposits, BTreeMap::from([(0, vec![deposit(0), deposit(1), deposit(2)])]));
    let leaf_keys: Vec<(u64, u64)> = tick.deposits[&0].iter().map(|d| (d.leaf_deposit_index, d.leaf_chain_id)).collect();
    assert_eq!(leaf_keys, vec![(5, CHAIN_ID), (7, CHAIN_ID), (9, CHAIN_ID)]);
    assert_eq!(tick.claims, BTreeMap::from([(CHAIN_ID, vec![claim()])]));
    assert_eq!(tick.batches, BTreeMap::from([(CHAIN_ID, vec![batch()])]));
    assert!(!tick.truncated);

    // The cursors are honoured: deposits from (local 2, deposit_index 9), claims
    // and batches strictly after their (block_number, id).
    let cursors = Cursors {
        deposits: BTreeMap::from([(0, DepositCursor { local_count: 2, next_deposit_index: 9 })]),
        claims: BTreeMap::from([(CHAIN_ID, (100, claim().id))]),
        batches: BTreeMap::from([(CHAIN_ID, (109, "zzz".to_owned()))]),
        ..Cursors::default()
    };
    let tick = source.read_tick(&cursors, 10).await.expect("second tick");
    assert_eq!(tick.deposits, BTreeMap::from([(0, vec![deposit(2)])]));
    assert_eq!(tick.claims, BTreeMap::from([(CHAIN_ID, vec![])]));
    assert_eq!(tick.batches, BTreeMap::from([(CHAIN_ID, vec![batch()])]));
    assert!(!tick.truncated);

    // max_rows = 2 truncates the three deposits; exactly max_rows rows does not.
    let tick = source.read_tick(&Cursors::default(), 2).await.expect("truncated tick");
    assert_eq!(tick.deposits, BTreeMap::from([(0, vec![deposit(0), deposit(1)])]));
    assert!(tick.truncated);
    let tick = source.read_tick(&Cursors::default(), 3).await.expect("exact tick");
    assert_eq!(tick.deposits[&0].len(), 3);
    assert!(!tick.truncated);

    // A skipped chain index keeps its meta row but has no deposit read.
    let skip = Cursors { skip: BTreeSet::from([0]), ..Cursors::default() };
    let tick = source.read_tick(&skip, 10).await.expect("skipping tick");
    assert_eq!(tick.metas, vec![TreeMetaRow { chain_index: 0, last_count: 3, root: tree_root() }]);
    assert!(tick.deposits.is_empty());
    assert_eq!(tick.skipped, BTreeSet::from([0]));

    // A claim beyond max_rows truncates too.
    seed.batch_execute(&format!(
        "INSERT INTO \"WithdrawalClaim\" (id, chain_id, nullifier, recipient, token, amount, block_number, tx_hash)
         VALUES ('{CHAIN_ID}-0xnull2', {CHAIN_ID}, '0xnull2', '0xrecipient', '0xtoken', 1, 101, '0xclaimtx2');"
    ))
    .await
    .unwrap();
    let tick = source.read_tick(&Cursors::default(), 1).await.expect("claim-truncated tick");
    assert_eq!(tick.claims, BTreeMap::from([(CHAIN_ID, vec![claim()])]));
    assert!(tick.truncated);

    // Deposits and leaves are cut to their common length: a deposit whose leaf
    // is missing is not returned, and that alone is not truncation.
    seed.batch_execute(&format!(
        "INSERT INTO \"Deposit\" (id, chain_id, deposit_index, chain_local_deposit_index, shield_address, token,
             l2_token_contract_id, amount, note_commitment, chain_index, leaf_hash, block_number, block_timestamp,
             tx_hash)
         VALUES ('{CHAIN_ID}-11', {CHAIN_ID}, 11, 3, '0xs', '0xt', '0xl2', 1, '0xn', 0, '0xl', 96, 1, '0xtx3');"
    ))
    .await
    .unwrap();
    let tick = source.read_tick(&Cursors::default(), 10).await.expect("leafless tick");
    assert_eq!(tick.deposits[&0].len(), 3);
    assert!(!tick.truncated);

    drop(source);
    drop(seed);
    drop_db(db).await;
}

#[tokio::test]
#[ignore]
async fn a_leaf_that_disagrees_with_its_deposit_is_returned_for_the_model_to_catch() {
    let db = clone_db().await;
    let seed = seeded(&db).await;
    // Local index 1 belongs to deposit_index 7 on CHAIN_ID; its leaf claims 8 on 97.
    seed.batch_execute("UPDATE \"DepositLeaf\" SET deposit_index = 8, chain_id = 97 WHERE id = '0-1'")
        .await
        .unwrap();
    let mut source = PgSource::connect(&cfg(&db.url)).await.expect("connect");
    let tick = source.read_tick(&Cursors::default(), 10).await.expect("a mismatch is not a source error");
    let d = &tick.deposits[&0];
    assert_eq!(d.len(), 3);
    assert_eq!((d[1].row.deposit_index, d[1].row.chain_id), (7, CHAIN_ID));
    assert_eq!((d[1].leaf_deposit_index, d[1].leaf_chain_id), (8, 97));
    assert_eq!(d[1].row.chain_local_deposit_index, 1);
    assert_eq!(d[0], deposit(0));
    assert_eq!(d[2], deposit(2));
    assert!(!tick.truncated);
    drop(source);
    drop(seed);
    drop_db(db).await;
}

#[tokio::test]
#[ignore]
async fn a_missing_index_is_schema_missing() {
    let db = clone_db().await;
    let c = connect(&db.url).await;
    c.batch_execute(&format!(
        "DROP INDEX \"{}\".\"WithdrawalClaim_chain_id_block_number_id\"",
        test_schema()
    ))
    .await
    .unwrap();
    match PgSource::connect(&cfg(&db.url)).await {
        Err(SourceError::SchemaMissing(msg)) => {
            assert!(msg.contains("WithdrawalClaim_chain_id_block_number_id"), "{msg}")
        }
        Err(other) => panic!("expected SchemaMissing, got {other:?}"),
        Ok(_) => panic!("expected SchemaMissing, got a source"),
    }
    drop(c);
    drop_db(db).await;
}

#[tokio::test]
#[ignore]
async fn a_missing_table_is_schema_missing() {
    let db = clone_db().await;
    let c = connect(&db.url).await;
    c.batch_execute(&format!("DROP TABLE \"{}\".\"FinalizedBatch\"", test_schema())).await.unwrap();
    match PgSource::connect(&cfg(&db.url)).await {
        Err(SourceError::SchemaMissing(msg)) => assert!(msg.contains("FinalizedBatch"), "{msg}"),
        Err(other) => panic!("expected SchemaMissing, got {other:?}"),
        Ok(_) => panic!("expected SchemaMissing, got a source"),
    }
    drop(c);
    drop_db(db).await;
}

#[tokio::test]
#[ignore]
async fn a_table_dropped_after_connect_is_schema_missing() {
    let db = clone_db().await;
    let mut source = PgSource::connect(&cfg(&db.url)).await.expect("connect");
    let c = connect(&db.url).await;
    c.batch_execute(&format!("DROP TABLE \"{}\".\"FinalizedBatch\"", test_schema())).await.unwrap();
    match source.read_tick(&Cursors::default(), 10).await {
        Err(SourceError::SchemaMissing(_)) => {}
        other => panic!("expected SchemaMissing, got {other:?}"),
    }
    drop(source);
    drop(c);
    drop_db(db).await;
}

#[tokio::test]
async fn an_unreachable_server_is_unavailable() {
    // Port 1 on localhost refuses connections.
    let cfg = cfg("postgresql://postgres:x@127.0.0.1:1/envio");
    match PgSource::connect(&cfg).await {
        Err(SourceError::Unavailable(_)) => {}
        Err(other) => panic!("expected Unavailable, got {other:?}"),
        Ok(_) => panic!("expected Unavailable, got a source"),
    }
}
