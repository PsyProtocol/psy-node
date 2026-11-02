//! The Envio PostgreSQL source. Every tick reads in one
//! `REPEATABLE READ READ ONLY` transaction: Envio commits entity rows,
//! `envio_chains.progress_block` and its checkpoints in one transaction, so a
//! snapshot of them is coherent. The source never writes.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use psy_bridge_reader_api::{query, DepositRow, FinalizedBatchRow, WithdrawalClaimRow};
use tokio_postgres::error::SqlState;
use tokio_postgres::types::{FromSql, Type};
use tokio_postgres::{Client, IsolationLevel, NoTls, Row, Statement, Transaction};

use super::{guard, EnvioSource, SourceError};
use crate::model::{ChainProgress, Cursors, DepositWithLeaf, Identity, TickData, TreeMetaRow};
use crate::tree::hash::{parse_display_hex, Hash};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgConfig {
    pub url: String,
    /// The Envio schema (`ENVIO_PG_PUBLIC_SCHEMA`).
    pub schema: String,
    pub statement_timeout_ms: u32,
    pub application_name: String,
}

pub struct PgSource {
    client: Client,
    statements: Statements,
}

/// The registered statements a tick runs, prepared once per connection.
struct Statements {
    identity: Statement,
    progress: Statement,
    metas: Statement,
    deposits: Statement,
    leaves: Statement,
    claims: Statement,
    batches: Statement,
}

impl PgSource {
    /// Connects, applies the session settings, runs the schema guard and
    /// prepares the tick statements.
    pub async fn connect(cfg: &PgConfig) -> Result<PgSource, SourceError> {
        check_config(cfg)?;
        let (client, connection) = tokio_postgres::connect(&cfg.url, NoTls)
            .await
            .map_err(|e| db_error("connect", e))?;
        // A closed connection surfaces as an error of the next client call.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .batch_execute(&format!(
                "SET search_path TO {}; \
                 SET statement_timeout = {}; \
                 SET lock_timeout = 1000; \
                 SET idle_in_transaction_session_timeout = 5000",
                quote_ident(&cfg.schema),
                cfg.statement_timeout_ms
            ))
            .await
            .map_err(|e| db_error("session settings", e))?;
        // SET application_name, with the name bound as a parameter.
        client
            .query_one("SELECT set_config('application_name', $1, false)", &[&cfg.application_name])
            .await
            .map_err(|e| db_error("session settings", e))?;
        guard::check(&client, &cfg.schema).await?;
        let statements = Statements {
            identity: prepare(&client, "envio_identity").await?,
            progress: prepare(&client, "chain_progress").await?,
            metas: prepare(&client, "tree_meta_all").await?,
            deposits: prepare(&client, "follow_deposits").await?,
            leaves: prepare(&client, "follow_leaves").await?,
            claims: prepare(&client, "follow_claims").await?,
            batches: prepare(&client, "follow_batches").await?,
        };
        Ok(PgSource { client, statements })
    }
}

impl EnvioSource for PgSource {
    async fn read_tick(&mut self, cursors: &Cursors, max_rows: usize) -> Result<TickData, SourceError> {
        let started_unix_ms = now_unix_ms();
        // One row past the limit tells whether more remain.
        let limit = i64::try_from(max_rows).unwrap_or(i64::MAX).saturating_add(1);
        let PgSource { client, statements: s } = self;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(|e| db_error("begin", e))?;
        // On an error return `tx` is dropped, which rolls the transaction back.

        let row = tx.query_one(&s.identity, &[]).await.map_err(|e| db_error("envio_identity", e))?;
        let identity = Identity {
            chains_oid: get(&row, "chains_oid", "envio_identity")?,
            deposit_oid: get(&row, "deposit_oid", "envio_identity")?,
        };

        let mut progress = Vec::new();
        for row in tx.query(&s.progress, &[]).await.map_err(|e| db_error("chain_progress", e))? {
            progress.push(ChainProgress {
                chain_id: get_u64(&row, "id", "chain_progress")?,
                progress_block: i64::from(get::<i32>(&row, "progress_block", "chain_progress")?),
                max_reorg_depth: get_u64(&row, "max_reorg_depth", "chain_progress")?,
            });
        }

        let mut metas = Vec::new();
        for row in tx.query(&s.metas, &[]).await.map_err(|e| db_error("tree_meta_all", e))? {
            metas.push(TreeMetaRow {
                chain_index: get_u64(&row, "chain_index", "tree_meta_all")?,
                last_count: get_u64(&row, "last_count", "tree_meta_all")?,
                root: get_hash(&row, "poseidon_deposit_tree_root", "tree_meta_all")?,
            });
        }

        let mut truncated = false;
        let mut deposits = BTreeMap::new();
        for meta in metas.iter().filter(|m| !cursors.skip.contains(&m.chain_index)) {
            let cursor = cursors.deposits.get(&meta.chain_index).copied().unwrap_or_default();
            let chain_index = to_int4(meta.chain_index, "chain_index")?;
            let from_deposit = to_int4(cursor.next_deposit_index, "next_deposit_index cursor")?;
            let from_local = to_int4(cursor.local_count, "local_count cursor")?;
            let rows = tx
                .query(&s.deposits, &[&chain_index, &from_deposit, &limit])
                .await
                .map_err(|e| db_error("follow_deposits", e))?;
            let leaves = tx
                .query(&s.leaves, &[&chain_index, &from_local, &limit])
                .await
                .map_err(|e| db_error("follow_leaves", e))?;
            truncated |= rows.len() > max_rows || leaves.len() > max_rows;
            let n = rows.len().min(leaves.len()).min(max_rows);
            let mut out = Vec::with_capacity(n);
            for (k, (row, leaf)) in rows.iter().zip(&leaves).take(n).enumerate() {
                let local = get_u64(leaf, "chain_local_deposit_index", "follow_leaves")?;
                let expected = cursor.local_count + k as u64;
                if local != expected {
                    return Err(SourceError::Decode(format!(
                        "follow_leaves: chain_index {} is not dense: leaf {local} where {expected} was expected",
                        meta.chain_index
                    )));
                }
                out.push(DepositWithLeaf {
                    row: decode_deposit(row)?,
                    leaf: get_hash(leaf, "poseidon_leaf_hash", "follow_leaves")?,
                    leaf_deposit_index: get_u64(leaf, "deposit_index", "follow_leaves")?,
                    leaf_chain_id: get_u64(leaf, "chain_id", "follow_leaves")?,
                    leaf_block_number: get_u64(leaf, "block_number", "follow_leaves")?,
                });
            }
            deposits.insert(meta.chain_index, out);
        }

        let mut claims = BTreeMap::new();
        let mut batches = BTreeMap::new();
        for chain in &progress {
            let chain_id = to_int4(chain.chain_id, "chain_id")?;

            let (block, id) = after(cursors.claims.get(&chain.chain_id), "claims")?;
            let rows = tx
                .query(&s.claims, &[&chain_id, &block, &id, &limit])
                .await
                .map_err(|e| db_error("follow_claims", e))?;
            truncated |= rows.len() > max_rows;
            let out = rows.iter().take(max_rows).map(decode_claim).collect::<Result<Vec<_>, _>>()?;
            claims.insert(chain.chain_id, out);

            let (block, id) = after(cursors.batches.get(&chain.chain_id), "batches")?;
            let rows = tx
                .query(&s.batches, &[&chain_id, &block, &id, &limit])
                .await
                .map_err(|e| db_error("follow_batches", e))?;
            truncated |= rows.len() > max_rows;
            let out = rows.iter().take(max_rows).map(decode_batch).collect::<Result<Vec<_>, _>>()?;
            batches.insert(chain.chain_id, out);
        }

        commit(tx).await?;
        let skipped = cursors.skip.clone();
        Ok(TickData { identity, started_unix_ms, progress, metas, deposits, claims, batches, truncated, skipped })
    }
}

/// Settings `connect` refuses before it opens a connection.
fn check_config(cfg: &PgConfig) -> Result<(), SourceError> {
    // 0 would disable the server-side statement timeout (design section 9).
    if cfg.statement_timeout_ms == 0 {
        return Err(SourceError::Unavailable(
            "statement_timeout_ms is 0: a server-side statement timeout is required".to_owned(),
        ));
    }
    Ok(())
}

async fn commit(tx: Transaction<'_>) -> Result<(), SourceError> {
    tx.commit().await.map_err(|e| db_error("commit", e))
}

async fn prepare(client: &Client, name: &str) -> Result<Statement, SourceError> {
    let q = query(name);
    let types: Vec<Type> = q.params.iter().map(|p| param_type(name, p)).collect();
    client.prepare_typed(q.sql, &types).await.map_err(|e| db_error(name, e))
}

/// A registered parameter type; anything else is a programming error.
fn param_type(query: &str, name: &str) -> Type {
    match name {
        "int4" => Type::INT4,
        "int8" => Type::INT8,
        "text" => Type::TEXT,
        "text[]" => Type::TEXT_ARRAY,
        other => panic!("query {query}: unsupported parameter type {other}"),
    }
}

/// The `(block_number, id)` a claim or batch read continues after; `(-1, "")`
/// before the first row.
fn after<'a>(cursor: Option<&'a (u64, String)>, what: &str) -> Result<(i32, &'a str), SourceError> {
    match cursor {
        None => Ok((-1, "")),
        Some((block, id)) => Ok((to_int4(*block, &format!("{what} cursor block_number"))?, id.as_str())),
    }
}

fn decode_deposit(row: &Row) -> Result<DepositRow, SourceError> {
    const Q: &str = "follow_deposits";
    Ok(DepositRow {
        id: get(row, "id", Q)?,
        chain_id: get_u64(row, "chain_id", Q)?,
        chain_index: get_u64(row, "chain_index", Q)?,
        deposit_index: get_u64(row, "deposit_index", Q)?,
        chain_local_deposit_index: get_u64(row, "chain_local_deposit_index", Q)?,
        shield_address: get(row, "shield_address", Q)?,
        token: get(row, "token", Q)?,
        l2_token_contract_id: get(row, "l2_token_contract_id", Q)?,
        amount: get_integer_text(row, "amount", Q)?,
        note_commitment: get(row, "note_commitment", Q)?,
        leaf_hash: get(row, "leaf_hash", Q)?,
        block_number: get_u64(row, "block_number", Q)?,
        block_timestamp: get_numeric_u64(row, "block_timestamp", Q)?,
        tx_hash: get(row, "tx_hash", Q)?,
    })
}

fn decode_claim(row: &Row) -> Result<WithdrawalClaimRow, SourceError> {
    const Q: &str = "follow_claims";
    Ok(WithdrawalClaimRow {
        id: get(row, "id", Q)?,
        chain_id: get_u64(row, "chain_id", Q)?,
        nullifier: get(row, "nullifier", Q)?,
        recipient: get(row, "recipient", Q)?,
        token: get(row, "token", Q)?,
        amount: get_integer_text(row, "amount", Q)?,
        block_number: get_u64(row, "block_number", Q)?,
        tx_hash: get(row, "tx_hash", Q)?,
    })
}

fn decode_batch(row: &Row) -> Result<FinalizedBatchRow, SourceError> {
    const Q: &str = "follow_batches";
    Ok(FinalizedBatchRow {
        id: get(row, "id", Q)?,
        chain_id: get_u64(row, "chain_id", Q)?,
        finalized_checkpoint_id: get_integer_text(row, "finalized_checkpoint_id", Q)?,
        deposit_tree_root: get(row, "deposit_tree_root", Q)?,
        withdrawal_tree_root: get(row, "withdrawal_tree_root", Q)?,
        block_number: get_u64(row, "block_number", Q)?,
        tx_hash: get(row, "tx_hash", Q)?,
    })
}

fn get<'a, T: FromSql<'a>>(row: &'a Row, column: &str, query: &str) -> Result<T, SourceError> {
    row.try_get(column).map_err(|e| decode_error(&format!("{query}.{column}"), e))
}

/// An Envio `Int` (int4) column that must not be negative.
fn get_u64(row: &Row, column: &str, query: &str) -> Result<u64, SourceError> {
    let v: i32 = get(row, column, query)?;
    u64::try_from(v).map_err(|_| SourceError::Decode(format!("{query}.{column}: negative value {v}")))
}

/// An Envio `BigInt` (numeric) column read as `::text` that must fit `u64`.
fn get_numeric_u64(row: &Row, column: &str, query: &str) -> Result<u64, SourceError> {
    let s: String = get(row, column, query)?;
    s.parse::<u64>()
        .map_err(|e| SourceError::Decode(format!("{query}.{column}: {s:?} is not a u64: {e}")))
}

/// An Envio `BigInt` (numeric) column read as `::text` and kept as text (it may
/// exceed `u64`): it must be a non-negative integer.
fn get_integer_text(row: &Row, column: &str, query: &str) -> Result<String, SourceError> {
    let s: String = get(row, column, query)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SourceError::Decode(format!("{query}.{column}: {s:?} is not a non-negative integer")));
    }
    Ok(s)
}

fn get_hash(row: &Row, column: &str, query: &str) -> Result<Hash, SourceError> {
    let s: String = get(row, column, query)?;
    parse_display_hex(&s).map_err(|e| SourceError::Decode(format!("{query}.{column}: {e}")))
}

/// A cursor value bound to an int4 parameter.
fn to_int4(v: u64, what: &str) -> Result<i32, SourceError> {
    i32::try_from(v).map_err(|_| SourceError::Decode(format!("{what} {v} does not fit an int4 parameter")))
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// A failed statement or connection. A missing relation, column or schema, or
/// a revoked privilege, is `SchemaMissing`; everything else (connection loss,
/// timeouts, shutdown) is `Unavailable`.
pub(crate) fn db_error(what: &str, e: tokio_postgres::Error) -> SourceError {
    let schema = [
        SqlState::UNDEFINED_TABLE,
        SqlState::UNDEFINED_COLUMN,
        SqlState::INVALID_SCHEMA_NAME,
        SqlState::INSUFFICIENT_PRIVILEGE,
    ];
    let message = format!("{what}: {}", describe(&e));
    match e.code() {
        Some(code) if schema.contains(code) => SourceError::SchemaMissing(message),
        _ => SourceError::Unavailable(message),
    }
}

/// A column that could not be read into its Rust type.
pub(crate) fn decode_error(what: &str, e: tokio_postgres::Error) -> SourceError {
    SourceError::Decode(format!("{what}: {}", describe(&e)))
}

fn describe(e: &tokio_postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return format!("{} ({})", db.message(), db.code().code());
    }
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_zero_statement_timeout_is_refused_before_connecting() {
        // Nothing listens on port 1; the refusal must come first.
        let cfg = PgConfig {
            url: "postgresql://postgres:x@127.0.0.1:1/envio".to_owned(),
            schema: "public".to_owned(),
            statement_timeout_ms: 0,
            application_name: "psy-bridge-reader".to_owned(),
        };
        match PgSource::connect(&cfg).await {
            Err(SourceError::Unavailable(msg)) => assert!(msg.contains("statement_timeout_ms"), "{msg}"),
            Err(other) => panic!("expected the statement timeout refusal, got {other:?}"),
            Ok(_) => panic!("expected the statement timeout refusal, got a source"),
        }
    }

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(quote_ident("public"), "\"public\"");
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn every_statement_used_has_supported_parameter_types() {
        for name in [
            "envio_identity",
            "chain_progress",
            "tree_meta_all",
            "follow_deposits",
            "follow_leaves",
            "follow_claims",
            "follow_batches",
        ] {
            for p in &query(name).params {
                param_type(name, p);
            }
        }
    }

    #[test]
    fn an_absent_cursor_starts_before_every_row() {
        assert_eq!(after(None, "claims").unwrap(), (-1, ""));
        let c = (7u64, "x".to_owned());
        assert_eq!(after(Some(&c), "claims").unwrap(), (7, "x"));
        let big = (u64::from(u32::MAX), String::new());
        assert!(matches!(after(Some(&big), "claims"), Err(SourceError::Decode(_))));
    }
}
