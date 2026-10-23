//! The schema guard: the Reader refuses to run unless every table it reads is
//! readable and every index its statements rely on exists and is valid. It
//! never creates anything.

use psy_bridge_reader_api::{reader_required_indexes, GUARD_SQL, READER_TABLES};
use tokio_postgres::Client;

use super::pg::{db_error, decode_error};
use super::SourceError;

/// Checks `schema` on `client`. Every problem found is listed in one
/// `SchemaMissing`.
pub async fn check(client: &Client, schema: &str) -> Result<(), SourceError> {
    let usage = client
        .query_opt(GUARD_SQL.schema_usage, &[&schema])
        .await
        .map_err(|e| db_error("schema guard (schema)", e))?;
    match usage {
        None => return Err(SourceError::SchemaMissing(format!("schema {schema:?} does not exist"))),
        Some(row) => {
            let usable: bool = row.try_get(0).map_err(|e| decode_error("schema guard (schema)", e))?;
            if !usable {
                return Err(SourceError::SchemaMissing(format!("the role may not use schema {schema:?}")));
            }
        }
    }

    let mut problems = Vec::new();

    let tables = client
        .query(GUARD_SQL.table_privileges, &[&READER_TABLES, &schema])
        .await
        .map_err(|e| db_error("schema guard (tables)", e))?;
    let mut found: Vec<(String, bool)> = Vec::with_capacity(tables.len());
    for row in &tables {
        let name: String = row.try_get(0).map_err(|e| decode_error("schema guard (tables)", e))?;
        let readable: bool = row.try_get(1).map_err(|e| decode_error("schema guard (tables)", e))?;
        found.push((name, readable));
    }
    for &table in READER_TABLES {
        match found.iter().find(|(name, _)| name == table) {
            None => problems.push(format!("table {table:?} does not exist")),
            Some((_, false)) => problems.push(format!("table {table:?} is not readable by the role")),
            Some((_, true)) => {}
        }
    }

    let required = reader_required_indexes();
    let names: Vec<&str> = required.iter().map(|i| i.name).collect();
    let indexes = client
        .query(GUARD_SQL.indexes, &[&names, &schema])
        .await
        .map_err(|e| db_error("schema guard (indexes)", e))?;
    let mut found: Vec<(String, String, bool)> = Vec::with_capacity(indexes.len());
    for row in &indexes {
        let table: String = row.try_get(0).map_err(|e| decode_error("schema guard (indexes)", e))?;
        let name: String = row.try_get(1).map_err(|e| decode_error("schema guard (indexes)", e))?;
        let valid: bool = row.try_get(2).map_err(|e| decode_error("schema guard (indexes)", e))?;
        found.push((table, name, valid));
    }
    for index in &required {
        match found.iter().find(|(_, name, _)| name == index.name) {
            None => problems.push(format!("index {:?} on {:?} does not exist", index.name, index.table)),
            Some((table, _, _)) if table != index.table => problems.push(format!(
                "index {:?} is on table {table:?}, expected {:?}",
                index.name, index.table
            )),
            Some((_, _, false)) => problems.push(format!("index {:?} is not valid", index.name)),
            Some(_) => {}
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(SourceError::SchemaMissing(problems.join("; ")))
    }
}
