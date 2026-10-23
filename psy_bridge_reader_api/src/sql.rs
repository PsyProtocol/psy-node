//! The registered Envio SQL: the one copy used by the Reader, psy-services and
//! the plan test (`run_plan_test.py`).

use std::sync::OnceLock;

const QUERIES: &str = include_str!("../sql/queries.sql");

/// Role script for the Envio read-only role (psql variables `:reader_role`,
/// `:envio_schema`).
pub const READER_ROLE_SQL: &str = include_str!("../sql/reader-role.sql");

/// Every Envio table a registered statement reads.
pub const READER_TABLES: &[&str] = &[
    "Deposit",
    "DepositLeaf",
    "DepositTreeMeta",
    "WithdrawalClaim",
    "FinalizedBatch",
    "envio_chains",
];

/// Tables read only by the psy-services direct-PostgreSQL fallback (design
/// C13); the Reader never reads them (plan P11).
pub const LEGACY_TABLES: &[&str] = &["AccountDepositStats"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryClass {
    Bridge,
    Interactive,
    Background,
}

#[derive(Debug)]
pub struct Query {
    pub name: &'static str,
    pub class: QueryClass,
    /// PREPARE parameter types, in `$n` order.
    pub params: Vec<&'static str>,
    /// Indexes the statement's plan must use.
    pub index: Vec<&'static str>,
    /// The statement without its trailing `;`.
    pub sql: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredIndex {
    pub table: &'static str,
    pub name: &'static str,
}

/// Catalog statements of the schema guard (parameters: `$1` names, `$2`
/// schema; `schema_usage` takes the schema as `$1`).
#[derive(Debug, Clone, Copy)]
pub struct GuardSql {
    /// Whether the connected role may use the schema (no row: no such schema).
    /// `pg_namespace` is readable whatever the role's grants.
    pub schema_usage: &'static str,
    /// The expected tables that exist, and whether the role may read them.
    /// `information_schema.columns` hides a table the role cannot read, so
    /// existence comes from `pg_class`.
    pub table_privileges: &'static str,
    pub columns: &'static str,
    pub indexes: &'static str,
}

pub const GUARD_SQL: GuardSql = GuardSql {
    schema_usage:
        "SELECT has_schema_privilege(n.oid, 'USAGE') FROM pg_namespace n WHERE n.nspname = $1",
    table_privileges: "SELECT c.relname::text, has_table_privilege(c.oid, 'SELECT') \
     FROM pg_class c \
     JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE n.nspname = $2 AND c.relname = ANY($1) AND c.relkind IN ('r', 'p')",
    columns: "SELECT table_name::text, column_name::text, data_type::text \
     FROM information_schema.columns \
     WHERE table_schema = $2 AND table_name = ANY($1)",
    indexes:
        "SELECT t.relname::text, i.relname::text, x.indisvalid, pg_get_indexdef(x.indexrelid) \
     FROM pg_index x \
     JOIN pg_class i ON i.oid = x.indexrelid \
     JOIN pg_class t ON t.oid = x.indrelid \
     JOIN pg_namespace n ON n.oid = t.relnamespace \
     WHERE n.nspname = $2 AND i.relname = ANY($1)",
};

static REGISTRY: OnceLock<Vec<Query>> = OnceLock::new();

pub fn registry() -> &'static [Query] {
    REGISTRY.get_or_init(|| parse(QUERIES))
}

/// Panics on an unknown name, which is a programming error.
pub fn query(name: &str) -> &'static Query {
    registry()
        .iter()
        .find(|q| q.name == name)
        .unwrap_or_else(|| panic!("unregistered query {name}"))
}

/// Every index named by a registered query. The table is the known table the
/// index name is prefixed with (`<Table>_...`, longest match over
/// `READER_TABLES` and `LEGACY_TABLES`), which is also the table the statement
/// reads it from; a join's driving `FROM` table can differ. A name matching
/// neither list panics: a typo or a new table must be added deliberately.
pub fn required_indexes() -> Vec<RequiredIndex> {
    let mut out: Vec<RequiredIndex> = Vec::new();
    for q in registry() {
        for &name in &q.index {
            if out.iter().any(|i| i.name == name) {
                continue;
            }
            let table = READER_TABLES
                .iter()
                .chain(LEGACY_TABLES)
                .copied()
                .filter(|t| name.strip_prefix(t).is_some_and(|r| r.starts_with('_')))
                .max_by_key(|t| t.len())
                .unwrap_or_else(|| panic!("index {name} of query {} names no known table", q.name));
            out.push(RequiredIndex { table, name });
        }
    }
    out
}

/// `required_indexes()` restricted to `READER_TABLES`: the set the Reader's
/// guard checks.
pub fn reader_required_indexes() -> Vec<RequiredIndex> {
    required_indexes()
        .into_iter()
        .filter(|i| READER_TABLES.contains(&i.table))
        .collect()
}

fn parse(text: &'static str) -> Vec<Query> {
    let mut blocks: Vec<&'static str> = Vec::new();
    let mut start = None;
    let mut pos = 0;
    for line in text.split_inclusive('\n') {
        if line.starts_with("-- name:") {
            if let Some(s) = start {
                blocks.push(&text[s..pos]);
            }
            start = Some(pos);
        }
        pos += line.len();
    }
    if let Some(s) = start {
        blocks.push(&text[s..]);
    }
    blocks.into_iter().map(parse_block).collect()
}

fn parse_block(block: &'static str) -> Query {
    let name = block
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("-- name:"))
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| panic!("query block without a name: {block:.40}"));
    let meta = |key: &str| -> Option<&'static str> {
        let prefix = format!("-- {key}:");
        block
            .lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .map(str::trim)
    };
    let list = |key: &str| -> Vec<&'static str> {
        meta(key)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    };
    let class = match meta("class") {
        Some("bridge") => QueryClass::Bridge,
        Some("interactive") => QueryClass::Interactive,
        Some("background") => QueryClass::Background,
        other => panic!("query {name}: bad class {other:?}"),
    };
    // The statement runs from the first non-comment line to the first `;`.
    let mut offset = 0;
    let mut body_start = None;
    for line in block.split_inclusive('\n') {
        if body_start.is_none() && !line.trim().is_empty() && !line.starts_with("--") {
            body_start = Some(offset);
            break;
        }
        offset += line.len();
    }
    let body_start = body_start.unwrap_or_else(|| panic!("query {name}: no SQL"));
    let body = &block[body_start..];
    let end = body
        .find(';')
        .unwrap_or_else(|| panic!("query {name}: no terminating ;"));
    Query {
        name,
        class,
        params: list("params"),
        index: list("index"),
        sql: body[..end].trim_end(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_parses_every_block_with_its_metadata() {
        let q = query("follow_deposits");
        assert_eq!(q.class, QueryClass::Background);
        assert_eq!(q.params, vec!["int4", "int4", "int8"]);
        assert_eq!(q.index, vec!["Deposit_chain_index_deposit_index"]);
        assert!(q.sql.trim_start().starts_with("SELECT"));
        assert!(!q.sql.contains("-- name:"));
    }

    #[test]
    fn every_placeholder_has_a_declared_param() {
        for q in registry() {
            let highest = (1..=9)
                .rev()
                .find(|n| q.sql.contains(&format!("${n}")))
                .unwrap_or(0);
            assert_eq!(highest, q.params.len(), "{}", q.name);
        }
    }

    #[test]
    fn the_reader_shapes_are_registered() {
        for name in [
            "follow_deposits",
            "follow_leaves",
            "follow_claims",
            "follow_batches",
            "tree_meta_all",
            "chain_progress",
            "envio_identity",
            "deposit_by_tx_hash",
            "withdrawal_claims_by_nullifier",
            "global_to_local_probe",
        ] {
            query(name);
        }
    }

    #[test]
    fn required_indexes_name_their_table() {
        let all = required_indexes();
        assert!(all.iter().any(|i| i.table == "WithdrawalClaim"
            && i.name == "WithdrawalClaim_chain_id_block_number_id"));
        assert!(all
            .iter()
            .any(|i| i.table == "AccountDepositStats" && i.name == "AccountDepositStats_pkey"));
    }

    #[test]
    fn reader_required_indexes_cover_only_reader_tables() {
        let all = reader_required_indexes();
        assert!(all.iter().all(|i| READER_TABLES.contains(&i.table)));
        assert!(!all.iter().any(|i| i.name == "AccountDepositStats_pkey"));
    }

    #[test]
    fn a_joined_index_is_attributed_to_its_own_table() {
        let all = required_indexes();
        assert!(all
            .iter()
            .any(|i| i.table == "DepositLeaf" && i.name == "DepositLeaf_pkey"));
    }

    #[test]
    fn the_role_script_grants_exactly_the_reader_tables() {
        for t in READER_TABLES {
            assert!(READER_ROLE_SQL.contains(&format!("\"{t}\"")), "{t}");
        }
        assert!(!READER_ROLE_SQL.contains("INSERT"));
    }
}
