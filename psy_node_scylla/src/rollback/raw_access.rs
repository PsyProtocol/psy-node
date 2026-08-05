//! Lexical guard for raw Scylla driver capabilities.
//!
//! This is intentionally conservative and exact-path based. It freezes the
//! G0-04b baseline while D-02T incrementally moves legacy adapters behind the
//! typed store. Adding a new raw `Session`, prepared statement, execution call,
//! or CQL literal requires an explicit allowlist review.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RawScyllaAccessScope {
    DriverCore,
    LegacyTableAdapter,
    RollbackPrototypeAdapter,
    GuardImplementation,
    TestHarness,
    Benchmark,
    Example,
    DeveloperTool,
    Scratchpad,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawScyllaAccessAllowance {
    pub path: &'static str,
    pub scope: RawScyllaAccessScope,
}

macro_rules! allow {
    ($path:literal, $scope:ident) => {
        RawScyllaAccessAllowance { path: $path, scope: RawScyllaAccessScope::$scope }
    };
}

/// Exact G0-04b raw-driver/CQL allowlist. There are deliberately no prefix,
/// suffix, glob, or default rules.
pub const RAW_SCYLLA_ACCESS_ALLOWLIST: &[RawScyllaAccessAllowance] = &[
    allow!("psy_cli/psy_dev_cli/src/subcommand/scylla_inspect.rs", DeveloperTool),
    allow!("psy_node_scylla/benches/bench_nodes.rs", Benchmark),
    allow!("psy_node_scylla/benches/merkle_double_id.rs", Benchmark),
    allow!("psy_node_scylla/benches/merkle_double_id_burst.rs", Benchmark),
    allow!("psy_node_scylla/benches/merkle_double_old.rs", Benchmark),
    allow!("psy_node_scylla/examples/page_test.rs", Example),
    allow!("psy_node_scylla/examples/page_test_nb2.rs", Example),
    allow!("psy_node_scylla/examples/page_test_no_bucket.rs", Example),
    allow!("psy_node_scylla/examples/page_test_nobucket.rs", Example),
    allow!("psy_node_scylla/examples/tst2.rs", Example),
    allow!("psy_node_scylla/examples/tst3.rs", Example),
    allow!("psy_node_scylla/examples/tst5.rs", Example),
    allow!("psy_node_scylla/examples/tst6.rs", Example),
    allow!("psy_node_scylla/examples/tst6_nobucket.rs", Example),
    allow!("psy_node_scylla/examples/tst7.rs", Example),
    allow!("psy_node_scylla/examples/tst7_nobucket.rs", Example),
    allow!("psy_node_scylla/src/core.rs", DriverCore),
    allow!("psy_node_scylla/src/core_db.rs", DriverCore),
    allow!("psy_node_scylla/src/rollback/canonical_head_prototype.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/confinement.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/namespace_prototype.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/raw_access.rs", GuardImplementation),
    allow!("psy_node_scylla/src/rollback/timestamp_prototype.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/table_creator.rs", DriverCore),
    allow!("psy_node_scylla/src/tables/blob.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/bridge/deposit_leaf.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/bridge/next_index.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/counter/u64_counter.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/hash_to_many_ids.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/imt/imt_key_index.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/imt/imt_leaf.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/imt/imt_next_append_index.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/double.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/gwz.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/nbzero.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/nzr1.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/oldv2zero.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/oldzero.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/ooozero.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/oqz.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/single.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/twzero.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/merkle/zero.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/object/double.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/object/kiv.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/object/single.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/tag_tree.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/traits.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/u64_table/u128_to_u64.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/u64_table/u64_to_u128.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/u64_table/u64_to_u64.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/u64_table/u64_u128_bidirectional.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/tables/u64_tbl.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/src/utils.rs", LegacyTableAdapter),
    allow!("psy_node_scylla/tests/rollback_confinement.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_namespace_prototype.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_namespace_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_timestamp_prototype.rs", TestHarness),
    allow!("psy_scratchpad/src/scylla/traits.rs", Scratchpad),
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawScyllaAccessCounts {
    pub session_type: usize,
    pub session_builder: usize,
    pub session_field_access: usize,
    pub prepared_statement: usize,
    pub prepare_call: usize,
    pub execute_call: usize,
    pub query_call: usize,
    pub direct_cql: usize,
}

impl RawScyllaAccessCounts {
    pub const fn is_empty(self) -> bool {
        self.session_type == 0
            && self.session_builder == 0
            && self.session_field_access == 0
            && self.prepared_statement == 0
            && self.prepare_call == 0
            && self.execute_call == 0
            && self.query_call == 0
            && self.direct_cql == 0
    }
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn count_word(source: &str, word: &str) -> usize {
    let source = source.as_bytes();
    let word = word.as_bytes();
    if word.is_empty() || source.len() < word.len() {
        return 0;
    }
    (0..=source.len() - word.len())
        .filter(|&start| {
            &source[start..start + word.len()] == word
                && (start == 0 || !is_word_byte(source[start - 1]))
                && (start + word.len() == source.len() || !is_word_byte(source[start + word.len()]))
        })
        .count()
}

fn count_fragments(source: &str, fragments: &[&str]) -> usize {
    fragments.iter().map(|fragment| source.matches(fragment).count()).sum()
}

fn count_member_access(source: &str, member: &str) -> usize {
    let needle = format!(".{member}");
    source
        .match_indices(&needle)
        .filter(|(start, _)| {
            let end = *start + needle.len();
            end == source.len() || !is_word_byte(source.as_bytes()[end])
        })
        .count()
}

/// Performs a deterministic lexical inventory. It does not attempt to parse
/// Rust; false positives are intentionally guarded rather than silently
/// ignored. CQL literals are counted only in the Scylla crate or in a source
/// file that explicitly refers to the Scylla driver.
pub fn inspect_raw_scylla_source(path: &str, source: &str) -> RawScyllaAccessCounts {
    let driver_context = path.starts_with("psy_node_scylla/") || source.contains("scylla::");
    let session_owner_context = driver_context || source.contains("ScyllaCoreStore");
    let session_field_access = if session_owner_context {
        count_member_access(source, "session") + source.matches("pub session:").count()
    } else {
        0
    };
    let specific_driver_call = count_fragments(
        source,
        &[
            ".prepare_batch(",
            ".execute_unpaged(",
            ".execute_iter(",
            ".execute_single_page(",
            ".execute_batch(",
            ".query_unpaged(",
            ".query_iter(",
            ".query_single_page(",
        ],
    ) + session_field_access;
    if !driver_context && specific_driver_call == 0 {
        return RawScyllaAccessCounts::default();
    }

    let direct_cql = if driver_context {
        count_fragments(
            source,
            &[
                "INSERT INTO",
                "DELETE FROM",
                "SELECT ",
                "UPDATE ",
                "CREATE TABLE",
                "CREATE KEYSPACE",
                "DROP TABLE",
                "DROP KEYSPACE",
                "ALTER TABLE",
            ],
        )
    } else {
        0
    };

    RawScyllaAccessCounts {
        session_type: if driver_context { count_word(source, "Session") } else { 0 },
        session_builder: if driver_context { count_word(source, "SessionBuilder") } else { 0 },
        session_field_access,
        prepared_statement: if driver_context { count_word(source, "PreparedStatement") } else { 0 },
        prepare_call: if driver_context {
            source.matches(".prepare(").count() + source.matches(".prepare_batch(").count()
        } else {
            0
        },
        execute_call: count_fragments(
            source,
            &[".execute_unpaged(", ".execute_iter(", ".execute_single_page(", ".execute_batch("],
        ),
        query_call: count_fragments(source, &[".query_unpaged(", ".query_iter(", ".query_single_page("]),
        direct_cql,
    }
}

pub fn raw_scylla_access_allowance(path: &str) -> Option<RawScyllaAccessAllowance> {
    RAW_SCYLLA_ACCESS_ALLOWLIST.iter().copied().find(|entry| entry.path == path)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawScyllaAccessViolation {
    pub path: String,
    pub counts: RawScyllaAccessCounts,
}

/// Fail-closed check used by the repository static guard.
pub fn require_raw_scylla_access_allowlisted(
    path: &str,
    source: &str,
) -> Result<RawScyllaAccessCounts, RawScyllaAccessViolation> {
    let counts = inspect_raw_scylla_source(path, source);
    if counts.is_empty() || raw_scylla_access_allowance(path).is_some() {
        Ok(counts)
    } else {
        Err(RawScyllaAccessViolation { path: path.to_owned(), counts })
    }
}
