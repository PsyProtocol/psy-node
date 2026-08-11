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
    CanonicalHeadAuthority,
    DurableControlAuthority,
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
    allow!("psy_node_scylla/src/psy_setup.rs", DriverCore),
    allow!("psy_node_scylla/src/rollback/authority_local_head_prototype.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/authority_timestamp_prototype.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/branch_exact_schema_backfill_executor.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_dual_write_executor.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_schema_exporter.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_schema_setup.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_schema_setup_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/src/rollback/branch_exact_startup_preflight.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/branch_exact_shadow_reader.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_shadow_audit.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/branch_exact_shadow_reader_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/src/rollback/branch_exact_pending_runtime.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/branch_exact_writer_lifecycle_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/branch_exact_writer_runtime.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_writer_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/src/rollback/branch_exact_cutover_runtime.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/branch_exact_cutover_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/branch_exact_schema_deployment.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_schema_deployment_lifecycle.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/branch_exact_schema_migration.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/canonical_head_prototype.rs", CanonicalHeadAuthority),
    allow!("psy_node_scylla/src/rollback/checkpoint_kiv.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/checkpoint_merkle.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/checkpoint_object_single.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/checkpoint_root_pair.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/public_key_projection.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/realm_imt_predecessor.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/realm_imt_predecessor_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/src/rollback/imt_family.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/manifest_prepared.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/mutable_singleton.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/pending_counter.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/pending_context.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/pending_generation_pipeline_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_artifact_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_consumer_gate.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_generation_terminal.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_segment_lifecycle.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_segment_ledger.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_stream_provision.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_semantic_aggregate.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_sidecar_lifecycle.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_sidecar_schema.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_queue_publish_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/pending_namespace_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/src/rollback/confinement.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/namespace_prototype.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/normal_state_replay_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/src/rollback/raw_access.rs", GuardImplementation),
    allow!("psy_node_scylla/src/rollback/realm_edge_durable_publisher.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_processor_application_archive.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_processor_deferred_carryover.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_processor_durable_capture.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_processor_generation_terminal.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_user_update_claim_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_user_update_admission_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_user_update_dependency_store.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_user_update_durable_consumer.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_user_update_ingress.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/realm_user_update_router.rs", DurableControlAuthority),
    allow!("psy_node_scylla/src/rollback/reward_tag_tree.rs", RollbackPrototypeAdapter),
    allow!("psy_node_scylla/src/rollback/rollback_admission.rs", DurableControlAuthority),
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
    allow!("psy_node_scylla/tests/rollback_authority_timestamp_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_branch_exact_backfill_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_branch_exact_exporter_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_branch_exact_deployment_lifecycle_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_branch_exact_schema_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_normal_commit_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_canonical_head_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_checkpoint_kiv.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_checkpoint_merkle.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_checkpoint_object_single.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_checkpoint_root_pair.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_public_key_projection.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_admission_inbox.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_admission_inbox_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_confinement.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_manifest_prepared.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_manifest_prepared_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_namespace_prototype.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_namespace_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_pending_counter.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_reward_tag_tree.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_rf3_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rollback_timestamp_prototype.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h22e_consumer_gate.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h22e2b_segment_lifecycle.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h22e3_cutover.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h23c4c1_queue_schema.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h23c4c2b3b2_claim_admission.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h23c4c2b4e3_edge_handler_ingress.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h23c4c2b4d2_stream_provision.rs", TestHarness),
    allow!("psy_node_scylla/tests/rf3/d04b6h23c4c4b2b_terminal_carryover.rs", TestHarness),
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
