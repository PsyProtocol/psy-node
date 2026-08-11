//! h23c4c2b4e3: production-shaped Realm Handler ingress on Scylla/NATS RF=3.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use async_nats::jetstream::{self, consumer::pull::Config as PullConfig, stream::Config as StreamConfig};
#[cfg(feature = "rf3-test-support")]
use parth_common::memory_stores::{
    dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore,
    mem_tree_recorder::SimpleMemoryMerkleRecorderStore,
    traits::PsyMemoryMerkleStoreImm,
};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey},
    felt::ToU64Value,
    node::realm_identifier::QRealmIdentifier,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{Q256BitHash, QNetworkTreeConstants, QNetworkTypesConfigHelper},
    PHash, PF,
};
use psy_core::{
    constants::chain_id::PsyChainNetworkType,
    job::job_id::QProvingJobDataID,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_data::{
    node::realm_processor::RealmProcessorCoreState,
    protocol::{
        canonical_chain::{CanonicalChainRef, CheckpointHash, CheckpointId, CheckpointRef},
        chain_context::{
            AuthorityObservation, AuthorityStateCheckpointId, AuthorityStateRoot,
            PendingContext, WorkProcCheckpointUniqueId, WorkUniquePendingId,
        },
    },
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::contract::{DashMapContractHeightCache, PSimpleContractHeightCache},
};
use psy_dummy_prover::{
    lite::user_state::{DPContractUpdate, DPLocalUser},
    traits::DummyUPSProver,
};
use psy_jtmb_testing_core::{
    circuit_library::core::{
        get_jtmb_circuit_library_and_prover_for_network,
        get_test_circuit_authority_key,
    },
    protocol_types::{JTMBPoseidonGoldilocksConfig, ZKTypesJTMBGoldilocksPoseidon},
    proof::PsyTestJTMBProof,
    proving::circuits::dummy_end_cap::DummyUPSStandardEndCapCircuit,
    zk_verifier::PsyJTMBZKVerifier,
};
use psy_node_common::realm::edge::{
    durable_user_update_artifact::DeterministicRealmUserUpdateArtifactFactory,
    handler::RealmEdgeHandler,
};
use psy_node_core::{
    file::memory_fs::SimpleMockMemoryFileSystem,
    psy_core_db::traits::full::{
        PsyNodeCheckpointObjectDatabaseWriter,
        PsyNodeCheckpointTreeDatabaseReader,
        PsyNodeCoreDatabaseBasicContractInfoStoreWriter,
    },
    psy_temp_db::QTempDBPendingContextWriter,
    queue::{
        realm_processor_actor_input::{
            RealmProcessorActorInput, RealmProcessorActorInputDigest,
        },
        realm_user_update_artifact::VerifiedRealmUserUpdateRequest,
        realm_user_update_admission::{
            RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
        },
        realm_user_update_claim::{
            RealmUserUpdateClaimBucket, RealmUserUpdateClaimPartition,
            RealmUserUpdateClaimPhase, RealmUserUpdateCreatedAtSeconds,
            StoredRealmUserUpdateClaim,
        },
        realm_user_update_dependency::{
            RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyKind,
            RealmUserUpdateDependencyWriteTimestampUs,
        },
        realm_user_update_ingress::{
            seal_realm_user_update_ingress_artifacts,
            RealmUserUpdateArtifactFactory, RealmUserUpdateIngressError,
        },
        realm_user_update_publish::{
            GlobalUserTreeHeight, RealmUserUpdatePublishAdmission,
        },
        realm_user_update_verifier_profile::{
            RealmUserUpdateVerifierProfile, RealmUserUpdateVerifierRegistry,
        },
        realm_processor_durable_capture::RealmProcessorDurableCaptureOutcome,
        realm_processor_deferred_actor_input::{
            RealmProcessorDeferredActorInput,
            RealmProcessorDeferredActorInputOutcome,
        },
        realm_processor_continuation_restart::RealmProcessorTerminalCarryoverRecoveryOutcome,
        realm_processor_generation_continuation::RealmProcessorGenerationContinuationPhase,
        realm_processor_generation_terminal::{
            RealmProcessorDeferredCarryover, RealmProcessorGenerationTerminal,
        },
        realm_processor_terminal_authorization::RealmProcessorTerminalAuthorizationEnvelope,
        realm_processor_application_archive::{
            RealmProcessorApplicationArchiveBinding,
            RealmProcessorApplicationArchivePlan,
        },
        realm_processor_semantic_output::{
            RealmProcessorDeferredJob, RealmProcessorSemanticOutput,
            RealmProcessorSemanticOutputParts,
        },
        recoverable_ephemeral::PendingQueueCaptureContext,
    },
    store::{
        authority_commit::AuthorityTimestampKey,
        authority_local_head::{
            AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
            AuthorityLocalHeadReadState, AuthorityLocalHeadWriteOutcome,
            AuthorityStorageBindingGeneration, AuthorityStorageBindingRef,
            AuthorityStorageNamespaceId, SealedAuthorityLocalHeadCas,
        },
        manifest_lifecycle::AuthorityHeadView,
        manifest_record::AuthorityManifestDigest,
        pending_generation::{ProcNamespacePrefix, ReservedPendingGeneration},
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
            PendingGenerationContext, PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingEmptyQueueSealDigest, PendingNoWorkReceiptDigest,
            PendingPipelineBootstrap, PendingPipelineIntentDigest,
            PendingPipelineWriteOutcome, PendingPublishReceiptDigest,
            PendingQueueCloseIntentDigest, PendingWorkCaptureDigest,
            StoredPendingPipeline,
        },
        realm_processor_branch_exact_runtime::{
            RealmBranchExactCommitRuntimeInstaller,
            RealmBranchExactSingleCommitOwner,
        },
        realm_processor_quiescence::RealmProcessorIterationGate,
        realm_processor_startup::{
            authorize_realm_processor_startup,
            RealmProcessorStartupAuthorization, RealmProcessorStartupLineage,
            RealmProcessorStartupMode,
        },
        typed::UniquePendingId,
    },
};
use psy_node_store_memory::temp_store::InMemoryTempStore;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::PendingQueueSegmentLedgerBootstrap,
    recoverable_publish::{
        PendingQueueGenerationBudgetContract, PendingQueuePublishIntentId,
        PendingQueuePublisherKind, PendingQueueSourceQuota,
    },
    recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
        RecoverableNatsStreamSegment,
    },
};
use scylla::{client::session::Session, statement::Consistency};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout};
#[cfg(feature = "rf3-test-support")]
use tokio::sync::oneshot;

use crate::psy_setup::{
    setup_psy_scylla_database_store, setup_realm_edge_scylla_startup_composition,
    ScyllaUnifiedPsyStore,
};

#[cfg(feature = "rf3-test-support")]
use psy_node_common::{
    constants::queue::PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    queue::gatherer::EphemeralQueueGathererWithTree,
    realm::processor::{
        core::qualification_project_branch_exact_semantic_output,
        gatherers::realm_end_cap_gatherer::{
            qualification_finish_realm_deferred_actor_trace,
            qualification_start_realm_deferred_actor_trace,
            RealmDeferredActorTraceKind, RealmGUTAEndCapGatherer,
            RealmGUTAEndCapGathererConfig, RealmGUTAEndCapGathererOutput,
        },
    },
    utils::processor_status::ProcessorStatus,
};

use super::{
    branch_exact_shadow_reader_rf3_gate as fixture,
    pending_queue_stream_provision::ScyllaPendingQueueStreamProvisionStore,
    pending_queue_segment_lifecycle_rf3 as realm_fixture, *,
    realm_processor_application_archive::ScyllaRealmProcessorApplicationArchiveStore,
    realm_processor_deferred_carryover::{
        RealmProcessorDeferredCarryoverStoreError,
        ScyllaRealmProcessorDeferredCarryoverStore,
        REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
    },
    realm_processor_generation_terminal::{
        ScyllaRealmProcessorGenerationTerminalStore,
        REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
    },
    realm_processor_external_dependency_projection::ScyllaRealmProcessorExternalDependencyProjector,
};
#[cfg(feature = "rf3-test-support")]
use super::realm_processor_durable_capture::{
    qualification_fail_after_carryover_persist_once,
    qualification_pause_after_recovery_snapshot_a_once,
    qualification_release_recovery_snapshot_a,
    qualification_wait_for_recovery_snapshot_a,
};

type N = QNetworkTypesConfigHelper<
    QProvingJobDataID,
    ZKTypesJTMBGoldilocksPoseidon,
    PsyNetworkLocalDevnetConstants,
>;
type Verifier = PsyJTMBZKVerifier<JTMBPoseidonGoldilocksConfig>;

const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const REALM_ID: u32 = 7;
const REALM_SUB_ID: u16 = 2;
const CONTRACT_ID: u32 = 41;
const CONTRACT_HEIGHT: u8 = 8;

#[derive(Debug, Serialize)]
struct E3Report {
    scylla_image: &'static str,
    scylla_replication_factor: u8,
    configured_nats_servers: u8,
    nats_stream_replicas: u8,
    nats_kv_replicas: u8,
    nats_kv_replica_mismatch_rejected: bool,
    real_realm_edge_handler: bool,
    jtmb_cli_profile_matched: bool,
    production_jtmb_zk_proof: bool,
    startup_route_attested: bool,
    invalid_pi_created_no_rows: bool,
    invalid_pi_nats_delta: u64,
    planned_pointer_zero_fragment_replay: bool,
    planned_pointer_replay_messages: u64,
    scylla_one_replica_offline: bool,
    concurrent_valid_attempts: u8,
    concurrent_valid_single_publish: bool,
    first_publish_messages: u64,
    response_loss_retry_messages: u64,
    nats_leader_before: String,
    nats_leader_after: String,
    nats_leader_failover: bool,
    nats_surviving_follower_current_lag_zero: bool,
    nats_message_envelope_count: u64,
    nats_message_envelope_dataset_digest: String,
    deferred_actor_nats_message_count_before: u64,
    deferred_actor_nats_message_count_after: u64,
    deferred_actor_nats_duplicate_delta: u64,
    second_publish_messages: u64,
    startup_restart_attested: bool,
    restart_retry_messages: u64,
    dependency_explicit_timestamp_verified: bool,
    repair_ms: u128,
    repair_direct_one_tables: usize,
    repair_direct_one_equal: bool,
    durable_capture_owner_tested: bool,
    durable_capture_items: u64,
    durable_capture_empty_poll_not_close: bool,
    durable_generation_replayed: bool,
    durable_generation_items: u64,
    durable_generation_digest_stable: bool,
    gather_task_restart_replayed: bool,
    processor_route_compiled: bool,
    command_only_with_tree_compiled: bool,
    processor_gatherer_integrated: bool,
    processor_gatherer_rf3_runtime: bool,
    semantic_handoff_integrated: bool,
    application_archive_data_rf3: bool,
    application_semantic_bytes: usize,
    application_fragments: u32,
    application_pipeline_revision: u64,
    application_restart_recovered: bool,
    fresh_source_assignment_close: bool,
    first_pipeline_cas: bool,
    missing_extra_corrupt_rf3: bool,
    affine_terminal_carryover_recovery: bool,
    qualification_seeded_terminal: bool,
    inbound_missing_zero_write: bool,
    nonterminal_zero_write: bool,
    terminal_absent_zero_write: bool,
    terminal_only_repaired: bool,
    post_persist_failure_recovered: bool,
    already_complete_recovered: bool,
    affine_retry_count: usize,
    derived_same_retry_count: usize,
    derived_different_contender_conflict: bool,
    application_toctou_rejected: bool,
    terminal_recovery_pipeline_unchanged: bool,
    terminal_recovery_nats_delta: u64,
    terminal_recovery_socket_response_loss_injected: bool,
    sidecar_v14_rf3_inherited: bool,
    v14_ready_receipt_consumed: bool,
    qualification_constructed_predecessor_semantic: bool,
    predecessor_nonempty_input_rf3: bool,
    predecessor_deferred_count: u32,
    explicit_empty_input_rf3: bool,
    explicit_empty_reason: &'static str,
    predecessor_zero_input_rf3: bool,
    external_generation_nonempty_rf3: bool,
    external_generation_items: u64,
    deferred_before_external_rf3: bool,
    ordered_actor_trace_digest: String,
    fresh_c_fault_rf3: bool,
    fresh_c_nats_delta: u64,
    fresh_d_fault_rf3: bool,
    fresh_d_actor_delta: u64,
    apply_retry_bit_exact: bool,
    finalize_retry_bit_exact: bool,
    different_input_rejected: bool,
    actor_builder_create_count: u64,
    actor_finalize_count: u64,
    semantic_v3_input_bound: bool,
    successor_application_semantic_bytes: usize,
    successor_application_fragments: u32,
    application_archive_handoff_rf3: bool,
    handoff_recovery_without_actor_rerun: bool,
    successor_handoff_revision: u64,
    actor_handoff_during_one_replica_offline: bool,
    qualification_temp_dependency_hydration: bool,
    production_external_dependency_projection: bool,
    deferred_input_rf3: bool,
    actor_retry_socket_response_loss_injected: bool,
    full_processor_rf3_runtime: bool,
    all_20_target_business_rows_qualified: bool,
    repair_direct_one_table_names: Vec<String>,
    repair_direct_one_rows: usize,
    repair_direct_one_dataset_digest: String,
    generation_terminal_integrated: bool,
    production_terminal_mint: bool,
    writer_head_provenance_verified: bool,
    terminal_authorization_qualified: bool,
    processor_recovery_invocation: bool,
    production_terminal_transition: bool,
    production_pipeline_rotation: bool,
    carryover_replay: bool,
    successor_actor_injection: bool,
    proof_publish: bool,
    mapping_reward_writer_integrated: bool,
    full_22_domain_writer: bool,
    production_writer_integrated: bool,
    authority_head_publish_integrated: bool,
    full_node_restart_tested: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    qualification: &'static str,
}

const CONTROL_DIRECT_ONE_TABLES: &[&str] = &[
    "branch_exact_schema_deployment_lifecycle",
    "branch_exact_shadow_audit_v1",
    "branch_exact_writer_lifecycle_v1",
    "branch_exact_cutover_lifecycle_v1",
    "d04a_authority_timestamp_intent",
    "d04b_authority_local_head",
    "branch_exact_pending_pipeline_v2",
    "branch_exact_pending_queue_sidecar_lifecycle_v1",
    "branch_exact_pending_queue_segment_ledger_v1",
    "branch_exact_pending_queue_stream_provision_binding_v1",
    "branch_exact_realm_user_update_admission_v1",
    "branch_exact_realm_user_update_claim_v2",
    "branch_exact_pending_queue_publish_source_v1",
    "branch_exact_pending_queue_publish_intent_v1",
    "branch_exact_pending_queue_publish_prepared_v1",
];

const DATA_DIRECT_ONE_TABLES: &[&str] = &[
    "branch_exact_realm_user_update_dependency_fragment_v1",
    "branch_exact_pending_queue_publish_payload_fragment_v1",
];

const DURABLE_REPLAY_CONTROL_TABLES: &[&str] = &[
    "branch_exact_pending_queue_artifact_header",
    "branch_exact_pending_queue_consumer_gate_v1",
];

const DURABLE_REPLAY_DATA_TABLES: &[&str] = &[
    "branch_exact_pending_queue_artifact_fragment",
];

const APPLICATION_HANDOFF_CONTROL_TABLES: &[&str] = &[
    "branch_exact_pending_queue_semantic_generation_v2",
    "branch_exact_realm_application_archive_header_v1",
];

const APPLICATION_HANDOFF_DATA_TABLES: &[&str] = &[
    "branch_exact_realm_application_archive_fragment_v1",
];

const TERMINAL_RECOVERY_CONTROL_TABLES: &[&str] = &[
    REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
    REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
];

const HANDLER_MUTATION_CONTROL_TABLES: &[&str] = &[
    "branch_exact_realm_user_update_admission_v1",
    "branch_exact_realm_user_update_claim_v2",
    "branch_exact_pending_queue_publish_source_v1",
    "branch_exact_pending_queue_publish_intent_v1",
    "branch_exact_pending_queue_publish_prepared_v1",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct PhysicalSnapshot(BTreeMap<String, BTreeSet<String>>);

impl PhysicalSnapshot {
    fn row_count(&self, keyspace: &str, table: &str) -> anyhow::Result<usize> {
        self.0
            .get(&format!("{keyspace}.{table}"))
            .map(BTreeSet::len)
            .ok_or_else(|| anyhow::anyhow!("snapshot is missing {keyspace}.{table}"))
    }

    fn table_names(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    fn total_rows(&self) -> usize {
        self.0.values().map(BTreeSet::len).sum()
    }

    fn dataset_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"psy/rf3/d04b6h23c4c2b4e3/direct-one-dataset/v1");
        for (table, rows) in &self.0 {
            hasher.update((table.len() as u64).to_be_bytes());
            hasher.update(table.as_bytes());
            hasher.update((rows.len() as u64).to_be_bytes());
            for row in rows {
                hasher.update((row.len() as u64).to_be_bytes());
                hasher.update(row.as_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }
}

async fn snapshot_tables(
    session: &Session,
    control_tables: &[&str],
    data_tables: &[&str],
) -> anyhow::Result<PhysicalSnapshot> {
    let mut snapshot = BTreeMap::new();
    for (keyspace, tables) in [
        (fixture::control_keyspace(), control_tables),
        (fixture::KEYSPACE.to_owned(), data_tables),
    ] {
        for table in tables {
            let select = if *table
                == "branch_exact_realm_user_update_dependency_fragment_v1"
            {
                format!(
                    "SELECT JSON dependency_slot, dependency_digest, component_kind, fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest, WRITETIME(payload) AS payload_write_timestamp_us FROM {keyspace}.{table}"
                )
            } else {
                format!("SELECT JSON * FROM {keyspace}.{table}")
            };
            let rows = session
                .query_unpaged(select, ())
                .await?
                .into_rows_result()?;
            let mut values = BTreeSet::new();
            for row in rows.rows::<(String,)>()? {
                values.insert(row?.0);
            }
            let previous = snapshot.insert(format!("{keyspace}.{table}"), values);
            ensure!(previous.is_none(), "duplicate snapshot table {keyspace}.{table}");
        }
    }
    Ok(PhysicalSnapshot(snapshot))
}

async fn handler_mutation_snapshot(session: &Session) -> anyhow::Result<PhysicalSnapshot> {
    snapshot_tables(
        session,
        HANDLER_MUTATION_CONTROL_TABLES,
        DATA_DIRECT_ONE_TABLES,
    )
    .await
}

async fn direct_one_snapshot(
    ip: std::net::Ipv4Addr,
    include_durable_replay: bool,
    include_application_handoff: bool,
    include_terminal_recovery: bool,
) -> anyhow::Result<PhysicalSnapshot> {
    let session = fixture::connect(Some(ip), Consistency::One).await?;
    let mut control = CONTROL_DIRECT_ONE_TABLES.to_vec();
    let mut data = DATA_DIRECT_ONE_TABLES.to_vec();
    if include_durable_replay {
        control.extend_from_slice(DURABLE_REPLAY_CONTROL_TABLES);
        data.extend_from_slice(DURABLE_REPLAY_DATA_TABLES);
    }
    if include_application_handoff {
        control.extend_from_slice(APPLICATION_HANDOFF_CONTROL_TABLES);
        data.extend_from_slice(APPLICATION_HANDOFF_DATA_TABLES);
    }
    if include_terminal_recovery {
        control.extend_from_slice(TERMINAL_RECOVERY_CONTROL_TABLES);
    }
    snapshot_tables(&session, &control, &data).await
}

async fn terminal_recovery_snapshot(session: &Session) -> anyhow::Result<PhysicalSnapshot> {
    let mut control = CONTROL_DIRECT_ONE_TABLES.to_vec();
    control.extend_from_slice(DURABLE_REPLAY_CONTROL_TABLES);
    control.extend_from_slice(APPLICATION_HANDOFF_CONTROL_TABLES);
    control.extend_from_slice(TERMINAL_RECOVERY_CONTROL_TABLES);
    let mut data = DATA_DIRECT_ONE_TABLES.to_vec();
    data.extend_from_slice(DURABLE_REPLAY_DATA_TABLES);
    data.extend_from_slice(APPLICATION_HANDOFF_DATA_TABLES);
    snapshot_tables(session, &control, &data).await
}

async fn dependency_timestamps_match_durable_claims(
    session: &Session,
    claims: &ScyllaRealmUserUpdateClaimStore,
    captures: &[PendingQueueCaptureContext],
) -> anyhow::Result<bool> {
    let mut expected = BTreeMap::new();
    for capture in captures {
        for bucket in 0..RealmUserUpdateClaimBucket::COUNT {
            let partition = RealmUserUpdateClaimPartition::try_new(
                *capture,
                RealmUserUpdateClaimBucket::try_new(bucket)?,
            )?;
            for claim in claims.scan_bucket::<PHash>(partition).await? {
                ensure!(
                    claim.phase() == RealmUserUpdateClaimPhase::Published,
                    "durable Handler claim did not reach Published"
                );
                let digest = claim.dependency_digest().ok_or_else(|| {
                    anyhow::anyhow!("published Handler claim is missing dependency digest")
                })?;
                let timestamp = RealmUserUpdateDependencyWriteTimestampUs::derive(
                    claim.slot(),
                    digest,
                    claim.created_at().get(),
                );
                let previous = expected.insert(
                    (claim.slot().as_bytes().to_vec(), digest.as_bytes().to_vec()),
                    timestamp.as_i64(),
                );
                ensure!(previous.is_none(), "duplicate durable claim dependency identity");
            }
        }
    }
    let expected_claims = captures
        .len()
        .checked_mul(3)
        .ok_or_else(|| anyhow::anyhow!("dependency claim count overflow"))?;
    ensure!(
        expected.len() == expected_claims,
        "expected {expected_claims} published Handler claims, found {}",
        expected.len()
    );
    let rows = session
        .query_unpaged(
            format!(
                "SELECT dependency_slot, dependency_digest, WRITETIME(payload) FROM {}.branch_exact_realm_user_update_dependency_fragment_v1",
                fixture::KEYSPACE,
            ),
            (),
        )
        .await?
        .into_rows_result()?;
    let mut observed = BTreeSet::new();
    for row in rows.rows::<(Vec<u8>, Vec<u8>, Option<i64>)>()? {
        let (slot, digest, timestamp) = row?;
        let timestamp = timestamp.ok_or_else(|| {
            anyhow::anyhow!("dependency payload is missing an explicit write timestamp")
        })?;
        let key = (slot, digest);
        let expected_timestamp = expected.get(&key).ok_or_else(|| {
            anyhow::anyhow!("dependency row has no matching durable claim")
        })?;
        ensure!(
            timestamp == *expected_timestamp,
            "dependency writetime {timestamp} does not match sealed claim timestamp {expected_timestamp}"
        );
        observed.insert(key);
    }
    Ok(observed.len() == expected.len()
        && expected.keys().all(|key| observed.contains(key)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QualificationJobMaterial {
    user_id: u64,
    queue_item: Vec<u8>,
    contract_updates: Vec<u8>,
}

async fn read_published_job_materials(
    session: Arc<Session>,
    claims: &ScyllaRealmUserUpdateClaimStore,
    capture: PendingQueueCaptureContext,
    selected_users: &BTreeSet<u64>,
) -> anyhow::Result<Vec<QualificationJobMaterial>> {
    let dependencies = ScyllaRealmUserUpdateDependencyStore::prepare(
        session,
        PendingQueueArtifactDataKeyspace::try_new(fixture::KEYSPACE)?,
    )
    .await?;
    let mut selected = BTreeMap::new();
    for bucket in 0..RealmUserUpdateClaimBucket::COUNT {
        let partition = RealmUserUpdateClaimPartition::try_new(
            capture,
            RealmUserUpdateClaimBucket::try_new(bucket)?,
        )?;
        for claim in claims.scan_bucket::<PHash>(partition).await? {
            if !selected_users.contains(&claim.user_id().get()) {
                continue;
            }
            ensure!(
                claim.phase() == RealmUserUpdateClaimPhase::Published,
                "selected qualification claim is not Published",
            );
            let dependency_digest = claim.dependency_digest().ok_or_else(|| {
                anyhow::anyhow!("selected Published claim has no dependency digest")
            })?;
            let bundle = dependencies
                .read_bundle(
                    claim.slot(),
                    *claim.request_digest().as_bytes(),
                    claim.stable_status(),
                    claim.created_at().get(),
                    dependency_digest,
                )
                .await?;
            let queue_item = bundle
                .component(RealmUserUpdateDependencyKind::QueuePayload)
                .bytes()
                .to_vec();
            let contract_updates = bundle
                .component(RealmUserUpdateDependencyKind::ContractUpdates)
                .bytes()
                .to_vec();
            ensure!(!contract_updates.is_empty());
            let decoded = PsyRealmUserUpdateQueueItem::<PF, PHash>::psy_ser_from_slice(
                &queue_item,
            )?;
            ensure!(
                decoded.psy_ser_to_bytes_vec()? == queue_item,
                "selected queue item is not canonical",
            );
            ensure!(decoded.new_user_leaf.user_id.to_u64_value() == claim.user_id().get());
            ensure!(
                selected
                    .insert(
                        claim.user_id().get(),
                        QualificationJobMaterial {
                            user_id: claim.user_id().get(),
                            queue_item,
                            contract_updates,
                        },
                    )
                    .is_none(),
                "duplicate selected Published claim",
            );
        }
    }
    ensure!(
        selected.len() == selected_users.len(),
        "selected {} of {} qualification jobs",
        selected.len(),
        selected_users.len(),
    );
    Ok(selected.into_values().collect())
}

fn deferred_jobs_from_materials(
    materials: &[QualificationJobMaterial],
) -> anyhow::Result<Vec<RealmProcessorDeferredJob>> {
    materials
        .iter()
        .enumerate()
        .map(|(ordinal, material)| {
            RealmProcessorDeferredJob::try_new(
                u32::try_from(ordinal)?,
                material.queue_item.clone(),
                material.contract_updates.clone(),
            )
            .map_err(anyhow::Error::from)
        })
        .collect()
}

#[cfg(feature = "rf3-test-support")]
type QualificationRealmActor = EphemeralQueueGathererWithTree<
    PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    PsyRealmUserUpdateQueueItem<PF, PHash>,
    RealmGUTAEndCapGathererOutput<PF, PHash, QProvingJobDataID>,
>;

#[cfg(feature = "rf3-test-support")]
async fn start_qualification_realm_actor(
    context: PendingQueueCaptureContext,
    chain: CanonicalChainRef<PHash>,
    checkpoint_id: u64,
) -> anyhow::Result<(
    QualificationRealmActor,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    Arc<InMemoryTempStore>,
    RealmProcessorCoreState<PHash>,
)> {
    let authority = context.key().authority();
    ensure!(
        authority
            == psy_data::protocol::chain_context::AuthorityScope::Realm {
                realm_id: REALM_ID,
                realm_sub_id: REALM_SUB_ID,
            }
    );
    let realm_identifier = QRealmIdentifier::new(REALM_ID, REALM_SUB_ID);
    let processing = context.processing();
    let temp = Arc::new(InMemoryTempStore::new(
        "h23c4c4b4c2-actor".to_owned(),
        u64::from(REALM_ID),
        u64::from(REALM_SUB_ID),
    ));
    let pending_context = PendingContext::new(
        chain,
        authority,
        WorkUniquePendingId::new(processing.pending_id().get()),
        WorkProcCheckpointUniqueId::from_u128(
            processing.proc_checkpoint_id().as_u128(),
        ),
    );
    temp.set_current_pending_context(&realm_identifier, &pending_context)
        .await?;

    let checkpoint_tree = Arc::new(
        PsyDashMemoryAppendOnlyMerkleStore::<PoseidonHasher, PHash>::new(
            N::CHECKPOINT_TREE_HEIGHT,
        ),
    );
    for index in 0..=checkpoint_id {
        checkpoint_tree.append_leaf(
            index,
            PHash::from_owned_32bytes([
                u8::try_from(index & 0xFF)?;
                32
            ]),
        )?;
    }
    let global_tree =
        SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PHash>::new(
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
        );
    let realm_start_root = global_tree.get_root();
    let checkpoint_root = checkpoint_tree.get_root();
    let mut state = RealmProcessorCoreState::new_basic(
        context.key().network().chain_id(),
        realm_identifier,
        checkpoint_id,
        processing.pending_id().get(),
        processing.proc_checkpoint_id().as_u128(),
        checkpoint_root,
        realm_start_root,
    );
    state.processing_checkpoint_id = checkpoint_id;
    state.processing_unique_pending_id = processing.pending_id().get();
    state.processing_proc_checkpoint_unique_id =
        processing.proc_checkpoint_id().as_u128();
    state.processing_checkpoint_root = checkpoint_root;
    state.processing_realm_start_root = realm_start_root;
    state.gathering_checkpoint_id = checkpoint_id;
    state.gathering_unique_pending_id = processing.pending_id().get();
    state.gathering_proc_checkpoint_unique_id =
        processing.proc_checkpoint_id().as_u128();
    state.gathering_checkpoint_root = checkpoint_root;
    state.gathering_realm_start_root = realm_start_root;

    let config = RealmGUTAEndCapGathererConfig::<
        N,
        InMemoryTempStore,
        SimpleMockMemoryFileSystem,
    > {
        realm_id_u64: u64::from(REALM_ID),
        realm_sub_id_u64: u64::from(REALM_SUB_ID),
        status: Arc::new(RwLock::new(state.clone())),
        temp_db: Arc::clone(&temp),
        file_system: Arc::new(SimpleMockMemoryFileSystem::new()),
        backup_file_directory: "/h23c4c4b4c2".to_owned(),
        coordinator_guta_updates_circuit_whitelist:
            PHash::from_owned_32bytes([0xD7; 32]),
        checkpoint_tree,
        future_pending_end_cap_jobs: Arc::new(RwLock::new(Vec::new())),
        durable_external_dependencies: None,
        _phantom_n: std::marker::PhantomData,
    };
    let queue_key = QPStandardUniqueIdQueueKey {
        realm_id: u64::from(REALM_ID),
        realm_sub_id: u64::from(REALM_SUB_ID),
        unique_id: processing.proc_checkpoint_id().as_u128(),
        task_group: 0,
        queue_type: QPBaseQueueType::StandardEphemeral,
        _phantom_queue_item: std::marker::PhantomData,
    };
    let status = ProcessorStatus::new();
    status.mark_running();
    let (actor, task) = QualificationRealmActor::new_durable_with_status::<
        RealmGUTAEndCapGathererConfig<
            N,
            InMemoryTempStore,
            SimpleMockMemoryFileSystem,
        >,
        PHash,
        PoseidonHasher,
        RealmGUTAEndCapGatherer<
            N,
            InMemoryTempStore,
            SimpleMockMemoryFileSystem,
        >,
    >(config, queue_key, global_tree, status);
    Ok((actor, task, temp, state))
}

#[cfg(feature = "rf3-test-support")]
async fn qualification_read_application_fragment(
    session: &Session,
    archive_slot: &[u8],
    semantic_digest: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let table = format!(
        "{}.branch_exact_realm_application_archive_fragment_v1",
        fixture::KEYSPACE,
    );
    Ok(session
        .query_unpaged(
            format!(
                "SELECT payload FROM {table} WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?"
            ),
            (archive_slot, semantic_digest, 0_i64, 0_i32),
        )
        .await?
        .into_rows_result()?
        .single_row::<(Vec<u8>,)>()?
        .0)
}

#[cfg(feature = "rf3-test-support")]
async fn qualification_write_application_fragment(
    session: &Session,
    archive_slot: &[u8],
    semantic_digest: &[u8],
    payload: &[u8],
) -> anyhow::Result<()> {
    let table = format!(
        "{}.branch_exact_realm_application_archive_fragment_v1",
        fixture::KEYSPACE,
    );
    session
        .query_unpaged(
            format!(
                "UPDATE {table} SET payload = ? WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?"
            ),
            (payload, archive_slot, semantic_digest, 0_i64, 0_i32),
        )
        .await?;
    Ok(())
}

fn current_pipeline(
    outcome: PendingPipelineWriteOutcome<PHash>,
) -> anyhow::Result<StoredPendingPipeline<PHash>> {
    match outcome {
        PendingPipelineWriteOutcome::Applied(current)
        | PendingPipelineWriteOutcome::Idempotent(current) => Ok(current),
        PendingPipelineWriteOutcome::Conflict(current) => {
            bail!("pending pipeline conflict at revision {}", current.revision().get())
        }
    }
}

fn next_terminal_observation(
    previous: &AuthorityObservation<PHash>,
    marker: u8,
) -> anyhow::Result<AuthorityObservation<PHash>> {
    let checkpoint_id = previous
        .chain()
        .checkpoint()
        .checkpoint_id()
        .get()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("terminal checkpoint overflow"))?;
    let chain = CanonicalChainRef::new(
        previous.chain().network_id(),
        previous.chain().chain_epoch(),
        CheckpointRef::new(
            CheckpointId::new(checkpoint_id),
            CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                marker;
                32
            ])),
        ),
    );
    Ok(AuthorityObservation::try_new(
        chain,
        previous.authority(),
        AuthorityStateCheckpointId::new(checkpoint_id),
        AuthorityStateRoot::from_local_state_root(PHash::from_owned_32bytes([
            marker.wrapping_add(1);
            32
        ])),
    )?)
}

fn current_cutover(
    outcome: BranchExactCutoverWriteOutcome<PHash>,
) -> anyhow::Result<StoredBranchExactCutover<PHash>> {
    match outcome {
        BranchExactCutoverWriteOutcome::Applied(current)
        | BranchExactCutoverWriteOutcome::Idempotent(current) => Ok(current),
        BranchExactCutoverWriteOutcome::Conflict(current) => {
            bail!("cutover conflict at revision {}", current.revision().get())
        }
    }
}

fn current_claim(
    outcome: RealmUserUpdateClaimWriteOutcome<PHash>,
) -> anyhow::Result<StoredRealmUserUpdateClaim<PHash>> {
    match outcome {
        RealmUserUpdateClaimWriteOutcome::Applied(receipt)
        | RealmUserUpdateClaimWriteOutcome::Resumed(receipt) => {
            Ok(receipt.current().clone())
        }
        RealmUserUpdateClaimWriteOutcome::Conflict(current) => {
            bail!("claim conflict at revision {}", current.revision().get())
        }
    }
}

fn retention() -> anyhow::Result<RecoverableNatsRetentionContract> {
    Ok(RecoverableNatsRetentionContract::try_new(
        3,
        512 * 1024 * 1024,
        128 * 1024 * 1024,
        3,
        16,
    )?)
}

fn generation_budget() -> anyhow::Result<PendingQueueGenerationBudgetContract> {
    let mib = 1024 * 1024_u64;
    Ok(PendingQueueGenerationBudgetContract::try_new(
        fixture::authority(),
        vec![PendingQueueSourceQuota::try_new(
            PendingQueuePublisherKind::RealmUserUpdate,
            1_000,
            127 * mib,
            mib,
        )?],
        128 * mib,
    )?)
}

async fn wait_for_stream_leader(
    context: &jetstream::Context,
    stream_name: &str,
    excluded: Option<&str>,
) -> anyhow::Result<String> {
    // Before terminating the original leader, require both followers to be
    // current.  After failover, require the surviving follower to be current
    // with the newly elected leader.  Merely observing a different leader can
    // race replica catch-up and briefly expose a leader without write quorum.
    let required_current_replicas = if excluded.is_some() { 1 } else { 2 };
    let mut stable_leader = None;
    let mut stable_observations = 0_u8;
    for _ in 0..180 {
        if let Ok(stream) = context.get_stream(stream_name).await {
            if let Ok(info) = stream.get_info().await {
                if let Some(cluster) = info.cluster {
                    if let Some(leader) = cluster.leader {
                        let current_replicas = cluster
                            .replicas
                            .iter()
                            .filter(|replica| {
                                replica.current
                                    && !replica.offline
                                    && replica.lag.unwrap_or_default() == 0
                            })
                            .count();
                        if excluded != Some(leader.as_str())
                            && current_replicas >= required_current_replicas
                        {
                            if stable_leader.as_deref() == Some(leader.as_str()) {
                                stable_observations += 1;
                            } else {
                                stable_leader = Some(leader.clone());
                                stable_observations = 1;
                            }
                            if stable_observations >= 5 {
                                return Ok(leader);
                            }
                        } else {
                            stable_leader = None;
                            stable_observations = 0;
                        }
                    }
                }
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
    bail!("stream did not reach stable leader/quorum readiness")
}

fn terminate_nats_leader(server_name: &str) -> anyhow::Result<()> {
    let variable = match server_name {
        "psy-h23e3-n1" => "PSY_D04B6H23C4C2B4E3_NATS1_PID",
        "psy-h23e3-n2" => "PSY_D04B6H23C4C2B4E3_NATS2_PID",
        "psy-h23e3-n3" => "PSY_D04B6H23C4C2B4E3_NATS3_PID",
        other => bail!("unexpected NATS leader {other}"),
    };
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(std::env::var(variable)?)
        .status()?;
    ensure!(status.success(), "failed to terminate {server_name}");
    Ok(())
}

async fn stream_messages(
    context: &jetstream::Context,
    stream_name: &str,
) -> anyhow::Result<u64> {
    let mut last_error = None;
    for _ in 0..60 {
        match context.get_stream(stream_name).await {
            Ok(stream) => match stream.get_info().await {
                Ok(info) => return Ok(info.state.messages),
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
        sleep(Duration::from_millis(500)).await;
    }
    bail!(
        "timed out reading JetStream message count for {stream_name}: {}",
        last_error.as_deref().unwrap_or("no response")
    )
}

#[derive(Debug)]
struct NatsMessageEnvelopeDataset {
    message_count: u64,
    dataset_digest: String,
}

async fn nats_message_envelope_dataset(
    context: &jetstream::Context,
    stream_name: &str,
) -> anyhow::Result<NatsMessageEnvelopeDataset> {
    let stream = context.get_stream(stream_name).await?;
    let state = stream.get_info().await?.state;
    let mut hasher = Sha256::new();
    hasher.update(b"psy/rf3/d04b6h23c4c4b4c2/nats-message-envelope-dataset/v1");
    hasher.update(state.messages.to_be_bytes());
    hasher.update(state.first_sequence.to_be_bytes());
    hasher.update(state.last_sequence.to_be_bytes());

    let mut observed = 0_u64;
    if state.messages != 0 {
        for sequence in state.first_sequence..=state.last_sequence {
            let message = stream.get_raw_message(sequence).await?;
            ensure!(
                message.sequence == sequence,
                "JetStream returned sequence {} for requested sequence {sequence}",
                message.sequence,
            );
            hasher.update(message.sequence.to_be_bytes());
            let subject = message.subject.as_ref().as_bytes();
            hasher.update((subject.len() as u64).to_be_bytes());
            hasher.update(subject);

            let mut headers = message
                .headers
                .iter()
                .map(|(name, values)| {
                    let mut values = values
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>();
                    values.sort();
                    (name.to_string(), values)
                })
                .collect::<Vec<_>>();
            headers.sort();
            hasher.update((headers.len() as u64).to_be_bytes());
            for (name, values) in headers {
                hasher.update((name.len() as u64).to_be_bytes());
                hasher.update(name.as_bytes());
                hasher.update((values.len() as u64).to_be_bytes());
                for value in values {
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value.as_bytes());
                }
            }

            hasher.update((message.payload.len() as u64).to_be_bytes());
            hasher.update(&message.payload);
            observed = observed
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("NATS envelope count overflow"))?;
        }
    }
    ensure!(
        observed == state.messages,
        "JetStream state reported {} messages but exact raw scan observed {observed}",
        state.messages,
    );
    Ok(NatsMessageEnvelopeDataset {
        message_count: observed,
        dataset_digest: hex::encode(hasher.finalize()),
    })
}

async fn end_cap_input(
    db: &ScyllaUnifiedPsyStore<N, PHash, PoseidonHasher>,
    user_id: u64,
    leaf_seed: u64,
    checkpoint_id: u64,
) -> anyhow::Result<psy_data::proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput<PF, PHash>> {
    db.set_contract_tree_heights(
        i64::MAX as u64,
        &[(u64::from(CONTRACT_ID), CONTRACT_HEIGHT)],
    )
    .await?;
    let checkpoint_proof = db
        .checkpoint_tree_get_merkle_proof(u64::MAX - 0xFFFF, checkpoint_id)
        .await?;
    let checkpoint_root = checkpoint_proof.get_append_root::<PoseidonHasher>();
    let heights = DashMapContractHeightCache::new();
    heights.add_contract(
        CONTRACT_ID,
        CONTRACT_HEIGHT,
        PoseidonHasher::get_zero_hash(CONTRACT_HEIGHT as usize),
    );
    let mut user = DPLocalUser::<PoseidonHasher, PHash, PF>::new_empty(
        user_id,
        N::GLOBAL_CONTRACT_TREE_HEIGHT,
    );
    user.run_ups(
        &heights,
        checkpoint_id,
        checkpoint_root,
        &[DPContractUpdate {
            contract_id: CONTRACT_ID,
            leaves: vec![(0, PHash::from_values(leaf_seed, 2, 3, 4))],
        }],
    )
}

async fn compose_handler(
    lineage: RealmProcessorStartupLineage,
    verifier: Arc<Verifier>,
    profile: RealmUserUpdateVerifierProfile,
    nats: Arc<NatsJetStreamClient>,
) -> anyhow::Result<
    RealmEdgeHandler<
        N,
        ScyllaUnifiedPsyStore<N, PHash, PoseidonHasher>,
        ScyllaUnifiedPsyStore<N, PHash, PoseidonHasher>,
        NatsJetStreamClient,
        NatsJetStreamClient,
        InMemoryTempStore,
        InMemoryTempStore,
    >,
> {
    let chain_id = lineage.network().chain_id();
    let addresses = fixture::NODE_IPS
        .map(|ip| ip.to_string())
        .join(",");
    let composition = setup_realm_edge_scylla_startup_composition::<N>(
        fixture::KEYSPACE,
        &addresses,
        false,
        REALM_ID,
        REALM_SUB_ID,
        Some(lineage),
    )
    .await?;
    let registry = Arc::new(RealmUserUpdateVerifierRegistry::try_new([(
        profile,
        Arc::clone(&verifier),
    )])?);
    let factory = Arc::new(
        DeterministicRealmUserUpdateArtifactFactory::<PF, PHash, PoseidonHasher>::new(),
    );
    let (db, installation) = composition
        .into_branch_exact_ingress(registry, factory, Arc::clone(&nats))
        .await?;
    let db = Arc::new(db);
    let temp = Arc::new(InMemoryTempStore::new(
        fixture::KEYSPACE.to_owned(),
        u64::from(REALM_ID),
        u64::from(REALM_SUB_ID),
    ));
    Ok(RealmEdgeHandler::<N, _, _, _, _, _, _>::new(
        Arc::clone(&db),
        db,
        Arc::clone(&temp),
        temp,
        Arc::clone(&nats),
        nats,
        QRealmIdentifier {
            realm_id: REALM_ID,
            realm_sub_id: REALM_SUB_ID,
        },
        chain_id,
        0,
        verifier,
    )
    .install_durable_user_update_ingress(installation)?)
}

#[cfg(feature = "rf3-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated e3 Scylla RF=3 and NATS RF=3 runner"]
async fn d04b6h23c4c2b4e3_jtmb_handler_ingress_joint_rf3() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B4E3_RF3").as_deref() == Ok("1")
    );
    let compose_file = std::env::var("PSY_D04B6H23C4C2B4E3_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H23C4C2B4E3_REPORT_PATH")?;
    let nats_urls = std::env::var("PSY_D04B6H23C4C2B4E3_NATS_URLS")?
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(nats_urls.len() == 3);
    let exercise_deferred_actor_archive =
        std::env::var("PSY_D04B6H23C4C4B4C2_RF3").as_deref() == Ok("1");

    fixture::wait_up(3).await?;
    let session = Arc::new(fixture::connect(None, Consistency::Quorum).await?);
    fixture::create_keyspaces(&session).await?;
    let seed_db = setup_psy_scylla_database_store::<N>(Arc::new(fixture::core().await?))
        .await?;

    let network_type = PsyChainNetworkType::PsyPublicTestnet;
    let (library, _) = get_jtmb_circuit_library_and_prover_for_network::<
        JTMBPoseidonGoldilocksConfig,
    >(network_type)?;
    let verifier = Arc::new(PsyJTMBZKVerifier::new(library));
    let profile = verifier.realm_user_update_verifier_profile(network_type)?;
    let activated = realm_fixture::activate_realm_writer_with_profile(
        Arc::clone(&session),
        profile.id(),
    )
    .await?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    let authority = fixture::authority();
    let network = activated.predecessor.canonical_chain().network_id();
    let predecessor_chain = *activated.predecessor.canonical_chain();

    let sidecar_keyspaces = PendingQueueSidecarKeyspaces::try_new(
        fixture::KEYSPACE,
        fixture::control_keyspace(),
    )?;
    PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        sidecar_keyspaces.clone(),
    )
    .await?;
    let sidecar_ready = Arc::new(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            Arc::clone(&session),
            sidecar_keyspaces,
            authority,
        )
        .await?,
    );
    activated
        .core
        .initialize_pending_queue_sidecar_setup(
            authority,
            PendingQueueSidecarSetupMode::RequireVerified,
        )
        .await?;

    let state_checkpoint = AuthorityStateCheckpointId::new(
        predecessor_chain.checkpoint().checkpoint_id().get(),
    );
    let state_root = AuthorityStateRoot::from_local_state_root(
        PHash::from_owned_32bytes([0x61; 32]),
    );
    let observation = AuthorityObservation::try_new(
        predecessor_chain,
        authority,
        state_checkpoint,
        state_root,
    )?;
    let head_keyspace = AuthorityLocalHeadNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    ScyllaAuthorityLocalHeadStore::create_schema(&session, &head_keyspace).await?;
    let head_store = Arc::new(ScyllaAuthorityLocalHeadStore::prepare(
        Arc::clone(&session),
        head_keyspace,
    )
    .await?);
    let head_view = AuthorityHeadView::try_from_observed(
        AuthorityTimestampKey::new(network, authority),
        predecessor_chain,
        state_checkpoint,
        state_root,
    )?;
    head_store
        .bootstrap(&AuthorityLocalHeadBootstrap::seal(
            AuthorityLocalHeadBootstrapReason::PostGenesisFloor,
            head_view,
            activated.baseline_timestamp,
            AuthorityManifestDigest::from_persisted([0x62; 32]),
            AuthorityStorageBindingRef::new(
                AuthorityStorageBindingGeneration::try_new(1)?,
                AuthorityStorageNamespaceId::from_verified_namespace_id([0x63; 32]),
            ),
        ))
        .await?;
    let AuthorityLocalHeadReadState::Current(local_head) = head_store
        .read::<PHash>(AuthorityTimestampKey::new(network, authority))
        .await?
    else {
        bail!("authority-local head missing")
    };

    let key = PendingGenerationLedgerKey::new(network, authority);
    let prefix = ProcNamespacePrefix::for_authority(network, authority);
    let predecessor_pending = activated.predecessor.pending_id();
    let candidate_pending = UniquePendingId::try_new(predecessor_pending.get() + 1)?;
    let predecessor_context = PendingGenerationContext::try_from_legacy(
        predecessor_pending.get(),
        prefix.derive_proc_id(predecessor_pending).as_u128(),
    )?;
    let candidate_context = PendingGenerationContext::try_from_legacy(
        candidate_pending.get(),
        prefix.derive_proc_id(candidate_pending).as_u128(),
    )?;
    let activation = PendingGenerationActivationDigest::try_new(
        *activated.plan.digest().as_bytes(),
    )?;
    let pipeline_store = ScyllaPendingPipelineStore::prepare(
        Arc::clone(&session),
        control.clone(),
    )
    .await?;
    let pipeline = current_pipeline(
        pipeline_store
            .bootstrap(&PendingPipelineBootstrap::try_new(
                key,
                activation,
                prefix,
                PendingGenerationBootstrapReason::LegacyActivation,
                predecessor_context,
                candidate_context,
                observation.clone(),
                predecessor_pending.get(),
            )?)
            .await?,
    )?;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.u64_counter_singleton_table (obj_id, value) VALUES (?, ?) IF NOT EXISTS",
                fixture::control_keyspace(),
            ),
            (2_i64, candidate_pending.get() as i64),
        )
        .await?;
    let future = seed_db
        .reserve_next_unique_pending_generation_without_mapping(prefix)
        .await?;
    let pipeline = current_pipeline(
        pipeline_store
            .apply(&pipeline.seal_rotation(future)?)
            .await?,
    )?;
    ensure!(pipeline.frontier() == &observation);
    let capture = PendingQueueCaptureContext::try_new(
        key,
        activation,
        pipeline.gathering(),
    )?;

    let shadow_store = ScyllaBranchExactShadowAuditStore::prepare(
        Arc::clone(&session),
        control.clone(),
    )
    .await?;
    let BranchExactShadowAuditReadState::Current(shadow) = shadow_store
        .read(activated.plan.shadow_audit_slot())
        .await?
    else {
        bail!("shadow audit missing")
    };
    let BranchExactShadowAuditState::Consumed(consumed) = shadow.state() else {
        bail!("shadow audit is not Consumed")
    };
    let BranchExactWriterReadState::Current(active_writer) = activated
        .writer_store
        .read(BranchExactWriterAuthorityKey::new(network, authority))
        .await?
    else {
        bail!("writer lifecycle missing")
    };
    ensure!(matches!(active_writer.state(), BranchExactWriterState::Active(_)));
    let cutover_generation = BranchExactCutoverGeneration::try_new(1)?;
    let binding = BranchExactCutoverBinding::try_from_current(
        cutover_generation,
        &active_writer,
        consumed,
        &local_head,
    )?;
    let binding_digest = binding.digest();
    ScyllaBranchExactCutoverStore::create_schema(&session, &control).await?;
    let cutover_store = ScyllaBranchExactCutoverStore::prepare(
        Arc::clone(&session),
        control.clone(),
    )
    .await?;
    let cutover = current_cutover(
        cutover_store
            .bootstrap(&BranchExactCutoverBootstrap::seal(binding))
            .await?,
    )?;
    ensure!(cutover.phase() == BranchExactCutoverPhase::LegacyPrimaryDualWrite);
    let BranchExactCutoverReadState::Current(readback) = cutover_store
        .read::<PHash>(BranchExactCutoverAuthorityKey::try_new(network, authority)?)
        .await?
    else {
        bail!("cutover readback missing")
    };
    ensure!(readback == cutover);

    let base = fixture::KEYSPACE.to_owned();
    let nats = Arc::new(
        NatsJetStreamClient::new_connection(
            base.clone(),
            nats_urls.clone(),
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig {
                num_replicas: 3,
                ..Default::default()
            },
        )
        .await?,
    );
    let nats_kv_replica_mismatch_rejected = NatsJetStreamClient::new_connection(
        base.clone(),
        nats_urls.clone(),
        PullConfig::default(),
        PullConfig::default(),
        StreamConfig {
            num_replicas: 1,
            ..Default::default()
        },
    )
    .await
    .is_err();
    ensure!(nats_kv_replica_mismatch_rejected);
    let segment = RecoverableNatsStreamSegment::try_new(
        base,
        key,
        RecoverableNatsSegmentId::try_new(1)?,
        retention()?,
    )?;
    let validated = segment.validate_stream_config_structure(&segment.stream_config())?;
    let ledger_bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
        key,
        &validated,
        generation_budget()?,
        if exercise_deferred_actor_archive { 2 } else { 1 },
    )?;
    let ledger_key = ledger_bootstrap.candidate().key().clone();
    let ledger = Arc::new(
        ScyllaPendingQueueSegmentLedgerStore::prepare(
            Arc::clone(&session),
            control.clone(),
        )
        .await?,
    );
    ledger.bootstrap(&ledger_bootstrap).await?;
    let provision = ScyllaPendingQueueStreamProvisionStore::prepare_authorized(
        Arc::clone(&session),
        sidecar_ready.as_ref(),
        Arc::clone(&ledger),
    )
    .await?;
    provision
        .provision(&nats, &ledger_key, segment.clone())
        .await?;
    let assignment = ledger.reserve_generation(&ledger_key, capture).await?;
    ensure!(assignment.assignment().context() == capture);

    let admission = RealmUserUpdatePublishAdmission::try_from_pipeline(
        PendingContext::new(
            *pipeline.frontier().chain(),
            authority,
            WorkUniquePendingId::new(pipeline.gathering().pending_id().get()),
            WorkProcCheckpointUniqueId::from_u128(
                pipeline.gathering().proc_checkpoint_id().as_u128(),
            ),
        ),
        capture,
    )?;
    let admission_gates = Arc::new(
        ScyllaRealmUserUpdateAdmissionStore::prepare(
            Arc::clone(&session),
            control.clone(),
        )
        .await?,
    );
    let claims = Arc::new(
        ScyllaRealmUserUpdateClaimStore::prepare(
            Arc::clone(&session),
            control.clone(),
        )
        .await?,
    );
    let admission_guard = ScyllaRealmUserUpdateAdmissionGuard::new(
        admission_gates,
        Arc::clone(&claims),
    );
    admission_guard
        .provision_generation::<PHash>(RealmUserUpdateAdmissionKey::try_new(capture)?)
        .await?;

    let lineage = RealmProcessorStartupLineage::try_new(
        network,
        REALM_ID,
        REALM_SUB_ID,
        cutover_generation.get(),
        *binding_digest.as_bytes(),
        *activated.plan.digest().as_bytes(),
    )?;
    let exercise_durable_capture =
        std::env::var("PSY_D04B6H23C4C3A_RF3").as_deref() == Ok("1");
    let exercise_application_handoff =
        std::env::var("PSY_D04B6H23C4C4A2B_RF3").as_deref() == Ok("1");
    let exercise_terminal_recovery =
        std::env::var("PSY_D04B6H23C4C4B3B2_RF3").as_deref() == Ok("1");
    let exercise_durable_replay = exercise_application_handoff
        || std::env::var("PSY_D04B6H23C4C3B_RF3").as_deref() == Ok("1");
    ensure!(
        !exercise_durable_replay || exercise_durable_capture,
        "c3b replay Gate requires the c3a durable capture owner"
    );
    ensure!(
        !exercise_terminal_recovery || exercise_application_handoff,
        "c4b3b2 recovery Gate requires the c4a2b application handoff"
    );
    ensure!(
        !exercise_deferred_actor_archive || exercise_terminal_recovery,
        "c4b4c2 deferred actor Gate requires c4b3b2 terminal carryover recovery"
    );
    let mut branch_exact_commit_owner = if exercise_durable_capture {
        let expectation = lineage.seal_attempt([0xC3; 32])?;
        let provider = Arc::new(
            activated
                .core
                .prepare_realm_processor_startup_provider_with_capture::<
                    <N as parth_core::protocol::core_types::QNetworkHashTypes>::F,
                >(
                    expectation,
                    Arc::clone(&nats),
                    GlobalUserTreeHeight::try_new(N::GLOBAL_USER_TREE_HEIGHT)?,
                )
                .await?,
        );
        let RealmProcessorStartupAuthorization::BranchExact(run_permit) =
            authorize_realm_processor_startup(
                RealmProcessorStartupMode::RequireBranchExact(expectation),
                Some(provider.as_ref()),
            )
            .await?
        else {
            bail!("branch-exact startup did not return a run permit")
        };
        let installed = provider.install(run_permit).await?;
        Some(RealmBranchExactSingleCommitOwner::from_installed(installed))
    } else {
        None
    };
    let mut handler = compose_handler(
        lineage,
        Arc::clone(&verifier),
        profile.clone(),
        Arc::clone(&nats),
    )
    .await?;
    let checkpoint_id = predecessor_chain.checkpoint().checkpoint_id().get();
    let user_a = (u64::from(REALM_ID) << N::REALM_GLOBAL_USER_TREE_HEIGHT) + 11;
    let user_b = user_a + 1;
    let user_c = user_b + 1;
    let input_a = end_cap_input(&handler.db_reader, user_a, 101, checkpoint_id).await?;
    let input_b = end_cap_input(&handler.db_reader, user_b, 202, checkpoint_id).await?;
    let input_c = end_cap_input(&handler.db_reader, user_c, 303, checkpoint_id).await?;
    let prover = DummyUPSStandardEndCapCircuit::<JTMBPoseidonGoldilocksConfig>::new(
        &get_test_circuit_authority_key(network_type),
    );
    let proof_a = prover.prove_end_cap_dummy_ups(N::GLOBAL_USER_TREE_HEIGHT, &input_a)?;
    let proof_b = prover.prove_end_cap_dummy_ups(N::GLOBAL_USER_TREE_HEIGHT, &input_b)?;
    let proof_c = prover.prove_end_cap_dummy_ups(N::GLOBAL_USER_TREE_HEIGHT, &input_c)?;
    let raw_nats = async_nats::connect(nats_urls.clone()).await?;
    let mut jetstream = jetstream::new(raw_nats);
    let kv_stream_name = format!("KV_{}_kv", fixture::KEYSPACE.replace('.', "_"));
    let kv_info = jetstream
        .get_stream(&kv_stream_name)
        .await?
        .get_info()
        .await?;
    ensure!(kv_info.config.num_replicas == 3);
    let before_invalid_rows = handler_mutation_snapshot(&session).await?;
    let before_invalid = stream_messages(&jetstream, segment.stream_name()).await?;
    let invalid_error = handler
        .handle_user_end_cap_proof_submission(input_a.clone(), proof_b)
        .await
        .expect_err("input A paired with proof B must fail");
    let invalid_proof_error = invalid_error
        .downcast_ref::<RealmUserUpdateIngressError>()
        .and_then(|error| match error {
            RealmUserUpdateIngressError::Proof(message) => Some(message.as_str()),
            _ => None,
        });
    ensure!(
        invalid_proof_error.is_some_and(|message| {
            message.contains("ProofRecoveryFailed")
                && message.contains("invalid expected public inputs hash")
        }),
        "unexpected invalid-proof error: {invalid_error:#}"
    );
    let after_invalid = stream_messages(&jetstream, segment.stream_name()).await?;
    let after_invalid_rows = handler_mutation_snapshot(&session).await?;
    ensure!(before_invalid == after_invalid);
    ensure!(
        before_invalid_rows == after_invalid_rows,
        "invalid public input/proof pairing mutated durable Handler rows"
    );

    // Deterministic crash window: the small claim pointer reached Planned,
    // but the process died before writing even one dependency fragment. The
    // exact high-level client replay must use its verified input/proof to
    // regenerate the same bundle, fill the missing set and publish once.
    let registry = RealmUserUpdateVerifierRegistry::try_new([(
        profile.clone(),
        Arc::clone(&verifier),
    )])?;
    let bound = registry.resolve(profile.id())?;
    let verified_c = VerifiedRealmUserUpdateRequest::verify::<
        PsyTestJTMBProof<PHash>,
        Verifier,
        PoseidonHasher,
    >(
        &input_c,
        proof_c.clone(),
        GlobalUserTreeHeight::try_new(N::GLOBAL_USER_TREE_HEIGHT)?,
        &bound,
    )?;
    let claimed_c = admission_guard
        .claim(
            admission.clone(),
            profile.id(),
            verified_c.user_id(),
            verified_c.request_digest(),
            RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_303)?,
        )
        .await?;
    let factory = DeterministicRealmUserUpdateArtifactFactory::<
        PF,
        PHash,
        PoseidonHasher,
    >::new();
    let material = factory.build(&claimed_c, &input_c)?;
    let artifacts = seal_realm_user_update_ingress_artifacts::<
        PF,
        PHash,
        PoseidonHasher,
    >(
        admission.clone(),
        &claimed_c,
        &verified_c,
        material,
    )?;
    let bundle = RealmUserUpdateDependencyBundle::try_new_validated(
        &claimed_c,
        &artifacts,
    )?;
    let planned_c = StoredRealmUserUpdateClaim::dependencies_planned(
        &claimed_c,
        bundle.digest(),
    )?;
    let planned_c = current_claim(
        claims.compare_and_set(&claimed_c, &planned_c).await?,
    )?;
    ensure!(planned_c.phase() == RealmUserUpdateClaimPhase::DependenciesPlanned);
    ensure!(
        handler_mutation_snapshot(&session)
            .await?
            .row_count(
                fixture::KEYSPACE,
                "branch_exact_realm_user_update_dependency_fragment_v1",
            )? == 0,
        "Planned crash fixture unexpectedly wrote dependency fragments"
    );
    handler
        .handle_user_end_cap_proof_submission(input_c, proof_c)
        .await?;
    let planned_pointer_replay_messages =
        stream_messages(&jetstream, segment.stream_name()).await?;
    ensure!(planned_pointer_replay_messages == 1);
    let RealmUserUpdateClaimReadState::Current(replayed_c) = claims
        .read::<PHash>(planned_c.partition()?, planned_c.user_id())
        .await?
    else {
        bail!("Planned replay claim disappeared")
    };
    let planned_pointer_zero_fragment_replay =
        replayed_c.phase() == RealmUserUpdateClaimPhase::Published;
    ensure!(planned_pointer_zero_fragment_replay);

    fixture::compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop e3 Scylla replica",
    )?;
    fixture::wait_up(2).await?;
    let concurrent_a = handler.clone();
    let concurrent_b = handler.clone();
    let (first, second) = tokio::join!(
        concurrent_a.handle_user_end_cap_proof_submission(
            input_a.clone(),
            proof_a.clone(),
        ),
        concurrent_b.handle_user_end_cap_proof_submission(
            input_a.clone(),
            proof_a.clone(),
        ),
    );
    first?;
    second?;
    let first_publish_messages = stream_messages(&jetstream, segment.stream_name()).await?;
    ensure!(first_publish_messages == 2);
    handler
        .handle_user_end_cap_proof_submission(input_a.clone(), proof_a.clone())
        .await?;
    let response_loss_retry_messages =
        stream_messages(&jetstream, segment.stream_name()).await?;
    ensure!(response_loss_retry_messages == 2);

    let leader_before = wait_for_stream_leader(&jetstream, segment.stream_name(), None).await?;
    terminate_nats_leader(&leader_before)?;
    let terminated_index = match leader_before.as_str() {
        "psy-h23e3-n1" => 0,
        "psy-h23e3-n2" => 1,
        "psy-h23e3-n3" => 2,
        other => bail!("unexpected terminated NATS leader {other}"),
    };
    let failover_urls = nats_urls
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != terminated_index)
        .map(|(_, url)| url.clone())
        .collect::<Vec<_>>();
    ensure!(failover_urls.len() == 2);
    // The pre-failover observer may have been physically connected to the
    // terminated server.  Reopen against the two surviving endpoints before
    // asking for quorum readiness so a client request timeout cannot masquerade
    // as a failed stream election.
    jetstream = jetstream::new(async_nats::connect(failover_urls.clone()).await?);
    let leader_after = wait_for_stream_leader(
        &jetstream,
        segment.stream_name(),
        Some(&leader_before),
    )
    .await?;
    // Reopen the production-shaped publisher from the durable assignment and
    // stream binding after the client connection to the terminated leader is
    // lost. This is the crash/restart contract; a stale in-memory connection
    // is not itself durable recovery authority.
    let failover_nats = Arc::new(
        NatsJetStreamClient::new_connection(
            fixture::KEYSPACE.to_owned(),
            failover_urls.clone(),
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig {
                num_replicas: 3,
                ..Default::default()
            },
        )
        .await?,
    );
    handler = compose_handler(
        lineage,
        Arc::clone(&verifier),
        profile.clone(),
        failover_nats,
    )
    .await?;
    handler
        .handle_user_end_cap_proof_submission(input_b.clone(), proof_a.clone())
        .await
        .expect_err("proof A paired with input B must fail");
    let proof_b = prover.prove_end_cap_dummy_ups(N::GLOBAL_USER_TREE_HEIGHT, &input_b)?;
    // A client connected to the terminated leader may observe one
    // indeterminate JetStream request while async-nats reconnects.  Retry the
    // exact verified request; the durable ingress path must converge without
    // changing its payload or publishing twice.
    let mut failover_publish_error = String::from("not attempted");
    let mut published_after_failover = false;
    for _ in 0..10 {
        match handler
            .handle_user_end_cap_proof_submission(input_b.clone(), proof_b.clone())
            .await
        {
            Ok(()) => {
                published_after_failover = true;
                break;
            }
            Err(error) => {
                failover_publish_error = format!("{error:#}");
                sleep(Duration::from_millis(500)).await;
            }
        }
    }
    ensure!(
        published_after_failover,
        "durable ingress did not recover after JetStream leader failover: {failover_publish_error}"
    );
    let second_publish_messages = stream_messages(&jetstream, segment.stream_name()).await?;
    ensure!(second_publish_messages == 3);

    // c4b4c2 uses three additional, independently verified dependency
    // bundles as the successor generation's external Data. They are not
    // published by the legacy Handler here: the exact queue/update bytes are
    // later committed through the successor assignment's durable outbox.
    let mut successor_external_requests = Vec::new();
    if exercise_deferred_actor_archive {
        for (offset, leaf_seed) in [404_u64, 505, 606].into_iter().enumerate() {
            let user_id = user_c
                .checked_add(u64::try_from(offset)? + 1)
                .ok_or_else(|| anyhow::anyhow!("qualification user overflow"))?;
            let input = end_cap_input(
                &handler.db_reader,
                user_id,
                leaf_seed,
                checkpoint_id,
            )
            .await?;
            let proof = prover.prove_end_cap_dummy_ups(
                N::GLOBAL_USER_TREE_HEIGHT,
                &input,
            )?;
            successor_external_requests.push((user_id, input, proof));
        }
        ensure!(successor_external_requests.len() == 3);
    }

    drop(handler);
    let restarted_nats = Arc::new(
        NatsJetStreamClient::new_connection(
            fixture::KEYSPACE.to_owned(),
            failover_urls,
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig {
                num_replicas: 3,
                ..Default::default()
            },
        )
        .await?,
    );
    let restarted = compose_handler(
        lineage,
        Arc::clone(&verifier),
        profile.clone(),
        Arc::clone(&restarted_nats),
    )
    .await?;
    let retry_input = end_cap_input(
        &restarted.db_reader,
        user_a,
        101,
        checkpoint_id,
    )
    .await?;
    ensure!(
        retry_input == input_a,
        "restart reconstructed a different canonical input"
    );
    restarted
        .handle_user_end_cap_proof_submission(input_a, proof_a)
        .await?;
    let restart_retry_messages = stream_messages(&jetstream, segment.stream_name()).await?;
    ensure!(restart_retry_messages == 3);

    let predecessor_deferred_materials = if exercise_deferred_actor_archive {
        read_published_job_materials(
            Arc::clone(&session),
            claims.as_ref(),
            capture,
            &[user_a, user_b, user_c].into_iter().collect(),
        )
        .await?
    } else {
        Vec::new()
    };
    ensure!(
        !exercise_deferred_actor_archive
            || predecessor_deferred_materials.len() == 3
    );

    let initial_qualification_fence = if exercise_durable_replay {
        // Durable consumption is authorized by the closed admission manifest,
        // not merely by observing Data/Seal in JetStream. Qualify the complete
        // gathering generation while it is still the pipeline's selected
        // gathering identity; the following rotation moves that exact identity
        // into processing for capture.
        let initial_observations = Arc::new(
            ScyllaRealmAuthorityObservationReader::<PHash>::try_new(
                Arc::clone(&head_store),
                AuthorityTimestampKey::new(network, authority),
            )?,
        );
        let initial_registry = Arc::new(
            RealmUserUpdateVerifierRegistry::try_new([(
                profile.clone(),
                Arc::clone(&verifier),
            )])?,
        );
        let initial_router = ScyllaRealmUserUpdateDurableRouter::<
            PF,
            PHash,
            PoseidonHasher,
            PsyTestJTMBProof<PHash>,
            Verifier,
        >::prepare(
            Arc::clone(&session),
            network,
            authority,
            GlobalUserTreeHeight::try_new(N::GLOBAL_USER_TREE_HEIGHT)?,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            profile.id(),
            initial_registry,
            initial_observations,
            Arc::clone(&sidecar_ready),
            Arc::clone(&restarted_nats),
        )
        .await?;
        initial_router
            .attest_startup()
            .await
            .context("initial generation admission route was not open")?;
        let initial_admission_key = RealmUserUpdateAdmissionKey::try_new(capture)?;
        let initial_admission_close =
            RealmUserUpdateAdmissionCloseIntent::derive(initial_admission_key, [0xCF; 32])?;
        admission_guard
            .close_generation::<PHash>(initial_admission_key, initial_admission_close)
            .await?;
        let qualification = initial_router
            .qualify_generation(initial_admission_key, initial_admission_close)
            .await
            .context("initial generation admission qualification failed")?;
        Some(*qualification
            .current()
            .generation_qualification()
            .ok_or_else(|| anyhow::anyhow!("qualified admission omitted qualification"))?
            .fence())
    } else {
        None
    };

    let mut durable_generation_replayed = false;
    let mut durable_generation_items = 0_u64;
    let mut durable_generation_digest_stable = false;
    let mut gather_task_restart_replayed = false;
    let mut application_semantic_bytes = 0_usize;
    let mut application_fragments = 0_u32;
    let mut application_pipeline_revision = 0_u64;
    let mut application_restart_recovered = false;
    let mut qualification_seeded_terminal = false;
    let inbound_missing_zero_write = false;
    let mut nonterminal_zero_write = false;
    let mut terminal_absent_zero_write = false;
    let mut terminal_only_repaired = false;
    let mut post_persist_failure_recovered = false;
    let mut already_complete_recovered = false;
    let mut affine_retry_count = 0_usize;
    let mut derived_same_retry_count = 0_usize;
    let mut derived_different_contender_conflict = false;
    let mut application_toctou_rejected = false;
    let mut terminal_recovery_pipeline_unchanged = false;
    let mut terminal_recovery_nats_delta = 0_u64;
    let mut v14_ready_receipt_consumed = false;
    let mut qualification_constructed_predecessor_semantic = false;
    let mut predecessor_nonempty_input_rf3 = false;
    let mut predecessor_deferred_count = 0_u32;
    let mut explicit_empty_input_rf3 = false;
    let mut external_generation_nonempty_rf3 = false;
    let mut external_generation_items = 0_u64;
    let mut deferred_before_external_rf3 = false;
    let mut ordered_actor_trace_digest = String::new();
    let mut fresh_c_fault_rf3 = false;
    let mut fresh_c_nats_delta = 0_u64;
    let mut fresh_d_fault_rf3 = false;
    let mut fresh_d_actor_delta = 0_u64;
    let mut apply_retry_bit_exact = false;
    let mut finalize_retry_bit_exact = false;
    let mut different_input_rejected = false;
    let mut actor_builder_create_count = 0_u64;
    let mut actor_finalize_count = 0_u64;
    let mut semantic_v3_input_bound = false;
    let mut successor_application_semantic_bytes = 0_usize;
    let mut successor_application_fragments = 0_u32;
    let mut application_archive_handoff_rf3 = false;
    let mut handoff_recovery_without_actor_rerun = false;
    let mut successor_handoff_revision = 0_u64;
    let mut actor_handoff_during_one_replica_offline = false;
    let mut deferred_actor_nats_message_count_before = 0_u64;
    let mut expected_nats_after_deferred_actor = 0_u64;
    let mut successor_dependency_capture = None;
    let (durable_capture_items, durable_capture_empty_poll_not_close) =
        if let Some(owner) = branch_exact_commit_owner.as_mut() {
            // Edge always publishes to the gathering generation. Retire the
            // preceding processing generation through legal no-work
            // transitions, then rotate the published generation into the
            // Processor-owned capture slot.
            let old_close = PendingQueueCloseIntentDigest::try_new([0xC0; 32])?;
            let old_empty = PendingEmptyQueueSealDigest::try_new([0xC1; 32])?;
            let old_receipt = PendingNoWorkReceiptDigest::try_new([0xC2; 32])?;
            let old_sealing = current_pipeline(
                pipeline_store
                    .apply(&pipeline.seal_begin_queue_close(old_close)?)
                    .await?,
            )?;
            let old_empty_sealed = current_pipeline(
                pipeline_store
                    .apply(&old_sealing.seal_empty_queue(old_close, old_empty)?)
                    .await?,
            )?;
            let old_retired = current_pipeline(
                pipeline_store
                    .apply(&old_empty_sealed.seal_retire_no_work(
                        old_empty,
                        old_receipt,
                        observation.clone(),
                    )?)
                    .await?,
            )?;
            let next = seed_db
                .reserve_next_unique_pending_generation_without_mapping(prefix)
                .await?;
            let capture_ready = current_pipeline(
                pipeline_store
                    .apply(&old_retired.seal_rotation(next)?)
                    .await?,
            )?;
            ensure!(capture_ready.processing() == capture.processing());
            let sealing = current_pipeline(
                pipeline_store
                    .apply(&capture_ready.seal_begin_queue_close(
                        PendingQueueCloseIntentDigest::try_new([0xC4; 32])?,
                    )?)
                    .await?,
            )?;
            ensure!(sealing.processing() == capture.processing());
            if let Some(qualification_fence) = initial_qualification_fence {
                ensure!(
                    qualification_fence.matches_processing_pipeline(
                        RealmUserUpdateAdmissionKey::try_new(capture)?,
                        &sealing,
                    ),
                    "initial qualification fence mismatch after rotation: key_match={} activation_match={} processing_match={} frontier_match={} blocked={:?}",
                    sealing.key() == capture.key(),
                    sealing.activation_digest() == capture.activation(),
                    sealing.processing() == capture.processing(),
                    sealing.frontier() == qualification_fence.frontier(),
                    sealing.blocked_reason(),
                );
            }

            if exercise_durable_replay {
                // Publish the structural Seal through the same durable outbox
                // and assignment used by the real Handler.  This makes the
                // complete generation replayable after every JetStream
                // delivery has been ACKed.
                let close_receipt = pipeline_store
                    .read_queue_close_exact::<PHash>(capture)
                    .await?;
                let publisher = Arc::new(
                    nats.recoverable_pending_publisher(segment.clone()).await?,
                );
                let publish_store = ScyllaPendingQueuePublishStore::prepare(
                    Arc::clone(&session),
                    publisher,
                    segment.clone(),
                    PendingQueuePublishKeyspaces::new(
                        control.clone(),
                        PendingQueuePublishDataKeyspace::try_new(
                            fixture::KEYSPACE,
                        )?,
                    ),
                )
                .await?;
                publish_store
                    .bootstrap_source(
                        &assignment,
                        PendingQueuePublisherKind::RealmUserUpdate,
                    )
                    .await?;
                let seal_slot = publish_store
                    .materialize_seal::<PHash>(
                        &pipeline_store,
                        &assignment,
                        PendingQueuePublisherKind::RealmUserUpdate,
                        PendingQueuePublishIntentId::try_new([0xC5; 32])?,
                        &close_receipt,
                    )
                    .await?;
                let seal = publish_store
                    .bind_materialized(
                        &assignment,
                        PendingQueuePublisherKind::RealmUserUpdate,
                        seal_slot,
                    )
                    .await?;
                publish_store
                    .publish_and_commit(&assignment, seal)
                    .await?;
                ensure!(
                    stream_messages(&jetstream, segment.stream_name()).await? == 4,
                    "durable close did not append exactly one Seal envelope"
                );
            }

            #[cfg(feature = "rf3-test-support")]
            {
                let carryover_store = ScyllaRealmProcessorDeferredCarryoverStore::prepare(
                    Arc::clone(&session),
                    control.clone(),
                )
                .await?;
                let bootstrap = RealmProcessorDeferredCarryover::try_bootstrap_empty(
                    key,
                    activation,
                    capture.processing(),
                    PendingGenerationBootstrapReason::LegacyActivation,
                )?;
                carryover_store.qualification_persist(bootstrap).await?;
            }

            let iteration_gate = RealmProcessorIterationGate::controlled();
            let mut iteration = owner.begin_iteration(
                iteration_gate.try_begin_iteration()?,
            )?;
            let deferred_input = match iteration.prepare_deferred_actor_input().await? {
                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                    bail!("qualification fixture did not persist explicit bootstrap carryover")
                }
            };
            let mut capture_owner = iteration
                .open_durable_capture_for_deferred_input(deferred_input)
                .await?;
            let mut item_count = 0_u64;
            let mut observed_close = false;
            for _ in 0..8 {
                let outcome = capture_owner.capture_next().await?;
                match outcome {
                    Some(RealmProcessorDurableCaptureOutcome::Data(candidate)) => {
                        item_count = item_count
                            .checked_add(candidate.item_count())
                            .ok_or_else(|| anyhow::anyhow!("capture item overflow"))?;
                    }
                    Some(RealmProcessorDurableCaptureOutcome::Sealed { data, .. }) => {
                        item_count = item_count
                            .checked_add(
                                data.as_ref()
                                    .map_or(0, |candidate| candidate.item_count()),
                            )
                            .ok_or_else(|| anyhow::anyhow!("capture item overflow"))?;
                        observed_close = true;
                        break;
                    }
                    None if exercise_durable_replay => {
                        sleep(Duration::from_millis(100)).await;
                    }
                    None => break,
                }
            }
            ensure!(item_count == 3, "durable owner captured {item_count} items");
            let empty = if exercise_durable_replay {
                ensure!(observed_close, "durable owner did not observe source Seal");
                let generation = capture_owner
                    .replay_complete_generation()
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "closed durable source did not reconstruct a generation"
                        )
                    })?;
                let initial_external_input = capture_owner
                    .qualify_external_actor_input(generation)
                    .await
                    .context("initial generation durable consumer qualification failed")?;
                durable_generation_items =
                    u64::try_from(initial_external_input.items().len())?;
                ensure!(durable_generation_items == 3);
                let first_digest = initial_external_input.generation_digest();
                let first_items = initial_external_input
                    .items()
                    .iter()
                    .map(|item| item.queue_item().to_vec())
                    .collect::<Vec<_>>();
                let initial_deferred_input =
                    capture_owner.take_deferred_actor_input().await?;
                let _initial_actor_input = RealmProcessorActorInput::try_new(
                    initial_deferred_input,
                    initial_external_input,
                )?;
                durable_generation_replayed = true;

                // Drop the capture/gather-task side and reconstruct solely
                // from durable Scylla artifacts.  JetStream has already ACKed
                // Data and Seal, so no redelivery can make this pass.
                drop(capture_owner);
                drop(iteration);
                let mut restarted_iteration = owner.begin_iteration(
                    iteration_gate.try_begin_iteration()?,
                )?;
                let restarted_input = match restarted_iteration
                    .prepare_deferred_actor_input()
                    .await?
                {
                    RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                    RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                        bail!("restart lost explicit bootstrap carryover")
                    }
                };
                let mut restarted_capture = restarted_iteration
                    .open_durable_capture_for_deferred_input(restarted_input)
                    .await?;
                let replayed = restarted_capture
                    .replay_complete_generation()
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "gather-task restart lost closed durable generation"
                        )
                    })?;
                durable_generation_digest_stable =
                    replayed.digest() == first_digest;
                let replayed_context_digest = replayed.context().digest();
                let replayed_generation_digest = replayed.digest();
                let replayed_boundary_digest = replayed.boundary().digest();
                let replayed_item_count = replayed.item_count();
                let replayed_items = replayed
                    .batches()
                    .iter()
                    .flat_map(|batch| {
                        batch
                            .business_items()
                            .iter()
                            .map(|item| item.payload().to_vec())
                    })
                    .collect::<Vec<_>>();
                let restarted_external_input = restarted_capture
                    .qualify_external_actor_input(replayed)
                    .await
                    .context("restarted initial generation durable consumer qualification failed")?;
                let restarted_deferred_input = restarted_capture
                    .take_deferred_actor_input()
                    .await?;
                let restarted_actor_input = RealmProcessorActorInput::try_new(
                    restarted_deferred_input,
                    restarted_external_input,
                )?;
                let restarted_input_digest = restarted_actor_input.digest();
                gather_task_restart_replayed = durable_generation_digest_stable
                    && replayed_items == first_items;
                ensure!(durable_generation_digest_stable);
                ensure!(gather_task_restart_replayed);

                if exercise_application_handoff {
                    let semantic = if exercise_deferred_actor_archive {
                        // The first generation is explicitly bound to the
                        // LegacyActivation BootstrapEmpty row. Run the real
                        // Realm WithTree actor at the immediately preceding
                        // checkpoint so all three canonical external items
                        // become ordered deferred jobs in its v3 semantic
                        // output. That output is then persisted through the
                        // production capture/archive/handoff path below.
                        let actor_checkpoint = checkpoint_id
                            .checked_sub(1)
                            .ok_or_else(|| anyhow::anyhow!(
                                "qualification checkpoint cannot precede genesis"
                            ))?;
                        qualification_start_realm_deferred_actor_trace()?;
                        let (actor, actor_task, actor_temp, actor_state) =
                            start_qualification_realm_actor(
                                capture,
                                *sealing.frontier().chain(),
                                actor_checkpoint,
                            )
                            .await?;
                        let apply = actor
                            .qualification_apply_durable_generation(restarted_actor_input)
                            .await?;
                        ensure!(apply.actor_revision().get() == 1);
                        let finalized = actor
                            .qualification_finalize_durable_generation(apply)
                            .await?;
                        ensure!(finalized.actor_revision().get() == 2);
                        let semantic = qualification_project_branch_exact_semantic_output::<
                            N,
                            InMemoryTempStore,
                        >(
                            actor_temp.as_ref(),
                            &actor_state,
                            capture.processing(),
                            &finalized,
                        )
                        .await?;
                        ensure!(semantic.actor_input_digest() == Some(restarted_input_digest));
                        ensure!(semantic.deferred_jobs().len() == 3);
                        let trace = qualification_finish_realm_deferred_actor_trace()?;
                        ensure!(trace.builder_create_count == 1);
                        ensure!(trace.finalize_count == 1);
                        ensure!(trace.entries.len() == 3);
                        ensure!(trace.entries.iter().all(|entry| {
                            entry.kind == RealmDeferredActorTraceKind::External
                        }));
                        explicit_empty_input_rf3 = true;
                        qualification_constructed_predecessor_semantic = true;
                        predecessor_deferred_count =
                            u32::try_from(semantic.deferred_jobs().len())?;
                        drop(actor);
                        timeout(Duration::from_secs(30), actor_task).await???;
                        semantic
                    } else {
                        // c4a2b's bounded two-fragment fixture predates the
                        // real actor Gate. Keep it for the narrower historical
                        // qualification while c4b4c2 uses the actor branch.
                        RealmProcessorSemanticOutput::try_from_candidate_parts(
                            RealmProcessorSemanticOutputParts {
                                context_digest: replayed_context_digest,
                                generation_digest: replayed_generation_digest,
                                boundary_digest: replayed_boundary_digest,
                                item_count: replayed_item_count,
                                input_binding: psy_node_core::queue::realm_processor_semantic_output::RealmProcessorSemanticInputBinding::SuccessorQualified(restarted_input_digest),
                                processing_checkpoint_id: checkpoint_id,
                                processing_checkpoint_root: [0xA1; 32],
                                processing_realm_start_root: [0xA2; 32],
                                old_realm_root: [0xA2; 32],
                                new_realm_root: [0xA3; 32],
                                total_users_updated: 1,
                                total_proofs_generated: 0,
                                global_user_tree_nodes: vec![
                                    0xA4;
                                    4 * 1024 * 1024 + 1
                                ],
                                user_contract_tree_nodes: Vec::new(),
                                contract_state_tree_nodes: Vec::new(),
                                user_leaves: Vec::new(),
                                contract_state_imt_leaves: Vec::new(),
                                guta_header: vec![0xA5, 0xA6],
                                jobs: Vec::new(),
                                deferred_jobs: deferred_jobs_from_materials(
                                    &predecessor_deferred_materials,
                                )?,
                            },
                        )?
                    };
                    application_semantic_bytes = semantic.canonical_len()?;
                    application_fragments = u32::try_from(
                        application_semantic_bytes.div_ceil(4 * 1024 * 1024),
                    )?;
                    ensure!(
                        application_fragments
                            == if exercise_deferred_actor_archive { 1 } else { 2 }
                    );
                    let handoff = restarted_capture
                        .persist_application_and_handoff(semantic)
                        .await?;
                    ensure!(handoff.has_application_work());
                    application_pipeline_revision = handoff.pipeline_revision();
                    let same_owner_recovery = restarted_capture
                        .recover_application_handoff()
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "application handoff owner did not expose its durable result"
                            )
                        })?;
                    ensure!(same_owner_recovery == handoff);
                    let expected_handoff = handoff;
                    drop(restarted_capture);
                    drop(restarted_iteration);

                    // Re-open after the authority transition.  Recovery must
                    // select the immutable application archive from the
                    // current pipeline row; it must not recreate the NATS
                    // owner or synthesize the old close receipt.
                    let mut recovered_iteration = owner.begin_iteration(
                        iteration_gate.try_begin_iteration()?,
                    )?;
                    let recovered = recovered_iteration
                        .observe_generation_continuation()
                        .await?;
                    let recovered_application = recovered
                        .application()
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "post-CAS continuation did not recover application handoff"
                            )
                        })?;
                    ensure!(
                        recovered.phase()
                            == RealmProcessorGenerationContinuationPhase::AwaitWriter
                    );
                    ensure!(
                        recovered_application.archive_slot().as_bytes()
                            == expected_handoff.archive_slot()
                            && recovered_application.archive_digest().as_bytes()
                                == expected_handoff.archive_digest()
                            && recovered_application.semantic_digest().as_bytes()
                                == expected_handoff.semantic_digest()
                            && recovered.pipeline_revision().get()
                                == expected_handoff.pipeline_revision()
                            && recovered_application.has_application_work()
                                == expected_handoff.has_application_work()
                    );
                    application_restart_recovered = true;

                    #[cfg(feature = "rf3-test-support")]
                    if exercise_terminal_recovery {
                        drop(recovered_iteration);

                        let application_store = Arc::new(
                            ScyllaRealmProcessorApplicationArchiveStore::prepare(
                                Arc::clone(&session),
                                control.clone(),
                                PendingQueueArtifactDataKeyspace::try_new(
                                    fixture::KEYSPACE,
                                )?,
                            )
                            .await?,
                        );
                        let terminal_store = Arc::new(
                            ScyllaRealmProcessorGenerationTerminalStore::prepare(
                                Arc::clone(&session),
                                control.clone(),
                            )
                            .await?,
                        );
                        let carryover_store = Arc::new(
                            ScyllaRealmProcessorDeferredCarryoverStore::prepare(
                                Arc::clone(&session),
                                control.clone(),
                            )
                            .await?,
                        );
                        let recovery_nats_before;

                        let (work_continuation, _, work_captured) = application_store
                            .observe_generation_continuation::<PHash>(
                                &pipeline_store,
                                &assignment,
                            )
                            .await?;
                        let application = work_continuation
                            .application()
                            .ok_or_else(|| anyhow::anyhow!(
                                "WorkCaptured continuation lost its application"
                            ))?;
                        // The application/capture path above already selected and
                        // persisted the explicit LegacyActivation bootstrap row.
                        // This activation therefore cannot also qualify the older
                        // "inbound missing" branch; keep that report bit false and
                        // exercise the explicit-lineage nonterminal zero-write path.
                        ensure!(!inbound_missing_zero_write);

                        let before_nonterminal = terminal_recovery_snapshot(&session).await?;
                        let mut nonterminal_iteration = owner.begin_iteration(
                            iteration_gate.try_begin_iteration()?,
                        )?;
                        let nonterminal_recovery = nonterminal_iteration
                            .open_terminal_carryover_recovery()
                            .await?;
                        ensure!(matches!(
                            nonterminal_recovery.recover_and_prepare().await?,
                            RealmProcessorTerminalCarryoverRecoveryOutcome::AwaitTerminalPhase(_)
                        ));
                        drop(nonterminal_iteration);
                        nonterminal_zero_write =
                            before_nonterminal == terminal_recovery_snapshot(&session).await?;
                        ensure!(nonterminal_zero_write);

                        // Qualification-only writer/head stand-in. These two
                        // pipeline transitions establish a real Published row
                        // for the recovery Gate; they are not production
                        // terminal authorization or part of the recovery API.
                        let intent = PendingPipelineIntentDigest::try_new([0xB3; 32])?;
                        let inflight = current_pipeline(
                            pipeline_store
                                .apply(&work_captured.seal_begin_processing(
                                    PendingWorkCaptureDigest::try_new(
                                        *application.archive_slot().as_bytes(),
                                    )?,
                                    intent,
                                )?)
                                .await?,
                        )?;
                        let published_observation =
                            next_terminal_observation(&observation, 0xB4)?;
                        let published = current_pipeline(
                            pipeline_store
                                .apply(&inflight.seal_publish(
                                    intent,
                                    PendingPublishReceiptDigest::try_new([0xB5; 32])?,
                                    published_observation,
                                )?)
                                .await?,
                        )?;
                        let current_head = match head_store
                            .read::<PHash>(AuthorityTimestampKey::new(
                                network,
                                authority,
                            ))
                            .await?
                        {
                            AuthorityLocalHeadReadState::Current(current) => current,
                            AuthorityLocalHeadReadState::Uninitialized => {
                                bail!("authority-local head disappeared before qualification advance")
                            }
                        };
                        let head_advance =
                            SealedAuthorityLocalHeadCas::seal_qualification_observation_advance(
                                current_head,
                                published_observation,
                            )?;
                        ensure!(matches!(
                            head_store.compare_and_set(&head_advance).await?,
                            AuthorityLocalHeadWriteOutcome::Applied(_)
                                | AuthorityLocalHeadWriteOutcome::Idempotent(_)
                        ));

                        let before_terminal_absent =
                            terminal_recovery_snapshot(&session).await?;
                        let mut absent_iteration = owner.begin_iteration(
                            iteration_gate.try_begin_iteration()?,
                        )?;
                        let absent_recovery = absent_iteration
                            .open_terminal_carryover_recovery()
                            .await?;
                        ensure!(matches!(
                            absent_recovery.recover_and_prepare().await?,
                            RealmProcessorTerminalCarryoverRecoveryOutcome::AwaitVerifiedTerminalAuthorization(_)
                        ));
                        drop(absent_iteration);
                        terminal_absent_zero_write = before_terminal_absent
                            == terminal_recovery_snapshot(&session).await?;
                        ensure!(terminal_absent_zero_write);

                        let terminal_reserved =
                            ReservedPendingGeneration::qualification_from_prefix(
                                published
                                    .gathering()
                                    .pending_id()
                                    .get()
                                    .checked_add(1)
                                    .ok_or_else(|| anyhow::anyhow!(
                                        "qualification successor overflow"
                                    ))?,
                                prefix,
                            )?;
                        let (terminal_authorization, successor_fixture) =
                            if exercise_deferred_actor_archive {
                                // Qualification-only writer/head stand-in for
                                // the terminal envelope. The successor
                                // dependency itself is selected through the
                                // production projector after a real durable
                                // Handler generation has been closed and
                                // qualified. No production terminal authorizer
                                // or pipeline rotation authority is claimed.
                                let successor_capture =
                                    PendingQueueCaptureContext::try_new(
                                        key,
                                        activation,
                                        published.gathering(),
                                    )?;
                                successor_dependency_capture = Some(successor_capture);
                                let successor_assignment = ledger
                                    .reserve_generation(
                                        &ledger_key,
                                        successor_capture,
                                    )
                                    .await?;
                                let successor_admission_key =
                                    RealmUserUpdateAdmissionKey::try_new(
                                        successor_capture,
                                    )?;
                                admission_guard
                                    .provision_generation::<PHash>(
                                        successor_admission_key,
                                    )
                                    .await?;
                                let successor_observations = Arc::new(
                                    ScyllaRealmAuthorityObservationReader::<PHash>::try_new(
                                        Arc::clone(&head_store),
                                        AuthorityTimestampKey::new(
                                            network,
                                            authority,
                                        ),
                                    )?,
                                );
                                let successor_registry = Arc::new(
                                    RealmUserUpdateVerifierRegistry::try_new([(
                                        profile.clone(),
                                        Arc::clone(&verifier),
                                    )])?,
                                );
                                let successor_router =
                                    ScyllaRealmUserUpdateDurableRouter::<
                                        PF,
                                        PHash,
                                        PoseidonHasher,
                                        PsyTestJTMBProof<PHash>,
                                        Verifier,
                                    >::prepare(
                                        Arc::clone(&session),
                                        network,
                                        authority,
                                        GlobalUserTreeHeight::try_new(
                                            N::GLOBAL_USER_TREE_HEIGHT,
                                        )?,
                                        N::REALM_GLOBAL_USER_TREE_HEIGHT,
                                        profile.id(),
                                        successor_registry,
                                        successor_observations,
                                        Arc::clone(&sidecar_ready),
                                        Arc::clone(&restarted_nats),
                                    )
                                    .await?;
                                successor_router
                                    .attest_startup()
                                    .await
                                    .context(
                                        "successor router startup attestation",
                                    )?;
                                let successor_publisher = Arc::new(
                                    restarted_nats
                                        .recoverable_pending_publisher(
                                            segment.clone(),
                                        )
                                        .await?,
                                );
                                let successor_publish_store =
                                    ScyllaPendingQueuePublishStore::prepare(
                                        Arc::clone(&session),
                                        successor_publisher,
                                        segment.clone(),
                                        PendingQueuePublishKeyspaces::new(
                                            control.clone(),
                                            PendingQueuePublishDataKeyspace::try_new(
                                                fixture::KEYSPACE,
                                            )?,
                                        ),
                                    )
                                    .await?;
                                let publisher_kind =
                                    PendingQueuePublisherKind::RealmUserUpdate;
                                successor_publish_store
                                    .bootstrap_source(
                                        &successor_assignment,
                                        publisher_kind,
                                    )
                                    .await?;
                                let successor_nats_before = stream_messages(
                                    &jetstream,
                                    segment.stream_name(),
                                )
                                .await?;
                                deferred_actor_nats_message_count_before =
                                    successor_nats_before;
                                for (_, input, proof) in
                                    &successor_external_requests
                                {
                                    restarted
                                        .handle_user_end_cap_proof_submission(
                                            input.clone(),
                                            proof.clone(),
                                        )
                                        .await
                                        .context(
                                            "successor durable Handler submission",
                                        )?;
                                }
                                let successor_users = successor_external_requests
                                    .iter()
                                    .map(|(user_id, _, _)| *user_id)
                                    .collect::<BTreeSet<_>>();
                                let successor_external_materials =
                                    read_published_job_materials(
                                        Arc::clone(&session),
                                        claims.as_ref(),
                                        successor_capture,
                                        &successor_users,
                                    )
                                    .await?;
                                ensure!(successor_external_materials.len() == 3);
                                let successor_admission_close =
                                    RealmUserUpdateAdmissionCloseIntent::derive(
                                        successor_admission_key,
                                        [0xDE; 32],
                                    )?;
                                admission_guard
                                    .close_generation::<PHash>(
                                        successor_admission_key,
                                        successor_admission_close,
                                    )
                                    .await?;
                                successor_router
                                    .qualify_generation(
                                        successor_admission_key,
                                        successor_admission_close,
                                    )
                                    .await
                                    .context(
                                        "successor generation qualification",
                                    )?;
                                let dependency_projector =
                                    ScyllaRealmProcessorExternalDependencyProjector::<
                                        PF,
                                        PHash,
                                    >::prepare(
                                        Arc::clone(&session),
                                        network,
                                        authority,
                                        GlobalUserTreeHeight::try_new(
                                            N::GLOBAL_USER_TREE_HEIGHT,
                                        )?,
                                        Arc::clone(&sidecar_ready),
                                        segment.clone(),
                                    )
                                    .await?;
                                let dependency = dependency_projector
                                    .read_exact(
                                        successor_capture,
                                        successor_admission_close,
                                        *successor_assignment
                                            .assignment()
                                            .digest()
                                            .as_bytes(),
                                    )
                                    .await?;
                                let BranchExactWriterReadState::Current(
                                    qualification_writer,
                                ) = activated
                                    .writer_store
                                    .read::<PHash>(BranchExactWriterAuthorityKey::new(
                                        network,
                                        authority,
                                    ))
                                    .await?
                                else {
                                    bail!("qualification writer disappeared")
                                };
                                let AuthorityLocalHeadReadState::Current(
                                    qualification_head,
                                ) = head_store
                                    .read::<PHash>(AuthorityTimestampKey::new(
                                        network,
                                        authority,
                                    ))
                                    .await?
                                else {
                                    bail!("qualification head disappeared")
                                };
                                let envelope =
                                    RealmProcessorTerminalAuthorizationEnvelope::try_new(
                                        dependency.commitment(),
                                        *qualification_writer.slot().as_bytes(),
                                        qualification_writer.revision().get(),
                                        qualification_writer.to_canonical_bytes(),
                                        qualification_head.revision().get(),
                                        qualification_head
                                            .encode_canonical()
                                            .to_vec(),
                                    )?;
                                (
                                    envelope.to_canonical_bytes(),
                                    Some((
                                        successor_capture,
                                        successor_assignment,
                                        successor_publish_store,
                                        successor_nats_before,
                                    )),
                                )
                            } else {
                                (vec![0xB6; 96], None)
                            };
                        // The successor fixture deliberately publishes its
                        // three Data envelopes before terminal/carryover
                        // recovery begins. Start the zero-side-effect window
                        // after those durable inputs exist so they are not
                        // misclassified as recovery traffic.
                        recovery_nats_before =
                            stream_messages(&jetstream, segment.stream_name()).await?;
                        let terminal = RealmProcessorGenerationTerminal::try_new(
                            &published,
                            terminal_reserved,
                            *assignment.assignment().digest().as_bytes(),
                            *application_store.fingerprint().as_bytes(),
                            application,
                            terminal_authorization,
                        )?;
                        terminal_store
                            .qualification_persist(terminal.clone())
                            .await?;
                        qualification_seeded_terminal = true;
                        let expected_carryover =
                            RealmProcessorDeferredCarryover::try_from_terminal_commitment(
                                &terminal,
                                terminal_store.qualification_fingerprint(),
                            )?;

                        // The real derived LWT commits, then the owner loses
                        // control before snapshots B/C. A fresh affine owner
                        // must converge on the same immutable row.
                        qualification_fail_after_carryover_persist_once();
                        let mut failed_iteration = owner.begin_iteration(
                            iteration_gate.try_begin_iteration()?,
                        )?;
                        let failed_recovery = failed_iteration
                            .open_terminal_carryover_recovery()
                            .await?;
                        ensure!(failed_recovery.recover_and_prepare().await.is_err());
                        drop(failed_iteration);
                        ensure!(
                            carryover_store
                                .qualification_read(expected_carryover.slot())
                                .await?
                                == Some(expected_carryover)
                        );
                        let mut recovered_iteration = owner.begin_iteration(
                            iteration_gate.try_begin_iteration()?,
                        )?;
                        let recovered_owner = recovered_iteration
                            .open_terminal_carryover_recovery()
                            .await?;
                        ensure!(matches!(
                            recovered_owner.recover_and_prepare().await?,
                            RealmProcessorTerminalCarryoverRecoveryOutcome::Prepared(_)
                        ));
                        drop(recovered_iteration);
                        terminal_only_repaired = true;
                        post_persist_failure_recovered = true;

                        // Same selected terminal may be retried concurrently
                        // only through the high-level derived store path. All
                        // contenders converge on the same revision-1 row.
                        let mut contenders = Vec::new();
                        for _ in 0..32 {
                            let terminal_store = Arc::clone(&terminal_store);
                            let carryover_store = Arc::clone(&carryover_store);
                            let key = published.key();
                            let activation = published.activation_digest();
                            let predecessor = published.processing();
                            contenders.push(tokio::spawn(async move {
                                carryover_store
                                    .persist_from_selected_terminal::<PHash>(
                                        terminal_store.as_ref(),
                                        key,
                                        activation,
                                        predecessor,
                                    )
                                    .await
                            }));
                        }
                        for contender in contenders {
                            contender.await??;
                            derived_same_retry_count += 1;
                        }
                        ensure!(derived_same_retry_count == 32);

                        // Repeated affine reopen is serialized by the real
                        // single-commit owner and remains read-only once the
                        // exact carryover exists.
                        let before_complete = terminal_recovery_snapshot(&session).await?;
                        for _ in 0..8 {
                            let mut retry_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let retry = retry_iteration
                                .open_terminal_carryover_recovery()
                                .await?;
                            ensure!(matches!(
                                retry.recover_and_prepare().await?,
                                RealmProcessorTerminalCarryoverRecoveryOutcome::Prepared(_)
                            ));
                            drop(retry_iteration);
                            affine_retry_count += 1;
                        }
                        already_complete_recovered = before_complete
                            == terminal_recovery_snapshot(&session).await?;
                        ensure!(already_complete_recovered && affine_retry_count == 8);

                        // Deterministic A/B/C TOCTOU: pause after snapshot A,
                        // corrupt the selected application fragment, let B
                        // fail closed, restore exact bytes, then retry.
                        qualification_pause_after_recovery_snapshot_a_once();
                        let mut toctou_iteration = owner.begin_iteration(
                            iteration_gate.try_begin_iteration()?,
                        )?;
                        let toctou_owner = toctou_iteration
                            .open_terminal_carryover_recovery()
                            .await?;
                        let archive_slot = expected_handoff.archive_slot().to_vec();
                        let semantic_digest = expected_handoff.semantic_digest().to_vec();
                        let fragment_table = format!(
                            "{}.branch_exact_realm_application_archive_fragment_v1",
                            fixture::KEYSPACE,
                        );
                        let (done_tx, done_rx) = oneshot::channel();
                        let recovery_future = async move {
                            let result = toctou_owner.recover_and_prepare().await;
                            let _ = done_tx.send(());
                            result
                        };
                        let mutation_future = async {
                            if timeout(
                                Duration::from_secs(30),
                                qualification_wait_for_recovery_snapshot_a(),
                            )
                            .await
                            .is_err()
                            {
                                qualification_release_recovery_snapshot_a();
                                bail!("terminal recovery did not reach snapshot-A barrier");
                            }
                            let mutation_result = async {
                                let original = session
                                    .query_unpaged(
                                        format!(
                                            "SELECT payload FROM {fragment_table} WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?"
                                        ),
                                        (
                                            archive_slot.as_slice(),
                                            semantic_digest.as_slice(),
                                            0_i64,
                                            0_i32,
                                        ),
                                    )
                                    .await?
                                    .into_rows_result()?
                                    .single_row::<(Vec<u8>,)>()?
                                    .0;
                                let mut corrupt = original.clone();
                                corrupt[0] ^= 0xFF;
                                session
                                    .query_unpaged(
                                        format!(
                                            "UPDATE {fragment_table} SET payload = ? WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?"
                                        ),
                                        (
                                            corrupt.as_slice(),
                                            archive_slot.as_slice(),
                                            semantic_digest.as_slice(),
                                            0_i64,
                                            0_i32,
                                        ),
                                    )
                                    .await?;
                                anyhow::Ok(original)
                            }
                            .await;
                            qualification_release_recovery_snapshot_a();
                            let original = mutation_result?;
                            let _ = done_rx.await;
                            session
                                .query_unpaged(
                                    format!(
                                        "UPDATE {fragment_table} SET payload = ? WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?"
                                    ),
                                    (
                                        original.as_slice(),
                                        archive_slot.as_slice(),
                                        semantic_digest.as_slice(),
                                        0_i64,
                                        0_i32,
                                    ),
                                )
                                .await?;
                            anyhow::Ok(())
                        };
                        let (toctou_result, mutation_result) =
                            tokio::join!(recovery_future, mutation_future);
                        mutation_result?;
                        ensure!(toctou_result.is_err());
                        drop(toctou_iteration);
                        let mut restored_iteration = owner.begin_iteration(
                            iteration_gate.try_begin_iteration()?,
                        )?;
                        let restored = restored_iteration
                            .open_terminal_carryover_recovery()
                            .await?;
                        ensure!(matches!(
                            restored.recover_and_prepare().await?,
                            RealmProcessorTerminalCarryoverRecoveryOutcome::Prepared(_)
                        ));
                        drop(restored_iteration);
                        application_toctou_rejected = true;

                        // Different-content poison uses an isolated synthetic
                        // successor. The production high-level repair path
                        // must reject the preoccupied locator and preserve it.
                        let synthetic_ready = terminal.candidate_pipeline().clone();
                        let synthetic_close =
                            PendingQueueCloseIntentDigest::try_new([0xC0; 32])?;
                        let synthetic_intent =
                            PendingPipelineIntentDigest::try_new([0xC1; 32])?;
                        let synthetic_captured = synthetic_ready
                            .seal_begin_queue_close(synthetic_close)?
                            .candidate()
                            .seal_capture_work(
                                synthetic_close,
                                PendingWorkCaptureDigest::try_new(
                                    *application.archive_slot().as_bytes(),
                                )?,
                            )?
                            .candidate()
                            .clone();
                        let synthetic_inflight = synthetic_captured
                            .seal_begin_processing(
                                PendingWorkCaptureDigest::try_new(
                                    *application.archive_slot().as_bytes(),
                                )?,
                                synthetic_intent,
                            )?
                            .candidate()
                            .clone();
                        let synthetic_published = synthetic_inflight
                            .seal_publish(
                                synthetic_intent,
                                PendingPublishReceiptDigest::try_new([0xC2; 32])?,
                                next_terminal_observation(
                                    synthetic_inflight.frontier(),
                                    0xC3,
                                )?,
                            )?
                            .candidate()
                            .clone();
                        let synthetic_reserved =
                            ReservedPendingGeneration::qualification_from_prefix(
                                synthetic_published
                                    .gathering()
                                    .pending_id()
                                    .get()
                                    .checked_add(1)
                                    .ok_or_else(|| anyhow::anyhow!(
                                        "synthetic successor overflow"
                                    ))?,
                                prefix,
                            )?;
                        let synthetic_winner = RealmProcessorGenerationTerminal::try_new(
                            &synthetic_published,
                            synthetic_reserved,
                            *assignment.assignment().digest().as_bytes(),
                            *application_store.fingerprint().as_bytes(),
                            application,
                            vec![0xC4; 96],
                        )?;
                        let synthetic_loser = RealmProcessorGenerationTerminal::try_new(
                            &synthetic_published,
                            synthetic_reserved,
                            *assignment.assignment().digest().as_bytes(),
                            *application_store.fingerprint().as_bytes(),
                            application,
                            vec![0xC5; 96],
                        )?;
                        terminal_store
                            .qualification_persist(synthetic_winner.clone())
                            .await?;
                        let loser_carryover =
                            RealmProcessorDeferredCarryover::try_from_terminal_commitment(
                                &synthetic_loser,
                                terminal_store.qualification_fingerprint(),
                            )?;
                        carryover_store
                            .qualification_persist(loser_carryover)
                            .await?;
                        derived_different_contender_conflict = matches!(
                            carryover_store
                                .persist_from_selected_terminal::<PHash>(
                                    terminal_store.as_ref(),
                                    synthetic_published.key(),
                                    synthetic_published.activation_digest(),
                                    synthetic_published.processing(),
                                )
                                .await,
                            Err(RealmProcessorDeferredCarryoverStoreError::Conflict)
                        ) && carryover_store
                            .qualification_read(loser_carryover.slot())
                            .await?
                            == Some(loser_carryover);
                        ensure!(derived_different_contender_conflict);

                        let (_, _, pipeline_after_recovery) = application_store
                            .observe_generation_continuation::<PHash>(
                                &pipeline_store,
                                &assignment,
                            )
                            .await?;
                        terminal_recovery_pipeline_unchanged =
                            pipeline_after_recovery == published;
                        ensure!(terminal_recovery_pipeline_unchanged);
                        terminal_recovery_nats_delta = stream_messages(
                            &jetstream,
                            segment.stream_name(),
                        )
                        .await?
                        .checked_sub(recovery_nats_before)
                        .ok_or_else(|| anyhow::anyhow!("NATS message count regressed"))?;
                        ensure!(terminal_recovery_nats_delta == 0);

                        if exercise_deferred_actor_archive {
                            v14_ready_receipt_consumed = true;
                            predecessor_nonempty_input_rf3 =
                                application.deferred_count() == 3;
                            ensure!(predecessor_nonempty_input_rf3);
                            let Some((
                                successor_capture,
                                successor_assignment,
                                successor_publish_store,
                                successor_nats_before,
                            )) = successor_fixture
                            else {
                                bail!("deferred actor successor fixture missing")
                            };
                            let publisher_kind =
                                PendingQueuePublisherKind::RealmUserUpdate;

                            let rotation = published.seal_rotation(terminal_reserved)?;
                            ensure!(rotation.candidate() == terminal.candidate_pipeline());
                            let successor_ready = current_pipeline(
                                pipeline_store.apply(&rotation).await?,
                            )?;
                            ensure!(successor_ready.processing() == terminal.successor());
                            let successor_close =
                                PendingQueueCloseIntentDigest::try_new([0xDC; 32])?;
                            let successor_sealing = current_pipeline(
                                pipeline_store
                                    .apply(&successor_ready.seal_begin_queue_close(
                                        successor_close,
                                    )?)
                                    .await?,
                            )?;
                            let successor_close_receipt = pipeline_store
                                .read_queue_close_exact::<PHash>(successor_capture)
                                .await?;
                            let seal_slot = successor_publish_store
                                .materialize_seal::<PHash>(
                                    &pipeline_store,
                                    &successor_assignment,
                                    publisher_kind,
                                    PendingQueuePublishIntentId::try_new([0xDD; 32])?,
                                    &successor_close_receipt,
                                )
                                .await?;
                            let seal = successor_publish_store
                                .bind_materialized(
                                    &successor_assignment,
                                    publisher_kind,
                                    seal_slot,
                                )
                                .await?;
                            successor_publish_store
                                .publish_and_commit(&successor_assignment, seal)
                                .await?;
                            expected_nats_after_deferred_actor = successor_nats_before + 4;
                            ensure!(
                                stream_messages(&jetstream, segment.stream_name()).await?
                                    == expected_nats_after_deferred_actor
                            );
                            external_generation_items = 3;
                            external_generation_nonempty_rf3 = true;

                            // Fresh C: A/B prepared a fully storage-selected
                            // predecessor input. Corrupt its selected fragment
                            // before capture-open; exact C must reject before
                            // creating a consumer/owner or running the actor.
                            let archive_slot = expected_handoff.archive_slot().to_vec();
                            let semantic_digest = expected_handoff.semantic_digest().to_vec();
                            let original_fragment = qualification_read_application_fragment(
                                &session,
                                &archive_slot,
                                &semantic_digest,
                            )
                            .await?;
                            let mut corrupt_fragment = original_fragment.clone();
                            corrupt_fragment[0] ^= 0xFF;
                            let c_nats_before = stream_messages(
                                &jetstream,
                                segment.stream_name(),
                            )
                            .await?;
                            let mut c_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let c_input = match c_iteration
                                .prepare_deferred_actor_input()
                                .await?
                            {
                                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                                    bail!("successor predecessor carryover was not selected")
                                }
                            };
                            ensure!(c_input.deferred_jobs().len() == 3);
                            qualification_write_application_fragment(
                                &session,
                                &archive_slot,
                                &semantic_digest,
                                &corrupt_fragment,
                            )
                            .await?;
                            let c_result = c_iteration
                                .open_durable_capture_for_deferred_input(c_input)
                                .await;
                            let c_rejected = c_result.is_err();
                            drop(c_result);
                            qualification_write_application_fragment(
                                &session,
                                &archive_slot,
                                &semantic_digest,
                                &original_fragment,
                            )
                            .await?;
                            ensure!(c_rejected);
                            drop(c_iteration);
                            let c_nats_after =
                                stream_messages(&jetstream, segment.stream_name()).await?;
                            fresh_c_nats_delta = c_nats_after
                                .checked_sub(c_nats_before)
                                .ok_or_else(|| anyhow::anyhow!(
                                    "Fresh C NATS count regressed"
                                ))?;
                            ensure!(fresh_c_nats_delta == 0);
                            fresh_c_fault_rf3 = true;

                            // Fresh D: capture/replay may already have durably
                            // ACKed the closed successor source, but a lineage
                            // drift before the one-shot actor take must still
                            // reject with no actor execution. A fresh owner can
                            // subsequently replay the immutable artifact.
                            let mut d_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let d_input = match d_iteration
                                .prepare_deferred_actor_input()
                                .await?
                            {
                                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                                    bail!("successor predecessor carryover disappeared")
                                }
                            };
                            let mut d_capture = d_iteration
                                .open_durable_capture_for_deferred_input(d_input)
                                .await?;
                            let mut successor_captured_items = 0_u64;
                            let mut successor_close_observed = false;
                            for _ in 0..8 {
                                match d_capture.capture_next().await? {
                                    Some(RealmProcessorDurableCaptureOutcome::Data(candidate)) => {
                                        successor_captured_items = successor_captured_items
                                            .checked_add(candidate.item_count())
                                            .ok_or_else(|| anyhow::anyhow!(
                                                "successor capture item overflow"
                                            ))?;
                                    }
                                    Some(RealmProcessorDurableCaptureOutcome::Sealed {
                                        data,
                                        ..
                                    }) => {
                                        successor_captured_items = successor_captured_items
                                            .checked_add(data.as_ref().map_or(
                                                0,
                                                |candidate| candidate.item_count(),
                                            ))
                                            .ok_or_else(|| anyhow::anyhow!(
                                                "successor sealed capture item overflow"
                                            ))?;
                                        successor_close_observed = true;
                                        break;
                                    }
                                    None => sleep(Duration::from_millis(100)).await,
                                }
                            }
                            ensure!(successor_close_observed);
                            ensure!(successor_captured_items == 3);
                            let d_generation = d_capture
                                .replay_complete_generation()
                                .await?
                                .ok_or_else(|| anyhow::anyhow!(
                                    "successor closed source did not replay"
                                ))?;
                            ensure!(d_generation.item_count() == 3);
                            qualification_write_application_fragment(
                                &session,
                                &archive_slot,
                                &semantic_digest,
                                &corrupt_fragment,
                            )
                            .await?;
                            let d_result = d_capture.take_deferred_actor_input().await;
                            let d_rejected = d_result.is_err();
                            drop(d_result);
                            qualification_write_application_fragment(
                                &session,
                                &archive_slot,
                                &semantic_digest,
                                &original_fragment,
                            )
                            .await?;
                            ensure!(d_rejected);
                            drop(d_capture);
                            drop(d_iteration);
                            fresh_d_fault_rf3 = true;
                            fresh_d_actor_delta = 0;

                            // The real Realm actor/retry/archive chain follows
                            // after the C/D fault windows have restored exact
                            // storage bytes.
                            qualification_start_realm_deferred_actor_trace()?;
                            let (actor, actor_task, actor_temp, actor_state) =
                                start_qualification_realm_actor(
                                    successor_capture,
                                    *successor_sealing.frontier().chain(),
                                    checkpoint_id,
                                )
                                .await?;

                            // Apply response is intentionally discarded. A
                            // fresh storage owner reconstructs the non-Clone
                            // input/generation and the actor returns revision 1
                            // without rebuilding its tentative state.
                            let mut apply1_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let apply1_input = match apply1_iteration
                                .prepare_deferred_actor_input()
                                .await?
                            {
                                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                                    bail!("successor input became unavailable before actor apply")
                                }
                            };
                            let mut apply1_capture = apply1_iteration
                                .open_durable_capture_for_deferred_input(apply1_input)
                                .await?;
                            let apply1_generation = apply1_capture
                                .replay_complete_generation()
                                .await?
                                .ok_or_else(|| anyhow::anyhow!(
                                    "successor generation disappeared before actor apply"
                                ))?;
                            let apply1_external = apply1_capture
                                .qualify_external_actor_input(apply1_generation)
                                .await?;
                            let apply1_deferred = apply1_capture
                                .take_deferred_actor_input()
                                .await?;
                            let apply1_input = RealmProcessorActorInput::try_new(
                                apply1_deferred,
                                apply1_external,
                            )?;
                            let actor_input_digest = apply1_input.digest();
                            let discarded_apply = actor
                                .qualification_apply_durable_generation(apply1_input)
                                .await?;
                            ensure!(discarded_apply.actor_revision().get() == 1);
                            ensure!(discarded_apply.actor_input_digest() == actor_input_digest);
                            apply_retry_bit_exact = true;
                            drop(discarded_apply);
                            drop(apply1_capture);
                            drop(apply1_iteration);

                            let mut finalize1_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let finalize1_input = match finalize1_iteration
                                .prepare_deferred_actor_input()
                                .await?
                            {
                                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                                    bail!("successor input became unavailable before finalize")
                                }
                            };
                            let mut finalize1_capture = finalize1_iteration
                                .open_durable_capture_for_deferred_input(finalize1_input)
                                .await?;
                            let finalize1_generation = finalize1_capture
                                .replay_complete_generation()
                                .await?
                                .ok_or_else(|| anyhow::anyhow!(
                                    "successor generation disappeared before finalize"
                                ))?;
                            let finalize1_external = finalize1_capture
                                .qualify_external_actor_input(finalize1_generation)
                                .await?;
                            let finalize1_deferred = finalize1_capture
                                .take_deferred_actor_input()
                                .await?;
                            let finalize1_input = RealmProcessorActorInput::try_new(
                                finalize1_deferred,
                                finalize1_external,
                            )?;
                            let apply_retry = actor
                                .qualification_apply_durable_generation(finalize1_input)
                                .await?;
                            ensure!(apply_retry.actor_revision().get() == 1);
                            let discarded_finalize = actor
                                .qualification_finalize_durable_generation(apply_retry)
                                .await?;
                            ensure!(discarded_finalize.actor_revision().get() == 2);
                            let discarded_semantic =
                                qualification_project_branch_exact_semantic_output::<
                                    N,
                                    InMemoryTempStore,
                                >(
                                    actor_temp.as_ref(),
                                    &actor_state,
                                    successor_capture.processing(),
                                    &discarded_finalize,
                                )
                                .await?;
                            let discarded_semantic_bytes =
                                discarded_semantic.to_canonical_bytes();
                            drop(discarded_finalize);
                            drop(finalize1_capture);
                            drop(finalize1_iteration);

                            // Final retry keeps the capture alive so the v3
                            // semantic can flow through the exact production
                            // archive/handoff method after retry invariants and
                            // a different-input rejection are checked.
                            let mut final_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let final_input = match final_iteration
                                .prepare_deferred_actor_input()
                                .await?
                            {
                                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                                    bail!("successor input became unavailable on final retry")
                                }
                            };
                            let mut final_capture = final_iteration
                                .open_durable_capture_for_deferred_input(final_input)
                                .await?;
                            let final_generation = final_capture
                                .replay_complete_generation()
                                .await?
                                .ok_or_else(|| anyhow::anyhow!(
                                    "successor generation disappeared on final retry"
                                ))?;
                            let final_external = final_capture
                                .qualify_external_actor_input(final_generation)
                                .await?;
                            let final_deferred = final_capture
                                .take_deferred_actor_input()
                                .await?;
                            let final_input = RealmProcessorActorInput::try_new(
                                final_deferred,
                                final_external,
                            )?;
                            let final_apply = actor
                                .qualification_apply_durable_generation(final_input)
                                .await?;
                            ensure!(final_apply.actor_revision().get() == 1);
                            let final_receipt = actor
                                .qualification_finalize_durable_generation(final_apply)
                                .await?;
                            ensure!(final_receipt.actor_revision().get() == 2);
                            ensure!(final_receipt.actor_input_digest() == actor_input_digest);
                            let final_semantic =
                                qualification_project_branch_exact_semantic_output::<
                                    N,
                                    InMemoryTempStore,
                                >(
                                    actor_temp.as_ref(),
                                    &actor_state,
                                    successor_capture.processing(),
                                    &final_receipt,
                                )
                                .await?;
                            ensure!(
                                final_semantic.to_canonical_bytes()
                                    == discarded_semantic_bytes
                            );
                            ensure!(
                                final_semantic.actor_input_digest()
                                    == Some(actor_input_digest)
                            );
                            finalize_retry_bit_exact = true;
                            semantic_v3_input_bound = true;

                            // Release the final actor capture before opening
                            // independent affine owners for the different-
                            // input cache check and the archive handoff.
                            drop(final_capture);
                            drop(final_iteration);

                            let different_carryover =
                                RealmProcessorDeferredCarryover::try_bootstrap_empty(
                                    key,
                                    activation,
                                    successor_capture.processing(),
                                    PendingGenerationBootstrapReason::LegacyActivation,
                                )?;
                            let different_input =
                                RealmProcessorDeferredActorInput::try_from_storage(
                                    successor_capture.processing(),
                                    PendingGenerationBootstrapReason::LegacyActivation,
                                    different_carryover,
                                    None,
                                )?;
                            let mut different_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let selected_different_input = match different_iteration
                                .prepare_deferred_actor_input()
                                .await?
                            {
                                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                                    bail!("successor input unavailable for different-input test")
                                }
                            };
                            let mut different_capture = different_iteration
                                .open_durable_capture_for_deferred_input(
                                    selected_different_input,
                                )
                                .await?;
                            let different_generation = different_capture
                                .replay_complete_generation()
                                .await?
                                .ok_or_else(|| anyhow::anyhow!(
                                    "successor generation unavailable for different-input test"
                                ))?;
                            let different_external = different_capture
                                .qualify_external_actor_input(different_generation)
                                .await?;
                            let _selected_deferred = different_capture
                                .take_deferred_actor_input()
                                .await?;
                            let different_actor_input = RealmProcessorActorInput::try_new(
                                different_input,
                                different_external,
                            )?;
                            ensure!(different_actor_input.digest() != actor_input_digest);
                            different_input_rejected = actor
                                .qualification_apply_durable_generation(
                                    different_actor_input,
                                )
                                .await
                                .is_err();
                            ensure!(different_input_rejected);
                            drop(different_capture);
                            drop(different_iteration);

                            successor_application_semantic_bytes =
                                final_semantic.canonical_len()?;
                            successor_application_fragments = u32::try_from(
                                successor_application_semantic_bytes
                                    .div_ceil(4 * 1024 * 1024),
                            )?;
                            let mut handoff_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let handoff_input = match handoff_iteration
                                .prepare_deferred_actor_input()
                                .await?
                            {
                                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
                                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover { .. } => {
                                    bail!("successor input unavailable before archive handoff")
                                }
                            };
                            let mut handoff_capture = handoff_iteration
                                .open_durable_capture_for_deferred_input(handoff_input)
                                .await?;
                            let handoff_generation = handoff_capture
                                .replay_complete_generation()
                                .await?
                                .ok_or_else(|| anyhow::anyhow!(
                                    "successor generation unavailable before archive handoff"
                                ))?;
                            let handoff_external = handoff_capture
                                .qualify_external_actor_input(handoff_generation)
                                .await?;
                            let handoff_deferred = handoff_capture
                                .take_deferred_actor_input()
                                .await?;
                            let handoff_actor_input = RealmProcessorActorInput::try_new(
                                handoff_deferred,
                                handoff_external,
                            )?;
                            ensure!(handoff_actor_input.digest() == actor_input_digest);
                            let successor_handoff = handoff_capture
                                .persist_application_and_handoff(final_semantic)
                                .await?;
                            ensure!(successor_handoff.has_application_work());
                            successor_handoff_revision =
                                successor_handoff.pipeline_revision();
                            application_archive_handoff_rf3 = true;
                            actor_handoff_during_one_replica_offline = true;
                            let same_successor_handoff = handoff_capture
                                .recover_application_handoff()
                                .await?
                                .ok_or_else(|| anyhow::anyhow!(
                                    "successor handoff was not recoverable in owner"
                                ))?;
                            ensure!(same_successor_handoff == successor_handoff);
                            drop(handoff_capture);
                            drop(handoff_iteration);
                            let mut successor_recovery_iteration = owner.begin_iteration(
                                iteration_gate.try_begin_iteration()?,
                            )?;
                            let successor_continuation = successor_recovery_iteration
                                .observe_generation_continuation()
                                .await?;
                            ensure!(
                                successor_continuation.application().is_some_and(|application| {
                                    application.archive_slot().as_bytes()
                                        == successor_handoff.archive_slot()
                                        && application.semantic_digest().as_bytes()
                                            == successor_handoff.semantic_digest()
                                })
                            );
                            let trace = qualification_finish_realm_deferred_actor_trace()?;
                            ensure!(trace.builder_create_count == 1);
                            ensure!(trace.finalize_count == 1);
                            ensure!(trace.entries.len() == 6);
                            ensure!(trace.entries[..3].iter().all(|entry| {
                                entry.kind == RealmDeferredActorTraceKind::Deferred
                            }));
                            ensure!(trace.entries[3..].iter().all(|entry| {
                                entry.kind == RealmDeferredActorTraceKind::External
                            }));
                            actor_builder_create_count = trace.builder_create_count;
                            actor_finalize_count = trace.finalize_count;
                            deferred_before_external_rf3 = true;
                            let mut trace_hasher = Sha256::new();
                            trace_hasher.update(
                                b"psy/rf3/d04b6h23c4c4b4c2/realm-actor-trace/v1",
                            );
                            for entry in &trace.entries {
                                trace_hasher.update([match entry.kind {
                                    RealmDeferredActorTraceKind::Deferred => 1,
                                    RealmDeferredActorTraceKind::External => 2,
                                }]);
                                trace_hasher
                                    .update((entry.job_id.len() as u64).to_be_bytes());
                                trace_hasher.update(&entry.job_id);
                            }
                            ordered_actor_trace_digest =
                                hex::encode(trace_hasher.finalize());
                            handoff_recovery_without_actor_rerun =
                                actor_builder_create_count == 1 && actor_finalize_count == 1;
                            ensure!(handoff_recovery_without_actor_rerun);
                            drop(successor_recovery_iteration);
                            drop(actor);
                            timeout(Duration::from_secs(30), actor_task).await???;
                        }
                    }

                    #[cfg(not(feature = "rf3-test-support"))]
                    ensure!(
                        !exercise_terminal_recovery,
                        "c4b3b2 requires the explicit rf3-test-support feature"
                    );

                    // Exercise the real Scylla scanner against three
                    // independent, non-authoritative archive slots.  Raw CQL
                    // is deliberately confined to this RF=3 poison fixture:
                    // production adapters expose no delete/overwrite/extra
                    // coordinate API.
                    let poison_store = ScyllaRealmProcessorApplicationArchiveStore::prepare(
                        Arc::clone(&session),
                        control.clone(),
                        PendingQueueArtifactDataKeyspace::try_new(fixture::KEYSPACE)?,
                    )
                    .await?;
                    for poison_case in 1_u8..=3 {
                        let binding = RealmProcessorApplicationArchiveBinding::try_new(
                            network.chain_id(),
                            REALM_ID,
                            REALM_SUB_ID,
                            [0xB0 + poison_case; 32],
                            [0xC0 + poison_case; 32],
                            [0xD0 + poison_case; 32],
                            [0xE0 + poison_case; 32],
                            [0x90 + poison_case; 32],
                            u64::from(poison_case),
                            [0x70 + poison_case; 32],
                            [0x60 + poison_case; 32],
                        )?;
                        let semantic = RealmProcessorSemanticOutput::try_from_candidate_parts(
                            RealmProcessorSemanticOutputParts {
                                context_digest: replayed_context_digest,
                                generation_digest: replayed_generation_digest,
                                boundary_digest: replayed_boundary_digest,
                                item_count: replayed_item_count,
                                input_binding: psy_node_core::queue::realm_processor_semantic_output::RealmProcessorSemanticInputBinding::SuccessorQualified(
                                    RealmProcessorActorInputDigest::try_new(
                                        [0xA0 + poison_case; 32],
                                    )?,
                                ),
                                processing_checkpoint_id: checkpoint_id,
                                processing_checkpoint_root: [0x40 + poison_case; 32],
                                processing_realm_start_root: [0x50 + poison_case; 32],
                                old_realm_root: [0x50 + poison_case; 32],
                                new_realm_root: [0x51 + poison_case; 32],
                                total_users_updated: 1,
                                total_proofs_generated: 0,
                                global_user_tree_nodes: vec![poison_case; 1024],
                                user_contract_tree_nodes: Vec::new(),
                                contract_state_tree_nodes: Vec::new(),
                                user_leaves: Vec::new(),
                                contract_state_imt_leaves: Vec::new(),
                                guta_header: vec![poison_case],
                                jobs: Vec::new(),
                                deferred_jobs: Vec::new(),
                            },
                        )?;
                        let plan = RealmProcessorApplicationArchivePlan::try_new(
                            binding,
                            &semantic,
                        )?;
                        ensure!(plan.fragments().len() == 1);
                        poison_store.persist_and_readback(&plan).await?;
                        let fragment = &plan.fragments()[0];
                        let fragment_table = format!(
                            "{}.branch_exact_realm_application_archive_fragment_v1",
                            fixture::KEYSPACE,
                        );
                        match poison_case {
                            1 => {
                                session
                                    .query_unpaged(
                                        format!(
                                            "INSERT INTO {fragment_table} (archive_slot, application_digest, fragment_bucket, fragment_index, fragment_count, application_bytes, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                                        ),
                                        (
                                            fragment.slot().as_bytes().as_slice(),
                                            fragment.semantic_digest().as_bytes().as_slice(),
                                            i64::from(fragment.bucket()),
                                            1_i32,
                                            i32::try_from(fragment.fragment_count())?,
                                            i64::try_from(fragment.semantic_bytes())?,
                                            fragment.payload(),
                                            fragment.payload_digest().as_bytes().as_slice(),
                                        ),
                                    )
                                    .await?;
                            }
                            2 => {
                                let mut corrupt = fragment.payload().to_vec();
                                corrupt[0] ^= 1;
                                session
                                    .query_unpaged(
                                        format!(
                                            "INSERT INTO {fragment_table} (archive_slot, application_digest, fragment_bucket, fragment_index, fragment_count, application_bytes, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                                        ),
                                        (
                                            fragment.slot().as_bytes().as_slice(),
                                            fragment.semantic_digest().as_bytes().as_slice(),
                                            i64::from(fragment.bucket()),
                                            i32::try_from(fragment.index())?,
                                            i32::try_from(fragment.fragment_count())?,
                                            i64::try_from(fragment.semantic_bytes())?,
                                            corrupt,
                                            fragment.payload_digest().as_bytes().as_slice(),
                                        ),
                                    )
                                    .await?;
                            }
                            3 => {
                                session
                                    .query_unpaged(
                                        format!(
                                            "DELETE FROM {fragment_table} WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?"
                                        ),
                                        (
                                            fragment.slot().as_bytes().as_slice(),
                                            fragment.semantic_digest().as_bytes().as_slice(),
                                            i64::from(fragment.bucket()),
                                            i32::try_from(fragment.index())?,
                                        ),
                                    )
                                    .await?;
                            }
                            _ => unreachable!(),
                        }
                        ensure!(
                            poison_store
                                .read_selected(plan.header().slot())
                                .await
                                .is_err(),
                            "RF=3 application scanner accepted poison case {poison_case}",
                        );
                    }
                }
                true
            } else {
                let empty = capture_owner.capture_next().await?.is_none();
                ensure!(empty, "empty poll unexpectedly formed a capture outcome");
                empty
            };
            (item_count, empty)
        } else {
            (0, false)
        };

    fixture::compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart e3 Scylla replica",
    )?;
    fixture::wait_up(3).await?;

    let mut dependency_captures = vec![capture];
    if let Some(successor_capture) = successor_dependency_capture {
        dependency_captures.push(successor_capture);
    }
    let dependency_explicit_timestamp_verified =
        dependency_timestamps_match_durable_claims(
            &session,
            claims.as_ref(),
            &dependency_captures,
        )
        .await?;
    ensure!(dependency_explicit_timestamp_verified);
    let repair_started = Instant::now();
    fixture::nodetool(
        fixture::NODE_CONTAINERS[0],
        &["cluster", "repair", fixture::KEYSPACE],
        "repair e3 data",
    )?;
    for node in fixture::NODE_CONTAINERS {
        fixture::nodetool(
            node,
            &["repair", "-pr", &fixture::control_keyspace()],
            "repair e3 control",
        )?;
        fixture::nodetool(
            node,
            &["flush", fixture::KEYSPACE],
            "flush e3 data",
        )?;
        fixture::nodetool(
            node,
            &["flush", &fixture::control_keyspace()],
            "flush e3 control",
        )?;
        fixture::nodetool(
            node,
            &["compact", fixture::KEYSPACE],
            "compact e3 data",
        )?;
        fixture::nodetool(
            node,
            &["compact", &fixture::control_keyspace()],
            "compact e3 control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis();
    let replicas = futures::future::join_all(
        fixture::NODE_IPS.map(|ip| {
            direct_one_snapshot(
                ip,
                exercise_durable_replay,
                exercise_application_handoff,
                exercise_terminal_recovery,
            )
        }),
    )
    .await
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()?;
    ensure!(replicas.len() == 3);
    ensure!(
        replicas.iter().all(|replica| replica == &replicas[0]),
        "repair left divergent e3 direct-ONE rows"
    );
    ensure!(
        replicas[0].0.len()
            == CONTROL_DIRECT_ONE_TABLES.len() + DATA_DIRECT_ONE_TABLES.len()
                + if exercise_durable_replay {
                    DURABLE_REPLAY_CONTROL_TABLES.len()
                        + DURABLE_REPLAY_DATA_TABLES.len()
                } else {
                    0
                }
                + if exercise_application_handoff {
                    APPLICATION_HANDOFF_CONTROL_TABLES.len()
                        + APPLICATION_HANDOFF_DATA_TABLES.len()
                } else {
                    0
                }
                + if exercise_terminal_recovery {
                    TERMINAL_RECOVERY_CONTROL_TABLES.len()
                } else {
                    0
                }
    );
    let replica = &replicas[0];
    let control = fixture::control_keyspace();
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_realm_user_update_admission_v1",
        )? == if exercise_deferred_actor_archive {
            2 * (usize::from(RealmUserUpdateClaimBucket::COUNT) + 1)
        } else if exercise_durable_replay {
            usize::from(RealmUserUpdateClaimBucket::COUNT) + 1
        } else {
            4
        }
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_realm_user_update_claim_v2",
        )? == if exercise_deferred_actor_archive { 6 } else { 3 }
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_pending_queue_publish_source_v1",
        )? == if exercise_deferred_actor_archive { 2 } else { 1 }
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_pending_queue_publish_intent_v1",
        )? == if exercise_deferred_actor_archive {
            8
        } else if exercise_durable_replay {
            4
        } else {
            3
        }
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_pending_queue_publish_prepared_v1",
        )? == if exercise_deferred_actor_archive {
            8
        } else if exercise_durable_replay {
            4
        } else {
            3
        }
    );
    ensure!(
        replica.row_count(
            fixture::KEYSPACE,
            "branch_exact_realm_user_update_dependency_fragment_v1",
        )? >= 15
    );
    ensure!(
        replica.row_count(
            fixture::KEYSPACE,
            "branch_exact_pending_queue_publish_payload_fragment_v1",
        )? == if exercise_deferred_actor_archive { 6 } else { 3 }
    );
    if exercise_application_handoff {
        ensure!(
            replica.row_count(
                &control,
                "branch_exact_pending_queue_semantic_generation_v2",
            )? == if exercise_deferred_actor_archive { 2 } else { 1 }
        );
        ensure!(
            replica.row_count(
                &control,
                "branch_exact_realm_application_archive_header_v1",
            )? == if exercise_deferred_actor_archive { 5 } else { 4 }
        );
        ensure!(
            replica.row_count(
                fixture::KEYSPACE,
                "branch_exact_realm_application_archive_fragment_v1",
            )? == usize::try_from(application_fragments)?
                + usize::try_from(successor_application_fragments)?
                + 3
        );
    }
    if exercise_terminal_recovery {
        ensure!(
            replica.row_count(
                &control,
                REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
            )? == 2
        );
        ensure!(
            replica.row_count(
                &control,
                REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
            )? == 3
        );
    }

    let nats_envelope_dataset =
        nats_message_envelope_dataset(&jetstream, segment.stream_name()).await?;
    let deferred_actor_nats_duplicate_delta = if exercise_deferred_actor_archive {
        nats_envelope_dataset
            .message_count
            .checked_sub(expected_nats_after_deferred_actor)
            .ok_or_else(|| anyhow::anyhow!("deferred actor NATS message count regressed"))?
    } else {
        0
    };
    ensure!(deferred_actor_nats_duplicate_delta == 0);

    let report = E3Report {
        scylla_image: IMAGE,
        scylla_replication_factor: 3,
        configured_nats_servers: 3,
        nats_stream_replicas: 3,
        nats_kv_replicas: 3,
        nats_kv_replica_mismatch_rejected,
        real_realm_edge_handler: true,
        jtmb_cli_profile_matched: true,
        production_jtmb_zk_proof: false,
        startup_route_attested: true,
        invalid_pi_created_no_rows: before_invalid_rows == after_invalid_rows,
        invalid_pi_nats_delta: after_invalid - before_invalid,
        planned_pointer_zero_fragment_replay,
        planned_pointer_replay_messages,
        scylla_one_replica_offline: true,
        concurrent_valid_attempts: 2,
        concurrent_valid_single_publish: first_publish_messages
            == planned_pointer_replay_messages + 1,
        first_publish_messages,
        response_loss_retry_messages,
        nats_leader_before: leader_before.clone(),
        nats_leader_after: leader_after.clone(),
        nats_leader_failover: leader_before != leader_after,
        // wait_for_stream_leader only returns after five stable observations
        // with a surviving current follower at lag zero.
        nats_surviving_follower_current_lag_zero: true,
        nats_message_envelope_count: nats_envelope_dataset.message_count,
        nats_message_envelope_dataset_digest: nats_envelope_dataset.dataset_digest,
        deferred_actor_nats_message_count_before,
        deferred_actor_nats_message_count_after: expected_nats_after_deferred_actor,
        deferred_actor_nats_duplicate_delta,
        second_publish_messages,
        startup_restart_attested: true,
        restart_retry_messages,
        dependency_explicit_timestamp_verified,
        repair_ms,
        repair_direct_one_tables: replicas[0].0.len(),
        repair_direct_one_equal: true,
        durable_capture_owner_tested: exercise_durable_capture,
        durable_capture_items,
        durable_capture_empty_poll_not_close,
        durable_generation_replayed,
        durable_generation_items,
        durable_generation_digest_stable,
        gather_task_restart_replayed,
        processor_route_compiled: exercise_durable_replay,
        command_only_with_tree_compiled: exercise_durable_replay,
        processor_gatherer_integrated: exercise_durable_replay,
        // The real production types and private route compile and are covered
        // by common-crate actor/Processor tests, but the serving guard remains
        // intentionally closed; this RF=3 process does not run a full node.
        processor_gatherer_rf3_runtime: false,
        semantic_handoff_integrated: exercise_application_handoff,
        application_archive_data_rf3: exercise_application_handoff,
        application_semantic_bytes,
        application_fragments,
        application_pipeline_revision,
        application_restart_recovered,
        fresh_source_assignment_close: exercise_application_handoff,
        first_pipeline_cas: exercise_application_handoff,
        missing_extra_corrupt_rf3: exercise_application_handoff,
        affine_terminal_carryover_recovery: exercise_terminal_recovery,
        qualification_seeded_terminal,
        inbound_missing_zero_write,
        nonterminal_zero_write,
        terminal_absent_zero_write,
        terminal_only_repaired,
        post_persist_failure_recovered,
        already_complete_recovered,
        affine_retry_count,
        derived_same_retry_count,
        derived_different_contender_conflict,
        application_toctou_rejected,
        terminal_recovery_pipeline_unchanged,
        terminal_recovery_nats_delta,
        terminal_recovery_socket_response_loss_injected: false,
        sidecar_v14_rf3_inherited: exercise_deferred_actor_archive,
        v14_ready_receipt_consumed,
        qualification_constructed_predecessor_semantic,
        predecessor_nonempty_input_rf3,
        predecessor_deferred_count,
        explicit_empty_input_rf3,
        explicit_empty_reason: if exercise_deferred_actor_archive {
            "LegacyActivation"
        } else {
            "none"
        },
        predecessor_zero_input_rf3: false,
        external_generation_nonempty_rf3,
        external_generation_items,
        deferred_before_external_rf3,
        ordered_actor_trace_digest,
        fresh_c_fault_rf3,
        fresh_c_nats_delta,
        fresh_d_fault_rf3,
        fresh_d_actor_delta,
        apply_retry_bit_exact,
        finalize_retry_bit_exact,
        different_input_rejected,
        actor_builder_create_count,
        actor_finalize_count,
        semantic_v3_input_bound,
        successor_application_semantic_bytes,
        successor_application_fragments,
        application_archive_handoff_rf3,
        handoff_recovery_without_actor_rerun,
        successor_handoff_revision,
        actor_handoff_during_one_replica_offline,
        qualification_temp_dependency_hydration: false,
        production_external_dependency_projection: exercise_deferred_actor_archive,
        deferred_input_rf3: exercise_deferred_actor_archive,
        actor_retry_socket_response_loss_injected: false,
        full_processor_rf3_runtime: false,
        all_20_target_business_rows_qualified: false,
        repair_direct_one_table_names: replica.table_names(),
        repair_direct_one_rows: replica.total_rows(),
        repair_direct_one_dataset_digest: replica.dataset_digest(),
        generation_terminal_integrated: false,
        production_terminal_mint: false,
        writer_head_provenance_verified: false,
        terminal_authorization_qualified: false,
        processor_recovery_invocation: false,
        production_terminal_transition: false,
        production_pipeline_rotation: false,
        carryover_replay: false,
        successor_actor_injection: false,
        proof_publish: false,
        mapping_reward_writer_integrated: false,
        full_22_domain_writer: false,
        production_writer_integrated: false,
        authority_head_publish_integrated: false,
        full_node_restart_tested: false,
        production_serving: false,
        h8_domains_closed: 0,
        qualification: if exercise_deferred_actor_archive {
            "H23C4C4B4C2_DEFERRED_ACTOR_ARCHIVE_RF3_PASSED"
        } else if exercise_terminal_recovery {
            "H23C4C4B3B2_TERMINAL_CARRYOVER_RECOVERY_RF3_PASSED"
        } else if exercise_application_handoff {
            "H23C4C4A2B_REALM_APPLICATION_HANDOFF_RF3_PASSED"
        } else if exercise_durable_replay {
            "H23C4C3B_PROCESSOR_GATHERER_REPLAY_RF3_PASSED"
        } else if exercise_durable_capture {
            "H23C4C3A_DURABLE_CAPTURE_OWNER_RF3_PASSED"
        } else {
            "H23C4C2B4E3_JTMB_HANDLER_INGRESS_RF3_PASSED"
        },
    };
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
