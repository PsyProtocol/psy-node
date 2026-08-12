//! h23c4c1: queue-sidecar schema/lifecycle production setup gate on RF=3.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use parth_core::{
    pgoldilocks::PoseidonHasher,
    protocol::core_types::Q256BitHash,
    PHash,
};
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    },
    chain_context::{
        AuthorityScope, PendingContext, WorkProcCheckpointUniqueId,
        WorkUniquePendingId,
    },
};
use psy_node_core::{
    queue::{
        coordinator_guta_durable_submission::{
            CoordinatorGutaDurableSubmission,
            CoordinatorGutaDurableSubmissionStore,
        },
        realm_user_update_claim::{
            RealmUserUpdateCreatedAtSeconds, StoredRealmUserUpdateClaim,
        },
        realm_user_update_publish::{
            RealmUserUpdatePublishAdmission, RealmUserUpdateRequestDigest,
        },
        recoverable_ephemeral::PendingQueueCaptureContext,
    },
    store::{
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
        typed::{UniquePendingId, UserId},
    },
};
use scylla::{
    client::{
        execution_profile::ExecutionProfile, session::Session,
        session_builder::SessionBuilder,
    },
    policies::load_balancing::{
        NodeIdentifier, SingleTargetLoadBalancingPolicy,
    },
    statement::Consistency,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::sleep;

use crate::core::ScyllaCoreStore;

use super::*;

const EXACT: &str = "psy_h23c4c1_exact";
const PARTIAL: &str = "psy_h23c4c1_partial";
const WRONG: &str = "psy_h23c4c1_wrong";
const UPGRADE: &str = "psy_h23c4c1_upgrade";
const V13_UPGRADE: &str = "psy_h23c4c4b4c1_upgrade";
const V13_CONFLICT: &str = "psy_h23c4c4b4c1_conflict";
const V14_UPGRADE: &str = "psy_h23c4c4b4c2a_upgrade";
const V14_CONFLICT: &str = "psy_h23c4c4b4c2a_conflict";
const V15_UPGRADE: &str = "psy_h23c4d3b2b2_upgrade";
const V15_CONFLICT: &str = "psy_h23c4d3b2b2_conflict";
const V16_UPGRADE: &str = "psy_h23c4d3b2b2b4c2a_upgrade";
const V16_CONFLICT: &str = "psy_h23c4d3b2b2b4c2a_conflict";
const V17_UPGRADE: &str = "psy_h23c4e2c3c2a_upgrade";
const V17_CONFLICT: &str = "psy_h23c4e2c3c2a_conflict";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const NODE_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(172, 29, 86, 11),
    Ipv4Addr::new(172, 29, 86, 12),
    Ipv4Addr::new(172, 29, 86, 13),
];
const NODE_CONTAINERS: [&str; 3] = [
    "psy-g0-02-rf3-scylla1-1",
    "psy-g0-02-rf3-scylla2-1",
    "psy-g0-02-rf3-scylla3-1",
];

fn no_tablet(keyspace: &str) -> String { format!("{keyspace}_no_tablet") }
fn realm() -> AuthorityScope {
    AuthorityScope::Realm { realm_id: 7, realm_sub_id: 2 }
}

fn claim(epoch: u64, user_id: u64) -> anyhow::Result<StoredRealmUserUpdateClaim<PHash>> {
    let network = NetworkId::try_from_chain_id(1337)?;
    let authority = realm();
    let pending_id = 77;
    let proc_id = 0x1234_u128;
    let pending = PendingContext::new(
        CanonicalChainRef::new(
            network,
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(10 + epoch),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                    epoch as u8;
                    32
                ])),
            ),
        ),
        authority,
        WorkUniquePendingId::new(pending_id),
        WorkProcCheckpointUniqueId::from_u128(proc_id),
    );
    let capture = PendingQueueCaptureContext::try_new(
        PendingGenerationLedgerKey::new(network, authority),
        PendingGenerationActivationDigest::try_new([9; 32])?,
        PendingGenerationContext::try_from_legacy(
            UniquePendingId::try_new(pending_id)?.get(),
            proc_id,
        )?,
    )?;
    let admission = RealmUserUpdatePublishAdmission::try_from_pipeline(pending, capture)?;
    Ok(StoredRealmUserUpdateClaim::claimed(
        admission,
        psy_node_core::queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierProfileId::try_from_persisted([0xA5; 32])?,
        UserId::new(user_id),
        RealmUserUpdateRequestDigest::derive(
            &[epoch as u8, user_id as u8],
            &[3, 4, 5],
        )?,
        RealmUserUpdateCreatedAtSeconds::try_new(100 + epoch as u32)?,
        psy_node_core::queue::realm_user_update_claim::RealmUserUpdateAdmissionOrdinal::FIRST,
    )?)
}

fn coordinator_submission(
    proof_byte: u8,
) -> anyhow::Result<CoordinatorGutaDurableSubmission<PHash>> {
    let pending = PendingContext::new(
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337)?,
            ChainEpoch::new(15),
            CheckpointRef::new(
                CheckpointId::new(150),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                    0x15; 32
                ])),
            ),
        ),
        AuthorityScope::Coordinator,
        WorkUniquePendingId::new(1500),
        WorkProcCheckpointUniqueId::from_u128(0x1500),
    );
    Ok(CoordinatorGutaDurableSubmission::try_new(
        pending,
        7,
        vec![0xA1, 0xA2, 0xA3],
        vec![proof_byte; 4097],
        vec![0xB1, 0xB2, 0xB3, 0xB4],
    )?)
}

fn two_users_in_one_bucket() -> (u64, u64) {
    let mut first_by_bucket = std::collections::HashMap::new();
    for user in 1..100_000 {
        let bucket = psy_node_core::queue::realm_user_update_claim::RealmUserUpdateClaimBucket::for_user(UserId::new(user));
        if let Some(first) = first_by_bucket.insert(bucket, user) {
            return (first, user);
        }
    }
    panic!("256 buckets must collide in a finite search");
}

async fn connect(target: Option<Ipv4Addr>, consistency: Consistency) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(180)));
    if let Some(ip) = target {
        profile = profile.load_balancing_policy(
            SingleTargetLoadBalancingPolicy::new(
                NodeIdentifier::NodeAddress(SocketAddr::new(IpAddr::V4(ip), 9042)),
                None,
            ),
        );
    }
    Ok(SessionBuilder::new()
        .known_nodes_addr(NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)))
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await?)
}

async fn create_keyspaces(session: &Session) -> anyhow::Result<()> {
    for keyspace in [
        EXACT,
        PARTIAL,
        WRONG,
        UPGRADE,
        V13_UPGRADE,
        V13_CONFLICT,
        V14_UPGRADE,
        V14_CONFLICT,
        V15_UPGRADE,
        V15_CONFLICT,
        V16_UPGRADE,
        V16_CONFLICT,
        V17_UPGRADE,
        V17_CONFLICT,
    ] {
        session.query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        ).await?;
        let control = no_tablet(keyspace);
        session.query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {control} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"),
            &[],
        ).await?;
    }
    session.await_schema_agreement().await?;
    Ok(())
}

fn keyspaces(keyspace: &str) -> anyhow::Result<PendingQueueSidecarKeyspaces> {
    Ok(PendingQueueSidecarKeyspaces::try_new(keyspace, no_tablet(keyspace))?)
}

async fn core(keyspace: &str) -> anyhow::Result<ScyllaCoreStore<PHash, PoseidonHasher>> {
    let nodes = NODE_IPS.iter().map(|ip| format!("{ip}:9042")).collect::<Vec<_>>();
    ScyllaCoreStore::new(7, 2, keyspace.to_owned(), &nodes).await
}

async fn queue_table_count_including_lifecycle(
    session: &Session,
    keyspace: &str,
) -> anyhow::Result<usize> {
    let data = session.query_unpaged(
        "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?",
        (keyspace,),
    ).await?.into_rows_result()?.rows::<(String,)>()?.count();
    let control = session.query_unpaged(
        "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?",
        (no_tablet(keyspace),),
    ).await?.into_rows_result()?.rows::<(String,)>()?.count();
    Ok(data + control)
}

fn compose(compose_file: &Path, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker").arg("compose").arg("-f").arg(compose_file).args(args).status().with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

fn docker_exec(container: &str, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker").arg("exec").arg(container).args(args).status().with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

async fn wait_up(expected: usize) -> anyhow::Result<()> {
    for _ in 0..120 {
        let mut up = 0;
        for ip in NODE_IPS {
            if connect(Some(ip), Consistency::One).await.is_ok() { up += 1; }
        }
        if up >= expected { return Ok(()); }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("only part of RF=3 became available")
}

#[derive(Serialize)]
struct H23c4c1Report {
    image: &'static str,
    replication_factor: u8,
    schema_version: u16,
    target_tables: usize,
    lifecycle_tables: usize,
    disabled_zero_queue_tables: bool,
    partial_retry_converged: bool,
    wrong_schema_rejected: bool,
    idempotent_deploy: bool,
    v10_verified_does_not_authorize_v11: bool,
    v10_lifecycle_row_preserved: bool,
    one_replica_offline_ready: bool,
    direct_one_nodes_exact: usize,
    direct_one_lifecycle_equal: bool,
    claim_v2_addressable: bool,
    claim_lwt_conflict: bool,
    claim_scan_one_replica_offline: bool,
    claim_direct_one_equal: bool,
    repair_flush_compact: bool,
    ready_ms: u64,
    qualification: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct HistoricalRepresentativeRows {
    pipeline: (i64, Vec<u8>),
    application_header: (i64, Vec<u8>),
    application_fragment: (i32, i64, Vec<u8>, Vec<u8>),
    terminal: (i64, Vec<u8>),
    carryover: (i64, Vec<u8>),
}

impl HistoricalRepresentativeRows {
    const fn row_count(&self) -> usize { 5 }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct V12V13DirectDataset {
    historical_v12_lifecycle: (i64, Vec<u8>),
    current_v13_lifecycle: (i64, Vec<u8>),
    representative: HistoricalRepresentativeRows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct V13V14DirectDataset {
    historical_v13_lifecycle: (i64, Vec<u8>),
    current_v14_lifecycle: (i64, Vec<u8>),
    representative: HistoricalRepresentativeRows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct V14V15DirectDataset {
    historical_v14_lifecycle: (i64, Vec<u8>),
    current_v15_lifecycle: (i64, Vec<u8>),
    representative: HistoricalRepresentativeRows,
    coordinator_submission: (i64, Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct V15V16DirectDataset {
    historical_v15_lifecycle: (i64, Vec<u8>),
    current_v16_lifecycle: (i64, Vec<u8>),
    representative: HistoricalRepresentativeRows,
    coordinator_submission: (i64, Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct V16V17DirectDataset {
    historical_v16_lifecycle: (i64, Vec<u8>),
    current_v17_lifecycle: (i64, Vec<u8>),
    representative: HistoricalRepresentativeRows,
    coordinator_submission: (i64, Vec<u8>),
}

impl V16V17DirectDataset {
    const fn row_count(&self) -> usize {
        3 + self.representative.row_count()
    }
}

impl V15V16DirectDataset {
    const fn row_count(&self) -> usize {
        3 + self.representative.row_count()
    }
}

impl V14V15DirectDataset {
    const fn row_count(&self) -> usize {
        3 + self.representative.row_count()
    }
}

impl V13V14DirectDataset {
    const fn row_count(&self) -> usize {
        2 + self.representative.row_count()
    }
}

impl V12V13DirectDataset {
    const fn row_count(&self) -> usize {
        2 + self.representative.row_count()
    }
}

#[derive(Serialize)]
struct H23c4c4b4c1Report {
    image: &'static str,
    replication_factor: u8,
    historical_schema_version: u16,
    current_schema_version: u16,
    target_tables: usize,
    lifecycle_tables: usize,
    control_targets: usize,
    data_targets: usize,
    expected_columns: usize,
    historical_schema_fingerprint: String,
    current_schema_fingerprint: String,
    same_physical_shape: bool,
    v12_verified_rejected_for_v13: bool,
    v12_payload_rejected_by_v13_decoder: bool,
    v13_slot_differs_from_v12: bool,
    v13_deploy_idempotent: bool,
    different_current_rejected: bool,
    v12_lifecycle_preserved: bool,
    v12_representative_rows_preserved: bool,
    one_replica_offline_deploy: bool,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    representative_rows_preserved_and_current_manifest_unchanged: bool,
    repair_flush_compact: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_table_names: Vec<String>,
    direct_one_table_count: usize,
    direct_one_row_count: usize,
    direct_one_dataset_digest: String,
    direct_one_equal: bool,
    sidecar_v13_rf3: bool,
    deferred_input_rf3: bool,
    production_terminal_transition: bool,
    production_pipeline_rotation: bool,
    production_writer_integrated: bool,
    authority_head_publish_integrated: bool,
    full_node_restart_tested: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    h8_domains_total: u8,
    qualification: &'static str,
}

#[derive(Serialize)]
struct H23c4c4b4c2aReport {
    image: &'static str,
    replication_factor: u8,
    historical_schema_version: u16,
    current_schema_version: u16,
    target_tables: usize,
    lifecycle_tables: usize,
    control_targets: usize,
    data_targets: usize,
    expected_columns: usize,
    historical_schema_fingerprint: String,
    current_schema_fingerprint: String,
    same_physical_shape: bool,
    v13_verified_rejected_for_v14: bool,
    v13_payload_rejected_by_v14_decoder: bool,
    v14_slot_differs_from_v13: bool,
    v14_deploy_idempotent: bool,
    different_current_rejected: bool,
    v13_lifecycle_preserved: bool,
    v13_representative_rows_preserved: bool,
    one_replica_offline_deploy: bool,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    representative_rows_preserved_and_current_manifest_unchanged: bool,
    repair_flush_compact: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_table_names: Vec<String>,
    direct_one_table_count: usize,
    direct_one_row_count: usize,
    direct_one_dataset_digest: String,
    direct_one_equal: bool,
    sidecar_v14_rf3: bool,
    deferred_input_rf3: bool,
    production_terminal_transition: bool,
    production_pipeline_rotation: bool,
    production_writer_integrated: bool,
    authority_head_publish_integrated: bool,
    full_node_restart_tested: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    h8_domains_total: u8,
    qualification: &'static str,
}

#[derive(Serialize)]
struct H23c4d3b2b2SidecarReport {
    image: &'static str,
    replication_factor: u8,
    historical_schema_version: u16,
    current_schema_version: u16,
    historical_target_tables: usize,
    target_tables: usize,
    lifecycle_tables: usize,
    control_targets: usize,
    data_targets: usize,
    expected_columns: usize,
    historical_schema_fingerprint: String,
    current_schema_fingerprint: String,
    v14_missing_exact_coordinator_table: bool,
    v14_verified_rejected_for_v15: bool,
    v14_payload_rejected_by_v15_decoder: bool,
    v15_slot_differs_from_v14: bool,
    v15_deploy_idempotent: bool,
    different_current_rejected: bool,
    v14_lifecycle_preserved: bool,
    v14_representative_rows_preserved: bool,
    coordinator_submission_exact: bool,
    coordinator_submission_same_retry: bool,
    coordinator_submission_different_conflict: bool,
    one_replica_offline_deploy_and_write: bool,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    no_drop_upgrade: bool,
    repair_flush_compact: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_table_names: Vec<String>,
    direct_one_table_count: usize,
    direct_one_row_count: usize,
    direct_one_dataset_digest: String,
    direct_one_equal: bool,
    sidecar_v15_rf3: bool,
    coordinator_submission_store_rf3: bool,
    handler_processor_rf3: bool,
    redis_loss_recovery_rf3: bool,
    mixed_version_activation_safe: bool,
    production_terminal_transition: bool,
    production_pipeline_rotation: bool,
    production_writer_integrated: bool,
    authority_head_publish_integrated: bool,
    full_node_restart_tested: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    h8_domains_total: u8,
    qualification: &'static str,
}

#[derive(Serialize)]
struct H23c4d3b2b2b4c2aReport {
    image: &'static str,
    replication_factor: u8,
    historical_schema_version: u16,
    current_schema_version: u16,
    target_tables: usize,
    lifecycle_tables: usize,
    control_targets: usize,
    data_targets: usize,
    expected_columns: usize,
    historical_schema_fingerprint: String,
    current_schema_fingerprint: String,
    same_physical_shape: bool,
    v15_verified_rejected_for_v16: bool,
    v15_payload_rejected_by_v16_decoder: bool,
    v16_slot_differs_from_v15: bool,
    v16_deploy_idempotent: bool,
    different_current_rejected: bool,
    v15_lifecycle_preserved: bool,
    v15_representative_rows_preserved: bool,
    coordinator_submission_preserved: bool,
    one_replica_offline_deploy: bool,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    representative_rows_preserved_and_current_manifest_unchanged: bool,
    repair_flush_compact: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_table_names: Vec<String>,
    direct_one_table_count: usize,
    direct_one_row_count: usize,
    direct_one_dataset_digest: String,
    direct_one_equal: bool,
    sidecar_v16_rf3: bool,
    coordinator_capture_replay_rf3: bool,
    production_coordinator_processor_rf3: bool,
    mixed_version_clean_boundary_qualified: bool,
    production_terminal_transition: bool,
    production_pipeline_rotation: bool,
    production_writer_integrated: bool,
    authority_head_publish_integrated: bool,
    full_node_restart_tested: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    h8_domains_total: u8,
    qualification: &'static str,
}

#[derive(Serialize)]
struct H23c4e2c3c2aReport {
    image: &'static str,
    replication_factor: u8,
    historical_schema_version: u16,
    current_schema_version: u16,
    historical_target_tables: usize,
    target_tables: usize,
    lifecycle_tables: usize,
    control_targets: usize,
    data_targets: usize,
    expected_columns: usize,
    historical_schema_fingerprint: String,
    current_schema_fingerprint: String,
    v16_missing_exact_manifest_table: bool,
    v16_verified_rejected_for_v17: bool,
    v16_payload_rejected_by_v17_decoder: bool,
    v17_slot_differs_from_v16: bool,
    v17_deploy_idempotent: bool,
    different_current_rejected: bool,
    v16_lifecycle_preserved: bool,
    v16_representative_rows_preserved: bool,
    coordinator_submission_preserved: bool,
    manifest_table_added_without_drop: bool,
    one_replica_offline_deploy: bool,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    repair_flush_compact: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_table_names: Vec<String>,
    direct_one_table_count: usize,
    direct_one_row_count: usize,
    direct_one_dataset_digest: String,
    direct_one_equal: bool,
    sidecar_v17_rf3: bool,
    full_commit_manifest_data_rf3_in_this_gate: bool,
    production_processor_invocation: bool,
    production_terminal_transition: bool,
    production_pipeline_rotation: bool,
    authority_head_publish_integrated: bool,
    full_node_restart_tested: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    h8_domains_total: u8,
    qualification: &'static str,
}

fn historical_v10_slot(keyspaces: &PendingQueueSidecarKeyspaces) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/rollback/pending-queue-sidecar-slot/v1");
    for value in [keyspaces.data().as_str(), keyspaces.control().as_str()] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().into()
}

fn historical_v10_fingerprint() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/rollback/pending-queue-sidecar-schema/v10");
    hasher.update(10_u16.to_be_bytes());
    for table in PendingQueueSidecarPhysicalTable::ALL.iter().copied().take(16) {
        hasher.update([table as u8]);
        hasher.update((table.table_name().len() as u64).to_be_bytes());
        hasher.update(table.table_name().as_bytes());
        hasher.update([match table.keyspace_kind() {
            PendingQueueSidecarKeyspaceKind::StandardData => 1,
            PendingQueueSidecarKeyspaceKind::NoTabletControl => 2,
        }]);
        for column in PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS
            .iter()
            .filter(|column| column.table == table)
        {
            for value in [
                column.name,
                column.cql_type,
                match column.kind {
                    PendingQueueSidecarColumnKind::PartitionKey => "partition_key",
                    PendingQueueSidecarColumnKind::Clustering => "clustering",
                    PendingQueueSidecarColumnKind::Regular => "regular",
                },
            ] {
                hasher.update((value.len() as u64).to_be_bytes());
                hasher.update(value.as_bytes());
            }
            hasher.update(column.position.to_be_bytes());
            let order = match column.clustering_order {
                PendingQueueSidecarClusteringOrder::Asc => "asc",
                PendingQueueSidecarClusteringOrder::None => "none",
            };
            hasher.update((order.len() as u64).to_be_bytes());
            hasher.update(order.as_bytes());
        }
    }
    hasher.finalize().into()
}

fn historical_v10_verified_payload(keyspaces: &PendingQueueSidecarKeyspaces) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PSYQSCAR");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&2_u64.to_be_bytes());
    bytes.push(2);
    bytes.extend_from_slice(&10_u16.to_be_bytes());
    bytes.extend_from_slice(&16_u16.to_be_bytes());
    for value in [keyspaces.data().as_str(), keyspaces.control().as_str()] {
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&historical_v10_fingerprint());
    let mut state = Sha256::new();
    state.update(b"psy/rollback/pending-queue-sidecar-state/v1");
    state.update(&bytes);
    bytes.extend_from_slice(&<[u8; 32]>::from(state.finalize()));
    bytes
}

async fn seed_historical_representative_rows(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    historical_version: u16,
) -> anyhow::Result<HistoricalRepresentativeRows> {
    let pipeline = (
        i64::from(historical_version),
        format!("historical-v{historical_version}-pipeline").into_bytes(),
    );
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, pipeline) VALUES (?, ?, ?, ?, ?, ?)",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::Pipeline.table_name(),
            ),
            (
                1337_i64,
                1_i8,
                7_i64,
                2_i32,
                pipeline.0,
                pipeline.1.clone(),
            ),
        )
        .await?;

    let application_slot = vec![0xA1_u8; 32];
    let application_digest = vec![0xA2_u8; 32];
    let application_header = (
        1_i64,
        format!("historical-v{historical_version}-application-header").into_bytes(),
    );
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (archive_slot, revision, archive_payload) VALUES (?, ?, ?)",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader.table_name(),
            ),
            (
                application_slot.clone(),
                application_header.0,
                application_header.1.clone(),
            ),
        )
        .await?;
    let application_fragment = (
        1_i32,
        23_i64,
        format!("historical-v{historical_version}-fragment").into_bytes(),
        vec![0xA3_u8; 32],
    );
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (archive_slot, application_digest, fragment_bucket, fragment_index, fragment_count, application_bytes, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                keyspaces.data().as_str(),
                PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment.table_name(),
            ),
            (
                application_slot,
                application_digest,
                0_i64,
                0_i32,
                application_fragment.0,
                application_fragment.1,
                application_fragment.2.clone(),
                application_fragment.3.clone(),
            ),
        )
        .await?;

    let terminal = (
        1_i64,
        format!("historical-v{historical_version}-terminal").into_bytes(),
    );
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (terminal_slot, revision, terminal_payload) VALUES (?, ?, ?)",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent.table_name(),
            ),
            (vec![0xB1_u8; 32], terminal.0, terminal.1.clone()),
        )
        .await?;
    let carryover = (
        1_i64,
        format!("historical-v{historical_version}-carryover").into_bytes(),
    );
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (successor_slot, revision, carryover_payload) VALUES (?, ?, ?)",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::RealmDeferredCarryover.table_name(),
            ),
            (vec![0xC1_u8; 32], carryover.0, carryover.1.clone()),
        )
        .await?;
    Ok(HistoricalRepresentativeRows {
        pipeline,
        application_header,
        application_fragment,
        terminal,
        carryover,
    })
}

async fn read_historical_representative_rows(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
) -> anyhow::Result<HistoricalRepresentativeRows> {
    let pipeline = session
        .query_unpaged(
            format!(
                "SELECT revision, pipeline FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::Pipeline.table_name(),
            ),
            (1337_i64, 1_i8, 7_i64, 2_i32),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let application_header = session
        .query_unpaged(
            format!(
                "SELECT revision, archive_payload FROM {}.{} WHERE archive_slot = ?",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader.table_name(),
            ),
            (vec![0xA1_u8; 32],),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let application_fragment = session
        .query_unpaged(
            format!(
                "SELECT fragment_count, application_bytes, payload, payload_digest FROM {}.{} WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?",
                keyspaces.data().as_str(),
                PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment.table_name(),
            ),
            (
                vec![0xA1_u8; 32],
                vec![0xA2_u8; 32],
                0_i64,
                0_i32,
            ),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i32, i64, Vec<u8>, Vec<u8>)>()?;
    let terminal = session
        .query_unpaged(
            format!(
                "SELECT revision, terminal_payload FROM {}.{} WHERE terminal_slot = ?",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent.table_name(),
            ),
            (vec![0xB1_u8; 32],),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let carryover = session
        .query_unpaged(
            format!(
                "SELECT revision, carryover_payload FROM {}.{} WHERE successor_slot = ?",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::RealmDeferredCarryover.table_name(),
            ),
            (vec![0xC1_u8; 32],),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    Ok(HistoricalRepresentativeRows {
        pipeline,
        application_header,
        application_fragment,
        terminal,
        carryover,
    })
}

async fn read_lifecycle_row(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    slot: &[u8; 32],
) -> anyhow::Result<(i64, Vec<u8>)> {
    Ok(session
        .query_unpaged(
            format!(
                "SELECT revision, deployment_payload FROM {}.{} WHERE deployment_slot = ?",
                keyspaces.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (slot.to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?)
}

async fn read_coordinator_submission_row(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    slot: &[u8; 32],
) -> anyhow::Result<(i64, Vec<u8>)> {
    Ok(session
        .query_unpaged(
            format!(
                "SELECT revision, submission_payload FROM {}.{} WHERE submission_slot = ?",
                keyspaces.control().as_str(),
                PendingQueueSidecarPhysicalTable::CoordinatorGutaSubmission.table_name(),
            ),
            (slot.to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c1_queue_schema_lifecycle_rf3_gate() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_D04B6H23C4C1_RF3").as_deref() == Ok("1"), "run through tests/rf3/run-d04b6h23c4c1.sh");
    let compose_file = std::env::var("PSY_D04B6H23C4C1_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;

    let exact_core = core(EXACT).await?;
    ensure!(matches!(exact_core.initialize_pending_queue_sidecar_setup(realm(), PendingQueueSidecarSetupMode::Disabled).await?, PendingQueueSidecarSetupOutcome::Disabled));
    let disabled_zero_queue_tables =
        queue_table_count_including_lifecycle(&session, EXACT).await? == 0;
    ensure!(disabled_zero_queue_tables);

    let exact_receipt = PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), keyspaces(EXACT)?).await?;
    ensure!(
        queue_table_count_including_lifecycle(&session, EXACT).await?
            == PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT + 1,
        "expected current target tables plus one lifecycle table"
    );
    let repeated = PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), keyspaces(EXACT)?).await?;
    let idempotent_deploy = repeated == exact_receipt;
    ensure!(idempotent_deploy);

    let upgrade_keys = keyspaces(UPGRADE)?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        upgrade_keys.control(),
    )
    .await?;
    let old_slot = historical_v10_slot(&upgrade_keys);
    let old_payload = historical_v10_verified_payload(&upgrade_keys);
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?)",
                upgrade_keys.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (old_slot.to_vec(), 2_i64, old_payload.clone()),
        )
        .await?;
    let v10_verified_does_not_authorize_v11 = matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            session.clone(),
            upgrade_keys.clone(),
            realm(),
        )
        .await,
        Err(PendingQueueSidecarLifecycleError::Uninitialized),
    );
    ensure!(v10_verified_does_not_authorize_v11);
    PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        upgrade_keys.clone(),
    )
    .await?;
    let preserved = session
        .query_unpaged(
            format!(
                "SELECT revision, deployment_payload FROM {}.{} WHERE deployment_slot = ?",
                upgrade_keys.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (old_slot.to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let v10_lifecycle_row_preserved = preserved == (2, old_payload);
    ensure!(v10_lifecycle_row_preserved);

    let partial_keys = keyspaces(PARTIAL)?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(&session, partial_keys.control()).await?;
    let partial_store = ScyllaPendingQueueSidecarLifecycleStore::prepare(session.clone(), partial_keys.control().clone()).await?;
    let partial_materializing = StoredPendingQueueSidecarDeployment::materializing(partial_keys.clone());
    ensure!(matches!(partial_store.bootstrap(&partial_materializing).await?, PendingQueueSidecarDeploymentWriteOutcome::Applied(_) | PendingQueueSidecarDeploymentWriteOutcome::Idempotent(_)));
    ScyllaPendingPipelineStore::create_schema(&session, partial_keys.control()).await?;
    ensure!(matches!(PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &partial_keys).await?, PendingQueueSidecarSchemaInspection::Partial { .. }));
    PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), partial_keys.clone()).await?;
    let partial_retry_converged = matches!(PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &partial_keys).await?, PendingQueueSidecarSchemaInspection::Exact { .. });
    ensure!(partial_retry_converged);

    let wrong_keys = keyspaces(WRONG)?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(&session, wrong_keys.control()).await?;
    session.query_unpaged(
        format!("CREATE TABLE {}.{} (network_chain_id bigint PRIMARY KEY, wrong blob)", wrong_keys.control().as_str(), PendingQueueSidecarPhysicalTable::Pipeline.table_name()),
        &[],
    ).await?;
    session.await_schema_agreement().await?;
    let wrong_schema_rejected = PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), wrong_keys).await.is_err();
    ensure!(wrong_schema_rejected);

    let claim_store = ScyllaRealmUserUpdateClaimStore::prepare(
        session.clone(),
        keyspaces(EXACT)?.control().clone(),
    )
    .await?;
    let (first_user, second_user) = two_users_in_one_bucket();
    let first = claim(1, first_user)?;
    let second = claim(2, second_user)?;
    ensure!(first.partition()? == second.partition()?);
    ensure!(first.slot() != second.slot());
    ensure!(matches!(claim_store.claim_retired_v5_fixture(&first).await?, RealmUserUpdateClaimWriteOutcome::Applied(_)));
    ensure!(matches!(claim_store.claim_retired_v5_fixture(&second).await?, RealmUserUpdateClaimWriteOutcome::Applied(_)));
    let conflict = claim(2, first_user)?;
    let claim_lwt_conflict = matches!(claim_store.claim_retired_v5_fixture(&conflict).await?, RealmUserUpdateClaimWriteOutcome::Conflict(_));
    ensure!(claim_lwt_conflict);
    let initial_scan = claim_store.scan_bucket::<PHash>(first.partition()?).await?;
    let claim_v2_addressable = initial_scan.len() == 2
        && initial_scan.iter().any(|value| value == &first)
        && initial_scan.iter().any(|value| value == &second);
    ensure!(claim_v2_addressable);

    compose(Path::new(&compose_file), &["stop", "scylla3"], "stop third replica")?;
    wait_up(2).await?;
    let started = Instant::now();
    let ready = exact_core.initialize_pending_queue_sidecar_setup(realm(), PendingQueueSidecarSetupMode::RequireVerified).await?;
    ensure!(matches!(ready, PendingQueueSidecarSetupOutcome::Ready(_)));
    let ready_ms = started.elapsed().as_millis() as u64;
    let one_replica_offline_ready = exact_core.pending_queue_sidecar_setup_view().is_some();
    ensure!(one_replica_offline_ready);
    let claim_scan_one_replica_offline =
        claim_store.scan_bucket::<PHash>(first.partition()?).await? == initial_scan;
    ensure!(claim_scan_one_replica_offline);

    compose(Path::new(&compose_file), &["start", "scylla3"], "restart third replica")?;
    wait_up(3).await?;
    docker_exec(NODE_CONTAINERS[0], &["nodetool", "cluster", "repair", EXACT], "repair tablet data")?;
    for node in NODE_CONTAINERS {
        docker_exec(node, &["nodetool", "repair", "-pr", &no_tablet(EXACT)], "repair control")?;
        docker_exec(node, &["nodetool", "flush", EXACT], "flush data")?;
        docker_exec(node, &["nodetool", "flush", &no_tablet(EXACT)], "flush control")?;
        docker_exec(node, &["nodetool", "compact", EXACT], "compact data")?;
        docker_exec(node, &["nodetool", "compact", &no_tablet(EXACT)], "compact control")?;
    }

    let mut direct_payloads = Vec::new();
    let mut direct_claims = Vec::new();
    let mut direct_one_nodes_exact = 0;
    let slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&keyspaces(EXACT)?);
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        ensure!(matches!(PendingQueueSidecarSchemaMaterializer::inspect_schema(&local, &keyspaces(EXACT)?).await?, PendingQueueSidecarSchemaInspection::Exact { .. }));
        direct_one_nodes_exact += 1;
        let row = local.query_unpaged(
            format!("SELECT revision, deployment_payload FROM {}.{} WHERE deployment_slot = ?", no_tablet(EXACT), PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE),
            (slot.as_bytes().to_vec(),),
        ).await?.into_rows_result()?.single_row::<(i64, Vec<u8>)>()?;
        direct_payloads.push(row);
        let partition = first.partition()?;
        let capture = partition.capture();
        let AuthorityScope::Realm { realm_id, realm_sub_id } = capture.key().authority() else {
            bail!("test claim must be Realm scoped")
        };
        let rows = local
            .query_unpaged(
                format!(
                    "SELECT user_id, revision, claim_payload FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ?",
                    no_tablet(EXACT),
                    REALM_USER_UPDATE_CLAIM_TABLE,
                ),
                (
                    i64::from(capture.key().network().chain_id()),
                    crate::rollback::realm_generation_scope::REALM_AUTHORITY_KIND,
                    i64::from(realm_id),
                    i32::from(realm_sub_id),
                    capture.activation().as_bytes().to_vec(),
                    i64::try_from(capture.processing().pending_id().get())?,
                    capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
                    partition.bucket().as_i16()?,
                ),
            )
            .await?
            .into_rows_result()?
            .rows::<(i64, i64, Vec<u8>)>()?
            .collect::<Result<Vec<_>, _>>()?;
        direct_claims.push(rows);
    }
    let direct_one_lifecycle_equal = direct_payloads.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_lifecycle_equal);
    let claim_direct_one_equal = direct_claims.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(claim_direct_one_equal);

    let report = H23c4c1Report {
        image: IMAGE,
        replication_factor: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        lifecycle_tables: 1,
        disabled_zero_queue_tables,
        partial_retry_converged,
        wrong_schema_rejected,
        idempotent_deploy,
        v10_verified_does_not_authorize_v11,
        v10_lifecycle_row_preserved,
        one_replica_offline_ready,
        direct_one_nodes_exact,
        direct_one_lifecycle_equal,
        claim_v2_addressable,
        claim_lwt_conflict,
        claim_scan_one_replica_offline,
        claim_direct_one_equal,
        repair_flush_compact: true,
        ready_ms,
        qualification: "H23C4C4A2A_SIDECAR_V11_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4C1_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(feature = "rf3-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c4b4c1_sidecar_v13_lifecycle_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C4B4C1_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c4b4c1.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H23C4C4B4C1_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let upgrade_keys = keyspaces(V13_UPGRADE)?;

    let physical = PendingQueueSidecarSchemaMaterializer::materialize_schema(
        &session,
        &upgrade_keys,
    )
    .await?;
    ensure!(
        matches!(
            PendingQueueSidecarSchemaMaterializer::inspect_schema(
                &session,
                &upgrade_keys,
            )
            .await?,
            PendingQueueSidecarSchemaInspection::Exact { .. }
        ),
        "v12/v13 shared physical schema is not exact"
    );
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        upgrade_keys.control(),
    )
    .await?;
    let lifecycle = ScyllaPendingQueueSidecarLifecycleStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
    )
    .await?;
    let historical = lifecycle
        .qualification_persist_historical_v12_verified(&upgrade_keys)
        .await?;
    let historical_row = (
        historical.revision(),
        historical.payload().to_vec(),
    );
    let representative =
        seed_historical_representative_rows(&session, &upgrade_keys, 12).await?;

    let current_slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&upgrade_keys);
    let v13_slot_differs_from_v12 = current_slot.as_bytes() != historical.slot();
    ensure!(v13_slot_differs_from_v12);
    let v12_verified_rejected_for_v13 = matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            Arc::clone(&session),
            upgrade_keys.clone(),
            realm(),
        )
        .await,
        Err(PendingQueueSidecarLifecycleError::Uninitialized),
    );
    ensure!(v12_verified_rejected_for_v13);
    let v12_payload_rejected_by_v13_decoder = matches!(
        StoredPendingQueueSidecarDeployment::decode_selected(
            current_slot,
            historical.revision(),
            historical.payload(),
        ),
        Err(PendingQueueSidecarLifecycleError::UnknownSchemaVersion),
    );
    ensure!(v12_payload_rejected_by_v13_decoder);

    let conflict_keys = keyspaces(V13_CONFLICT)?;
    PendingQueueSidecarSchemaMaterializer::materialize_schema(&session, &conflict_keys)
        .await?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        conflict_keys.control(),
    )
    .await?;
    let conflict = StoredPendingQueueSidecarDeployment::materializing(conflict_keys.clone());
    let mut poisoned = conflict.to_canonical_bytes();
    let last = poisoned
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("empty lifecycle payload"))?;
    *last ^= 0xFF;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?)",
                conflict_keys.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (
                conflict.slot().as_bytes().to_vec(),
                i64::try_from(conflict.revision().get())?,
                poisoned,
            ),
        )
        .await?;
    let different_current_rejected = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        conflict_keys,
    )
    .await
    .is_err();
    ensure!(different_current_rejected);

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop third replica for v13 lifecycle",
    )?;
    wait_up(2).await?;
    let first = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let first_ready_digest = *first.ready_digest();
    drop(first);
    let second = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let v13_deploy_idempotent = second.ready_digest() == &first_ready_digest;
    ensure!(v13_deploy_idempotent);
    let caller_discard_retry = v13_deploy_idempotent;
    let ready = ScyllaPendingQueueSidecarSetupGate::authorize(
        Arc::clone(&session),
        upgrade_keys.clone(),
        realm(),
    )
    .await?;
    ensure!(ready.view().verified().ready_digest() == &first_ready_digest);
    let one_replica_offline_deploy = true;

    let v12_lifecycle_preserved = read_lifecycle_row(
        &session,
        &upgrade_keys,
        historical.slot(),
    )
    .await?
        == historical_row;
    ensure!(v12_lifecycle_preserved);
    let v12_representative_rows_preserved =
        read_historical_representative_rows(&session, &upgrade_keys).await?
            == representative;
    ensure!(v12_representative_rows_preserved);

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart third replica after v13 lifecycle",
    )?;
    wait_up(3).await?;
    let repair_started = Instant::now();
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", V13_UPGRADE],
        "repair v13 representative data",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", &no_tablet(V13_UPGRADE)],
            "repair v13 lifecycle/control",
        )?;
        docker_exec(
            node,
            &["nodetool", "flush", V13_UPGRADE],
            "flush v13 representative data",
        )?;
        docker_exec(
            node,
            &["nodetool", "flush", &no_tablet(V13_UPGRADE)],
            "flush v13 lifecycle/control",
        )?;
        docker_exec(
            node,
            &["nodetool", "compact", V13_UPGRADE],
            "compact v13 representative data",
        )?;
        docker_exec(
            node,
            &["nodetool", "compact", &no_tablet(V13_UPGRADE)],
            "compact v13 lifecycle/control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;

    let mut datasets = Vec::new();
    let mut direct_one_nodes = 0;
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        ensure!(matches!(
            PendingQueueSidecarSchemaMaterializer::inspect_schema(
                &local,
                &upgrade_keys,
            )
            .await?,
            PendingQueueSidecarSchemaInspection::Exact { fingerprint }
                if fingerprint == physical.fingerprint()
        ));
        datasets.push(V12V13DirectDataset {
            historical_v12_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                historical.slot(),
            )
            .await?,
            current_v13_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                current_slot.as_bytes(),
            )
            .await?,
            representative: read_historical_representative_rows(
                &local,
                &upgrade_keys,
            )
            .await?,
        });
        direct_one_nodes += 1;
    }
    let direct_one_equal = datasets.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_equal);
    let direct_one_dataset_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(
            datasets
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?,
        )?,
    ));
    let direct_one_table_names = vec![
        PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE.to_owned(),
        PendingQueueSidecarPhysicalTable::Pipeline
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmDeferredCarryover
            .table_name()
            .to_owned(),
    ];
    let control_targets = PendingQueueSidecarPhysicalTable::ALL
        .iter()
        .filter(|table| {
            table.keyspace_kind()
                == PendingQueueSidecarKeyspaceKind::NoTabletControl
        })
        .count();
    let data_targets = PendingQueueSidecarPhysicalTable::ALL.len() - control_targets;
    let same_physical_shape = current_physical_schema_matches_historical_v12()
        && PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT == 20
        && PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len() == 102
        && control_targets == 16
        && data_targets == 4;
    ensure!(same_physical_shape);
    let representative_rows_preserved_and_current_manifest_unchanged = same_physical_shape
        && v12_lifecycle_preserved
        && v12_representative_rows_preserved;
    ensure!(representative_rows_preserved_and_current_manifest_unchanged);
    let direct_one_row_count = datasets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?
        .row_count();

    let report = H23c4c4b4c1Report {
        image: IMAGE,
        replication_factor: 3,
        historical_schema_version: 12,
        current_schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        lifecycle_tables: 1,
        control_targets,
        data_targets,
        expected_columns: PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len(),
        historical_schema_fingerprint: hex::encode(
            historical_v12_schema_fingerprint().as_bytes(),
        ),
        current_schema_fingerprint: hex::encode(
            pending_queue_sidecar_schema_fingerprint().as_bytes(),
        ),
        same_physical_shape,
        v12_verified_rejected_for_v13,
        v12_payload_rejected_by_v13_decoder,
        v13_slot_differs_from_v12,
        v13_deploy_idempotent,
        different_current_rejected,
        v12_lifecycle_preserved,
        v12_representative_rows_preserved,
        one_replica_offline_deploy,
        caller_discard_retry,
        socket_response_loss_injected: false,
        representative_rows_preserved_and_current_manifest_unchanged,
        repair_flush_compact: true,
        repair_ms,
        direct_one_nodes,
        direct_one_table_count: direct_one_table_names.len(),
        direct_one_table_names,
        direct_one_row_count,
        direct_one_dataset_digest,
        direct_one_equal,
        sidecar_v13_rf3: true,
        deferred_input_rf3: false,
        production_terminal_transition: false,
        production_pipeline_rotation: false,
        production_writer_integrated: false,
        authority_head_publish_integrated: false,
        full_node_restart_tested: false,
        production_serving: false,
        h8_domains_closed: 0,
        h8_domains_total: 22,
        qualification: "H23C4C4B4C1_SIDECAR_V13_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4C4B4C1_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(feature = "rf3-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c4b4c2a_sidecar_v14_lifecycle_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C4B4C2A_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c4b4c2a.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H23C4C4B4C2A_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let upgrade_keys = keyspaces(V14_UPGRADE)?;

    let physical = PendingQueueSidecarSchemaMaterializer::materialize_schema(
        &session,
        &upgrade_keys,
    )
    .await?;
    ensure!(
        matches!(
            PendingQueueSidecarSchemaMaterializer::inspect_schema(
                &session,
                &upgrade_keys,
            )
            .await?,
            PendingQueueSidecarSchemaInspection::Exact { .. }
        ),
        "v13/v14 shared physical schema is not exact"
    );
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        upgrade_keys.control(),
    )
    .await?;
    let lifecycle = ScyllaPendingQueueSidecarLifecycleStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
    )
    .await?;
    let historical = lifecycle
        .qualification_persist_historical_v13_verified(&upgrade_keys)
        .await?;
    let historical_row = (historical.revision(), historical.payload().to_vec());
    let representative =
        seed_historical_representative_rows(&session, &upgrade_keys, 13).await?;

    let current_slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&upgrade_keys);
    let v14_slot_differs_from_v13 = current_slot.as_bytes() != historical.slot();
    ensure!(v14_slot_differs_from_v13);
    let v13_verified_rejected_for_v14 = matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            Arc::clone(&session),
            upgrade_keys.clone(),
            realm(),
        )
        .await,
        Err(PendingQueueSidecarLifecycleError::Uninitialized),
    );
    ensure!(v13_verified_rejected_for_v14);
    let v13_payload_rejected_by_v14_decoder = matches!(
        StoredPendingQueueSidecarDeployment::decode_selected(
            current_slot,
            historical.revision(),
            historical.payload(),
        ),
        Err(PendingQueueSidecarLifecycleError::UnknownSchemaVersion),
    );
    ensure!(v13_payload_rejected_by_v14_decoder);

    let conflict_keys = keyspaces(V14_CONFLICT)?;
    PendingQueueSidecarSchemaMaterializer::materialize_schema(&session, &conflict_keys)
        .await?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        conflict_keys.control(),
    )
    .await?;
    let conflict = StoredPendingQueueSidecarDeployment::materializing(conflict_keys.clone());
    let mut poisoned = conflict.to_canonical_bytes();
    let last = poisoned
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("empty lifecycle payload"))?;
    *last ^= 0xFF;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?)",
                conflict_keys.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (
                conflict.slot().as_bytes().to_vec(),
                i64::try_from(conflict.revision().get())?,
                poisoned,
            ),
        )
        .await?;
    let different_current_rejected = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        conflict_keys,
    )
    .await
    .is_err();
    ensure!(different_current_rejected);

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop third replica for v14 lifecycle",
    )?;
    wait_up(2).await?;
    let first = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let first_ready_digest = *first.ready_digest();
    drop(first);
    let second = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let v14_deploy_idempotent = second.ready_digest() == &first_ready_digest;
    ensure!(v14_deploy_idempotent);
    let caller_discard_retry = v14_deploy_idempotent;
    let ready = ScyllaPendingQueueSidecarSetupGate::authorize(
        Arc::clone(&session),
        upgrade_keys.clone(),
        realm(),
    )
    .await?;
    ensure!(ready.view().verified().ready_digest() == &first_ready_digest);
    let one_replica_offline_deploy = true;

    let v13_lifecycle_preserved = read_lifecycle_row(
        &session,
        &upgrade_keys,
        historical.slot(),
    )
    .await?
        == historical_row;
    ensure!(v13_lifecycle_preserved);
    let v13_representative_rows_preserved =
        read_historical_representative_rows(&session, &upgrade_keys).await?
            == representative;
    ensure!(v13_representative_rows_preserved);

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart third replica after v14 lifecycle",
    )?;
    wait_up(3).await?;
    let repair_started = Instant::now();
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", V14_UPGRADE],
        "repair v14 representative data",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", &no_tablet(V14_UPGRADE)],
            "repair v14 lifecycle/control",
        )?;
        docker_exec(
            node,
            &["nodetool", "flush", V14_UPGRADE],
            "flush v14 representative data",
        )?;
        docker_exec(
            node,
            &["nodetool", "flush", &no_tablet(V14_UPGRADE)],
            "flush v14 lifecycle/control",
        )?;
        docker_exec(
            node,
            &["nodetool", "compact", V14_UPGRADE],
            "compact v14 representative data",
        )?;
        docker_exec(
            node,
            &["nodetool", "compact", &no_tablet(V14_UPGRADE)],
            "compact v14 lifecycle/control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;

    let mut datasets = Vec::new();
    let mut direct_one_nodes = 0;
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        ensure!(matches!(
            PendingQueueSidecarSchemaMaterializer::inspect_schema(
                &local,
                &upgrade_keys,
            )
            .await?,
            PendingQueueSidecarSchemaInspection::Exact { fingerprint }
                if fingerprint == physical.fingerprint()
        ));
        datasets.push(V13V14DirectDataset {
            historical_v13_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                historical.slot(),
            )
            .await?,
            current_v14_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                current_slot.as_bytes(),
            )
            .await?,
            representative: read_historical_representative_rows(
                &local,
                &upgrade_keys,
            )
            .await?,
        });
        direct_one_nodes += 1;
    }
    let direct_one_equal = datasets.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_equal);
    let direct_one_dataset_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(
            datasets
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?,
        )?,
    ));
    let direct_one_table_names = vec![
        PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE.to_owned(),
        PendingQueueSidecarPhysicalTable::Pipeline
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmDeferredCarryover
            .table_name()
            .to_owned(),
    ];
    let control_targets = PendingQueueSidecarPhysicalTable::ALL
        .iter()
        .filter(|table| {
            table.keyspace_kind()
                == PendingQueueSidecarKeyspaceKind::NoTabletControl
        })
        .count();
    let data_targets = PendingQueueSidecarPhysicalTable::ALL.len() - control_targets;
    let same_physical_shape = current_physical_schema_matches_historical_v13()
        && PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT == 20
        && PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len() == 102
        && control_targets == 16
        && data_targets == 4;
    ensure!(same_physical_shape);
    let representative_rows_preserved_and_current_manifest_unchanged = same_physical_shape
        && v13_lifecycle_preserved
        && v13_representative_rows_preserved;
    ensure!(representative_rows_preserved_and_current_manifest_unchanged);
    let direct_one_row_count = datasets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?
        .row_count();

    let report = H23c4c4b4c2aReport {
        image: IMAGE,
        replication_factor: 3,
        historical_schema_version: 13,
        current_schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        lifecycle_tables: 1,
        control_targets,
        data_targets,
        expected_columns: PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len(),
        historical_schema_fingerprint: hex::encode(
            historical_v13_schema_fingerprint().as_bytes(),
        ),
        current_schema_fingerprint: hex::encode(
            pending_queue_sidecar_schema_fingerprint().as_bytes(),
        ),
        same_physical_shape,
        v13_verified_rejected_for_v14,
        v13_payload_rejected_by_v14_decoder,
        v14_slot_differs_from_v13,
        v14_deploy_idempotent,
        different_current_rejected,
        v13_lifecycle_preserved,
        v13_representative_rows_preserved,
        one_replica_offline_deploy,
        caller_discard_retry,
        socket_response_loss_injected: false,
        representative_rows_preserved_and_current_manifest_unchanged,
        repair_flush_compact: true,
        repair_ms,
        direct_one_nodes,
        direct_one_table_count: direct_one_table_names.len(),
        direct_one_table_names,
        direct_one_row_count,
        direct_one_dataset_digest,
        direct_one_equal,
        sidecar_v14_rf3: true,
        deferred_input_rf3: false,
        production_terminal_transition: false,
        production_pipeline_rotation: false,
        production_writer_integrated: false,
        authority_head_publish_integrated: false,
        full_node_restart_tested: false,
        production_serving: false,
        h8_domains_closed: 0,
        h8_domains_total: 22,
        qualification: "H23C4C4B4C2A_SIDECAR_V14_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4C4B4C2A_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(feature = "rf3-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4d3b2b2a_sidecar_v15_submission_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4D3B2B2A_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4d3b2b2a.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H23C4D3B2B2A_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let upgrade_keys = keyspaces(V15_UPGRADE)?;

    PendingQueueSidecarSchemaMaterializer::qualification_materialize_historical_v14(
        &session,
        &upgrade_keys,
    )
    .await?;
    let v14_missing_exact_coordinator_table = matches!(
        PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &upgrade_keys).await?,
        PendingQueueSidecarSchemaInspection::Partial { missing, .. }
            if missing == vec![PendingQueueSidecarPhysicalTable::CoordinatorGutaSubmission]
    );
    ensure!(v14_missing_exact_coordinator_table);
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        upgrade_keys.control(),
    )
    .await?;
    let lifecycle = ScyllaPendingQueueSidecarLifecycleStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
    )
    .await?;
    let historical = lifecycle
        .qualification_persist_historical_v14_verified(&upgrade_keys)
        .await?;
    let historical_row = (historical.revision(), historical.payload().to_vec());
    let representative =
        seed_historical_representative_rows(&session, &upgrade_keys, 14).await?;

    let current_slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&upgrade_keys);
    let v15_slot_differs_from_v14 = current_slot.as_bytes() != historical.slot();
    ensure!(v15_slot_differs_from_v14);
    let v14_verified_rejected_for_v15 = matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            Arc::clone(&session),
            upgrade_keys.clone(),
            AuthorityScope::Coordinator,
        )
        .await,
        Err(PendingQueueSidecarLifecycleError::Uninitialized),
    );
    ensure!(v14_verified_rejected_for_v15);
    let v14_payload_rejected_by_v15_decoder = matches!(
        StoredPendingQueueSidecarDeployment::decode_selected(
            current_slot,
            historical.revision(),
            historical.payload(),
        ),
        Err(PendingQueueSidecarLifecycleError::UnknownSchemaVersion),
    );
    ensure!(v14_payload_rejected_by_v15_decoder);

    let conflict_keys = keyspaces(V15_CONFLICT)?;
    PendingQueueSidecarSchemaMaterializer::materialize_schema(&session, &conflict_keys)
        .await?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        conflict_keys.control(),
    )
    .await?;
    let conflict = StoredPendingQueueSidecarDeployment::materializing(conflict_keys.clone());
    let mut poisoned = conflict.to_canonical_bytes();
    let last = poisoned
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("empty lifecycle payload"))?;
    *last ^= 0xFF;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?)",
                conflict_keys.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (
                conflict.slot().as_bytes().to_vec(),
                i64::try_from(conflict.revision().get())?,
                poisoned,
            ),
        )
        .await?;
    let different_current_rejected = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        conflict_keys,
    )
    .await
    .is_err();
    ensure!(different_current_rejected);

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop third replica for v15 lifecycle and submission",
    )?;
    wait_up(2).await?;
    let first = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let first_ready_digest = *first.ready_digest();
    drop(first);
    let second = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let v15_deploy_idempotent = second.ready_digest() == &first_ready_digest;
    ensure!(v15_deploy_idempotent);
    let ready = ScyllaPendingQueueSidecarSetupGate::authorize(
        Arc::clone(&session),
        upgrade_keys.clone(),
        AuthorityScope::Coordinator,
    )
    .await?;
    ensure!(ready.view().verified().ready_digest() == &first_ready_digest);

    let submission_store = ScyllaCoordinatorGutaDurableSubmissionStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
        NetworkId::try_from_chain_id(1337)?,
        *ready.view().ready_digest(),
    )
    .await?;
    let winner = coordinator_submission(0xAA)?;
    let winner_slot = winner.slot();
    let persisted = submission_store
        .persist_and_readback(winner.clone())
        .await?;
    ensure!(persisted == winner);
    let first_submission_row = read_coordinator_submission_row(
        &session,
        &upgrade_keys,
        winner_slot.as_bytes(),
    )
    .await?;
    let coordinator_submission_exact = submission_store
        .read_selected(winner_slot)
        .await?
        .as_ref()
        == Some(&winner);
    ensure!(coordinator_submission_exact);
    let coordinator_submission_same_retry = submission_store
        .persist_and_readback(winner.clone())
        .await?
        == winner
        && read_coordinator_submission_row(
            &session,
            &upgrade_keys,
            winner_slot.as_bytes(),
        )
        .await?
            == first_submission_row;
    ensure!(coordinator_submission_same_retry);
    let coordinator_submission_different_conflict = submission_store
        .persist_and_readback(coordinator_submission(0xBB)?)
        .await
        .is_err()
        && submission_store
            .read_selected(winner_slot)
            .await?
            .as_ref()
            == Some(&winner);
    ensure!(coordinator_submission_different_conflict);

    let v14_lifecycle_preserved = read_lifecycle_row(
        &session,
        &upgrade_keys,
        historical.slot(),
    )
    .await?
        == historical_row;
    ensure!(v14_lifecycle_preserved);
    let v14_representative_rows_preserved =
        read_historical_representative_rows(&session, &upgrade_keys).await?
            == representative;
    ensure!(v14_representative_rows_preserved);

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart third replica after v15 lifecycle and submission",
    )?;
    wait_up(3).await?;
    let repair_started = Instant::now();
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", V15_UPGRADE],
        "repair v15 representative data",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", &no_tablet(V15_UPGRADE)],
            "repair v15 lifecycle/control",
        )?;
        docker_exec(node, &["nodetool", "flush", V15_UPGRADE], "flush v15 data")?;
        docker_exec(
            node,
            &["nodetool", "flush", &no_tablet(V15_UPGRADE)],
            "flush v15 lifecycle/control",
        )?;
        docker_exec(node, &["nodetool", "compact", V15_UPGRADE], "compact v15 data")?;
        docker_exec(
            node,
            &["nodetool", "compact", &no_tablet(V15_UPGRADE)],
            "compact v15 lifecycle/control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;

    let physical_fingerprint = pending_queue_sidecar_schema_fingerprint();
    let mut datasets = Vec::new();
    let mut direct_one_nodes = 0;
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        ensure!(matches!(
            PendingQueueSidecarSchemaMaterializer::inspect_schema(&local, &upgrade_keys).await?,
            PendingQueueSidecarSchemaInspection::Exact { fingerprint }
                if fingerprint == physical_fingerprint
        ));
        datasets.push(V14V15DirectDataset {
            historical_v14_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                historical.slot(),
            )
            .await?,
            current_v15_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                current_slot.as_bytes(),
            )
            .await?,
            representative: read_historical_representative_rows(&local, &upgrade_keys).await?,
            coordinator_submission: read_coordinator_submission_row(
                &local,
                &upgrade_keys,
                winner_slot.as_bytes(),
            )
            .await?,
        });
        direct_one_nodes += 1;
    }
    let direct_one_equal = datasets.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_equal);
    let direct_one_dataset_digest = hex::encode(Sha256::digest(serde_json::to_vec(
        datasets
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?,
    )?));
    let direct_one_table_names = vec![
        PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE.to_owned(),
        PendingQueueSidecarPhysicalTable::Pipeline.table_name().to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmDeferredCarryover
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::CoordinatorGutaSubmission
            .table_name()
            .to_owned(),
    ];
    let control_targets = PendingQueueSidecarPhysicalTable::ALL
        .iter()
        .filter(|table| {
            table.keyspace_kind()
                == PendingQueueSidecarKeyspaceKind::NoTabletControl
        })
        .count();
    let data_targets = PendingQueueSidecarPhysicalTable::ALL.len() - control_targets;
    ensure!(PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT == 21);
    ensure!(PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len() == 105);
    ensure!(control_targets == 17 && data_targets == 4);
    let no_drop_upgrade = v14_missing_exact_coordinator_table
        && v14_lifecycle_preserved
        && v14_representative_rows_preserved;
    ensure!(no_drop_upgrade);
    let direct_one_row_count = datasets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?
        .row_count();

    let report = H23c4d3b2b2SidecarReport {
        image: IMAGE,
        replication_factor: 3,
        historical_schema_version: 14,
        current_schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        historical_target_tables: 20,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        lifecycle_tables: 1,
        control_targets,
        data_targets,
        expected_columns: PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len(),
        historical_schema_fingerprint: hex::encode(
            historical_v14_schema_fingerprint().as_bytes(),
        ),
        current_schema_fingerprint: hex::encode(
            pending_queue_sidecar_schema_fingerprint().as_bytes(),
        ),
        v14_missing_exact_coordinator_table,
        v14_verified_rejected_for_v15,
        v14_payload_rejected_by_v15_decoder,
        v15_slot_differs_from_v14,
        v15_deploy_idempotent,
        different_current_rejected,
        v14_lifecycle_preserved,
        v14_representative_rows_preserved,
        coordinator_submission_exact,
        coordinator_submission_same_retry,
        coordinator_submission_different_conflict,
        one_replica_offline_deploy_and_write: true,
        caller_discard_retry: v15_deploy_idempotent && coordinator_submission_same_retry,
        socket_response_loss_injected: false,
        no_drop_upgrade,
        repair_flush_compact: true,
        repair_ms,
        direct_one_nodes,
        direct_one_table_count: direct_one_table_names.len(),
        direct_one_table_names,
        direct_one_row_count,
        direct_one_dataset_digest,
        direct_one_equal,
        sidecar_v15_rf3: true,
        coordinator_submission_store_rf3: true,
        handler_processor_rf3: false,
        redis_loss_recovery_rf3: false,
        mixed_version_activation_safe: false,
        production_terminal_transition: false,
        production_pipeline_rotation: false,
        production_writer_integrated: false,
        authority_head_publish_integrated: false,
        full_node_restart_tested: false,
        production_serving: false,
        h8_domains_closed: 0,
        h8_domains_total: 22,
        qualification: "H23C4D3B2B2A_SIDECAR_V15_SUBMISSION_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4D3B2B2A_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(feature = "rf3-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4d3b2b2b4c2a_sidecar_v16_lifecycle_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4D3B2B2B4C2A_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4d3b2b2b4c2a.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H23C4D3B2B2B4C2A_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let upgrade_keys = keyspaces(V16_UPGRADE)?;

    let physical = PendingQueueSidecarSchemaMaterializer::materialize_schema(
        &session,
        &upgrade_keys,
    )
    .await?;
    ensure!(current_physical_schema_matches_historical_v15());
    ensure!(matches!(
        PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &upgrade_keys).await?,
        PendingQueueSidecarSchemaInspection::Exact { fingerprint }
            if fingerprint == physical.fingerprint()
    ));
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        upgrade_keys.control(),
    )
    .await?;
    let lifecycle = ScyllaPendingQueueSidecarLifecycleStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
    )
    .await?;
    let historical = lifecycle
        .qualification_persist_historical_v15_verified(&upgrade_keys)
        .await?;
    let historical_row = (historical.revision(), historical.payload().to_vec());
    let representative =
        seed_historical_representative_rows(&session, &upgrade_keys, 15).await?;
    let historical_submission_store = ScyllaCoordinatorGutaDurableSubmissionStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
        NetworkId::try_from_chain_id(1337)?,
        [0x15; 32],
    )
    .await?;
    let submission = coordinator_submission(0xC1)?;
    let submission_slot = submission.slot();
    ensure!(
        historical_submission_store
            .persist_and_readback(submission.clone())
            .await?
            == submission
    );
    let historical_submission_row = read_coordinator_submission_row(
        &session,
        &upgrade_keys,
        submission_slot.as_bytes(),
    )
    .await?;

    let current_slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&upgrade_keys);
    let v16_slot_differs_from_v15 = current_slot.as_bytes() != historical.slot();
    ensure!(v16_slot_differs_from_v15);
    let v15_verified_rejected_for_v16 = matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            Arc::clone(&session),
            upgrade_keys.clone(),
            AuthorityScope::Coordinator,
        )
        .await,
        Err(PendingQueueSidecarLifecycleError::Uninitialized),
    );
    ensure!(v15_verified_rejected_for_v16);
    let v15_payload_rejected_by_v16_decoder = matches!(
        StoredPendingQueueSidecarDeployment::decode_selected(
            current_slot,
            historical.revision(),
            historical.payload(),
        ),
        Err(PendingQueueSidecarLifecycleError::UnknownSchemaVersion),
    );
    ensure!(v15_payload_rejected_by_v16_decoder);

    let conflict_keys = keyspaces(V16_CONFLICT)?;
    PendingQueueSidecarSchemaMaterializer::materialize_schema(&session, &conflict_keys)
        .await?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        conflict_keys.control(),
    )
    .await?;
    let conflict = StoredPendingQueueSidecarDeployment::materializing(conflict_keys.clone());
    let mut poisoned = conflict.to_canonical_bytes();
    *poisoned
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("empty lifecycle payload"))? ^= 0xFF;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?)",
                conflict_keys.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (
                conflict.slot().as_bytes().to_vec(),
                i64::try_from(conflict.revision().get())?,
                poisoned,
            ),
        )
        .await?;
    let different_current_rejected = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        conflict_keys,
    )
    .await
    .is_err();
    ensure!(different_current_rejected);

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop third replica for v16 lifecycle",
    )?;
    wait_up(2).await?;
    let first = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let first_ready_digest = *first.ready_digest();
    drop(first);
    let second = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let v16_deploy_idempotent = second.ready_digest() == &first_ready_digest;
    ensure!(v16_deploy_idempotent);
    let ready = ScyllaPendingQueueSidecarSetupGate::authorize(
        Arc::clone(&session),
        upgrade_keys.clone(),
        AuthorityScope::Coordinator,
    )
    .await?;
    ensure!(ready.view().verified().ready_digest() == &first_ready_digest);

    let v15_lifecycle_preserved = read_lifecycle_row(
        &session,
        &upgrade_keys,
        historical.slot(),
    )
    .await?
        == historical_row;
    ensure!(v15_lifecycle_preserved);
    let v15_representative_rows_preserved =
        read_historical_representative_rows(&session, &upgrade_keys).await?
            == representative;
    ensure!(v15_representative_rows_preserved);
    let coordinator_submission_preserved = read_coordinator_submission_row(
        &session,
        &upgrade_keys,
        submission_slot.as_bytes(),
    )
    .await?
        == historical_submission_row;
    ensure!(coordinator_submission_preserved);
    let current_submission_store = ScyllaCoordinatorGutaDurableSubmissionStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
        NetworkId::try_from_chain_id(1337)?,
        *ready.view().ready_digest(),
    )
    .await?;
    ensure!(
        current_submission_store
            .read_selected(submission_slot)
            .await?
            .as_ref()
            == Some(&submission)
    );

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart third replica after v16 lifecycle",
    )?;
    wait_up(3).await?;
    let repair_started = Instant::now();
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", V16_UPGRADE],
        "repair v16 representative data",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", &no_tablet(V16_UPGRADE)],
            "repair v16 lifecycle/control",
        )?;
        docker_exec(node, &["nodetool", "flush", V16_UPGRADE], "flush v16 data")?;
        docker_exec(
            node,
            &["nodetool", "flush", &no_tablet(V16_UPGRADE)],
            "flush v16 lifecycle/control",
        )?;
        docker_exec(node, &["nodetool", "compact", V16_UPGRADE], "compact v16 data")?;
        docker_exec(
            node,
            &["nodetool", "compact", &no_tablet(V16_UPGRADE)],
            "compact v16 lifecycle/control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;

    let mut datasets = Vec::new();
    let mut direct_one_nodes = 0;
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        ensure!(matches!(
            PendingQueueSidecarSchemaMaterializer::inspect_schema(&local, &upgrade_keys).await?,
            PendingQueueSidecarSchemaInspection::Exact { fingerprint }
                if fingerprint == physical.fingerprint()
        ));
        datasets.push(V15V16DirectDataset {
            historical_v15_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                historical.slot(),
            )
            .await?,
            current_v16_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                current_slot.as_bytes(),
            )
            .await?,
            representative: read_historical_representative_rows(&local, &upgrade_keys).await?,
            coordinator_submission: read_coordinator_submission_row(
                &local,
                &upgrade_keys,
                submission_slot.as_bytes(),
            )
            .await?,
        });
        direct_one_nodes += 1;
    }
    let direct_one_equal = datasets.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_equal);
    let direct_one_dataset_digest = hex::encode(Sha256::digest(serde_json::to_vec(
        datasets
            .first()
            .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?,
    )?));
    let direct_one_table_names = vec![
        PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE.to_owned(),
        PendingQueueSidecarPhysicalTable::Pipeline.table_name().to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmDeferredCarryover
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::CoordinatorGutaSubmission
            .table_name()
            .to_owned(),
    ];
    let control_targets = PendingQueueSidecarPhysicalTable::ALL
        .iter()
        .filter(|table| {
            table.keyspace_kind()
                == PendingQueueSidecarKeyspaceKind::NoTabletControl
        })
        .count();
    let data_targets = PendingQueueSidecarPhysicalTable::ALL.len() - control_targets;
    let same_physical_shape = current_physical_schema_matches_historical_v15()
        && PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT == 21
        && PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len() == 105
        && control_targets == 17
        && data_targets == 4;
    ensure!(same_physical_shape);
    let representative_rows_preserved_and_current_manifest_unchanged = same_physical_shape
        && v15_lifecycle_preserved
        && v15_representative_rows_preserved
        && coordinator_submission_preserved;
    ensure!(representative_rows_preserved_and_current_manifest_unchanged);
    let direct_one_row_count = datasets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?
        .row_count();

    let report = H23c4d3b2b2b4c2aReport {
        image: IMAGE,
        replication_factor: 3,
        historical_schema_version: 15,
        current_schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        lifecycle_tables: 1,
        control_targets,
        data_targets,
        expected_columns: PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len(),
        historical_schema_fingerprint: hex::encode(
            historical_v15_schema_fingerprint().as_bytes(),
        ),
        current_schema_fingerprint: hex::encode(
            pending_queue_sidecar_schema_fingerprint().as_bytes(),
        ),
        same_physical_shape,
        v15_verified_rejected_for_v16,
        v15_payload_rejected_by_v16_decoder,
        v16_slot_differs_from_v15,
        v16_deploy_idempotent,
        different_current_rejected,
        v15_lifecycle_preserved,
        v15_representative_rows_preserved,
        coordinator_submission_preserved,
        one_replica_offline_deploy: true,
        caller_discard_retry: v16_deploy_idempotent,
        socket_response_loss_injected: false,
        representative_rows_preserved_and_current_manifest_unchanged,
        repair_flush_compact: true,
        repair_ms,
        direct_one_nodes,
        direct_one_table_count: direct_one_table_names.len(),
        direct_one_table_names,
        direct_one_row_count,
        direct_one_dataset_digest,
        direct_one_equal,
        sidecar_v16_rf3: true,
        coordinator_capture_replay_rf3: false,
        production_coordinator_processor_rf3: false,
        mixed_version_clean_boundary_qualified: false,
        production_terminal_transition: false,
        production_pipeline_rotation: false,
        production_writer_integrated: false,
        authority_head_publish_integrated: false,
        full_node_restart_tested: false,
        production_serving: false,
        h8_domains_closed: 0,
        h8_domains_total: 22,
        qualification: "H23C4D3B2B2B4C2A_SIDECAR_V16_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4D3B2B2B4C2A_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(feature = "rf3-test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4e2c3c2a_sidecar_v17_lifecycle_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4E2C3C2A_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4e2c3c2a.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H23C4E2C3C2A_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let upgrade_keys = keyspaces(V17_UPGRADE)?;

    PendingQueueSidecarSchemaMaterializer::qualification_materialize_historical_v16(
        &session,
        &upgrade_keys,
    )
    .await?;
    let v16_missing_exact_manifest_table = matches!(
        PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &upgrade_keys).await?,
        PendingQueueSidecarSchemaInspection::Partial { missing, .. }
            if missing == vec![PendingQueueSidecarPhysicalTable::RealmFullCommitManifest]
    );
    ensure!(v16_missing_exact_manifest_table);

    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        upgrade_keys.control(),
    )
    .await?;
    let lifecycle = ScyllaPendingQueueSidecarLifecycleStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
    )
    .await?;
    let historical = lifecycle
        .qualification_persist_historical_v16_verified(&upgrade_keys)
        .await?;
    let historical_row = (historical.revision(), historical.payload().to_vec());
    let representative =
        seed_historical_representative_rows(&session, &upgrade_keys, 16).await?;
    let historical_submission_store = ScyllaCoordinatorGutaDurableSubmissionStore::prepare(
        Arc::clone(&session),
        upgrade_keys.control().clone(),
        NetworkId::try_from_chain_id(1337)?,
        [0x16; 32],
    )
    .await?;
    let submission = coordinator_submission(0xC2)?;
    let submission_slot = submission.slot();
    ensure!(
        historical_submission_store
            .persist_and_readback(submission.clone())
            .await?
            == submission
    );
    let historical_submission_row = read_coordinator_submission_row(
        &session,
        &upgrade_keys,
        submission_slot.as_bytes(),
    )
    .await?;

    let current_slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&upgrade_keys);
    let v17_slot_differs_from_v16 = current_slot.as_bytes() != historical.slot();
    ensure!(v17_slot_differs_from_v16);
    let v16_verified_rejected_for_v17 = matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            Arc::clone(&session),
            upgrade_keys.clone(),
            AuthorityScope::Coordinator,
        )
        .await,
        Err(PendingQueueSidecarLifecycleError::Uninitialized),
    );
    ensure!(v16_verified_rejected_for_v17);
    let v16_payload_rejected_by_v17_decoder = matches!(
        StoredPendingQueueSidecarDeployment::decode_selected(
            current_slot,
            historical.revision(),
            historical.payload(),
        ),
        Err(PendingQueueSidecarLifecycleError::UnknownSchemaVersion),
    );
    ensure!(v16_payload_rejected_by_v17_decoder);

    let conflict_keys = keyspaces(V17_CONFLICT)?;
    PendingQueueSidecarSchemaMaterializer::materialize_schema(&session, &conflict_keys)
        .await?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        conflict_keys.control(),
    )
    .await?;
    let conflict = StoredPendingQueueSidecarDeployment::materializing(conflict_keys.clone());
    let mut poisoned = conflict.to_canonical_bytes();
    *poisoned
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("empty lifecycle payload"))? ^= 0xFF;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?)",
                conflict_keys.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (
                conflict.slot().as_bytes().to_vec(),
                i64::try_from(conflict.revision().get())?,
                poisoned,
            ),
        )
        .await?;
    let different_current_rejected = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        conflict_keys,
    )
    .await
    .is_err();
    ensure!(different_current_rejected);

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop third replica for v17 lifecycle",
    )?;
    wait_up(2).await?;
    let first = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let first_ready_digest = *first.ready_digest();
    drop(first);
    let second = PendingQueueSidecarDeploymentExecutor::deploy(
        Arc::clone(&session),
        upgrade_keys.clone(),
    )
    .await?;
    let v17_deploy_idempotent = second.ready_digest() == &first_ready_digest;
    ensure!(v17_deploy_idempotent);
    let ready = ScyllaPendingQueueSidecarSetupGate::authorize(
        Arc::clone(&session),
        upgrade_keys.clone(),
        AuthorityScope::Coordinator,
    )
    .await?;
    ensure!(ready.view().verified().ready_digest() == &first_ready_digest);
    ensure!(matches!(
        PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &upgrade_keys).await?,
        PendingQueueSidecarSchemaInspection::Exact { fingerprint }
            if fingerprint == pending_queue_sidecar_schema_fingerprint()
    ));
    ensure!(
        queue_table_count_including_lifecycle(&session, V17_UPGRADE).await?
            == PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT + 1
    );

    let v16_lifecycle_preserved = read_lifecycle_row(
        &session,
        &upgrade_keys,
        historical.slot(),
    )
    .await?
        == historical_row;
    ensure!(v16_lifecycle_preserved);
    let v16_representative_rows_preserved =
        read_historical_representative_rows(&session, &upgrade_keys).await?
            == representative;
    ensure!(v16_representative_rows_preserved);
    let coordinator_submission_preserved = read_coordinator_submission_row(
        &session,
        &upgrade_keys,
        submission_slot.as_bytes(),
    )
    .await?
        == historical_submission_row;
    ensure!(coordinator_submission_preserved);

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart third replica after v17 lifecycle",
    )?;
    wait_up(3).await?;
    let repair_started = Instant::now();
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", V17_UPGRADE],
        "repair v17 representative data",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", &no_tablet(V17_UPGRADE)],
            "repair v17 lifecycle/control",
        )?;
        docker_exec(node, &["nodetool", "flush", V17_UPGRADE], "flush v17 data")?;
        docker_exec(
            node,
            &["nodetool", "flush", &no_tablet(V17_UPGRADE)],
            "flush v17 lifecycle/control",
        )?;
        docker_exec(node, &["nodetool", "compact", V17_UPGRADE], "compact v17 data")?;
        docker_exec(
            node,
            &["nodetool", "compact", &no_tablet(V17_UPGRADE)],
            "compact v17 lifecycle/control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;

    let mut datasets = Vec::new();
    let mut direct_one_nodes = 0;
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        ensure!(matches!(
            PendingQueueSidecarSchemaMaterializer::inspect_schema(&local, &upgrade_keys).await?,
            PendingQueueSidecarSchemaInspection::Exact { fingerprint }
                if fingerprint == pending_queue_sidecar_schema_fingerprint()
        ));
        datasets.push(V16V17DirectDataset {
            historical_v16_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                historical.slot(),
            )
            .await?,
            current_v17_lifecycle: read_lifecycle_row(
                &local,
                &upgrade_keys,
                current_slot.as_bytes(),
            )
            .await?,
            representative: read_historical_representative_rows(&local, &upgrade_keys).await?,
            coordinator_submission: read_coordinator_submission_row(
                &local,
                &upgrade_keys,
                submission_slot.as_bytes(),
            )
            .await?,
        });
        direct_one_nodes += 1;
    }
    let direct_one_equal = datasets.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_equal);
    let selected = datasets
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing direct-ONE dataset"))?;
    let direct_one_dataset_digest =
        hex::encode(Sha256::digest(serde_json::to_vec(selected)?));
    let direct_one_row_count = selected.row_count();
    let direct_one_table_names = vec![
        PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE.to_owned(),
        PendingQueueSidecarPhysicalTable::Pipeline.table_name().to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::RealmDeferredCarryover
            .table_name()
            .to_owned(),
        PendingQueueSidecarPhysicalTable::CoordinatorGutaSubmission
            .table_name()
            .to_owned(),
    ];
    let control_targets = PendingQueueSidecarPhysicalTable::ALL
        .iter()
        .filter(|table| {
            table.keyspace_kind()
                == PendingQueueSidecarKeyspaceKind::NoTabletControl
        })
        .count();
    let data_targets = PendingQueueSidecarPhysicalTable::ALL.len() - control_targets;
    let manifest_table_added_without_drop = v16_missing_exact_manifest_table
        && v16_lifecycle_preserved
        && v16_representative_rows_preserved
        && coordinator_submission_preserved
        && PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT == 22
        && PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len() == 108
        && control_targets == 18
        && data_targets == 4;
    ensure!(manifest_table_added_without_drop);

    let report = H23c4e2c3c2aReport {
        image: IMAGE,
        replication_factor: 3,
        historical_schema_version: 16,
        current_schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        historical_target_tables: 21,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        lifecycle_tables: 1,
        control_targets,
        data_targets,
        expected_columns: PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.len(),
        historical_schema_fingerprint: hex::encode(
            historical_v16_schema_fingerprint().as_bytes(),
        ),
        current_schema_fingerprint: hex::encode(
            pending_queue_sidecar_schema_fingerprint().as_bytes(),
        ),
        v16_missing_exact_manifest_table,
        v16_verified_rejected_for_v17,
        v16_payload_rejected_by_v17_decoder,
        v17_slot_differs_from_v16,
        v17_deploy_idempotent,
        different_current_rejected,
        v16_lifecycle_preserved,
        v16_representative_rows_preserved,
        coordinator_submission_preserved,
        manifest_table_added_without_drop,
        one_replica_offline_deploy: true,
        caller_discard_retry: v17_deploy_idempotent,
        socket_response_loss_injected: false,
        repair_flush_compact: true,
        repair_ms,
        direct_one_nodes,
        direct_one_table_count: direct_one_table_names.len(),
        direct_one_table_names,
        direct_one_row_count,
        direct_one_dataset_digest,
        direct_one_equal,
        sidecar_v17_rf3: true,
        full_commit_manifest_data_rf3_in_this_gate: false,
        production_processor_invocation: false,
        production_terminal_transition: false,
        production_pipeline_rotation: false,
        authority_head_publish_integrated: false,
        full_node_restart_tested: false,
        production_serving: false,
        h8_domains_closed: 0,
        h8_domains_total: 22,
        qualification: "H23C4E2C3C2A_SIDECAR_V17_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4E2C3C2A_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
