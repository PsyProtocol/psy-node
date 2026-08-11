//! h23c4c4b2b: Realm terminal/carryover immutable substrate on Scylla RF=3.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use parth_core::PHash;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    },
    chain_context::{
        AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
        AuthorityStateRoot,
    },
};
use psy_node_core::{
    queue::{
        realm_processor_application_archive::{
            RealmProcessorApplicationArchiveDigest,
            RealmProcessorApplicationArchiveSlot,
        },
        realm_processor_generation_continuation::{
            RealmProcessorApplicationContinuation,
            RealmProcessorDeferredCarryoverDigest,
        },
        realm_processor_generation_terminal::{
            RealmProcessorDeferredCarryover,
            RealmProcessorDeferredCarryoverSlot,
            RealmProcessorGenerationTerminal,
            RealmProcessorGenerationTerminalSlot,
        },
        realm_processor_semantic_output::RealmProcessorSemanticOutputDigest,
    },
    store::{
        pending_generation::{ProcNamespacePrefix, ReservedPendingGeneration},
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
            PendingGenerationContext, PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingEmptyQueueSealDigest, PendingNoWorkReceiptDigest,
            PendingPipelineBootstrap, PendingPipelineIntentDigest,
            PendingPublishReceiptDigest, PendingQueueCloseIntentDigest,
            PendingWorkCaptureDigest, StoredPendingPipeline,
        },
        typed::UniquePendingId,
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

use super::{
    pending_queue_sidecar_lifecycle::PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
    realm_processor_application_archive::{
        REALM_PROCESSOR_APPLICATION_ARCHIVE_FRAGMENT_TABLE,
        REALM_PROCESSOR_APPLICATION_ARCHIVE_HEADER_TABLE,
    },
    realm_processor_deferred_carryover::{
        RealmProcessorDeferredCarryoverStoreError,
        ScyllaRealmProcessorDeferredCarryoverStore,
        REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
    },
    realm_processor_generation_terminal::{
        RealmProcessorGenerationTerminalStoreError,
        ScyllaRealmProcessorGenerationTerminalStore,
        REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
    },
    *
};

const UPGRADE: &str = "psy_h23c4c4b2b_upgrade";
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

fn keyspaces() -> anyhow::Result<PendingQueueSidecarKeyspaces> {
    Ok(PendingQueueSidecarKeyspaces::try_new(
        UPGRADE,
        no_tablet(UPGRADE),
    )?)
}

fn realm() -> AuthorityScope {
    AuthorityScope::Realm {
        realm_id: 3,
        realm_sub_id: 4,
    }
}

fn key() -> PendingGenerationLedgerKey {
    PendingGenerationLedgerKey::new(
        NetworkId::from(PsyChainNetworkType::PsyMainnet),
        realm(),
    )
}

fn activation() -> PendingGenerationActivationDigest {
    PendingGenerationActivationDigest::try_new([7; 32]).unwrap()
}

fn prefix() -> ProcNamespacePrefix {
    ProcNamespacePrefix::for_authority(key().network(), key().authority())
}

fn generation(pending: u64) -> PendingGenerationContext {
    PendingGenerationContext::try_from_legacy(
        pending,
        prefix()
            .derive_proc_id(UniquePendingId::try_new(pending).unwrap())
            .as_u128(),
    )
    .unwrap()
}

fn observation(checkpoint: u64) -> AuthorityObservation<PHash> {
    AuthorityObservation::try_new(
        CanonicalChainRef::new(
            key().network(),
            ChainEpoch::new(0),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    checkpoint,
                    checkpoint + 1,
                    checkpoint + 2,
                    checkpoint + 3,
                )),
            ),
        ),
        key().authority(),
        AuthorityStateCheckpointId::new(checkpoint),
        AuthorityStateRoot::from_local_state_root(PHash::from_values(
            checkpoint + 10,
            checkpoint + 11,
            checkpoint + 12,
            checkpoint + 13,
        )),
    )
    .unwrap()
}

fn ready(base: u64) -> StoredPendingPipeline<PHash> {
    let baseline = PendingPipelineBootstrap::try_new(
        key(),
        activation(),
        prefix(),
        PendingGenerationBootstrapReason::LegacyActivation,
        generation(base),
        generation(base + 1),
        observation(base),
        base,
    )
    .unwrap()
    .candidate()
    .clone();
    baseline
        .seal_rotation(
            ReservedPendingGeneration::qualification_from_prefix(base + 2, prefix())
                .unwrap(),
        )
        .unwrap()
        .candidate()
        .clone()
}

fn application(
    slot_byte: u8,
    work: bool,
    deferred_count: u32,
) -> RealmProcessorApplicationContinuation {
    RealmProcessorApplicationContinuation::try_from_committed_parts(
        RealmProcessorApplicationArchiveSlot::try_new([slot_byte; 32]).unwrap(),
        RealmProcessorApplicationArchiveDigest::try_new([slot_byte.wrapping_add(1); 32])
            .unwrap(),
        RealmProcessorSemanticOutputDigest::try_new([slot_byte.wrapping_add(2); 32])
            .unwrap(),
        work,
        deferred_count,
        RealmProcessorDeferredCarryoverDigest::try_new([
            slot_byte.wrapping_add(3);
            32
        ])
        .unwrap(),
    )
    .unwrap()
}

fn published(
    base: u64,
    slot_byte: u8,
    deferred_count: u32,
) -> (StoredPendingPipeline<PHash>, RealmProcessorApplicationContinuation) {
    let application = application(slot_byte, true, deferred_count);
    let close = PendingQueueCloseIntentDigest::try_new([slot_byte.wrapping_add(4); 32])
        .unwrap();
    let intent = PendingPipelineIntentDigest::try_new([slot_byte.wrapping_add(5); 32])
        .unwrap();
    let captured = ready(base)
        .seal_begin_queue_close(close)
        .unwrap()
        .candidate()
        .seal_capture_work(
            close,
            PendingWorkCaptureDigest::try_new(*application.archive_slot().as_bytes())
                .unwrap(),
        )
        .unwrap()
        .candidate()
        .clone();
    let inflight = captured
        .seal_begin_processing(
            PendingWorkCaptureDigest::try_new(*application.archive_slot().as_bytes())
                .unwrap(),
            intent,
        )
        .unwrap()
        .candidate()
        .clone();
    let terminal = inflight
        .seal_publish(
            intent,
            PendingPublishReceiptDigest::try_new([slot_byte.wrapping_add(6); 32])
                .unwrap(),
            observation(base + 1),
        )
        .unwrap()
        .candidate()
        .clone();
    (terminal, application)
}

fn retired(
    base: u64,
    slot_byte: u8,
) -> (StoredPendingPipeline<PHash>, RealmProcessorApplicationContinuation) {
    let application = application(slot_byte, false, 0);
    let close = PendingQueueCloseIntentDigest::try_new([slot_byte.wrapping_add(4); 32])
        .unwrap();
    let empty = ready(base)
        .seal_begin_queue_close(close)
        .unwrap()
        .candidate()
        .seal_empty_queue(
            close,
            PendingEmptyQueueSealDigest::try_new(*application.archive_slot().as_bytes())
                .unwrap(),
        )
        .unwrap()
        .candidate()
        .clone();
    let terminal = empty
        .seal_retire_no_work(
            PendingEmptyQueueSealDigest::try_new(*application.archive_slot().as_bytes())
                .unwrap(),
            PendingNoWorkReceiptDigest::try_new([slot_byte.wrapping_add(5); 32])
                .unwrap(),
            ready(base).frontier().clone(),
        )
        .unwrap()
        .candidate()
        .clone();
    (terminal, application)
}

fn terminal(
    pipeline: &StoredPendingPipeline<PHash>,
    application: RealmProcessorApplicationContinuation,
    authorization_byte: u8,
) -> RealmProcessorGenerationTerminal<PHash> {
    RealmProcessorGenerationTerminal::try_new(
        pipeline,
        ReservedPendingGeneration::qualification_from_prefix(
            pipeline.gathering().pending_id().get() + 1,
            prefix(),
        )
        .unwrap(),
        [40; 32],
        [41; 32],
        application,
        vec![authorization_byte; 96],
    )
    .unwrap()
}

async fn connect(
    target: Option<Ipv4Addr>,
    consistency: Consistency,
) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(180)));
    if let Some(ip) = target {
        profile = profile.load_balancing_policy(
            SingleTargetLoadBalancingPolicy::new(
                NodeIdentifier::NodeAddress(SocketAddr::new(
                    IpAddr::V4(ip),
                    9042,
                )),
                None,
            ),
        );
    }
    Ok(SessionBuilder::new()
        .known_nodes_addr(
            NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)),
        )
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await?)
}

async fn create_keyspaces(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {UPGRADE} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}",
                no_tablet(UPGRADE),
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    Ok(())
}

fn historical_v11_fingerprint() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/rollback/pending-queue-sidecar-schema/v11");
    hasher.update(11_u16.to_be_bytes());
    for table in PendingQueueSidecarPhysicalTable::ALL
        .iter()
        .copied()
        .take(18)
    {
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

fn historical_v11_slot(keyspaces: &PendingQueueSidecarKeyspaces) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/rollback/pending-queue-sidecar-slot/v2");
    hasher.update(11_u16.to_be_bytes());
    hasher.update(historical_v11_fingerprint());
    for value in [keyspaces.data().as_str(), keyspaces.control().as_str()] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().into()
}

fn historical_v11_verified_payload(
    keyspaces: &PendingQueueSidecarKeyspaces,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PSYQSCAR");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&2_u64.to_be_bytes());
    bytes.push(2);
    bytes.extend_from_slice(&11_u16.to_be_bytes());
    bytes.extend_from_slice(&18_u16.to_be_bytes());
    for value in [keyspaces.data().as_str(), keyspaces.control().as_str()] {
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&historical_v11_fingerprint());
    let mut state = Sha256::new();
    state.update(b"psy/rollback/pending-queue-sidecar-state/v1");
    state.update(&bytes);
    bytes.extend_from_slice(&<[u8; 32]>::from(state.finalize()));
    bytes
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoricalRows {
    lifecycle: (i64, Vec<u8>),
    application_header: (i64, Vec<u8>),
    application_fragment: (i32, i64, Vec<u8>, Vec<u8>),
    pipeline: (i64, Vec<u8>),
    lifecycle_slot: [u8; 32],
    application_slot: [u8; 32],
    application_digest: [u8; 32],
    pipeline_key: (i64, i8, i64, i32),
}

async fn seed_historical_v11_rows(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    terminal: &RealmProcessorGenerationTerminal<PHash>,
) -> anyhow::Result<HistoricalRows> {
    let lifecycle_slot = historical_v11_slot(keyspaces);
    let lifecycle = (2_i64, historical_v11_verified_payload(keyspaces));
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (deployment_slot, revision, deployment_payload) VALUES (?, ?, ?)",
                keyspaces.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (
                lifecycle_slot.to_vec(),
                lifecycle.0,
                lifecycle.1.clone(),
            ),
        )
        .await?;

    let application_slot = [0xA1; 32];
    let application_digest = [0xA2; 32];
    let application_header = (1_i64, vec![0xA3; 73]);
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (archive_slot, revision, archive_payload) VALUES (?, ?, ?)",
                keyspaces.control().as_str(),
                REALM_PROCESSOR_APPLICATION_ARCHIVE_HEADER_TABLE,
            ),
            (
                application_slot.to_vec(),
                application_header.0,
                application_header.1.clone(),
            ),
        )
        .await?;
    let fragment_payload = vec![1_u8, 2, 3, 4, 5];
    let mut fragment_hasher = Sha256::new();
    fragment_hasher.update(&fragment_payload);
    let fragment_digest: [u8; 32] = fragment_hasher.finalize().into();
    let application_fragment = (
        1_i32,
        fragment_payload.len() as i64,
        fragment_payload,
        fragment_digest.to_vec(),
    );
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (archive_slot, fragment_bucket, fragment_index, application_digest, fragment_count, application_bytes, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                keyspaces.data().as_str(),
                REALM_PROCESSOR_APPLICATION_ARCHIVE_FRAGMENT_TABLE,
            ),
            (
                application_slot.to_vec(),
                0_i64,
                0_i32,
                application_digest.to_vec(),
                application_fragment.0,
                application_fragment.1,
                application_fragment.2.clone(),
                application_fragment.3.clone(),
            ),
        )
        .await?;

    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = terminal.key().authority()
    else {
        bail!("test terminal must be Realm scoped")
    };
    let pipeline_key = (
        i64::from(terminal.key().network().chain_id()),
        2_i8,
        i64::from(realm_id),
        i32::from(realm_sub_id),
    );
    let pipeline = (
        terminal.expected_pipeline().revision().as_i64(),
        terminal.expected_pipeline().canonical_payload().to_vec(),
    );
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (network_chain_id, authority_kind, realm_id, realm_sub_id, revision, pipeline) VALUES (?, ?, ?, ?, ?, ?)",
                keyspaces.control().as_str(),
                PIPELINE_TABLE,
            ),
            (
                pipeline_key.0,
                pipeline_key.1,
                pipeline_key.2,
                pipeline_key.3,
                pipeline.0,
                pipeline.1.clone(),
            ),
        )
        .await?;

    Ok(HistoricalRows {
        lifecycle,
        application_header,
        application_fragment,
        pipeline,
        lifecycle_slot,
        application_slot,
        application_digest,
        pipeline_key,
    })
}

async fn read_historical_rows(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    expected: &HistoricalRows,
) -> anyhow::Result<HistoricalRows> {
    let lifecycle = session
        .query_unpaged(
            format!(
                "SELECT revision, deployment_payload FROM {}.{} WHERE deployment_slot = ?",
                keyspaces.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (expected.lifecycle_slot.to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let application_header = session
        .query_unpaged(
            format!(
                "SELECT revision, archive_payload FROM {}.{} WHERE archive_slot = ?",
                keyspaces.control().as_str(),
                REALM_PROCESSOR_APPLICATION_ARCHIVE_HEADER_TABLE,
            ),
            (expected.application_slot.to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let application_fragment = session
        .query_unpaged(
            format!(
                "SELECT fragment_count, application_bytes, payload, payload_digest FROM {}.{} WHERE archive_slot = ? AND application_digest = ? AND fragment_bucket = ? AND fragment_index = ?",
                keyspaces.data().as_str(),
                REALM_PROCESSOR_APPLICATION_ARCHIVE_FRAGMENT_TABLE,
            ),
            (
                expected.application_slot.to_vec(),
                expected.application_digest.to_vec(),
                0_i64,
                0_i32,
            ),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i32, i64, Vec<u8>, Vec<u8>)>()?;
    let pipeline = session
        .query_unpaged(
            format!(
                "SELECT revision, pipeline FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?",
                keyspaces.control().as_str(),
                PIPELINE_TABLE,
            ),
            expected.pipeline_key,
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    Ok(HistoricalRows {
        lifecycle,
        application_header,
        application_fragment,
        pipeline,
        lifecycle_slot: expected.lifecycle_slot,
        application_slot: expected.application_slot,
        application_digest: expected.application_digest,
        pipeline_key: expected.pipeline_key,
    })
}

fn compose(compose_file: &Path, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .args(args)
        .status()
        .with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

fn docker_exec(container: &str, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("exec")
        .arg(container)
        .args(args)
        .status()
        .with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

async fn wait_up(expected: usize) -> anyhow::Result<()> {
    for _ in 0..120 {
        let mut up = 0;
        for ip in NODE_IPS {
            if connect(Some(ip), Consistency::One).await.is_ok() {
                up += 1;
            }
        }
        if up >= expected {
            return Ok(());
        }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("only part of RF=3 became available")
}

async fn table_count(session: &Session, keyspace: &str) -> anyhow::Result<usize> {
    Ok(session
        .query_unpaged(
            "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?",
            (keyspace,),
        )
        .await?
        .into_rows_result()?
        .rows::<(String,)>()?
        .count())
}

async fn target_column_count(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
) -> anyhow::Result<usize> {
    let mut count = 0;
    for table in PendingQueueSidecarPhysicalTable::ALL {
        count += session
            .query_unpaged(
                "SELECT column_name FROM system_schema.columns WHERE keyspace_name = ? AND table_name = ?",
                (
                    match table.keyspace_kind() {
                        PendingQueueSidecarKeyspaceKind::StandardData => {
                            keyspaces.data().as_str()
                        }
                        PendingQueueSidecarKeyspaceKind::NoTabletControl => {
                            keyspaces.control().as_str()
                        }
                    },
                    table.table_name(),
                ),
            )
            .await?
            .into_rows_result()?
            .rows::<(String,)>()?
            .count();
    }
    Ok(count)
}

async fn raw_terminal(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    terminal: &RealmProcessorGenerationTerminal<PHash>,
) -> anyhow::Result<(i64, Vec<u8>)> {
    Ok(session
        .query_unpaged(
            format!(
                "SELECT revision, terminal_payload FROM {}.{} WHERE terminal_slot = ?",
                keyspaces.control().as_str(),
                REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
            ),
            (terminal.slot().as_bytes().to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?)
}

async fn raw_carryover(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    carryover: &RealmProcessorDeferredCarryover,
) -> anyhow::Result<(i64, Vec<u8>)> {
    Ok(session
        .query_unpaged(
            format!(
                "SELECT revision, carryover_payload FROM {}.{} WHERE successor_slot = ?",
                keyspaces.control().as_str(),
                REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
            ),
            (carryover.slot().as_bytes().to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?)
}

async fn direct_snapshot(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
    historical: &HistoricalRows,
    terminals: &[RealmProcessorGenerationTerminal<PHash>],
    carryovers: &[RealmProcessorDeferredCarryover],
) -> anyhow::Result<[u8; 32]> {
    ensure!(matches!(
        PendingQueueSidecarSchemaMaterializer::inspect_schema(session, keyspaces).await?,
        PendingQueueSidecarSchemaInspection::Exact { .. }
    ));
    ensure!(read_historical_rows(session, keyspaces, historical).await? == *historical);
    let current_slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(keyspaces);
    let current = session
        .query_unpaged(
            format!(
                "SELECT revision, deployment_payload FROM {}.{} WHERE deployment_slot = ?",
                keyspaces.control().as_str(),
                PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE,
            ),
            (current_slot.as_bytes().to_vec(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let mut hasher = Sha256::new();
    hasher.update(current.0.to_be_bytes());
    hasher.update((current.1.len() as u64).to_be_bytes());
    hasher.update(&current.1);
    for terminal in terminals {
        let row = raw_terminal(session, keyspaces, terminal).await?;
        ensure!(row == (1, terminal.to_canonical_bytes()));
        hasher.update(terminal.slot().as_bytes());
        hasher.update((row.1.len() as u64).to_be_bytes());
        hasher.update(row.1);
    }
    for carryover in carryovers {
        let row = raw_carryover(session, keyspaces, carryover).await?;
        ensure!(row == (1, carryover.to_canonical_bytes()));
        hasher.update(carryover.slot().as_bytes());
        hasher.update((row.1.len() as u64).to_be_bytes());
        hasher.update(row.1);
    }
    Ok(hasher.finalize().into())
}

#[derive(Serialize)]
struct H23c4c4b2bReport {
    image: &'static str,
    replication_factor: u8,
    schema_version: u16,
    target_tables: usize,
    lifecycle_tables: usize,
    control_tables: usize,
    data_tables: usize,
    target_columns: usize,
    historical_v11_exact: bool,
    v11_missing_exact_two: bool,
    v11_verified_rejected_for_v12: bool,
    v12_deploy_idempotent: bool,
    v11_lifecycle_preserved: bool,
    v11_application_rows_preserved: bool,
    v11_pipeline_row_preserved: bool,
    work_terminal_carryover_exact: bool,
    retired_terminal_carryover_exact: bool,
    bootstrap_empty_exact: bool,
    terminal_same_retry_count: usize,
    terminal_different_conflict: bool,
    carryover_same_retry_count: usize,
    carryover_different_conflict: bool,
    missing_returns_none: bool,
    malformed_rejected: bool,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    terminal_only_then_carryover_resumed: bool,
    pipeline_unchanged: bool,
    one_replica_offline_read_write: bool,
    repair_flush_compact: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_rows: usize,
    direct_one_equal: bool,
    production_persist_exposed: bool,
    writer_head_provenance_verified: bool,
    terminal_authorization_qualified: bool,
    composite_owner: bool,
    production_terminal_transition: bool,
    production_pipeline_rotation: bool,
    carryover_replay: bool,
    successor_actor_injection: bool,
    processor_owner_integration: bool,
    proof_publish: bool,
    full_22_domain_writer: bool,
    authority_head_publish: bool,
    full_node_restart: bool,
    production_serving: bool,
    h8_domains_closed: u8,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c4b2b_terminal_carryover_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C4B2B_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c4b2b.sh",
    );
    let compose_file = std::env::var("PSY_D04B6H23C4C4B2B_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let keyspaces = keyspaces()?;

    PendingQueueSidecarSchemaMaterializer::qualification_materialize_historical_v11(
        &session,
        &keyspaces,
    )
    .await?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(
        &session,
        keyspaces.control(),
    )
    .await?;
    let historical_v11_exact =
        table_count(&session, keyspaces.data().as_str()).await?
            + table_count(&session, keyspaces.control().as_str()).await?
            == 19;
    ensure!(historical_v11_exact);
    let inspection = PendingQueueSidecarSchemaMaterializer::inspect_schema(
        &session,
        &keyspaces,
    )
    .await?;
    let v11_missing_exact_two = matches!(
        inspection,
        PendingQueueSidecarSchemaInspection::Partial { missing, .. }
            if missing == vec![
                PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent,
                PendingQueueSidecarPhysicalTable::RealmDeferredCarryover,
            ]
    );
    ensure!(v11_missing_exact_two);

    let (legacy_pipeline, legacy_application) = published(1, 21, 2);
    let legacy_terminal = terminal(&legacy_pipeline, legacy_application, 42);
    let historical = seed_historical_v11_rows(
        &session,
        &keyspaces,
        &legacy_terminal,
    )
    .await?;
    let v11_verified_rejected_for_v12 = matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            session.clone(),
            keyspaces.clone(),
            realm(),
        )
        .await,
        Err(PendingQueueSidecarLifecycleError::Uninitialized),
    );
    ensure!(v11_verified_rejected_for_v12);

    let first_deploy = PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        keyspaces.clone(),
    )
    .await?;
    let second_deploy = PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        keyspaces.clone(),
    )
    .await?;
    let v12_deploy_idempotent = first_deploy == second_deploy;
    ensure!(v12_deploy_idempotent);
    ensure!(matches!(
        PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &keyspaces).await?,
        PendingQueueSidecarSchemaInspection::Exact { .. }
    ));
    ensure!(
        table_count(&session, keyspaces.data().as_str()).await?
            + table_count(&session, keyspaces.control().as_str()).await?
            == PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT + 1
    );
    ensure!(target_column_count(&session, &keyspaces).await? == 102);
    let preserved = read_historical_rows(&session, &keyspaces, &historical).await?;
    let v11_lifecycle_preserved = preserved.lifecycle == historical.lifecycle;
    let v11_application_rows_preserved = preserved.application_header
        == historical.application_header
        && preserved.application_fragment == historical.application_fragment;
    let v11_pipeline_row_preserved = preserved.pipeline == historical.pipeline;
    ensure!(v11_lifecycle_preserved);
    ensure!(v11_application_rows_preserved);
    ensure!(v11_pipeline_row_preserved);

    let terminal_store = Arc::new(
        ScyllaRealmProcessorGenerationTerminalStore::prepare(
            session.clone(),
            keyspaces.control().clone(),
        )
        .await?,
    );
    let carryover_store = Arc::new(
        ScyllaRealmProcessorDeferredCarryoverStore::prepare(
            session.clone(),
            keyspaces.control().clone(),
        )
        .await?,
    );

    let (work_pipeline, work_application) = published(10, 51, 2);
    let work_terminal = terminal(&work_pipeline, work_application, 52);
    terminal_store
        .qualification_commit_then_discard_response(work_terminal.clone())
        .await?;
    let work_carryover = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
        &work_terminal,
        terminal_store.qualification_fingerprint(),
    )?;
    carryover_store
        .qualification_commit_then_discard_response(work_carryover)
        .await?;
    let work_terminal_carryover_exact = terminal_store
        .qualification_read::<PHash>(work_terminal.slot())
        .await?
        == Some(work_terminal.clone())
        && carryover_store
            .qualification_read(work_carryover.slot())
            .await?
            == Some(work_carryover);
    ensure!(work_terminal_carryover_exact);

    let (retired_pipeline, retired_application) = retired(20, 61);
    let retired_terminal = terminal(&retired_pipeline, retired_application, 62);
    terminal_store
        .qualification_persist(retired_terminal.clone())
        .await?;
    let retired_carryover =
        RealmProcessorDeferredCarryover::try_from_terminal_commitment(
            &retired_terminal,
            terminal_store.qualification_fingerprint(),
        )?;
    carryover_store
        .qualification_persist(retired_carryover)
        .await?;
    let retired_terminal_carryover_exact = terminal_store
        .qualification_read::<PHash>(retired_terminal.slot())
        .await?
        == Some(retired_terminal.clone())
        && carryover_store
            .qualification_read(retired_carryover.slot())
            .await?
            == Some(retired_carryover);
    ensure!(retired_terminal_carryover_exact);

    let bootstrap_empty = RealmProcessorDeferredCarryover::try_bootstrap_empty(
        key(),
        activation(),
        generation(100),
        PendingGenerationBootstrapReason::Genesis,
    )?;
    carryover_store
        .qualification_persist(bootstrap_empty)
        .await?;
    let bootstrap_empty_exact = carryover_store
        .qualification_read(bootstrap_empty.slot())
        .await?
        == Some(bootstrap_empty);
    ensure!(bootstrap_empty_exact);

    let (same_pipeline, same_application) = published(30, 71, 1);
    let same_terminal = terminal(&same_pipeline, same_application, 72);
    let mut same_terminal_tasks = Vec::new();
    for _ in 0..32 {
        let store = terminal_store.clone();
        let value = same_terminal.clone();
        same_terminal_tasks.push(tokio::spawn(async move {
            store.qualification_persist(value).await
        }));
    }
    let mut terminal_same_retry_count = 0;
    for task in same_terminal_tasks {
        task.await??;
        terminal_same_retry_count += 1;
    }
    ensure!(terminal_same_retry_count == 32);
    let same_carryover = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
        &same_terminal,
        terminal_store.qualification_fingerprint(),
    )?;
    let mut same_carryover_tasks = Vec::new();
    for _ in 0..32 {
        let store = carryover_store.clone();
        same_carryover_tasks.push(tokio::spawn(async move {
            store.qualification_persist(same_carryover).await
        }));
    }
    let mut carryover_same_retry_count = 0;
    for task in same_carryover_tasks {
        task.await??;
        carryover_same_retry_count += 1;
    }
    ensure!(carryover_same_retry_count == 32);

    let (conflict_pipeline, conflict_application) = published(40, 81, 1);
    let conflict_winner = terminal(&conflict_pipeline, conflict_application, 82);
    let conflict_loser = terminal(&conflict_pipeline, conflict_application, 83);
    ensure!(conflict_winner.slot() == conflict_loser.slot());
    terminal_store
        .qualification_persist(conflict_winner.clone())
        .await?;
    let terminal_different_conflict = matches!(
        terminal_store
            .qualification_persist(conflict_loser.clone())
            .await,
        Err(RealmProcessorGenerationTerminalStoreError::Conflict),
    );
    ensure!(terminal_different_conflict);
    let conflict_carryover = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
        &conflict_winner,
        terminal_store.qualification_fingerprint(),
    )?;
    let conflict_carryover_loser =
        RealmProcessorDeferredCarryover::try_from_terminal_commitment(
            &conflict_loser,
            terminal_store.qualification_fingerprint(),
        )?;
    ensure!(conflict_carryover.slot() == conflict_carryover_loser.slot());
    carryover_store
        .qualification_persist(conflict_carryover)
        .await?;
    let carryover_different_conflict = matches!(
        carryover_store
            .qualification_persist(conflict_carryover_loser)
            .await,
        Err(RealmProcessorDeferredCarryoverStoreError::Conflict),
    );
    ensure!(carryover_different_conflict);

    let missing_returns_none = terminal_store
        .qualification_read::<PHash>(
            RealmProcessorGenerationTerminalSlot::try_new([0xF1; 32])?,
        )
        .await?
        .is_none()
        && carryover_store
            .qualification_read(RealmProcessorDeferredCarryoverSlot::try_new([
                0xF2;
                32
            ])?)
            .await?
            .is_none();
    ensure!(missing_returns_none);
    let malformed_terminal_slot = RealmProcessorGenerationTerminalSlot::try_new([0xF3; 32])?;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (terminal_slot, revision, terminal_payload) VALUES (?, ?, ?)",
                keyspaces.control().as_str(),
                REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
            ),
            (
                malformed_terminal_slot.as_bytes().to_vec(),
                2_i64,
                vec![1_u8, 2, 3],
            ),
        )
        .await?;
    let malformed_carryover_slot = RealmProcessorDeferredCarryoverSlot::try_new([0xF4; 32])?;
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.{} (successor_slot, revision, carryover_payload) VALUES (?, ?, ?)",
                keyspaces.control().as_str(),
                REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
            ),
            (
                malformed_carryover_slot.as_bytes().to_vec(),
                2_i64,
                vec![4_u8, 5, 6],
            ),
        )
        .await?;
    let malformed_rejected = terminal_store
        .qualification_read::<PHash>(malformed_terminal_slot)
        .await
        .is_err()
        && carryover_store
            .qualification_read(malformed_carryover_slot)
            .await
            .is_err();
    ensure!(malformed_rejected);

    let (resume_pipeline, resume_application) = published(50, 91, 1);
    let resume_terminal = terminal(&resume_pipeline, resume_application, 92);
    terminal_store
        .qualification_persist(resume_terminal.clone())
        .await?;
    let reopened_terminal_store = ScyllaRealmProcessorGenerationTerminalStore::prepare(
        session.clone(),
        keyspaces.control().clone(),
    )
    .await?;
    let resumed_terminal = reopened_terminal_store
        .qualification_read::<PHash>(resume_terminal.slot())
        .await?
        .context("terminal-only restart lost its predecessor terminal")?;
    ensure!(resumed_terminal == resume_terminal);
    let reopened_carryover_store = ScyllaRealmProcessorDeferredCarryoverStore::prepare(
        session.clone(),
        keyspaces.control().clone(),
    )
    .await?;
    let resume_carryover = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
        &resumed_terminal,
        reopened_terminal_store.qualification_fingerprint(),
    )?;
    reopened_carryover_store
        .qualification_persist(resume_carryover)
        .await?;
    let terminal_only_then_carryover_resumed = reopened_carryover_store
        .qualification_read(resume_carryover.slot())
        .await?
        == Some(resume_carryover);
    ensure!(terminal_only_then_carryover_resumed);

    let pipeline_before_offline = read_historical_rows(&session, &keyspaces, &historical)
        .await?
        .pipeline;
    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop third replica",
    )?;
    wait_up(2).await?;
    ensure!(terminal_store
        .qualification_read::<PHash>(work_terminal.slot())
        .await?
        == Some(work_terminal.clone()));
    ensure!(carryover_store
        .qualification_read(retired_carryover.slot())
        .await?
        == Some(retired_carryover));
    let (offline_pipeline, offline_application) = published(60, 101, 1);
    let offline_terminal = terminal(&offline_pipeline, offline_application, 102);
    terminal_store
        .qualification_persist(offline_terminal.clone())
        .await?;
    let offline_carryover = RealmProcessorDeferredCarryover::try_from_terminal_commitment(
        &offline_terminal,
        terminal_store.qualification_fingerprint(),
    )?;
    carryover_store
        .qualification_persist(offline_carryover)
        .await?;
    ensure!(matches!(
        ScyllaPendingQueueSidecarSetupGate::authorize(
            session.clone(),
            keyspaces.clone(),
            realm(),
        )
        .await,
        Ok(_)
    ));
    let one_replica_offline_read_write = terminal_store
        .qualification_read::<PHash>(offline_terminal.slot())
        .await?
        == Some(offline_terminal.clone())
        && carryover_store
            .qualification_read(offline_carryover.slot())
            .await?
            == Some(offline_carryover);
    ensure!(one_replica_offline_read_write);

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart third replica",
    )?;
    wait_up(3).await?;
    let repair_started = Instant::now();
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", UPGRADE],
        "repair tablet data",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", &no_tablet(UPGRADE)],
            "repair control",
        )?;
        docker_exec(node, &["nodetool", "flush", UPGRADE], "flush data")?;
        docker_exec(
            node,
            &["nodetool", "flush", &no_tablet(UPGRADE)],
            "flush control",
        )?;
        docker_exec(node, &["nodetool", "compact", UPGRADE], "compact data")?;
        docker_exec(
            node,
            &["nodetool", "compact", &no_tablet(UPGRADE)],
            "compact control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;

    let terminals = vec![
        work_terminal,
        retired_terminal,
        same_terminal,
        conflict_winner,
        resume_terminal,
        offline_terminal,
    ];
    let carryovers = vec![
        work_carryover,
        retired_carryover,
        bootstrap_empty,
        same_carryover,
        conflict_carryover,
        resume_carryover,
        offline_carryover,
    ];
    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        direct.push(
            direct_snapshot(
                &local,
                &keyspaces,
                &historical,
                &terminals,
                &carryovers,
            )
            .await?,
        );
    }
    let direct_one_equal = direct.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_equal);
    let pipeline_after = read_historical_rows(&session, &keyspaces, &historical)
        .await?
        .pipeline;
    let pipeline_unchanged = pipeline_before_offline == pipeline_after;
    ensure!(pipeline_unchanged);

    let report = H23c4c4b2bReport {
        image: IMAGE,
        replication_factor: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        lifecycle_tables: 1,
        control_tables: 16,
        data_tables: 4,
        target_columns: 102,
        historical_v11_exact,
        v11_missing_exact_two,
        v11_verified_rejected_for_v12,
        v12_deploy_idempotent,
        v11_lifecycle_preserved,
        v11_application_rows_preserved,
        v11_pipeline_row_preserved,
        work_terminal_carryover_exact,
        retired_terminal_carryover_exact,
        bootstrap_empty_exact,
        terminal_same_retry_count,
        terminal_different_conflict,
        carryover_same_retry_count,
        carryover_different_conflict,
        missing_returns_none,
        malformed_rejected,
        caller_discard_retry: true,
        socket_response_loss_injected: false,
        terminal_only_then_carryover_resumed,
        pipeline_unchanged,
        one_replica_offline_read_write,
        repair_flush_compact: true,
        repair_ms,
        direct_one_nodes: 3,
        // Four preserved v11 rows, one current v12 lifecycle row, and every selected
        // terminal/carryover row. The two intentionally malformed poison rows are
        // outside this exact-read qualification set.
        direct_one_rows: 1 + terminals.len() + carryovers.len() + 4,
        direct_one_equal,
        production_persist_exposed: false,
        writer_head_provenance_verified: false,
        terminal_authorization_qualified: false,
        composite_owner: false,
        production_terminal_transition: false,
        production_pipeline_rotation: false,
        carryover_replay: false,
        successor_actor_injection: false,
        processor_owner_integration: false,
        proof_publish: false,
        full_22_domain_writer: false,
        authority_head_publish: false,
        full_node_restart: false,
        production_serving: false,
        h8_domains_closed: 0,
        qualification:
            "H23C4C4B2B_REALM_TERMINAL_CARRYOVER_SUBSTRATE_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4C4B2B_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
