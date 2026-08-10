//! h23c4c2b4d2b: durable stream provisioning on real RF=3 Scylla and NATS.

use std::{
    collections::BTreeSet,
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use async_nats::jetstream::{
    self,
    consumer::pull::Config as PullConfig,
    stream::Config as StreamConfig,
};
use futures::future::join_all;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::recoverable_ephemeral::PendingQueueCaptureContext,
    store::pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::{
        PendingQueueGenerationSegmentAssignment, PendingQueueSegmentLedgerBootstrap,
    },
    recoverable_publish::{
        PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
        PendingQueuePublishEnvelope, PendingQueuePublishIntentId,
        PendingQueuePublisherKind, PendingQueueSourceQuota,
        RecoverableNatsSourceRoute,
    },
    recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
        RecoverableNatsStreamSegment,
        RECOVERABLE_NATS_PROVISION_OPERATION_METADATA_KEY,
    },
};
use scylla::statement::Consistency;
use serde::Serialize;
use tokio::time::sleep;

use super::{
    branch_exact_shadow_reader_rf3_gate as fixture,
    pending_queue_stream_provision::{
        PendingQueueStreamProvisionError, ScyllaPendingQueueStreamProvisionStore,
        PENDING_QUEUE_STREAM_PROVISION_TABLE,
    },
    pending_queue_segment_ledger::SEGMENT_LEDGER_TABLE,
    PendingQueueSegmentLedgerReadState, ScyllaPendingQueueSegmentLedgerStore,
    BranchExactDeploymentNoTabletKeyspace,
    PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
    PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
};

const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const CONCURRENT_RESUMES: usize = 64;

#[derive(Debug, Serialize)]
struct H23c4c2b4d2Report {
    scylla_image: &'static str,
    scylla_replication_factor: u8,
    nats_servers: u8,
    nats_stream_replicas: u8,
    sidecar_schema_version: u16,
    sidecar_target_tables: usize,
    provisioning_before_create_recovered: bool,
    create_response_loss_reconciled: bool,
    completion_response_loss_idempotent: bool,
    concurrent_resumes: usize,
    concurrent_single_instance: bool,
    same_slot_contract_conflict_rejected: bool,
    one_scylla_replica_offline: bool,
    nats_leader_before: String,
    nats_leader_after: String,
    nats_leader_failover: bool,
    recreated_instance_rejected: bool,
    provision_rows: usize,
    provision_revision: u64,
    repair_direct_one_equal: bool,
    repair_ms: u64,
    rotation_qualified: bool,
    qualification: &'static str,
}

#[derive(Debug, Serialize)]
struct H23c4c2b4d2cReport {
    scylla_image: &'static str,
    scylla_replication_factor: u8,
    nats_servers: u8,
    nats_stream_replicas: u8,
    sidecar_schema_version: u16,
    same_ledger_segments: usize,
    stage_contenders: usize,
    stage_single_candidate: bool,
    create_response_loss_reconciled: bool,
    activation_contenders: usize,
    activation_single_candidate: bool,
    activation_response_loss_idempotent: bool,
    old_assignment_segment: u64,
    new_assignment_segment: u64,
    old_route_survived_rotation: bool,
    new_route_used_new_instance: bool,
    old_closure_stable_after_new_assignment: bool,
    old_closure_reconstructed_after_restart: bool,
    one_scylla_replica_offline: bool,
    nats_leader_before: String,
    nats_leader_after: String,
    nats_leader_failover: bool,
    ledger_revision: u64,
    ledger_rows: usize,
    provision_rows: usize,
    repair_direct_one_equal: bool,
    repair_ms: u64,
    rotation_ms: u64,
    handler_cli_integrated: bool,
    h8_closed_domains: u8,
    qualification: &'static str,
}

fn retention(max_stream_bytes: i64) -> anyhow::Result<RecoverableNatsRetentionContract> {
    Ok(RecoverableNatsRetentionContract::try_new(
        3,
        max_stream_bytes,
        128 * 1024 * 1024,
        3,
        16,
    )?)
}

fn ledger_and_segment(
    base: &str,
    segment_id: u64,
    max_stream_bytes: i64,
) -> anyhow::Result<(PendingQueueSegmentLedgerBootstrap, RecoverableNatsStreamSegment)> {
    let authority = AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    };
    let generation_key = PendingGenerationLedgerKey::new(
        NetworkId::try_from_chain_id(1337)?,
        authority,
    );
    let segment = RecoverableNatsStreamSegment::try_new(
        base,
        generation_key,
        RecoverableNatsSegmentId::try_new(segment_id)?,
        retention(max_stream_bytes)?,
    )?;
    let budget = PendingQueueGenerationBudgetContract::try_new(
        authority,
        vec![PendingQueueSourceQuota::try_new(
            PendingQueuePublisherKind::RealmUserUpdate,
            1024,
            127 * 1024 * 1024,
            1024 * 1024,
        )?],
        128 * 1024 * 1024,
    )?;
    let validated = segment.validate_stream_config_structure(&segment.stream_config())?;
    let bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
        generation_key,
        &validated,
        budget,
        16,
    )?;
    Ok((bootstrap, segment))
}

fn rotation_ledger_and_segment(
    base: &str,
) -> anyhow::Result<(PendingQueueSegmentLedgerBootstrap, RecoverableNatsStreamSegment)> {
    let authority = AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    };
    let generation_key = PendingGenerationLedgerKey::new(
        NetworkId::try_from_chain_id(1337)?,
        authority,
    );
    let segment = RecoverableNatsStreamSegment::try_new(
        base,
        generation_key,
        RecoverableNatsSegmentId::try_new(1)?,
        retention(512 * 1024 * 1024)?,
    )?;
    let budget = PendingQueueGenerationBudgetContract::try_new(
        authority,
        vec![PendingQueueSourceQuota::try_new(
            PendingQueuePublisherKind::RealmUserUpdate,
            1024,
            127 * 1024 * 1024,
            1024 * 1024,
        )?],
        128 * 1024 * 1024,
    )?;
    let validated = segment.validate_stream_config_structure(&segment.stream_config())?;
    let bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
        generation_key,
        &validated,
        budget,
        1,
    )?;
    Ok((bootstrap, segment))
}

fn capture_context(pending: u64) -> anyhow::Result<PendingQueueCaptureContext> {
    let key = PendingGenerationLedgerKey::new(
        NetworkId::try_from_chain_id(1337)?,
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        },
    );
    Ok(PendingQueueCaptureContext::try_new(
        key,
        PendingGenerationActivationDigest::try_new([33; 32])?,
        PendingGenerationContext::try_from_legacy(pending, u128::from(pending) + 5000)?,
    )?)
}

fn data_envelope(
    context: PendingQueueCaptureContext,
    assignment: &PendingQueueGenerationSegmentAssignment,
    segment: &RecoverableNatsStreamSegment,
    ordinal: u32,
    previous_sequence: u64,
    previous_digest: [u8; 32],
) -> anyhow::Result<PendingQueuePublishEnvelope> {
    let route = RecoverableNatsSourceRoute::try_new(
        context,
        PendingQueuePublisherKind::RealmUserUpdate,
        segment,
    )?;
    Ok(PendingQueuePublishEnvelope::data(
        &route,
        assignment,
        PendingQueuePublishIntentId::try_new([ordinal as u8; 32])?,
        PendingQueueMemberOrdinal::try_new(ordinal)?,
        previous_sequence,
        previous_digest,
        format!("segment-{}-message-{ordinal}", segment.segment_id().get()).into_bytes(),
    )?)
}

async fn wait_for_stream_leader(
    context: &jetstream::Context,
    stream_name: &str,
    excluded: Option<&str>,
) -> anyhow::Result<String> {
    for _ in 0..90 {
        if let Ok(stream) = context.get_stream(stream_name).await {
            if let Ok(info) = stream.get_info().await {
                if let Some(leader) = info.cluster.and_then(|cluster| cluster.leader) {
                    if excluded != Some(leader.as_str()) {
                        return Ok(leader);
                    }
                }
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("JetStream stream {stream_name} did not elect a replacement leader")
}

fn stop_nats_server(server_name: &str) -> anyhow::Result<()> {
    let variable = match server_name {
        "psy-h23d2-n1" => "PSY_D04B6H23C4C2B4D2_NATS1_PID",
        "psy-h23d2-n2" => "PSY_D04B6H23C4C2B4D2_NATS2_PID",
        "psy-h23d2-n3" => "PSY_D04B6H23C4C2B4D2_NATS3_PID",
        other => bail!("unexpected JetStream leader {other}"),
    };
    let pid = std::env::var(variable)
        .with_context(|| format!("missing {variable}"))?
        .parse::<u32>()?;
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    ensure!(status.success(), "failed to stop isolated NATS leader");
    Ok(())
}

fn stop_nats_server_d2c(server_name: &str) -> anyhow::Result<()> {
    let variable = match server_name {
        "psy-h23d2c-n1" => "PSY_D04B6H23C4C2B4D2C_NATS1_PID",
        "psy-h23d2c-n2" => "PSY_D04B6H23C4C2B4D2C_NATS2_PID",
        "psy-h23d2c-n3" => "PSY_D04B6H23C4C2B4D2C_NATS3_PID",
        other => bail!("unexpected d2c JetStream leader {other}"),
    };
    let pid = std::env::var(variable)
        .with_context(|| format!("missing {variable}"))?
        .parse::<u32>()?;
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    ensure!(status.success(), "failed to stop isolated d2c NATS leader");
    Ok(())
}

async fn direct_rows(
    ip: std::net::Ipv4Addr,
) -> anyhow::Result<BTreeSet<(Vec<u8>, i64, Vec<u8>)>> {
    let session = fixture::connect(Some(ip), Consistency::One).await?;
    Ok(session
        .query_unpaged(
            format!(
                "SELECT provision_slot, revision, provision_payload FROM {}.{}",
                fixture::control_keyspace(),
                PENDING_QUEUE_STREAM_PROVISION_TABLE,
            ),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(Vec<u8>, i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?)
}


async fn direct_rotation_rows(
    ip: std::net::Ipv4Addr,
) -> anyhow::Result<(
    BTreeSet<(Vec<u8>, i64, Vec<u8>)>,
    BTreeSet<(Vec<u8>, i64, Vec<u8>)>,
)> {
    let session = fixture::connect(Some(ip), Consistency::One).await?;
    let ledger = session
        .query_unpaged(
            format!(
                "SELECT ledger_slot, revision, ledger_payload FROM {}.{}",
                fixture::control_keyspace(),
                SEGMENT_LEDGER_TABLE,
            ),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(Vec<u8>, i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let provision = session
        .query_unpaged(
            format!(
                "SELECT provision_slot, revision, provision_payload FROM {}.{}",
                fixture::control_keyspace(),
                PENDING_QUEUE_STREAM_PROVISION_TABLE,
            ),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(Vec<u8>, i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok((ledger, provision))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires the isolated h23c4c2b4d2 RF=3 Scylla and NATS runner"]
async fn d04b6h23c4c2b4d2_stream_provision_joint_rf3() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B4D2_RF3").as_deref() == Ok("1")
    );
    let compose_file = std::env::var("PSY_D04B6H23C4C2B4D2_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H23C4C2B4D2_REPORT_PATH")?;
    let nats_urls = std::env::var("PSY_D04B6H23C4C2B4D2_NATS_URLS")?
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(nats_urls.len() == 3);

    let session = Arc::new(fixture::connect(None, Consistency::Quorum).await?);
    fixture::create_keyspaces(&session).await?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    ScyllaPendingQueueStreamProvisionStore::create_schema(&session, &control).await?;
    ScyllaPendingQueueSegmentLedgerStore::create_schema(&session, &control).await?;
    let ledger_store = Arc::new(
        ScyllaPendingQueueSegmentLedgerStore::prepare(
            session.clone(),
            control.clone(),
        )
        .await?,
    );
    let store = Arc::new(
        ScyllaPendingQueueStreamProvisionStore::prepare_for_test(
            session.clone(),
            control,
            ledger_store.clone(),
        )
        .await?,
    );

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let base = format!("psy_h23d2_{nonce}");
    let nats = Arc::new(
        NatsJetStreamClient::new_connection(
            base.clone(),
            nats_urls.clone(),
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig::default(),
        )
        .await?,
    );
    let raw = async_nats::connect(nats_urls).await?;
    let context = jetstream::new(raw);

    fixture::compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h23d2 Scylla replica",
    )?;
    fixture::wait_up(2).await?;

    // Crash after the durable begin but before any JetStream mutation.
    let (bootstrap1, segment1) = ledger_and_segment(&base, 1, 512 * 1024 * 1024)?;
    ledger_store.bootstrap(&bootstrap1).await?;
    let ledger1 = bootstrap1.candidate().key();
    let operation1 = store
        .persist_provisioning_without_transport_for_test(ledger1, segment1.clone())
        .await?;
    ensure!(context.get_stream(segment1.stream_name()).await.is_err());
    let receipt1 = store
        .provision(&nats, ledger1, segment1.clone())
        .await?;
    ensure!(receipt1.segment().segment_id() == segment1.segment_id());

    // Crash after physical create/readback but before durable completion.
    // A separate ledger namespace is required because segment rotation is a
    // later milestone. This case proves create-response recovery only.
    let base2 = format!("{base}_create_loss");
    let (bootstrap2, segment2) = ledger_and_segment(&base2, 1, 512 * 1024 * 1024)?;
    ledger_store.bootstrap(&bootstrap2).await?;
    let ledger2 = bootstrap2.candidate().key();
    let nats2 = NatsJetStreamClient::new_connection(
        base2,
        std::env::var("PSY_D04B6H23C4C2B4D2_NATS_URLS")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        PullConfig::default(),
        PullConfig::default(),
        StreamConfig::default(),
    ).await?;
    let operation2 = store
        .persist_provisioning_without_transport_for_test(ledger2, segment2.clone())
        .await?;
    let dropped_create = nats2
        .provision_recoverable_segment(segment2.clone(), operation2)
        .await?;
    let created_instance2 = dropped_create.instance_id();
    drop(dropped_create);
    let receipt2 = store
        .provision(&nats2, ledger2, segment2.clone())
        .await?;
    ensure!(receipt2.instance_id() == created_instance2);

    // Completion LWT succeeds, but its caller response is discarded.
    let base3 = format!("{base}_complete_loss");
    let (bootstrap3, segment3) = ledger_and_segment(&base3, 1, 512 * 1024 * 1024)?;
    ledger_store.bootstrap(&bootstrap3).await?;
    let ledger3 = bootstrap3.candidate().key();
    let nats3 = NatsJetStreamClient::new_connection(
        base3,
        std::env::var("PSY_D04B6H23C4C2B4D2_NATS_URLS")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        PullConfig::default(),
        PullConfig::default(),
        StreamConfig::default(),
    ).await?;
    let operation3 = store
        .persist_provisioning_without_transport_for_test(ledger3, segment3.clone())
        .await?;
    let created3 = nats3
        .provision_recoverable_segment(segment3.clone(), operation3)
        .await?;
    let instance3 = created3.instance_id();
    store
        .complete_without_return_for_test(ledger3, &segment3, &created3)
        .await?;
    let receipt3 = store
        .provision(&nats3, ledger3, segment3.clone())
        .await?;
    ensure!(receipt3.instance_id() == instance3);

    // Identical concurrent callers converge on one row and one incarnation.
    let base4 = format!("{base}_concurrent");
    let (bootstrap4, segment4) = ledger_and_segment(&base4, 1, 512 * 1024 * 1024)?;
    ledger_store.bootstrap(&bootstrap4).await?;
    let ledger4 = bootstrap4.candidate().key().clone();
    let nats4 = Arc::new(NatsJetStreamClient::new_connection(
        base4.clone(),
        std::env::var("PSY_D04B6H23C4C2B4D2_NATS_URLS")?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        PullConfig::default(),
        PullConfig::default(),
        StreamConfig::default(),
    ).await?);
    let results = join_all((0..CONCURRENT_RESUMES).map(|_| {
        let store = store.clone();
        let nats = nats4.clone();
        let ledger = ledger4.clone();
        let segment = segment4.clone();
        async move { store.provision(&nats, &ledger, segment).await }
    }))
    .await;
    let mut instances = BTreeSet::new();
    for (index, result) in results.into_iter().enumerate() {
        instances.insert(
            result
                .with_context(|| format!("concurrent provision {index}"))?
                .instance_id()
                .as_bytes()
                .to_vec(),
        );
    }
    ensure!(instances.len() == 1);

    // Same stable slot with a different contract must conflict before NATS.
    let (_, conflicting_segment4) =
        ledger_and_segment(&base4, 1, 513 * 1024 * 1024)?;
    ensure!(matches!(
        store
            .provision(&nats4, &ledger4, conflicting_segment4)
            .await,
        Err(PendingQueueStreamProvisionError::Ledger(_))
    ));

    // A same-name, same-contract replacement cannot inherit the old binding,
    // even when a test injector copies the durable operation marker.
    context.delete_stream(segment1.stream_name()).await?;
    sleep(Duration::from_millis(10)).await;
    let mut replacement = segment1.stream_config();
    replacement.metadata.insert(
        RECOVERABLE_NATS_PROVISION_OPERATION_METADATA_KEY.to_owned(),
        hex::encode(operation1.as_bytes()),
    );
    context.create_stream(replacement).await?;
    ensure!(store
        .read_provisioned(ledger1, &segment1)
        .await?
        .open_publisher(&store, &nats)
        .await
        .is_err());

    // Keep all three NATS replicas available for the destructive recreation
    // case above. Exercise leader failover on a different, still-authoritative
    // stream so the RF=3 replacement stream is never created while a replica
    // is deliberately offline.
    let leader_before = wait_for_stream_leader(&context, segment2.stream_name(), None).await?;
    stop_nats_server(&leader_before)?;
    let leader_after = wait_for_stream_leader(
        &context,
        segment2.stream_name(),
        Some(&leader_before),
    )
    .await?;
    let reopened2 = store.read_provisioned(ledger2, &segment2).await?;
    ensure!(reopened2.instance_id() == created_instance2);
    reopened2.open_publisher(&store, &nats2).await?;

    fixture::compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart h23d2 Scylla replica",
    )?;
    fixture::wait_up(3).await?;
    let repair_started = Instant::now();
    for node in fixture::NODE_CONTAINERS {
        fixture::nodetool(
            node,
            &["repair", "-pr", &fixture::control_keyspace()],
            "repair h23d2 provision rows",
        )?;
        fixture::nodetool(
            node,
            &["flush", &fixture::control_keyspace()],
            "flush h23d2 provision rows",
        )?;
        fixture::nodetool(
            node,
            &["compact", &fixture::control_keyspace()],
            "compact h23d2 provision rows",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let replicas = join_all(fixture::NODE_IPS.map(direct_rows))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(replicas.windows(2).all(|pair| pair[0] == pair[1]));
    ensure!(replicas[0].len() == 4);
    ensure!(replicas[0].iter().all(|(_, revision, _)| *revision == 2));

    let report = H23c4c2b4d2Report {
        scylla_image: IMAGE,
        scylla_replication_factor: 3,
        nats_servers: 3,
        nats_stream_replicas: 3,
        sidecar_schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        sidecar_target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        provisioning_before_create_recovered: true,
        create_response_loss_reconciled: true,
        completion_response_loss_idempotent: true,
        concurrent_resumes: CONCURRENT_RESUMES,
        concurrent_single_instance: true,
        same_slot_contract_conflict_rejected: true,
        one_scylla_replica_offline: true,
        nats_leader_before: leader_before,
        nats_leader_after: leader_after,
        nats_leader_failover: true,
        recreated_instance_rejected: true,
        provision_rows: replicas[0].len(),
        provision_revision: 2,
        repair_direct_one_equal: true,
        repair_ms,
        rotation_qualified: false,
        qualification: "H23C4C2B4D2_STREAM_PROVISION_RF3_PASSED",
    };
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires the isolated h23c4c2b4d2c RF=3 Scylla and NATS runner"]
async fn d04b6h23c4c2b4d2c_rotation_route_joint_rf3() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B4D2C_RF3").as_deref() == Ok("1")
    );
    let compose_file = std::env::var("PSY_D04B6H23C4C2B4D2C_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H23C4C2B4D2C_REPORT_PATH")?;
    let nats_urls = std::env::var("PSY_D04B6H23C4C2B4D2C_NATS_URLS")?
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(nats_urls.len() == 3);

    let session = Arc::new(fixture::connect(None, Consistency::Quorum).await?);
    fixture::create_keyspaces(&session).await?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    ScyllaPendingQueueStreamProvisionStore::create_schema(&session, &control).await?;
    ScyllaPendingQueueSegmentLedgerStore::create_schema(&session, &control).await?;
    let ledger_store = Arc::new(
        ScyllaPendingQueueSegmentLedgerStore::prepare(session.clone(), control.clone()).await?,
    );
    let store = Arc::new(
        ScyllaPendingQueueStreamProvisionStore::prepare_for_test(
            session.clone(),
            control.clone(),
            ledger_store.clone(),
        )
        .await?,
    );

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let base = format!("psy_h23d2c_{nonce}");
    let nats = Arc::new(
        NatsJetStreamClient::new_connection(
            base.clone(),
            nats_urls.clone(),
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig::default(),
        )
        .await?,
    );
    let raw = async_nats::connect(nats_urls).await?;
    let context = jetstream::new(raw);

    fixture::compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h23d2c Scylla replica",
    )?;
    fixture::wait_up(2).await?;

    let rotation_started = Instant::now();
    let (bootstrap, segment1) = rotation_ledger_and_segment(&base)?;
    ledger_store.bootstrap(&bootstrap).await?;
    let ledger_key = bootstrap.candidate().key().clone();
    let provisioned1 = store
        .provision(&nats, &ledger_key, segment1.clone())
        .await?;
    let instance1 = provisioned1.instance_id();
    let context1 = capture_context(1)?;
    let assignment1 = ledger_store
        .reserve_generation(&ledger_key, context1)
        .await?;
    ensure!(assignment1.assignment().segment_id() == segment1.segment_id());
    let closure1 = ledger_store
        .observe_segment_closure(&ledger_key, segment1.segment_id())
        .await?;

    // Sixty-four contenders construct the same deterministic SG2 candidate.
    // The LWT has one physical winner and every response-loss style retry
    // reads back the exact same revision/payload.
    let stage_results = join_all((0..CONCURRENT_RESUMES).map(|_| {
        let ledger_store = ledger_store.clone();
        let ledger_key = ledger_key.clone();
        async move { ledger_store.stage_next_rotation(&ledger_key).await }
    }))
    .await;
    let mut staged_receipts = Vec::with_capacity(CONCURRENT_RESUMES);
    let mut staged_revisions = BTreeSet::new();
    let mut staged_segments = BTreeSet::new();
    for (index, result) in stage_results.into_iter().enumerate() {
        let staged = result.with_context(|| format!("stage contender {index}"))?;
        staged_revisions.insert(staged.ledger_revision().get());
        staged_segments.insert(staged.segment().segment_id().get());
        staged_receipts.push(staged);
    }
    ensure!(staged_revisions == BTreeSet::from([3]));
    ensure!(staged_segments == BTreeSet::from([2]));
    let staged = Arc::new(staged_receipts.pop().unwrap());
    let segment2 = staged.segment().clone();
    // A retry that starts strictly after the stage CAS must observe the same
    // staged successor. It must not derive SG3 from highest_segment_id.
    let staged_retry = ledger_store.stage_next_rotation(&ledger_key).await?;
    ensure!(staged_retry.ledger_revision().get() == 3);
    ensure!(staged_retry.segment() == &segment2);
    ensure!(ledger_store
        .reserve_generation(&ledger_key, capture_context(2)?)
        .await
        .is_err());

    // Persist Provisioning, create the physical stream and lose that response.
    // A freshly prepared store recovers the exact operation/instance.
    let operation2 = store
        .persist_provisioning_without_transport_for_test(&ledger_key, segment2.clone())
        .await?;
    let dropped_create = nats
        .provision_recoverable_segment(segment2.clone(), operation2)
        .await?;
    let instance2 = dropped_create.instance_id();
    drop(dropped_create);
    let restarted_ledger = Arc::new(
        ScyllaPendingQueueSegmentLedgerStore::prepare(session.clone(), control.clone()).await?,
    );
    let restarted_store = Arc::new(
        ScyllaPendingQueueStreamProvisionStore::prepare_for_test(
            session.clone(),
            control.clone(),
            restarted_ledger.clone(),
        )
        .await?,
    );
    let provisioned2 = restarted_store
        .provision_staged_rotation(&nats, &staged)
        .await?;
    ensure!(provisioned2.instance_id() == instance2);

    // Activation contenders all consume the same opaque staging receipt and
    // fresh Provisioned row. One rev4 CAS wins; the rest classify exact current
    // as idempotent success.
    let activate_results = join_all((0..CONCURRENT_RESUMES).map(|_| {
        let store = restarted_store.clone();
        let nats = nats.clone();
        let staged = staged.clone();
        async move { store.activate_staged_rotation(&nats, &staged).await }
    }))
    .await;
    let mut activation_revisions = BTreeSet::new();
    for (index, result) in activate_results.into_iter().enumerate() {
        let activated = result.with_context(|| format!("activation contender {index}"))?;
        activation_revisions.insert(activated.ledger_revision().get());
        ensure!(activated.segment() == &segment2);
    }
    ensure!(activation_revisions == BTreeSet::from([4]));

    // Reprepare again and retry after discarding every activation response.
    let final_ledger = Arc::new(
        ScyllaPendingQueueSegmentLedgerStore::prepare(session.clone(), control.clone()).await?,
    );
    let final_store = Arc::new(
        ScyllaPendingQueueStreamProvisionStore::prepare_for_test(
            session.clone(),
            control,
            final_ledger.clone(),
        )
        .await?,
    );
    let activated_retry = final_store
        .activate_staged_rotation(&nats, &staged)
        .await?;
    ensure!(activated_retry.ledger_revision().get() == 4);

    let context2 = capture_context(2)?;
    let assignment2 = final_ledger
        .reserve_generation(&ledger_key, context2)
        .await?;
    ensure!(assignment2.assignment().segment_id() == segment2.segment_id());
    let rotation_ms = rotation_started.elapsed().as_millis() as u64;
    let PendingQueueSegmentLedgerReadState::Current(final_state) =
        final_ledger.read(&ledger_key).await?
    else {
        bail!("rotation ledger disappeared")
    };
    ensure!(final_state.revision().get() == 5);
    ensure!(final_state.live_segments().len() == 2);
    ensure!(final_state.assignments().len() == 2);
    ensure!(final_state.live_segments()[0].generation_count() == 1);
    ensure!(final_state.live_segments()[1].generation_count() == 1);
    final_ledger.revalidate_segment_closure(&closure1).await?;
    let reconstructed_closure1 = final_ledger
        .observe_segment_closure(&ledger_key, segment1.segment_id())
        .await?;
    ensure!(reconstructed_closure1.ledger_revision() == closure1.ledger_revision());
    ensure!(
        reconstructed_closure1.ledger_payload_digest()
            == closure1.ledger_payload_digest()
    );
    ensure!(reconstructed_closure1.assignments().len() == closure1.assignments().len());
    final_ledger
        .revalidate_segment_closure(&reconstructed_closure1)
        .await?;

    // Resolution is assignment-bound, not active-segment-bound. A1 continues
    // to open SG1 after SG2 becomes active; A2 opens only SG2.
    let resolver = final_store.assignment_resolver(nats.clone());
    let old_route = resolver.resolve(&ledger_key, context1).await?;
    let new_route = resolver.resolve(&ledger_key, context2).await?;
    ensure!(old_route.assignment_digest() == assignment1.assignment().digest());
    ensure!(new_route.assignment_digest() == assignment2.assignment().digest());
    ensure!(old_route.segment() == &segment1);
    ensure!(new_route.segment() == &segment2);
    ensure!(old_route.instance_id() == instance1);
    ensure!(new_route.instance_id() == instance2);
    let old_first = data_envelope(
        context1,
        assignment1.assignment(),
        &segment1,
        1,
        0,
        [0; 32],
    )?;
    let new_first = data_envelope(
        context2,
        assignment2.assignment(),
        &segment2,
        1,
        0,
        [0; 32],
    )?;
    let old_outcome = old_route.publish(&old_first).await?;
    let new_outcome = new_route.publish(&new_first).await?;

    let leader_before = wait_for_stream_leader(&context, segment2.stream_name(), None).await?;
    stop_nats_server_d2c(&leader_before)?;
    let leader_after = wait_for_stream_leader(
        &context,
        segment2.stream_name(),
        Some(&leader_before),
    )
    .await?;
    let old_after_failover = resolver.resolve(&ledger_key, context1).await?;
    let new_after_failover = resolver.resolve(&ledger_key, context2).await?;
    let old_second = data_envelope(
        context1,
        assignment1.assignment(),
        &segment1,
        2,
        old_outcome.subject_sequence(),
        *old_first.digest().as_bytes(),
    )?;
    let new_second = data_envelope(
        context2,
        assignment2.assignment(),
        &segment2,
        2,
        new_outcome.subject_sequence(),
        *new_first.digest().as_bytes(),
    )?;
    old_after_failover.publish(&old_second).await?;
    new_after_failover.publish(&new_second).await?;
    let info1 = context.get_stream(segment1.stream_name()).await?.get_info().await?;
    let info2 = context.get_stream(segment2.stream_name()).await?.get_info().await?;
    ensure!(info1.state.messages == 2 && info2.state.messages == 2);
    ensure!(info1.config.num_replicas == 3 && info2.config.num_replicas == 3);

    fixture::compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart h23d2c Scylla replica",
    )?;
    fixture::wait_up(3).await?;
    let repair_started = Instant::now();
    for node in fixture::NODE_CONTAINERS {
        fixture::nodetool(
            node,
            &["repair", "-pr", &fixture::control_keyspace()],
            "repair h23d2c rotation rows",
        )?;
        fixture::nodetool(
            node,
            &["flush", &fixture::control_keyspace()],
            "flush h23d2c rotation rows",
        )?;
        fixture::nodetool(
            node,
            &["compact", &fixture::control_keyspace()],
            "compact h23d2c rotation rows",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let replicas = join_all(fixture::NODE_IPS.map(direct_rotation_rows))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(replicas.windows(2).all(|pair| pair[0] == pair[1]));
    ensure!(replicas[0].0.len() == 1);
    ensure!(replicas[0].0.iter().all(|(_, revision, _)| *revision == 5));
    ensure!(replicas[0].1.len() == 2);
    ensure!(replicas[0].1.iter().all(|(_, revision, _)| *revision == 2));

    let report = H23c4c2b4d2cReport {
        scylla_image: IMAGE,
        scylla_replication_factor: 3,
        nats_servers: 3,
        nats_stream_replicas: 3,
        sidecar_schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        same_ledger_segments: 2,
        stage_contenders: CONCURRENT_RESUMES,
        stage_single_candidate: true,
        create_response_loss_reconciled: true,
        activation_contenders: CONCURRENT_RESUMES,
        activation_single_candidate: true,
        activation_response_loss_idempotent: true,
        old_assignment_segment: segment1.segment_id().get(),
        new_assignment_segment: segment2.segment_id().get(),
        old_route_survived_rotation: true,
        new_route_used_new_instance: true,
        old_closure_stable_after_new_assignment: true,
        old_closure_reconstructed_after_restart: true,
        one_scylla_replica_offline: true,
        nats_leader_before: leader_before,
        nats_leader_after: leader_after,
        nats_leader_failover: true,
        ledger_revision: 5,
        ledger_rows: replicas[0].0.len(),
        provision_rows: replicas[0].1.len(),
        repair_direct_one_equal: true,
        repair_ms,
        rotation_ms,
        handler_cli_integrated: false,
        h8_closed_domains: 0,
        qualification: "H23C4C2B4D2C_ROTATION_ROUTE_RF3_PASSED",
    };
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
