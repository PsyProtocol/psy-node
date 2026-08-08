//! h22e2: joint RF=3 Scylla + JetStream consumer-gate qualification.

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
    consumer::{pull::Config as PullConfig, FromConsumer},
    stream::Config as StreamConfig,
};
use futures::future::join_all;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::store::pending_generation_identity::PendingGenerationLedgerKey;
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
        RecoverableNatsStreamSegment,
    },
    recoverable_transport::{
        RecoverableNatsCaptureSpec, RecoverableNatsConsumerProvisioningOperationId,
        RecoverableNatsExpectedStreamMode, RecoverableNatsSealDisposition,
    },
};
use scylla::statement::Consistency;
use serde::Serialize;
use tokio::time::sleep;

use super::{
    branch_exact_shadow_reader_rf3_gate as fixture,
    pending_queue_consumer_gate::{
        PendingQueueConsumerGateIdentity, PendingQueueConsumerProvisioningStart,
        PendingQueueExpectedConsumer, ScyllaPendingQueueConsumerGateStore,
        PENDING_QUEUE_CONSUMER_GATE_TABLE,
    },
    BranchExactDeploymentNoTabletKeyspace,
};

const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const CONCURRENT_RESUMES: usize = 24;

#[derive(Debug, Serialize)]
struct H22e2Report {
    scylla_image: &'static str,
    scylla_replication_factor: u8,
    nats_servers: u8,
    nats_stream_replicas: u8,
    nats_leader_before: String,
    nats_leader_after: String,
    nats_leader_failover: bool,
    scylla_one_replica_offline: bool,
    provisioning_restart_from_durable_operation: bool,
    concurrent_resume_attempts: usize,
    physical_consumer_exactly_once: bool,
    existing_only_response_loss_retry: bool,
    live_exact_set_verified: bool,
    seal_response_loss_idempotent: bool,
    sealed_exact_set_verified: bool,
    same_config_consumer_recreate_blocked: bool,
    gate_rows: usize,
    gate_revision: u64,
    repair_direct_one_equal: bool,
    repair_ms: u64,
    qualification: &'static str,
}

fn retention() -> anyhow::Result<RecoverableNatsRetentionContract> {
    Ok(RecoverableNatsRetentionContract::try_new(
        3,
        8 * 1024 * 1024 * 1024,
        3 * 1024 * 1024 * 1024,
        3,
        16,
    )?)
}

fn segment(base: &str, id: u64) -> anyhow::Result<RecoverableNatsStreamSegment> {
    Ok(RecoverableNatsStreamSegment::try_new(
        base,
        PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337)?,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
        ),
        RecoverableNatsSegmentId::try_new(id)?,
        retention()?,
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
    bail!("JetStream stream {stream_name} did not elect the expected leader")
}

fn stop_nats_server(server_name: &str) -> anyhow::Result<()> {
    let variable = match server_name {
        "psy-h22e-n1" => "PSY_D04B6H22E2_NATS1_PID",
        "psy-h22e-n2" => "PSY_D04B6H22E2_NATS2_PID",
        "psy-h22e-n3" => "PSY_D04B6H22E2_NATS3_PID",
        other => bail!("unexpected JetStream leader {other}"),
    };
    let pid = std::env::var(variable)
        .with_context(|| format!("missing {variable}"))?
        .parse::<u32>()
        .with_context(|| format!("invalid {variable}"))?;
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    ensure!(status.success(), "failed to stop isolated NATS leader {server_name}");
    Ok(())
}

async fn direct_gate_rows(
    ip: std::net::Ipv4Addr,
) -> anyhow::Result<BTreeSet<(Vec<u8>, i64, Vec<u8>)>> {
    let session = fixture::connect(Some(ip), Consistency::One).await?;
    Ok(session
        .query_unpaged(
            format!(
                "SELECT gate_slot, revision, gate_payload FROM {}.{}",
                fixture::control_keyspace(),
                PENDING_QUEUE_CONSUMER_GATE_TABLE,
            ),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(Vec<u8>, i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated h22e2 RF=3 Scylla and NATS runner"]
async fn d04b6h22e2_consumer_gate_joint_rf3() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_D04B6H22E2_RF3").as_deref() == Ok("1"));
    let compose_file = std::env::var("PSY_D04B6H22E2_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H22E2_REPORT_PATH")?;
    let nats_urls = std::env::var("PSY_D04B6H22E2_NATS_URLS")?
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(nats_urls.len() == 3);

    let session = Arc::new(fixture::connect(None, Consistency::Quorum).await?);
    fixture::create_keyspaces(&session).await?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    ScyllaPendingQueueConsumerGateStore::create_schema(&session, &control).await?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let base = format!("psy_h22e2_{nonce}");
    let primary = segment(&base, 1)?;
    let recreate = segment(&base, 2)?;
    let raw = async_nats::connect(nats_urls.clone()).await?;
    let context = jetstream::new(raw);
    context.create_stream(primary.stream_config()).await?;
    context.create_stream(recreate.stream_config()).await?;
    let nats = NatsJetStreamClient::new_connection(
        base.clone(),
        nats_urls,
        PullConfig::default(),
        PullConfig::default(),
        StreamConfig::default(),
    )
    .await?;

    let leader_before = wait_for_stream_leader(&context, primary.stream_name(), None).await?;
    stop_nats_server(&leader_before)?;
    let leader_after = wait_for_stream_leader(
        &context,
        primary.stream_name(),
        Some(&leader_before),
    )
    .await?;

    fixture::compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h22e2 Scylla replica",
    )?;
    fixture::wait_up(2).await?;

    let store = ScyllaPendingQueueConsumerGateStore::prepare(
        session.clone(),
        control.clone(),
    )
    .await?;
    let live = nats.observe_recoverable_segment_instance(primary.clone()).await?;
    let identity = PendingQueueConsumerGateIdentity::new(
        primary.segment_id(),
        primary.digest(),
        live.instance_id(),
    );
    let open = store.bootstrap_open(identity).await?;
    let subject = format!("{}.source", primary.subject_prefix());
    let spec = RecoverableNatsCaptureSpec::for_segment(primary.clone(), subject, 16)?;
    let expected = PendingQueueExpectedConsumer::try_new(
        spec.subject(),
        spec.consumer_digest(),
    )?;
    let operation = RecoverableNatsConsumerProvisioningOperationId::try_new([41; 32])?;
    ensure!(matches!(
        store
            .begin_provisioning(&open, expected.clone(), operation)
            .await?,
        PendingQueueConsumerProvisioningStart::Lease(_)
    ));
    drop(store);

    // Recreate the process-local adapter and recover the operation id solely
    // from the durable Provisioning entry. Concurrent retries may race at
    // both the LWT and physical create/readback boundaries.
    let resumed_store = ScyllaPendingQueueConsumerGateStore::prepare(
        session.clone(),
        control.clone(),
    )
    .await?;
    let resumed_open = resumed_store.bootstrap_open(identity).await?;
    let resumed = join_all((0..CONCURRENT_RESUMES).map(|_| {
        resumed_store.resume_capture_consumer(
            &nats,
            &resumed_open,
            &live,
            spec.clone(),
        )
    }))
    .await;
    for (index, result) in resumed.into_iter().enumerate() {
        result.with_context(|| format!("concurrent durable resume {index}"))?;
    }

    // Simulate successful completion with a lost response and another process
    // restart. The retry is existing-only and cannot create or replace.
    let response_loss_store = ScyllaPendingQueueConsumerGateStore::prepare(
        session.clone(),
        control.clone(),
    )
    .await?;
    let response_loss_open = response_loss_store.bootstrap_open(identity).await?;
    let provisioned = response_loss_store
        .resume_capture_consumer(&nats, &response_loss_open, &live, spec.clone())
        .await
        .context("response-loss durable resume")?;
    let binding = response_loss_store
        .recover_existing_binding(&provisioned, &spec)
        .await?;
    nats.open_existing_recoverable_capture(spec.clone(), &binding)
        .await
        .context("existing-only open after response loss")?;
    let closed = response_loss_store.close(identity, &[expected.clone()]).await?;
    response_loss_store
        .revalidate_nats_consumer_set(
            &nats,
            closed.commitment(),
            primary.clone(),
            RecoverableNatsExpectedStreamMode::Live,
        )
        .await
        .context("live exact consumer set")?;
    let live_for_seal = nats
        .observe_recoverable_segment_instance(primary.clone())
        .await?;
    ensure!(live_for_seal.instance_id() == live.instance_id());
    let seal = nats
        .seal_recoverable_segment_instance(&live_for_seal)
        .await
        .context("physical stream seal")?;
    ensure!(seal.disposition() == RecoverableNatsSealDisposition::Applied);
    response_loss_store
        .revalidate_nats_consumer_set(
            &nats,
            closed.commitment(),
            primary.clone(),
            RecoverableNatsExpectedStreamMode::Sealed,
        )
        .await
        .context("sealed exact consumer set")?;
    let seal_retry = nats
        .seal_recoverable_segment_instance(&live_for_seal)
        .await
        .context("seal response-loss retry")?;
    ensure!(seal_retry.disposition() == RecoverableNatsSealDisposition::AlreadySealed);

    // A second exact incarnation proves that deleting and recreating a
    // same-name, same-config consumer changes its server identity and is not
    // accepted by the durable gate.
    let live_recreate = nats
        .observe_recoverable_segment_instance(recreate.clone())
        .await?;
    let recreate_identity = PendingQueueConsumerGateIdentity::new(
        recreate.segment_id(),
        recreate.digest(),
        live_recreate.instance_id(),
    );
    let recreate_open = response_loss_store
        .bootstrap_open(recreate_identity)
        .await?;
    let recreate_subject = format!("{}.source", recreate.subject_prefix());
    let recreate_spec = RecoverableNatsCaptureSpec::for_segment(
        recreate.clone(),
        recreate_subject,
        16,
    )?;
    let recreate_expected = PendingQueueExpectedConsumer::try_new(
        recreate_spec.subject(),
        recreate_spec.consumer_digest(),
    )?;
    let recreate_operation =
        RecoverableNatsConsumerProvisioningOperationId::try_new([42; 32])?;
    response_loss_store
        .provision_capture_consumer(
            &nats,
            &recreate_open,
            &live_recreate,
            recreate_spec.clone(),
            recreate_operation,
        )
        .await
        .context("recreate fixture provision")?;
    let recreate_closed = response_loss_store
        .close(recreate_identity, &[recreate_expected])
        .await?;
    response_loss_store
        .revalidate_nats_consumer_set(
            &nats,
            recreate_closed.commitment(),
            recreate.clone(),
            RecoverableNatsExpectedStreamMode::Live,
        )
        .await
        .context("recreate fixture exact set before replacement")?;
    let raw_stream = context.get_stream(recreate.stream_name()).await?;
    let old = raw_stream.consumer_info(recreate_spec.durable()).await?;
    let old_created = old.created;
    let pull = PullConfig::try_from_consumer_config(old.config)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    raw_stream.delete_consumer(recreate_spec.durable()).await?;
    let mut replacement = raw_stream.create_consumer_strict(pull).await?;
    let replacement_created = replacement.info().await?.created;
    ensure!(old_created != replacement_created);
    ensure!(response_loss_store
        .revalidate_nats_consumer_set(
            &nats,
            recreate_closed.commitment(),
            recreate,
            RecoverableNatsExpectedStreamMode::Live,
        )
        .await
        .is_err());

    fixture::compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart h22e2 Scylla replica",
    )?;
    fixture::wait_up(3).await?;
    let repair_started = Instant::now();
    for node in fixture::NODE_CONTAINERS {
        fixture::nodetool(
            node,
            &["repair", "-pr", &fixture::control_keyspace()],
            "repair h22e2 control ranges",
        )?;
        fixture::nodetool(
            node,
            &["flush", &fixture::control_keyspace()],
            "flush h22e2 control",
        )?;
        fixture::nodetool(
            node,
            &["compact", &fixture::control_keyspace()],
            "compact h22e2 control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let replicas = join_all(fixture::NODE_IPS.map(direct_gate_rows))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(replicas.windows(2).all(|pair| pair[0] == pair[1]));
    ensure!(replicas[0].len() == 2);
    ensure!(replicas[0].iter().all(|(_, revision, _)| *revision == 3));

    let report = H22e2Report {
        scylla_image: IMAGE,
        scylla_replication_factor: 3,
        nats_servers: 3,
        nats_stream_replicas: 3,
        nats_leader_before: leader_before,
        nats_leader_after: leader_after,
        nats_leader_failover: true,
        scylla_one_replica_offline: true,
        provisioning_restart_from_durable_operation: true,
        concurrent_resume_attempts: CONCURRENT_RESUMES,
        physical_consumer_exactly_once: true,
        existing_only_response_loss_retry: true,
        live_exact_set_verified: true,
        seal_response_loss_idempotent: true,
        sealed_exact_set_verified: true,
        same_config_consumer_recreate_blocked: true,
        gate_rows: replicas[0].len(),
        gate_revision: 3,
        repair_direct_one_equal: true,
        repair_ms,
        qualification: "PASS",
    };
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
