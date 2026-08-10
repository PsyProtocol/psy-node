//! h22e2b: complete Realm Data+Seal generation and segment lifecycle on RF=3.

use std::{
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
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants},
    PF,
    PHash,
};
use psy_data::protocol::chain_context::{
    AuthorityObservation, AuthorityStateCheckpointId, AuthorityStateRoot,
};
use psy_node_core::{
    psy_core_db::traits::full::PsyNodeCheckpointObjectDatabaseWriter,
    queue::recoverable_artifact::{
        PendingQueueArtifactOwnerAttemptId, PendingQueueArtifactOwnerReasonDigest,
    },
    queue::recoverable_ephemeral::{
        PendingQueueArtifactIdentity, PendingQueueCaptureContext,
    },
    store::{
        authority_commit::{
            AuthorityClockSampleUs, AuthorityTimestampBootstrap,
            AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
            AuthorityTimestampWriteOutcome,
        },
        authority_local_head::{
            AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
            AuthorityStorageBindingGeneration, AuthorityStorageBindingRef,
            AuthorityStorageNamespaceId,
        },
        branch_exact_dual_write::BranchExactDualWriteIntent,
        manifest_lifecycle::AuthorityHeadView,
        manifest_record::AuthorityManifestDigest,
        pending_generation::ProcNamespacePrefix,
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
            PendingGenerationContext, PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingPipelineBootstrap, PendingPipelineReadState,
            PendingPipelineWriteOutcome, StoredPendingPipeline,
        },
        timestamp::CommitWriteTimestampUs,
        typed::UniquePendingId,
    },
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::{
        PendingQueueSegmentLedgerBootstrap, PendingQueueSegmentLedgerKey,
    },
    recoverable_publish::{
        PendingQueueGenerationBudgetContract, PendingQueuePublishIntentId,
        PendingQueuePublisherKind, PendingQueueSourceQuota,
        RecoverableNatsSourceRoute,
    },
    recoverable_segment::{
        RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
        RecoverableNatsStreamSegment,
    },
    recoverable_transport::{
        RecoverableNatsCaptureSpec,
        RecoverableNatsConsumerProvisioningOperationId,
    },
};
use scylla::statement::Consistency;
use serde::Serialize;
use tokio::time::sleep;

use crate::core::ScyllaCoreStore;

use super::{branch_exact_shadow_reader_rf3_gate as fixture, *};
use super::{
    branch_exact_pending_orchestration::{
        seal_branch_exact_begin, seal_branch_exact_publish,
        seal_branch_exact_queue_close, PendingQueueClosePlan,
    },
    pending_queue_consumer_gate::{
        PendingQueueConsumerGateIdentity, PendingQueueExpectedConsumer,
        ScyllaPendingQueueConsumerGateStore,
    },
    pending_queue_generation_terminal::ScyllaPendingQueueGenerationTerminalStore,
    pending_queue_nats_capture::{
        PendingQueueNatsCaptureOutcome, ScyllaBackedRecoverableNatsSource,
    },
    pending_queue_segment_lifecycle::{
        ResumedPendingQueueSegmentLifecycle,
        ScyllaPendingQueueSegmentLifecycleStore,
    },
    pending_queue_semantic_aggregate::{
        ScyllaPendingQueueSemanticAggregateStore,
        StoredPendingQueueSemanticGeneration,
    },
    pending_queue_semantic_terminal::verify_semantic_source_terminal,
};

const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const KIND: PendingQueuePublisherKind = PendingQueuePublisherKind::RealmUserUpdate;

#[derive(Clone, Copy)]
struct RealmRf3Network;

impl QNetworkTreeConstants for RealmRf3Network {
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
    const CHECKPOINT_TREE_HEIGHT: u8 = 32;
    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 32;
    const GLOBAL_USER_TREE_HEIGHT: u8 = 32;
    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = 24;
    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = 16;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 12;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = 12;
    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 20;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = 20;
    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = 32;
    const GROUP_REALM_HEIGHT: u8 = 1;
    const MAX_USERS: u64 = 1 << 32;
    const MAX_REALMS: u32 = 1 << 12;
    const MAX_USERS_PER_REALM: u32 = 1 << 20;
}

impl QNetworkHashTypes for RealmRf3Network {
    type QHash = PHash;
    type HasherBase = PoseidonHasher;
    type F = PF;
}

#[derive(Debug, Serialize)]
struct H22e2bReport {
    scylla_image: &'static str,
    scylla_replication_factor: u8,
    nats_servers: u8,
    nats_stream_replicas: u8,
    data_members: u8,
    seal_members: u8,
    lifecycle_revisions_resumed: Vec<u64>,
    nats_leader_before: String,
    nats_leader_after: String,
    nats_leader_failover: bool,
    nats_same_process_rejoined: bool,
    scylla_one_replica_offline: bool,
    pre_delete_ponr_stream_retained: bool,
    delete_after_physical_before_rev6_injected: bool,
    absent_retry_reached_rev6: bool,
    repair_direct_one_equal: bool,
    repair_ms: u64,
    qualification: &'static str,
}

pub(super) struct ActivatedRealmWriter {
    pub(super) core: ScyllaCoreStore<PHash, PoseidonHasher>,
    pub(super) writer_store: ScyllaBranchExactWriterLifecycleStore,
    pub(super) plan: BranchExactWriterActivationPlan<PHash>,
    pub(super) predecessor: psy_node_core::store::branch_pending_mapping::BranchPendingMapping<PHash>,
    pub(super) baseline_timestamp: CommitWriteTimestampUs,
}

fn current_pipeline(
    outcome: PendingPipelineWriteOutcome<PHash>,
) -> anyhow::Result<StoredPendingPipeline<PHash>> {
    match outcome {
        PendingPipelineWriteOutcome::Applied(current)
        | PendingPipelineWriteOutcome::Idempotent(current) => Ok(current),
        PendingPipelineWriteOutcome::Conflict(current) => {
            bail!("pipeline conflict at revision {}", current.revision().get())
        }
    }
}

pub(super) async fn activate_realm_writer(
    session: Arc<scylla::client::session::Session>,
) -> anyhow::Result<ActivatedRealmWriter> {
    activate_realm_writer_with_profile(
        session,
        psy_node_core::queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierProfileId::try_from_persisted([0xA5; 32])?,
    )
    .await
}

pub(super) async fn activate_realm_writer_with_profile(
    session: Arc<scylla::client::session::Session>,
    verifier_profile: psy_node_core::queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierProfileId,
) -> anyhow::Result<ActivatedRealmWriter> {
    for table in [
        "pending_id_to_pending_proc_id_table_u64_to_u128",
        "pending_id_to_pending_proc_id_table_u128_to_u64",
    ] {
        let (key, value) = if table.ends_with("u64_to_u128") {
            ("obj_id bigint", "value uuid")
        } else {
            ("obj_id uuid", "value bigint")
        };
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {}.{table} ({key} PRIMARY KEY, {value})",
                    fixture::KEYSPACE,
                ),
                &[],
            )
            .await?;
    }
    session.await_schema_agreement().await?;

    let (request, freeze) = fixture::request_and_freeze()?;
    let artifact = fixture::artifact()?;
    fixture::seed_legacy(&session, &artifact).await?;
    let verified = fixture::deploy_and_backfill(session.clone(), &request, &artifact).await?;
    let source = BranchExactLegacyExportReceipt::test_fixture_for_permit(
        &freeze,
        artifact.dataset_digest(),
        artifact.pair_rows_per_direction(),
        artifact.proof_rows(),
    );
    let core = fixture::core().await?;
    core.initialize_branch_exact_schema_setup(
        fixture::authority(),
        BranchExactSchemaSetupMode::RequireVerified(
            BranchExactSchemaSetupRequest::new(verified),
        ),
    )
    .await?;
    let reader = core.prepare_branch_exact_shadow_reader().await?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    ScyllaBranchExactShadowAuditStore::create_schema(&session, &control).await?;
    let shadow_store =
        ScyllaBranchExactShadowAuditStore::prepare(session.clone(), control.clone()).await?;
    let shadow = match ScyllaBranchExactShadowAuditExecutor::run(
        &shadow_store,
        &reader,
        &artifact,
        &source,
        &freeze,
        BranchExactShadowAuditGeneration::try_new(1)?,
    )
    .await?
    {
        BranchExactShadowAuditExecutionOutcome::Verified(receipt)
        | BranchExactShadowAuditExecutionOutcome::Idempotent(receipt) => receipt,
    };
    ScyllaBranchExactWriterLifecycleStore::create_schema(&session, &control).await?;
    let writer_store =
        ScyllaBranchExactWriterLifecycleStore::prepare(session.clone(), control).await?;
    let timestamp_keyspace =
        AuthorityTimestampNoTabletKeyspace::try_new(fixture::control_keyspace())?;
    ScyllaAuthorityTimestampStore::create_schema(&session, &timestamp_keyspace).await?;
    let timestamps =
        ScyllaAuthorityTimestampStore::prepare(session, timestamp_keyspace).await?;
    let baseline_timestamp = CommitWriteTimestampUs::try_from_i128(1_700_000_000_000_000)?;
    let timestamp_key = AuthorityTimestampKey::new(
        artifact.rows()[0].mapping().canonical_chain().network_id(),
        fixture::authority(),
    );
    match timestamps
        .bootstrap(AuthorityTimestampBootstrap::new(
            timestamp_key,
            baseline_timestamp,
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        ))
        .await?
    {
        AuthorityTimestampWriteOutcome::Applied(_)
        | AuthorityTimestampWriteOutcome::Idempotent(_) => {}
        AuthorityTimestampWriteOutcome::Conflict(_) => bail!("timestamp bootstrap conflict"),
    }
    let observed = timestamps
        .read_observed(timestamp_key)
        .await?
        .context("timestamp row missing")?;
    let ready = core.require_branch_exact_schema_ready()?;
    let plan = BranchExactWriterActivationPlan::try_new(
        BranchExactWriterGeneration::try_new(1)?,
        ready,
        &shadow,
        &artifact,
        &source,
        &freeze,
        observed,
        BranchExactWriterVerifierProfile::for_authority(
            fixture::authority(),
            Some(verifier_profile),
        )?,
    )?;
    match ScyllaBranchExactWriterActivationExecutor::activate(
        &writer_store,
        &shadow_store,
        plan.clone(),
    )
    .await?
    {
        BranchExactWriterActivationOutcome::Activated(_)
        | BranchExactWriterActivationOutcome::Idempotent(_) => {}
    }
    Ok(ActivatedRealmWriter {
        core,
        writer_store,
        plan,
        predecessor: *artifact.rows().last().unwrap().mapping(),
        baseline_timestamp,
    })
}

fn retention() -> anyhow::Result<RecoverableNatsRetentionContract> {
    Ok(RecoverableNatsRetentionContract::try_new(
        3,
        512 * 1024 * 1024,
        128 * 1024 * 1024,
        2,
        16,
    )?)
}

fn generation_budget() -> anyhow::Result<PendingQueueGenerationBudgetContract> {
    let mib = 1024 * 1024_u64;
    Ok(PendingQueueGenerationBudgetContract::try_new(
        fixture::authority(),
        vec![PendingQueueSourceQuota::try_new(KIND, 1_000, 127 * mib, mib)?],
        128 * mib,
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
    bail!("stream did not elect the expected leader")
}

fn signal_nats(server_name: &str, signal: &str) -> anyhow::Result<()> {
    let variable = match server_name {
        "psy-h22e-n1" => "PSY_D04B6H22E2B_NATS1_PID",
        "psy-h22e-n2" => "PSY_D04B6H22E2B_NATS2_PID",
        "psy-h22e-n3" => "PSY_D04B6H22E2B_NATS3_PID",
        other => bail!("unexpected NATS server {other}"),
    };
    let pid = std::env::var(variable)?.parse::<u32>()?;
    let status = Command::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .status()?;
    ensure!(status.success(), "failed to signal {server_name}");
    Ok(())
}

async fn read_lifecycle_row(
    ip: std::net::Ipv4Addr,
) -> anyhow::Result<(Vec<u8>, i64, Vec<u8>)> {
    let session = fixture::connect(Some(ip), Consistency::One).await?;
    Ok(session
        .query_unpaged(
            format!(
                "SELECT lifecycle_slot, revision, lifecycle_payload FROM {}.branch_exact_pending_queue_segment_lifecycle_v1",
                fixture::control_keyspace(),
            ),
            &[],
        )
        .await?
        .into_rows_result()?
        .single_row::<(Vec<u8>, i64, Vec<u8>)>()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 and NATS RF=3 runner"]
async fn d04b6h22e2b_complete_segment_lifecycle_joint_rf3() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_D04B6H22E2B_RF3").as_deref() == Ok("1"));
    let compose_file = std::env::var("PSY_D04B6H22E2B_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H22E2B_REPORT_PATH")?;
    let nats_urls = std::env::var("PSY_D04B6H22E2B_NATS_URLS")?
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(nats_urls.len() == 3);

    fixture::wait_up(3).await?;
    let session = Arc::new(fixture::connect(None, Consistency::Quorum).await?);
    fixture::create_keyspaces(&session).await?;
    fixture::create_legacy_tables(&session).await?;
    let activated = activate_realm_writer(session.clone()).await?;
    let control =
        BranchExactDeploymentNoTabletKeyspace::try_new(fixture::control_keyspace())?;

    ScyllaPendingPipelineStore::create_schema(&session, &control).await?;
    ScyllaPendingQueueSegmentLedgerStore::create_schema(&session, &control).await?;
    ScyllaPendingQueueConsumerGateStore::create_schema(&session, &control).await?;
    ScyllaPendingQueueSemanticAggregateStore::create_schema(&session, &control).await?;
    ScyllaPendingQueueGenerationTerminalStore::create_schema(&session, &control).await?;
    ScyllaPendingQueueSegmentLifecycleStore::create_schema(&session, &control).await?;
    let head_keyspace =
        AuthorityLocalHeadNoTabletKeyspace::try_new(fixture::control_keyspace())?;
    ScyllaAuthorityLocalHeadStore::create_schema(&session, &head_keyspace).await?;

    let artifact_keyspaces = PendingQueueArtifactKeyspaces::new(
        PendingQueueArtifactControlKeyspace::try_new(fixture::control_keyspace())?,
        PendingQueueArtifactDataKeyspace::try_new(fixture::KEYSPACE)?,
    );
    let publish_keyspaces = PendingQueuePublishKeyspaces::new(
        control.clone(),
        PendingQueuePublishDataKeyspace::try_new(fixture::KEYSPACE)?,
    );
    ScyllaPendingQueueArtifactStore::create_schema(&session, &artifact_keyspaces).await?;
    ScyllaPendingQueuePublishStore::create_schema(&session, &publish_keyspaces).await?;

    let network = activated.predecessor.canonical_chain().network_id();
    let authority = fixture::authority();
    let key = PendingGenerationLedgerKey::new(network, authority);
    let prefix = ProcNamespacePrefix::for_authority(network, authority);
    let predecessor_pending = activated.predecessor.pending_id();
    let candidate_pending = UniquePendingId::try_new(predecessor_pending.get() + 1)?;
    let future_pending = candidate_pending.get() + 1;
    let candidate_chain = fixture::chain(
        activated
            .predecessor
            .canonical_chain()
            .chain_epoch()
            .get(),
        activated
            .predecessor
            .canonical_chain()
            .checkpoint()
            .checkpoint_id()
            .get()
            + 1,
        90_000,
    )?;
    let candidate = psy_node_core::store::branch_pending_mapping::BranchPendingMapping::new(
        candidate_chain,
        candidate_pending,
    );
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
    let old_root = AuthorityStateRoot::from_local_state_root(PHash::from_values(31, 32, 33, 34));
    let initial_frontier = AuthorityObservation::try_new(
        *activated.predecessor.canonical_chain(),
        authority,
        AuthorityStateCheckpointId::new(
            activated
                .predecessor
                .canonical_chain()
                .checkpoint()
                .checkpoint_id()
                .get(),
        ),
        old_root,
    )?;
    let pipeline_bootstrap = PendingPipelineBootstrap::try_new(
        key,
        activation,
        prefix,
        PendingGenerationBootstrapReason::LegacyActivation,
        predecessor_context,
        candidate_context,
        initial_frontier,
        predecessor_pending.get(),
    )?;
    let pipeline_store =
        ScyllaPendingPipelineStore::prepare(session.clone(), control.clone()).await?;
    let pipeline = current_pipeline(pipeline_store.bootstrap(&pipeline_bootstrap).await?)?;

    let mut setup_attempt = 0_u8;
    let full_db = loop {
        setup_attempt += 1;
        match crate::psy_setup::setup_psy_scylla_database_store::<RealmRf3Network>(Arc::new(
            activated.core.clone(),
        ))
        .await
        {
            Ok(database) => break database,
            Err(error)
                if setup_attempt < 10
                    && error
                        .to_string()
                        .contains("group 0 change due to concurrent modification") =>
            {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error),
        }
    };
    session
        .query_unpaged(
            format!(
                "INSERT INTO {}.u64_counter_singleton_table (obj_id, value) VALUES (?, ?) IF NOT EXISTS",
                fixture::control_keyspace(),
            ),
            (2_i64, candidate_pending.get() as i64),
        )
        .await?;
    let reserved = full_db
        .reserve_next_unique_pending_generation_without_mapping(prefix)
        .await?;
    ensure!(reserved.pending_id().get() == future_pending);
    let pipeline = current_pipeline(
        pipeline_store
            .apply(&pipeline.seal_rotation(reserved)?)
            .await?,
    )?;
    ensure!(pipeline.processing() == candidate_context);
    let capture_context = PendingQueueCaptureContext::try_new(key, activation, candidate_context)?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let base = format!("psy_h22e2b_{nonce}");
    let segment = RecoverableNatsStreamSegment::try_new(
        base.clone(),
        key,
        RecoverableNatsSegmentId::try_new(1)?,
        retention()?,
    )?;
    let validated = segment.validate_stream_config_structure(&segment.stream_config())?;
    let ledger_bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
        key,
        &validated,
        generation_budget()?,
        1,
    )?;
    let ledger_key: PendingQueueSegmentLedgerKey = ledger_bootstrap.candidate().key().clone();
    let ledger_store =
        ScyllaPendingQueueSegmentLedgerStore::prepare(session.clone(), control.clone()).await?;
    ledger_store.bootstrap(&ledger_bootstrap).await?;
    let assignment = ledger_store
        .reserve_generation(&ledger_key, capture_context)
        .await?;

    let raw = async_nats::connect(nats_urls.clone()).await?;
    let context = jetstream::new(raw);
    context.create_stream(segment.stream_config()).await?;
    let nats = Arc::new(
        NatsJetStreamClient::new_connection(
            base,
            nats_urls,
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig::default(),
        )
        .await?,
    );
    let publisher = Arc::new(nats.recoverable_pending_publisher(segment.clone()).await?);
    let publish_store = ScyllaPendingQueuePublishStore::prepare(
        session.clone(),
        publisher.clone(),
        segment.clone(),
        publish_keyspaces,
    )
    .await?;
    publish_store.bootstrap_source(&assignment, KIND).await?;
    let data_slot = publish_store
        .materialize_data(
            &assignment,
            KIND,
            PendingQueuePublishIntentId::try_new([41; 32])?,
            b"h22e2b-real-realm-user-update",
        )
        .await?;
    let data_bound = publish_store
        .bind_materialized(&assignment, KIND, data_slot)
        .await?;
    publish_store
        .publish_and_commit(&assignment, data_bound)
        .await?;

    let writer_key = BranchExactWriterAuthorityKey::new(network, authority);
    let BranchExactWriterReadState::Current(active_writer) =
        activated.writer_store.read(writer_key).await?
    else {
        bail!("active writer missing")
    };
    let close_plan = PendingQueueClosePlan::model(&pipeline)?;
    let _ = current_pipeline(
        pipeline_store
            .apply(&seal_branch_exact_queue_close(
                &pipeline,
                &active_writer,
                close_plan,
            )?)
            .await?,
    )?;
    let close_receipt = pipeline_store
        .read_queue_close_exact::<PHash>(capture_context)
        .await?;
    let seal_slot = publish_store
        .materialize_seal::<PHash>(
            &pipeline_store,
            &assignment,
            KIND,
            PendingQueuePublishIntentId::try_new([42; 32])?,
            &close_receipt,
        )
        .await?;
    let seal_bound = publish_store
        .bind_materialized(&assignment, KIND, seal_slot)
        .await?;
    publish_store
        .publish_and_commit(&assignment, seal_bound)
        .await?;

    let live_for_consumer = nats
        .observe_recoverable_segment_instance(segment.clone())
        .await?;
    let gate_store = Arc::new(
        ScyllaPendingQueueConsumerGateStore::prepare(session.clone(), control.clone()).await?,
    );
    let gate_identity = PendingQueueConsumerGateIdentity::new(
        segment.segment_id(),
        segment.digest(),
        live_for_consumer.instance_id(),
    );
    let gate_open = gate_store
        .bootstrap_open(gate_identity)
        .await
        .context("bootstrap pending-queue consumer gate")?;
    let route = RecoverableNatsSourceRoute::try_new(capture_context, KIND, &segment)?;
    let capture_spec = RecoverableNatsCaptureSpec::for_segment(
        segment.clone(),
        route.subject(),
        16,
    )?;
    let provisioned = match gate_store
        .provision_capture_consumer(
            &nats,
            &gate_open,
            &live_for_consumer,
            capture_spec.clone(),
            RecoverableNatsConsumerProvisioningOperationId::try_new([43; 32])?,
        )
        .await
    {
        Ok(receipt) => receipt,
        Err(mut last_error) => {
            let mut recovered = None;
            for _ in 0..10 {
                sleep(Duration::from_millis(500)).await;
                match gate_store
                    .resume_capture_consumer(
                        &nats,
                        &gate_open,
                        &live_for_consumer,
                        capture_spec.clone(),
                    )
                    .await
                {
                    Ok(receipt) => {
                        recovered = Some(receipt);
                        break;
                    }
                    Err(error) => last_error = error,
                }
            }
            recovered.ok_or(last_error).context(
                "provision or durably resume pending-queue capture consumer",
            )?
        }
    };
    let artifact_store = Arc::new(
        ScyllaPendingQueueArtifactStore::prepare(session.clone(), artifact_keyspaces).await?,
    );
    let artifact_identity = PendingQueueArtifactIdentity::try_new(
        capture_context,
        capture_spec.source_identity()?,
    )?;
    let artifact_owner = artifact_store
        .claim_owner(
            &artifact_identity,
            PendingQueueArtifactOwnerAttemptId::try_new([44; 32])?,
            PendingQueueArtifactOwnerReasonDigest::try_new([45; 32])?,
        )
        .await?;
    let source = ScyllaBackedRecoverableNatsSource::new(
        nats.clone(),
        artifact_store.clone(),
        gate_store.clone(),
        capture_spec.clone(),
        provisioned,
        artifact_owner,
    )?;
    let Some(PendingQueueNatsCaptureOutcome::Sealed {
        data: Some(_),
        ..
    }) = source
        .capture_one::<PHash>(&pipeline_store, capture_context, &close_receipt)
        .await
        .context("capture Data+Seal from pending-queue consumer")?
    else {
        bail!("expected one Data plus trailing Seal in one capture")
    };
    let nats_scan = publisher.scan_source_retained_set(assignment.assignment(), KIND).await?;
    let semantic_source = verify_semantic_source_terminal::<PHash>(
        &pipeline_store,
        &publish_store,
        &artifact_store,
        &assignment,
        source.owner_permit(),
        &close_receipt,
        &capture_spec,
        KIND,
        nats_scan,
    )
    .await?;
    let aggregate = StoredPendingQueueSemanticGeneration::try_from_source_receipts(
        &assignment,
        &close_receipt,
        vec![semantic_source],
    )?;
    let aggregate_store =
        ScyllaPendingQueueSemanticAggregateStore::prepare(session.clone(), control.clone()).await?;
    let aggregate_receipt = aggregate_store
        .persist_verified::<PHash>(
            &pipeline_store,
            &assignment,
            &close_receipt,
            &aggregate,
        )
        .await?;
    aggregate_store
        .handoff_to_pipeline::<PHash>(
            &pipeline_store,
            &assignment,
            &close_receipt,
            &aggregate_receipt,
        )
        .await?;
    let PendingPipelineReadState::Current(pipeline) = pipeline_store.read::<PHash>(key).await?
    else {
        bail!("pipeline missing after semantic handoff")
    };

    let intent = BranchExactDualWriteIntent::try_realm(
        authority,
        activated.predecessor,
        candidate,
        prefix.derive_proc_id(candidate_pending),
        &TagTreeMerkleProof::<PHash>::new_empty(),
    )?;
    let request = BranchExactWriterRuntimeRequest::new(network, authority, activated.plan.digest());
    let runtime = ScyllaBranchExactWriterRuntime::<PHash>::prepare(
        session.clone(),
        fixture::KEYSPACE,
        &fixture::control_keyspace(),
        request,
    )
    .await?;
    let barrier = runtime
        .prepare_and_verify(
            intent,
            AuthorityClockSampleUs::try_from_i128(
                activated.baseline_timestamp.as_i64() as i128 + 100,
            )?,
        )
        .await?;
    let writer = runtime.read_writer().await?;
    let pipeline = current_pipeline(
        pipeline_store
            .apply(&seal_branch_exact_begin(&pipeline, &writer)?)
            .await?,
    )?;

    let state_root = AuthorityStateRoot::from_local_state_root(PHash::from_values(71, 72, 73, 74));
    let observed = AuthorityObservation::try_new(
        candidate_chain,
        authority,
        AuthorityStateCheckpointId::new(
            candidate_chain.checkpoint().checkpoint_id().get(),
        ),
        state_root,
    )?;
    let head_store =
        ScyllaAuthorityLocalHeadStore::prepare(session.clone(), head_keyspace).await?;
    let head = AuthorityHeadView::try_from_observed(
        AuthorityTimestampKey::new(network, authority),
        candidate_chain,
        observed.state_checkpoint_id(),
        state_root,
    )?;
    let head_bootstrap = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::PostGenesisFloor,
        head,
        CommitWriteTimestampUs::try_from_i128(
            activated.baseline_timestamp.as_i64() as i128 + 100,
        )?,
        AuthorityManifestDigest::from_persisted([81; 32]),
        AuthorityStorageBindingRef::new(
            AuthorityStorageBindingGeneration::try_new(1)?,
            AuthorityStorageNamespaceId::from_verified_namespace_id([82; 32]),
        ),
    );
    head_store.bootstrap(&head_bootstrap).await?;
    let pipeline = current_pipeline(
        pipeline_store
            .apply(&seal_branch_exact_publish(&pipeline, &writer, observed)?)
            .await?,
    )?;
    runtime.require_fresh_barrier(&barrier).await?;
    runtime.finish_published(&barrier, &candidate_chain).await?;
    ensure!(matches!(
        pipeline.processing_state(),
        psy_node_core::store::pending_generation_pipeline::PendingProcessingState::Published { .. }
    ));

    let terminal_store =
        ScyllaPendingQueueGenerationTerminalStore::prepare(session.clone(), control.clone()).await?;
    terminal_store
        .persist_verified::<PHash>(
            &aggregate_store,
            &pipeline_store,
            &activated.writer_store,
            &head_store,
            &assignment,
        )
        .await?;
    let expected_consumer = PendingQueueExpectedConsumer::try_new(
        capture_spec.subject(),
        capture_spec.consumer_digest(),
    )?;
    let gate_closed = gate_store
        .close(gate_identity, &[expected_consumer])
        .await
        .context("close pending-queue consumer gate")?;
    let closure = ledger_store
        .observe_segment_closure(&ledger_key, segment.segment_id())
        .await?;
    let live = nats
        .observe_recoverable_segment_instance(segment.clone())
        .await?;

    let leader_before = wait_for_stream_leader(&context, segment.stream_name(), None).await?;
    signal_nats(&leader_before, "-STOP")?;
    let leader_after =
        wait_for_stream_leader(&context, segment.stream_name(), Some(&leader_before)).await?;
    fixture::compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h22e2b Scylla replica",
    )?;
    fixture::wait_up(2).await?;

    let mut resumed_revisions = Vec::new();
    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(),
        control.clone(),
    )
    .await?;
    lifecycle
        .persist_seal_requested::<PHash>(
            &nats,
            &gate_store,
            &gate_closed,
            &ledger_store,
            &terminal_store,
            &aggregate_store,
            &pipeline_store,
            &activated.writer_store,
            &head_store,
            &closure,
            &live,
        )
        .await?;
    drop(lifecycle);

    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(), control.clone(),
    ).await?;
    let ResumedPendingQueueSegmentLifecycle::SealRequested(rev1) =
        lifecycle.resume(&ledger_store, &closure).await?
    else { bail!("expected resumed revision 1") };
    resumed_revisions.push(1);
    lifecycle.seal_requested_stream::<PHash>(
        &nats, &gate_store, &ledger_store, &terminal_store, &aggregate_store,
        &pipeline_store, &activated.writer_store, &head_store, &closure, &rev1,
        segment.clone(),
    ).await?;
    drop(lifecycle);

    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(), control.clone(),
    ).await?;
    let ResumedPendingQueueSegmentLifecycle::StreamSealed(rev2) =
        lifecycle.resume(&ledger_store, &closure).await?
    else { bail!("expected resumed revision 2") };
    resumed_revisions.push(2);
    lifecycle.scan_stream_sealed_messages::<PHash>(
        &nats, &ledger_store, &terminal_store, &aggregate_store, &pipeline_store,
        &activated.writer_store, &head_store, &closure, &rev2, segment.clone(),
    ).await?;
    drop(lifecycle);

    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(), control.clone(),
    ).await?;
    let ResumedPendingQueueSegmentLifecycle::MessagesScanVerified(rev3) =
        lifecycle.resume(&ledger_store, &closure).await?
    else { bail!("expected resumed revision 3") };
    resumed_revisions.push(3);
    lifecycle.verify_messages_scanned_consumers::<PHash>(
        &nats, &ledger_store, &terminal_store, &aggregate_store, &pipeline_store,
        &activated.writer_store, &head_store, &closure, &rev3, segment.clone(),
    ).await?;
    drop(lifecycle);

    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(), control.clone(),
    ).await?;
    let ResumedPendingQueueSegmentLifecycle::ScanVerified(rev4) =
        lifecycle.resume(&ledger_store, &closure).await?
    else { bail!("expected resumed revision 4") };
    resumed_revisions.push(4);
    nats.observe_recoverable_sealed_segment_instance(segment.clone()).await?;
    lifecycle.request_delete_for_scan_verified::<PHash>(
        &nats, &ledger_store, &terminal_store, &aggregate_store, &pipeline_store,
        &activated.writer_store, &head_store, &closure, &rev4, segment.clone(),
    ).await?;
    drop(lifecycle);

    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(), control.clone(),
    ).await?;
    let ResumedPendingQueueSegmentLifecycle::DeleteRequested(rev5) =
        lifecycle.resume(&ledger_store, &closure).await?
    else { bail!("expected resumed revision 5") };
    resumed_revisions.push(5);
    lifecycle.delete_requested_stream_then_simulate_crash(
        &nats, &aggregate_store, &rev5, segment.clone(),
    ).await?;
    ensure!(nats.observe_recoverable_sealed_segment_instance(segment.clone()).await.is_err());
    drop(lifecycle);

    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(), control.clone(),
    ).await?;
    let ResumedPendingQueueSegmentLifecycle::DeleteRequested(rev5_after_crash) =
        lifecycle.resume(&ledger_store, &closure).await?
    else { bail!("expected revision 5 after physical delete crash") };
    lifecycle.delete_requested_stream(
        &nats, &aggregate_store, &rev5_after_crash, segment.clone(),
    ).await?;
    drop(lifecycle);

    let lifecycle = ScyllaPendingQueueSegmentLifecycleStore::prepare(
        session.clone(), control.clone(),
    ).await?;
    let ResumedPendingQueueSegmentLifecycle::Deleted(_) =
        lifecycle.resume(&ledger_store, &closure).await?
    else { bail!("expected resumed revision 6") };
    resumed_revisions.push(6);

    fixture::compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart h22e2b Scylla replica",
    )?;
    fixture::wait_up(3).await?;
    signal_nats(&leader_before, "-CONT")?;
    sleep(Duration::from_secs(5)).await;
    let nats_rejoined = Command::new("curl")
        .args(["-fsS", match leader_before.as_str() {
            "psy-h22e-n1" => "http://127.0.0.1:47222/healthz?js-enabled-only=true",
            "psy-h22e-n2" => "http://127.0.0.1:47223/healthz?js-enabled-only=true",
            "psy-h22e-n3" => "http://127.0.0.1:47224/healthz?js-enabled-only=true",
            _ => unreachable!(),
        }])
        .status()?
        .success();
    ensure!(nats_rejoined);

    let repair_started = Instant::now();
    for node in fixture::NODE_CONTAINERS {
        fixture::nodetool(
            node,
            &["repair", "-pr", &fixture::control_keyspace()],
            "repair h22e2b control ranges",
        )?;
        fixture::nodetool(
            node,
            &["flush", &fixture::control_keyspace()],
            "flush h22e2b control",
        )?;
        fixture::nodetool(
            node,
            &["compact", &fixture::control_keyspace()],
            "compact h22e2b control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let rows = futures::future::join_all(fixture::NODE_IPS.map(read_lifecycle_row))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(rows.windows(2).all(|pair| pair[0] == pair[1]));
    ensure!(rows[0].1 == 6);

    let report = H22e2bReport {
        scylla_image: IMAGE,
        scylla_replication_factor: 3,
        nats_servers: 3,
        nats_stream_replicas: 3,
        data_members: 1,
        seal_members: 1,
        lifecycle_revisions_resumed: resumed_revisions,
        nats_leader_before: leader_before,
        nats_leader_after: leader_after,
        nats_leader_failover: true,
        nats_same_process_rejoined: nats_rejoined,
        scylla_one_replica_offline: true,
        pre_delete_ponr_stream_retained: true,
        delete_after_physical_before_rev6_injected: true,
        absent_retry_reached_rev6: true,
        repair_direct_one_equal: true,
        repair_ms,
        qualification: "PASS",
    };
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
