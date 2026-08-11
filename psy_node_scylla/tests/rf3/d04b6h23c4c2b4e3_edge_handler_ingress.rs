//! h23c4c2b4e3: production-shaped Realm Handler ingress on Scylla/NATS RF=3.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure};
use async_nats::jetstream::{self, consumer::pull::Config as PullConfig, stream::Config as StreamConfig};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
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
    protocol::chain_context::{
        AuthorityObservation, AuthorityStateCheckpointId, AuthorityStateRoot,
        PendingContext, WorkProcCheckpointUniqueId, WorkUniquePendingId,
    },
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
    psy_core_db::traits::full::{
        PsyNodeCheckpointObjectDatabaseWriter,
        PsyNodeCheckpointTreeDatabaseReader,
        PsyNodeCoreDatabaseBasicContractInfoStoreWriter,
    },
    queue::{
        realm_user_update_artifact::VerifiedRealmUserUpdateRequest,
        realm_user_update_admission::RealmUserUpdateAdmissionKey,
        realm_user_update_claim::{
            RealmUserUpdateClaimBucket, RealmUserUpdateClaimPartition,
            RealmUserUpdateClaimPhase, RealmUserUpdateCreatedAtSeconds,
            StoredRealmUserUpdateClaim,
        },
        realm_user_update_dependency::{
            RealmUserUpdateDependencyBundle,
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
        realm_processor_application_archive::{
            RealmProcessorApplicationArchiveBinding,
            RealmProcessorApplicationArchivePlan,
        },
        realm_processor_semantic_output::{
            RealmProcessorSemanticOutput, RealmProcessorSemanticOutputParts,
        },
        recoverable_ephemeral::PendingQueueCaptureContext,
    },
    store::{
        authority_commit::AuthorityTimestampKey,
        authority_local_head::{
            AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
            AuthorityLocalHeadReadState, AuthorityStorageBindingGeneration,
            AuthorityStorageBindingRef, AuthorityStorageNamespaceId,
        },
        manifest_lifecycle::AuthorityHeadView,
        manifest_record::AuthorityManifestDigest,
        pending_generation::ProcNamespacePrefix,
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
            PendingGenerationContext, PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingEmptyQueueSealDigest, PendingNoWorkReceiptDigest,
            PendingPipelineBootstrap, PendingPipelineWriteOutcome,
            PendingQueueCloseIntentDigest, StoredPendingPipeline,
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
use tokio::time::sleep;

use crate::psy_setup::{
    setup_psy_scylla_database_store, setup_realm_edge_scylla_startup_composition,
    ScyllaUnifiedPsyStore,
};

use super::{
    branch_exact_shadow_reader_rf3_gate as fixture,
    pending_queue_stream_provision::ScyllaPendingQueueStreamProvisionStore,
    pending_queue_segment_lifecycle_rf3 as realm_fixture, *,
    realm_processor_application_archive::ScyllaRealmProcessorApplicationArchiveStore,
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
    generation_terminal_integrated: bool,
    production_writer_integrated: bool,
    authority_head_publish_integrated: bool,
    full_node_restart_tested: bool,
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
    snapshot_tables(&session, &control, &data).await
}

async fn dependency_timestamps_match_durable_claims(
    session: &Session,
    claims: &ScyllaRealmUserUpdateClaimStore,
    capture: PendingQueueCaptureContext,
) -> anyhow::Result<bool> {
    let mut expected = BTreeMap::new();
    for bucket in 0..RealmUserUpdateClaimBucket::COUNT {
        let partition = RealmUserUpdateClaimPartition::try_new(
            capture,
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
    ensure!(
        expected.len() == 3,
        "expected three published Handler claims, found {}",
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
    bail!("stream did not elect a different leader")
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
    let head_store = ScyllaAuthorityLocalHeadStore::prepare(
        Arc::clone(&session),
        head_keyspace,
    )
    .await?;
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
            StreamConfig::default(),
        )
        .await?,
    );
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
        1,
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
    let exercise_durable_replay = exercise_application_handoff
        || std::env::var("PSY_D04B6H23C4C3B_RF3").as_deref() == Ok("1");
    ensure!(
        !exercise_durable_replay || exercise_durable_capture,
        "c3b replay Gate requires the c3a durable capture owner"
    );
    let mut branch_exact_commit_owner = if exercise_durable_capture {
        let expectation = lineage.seal_attempt([0xC3; 32])?;
        let provider = Arc::new(
            activated
                .core
                .prepare_realm_processor_startup_provider_with_capture(
                    expectation,
                    Arc::clone(&nats),
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
    let handler = compose_handler(
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
    let jetstream = jetstream::new(raw_nats);
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
    let leader_after = wait_for_stream_leader(
        &jetstream,
        segment.stream_name(),
        Some(&leader_before),
    )
    .await?;
    handler
        .handle_user_end_cap_proof_submission(input_b.clone(), proof_a.clone())
        .await
        .expect_err("proof A paired with input B must fail");
    let proof_b = prover.prove_end_cap_dummy_ups(N::GLOBAL_USER_TREE_HEIGHT, &input_b)?;
    handler
        .handle_user_end_cap_proof_submission(input_b, proof_b)
        .await?;
    let second_publish_messages = stream_messages(&jetstream, segment.stream_name()).await?;
    ensure!(second_publish_messages == 3);

    drop(handler);
    let restarted_nats = Arc::new(
        NatsJetStreamClient::new_connection(
            fixture::KEYSPACE.to_owned(),
            nats_urls,
            PullConfig::default(),
            PullConfig::default(),
            StreamConfig::default(),
        )
        .await?,
    );
    let restarted = compose_handler(
        lineage,
        verifier,
        profile,
        restarted_nats,
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

    let mut durable_generation_replayed = false;
    let mut durable_generation_items = 0_u64;
    let mut durable_generation_digest_stable = false;
    let mut gather_task_restart_replayed = false;
    let mut application_semantic_bytes = 0_usize;
    let mut application_fragments = 0_u32;
    let mut application_pipeline_revision = 0_u64;
    let mut application_restart_recovered = false;
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

            let iteration_gate = RealmProcessorIterationGate::controlled();
            let mut iteration = owner.begin_iteration(
                iteration_gate.try_begin_iteration()?,
            )?;
            let mut capture_owner = iteration
                .open_durable_capture_for_processing(capture.processing())
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
                durable_generation_items = generation.item_count();
                ensure!(durable_generation_items == 3);
                let first_digest = generation.digest();
                let first_items = generation.into_business_items();
                durable_generation_replayed = true;

                // Drop the capture/gather-task side and reconstruct solely
                // from durable Scylla artifacts.  JetStream has already ACKed
                // Data and Seal, so no redelivery can make this pass.
                drop(capture_owner);
                drop(iteration);
                let mut restarted_iteration = owner.begin_iteration(
                    iteration_gate.try_begin_iteration()?,
                )?;
                let mut restarted_capture = restarted_iteration
                    .open_durable_capture_for_processing(capture.processing())
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
                gather_task_restart_replayed = durable_generation_digest_stable
                    && replayed.into_business_items() == first_items;
                ensure!(durable_generation_digest_stable);
                ensure!(gather_task_restart_replayed);

                if exercise_application_handoff {
                    // Force a real two-fragment application archive while
                    // keeping this RF=3 fixture below the c4a2b boundary: the
                    // semantic output is persisted and becomes the first
                    // pipeline candidate, but no proof/writer/head path runs.
                    let semantic = RealmProcessorSemanticOutput::try_from_candidate_parts(
                        RealmProcessorSemanticOutputParts {
                            context_digest: replayed_context_digest,
                            generation_digest: replayed_generation_digest,
                            boundary_digest: replayed_boundary_digest,
                            item_count: replayed_item_count,
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
                            deferred_jobs: Vec::new(),
                        },
                    )?;
                    application_semantic_bytes = semantic.canonical_len()?;
                    application_fragments = u32::try_from(
                        application_semantic_bytes.div_ceil(4 * 1024 * 1024),
                    )?;
                    ensure!(application_fragments == 2);
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
                    let mut recovered_capture = recovered_iteration
                        .open_durable_capture_for_processing(capture.processing())
                        .await?;
                    let recovered = recovered_capture
                        .recover_application_handoff()
                        .await?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "post-CAS capture reopen did not recover application handoff"
                            )
                        })?;
                    ensure!(recovered == expected_handoff);
                    application_restart_recovered = true;

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

    let dependency_explicit_timestamp_verified =
        dependency_timestamps_match_durable_claims(
            &session,
            claims.as_ref(),
            capture,
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
    );
    let replica = &replicas[0];
    let control = fixture::control_keyspace();
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_realm_user_update_admission_v1",
        )? == 4
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_realm_user_update_claim_v2",
        )? == 3
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_pending_queue_publish_source_v1",
        )? == 1
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_pending_queue_publish_intent_v1",
        )? == if exercise_durable_replay { 4 } else { 3 }
    );
    ensure!(
        replica.row_count(
            &control,
            "branch_exact_pending_queue_publish_prepared_v1",
        )? == if exercise_durable_replay { 4 } else { 3 }
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
        )? == 3
    );
    if exercise_application_handoff {
        ensure!(
            replica.row_count(
                &control,
                "branch_exact_pending_queue_semantic_generation_v2",
            )? == 1
        );
        ensure!(
            replica.row_count(
                &control,
                "branch_exact_realm_application_archive_header_v1",
            )? == 4
        );
        ensure!(
            replica.row_count(
                fixture::KEYSPACE,
                "branch_exact_realm_application_archive_fragment_v1",
            )? == usize::try_from(application_fragments)? + 3
        );
    }

    let report = E3Report {
        scylla_image: IMAGE,
        scylla_replication_factor: 3,
        configured_nats_servers: 3,
        nats_stream_replicas: 3,
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
        generation_terminal_integrated: false,
        production_writer_integrated: false,
        authority_head_publish_integrated: false,
        full_node_restart_tested: false,
        h8_domains_closed: 0,
        qualification: if exercise_application_handoff {
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
