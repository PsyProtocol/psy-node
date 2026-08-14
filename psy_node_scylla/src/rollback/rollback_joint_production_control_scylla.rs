//! Single-node production-store composition test for the delete-only rollback
//! control plane. It covers durable request selection plus one Realm's exact
//! physical archive and recovery. Physical deletion remains a later slice.

use std::sync::Arc;

use anyhow::{bail, ensure};
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    data::db::table::QDatabaseTableRoutingKey,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants},
    PHash, PF,
};
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    },
    chain_context::AuthorityScope,
    chain_context::{
        AuthorityObservation, AuthorityStateCheckpointId, AuthorityStateRoot,
    },
};
use psy_node_core::store::{
    authority_commit::AuthorityTimestampKey,
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
        AuthorityStorageBindingGeneration, AuthorityStorageBindingRef,
        AuthorityStorageNamespaceId,
    },
    branch_exact_dual_write::BranchExactDualWriteIntent,
    branch_pending_mapping::BranchPendingMapping,
    branch_exact_schema::BranchExactSchemaMaterializationPlan,
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
        CanonicalHeadReadState, CoordinatorCanonicalHeadReader,
        CoordinatorCanonicalHeadStore,
    },
    rollback_admin::{
        CoordinatorRollbackAdminInbox, RollbackAdminInboxAccess,
        RollbackAdminPlannedStartIntent, RollbackAdminStartDisposition,
    },
    rollback_admission::{
        CoordinatorRollbackAdmissionBoundary, RollbackAdmissionBoundaryOutcome,
    },
    rollback_participant_maintenance::{
        CoordinatorRollbackGlobalProgress, CoordinatorRollbackMaintenanceExecutor,
        CoordinatorRollbackMaintenanceOutcome,
    },
    rollback_participant_plan::RollbackRealmParticipant,
    rollback_runtime_rebuild::{
        RealmRollbackParticipantProgress, RealmRollbackRuntimeControl,
    },
    rollback_control::RollbackControlState,
    rollback_topology::RollbackTopologySnapshot,
    manifest_lifecycle::AuthorityHeadView,
    manifest_record::AuthorityManifestDigest,
    pending_generation::{ProcNamespacePrefix, ReservedPendingGeneration},
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
        PendingGenerationContext, PendingGenerationLedgerKey,
    },
    pending_generation_pipeline::{
        PendingPipelineBootstrap, PendingPipelineIntentDigest,
        PendingPublishReceiptDigest, PendingQueueCloseIntentDigest,
        PendingWorkCaptureDigest, StoredPendingPipeline,
    },
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};

use crate::core::ScyllaCoreStore;
use crate::tables::{
    object::ScyllaGenericKeyIdValueTablePreparedStatements,
    u64_table::ScyllaU64ToU64TablePreparedStatements,
};

use super::{
    AuthorityLocalHeadNoTabletKeyspace, BranchExactBackfillPlan,
    BranchExactBackfillReadbackObservation, BranchExactDeploymentIntent,
    BranchExactDeploymentLifecycleBootstrap,
    BranchExactDeploymentLifecycleReadState,
    BranchExactDeploymentLifecycleState, BranchExactDeploymentNoTabletKeyspace,
    BranchExactExpectedTopology, BranchExactNodeSchemaPostflight,
    BranchExactSchemaInspection, BranchExactSchemaMaterializationRequest,
    BranchExactSchemaMaterializer, BranchExactSchemaSetupMode,
    BranchExactSchemaSetupRequest, BranchExactScyllaNodeId,
    BranchExactScyllaSchemaVersion, BranchExactTopologyAttestation,
    BranchExactVerifiedDeploymentReceipt, CqlKeyspaceName,
    PendingQueueSidecarKeyspaces, PendingQueueSidecarSchemaMaterializer,
    ScyllaAuthorityLocalHeadStore, ScyllaBranchExactDeploymentLifecycleStore,
    ScyllaRealmRollbackRuntimeControl, SealedBranchExactBackfillPlanCas,
    SealedBranchExactBackfillVerifiedCas, SealedBranchExactSchemaVerifiedCas,
};

const COORDINATOR_KEYSPACE: &str = "psy_rollback_joint_control";
const REALM_10_KEYSPACE: &str = "psy_rollback_joint_control_realm_10";
const REALM_20_KEYSPACE: &str = "psy_rollback_joint_control_realm_20";
const NODE: &str = "172.29.86.11:9042";

#[derive(Clone, Copy)]
struct RealmRollbackTestNetwork;

impl QNetworkTreeConstants for RealmRollbackTestNetwork {
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

impl QNetworkHashTypes for RealmRollbackTestNetwork {
    type QHash = PHash;
    type HasherBase = PoseidonHasher;
    type F = PF;
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1).expect("test network")
}

fn hash(seed: u8) -> PHash {
    let seed = u64::from(seed);
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn chain(checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(0),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn realm_chain(checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        // One explicit rollback request is epoch-scoped across Coordinator and
        // all Realm participants. Individual Realm state roots may differ,
        // but their committed history must belong to the selected epoch.
        ChainEpoch::new(0),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn realm_observation(
    authority: AuthorityScope,
    checkpoint: u64,
    seed: u8,
) -> anyhow::Result<AuthorityObservation<PHash>> {
    Ok(AuthorityObservation::try_new(
        realm_chain(checkpoint, seed),
        authority,
        AuthorityStateCheckpointId::new(checkpoint),
        AuthorityStateRoot::from_local_state_root(hash(seed.wrapping_add(0x20))),
    )?)
}

fn realm_commit_models(
    authority: AuthorityScope,
    checkpoint: u64,
    pending: u64,
    timestamp: i64,
    seed: u8,
) -> anyhow::Result<(
    BranchExactDualWriteIntent<PHash>,
    CommitWriteTimestampUs,
    psy_node_core::store::authority_local_head::StoredAuthorityLocalHead<PHash>,
    StoredPendingPipeline<PHash>,
    AuthorityLocalHeadBootstrap<PHash>,
)> {
    let predecessor = BranchPendingMapping::new(
        realm_chain(checkpoint - 1, seed.wrapping_sub(1)),
        UniquePendingId::try_new(pending - 1)?,
    );
    let candidate = BranchPendingMapping::new(
        realm_chain(checkpoint, seed),
        UniquePendingId::try_new(pending)?,
    );
    let intent = BranchExactDualWriteIntent::try_realm(
        authority,
        predecessor,
        candidate,
        ProcCheckpointUniqueId::from_u128(10_000 + u128::from(pending)),
        &TagTreeMerkleProof::<PHash>::new_empty(),
    )?;
    let timestamp = CommitWriteTimestampUs::try_from_i128(timestamp as i128)?;
    let observation = realm_observation(authority, checkpoint, seed)?;
    let head_bootstrap = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        AuthorityHeadView::try_from_observed(
            AuthorityTimestampKey::new(network(), authority),
            *observation.chain(),
            observation.state_checkpoint_id(),
            *observation.state_root(),
        )?,
        timestamp,
        AuthorityManifestDigest::from_persisted([seed.max(1); 32]),
        AuthorityStorageBindingRef::new(
            AuthorityStorageBindingGeneration::try_new(1)?,
            AuthorityStorageNamespaceId::from_verified_namespace_id([0xB1; 32]),
        ),
    );
    let head = head_bootstrap.candidate().clone();

    let key = PendingGenerationLedgerKey::new(network(), authority);
    let prefix = ProcNamespacePrefix::for_authority(network(), authority);
    let context = |value: u64| {
        PendingGenerationContext::try_from_legacy(
            value,
            (prefix.get() as u128) << 64 | u128::from(value),
        )
    };
    let bootstrap = PendingPipelineBootstrap::try_new(
        key,
        PendingGenerationActivationDigest::try_new([0xA5; 32])?,
        prefix,
        PendingGenerationBootstrapReason::LegacyActivation,
        context(pending - 1)?,
        context(pending)?,
        realm_observation(authority, checkpoint - 1, seed.wrapping_sub(1))?,
        pending - 1,
    )?;
    let ready = bootstrap
        .candidate()
        .seal_rotation(ReservedPendingGeneration::qualification_from_prefix(
            pending + 1,
            prefix,
        )?)?
        .candidate()
        .clone();
    let close = PendingQueueCloseIntentDigest::try_new([seed.wrapping_add(1); 32])?;
    let capture = PendingWorkCaptureDigest::try_new([seed.wrapping_add(2); 32])?;
    let processing = PendingPipelineIntentDigest::try_new([seed.wrapping_add(3); 32])?;
    let sealing = ready.seal_begin_queue_close(close)?.candidate().clone();
    let captured = sealing.seal_capture_work(close, capture)?.candidate().clone();
    let inflight = captured
        .seal_begin_processing(capture, processing)?
        .candidate()
        .clone();
    let pipeline = inflight
        .seal_publish(
            processing,
            PendingPublishReceiptDigest::try_new([seed.wrapping_add(4); 32])?,
            observation,
        )?
        .candidate()
        .clone();
    Ok((intent, timestamp, head, pipeline, head_bootstrap))
}

fn routing_key(table_id: u64) -> QDatabaseTableRoutingKey {
    QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(
        table_id,
        0,
    )
}

async fn establish_coordinator_floor_tables(
    store: &ScyllaCoreStore<PHash, PoseidonHasher>,
) -> anyhow::Result<()> {
    store
        .init_std_table::<ScyllaGenericKeyIdValueTablePreparedStatements>(
            "l2_block_state_table",
            routing_key(4),
        )
        .await?;
    store
        .init_std_table::<ScyllaGenericKeyIdValueTablePreparedStatements>(
            "latest_info_table",
            routing_key(6),
        )
        .await?;
    store
        .init_std_table::<ScyllaU64ToU64TablePreparedStatements>(
            "u64_singleton_table",
            routing_key(11),
        )
        .await?;
    Ok(())
}

async fn establish_realm_branch_ready(
    store: &ScyllaCoreStore<PHash, PoseidonHasher>,
    authority: AuthorityScope,
) -> anyhow::Result<()> {
    // The physical archive reader prepares the complete Realm table catalog,
    // just as a production node does.  Build that existing production schema
    // rather than a reduced test-only subset; only the narrow rows seeded
    // below become part of this qualification fixture's committed inventory.
    crate::psy_setup::setup_psy_scylla_database_store::<RealmRollbackTestNetwork>(
        Arc::new(store.clone()),
    )
    .await?;

    let bootstrap = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        chain(0, 0xA0),
    )?;
    let plan = BranchExactSchemaMaterializationPlan::try_new(
        &bootstrap,
        authority,
        None,
    )?;
    let request = BranchExactSchemaMaterializationRequest::try_new(
        CqlKeyspaceName::try_new(store.keyspace.clone())?,
        plan,
    )?;
    let schema = BranchExactSchemaMaterializer::materialize_schema(
        &store.session,
        &request,
    )
    .await?;
    let nodes = [1_u8, 2, 3]
        .map(|seed| BranchExactScyllaNodeId::try_new([seed; 16]))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let topology = BranchExactExpectedTopology::try_new(nodes)?;
    let observations = topology
        .nodes()
        .iter()
        .map(|node| {
            BranchExactNodeSchemaPostflight::try_new(
                *node,
                BranchExactScyllaSchemaVersion::try_new([1; 16])?,
                BranchExactSchemaInspection::Exact {
                    fingerprint: schema.schema_fingerprint(),
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let intent = BranchExactDeploymentIntent::new(&request, topology.clone());
    let attestation = BranchExactTopologyAttestation::try_new(
        &schema,
        topology,
        observations,
    )?;
    let deployment = BranchExactVerifiedDeploymentReceipt::try_new(
        intent.clone(),
        attestation,
    )?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(
        store.no_tablet_keyspace.clone(),
    )?;
    ScyllaBranchExactDeploymentLifecycleStore::create_schema(
        &store.session,
        &control,
    )
    .await?;
    let lifecycle = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        store.session.clone(),
        control,
    )
    .await?;
    let lifecycle_bootstrap = BranchExactDeploymentLifecycleBootstrap::new(intent);
    lifecycle.bootstrap(&lifecycle_bootstrap).await?;
    let schema_verified = SealedBranchExactSchemaVerifiedCas::try_new(
        lifecycle_bootstrap.candidate(),
        deployment.clone(),
    )?;
    lifecycle.mark_schema_verified(&schema_verified).await?;
    let backfill = BranchExactBackfillPlan::genesis_empty(&request, deployment)?;
    let planned = SealedBranchExactBackfillPlanCas::try_new(
        schema_verified.candidate(),
        backfill.clone(),
    )?;
    lifecycle.plan_backfill(&planned).await?;
    let verified = SealedBranchExactBackfillVerifiedCas::try_new(
        planned.candidate(),
        BranchExactBackfillReadbackObservation::new(
            backfill.digest(),
            backfill.dataset_digest(),
            0,
            0,
            0,
        ),
    )?;
    lifecycle.mark_backfill_verified(&verified).await?;
    let BranchExactDeploymentLifecycleReadState::Current(current) =
        lifecycle.read(verified.slot()).await?
    else {
        bail!("Realm branch-exact lifecycle disappeared")
    };
    let BranchExactDeploymentLifecycleState::BackfillVerified(receipt) =
        current.state()
    else {
        bail!("Realm branch-exact lifecycle did not reach BACKFILL_VERIFIED")
    };
    store
        .initialize_branch_exact_schema_setup(
            authority,
            BranchExactSchemaSetupMode::RequireVerified(
                BranchExactSchemaSetupRequest::new(receipt.clone()),
            ),
        )
        .await?;

    PendingQueueSidecarSchemaMaterializer::materialize_schema(
        &store.session,
        &PendingQueueSidecarKeyspaces::try_new(
            store.keyspace.clone(),
            store.no_tablet_keyspace.clone(),
        )?,
    )
    .await?;
    ScyllaAuthorityLocalHeadStore::create_schema(
        &store.session,
        &AuthorityLocalHeadNoTabletKeyspace::try_new(
            store.no_tablet_keyspace.clone(),
        )?,
    )
    .await?;
    Ok(())
}

async fn realm_control(
    keyspace: &str,
    realm_id: u32,
) -> anyhow::Result<ScyllaRealmRollbackRuntimeControl> {
    let store = ScyllaCoreStore::<PHash, PoseidonHasher>::new(
        u64::from(realm_id),
        0,
        keyspace.to_owned(),
        &[NODE.to_owned()],
    )
    .await?;
    let authority = AuthorityScope::Realm {
        realm_id,
        realm_sub_id: 0,
    };
    establish_realm_branch_ready(&store, authority).await?;
    store
        .prepare_realm_rollback_runtime_control(COORDINATOR_KEYSPACE)
        .await
}

#[tokio::test]
#[ignore = "runs against the isolated single-node Scylla rollback fixture"]
async fn explicit_admin_request_is_selected_by_every_production_realm_control(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_ROLLBACK_JOINT_SINGLE").as_deref() == Ok("1"),
        "run through tests/rf3/run-rollback-joint-single.sh"
    );

    let coordinator = Arc::new(
        ScyllaCoreStore::<PHash, PoseidonHasher>::new(
            0,
            0,
            COORDINATOR_KEYSPACE.to_owned(),
            &[NODE.to_owned()],
        )
        .await?,
    );
    establish_coordinator_floor_tables(&coordinator).await?;
    coordinator
        .initialize_coordinator_canonical_head(true)
        .await?;
    coordinator
        .initialize_coordinator_rollback_admission(true)
        .await?;
    let old_head = chain(3, 0xA3);
    coordinator
        .bootstrap_canonical_head(&CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            old_head,
        )?)
        .await?;

    let realms = vec![
        RollbackRealmParticipant::new(10, 0),
        RollbackRealmParticipant::new(20, 0),
    ];
    let topology = RollbackTopologySnapshot::try_new(
        network(),
        0,
        realms,
    )?;
    coordinator
        .install_coordinator_rollback_topology(&topology)
        .await?;
    let boundary = CoordinatorRollbackAdmissionBoundary::new(
        network(),
        coordinator.clone(),
        coordinator.clone(),
    );
    boundary.ensure_slot_initialized().await?;
    let inbox = CoordinatorRollbackAdminInbox::new(
        network(),
        RollbackAdminInboxAccess::ManualPreflight,
        coordinator.clone(),
        coordinator.clone(),
    )
    .with_participant_plan_store(coordinator.clone());
    let receipt = inbox
        .start_planned(RollbackAdminPlannedStartIntent::new(
            psy_node_core::store::canonical_head::CanonicalHeadRevision::try_new(0)?,
            old_head,
            *chain(1, 0xA1).checkpoint(),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(100)?,
                200,
                300,
            )?,
            topology.revision(),
            *topology.digest(),
        ))
        .await?;
    ensure!(
        receipt.disposition() == RollbackAdminStartDisposition::Accepted,
        "explicit request must enter the durable inbox"
    );
    let RollbackAdmissionBoundaryOutcome::Maintenance(requested) =
        boundary.reconcile_at_loop_boundary().await?
    else {
        bail!("Processor boundary must promote the request into maintenance")
    };
    ensure!(requested.rollback_control().requested().is_some());

    let realm_10 = realm_control(REALM_10_KEYSPACE, 10).await?;
    let realm_20 = realm_control(REALM_20_KEYSPACE, 20).await?;
    for (control, authority) in [
        (&realm_10, AuthorityScope::Realm { realm_id: 10, realm_sub_id: 0 }),
        (&realm_20, AuthorityScope::Realm { realm_id: 20, realm_sub_id: 0 }),
    ] {
        let RealmRollbackParticipantProgress::AwaitingCoordinator(observed) = control
            .progress_realm_rollback_participant(network(), authority)
            .await?
        else {
            bail!("REQUESTED Realm must wait for Coordinator ARCHIVING")
        };
        ensure!(observed == requested, "Realm selected a different durable head");
    }
    ensure!(
        <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<PHash>>::
            progress_realm_rollback_participant(
                &realm_10,
                network(),
                AuthorityScope::Realm { realm_id: 99, realm_sub_id: 0 },
            )
            .await
            .is_err(),
        "a Realm absent from the immutable topology must fail closed"
    );

    ensure!(matches!(
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
            PF,
            PHash,
        >>::progress_coordinator_rollback(&coordinator, network(), 32)
        .await?,
        CoordinatorRollbackGlobalProgress::Progressed(current) if current == requested
    ));

    // The archive preparer durably advances the shared control row before it
    // selects any participant data. With no committed Realm inventory in this
    // control-only fixture, both production Realm controls must enter the
    // archive path and fail closed instead of publishing a completion.
    ensure!(
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
            PF,
            PHash,
        >>::prepare_coordinator_archive(&coordinator, network(), 32)
        .await
        .is_err(),
        "control-only fixture must not fabricate Coordinator archive readiness"
    );
    let CanonicalHeadReadState::Current(archiving) = coordinator
        .read_canonical_head(network())
        .await?
    else {
        bail!("Coordinator canonical head disappeared after archive transition")
    };
    ensure!(
        matches!(archiving.rollback_control(), RollbackControlState::Archiving(_)),
        "archive preparation must durably enter ARCHIVING before selecting data"
    );
    ensure!(
        !matches!(
            <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
                PF,
                PHash,
            >>::prepare_coordinator_archive(&coordinator, network(), 32)
            .await,
            Ok(CoordinatorRollbackMaintenanceOutcome::ArchivePrepared(_))
        ),
        "retry without committed sources must not fabricate archive readiness"
    );
    for (control, authority) in [
        (&realm_10, AuthorityScope::Realm { realm_id: 10, realm_sub_id: 0 }),
        (&realm_20, AuthorityScope::Realm { realm_id: 20, realm_sub_id: 0 }),
    ] {
        ensure!(
            <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
                PHash,
            >>::progress_realm_rollback_participant(
                control, network(), authority,
            )
            .await
            .is_err(),
            "ARCHIVING Realm without committed inventory must fail closed"
        );
    }

    // Seed only Realm 10 with a small canonical committed history. The setup
    // is qualification-only, but the archive selection, physical reads,
    // immutable writes, exact second pass, completion, and restart recovery
    // below all use the production runtime control.
    let realm_10_authority = AuthorityScope::Realm {
        realm_id: 10,
        realm_sub_id: 0,
    };
    let mut commits = Vec::new();
    let mut source_bootstrap = None;
    for checkpoint in 1_u64..=3 {
        let (intent, timestamp, head, pipeline, bootstrap) = realm_commit_models(
            realm_10_authority,
            checkpoint,
            100 + checkpoint,
            1_000 + checkpoint as i64,
            0xC0 + checkpoint as u8,
        )?;
        commits.push((intent, timestamp, head, pipeline));
        if checkpoint == 3 {
            source_bootstrap = Some(bootstrap);
        }
    }
    realm_10
        .qualification_seed_narrow_commit_history(
            commits,
            source_bootstrap
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("source bootstrap missing"))?,
        )
        .await?;
    let RealmRollbackParticipantProgress::ArchivePrepared {
        entry_count,
        ..
    } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
        PHash,
    >>::progress_realm_rollback_participant(
        &realm_10, network(), realm_10_authority,
    )
    .await?
    else {
        bail!("Realm 10 did not publish an exact archive completion")
    };
    ensure!(entry_count > 0, "Realm archive must contain physical rows");
    let RealmRollbackParticipantProgress::ArchivePrepared {
        entry_count: recovered_count,
        ..
    } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
        PHash,
    >>::progress_realm_rollback_participant(
        &realm_10, network(), realm_10_authority,
    )
    .await?
    else {
        bail!("Realm 10 archive completion did not recover after reopen")
    };
    ensure!(
        recovered_count == entry_count,
        "recovered Realm archive selected a different physical dataset"
    );
    ensure!(
        <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::progress_realm_rollback_participant(
            &realm_20,
            network(),
            AuthorityScope::Realm { realm_id: 20, realm_sub_id: 0 },
        )
        .await
        .is_err(),
        "unseeded Realm must remain fail closed after another Realm completes"
    );
    Ok(())
}
