//! Single-node production-store composition test for the delete-only rollback
//! control plane. It covers durable request selection plus one Realm's exact
//! physical archive and recovery. Physical deletion remains a later slice.

use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use parth_core::{
    crypto::hash::{
        merkle_proof::DeltaMerkleProofCore,
        tag_tree::TagTreeMerkleProof,
        traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
    },
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants},
    PHash, PF,
};
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId, checkpoint_hash_from_previous,
    },
    chain_context::AuthorityScope,
    chain_context::{
        AuthorityObservation, AuthorityStateCheckpointId, AuthorityStateRoot,
    },
};
use psy_data::{
    prepared_block::{
        common::PsyCoordinatorPendingCheckpointBase,
        coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    },
    v1::qdata::{
        checkpoint::{
            PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats,
            QEDL2BlockState,
        },
        populated_checkpoint::PsyCheckpointLeafPopulated,
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
        CanonicalHeadReadState, CanonicalHeadTransition,
        CoordinatorCanonicalHeadReader, CoordinatorCanonicalHeadStore,
    },
    coordinator_commit_source::{
        CoordinatorCommitSource, CoordinatorCommitSourcePayload,
        CoordinatorCommitSourceStore,
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
use psy_serialize::PsyIOReadWrite;
use scylla::statement::Consistency;

use crate::core::ScyllaCoreStore;
use super::{
    AuthorityLocalHeadNoTabletKeyspace, AuthorityTimestampNoTabletKeyspace,
    BranchExactBackfillPlan,
    BranchExactBackfillReadbackObservation, BranchExactDeploymentIntent,
    BranchExactDeploymentLifecycleBootstrap,
    BranchExactDeploymentLifecycleReadState,
    BranchExactDeploymentLifecycleState, BranchExactDeploymentNoTabletKeyspace,
    BranchExactExpectedTopology, BranchExactNodeSchemaPostflight,
    BranchExactSchemaInspection, BranchExactSchemaMaterializationRequest,
    BranchExactSchemaMaterializer, BranchExactSchemaSetupMode,
    BranchExactSchemaSetupRequest, BranchExactScyllaNodeId,
    BranchExactScyllaSchemaVersion, BranchExactTopologyAttestation,
    BranchExactVerifiedDeploymentReceipt, BranchExactCutoverPhase,
    BranchExactWriterCutoverFence, BranchExactWriterPrepared, CqlKeyspaceName,
    PendingQueueSidecarKeyspaces, PendingQueueSidecarSchemaMaterializer,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaBranchExactDeploymentLifecycleStore,
    ScyllaBranchExactWriterLifecycleStore,
    ScyllaRealmRollbackRuntimeControl, SealedBranchExactBackfillPlanCas,
    SealedBranchExactBackfillVerifiedCas, SealedBranchExactSchemaVerifiedCas,
};
use super::branch_exact_dual_write_executor::ScyllaBranchExactDualWriteAdapter;
use super::coordinator_commit_physical_execution::CoordinatorCommitPhysicalExecutionSchedule;
use super::coordinator_commit_physical_scylla::CoordinatorCommitPhysicalScyllaExecutor;
use super::coordinator_commit_physical_write_plan::CoordinatorCommitPhysicalWritePlan;

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

fn coordinator_leaf(seed: u8) -> PsyCheckpointLeafPopulated<PF, PHash> {
    PsyCheckpointLeafPopulated {
        global_state_roots: PQEDCheckpointGlobalStateRoots {
            contract_tree_root: hash(seed),
            deposit_tree_root: PHash::get_zero_value(),
            user_tree_root: PHash::get_zero_value(),
            withdrawal_tree_root: PHash::get_zero_value(),
            user_registration_tree_root: PHash::get_zero_value(),
        },
        stats: PQEDCheckpointLeafStats::get_empty_stats(),
    }
}

fn coordinator_block_state(checkpoint: u64) -> QEDL2BlockState {
    QEDL2BlockState {
        checkpoint_id: checkpoint,
        next_add_withdrawal_id: 11 + checkpoint,
        next_process_withdrawal_id: 21 + checkpoint,
        next_deposit_id: 31 + checkpoint,
        total_deposits_claimed_epoch: 41 + checkpoint,
        next_user_id: 51 + checkpoint,
        end_balance: 61 + checkpoint,
        next_contract_id: 71 + checkpoint as u32,
    }
}

fn coordinator_commit_source(
    expected: psy_node_core::store::canonical_head::StoredCanonicalHead<PHash>,
    checkpoint: u64,
    pending: u64,
    seed: u8,
) -> anyhow::Result<(CoordinatorCommitSource<PHash>, BranchExactWriterPrepared<PHash>)> {
    let old_leaf = coordinator_leaf(seed.wrapping_sub(1));
    let new_leaf = coordinator_leaf(seed);
    let old_leaf_hash = old_leaf.qfhash::<PoseidonHasher>();
    let new_leaf_hash = new_leaf.qfhash::<PoseidonHasher>();
    let proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(
        checkpoint,
        old_leaf_hash,
        new_leaf_hash,
        (0..RealmRollbackTestNetwork::CHECKPOINT_TREE_HEIGHT_USIZE)
            .map(PoseidonHasher::get_zero_hash)
            .collect(),
    );
    let prepared = PsyPreparedCoordinatorBlockStateUpdates {
        coordinator_id: 0,
        checkpoint_id: checkpoint,
        unique_pending_id: pending,
        proc_checkpoint_unique_id: 20_000 + u128::from(pending),
        old_base: PsyCoordinatorPendingCheckpointBase {
            block_state: coordinator_block_state(checkpoint - 1),
            checkpoint_leaf: old_leaf,
            checkpoint_leaf_hash: old_leaf_hash,
            checkpoint_tree_root: proof.old_root,
        },
        new_base: PsyCoordinatorPendingCheckpointBase {
            block_state: coordinator_block_state(checkpoint),
            checkpoint_leaf: new_leaf,
            checkpoint_leaf_hash: new_leaf_hash,
            checkpoint_tree_root: proof.new_root,
        },
        update_global_contract_tree_nodes_ffs: Vec::new(),
        update_contract_function_tree_nodes_ffs: Vec::new(),
        new_contract_leaves_ffs: Vec::new(),
        new_contract_code_definitions: Vec::new(),
        update_user_registration_tree_nodes_ffs: Vec::new(),
        new_user_public_keys_ffs: Vec::new(),
        new_public_key_hash_to_user_id_rows_ffs: Vec::new(),
        update_global_user_tree_nodes_ffs: Vec::new(),
        new_realm_guta_reward_tree_node_keys_ffs: Vec::new(),
        checkpoint_tree_update_proof: proof,
    };
    // A Coordinator candidate is committed to the prepared checkpoint-tree
    // transition.  Derive the chain hash from that exact payload instead of
    // inventing a fixture hash: the production physical planner independently
    // recomputes this value and rejects any mismatch.
    let candidate_hash = checkpoint_hash_from_previous::<_, PoseidonHasher>(
        *expected.canonical_ref().checkpoint().checkpoint_hash(),
        prepared.new_base.checkpoint_tree_root,
        prepared.new_base.checkpoint_leaf_hash,
        hash(0xE2),
    )
    .into_inner();
    let candidate = CanonicalChainRef::new(
        expected.canonical_ref().network_id(),
        expected.canonical_ref().chain_epoch(),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(candidate_hash),
        ),
    );
    let mut prepared_bytes = Vec::new();
    prepared.pio_write_to_io(&mut prepared_bytes)?;
    let source = CoordinatorCommitSource::try_new(
        expected,
        candidate,
        CoordinatorCommitSourcePayload::try_new(
            prepared_bytes,
            17,
            vec![seed.max(1); 64],
        )?
        .encode_canonical(),
    )?;
    let intent = BranchExactDualWriteIntent::try_coordinator(
        BranchPendingMapping::new(*source.expected(), UniquePendingId::try_new(pending - 1)?),
        BranchPendingMapping::new(*source.candidate(), UniquePendingId::try_new(pending)?),
        ProcCheckpointUniqueId::from_u128(20_000 + u128::from(pending)),
    )?;
    let mut fence_bytes = [0_u8; 81];
    fence_bytes[..8].copy_from_slice(&9_u64.to_be_bytes());
    fence_bytes[8..16].copy_from_slice(&3_u64.to_be_bytes());
    fence_bytes[16..48].fill(0x44);
    fence_bytes[48..80].fill(0x55);
    fence_bytes[80] = BranchExactCutoverPhase::LegacyPrimaryDualWrite as u8;
    let fence = BranchExactWriterCutoverFence::decode_canonical(&fence_bytes)?;
    let narrow = BranchExactWriterPrepared::test_fixture(
        intent,
        CommitWriteTimestampUs::try_from_i128(10_000 + i128::from(checkpoint))?,
        fence,
    );
    Ok((source, narrow))
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

async fn establish_branch_ready(
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
    ScyllaBranchExactWriterLifecycleStore::create_schema(
        &store.session,
        &BranchExactDeploymentNoTabletKeyspace::try_new(
            store.no_tablet_keyspace.clone(),
        )?,
    )
    .await?;
    ScyllaAuthorityTimestampStore::create_schema(
        &store.session,
        &AuthorityTimestampNoTabletKeyspace::try_new(
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

async fn qualification_seed_coordinator_commit(
    store: &ScyllaCoreStore<PHash, PoseidonHasher>,
    source: &CoordinatorCommitSource<PHash>,
    narrow: &BranchExactWriterPrepared<PHash>,
) -> anyhow::Result<()> {
    store.persist_coordinator_commit_source(source).await?;
    let ready = store.require_branch_exact_schema_ready()?;
    let narrow_writer = ScyllaBranchExactDualWriteAdapter::prepare(
        store.session.clone(),
        ready,
    )
    .await?;
    narrow_writer
        .qualification_write_inventory_exact(narrow.intent(), narrow.timestamp())
        .await?;
    let plan = CoordinatorCommitPhysicalWritePlan::try_new::<PF, PoseidonHasher>(
        source,
        narrow,
        hash(0xE1),
        hash(0xE2),
        RealmRollbackTestNetwork::CHECKPOINT_TREE_HEIGHT,
    )?;
    let schedule = CoordinatorCommitPhysicalExecutionSchedule::try_from_plan(
        &plan,
        narrow,
    )?;
    CoordinatorCommitPhysicalScyllaExecutor::prepare_with_consistency(
        &store.session,
        CqlKeyspaceName::try_new(store.keyspace.clone())?,
        Consistency::Quorum,
    )
    .await?
    .write_and_verify(&store.session, &schedule)
    .await?;
    store
        .mark_coordinator_commit_source_committed(source)
        .await?;
    Ok(())
}

async fn qualification_seed_coordinator_history(
    store: &ScyllaCoreStore<PHash, PoseidonHasher>,
) -> anyhow::Result<(
    psy_node_core::store::canonical_head::StoredCanonicalHead<PHash>,
    CanonicalChainRef<PHash>,
)> {
    let floor_predecessor = *CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        chain(0, 0xA0),
    )?
    .candidate();
    let (target_source, target_narrow) =
        coordinator_commit_source(floor_predecessor, 1, 101, 0xA1)?;
    let target = *target_source.candidate();
    let target_bootstrap = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::PostGenesisFloor,
        target,
    )?;
    let target_head = *target_bootstrap.candidate();
    store.bootstrap_canonical_head(&target_bootstrap).await?;

    qualification_seed_coordinator_commit(store, &target_source, &target_narrow)
        .await?;
    store.ensure_coordinator_rollback_floor(&target_head).await?;

    let mut current = target_head;
    for (checkpoint, pending, seed) in [(2_u64, 102_u64, 0xA2_u8), (3, 103, 0xA3)] {
        let (source, narrow) =
            coordinator_commit_source(current, checkpoint, pending, seed)?;
        let candidate = *source.candidate();
        qualification_seed_coordinator_commit(store, &source, &narrow).await?;
        let sealed = CanonicalHeadTransition::normal_checkpoint_advance(
            current,
            candidate,
        )?
        .seal();
        let outcome = store.compare_and_set_canonical_head(&sealed).await?;
        current = *outcome.current();
        ensure!(
            current == *sealed.candidate(),
            "qualification Coordinator head did not advance to its committed source",
        );
    }
    Ok((current, target))
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
    establish_branch_ready(&store, authority).await?;
    store
        .prepare_realm_rollback_runtime_control(COORDINATOR_KEYSPACE)
        .await
}

async fn qualification_seed_realm_history(
    control: &ScyllaRealmRollbackRuntimeControl,
    authority: AuthorityScope,
    pending_base: u64,
    seed_base: u8,
) -> anyhow::Result<()> {
    let mut commits = Vec::new();
    let mut source_bootstrap = None;
    for checkpoint in 1_u64..=3 {
        let (intent, timestamp, head, pipeline, bootstrap) = realm_commit_models(
            authority,
            checkpoint,
            pending_base + checkpoint,
            1_000 + checkpoint as i64,
            seed_base.wrapping_add(checkpoint as u8),
        )?;
        commits.push((intent, timestamp, head, pipeline));
        if checkpoint == 3 {
            source_bootstrap = Some(bootstrap);
        }
    }
    control
        .qualification_seed_narrow_commit_history(
            commits,
            source_bootstrap
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("source bootstrap missing"))?,
        )
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
    establish_branch_ready(&coordinator, AuthorityScope::Coordinator).await?;
    coordinator
        .initialize_coordinator_canonical_head(true)
        .await?;
    coordinator
        .initialize_coordinator_rollback_admission(true)
        .await?;
    let (committed_head, target) =
        qualification_seed_coordinator_history(&coordinator).await?;
    let old_head = *committed_head.canonical_ref();

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
            committed_head.revision(),
            old_head,
            *target.checkpoint(),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(11_000)?,
                12_000,
                13_000,
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

    // The Coordinator uses its production archive owner over three exact
    // qualification commits. This also durably advances the shared control
    // row before either Realm may publish its own completion.
    let CoordinatorRollbackMaintenanceOutcome::ArchivePrepared(coordinator_archive) =
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
            PF,
            PHash,
        >>::prepare_coordinator_archive(&coordinator, network(), 32)
        .await?
    else {
        bail!("Coordinator did not publish exact archive readiness")
    };
    ensure!(
        coordinator_archive.entry_count() > 0,
        "Coordinator archive must contain physical rows",
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
    let CoordinatorRollbackMaintenanceOutcome::ArchivePrepared(recovered_coordinator_archive) =
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
            PF,
            PHash,
        >>::prepare_coordinator_archive(&coordinator, network(), 32)
        .await?
    else {
        bail!("Coordinator archive readiness did not recover after reopen")
    };
    ensure!(
        recovered_coordinator_archive == coordinator_archive,
        "Coordinator archive retry selected different evidence",
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

    // Seed both planned Realms with small canonical committed histories. The
    // setup is qualification-only, but selection, physical reads, immutable
    // archive writes, exact second pass, completion, and recovery all use the
    // production runtime control.
    let realm_10_authority = AuthorityScope::Realm {
        realm_id: 10,
        realm_sub_id: 0,
    };
    let realm_20_authority = AuthorityScope::Realm {
        realm_id: 20,
        realm_sub_id: 0,
    };
    qualification_seed_realm_history(&realm_10, realm_10_authority, 1, 0xC0)
        .await?;
    qualification_seed_realm_history(&realm_20, realm_20_authority, 1, 0xD0)
        .await?;
    for (control, authority) in [
        (&realm_10, realm_10_authority),
        (&realm_20, realm_20_authority),
    ] {
        let RealmRollbackParticipantProgress::ArchivePrepared {
            entry_count,
            ..
        } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::progress_realm_rollback_participant(control, network(), authority)
        .await
        .with_context(|| format!("first archive progress for {authority:?}"))?
        else {
            bail!("planned Realm did not publish an exact archive completion")
        };
        ensure!(entry_count > 0, "Realm archive must contain physical rows");
        let RealmRollbackParticipantProgress::ArchivePrepared {
            entry_count: recovered_count,
            ..
        } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::progress_realm_rollback_participant(control, network(), authority)
        .await
        .with_context(|| format!("archive recovery progress for {authority:?}"))?
        else {
            bail!("Realm archive completion did not recover after reopen")
        };
        ensure!(
            recovered_count == entry_count,
            "recovered Realm archive selected a different physical dataset",
        );
    }

    let CoordinatorRollbackGlobalProgress::AwaitingParticipants {
        head: deleting_head,
        completed,
        expected,
    } = <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
        PF,
        PHash,
    >>::progress_coordinator_rollback(&coordinator, network(), 32)
    .await
    .context("Coordinator global archive barrier/delete progress")?
    else {
        bail!("Coordinator did not cross the all-participant archive barrier")
    };
    ensure!(
        matches!(deleting_head.rollback_control(), RollbackControlState::Deleting(_)),
        "global archive barrier did not enter DELETING",
    );
    ensure!(
        completed == 1 && expected == 3,
        "only the Coordinator delete may be complete before Realm execution",
    );

    for (control, authority) in [
        (&realm_10, realm_10_authority),
        (&realm_20, realm_20_authority),
    ] {
        let RealmRollbackParticipantProgress::DeletePrepared {
            physical_delete_count,
            restored_row_count,
            ..
        } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::progress_realm_rollback_participant(control, network(), authority)
        .await
        .with_context(|| format!("Realm delete progress for {authority:?}"))?
        else {
            bail!("planned Realm did not execute its production delete")
        };
        ensure!(
            physical_delete_count > 0,
            "Realm delete must remove its archived suffix rows",
        );
        let RealmRollbackParticipantProgress::DeletePrepared {
            physical_delete_count: recovered_delete_count,
            restored_row_count: recovered_restore_count,
            ..
        } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::progress_realm_rollback_participant(control, network(), authority)
        .await
        .with_context(|| format!("Realm delete retry for {authority:?}"))?
        else {
            bail!("Realm delete completion did not recover after retry")
        };
        ensure!(
            recovered_delete_count == physical_delete_count
                && recovered_restore_count == restored_row_count,
            "Realm delete retry selected different physical work",
        );
    }

    let CoordinatorRollbackGlobalProgress::Progressed(restoring_head) =
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
            PF,
            PHash,
        >>::progress_coordinator_rollback(&coordinator, network(), 32)
        .await
        .context("Coordinator global delete barrier progress")?
    else {
        bail!("Coordinator did not cross the all-participant delete barrier")
    };
    ensure!(
        matches!(restoring_head.rollback_control(), RollbackControlState::Restoring(_)),
        "all-participant delete barrier did not enter RESTORING",
    );

    for (control, authority) in [
        (&realm_10, realm_10_authority),
        (&realm_20, realm_20_authority),
    ] {
        let RealmRollbackParticipantProgress::RestorePrepared {
            final_rows_digest,
            ..
        } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::progress_realm_rollback_participant(control, network(), authority)
        .await
        .with_context(|| format!("Realm target restore for {authority:?}"))?
        else {
            bail!("planned Realm did not restore its selected target")
        };
        let RealmRollbackParticipantProgress::RestorePrepared {
            final_rows_digest: recovered_digest,
            ..
        } = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::progress_realm_rollback_participant(control, network(), authority)
        .await
        .with_context(|| format!("Realm target restore retry for {authority:?}"))?
        else {
            bail!("Realm target restore completion did not recover after retry")
        };
        ensure!(
            recovered_digest == final_rows_digest,
            "Realm target restore retry selected different final rows",
        );
    }

    let CoordinatorRollbackGlobalProgress::Progressed(verifying_head) =
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
            PF,
            PHash,
        >>::progress_coordinator_rollback(&coordinator, network(), 32)
        .await
        .context("Coordinator global restore barrier progress")?
    else {
        bail!("Coordinator did not cross the all-participant restore barrier")
    };
    ensure!(
        matches!(verifying_head.rollback_control(), RollbackControlState::Verifying(_)),
        "all-participant restore barrier did not enter VERIFYING",
    );
    Ok(())
}
