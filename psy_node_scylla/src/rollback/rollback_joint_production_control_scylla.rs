//! Production-store composition test for the delete-only rollback control
//! plane. The same flow runs against an isolated RF=1 or pre-provisioned RF=3
//! fixture.

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
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampKey, AuthorityTimestampReadState,
    },
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
        CoordinatorRollbackRuntimePublication,
        CoordinatorRollbackRuntimeRebuildStore, RealmRollbackParticipantProgress,
        RealmRollbackRuntimeControl, RollbackRuntimeRebuildDirective,
        RollbackRuntimeRebuildReport,
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
    PendingCounterAdapter, PendingCounterAllocationOutcome, PendingCounterExpected,
    PendingQueueSidecarKeyspaces, PendingQueueSidecarSchemaMaterializer,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaBranchExactDeploymentLifecycleStore,
    ScyllaBranchExactWriterLifecycleStore,
    ScyllaRealmRollbackRuntimeControl, SealedBranchExactBackfillPlanCas,
    SealedBranchExactBackfillVerifiedCas, SealedBranchExactSchemaVerifiedCas,
    SealedPendingCounterAllocation,
};
use super::branch_exact_dual_write_executor::ScyllaBranchExactDualWriteAdapter;
use super::coordinator_commit_physical_execution::CoordinatorCommitPhysicalExecutionSchedule;
use super::coordinator_commit_physical_scylla::CoordinatorCommitPhysicalScyllaExecutor;
use super::coordinator_commit_physical_write_plan::CoordinatorCommitPhysicalWritePlan;

const COORDINATOR_KEYSPACE: &str = "psy_rollback_joint_control";
const REALM_10_KEYSPACE: &str = "psy_rollback_joint_control_realm_10";
const REALM_20_KEYSPACE: &str = "psy_rollback_joint_control_realm_20";
const NODES: [&str; 3] = [
    "172.29.86.11:9042",
    "172.29.86.12:9042",
    "172.29.86.13:9042",
];

fn rf3_enabled() -> bool {
    std::env::var("PSY_ROLLBACK_JOINT_RF3").as_deref() == Ok("1")
}

fn known_nodes() -> Vec<String> {
    let count = if rf3_enabled() { NODES.len() } else { 1 };
    NODES[..count]
        .iter()
        .map(|node| (*node).to_owned())
        .collect()
}

async fn open_store(
    realm_id: u64,
    keyspace: &str,
) -> anyhow::Result<ScyllaCoreStore<PHash, PoseidonHasher>> {
    let nodes = known_nodes();
    if rf3_enabled() {
        ScyllaCoreStore::<PHash, PoseidonHasher>::new_existing(
            realm_id,
            0,
            keyspace.to_owned(),
            &nodes,
        )
        .await
    } else {
        ScyllaCoreStore::<PHash, PoseidonHasher>::new(
            realm_id,
            0,
            keyspace.to_owned(),
            &nodes,
        )
        .await
    }
}

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
    coordinator_commit_source_from(
        expected,
        checkpoint,
        pending - 1,
        pending,
        ProcCheckpointUniqueId::from_u128(20_000 + u128::from(pending)),
        seed.wrapping_sub(1),
        seed,
        CommitWriteTimestampUs::try_from_i128(10_000 + i128::from(checkpoint))?,
    )
}

#[allow(clippy::too_many_arguments)]
fn coordinator_commit_source_from(
    expected: psy_node_core::store::canonical_head::StoredCanonicalHead<PHash>,
    checkpoint: u64,
    predecessor_pending: u64,
    pending: u64,
    proc_checkpoint_id: ProcCheckpointUniqueId,
    old_leaf_seed: u8,
    new_leaf_seed: u8,
    timestamp: CommitWriteTimestampUs,
) -> anyhow::Result<(CoordinatorCommitSource<PHash>, BranchExactWriterPrepared<PHash>)> {
    let old_leaf = coordinator_leaf(old_leaf_seed);
    let new_leaf = coordinator_leaf(new_leaf_seed);
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
        proc_checkpoint_unique_id: proc_checkpoint_id.as_u128(),
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
            vec![new_leaf_seed.max(1); 64],
        )?
        .encode_canonical(),
    )?;
    let intent = BranchExactDualWriteIntent::try_coordinator(
        BranchPendingMapping::new(
            *source.expected(),
            UniquePendingId::try_new(predecessor_pending)?,
        ),
        BranchPendingMapping::new(*source.candidate(), UniquePendingId::try_new(pending)?),
        proc_checkpoint_id,
    )?;
    Ok((source, narrow_prepared(intent, timestamp)?))
}

fn narrow_prepared<Hash: parth_core::protocol::core_types::Q256BitHash>(
    intent: BranchExactDualWriteIntent<Hash>,
    timestamp: CommitWriteTimestampUs,
) -> anyhow::Result<BranchExactWriterPrepared<Hash>> {
    let mut fence_bytes = [0_u8; 81];
    fence_bytes[..8].copy_from_slice(&9_u64.to_be_bytes());
    fence_bytes[8..16].copy_from_slice(&3_u64.to_be_bytes());
    fence_bytes[16..48].fill(0x44);
    fence_bytes[48..80].fill(0x55);
    fence_bytes[80] = BranchExactCutoverPhase::LegacyPrimaryDualWrite as u8;
    let fence = BranchExactWriterCutoverFence::decode_canonical(&fence_bytes)?;
    Ok(BranchExactWriterPrepared::test_fixture(
        intent,
        timestamp,
        fence,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn qualification_append_post_rollback_coordinator_commit(
    store: &ScyllaCoreStore<PHash, PoseidonHasher>,
    expected: psy_node_core::store::canonical_head::StoredCanonicalHead<PHash>,
    checkpoint: u64,
    predecessor_pending: u64,
    processing: PendingGenerationContext,
    timestamp: CommitWriteTimestampUs,
    old_leaf_seed: u8,
    new_leaf_seed: u8,
) -> anyhow::Result<psy_node_core::store::canonical_head::StoredCanonicalHead<PHash>> {
    let (source, narrow) = coordinator_commit_source_from(
        expected,
        checkpoint,
        predecessor_pending,
        processing.pending_id().get(),
        processing.proc_checkpoint_id(),
        old_leaf_seed,
        new_leaf_seed,
        timestamp,
    )?;
    let timestamp_store = ScyllaAuthorityTimestampStore::prepare(
        store.session.clone(),
        AuthorityTimestampNoTabletKeyspace::try_new(
            store.no_tablet_keyspace.clone(),
        )?,
    )
    .await?;
    let key = AuthorityTimestampKey::new(network(), AuthorityScope::Coordinator);
    let AuthorityTimestampReadState::Current(timestamp_state) =
        timestamp_store.read(key).await?
    else {
        bail!("restored Coordinator timestamp state is missing")
    };
    let reservation = timestamp_state.seal_reservation(
        key,
        narrow.intent().intent_digest().authority_intent(),
        AuthorityClockSampleUs::try_from_i128(i128::from(timestamp.as_i64()))?,
    )?;
    ensure!(
        reservation.lease().timestamp() == timestamp,
        "Coordinator did not reserve the requested post-fence timestamp",
    );
    let _ = timestamp_store.reserve(reservation).await?;
    qualification_seed_coordinator_commit(store, &source, &narrow).await?;
    let transition =
        CanonicalHeadTransition::normal_checkpoint_advance(expected, *source.candidate())?.seal();
    let outcome = store.compare_and_set_canonical_head(&transition).await?;
    ensure!(
        outcome.current() == transition.candidate(),
        "Coordinator post-rollback head advance conflicted",
    );
    let completion = reservation
        .candidate()
        .seal_completion(key, reservation.lease())?;
    let _ = timestamp_store.complete(completion).await?;
    Ok(outcome.current().clone())
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

fn runtime_rebuild_report(
    directive: &RollbackRuntimeRebuildDirective<PHash>,
    state_root: PHash,
) -> anyhow::Result<RollbackRuntimeRebuildReport<PHash>> {
    let target_checkpoint = directive.target().checkpoint().checkpoint_id().get();
    Ok(RollbackRuntimeRebuildReport::try_after_exact_rebuild(
        directive,
        0,
        target_checkpoint + 1,
        state_root,
        target_checkpoint,
        target_checkpoint,
        state_root,
        directive.processing(),
        directive.gathering(),
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

fn post_rollback_realm_commit(
    authority: AuthorityScope,
    predecessor: CanonicalChainRef<PHash>,
    predecessor_pending: u64,
    processing: PendingGenerationContext,
    timestamp: CommitWriteTimestampUs,
    seed: u8,
) -> anyhow::Result<(
    BranchExactWriterPrepared<PHash>,
    AuthorityObservation<PHash>,
)> {
    let checkpoint = predecessor
        .checkpoint()
        .checkpoint_id()
        .get()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("post-rollback Realm checkpoint overflow"))?;
    let candidate = CanonicalChainRef::new(
        predecessor.network_id(),
        predecessor.chain_epoch(),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    );
    let intent = BranchExactDualWriteIntent::try_realm(
        authority,
        BranchPendingMapping::new(
            predecessor,
            UniquePendingId::try_new(predecessor_pending)?,
        ),
        BranchPendingMapping::new(candidate, processing.pending_id()),
        processing.proc_checkpoint_id(),
        &TagTreeMerkleProof::<PHash>::new_empty(),
    )?;
    let observation = AuthorityObservation::try_new(
        candidate,
        authority,
        AuthorityStateCheckpointId::new(checkpoint),
        AuthorityStateRoot::from_local_state_root(hash(seed.wrapping_add(0x20))),
    )?;
    Ok((narrow_prepared(intent, timestamp)?, observation))
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
        coordinator_commit_source(floor_predecessor, 1, 2, 0xA1)?;
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
    for (checkpoint, pending, seed) in [(2_u64, 3_u64, 0xA2_u8), (3, 4, 0xA3)] {
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

    // The qualification commits above write the production checkpoint/pending
    // mappings but do not run the full Processor allocator. Seed that same
    // monotonic counter so rollback rebuild cannot reuse pending 1 after the
    // historical target already used pending 2.
    let counter = PendingCounterAdapter::prepare(
        store.session.clone(),
        CqlKeyspaceName::try_new(store.no_tablet_keyspace.clone())?,
        CqlKeyspaceName::try_new(store.keyspace.clone())?,
    )
    .await?;
    for value in 1_u64..=4 {
        let candidate = UniquePendingId::try_new(value)?;
        let expected = if value == 1 {
            PendingCounterExpected::Absent
        } else {
            PendingCounterExpected::Present(UniquePendingId::try_new(value - 1)?)
        };
        let proc_id = ProcCheckpointUniqueId::from_u128(20_000 + u128::from(value));
        let allocation = SealedPendingCounterAllocation::try_for_commit(
            expected,
            proc_id,
            CommitWriteTimestampUs::try_from_i128(10_003)?,
        )?;
        match counter.allocate(&allocation).await? {
            PendingCounterAllocationOutcome::Owned(owned)
                if owned.pending() == candidate && owned.proc_id() == proc_id => {}
            other => anyhow::bail!(
                "qualification Coordinator pending counter conflict at {value}: {other:?}"
            ),
        }
    }
    Ok((current, target))
}

async fn realm_control(
    keyspace: &str,
    realm_id: u32,
) -> anyhow::Result<ScyllaRealmRollbackRuntimeControl> {
    let store = open_store(u64::from(realm_id), keyspace).await?;
    let authority = AuthorityScope::Realm {
        realm_id,
        realm_sub_id: 0,
    };
    establish_branch_ready(&store, authority).await?;
    store
        .prepare_realm_rollback_runtime_control(COORDINATOR_KEYSPACE)
        .await
}

async fn coordinator_control(
) -> anyhow::Result<Arc<ScyllaCoreStore<PHash, PoseidonHasher>>> {
    let store = Arc::new(open_store(0, COORDINATOR_KEYSPACE).await?);
    establish_branch_ready(&store, AuthorityScope::Coordinator).await?;
    store.initialize_coordinator_canonical_head(true).await?;
    store.initialize_coordinator_rollback_admission(true).await?;
    Ok(store)
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
        std::env::var("PSY_ROLLBACK_JOINT_SINGLE").as_deref() == Ok("1")
            || rf3_enabled(),
        "run through the rollback joint RF=1 or RF=3 wrapper"
    );

    let mut coordinator = coordinator_control().await?;
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

    let mut realm_10 = realm_control(REALM_10_KEYSPACE, 10).await?;
    let mut realm_20 = realm_control(REALM_20_KEYSPACE, 20).await?;
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

    // Lose every archive owner before the first destructive transition. Only
    // the Coordinator is reopened now; Realm processes stay down until their
    // post-PONR delete work is selected.
    coordinator = coordinator_control().await?;
    drop(realm_10);
    drop(realm_20);

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

    // The Coordinator process also exits immediately after the destructive
    // PONR. Rebuild each Realm from its deployed keyspace; no in-memory
    // archive/delete capability is carried into Realm execution.
    drop(inbox);
    drop(boundary);
    drop(coordinator);
    realm_10 = realm_control(REALM_10_KEYSPACE, 10).await?;
    realm_20 = realm_control(REALM_20_KEYSPACE, 20).await?;

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

    // Lose the delete executors after every participant completion but before
    // the global delete barrier. The Coordinator must select the exact rows
    // again rather than trusting the previous process's return values.
    coordinator = coordinator_control().await?;
    realm_10 = realm_control(REALM_10_KEYSPACE, 10).await?;
    realm_20 = realm_control(REALM_20_KEYSPACE, 20).await?;

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

    // Drop the target-restore owners before global verification. Only the
    // Coordinator is restarted until VERIFYING asks Realms for reports.
    drop(realm_10);
    drop(realm_20);
    coordinator = coordinator_control().await?;

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
    let CoordinatorRollbackGlobalProgress::ReadyForRuntimeRebuild(runtime_ready_head) =
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackMaintenanceExecutor<
            PF,
            PHash,
        >>::progress_coordinator_rollback(&coordinator, network(), 32)
        .await
        .context("Coordinator post-fence timestamp rebuild")?
    else {
        bail!("Coordinator did not restore its timestamp before runtime rebuild")
    };
    ensure!(
        runtime_ready_head == verifying_head,
        "Coordinator runtime rebuild selected a different VERIFYING head",
    );

    // Rebuild the controls after entering VERIFYING. Runtime directives and
    // participant reports must be selected from storage, not retained owners.
    coordinator = coordinator_control().await?;
    realm_10 = realm_control(REALM_10_KEYSPACE, 10).await?;
    realm_20 = realm_control(REALM_20_KEYSPACE, 20).await?;
    let coordinator_directive =
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackRuntimeRebuildStore<
            PHash,
        >>::read_selected_coordinator_runtime_rebuild(&coordinator, network())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Coordinator runtime rebuild directive is missing"))?;

    // Each process rebuilds its own runtime from the storage-authored
    // directive. A Realm may only append its report; it cannot publish the
    // Coordinator head or provide the participant set.
    let mut selected_realms = Vec::new();
    for (control, authority, seed) in [
        (&realm_10, realm_10_authority, 0xC1),
        (&realm_20, realm_20_authority, 0xD1),
    ] {
        let RealmRollbackParticipantProgress::ReadyForRuntimeRebuild(observed) =
            <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
                PHash,
            >>::progress_realm_rollback_participant(control, network(), authority)
            .await?
        else {
            bail!("VERIFYING Realm did not expose its runtime rebuild task")
        };
        ensure!(
            observed == verifying_head,
            "Realm runtime rebuild selected a different Coordinator head",
        );
        let selected = <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<
            PHash,
        >>::read_selected_realm_runtime_rebuild(control, network(), authority)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("Realm runtime rebuild directive is missing for {authority:?}")
        })?;
        let report = runtime_rebuild_report(
            selected.directive(),
            *realm_observation(authority, 1, seed)?.state_root().as_inner(),
        )?;
        <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<PHash>>
            ::persist_realm_runtime_rebuild_report(control, selected, report)
            .await?;
        // Exact retry must recover the same immutable report rather than
        // creating a second completion.
        <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<PHash>>
            ::persist_realm_runtime_rebuild_report(control, selected, report)
            .await?;
        selected_realms.push(selected);
    }


    // Reports are immutable restart evidence. Drop every reporting process
    // before the Coordinator appends its own report and publishes the target.
    coordinator = coordinator_control().await?;
    realm_10 = realm_control(REALM_10_KEYSPACE, 10).await?;
    realm_20 = realm_control(REALM_20_KEYSPACE, 20).await?;

    let coordinator_report = runtime_rebuild_report(&coordinator_directive, hash(0xA1))?;
    <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackRuntimeRebuildStore<
        PHash,
    >>::persist_coordinator_runtime_rebuild_report(
        &coordinator,
        coordinator_directive,
        coordinator_report,
    )
    .await?;

    let CoordinatorRollbackRuntimePublication::Published(published) =
        <ScyllaCoreStore<PHash, PoseidonHasher> as CoordinatorRollbackRuntimeRebuildStore<
            PHash,
        >>::try_publish_restored_runtime(&coordinator, network())
        .await?
    else {
        bail!("complete Coordinator and Realm report set did not publish restored runtime")
    };
    ensure!(
        published.canonical_ref().checkpoint() == target.checkpoint()
            && published.canonical_ref().chain_epoch().get()
                == target.chain_epoch().get() + 1
            && matches!(published.rollback_control(), RollbackControlState::Idle),
        "runtime publication did not select IDLE at the rollback target in the new epoch",
    );
    for (control, selected) in [
        (&realm_10, selected_realms[0]),
        (&realm_20, selected_realms[1]),
    ] {
        ensure!(
            <ScyllaRealmRollbackRuntimeControl as RealmRollbackRuntimeControl<PHash>>
                ::is_realm_runtime_rebuild_published(control, selected)
                .await?,
            "Realm did not observe the globally published restored runtime",
        );
    }


    // The published IDLE target is the only authority carried into normal
    // execution. Reopen all stores once more before producing T+1/T+2.
    coordinator = coordinator_control().await?;
    realm_10 = realm_control(REALM_10_KEYSPACE, 10).await?;
    realm_20 = realm_control(REALM_20_KEYSPACE, 20).await?;

    // Prove the minimum product outcome after publication: the restored
    // target can advance through a different T+1 and T+2 branch using
    // timestamps strictly above the delete fence. The fixture assembles
    // commit inputs, while the physical writes, timestamp allocator and head
    // CAS use the real stores.
    let coordinator_processing = coordinator_directive
        .processing()
        .ok_or_else(|| anyhow::anyhow!("Coordinator processing context is missing"))?;
    let coordinator_gathering = coordinator_directive
        .gathering()
        .ok_or_else(|| anyhow::anyhow!("Coordinator gathering context is missing"))?;
    let coordinator_t1_timestamp = CommitWriteTimestampUs::try_from_i128(
        i128::from(
            coordinator_directive
                .new_branch_write()
                .as_commit_timestamp()
                .as_i64(),
        ) + 1,
    )?;
    let coordinator_t1 = qualification_append_post_rollback_coordinator_commit(
        &coordinator,
        published,
        2,
        2,
        coordinator_processing,
        coordinator_t1_timestamp,
        0xA1,
        0xB2,
    )
    .await?;
    ensure!(
        coordinator_t1.canonical_ref().checkpoint().checkpoint_id().get() == 2
            && coordinator_t1.canonical_ref().chain_epoch().get() == 1,
        "Coordinator did not advance from restored T to new-epoch T+1",
    );
    let coordinator_t2_timestamp = CommitWriteTimestampUs::try_from_i128(
        i128::from(coordinator_t1_timestamp.as_i64()) + 1,
    )?;
    let coordinator_t2 = qualification_append_post_rollback_coordinator_commit(
        &coordinator,
        coordinator_t1,
        3,
        coordinator_processing.pending_id().get(),
        coordinator_gathering,
        coordinator_t2_timestamp,
        0xB2,
        0xC3,
    )
    .await?;
    ensure!(
        coordinator_t2.canonical_ref().checkpoint().checkpoint_id().get() == 3
            && coordinator_t2.canonical_ref().chain_epoch().get() == 1,
        "Coordinator did not continue from T+1 to new-epoch T+2",
    );

    for ((control, selected), (predecessor_pending, seed)) in [
        (&realm_10, selected_realms[0]),
        (&realm_20, selected_realms[1]),
    ]
        .into_iter()
        .zip([(2_u64, 0xE2_u8), (2_u64, 0xF2_u8)])
    {
        let directive = selected.directive();
        let processing = directive
            .processing()
            .ok_or_else(|| anyhow::anyhow!("Realm processing context is missing"))?;
        let timestamp = CommitWriteTimestampUs::try_from_i128(
            i128::from(
                directive
                    .new_branch_write()
                    .as_commit_timestamp()
                    .as_i64(),
            ) + 1,
        )?;
        let (narrow, observation) = post_rollback_realm_commit(
            directive.authority(),
            *directive.target(),
            predecessor_pending,
            processing,
            timestamp,
            seed,
        )?;
        let (head, committed_timestamp) = control
            .qualification_append_post_rollback_narrow_commit(
                narrow,
                observation,
                AuthorityClockSampleUs::try_from_i128(i128::from(timestamp.as_i64()))?,
            )
            .await?;
        ensure!(
            head.head().chain() == observation.chain()
                && head.head().chain().checkpoint().checkpoint_id().get() == 2
                && head.head().chain().chain_epoch().get() == 1
                && committed_timestamp.as_i64()
                    > directive
                        .new_branch_write()
                        .delete_fence()
                        .as_i64(),
            "Realm did not advance from restored T to new-epoch T+1 above the fence",
        );

        let t2_timestamp = CommitWriteTimestampUs::try_from_i128(
            i128::from(timestamp.as_i64()) + 1,
        )?;
        let t2_processing = control
            .qualification_rotate_post_rollback_generation::<PHash>(
                directive.target().network_id(),
                directive.authority(),
                t2_timestamp,
            )
            .await?;
        ensure!(
            t2_processing == directive.gathering().ok_or_else(|| {
                anyhow::anyhow!("Realm gathering context is missing")
            })?,
            "Realm rotation did not select the preallocated gathering identity",
        );
        let (t2_narrow, t2_observation) = post_rollback_realm_commit(
            directive.authority(),
            *head.head().chain(),
            processing.pending_id().get(),
            t2_processing,
            t2_timestamp,
            seed.wrapping_add(1),
        )?;
        let (t2_head, t2_committed_timestamp) = control
            .qualification_append_post_rollback_narrow_commit(
                t2_narrow,
                t2_observation,
                AuthorityClockSampleUs::try_from_i128(i128::from(
                    t2_timestamp.as_i64(),
                ))?,
            )
            .await?;
        ensure!(
            t2_head.head().chain() == t2_observation.chain()
                && t2_head.head().chain().checkpoint().checkpoint_id().get() == 3
                && t2_head.head().chain().chain_epoch().get() == 1
                && t2_committed_timestamp.as_i64() > committed_timestamp.as_i64(),
            "Realm did not continue from T+1 to new-epoch T+2",
        );
    }
    Ok(())
}
