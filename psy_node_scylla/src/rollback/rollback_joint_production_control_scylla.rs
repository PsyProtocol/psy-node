//! Single-node production-store composition smoke test for the delete-only
//! rollback control plane.  Physical archive/delete execution is deliberately
//! left to the next slice; this test closes the durable request-selection seam
//! shared by Coordinator and every configured Realm.

use std::sync::Arc;

use anyhow::{bail, ensure};
use parth_core::{
    data::db::table::QDatabaseTableRoutingKey,
    pgoldilocks::PoseidonHasher,
    PHash, PF,
};
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    },
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    branch_exact_schema::BranchExactSchemaMaterializationPlan,
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
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
    },
    rollback_participant_plan::RollbackRealmParticipant,
    rollback_runtime_rebuild::{
        RealmRollbackParticipantProgress, RealmRollbackRuntimeControl,
    },
    rollback_topology::RollbackTopologySnapshot,
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
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
    Ok(())
}
