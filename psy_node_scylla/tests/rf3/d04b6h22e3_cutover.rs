//! h22e3d: real RF=3 qualification of the reversible cutover substrate.

use std::{path::Path, sync::Arc, time::Instant};

use anyhow::{bail, ensure};
use futures::future::join_all;
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    protocol::core_types::Q256BitHash,
    PHash,
};
use psy_data::protocol::chain_context::{
    AuthorityStateCheckpointId, AuthorityStateRoot,
};
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampKey,
    },
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
        AuthorityLocalHeadReadState, AuthorityStorageBindingGeneration,
        AuthorityStorageBindingRef, AuthorityStorageNamespaceId,
    },
    branch_exact_dual_write::BranchExactDualWriteIntent,
    branch_pending_mapping::BranchPendingMapping,
    manifest_lifecycle::AuthorityHeadView,
    manifest_record::AuthorityManifestDigest,
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};
use scylla::statement::Consistency;
use serde::Serialize;

use super::{
    branch_exact_shadow_reader_rf3_gate as fixture,
    pending_queue_segment_lifecycle_rf3 as realm_fixture, *,
};

const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplicaSnapshot {
    cutover: (i64, Vec<u8>),
    writer: (i64, Vec<u8>),
    timestamp: (i64, Vec<u8>),
    local_head: (i64, Vec<u8>),
    legacy_forward: (i64, i64),
    target_forward: (i64, Vec<u8>, i64),
}

#[derive(Debug, Serialize)]
struct H22e3Report {
    image: &'static str,
    replication_factor: u8,
    writer_codec: u8,
    concurrent_cutover_contenders: u8,
    concurrent_applied: u8,
    concurrent_conflicts: u8,
    response_loss_idempotent: bool,
    aba_stale_cas_rejected: bool,
    managed_writer_restart_bit_exact: bool,
    managed_writer_fence_persisted: bool,
    quiescing_rejects_new_work: bool,
    target_publish_and_fallback: bool,
    pre_publish_abort_both_directions: bool,
    legacy_retained: bool,
    no_delete_or_retirement_cql: bool,
    one_replica_offline: bool,
    repair_direct_one_equal: bool,
    writer_prepare_verify_ms: u64,
    cutover_transition_ms: u64,
    repair_ms: u64,
    qualification: &'static str,
}

async fn direct_snapshot(
    ip: std::net::Ipv4Addr,
    candidate: &BranchPendingMapping<PHash>,
) -> anyhow::Result<ReplicaSnapshot> {
    let session = fixture::connect(Some(ip), Consistency::One).await?;
    let control = fixture::control_keyspace();
    let canonical = candidate.canonical_chain().to_canonical_bytes();
    let pending = candidate.pending_id().get() as i64;
    let height = candidate
        .canonical_chain()
        .checkpoint()
        .checkpoint_id()
        .get() as i64;
    let cutover = session
        .query_unpaged(
            format!(
                "SELECT revision, cutover FROM {control}.branch_exact_cutover_lifecycle_v1 WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?"
            ),
            (1337_i64, 2_i8, 7_i64, 2_i32),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let writer = session
        .query_unpaged(
            format!(
                "SELECT revision, lifecycle FROM {control}.branch_exact_writer_lifecycle_v1 WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?"
            ),
            (1337_i64, 2_i8, 7_i64, 2_i32),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let timestamp = session
        .query_unpaged(
            format!(
                "SELECT revision, state FROM {control}.{D04A_AUTHORITY_TIMESTAMP_TABLE} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?"
            ),
            (1337_i64, 2_i8, 7_i64, 2_i64),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let local_head = session
        .query_unpaged(
            format!(
                "SELECT revision, head FROM {control}.{D04B_AUTHORITY_LOCAL_HEAD_TABLE} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?"
            ),
            (1337_i64, 2_i8, 7_i64, 2_i64),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let legacy_forward = session
        .query_unpaged(
            format!(
                "SELECT value, writetime(value) FROM {}.checkpoint_id_to_pending_id_table WHERE obj_id = ?",
                fixture::KEYSPACE,
            ),
            (height,),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, i64)>()?;
    let target_forward = session
        .query_unpaged(
            format!(
                "SELECT pending_id, mapping_digest, writetime(mapping_digest) FROM {}.{BRANCH_TO_PENDING_TABLE} WHERE canonical_ref = ? AND pending_id = ?",
                fixture::KEYSPACE,
            ),
            (canonical.as_slice(), pending),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>, i64)>()?;
    Ok(ReplicaSnapshot {
        cutover,
        writer,
        timestamp,
        local_head,
        legacy_forward,
        target_forward,
    })
}

fn current_cutover(
    outcome: BranchExactCutoverWriteOutcome<PHash>,
) -> StoredBranchExactCutover<PHash> {
    match outcome {
        BranchExactCutoverWriteOutcome::Applied(current)
        | BranchExactCutoverWriteOutcome::Idempotent(current)
        | BranchExactCutoverWriteOutcome::Conflict(current) => current,
    }
}

fn transitioned(
    outcome: BranchExactCutoverTransitionOutcome<PHash>,
) -> StoredBranchExactCutover<PHash> {
    match outcome {
        BranchExactCutoverTransitionOutcome::Applied(current)
        | BranchExactCutoverTransitionOutcome::Idempotent(current) => current,
    }
}

async fn prepare_managed_runtime(
    session: Arc<scylla::client::session::Session>,
    writer_request: BranchExactWriterRuntimeRequest<PHash>,
    cutover_request: BranchExactCutoverRuntimeRequest,
) -> anyhow::Result<ScyllaBranchExactCutoverRuntime<PHash>> {
    let writer = ScyllaBranchExactWriterRuntime::prepare(
        session.clone(),
        fixture::KEYSPACE,
        &fixture::control_keyspace(),
        writer_request,
    )
    .await?;
    Ok(ScyllaBranchExactCutoverRuntime::prepare(
        session,
        &fixture::control_keyspace(),
        cutover_request,
        writer,
    )
    .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h22e3_cutover_rf3_gate() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_D04B6H22E3_RF3").as_deref() == Ok("1"));
    let compose_file = std::env::var("PSY_D04B6H22E3_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H22E3_REPORT_PATH")?;
    fixture::wait_up(3).await?;
    let session = Arc::new(fixture::connect(None, Consistency::Quorum).await?);
    fixture::create_keyspaces(&session).await?;
    fixture::create_legacy_tables(&session).await?;
    let activated = realm_fixture::activate_realm_writer(session.clone()).await?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;

    let head_keyspace = AuthorityLocalHeadNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    ScyllaAuthorityLocalHeadStore::create_schema(&session, &head_keyspace).await?;
    let head_store = ScyllaAuthorityLocalHeadStore::prepare(
        session.clone(),
        head_keyspace,
    )
    .await?;
    let network = activated.predecessor.canonical_chain().network_id();
    let authority = fixture::authority();
    let predecessor_chain = *activated.predecessor.canonical_chain();
    let state_root = AuthorityStateRoot::from_local_state_root(
        PHash::from_owned_32bytes([0x61; 32]),
    );
    let head_view = AuthorityHeadView::try_from_observed(
        AuthorityTimestampKey::new(network, authority),
        predecessor_chain,
        AuthorityStateCheckpointId::new(
            predecessor_chain.checkpoint().checkpoint_id().get(),
        ),
        state_root,
    )?;
    let head_bootstrap = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::PostGenesisFloor,
        head_view,
        activated.baseline_timestamp,
        AuthorityManifestDigest::from_persisted([0x62; 32]),
        AuthorityStorageBindingRef::new(
            AuthorityStorageBindingGeneration::try_new(1)?,
            AuthorityStorageNamespaceId::from_verified_namespace_id([0x63; 32]),
        ),
    );
    head_store.bootstrap(&head_bootstrap).await?;
    let AuthorityLocalHeadReadState::Current(local_head) = head_store
        .read::<PHash>(AuthorityTimestampKey::new(network, authority))
        .await?
    else {
        bail!("authority-local head missing")
    };

    let shadow_store = ScyllaBranchExactShadowAuditStore::prepare(
        session.clone(),
        control.clone(),
    )
    .await?;
    let BranchExactShadowAuditReadState::Current(shadow) = shadow_store
        .read(activated.plan.shadow_audit_slot())
        .await?
    else {
        bail!("consumed shadow row missing")
    };
    let BranchExactShadowAuditState::Consumed(consumed) = shadow.state() else {
        bail!("shadow row is not Consumed")
    };
    let writer_key = BranchExactWriterAuthorityKey::new(network, authority);
    let BranchExactWriterReadState::Current(active_writer) = activated
        .writer_store
        .read(writer_key)
        .await?
    else {
        bail!("active writer missing")
    };
    ensure!(matches!(active_writer.state(), BranchExactWriterState::Active(_)));

    let generation = BranchExactCutoverGeneration::try_new(1)?;
    let binding = BranchExactCutoverBinding::try_from_current(
        generation,
        &active_writer,
        consumed,
        &local_head,
    )?;
    let binding_digest = binding.digest();
    ScyllaBranchExactCutoverStore::create_schema(&session, &control).await?;
    let cutover_store = Arc::new(
        ScyllaBranchExactCutoverStore::prepare(session.clone(), control.clone()).await?,
    );
    let bootstrap = BranchExactCutoverBootstrap::seal(binding);
    let bootstrapped = current_cutover(cutover_store.bootstrap(&bootstrap).await?);
    ensure!(bootstrapped.phase() == BranchExactCutoverPhase::LegacyPrimaryDualWrite);
    ensure!(matches!(
        cutover_store.bootstrap(&bootstrap).await?,
        BranchExactCutoverWriteOutcome::Idempotent(_)
    ));

    fixture::compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h22e3 replica",
    )?;
    fixture::wait_up(2).await?;

    let contenders = (1u8..=64)
        .map(|seed| {
            let permit = BranchExactCutoverPermit::after_processor_drain(
                &bootstrapped,
                [seed; 32],
            )?;
            Ok::<_, anyhow::Error>(SealedBranchExactCutoverCas::prepare_target(
                &bootstrapped,
                &permit,
            )?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let stale_cas = contenders[0].clone();
    let results = join_all(contenders.into_iter().map(|sealed| {
        let store = cutover_store.clone();
        async move { store.compare_and_set(&sealed).await }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let concurrent_applied = results
        .iter()
        .filter(|outcome| matches!(outcome, BranchExactCutoverWriteOutcome::Applied(_)))
        .count();
    let concurrent_conflicts = results
        .iter()
        .filter(|outcome| matches!(outcome, BranchExactCutoverWriteOutcome::Conflict(_)))
        .count();
    ensure!(concurrent_applied == 1 && concurrent_conflicts == 63);
    let BranchExactCutoverReadState::Current(quiescing) = cutover_store
        .read::<PHash>(BranchExactCutoverAuthorityKey::try_new(network, authority)?)
        .await?
    else {
        bail!("cutover row missing after contenders")
    };
    ensure!(quiescing.phase() == BranchExactCutoverPhase::QuiescingToTarget);
    let abort_permit = BranchExactCutoverPermit::after_processor_drain(
        &quiescing,
        [80; 32],
    )?;
    let abort = SealedBranchExactCutoverCas::abort_target(&quiescing, &abort_permit)?;
    ensure!(matches!(
        cutover_store.compare_and_set(&abort).await?,
        BranchExactCutoverWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        cutover_store.compare_and_set(&abort).await?,
        BranchExactCutoverWriteOutcome::Idempotent(_)
    ));
    ensure!(matches!(
        cutover_store.compare_and_set(&stale_cas).await?,
        BranchExactCutoverWriteOutcome::Conflict(_)
    ));

    let writer_request = BranchExactWriterRuntimeRequest::new(
        network,
        authority,
        activated.plan.digest(),
    );
    let cutover_request = BranchExactCutoverRuntimeRequest::try_new(
        network,
        authority,
        generation,
        binding_digest,
    )?;
    let runtime = prepare_managed_runtime(
        session.clone(),
        writer_request.clone(),
        cutover_request,
    )
    .await?;
    let candidate = BranchPendingMapping::new(
        fixture::chain(0, fixture::ROWS as u64, 88_000)?,
        UniquePendingId::try_new(1_000 + fixture::ROWS as u64)?,
    );
    let intent = BranchExactDualWriteIntent::try_realm(
        authority,
        activated.predecessor,
        candidate,
        ProcCheckpointUniqueId::from_u128(99_001),
        &TagTreeMerkleProof::<PHash>::new_empty(),
    )?;
    let route_fence = runtime.begin_write().await?;
    let writer_started = Instant::now();
    let barrier = runtime
        .prepare_and_verify(
            &route_fence,
            intent.clone(),
            AuthorityClockSampleUs::try_from_i128(
                activated.baseline_timestamp.as_i64() as i128 + 100,
            )?,
        )
        .await?;
    let writer_prepare_verify_ms = writer_started.elapsed().as_millis() as u64;
    let restarted = prepare_managed_runtime(
        session.clone(),
        writer_request.clone(),
        cutover_request,
    )
    .await?;
    let retried = restarted
        .prepare_and_verify(
            &route_fence,
            intent,
            AuthorityClockSampleUs::try_from_i128(
                activated.baseline_timestamp.as_i64() as i128 + 50_000,
            )?,
        )
        .await?;
    ensure!(retried == barrier);
    restarted.require_fresh_barrier(&retried).await?;
    let observation = BranchExactProcessorDrainObservation::try_new(true, 0, false)?;
    let lease = BranchExactProcessorOwnedLease::seal(route_fence.clone(), observation);
    restarted
        .finish_published(&lease, &retried, candidate.canonical_chain())
        .await?;
    restarted
        .finish_published(&lease, &retried, candidate.canonical_chain())
        .await?;
    let writer_state = restarted.read_writer_state().await?;
    let BranchExactWriterState::Active(writer_active) = writer_state.state() else {
        bail!("managed writer did not return Active")
    };
    ensure!(writer_active.watermark() == &candidate);

    let transition_started = Instant::now();
    let q_target = transitioned(
        restarted
            .transition_route(
                observation,
                [90; 32],
                BranchExactCutoverTransitionAction::PrepareTarget,
            )
            .await?,
    );
    ensure!(q_target.phase() == BranchExactCutoverPhase::QuiescingToTarget);
    ensure!(matches!(
        restarted.begin_write().await,
        Err(BranchExactCutoverRuntimeError::RouteQuiescing)
    ));
    let restarted_quiescing = prepare_managed_runtime(
        session.clone(),
        writer_request.clone(),
        cutover_request,
    )
    .await?;
    let target = transitioned(
        restarted_quiescing
            .transition_route(
                observation,
                [91; 32],
                BranchExactCutoverTransitionAction::PublishTarget,
            )
            .await?,
    );
    ensure!(target.phase() == BranchExactCutoverPhase::TargetPrimaryDualWrite);
    ensure!(restarted_quiescing.begin_write().await?.phase()
        == BranchExactCutoverPhase::TargetPrimaryDualWrite);
    let q_legacy = transitioned(
        restarted_quiescing
            .transition_route(
                observation,
                [92; 32],
                BranchExactCutoverTransitionAction::PrepareLegacy,
            )
            .await?,
    );
    ensure!(q_legacy.phase() == BranchExactCutoverPhase::QuiescingToLegacy);
    let legacy = transitioned(
        restarted_quiescing
            .transition_route(
                observation,
                [93; 32],
                BranchExactCutoverTransitionAction::PublishLegacy,
            )
            .await?,
    );
    ensure!(legacy.phase() == BranchExactCutoverPhase::LegacyPrimaryDualWrite);

    restarted_quiescing
        .transition_route(
            observation,
            [94; 32],
            BranchExactCutoverTransitionAction::PrepareTarget,
        )
        .await?;
    let aborted_target = transitioned(
        restarted_quiescing
            .transition_route(
                observation,
                [95; 32],
                BranchExactCutoverTransitionAction::AbortTarget,
            )
            .await?,
    );
    ensure!(aborted_target.phase() == BranchExactCutoverPhase::LegacyPrimaryDualWrite);
    restarted_quiescing
        .transition_route(
            observation,
            [96; 32],
            BranchExactCutoverTransitionAction::PrepareTarget,
        )
        .await?;
    restarted_quiescing
        .transition_route(
            observation,
            [97; 32],
            BranchExactCutoverTransitionAction::PublishTarget,
        )
        .await?;
    restarted_quiescing
        .transition_route(
            observation,
            [98; 32],
            BranchExactCutoverTransitionAction::PrepareLegacy,
        )
        .await?;
    let aborted_legacy = transitioned(
        restarted_quiescing
            .transition_route(
                observation,
                [99; 32],
                BranchExactCutoverTransitionAction::AbortLegacy,
            )
            .await?,
    );
    ensure!(aborted_legacy.phase() == BranchExactCutoverPhase::TargetPrimaryDualWrite);
    restarted_quiescing
        .transition_route(
            observation,
            [100; 32],
            BranchExactCutoverTransitionAction::PrepareLegacy,
        )
        .await?;
    let final_legacy = transitioned(
        restarted_quiescing
            .transition_route(
                observation,
                [101; 32],
                BranchExactCutoverTransitionAction::PublishLegacy,
            )
            .await?,
    );
    ensure!(final_legacy.phase() == BranchExactCutoverPhase::LegacyPrimaryDualWrite);
    let cutover_transition_ms = transition_started.elapsed().as_millis() as u64;

    fixture::compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "start h22e3 replica",
    )?;
    fixture::wait_up(3).await?;
    let repair_started = Instant::now();
    fixture::nodetool(
        fixture::NODE_CONTAINERS[0],
        &["cluster", "repair", fixture::KEYSPACE],
        "repair h22e3 standard keyspace",
    )?;
    for node in fixture::NODE_CONTAINERS {
        fixture::nodetool(
            node,
            &["repair", "-pr", &fixture::control_keyspace()],
            "repair h22e3 control keyspace",
        )?;
        fixture::nodetool(node, &["flush", fixture::KEYSPACE], "flush h22e3 standard")?;
        fixture::nodetool(node, &["flush", &fixture::control_keyspace()], "flush h22e3 control")?;
        fixture::nodetool(node, &["compact", fixture::KEYSPACE], "compact h22e3 standard")?;
        fixture::nodetool(node, &["compact", &fixture::control_keyspace()], "compact h22e3 control")?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let snapshots = join_all(
        fixture::NODE_IPS.map(|ip| direct_snapshot(ip, &candidate)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    ensure!(snapshots.windows(2).all(|pair| pair[0] == pair[1]));
    let snapshot = &snapshots[0];
    ensure!(snapshot.cutover.0 == final_legacy.revision().as_i64());
    ensure!(snapshot.cutover.1 == final_legacy.to_canonical_bytes());
    ensure!(snapshot.legacy_forward.0 == candidate.pending_id().get() as i64);
    ensure!(snapshot.target_forward.0 == candidate.pending_id().get() as i64);
    ensure!(snapshot.legacy_forward.1 == snapshot.target_forward.2);
    let no_delete = !include_str!("../../src/rollback/branch_exact_cutover_store.rs")
        .contains("DELETE FROM")
        && !include_str!("../../src/rollback/branch_exact_cutover_runtime.rs")
            .contains("DELETE FROM");
    ensure!(no_delete);

    let report = H22e3Report {
        image: IMAGE,
        replication_factor: 3,
        writer_codec: 4,
        concurrent_cutover_contenders: 64,
        concurrent_applied: concurrent_applied as u8,
        concurrent_conflicts: concurrent_conflicts as u8,
        response_loss_idempotent: true,
        aba_stale_cas_rejected: true,
        managed_writer_restart_bit_exact: true,
        managed_writer_fence_persisted: true,
        quiescing_rejects_new_work: true,
        target_publish_and_fallback: true,
        pre_publish_abort_both_directions: true,
        legacy_retained: true,
        no_delete_or_retirement_cql: no_delete,
        one_replica_offline: true,
        repair_direct_one_equal: true,
        writer_prepare_verify_ms,
        cutover_transition_ms,
        repair_ms,
        qualification: "PASS",
    };
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
