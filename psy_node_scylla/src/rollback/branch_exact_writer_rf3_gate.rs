//! h22e: real RF=3 requalification of the branch-exact Realm writer.

use std::{path::Path, sync::Arc, time::Instant};

use anyhow::{bail, ensure};
use parth_core::{crypto::hash::tag_tree::TagTreeMerkleProof, PHash};
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap,
        AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
        AuthorityTimestampWriteOutcome,
    },
    branch_exact_dual_write::BranchExactDualWriteIntent,
    branch_pending_mapping::BranchPendingMapping,
    timestamp::CommitWriteTimestampUs,
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};
use scylla::statement::Consistency;
use serde::Serialize;
use uuid::Uuid;

use super::{
    branch_exact_shadow_reader_rf3_gate as fixture, *,
};

const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplicaSnapshot {
    legacy_checkpoint_to_pending: (i64, i64),
    legacy_pending_to_checkpoint: (i64, i64),
    legacy_pending_to_proc: (Uuid, i64),
    legacy_proc_to_pending: (i64, i64),
    legacy_proof: (Vec<u8>, i64),
    target_forward: (i64, Vec<u8>, i64),
    target_reverse: (Vec<u8>, Vec<u8>, i64),
    target_proof: (Vec<u8>, i64),
    writer_row: (i64, Vec<u8>),
    timestamp_row: (i64, Vec<u8>),
}

#[derive(Debug, Serialize)]
struct H22eWriterReport {
    image: &'static str,
    replication_factor: u8,
    baseline_rows: usize,
    dual_write_mutations: usize,
    one_replica_offline: bool,
    restart_from_writes_verified: bool,
    retry_barrier_bit_exact: bool,
    finish_response_loss_idempotent: bool,
    explicit_timestamp_all_rows: bool,
    repair_direct_one_equal: bool,
    prepare_verify_ms: u64,
    repair_ms: u64,
    qualification: &'static str,
}

async fn create_writer_legacy_tables(session: &scylla::client::session::Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {}.pending_id_to_pending_proc_id_table_u64_to_u128 (obj_id bigint PRIMARY KEY, value uuid)",
                fixture::KEYSPACE,
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {}.pending_id_to_pending_proc_id_table_u128_to_u64 (obj_id uuid PRIMARY KEY, value bigint)",
                fixture::KEYSPACE,
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn direct_replica_snapshot(
    ip: std::net::Ipv4Addr,
    candidate: &BranchPendingMapping<PHash>,
    proc_id: ProcCheckpointUniqueId,
) -> anyhow::Result<ReplicaSnapshot> {
    let session = fixture::connect(Some(ip), Consistency::One).await?;
    let height = candidate
        .canonical_chain()
        .checkpoint()
        .checkpoint_id()
        .get() as i64;
    let pending = candidate.pending_id().get() as i64;
    let proc_uuid = Uuid::from_bytes(*proc_id.as_bytes());
    let canonical = candidate.canonical_chain().to_canonical_bytes();
    let legacy_checkpoint_to_pending = session
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
    let legacy_pending_to_checkpoint = session
        .query_unpaged(
            format!(
                "SELECT value, writetime(value) FROM {}.pending_id_to_checkpoint_id_table WHERE obj_id = ?",
                fixture::KEYSPACE,
            ),
            (pending,),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, i64)>()?;
    let legacy_pending_to_proc = session
        .query_unpaged(
            format!(
                "SELECT value, writetime(value) FROM {}.pending_id_to_pending_proc_id_table_u64_to_u128 WHERE obj_id = ?",
                fixture::KEYSPACE,
            ),
            (pending,),
        )
        .await?
        .into_rows_result()?
        .single_row::<(Uuid, i64)>()?;
    let legacy_proc_to_pending = session
        .query_unpaged(
            format!(
                "SELECT value, writetime(value) FROM {}.pending_id_to_pending_proc_id_table_u128_to_u64 WHERE obj_id = ?",
                fixture::KEYSPACE,
            ),
            (proc_uuid,),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, i64)>()?;
    let legacy_proof = session
        .query_unpaged(
            format!(
                "SELECT value, writetime(value) FROM {}.checkpointed_object_table WHERE obj_id = ? AND checkpoint_id = ?",
                fixture::KEYSPACE,
            ),
            (2_i64, pending),
        )
        .await?
        .into_rows_result()?
        .single_row::<(Vec<u8>, i64)>()?;
    let target_forward = session
        .query_unpaged(
            format!(
                "SELECT pending_id, mapping_digest, writetime(mapping_digest) FROM {}.{} WHERE canonical_ref = ? AND pending_id = ?",
                fixture::KEYSPACE,
                BRANCH_TO_PENDING_TABLE,
            ),
            (canonical.as_slice(), pending),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>, i64)>()?;
    let target_reverse = session
        .query_unpaged(
            format!(
                "SELECT canonical_ref, mapping_digest, writetime(mapping_digest) FROM {}.{} WHERE pending_id = ? AND canonical_ref = ?",
                fixture::KEYSPACE,
                PENDING_TO_BRANCH_TABLE,
            ),
            (pending, canonical.as_slice()),
        )
        .await?
        .into_rows_result()?
        .single_row::<(Vec<u8>, Vec<u8>, i64)>()?;
    let target_proof = session
        .query_unpaged(
            format!(
                "SELECT value, writetime(value) FROM {}.{} WHERE pending_id = ?",
                fixture::KEYSPACE,
                PENDING_REWARD_PROOF_TABLE,
            ),
            (pending,),
        )
        .await?
        .into_rows_result()?
        .single_row::<(Vec<u8>, i64)>()?;
    let writer_row = session
        .query_unpaged(
            format!(
                "SELECT revision, lifecycle FROM {}.branch_exact_writer_lifecycle_v1 WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?",
                fixture::control_keyspace(),
            ),
            (1337_i64, 2_i8, 7_i64, 2_i32),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    let timestamp_row = session
        .query_unpaged(
            format!(
                "SELECT revision, state FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?",
                fixture::control_keyspace(),
                D04A_AUTHORITY_TIMESTAMP_TABLE,
            ),
            (1337_i64, 2_i8, 7_i64, 2_i64),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, Vec<u8>)>()?;
    Ok(ReplicaSnapshot {
        legacy_checkpoint_to_pending,
        legacy_pending_to_checkpoint,
        legacy_pending_to_proc,
        legacy_proc_to_pending,
        legacy_proof,
        target_forward,
        target_reverse,
        target_proof,
        writer_row,
        timestamp_row,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h22e_branch_exact_writer_rf3_gate() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_D04B6H22E_RF3").as_deref() == Ok("1"));
    let compose_file = std::env::var("PSY_D04B6H22E_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H22E_REPORT_PATH")?;
    fixture::wait_up(3).await?;
    let session = Arc::new(fixture::connect(None, Consistency::Quorum).await?);
    fixture::create_keyspaces(&session).await?;
    fixture::create_legacy_tables(&session).await?;
    create_writer_legacy_tables(&session).await?;
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
    let shadow_store = ScyllaBranchExactShadowAuditStore::prepare(
        session.clone(),
        control.clone(),
    )
    .await?;
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
    let writer_store = ScyllaBranchExactWriterLifecycleStore::prepare(
        session.clone(),
        control.clone(),
    )
    .await?;
    let timestamp_keyspace = AuthorityTimestampNoTabletKeyspace::try_new(
        fixture::control_keyspace(),
    )?;
    ScyllaAuthorityTimestampStore::create_schema(&session, &timestamp_keyspace).await?;
    let timestamps = ScyllaAuthorityTimestampStore::prepare(
        session.clone(),
        timestamp_keyspace,
    )
    .await?;
    let baseline_timestamp = verified_timestamp(&reader)?;
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
        .ok_or_else(|| anyhow::anyhow!("timestamp row missing"))?;
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
            Some(psy_node_core::queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierProfileId::try_from_persisted([0xA5; 32])?),
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

    let predecessor = *artifact.rows().last().unwrap().mapping();
    let candidate = BranchPendingMapping::new(
        fixture::chain(0, fixture::ROWS as u64, 80_000)?,
        UniquePendingId::try_new(1_000 + fixture::ROWS as u64)?,
    );
    let proc_id = ProcCheckpointUniqueId::from_u128(90_001);
    let intent = BranchExactDualWriteIntent::try_realm(
        fixture::authority(),
        predecessor,
        candidate,
        proc_id,
        &TagTreeMerkleProof::<PHash>::new_empty(),
    )?;
    ensure!(intent.mutations().len() == 8);
    let request = BranchExactWriterRuntimeRequest::new(
        candidate.canonical_chain().network_id(),
        fixture::authority(),
        plan.digest(),
    );
    let runtime = ScyllaBranchExactWriterRuntime::<PHash>::prepare(
        session.clone(),
        fixture::KEYSPACE,
        &fixture::control_keyspace(),
        request.clone(),
    )
    .await?;

    fixture::compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h22e replica",
    )?;
    fixture::wait_up(2).await?;
    let started = Instant::now();
    let barrier = runtime
        .prepare_and_verify(
            intent.clone(),
            AuthorityClockSampleUs::try_from_i128(
                baseline_timestamp.as_i64() as i128 + 100,
            )?,
        )
        .await?;
    let prepare_verify_ms = started.elapsed().as_millis() as u64;
    runtime.require_fresh_barrier(&barrier).await?;

    let restarted = ScyllaBranchExactWriterRuntime::<PHash>::prepare(
        session.clone(),
        fixture::KEYSPACE,
        &fixture::control_keyspace(),
        request,
    )
    .await?;
    let retried = restarted
        .prepare_and_verify(
            intent,
            AuthorityClockSampleUs::try_from_i128(
                baseline_timestamp.as_i64() as i128 + 10_000,
            )?,
        )
        .await?;
    ensure!(retried == barrier);
    restarted.require_fresh_barrier(&retried).await?;
    restarted
        .finish_published(&retried, candidate.canonical_chain())
        .await?;
    restarted
        .finish_published(&retried, candidate.canonical_chain())
        .await?;
    let final_state = restarted.read_writer().await?;
    let BranchExactWriterState::Active(active) = final_state.state() else {
        bail!("writer did not return Active")
    };
    ensure!(active.watermark() == &candidate);
    let write_timestamp = active.timestamp_high_water().as_i64();

    fixture::compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "start h22e replica",
    )?;
    fixture::wait_up(3).await?;
    let repair_started = Instant::now();
    fixture::nodetool(
        fixture::NODE_CONTAINERS[0],
        &["cluster", "repair", fixture::KEYSPACE],
        "repair h22e standard keyspace",
    )?;
    for node in fixture::NODE_CONTAINERS {
        fixture::nodetool(
            node,
            &["repair", "-pr", &fixture::control_keyspace()],
            "repair h22e control keyspace",
        )?;
        fixture::nodetool(node, &["flush", fixture::KEYSPACE], "flush h22e standard")?;
        fixture::nodetool(
            node,
            &["flush", &fixture::control_keyspace()],
            "flush h22e control",
        )?;
        fixture::nodetool(node, &["compact", fixture::KEYSPACE], "compact h22e standard")?;
        fixture::nodetool(
            node,
            &["compact", &fixture::control_keyspace()],
            "compact h22e control",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let snapshots = futures::future::join_all(
        fixture::NODE_IPS.map(|ip| direct_replica_snapshot(ip, &candidate, proc_id)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    ensure!(snapshots.windows(2).all(|pair| pair[0] == pair[1]));
    let snapshot = &snapshots[0];
    let writetimes = [
        snapshot.legacy_checkpoint_to_pending.1,
        snapshot.legacy_pending_to_checkpoint.1,
        snapshot.legacy_pending_to_proc.1,
        snapshot.legacy_proc_to_pending.1,
        snapshot.legacy_proof.1,
        snapshot.target_forward.2,
        snapshot.target_reverse.2,
        snapshot.target_proof.1,
    ];
    ensure!(writetimes.into_iter().all(|value| value == write_timestamp));
    ensure!(snapshot.legacy_checkpoint_to_pending.0 == candidate.pending_id().get() as i64);
    ensure!(snapshot.legacy_pending_to_checkpoint.0 == candidate.canonical_chain().checkpoint().checkpoint_id().get() as i64);
    ensure!(snapshot.legacy_pending_to_proc.0 == Uuid::from_bytes(*proc_id.as_bytes()));
    ensure!(snapshot.legacy_proc_to_pending.0 == candidate.pending_id().get() as i64);
    ensure!(snapshot.target_forward.0 == candidate.pending_id().get() as i64);
    ensure!(snapshot.target_reverse.0 == candidate.canonical_chain().to_canonical_bytes());

    let report = H22eWriterReport {
        image: IMAGE,
        replication_factor: 3,
        baseline_rows: artifact.rows().len(),
        dual_write_mutations: 8,
        one_replica_offline: true,
        restart_from_writes_verified: true,
        retry_barrier_bit_exact: true,
        finish_response_loss_idempotent: true,
        explicit_timestamp_all_rows: true,
        repair_direct_one_equal: true,
        prepare_verify_ms,
        repair_ms,
        qualification: "PASS",
    };
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn verified_timestamp(
    _reader: &ScyllaBranchExactShadowReader<PHash>,
) -> anyhow::Result<CommitWriteTimestampUs> {
    // The shared h21 fixture seals this exact timestamp into the post-genesis
    // backfill plan before producing the VERIFIED receipt consumed above.
    Ok(CommitWriteTimestampUs::try_from_i128(
        1_700_000_000_000_000,
    )?)
}
