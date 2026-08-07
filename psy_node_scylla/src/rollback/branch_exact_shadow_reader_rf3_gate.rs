use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use futures::future::join_all;
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    pgoldilocks::PoseidonHasher,
    PHash,
};
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
    CheckpointRef, NetworkId,
};
use psy_node_core::store::{
    branch_exact_schema::{
        AuthorityScope, BaselineSnapshotArtifactDigest,
        BranchExactPostGenesisFloorEvidence,
        BranchExactSchemaMaterializationPlan,
    },
    branch_pending_mapping::BranchPendingMapping,
    canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
    manifest_record::AuthorityManifestDigest,
    timestamp::CommitWriteTimestampUs,
    typed::UniquePendingId,
};
use scylla::{
    client::{
        execution_profile::ExecutionProfile, session::Session,
        session_builder::SessionBuilder,
    },
    policies::load_balancing::{
        NodeIdentifier, SingleTargetLoadBalancingPolicy,
    },
    statement::Consistency,
};
use serde::Serialize;
use tokio::time::sleep;
use uuid::Uuid;

use crate::core::ScyllaCoreStore;

use super::*;

const KEYSPACE: &str = "psy_d04b6h21_realm";
const BASELINE: &str = "961809cbde127e126f1c7816b9d14e8b4450e043";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const ROWS: usize = 64;
const CHUNKS: u32 = 4;
const NODE_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(172, 29, 86, 11),
    Ipv4Addr::new(172, 29, 86, 12),
    Ipv4Addr::new(172, 29, 86, 13),
];
const NODE_CONTAINERS: [&str; 3] = [
    "psy-g0-02-rf3-scylla1-1",
    "psy-g0-02-rf3-scylla2-1",
    "psy-g0-02-rf3-scylla3-1",
];

fn control_keyspace() -> String { format!("{KEYSPACE}_no_tablet") }

fn authority() -> AuthorityScope {
    AuthorityScope::Realm { realm_id: 7, realm_sub_id: 2 }
}

fn chain(epoch: u64, height: u64, seed: u64) -> anyhow::Result<CanonicalChainRef<PHash>> {
    Ok(CanonicalChainRef::new(
        NetworkId::try_from_chain_id(1337)?,
        ChainEpoch::new(epoch),
        CheckpointRef::new(
            CheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(PHash::from_values(
                seed, seed + 1, seed + 2, seed + 3,
            )),
        ),
    ))
}

fn request_and_freeze() -> anyhow::Result<(
    BranchExactSchemaMaterializationRequest,
    BranchExactFrozenLegacyExportPermit<PHash>,
)> {
    let bootstrap = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::PostGenesisFloor,
        chain(0, ROWS as u64 - 1, 10_000)?,
    )?;
    let floor = BranchExactPostGenesisFloorEvidence::new(
        authority(),
        BaselineSnapshotArtifactDigest::try_new([7; 32])?,
        AuthorityManifestDigest::from_persisted([8; 32]),
    );
    let plan = BranchExactSchemaMaterializationPlan::try_new(
        &bootstrap,
        authority(),
        Some(floor),
    )?;
    let request = BranchExactSchemaMaterializationRequest::try_new(
        CqlKeyspaceName::try_new(KEYSPACE)?,
        plan,
    )?;
    let freeze = BranchExactFrozenLegacyExportPermit::try_new(
        request.clone(),
        *bootstrap.candidate(),
        BranchExactLegacyFreezeReason::AllAuthorityProcessorsStoppedAndDrained,
    )?;
    Ok((request, freeze))
}

fn artifact() -> anyhow::Result<BranchExactBackfillArtifact<PHash>> {
    let proof = TagTreeMerkleProof::<PHash>::new_empty();
    let rows = (0..ROWS)
        .map(|index| {
            Ok(BranchExactBackfillArtifactRow::try_new(
                BranchPendingMapping::new(
                    chain(0, index as u64, 100 + index as u64)?,
                    UniquePendingId::try_new(1_000 + index as u64)?,
                ),
                Some(&proof),
            )?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(BranchExactBackfillArtifact::try_new(authority(), rows)?)
}

async fn connect(target: Option<Ipv4Addr>, consistency: Consistency) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(180)));
    if let Some(ip) = target {
        profile = profile.load_balancing_policy(
            SingleTargetLoadBalancingPolicy::new(
                NodeIdentifier::NodeAddress(SocketAddr::new(IpAddr::V4(ip), 9042)),
                None,
            ),
        );
    }
    Ok(SessionBuilder::new()
        .known_nodes_addr(NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)))
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await?)
}

async fn create_keyspaces(session: &Session) -> anyhow::Result<()> {
    session.query_unpaged(
        format!("CREATE KEYSPACE IF NOT EXISTS {KEYSPACE} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
        &[],
    ).await?;
    session.query_unpaged(
        format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}", control_keyspace()),
        &[],
    ).await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn create_legacy_tables(session: &Session) -> anyhow::Result<()> {
    for table in ["checkpoint_id_to_pending_id_table", "pending_id_to_checkpoint_id_table"] {
        session.query_unpaged(
            format!("CREATE TABLE IF NOT EXISTS {KEYSPACE}.{table} (obj_id bigint PRIMARY KEY, value bigint)"),
            &[],
        ).await?;
    }
    session.query_unpaged(
        format!("CREATE TABLE IF NOT EXISTS {KEYSPACE}.checkpointed_object_table (obj_id bigint, checkpoint_id bigint, value blob, PRIMARY KEY ((obj_id), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id DESC)"),
        &[],
    ).await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn seed_legacy(session: &Session, artifact: &BranchExactBackfillArtifact<PHash>) -> anyhow::Result<()> {
    for row in artifact.rows() {
        let height = row.mapping().canonical_chain().checkpoint().checkpoint_id().get() as i64;
        let pending = row.mapping().pending_id().get() as i64;
        session.query_unpaged(
            format!("INSERT INTO {KEYSPACE}.checkpoint_id_to_pending_id_table (obj_id, value) VALUES (?, ?)"),
            (height, pending),
        ).await?;
        session.query_unpaged(
            format!("INSERT INTO {KEYSPACE}.pending_id_to_checkpoint_id_table (obj_id, value) VALUES (?, ?)"),
            (pending, height),
        ).await?;
        let proof = row.reward_proof_canonical().context("Realm artifact proof")?;
        session.query_unpaged(
            format!("INSERT INTO {KEYSPACE}.checkpointed_object_table (obj_id, checkpoint_id, value) VALUES (?, ?, ?)"),
            (2_i64, pending, crate::compression::compress(proof)?),
        ).await?;
    }
    Ok(())
}

async fn topology() -> anyhow::Result<BranchExactExpectedTopology> {
    let nodes = join_all(NODE_IPS.map(|ip| async move {
        let session = connect(Some(ip), Consistency::One).await?;
        let host_id = session.query_unpaged("SELECT host_id FROM system.local", &[]).await?
            .into_rows_result()?.single_row::<(Uuid,)>()?.0;
        Ok::<_, anyhow::Error>(BranchExactScyllaNodeId::from_uuid(host_id)?)
    })).await.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok(BranchExactExpectedTopology::try_new(nodes)?)
}

async fn deploy_and_backfill(
    session: Arc<Session>,
    request: &BranchExactSchemaMaterializationRequest,
    artifact: &BranchExactBackfillArtifact<PHash>,
) -> anyhow::Result<BranchExactBackfillVerifiedReceipt> {
    let topology = topology().await?;
    let schema = BranchExactSchemaMaterializer::materialize_schema(&session, request).await?;
    let observations = join_all(NODE_IPS.map(|ip| {
        let keyspace = request.keyspace().clone();
        async move {
            inspect_branch_exact_local_node_postflight(&connect(Some(ip), Consistency::One).await?, &keyspace, authority()).await
        }
    })).await.into_iter().collect::<Result<Vec<_>, _>>()?;
    let intent = BranchExactDeploymentIntent::new(request, topology.clone());
    let attestation = BranchExactTopologyAttestation::try_new(&schema, topology, observations)?;
    let deployment = BranchExactVerifiedDeploymentReceipt::try_new(intent.clone(), attestation)?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(control_keyspace())?;
    ScyllaBranchExactDeploymentLifecycleStore::create_schema(&session, &control).await?;
    let lifecycle = ScyllaBranchExactDeploymentLifecycleStore::prepare(session.clone(), control).await?;
    let bootstrap = BranchExactDeploymentLifecycleBootstrap::new(intent);
    lifecycle.bootstrap(&bootstrap).await?;
    let schema_cas = SealedBranchExactSchemaVerifiedCas::try_new(bootstrap.candidate(), deployment.clone())?;
    lifecycle.mark_schema_verified(&schema_cas).await?;
    let plan = BranchExactBackfillPlan::post_genesis_artifact(
        request,
        deployment,
        artifact.dataset_digest(),
        CommitWriteTimestampUs::try_from_i128(1_700_000_000_000_000)?,
        CHUNKS,
        artifact.pair_rows_per_direction(),
        artifact.proof_rows(),
    )?;
    let planned = SealedBranchExactBackfillPlanCas::try_new(schema_cas.candidate(), plan.clone())?;
    lifecycle.plan_backfill(&planned).await?;
    let executor = ScyllaBranchExactBackfillExecutor::prepare(session, &plan).await?;
    let mut current = planned.candidate().clone();
    for index in 0..CHUNKS {
        let receipt = executor.execute_chunk(&plan, artifact, index).await?;
        let sealed = SealedBranchExactBackfillChunkCas::try_new(&current, receipt)?;
        lifecycle.record_backfill_chunk(&sealed).await?;
        current = sealed.candidate().clone();
    }
    let observation = executor.verify_artifact_readback(&plan, artifact).await?;
    let verified = SealedBranchExactBackfillVerifiedCas::try_new(&current, observation)?;
    lifecycle.mark_backfill_verified(&verified).await?;
    let BranchExactDeploymentLifecycleState::BackfillVerified(receipt) = verified.candidate().state() else { bail!("expected BACKFILL_VERIFIED") };
    Ok(receipt.clone())
}

async fn core() -> anyhow::Result<ScyllaCoreStore<PHash, PoseidonHasher>> {
    ScyllaCoreStore::new(7, 2, KEYSPACE.to_owned(), &NODE_IPS.map(|ip| ip.to_string())).await
}

fn run_command(mut command: Command, label: &str) -> anyhow::Result<String> {
    let output = command.output().with_context(|| format!("run {label}"))?;
    if !output.status.success() {
        bail!("{label} failed: stdout={} stderr={}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn compose(file: &Path, args: &[&str], label: &str) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command.arg("compose").arg("-f").arg(file).args(args);
    run_command(command, label)
}

fn nodetool(container: &str, args: &[&str], label: &str) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command.arg("exec").arg(container).arg("nodetool").args(args);
    run_command(command, label)
}

async fn wait_up(count: usize) -> anyhow::Result<()> {
    for _ in 0..90 {
        let status = nodetool(NODE_CONTAINERS[0], &["status"], "h21 status")?;
        if status.lines().filter(|line| line.starts_with("UN ")).count() == count { return Ok(()); }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("h21 cluster did not converge to {count} nodes")
}

#[derive(Serialize)]
struct H21Report {
    baseline: &'static str,
    image: &'static str,
    replication_factor: u8,
    rows: usize,
    proofs: usize,
    clean_audit_ms: u64,
    extra_row_blocked: bool,
    legacy_read_through_blocked: bool,
    same_height_hash_new_epoch_blocked: bool,
    one_replica_offline: bool,
    unknown_lwt_response_readback_idempotent: bool,
    mismatch_dominates_verified: bool,
    repair_all_rows_direct_one_equal: bool,
    legacy_adapter_served_old_value: bool,
    qualification: &'static str,
}

#[derive(Debug, Eq, PartialEq)]
struct DirectReplicaSnapshot {
    legacy_forward: BTreeSet<(i64, i64)>,
    legacy_reverse: BTreeSet<(i64, i64)>,
    legacy_proofs: BTreeSet<(i64, Vec<u8>)>,
    target_forward: BTreeSet<(Vec<u8>, i64)>,
    target_reverse: BTreeSet<(i64, Vec<u8>)>,
    target_proofs: BTreeSet<(i64, Vec<u8>)>,
    audit: BranchExactShadowAuditReadState,
}

async fn direct_replica_snapshot(
    ip: Ipv4Addr,
    control: &BranchExactDeploymentNoTabletKeyspace,
    slot: BranchExactShadowAuditSlot,
) -> anyhow::Result<DirectReplicaSnapshot> {
    let session = Arc::new(connect(Some(ip), Consistency::One).await?);
    let legacy_forward = session
        .query_unpaged(
            format!("SELECT obj_id, value FROM {KEYSPACE}.checkpoint_id_to_pending_id_table"),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, i64)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let legacy_reverse = session
        .query_unpaged(
            format!("SELECT obj_id, value FROM {KEYSPACE}.pending_id_to_checkpoint_id_table"),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, i64)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let legacy_proofs = session
        .query_unpaged(
            format!("SELECT checkpoint_id, value FROM {KEYSPACE}.checkpointed_object_table WHERE obj_id = ?"),
            (2_i64,),
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let target_forward = session
        .query_unpaged(
            format!("SELECT canonical_ref, pending_id FROM {KEYSPACE}.{BRANCH_TO_PENDING_TABLE}"),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(Vec<u8>, i64)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let target_reverse = session
        .query_unpaged(
            format!("SELECT pending_id, canonical_ref FROM {KEYSPACE}.{PENDING_TO_BRANCH_TABLE}"),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let target_proofs = session
        .query_unpaged(
            format!("SELECT pending_id, value FROM {KEYSPACE}.{PENDING_REWARD_PROOF_TABLE}"),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let audit = ScyllaBranchExactShadowAuditStore::prepare(
        session,
        control.clone(),
    )
    .await?
    .read(slot)
    .await?;
    Ok(DirectReplicaSnapshot {
        legacy_forward,
        legacy_reverse,
        legacy_proofs,
        target_forward,
        target_reverse,
        target_proofs,
        audit,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h21_branch_exact_shadow_reader_rf3_gate() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_D04B6H21_RF3").as_deref() == Ok("1"));
    let compose_file = std::env::var("PSY_D04B6H21_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D04B6H21_REPORT_PATH")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    create_legacy_tables(&session).await?;
    let (request, freeze) = request_and_freeze()?;
    let artifact = artifact()?;
    seed_legacy(&session, &artifact).await?;
    let verified = deploy_and_backfill(session.clone(), &request, &artifact).await?;
    let source = BranchExactLegacyExportReceipt::test_fixture_for_permit(
        &freeze,
        artifact.dataset_digest(), artifact.pair_rows_per_direction(), artifact.proof_rows(),
    );

    let core = core().await?;
    core.initialize_branch_exact_schema_setup(
        authority(),
        BranchExactSchemaSetupMode::RequireVerified(BranchExactSchemaSetupRequest::new(verified.clone())),
    ).await?;
    let reader = core.prepare_branch_exact_shadow_reader().await?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(control_keyspace())?;
    ScyllaBranchExactShadowAuditStore::create_schema(&session, &control).await?;
    let audit_store = ScyllaBranchExactShadowAuditStore::prepare(session.clone(), control.clone()).await?;

    // Extra target state must make a new generation terminal BLOCKED.
    let orphan = BranchPendingMapping::new(chain(0, 9_999, 55_000)?, UniquePendingId::try_new(99_999)?);
    session.query_unpaged(
        format!("INSERT INTO {KEYSPACE}.{BRANCH_TO_PENDING_TABLE} (canonical_ref, pending_id) VALUES (?, ?) USING TIMESTAMP ?"),
        (orphan.canonical_chain_bytes().as_slice(), 99_999_i64, 1_700_000_000_000_001_i64),
    ).await?;
    let blocked = ScyllaBranchExactShadowAuditExecutor::run(
        &audit_store, &reader, &artifact, &source, &freeze, BranchExactShadowAuditGeneration::try_new(1)?,
    ).await;
    ensure!(matches!(blocked, Err(BranchExactShadowAuditRunError::Comparison { .. })));
    session.query_unpaged(
        format!("DELETE FROM {KEYSPACE}.{BRANCH_TO_PENDING_TABLE} WHERE canonical_ref = ? AND pending_id = ?"),
        (orphan.canonical_chain_bytes().as_slice(), 99_999_i64),
    ).await?;

    // The shadow path must reproduce the real legacy <= pending serving read,
    // observe the predecessor, and then fail closed on read-through.
    let proof_pending = artifact.rows()[10].mapping().pending_id().get() as i64;
    let proof_bytes = artifact.rows()[10].reward_proof_canonical().unwrap();
    session.query_unpaged(
        format!("DELETE FROM {KEYSPACE}.checkpointed_object_table WHERE obj_id = ? AND checkpoint_id = ?"),
        (2_i64, proof_pending),
    ).await?;
    let missing_proof = reader.compare_and_serve_reward_proof(&artifact.rows()[10]).await;
    ensure!(matches!(
        missing_proof,
        Err(BranchExactShadowReadError::LegacyReadThrough {
            requested_pending_id,
            returned_pending_id,
        }) if requested_pending_id == proof_pending as u64
            && returned_pending_id == proof_pending as u64 - 1
    ));
    session.query_unpaged(
        format!("INSERT INTO {KEYSPACE}.checkpointed_object_table (obj_id, checkpoint_id, value) VALUES (?, ?, ?)"),
        (2_i64, proof_pending, crate::compression::compress(proof_bytes)?),
    ).await?;

    // Legacy height->pending still agrees, so only the full canonical identity
    // can reject this same-height/hash, new-epoch branch.
    let active = *artifact.rows()[10].mapping();
    let same_height_new_epoch = BranchPendingMapping::new(
        CanonicalChainRef::new(
            active.canonical_chain().network_id(),
            ChainEpoch::new(1),
            *active.canonical_chain().checkpoint(),
        ),
        active.pending_id(),
    );
    let orphan_result = reader.compare_and_serve_mapping(&same_height_new_epoch).await;
    ensure!(matches!(
        orphan_result,
        Err(BranchExactShadowReadError::TargetCardinality {
            direction: BranchExactShadowDirection::TargetForward,
            actual: 0,
        })
    ));

    let served = reader
        .compare_and_serve_mapping(artifact.rows()[0].mapping())
        .await?;
    ensure!(served.served_pending_id() == artifact.rows()[0].mapping().pending_id());

    compose(Path::new(&compose_file), &["stop", "scylla3"], "stop h21 replica")?;
    wait_up(2).await?;
    let started = Instant::now();
    let completed = ScyllaBranchExactShadowAuditExecutor::run(
        &audit_store, &reader, &artifact, &source, &freeze, BranchExactShadowAuditGeneration::try_new(2)?,
    ).await?;
    ensure!(matches!(completed, BranchExactShadowAuditExecutionOutcome::Verified(_)));
    let clean_audit_ms = started.elapsed().as_millis() as u64;
    let retried = ScyllaBranchExactShadowAuditExecutor::run(
        &audit_store, &reader, &artifact, &source, &freeze, BranchExactShadowAuditGeneration::try_new(2)?,
    ).await?;
    ensure!(matches!(retried, BranchExactShadowAuditExecutionOutcome::Idempotent(_)));

    compose(Path::new(&compose_file), &["start", "scylla3"], "start h21 replica")?;
    wait_up(3).await?;

    // Exercise the actual LWT race shape.  A clean candidate wins first, a
    // stale mismatch CAS observes that VERIFIED value, and the mismatch then
    // monotonically advances it to BLOCKED at revision 2.
    let race_generation = BranchExactShadowAuditGeneration::try_new(3)?;
    let race_plan = BranchExactShadowAuditPlan::try_new(
        race_generation,
        reader.setup_view().digest(),
        artifact.dataset_digest(),
        &source,
    )?;
    let race_bootstrap = BranchExactShadowAuditBootstrap::new(race_plan.clone());
    let race_initial = match audit_store.bootstrap(&race_bootstrap).await? {
        BranchExactShadowAuditWriteOutcome::Applied(current)
        | BranchExactShadowAuditWriteOutcome::Idempotent(current) => current,
        BranchExactShadowAuditWriteOutcome::Conflict(_) => bail!("unexpected h21 race slot conflict"),
    };
    let observation = reader.audit_artifact(&artifact).await?;
    let verified_receipt = BranchExactShadowVerifiedReceipt::try_new(
        race_plan.clone(),
        &observation,
    )?;
    let verify_cas = SealedBranchExactShadowAuditCas::verify(
        &race_initial,
        verified_receipt,
    )?;
    let blocked_receipt = BranchExactShadowBlockedReceipt::from_error(
        race_plan,
        &BranchExactShadowReadError::DatasetMismatch,
    );
    let stale_block_cas = SealedBranchExactShadowAuditCas::block(
        &race_initial,
        blocked_receipt.clone(),
    )?;
    ensure!(matches!(
        audit_store.compare_and_set(&verify_cas).await?,
        BranchExactShadowAuditWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        audit_store
            .reconcile_unknown_outcome_for_test(verify_cas.candidate())
            .await?,
        BranchExactShadowAuditWriteOutcome::Idempotent(_)
    ));
    let verified_current = match audit_store.compare_and_set(&stale_block_cas).await? {
        BranchExactShadowAuditWriteOutcome::Conflict(current) => current,
        other => bail!("stale mismatch did not conflict with VERIFIED: {other:?}"),
    };
    let dominant_block = SealedBranchExactShadowAuditCas::block(
        &verified_current,
        blocked_receipt,
    )?;
    ensure!(matches!(
        audit_store.compare_and_set(&dominant_block).await?,
        BranchExactShadowAuditWriteOutcome::Applied(_)
    ));
    let BranchExactShadowAuditReadState::Current(race_terminal) =
        audit_store.read(race_bootstrap.candidate().slot()).await?
    else {
        bail!("h21 race state disappeared")
    };
    ensure!(race_terminal.revision() == 2);
    ensure!(matches!(race_terminal.state(), BranchExactShadowAuditState::Blocked(_)));

    nodetool(NODE_CONTAINERS[0], &["cluster", "repair", KEYSPACE], "repair h21 target")?;
    for node in NODE_CONTAINERS {
        nodetool(node, &["repair", "-pr", &control_keyspace()], "repair h21 control")?;
        nodetool(node, &["flush", KEYSPACE], "flush h21 target")?;
        nodetool(node, &["flush", &control_keyspace()], "flush h21 control")?;
        nodetool(node, &["compact", KEYSPACE], "compact h21 target")?;
        nodetool(node, &["compact", &control_keyspace()], "compact h21 control")?;
    }

    let generation = BranchExactShadowAuditGeneration::try_new(3)?;
    let plan = BranchExactShadowAuditPlan::try_new(
        generation, reader.setup_view().digest(), artifact.dataset_digest(), &source,
    )?;
    let direct = join_all(
        NODE_IPS.map(|ip| direct_replica_snapshot(ip, &control, plan.slot())),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    ensure!(direct.windows(2).all(|pair| pair[0] == pair[1]));

    let report = H21Report {
        baseline: BASELINE,
        image: IMAGE,
        replication_factor: 3,
        rows: ROWS,
        proofs: ROWS,
        clean_audit_ms,
        extra_row_blocked: true,
        legacy_read_through_blocked: true,
        same_height_hash_new_epoch_blocked: true,
        one_replica_offline: true,
        unknown_lwt_response_readback_idempotent: true,
        mismatch_dominates_verified: true,
        repair_all_rows_direct_one_equal: true,
        legacy_adapter_served_old_value: true,
        qualification: "PASS",
    };
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
