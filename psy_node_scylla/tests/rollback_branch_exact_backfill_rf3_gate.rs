use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use futures::future::join_all;
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
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
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
    },
    manifest_record::AuthorityManifestDigest,
    timestamp::CommitWriteTimestampUs,
    typed::UniquePendingId,
};
use psy_node_scylla::rollback::{
    decode_branch_exact_deployment_lifecycle_persisted_cells,
    inspect_branch_exact_local_node_postflight,
    BranchExactBackfillArtifact, BranchExactBackfillArtifactRow,
    BranchExactBackfillExecutionBoundary, BranchExactBackfillPlan,
    BranchExactDeploymentIntent, BranchExactDeploymentLifecycleBootstrap,
    BranchExactDeploymentLifecycleReadState,
    BranchExactDeploymentLifecycleState,
    BranchExactDeploymentLifecycleWriteOutcome,
    BranchExactDeploymentNoTabletKeyspace, BranchExactExpectedTopology,
    BranchExactQueries, BranchExactQueryId,
    BranchExactSchemaMaterializationRequest, BranchExactSchemaMaterializer,
    BranchExactScyllaNodeId, BranchExactTopologyAttestation,
    BranchExactVerifiedDeploymentReceipt, CqlKeyspaceName,
    ScyllaBranchExactBackfillExecutor,
    ScyllaBranchExactDeploymentLifecycleStore,
    SealedBranchExactBackfillChunkCas, SealedBranchExactBackfillPlanCas,
    SealedBranchExactBackfillVerifiedCas,
    SealedBranchExactSchemaVerifiedCas,
    StoredBranchExactDeploymentLifecycle,
    BRANCH_EXACT_DEPLOYMENT_LIFECYCLE_TABLE,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
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

const TARGET_KEYSPACE: &str = "psy_d04b6h18_realm";
const CONTROL_KEYSPACE: &str = "psy_d04b6h18_control_nt";
const BASELINE: &str = "8e1c3b971e9f79496a8c4451af2e7f33934ed98f";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const ARTIFACT_ROWS: usize = 1_002;
const ARTIFACT_CHUNKS: u32 = 20;
const WRITE_TIMESTAMP_US: i64 = 1_700_000_000_000_000;
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

fn authority() -> AuthorityScope {
    AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    }
}

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
}

fn bootstrap(seed: u64) -> anyhow::Result<CanonicalHeadBootstrap<PHash>> {
    Ok(CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::PostGenesisFloor,
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337)?,
            ChainEpoch::new(0),
            CheckpointRef::new(
                CheckpointId::new(1_000),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    seed,
                    seed + 1,
                    seed + 2,
                    seed + 3,
                )),
            ),
        ),
    )?)
}

fn request(seed: u64) -> anyhow::Result<BranchExactSchemaMaterializationRequest> {
    let floor = BranchExactPostGenesisFloorEvidence::new(
        authority(),
        BaselineSnapshotArtifactDigest::try_new([7; 32])?,
        AuthorityManifestDigest::from_persisted([8; 32]),
    );
    let plan = BranchExactSchemaMaterializationPlan::try_new(
        &bootstrap(seed)?,
        authority(),
        Some(floor),
    )?;
    Ok(BranchExactSchemaMaterializationRequest::try_new(
        CqlKeyspaceName::try_new(TARGET_KEYSPACE)?,
        plan,
    )?)
}

fn artifact() -> anyhow::Result<BranchExactBackfillArtifact<PHash>> {
    let proof = TagTreeMerkleProof::<PHash>::new_empty();
    let mut rows = Vec::with_capacity(ARTIFACT_ROWS);
    for index in 0..ARTIFACT_ROWS {
        let (epoch, height, hash_seed) = if index == ARTIFACT_ROWS - 2 {
            // Same height as the first row, but a different checkpoint hash.
            (0, 1, 50_000)
        } else if index == ARTIFACT_ROWS - 1 {
            // Same height and hash as the first row, but a new chain epoch.
            (1, 1, 1)
        } else {
            (0, index as u64 + 1, index as u64 + 1)
        };
        let mapping = BranchPendingMapping::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337)?,
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(height),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        hash_seed,
                        hash_seed + 1,
                        hash_seed + 2,
                        hash_seed + 3,
                    )),
                ),
            ),
            UniquePendingId::try_new(100_000 + index as u64)?,
        );
        rows.push(BranchExactBackfillArtifactRow::try_new(
            mapping,
            (index % 100 == 0).then_some(&proof),
        )?);
    }
    Ok(BranchExactBackfillArtifact::try_new(authority(), rows)?)
}

async fn connect(
    target: Option<Ipv4Addr>,
    consistency: Consistency,
) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(180)));
    if let Some(ip) = target {
        profile = profile.load_balancing_policy(
            SingleTargetLoadBalancingPolicy::new(
                NodeIdentifier::NodeAddress(SocketAddr::new(
                    IpAddr::V4(ip),
                    9042,
                )),
                None,
            ),
        );
    }
    SessionBuilder::new()
        .known_nodes_addr(
            NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)),
        )
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await
        .context("connect to isolated D-04b6h18 RF=3 Scylla cluster")
}

async fn create_keyspaces(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {TARGET_KEYSPACE} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {CONTROL_KEYSPACE} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn expected_topology() -> anyhow::Result<BranchExactExpectedTopology> {
    let nodes = join_all(NODE_IPS.map(|ip| async move {
        let session = connect(Some(ip), Consistency::One).await?;
        let host_id = session
            .query_unpaged("SELECT host_id FROM system.local", &[])
            .await?
            .into_rows_result()?
            .single_row::<(Uuid,)>()?
            .0;
        Ok::<_, anyhow::Error>(BranchExactScyllaNodeId::from_uuid(host_id)?)
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    Ok(BranchExactExpectedTopology::try_new(nodes)?)
}

async fn verified_receipt(
    request: &BranchExactSchemaMaterializationRequest,
    intent: BranchExactDeploymentIntent,
    topology: BranchExactExpectedTopology,
) -> anyhow::Result<BranchExactVerifiedDeploymentReceipt> {
    let session = connect(None, Consistency::Quorum).await?;
    let schema_receipt =
        BranchExactSchemaMaterializer::materialize_schema(&session, request)
            .await?;
    let observations = join_all(NODE_IPS.map(|ip| {
        let keyspace = request.keyspace().clone();
        async move {
            let targeted = connect(Some(ip), Consistency::One).await?;
            inspect_branch_exact_local_node_postflight(
                &targeted,
                &keyspace,
                authority(),
            )
            .await
        }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    Ok(BranchExactVerifiedDeploymentReceipt::try_new(
        intent,
        BranchExactTopologyAttestation::try_new(
            &schema_receipt,
            topology,
            observations,
        )?,
    )?)
}

fn current(
    state: BranchExactDeploymentLifecycleReadState,
) -> anyhow::Result<StoredBranchExactDeploymentLifecycle> {
    match state {
        BranchExactDeploymentLifecycleReadState::Current(current) => Ok(current),
        BranchExactDeploymentLifecycleReadState::Uninitialized => {
            bail!("deployment lifecycle unexpectedly uninitialized")
        }
    }
}

fn run_command(mut command: Command, description: &str) -> anyhow::Result<String> {
    let output = command
        .output()
        .with_context(|| format!("start {description}"))?;
    if !output.status.success() {
        bail!(
            "{description} failed ({}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn docker_exec(
    container: &str,
    args: &[&str],
    description: &str,
) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command.arg("exec").arg(container).args(args);
    run_command(command, description)
}

fn compose(
    compose_file: &Path,
    args: &[&str],
    description: &str,
) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .args(args);
    run_command(command, description)
}

fn cluster_status() -> anyhow::Result<String> {
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "status"],
        "read D-04b6h18 RF=3 cluster status",
    )
}

async fn wait_for_up_nodes(expected: usize) -> anyhow::Result<String> {
    for _ in 0..90 {
        let status = cluster_status()?;
        if status
            .lines()
            .filter(|line| line.starts_with("UN "))
            .count()
            == expected
        {
            return Ok(status);
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!(
        "cluster did not converge to {expected} Up/Normal nodes: {}",
        cluster_status()?
    )
}

fn read_memory_kib(label: &str) -> anyhow::Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with(label))
        .with_context(|| format!("{label} missing from /proc/self/status"))?;
    line.split_ascii_whitespace()
        .nth(1)
        .context("memory status value is missing")?
        .parse()
        .context("parse memory status KiB")
}

#[derive(Clone, Debug, Serialize)]
struct MaintenanceTiming {
    target_repair_ms: u64,
    control_repair_ms: u64,
    flush_ms: u64,
    compact_ms: u64,
}

fn repair_flush_compact() -> anyhow::Result<MaintenanceTiming> {
    let started = Instant::now();
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", TARGET_KEYSPACE],
        "repair D-04b6h18 tablet target keyspace",
    )?;
    let target_repair_ms = started.elapsed().as_millis() as u64;

    let started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", CONTROL_KEYSPACE],
            "repair D-04b6h18 no-tablet control ranges",
        )?;
    }
    let control_repair_ms = started.elapsed().as_millis() as u64;

    let started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(node, &["nodetool", "flush", TARGET_KEYSPACE], "flush target")?;
        docker_exec(node, &["nodetool", "flush", CONTROL_KEYSPACE], "flush control")?;
    }
    let flush_ms = started.elapsed().as_millis() as u64;

    let started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(node, &["nodetool", "compact", TARGET_KEYSPACE], "compact target")?;
        docker_exec(node, &["nodetool", "compact", CONTROL_KEYSPACE], "compact control")?;
    }
    Ok(MaintenanceTiming {
        target_repair_ms,
        control_repair_ms,
        flush_ms,
        compact_ms: started.elapsed().as_millis() as u64,
    })
}

type ScanSets = (
    BTreeSet<(Vec<u8>, i64)>,
    BTreeSet<(i64, Vec<u8>)>,
    BTreeSet<(i64, Vec<u8>)>,
);

fn expected_scan_sets(artifact: &BranchExactBackfillArtifact<PHash>) -> ScanSets {
    let forward = artifact
        .rows()
        .iter()
        .map(|row| {
            (
                row.mapping().canonical_chain_bytes().to_vec(),
                row.mapping().pending_id().get() as i64,
            )
        })
        .collect();
    let reverse = artifact
        .rows()
        .iter()
        .map(|row| {
            (
                row.mapping().pending_id().get() as i64,
                row.mapping().canonical_chain_bytes().to_vec(),
            )
        })
        .collect();
    let proofs = artifact
        .rows()
        .iter()
        .filter_map(|row| {
            row.reward_proof_canonical().map(|proof| {
                (row.mapping().pending_id().get() as i64, proof.to_vec())
            })
        })
        .collect();
    (forward, reverse, proofs)
}

async fn direct_one_scan(session: &Session) -> anyhow::Result<ScanSets> {
    let keyspace = CqlKeyspaceName::try_new(TARGET_KEYSPACE)?;
    let queries = BranchExactQueries::new(&keyspace);
    let forward = session
        .query_unpaged(
            queries.get(BranchExactQueryId::ScanBranchToPending).cql(),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(Vec<u8>, i64)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let reverse = session
        .query_unpaged(
            queries.get(BranchExactQueryId::ScanPendingToBranch).cql(),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, Vec<u8>)>()?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut proofs = BTreeSet::new();
    for row in session
        .query_unpaged(
            queries.get(BranchExactQueryId::ScanPendingRewardProof).cql(),
            &[],
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, Vec<u8>)>()?
    {
        let (pending, stored) = row?;
        let proof = TagTreeMerkleProof::<PHash>::psy_ser_from_owned_bytes_vec(
            psy_node_scylla::compression::decompress(&stored)?,
        )?;
        proofs.insert((pending, proof.psy_ser_to_bytes_vec()?));
    }
    Ok((forward, reverse, proofs))
}

async fn direct_one_lifecycle(
    session: &Session,
    expected: &StoredBranchExactDeploymentLifecycle,
) -> anyhow::Result<StoredBranchExactDeploymentLifecycle> {
    let row = session
        .query_unpaged(
            format!(
                "SELECT deployment_slot, revision, lifecycle FROM \
                 {CONTROL_KEYSPACE}.{BRANCH_EXACT_DEPLOYMENT_LIFECYCLE_TABLE} \
                 WHERE deployment_slot = ?"
            ),
            (expected.slot().as_bytes().as_slice(),),
        )
        .await?
        .into_rows_result()?
        .single_row::<(Vec<u8>, Option<i64>, Option<Vec<u8>>)>()?;
    Ok(decode_branch_exact_deployment_lifecycle_persisted_cells(
        expected.slot(),
        &row.0,
        row.1,
        row.2.as_deref(),
    )?)
}

async fn inject_extra_rows(
    session: &Session,
    mapping: &BranchPendingMapping<PHash>,
    proof: &TagTreeMerkleProof<PHash>,
) -> anyhow::Result<()> {
    let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new(TARGET_KEYSPACE)?);
    let timestamp = WRITE_TIMESTAMP_US + 100;
    session
        .query_unpaged(
            queries.get(BranchExactQueryId::PutBranchToPending).cql(),
            (
                mapping.canonical_chain_bytes().as_slice(),
                mapping.pending_id().get() as i64,
                timestamp,
            ),
        )
        .await?;
    session
        .query_unpaged(
            queries.get(BranchExactQueryId::PutPendingToBranch).cql(),
            (
                mapping.pending_id().get() as i64,
                mapping.canonical_chain_bytes().as_slice(),
                timestamp,
            ),
        )
        .await?;
    let proof_bytes = proof.psy_ser_to_bytes_vec()?;
    let stored = psy_node_scylla::compression::compress(&proof_bytes)?;
    session
        .query_unpaged(
            queries.get(BranchExactQueryId::PutPendingRewardProof).cql(),
            (mapping.pending_id().get() as i64, stored, timestamp),
        )
        .await?;
    Ok(())
}

async fn delete_extra_rows(
    session: &Session,
    mapping: &BranchPendingMapping<PHash>,
) -> anyhow::Result<()> {
    let timestamp = WRITE_TIMESTAMP_US + 101;
    session
        .query_unpaged(
            format!(
                "DELETE FROM {TARGET_KEYSPACE}.canonical_chain_ref_to_pending_id_table \
                 USING TIMESTAMP ? WHERE canonical_ref = ? AND pending_id = ?"
            ),
            (
                timestamp,
                mapping.canonical_chain_bytes().as_slice(),
                mapping.pending_id().get() as i64,
            ),
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "DELETE FROM {TARGET_KEYSPACE}.pending_id_to_canonical_chain_ref_table \
                 USING TIMESTAMP ? WHERE pending_id = ? AND canonical_ref = ?"
            ),
            (
                timestamp,
                mapping.pending_id().get() as i64,
                mapping.canonical_chain_bytes().as_slice(),
            ),
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "DELETE FROM {TARGET_KEYSPACE}.pending_reward_top_proof_table \
                 USING TIMESTAMP ? WHERE pending_id = ?"
            ),
            (timestamp, mapping.pending_id().get() as i64),
        )
        .await?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct D04b6h18Report {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    target_keyspace: &'static str,
    control_keyspace: &'static str,
    artifact_rows: usize,
    artifact_bytes: usize,
    proof_rows: u64,
    chunks: u32,
    write_timestamp_us: i64,
    copy_with_crash_retry_ms: u64,
    clean_scan_ms: u64,
    same_artifact_retry_ms: u64,
    planned_to_verified_rto_ms: u64,
    vm_rss_before_kib: u64,
    vm_hwm_after_kib: u64,
    maintenance: MaintenanceTiming,
    topology_before: String,
    topology_after: String,
    scenarios_passed: Vec<&'static str>,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn d04b6h18_branch_exact_backfill_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H18_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h18.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H18_COMPOSE_FILE")
        .context("PSY_D04B6H18_COMPOSE_FILE is required")?;
    let report_path = std::env::var("PSY_D04B6H18_REPORT_PATH")
        .context("PSY_D04B6H18_REPORT_PATH is required")?;
    let started_unix_ms = unix_ms()?;
    let topology_before = wait_for_up_nodes(3).await?;
    let vm_rss_before_kib = read_memory_kib("VmRSS:")?;

    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let topology = expected_topology().await?;
    let request = request(100)?;
    let intent = BranchExactDeploymentIntent::new(&request, topology.clone());
    let deployment =
        verified_receipt(&request, intent.clone(), topology).await?;

    let control = BranchExactDeploymentNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?;
    ScyllaBranchExactDeploymentLifecycleStore::create_schema(&session, &control)
        .await?;
    let mut store = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        Arc::clone(&session),
        control.clone(),
    )
    .await?;
    let bootstrap = BranchExactDeploymentLifecycleBootstrap::new(intent);
    ensure!(matches!(
        store.bootstrap(&bootstrap).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
    ));
    let schema_expected = current(store.read(bootstrap.slot()).await?)?;
    let schema_transition = SealedBranchExactSchemaVerifiedCas::try_new(
        &schema_expected,
        deployment.clone(),
    )?;
    ensure!(matches!(
        store.mark_schema_verified(&schema_transition).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
    ));

    let artifact = artifact()?;
    let reversed = BranchExactBackfillArtifact::try_new(
        authority(),
        artifact.rows().iter().cloned().rev().collect(),
    )?;
    ensure!(artifact == reversed);
    let plan = BranchExactBackfillPlan::post_genesis_artifact(
        &request,
        deployment,
        artifact.dataset_digest(),
        CommitWriteTimestampUs::try_from_i128(WRITE_TIMESTAMP_US as i128)?,
        ARTIFACT_CHUNKS,
        artifact.pair_rows_per_direction(),
        artifact.proof_rows(),
    )?;
    let plan_expected = current(store.read(bootstrap.slot()).await?)?;
    let plan_transition =
        SealedBranchExactBackfillPlanCas::try_new(&plan_expected, plan.clone())?;
    ensure!(matches!(
        store.plan_backfill(&plan_transition).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
    ));
    let rto_started = Instant::now();
    let copy_started = Instant::now();

    let mut executor = ScyllaBranchExactBackfillExecutor::prepare(
        Arc::clone(&session),
        &plan,
    )
    .await?;
    ensure!(executor.verify_artifact_readback(&plan, &artifact).await.is_err());
    ensure!(matches!(
        current(store.read(bootstrap.slot()).await?)?.state(),
        BranchExactDeploymentLifecycleState::BackfillPlanned(_)
    ));

    for boundary in [
        BranchExactBackfillExecutionBoundary::ChunkStarted,
        BranchExactBackfillExecutionBoundary::MappingPairWritten {
            row_offset: 0,
        },
        BranchExactBackfillExecutionBoundary::RewardProofWritten {
            row_offset: 0,
        },
        BranchExactBackfillExecutionBoundary::PointReadbackComplete {
            row_offset: 0,
        },
    ] {
        let mut injected = false;
        let result = executor
            .execute_chunk_observed(&plan, &artifact, 0, |observed| {
                if !injected
                    && std::mem::discriminant(&observed)
                        == std::mem::discriminant(&boundary)
                {
                    injected = true;
                    bail!("injected process loss at {observed:?}");
                }
                Ok(())
            })
            .await;
        ensure!(injected && result.is_err());
        drop(executor);
        executor = ScyllaBranchExactBackfillExecutor::prepare(
            Arc::clone(&session),
            &plan,
        )
        .await?;
        ensure!(matches!(
            current(store.read(bootstrap.slot()).await?)?.state(),
            BranchExactDeploymentLifecycleState::BackfillPlanned(_)
        ));
    }

    // A complete chunk receipt is still not durable progress.  Reconstructing
    // the executor and replaying the same plan must produce the same receipt.
    let first_receipt = executor.execute_chunk(&plan, &artifact, 0).await?;
    drop(executor);
    executor = ScyllaBranchExactBackfillExecutor::prepare(
        Arc::clone(&session),
        &plan,
    )
    .await?;
    let replayed_receipt = executor.execute_chunk(&plan, &artifact, 0).await?;
    ensure!(first_receipt == replayed_receipt);
    let progress_expected = current(store.read(bootstrap.slot()).await?)?;
    let chunk_zero = SealedBranchExactBackfillChunkCas::try_new(
        &progress_expected,
        replayed_receipt,
    )?;
    let lost_response = store.record_backfill_chunk(&chunk_zero).await?;
    ensure!(matches!(
        lost_response,
        BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
    ));
    drop(store);
    store = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        Arc::clone(&session),
        control.clone(),
    )
    .await?;
    ensure!(matches!(
        store.record_backfill_chunk(&chunk_zero).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Idempotent(_)
    ));

    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop one D-04b6h18 RF=3 replica",
    )?;
    wait_for_up_nodes(2).await?;

    for chunk_index in 1..ARTIFACT_CHUNKS {
        let receipt = executor
            .execute_chunk(&plan, &artifact, chunk_index)
            .await?;
        let expected = current(store.read(bootstrap.slot()).await?)?;
        let sealed =
            SealedBranchExactBackfillChunkCas::try_new(&expected, receipt)?;
        ensure!(matches!(
            store.record_backfill_chunk(&sealed).await?,
            BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
        ));
    }
    let copy_with_crash_retry_ms = copy_started.elapsed().as_millis() as u64;

    let extra_proof = TagTreeMerkleProof::<PHash>::new_empty();
    let extra_mapping = BranchPendingMapping::new(
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337)?,
            ChainEpoch::new(99),
            CheckpointRef::new(
                CheckpointId::new(99_999),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    90_000, 90_001, 90_002, 90_003,
                )),
            ),
        ),
        UniquePendingId::try_new(9_999_999)?,
    );
    inject_extra_rows(&session, &extra_mapping, &extra_proof).await?;
    ensure!(executor.verify_artifact_readback(&plan, &artifact).await.is_err());
    ensure!(matches!(
        current(store.read(bootstrap.slot()).await?)?.state(),
        BranchExactDeploymentLifecycleState::BackfillProgress(_)
    ));
    delete_extra_rows(&session, &extra_mapping).await?;

    let scan_started = Instant::now();
    let observation = executor.verify_artifact_readback(&plan, &artifact).await?;
    let clean_scan_ms = scan_started.elapsed().as_millis() as u64;
    let verified_expected = current(store.read(bootstrap.slot()).await?)?;
    let verified = SealedBranchExactBackfillVerifiedCas::try_new(
        &verified_expected,
        observation,
    )?;
    let lost_verified_response = store.mark_backfill_verified(&verified).await?;
    ensure!(matches!(
        lost_verified_response,
        BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
    ));
    drop(store);
    store = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        Arc::clone(&session),
        control.clone(),
    )
    .await?;
    ensure!(matches!(
        store.mark_backfill_verified(&verified).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Idempotent(_)
    ));
    let durable_verified = current(store.read(bootstrap.slot()).await?)?;
    ensure!(matches!(
        durable_verified.state(),
        BranchExactDeploymentLifecycleState::BackfillVerified(_)
    ));
    let planned_to_verified_rto_ms = rto_started.elapsed().as_millis() as u64;

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart D-04b6h18 RF=3 replica",
    )?;
    wait_for_up_nodes(3).await?;
    let maintenance = repair_flush_compact()?;
    let expected_sets = expected_scan_sets(&artifact);
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        ensure!(
            direct_one_scan(&direct).await? == expected_sets,
            "direct ONE target scan on {ip} did not converge"
        );
        ensure!(
            direct_one_lifecycle(&direct, &durable_verified).await?
                == durable_verified,
            "direct ONE lifecycle read on {ip} did not converge"
        );
    }

    let retry_started = Instant::now();
    for chunk_index in 0..ARTIFACT_CHUNKS {
        executor
            .execute_chunk(&plan, &artifact, chunk_index)
            .await?;
    }
    executor.verify_artifact_readback(&plan, &artifact).await?;
    let same_artifact_retry_ms = retry_started.elapsed().as_millis() as u64;
    ensure!(current(store.read(bootstrap.slot()).await?)? == durable_verified);

    let proof_pending = artifact
        .rows()
        .iter()
        .find(|row| row.reward_proof_canonical().is_some())
        .context("representative artifact must contain a proof")?
        .mapping()
        .pending_id()
        .get() as i64;
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        let observed_timestamp = direct
            .query_unpaged(
                format!(
                    "SELECT writetime(value) FROM {TARGET_KEYSPACE}.pending_reward_top_proof_table WHERE pending_id = ?"
                ),
                (proof_pending,),
            )
            .await?
            .into_rows_result()?
            .single_row::<(i64,)>()?
            .0;
        ensure!(observed_timestamp == WRITE_TIMESTAMP_US);
    }

    let topology_after = wait_for_up_nodes(3).await?;
    let scylla_release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read Scylla release",
    )?
    .trim()
    .to_owned();
    let report = D04b6h18Report {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release,
        replication_factor: 3,
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        target_keyspace: TARGET_KEYSPACE,
        control_keyspace: CONTROL_KEYSPACE,
        artifact_rows: ARTIFACT_ROWS,
        artifact_bytes: artifact.to_canonical_bytes().len(),
        proof_rows: artifact.proof_rows(),
        chunks: ARTIFACT_CHUNKS,
        write_timestamp_us: WRITE_TIMESTAMP_US,
        copy_with_crash_retry_ms,
        clean_scan_ms,
        same_artifact_retry_ms,
        planned_to_verified_rto_ms,
        vm_rss_before_kib,
        vm_hwm_after_kib: read_memory_kib("VmHWM:")?,
        maintenance,
        topology_before,
        topology_after,
        scenarios_passed: vec![
            "canonical artifact is deterministic across reversed input",
            "missing target rows cannot produce a readback observation or VERIFIED lifecycle",
            "chunk-start, mapping-pair, proof, and point-readback process-loss retries reuse one sealed plan",
            "chunk receipt is deterministic before durable progress CAS",
            "lost progress-CAS response reconciles as exact idempotent success",
            "QUORUM copy and lifecycle progress continue with one replica offline",
            "extra forward, reverse, and proof rows prevent VERIFIED",
            "lost final-CAS response reconciles as exact idempotent success",
            "tablet/no-tablet repair plus flush/compact converges all direct-ONE replicas",
            "same artifact rerun preserves timestamp, exact data, and durable lifecycle",
            "same height different hash and same hash new epoch remain distinct",
        ],
        qualification: "isolated D-04b6h18 RF=3 Gate for branch-exact backfill/lifecycle only; no exporter, production setup, reader/writer cutover, or rollback executor",
    };
    if let Some(parent) = Path::new(&report_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
