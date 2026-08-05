use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs, NewBranchWriteTimestampUs},
    typed::{
        CheckpointId, CheckpointRootKey, LogicalMutation, MerkleNode, MutationValue, NodeIndex,
        TypedTableKey,
    },
};
use psy_node_scylla::{compression, rollback::*};
use scylla::{
    client::{execution_profile::ExecutionProfile, session::Session, session_builder::SessionBuilder},
    policies::load_balancing::{NodeIdentifier, SingleTargetLoadBalancingPolicy},
    statement::Consistency,
};
use serde::Serialize;
use tokio::time::sleep;

const KEYSPACE: &str = "psy_g002_rf3";
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
const POSITIONS: u64 = 64;
const TARGET: u64 = 100;
const SUFFIX_VERSIONS: u64 = 32;
const OLD_HEAD: u64 = TARGET + SUFFIX_VERSIONS;
const POINT_LEVEL: u8 = 10;
const RANGE_LEVEL: u8 = 11;
const OLD_WRITE_TS: i64 = 1_000_000;
const DELETE_FENCE_TS: i64 = 2_000_000;
const NEW_WRITE_TS: i64 = 3_000_000;
const OLD_VALUE: [u8; 32] = [0x11; 32];
const NEW_VALUE: [u8; 32] = [0x22; 32];
const BASELINE: &str = "9c3e2d27e919ca85cee315f6a11c8c7c7fd42fa7";
const IMAGE_DIGEST: &str = "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).expect("test checkpoint must fit the production CQL representation")
}

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
}

fn commit_timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128).expect("test timestamp is in CQL range")
}

fn fence() -> DeleteFenceTimestampUs {
    DeleteFenceTimestampUs::try_after(commit_timestamp(OLD_WRITE_TS), DELETE_FENCE_TS as i128)
        .expect("fence is strictly after old writes")
}

fn new_timestamp() -> NewBranchWriteTimestampUs {
    NewBranchWriteTimestampUs::try_after(fence(), NEW_WRITE_TS as i128)
        .expect("new writes are strictly after the fence")
}

fn merkle_key(level: u8, position: u64, version: u64) -> TypedTableKey {
    TypedTableKey::GlobalUserMerkle {
        node: MerkleNode::new(level, NodeIndex::new(position)),
        checkpoint: checkpoint(version),
    }
}

fn merkle_intent(level: u8, position: u64, version: u64, value: &[u8; 32]) -> LogicalMutation {
    LogicalMutation::Put {
        key: merkle_key(level, position, version),
        value: MutationValue::PsyCanonicalBytes(value.to_vec()),
    }
}

fn leaf_intent(version: u64, marker: u8) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::CheckpointLeaf(checkpoint(version)),
        value: MutationValue::PsyCanonicalBytes(vec![marker; 48]),
    }
}

fn root_intent(root: &[u8; 32], version: u64) -> LogicalMutation {
    LogicalMutation::CheckpointRootMapping {
        root: CheckpointRootKey::new(root.to_vec()),
        checkpoint: checkpoint(version),
    }
}

async fn connect(target: Option<Ipv4Addr>, consistency: Consistency) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(120)));
    if let Some(ip) = target {
        profile = profile.load_balancing_policy(SingleTargetLoadBalancingPolicy::new(
            NodeIdentifier::NodeAddress(SocketAddr::new(IpAddr::V4(ip), 9042)),
            None,
        ));
    }
    SessionBuilder::new()
        .known_nodes_addr(NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)))
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .build()
        .await
        .context("connect to isolated RF=3 Scylla cluster")
}

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {KEYSPACE} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    for cql in [
        format!(
            "CREATE TABLE IF NOT EXISTS {KEYSPACE}.checkpoint_leaf_table \
             (obj_id bigint, value blob, PRIMARY KEY ((obj_id)))"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {KEYSPACE}.global_user_tree_table \
             (level tinyint, node_index bigint, checkpoint_id bigint, value blob, \
             PRIMARY KEY ((level), node_index, checkpoint_id))"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {KEYSPACE}.checkpoint_root_to_checkpoint_id_table_k1 \
             (obj_id blob, value blob, PRIMARY KEY ((obj_id)))"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {KEYSPACE}.checkpoint_root_to_checkpoint_id_table_k2 \
             (obj_id blob, value blob, PRIMARY KEY ((obj_id)))"
        ),
    ] {
        session.query_unpaged(cql, &[]).await?;
    }
    session.await_schema_agreement().await?;
    Ok(())
}

async fn put_old_merkle_dataset(
    adapter: &TimestampPrototypeAdapter,
    session: &Session,
) -> anyhow::Result<()> {
    for level in [POINT_LEVEL, RANGE_LEVEL] {
        for position in 0..POSITIONS {
            for version in TARGET + 1..=OLD_HEAD {
                let sealed = seal_commit_put(
                    merkle_intent(level, position, version, &OLD_VALUE),
                    commit_timestamp(OLD_WRITE_TS),
                )?;
                adapter.put_global_user_merkle(session, &sealed).await?;
            }
        }
    }
    Ok(())
}

async fn put_new_merkle_dataset(
    adapter: &TimestampPrototypeAdapter,
    session: &Session,
) -> anyhow::Result<()> {
    for level in [POINT_LEVEL, RANGE_LEVEL] {
        for position in 0..POSITIONS {
            for version in TARGET + 1..=OLD_HEAD {
                let sealed = seal_new_branch_put(
                    merkle_intent(level, position, version, &NEW_VALUE),
                    new_timestamp(),
                )?;
                adapter.put_global_user_merkle(session, &sealed).await?;
            }
        }
    }
    Ok(())
}

async fn put_old_leaf_dataset(
    adapter: &TimestampPrototypeAdapter,
    session: &Session,
) -> anyhow::Result<()> {
    for version in TARGET + 1..=OLD_HEAD {
        let sealed = seal_commit_put(leaf_intent(version, 0x33), commit_timestamp(OLD_WRITE_TS))?;
        adapter.put_checkpoint_leaf(session, &sealed).await?;
    }
    Ok(())
}

async fn put_new_leaf_dataset(
    adapter: &TimestampPrototypeAdapter,
    session: &Session,
) -> anyhow::Result<()> {
    for version in TARGET + 1..=OLD_HEAD {
        let sealed = seal_new_branch_put(leaf_intent(version, 0x44), new_timestamp())?;
        adapter.put_checkpoint_leaf(session, &sealed).await?;
    }
    Ok(())
}

async fn replay_old_writes(
    adapter: &TimestampPrototypeAdapter,
    session: &Session,
) -> anyhow::Result<()> {
    put_old_merkle_dataset(adapter, session).await?;
    put_old_leaf_dataset(adapter, session).await
}

fn run_command(mut command: Command, description: &str) -> anyhow::Result<String> {
    let output = command.output().with_context(|| format!("start {description}"))?;
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

fn docker_exec(container: &str, args: &[&str], description: &str) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command.arg("exec").arg(container).args(args);
    run_command(command, description)
}

fn compose(compose_file: &Path, args: &[&str], description: &str) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command.arg("compose").arg("-f").arg(compose_file).args(args);
    run_command(command, description)
}

fn cluster_status() -> anyhow::Result<String> {
    docker_exec(NODE_CONTAINERS[0], &["nodetool", "status"], "read RF=3 cluster status")
}

async fn wait_for_three_up_normal() -> anyhow::Result<String> {
    for _ in 0..90 {
        let status = cluster_status()?;
        if status.lines().filter(|line| line.starts_with("UN ")).count() == 3 {
            return Ok(status);
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("cluster did not return to three Up/Normal members: {}", cluster_status()?)
}

fn flush_all() -> anyhow::Result<Duration> {
    let started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(node, &["nodetool", "flush", KEYSPACE], "flush RF=3 test keyspace")?;
    }
    Ok(started.elapsed())
}

fn repair_flush_compact_all() -> anyhow::Result<MaintenanceTiming> {
    let repair_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", KEYSPACE],
            "repair RF=3 test keyspace primary ranges",
        )?;
    }
    let repair = repair_started.elapsed();
    let flush = flush_all()?;
    let compact_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(node, &["nodetool", "compact", KEYSPACE], "compact RF=3 test keyspace")?;
    }
    Ok(MaintenanceTiming::new(repair, flush, compact_started.elapsed()))
}

async fn merkle_count(session: &Session, level: u8) -> anyhow::Result<i64> {
    let rows = session
        .query_unpaged(
            format!("SELECT count(*) FROM {KEYSPACE}.global_user_tree_table WHERE level = ?"),
            (level as i8,),
        )
        .await?
        .into_rows_result()?;
    Ok(rows.first_row::<(i64,)>()?.0)
}

async fn merkle_value(
    session: &Session,
    level: u8,
    position: u64,
    version: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(session
        .query_unpaged(
            format!(
                "SELECT value FROM {KEYSPACE}.global_user_tree_table \
                 WHERE level = ? AND node_index = ? AND checkpoint_id = ?"
            ),
            (level as i8, position as i64, version as i64),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(Vec<u8>,)>()?
        .map(|(value,)| value))
}

async fn leaf_count(session: &Session) -> anyhow::Result<i64> {
    Ok(session
        .query_unpaged(format!("SELECT count(*) FROM {KEYSPACE}.checkpoint_leaf_table"), &[])
        .await?
        .into_rows_result()?
        .first_row::<(i64,)>()?
        .0)
}

async fn leaf_value(session: &Session, version: u64) -> anyhow::Result<Option<Vec<u8>>> {
    let value = session
        .query_unpaged(
            format!("SELECT value FROM {KEYSPACE}.checkpoint_leaf_table WHERE obj_id = ?"),
            (version as i64,),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(Vec<u8>,)>()?
        .map(|(value,)| value);
    value.map(|stored| compression::decompress(&stored)).transpose()
}

async fn verify_deleted_on_replica(session: &Session, root_a: &CheckpointRootKey) -> anyhow::Result<()> {
    ensure!(merkle_count(session, POINT_LEVEL).await? == 0, "point-deleted rows resurrected");
    ensure!(merkle_count(session, RANGE_LEVEL).await? == 0, "range-deleted rows resurrected");
    ensure!(leaf_count(session).await? == 0, "version-partition rows resurrected");
    let root_adapter = CheckpointRootPrototypeAdapter::prepare_with_consistency(
        session,
        CqlKeyspaceName::try_new(KEYSPACE)?,
        Consistency::One,
    )
    .await?;
    ensure!(
        root_adapter.get_checkpoint_for_root(session, root_a).await?.is_none(),
        "orphan root reverse lookup survived"
    );
    Ok(())
}

async fn verify_new_on_replica(
    session: &Session,
    root_a: &CheckpointRootKey,
    root_b: &CheckpointRootKey,
) -> anyhow::Result<()> {
    let expected = (POSITIONS * SUFFIX_VERSIONS) as i64;
    ensure!(merkle_count(session, POINT_LEVEL).await? == expected, "point dataset count mismatch");
    ensure!(merkle_count(session, RANGE_LEVEL).await? == expected, "range dataset count mismatch");
    ensure!(leaf_count(session).await? == SUFFIX_VERSIONS as i64, "leaf dataset count mismatch");
    for level in [POINT_LEVEL, RANGE_LEVEL] {
        for position in 0..POSITIONS {
            ensure!(
                merkle_value(session, level, position, TARGET + 1).await? == Some(NEW_VALUE.to_vec()),
                "new branch value lost at level={level} position={position}"
            );
        }
    }
    for version in TARGET + 1..=OLD_HEAD {
        ensure!(leaf_value(session, version).await? == Some(vec![0x44; 48]), "new KIV value lost at {version}");
    }
    let root_adapter = CheckpointRootPrototypeAdapter::prepare_with_consistency(
        session,
        CqlKeyspaceName::try_new(KEYSPACE)?,
        Consistency::One,
    )
    .await?;
    ensure!(root_adapter.get_checkpoint_for_root(session, root_a).await?.is_none(), "orphan root A returned");
    ensure!(
        root_adapter.get_checkpoint_for_root(session, root_b).await? == Some(checkpoint(TARGET + 1)),
        "canonical root B did not map to reused height"
    );
    Ok(())
}

async fn sample_new_branch_reads(session: &Session) -> anyhow::Result<Vec<u64>> {
    let mut samples = Vec::with_capacity((POSITIONS * 2 + SUFFIX_VERSIONS) as usize);
    for level in [POINT_LEVEL, RANGE_LEVEL] {
        for position in 0..POSITIONS {
            let started = Instant::now();
            ensure!(
                merkle_value(session, level, position, TARGET + 1).await? == Some(NEW_VALUE.to_vec()),
                "read sample returned the wrong new-branch value"
            );
            samples.push(started.elapsed().as_micros() as u64);
        }
    }
    for version in TARGET + 1..=OLD_HEAD {
        let started = Instant::now();
        ensure!(leaf_value(session, version).await? == Some(vec![0x44; 48]), "read sample returned the wrong KIV value");
        samples.push(started.elapsed().as_micros() as u64);
    }
    Ok(samples)
}

fn disk_bytes() -> anyhow::Result<Vec<u64>> {
    NODE_CONTAINERS
        .iter()
        .map(|node| {
            let output = docker_exec(
                node,
                &["du", "-sb", &format!("/var/lib/scylla/data/{KEYSPACE}")],
                "measure RF=3 keyspace disk bytes",
            )?;
            output
                .split_whitespace()
                .next()
                .context("du output had no byte count")?
                .parse::<u64>()
                .context("parse du byte count")
        })
        .collect()
}

#[derive(Clone, Debug, Serialize)]
struct LatencySummary {
    operations: usize,
    total_us: u64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

impl LatencySummary {
    fn from_samples(mut samples: Vec<u64>) -> Self {
        samples.sort_unstable();
        let percentile = |percent: usize| -> u64 {
            let index = ((samples.len() * percent).div_ceil(100)).saturating_sub(1);
            samples[index]
        };
        Self {
            operations: samples.len(),
            total_us: samples.iter().sum(),
            p50_us: percentile(50),
            p95_us: percentile(95),
            p99_us: percentile(99),
            max_us: *samples.last().expect("benchmark records at least one sample"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct TombstoneOperations {
    point: u64,
    bounded_range: u64,
    version_partition: u64,
    orphan_root_point: u64,
}

#[derive(Clone, Debug, Serialize)]
struct MaintenanceTiming {
    repair_ms: u64,
    flush_ms: u64,
    compaction_ms: u64,
}

impl MaintenanceTiming {
    fn new(repair: Duration, flush: Duration, compaction: Duration) -> Self {
        Self {
            repair_ms: repair.as_millis() as u64,
            flush_ms: flush.as_millis() as u64,
            compaction_ms: compaction.as_millis() as u64,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct StrategyCoverage {
    physical_table: String,
    readiness: String,
    candidates: String,
}

#[derive(Clone, Debug, Serialize)]
struct GateReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    topology_before: String,
    topology_after: String,
    positions: u64,
    suffix_versions: u64,
    point_delete: LatencySummary,
    bounded_range_delete: LatencySummary,
    version_partition_delete: LatencySummary,
    post_repair_read: LatencySummary,
    tombstone_operations_emitted: TombstoneOperations,
    first_maintenance: MaintenanceTiming,
    second_maintenance: MaintenanceTiming,
    disk_bytes_before: Vec<u64>,
    disk_bytes_after_delete: Vec<u64>,
    disk_bytes_after_reuse: Vec<u64>,
    scenarios_passed: Vec<&'static str>,
    physical_registry_coverage: Vec<StrategyCoverage>,
    tablestats_after_reuse: String,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn rollback_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_G0_02_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-g0-02.sh"
    );
    let started_unix_ms = unix_ms()?;
    let compose_file = std::env::var("PSY_G0_02_COMPOSE_FILE").context("PSY_G0_02_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_G0_02_REPORT_PATH").context("PSY_G0_02_REPORT_PATH")?;
    let topology_before = wait_for_three_up_normal().await?;
    let session = connect(None, Consistency::One).await?;
    create_schema(&session).await?;
    let keyspace = CqlKeyspaceName::try_new(KEYSPACE)?;
    let all = TimestampPrototypeAdapter::prepare_with_consistency(&session, keyspace.clone(), Consistency::All).await?;
    let quorum = TimestampPrototypeAdapter::prepare_with_consistency(&session, keyspace.clone(), Consistency::Quorum).await?;
    let roots_all = CheckpointRootPrototypeAdapter::prepare_with_consistency(&session, keyspace.clone(), Consistency::All).await?;
    let roots_quorum =
        CheckpointRootPrototypeAdapter::prepare_with_consistency(&session, keyspace.clone(), Consistency::Quorum).await?;

    // system.local.release_version is the Cassandra compatibility version
    // (3.0.8 in this image), not the Scylla build version.
    let release = docker_exec(NODE_CONTAINERS[0], &["scylla", "--version"], "read Scylla build version")?
        .trim()
        .to_owned();
    put_old_merkle_dataset(&all, &session).await?;
    put_old_leaf_dataset(&all, &session).await?;
    let root_a_bytes = [0xa1; 32];
    let root_b_bytes = [0xb2; 32];
    let root_a = CheckpointRootKey::new(root_a_bytes.to_vec());
    let root_b = CheckpointRootKey::new(root_b_bytes.to_vec());
    let old_root = seal_commit_put_batch(root_intent(&root_a_bytes, TARGET + 1), commit_timestamp(OLD_WRITE_TS))?;
    roots_all.put_mapping(&session, &old_root).await?;
    flush_all()?;
    let disk_bytes_before = disk_bytes()?;

    // S13 is an intent-layer rejection. It deliberately never reaches CQL.
    let retry = seal_commit_put(
        merkle_intent(POINT_LEVEL, 0, TARGET + 1, &OLD_VALUE),
        commit_timestamp(OLD_WRITE_TS),
    )?;
    ensure!(
        matches!(
            retry.ensure_exact_retry(
                merkle_intent(POINT_LEVEL, 0, TARGET + 1, &NEW_VALUE),
                commit_timestamp(OLD_WRITE_TS),
                TimestampedWriteKind::AuthorityCommit,
            ),
            Err(TimestampedMutationError::RetryMutationChanged)
        ),
        "same timestamp with a different value was not rejected"
    );

    compose(Path::new(&compose_file), &["stop", "--timeout", "30", "scylla3"], "stop stale replica")?;

    let mut point_samples = Vec::with_capacity((POSITIONS * SUFFIX_VERSIONS) as usize);
    for position in 0..POSITIONS {
        for version in TARGET + 1..=OLD_HEAD {
            let plan = GlobalUserMerklePointDeletePlan::try_new(merkle_key(POINT_LEVEL, position, version), fence())?;
            let started = Instant::now();
            quorum.delete_global_user_merkle_point(&session, &plan).await?;
            point_samples.push(started.elapsed().as_micros() as u64);
        }
    }

    let mut range_samples = Vec::with_capacity(POSITIONS as usize);
    for position in 0..POSITIONS {
        let plan = GlobalUserMerkleBoundedRangeDeletePlan::try_new(
            merkle_key(RANGE_LEVEL, position, TARGET),
            checkpoint(OLD_HEAD),
            fence(),
        )?;
        let started = Instant::now();
        quorum.delete_global_user_merkle_range(&session, &plan).await?;
        range_samples.push(started.elapsed().as_micros() as u64);
    }

    let mut partition_samples = Vec::with_capacity(SUFFIX_VERSIONS as usize);
    for version in TARGET + 1..=OLD_HEAD {
        let plan = CheckpointLeafVersionDeletePlan::try_new(TypedTableKey::CheckpointLeaf(checkpoint(version)), fence())?;
        let started = Instant::now();
        quorum.delete_checkpoint_leaf_version(&session, &plan).await?;
        partition_samples.push(started.elapsed().as_micros() as u64);
    }
    roots_quorum
        .delete_orphan_root(&session, &CheckpointRootOrphanDeletePlan::try_new(root_a.clone(), fence())?)
        .await?;

    // S09/S10: a late replay at the orphan timestamp stays hidden behind the
    // higher timestamp delete fence while the third replica is still stale.
    replay_old_writes(&quorum, &session).await?;
    ensure!(merkle_value(&session, POINT_LEVEL, 0, TARGET + 1).await?.is_none(), "S09/S10 point row visible");
    ensure!(merkle_value(&session, RANGE_LEVEL, 0, TARGET + 1).await?.is_none(), "S09/S10 range row visible");
    ensure!(leaf_value(&session, TARGET + 1).await?.is_none(), "S09/S10 KIV row visible");
    ensure!(roots_quorum.get_checkpoint_for_root(&session, &root_a).await?.is_none(), "S16 orphan root visible");

    compose(Path::new(&compose_file), &["start", "scylla3"], "restart stale replica")?;
    wait_for_three_up_normal().await?;
    let first_maintenance = repair_flush_compact_all()?;
    let disk_bytes_after_delete = disk_bytes()?;
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        verify_deleted_on_replica(&direct, &root_a).await?;
    }
    let all_read = connect(None, Consistency::All).await?;
    verify_deleted_on_replica(&all_read, &root_a).await?;
    ensure!(
        roots_all.get_checkpoint_for_root(&session, &root_a).await?.is_none(),
        "orphan root survived an ALL read after repair"
    );

    // S11: reuse the same heights with timestamps strictly after the fence.
    put_new_merkle_dataset(&all, &session).await?;
    put_new_leaf_dataset(&all, &session).await?;
    let new_root = seal_new_branch_put_batch(root_intent(&root_b_bytes, TARGET + 1), new_timestamp())?;
    roots_all.put_mapping(&session, &new_root).await?;
    ensure!(
        roots_all.get_checkpoint_for_root(&session, &root_a).await?.is_none(),
        "orphan root A returned after same-height reuse"
    );
    ensure!(
        roots_all.get_checkpoint_for_root(&session, &root_b).await? == Some(checkpoint(TARGET + 1)),
        "canonical root B missing after same-height reuse"
    );

    // S12: even an all-replica late old write loses to the new branch.
    replay_old_writes(&all, &session).await?;
    let second_maintenance = repair_flush_compact_all()?;
    let disk_bytes_after_reuse = disk_bytes()?;
    let mut read_samples = Vec::new();
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        verify_new_on_replica(&direct, &root_a, &root_b).await?;
        read_samples.extend(sample_new_branch_reads(&direct).await?);
    }
    let all_read = connect(None, Consistency::All).await?;
    verify_new_on_replica(&all_read, &root_a, &root_b).await?;
    read_samples.extend(sample_new_branch_reads(&all_read).await?);
    let topology_after = wait_for_three_up_normal().await?;
    let tablestats_after_reuse = docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "tablestats", KEYSPACE],
        "capture RF=3 table statistics",
    )?;

    let physical_registry_coverage = physical_registry()
        .into_iter()
        .map(|descriptor| StrategyCoverage {
            physical_table: descriptor.physical_name.to_owned(),
            readiness: format!("{:?}", descriptor.readiness),
            candidates: format!("{:?}", descriptor.delete_candidates),
        })
        .collect::<Vec<_>>();
    ensure!(physical_registry_coverage.len() == 35, "physical registry drifted from 35 tables");

    let report = GateReport {
        baseline: BASELINE,
        image: IMAGE_DIGEST,
        scylla_release: release,
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        topology_before,
        topology_after,
        positions: POSITIONS,
        suffix_versions: SUFFIX_VERSIONS,
        point_delete: LatencySummary::from_samples(point_samples),
        bounded_range_delete: LatencySummary::from_samples(range_samples),
        version_partition_delete: LatencySummary::from_samples(partition_samples),
        post_repair_read: LatencySummary::from_samples(read_samples),
        tombstone_operations_emitted: TombstoneOperations {
            point: POSITIONS * SUFFIX_VERSIONS,
            bounded_range: POSITIONS,
            version_partition: SUFFIX_VERSIONS,
            orphan_root_point: 1,
        },
        first_maintenance,
        second_maintenance,
        disk_bytes_before,
        disk_bytes_after_delete,
        disk_bytes_after_reuse,
        scenarios_passed: vec!["S09", "S10", "S11", "S12", "S13", "S14", "S15", "S16"],
        physical_registry_coverage,
        tablestats_after_reuse,
        qualification: "Representative mechanism evidence only; not full D-02T coverage or complete P0b Gate closure.",
    };
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
