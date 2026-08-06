use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use futures::future::join_all;
use psy_node_core::store::{
    timestamp::CommitWriteTimestampUs,
    typed::{
        LogicalMutation, MerkleNode, NodeIndex, ProcCheckpointUniqueId,
        TypedTableKey, UniquePendingId,
    },
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

use super::{
    pending_counter::{PendingCounterAdapter, PendingCounterAdapterError},
    reward_tag_tree::RewardTagTreeAdapter, physical_descriptor,
    seal_commit_put, CqlKeyspaceName, PendingCounterAllocationOutcome,
    PendingCounterExpected, PendingOwnershipStatus,
    RewardTagTreeNodePayloadV1, RewardTagTreePutBinding,
    ScyllaPhysicalTableId, SealedPendingCounterAllocation,
};

const STANDARD_KEYSPACE: &str = "psy_d02t10_rf3";
const NO_TABLET_KEYSPACE: &str = "psy_d02t10_rf3_nt";
const BASELINE: &str = "702f6e5b8277e26f2d7f569bc05962b4a30bbbba";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const CONCURRENT_ALLOCATORS: usize = 64;
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

fn pending(value: u64) -> UniquePendingId {
    UniquePendingId::try_new(value).expect("RF=3 fixture pending ID is non-zero")
}

fn proc_id(value: u128) -> ProcCheckpointUniqueId {
    ProcCheckpointUniqueId::from_u128(value)
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(i128::from(value))
        .expect("RF=3 fixture timestamp is valid")
}

fn full_intent(
    pending_id: u64,
    level: u8,
    index: u64,
    value: u8,
    tag: u8,
) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::RewardTagMerkle {
            pending: pending(pending_id),
            node: MerkleNode::new(level, NodeIndex::new(index)),
        },
        value: RewardTagTreeNodePayloadV1::try_full(
            &[value; 32],
            &[tag; 32],
        )
        .expect("valid tag-tree payload")
        .into_mutation_value(),
    }
}

fn value_only_intent(
    pending_id: u64,
    level: u8,
    index: u64,
    value: u8,
) -> LogicalMutation {
    LogicalMutation::Put {
        key: TypedTableKey::RewardTagMerkle {
            pending: pending(pending_id),
            node: MerkleNode::new(level, NodeIndex::new(index)),
        },
        value: RewardTagTreeNodePayloadV1::try_value_only(&[value; 32])
            .expect("valid tag-tree payload")
            .into_mutation_value(),
    }
}

async fn connect(
    target: Option<Ipv4Addr>,
    consistency: Consistency,
) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(consistency)
        .request_timeout(Some(Duration::from_secs(120)));
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
        .build()
        .await
        .context("connect to isolated D-02T9/T10 RF=3 Scylla cluster")
}

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    for keyspace in [STANDARD_KEYSPACE, NO_TABLET_KEYSPACE] {
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = \
                     {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} \
                     AND tablets = {{'enabled': false}}"
                ),
                &[],
            )
            .await?;
    }

    let counter = physical_descriptor(
        ScyllaPhysicalTableId::U64CounterSingleton,
    )
    .physical_name;
    let owner = physical_descriptor(
        ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
    )
    .physical_name;
    let tag_tree = physical_descriptor(
        ScyllaPhysicalTableId::GutaRewardTagTree,
    )
    .physical_name;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {NO_TABLET_KEYSPACE}.{counter} \
                 (obj_id BIGINT PRIMARY KEY, value BIGINT)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STANDARD_KEYSPACE}.{owner} \
                 (obj_id BIGINT PRIMARY KEY, value UUID)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STANDARD_KEYSPACE}.{tag_tree} \
                 (unique_pending_id BIGINT, level TINYINT, node_index BIGINT, \
                  node_value BLOB, node_tag BLOB, \
                  PRIMARY KEY ((unique_pending_id), level, node_index)) \
                 WITH CLUSTERING ORDER BY (level ASC, node_index ASC)"
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn allocate_until_observed(
    adapter: &PendingCounterAdapter,
    plan: &SealedPendingCounterAllocation,
) -> anyhow::Result<PendingCounterAllocationOutcome> {
    for attempt in 1..=12_u64 {
        match adapter.allocate(plan).await {
            Ok(outcome) => return Ok(outcome),
            Err(
                PendingCounterAdapterError::IndeterminateCounter { .. }
                | PendingCounterAdapterError::IndeterminateOwnership { .. },
            ) => sleep(Duration::from_millis(attempt * 100)).await,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("pending allocation remained indeterminate after exact-plan retries")
}

async fn read_tag_node(
    session: &Session,
    pending_id: u64,
    level: u8,
    index: u64,
) -> anyhow::Result<Option<TagNodeRow>> {
    let table = physical_descriptor(
        ScyllaPhysicalTableId::GutaRewardTagTree,
    )
    .physical_name;
    let row = session
        .query_unpaged(
            format!(
                "SELECT node_value, node_tag, writetime(node_value), \
                 writetime(node_tag) FROM {STANDARD_KEYSPACE}.{table} \
                 WHERE unique_pending_id = ? AND level = ? AND node_index = ?"
            ),
            (pending_id as i64, level as i8, index as i64),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<i64>,
        )>()?;
    Ok(row.map(
        |(value, tag, value_timestamp, tag_timestamp)| TagNodeRow {
            value,
            tag,
            value_timestamp,
            tag_timestamp,
        },
    ))
}

fn run_command(
    mut command: Command,
    description: &str,
) -> anyhow::Result<String> {
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
        "read D-02T9/T10 RF=3 cluster status",
    )
}

async fn wait_for_three_up_normal() -> anyhow::Result<String> {
    for _ in 0..90 {
        let status = cluster_status()?;
        if status
            .lines()
            .filter(|line| line.starts_with("UN "))
            .count()
            == 3
        {
            return Ok(status);
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!(
        "cluster did not return to three Up/Normal members: {}",
        cluster_status()?
    )
}

fn repair_flush_all() -> anyhow::Result<MaintenanceTiming> {
    let repair_started = Instant::now();
    for keyspace in [STANDARD_KEYSPACE, NO_TABLET_KEYSPACE] {
        for node in NODE_CONTAINERS {
            docker_exec(
                node,
                &["nodetool", "repair", "-pr", keyspace],
                "repair pending namespace RF=3 primary ranges",
            )?;
        }
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let flush_started = Instant::now();
    for keyspace in [STANDARD_KEYSPACE, NO_TABLET_KEYSPACE] {
        for node in NODE_CONTAINERS {
            docker_exec(
                node,
                &["nodetool", "flush", keyspace],
                "flush pending namespace RF=3 keyspace",
            )?;
        }
    }
    Ok(MaintenanceTiming {
        repair_ms,
        flush_ms: flush_started.elapsed().as_millis() as u64,
    })
}

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TagNodeRow {
    value: Option<Vec<u8>>,
    tag: Option<Vec<u8>>,
    value_timestamp: Option<i64>,
    tag_timestamp: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct MaintenanceTiming {
    repair_ms: u64,
    flush_ms: u64,
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
    standard_keyspace: &'static str,
    no_tablet_keyspace: &'static str,
    concurrent_allocators: usize,
    allocation_owned: usize,
    allocation_conflicts: usize,
    maintenance: MaintenanceTiming,
    scenarios_passed: Vec<&'static str>,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn pending_namespace_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D02T10_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d02t10.sh"
    );
    let compose_file = std::env::var("PSY_D02T10_COMPOSE_FILE")
        .context("PSY_D02T10_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_D02T10_REPORT_PATH")
        .context("PSY_D02T10_REPORT_PATH")?;
    let started_unix_ms = unix_ms()?;
    let topology_before = wait_for_three_up_normal().await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_schema(&session).await?;
    let counter_adapter = PendingCounterAdapter::prepare(
        Arc::clone(&session),
        CqlKeyspaceName::try_new(NO_TABLET_KEYSPACE)?,
        CqlKeyspaceName::try_new(STANDARD_KEYSPACE)?,
    )
    .await?;
    ensure!(
        counter_adapter.lwt_contract().regular() == Consistency::Quorum
    );
    ensure!(
        counter_adapter.lwt_contract().serial()
            == scylla::statement::SerialConsistency::LocalSerial
    );

    // Sixty-four different proc contexts race for candidate pending=1. The
    // owner IF NOT EXISTS and counter CAS must produce exactly one owner.
    let competing = (0..CONCURRENT_ALLOCATORS)
        .map(|index| {
            SealedPendingCounterAllocation::try_for_commit(
                PendingCounterExpected::Absent,
                proc_id(0x1_0000 + index as u128),
                timestamp(1_000),
            )
            .expect("valid allocation")
        })
        .collect::<Vec<_>>();
    let outcomes = join_all(
        competing
            .iter()
            .map(|plan| allocate_until_observed(&counter_adapter, plan)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let allocation_owned = outcomes
        .iter()
        .filter(|outcome| {
            matches!(outcome, PendingCounterAllocationOutcome::Owned(_))
        })
        .count();
    let allocation_conflicts = outcomes.len() - allocation_owned;
    ensure!(allocation_owned == 1);
    ensure!(allocation_conflicts == CONCURRENT_ALLOCATORS - 1);
    let winning_ownership = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            PendingCounterAllocationOutcome::Owned(ownership) => {
                Some(*ownership)
            }
            PendingCounterAllocationOutcome::Conflict(_) => None,
        })
        .context("find pending=1 owner")?;
    ensure!(winning_ownership.status() == PendingOwnershipStatus::CurrentCounter);
    let winning_plan = competing
        .iter()
        .find(|plan| plan.proc_id() == winning_ownership.proc_id())
        .context("find sealed winning allocation")?;

    // Discard the original applied response and retry the exact sealed plan.
    // Serial read-back must classify it as idempotent current ownership.
    let retry_ownership = match allocate_until_observed(
        &counter_adapter,
        winning_plan,
    )
    .await?
    {
        PendingCounterAllocationOutcome::Owned(ownership) => ownership,
        PendingCounterAllocationOutcome::Conflict(conflict) => {
            bail!("winning allocation retry conflicted: {conflict:?}")
        }
    };
    ensure!(retry_ownership == winning_ownership);
    let current_one = retry_ownership
        .try_into_current()
        .map_err(|_| anyhow::anyhow!("winning pending=1 ownership was historical"))?;

    let tag_adapter = RewardTagTreeAdapter::prepare_with_consistency(
        &session,
        CqlKeyspaceName::try_new(STANDARD_KEYSPACE)?,
        Consistency::All,
    )
    .await?;
    let old_sealed = seal_commit_put(
        full_intent(1, 3, 9, 0x11, 0xAA),
        timestamp(1_100),
    )?;
    let old_binding =
        RewardTagTreePutBinding::try_from_sealed(&old_sealed, current_one)?;
    tag_adapter
        .put_one(&session, &old_binding)
        .await?;

    // Rotate to pending=2 and prove the old token becomes historical on
    // serial reconciliation; it cannot be narrowed to a current capability.
    let second_plan = SealedPendingCounterAllocation::try_for_commit(
        PendingCounterExpected::Present(pending(1)),
        proc_id(0x2_0000),
        timestamp(2_000),
    )?;
    let current_two = match allocate_until_observed(
        &counter_adapter,
        &second_plan,
    )
    .await?
    {
        PendingCounterAllocationOutcome::Owned(ownership) => {
            ensure!(ownership.status() == PendingOwnershipStatus::CurrentCounter);
            ownership.try_into_current().map_err(|_| {
                anyhow::anyhow!("new pending=2 ownership was historical")
            })?
        }
        PendingCounterAllocationOutcome::Conflict(conflict) => {
            bail!("pending=2 allocation conflicted: {conflict:?}")
        }
    };
    let historical = match allocate_until_observed(
        &counter_adapter,
        winning_plan,
    )
    .await?
    {
        PendingCounterAllocationOutcome::Owned(ownership) => ownership,
        PendingCounterAllocationOutcome::Conflict(conflict) => {
            bail!("historical ownership reconcile conflicted: {conflict:?}")
        }
    };
    ensure!(historical.status() == PendingOwnershipStatus::HistoricalBackfill);
    ensure!(historical.try_into_current().is_err());

    let new_full = seal_commit_put(
        full_intent(2, 3, 9, 0x22, 0xBB),
        timestamp(2_100),
    )?;
    let new_full_binding =
        RewardTagTreePutBinding::try_from_sealed(&new_full, current_two)?;
    tag_adapter
        .put_one(&session, &new_full_binding)
        .await?;
    let new_latest = seal_commit_put(
        value_only_intent(2, 3, 9, 0x33),
        timestamp(2_200),
    )?;
    let new_latest_binding =
        RewardTagTreePutBinding::try_from_sealed(&new_latest, current_two)?;
    tag_adapter
        .put_one(&session, &new_latest_binding)
        .await?;
    // Execute a lower timestamp after the latest value. Scylla timestamp
    // arbitration must preserve the newer value and the original full tag.
    let stale = seal_commit_put(
        value_only_intent(2, 3, 9, 0x44),
        timestamp(2_150),
    )?;
    let stale_binding =
        RewardTagTreePutBinding::try_from_sealed(&stale, current_two)?;
    tag_adapter.put_one(&session, &stale_binding).await?;

    let old_before_outage = read_tag_node(&session, 1, 3, 9)
        .await?
        .context("old pending tag-tree row")?;
    let new_before_outage = read_tag_node(&session, 2, 3, 9)
        .await?
        .context("new pending tag-tree row")?;
    ensure!(old_before_outage.value == Some(vec![0x11; 32]));
    ensure!(old_before_outage.tag == Some(vec![0xAA; 32]));
    ensure!(old_before_outage.value_timestamp == Some(1_100));
    ensure!(old_before_outage.tag_timestamp == Some(1_100));
    ensure!(new_before_outage.value == Some(vec![0x33; 32]));
    ensure!(new_before_outage.tag == Some(vec![0xBB; 32]));
    ensure!(new_before_outage.value_timestamp == Some(2_200));
    ensure!(new_before_outage.tag_timestamp == Some(2_100));

    // A quorum ownership/counter rotation must remain available with one RF=3
    // replica offline. Repair then converges both namespaces on direct ONE reads.
    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop stale pending-namespace replica",
    )?;
    let third_plan = SealedPendingCounterAllocation::try_for_commit(
        PendingCounterExpected::Present(pending(2)),
        proc_id(0x3_0000),
        timestamp(3_000),
    )?;
    ensure!(matches!(
        allocate_until_observed(&counter_adapter, &third_plan).await?,
        PendingCounterAllocationOutcome::Owned(ownership)
            if ownership.status() == PendingOwnershipStatus::CurrentCounter
    ));
    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart stale pending-namespace replica",
    )?;
    wait_for_three_up_normal().await?;
    let maintenance = repair_flush_all()?;
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        ensure!(
            read_tag_node(&direct, 1, 3, 9).await? == Some(old_before_outage.clone()),
            "old namespace diverged on direct ONE read from {ip}"
        );
        ensure!(
            read_tag_node(&direct, 2, 3, 9).await? == Some(new_before_outage.clone()),
            "new namespace diverged on direct ONE read from {ip}"
        );
    }

    let topology_after = wait_for_three_up_normal().await?;
    let scylla_release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read Scylla build version",
    )?
    .trim()
    .to_owned();
    let report = GateReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release,
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        topology_before,
        topology_after,
        standard_keyspace: STANDARD_KEYSPACE,
        no_tablet_keyspace: NO_TABLET_KEYSPACE,
        concurrent_allocators: CONCURRENT_ALLOCATORS,
        allocation_owned,
        allocation_conflicts,
        maintenance,
        scenarios_passed: vec![
            "CONCURRENT_PENDING_OWNERSHIP_LWT",
            "EXACT_PLAN_RESPONSE_LOSS_RETRY",
            "CURRENT_TO_HISTORICAL_RECONCILIATION",
            "TAG_TREE_EXPLICIT_TIMESTAMP_ORDERING",
            "OLD_AND_NEW_PENDING_NAMESPACE_ISOLATION",
            "ONE_REPLICA_OFFLINE_PENDING_ROTATION",
            "REPAIR_DIRECT_ONE_CONVERGENCE",
        ],
        qualification: "D-02T9/T10 RF=3 substrate evidence only. D-04 must still hold the processor/context-rotation guard; production writer migration and full rollback execution remain out of scope.",
    };
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
