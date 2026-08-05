use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use futures::future::join_all;
use parth_core::PHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    NetworkId,
};
use psy_node_core::store::{
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile, StoredCanonicalHead,
    },
    rollback_admission::{
        RollbackAdmissionCommand, RollbackAdmissionSlotBootstrap,
        RollbackAdmissionSlotReadState, RollbackAdmissionSlotWriteOutcome,
        SealedRollbackAdmissionSlotCas, StoredRollbackAdmissionSlot,
    },
    rollback_control::{
        RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
    },
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
};
use psy_node_scylla::rollback::{
    decode_rollback_admission_persisted_cells, CanonicalHeadNoTabletKeyspace,
    RollbackAdmissionScyllaError, ScyllaRollbackAdmissionStore,
    COORDINATOR_ROLLBACK_ADMISSION_TABLE,
};
use scylla::{
    client::{
        execution_profile::ExecutionProfile, session::Session,
        session_builder::SessionBuilder,
    },
    policies::load_balancing::{NodeIdentifier, SingleTargetLoadBalancingPolicy},
    statement::Consistency,
};
use serde::Serialize;
use tokio::time::sleep;

const KEYSPACE: &str = "psy_c01d_rf3_nt";
const BASELINE: &str = "129a9423a9d5882533f1a7a58ceaa69331d2d18b";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const CONCURRENT_WRITERS: usize = 64;
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

fn network(chain_id: u32) -> NetworkId {
    NetworkId::try_from_chain_id(chain_id).expect("test uses a configured Psy network")
}

fn mainnet() -> NetworkId {
    network(0x6979_7350)
}

fn public_testnet() -> NetworkId {
    network(1337)
}

fn team_devnet() -> NetworkId {
    network(1)
}

fn internal_devnet() -> NetworkId {
    network(2)
}

fn hash(seed: u64) -> PHash {
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
    CheckpointRef::new(
        CheckpointId::new(height),
        CheckpointHash::from_last_chain_hash(hash(seed)),
    )
}

fn head(network: NetworkId, height: u64, seed: u64) -> StoredCanonicalHead<PHash> {
    *CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::PostGenesisFloor,
        CanonicalChainRef::new(
            network,
            ChainEpoch::new(0),
            checkpoint(height, seed),
        ),
    )
    .expect("valid test head")
    .candidate()
}

fn command(
    network: NetworkId,
    target: u64,
    seed: u64,
    digest: u8,
) -> RollbackAdmissionCommand<PHash> {
    let expected = head(network, 100, 1_000);
    RollbackAdmissionCommand::try_new(
        expected,
        RollbackRequest::try_new(
            *expected.canonical_ref().checkpoint(),
            checkpoint(target, seed),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(10_000 + i128::from(digest)).unwrap(),
                20_000 + i128::from(digest),
                30_000 + i128::from(digest),
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([digest; 32]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
}

async fn connect(
    target: Option<Ipv4Addr>,
    consistency: Consistency,
) -> anyhow::Result<Session> {
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
        .context("connect to isolated C-01d RF=3 Scylla cluster")
}

async fn create_schema(
    session: &Session,
) -> anyhow::Result<CanonicalHeadNoTabletKeyspace> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {KEYSPACE} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    let keyspace = CanonicalHeadNoTabletKeyspace::try_new(KEYSPACE)?;
    ScyllaRollbackAdmissionStore::create_schema(session, &keyspace).await?;
    Ok(keyspace)
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
        "read C-01d RF=3 cluster status",
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

fn repair_flush_compact_all() -> anyhow::Result<MaintenanceTiming> {
    let repair_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", KEYSPACE],
            "repair C-01d RF=3 keyspace primary ranges",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let flush_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "flush", KEYSPACE],
            "flush C-01d RF=3 keyspace",
        )?;
    }
    let flush_ms = flush_started.elapsed().as_millis() as u64;
    let compact_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "compact", KEYSPACE],
            "compact C-01d RF=3 keyspace",
        )?;
    }
    Ok(MaintenanceTiming {
        repair_ms,
        flush_ms,
        compact_ms: compact_started.elapsed().as_millis() as u64,
    })
}

fn current(
    state: RollbackAdmissionSlotReadState<PHash>,
) -> anyhow::Result<StoredRollbackAdmissionSlot<PHash>> {
    match state {
        RollbackAdmissionSlotReadState::Current(current) => Ok(current),
        RollbackAdmissionSlotReadState::Uninitialized => {
            bail!("rollback admission inbox unexpectedly uninitialized")
        }
    }
}

async fn bootstrap_until_observed(
    adapter: &ScyllaRollbackAdmissionStore,
    bootstrap: &RollbackAdmissionSlotBootstrap<PHash>,
) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<PHash>> {
    for attempt in 1..=12_u64 {
        match adapter.bootstrap(bootstrap).await {
            Ok(outcome) => return Ok(outcome),
            Err(
                RollbackAdmissionScyllaError::IndeterminateWrite { .. }
                | RollbackAdmissionScyllaError::IndeterminateReadFailed { .. },
            ) => sleep(Duration::from_millis(attempt * 100)).await,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("inbox bootstrap remained indeterminate after exact-intent retries")
}

async fn cas_until_observed(
    adapter: &ScyllaRollbackAdmissionStore,
    sealed: &SealedRollbackAdmissionSlotCas<PHash>,
) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<PHash>> {
    for attempt in 1..=12_u64 {
        match adapter.compare_and_set(sealed).await {
            Ok(outcome) => return Ok(outcome),
            Err(
                RollbackAdmissionScyllaError::IndeterminateWrite { .. }
                | RollbackAdmissionScyllaError::IndeterminateReadFailed { .. },
            ) => sleep(Duration::from_millis(attempt * 100)).await,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("inbox CAS remained indeterminate after exact-intent retries")
}

async fn read_direct(
    session: &Session,
    requested_network: NetworkId,
) -> anyhow::Result<Option<StoredRollbackAdmissionSlot<PHash>>> {
    let row = session
        .query_unpaged(
            format!(
                "SELECT network_chain_id, revision, slot FROM \
                 {KEYSPACE}.{COORDINATOR_ROLLBACK_ADMISSION_TABLE} WHERE network_chain_id = ?"
            ),
            (i64::from(requested_network.chain_id()),),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64, Option<i64>, Option<Vec<u8>>)>()?;
    row.map(|(network_chain_id, revision, slot)| {
        decode_rollback_admission_persisted_cells::<PHash>(
            requested_network,
            network_chain_id,
            revision,
            slot.as_deref(),
        )
        .map_err(Into::into)
    })
    .transpose()
}

async fn raw_put(
    session: &Session,
    partition_network: NetworkId,
    revision: i64,
    slot: &[u8],
) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "INSERT INTO {KEYSPACE}.{COORDINATOR_ROLLBACK_ADMISSION_TABLE} \
                 (network_chain_id, revision, slot) VALUES (?, ?, ?)"
            ),
            (
                i64::from(partition_network.chain_id()),
                revision,
                slot,
            ),
        )
        .await?;
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
struct MaintenanceTiming {
    repair_ms: u64,
    flush_ms: u64,
    compact_ms: u64,
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
    keyspace: &'static str,
    concurrent_writers: usize,
    bootstrap_applied: usize,
    bootstrap_idempotent: usize,
    offer_applied: usize,
    offer_idempotent: usize,
    offer_conflict: usize,
    winning_target: u64,
    maintenance: MaintenanceTiming,
    scenarios_passed: Vec<&'static str>,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn rollback_admission_inbox_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_C01D_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-c01d.sh"
    );
    let started_unix_ms = unix_ms()?;
    let compose_file =
        std::env::var("PSY_C01D_COMPOSE_FILE").context("PSY_C01D_COMPOSE_FILE")?;
    let report_path =
        std::env::var("PSY_C01D_REPORT_PATH").context("PSY_C01D_REPORT_PATH")?;
    let topology_before = wait_for_three_up_normal().await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    let keyspace = create_schema(&session).await?;
    let adapter = ScyllaRollbackAdmissionStore::prepare(Arc::clone(&session), keyspace).await?;
    ensure!(adapter.lwt_contract().regular() == Consistency::Quorum);
    ensure!(
        adapter.lwt_contract().serial()
            == scylla::statement::SerialConsistency::LocalSerial
    );

    ensure!(matches!(
        adapter.read::<PHash>(mainnet()).await?,
        RollbackAdmissionSlotReadState::Uninitialized
    ));

    let bootstrap = RollbackAdmissionSlotBootstrap::<PHash>::new(mainnet());
    let bootstrap_outcomes = join_all(
        (0..CONCURRENT_WRITERS).map(|_| bootstrap_until_observed(&adapter, &bootstrap)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let bootstrap_applied = bootstrap_outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RollbackAdmissionSlotWriteOutcome::Applied(_)))
        .count();
    let bootstrap_idempotent = bootstrap_outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RollbackAdmissionSlotWriteOutcome::Idempotent(_)))
        .count();
    ensure!(bootstrap_applied == 1);
    ensure!(bootstrap_idempotent == CONCURRENT_WRITERS - 1);

    let empty_zero = current(adapter.read::<PHash>(mainnet()).await?)?;
    let command_a = command(mainnet(), 90, 2_000, 0xA1);
    let command_b = command(mainnet(), 80, 3_000, 0xB2);
    let offer_a = SealedRollbackAdmissionSlotCas::offer(
        mainnet(),
        empty_zero,
        command_a,
    )?;
    let offer_b = SealedRollbackAdmissionSlotCas::offer(
        mainnet(),
        empty_zero,
        command_b,
    )?;
    let competing = (0..CONCURRENT_WRITERS)
        .map(|index| if index % 2 == 0 { offer_a } else { offer_b })
        .collect::<Vec<_>>();
    let outcomes = join_all(
        competing
            .iter()
            .map(|sealed| cas_until_observed(&adapter, sealed)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let offer_applied = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RollbackAdmissionSlotWriteOutcome::Applied(_)))
        .count();
    let offer_idempotent = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RollbackAdmissionSlotWriteOutcome::Idempotent(_)))
        .count();
    let offer_conflict = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RollbackAdmissionSlotWriteOutcome::Conflict { .. }))
        .count();
    ensure!(offer_applied == 1);
    ensure!(offer_idempotent == CONCURRENT_WRITERS / 2 - 1);
    ensure!(offer_conflict == CONCURRENT_WRITERS / 2);
    let winner = current(adapter.read::<PHash>(mainnet()).await?)?;
    ensure!(winner.revision().get() == 1);
    let winning_offer = competing
        .iter()
        .find(|sealed| sealed.candidate() == &winner)
        .context("find winning inbox offer")?;
    ensure!(cas_until_observed(&adapter, winning_offer)
        .await?
        .eq(&RollbackAdmissionSlotWriteOutcome::Idempotent(winner)));
    let winning_target = winner
        .state()
        .pending()
        .context("winner must be pending")?
        .request()
        .target()
        .checkpoint_id()
        .get();

    drop(adapter);
    drop(session);
    let reconnected_session = Arc::new(connect(None, Consistency::Quorum).await?);
    let reconnected = ScyllaRollbackAdmissionStore::prepare(
        Arc::clone(&reconnected_session),
        CanonicalHeadNoTabletKeyspace::try_new(KEYSPACE)?,
    )
    .await?;
    ensure!(current(reconnected.read::<PHash>(mainnet()).await?)? == winner);

    let clear = SealedRollbackAdmissionSlotCas::clear(mainnet(), winner)?;
    ensure!(matches!(
        cas_until_observed(&reconnected, &clear).await?,
        RollbackAdmissionSlotWriteOutcome::Applied(current)
            if current.revision().get() == 2 && current.state().is_empty()
    ));
    ensure!(matches!(
        cas_until_observed(&reconnected, winning_offer).await?,
        RollbackAdmissionSlotWriteOutcome::Conflict { current }
            if current.revision().get() == 2 && current.state().is_empty()
    ));

    let empty_two = current(reconnected.read::<PHash>(mainnet()).await?)?;
    let offline_offer = SealedRollbackAdmissionSlotCas::offer(
        mainnet(),
        empty_two,
        command(mainnet(), 70, 4_000, 0xC3),
    )?;
    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop C-01d stale replica",
    )?;
    ensure!(matches!(
        cas_until_observed(&reconnected, &offline_offer).await?,
        RollbackAdmissionSlotWriteOutcome::Applied(current)
            if current == *offline_offer.candidate()
    ));
    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart C-01d stale replica",
    )?;
    wait_for_three_up_normal().await?;
    let maintenance = repair_flush_compact_all()?;
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        ensure!(
            read_direct(&direct, mainnet()).await? == Some(*offline_offer.candidate()),
            "direct ONE read on {ip} did not converge to the pending inbox candidate"
        );
    }

    let all_session = connect(None, Consistency::All).await?;
    raw_put(&all_session, public_testnet(), 0, &[0x55; 17]).await?;
    ensure!(matches!(
        reconnected.read::<PHash>(public_testnet()).await,
        Err(RollbackAdmissionScyllaError::Model(_))
    ));
    ensure!(reconnected
        .bootstrap(&RollbackAdmissionSlotBootstrap::<PHash>::new(public_testnet()))
        .await
        .is_err());

    let team_bootstrap = RollbackAdmissionSlotBootstrap::<PHash>::new(team_devnet());
    let team_offer = SealedRollbackAdmissionSlotCas::offer(
        team_devnet(),
        *team_bootstrap.candidate(),
        command(team_devnet(), 60, 5_000, 0xD4),
    )?;
    raw_put(
        &all_session,
        internal_devnet(),
        team_offer.candidate().revision().as_i64(),
        team_offer.candidate_payload(),
    )
    .await?;
    ensure!(matches!(
        reconnected.read::<PHash>(internal_devnet()).await,
        Err(RollbackAdmissionScyllaError::Model(_))
    ));

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
        keyspace: KEYSPACE,
        concurrent_writers: CONCURRENT_WRITERS,
        bootstrap_applied,
        bootstrap_idempotent,
        offer_applied,
        offer_idempotent,
        offer_conflict,
        winning_target,
        maintenance,
        scenarios_passed: vec![
            "UNINITIALIZED",
            "CONCURRENT_IDENTICAL_BOOTSTRAP",
            "TWO_COMMAND_SINGLE_SLOT_RACE",
            "IDEMPOTENT_RESPONSE_LOSS_RETRY",
            "HANDLE_DROP_RECONNECT",
            "EMPTY_PENDING_EMPTY_ABA_FENCE",
            "ONE_REPLICA_OFFLINE_PENDING_WRITE",
            "REPAIR_FLUSH_COMPACT_DIRECT_ONE_CONVERGENCE",
            "MALFORMED_ROW_FAIL_CLOSED",
            "NETWORK_MISMATCH_FAIL_CLOSED",
        ],
        qualification: "C-01d durable inbox RF=3 substrate only; admin RPC, canonical-head phase progression, executor, and full C-01 remain out of scope.",
    };
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
