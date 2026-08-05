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
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
};
use psy_node_core::store::canonical_head::{
    CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile, CanonicalHeadReadState,
    CanonicalHeadTransition, CanonicalHeadWriteOutcome, SealedCanonicalHeadCas,
    StoredCanonicalHead,
};
use psy_node_scylla::rollback::{
    CanonicalHeadNoTabletKeyspace, CanonicalHeadPrototypeAdapter,
    CanonicalHeadPrototypeError, C01A_CANONICAL_HEAD_TABLE,
};
use scylla::{
    client::{execution_profile::ExecutionProfile, session::Session, session_builder::SessionBuilder},
    policies::load_balancing::{NodeIdentifier, SingleTargetLoadBalancingPolicy},
    statement::Consistency,
};
use serde::Serialize;
use tokio::time::sleep;

const KEYSPACE: &str = "psy_c01a_rf3_nt";
const BASELINE: &str = "43a1097f88df6d55810e7af30502d80c44401c09";
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

fn canary() -> NetworkId {
    network(0xCFCF_CFCF)
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

fn canonical_ref(
    network: NetworkId,
    epoch: u64,
    checkpoint: u64,
    hash_seed: u64,
) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network,
        ChainEpoch::new(epoch),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(hash_seed)),
        ),
    )
}

fn genesis(network: NetworkId, hash_seed: u64) -> CanonicalHeadBootstrap<PHash> {
    CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        canonical_ref(network, 0, 0, hash_seed),
    )
    .expect("valid test genesis")
}

fn advance(
    expected: StoredCanonicalHead<PHash>,
    hash_seed: u64,
) -> SealedCanonicalHeadCas<PHash> {
    CanonicalHeadTransition::normal_checkpoint_advance(
        expected,
        canonical_ref(
            expected.canonical_ref().network_id(),
            expected.canonical_ref().chain_epoch().get(),
            expected.canonical_ref().checkpoint().checkpoint_id().get() + 1,
            hash_seed,
        ),
    )
    .expect("valid one-checkpoint test advance")
    .seal()
}

fn open_epoch(expected: StoredCanonicalHead<PHash>) -> SealedCanonicalHeadCas<PHash> {
    CanonicalHeadTransition::open_rollback_epoch(
        expected,
        CanonicalChainRef::new(
            expected.canonical_ref().network_id(),
            ChainEpoch::new(expected.canonical_ref().chain_epoch().get() + 1),
            *expected.canonical_ref().checkpoint(),
        ),
    )
    .expect("valid test epoch transition")
    .seal()
}

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
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
        .context("connect to isolated C-01a RF=3 Scylla cluster")
}

async fn create_schema(session: &Session) -> anyhow::Result<CanonicalHeadNoTabletKeyspace> {
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
    CanonicalHeadPrototypeAdapter::create_schema(session, &keyspace).await?;
    Ok(keyspace)
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
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "status"],
        "read C-01a RF=3 cluster status",
    )
}

async fn wait_for_three_up_normal() -> anyhow::Result<String> {
    for _ in 0..90 {
        let status = cluster_status()?;
        if status.lines().filter(|line| line.starts_with("UN ")).count() == 3 {
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
            "repair C-01a RF=3 keyspace primary ranges",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let flush_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "flush", KEYSPACE],
            "flush C-01a RF=3 keyspace",
        )?;
    }
    let flush_ms = flush_started.elapsed().as_millis() as u64;
    let compact_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "compact", KEYSPACE],
            "compact C-01a RF=3 keyspace",
        )?;
    }
    Ok(MaintenanceTiming {
        repair_ms,
        flush_ms,
        compact_ms: compact_started.elapsed().as_millis() as u64,
    })
}

async fn read_direct(
    session: &Session,
    requested_network: NetworkId,
) -> anyhow::Result<Option<StoredCanonicalHead<PHash>>> {
    let row = session
        .query_unpaged(
            format!(
                "SELECT network_chain_id, revision, canonical_ref FROM \
                 {KEYSPACE}.{C01A_CANONICAL_HEAD_TABLE} WHERE network_chain_id = ?"
            ),
            (i64::from(requested_network.chain_id()),),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64, Option<i64>, Option<Vec<u8>>)>()?;
    row.map(|(network_chain_id, revision, canonical_ref)| {
        psy_node_scylla::rollback::decode_canonical_head_persisted_cells::<PHash>(
            requested_network,
            network_chain_id,
            revision,
            canonical_ref.as_deref(),
        )
        .map_err(Into::into)
    })
    .transpose()
}

async fn raw_put(
    session: &Session,
    partition_network: NetworkId,
    revision: i64,
    canonical_ref: &[u8],
) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "INSERT INTO {KEYSPACE}.{C01A_CANONICAL_HEAD_TABLE} \
                 (network_chain_id, revision, canonical_ref) VALUES (?, ?, ?)"
            ),
            (
                i64::from(partition_network.chain_id()),
                revision,
                canonical_ref,
            ),
        )
        .await?;
    Ok(())
}

fn current(
    state: CanonicalHeadReadState<PHash>,
) -> anyhow::Result<StoredCanonicalHead<PHash>> {
    match state {
        CanonicalHeadReadState::Current(current) => Ok(current),
        CanonicalHeadReadState::Uninitialized => bail!("canonical head unexpectedly uninitialized"),
    }
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
    identical_bootstrap_applied: usize,
    identical_bootstrap_idempotent: usize,
    competing_cas_applied: usize,
    competing_cas_conflict: usize,
    maintenance: MaintenanceTiming,
    scenarios_passed: Vec<&'static str>,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn canonical_head_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_C01A_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-c01a.sh"
    );
    let started_unix_ms = unix_ms()?;
    let compose_file = std::env::var("PSY_C01A_COMPOSE_FILE").context("PSY_C01A_COMPOSE_FILE")?;
    let report_path = std::env::var("PSY_C01A_REPORT_PATH").context("PSY_C01A_REPORT_PATH")?;
    let topology_before = wait_for_three_up_normal().await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    let keyspace = create_schema(&session).await?;
    let adapter = CanonicalHeadPrototypeAdapter::prepare(Arc::clone(&session), keyspace).await?;
    ensure!(adapter.prepared_contracts()[0] == (Some(Consistency::Quorum), None));
    ensure!(adapter.prepared_contracts()[1..].iter().all(|entry| {
        *entry
            == (
                Some(Consistency::Quorum),
                Some(scylla::statement::SerialConsistency::LocalSerial),
            )
    }));

    // A missing row is not genesis and must stay explicitly uninitialized.
    ensure!(matches!(
        adapter.read::<PHash>(mainnet()).await?,
        CanonicalHeadReadState::Uninitialized
    ));

    // Concurrent identical bootstrap is a single applied write plus exact
    // idempotent reconciliation for every loser.
    let mainnet_bootstrap = genesis(mainnet(), 1);
    let bootstrap_started = Instant::now();
    let bootstrap_outcomes = join_all(
        (0..CONCURRENT_WRITERS).map(|_| adapter.bootstrap(&mainnet_bootstrap)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let identical_bootstrap_applied = bootstrap_outcomes
        .iter()
        .filter(|outcome| outcome.was_applied())
        .count();
    let identical_bootstrap_idempotent = bootstrap_outcomes
        .iter()
        .filter(|outcome| outcome.was_idempotent())
        .count();
    ensure!(identical_bootstrap_applied == 1);
    ensure!(identical_bootstrap_idempotent == CONCURRENT_WRITERS - 1);
    ensure!(bootstrap_started.elapsed() < Duration::from_secs(120));

    // Different bootstrap candidates for another network still have exactly
    // one winner; all conflicts return that complete durable row.
    let competing_bootstraps = (0..CONCURRENT_WRITERS)
        .map(|index| genesis(team_devnet(), 10_000 + index as u64 * 4))
        .collect::<Vec<_>>();
    let outcomes = join_all(
        competing_bootstraps
            .iter()
            .map(|bootstrap| adapter.bootstrap(bootstrap)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    ensure!(outcomes.iter().filter(|outcome| outcome.was_applied()).count() == 1);
    let team_winner = current(adapter.read::<PHash>(team_devnet()).await?)?;
    for outcome in outcomes {
        ensure!(outcome.current() == &team_winner);
    }

    // Different valid candidates from the same expected state have one CAS
    // winner. Every loser observes the full winner row.
    let expected = *mainnet_bootstrap.candidate();
    let competing = (0..CONCURRENT_WRITERS)
        .map(|index| advance(expected, 20_000 + index as u64 * 4))
        .collect::<Vec<_>>();
    let outcomes = join_all(
        competing
            .iter()
            .map(|sealed| adapter.compare_and_set(sealed)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let competing_cas_applied = outcomes
        .iter()
        .filter(|outcome| outcome.was_applied())
        .count();
    let competing_cas_conflict = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, CanonicalHeadWriteOutcome::Conflict { .. }))
        .count();
    ensure!(competing_cas_applied == 1);
    ensure!(competing_cas_conflict == CONCURRENT_WRITERS - 1);
    let winner = current(adapter.read::<PHash>(mainnet()).await?)?;
    let winning_sealed = competing
        .iter()
        .find(|sealed| sealed.candidate() == &winner)
        .context("find winning sealed CAS")?;
    for outcome in outcomes {
        ensure!(outcome.current() == &winner);
    }

    // Simulate a lost caller response: the exact same sealed transition sees
    // candidate as current and reports idempotent success.
    ensure!(adapter
        .compare_and_set(winning_sealed)
        .await?
        .was_idempotent());

    // Opening the next rollback epoch changes only epoch and revision.
    let epoch_transition = open_epoch(winner);
    ensure!(adapter.compare_and_set(&epoch_transition).await?.was_applied());
    let epoch_head = *epoch_transition.candidate();

    // A quorum CAS remains durable while one replica is offline. After the
    // replica returns, repair/flush/compaction must converge every direct ONE
    // read to the exact candidate.
    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop C-01a stale replica",
    )?;
    let offline_transition = advance(epoch_head, 30_000);
    ensure!(adapter
        .compare_and_set(&offline_transition)
        .await?
        .was_applied());
    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart C-01a stale replica",
    )?;
    wait_for_three_up_normal().await?;
    let maintenance = repair_flush_compact_all()?;
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        ensure!(
            read_direct(&direct, mainnet()).await? == Some(*offline_transition.candidate()),
            "direct ONE read on {ip} did not converge to the canonical candidate"
        );
    }

    // Drop every adapter/session handle and prove startup-shaped reconnect
    // reads the same durable row.
    drop(adapter);
    drop(session);
    let reconnected_session = Arc::new(connect(None, Consistency::Quorum).await?);
    let reconnected = CanonicalHeadPrototypeAdapter::prepare(
        Arc::clone(&reconnected_session),
        CanonicalHeadNoTabletKeyspace::try_new(KEYSPACE)?,
    )
    .await?;
    ensure!(
        current(reconnected.read::<PHash>(mainnet()).await?)?
            == *offline_transition.candidate()
    );

    // Real Scylla ABA injection: payload returns to A but revision advances to
    // two. The original revision-zero expected state can no longer write B.
    let canary_bootstrap = genesis(canary(), 40_000);
    ensure!(reconnected.bootstrap(&canary_bootstrap).await?.was_applied());
    let canary_a_to_b = advance(*canary_bootstrap.candidate(), 41_000);
    ensure!(reconnected.compare_and_set(&canary_a_to_b).await?.was_applied());
    let all_session = connect(None, Consistency::All).await?;
    raw_put(
        &all_session,
        canary(),
        2,
        canary_bootstrap.candidate_payload(),
    )
    .await?;
    ensure!(matches!(
        reconnected.compare_and_set(&canary_a_to_b).await?,
        CanonicalHeadWriteOutcome::Conflict { current }
            if current.revision().get() == 2
                && current.canonical_ref() == canary_bootstrap.candidate().canonical_ref()
    ));

    // Malformed and partition/payload network-mismatched rows fail closed and
    // an IF NOT EXISTS bootstrap cannot repair or overwrite them.
    let malformed = vec![0x55; 17];
    raw_put(&all_session, public_testnet(), 0, &malformed).await?;
    ensure!(matches!(
        reconnected.read::<PHash>(public_testnet()).await,
        Err(CanonicalHeadPrototypeError::Model(_))
    ));
    ensure!(reconnected
        .bootstrap(&genesis(public_testnet(), 50_000))
        .await
        .is_err());
    let mismatch_payload = genesis(team_devnet(), 60_000).candidate_payload().to_vec();
    raw_put(&all_session, internal_devnet(), 0, &mismatch_payload).await?;
    ensure!(matches!(
        reconnected.read::<PHash>(internal_devnet()).await,
        Err(CanonicalHeadPrototypeError::Model(_))
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
        identical_bootstrap_applied,
        identical_bootstrap_idempotent,
        competing_cas_applied,
        competing_cas_conflict,
        maintenance,
        scenarios_passed: vec![
            "UNINITIALIZED",
            "CONCURRENT_IDENTICAL_BOOTSTRAP",
            "CONCURRENT_CONFLICTING_BOOTSTRAP",
            "CONCURRENT_EXPECTED_STATE_CAS",
            "IDEMPOTENT_RESPONSE_LOSS_RETRY",
            "OPEN_EPOCH",
            "ONE_REPLICA_OFFLINE_REPAIR_RESTART",
            "HANDLE_DROP_RECONNECT",
            "REVISION_ABA_FENCE",
            "MALFORMED_ROW_FAIL_CLOSED",
            "NETWORK_MISMATCH_FAIL_CLOSED",
        ],
        qualification: "C-01a durable-row RF=3 mechanism evidence only; not production authority, commit integration, D-01b RPC, or full C-01 control.",
    };
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
