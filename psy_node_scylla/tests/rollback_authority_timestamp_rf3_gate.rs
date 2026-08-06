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
    authority_commit::{
        AuthorityClockSampleUs, AuthorityCommitIntentDigest, AuthorityIntentObservation,
        AuthorityScope, AuthorityTimestampBootstrap, AuthorityTimestampBootstrapReason,
        AuthorityTimestampKey, AuthorityTimestampReadState, AuthorityTimestampWriteOutcome,
        SealedAuthorityTimestampCompletion, SealedAuthorityTimestampReservation,
        StoredAuthorityTimestampState,
    },
    timestamp::CommitWriteTimestampUs,
};
use psy_node_scylla::rollback::{
    decode_authority_timestamp_persisted_cells, AuthorityTimestampNoTabletKeyspace,
    AuthorityTimestampPrototypeError, ScyllaAuthorityTimestampStore,
    D04A_AUTHORITY_TIMESTAMP_TABLE,
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

const KEYSPACE: &str = "psy_d04a_rf3_nt";
const BASELINE: &str = "a814184ab2b69838e31a03bcda481c93dfd862de";
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

fn network() -> psy_node_core::store::authority_commit::NetworkId {
    psy_node_core::store::authority_commit::NetworkId::try_from_chain_id(1337)
        .expect("public testnet network is configured")
}

fn authority(realm_id: u32) -> AuthorityTimestampKey {
    AuthorityTimestampKey::new(
        network(),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id: 2,
        },
    )
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128)
        .expect("test timestamp fits CQL BIGINT")
}

fn sample(value: i64) -> AuthorityClockSampleUs {
    AuthorityClockSampleUs::try_from_i128(value as i128)
        .expect("test clock sample fits CQL BIGINT")
}

fn digest(value: u8) -> AuthorityCommitIntentDigest {
    AuthorityCommitIntentDigest::from_sealed_commit_digest([value; 32])
}

fn bootstrap(
    key: AuthorityTimestampKey,
    high_water: i64,
    reason: AuthorityTimestampBootstrapReason,
) -> AuthorityTimestampBootstrap {
    AuthorityTimestampBootstrap::new(key, timestamp(high_water), reason)
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
        profile = profile.load_balancing_policy(
            SingleTargetLoadBalancingPolicy::new(
                NodeIdentifier::NodeAddress(SocketAddr::new(IpAddr::V4(ip), 9042)),
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
        .context("connect to isolated D-04a RF=3 Scylla cluster")
}

async fn create_schema(
    session: &Session,
) -> anyhow::Result<AuthorityTimestampNoTabletKeyspace> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {KEYSPACE} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    let keyspace = AuthorityTimestampNoTabletKeyspace::try_new(KEYSPACE)?;
    ScyllaAuthorityTimestampStore::create_schema(session, &keyspace).await?;
    Ok(keyspace)
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
        "read D-04a RF=3 cluster status",
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
            "repair D-04a RF=3 keyspace primary ranges",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let flush_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "flush", KEYSPACE],
            "flush D-04a RF=3 keyspace",
        )?;
    }
    let flush_ms = flush_started.elapsed().as_millis() as u64;
    let compact_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "compact", KEYSPACE],
            "compact D-04a RF=3 keyspace",
        )?;
    }
    Ok(MaintenanceTiming {
        repair_ms,
        flush_ms,
        compact_ms: compact_started.elapsed().as_millis() as u64,
    })
}

fn partition_values(key: AuthorityTimestampKey) -> (i64, i8, i64, i64) {
    match key.authority() {
        AuthorityScope::Coordinator => {
            (i64::from(key.network().chain_id()), 1, 0, 0)
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => (
            i64::from(key.network().chain_id()),
            2,
            i64::from(realm_id),
            i64::from(realm_sub_id),
        ),
    }
}

async fn read_direct(
    session: &Session,
    key: AuthorityTimestampKey,
) -> anyhow::Result<Option<StoredAuthorityTimestampState>> {
    let (network_chain_id, authority_kind, realm_id, realm_sub_id) =
        partition_values(key);
    let row = session
        .query_unpaged(
            format!(
                "SELECT network_chain_id, authority_kind, realm_id, realm_sub_id, revision, state FROM \
                 {KEYSPACE}.{D04A_AUTHORITY_TIMESTAMP_TABLE} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ?"
            ),
            (
                network_chain_id,
                authority_kind,
                realm_id,
                realm_sub_id,
            ),
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(
            i64,
            i8,
            i64,
            i64,
            Option<i64>,
            Option<Vec<u8>>,
        )>()?;
    row.map(
        |(
            network_chain_id,
            authority_kind,
            realm_id,
            realm_sub_id,
            revision,
            state,
        )| {
            decode_authority_timestamp_persisted_cells(
                key,
                network_chain_id,
                authority_kind,
                realm_id,
                realm_sub_id,
                revision,
                state.as_deref(),
            )
            .map_err(Into::into)
        },
    )
    .transpose()
}

fn current(
    state: AuthorityTimestampReadState,
) -> anyhow::Result<StoredAuthorityTimestampState> {
    match state {
        AuthorityTimestampReadState::Current(current) => Ok(current),
        AuthorityTimestampReadState::Uninitialized => {
            bail!("authority timestamp row unexpectedly uninitialized")
        }
    }
}

async fn reserve_until_observed(
    adapter: &ScyllaAuthorityTimestampStore,
    sealed: SealedAuthorityTimestampReservation,
) -> anyhow::Result<AuthorityTimestampWriteOutcome> {
    for attempt in 1..=12_u64 {
        match adapter.reserve(sealed).await {
            Ok(outcome) => return Ok(outcome),
            Err(
                AuthorityTimestampPrototypeError::IndeterminateWrite { .. }
                | AuthorityTimestampPrototypeError::IndeterminateReadFailed {
                    ..
                },
            ) => sleep(Duration::from_millis(attempt * 100)).await,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("reservation remained indeterminate after exact-intent retries")
}

async fn complete_until_observed(
    adapter: &ScyllaAuthorityTimestampStore,
    sealed: SealedAuthorityTimestampCompletion,
) -> anyhow::Result<AuthorityTimestampWriteOutcome> {
    for attempt in 1..=12_u64 {
        match adapter.complete(sealed).await {
            Ok(outcome) => return Ok(outcome),
            Err(
                AuthorityTimestampPrototypeError::IndeterminateWrite { .. }
                | AuthorityTimestampPrototypeError::IndeterminateReadFailed {
                    ..
                },
            ) => sleep(Duration::from_millis(attempt * 100)).await,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("completion remained indeterminate after exact-intent retries")
}

#[derive(Clone, Debug, Serialize)]
struct LatencySummary {
    samples: usize,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

impl LatencySummary {
    fn from_samples(mut values: Vec<u64>) -> Self {
        values.sort_unstable();
        let percentile = |percent: usize| {
            let index = ((values.len() * percent).div_ceil(100)).saturating_sub(1);
            values[index]
        };
        Self {
            samples: values.len(),
            p50_us: percentile(50),
            p95_us: percentile(95),
            p99_us: percentile(99),
            max_us: *values.last().expect("latency report has samples"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct MaintenanceTiming {
    repair_ms: u64,
    flush_ms: u64,
    compact_ms: u64,
}

#[derive(Debug, Serialize)]
struct D04aReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    serial_consistency: &'static str,
    reconciliation_read_consistency: &'static str,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    concurrent_writers: usize,
    concurrent_applied: usize,
    concurrent_conflicts: usize,
    winning_timestamp_us: i64,
    final_revision: u64,
    final_high_water_us: i64,
    concurrent_reserve_latency: LatencySummary,
    offline_reserve_complete_us: u64,
    maintenance: MaintenanceTiming,
    direct_one_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    cleanup_policy: &'static str,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive local three-node Scylla RF=3 harness"]
async fn d04a_authority_timestamp_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04A_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04a.sh"
    );
    let compose_file = std::env::var("PSY_D04A_COMPOSE_FILE")
        .context("PSY_D04A_COMPOSE_FILE is required")?;
    let report_path = std::env::var("PSY_D04A_REPORT_PATH")
        .context("PSY_D04A_REPORT_PATH is required")?;
    let started_unix_ms = unix_ms()?;
    let initial_status = cluster_status()?;
    ensure!(
        initial_status
            .lines()
            .filter(|line| line.starts_with("UN "))
            .count()
            == 3,
        "RF=3 cluster must begin with three Up/Normal nodes"
    );

    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    let keyspace = create_schema(&session).await?;
    let adapter = Arc::new(
        ScyllaAuthorityTimestampStore::prepare(Arc::clone(&session), keyspace.clone())
            .await?,
    );

    let competition_key = authority(70);
    let bootstraps = (0..32u8)
        .map(|value| {
            bootstrap(
                competition_key,
                100_000 + i64::from(value),
                if value % 2 == 0 {
                    AuthorityTimestampBootstrapReason::GenesisNative
                } else {
                    AuthorityTimestampBootstrapReason::ControlledWriterCutover
                },
            )
        })
        .collect::<Vec<_>>();
    let bootstrap_results = join_all(
        bootstraps
            .iter()
            .copied()
            .map(|candidate| adapter.bootstrap(candidate)),
    )
    .await;
    let bootstrap_applied = bootstrap_results
        .iter()
        .filter(|result| {
            matches!(result, Ok(AuthorityTimestampWriteOutcome::Applied(_)))
        })
        .count();
    let bootstrap_conflicts = bootstrap_results
        .iter()
        .filter(|result| {
            matches!(result, Ok(AuthorityTimestampWriteOutcome::Conflict(_)))
        })
        .count();
    ensure!(
        (bootstrap_applied, bootstrap_conflicts) == (1, 31),
        "concurrent bootstrap must have exactly one winner: applied={bootstrap_applied}, conflicts={bootstrap_conflicts}"
    );

    let key = authority(7);
    let initial_bootstrap = bootstrap(
        key,
        1_000_000,
        AuthorityTimestampBootstrapReason::GenesisNative,
    );
    ensure!(
        matches!(
            adapter.bootstrap(initial_bootstrap).await?,
            AuthorityTimestampWriteOutcome::Applied(_)
        ),
        "main authority bootstrap must apply"
    );
    ensure!(
        matches!(
            adapter.bootstrap(initial_bootstrap).await?,
            AuthorityTimestampWriteOutcome::Idempotent(_)
        ),
        "exact bootstrap retry must be idempotent"
    );

    let initial = current(adapter.read(key).await?)?;
    let plans = (1..=CONCURRENT_WRITERS)
        .map(|value| {
            initial
                .seal_reservation(
                    key,
                    digest(value as u8),
                    sample(2_000_000 + value as i64),
                )
                .expect("valid RF=3 reservation")
        })
        .collect::<Vec<_>>();
    let results = join_all(plans.iter().copied().map(|plan| {
        let adapter = Arc::clone(&adapter);
        async move {
            let started = Instant::now();
            let result = adapter.reserve(plan).await;
            (result, started.elapsed().as_micros() as u64)
        }
    }))
    .await;
    let mut applied = 0usize;
    let mut conflicts = 0usize;
    let mut winner = None;
    let mut latencies = Vec::with_capacity(results.len());
    for (index, (result, latency)) in results.into_iter().enumerate() {
        latencies.push(latency);
        match result? {
            AuthorityTimestampWriteOutcome::Applied(_) => {
                applied += 1;
                winner = Some(plans[index]);
            }
            AuthorityTimestampWriteOutcome::Conflict(_) => conflicts += 1,
            AuthorityTimestampWriteOutcome::Idempotent(_) => {
                bail!("distinct concurrent intents cannot be idempotent")
            }
        }
    }
    ensure!(
        (applied, conflicts) == (1, CONCURRENT_WRITERS - 1),
        "reservation competition must have one winner: applied={applied}, conflicts={conflicts}"
    );
    let winner = winner.context("reservation competition had no winner")?;
    ensure!(
        matches!(
            reserve_until_observed(&adapter, winner).await?,
            AuthorityTimestampWriteOutcome::Idempotent(_)
        ),
        "lost reservation response must reconcile to idempotent"
    );
    let winning_timestamp_us = winner.lease().timestamp().as_i64();
    let completion = winner
        .candidate()
        .seal_completion(key, winner.lease())?;
    ensure!(
        matches!(
            complete_until_observed(&adapter, completion).await?,
            AuthorityTimestampWriteOutcome::Applied(_)
        ),
        "winner completion must apply"
    );
    ensure!(
        matches!(
            complete_until_observed(&adapter, completion).await?,
            AuthorityTimestampWriteOutcome::Idempotent(_)
        ),
        "lost completion response must reconcile to idempotent"
    );

    let completed = current(adapter.read(key).await?)?;
    let stale_clock_plan = completed.seal_reservation(key, digest(100), sample(1))?;
    ensure!(
        stale_clock_plan.lease().timestamp().as_i64() == winning_timestamp_us + 1,
        "stale clock sample must allocate high_water + 1"
    );
    ensure!(
        matches!(
            reserve_until_observed(&adapter, stale_clock_plan).await?,
            AuthorityTimestampWriteOutcome::Applied(_)
        ),
        "stale-clock reservation must apply"
    );
    drop(adapter);
    drop(session);

    let restarted_session = Arc::new(connect(None, Consistency::Quorum).await?);
    let restarted = Arc::new(
        ScyllaAuthorityTimestampStore::prepare(
            Arc::clone(&restarted_session),
            keyspace,
        )
        .await?,
    );
    let recovered_active = current(restarted.read(key).await?)?;
    ensure!(
        matches!(
            recovered_active.observe_intent(key, digest(100)),
            AuthorityIntentObservation::Active(lease)
                if lease == stale_clock_plan.lease()
        ),
        "restart must recover the exact active lease"
    );
    ensure!(
        matches!(
            reserve_until_observed(&restarted, stale_clock_plan).await?,
            AuthorityTimestampWriteOutcome::Idempotent(_)
        ),
        "restart exact reservation retry must be idempotent"
    );
    let stale_completion = recovered_active
        .seal_completion(key, stale_clock_plan.lease())?;
    complete_until_observed(&restarted, stale_completion).await?;

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop one D-04a RF=3 replica",
    )?;
    sleep(Duration::from_secs(3)).await;
    let before_offline = current(restarted.read(key).await?)?;
    let offline_plan = before_offline.seal_reservation(
        key,
        digest(101),
        sample(before_offline.high_water().as_i64() + 10),
    )?;
    let offline_started = Instant::now();
    ensure!(
        matches!(
            reserve_until_observed(&restarted, offline_plan).await?,
            AuthorityTimestampWriteOutcome::Applied(_)
        ),
        "QUORUM reservation must succeed with one replica offline"
    );
    let offline_completion = offline_plan
        .candidate()
        .seal_completion(key, offline_plan.lease())?;
    complete_until_observed(&restarted, offline_completion).await?;
    let offline_reserve_complete_us =
        offline_started.elapsed().as_micros() as u64;

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart D-04a RF=3 replica",
    )?;
    wait_for_three_up_normal().await?;
    let maintenance = repair_flush_compact_all()?;

    let final_state = current(restarted.read(key).await?)?;
    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let session = connect(Some(ip), Consistency::One).await?;
        direct.push(
            read_direct(&session, key)
                .await?
                .context("direct ONE read must find allocator row")?,
        );
    }
    let direct_one_replicas_equal =
        direct.iter().all(|state| *state == final_state);
    ensure!(
        direct_one_replicas_equal,
        "repair/flush/compact must converge all direct ONE reads"
    );

    let scylla_release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read Scylla release",
    )?
    .trim()
    .to_owned();
    let report = D04aReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        serial_consistency: "LOCAL_SERIAL",
        reconciliation_read_consistency: "QUORUM",
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        concurrent_writers: CONCURRENT_WRITERS,
        concurrent_applied: applied,
        concurrent_conflicts: conflicts,
        winning_timestamp_us,
        final_revision: final_state.revision().get(),
        final_high_water_us: final_state.high_water().as_i64(),
        concurrent_reserve_latency: LatencySummary::from_samples(latencies),
        offline_reserve_complete_us,
        maintenance,
        direct_one_replicas_equal,
        scenarios_passed: vec![
            "32-way bootstrap has one winner",
            "64-way reservation has one winner",
            "reservation response loss is idempotent",
            "completion response loss is idempotent",
            "stale clock allocates high-water successor",
            "restart recovers exact active lease",
            "one replica offline reserve and complete",
            "repair flush compact direct-ONE convergence",
        ],
        cleanup_policy: "runner removes cluster and volumes unless PSY_D04A_KEEP_CLUSTER=1",
        qualification: "D-04a RF=3 substrate only; D-03 manifest, processor guard, production wiring, and commit-latency SLO remain open",
    };
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write D-04a RF=3 report {report_path}"))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
