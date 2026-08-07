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
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
    CheckpointRef, NetworkId,
};
use psy_node_core::store::{
    branch_exact_schema::{
        AuthorityScope, BranchExactSchemaMaterializationPlan,
    },
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
    },
};
use psy_node_scylla::rollback::{
    decode_branch_exact_deployment_lifecycle_persisted_cells,
    inspect_branch_exact_local_node_postflight,
    BranchExactDeploymentIntent, BranchExactDeploymentLifecycleBootstrap,
    BranchExactDeploymentLifecycleReadState,
    BranchExactDeploymentLifecycleState,
    BranchExactDeploymentLifecycleWriteOutcome,
    BranchExactDeploymentNoTabletKeyspace, BranchExactExpectedTopology,
    BranchExactSchemaMaterializationRequest, BranchExactSchemaMaterializer,
    BranchExactScyllaNodeId, BranchExactTopologyAttestation,
    BranchExactVerifiedDeploymentReceipt, CqlKeyspaceName,
    ScyllaBranchExactDeploymentLifecycleStore,
    SealedBranchExactSchemaVerifiedCas,
    StoredBranchExactDeploymentLifecycle,
    BRANCH_EXACT_DEPLOYMENT_LIFECYCLE_TABLE,
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

const TARGET_KEYSPACE: &str = "psy_d04b6h15_realm";
const CONTROL_KEYSPACE: &str = "psy_d04b6h15_control_nt";
const BASELINE: &str = "453647255b27a56a016a38d71b6e31439bc44c87";
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

fn genesis(seed: u64) -> anyhow::Result<CanonicalHeadBootstrap<PHash>> {
    Ok(CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337)?,
            ChainEpoch::new(0),
            CheckpointRef::new(
                CheckpointId::new(0),
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
    let plan = BranchExactSchemaMaterializationPlan::try_new(
        &genesis(seed)?,
        authority(),
        None,
    )?;
    Ok(BranchExactSchemaMaterializationRequest::try_new(
        CqlKeyspaceName::try_new(TARGET_KEYSPACE)?,
        plan,
    )?)
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
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await
        .context("connect to isolated D-04b6h15 RF=3 Scylla cluster")
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
    expected_topology: BranchExactExpectedTopology,
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
    let attestation = BranchExactTopologyAttestation::try_new(
        &schema_receipt,
        expected_topology,
        observations,
    )?;
    Ok(BranchExactVerifiedDeploymentReceipt::try_new(
        intent,
        attestation,
    )?)
}

fn current(
    state: BranchExactDeploymentLifecycleReadState,
) -> anyhow::Result<StoredBranchExactDeploymentLifecycle> {
    match state {
        BranchExactDeploymentLifecycleReadState::Current(current) => {
            Ok(current)
        }
        BranchExactDeploymentLifecycleReadState::Uninitialized => {
            bail!("deployment lifecycle unexpectedly uninitialized")
        }
    }
}

async fn read_direct(
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
        "read D-04b6h15 RF=3 cluster status",
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

fn repair_flush_compact_control() -> anyhow::Result<MaintenanceTiming> {
    let repair_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", CONTROL_KEYSPACE],
            "repair D-04b6h15 control primary ranges",
        )?;
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let flush_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "flush", CONTROL_KEYSPACE],
            "flush D-04b6h15 control keyspace",
        )?;
    }
    let flush_ms = flush_started.elapsed().as_millis() as u64;
    let compact_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "compact", CONTROL_KEYSPACE],
            "compact D-04b6h15 control keyspace",
        )?;
    }
    Ok(MaintenanceTiming {
        repair_ms,
        flush_ms,
        compact_ms: compact_started.elapsed().as_millis() as u64,
    })
}

#[derive(Clone, Debug, Serialize)]
struct MaintenanceTiming {
    repair_ms: u64,
    flush_ms: u64,
    compact_ms: u64,
}

#[derive(Debug, Serialize)]
struct D04b6h15Report {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    target_keyspace: &'static str,
    control_keyspace: &'static str,
    concurrent_writers: usize,
    bootstrap_applied: usize,
    bootstrap_idempotent: usize,
    verified_applied: usize,
    verified_idempotent: usize,
    final_revision: u64,
    maintenance: MaintenanceTiming,
    topology_before: String,
    topology_after: String,
    scenarios_passed: Vec<&'static str>,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn d04b6h15_branch_exact_deployment_lifecycle_rf3_gate(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H15_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h15.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H15_COMPOSE_FILE")
        .context("PSY_D04B6H15_COMPOSE_FILE is required")?;
    let report_path = std::env::var("PSY_D04B6H15_REPORT_PATH")
        .context("PSY_D04B6H15_REPORT_PATH is required")?;
    let started_unix_ms = unix_ms()?;
    let topology_before = wait_for_up_nodes(3).await?;

    let declared_topology = expected_topology().await?;
    let request_a = request(100)?;
    let request_b = request(200)?;
    let intent_a = BranchExactDeploymentIntent::new(
        &request_a,
        declared_topology.clone(),
    );
    let intent_b = BranchExactDeploymentIntent::new(
        &request_b,
        declared_topology.clone(),
    );

    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let control =
        BranchExactDeploymentNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?;
    ScyllaBranchExactDeploymentLifecycleStore::create_schema(
        &session,
        &control,
    )
    .await?;
    let store = Arc::new(
        ScyllaBranchExactDeploymentLifecycleStore::prepare(
            Arc::clone(&session),
            control,
        )
        .await?,
    );
    ensure!(
        store.lwt_contract().regular() == Consistency::Quorum,
        "lifecycle adapter must use QUORUM"
    );

    let bootstrap_a = BranchExactDeploymentLifecycleBootstrap::new(
        intent_a.clone(),
    );
    ensure!(matches!(
        store.read(bootstrap_a.slot()).await?,
        BranchExactDeploymentLifecycleReadState::Uninitialized
    ));
    let bootstrap_outcomes = join_all(
        (0..CONCURRENT_WRITERS)
            .map(|_| store.bootstrap(&bootstrap_a)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let bootstrap_applied = bootstrap_outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
            )
        })
        .count();
    let bootstrap_idempotent = bootstrap_outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                BranchExactDeploymentLifecycleWriteOutcome::Idempotent(_)
            )
        })
        .count();
    ensure!(bootstrap_applied == 1);
    ensure!(bootstrap_idempotent == CONCURRENT_WRITERS - 1);

    let bootstrap_b = BranchExactDeploymentLifecycleBootstrap::new(
        intent_b.clone(),
    );
    ensure!(bootstrap_b.slot() == bootstrap_a.slot());
    ensure!(matches!(
        store.bootstrap(&bootstrap_b).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Conflict(ref current)
            if current == bootstrap_a.candidate()
    ));

    let verified_a = verified_receipt(
        &request_a,
        intent_a,
        declared_topology.clone(),
    )
    .await?;
    let expected_a = current(store.read(bootstrap_a.slot()).await?)?;
    let sealed_a = SealedBranchExactSchemaVerifiedCas::try_new(
        &expected_a,
        verified_a,
    )?;

    // The exact schema is plan-independent, so a second request can produce a
    // structurally valid receipt. Its old INTENT revision/payload must still
    // lose once A has advanced the durable slot.
    let verified_b = verified_receipt(
        &request_b,
        intent_b,
        declared_topology.clone(),
    )
    .await?;
    let stale_b = SealedBranchExactSchemaVerifiedCas::try_new(
        bootstrap_b.candidate(),
        verified_b,
    )?;

    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop one D-04b6h15 RF=3 replica",
    )?;
    wait_for_up_nodes(2).await?;

    let verified_outcomes = join_all(
        (0..CONCURRENT_WRITERS)
            .map(|_| store.mark_schema_verified(&sealed_a)),
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let verified_applied = verified_outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                BranchExactDeploymentLifecycleWriteOutcome::Applied(_)
            )
        })
        .count();
    let verified_idempotent = verified_outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                BranchExactDeploymentLifecycleWriteOutcome::Idempotent(_)
            )
        })
        .count();
    ensure!(verified_applied == 1);
    ensure!(verified_idempotent == CONCURRENT_WRITERS - 1);

    // Exact response-loss retry is idempotent; a different old revision and
    // payload observes the complete A receipt and fails closed.
    ensure!(matches!(
        store.mark_schema_verified(&sealed_a).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Idempotent(_)
    ));
    let durable_verified = current(store.read(bootstrap_a.slot()).await?)?;
    ensure!(
        durable_verified == *sealed_a.candidate(),
        "durable row must equal the exact sealed VERIFIED candidate"
    );
    ensure!(matches!(
        durable_verified.state(),
        BranchExactDeploymentLifecycleState::SchemaVerified(_)
    ));
    ensure!(matches!(
        store.mark_schema_verified(&stale_b).await?,
        BranchExactDeploymentLifecycleWriteOutcome::Conflict(ref current)
            if current == &durable_verified
    ));

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart D-04b6h15 RF=3 replica",
    )?;
    wait_for_up_nodes(3).await?;
    let maintenance = repair_flush_compact_control()?;
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        ensure!(
            read_direct(&direct, &durable_verified).await?
                == durable_verified,
            "direct ONE read on {ip} did not converge to VERIFIED"
        );
    }

    drop(store);
    drop(session);
    let reconnected_session =
        Arc::new(connect(None, Consistency::Quorum).await?);
    let reconnected = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        Arc::clone(&reconnected_session),
        BranchExactDeploymentNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    ensure!(
        current(reconnected.read(durable_verified.slot()).await?)?
            == durable_verified
    );

    let topology_after = wait_for_up_nodes(3).await?;
    let scylla_release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read Scylla release",
    )?
    .trim()
    .to_owned();
    let report = D04b6h15Report {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release,
        replication_factor: 3,
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        target_keyspace: TARGET_KEYSPACE,
        control_keyspace: CONTROL_KEYSPACE,
        concurrent_writers: CONCURRENT_WRITERS,
        bootstrap_applied,
        bootstrap_idempotent,
        verified_applied,
        verified_idempotent,
        final_revision: durable_verified.revision().get(),
        maintenance,
        topology_before,
        topology_after,
        scenarios_passed: vec![
            "operator-declared three-host topology captured before materialization",
            "64 identical INTENT bootstraps produce one applied LWT",
            "conflicting plan digest for the same slot returns durable INTENT",
            "schema materialization plus every-node postflight produces VERIFIED receipt",
            "64 identical INTENT-to-VERIFIED CAS calls produce one applied LWT",
            "INTENT-to-VERIFIED CAS succeeds with one replica offline",
            "exact response-loss retry is idempotent",
            "stale revision and different lifecycle payload conflict",
            "repair, flush, and compaction converge direct ONE reads on all replicas",
            "startup-shaped reconnect reads the exact VERIFIED payload",
        ],
        qualification: "isolated D-04b6h15 RF=3 Gate for schema deployment lifecycle only; no production setup, startup cutover, backfill, or writer migration",
    };
    if let Some(parent) = Path::new(&report_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
