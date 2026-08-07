use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use parth_core::PHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    NetworkId,
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
    branch_exact_schema_fingerprint, BranchExactPhysicalTableId,
    BranchExactQueries, BranchExactQueryId, BranchExactSchemaInspection,
    BranchExactSchemaMaterializationRequest, BranchExactSchemaMaterializer,
    CqlKeyspaceName, PENDING_REWARD_PROOF_TABLE,
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

const COORDINATOR_KEYSPACE: &str = "psy_d04b6h12_coordinator";
const REALM_KEYSPACE: &str = "psy_d04b6h12_realm";
const PARTIAL_KEYSPACE: &str = "psy_d04b6h12_partial";
const INCOMPATIBLE_KEYSPACE: &str = "psy_d04b6h12_incompatible";
const WRONG_AUTHORITY_KEYSPACE: &str = "psy_d04b6h12_wrong_authority";
const OUTAGE_KEYSPACE: &str = "psy_d04b6h12_outage";
const BASELINE: &str = "5e8d4a38cff9479b3ce9f4f73435853fedf892e9";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
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

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
}

fn realm_authority() -> AuthorityScope {
    AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    }
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

fn request(
    keyspace: &'static str,
    authority: AuthorityScope,
    seed: u64,
) -> anyhow::Result<BranchExactSchemaMaterializationRequest> {
    let bootstrap = genesis(seed)?;
    let plan = BranchExactSchemaMaterializationPlan::try_new(
        &bootstrap,
        authority,
        None,
    )?;
    Ok(BranchExactSchemaMaterializationRequest::try_new(
        CqlKeyspaceName::try_new(keyspace)?,
        plan,
    )?)
}

async fn connect(target: Option<Ipv4Addr>) -> anyhow::Result<Session> {
    let mut profile = ExecutionProfile::builder()
        .consistency(Consistency::Quorum)
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
        .context("connect to isolated D-04b6h12 RF=3 Scylla cluster")
}

async fn create_keyspace(session: &Session, name: &str) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {name} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn table_column_count(
    session: &Session,
    keyspace: &str,
    table: &str,
) -> anyhow::Result<usize> {
    let rows = session
        .query_unpaged(
            "SELECT column_name FROM system_schema.columns WHERE keyspace_name = ? AND table_name = ?",
            (keyspace, table),
        )
        .await?
        .into_rows_result()?;
    let mut count = 0usize;
    for row in rows.rows::<(String,)>()? {
        row?;
        count += 1;
    }
    Ok(count)
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
        "read D-04b6h12 cluster status",
    )
}

async fn wait_for_up_nodes(expected: usize) -> anyhow::Result<()> {
    for _ in 0..90 {
        let status = cluster_status()?;
        let up = status
            .lines()
            .filter(|line| line.starts_with("UN "))
            .count();
        if up == expected {
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!(
        "cluster did not converge to {expected} Up/Normal nodes: {}",
        cluster_status()?
    )
}

#[derive(Debug, Serialize)]
struct D04b6h12Report {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    coordinator_materialize_us: u64,
    realm_materialize_us: u64,
    partial_retry_us: u64,
    outage_materialize_us: u64,
    live_pair_schema_version: String,
    rejoined_cluster_schema_version: String,
    scenarios_passed: Vec<&'static str>,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn d04b6h12_branch_exact_schema_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H12_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h12.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H12_COMPOSE_FILE")
        .context("PSY_D04B6H12_COMPOSE_FILE is required")?;
    let report_path = std::env::var("PSY_D04B6H12_REPORT_PATH")
        .context("PSY_D04B6H12_REPORT_PATH is required")?;
    let started_unix_ms = unix_ms()?;
    wait_for_up_nodes(3).await?;

    let session = connect(None).await?;
    for keyspace in [
        COORDINATOR_KEYSPACE,
        REALM_KEYSPACE,
        PARTIAL_KEYSPACE,
        INCOMPATIBLE_KEYSPACE,
        WRONG_AUTHORITY_KEYSPACE,
        OUTAGE_KEYSPACE,
    ] {
        create_keyspace(&session, keyspace).await?;
    }

    let coordinator_request = request(
        COORDINATOR_KEYSPACE,
        AuthorityScope::Coordinator,
        10,
    )?;
    ensure!(matches!(
        BranchExactSchemaMaterializer::inspect_schema(
            &session,
            coordinator_request.keyspace(),
            AuthorityScope::Coordinator,
        )
        .await?,
        BranchExactSchemaInspection::Absent
    ));
    let started = Instant::now();
    let coordinator_receipt =
        BranchExactSchemaMaterializer::materialize_schema(
            &session,
            &coordinator_request,
        )
        .await?;
    let coordinator_materialize_us = started.elapsed().as_micros() as u64;
    ensure!(
        coordinator_receipt.schema_fingerprint()
            == branch_exact_schema_fingerprint(AuthorityScope::Coordinator)
    );
    ensure!(
        table_column_count(
            &session,
            COORDINATOR_KEYSPACE,
            PENDING_REWARD_PROOF_TABLE,
        )
        .await?
            == 0,
        "Coordinator materialization must not create the Realm proof table"
    );
    let coordinator_retry =
        BranchExactSchemaMaterializer::materialize_schema(
            &session,
            &coordinator_request,
        )
        .await?;
    ensure!(coordinator_retry == coordinator_receipt);

    let realm_request = request(REALM_KEYSPACE, realm_authority(), 20)?;
    let started = Instant::now();
    let realm_receipt = BranchExactSchemaMaterializer::materialize_schema(
        &session,
        &realm_request,
    )
    .await?;
    let realm_materialize_us = started.elapsed().as_micros() as u64;
    ensure!(
        realm_receipt.schema_fingerprint()
            == branch_exact_schema_fingerprint(realm_authority())
    );
    ensure!(matches!(
        BranchExactSchemaMaterializer::inspect_schema(
            &session,
            realm_request.keyspace(),
            realm_authority(),
        )
        .await?,
        BranchExactSchemaInspection::Exact { .. }
    ));

    let partial_request = request(PARTIAL_KEYSPACE, realm_authority(), 30)?;
    let partial_queries = BranchExactQueries::new(partial_request.keyspace());
    session
        .query_unpaged(
            partial_queries
                .get(BranchExactQueryId::CreateBranchToPending)
                .cql(),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    ensure!(matches!(
        BranchExactSchemaMaterializer::inspect_schema(
            &session,
            partial_request.keyspace(),
            realm_authority(),
        )
        .await?,
        BranchExactSchemaInspection::Partial {
            present,
            missing,
        } if present == vec![BranchExactPhysicalTableId::CanonicalChainRefToPendingId]
            && missing == vec![
                BranchExactPhysicalTableId::PendingIdToCanonicalChainRef,
                BranchExactPhysicalTableId::PendingRewardTopProof,
            ]
    ));
    let started = Instant::now();
    BranchExactSchemaMaterializer::materialize_schema(
        &session,
        &partial_request,
    )
    .await?;
    let partial_retry_us = started.elapsed().as_micros() as u64;
    ensure!(matches!(
        BranchExactSchemaMaterializer::inspect_schema(
            &session,
            partial_request.keyspace(),
            realm_authority(),
        )
        .await?,
        BranchExactSchemaInspection::Exact { .. }
    ));

    let incompatible_request =
        request(INCOMPATIBLE_KEYSPACE, realm_authority(), 40)?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE {}.canonical_chain_ref_to_pending_id_table \
                 (canonical_ref text, pending_id bigint, PRIMARY KEY ((canonical_ref), pending_id))",
                incompatible_request.keyspace().as_str()
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    let incompatible_error =
        BranchExactSchemaMaterializer::materialize_schema(
            &session,
            &incompatible_request,
        )
        .await
        .expect_err("incompatible same-name table must fail closed");
    ensure!(incompatible_error.to_string().contains("IncompatibleTable"));
    ensure!(
        table_column_count(
            &session,
            INCOMPATIBLE_KEYSPACE,
            "pending_id_to_canonical_chain_ref_table",
        )
        .await?
            == 0,
        "preflight failure must not create later tables"
    );
    ensure!(
        table_column_count(
            &session,
            INCOMPATIBLE_KEYSPACE,
            PENDING_REWARD_PROOF_TABLE,
        )
        .await?
            == 0,
        "preflight failure must not create the Realm-only table"
    );

    let wrong_authority_request = request(
        WRONG_AUTHORITY_KEYSPACE,
        AuthorityScope::Coordinator,
        50,
    )?;
    BranchExactSchemaMaterializer::materialize_schema(
        &session,
        &wrong_authority_request,
    )
    .await?;
    let wrong_authority_queries =
        BranchExactQueries::new(wrong_authority_request.keyspace());
    session
        .query_unpaged(
            wrong_authority_queries
                .get(BranchExactQueryId::CreatePendingRewardProof)
                .cql(),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    let wrong_authority_error = BranchExactSchemaMaterializer::inspect_schema(
        &session,
        wrong_authority_request.keyspace(),
        AuthorityScope::Coordinator,
    )
    .await
    .expect_err("Coordinator keyspace with Realm-only table must fail closed");
    ensure!(
        wrong_authority_error
            .to_string()
            .contains("UnexpectedTableForAuthority")
    );

    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop one D-04b6h12 RF=3 replica",
    )?;
    wait_for_up_nodes(2).await?;

    let outage_request = request(OUTAGE_KEYSPACE, realm_authority(), 60)?;
    let started = Instant::now();
    let outage_receipt = BranchExactSchemaMaterializer::materialize_schema(
        &session,
        &outage_request,
    )
    .await?;
    let outage_materialize_us = started.elapsed().as_micros() as u64;
    let live_pair_schema_version = session.await_schema_agreement().await?;
    ensure!(
        BranchExactSchemaMaterializer::materialize_schema(
            &session,
            &outage_request,
        )
        .await?
            == outage_receipt,
        "exact retry with one replica offline must be idempotent"
    );

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart D-04b6h12 RF=3 replica",
    )?;
    wait_for_up_nodes(3).await?;
    let rejoined = connect(Some(NODE_IPS[2])).await?;
    let rejoined_cluster_schema_version = rejoined.await_schema_agreement().await?;
    ensure!(
        rejoined_cluster_schema_version == live_pair_schema_version,
        "rejoined node must converge to the schema version acknowledged by the live pair"
    );
    ensure!(matches!(
        BranchExactSchemaMaterializer::inspect_schema(
            &rejoined,
            outage_request.keyspace(),
            realm_authority(),
        )
        .await?,
        BranchExactSchemaInspection::Exact { fingerprint }
            if fingerprint == outage_receipt.schema_fingerprint()
    ));
    ensure!(
        BranchExactSchemaMaterializer::materialize_schema(
            &rejoined,
            &outage_request,
        )
        .await?
            == outage_receipt,
        "retry through the previously stale node must be idempotent"
    );

    let scylla_release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read Scylla release",
    )?
    .trim()
    .to_owned();
    let report = D04b6h12Report {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release,
        replication_factor: 3,
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        coordinator_materialize_us,
        realm_materialize_us,
        partial_retry_us,
        outage_materialize_us,
        live_pair_schema_version: live_pair_schema_version.to_string(),
        rejoined_cluster_schema_version: rejoined_cluster_schema_version
            .to_string(),
        scenarios_passed: vec![
            "Coordinator absent materialization creates exactly two shared tables",
            "Realm absent materialization creates all three target tables",
            "exact materialization retry is idempotent",
            "partial complete-table state converges to exact",
            "incompatible same-name table fails before creating missing tables",
            "Coordinator keyspace rejects unexpected Realm-only table",
            "one replica offline materialization reaches agreement on the live pair",
            "rejoined replica converges to the same schema version and exact columns",
            "retry through the previously stale replica is idempotent",
        ],
        qualification: "isolated RF=3 schema-only Gate; no backfill, cutover, production setup, or writer migration",
    };
    if let Some(parent) = Path::new(&report_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
