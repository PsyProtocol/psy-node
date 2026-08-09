//! h23c4c1: queue-sidecar schema/lifecycle production setup gate on RF=3.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use parth_core::{pgoldilocks::PoseidonHasher, PHash};
use psy_data::protocol::chain_context::AuthorityScope;
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

use crate::core::ScyllaCoreStore;

use super::*;

const EXACT: &str = "psy_h23c4c1_exact";
const PARTIAL: &str = "psy_h23c4c1_partial";
const WRONG: &str = "psy_h23c4c1_wrong";
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

fn no_tablet(keyspace: &str) -> String { format!("{keyspace}_no_tablet") }
fn realm() -> AuthorityScope {
    AuthorityScope::Realm { realm_id: 7, realm_sub_id: 2 }
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
    for keyspace in [EXACT, PARTIAL, WRONG] {
        session.query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        ).await?;
        let control = no_tablet(keyspace);
        session.query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {control} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"),
            &[],
        ).await?;
    }
    session.await_schema_agreement().await?;
    Ok(())
}

fn keyspaces(keyspace: &str) -> anyhow::Result<PendingQueueSidecarKeyspaces> {
    Ok(PendingQueueSidecarKeyspaces::try_new(keyspace, no_tablet(keyspace))?)
}

async fn core(keyspace: &str) -> anyhow::Result<ScyllaCoreStore<PHash, PoseidonHasher>> {
    let nodes = NODE_IPS.iter().map(|ip| format!("{ip}:9042")).collect::<Vec<_>>();
    ScyllaCoreStore::new(7, 2, keyspace.to_owned(), &nodes).await
}

async fn target_table_count(session: &Session, keyspace: &str) -> anyhow::Result<usize> {
    let data = session.query_unpaged(
        "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?",
        (keyspace,),
    ).await?.into_rows_result()?.rows::<(String,)>()?.count();
    let control = session.query_unpaged(
        "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?",
        (no_tablet(keyspace),),
    ).await?.into_rows_result()?.rows::<(String,)>()?.count();
    Ok(data + control)
}

fn compose(compose_file: &Path, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker").arg("compose").arg("-f").arg(compose_file).args(args).status().with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

fn docker_exec(container: &str, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker").arg("exec").arg(container).args(args).status().with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

async fn wait_up(expected: usize) -> anyhow::Result<()> {
    for _ in 0..120 {
        let mut up = 0;
        for ip in NODE_IPS {
            if connect(Some(ip), Consistency::One).await.is_ok() { up += 1; }
        }
        if up >= expected { return Ok(()); }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("only part of RF=3 became available")
}

#[derive(Serialize)]
struct H23c4c1Report {
    image: &'static str,
    replication_factor: u8,
    target_tables: usize,
    lifecycle_tables: usize,
    disabled_zero_queue_tables: bool,
    partial_retry_converged: bool,
    wrong_schema_rejected: bool,
    idempotent_deploy: bool,
    one_replica_offline_ready: bool,
    direct_one_nodes_exact: usize,
    direct_one_lifecycle_equal: bool,
    repair_flush_compact: bool,
    ready_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c1_queue_schema_lifecycle_rf3_gate() -> anyhow::Result<()> {
    ensure!(std::env::var("PSY_D04B6H23C4C1_RF3").as_deref() == Ok("1"), "run through tests/rf3/run-d04b6h23c4c1.sh");
    let compose_file = std::env::var("PSY_D04B6H23C4C1_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;

    let exact_core = core(EXACT).await?;
    ensure!(matches!(exact_core.initialize_pending_queue_sidecar_setup(realm(), PendingQueueSidecarSetupMode::Disabled).await?, PendingQueueSidecarSetupOutcome::Disabled));
    let disabled_zero_queue_tables = target_table_count(&session, EXACT).await? == 0;
    ensure!(disabled_zero_queue_tables);

    let exact_receipt = PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), keyspaces(EXACT)?).await?;
    ensure!(target_table_count(&session, EXACT).await? == 13);
    let repeated = PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), keyspaces(EXACT)?).await?;
    let idempotent_deploy = repeated == exact_receipt;
    ensure!(idempotent_deploy);

    let partial_keys = keyspaces(PARTIAL)?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(&session, partial_keys.control()).await?;
    let partial_store = ScyllaPendingQueueSidecarLifecycleStore::prepare(session.clone(), partial_keys.control().clone()).await?;
    let partial_materializing = StoredPendingQueueSidecarDeployment::materializing(partial_keys.clone());
    ensure!(matches!(partial_store.bootstrap(&partial_materializing).await?, PendingQueueSidecarDeploymentWriteOutcome::Applied(_) | PendingQueueSidecarDeploymentWriteOutcome::Idempotent(_)));
    ScyllaPendingPipelineStore::create_schema(&session, partial_keys.control()).await?;
    ensure!(matches!(PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &partial_keys).await?, PendingQueueSidecarSchemaInspection::Partial { .. }));
    PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), partial_keys.clone()).await?;
    let partial_retry_converged = matches!(PendingQueueSidecarSchemaMaterializer::inspect_schema(&session, &partial_keys).await?, PendingQueueSidecarSchemaInspection::Exact { .. });
    ensure!(partial_retry_converged);

    let wrong_keys = keyspaces(WRONG)?;
    ScyllaPendingQueueSidecarLifecycleStore::create_schema(&session, wrong_keys.control()).await?;
    session.query_unpaged(
        format!("CREATE TABLE {}.{} (network_chain_id bigint PRIMARY KEY, wrong blob)", wrong_keys.control().as_str(), PendingQueueSidecarPhysicalTable::Pipeline.table_name()),
        &[],
    ).await?;
    session.await_schema_agreement().await?;
    let wrong_schema_rejected = PendingQueueSidecarDeploymentExecutor::deploy(session.clone(), wrong_keys).await.is_err();
    ensure!(wrong_schema_rejected);

    compose(Path::new(&compose_file), &["stop", "scylla3"], "stop third replica")?;
    wait_up(2).await?;
    let started = Instant::now();
    let ready = exact_core.initialize_pending_queue_sidecar_setup(realm(), PendingQueueSidecarSetupMode::RequireVerified).await?;
    ensure!(matches!(ready, PendingQueueSidecarSetupOutcome::Ready(_)));
    let ready_ms = started.elapsed().as_millis() as u64;
    let one_replica_offline_ready = exact_core.pending_queue_sidecar_setup_view().is_some();
    ensure!(one_replica_offline_ready);

    compose(Path::new(&compose_file), &["start", "scylla3"], "restart third replica")?;
    wait_up(3).await?;
    docker_exec(NODE_CONTAINERS[0], &["nodetool", "cluster", "repair", EXACT], "repair tablet data")?;
    for node in NODE_CONTAINERS {
        docker_exec(node, &["nodetool", "repair", "-pr", &no_tablet(EXACT)], "repair control")?;
        docker_exec(node, &["nodetool", "flush", EXACT], "flush data")?;
        docker_exec(node, &["nodetool", "flush", &no_tablet(EXACT)], "flush control")?;
        docker_exec(node, &["nodetool", "compact", EXACT], "compact data")?;
        docker_exec(node, &["nodetool", "compact", &no_tablet(EXACT)], "compact control")?;
    }

    let mut direct_payloads = Vec::new();
    let mut direct_one_nodes_exact = 0;
    let slot = PendingQueueSidecarDeploymentSlot::for_keyspaces(&keyspaces(EXACT)?);
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        ensure!(matches!(PendingQueueSidecarSchemaMaterializer::inspect_schema(&local, &keyspaces(EXACT)?).await?, PendingQueueSidecarSchemaInspection::Exact { .. }));
        direct_one_nodes_exact += 1;
        let row = local.query_unpaged(
            format!("SELECT revision, deployment_payload FROM {}.{} WHERE deployment_slot = ?", no_tablet(EXACT), PENDING_QUEUE_SIDECAR_LIFECYCLE_TABLE),
            (slot.as_bytes().to_vec(),),
        ).await?.into_rows_result()?.single_row::<(i64, Vec<u8>)>()?;
        direct_payloads.push(row);
    }
    let direct_one_lifecycle_equal = direct_payloads.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_lifecycle_equal);

    let report = H23c4c1Report {
        image: IMAGE,
        replication_factor: 3,
        target_tables: 12,
        lifecycle_tables: 1,
        disabled_zero_queue_tables,
        partial_retry_converged,
        wrong_schema_rejected,
        idempotent_deploy,
        one_replica_offline_ready,
        direct_one_nodes_exact,
        direct_one_lifecycle_equal,
        repair_flush_compact: true,
        ready_ms,
        qualification: "H23C4C1_QUEUE_SCHEMA_SETUP_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D04B6H23C4C1_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
