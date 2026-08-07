use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use futures::future::join_all;
use parth_core::{pgoldilocks::PoseidonHasher, PHash};
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
    CheckpointRef, NetworkId,
};
use psy_node_core::store::{
    branch_exact_schema::{
        AuthorityScope, BranchExactSchemaMaterializationPlan,
    },
    canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
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

use super::{
    inspect_branch_exact_local_node_postflight,
    BranchExactBackfillPlan, BranchExactBackfillReadbackObservation,
    BranchExactBackfillVerifiedReceipt, BranchExactDeploymentIntent,
    BranchExactDeploymentLifecycleBootstrap,
    BranchExactDeploymentLifecyclePhase,
    BranchExactDeploymentLifecycleReadState,
    BranchExactDeploymentNoTabletKeyspace, BranchExactExpectedTopology,
    BranchExactPreparedInventoryCounts, BranchExactSchemaMaterializationRequest,
    BranchExactSchemaMaterializer, BranchExactSchemaSetupError,
    BranchExactSchemaSetupMode, BranchExactSchemaSetupOutcome,
    BranchExactSchemaSetupRequest, BranchExactScyllaNodeId,
    BranchExactTopologyAttestation, BranchExactVerifiedDeploymentReceipt,
    CqlKeyspaceName, ScyllaBranchExactDeploymentLifecycleStore,
    ScyllaBranchExactSchemaSetupGate, SealedBranchExactBackfillPlanCas,
    SealedBranchExactBackfillVerifiedCas,
    SealedBranchExactSchemaVerifiedCas,
};

const COORDINATOR_KEYSPACE: &str = "psy_d04b6h20_coordinator";
const REALM_KEYSPACE: &str = "psy_d04b6h20_realm";
const BASELINE: &str = "f2c18ac";
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

fn no_tablet(keyspace: &str) -> String {
    format!("{keyspace}_no_tablet")
}

fn realm() -> AuthorityScope {
    AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    }
}

fn request(
    keyspace: &str,
    authority: AuthorityScope,
) -> anyhow::Result<BranchExactSchemaMaterializationRequest> {
    let bootstrap = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337)?,
            ChainEpoch::new(0),
            CheckpointRef::new(
                CheckpointId::new(0),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    1, 2, 3, 4,
                )),
            ),
        ),
    )?;
    let plan = BranchExactSchemaMaterializationPlan::try_new(
        &bootstrap, authority, None,
    )?;
    Ok(BranchExactSchemaMaterializationRequest::try_new(
        CqlKeyspaceName::try_new(keyspace)?,
        plan,
    )?)
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
    Ok(SessionBuilder::new()
        .known_nodes_addr(
            NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)),
        )
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await?)
}

async fn create_keyspaces(session: &Session) -> anyhow::Result<()> {
    for keyspace in [COORDINATOR_KEYSPACE, REALM_KEYSPACE] {
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = \
                     {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
                ),
                &[],
            )
            .await?;
        let control = no_tablet(keyspace);
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {control} WITH replication = \
                     {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} \
                     AND tablets = {{'enabled': false}}"
                ),
                &[],
            )
            .await?;
    }
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

async fn establish_final_lifecycle(
    session: Arc<Session>,
    request: &BranchExactSchemaMaterializationRequest,
    topology: &BranchExactExpectedTopology,
) -> anyhow::Result<BranchExactBackfillVerifiedReceipt> {
    let authority = request.plan().authority();
    let schema =
        BranchExactSchemaMaterializer::materialize_schema(&session, request)
            .await?;
    let observations = join_all(NODE_IPS.map(|ip| {
        let keyspace = request.keyspace().clone();
        async move {
            let targeted = connect(Some(ip), Consistency::One).await?;
            inspect_branch_exact_local_node_postflight(
                &targeted,
                &keyspace,
                authority,
            )
            .await
        }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let intent = BranchExactDeploymentIntent::new(request, topology.clone());
    let attestation = BranchExactTopologyAttestation::try_new(
        &schema,
        topology.clone(),
        observations,
    )?;
    let deployment = BranchExactVerifiedDeploymentReceipt::try_new(
        intent.clone(),
        attestation,
    )?;
    let control = BranchExactDeploymentNoTabletKeyspace::try_new(no_tablet(
        request.keyspace().as_str(),
    ))?;
    ScyllaBranchExactDeploymentLifecycleStore::create_schema(&session, &control)
        .await?;
    let store = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        session,
        control,
    )
    .await?;
    let bootstrap = BranchExactDeploymentLifecycleBootstrap::new(intent);
    store.bootstrap(&bootstrap).await?;
    let schema_cas = SealedBranchExactSchemaVerifiedCas::try_new(
        bootstrap.candidate(),
        deployment.clone(),
    )?;
    store.mark_schema_verified(&schema_cas).await?;
    let plan = BranchExactBackfillPlan::genesis_empty(request, deployment)?;
    let planned = SealedBranchExactBackfillPlanCas::try_new(
        schema_cas.candidate(),
        plan.clone(),
    )?;
    store.plan_backfill(&planned).await?;
    let observation = BranchExactBackfillReadbackObservation::new(
        plan.digest(),
        plan.dataset_digest(),
        0,
        0,
        0,
    );
    let verified = SealedBranchExactBackfillVerifiedCas::try_new(
        planned.candidate(),
        observation,
    )?;
    store.mark_backfill_verified(&verified).await?;
    let BranchExactDeploymentLifecycleReadState::Current(current) =
        store.read(verified.slot()).await?
    else {
        bail!("h20 final lifecycle disappeared")
    };
    ensure!(current == *verified.candidate());
    let super::BranchExactDeploymentLifecycleState::BackfillVerified(receipt) =
        current.state()
    else {
        bail!("h20 lifecycle did not reach BACKFILL_VERIFIED")
    };
    Ok(receipt.clone())
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

async fn wait_up(expected: usize) -> anyhow::Result<()> {
    for _ in 0..90 {
        let status = docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "status"],
            "read h20 cluster status",
        )?;
        if status.lines().filter(|line| line.starts_with("UN ")).count()
            == expected
        {
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("h20 RF=3 cluster did not converge to {expected} Up/Normal nodes")
}

async fn core_store(
    keyspace: &str,
    authority: AuthorityScope,
) -> anyhow::Result<ScyllaCoreStore<PHash, PoseidonHasher>> {
    let nodes = NODE_IPS
        .map(|ip| ip.to_string())
        .to_vec();
    let (realm_id, realm_sub_id) = match authority {
        AuthorityScope::Coordinator => (0, 0),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => (u64::from(realm_id), u64::from(realm_sub_id)),
    };
    ScyllaCoreStore::new(
        realm_id,
        realm_sub_id,
        keyspace.to_owned(),
        &nodes,
    )
    .await
}

#[derive(Serialize)]
struct H20Report {
    baseline: &'static str,
    image: &'static str,
    replication_factor: u8,
    coordinator_prepared_tables: usize,
    realm_prepared_tables: usize,
    nonfinal_rejected: bool,
    wrong_authority_rejected: bool,
    one_replica_offline_ready: bool,
    restart_digest_stable: bool,
    ready_ms: u64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h20_branch_exact_controlled_setup_rf3_gate(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H20_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h20.sh"
    );
    let compose_file = std::env::var("PSY_D04B6H20_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_keyspaces(&session).await?;
    let topology = expected_topology().await?;
    let coordinator_request =
        request(COORDINATOR_KEYSPACE, AuthorityScope::Coordinator)?;
    let realm_request = request(REALM_KEYSPACE, realm())?;

    let coordinator_receipt = establish_final_lifecycle(
        session.clone(),
        &coordinator_request,
        &topology,
    )
    .await?;

    // Materialize Realm schema and stop at SCHEMA_VERIFIED first. Reuse the
    // final helper only after proving setup rejects the nonfinal lifecycle.
    let realm_schema = BranchExactSchemaMaterializer::materialize_schema(
        &session,
        &realm_request,
    )
    .await?;
    let realm_observations = join_all(NODE_IPS.map(|ip| {
        let keyspace = realm_request.keyspace().clone();
        async move {
            let targeted = connect(Some(ip), Consistency::One).await?;
            inspect_branch_exact_local_node_postflight(
                &targeted,
                &keyspace,
                realm(),
            )
            .await
        }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let realm_intent =
        BranchExactDeploymentIntent::new(&realm_request, topology.clone());
    let realm_attestation = BranchExactTopologyAttestation::try_new(
        &realm_schema,
        topology.clone(),
        realm_observations,
    )?;
    let realm_deployment = BranchExactVerifiedDeploymentReceipt::try_new(
        realm_intent.clone(),
        realm_attestation,
    )?;
    let realm_control = BranchExactDeploymentNoTabletKeyspace::try_new(
        no_tablet(REALM_KEYSPACE),
    )?;
    ScyllaBranchExactDeploymentLifecycleStore::create_schema(
        &session,
        &realm_control,
    )
    .await?;
    let realm_lifecycle = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        session.clone(),
        realm_control,
    )
    .await?;
    let realm_bootstrap =
        BranchExactDeploymentLifecycleBootstrap::new(realm_intent);
    realm_lifecycle.bootstrap(&realm_bootstrap).await?;
    let realm_schema_cas = SealedBranchExactSchemaVerifiedCas::try_new(
        realm_bootstrap.candidate(),
        realm_deployment.clone(),
    )?;
    realm_lifecycle
        .mark_schema_verified(&realm_schema_cas)
        .await?;
    let provisional_plan = BranchExactBackfillPlan::genesis_empty(
        &realm_request,
        realm_deployment.clone(),
    )?;
    let provisional_planned = SealedBranchExactBackfillPlanCas::try_new(
        realm_schema_cas.candidate(),
        provisional_plan.clone(),
    )?;
    let provisional_observation = BranchExactBackfillReadbackObservation::new(
        provisional_plan.digest(),
        provisional_plan.dataset_digest(),
        0,
        0,
        0,
    );
    let provisional_final = SealedBranchExactBackfillVerifiedCas::try_new(
        provisional_planned.candidate(),
        provisional_observation,
    )?;
    let super::BranchExactDeploymentLifecycleState::BackfillVerified(
        provisional_receipt,
    ) = provisional_final.candidate().state()
    else {
        unreachable!()
    };
    let nonfinal = ScyllaBranchExactSchemaSetupGate::authorize(
        session.clone(),
        REALM_KEYSPACE,
        &no_tablet(REALM_KEYSPACE),
        realm(),
        &BranchExactSchemaSetupRequest::new(provisional_receipt.clone()),
    )
    .await;
    ensure!(matches!(
        nonfinal,
        Err(BranchExactSchemaSetupError::LifecycleNotBackfillVerified(
            BranchExactDeploymentLifecyclePhase::SchemaVerified
        ))
    ));
    realm_lifecycle
        .plan_backfill(&provisional_planned)
        .await?;
    realm_lifecycle
        .mark_backfill_verified(&provisional_final)
        .await?;
    let realm_receipt = provisional_receipt.clone();

    let coordinator_core = core_store(
        COORDINATOR_KEYSPACE,
        AuthorityScope::Coordinator,
    )
    .await?;
    ensure!(matches!(
        coordinator_core
            .initialize_branch_exact_schema_setup(
                AuthorityScope::Coordinator,
                BranchExactSchemaSetupMode::Disabled,
            )
            .await?,
        BranchExactSchemaSetupOutcome::Disabled
    ));
    ensure!(coordinator_core.branch_exact_schema_setup_view().is_none());

    let wrong_authority = ScyllaBranchExactSchemaSetupGate::authorize(
        session.clone(),
        COORDINATOR_KEYSPACE,
        &no_tablet(COORDINATOR_KEYSPACE),
        realm(),
        &BranchExactSchemaSetupRequest::new(coordinator_receipt.clone()),
    )
    .await;
    ensure!(matches!(
        wrong_authority,
        Err(BranchExactSchemaSetupError::AuthorityMismatch { .. })
    ));

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h20 third replica",
    )?;
    wait_up(2).await?;
    let started = Instant::now();
    let ready = coordinator_core
        .initialize_branch_exact_schema_setup(
            AuthorityScope::Coordinator,
            BranchExactSchemaSetupMode::RequireVerified(
                BranchExactSchemaSetupRequest::new(
                    coordinator_receipt.clone(),
                ),
            ),
        )
        .await?;
    let ready_ms = started.elapsed().as_millis() as u64;
    let BranchExactSchemaSetupOutcome::Ready(coordinator_view) = ready else {
        bail!("first h20 setup must produce Ready")
    };
    ensure!(
        coordinator_view.prepared_inventory()
            == BranchExactPreparedInventoryCounts::COORDINATOR_READY
    );
    ensure!(matches!(
        coordinator_core
            .initialize_branch_exact_schema_setup(
                AuthorityScope::Coordinator,
                BranchExactSchemaSetupMode::RequireVerified(
                    BranchExactSchemaSetupRequest::new(
                        coordinator_receipt.clone(),
                    ),
                ),
            )
            .await?,
        BranchExactSchemaSetupOutcome::Idempotent(ref view)
            if view == &coordinator_view
    ));

    let realm_core = core_store(REALM_KEYSPACE, realm()).await?;
    let BranchExactSchemaSetupOutcome::Ready(realm_view) = realm_core
        .initialize_branch_exact_schema_setup(
            realm(),
            BranchExactSchemaSetupMode::RequireVerified(
                BranchExactSchemaSetupRequest::new(realm_receipt.clone()),
            ),
        )
        .await?
    else {
        bail!("Realm h20 setup must produce Ready")
    };
    ensure!(
        realm_view.prepared_inventory()
            == BranchExactPreparedInventoryCounts::REALM_READY
    );

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart h20 third replica",
    )?;
    wait_up(3).await?;
    for keyspace in [COORDINATOR_KEYSPACE, REALM_KEYSPACE] {
        docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "cluster", "repair", keyspace],
            "repair h20 tablet keyspace",
        )?;
        let control = no_tablet(keyspace);
        for node in NODE_CONTAINERS {
            docker_exec(
                node,
                &["nodetool", "repair", "-pr", &control],
                "repair h20 no-tablet keyspace",
            )?;
            docker_exec(node, &["nodetool", "flush", keyspace], "flush h20 target")?;
            docker_exec(node, &["nodetool", "flush", &control], "flush h20 control")?;
            docker_exec(node, &["nodetool", "compact", keyspace], "compact h20 target")?;
            docker_exec(node, &["nodetool", "compact", &control], "compact h20 control")?;
        }
    }

    let restarted = core_store(
        COORDINATOR_KEYSPACE,
        AuthorityScope::Coordinator,
    )
    .await?;
    let BranchExactSchemaSetupOutcome::Ready(restarted_view) = restarted
        .initialize_branch_exact_schema_setup(
            AuthorityScope::Coordinator,
            BranchExactSchemaSetupMode::RequireVerified(
                BranchExactSchemaSetupRequest::new(coordinator_receipt),
            ),
        )
        .await?
    else {
        bail!("restarted h20 setup must produce Ready")
    };
    ensure!(restarted_view.digest() == coordinator_view.digest());

    let report = H20Report {
        baseline: BASELINE,
        image: IMAGE,
        replication_factor: 3,
        coordinator_prepared_tables: 2,
        realm_prepared_tables: 3,
        nonfinal_rejected: true,
        wrong_authority_rejected: true,
        one_replica_offline_ready: true,
        restart_digest_stable: true,
        ready_ms,
    };
    let report_path = std::env::var("PSY_D04B6H20_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
