use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use parth_core::{protocol::core_types::Q256BitHash, PHash};
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    },
    chain_context::{
        AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
    },
};
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap,
        AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        PersistedAuthorityManifest, SealedAuthorityManifest,
    },
    manifest_record::AuthorityManifestIdentity,
    timestamp::CommitWriteTimestampUs,
    typed::{
        CheckpointId as StorageCheckpointId, LogicalMutation, MerkleNode,
        MutationOperation, MutationValue, NodeIndex, TypedTableKey,
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

use super::*;
use crate::utils::{
    convert_checkpoint_id_to_i64, u64_to_i64_exact, u8_to_i8_exact,
};

const CONTROL_KEYSPACE: &str = "psy_d04b2c_rf3_nt";
const ARTIFACT_KEYSPACE: &str = "psy_d04b2c_rf3_artifacts";
const STATE_KEYSPACE: &str = "psy_d04b2c_rf3_state";
const BASELINE: &str = "2e6f5d0b8d8ab1d87852d211a24170b23d24672a";
const IMAGE: &str = "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
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

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1337).expect("RF=3 network is configured")
}

fn chain(checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(7),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn fixture() -> VerifiedPreparedManifestPackage<PHash> {
    let checkpoint = StorageCheckpointId::try_new(41).unwrap();
    let semantic = [
        (MerkleNode::new(0, NodeIndex::new(0)), 4_u8),
        (MerkleNode::new(1, NodeIndex::new(0)), 5_u8),
        (MerkleNode::new(1, NodeIndex::new(1)), 6_u8),
    ];
    let payload = PreparedPayload::try_v1(
        PreparedPayloadKind::Realm,
        semantic
            .iter()
            .map(|(node, seed)| PreparedSemanticMutation::GlobalUserMerkle {
                checkpoint,
                node: *node,
                value: vec![*seed; 32],
            })
            .collect(),
    )
    .unwrap();
    let payload_bytes = payload.encode_canonical();
    let reference = DurablePreparedPayloadReference::try_from_source(
        payload.kind(),
        1,
        1,
        PreparedPayloadSource::ContentAddressedBytes(&payload_bytes),
    )
    .unwrap();
    let logical = semantic
        .iter()
        .map(|(node, seed)| LogicalMutation::Put {
            key: TypedTableKey::GlobalUserMerkle {
                node: *node,
                checkpoint,
            },
            value: MutationValue::PsyCanonicalBytes(vec![*seed; 32]),
        })
        .collect();
    let full = CanonicalPhysicalMutationBatch::from_logical(logical).unwrap();
    let compact = PreparedReferencePlusSupplementRecord::try_v1(
        reference,
        DerivedSupplementBatch::from_logical(Vec::new()).unwrap(),
        ReplayReceipt::new(
            ReplayAuthority::Realm,
            checkpoint,
            3,
            0,
            vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
        ),
        &payload_bytes,
        &full,
    )
    .unwrap();
    let artifacts =
        CanonicalManifestArtifacts::try_from_compact(&compact, &payload_bytes)
            .unwrap();
    let key = AuthorityTimestampKey::new(
        network(),
        AuthorityScope::Realm {
            realm_id: 3,
            realm_sub_id: 2,
        },
    );
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(40, 1),
        chain(41, 2),
        AuthorityStateTransition::Changed {
            previous_checkpoint: AuthorityStateCheckpointId::new(40),
            checkpoint: AuthorityStateCheckpointId::new(41),
            old_root: AuthorityStateRoot::from_local_state_root(hash(3)),
            new_root: AuthorityStateRoot::from_local_state_root(hash(4)),
        },
        AuthorityHeadPayload::try_new(vec![0x66; 16]).unwrap(),
        artifacts.commitment(),
    )
    .unwrap();
    let reservation = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(500).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    )
    .candidate()
    .seal_reservation(
        key,
        intent.digest(),
        AuthorityClockSampleUs::try_from_i128(501).unwrap(),
    )
    .unwrap();
    let prepared = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    VerifiedPreparedManifestPackage::try_new(&prepared, artifacts).unwrap()
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
        .context("connect to isolated D-04b2c RF=3 Scylla cluster")
}

fn keyspaces() -> anyhow::Result<ManifestPreparedKeyspaces> {
    Ok(ManifestPreparedKeyspaces::new(
        ManifestControlNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        ManifestArtifactKeyspace::try_new(ARTIFACT_KEYSPACE)?,
    ))
}

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {CONTROL_KEYSPACE} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    for keyspace in [ARTIFACT_KEYSPACE, STATE_KEYSPACE] {
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
                ),
                &[],
            )
            .await?;
    }
    ScyllaPreparedManifestStore::create_schema(session, &keyspaces()?).await?;
    // `RollbackableStorePrototype` deliberately prepares the complete G0-06
    // representative query set.  Keep the RF=3 fixture production-shaped by
    // creating the KIV representative table even though this gate executes
    // only the global-user Merkle path.
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.checkpoint_leaf_table (obj_id BIGINT PRIMARY KEY, value BLOB)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.global_user_tree_table (level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((level), node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    Ok(())
}

struct Stores {
    manifests: ScyllaPreparedManifestStore,
    state: RollbackableStorePrototype,
}

async fn open_stores() -> anyhow::Result<Stores> {
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    Ok(Stores {
        manifests: ScyllaPreparedManifestStore::prepare(
            Arc::clone(&session),
            keyspaces()?,
        )
        .await?,
        state: RollbackableStorePrototype::prepare_scylla(
            session,
            CqlKeyspaceName::try_new(STATE_KEYSPACE)?,
            Consistency::Quorum,
        )
        .await?,
    })
}

async fn load_plan(
    stores: &Stores,
    identity: AuthorityManifestIdentity<PHash>,
) -> anyhow::Result<RepresentativeRealmStateReplayPlan<PHash>> {
    let prepared = match stores
        .manifests
        .read_lifecycle(identity)
        .await?
        .context("durable PREPARED row is missing")?
    {
        PersistedAuthorityManifest::Prepared(prepared) => prepared,
        other => bail!("expected PREPARED lifecycle, got {other:?}"),
    };
    let artifacts = stores
        .manifests
        .load_verified_artifacts(&prepared)
        .await?;
    RepresentativeRealmStateReplayPlan::try_from_verified_artifacts(
        &prepared,
        &artifacts,
    )
    .map_err(Into::into)
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

fn docker_container(action: &str, container: &str) -> anyhow::Result<()> {
    let mut command = Command::new("docker");
    command.arg(action).arg(container);
    run_command(command, &format!("docker {action} {container}"))?;
    Ok(())
}

async fn wait_for_three_up_normal() -> anyhow::Result<()> {
    for _ in 0..90 {
        let status = docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "status"],
            "read D-04b2c RF=3 status",
        )?;
        if status.lines().filter(|line| line.starts_with("UN ")).count() == 3 {
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("cluster did not return to three Up/Normal members")
}

fn repair_flush_compact() -> anyhow::Result<()> {
    // The control substrate is intentionally vnode/no-tablet because it uses
    // LWT.  The artifact and representative state keyspaces use Scylla's
    // default tablets.  These two storage modes have distinct repair APIs.
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", CONTROL_KEYSPACE],
            "repair D-04b2c no-tablet control keyspace",
        )?;
    }
    for keyspace in [ARTIFACT_KEYSPACE, STATE_KEYSPACE] {
        docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "cluster", "repair", keyspace],
            "repair D-04b2c tablet keyspace",
        )?;
    }
    for node in NODE_CONTAINERS {
        for keyspace in [CONTROL_KEYSPACE, ARTIFACT_KEYSPACE, STATE_KEYSPACE] {
            docker_exec(
                node,
                &["nodetool", "flush", keyspace],
                "flush D-04b2c keyspace",
            )?;
            docker_exec(
                node,
                &["nodetool", "compact", keyspace],
                "compact D-04b2c keyspace",
            )?;
        }
    }
    Ok(())
}

async fn read_direct_rows(
    ip: Ipv4Addr,
    plan: &RepresentativeRealmStateReplayPlan<PHash>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let session = connect(Some(ip), Consistency::One).await?;
    let query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.global_user_tree_table WHERE level = ? AND node_index = ? AND checkpoint_id = ?"
    );
    let mut values = Vec::with_capacity(plan.mutation_count());
    for sealed in plan.puts() {
        let TypedTableKey::GlobalUserMerkle { node, checkpoint } =
            sealed.resolved().mutation().key()
        else {
            bail!("representative plan exposed a non-Merkle key");
        };
        let value = session
            .query_unpaged(
                query.as_str(),
                (
                    u8_to_i8_exact(node.level()),
                    u64_to_i64_exact(node.index().get()),
                    convert_checkpoint_id_to_i64(checkpoint.get()),
                ),
            )
            .await?
            .into_rows_result()?
            .single_row::<(Vec<u8>,)>()?
            .0;
        values.push(value);
    }
    Ok(values)
}

fn expected_rows(
    plan: &RepresentativeRealmStateReplayPlan<PHash>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    plan.puts()
        .map(|sealed| match sealed.resolved().mutation().operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => {
                Ok(value.clone())
            }
            _ => bail!("representative plan exposed a non-executable value"),
        })
        .collect()
}

#[derive(Serialize)]
struct D04b2cReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    restart_count: u8,
    partial_root_present_before_replay: bool,
    missing_row_rejected_before_seal: bool,
    exact_replay_sealed: bool,
    direct_one_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive local three-node Scylla RF=3 harness"]
async fn d04b2c_representative_state_replay_rf3_gate() -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B2C_RF3").is_none() {
        bail!("set PSY_D04B2C_RF3=1 through run-d04b2c.sh");
    }
    let initial_session = connect(None, Consistency::Quorum).await?;
    create_schema(&initial_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read D-04b2c Scylla version",
    )?
    .trim()
    .to_owned();
    drop(initial_session);

    let package = fixture();
    let identity = *package.record().identity();
    let stores = open_stores().await?;
    ensure!(matches!(
        stores.manifests.persist_prepared(&package).await?,
        psy_node_core::store::manifest_record::PreparedManifestWriteOutcome::Applied(_)
    ));
    let plan = load_plan(&stores, identity).await?;
    ensure!(plan.root_position() == 0, "fixture root must sort first");
    let prefix = plan.root_position() + 1;
    ensure!(prefix < plan.mutation_count());
    RepresentativeRealmStateReplayExecutor::new(&stores.state)
        .reapply_prefix_for_gate(&plan, prefix)
        .await?;
    drop(stores);

    // Simulated process restart: all adapters and sessions are recreated from
    // the durable PREPARED row and immutable artifact chunks.
    let stores = open_stores().await?;
    let plan = load_plan(&stores, identity).await?;
    let executor = RepresentativeRealmStateReplayExecutor::new(&stores.state);
    let partial = executor.read_exact(&plan).await?;
    let root_present = partial[plan.root_position()].is_some();
    ensure!(root_present);
    ensure!(matches!(
        plan.verify_observed_rows(&partial),
        Err(RepresentativeStateReplayError::PhysicalRowMissing { .. })
    ));

    docker_container("stop", NODE_CONTAINERS[2])?;
    executor.reapply_all(&plan).await?;
    let observation = executor.verify_exact(&plan).await?;
    SealedAuthorityManifest::verify_and_seal(
        plan.prepared().clone(),
        observation,
    )?;
    drop(stores);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    repair_flush_compact()?;
    let expected = expected_rows(&plan)?;
    let mut replicas = Vec::new();
    for ip in NODE_IPS {
        replicas.push(read_direct_rows(ip, &plan).await?);
    }
    ensure!(replicas.iter().all(|rows| rows == &expected));

    let report = D04b2cReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        restart_count: 1,
        partial_root_present_before_replay: root_present,
        missing_row_rejected_before_seal: true,
        exact_replay_sealed: true,
        direct_one_replicas_equal: true,
        scenarios_passed: vec![
            "M16_partial_state_write_restart_reapplies_exact_timestamped_rows",
            "M17_root_present_but_missing_non_root_row_cannot_seal",
            "one_replica_offline_quorum_replay_then_repair_flush_compact",
            "direct_one_all_replicas_equal_expected_rows",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "representative Realm global-user Merkle replay only; not production Processor integration or full 35-table replay coverage",
    };
    let report_path = std::env::var("PSY_D04B2C_REPORT_PATH")
        .unwrap_or_else(|_| "target/d04b2c-state-replay-rf3-report.json".into());
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
