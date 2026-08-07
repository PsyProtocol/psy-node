use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use parth_core::{
    crypto::hash::traits::{MerkleHasher, MerkleZeroHasher, QFieldHashable},
    data::hash::{
        merkle_node_key::SimpleMerkleNode,
        merkle_store_key::{
            QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode,
            QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode,
        },
    },
    felt::{FromPrimitiveValuesFelt, ToU64Value, ZeroableFelt},
    pgoldilocks::PoseidonHasher,
    protocol::core_types::Q256BitHash,
    PHash, PF, QCoreProcCheckpointUniqueId,
};
use psy_data::{
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    protocol::chain_context::{AuthorityScope, AuthorityStateCheckpointId},
    v1::qdata::{
        contract::{serialize_imt_leaf_ffs_entry_v2, IMTContractStateLeaf},
        user::PQEDUserLeaf,
    },
};
use psy_node_core::store::realm_imt_mutation_graph::{
    RealmImtBaselineNodeKey, RealmImtMutationGraphConfig,
    RealmImtMutationGraphPlan, RealmImtPredecessorReadPlan,
    RealmImtPredecessorReadRow,
};
use psy_serialize::FastFixedSerializable;
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
    CqlKeyspaceName, RealmImtPredecessorAdapter,
    RealmImtPredecessorReadConcurrency,
};
use crate::utils::{u64_to_i64_exact, u8_to_i8_exact};

const KEYSPACE: &str = "psy_d04b6f_realm_imt_predecessor";
const BASELINE: &str = "b2356eaba4729446eb98fef34f00dcce1173e3d8";
const IMAGE: &str = "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const GLOBAL_HEIGHT: u8 = 4;
const COORDINATOR_HEIGHT: u8 = 2;
const UCT_HEIGHT: u8 = 3;
const CST_HEIGHT: u8 = 3;
const REALM_ID: u64 = 1;
const REALM_SUB_ID: u64 = 2;
const USER_ID: u64 = 5;
const CONTRACT_ID: u64 = 2;
const IMT_INDEX: u64 = 3;
const PREDECESSOR: u64 = 40;
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

fn hash(seed: u8) -> PHash { PHash::from_owned_32bytes([seed; 32]) }

fn levels(mut leaves: Vec<PHash>, height: u8) -> Vec<Vec<PHash>> {
    assert_eq!(leaves.len(), 1usize << height);
    let mut result = vec![Vec::new(); usize::from(height) + 1];
    result[usize::from(height)] = std::mem::take(&mut leaves);
    for level in (0..usize::from(height)).rev() {
        result[level] = result[level + 1]
            .chunks_exact(2)
            .map(|pair| PoseidonHasher::two_to_one(&pair[0], &pair[1]))
            .collect();
    }
    result
}

fn simple_path(
    tree: &[Vec<PHash>],
    height: u8,
    index: u64,
    min_level: u8,
) -> Vec<SimpleMerkleNode<PHash>> {
    (min_level..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            SimpleMerkleNode::new(
                level,
                at_level,
                tree[usize::from(level)][at_level as usize],
            )
        })
        .collect()
}

fn single_path(
    tree: &[Vec<PHash>],
    height: u8,
    tree_id: u64,
    index: u64,
) -> Vec<QMerkleStoreSingleIdNode<PHash>> {
    (0..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            QMerkleStoreSingleIdNode {
                key: QMerkleStoreSingleIdKey {
                    tree_id,
                    level,
                    index: at_level,
                },
                value: tree[usize::from(level)][at_level as usize],
            }
        })
        .collect()
}

fn double_path(
    tree: &[Vec<PHash>],
    height: u8,
    tree_id: u64,
    tree_sub_id: u64,
    index: u64,
) -> Vec<QMerkleStoreDoubleIdNode<PHash>> {
    (0..=height)
        .rev()
        .map(|level| {
            let at_level = index >> (height - level);
            QMerkleStoreDoubleIdNode {
                key: QMerkleStoreDoubleIdKey {
                    tree_id,
                    tree_sub_id,
                    level,
                    index: at_level,
                },
                value: tree[usize::from(level)][at_level as usize],
            }
        })
        .collect()
}

fn encode_ffs<const N: usize, T: FastFixedSerializable<N>>(
    values: &[T],
) -> Vec<u8> {
    let mut result = Vec::with_capacity(values.len() * N);
    for value in values {
        result.extend_from_slice(&value.ffs_to_bytes());
    }
    result
}

struct Fixture {
    prepared: PsyPreparedRealmBlockStateUpdates<PHash>,
    heights: BTreeMap<u64, u8>,
    baseline: BTreeMap<RealmImtBaselineNodeKey, PHash>,
}

impl Fixture {
    fn plan(
        &self,
    ) -> anyhow::Result<RealmImtMutationGraphPlan<PHash, PoseidonHasher>> {
        Ok(RealmImtMutationGraphPlan::<PHash, PoseidonHasher>::try_from_prepared::<PF>(
            AuthorityScope::Realm {
                realm_id: REALM_ID as u32,
                realm_sub_id: REALM_SUB_ID as u16,
            },
            AuthorityStateCheckpointId::new(PREDECESSOR),
            AuthorityStateCheckpointId::new(PREDECESSOR + 1),
            RealmImtMutationGraphConfig::try_new(
                GLOBAL_HEIGHT,
                COORDINATOR_HEIGHT,
                UCT_HEIGHT,
            )?,
            &self.heights,
            &self.prepared,
        )?)
    }
}

fn fixture() -> Fixture {
    let imt_preimage = IMTContractStateLeaf::<PF, PHash> {
        key: hash(1),
        value: hash(2),
        next_key: hash(3),
        next_index: PF::from_u64_value(1),
    };
    let imt_hash = imt_preimage.qfhash::<PoseidonHasher>();

    let mut cst_old_leaves = (0..(1u8 << CST_HEIGHT))
        .map(|i| hash(20 + i))
        .collect::<Vec<_>>();
    cst_old_leaves[2] = PoseidonHasher::get_zero_hash(0);
    let cst_old = levels(cst_old_leaves.clone(), CST_HEIGHT);
    cst_old_leaves[IMT_INDEX as usize] = imt_hash;
    let cst_new = levels(cst_old_leaves, CST_HEIGHT);

    let mut uct_old_leaves = (0..(1u8 << UCT_HEIGHT))
        .map(|i| hash(40 + i))
        .collect::<Vec<_>>();
    uct_old_leaves[CONTRACT_ID as usize] = cst_old[0][0];
    let uct_old = levels(uct_old_leaves.clone(), UCT_HEIGHT);
    uct_old_leaves[CONTRACT_ID as usize] = cst_new[0][0];
    let uct_new = levels(uct_old_leaves, UCT_HEIGHT);

    let old_user = PQEDUserLeaf::<PF, PHash> {
        public_key: hash(60),
        user_state_tree_root: uct_old[0][0],
        balance: PF::from_u64_value(10),
        nonce: PF::ZERO_VALUE,
        last_checkpoint_id: PF::from_u64_value(PREDECESSOR),
        event_index: PF::ZERO_VALUE,
        user_id: PF::from_u64_value(USER_ID),
    };
    let new_user = PQEDUserLeaf::<PF, PHash> {
        user_state_tree_root: uct_new[0][0],
        nonce: PF::from_u64_value(1),
        last_checkpoint_id: PF::from_u64_value(PREDECESSOR + 1),
        ..old_user
    };
    let mut gut_old_leaves = (0..(1u8 << GLOBAL_HEIGHT))
        .map(|i| hash(80 + i))
        .collect::<Vec<_>>();
    gut_old_leaves[USER_ID as usize] = old_user.qfhash::<PoseidonHasher>();
    let gut_old = levels(gut_old_leaves.clone(), GLOBAL_HEIGHT);
    gut_old_leaves[USER_ID as usize] = new_user.qfhash::<PoseidonHasher>();
    let gut_new = levels(gut_old_leaves, GLOBAL_HEIGHT);

    let prepared = PsyPreparedRealmBlockStateUpdates {
        realm_id: REALM_ID,
        realm_sub_id: REALM_SUB_ID,
        unique_pending_id: 90,
        proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(91u128),
        old_realm_root: gut_old[COORDINATOR_HEIGHT as usize]
            [REALM_ID as usize],
        new_realm_root: gut_new[COORDINATOR_HEIGHT as usize]
            [REALM_ID as usize],
        update_global_user_tree_nodes_ffs: encode_ffs(&simple_path(
            &gut_new,
            GLOBAL_HEIGHT,
            USER_ID,
            COORDINATOR_HEIGHT,
        )),
        update_user_contract_tree_nodes_ffs: encode_ffs(&single_path(
            &uct_new,
            UCT_HEIGHT,
            USER_ID,
            CONTRACT_ID,
        )),
        update_contract_state_tree_nodes_ffs: encode_ffs(&double_path(
            &cst_new,
            CST_HEIGHT,
            USER_ID,
            CONTRACT_ID,
            IMT_INDEX,
        )),
        update_user_leaves_ffs: new_user.ffs_to_bytes().to_vec(),
        update_contract_state_imt_leaves_ffs:
            serialize_imt_leaf_ffs_entry_v2(
                USER_ID,
                CONTRACT_ID,
                IMT_INDEX,
                &imt_hash,
                &imt_preimage.key,
                &imt_preimage.value,
                &imt_preimage.next_key,
                imt_preimage.next_index.to_u64_value(),
                false,
            )
            .to_vec(),
    };

    let mut baseline = BTreeMap::new();
    for level in 0..=GLOBAL_HEIGHT {
        for (index, value) in
            gut_old[usize::from(level)].iter().enumerate()
        {
            baseline.insert(
                RealmImtBaselineNodeKey::GlobalUser {
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }
    for level in 0..=UCT_HEIGHT {
        for (index, value) in
            uct_old[usize::from(level)].iter().enumerate()
        {
            baseline.insert(
                RealmImtBaselineNodeKey::UserContract {
                    user_id: USER_ID,
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }
    for level in 0..=CST_HEIGHT {
        for (index, value) in
            cst_old[usize::from(level)].iter().enumerate()
        {
            baseline.insert(
                RealmImtBaselineNodeKey::ContractState {
                    user_id: USER_ID,
                    contract_id: CONTRACT_ID,
                    level,
                    index: index as u64,
                },
                *value,
            );
        }
    }
    Fixture {
        prepared,
        heights: BTreeMap::from([(CONTRACT_ID, CST_HEIGHT)]),
        baseline,
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
        .context("connect to isolated D-04b6f RF=3 Scylla cluster")
}

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {KEYSPACE} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {KEYSPACE}.global_user_tree_table (level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((level), node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (node_index ASC, checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {KEYSPACE}.user_contract_tree_table (tree_id BIGINT, level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {KEYSPACE}.contract_state_tree_table (tree_id BIGINT, tree_sub_id BIGINT, level TINYINT, node_index BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)) WITH CLUSTERING ORDER BY (level ASC, node_index ASC, checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    Ok(())
}

async fn insert_node(
    session: &Session,
    key: RealmImtBaselineNodeKey,
    checkpoint: u64,
    value: &[u8],
) -> anyhow::Result<()> {
    let checkpoint = i64::try_from(checkpoint)?;
    match key {
        RealmImtBaselineNodeKey::GlobalUser { level, index } => {
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {KEYSPACE}.global_user_tree_table (level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?)"
                    ),
                    (
                        u8_to_i8_exact(level),
                        u64_to_i64_exact(index),
                        checkpoint,
                        value,
                    ),
                )
                .await?;
        }
        RealmImtBaselineNodeKey::UserContract {
            user_id,
            level,
            index,
        } => {
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {KEYSPACE}.user_contract_tree_table (tree_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?)"
                    ),
                    (
                        u64_to_i64_exact(user_id),
                        u8_to_i8_exact(level),
                        u64_to_i64_exact(index),
                        checkpoint,
                        value,
                    ),
                )
                .await?;
        }
        RealmImtBaselineNodeKey::ContractState {
            user_id,
            contract_id,
            level,
            index,
        } => {
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {KEYSPACE}.contract_state_tree_table (tree_id, tree_sub_id, level, node_index, checkpoint_id, value) VALUES (?, ?, ?, ?, ?, ?)"
                    ),
                    (
                        u64_to_i64_exact(user_id),
                        u64_to_i64_exact(contract_id),
                        u8_to_i8_exact(level),
                        u64_to_i64_exact(index),
                        checkpoint,
                        value,
                    ),
                )
                .await?;
        }
    }
    Ok(())
}

async fn seed_versions(
    session: &Session,
    fixture: &Fixture,
    read_plan: &RealmImtPredecessorReadPlan,
) -> anyhow::Result<RealmImtBaselineNodeKey> {
    let zero = PoseidonHasher::get_zero_hash(0);
    let absent = read_plan
        .requests()
        .iter()
        .find(|request| fixture.baseline[&request.key()] == zero)
        .context("fixture must contain a zero leaf request")?
        .key();
    let mut wrote_older = false;
    for request in read_plan.requests() {
        let key = request.key();
        let expected = fixture.baseline[&key];
        if key != absent {
            if !wrote_older {
                insert_node(session, key, PREDECESSOR - 2, &[199; 32])
                    .await?;
                wrote_older = true;
            }
            insert_node(
                session,
                key,
                PREDECESSOR - 1,
                &expected.into_owned_32bytes(),
            )
            .await?;
        }
        insert_node(session, key, PREDECESSOR + 1, &[211; 32]).await?;
    }
    ensure!(wrote_older);
    Ok(absent)
}

fn assert_rows(
    fixture: &Fixture,
    rows: &[RealmImtPredecessorReadRow<PHash>],
    absent: RealmImtBaselineNodeKey,
) -> anyhow::Result<()> {
    for row in rows {
        let expected = fixture.baseline[&row.request().key()];
        if row.request().key() == absent {
            ensure!(row.value().is_none(), "absent zero row was materialized by storage");
        } else {
            ensure!(row.value() == Some(&expected), "predecessor row mismatch");
        }
    }
    Ok(())
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
            String::from_utf8_lossy(&output.stderr),
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
            "read D-04b6f RF=3 status",
        )?;
        if status
            .lines()
            .filter(|line| line.starts_with("UN "))
            .count()
            == 3
        {
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("cluster did not return to three Up/Normal members")
}

fn repair_flush_compact() -> anyhow::Result<()> {
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", KEYSPACE],
        "repair D-04b6f tablet keyspace",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "flush", KEYSPACE],
            "flush D-04b6f keyspace",
        )?;
        docker_exec(
            node,
            &["nodetool", "compact", KEYSPACE],
            "compact D-04b6f keyspace",
        )?;
    }
    Ok(())
}

#[derive(Serialize)]
struct D04b6fReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    predecessor_checkpoint: u64,
    predecessor_read_count: usize,
    absent_zero_row_count: usize,
    sequential_read_us: u128,
    concurrent_512_read_us: u128,
    restart_count: u8,
    newest_at_or_before_predecessor_selected: bool,
    newer_suffix_excluded: bool,
    absent_row_materialized_by_graph: bool,
    one_replica_offline_quorum_read_sealed: bool,
    repaired_direct_one_replicas_equal: bool,
    malformed_hash_rejected: bool,
    scenarios_passed: Vec<&'static str>,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive local three-node Scylla RF=3 harness"]
async fn d04b6f_realm_imt_predecessor_rf3_gate() -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B6F_RF3").is_none() {
        bail!("set PSY_D04B6F_RF3=1 through run-d04b6f.sh");
    }

    let seed_session = connect(None, Consistency::All).await?;
    create_schema(&seed_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read D-04b6f Scylla version",
    )?
    .trim()
    .to_owned();
    let fixture = fixture();
    let graph = fixture.plan()?;
    let read_plan = graph.predecessor_read_plan();
    let absent = seed_versions(&seed_session, &fixture, &read_plan).await?;
    drop(seed_session);

    let quorum = connect(None, Consistency::Quorum).await?;
    let adapter = RealmImtPredecessorAdapter::<PHash>::prepare_with_consistency(
        &quorum,
        CqlKeyspaceName::try_new(KEYSPACE)?,
        Consistency::Quorum,
    )
    .await?;

    let started = Instant::now();
    let sequential = adapter
        .read_plan_with_concurrency(
            &quorum,
            &read_plan,
            RealmImtPredecessorReadConcurrency::try_new(1)?,
        )
        .await?;
    let sequential_read_us = started.elapsed().as_micros();
    assert_rows(&fixture, &sequential, absent)?;
    let sequential_seal = graph.verify_predecessor_rows_and_seal(&sequential)?;

    let started = Instant::now();
    let concurrent = adapter
        .read_plan_with_concurrency(
            &quorum,
            &read_plan,
            RealmImtPredecessorReadConcurrency::default(),
        )
        .await?;
    let concurrent_512_read_us = started.elapsed().as_micros();
    assert_rows(&fixture, &concurrent, absent)?;
    let concurrent_seal = graph.verify_predecessor_rows_and_seal(&concurrent)?;
    ensure!(sequential == concurrent);
    ensure!(sequential_seal.digest() == concurrent_seal.digest());

    docker_container("stop", NODE_CONTAINERS[2])?;
    let degraded = adapter.read_plan(&quorum, &read_plan).await?;
    assert_rows(&fixture, &degraded, absent)?;
    let degraded_seal = graph.verify_predecessor_rows_and_seal(&degraded)?;
    ensure!(degraded_seal.digest() == sequential_seal.digest());
    drop(adapter);
    drop(quorum);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    repair_flush_compact()?;
    for ip in NODE_IPS {
        let direct = connect(Some(ip), Consistency::One).await?;
        let direct_adapter =
            RealmImtPredecessorAdapter::<PHash>::prepare_with_consistency(
                &direct,
                CqlKeyspaceName::try_new(KEYSPACE)?,
                Consistency::One,
            )
            .await?;
        let rows = direct_adapter.read_plan(&direct, &read_plan).await?;
        assert_rows(&fixture, &rows, absent)?;
        ensure!(
            graph.verify_predecessor_rows_and_seal(&rows)?.digest()
                == sequential_seal.digest()
        );
    }

    let malformed_key = read_plan
        .requests()
        .iter()
        .find(|request| request.key() != absent)
        .context("fixture must contain a non-zero read")?
        .key();
    let all = connect(None, Consistency::All).await?;
    insert_node(&all, malformed_key, PREDECESSOR, &[7; 31]).await?;
    let malformed_adapter =
        RealmImtPredecessorAdapter::<PHash>::prepare_with_consistency(
            &all,
            CqlKeyspaceName::try_new(KEYSPACE)?,
            Consistency::All,
        )
        .await?;
    ensure!(
        malformed_adapter.read_plan(&all, &read_plan).await.is_err(),
        "31-byte hash must fail closed",
    );

    let report = D04b6fReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        predecessor_checkpoint: PREDECESSOR,
        predecessor_read_count: read_plan.requests().len(),
        absent_zero_row_count: sequential
            .iter()
            .filter(|row| row.value().is_none())
            .count(),
        sequential_read_us,
        concurrent_512_read_us,
        restart_count: 1,
        newest_at_or_before_predecessor_selected: true,
        newer_suffix_excluded: true,
        absent_row_materialized_by_graph: true,
        one_replica_offline_quorum_read_sealed: true,
        repaired_direct_one_replicas_equal: true,
        malformed_hash_rejected: true,
        scenarios_passed: vec![
            "IMT41_prepare_and_execute_all_three_production_shaped_queries",
            "IMT42_select_latest_version_at_or_before_predecessor",
            "IMT43_absent_row_remains_none_and_graph_materializes_zero",
            "IMT44_sequential_and_512_concurrent_reads_seal_identically",
            "IMT45_one_replica_offline_quorum_then_repair_direct_one",
            "IMT46_malformed_stored_hash_fails_closed",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "RF=3 qualification of the isolated Realm IMT predecessor reader and graph seal; not production Processor integration, a normal commit bundle, or full-table rollback execution",
    };
    let report_path = std::env::var("PSY_D04B6F_REPORT_PATH")
        .unwrap_or_else(|_| {
            "target/d04b6f-realm-imt-predecessor-rf3-report.json".into()
        });
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
