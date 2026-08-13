//! D1-A08: pre-PONR Coordinator suffix archive on a real Scylla RF=3 cluster.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use parth_core::{
    crypto::hash::traits::{QFieldHashable, ZeroableHash},
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{Q256BitHash, QZKProofPublicInputsHasherReader},
    PHash, PF,
};
use psy_data::{
    protocol::{
        canonical_chain::{
            checkpoint_hash_from_previous, genesis_checkpoint_hash,
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        checkpoint_transition_hash::{
            CheckpointStateHashTransition,
            CheckpointStateTransitionPublicInputs,
        },
        verifiable_checkpoint_transition::{
            PsyVerifiableCheckpointTransition,
            PsyVerifiableCheckpointTransitionWithProof,
        },
    },
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats},
        populated_checkpoint::PsyCheckpointLeafPopulated,
    },
};
use psy_node_core::store::{
    branch_pending_mapping::BranchPendingMapping,
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
        CanonicalHeadTransition, StoredCanonicalHead,
    },
    rollback_control::{
        RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
    },
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    typed::UniquePendingId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
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
use sha2::{Digest, Sha256};
use tokio::time::sleep;

use crate::compression;

use super::{
    coordinator_rollback_archive_store::{
        ScyllaCoordinatorRollbackArchiveStore,
        COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
    },
    coordinator_rollback_branch_catalog::ScyllaCoordinatorRollbackBranchCatalog,
    coordinator_rollback_realm_reward_catalog::ScyllaCoordinatorRollbackRealmRewardCatalog,
    *,
};

const SOURCE: &str = "psy_d1a08_source";
const BRANCH: &str = "psy_d1a08_branch";
const ARCHIVE: &str = "psy_d1a08_archive";
const HEAD: &str = "psy_d1a08_head_nt";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const SOURCE_WRITETIME_US: i64 = 9_000;
const TARGET: u64 = 1;
const OLD_HEAD: u64 = 4;
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

#[derive(Clone, Copy, Debug)]
struct HashProofVerifier;

impl QZKProofPublicInputsHasherReader<PHash, PHash> for HashProofVerifier {
    fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
        Ok(*proof)
    }

    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
        Ok(PHash::from_owned_32bytes(bytes.try_into()?))
    }
}

#[derive(Clone, Debug)]
struct Fixture {
    config: BranchExactCheckpointChainConfig<PHash>,
    refs: Vec<CheckpointRef<PHash>>,
    transitions: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DirectDataset {
    tables: BTreeMap<String, Vec<String>>,
}

impl DirectDataset {
    fn row_count(&self) -> usize {
        self.tables.values().map(Vec::len).sum()
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(serde_json::to_vec(self).expect("snapshot is serializable")).into()
    }
}

#[derive(Serialize)]
struct GateReport {
    image: &'static str,
    replication_factor: u8,
    suffix_checkpoints: u64,
    checkpoint_archive_rows: u64,
    mapping_archive_rows: u64,
    reward_archive_rows: u64,
    archive_fragment_rows: usize,
    caller_discard_retry: bool,
    socket_response_loss_injected: bool,
    one_replica_offline_archive: bool,
    source_rows_preserved: bool,
    canonical_head_unchanged_during_archive: bool,
    archive_rerun_idempotent: bool,
    repair_flush_compact: bool,
    repair_ms: u64,
    direct_one_nodes: usize,
    direct_one_tables: usize,
    direct_one_rows: usize,
    direct_one_dataset_digest: String,
    direct_one_equal: bool,
    participant_archive_receipt: bool,
    global_archive_barrier: bool,
    destructive_started: bool,
    hot_suffix_deleted: bool,
    target_restored: bool,
    new_branch_t_plus_1: bool,
    production_rollback_available: bool,
    qualification: &'static str,
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1).expect("test network exists")
}

fn transitions() -> Fixture {
    let genesis_fingerprint = hash(100);
    let genesis_transition_hash = hash(200);
    let checkpoint_fingerprint = hash(300);
    let config = BranchExactCheckpointChainConfig::new(
        genesis_fingerprint,
        genesis_transition_hash,
        checkpoint_fingerprint,
    );
    let leaf = PsyCheckpointLeafPopulated {
        global_state_roots: PQEDCheckpointGlobalStateRoots {
            contract_tree_root: PHash::get_zero_value(),
            deposit_tree_root: PHash::get_zero_value(),
            user_tree_root: PHash::get_zero_value(),
            withdrawal_tree_root: PHash::get_zero_value(),
            user_registration_tree_root: PHash::get_zero_value(),
        },
        stats: PQEDCheckpointLeafStats::get_empty_stats(),
    };
    let leaf_hash = leaf.qfhash::<PoseidonHasher>();
    let mut previous_root = hash(400);
    let mut previous_leaf = leaf_hash;
    let mut previous_chain = None;
    let mut rows = Vec::new();
    let mut refs = Vec::new();
    for checkpoint_id in 0..=OLD_HEAD {
        let new_root = hash(500 + checkpoint_id * 10);
        let state = CheckpointStateHashTransition {
            old_checkpoint_tree_root: if checkpoint_id == 0 {
                new_root
            } else {
                previous_root
            },
            new_checkpoint_tree_root: new_root,
            old_checkpoint_leaf_hash: if checkpoint_id == 0 {
                leaf_hash
            } else {
                previous_leaf
            },
            new_checkpoint_leaf_hash: leaf_hash,
        };
        let chain_hash = if checkpoint_id == 0 {
            genesis_checkpoint_hash::<_, PoseidonHasher>(
                new_root,
                leaf_hash,
                genesis_fingerprint,
            )
        } else {
            checkpoint_hash_from_previous::<_, PoseidonHasher>(
                CheckpointHash::from_last_chain_hash(previous_chain.unwrap()),
                new_root,
                leaf_hash,
                checkpoint_fingerprint,
            )
        };
        let transition = PsyVerifiableCheckpointTransitionWithProof {
            info: PsyVerifiableCheckpointTransition {
                state_transition: CheckpointStateTransitionPublicInputs {
                    checkpoint_transition: state,
                    genesis_checkpoint_state_transition_hash: genesis_transition_hash,
                    checkpoint_state_transition_circuit_fingerprint: checkpoint_fingerprint,
                },
                checkpoint_leaf: leaf,
            },
            circuit_type: 7,
            zk_proof: if checkpoint_id == 0 {
                Vec::new()
            } else {
                chain_hash.as_inner().into_owned_32bytes().to_vec()
            },
        };
        rows.push(transition.psy_ser_to_bytes_vec().unwrap());
        refs.push(CheckpointRef::new(CheckpointId::new(checkpoint_id), chain_hash));
        previous_root = new_root;
        previous_leaf = leaf_hash;
        previous_chain = Some(*chain_hash.as_inner());
    }
    Fixture {
        config,
        refs,
        transitions: rows,
    }
}

fn hash(seed: u64) -> PHash {
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn request(fixture: &Fixture) -> RollbackRequest<PHash> {
    RollbackRequest::try_new(
        fixture.refs[OLD_HEAD as usize],
        fixture.refs[TARGET as usize],
        TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(10_000).unwrap(),
            10_001,
            10_002,
        )
        .unwrap(),
        RollbackExecutionMode::InPlace,
        RollbackPlanDigest::try_new([0xA8; 32]).unwrap(),
    )
    .unwrap()
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

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    for keyspace in [SOURCE, BRANCH, ARCHIVE] {
        session
            .query_unpaged(
                format!(
                    "CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
                ),
                &[],
            )
            .await?;
    }
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {HEAD} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    for table in [
        "checkpoint_leaf_table",
        "l2_block_state_table",
        "checkpoint_state_roots_table",
        "checkpoint_zk_proof_and_transition_table",
    ] {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {SOURCE}.{table} (obj_id bigint PRIMARY KEY, value blob)"
                ),
                &[],
            )
            .await?;
    }
    for table in [
        "checkpoint_id_to_pending_id_table",
        "pending_id_to_checkpoint_id_table",
    ] {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {SOURCE}.{table} (obj_id bigint PRIMARY KEY, value bigint)"
                ),
                &[],
            )
            .await?;
    }
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {SOURCE}.realm_rewards_tree_node_key_table (obj_id bigint, checkpoint_id bigint, value blob, PRIMARY KEY ((obj_id), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {BRANCH}.{BRANCH_TO_PENDING_TABLE} (canonical_ref blob, pending_id bigint, mapping_digest blob, PRIMARY KEY ((canonical_ref), pending_id))"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {BRANCH}.{PENDING_TO_BRANCH_TABLE} (pending_id bigint, canonical_ref blob, mapping_digest blob, PRIMARY KEY ((pending_id), canonical_ref))"
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    ScyllaCanonicalHeadStore::create_schema(
        session,
        &CanonicalHeadNoTabletKeyspace::try_new(HEAD)?,
    )
    .await?;
    ScyllaCoordinatorRollbackArchiveStore::create_schema(
        session,
        &CqlKeyspaceName::try_new(ARCHIVE)?,
    )
    .await?;
    Ok(())
}

async fn seed_sources(session: &Session, fixture: &Fixture) -> anyhow::Result<()> {
    for checkpoint in TARGET..=OLD_HEAD {
        let transition = compression::compress(&fixture.transitions[checkpoint as usize])?;
        session
            .query_unpaged(
                format!(
                    "INSERT INTO {SOURCE}.checkpoint_zk_proof_and_transition_table (obj_id, value) VALUES (?, ?) USING TIMESTAMP {SOURCE_WRITETIME_US}"
                ),
                (checkpoint as i64, transition),
            )
            .await?;
        if checkpoint > TARGET {
            for (index, table) in [
                "checkpoint_leaf_table",
                "l2_block_state_table",
                "checkpoint_state_roots_table",
            ]
            .into_iter()
            .enumerate()
            {
                session
                    .query_unpaged(
                        format!(
                            "INSERT INTO {SOURCE}.{table} (obj_id, value) VALUES (?, ?) USING TIMESTAMP {SOURCE_WRITETIME_US}"
                        ),
                        (checkpoint as i64, vec![index as u8, checkpoint as u8]),
                    )
                    .await?;
            }
            let pending = UniquePendingId::try_new(100 + checkpoint)?;
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {SOURCE}.checkpoint_id_to_pending_id_table (obj_id, value) VALUES (?, ?) USING TIMESTAMP {SOURCE_WRITETIME_US}"
                    ),
                    (checkpoint as i64, pending.get() as i64),
                )
                .await?;
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {SOURCE}.pending_id_to_checkpoint_id_table (obj_id, value) VALUES (?, ?) USING TIMESTAMP {SOURCE_WRITETIME_US}"
                    ),
                    (pending.get() as i64, checkpoint as i64),
                )
                .await?;
            let mapping = BranchPendingMapping::new(
                CanonicalChainRef::new(
                    network(),
                    ChainEpoch::new(0),
                    fixture.refs[checkpoint as usize],
                ),
                pending,
            );
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {BRANCH}.{BRANCH_TO_PENDING_TABLE} (canonical_ref, pending_id, mapping_digest) VALUES (?, ?, ?) USING TIMESTAMP {SOURCE_WRITETIME_US}"
                    ),
                    (
                        mapping.canonical_chain_bytes().to_vec(),
                        pending.get() as i64,
                        mapping.digest().as_bytes().to_vec(),
                    ),
                )
                .await?;
            session
                .query_unpaged(
                    format!(
                        "INSERT INTO {BRANCH}.{PENDING_TO_BRANCH_TABLE} (pending_id, canonical_ref, mapping_digest) VALUES (?, ?, ?) USING TIMESTAMP {SOURCE_WRITETIME_US}"
                    ),
                    (
                        pending.get() as i64,
                        mapping.canonical_chain_bytes().to_vec(),
                        mapping.digest().as_bytes().to_vec(),
                    ),
                )
                .await?;
        }
    }
    for (realm, pending, node_index) in [
        (7_i64, 102_i64, 1_u64),
        (8, 103, 2),
        (7, 104, 3),
        (9, 999, 4),
    ] {
        let compressed = compression::compress(
            &SimpleMerkleNodeKey::new(4, node_index).psy_ser_to_bytes_vec()?,
        )?;
        session
            .query_unpaged(
                format!(
                    "INSERT INTO {SOURCE}.realm_rewards_tree_node_key_table (obj_id, checkpoint_id, value) VALUES (?, ?, ?) USING TIMESTAMP {SOURCE_WRITETIME_US}"
                ),
                (realm, pending, compressed),
            )
            .await?;
    }
    Ok(())
}

async fn enter_archiving(
    store: &ScyllaCanonicalHeadStore,
    fixture: &Fixture,
    request: RollbackRequest<PHash>,
) -> anyhow::Result<StoredCanonicalHead<PHash>> {
    let bootstrap = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        CanonicalChainRef::new(network(), ChainEpoch::new(0), fixture.refs[0]),
    )?;
    ensure!(store.bootstrap(&bootstrap).await?.was_applied());
    let mut current = *bootstrap.candidate();
    for checkpoint in 1..=OLD_HEAD {
        let transition = CanonicalHeadTransition::normal_checkpoint_advance(
            current,
            CanonicalChainRef::new(
                network(),
                ChainEpoch::new(0),
                fixture.refs[checkpoint as usize],
            ),
        )?
        .seal();
        ensure!(store.compare_and_set(&transition).await?.was_applied());
        current = *transition.candidate();
    }
    let requested = CanonicalHeadTransition::start_rollback(current, request)?.seal();
    ensure!(store.compare_and_set(&requested).await?.was_applied());
    let archiving =
        CanonicalHeadTransition::begin_rollback_archive(*requested.candidate())?.seal();
    ensure!(store.compare_and_set(&archiving).await?.was_applied());
    Ok(*archiving.candidate())
}

async fn read_json_rows(session: &Session, query: String) -> anyhow::Result<Vec<String>> {
    let mut rows = session
        .query_unpaged(query, &[])
        .await?
        .into_rows_result()?
        .rows::<(String,)>()?
        .map(|row| row.map(|value| value.0))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort();
    Ok(rows)
}

async fn direct_dataset(session: &Session) -> anyhow::Result<DirectDataset> {
    let mut tables = BTreeMap::new();
    let queries = [
        (
            format!("{HEAD}.{COORDINATOR_CANONICAL_HEAD_TABLE}"),
            format!(
                "SELECT JSON network_chain_id, revision, canonical_ref, rollback_control FROM {HEAD}.{COORDINATOR_CANONICAL_HEAD_TABLE}"
            ),
        ),
        (
            format!("{ARCHIVE}.{COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE}"),
            format!(
                "SELECT JSON * FROM {ARCHIVE}.{COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE}"
            ),
        ),
        (
            format!("{SOURCE}.checkpoint_leaf_table"),
            format!(
                "SELECT JSON obj_id, value, writetime(value) AS writetime_us FROM {SOURCE}.checkpoint_leaf_table"
            ),
        ),
        (
            format!("{SOURCE}.l2_block_state_table"),
            format!(
                "SELECT JSON obj_id, value, writetime(value) AS writetime_us FROM {SOURCE}.l2_block_state_table"
            ),
        ),
        (
            format!("{SOURCE}.checkpoint_state_roots_table"),
            format!(
                "SELECT JSON obj_id, value, writetime(value) AS writetime_us FROM {SOURCE}.checkpoint_state_roots_table"
            ),
        ),
        (
            format!("{SOURCE}.checkpoint_zk_proof_and_transition_table"),
            format!(
                "SELECT JSON obj_id, value, writetime(value) AS writetime_us FROM {SOURCE}.checkpoint_zk_proof_and_transition_table"
            ),
        ),
        (
            format!("{SOURCE}.checkpoint_id_to_pending_id_table"),
            format!(
                "SELECT JSON obj_id, value, writetime(value) AS writetime_us FROM {SOURCE}.checkpoint_id_to_pending_id_table"
            ),
        ),
        (
            format!("{SOURCE}.pending_id_to_checkpoint_id_table"),
            format!(
                "SELECT JSON obj_id, value, writetime(value) AS writetime_us FROM {SOURCE}.pending_id_to_checkpoint_id_table"
            ),
        ),
        (
            format!("{SOURCE}.realm_rewards_tree_node_key_table"),
            format!(
                "SELECT JSON obj_id, checkpoint_id, value, writetime(value) AS writetime_us FROM {SOURCE}.realm_rewards_tree_node_key_table"
            ),
        ),
        (
            format!("{BRANCH}.{BRANCH_TO_PENDING_TABLE}"),
            format!(
                "SELECT JSON canonical_ref, pending_id, mapping_digest, writetime(mapping_digest) AS writetime_us FROM {BRANCH}.{BRANCH_TO_PENDING_TABLE}"
            ),
        ),
        (
            format!("{BRANCH}.{PENDING_TO_BRANCH_TABLE}"),
            format!(
                "SELECT JSON pending_id, canonical_ref, mapping_digest, writetime(mapping_digest) AS writetime_us FROM {BRANCH}.{PENDING_TO_BRANCH_TABLE}"
            ),
        ),
    ];
    for (name, query) in queries {
        tables.insert(name, read_json_rows(session, query).await?);
    }
    Ok(DirectDataset { tables })
}

fn compose(compose_file: &Path, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .args(args)
        .status()
        .with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

fn docker_exec(container: &str, args: &[&str], context: &str) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("exec")
        .arg(container)
        .args(args)
        .status()
        .with_context(|| context.to_owned())?;
    ensure!(status.success(), "{context} failed with {status}");
    Ok(())
}

async fn wait_up(expected: usize) -> anyhow::Result<()> {
    for _ in 0..120 {
        let mut up = 0;
        for ip in NODE_IPS {
            if connect(Some(ip), Consistency::One).await.is_ok() {
                up += 1;
            }
        }
        if up >= expected {
            return Ok(());
        }
        sleep(Duration::from_secs(1)).await;
    }
    bail!("only part of RF=3 became available")
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d1a08_coordinator_archive_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D1A08_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d1a08.sh",
    );
    let compose_file = std::env::var("PSY_D1A08_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_schema(&session).await?;
    let fixture = transitions();
    seed_sources(&session, &fixture).await?;

    let head_store = ScyllaCanonicalHeadStore::prepare(
        Arc::clone(&session),
        CanonicalHeadNoTabletKeyspace::try_new(HEAD)?,
    )
    .await?;
    let request = request(&fixture);
    let plan = CoordinatorRollbackArchivePlan::resolve(request);
    let expected_head = enter_archiving(&head_store, &fixture, request).await?;
    let archive_store = ScyllaCoordinatorRollbackArchiveStore::prepare(
        Arc::clone(&session),
        CqlKeyspaceName::try_new(ARCHIVE)?,
        CqlKeyspaceName::try_new(SOURCE)?,
    )
    .await?;
    let branch_catalog = ScyllaCoordinatorRollbackBranchCatalog::prepare(
        Arc::clone(&session),
        CqlKeyspaceName::try_new(SOURCE)?,
        CqlKeyspaceName::try_new(SOURCE)?,
        CqlKeyspaceName::try_new(BRANCH)?,
    )
    .await?;
    let reward_catalog = ScyllaCoordinatorRollbackRealmRewardCatalog::prepare(
        Arc::clone(&session),
        CqlKeyspaceName::try_new(SOURCE)?,
    )
    .await?;
    let before = direct_dataset(&session).await?;

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop third replica",
    )?;
    wait_up(2).await?;
    let checkpoint = archive_store
        .archive_checkpoint_partition_kiv_suffix(&head_store, expected_head, &plan)
        .await?;
    let reward = reward_catalog
        .archive_verified_suffix::<PF, PHash, PoseidonHasher, PHash, HashProofVerifier>(
            &branch_catalog,
            &archive_store,
            &head_store,
            expected_head,
            &plan,
            fixture.config,
        )
        .await?;
    ensure!(checkpoint.row_count() == 12);
    ensure!(reward.mapping().archive_rows() == 12);
    ensure!(reward.selected_rows() == 3);

    // The first successful result is deliberately not used to advance any
    // state. Re-running the same production-shaped path models a caller that
    // lost the response; all IFNE rows must reconcile idempotently.
    let checkpoint_retry = archive_store
        .archive_checkpoint_partition_kiv_suffix(&head_store, expected_head, &plan)
        .await?;
    let reward_retry = reward_catalog
        .archive_verified_suffix::<PF, PHash, PoseidonHasher, PHash, HashProofVerifier>(
            &branch_catalog,
            &archive_store,
            &head_store,
            expected_head,
            &plan,
            fixture.config,
        )
        .await?;
    ensure!(checkpoint_retry == checkpoint);
    ensure!(reward_retry == reward);
    let during = direct_dataset(&session).await?;
    ensure!(during.tables.get(&format!("{SOURCE}.realm_rewards_tree_node_key_table"))
        == before.tables.get(&format!("{SOURCE}.realm_rewards_tree_node_key_table")));
    ensure!(during.tables.get(&format!("{HEAD}.{COORDINATOR_CANONICAL_HEAD_TABLE}"))
        == before.tables.get(&format!("{HEAD}.{COORDINATOR_CANONICAL_HEAD_TABLE}")));

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart third replica",
    )?;
    wait_up(3).await?;
    let repair_started = Instant::now();
    for keyspace in [SOURCE, BRANCH, ARCHIVE] {
        docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "cluster", "repair", keyspace],
            "repair tablet keyspace",
        )?;
    }
    for node in NODE_CONTAINERS {
        docker_exec(node, &["nodetool", "repair", "-pr", HEAD], "repair head")?;
        for keyspace in [SOURCE, BRANCH, ARCHIVE, HEAD] {
            docker_exec(node, &["nodetool", "flush", keyspace], "flush keyspace")?;
            docker_exec(node, &["nodetool", "compact", keyspace], "compact keyspace")?;
        }
    }
    let repair_ms = repair_started.elapsed().as_millis() as u64;

    let mut direct = Vec::new();
    for ip in NODE_IPS {
        direct.push(direct_dataset(&connect(Some(ip), Consistency::One).await?).await?);
    }
    let direct_one_equal = direct.windows(2).all(|pair| pair[0] == pair[1]);
    ensure!(direct_one_equal);
    let final_dataset = &direct[0];
    let archive_fragment_rows = final_dataset
        .tables
        .get(&format!("{ARCHIVE}.{COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE}"))
        .map(Vec::len)
        .unwrap_or_default();
    ensure!(archive_fragment_rows == 27);
    let source_rows_preserved = [
        "checkpoint_leaf_table",
        "l2_block_state_table",
        "checkpoint_state_roots_table",
        "checkpoint_zk_proof_and_transition_table",
        "checkpoint_id_to_pending_id_table",
        "pending_id_to_checkpoint_id_table",
        "realm_rewards_tree_node_key_table",
    ]
    .into_iter()
    .all(|table| {
        final_dataset.tables.get(&format!("{SOURCE}.{table}"))
            == before.tables.get(&format!("{SOURCE}.{table}"))
    });
    ensure!(source_rows_preserved);
    let canonical_head_unchanged_during_archive = final_dataset
        .tables
        .get(&format!("{HEAD}.{COORDINATOR_CANONICAL_HEAD_TABLE}"))
        == before
            .tables
            .get(&format!("{HEAD}.{COORDINATOR_CANONICAL_HEAD_TABLE}"));
    ensure!(canonical_head_unchanged_during_archive);

    let report = GateReport {
        image: IMAGE,
        replication_factor: 3,
        suffix_checkpoints: OLD_HEAD - TARGET,
        checkpoint_archive_rows: checkpoint.row_count(),
        mapping_archive_rows: reward.mapping().archive_rows(),
        reward_archive_rows: reward.selected_rows(),
        archive_fragment_rows,
        caller_discard_retry: true,
        socket_response_loss_injected: false,
        one_replica_offline_archive: true,
        source_rows_preserved,
        canonical_head_unchanged_during_archive,
        archive_rerun_idempotent: true,
        repair_flush_compact: true,
        repair_ms,
        direct_one_nodes: direct.len(),
        direct_one_tables: final_dataset.tables.len(),
        direct_one_rows: final_dataset.row_count(),
        direct_one_dataset_digest: hex(final_dataset.digest()),
        direct_one_equal,
        participant_archive_receipt: false,
        global_archive_barrier: false,
        destructive_started: false,
        hot_suffix_deleted: false,
        target_restored: false,
        new_branch_t_plus_1: false,
        production_rollback_available: false,
        qualification: "D1A08_COORDINATOR_SUFFIX_ARCHIVE_RF3_PASSED",
    };
    let report_path = std::env::var("PSY_D1A08_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
