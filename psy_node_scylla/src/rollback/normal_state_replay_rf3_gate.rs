use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use futures::future::join_all;
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
        AuthorityTimestampWriteOutcome, ObservedAuthorityTimestampState,
        SealedAuthorityTimestampReservation,
    },
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
        AuthorityLocalHeadWriteOutcome, AuthorityStorageBindingGeneration,
        AuthorityStorageBindingRef, AuthorityStorageNamespaceId,
        StoredAuthorityLocalHead,
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityPostWriteObservation, AuthorityProofObservation,
        ManifestLifecycleError, PersistedAuthorityManifest,
        SealedAuthorityManifest,
    },
    manifest_record::AuthorityManifestIdentity,
    normal_commit::{
        plan_normal_commit_recovery, NormalCommitOrchestrationError,
        NormalCommitRecoveryAction, NormalHeadPublishProgress,
        SealedNormalHeadPublish,
    },
    timestamp::CommitWriteTimestampUs,
    typed::{
        CheckpointId as StorageCheckpointId, CheckpointRootKey,
        ImtEncodedKey, ImtKeyIndexRow, LeafIndex, LogicalMutation, MerkleNode,
        MutationValue, NodeIndex, StructuredValueSchema,
        TreeId, TreeSubId, TypedTableKey, U64SingletonSlot,
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
    convert_checkpoint_id_to_i64, i64_to_u64_exact, u64_to_i64_exact,
    u8_to_i8_exact,
};

const CONTROL_KEYSPACE: &str = "psy_d04b2c_rf3_nt";
const ARTIFACT_KEYSPACE: &str = "psy_d04b2c_rf3_artifacts";
const STATE_KEYSPACE: &str = "psy_d04b2c_rf3_state";
const BASELINE: &str = "01b31224f8f994a4d9940801418ba7955a8e6ca7";
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

fn imt_row(
    tree: u64,
    tree_sub: u64,
    leaf: u64,
    seed: u8,
    leaf_key: [u8; 32],
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 161];
    bytes[0..8].copy_from_slice(&tree.to_le_bytes());
    bytes[8..16].copy_from_slice(&tree_sub.to_le_bytes());
    bytes[16..24].copy_from_slice(&leaf.to_le_bytes());
    bytes[24..56].copy_from_slice(&[seed; 32]);
    bytes[56..88].copy_from_slice(&leaf_key);
    bytes[88..120].copy_from_slice(&[seed.wrapping_add(1); 32]);
    bytes[120..152].copy_from_slice(&[seed.wrapping_add(2); 32]);
    bytes[152..160].copy_from_slice(&(leaf + 1).to_le_bytes());
    bytes[160] = 1;
    bytes
}

struct Fixture {
    timestamp_bootstrap: AuthorityTimestampBootstrap,
    reservation: SealedAuthorityTimestampReservation,
    head_bootstrap: AuthorityLocalHeadBootstrap<PHash>,
    package: VerifiedPreparedManifestPackage<PHash>,
}

impl Fixture {
    fn identity(&self) -> AuthorityManifestIdentity<PHash> {
        *self.package.record().identity()
    }
}

fn seal_fixture_for_head_gate(
    fixture: &Fixture,
) -> SealedAuthorityManifest<PHash> {
    let prepared = fixture.package.record().clone();
    let observation = AuthorityPostWriteObservation::new(
        AuthorityHeadView::candidate(&prepared),
        prepared.intent().artifacts().mutation_digest(),
        AuthorityHeadPayloadDigest::from_verified_payload_bytes(
            prepared.intent().head_payload().as_bytes(),
        ),
        AuthorityProofObservation::NotApplicableForRealm,
    );
    SealedAuthorityManifest::verify_and_seal(prepared, observation).unwrap()
}

fn publish_fixture_for_head_gate(
    fixture: &Fixture,
    sealed: &SealedAuthorityManifest<PHash>,
    expected: &StoredAuthorityLocalHead<PHash>,
) -> SealedNormalHeadPublish<PHash> {
    let allocator = ObservedAuthorityTimestampState::from_selected_row(
        fixture.package.record().identity().timestamp_key(),
        fixture.reservation.candidate(),
    );
    match plan_normal_commit_recovery(
        &PersistedAuthorityManifest::Sealed(sealed.clone()),
        expected,
        allocator,
    )
    .unwrap()
    {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => panic!("unexpected conflict-gate plan: {other:?}"),
    }
}

fn fixture(
    realm_id: u32,
    checkpoint_id: u64,
    seed: u8,
    high_water: i64,
) -> Fixture {
    fixture_from_seeds(
        realm_id,
        checkpoint_id,
        seed,
        seed.wrapping_add(1),
        seed.wrapping_add(2),
        seed.wrapping_add(3),
        seed,
        high_water,
        seed.wrapping_add(6),
    )
}

#[allow(clippy::too_many_arguments)]
fn fixture_from_seeds(
    realm_id: u32,
    checkpoint_id: u64,
    expected_chain_seed: u8,
    candidate_chain_seed: u8,
    old_root_seed: u8,
    new_root_seed: u8,
    payload_seed: u8,
    high_water: i64,
    namespace_seed: u8,
) -> Fixture {
    let checkpoint = StorageCheckpointId::try_new(checkpoint_id).unwrap();
    let semantic = [
        (MerkleNode::new(0, NodeIndex::new(0)), new_root_seed),
        (
            MerkleNode::new(1, NodeIndex::new(0)),
            new_root_seed.wrapping_add(1),
        ),
        (
            MerkleNode::new(1, NodeIndex::new(1)),
            new_root_seed.wrapping_add(2),
        ),
    ];
    let imt_tree = TreeId::new(9);
    let imt_sub = TreeSubId::new(realm_id as u64);
    let imt_leaf = LeafIndex::new(3);
    let imt_leaf_key = [payload_seed.wrapping_add(30); 32];
    let imt_row = imt_row(
        imt_tree.get(),
        imt_sub.get(),
        imt_leaf.get(),
        payload_seed.wrapping_add(31),
        imt_leaf_key,
    );
    let mut prepared_semantic = semantic
        .iter()
        .map(|(node, value_seed)| {
            PreparedSemanticMutation::GlobalUserMerkle {
                checkpoint,
                node: *node,
                value: vec![*value_seed; 32],
            }
        })
        .collect::<Vec<_>>();
    prepared_semantic.push(PreparedSemanticMutation::ImtLeaf {
        tree: imt_tree,
        tree_sub: imt_sub,
        leaf: imt_leaf,
        checkpoint,
        canonical_row: imt_row.clone(),
    });
    let payload = PreparedPayload::try_v1(
        PreparedPayloadKind::Realm,
        prepared_semantic,
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
    let mut logical = semantic
        .iter()
        .map(|(node, value_seed)| LogicalMutation::Put {
            key: TypedTableKey::GlobalUserMerkle {
                node: *node,
                checkpoint,
            },
            value: MutationValue::PsyCanonicalBytes(vec![*value_seed; 32]),
        })
        .collect::<Vec<_>>();
    logical.push(LogicalMutation::Put {
        key: TypedTableKey::ImtLeaf {
            tree: imt_tree,
            tree_sub: imt_sub,
            leaf: imt_leaf,
            checkpoint,
        },
        value: MutationValue::Structured {
            schema: StructuredValueSchema::ImtLeafRowV1,
            canonical_bytes: imt_row,
        },
    });
    let latest_checkpoint = LogicalMutation::Put {
        key: TypedTableKey::U64Singleton(
            U64SingletonSlot::LatestCheckpoint,
        ),
        value: MutationValue::CqlU64(checkpoint.get()),
    };
    let checkpoint_root = LogicalMutation::CheckpointRootMapping {
        root: CheckpointRootKey::new(vec![payload_seed.wrapping_add(40); 32]),
        checkpoint,
    };
    let imt_supplements = imt_leaf_supplements(
        imt_tree,
        imt_sub,
        ImtEncodedKey::new(encode_raw_imt_key_for_sorting(imt_leaf_key)),
        imt_leaf_key,
        imt_leaf,
        checkpoint,
        3,
        4,
    )
    .unwrap();
    logical.extend(imt_supplements.clone());
    logical.push(checkpoint_root.clone());
    logical.push(latest_checkpoint.clone());
    let full = CanonicalPhysicalMutationBatch::from_logical(logical).unwrap();
    let compact = PreparedReferencePlusSupplementRecord::try_v1(
        reference,
        DerivedSupplementBatch::from_logical(
            imt_supplements
                .into_iter()
                .chain([checkpoint_root, latest_checkpoint])
                .collect(),
        )
        .unwrap(),
        ReplayReceipt::new(
            ReplayAuthority::Realm,
            checkpoint,
            4,
            5,
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
            realm_id,
            realm_sub_id: 2,
        },
    );
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(checkpoint_id - 1, expected_chain_seed),
        chain(checkpoint_id, candidate_chain_seed),
        AuthorityStateTransition::Changed {
            previous_checkpoint: AuthorityStateCheckpointId::new(
                checkpoint_id - 1,
            ),
            checkpoint: AuthorityStateCheckpointId::new(checkpoint_id),
            old_root: AuthorityStateRoot::from_local_state_root(hash(
                old_root_seed,
            )),
            new_root: AuthorityStateRoot::from_local_state_root(hash(
                new_root_seed,
            )),
        },
        AuthorityHeadPayload::try_new(vec![payload_seed; 16]).unwrap(),
        artifacts.commitment(),
    )
    .unwrap();
    let timestamp_bootstrap = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(high_water as i128).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    );
    let reservation = timestamp_bootstrap
        .candidate()
        .seal_reservation(
            key,
            intent.digest(),
            AuthorityClockSampleUs::try_from_i128((high_water + 1) as i128)
                .unwrap(),
        )
        .unwrap();
    let prepared = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    let package =
        VerifiedPreparedManifestPackage::try_new(&prepared, artifacts).unwrap();
    let head_bootstrap = AuthorityLocalHeadBootstrap::seal(
        AuthorityLocalHeadBootstrapReason::GenesisNative,
        AuthorityHeadView::expected(package.record()),
        CommitWriteTimestampUs::try_from_i128(high_water as i128).unwrap(),
        package.record().digest(),
        AuthorityStorageBindingRef::new(
            AuthorityStorageBindingGeneration::try_new(3).unwrap(),
            AuthorityStorageNamespaceId::from_verified_namespace_id([
                namespace_seed;
                32
            ]),
        ),
    );
    Fixture {
        timestamp_bootstrap,
        reservation,
        head_bootstrap,
        package,
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
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.imt_leaf_table (tree_id BIGINT, tree_sub_id BIGINT, leaf_index BIGINT, checkpoint_id BIGINT, leaf_hash BLOB, leaf_key BLOB, leaf_value BLOB, next_key BLOB, next_index BIGINT, PRIMARY KEY ((tree_id, tree_sub_id, leaf_index), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id DESC)"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.imt_key_index_table (tree_id BIGINT, tree_sub_id BIGINT, key_bucket SMALLINT, encoded_key BLOB, leaf_key BLOB, birth_checkpoint BIGINT, leaf_index BIGINT, PRIMARY KEY ((tree_id, tree_sub_id, key_bucket), encoded_key))"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.imt_next_append_index_table (tree_id BIGINT, tree_sub_id BIGINT, next_append_index BIGINT, PRIMARY KEY ((tree_id, tree_sub_id)))"
            ),
            &[],
        )
        .await?;
    for suffix in ["k1", "k2"] {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.checkpoint_root_to_checkpoint_id_table_{suffix} (obj_id BLOB PRIMARY KEY, value BLOB)"
                ),
                &[],
            )
            .await?;
    }
    ScyllaPreparedManifestStore::create_schema(session, &keyspaces()?).await?;
    // `RollbackableStorePrototype` deliberately prepares the complete G0-06
    // representative query set. Keep the RF=3 fixture production-shaped by
    // creating the KIV representative table even though this gate executes
    // Merkle, checkpoint-root pair and latest-checkpoint rows.
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
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.u64_singleton_table (obj_id BIGINT PRIMARY KEY, value BIGINT)"
            ),
            &[],
        )
        .await?;
    // The confined mutable-singleton adapter prepares its complete query
    // family. This table is not executed by this gate, but keeping the real
    // schema present proves preparation uses the production-shaped catalog.
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {STATE_KEYSPACE}.latest_info_table (obj_id BIGINT PRIMARY KEY, value BLOB)"
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

struct CombinedStores {
    manifests: ScyllaPreparedManifestStore,
    heads: ScyllaAuthorityLocalHeadStore,
    timestamps: ScyllaAuthorityTimestampStore,
    state: RollbackableStorePrototype,
}

impl CombinedStores {
    fn executor(&self) -> ScyllaRepresentativeRealmNormalCommitExecutor<'_> {
        ScyllaRepresentativeRealmNormalCommitExecutor::new(
            &self.manifests,
            &self.heads,
            &self.timestamps,
            &self.state,
        )
    }
}

async fn create_combined_schema(session: &Session) -> anyhow::Result<()> {
    create_schema(session).await?;
    ScyllaAuthorityTimestampStore::create_schema(
        session,
        &AuthorityTimestampNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    ScyllaAuthorityLocalHeadStore::create_schema(
        session,
        &AuthorityLocalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    Ok(())
}

async fn open_combined_stores() -> anyhow::Result<CombinedStores> {
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    Ok(CombinedStores {
        manifests: ScyllaPreparedManifestStore::prepare(
            Arc::clone(&session),
            keyspaces()?,
        )
        .await?,
        heads: ScyllaAuthorityLocalHeadStore::prepare(
            Arc::clone(&session),
            AuthorityLocalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        )
        .await?,
        timestamps: ScyllaAuthorityTimestampStore::prepare(
            Arc::clone(&session),
            AuthorityTimestampNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
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

async fn initialize_combined_fixture(
    stores: &CombinedStores,
    fixture: &Fixture,
) -> anyhow::Result<()> {
    ensure!(matches!(
        stores
            .timestamps
            .bootstrap(fixture.timestamp_bootstrap)
            .await?,
        AuthorityTimestampWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores.timestamps.reserve(fixture.reservation).await?,
        AuthorityTimestampWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores.heads.bootstrap(&fixture.head_bootstrap).await?,
        AuthorityLocalHeadWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores
            .manifests
            .persist_prepared(&fixture.package)
            .await?,
        psy_node_core::store::manifest_record::PreparedManifestWriteOutcome::Applied(_)
    ));
    Ok(())
}

async fn load_plan(
    stores: &Stores,
    identity: AuthorityManifestIdentity<PHash>,
) -> anyhow::Result<RepresentativeRealmStateReplayPlan<PHash>> {
    load_plan_from(&stores.manifests, identity).await
}

async fn load_plan_from(
    manifests: &ScyllaPreparedManifestStore,
    identity: AuthorityManifestIdentity<PHash>,
) -> anyhow::Result<RepresentativeRealmStateReplayPlan<PHash>> {
    let prepared = match manifests
        .read_lifecycle(identity)
        .await?
        .context("durable PREPARED row is missing")?
    {
        PersistedAuthorityManifest::Prepared(prepared) => prepared,
        other => bail!("expected PREPARED lifecycle, got {other:?}"),
    };
    let artifacts = manifests.load_verified_artifacts(&prepared).await?;
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
    let merkle_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.global_user_tree_table WHERE level = ? AND node_index = ? AND checkpoint_id = ?"
    );
    let singleton_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.u64_singleton_table WHERE obj_id = ?"
    );
    let checkpoint_root_k1_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.checkpoint_root_to_checkpoint_id_table_k1 WHERE obj_id = ?"
    );
    let checkpoint_root_k2_query = format!(
        "SELECT value FROM {STATE_KEYSPACE}.checkpoint_root_to_checkpoint_id_table_k2 WHERE obj_id = ?"
    );
    let imt_leaf_query = format!(
        "SELECT leaf_hash, leaf_key, leaf_value, next_key, next_index FROM {STATE_KEYSPACE}.imt_leaf_table WHERE tree_id = ? AND tree_sub_id = ? AND leaf_index = ? AND checkpoint_id = ?"
    );
    let imt_index_query = format!(
        "SELECT leaf_key, birth_checkpoint, leaf_index FROM {STATE_KEYSPACE}.imt_key_index_table WHERE tree_id = ? AND tree_sub_id = ? AND key_bucket = ? AND encoded_key = ?"
    );
    let imt_cursor_query = format!(
        "SELECT next_append_index FROM {STATE_KEYSPACE}.imt_next_append_index_table WHERE tree_id = ? AND tree_sub_id = ?"
    );
    let mut values = Vec::with_capacity(plan.mutation_count());
    for sealed in plan.puts() {
        let value = match sealed.resolved().mutation().key() {
            TypedTableKey::GlobalUserMerkle { node, checkpoint } => session
                .query_unpaged(
                    merkle_query.as_str(),
                    (
                        u8_to_i8_exact(node.level()),
                        u64_to_i64_exact(node.index().get()),
                        convert_checkpoint_id_to_i64(checkpoint.get()),
                    ),
                )
                .await?
                .into_rows_result()?
                .single_row::<(Vec<u8>,)>()?
                .0,
            TypedTableKey::U64Singleton(
                U64SingletonSlot::LatestCheckpoint,
            ) => i64_to_u64_exact(
                session
                    .query_unpaged(
                        singleton_query.as_str(),
                        (u64_to_i64_exact(
                            U64SingletonSlot::LatestCheckpoint as u8 as u64,
                        ),),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(i64,)>()?
                    .0,
            )
            .to_be_bytes()
            .to_vec(),
            TypedTableKey::CheckpointRootByHash(root) => {
                let stored = session
                    .query_unpaged(
                        checkpoint_root_k1_query.as_str(),
                        (root.as_bytes(),),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>,)>()?
                    .0;
                crate::compression::decompress(&stored)?
            }
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => {
                let stored = session
                    .query_unpaged(
                        checkpoint_root_k2_query.as_str(),
                        (checkpoint.get().to_le_bytes().as_slice(),),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>,)>()?
                    .0;
                crate::compression::decompress(&stored)?
            }
            TypedTableKey::ImtLeaf {
                tree,
                tree_sub,
                leaf,
                checkpoint,
            } => {
                let (leaf_hash, leaf_key, leaf_value, next_key, next_index) = session
                    .query_unpaged(
                        imt_leaf_query.as_str(),
                        (
                            u64_to_i64_exact(tree.get()),
                            u64_to_i64_exact(tree_sub.get()),
                            u64_to_i64_exact(leaf.get()),
                            convert_checkpoint_id_to_i64(checkpoint.get()),
                        ),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64)>()?;
                ensure!(
                    leaf_hash.len() == 32
                        && leaf_key.len() == 32
                        && leaf_value.len() == 32
                        && next_key.len() == 32
                );
                [leaf_hash, leaf_key, leaf_value, next_key]
                    .into_iter()
                    .flatten()
                    .chain(i64_to_u64_exact(next_index).to_be_bytes())
                    .collect()
            }
            TypedTableKey::ImtKeyIndex {
                tree,
                tree_sub,
                encoded_key,
            } => {
                let (leaf_key, birth_checkpoint, leaf_index) = session
                    .query_unpaged(
                        imt_index_query.as_str(),
                        (
                            u64_to_i64_exact(tree.get()),
                            u64_to_i64_exact(tree_sub.get()),
                            encoded_key.cql_bucket(),
                            encoded_key.as_bytes(),
                        ),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(Vec<u8>, i64, i64)>()?;
                ensure!(leaf_key.len() == 32 && birth_checkpoint >= 0);
                ImtKeyIndexRow::new(
                    leaf_key.as_slice().try_into().expect("validated length"),
                    StorageCheckpointId::try_new(birth_checkpoint as u64)?,
                    LeafIndex::new(i64_to_u64_exact(leaf_index)),
                )
                .encode_canonical()
                .to_vec()
            }
            TypedTableKey::ImtCursor { tree, tree_sub } => i64_to_u64_exact(
                session
                    .query_unpaged(
                        imt_cursor_query.as_str(),
                        (
                            u64_to_i64_exact(tree.get()),
                            u64_to_i64_exact(tree_sub.get()),
                        ),
                    )
                    .await?
                    .into_rows_result()?
                    .single_row::<(i64,)>()?
                    .0,
            )
            .to_be_bytes()
            .to_vec(),
            _ => bail!("representative plan exposed an unsupported typed key"),
        };
        values.push(value);
    }
    Ok(values)
}

fn expected_rows(
    plan: &RepresentativeRealmStateReplayPlan<PHash>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    Ok(plan
        .expected_physical_values()
        .map(<[u8]>::to_vec)
        .collect())
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
    exact_replay_verified_manifest_evidence_required: bool,
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

    let fixture = fixture(3, 41, 1, 500);
    let identity = fixture.identity();
    let stores = open_stores().await?;
    ensure!(matches!(
        stores.manifests.persist_prepared(&fixture.package).await?,
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
    ensure!(
        SealedAuthorityManifest::verify_and_seal(
            plan.prepared().clone(),
            observation,
        )
        .unwrap_err()
            == ManifestLifecycleError::ChangedRealmEvidenceRequired
    );
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
        exact_replay_verified_manifest_evidence_required: true,
        direct_one_replicas_equal: true,
        scenarios_passed: vec![
            "M16_partial_state_write_restart_reapplies_exact_timestamped_rows",
            "M17_root_present_but_missing_non_root_row_cannot_seal",
            "IMT_leaf_index_cursor_exact_rows_are_all_required_before_realm_evidence",
            "one_replica_offline_quorum_replay_then_repair_flush_compact",
            "direct_one_all_replicas_equal_expected_rows",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "representative Realm global-user Merkle, IMT leaf/key-index/cursor, checkpoint-root pair and latest-checkpoint singleton replay; verifies exact IMT physical durability, not upstream contract-state/root proof binding, production Processor integration, or full 35-table replay coverage",
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

#[derive(Serialize)]
struct D04b2dReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    serial_consistency: &'static str,
    restart_count: u8,
    partial_state_recovered_into_sealed: bool,
    head_response_loss_recovered: bool,
    committed_response_loss_recovered: bool,
    timestamp_response_loss_recovered: bool,
    one_replica_offline_drive_reached_done: bool,
    direct_one_state_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive RF=3 harness and changed-Realm supplement orchestration"]
async fn d04b2d_combined_representative_normal_commit_rf3_gate(
) -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B2D_RF3").is_none() {
        bail!("set PSY_D04B2D_RF3=1 through run-d04b2d.sh");
    }
    let initial_session = connect(None, Consistency::Quorum).await?;
    create_combined_schema(&initial_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read D-04b2d Scylla version",
    )?
    .trim()
    .to_owned();
    drop(initial_session);

    // Start from a real PREPARED row with only the physical prefix through the
    // root present, then destroy every Session/adapter. The combined executor
    // must reconstruct both root-covered state and the singleton supplement
    // from durable artifacts before it can persist SEALED.
    let crash = fixture(13, 51, 11, 1_500);
    let stores = open_combined_stores().await?;
    initialize_combined_fixture(&stores, &crash).await?;
    let crash_plan = load_plan_from(&stores.manifests, crash.identity()).await?;
    ensure!(crash_plan.root_position() == 0);
    let crash_prefix = crash_plan.root_position() + 1;
    ensure!(crash_prefix < crash_plan.mutation_count());
    RepresentativeRealmStateReplayExecutor::new(&stores.state)
        .reapply_prefix_for_gate(&crash_plan, crash_prefix)
        .await?;
    drop(stores);

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::StateVerifiedAndSealed { .. }
    ));
    drop(stores);

    // Each following response is deliberately discarded with the adapters.
    // The next process is allowed to advance only from durable observations.
    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::HeadPublishedAwaitingCommitted { .. }
    ));
    drop(stores);

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::CommittedPersisted { .. }
    ));
    drop(stores);

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::TimestampCompleted
    ));
    drop(stores);

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    drop(stores);

    // A second authority executes the same state+metadata loop while one
    // replica is offline.  The Session is prepared first so driver topology
    // discovery is not part of the measured fault.
    let offline = fixture(14, 52, 21, 2_500);
    let stores = open_combined_stores().await?;
    initialize_combined_fixture(&stores, &offline).await?;
    let offline_plan =
        load_plan_from(&stores.manifests, offline.identity()).await?;
    docker_container("stop", NODE_CONTAINERS[2])?;
    let committed = stores
        .executor()
        .drive_to_done(offline.identity(), 8)
        .await?;
    ensure!(
        committed.sealed().prepared().identity() == &offline.identity()
    );
    drop(stores);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    repair_flush_compact()?;

    let expected = expected_rows(&offline_plan)?;
    let mut replicas = Vec::new();
    for ip in NODE_IPS {
        replicas.push(read_direct_rows(ip, &offline_plan).await?);
    }
    let direct_one_state_replicas_equal =
        replicas.iter().all(|rows| rows == &expected);
    ensure!(direct_one_state_replicas_equal);

    let final_stores = open_combined_stores().await?;
    ensure!(matches!(
        final_stores.executor().step(crash.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    ensure!(matches!(
        final_stores.executor().step(offline.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    RepresentativeRealmStateReplayExecutor::new(&final_stores.state)
        .verify_exact(&offline_plan)
        .await?;

    let report = D04b2dReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        serial_consistency: "LOCAL_SERIAL",
        restart_count: 5,
        partial_state_recovered_into_sealed: true,
        head_response_loss_recovered: true,
        committed_response_loss_recovered: true,
        timestamp_response_loss_recovered: true,
        one_replica_offline_drive_reached_done: true,
        direct_one_state_replicas_equal,
        scenarios_passed: vec![
            "partial exact state restart replays before SEALED",
            "IMT leaf/index/cursor are reconstructed and verified as one replay unit",
            "SEALED restart resumes exact head publication",
            "head response loss recovers COMMITTED from durable state",
            "COMMITTED response loss recovers timestamp completion",
            "one replica offline combined drive reaches Done",
            "repair flush compact converges exact state rows on every replica",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "representative Realm global-user Merkle plus exact IMT leaf/key-index/cursor and checkpoint-root/latest-checkpoint supplements in the manifest/head/timestamp recovery loop; not upstream IMT root proof binding, production Processor integration, or full table coverage",
    };
    let report_path = std::env::var("PSY_D04B2D_REPORT_PATH")
        .unwrap_or_else(|_| "target/d04b2d-combined-normal-commit-rf3-report.json".into());
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[derive(Serialize)]
struct D04b2eReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    serial_consistency: &'static str,
    conflicting_reservations_applied: u8,
    conflicting_reservations_rejected: u8,
    losing_publish_rejected_before_head_io: bool,
    winning_head_published: bool,
    exact_idempotent_publish_retries: usize,
    losing_manifest_absent: bool,
    winner_reached_done: bool,
    one_replica_offline: bool,
    direct_one_state_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    finished_unix_ms: u64,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive RF=3 harness and changed-Realm supplement orchestration"]
async fn d04b2e_conflicting_normal_commit_rf3_gate() -> anyhow::Result<()> {
    if std::env::var_os("PSY_D04B2E_RF3").is_none() {
        bail!("set PSY_D04B2E_RF3=1 through run-d04b2e.sh");
    }
    let initial_session = connect(None, Consistency::Quorum).await?;
    create_combined_schema(&initial_session).await?;
    let release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read D-04b2e Scylla version",
    )?
    .trim()
    .to_owned();
    drop(initial_session);

    // Both requests target the same authority and exact expected head, but
    // commit different checkpoint hashes, state roots, payloads and artifact
    // digests.  Their independently sealed timestamp reservations therefore
    // compete for the same idle allocator revision.
    let left = fixture_from_seeds(
        15, 61, 31, 32, 33, 34, 35, 4_000, 40,
    );
    let right = fixture_from_seeds(
        15, 61, 31, 42, 33, 44, 45, 4_000, 40,
    );
    ensure!(
        AuthorityHeadView::expected(left.package.record())
            == AuthorityHeadView::expected(right.package.record())
    );
    ensure!(left.reservation.candidate() != right.reservation.candidate());
    ensure!(
        left.timestamp_bootstrap.candidate()
            == right.timestamp_bootstrap.candidate()
    );

    let common_head = left.head_bootstrap.candidate().clone();
    ensure!(
        *common_head.head() == AuthorityHeadView::expected(right.package.record())
    );
    let left_sealed = seal_fixture_for_head_gate(&left);
    let right_sealed = seal_fixture_for_head_gate(&right);
    let left_publish = publish_fixture_for_head_gate(
        &left,
        &left_sealed,
        &common_head,
    );
    let right_publish = publish_fixture_for_head_gate(
        &right,
        &right_sealed,
        &common_head,
    );
    ensure!(left_publish.head_cas().candidate() != right_publish.head_cas().candidate());

    let stores = open_combined_stores().await?;
    ensure!(matches!(
        stores
            .timestamps
            .bootstrap(left.timestamp_bootstrap)
            .await?,
        AuthorityTimestampWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        stores.heads.bootstrap(&left.head_bootstrap).await?,
        AuthorityLocalHeadWriteOutcome::Applied(_)
    ));

    // Exercise allocator ownership, state replay and the conflicting publish
    // attempts while one RF=3 member is unavailable.
    docker_container("stop", NODE_CONTAINERS[2])?;
    let (left_reservation, right_reservation) = tokio::join!(
        stores.timestamps.reserve(left.reservation),
        stores.timestamps.reserve(right.reservation),
    );
    let left_reservation = left_reservation?;
    let right_reservation = right_reservation?;
    let left_won = matches!(
        left_reservation,
        AuthorityTimestampWriteOutcome::Applied(_)
    );
    ensure!(
        (left_won
            && matches!(
                right_reservation,
                AuthorityTimestampWriteOutcome::Conflict(_)
            ))
            || (!left_won
                && matches!(
                    left_reservation,
                    AuthorityTimestampWriteOutcome::Conflict(_)
                )
                && matches!(
                    right_reservation,
                    AuthorityTimestampWriteOutcome::Applied(_)
                ))
    );

    let (winner, loser, winner_publish, loser_publish, winner_sealed) =
        if left_won {
            (
                &left,
                &right,
                left_publish,
                right_publish,
                left_sealed,
            )
        } else {
            (
                &right,
                &left,
                right_publish,
                left_publish,
                right_sealed,
            )
        };

    ensure!(matches!(
        stores.manifests.persist_prepared(&winner.package).await?,
        psy_node_core::store::manifest_record::PreparedManifestWriteOutcome::Applied(_)
    ));
    let winner_plan = load_plan_from(&stores.manifests, winner.identity()).await?;
    let combined = stores.executor();
    let durable_sealed = match combined.step(winner.identity()).await? {
        RepresentativeNormalCommitStep::StateVerifiedAndSealed { sealed } => sealed,
        other => bail!("unexpected winner state step: {other:?}"),
    };
    ensure!(durable_sealed == winner_sealed);

    let metadata = ScyllaNormalCommitMetadataExecutor::new(
        &stores.manifests,
        &stores.heads,
        &stores.timestamps,
    );
    let (winner_result, loser_result) = tokio::join!(
        metadata.publish_head(winner_publish.clone()),
        metadata.publish_head(loser_publish.clone()),
    );
    let committed = match winner_result? {
        NormalHeadPublishProgress::PersistCommitted { committed } => committed,
        other => bail!("unexpected winning publish result: {other:?}"),
    };
    ensure!(matches!(
        loser_result,
        Err(NormalCommitMetadataError::Orchestration(
            NormalCommitOrchestrationError::AllocatorOwnedByOtherIntent
        ))
    ));
    let current_head = match stores
        .heads
        .read(winner.identity().timestamp_key())
        .await?
    {
        psy_node_core::store::authority_local_head::AuthorityLocalHeadReadState::Current(head) => head,
        psy_node_core::store::authority_local_head::AuthorityLocalHeadReadState::Uninitialized => {
            bail!("authority head disappeared after winning publish")
        }
    };
    ensure!(current_head == *winner_publish.head_cas().candidate());

    // Exact duplicate requests remain safe: all observe the same candidate
    // and become idempotent COMMITTED capabilities rather than alternate
    // interpretations of the losing branch.
    let retry_results = join_all(
        (0..32).map(|_| metadata.publish_head(winner_publish.clone())),
    )
    .await;
    for result in retry_results {
        ensure!(matches!(
            result?,
            NormalHeadPublishProgress::PersistCommitted { .. }
        ));
    }

    metadata.persist_committed(&committed).await?;
    let completion = match metadata.plan(winner.identity()).await? {
        NormalCommitRecoveryAction::CompleteTimestampLease { completion } => completion,
        other => bail!("unexpected post-COMMITTED plan: {other:?}"),
    };
    metadata.complete_timestamp(completion).await?;
    ensure!(matches!(
        metadata.plan(winner.identity()).await?,
        NormalCommitRecoveryAction::Done { .. }
    ));
    ensure!(stores
        .manifests
        .read_lifecycle(loser.identity())
        .await?
        .is_none());
    ensure!(matches!(
        metadata.publish_head(loser_publish).await,
        Err(NormalCommitMetadataError::Orchestration(
            NormalCommitOrchestrationError::AllocatorDoesNotOwnIntent
        ))
    ));
    drop(metadata);
    drop(stores);

    docker_container("start", NODE_CONTAINERS[2])?;
    wait_for_three_up_normal().await?;
    repair_flush_compact()?;

    let expected = expected_rows(&winner_plan)?;
    let mut replicas = Vec::new();
    for ip in NODE_IPS {
        replicas.push(read_direct_rows(ip, &winner_plan).await?);
    }
    let direct_one_state_replicas_equal =
        replicas.iter().all(|rows| rows == &expected);
    ensure!(direct_one_state_replicas_equal);

    let final_stores = open_combined_stores().await?;
    ensure!(matches!(
        final_stores.executor().step(winner.identity()).await?,
        RepresentativeNormalCommitStep::Done { .. }
    ));
    ensure!(final_stores
        .manifests
        .read_lifecycle(loser.identity())
        .await?
        .is_none());

    let report = D04b2eReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        serial_consistency: "LOCAL_SERIAL",
        conflicting_reservations_applied: 1,
        conflicting_reservations_rejected: 1,
        losing_publish_rejected_before_head_io: true,
        winning_head_published: true,
        exact_idempotent_publish_retries: 32,
        losing_manifest_absent: true,
        winner_reached_done: true,
        one_replica_offline: true,
        direct_one_state_replicas_equal,
        scenarios_passed: vec![
            "two intent reservations have one durable owner",
            "stale losing publish is rejected before head CAS",
            "winning replay includes exact IMT leaf/index/cursor physical rows",
            "winning publish is the only canonical head",
            "32 exact publish retries are idempotent",
            "loser cannot persist a manifest or complete a timestamp lease",
            "one replica offline flow converges after repair flush compact",
        ],
        finished_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        qualification: "M20 for one representative Realm normal commit with global-user Merkle plus exact IMT leaf/key-index/cursor and checkpoint-root/latest-checkpoint supplements; not upstream IMT root proof binding, production Processor integration, or full table coverage",
    };
    let report_path = std::env::var("PSY_D04B2E_REPORT_PATH")
        .unwrap_or_else(|_| "target/d04b2e-normal-commit-conflict-rf3-report.json".into());
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
