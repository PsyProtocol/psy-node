use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use async_trait::async_trait;
use parth_core::{
    crypto::hash::{
        tag_tree::TagTreeMerkleProof,
        traits::{QFieldHashable, ZeroableHash},
    },
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
        checkpoint::{
            PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats,
        },
        populated_checkpoint::PsyCheckpointLeafPopulated,
    },
};
use psy_node_core::store::{
    branch_exact_schema::{
        AuthorityScope, BaselineSnapshotArtifactDigest,
        BranchExactPostGenesisFloorEvidence,
        BranchExactSchemaMaterializationPlan,
    },
    canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
        CanonicalHeadReadState, CoordinatorCanonicalHeadReader,
    },
    manifest_record::AuthorityManifestDigest,
};
use psy_node_scylla::rollback::{
    BranchExactCheckpointChainConfig, BranchExactFrozenLegacyExportPermit,
    BranchExactLegacyExportBoundary, BranchExactLegacyExportError,
    BranchExactLegacyExportObserver, BranchExactLegacyFreezeReason,
    BranchExactSchemaMaterializationRequest, CanonicalHeadNoTabletKeyspace,
    CqlKeyspaceName, ScyllaBranchExactLegacyExporter,
    ScyllaCanonicalHeadStore,
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
use tokio::time::sleep;

const LEGACY_KEYSPACE: &str = "psy_d04b6h19_legacy";
const CONTROL_KEYSPACE: &str = "psy_d04b6h19_control_nt";
const BASELINE: &str = "38aa9b67719b232acb271d89fdcc82e81039abbd";
const IMAGE: &str =
    "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const CHECKPOINT_HEAD: u64 = 100;
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

#[derive(Clone, Copy)]
struct HashProofVerifier;

impl QZKProofPublicInputsHasherReader<PHash, PHash> for HashProofVerifier {
    fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
        Ok(*proof)
    }

    fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
        Ok(PHash::from_owned_32bytes(bytes.try_into()?))
    }
}

fn authority() -> AuthorityScope {
    AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    }
}

fn network() -> anyhow::Result<NetworkId> {
    Ok(NetworkId::try_from_chain_id(1337)?)
}

fn hash(seed: u64) -> PHash {
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn empty_checkpoint_leaf() -> PsyCheckpointLeafPopulated<PF, PHash> {
    PsyCheckpointLeafPopulated {
        global_state_roots: PQEDCheckpointGlobalStateRoots {
            contract_tree_root: PHash::get_zero_value(),
            deposit_tree_root: PHash::get_zero_value(),
            user_tree_root: PHash::get_zero_value(),
            withdrawal_tree_root: PHash::get_zero_value(),
            user_registration_tree_root: PHash::get_zero_value(),
        },
        stats: PQEDCheckpointLeafStats::get_empty_stats(),
    }
}

struct Fixture {
    bootstrap: CanonicalHeadBootstrap<PHash>,
    config: BranchExactCheckpointChainConfig<PHash>,
    transitions: Vec<(i64, Vec<u8>)>,
    mappings: Vec<(i64, i64)>,
    reverse: Vec<(i64, i64)>,
    proofs: Vec<(i64, i64, Vec<u8>)>,
}

fn fixture() -> anyhow::Result<Fixture> {
    let genesis_fingerprint = hash(100);
    let genesis_transition_hash = hash(200);
    let checkpoint_fingerprint = hash(300);
    let config = BranchExactCheckpointChainConfig::new(
        genesis_fingerprint,
        genesis_transition_hash,
        checkpoint_fingerprint,
    );
    let leaf = empty_checkpoint_leaf();
    let leaf_hash = leaf.qfhash::<PoseidonHasher>();
    let mut previous_root = hash(400);
    let mut previous_chain = None;
    let mut transitions = Vec::new();
    let mut head_hash = None;
    for checkpoint_id in 0..=CHECKPOINT_HEAD {
        let new_root = hash(1_000 + checkpoint_id * 10);
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
                    checkpoint_transition: CheckpointStateHashTransition {
                        old_checkpoint_tree_root: if checkpoint_id == 0 {
                            new_root
                        } else {
                            previous_root
                        },
                        new_checkpoint_tree_root: new_root,
                        old_checkpoint_leaf_hash: leaf_hash,
                        new_checkpoint_leaf_hash: leaf_hash,
                    },
                    genesis_checkpoint_state_transition_hash:
                        genesis_transition_hash,
                    checkpoint_state_transition_circuit_fingerprint:
                        checkpoint_fingerprint,
                },
                checkpoint_leaf: leaf,
            },
            circuit_type: 7,
            zk_proof: if checkpoint_id == 0 {
                vec![]
            } else {
                chain_hash.as_inner().into_owned_32bytes().to_vec()
            },
        };
        transitions.push((
            checkpoint_id as i64,
            psy_node_scylla::compression::compress(
                &transition.psy_ser_to_bytes_vec()?,
            )?,
        ));
        previous_root = new_root;
        previous_chain = Some(*chain_hash.as_inner());
        head_hash = Some(chain_hash);
    }
    let bootstrap = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::PostGenesisFloor,
        CanonicalChainRef::new(
            network()?,
            ChainEpoch::new(0),
            CheckpointRef::new(
                CheckpointId::new(CHECKPOINT_HEAD),
                head_hash.unwrap(),
            ),
        ),
    )?;
    let proof = psy_node_scylla::compression::compress(
        &TagTreeMerkleProof::<PHash>::new_empty().psy_ser_to_bytes_vec()?,
    )?;
    let mappings = (0..=CHECKPOINT_HEAD)
        .step_by(2)
        .map(|checkpoint| (checkpoint as i64, (10_000 + checkpoint) as i64))
        .collect::<Vec<_>>();
    let reverse = mappings
        .iter()
        .map(|(checkpoint, pending)| (*pending, *checkpoint))
        .collect();
    let proofs = mappings
        .iter()
        .map(|(_, pending)| (2_i64, *pending, proof.clone()))
        .collect();
    Ok(Fixture {
        bootstrap,
        config,
        transitions,
        mappings,
        reverse,
        proofs,
    })
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
    SessionBuilder::new()
        .known_nodes_addr(
            NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)),
        )
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await
        .context("connect to D-04b6h19 RF=3 cluster")
}

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {LEGACY_KEYSPACE} WITH replication = \
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
    for cql in [
        format!(
            "CREATE TABLE {LEGACY_KEYSPACE}.checkpoint_id_to_pending_id_table (obj_id BIGINT PRIMARY KEY, value BIGINT)"
        ),
        format!(
            "CREATE TABLE {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table (obj_id BIGINT PRIMARY KEY, value BIGINT)"
        ),
        format!(
            "CREATE TABLE {LEGACY_KEYSPACE}.checkpoint_zk_proof_and_transition_table (obj_id BIGINT PRIMARY KEY, value BLOB)"
        ),
        format!(
            "CREATE TABLE {LEGACY_KEYSPACE}.checkpointed_object_table (obj_id BIGINT, checkpoint_id BIGINT, value BLOB, PRIMARY KEY ((obj_id), checkpoint_id)) WITH CLUSTERING ORDER BY (checkpoint_id DESC)"
        ),
    ] {
        session.query_unpaged(cql, &[]).await?;
    }
    ScyllaCanonicalHeadStore::create_schema(
        session,
        &CanonicalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn load_fixture(session: &Session, fixture: &Fixture) -> anyhow::Result<()> {
    let transition = session
        .prepare(format!(
            "INSERT INTO {LEGACY_KEYSPACE}.checkpoint_zk_proof_and_transition_table (obj_id, value) VALUES (?, ?)"
        ))
        .await?;
    for row in &fixture.transitions {
        session.execute_unpaged(&transition, row).await?;
    }
    let forward = session
        .prepare(format!(
            "INSERT INTO {LEGACY_KEYSPACE}.checkpoint_id_to_pending_id_table (obj_id, value) VALUES (?, ?)"
        ))
        .await?;
    for row in &fixture.mappings {
        session.execute_unpaged(&forward, row).await?;
    }
    let reverse = session
        .prepare(format!(
            "INSERT INTO {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table (obj_id, value) VALUES (?, ?)"
        ))
        .await?;
    for row in &fixture.reverse {
        session.execute_unpaged(&reverse, row).await?;
    }
    let proof = session
        .prepare(format!(
            "INSERT INTO {LEGACY_KEYSPACE}.checkpointed_object_table (obj_id, checkpoint_id, value) VALUES (?, ?, ?)"
        ))
        .await?;
    for row in &fixture.proofs {
        session.execute_unpaged(&proof, row).await?;
    }
    Ok(())
}

fn request(
    bootstrap: &CanonicalHeadBootstrap<PHash>,
) -> anyhow::Result<BranchExactSchemaMaterializationRequest> {
    let plan = BranchExactSchemaMaterializationPlan::try_new(
        bootstrap,
        authority(),
        Some(BranchExactPostGenesisFloorEvidence::new(
            authority(),
            BaselineSnapshotArtifactDigest::try_new([7; 32])?,
            AuthorityManifestDigest::from_persisted([8; 32]),
        )),
    )?;
    Ok(BranchExactSchemaMaterializationRequest::try_new(
        CqlKeyspaceName::try_new(LEGACY_KEYSPACE)?,
        plan,
    )?)
}

struct InjectOrphanReverse {
    session: Arc<Session>,
    fired: AtomicBool,
}

struct TestHeadReader(Arc<ScyllaCanonicalHeadStore>);

#[async_trait]
impl CoordinatorCanonicalHeadReader<PHash> for TestHeadReader {
    async fn read_canonical_head(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<CanonicalHeadReadState<PHash>> {
        Ok(self.0.read(network).await?)
    }
}

#[async_trait]
impl BranchExactLegacyExportObserver for InjectOrphanReverse {
    async fn observe(
        &self,
        boundary: BranchExactLegacyExportBoundary,
    ) -> anyhow::Result<()> {
        if boundary == BranchExactLegacyExportBoundary::FirstLegacySourceComplete
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            self.session
                .query_unpaged(
                    format!(
                        "INSERT INTO {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table (obj_id, value) VALUES (99999, 99)"
                    ),
                    &[],
                )
                .await?;
        }
        Ok(())
    }
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
    command.arg("compose").arg("-f").arg(compose_file).args(args);
    run_command(command, description)
}

async fn wait_up(expected: usize) -> anyhow::Result<()> {
    for _ in 0..90 {
        let status = docker_exec(
            NODE_CONTAINERS[0],
            &["nodetool", "status"],
            "read h19 cluster status",
        )?;
        if status.lines().filter(|line| line.starts_with("UN ")).count()
            == expected
        {
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("RF=3 cluster did not converge to {expected} Up/Normal nodes")
}

#[derive(Serialize)]
struct H19Report {
    baseline: &'static str,
    image: &'static str,
    replication_factor: u8,
    checkpoint_rows: usize,
    mapping_rows: usize,
    artifact_bytes: usize,
    first_export_ms: u64,
    retry_export_ms: u64,
    one_replica_offline_export_ms: u64,
    source_mutation_rejected: bool,
    orphan_reverse_rejected: bool,
    missing_reverse_rejected: bool,
    orphan_realm_proof_rejected: bool,
    malformed_realm_proof_rejected: bool,
    dataset_digest_hex: String,
}

#[tokio::test]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h19_branch_exact_legacy_exporter_rf3_gate() -> anyhow::Result<()> {
    if std::env::var("PSY_D04B6H19_RF3").as_deref() != Ok("1") {
        bail!("set PSY_D04B6H19_RF3=1 through the dedicated runner")
    }
    let compose_file = std::env::var("PSY_D04B6H19_COMPOSE_FILE")?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    create_schema(&session).await?;
    let fixture = fixture()?;
    load_fixture(&session, &fixture).await?;

    let head_store = Arc::new(
        ScyllaCanonicalHeadStore::prepare(
            session.clone(),
            CanonicalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        )
        .await?,
    );
    head_store.bootstrap(&fixture.bootstrap).await?;
    let head_reader: Arc<dyn CoordinatorCanonicalHeadReader<PHash>> =
        Arc::new(TestHeadReader(head_store.clone()));
    let exporter = ScyllaBranchExactLegacyExporter::prepare(
        session.clone(),
        session.clone(),
        authority(),
        CqlKeyspaceName::try_new(LEGACY_KEYSPACE)?,
        CqlKeyspaceName::try_new(LEGACY_KEYSPACE)?,
        head_reader,
    )
    .await?;
    let permit = BranchExactFrozenLegacyExportPermit::try_new(
        request(&fixture.bootstrap)?,
        *fixture.bootstrap.candidate(),
        BranchExactLegacyFreezeReason::AllAuthorityProcessorsStoppedAndDrained,
    )?;

    let started = Instant::now();
    let first = exporter
        .export::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
        )
        .await?;
    let first_export_ms = started.elapsed().as_millis() as u64;
    ensure!(first.receipt().pair_rows() == fixture.mappings.len() as u64);
    ensure!(first.receipt().proof_rows() == fixture.mappings.len() as u64);

    let started = Instant::now();
    let retry = exporter
        .export::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
        )
        .await?;
    let retry_export_ms = started.elapsed().as_millis() as u64;
    ensure!(
        first.artifact().to_canonical_bytes()
            == retry.artifact().to_canonical_bytes()
    );
    ensure!(first.receipt() == retry.receipt());

    let observer = InjectOrphanReverse {
        session: session.clone(),
        fired: AtomicBool::new(false),
    };
    let changed = exporter
        .export_observed::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
            &observer,
        )
        .await;
    ensure!(matches!(
        changed,
        Err(BranchExactLegacyExportError::LegacySourceChanged)
    ));
    session
        .query_unpaged(
            format!(
                "DELETE FROM {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table WHERE obj_id = 99999"
            ),
            &[],
        )
        .await?;

    session
        .query_unpaged(
            format!(
                "INSERT INTO {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table (obj_id, value) VALUES (99998, 98)"
            ),
            &[],
        )
        .await?;
    let orphan = exporter
        .export::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
        )
        .await;
    ensure!(matches!(
        orphan,
        Err(BranchExactLegacyExportError::OrphanReverse { .. })
    ));
    session
        .query_unpaged(
            format!(
                "DELETE FROM {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table WHERE obj_id = 99998"
            ),
            &[],
        )
        .await?;

    let missing_pending = fixture.reverse[0].0;
    session
        .query_unpaged(
            format!(
                "DELETE FROM {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table WHERE obj_id = ?"
            ),
            (missing_pending,),
        )
        .await?;
    let missing = exporter
        .export::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
        )
        .await;
    ensure!(matches!(
        missing,
        Err(BranchExactLegacyExportError::MissingReverse { .. })
    ));
    session
        .query_unpaged(
            format!(
                "INSERT INTO {LEGACY_KEYSPACE}.pending_id_to_checkpoint_id_table (obj_id, value) VALUES (?, ?)"
            ),
            fixture.reverse[0],
        )
        .await?;

    let proof_insert = session
        .prepare(format!(
            "INSERT INTO {LEGACY_KEYSPACE}.checkpointed_object_table (obj_id, checkpoint_id, value) VALUES (?, ?, ?)"
        ))
        .await?;
    session
        .execute_unpaged(
            &proof_insert,
            (2_i64, 99_997_i64, fixture.proofs[0].2.clone()),
        )
        .await?;
    let orphan_proof = exporter
        .export::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
        )
        .await;
    ensure!(matches!(
        orphan_proof,
        Err(BranchExactLegacyExportError::OrphanRealmProof(99_997))
    ));
    session
        .query_unpaged(
            format!(
                "DELETE FROM {LEGACY_KEYSPACE}.checkpointed_object_table WHERE obj_id = 2 AND checkpoint_id = 99997"
            ),
            &[],
        )
        .await?;

    let malformed_pending = fixture.proofs[0].1;
    session
        .execute_unpaged(
            &proof_insert,
            (
                2_i64,
                malformed_pending,
                vec![0xde_u8, 0xad, 0xbe, 0xef],
            ),
        )
        .await?;
    let malformed_proof = exporter
        .export::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
        )
        .await;
    ensure!(matches!(
        malformed_proof,
        Err(BranchExactLegacyExportError::MalformedRealmProof {
            pending_id,
            ..
        }) if pending_id == malformed_pending as u64
    ));
    session
        .execute_unpaged(&proof_insert, fixture.proofs[0].clone())
        .await?;

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
        "stop h19 third replica",
    )?;
    wait_up(2).await?;
    let started = Instant::now();
    let degraded = exporter
        .export::<PF, PoseidonHasher, PHash, HashProofVerifier>(
            &permit,
            fixture.config,
        )
        .await?;
    let one_replica_offline_export_ms = started.elapsed().as_millis() as u64;
    ensure!(
        degraded.artifact().to_canonical_bytes()
            == first.artifact().to_canonical_bytes()
    );
    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart h19 third replica",
    )?;
    wait_up(3).await?;
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair", LEGACY_KEYSPACE],
        "repair h19 tablet legacy keyspace",
    )?;
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", CONTROL_KEYSPACE],
            "repair h19 no-tablet control keyspace",
        )?;
        docker_exec(node, &["nodetool", "flush", LEGACY_KEYSPACE], "flush h19 legacy")?;
        docker_exec(node, &["nodetool", "flush", CONTROL_KEYSPACE], "flush h19 control")?;
        docker_exec(node, &["nodetool", "compact", LEGACY_KEYSPACE], "compact h19 legacy")?;
        docker_exec(node, &["nodetool", "compact", CONTROL_KEYSPACE], "compact h19 control")?;
    }

    let report = H19Report {
        baseline: BASELINE,
        image: IMAGE,
        replication_factor: 3,
        checkpoint_rows: fixture.transitions.len(),
        mapping_rows: fixture.mappings.len(),
        artifact_bytes: first.artifact().to_canonical_bytes().len(),
        first_export_ms,
        retry_export_ms,
        one_replica_offline_export_ms,
        source_mutation_rejected: true,
        orphan_reverse_rejected: true,
        missing_reverse_rejected: true,
        orphan_realm_proof_rejected: true,
        malformed_realm_proof_rejected: true,
        dataset_digest_hex: hex::encode(
            first.receipt().dataset_digest().as_bytes(),
        ),
    };
    let report_path = std::env::var("PSY_D04B6H19_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
