use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
        AuthorityTimestampReadState, AuthorityTimestampWriteOutcome,
        SealedAuthorityTimestampReservation,
    },
    authority_local_head::{
        AuthorityLocalHeadBootstrap, AuthorityLocalHeadBootstrapReason,
        AuthorityLocalHeadReadState, AuthorityLocalHeadWriteOutcome,
        AuthorityStorageBindingGeneration, AuthorityStorageBindingRef,
        AuthorityStorageNamespaceId,
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        SealedAuthorityCommitIntent,
    },
    manifest_lifecycle::{
        AuthorityHeadPayloadDigest, AuthorityHeadView,
        AuthorityPostWriteObservation, AuthorityProofObservation,
        PersistedAuthorityManifest,
    },
    manifest_record::{
        AuthorityManifestIdentity, PreparedManifestWriteOutcome,
    },
    normal_commit::{
        seal_verified_normal_commit, NormalCommitRecoveryAction,
        NormalHeadPublishProgress,
    },
    timestamp::CommitWriteTimestampUs,
    typed::CheckpointId as StorageCheckpointId,
};
use psy_node_scylla::rollback::{
    AuthorityLocalHeadNoTabletKeyspace, AuthorityLocalHeadQueries,
    AuthorityLocalHeadReadBinding, AuthorityTimestampNoTabletKeyspace,
    AuthorityTimestampQueries, AuthorityTimestampReadBinding,
    CanonicalManifestArtifacts, CanonicalPhysicalMutationBatch,
    FullPhysicalDeltaRecord,
    ManifestArtifactKeyspace, ManifestControlNoTabletKeyspace,
    ManifestPreparedKeyspaces, ManifestPreparedQueries, ManifestReadBinding,
    OperationalReplayAction, ReplayAuthority, ReplayReceipt,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaNormalCommitMetadataExecutor, ScyllaPreparedManifestStore,
    VerifiedPreparedManifestPackage,
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

const CONTROL_KEYSPACE: &str = "psy_d04b2b_rf3_nt";
const ARTIFACT_KEYSPACE: &str = "psy_d04b2b_rf3_artifacts";
const BASELINE: &str = "2e0871a94f461a4000253c5fd58ce73d09ffa146";
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

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1337).expect("test network is configured")
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

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

fn chain(
    checkpoint: u64,
    seed: u8,
) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(9),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128)
        .expect("test timestamp fits CQL BIGINT")
}

struct Fixture {
    key: AuthorityTimestampKey,
    timestamp_bootstrap: AuthorityTimestampBootstrap,
    reservation: SealedAuthorityTimestampReservation,
    head_bootstrap: AuthorityLocalHeadBootstrap<PHash>,
    package: VerifiedPreparedManifestPackage<PHash>,
}

impl Fixture {
    fn new(realm_id: u32, checkpoint: u64, seed: u8, high_water: i64) -> Self {
        let key = authority(realm_id);
        let checkpoint_id = StorageCheckpointId::try_new(checkpoint).unwrap();
        let replay = ReplayReceipt::new(
            ReplayAuthority::Realm,
            checkpoint_id,
            0,
            0,
            vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
        );
        let artifacts = CanonicalManifestArtifacts::try_from_full(
            &FullPhysicalDeltaRecord::try_new(
                CanonicalPhysicalMutationBatch::from_logical(Vec::new())
                    .unwrap(),
                replay,
            )
            .unwrap(),
        )
        .unwrap();
        let intent = SealedAuthorityCommitIntent::seal_normal_advance(
            key,
            chain(checkpoint - 1, seed),
            chain(checkpoint, seed.wrapping_add(1)),
            AuthorityStateTransition::Unchanged {
                checkpoint: AuthorityStateCheckpointId::new(checkpoint - 2),
                root: AuthorityStateRoot::from_local_state_root(hash(
                    seed.wrapping_add(2),
                )),
            },
            AuthorityHeadPayload::try_new(vec![seed; 16]).unwrap(),
            artifacts.commitment(),
        )
        .unwrap();
        let timestamp_bootstrap = AuthorityTimestampBootstrap::new(
            key,
            timestamp(high_water),
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
            timestamp(high_water),
            package.record().digest(),
            AuthorityStorageBindingRef::new(
                AuthorityStorageBindingGeneration::try_new(3).unwrap(),
                AuthorityStorageNamespaceId::from_verified_namespace_id([
                    seed.wrapping_add(3);
                    32
                ]),
            ),
        );
        Self {
            key,
            timestamp_bootstrap,
            reservation,
            head_bootstrap,
            package,
        }
    }

    fn identity(&self) -> AuthorityManifestIdentity<PHash> {
        *self.package.record().identity()
    }

    fn observation(&self) -> AuthorityPostWriteObservation<PHash> {
        AuthorityPostWriteObservation::new(
            AuthorityHeadView::candidate(self.package.record()),
            self.package.record().intent().artifacts().mutation_digest(),
            AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                self.package.record().intent().head_payload().as_bytes(),
            ),
            AuthorityProofObservation::NotApplicableForRealm,
        )
    }
}

struct Stores {
    manifests: ScyllaPreparedManifestStore,
    heads: ScyllaAuthorityLocalHeadStore,
    timestamps: ScyllaAuthorityTimestampStore,
}

impl Stores {
    fn executor(&self) -> ScyllaNormalCommitMetadataExecutor<'_> {
        ScyllaNormalCommitMetadataExecutor::new(
            &self.manifests,
            &self.heads,
            &self.timestamps,
        )
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
        .context("connect to isolated D-04b2b RF=3 Scylla cluster")
}

async fn create_schema(
    session: &Session,
) -> anyhow::Result<ManifestPreparedKeyspaces> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {CONTROL_KEYSPACE} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {ARTIFACT_KEYSPACE} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"
            ),
            &[],
        )
        .await?;
    let control = ManifestControlNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?;
    let artifacts = ManifestArtifactKeyspace::try_new(ARTIFACT_KEYSPACE)?;
    let keyspaces = ManifestPreparedKeyspaces::new(control.clone(), artifacts);
    ScyllaPreparedManifestStore::create_schema(session, &keyspaces).await?;
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
    Ok(keyspaces)
}

async fn open_stores(
    keyspaces: ManifestPreparedKeyspaces,
) -> anyhow::Result<Stores> {
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    let manifests = ScyllaPreparedManifestStore::prepare(
        Arc::clone(&session),
        keyspaces,
    )
    .await?;
    let heads = ScyllaAuthorityLocalHeadStore::prepare(
        Arc::clone(&session),
        AuthorityLocalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    let timestamps = ScyllaAuthorityTimestampStore::prepare(
        Arc::clone(&session),
        AuthorityTimestampNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
    )
    .await?;
    Ok(Stores {
        manifests,
        heads,
        timestamps,
    })
}

async fn initialize_fixture(stores: &Stores, fixture: &Fixture) -> anyhow::Result<()> {
    ensure!(matches!(
        stores.timestamps.bootstrap(fixture.timestamp_bootstrap).await?,
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
        stores.manifests.persist_prepared(&fixture.package).await?,
        PreparedManifestWriteOutcome::Applied(_)
    ));
    Ok(())
}

async fn seal_and_persist(stores: &Stores, fixture: &Fixture) -> anyhow::Result<()> {
    let prepared = match stores.executor().plan(fixture.identity()).await? {
        NormalCommitRecoveryAction::ReapplyExactMutationsAndVerify { prepared } => {
            prepared
        }
        other => bail!("expected PREPARED replay action, got {other:?}"),
    };
    let head = match stores.heads.read(fixture.key).await? {
        AuthorityLocalHeadReadState::Current(head) => head,
        AuthorityLocalHeadReadState::Uninitialized => bail!("head is missing"),
    };
    let allocator = stores
        .timestamps
        .read_observed(fixture.key)
        .await?
        .context("allocator is missing")?;
    let sealed = seal_verified_normal_commit(
        prepared,
        fixture.observation(),
        &head,
        allocator,
    )?;
    stores.executor().persist_sealed(&sealed).await?;
    Ok(())
}

async fn publish_head(stores: &Stores, fixture: &Fixture) -> anyhow::Result<()> {
    let publish = match stores.executor().plan(fixture.identity()).await? {
        NormalCommitRecoveryAction::PublishExactHead { publish } => publish,
        other => bail!("expected exact head publish, got {other:?}"),
    };
    ensure!(matches!(
        stores.executor().publish_head(publish).await?,
        NormalHeadPublishProgress::PersistCommitted { .. }
    ));
    Ok(())
}

async fn finish_recovered_commit(
    stores: &Stores,
    fixture: &Fixture,
) -> anyhow::Result<()> {
    let committed = match stores.executor().plan(fixture.identity()).await? {
        NormalCommitRecoveryAction::PersistRecoveredCommitted { committed } => {
            committed
        }
        other => bail!("expected recovered COMMITTED write, got {other:?}"),
    };
    stores.executor().persist_committed(&committed).await?;
    Ok(())
}

async fn complete_timestamp(
    stores: &Stores,
    fixture: &Fixture,
) -> anyhow::Result<()> {
    let completion = match stores.executor().plan(fixture.identity()).await? {
        NormalCommitRecoveryAction::CompleteTimestampLease { completion } => {
            completion
        }
        other => bail!("expected timestamp completion, got {other:?}"),
    };
    stores.executor().complete_timestamp(completion).await?;
    ensure!(matches!(
        stores.executor().plan(fixture.identity()).await?,
        NormalCommitRecoveryAction::Done { .. }
    ));
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
        "read D-04b2b RF=3 status",
    )
}

async fn wait_for_three_up_normal() -> anyhow::Result<()> {
    for _ in 0..90 {
        if cluster_status()?
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

#[derive(Clone, Copy, Debug, Serialize)]
struct MaintenanceTiming {
    repair_ms: u64,
    flush_ms: u64,
    compact_ms: u64,
}

fn repair_flush_compact_all() -> anyhow::Result<MaintenanceTiming> {
    let repair_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", CONTROL_KEYSPACE],
            "repair D-04b2b no-tablet control keyspace",
        )?;
    }
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair"],
        "repair D-04b2b tablet artifact keyspace",
    )?;
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let flush_started = Instant::now();
    for node in NODE_CONTAINERS {
        for keyspace in [CONTROL_KEYSPACE, ARTIFACT_KEYSPACE] {
            docker_exec(
                node,
                &["nodetool", "flush", keyspace],
                "flush D-04b2b keyspace",
            )?;
        }
    }
    let flush_ms = flush_started.elapsed().as_millis() as u64;
    let compact_started = Instant::now();
    for node in NODE_CONTAINERS {
        for keyspace in [CONTROL_KEYSPACE, ARTIFACT_KEYSPACE] {
            docker_exec(
                node,
                &["nodetool", "compact", keyspace],
                "compact D-04b2b keyspace",
            )?;
        }
    }
    Ok(MaintenanceTiming {
        repair_ms,
        flush_ms,
        compact_ms: compact_started.elapsed().as_millis() as u64,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectReplicaRows {
    manifest: (i64, i8, Vec<u8>, Vec<u8>, Vec<u8>),
    head: (i64, i8, i64, i64, Option<i64>, Option<Vec<u8>>),
    timestamp: (i64, i8, i64, i64, Option<i64>, Option<Vec<u8>>),
}

async fn read_direct_rows(
    ip: Ipv4Addr,
    fixture: &Fixture,
) -> anyhow::Result<DirectReplicaRows> {
    let session = connect(Some(ip), Consistency::One).await?;
    let manifest_keyspaces = ManifestPreparedKeyspaces::new(
        ManifestControlNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        ManifestArtifactKeyspace::try_new(ARTIFACT_KEYSPACE)?,
    );
    let manifest_queries = ManifestPreparedQueries::new(&manifest_keyspaces);
    let manifest = session
        .query_unpaged(
            manifest_queries.read_manifest().cql(),
            ManifestReadBinding::try_from_identity(&fixture.identity())?,
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, i8, Vec<u8>, Vec<u8>, Vec<u8>)>()?;

    let head_keyspace = AuthorityLocalHeadNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?;
    let head_queries = AuthorityLocalHeadQueries::new(&head_keyspace);
    let head = session
        .query_unpaged(
            head_queries.read().cql(),
            AuthorityLocalHeadReadBinding::from_key(fixture.key),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, i8, i64, i64, Option<i64>, Option<Vec<u8>>)>()?;

    let timestamp_keyspace =
        AuthorityTimestampNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?;
    let timestamp_queries = AuthorityTimestampQueries::new(&timestamp_keyspace);
    let timestamp = session
        .query_unpaged(
            timestamp_queries.read().cql(),
            AuthorityTimestampReadBinding::from_key(fixture.key),
        )
        .await?
        .into_rows_result()?
        .single_row::<(i64, i8, i64, i64, Option<i64>, Option<Vec<u8>>)>()?;
    Ok(DirectReplicaRows {
        manifest,
        head,
        timestamp,
    })
}

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
}

#[derive(Debug, Serialize)]
struct D04b2bReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    serial_consistency: &'static str,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    restart_count: u8,
    offline_full_commit_us: u64,
    maintenance: MaintenanceTiming,
    direct_one_replicas_equal: bool,
    scenarios_passed: Vec<&'static str>,
    cleanup_policy: &'static str,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive local three-node Scylla RF=3 harness"]
async fn d04b2b_normal_commit_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B2B_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b2b.sh"
    );
    let compose_file = std::env::var("PSY_D04B2B_COMPOSE_FILE")
        .context("PSY_D04B2B_COMPOSE_FILE is required")?;
    let report_path = std::env::var("PSY_D04B2B_REPORT_PATH")
        .context("PSY_D04B2B_REPORT_PATH is required")?;
    let started_unix_ms = unix_ms()?;
    ensure!(
        cluster_status()?.lines().filter(|line| line.starts_with("UN ")).count()
            == 3,
        "RF=3 cluster must start with three Up/Normal members"
    );

    let schema_session = connect(None, Consistency::Quorum).await?;
    let keyspaces = create_schema(&schema_session).await?;
    drop(schema_session);

    // M18: SEALED is durable, but the process restarts before head CAS. The
    // new session/adapter set must resume the exact sealed head publication.
    let response_loss = Fixture::new(41, 101, 0x31, 1_000_000);
    let stores = open_stores(keyspaces.clone()).await?;
    initialize_fixture(&stores, &response_loss).await?;
    seal_and_persist(&stores, &response_loss).await?;
    drop(stores);

    let stores = open_stores(keyspaces.clone()).await?;
    publish_head(&stores, &response_loss).await?;
    // M19: head LWT succeeds, its response/result is discarded, and the next
    // process derives COMMITTED from SEALED + the already-published head.
    drop(stores);

    let stores = open_stores(keyspaces.clone()).await?;
    finish_recovered_commit(&stores, &response_loss).await?;
    // COMMITTED LWT response is discarded before allocator completion.
    drop(stores);

    let stores = open_stores(keyspaces.clone()).await?;
    ensure!(matches!(
        stores
            .manifests
            .read_lifecycle(response_loss.identity())
            .await?,
        Some(PersistedAuthorityManifest::Committed(_))
    ));
    complete_timestamp(&stores, &response_loss).await?;
    ensure!(matches!(
        stores.timestamps.read(response_loss.key).await?,
        AuthorityTimestampReadState::Current(_)
    ));
    drop(stores);

    // The exact three-table lifecycle remains available with one RF=3 member
    // offline. This is metadata-only; state replay/root verification is not
    // claimed by this gate.
    let stores = open_stores(keyspaces.clone()).await?;
    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop one D-04b2b RF=3 replica",
    )?;
    sleep(Duration::from_secs(3)).await;
    let offline = Fixture::new(42, 102, 0x41, 2_000_000);
    let offline_started = Instant::now();
    initialize_fixture(&stores, &offline).await?;
    seal_and_persist(&stores, &offline).await?;
    publish_head(&stores, &offline).await?;
    finish_recovered_commit(&stores, &offline).await?;
    complete_timestamp(&stores, &offline).await?;
    let offline_full_commit_us = offline_started.elapsed().as_micros() as u64;
    drop(stores);

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart D-04b2b RF=3 replica",
    )?;
    wait_for_three_up_normal().await?;
    let maintenance = repair_flush_compact_all()?;

    let mut rows = Vec::new();
    for ip in NODE_IPS {
        rows.push(read_direct_rows(ip, &offline).await?);
    }
    let direct_one_replicas_equal = rows.iter().all(|row| row == &rows[0]);
    ensure!(
        direct_one_replicas_equal,
        "repair/flush/compact must converge manifest/head/timestamp direct ONE rows"
    );

    let final_stores = open_stores(keyspaces).await?;
    ensure!(matches!(
        final_stores.executor().plan(response_loss.identity()).await?,
        NormalCommitRecoveryAction::Done { .. }
    ));
    ensure!(matches!(
        final_stores.executor().plan(offline.identity()).await?,
        NormalCommitRecoveryAction::Done { .. }
    ));

    let scylla_release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read Scylla version",
    )?
    .trim()
    .to_owned();
    let report = D04b2bReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        serial_consistency: "LOCAL_SERIAL",
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        restart_count: 3,
        offline_full_commit_us,
        maintenance,
        direct_one_replicas_equal,
        scenarios_passed: vec![
            "M18 SEALED restart resumes the exact head publication",
            "M19 head publish response loss recovers COMMITTED from SEALED plus head",
            "COMMITTED response loss recovers timestamp completion",
            "restart planner reaches Done without guessed state",
            "one replica offline supports the three-table metadata lifecycle",
            "repair flush compact converges manifest head timestamp direct-ONE rows",
        ],
        cleanup_policy: "runner removes cluster and volumes unless PSY_D04B2B_KEEP_CLUSTER=1",
        qualification: "D-04b2b metadata durability gate only; no production Processor, state writer, M16/M17 root verification, rollback executor, or capability promotion",
    };
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write D-04b2b RF=3 report {report_path}"))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
