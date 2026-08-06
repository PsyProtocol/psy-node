use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    },
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition,
        SealedAuthorityCommitIntent,
    },
    manifest_record::PreparedManifestWriteOutcome,
    timestamp::CommitWriteTimestampUs,
    typed::{
        CheckpointId as StorageCheckpointId, LogicalMutation, MutationValue,
        TypedTableKey,
    },
};
use psy_node_scylla::rollback::{
    CanonicalManifestArtifacts, CanonicalPhysicalMutationBatch,
    FullPhysicalDeltaRecord, ManifestArtifactKeyspace,
    ManifestControlNoTabletKeyspace, ManifestPreparedKeyspaces,
    OperationalReplayAction, ReplayAuthority, ReplayReceipt,
    ScyllaPreparedManifestStore, VerifiedPreparedManifestPackage,
};
use scylla::{
    client::{
        execution_profile::ExecutionProfile, session::Session,
        session_builder::SessionBuilder,
    },
    statement::Consistency,
};
use serde::Serialize;
use tokio::time::sleep;

const CONTROL_KEYSPACE: &str = "psy_d03b_rf3_nt";
const ARTIFACT_KEYSPACE: &str = "psy_d03b_rf3_artifacts";
const BASELINE: &str = "3f485c776abb8cc3a7ee1dc2ed31d5cf55de0559";
const IMAGE: &str = "scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc";
const CONCURRENT_WRITERS: usize = 32;
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

fn hash(seed: u8) -> PHash {
    PHash::from_owned_32bytes([seed; 32])
}

fn chain(epoch: u64, checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(epoch),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn artifacts(
    checkpoint: u64,
    value: Option<u8>,
) -> CanonicalManifestArtifacts {
    let checkpoint = StorageCheckpointId::try_new(checkpoint).unwrap();
    let mutations = value.map_or_else(Vec::new, |value| {
        vec![LogicalMutation::Put {
            key: TypedTableKey::CheckpointLeaf(checkpoint),
            value: MutationValue::PsyCanonicalBytes(vec![value; 256]),
        }]
    });
    let mutation_count = mutations.len() as u32;
    let batch = CanonicalPhysicalMutationBatch::from_logical(mutations).unwrap();
    let receipt = ReplayReceipt::new(
        ReplayAuthority::Realm,
        checkpoint,
        0,
        mutation_count,
        vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
    );
    CanonicalManifestArtifacts::try_from_full(
        &FullPhysicalDeltaRecord::try_new(batch, receipt).unwrap(),
    )
    .unwrap()
}

fn package(
    epoch: u64,
    checkpoint: u64,
    candidate_hash_seed: u8,
    value: Option<u8>,
    timestamp: i64,
) -> VerifiedPreparedManifestPackage<PHash> {
    let artifacts = artifacts(checkpoint, value);
    let key = AuthorityTimestampKey::new(
        network(),
        AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 2,
        },
    );
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        chain(epoch, checkpoint - 1, 0x11),
        chain(epoch, checkpoint, candidate_hash_seed),
        AuthorityStateTransition::Unchanged {
            checkpoint: AuthorityStateCheckpointId::new(checkpoint - 1),
            root: AuthorityStateRoot::from_local_state_root(hash(0x71)),
        },
        AuthorityHeadPayload::try_new(vec![0x55; 12]).unwrap(),
        artifacts.commitment(),
    )
    .unwrap();
    let bootstrap = AuthorityTimestampBootstrap::new(
        key,
        CommitWriteTimestampUs::try_from_i128(timestamp as i128 - 1).unwrap(),
        AuthorityTimestampBootstrapReason::GenesisNative,
    );
    let reservation = bootstrap
        .candidate()
        .seal_reservation(
            key,
            intent.digest(),
            AuthorityClockSampleUs::try_from_i128(timestamp as i128).unwrap(),
        )
        .unwrap();
    let prepared = intent.attach_timestamp_lease(reservation.lease()).unwrap();
    VerifiedPreparedManifestPackage::try_new(&prepared, artifacts).unwrap()
}

fn unix_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time predates Unix epoch")?
        .as_millis() as u64)
}

async fn connect() -> anyhow::Result<Session> {
    let profile = ExecutionProfile::builder()
        .consistency(Consistency::Quorum)
        .request_timeout(Some(Duration::from_secs(120)))
        .build();
    SessionBuilder::new()
        .known_nodes_addr(NODE_IPS.map(|ip| SocketAddr::from((ip, 9042))))
        .default_execution_profile_handle(profile.into_handle())
        .connection_timeout(Duration::from_secs(120))
        .build()
        .await
        .context("connect to isolated D-03b RF=3 cluster")
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
    let keyspaces = ManifestPreparedKeyspaces::new(
        ManifestControlNoTabletKeyspace::try_new(CONTROL_KEYSPACE)?,
        ManifestArtifactKeyspace::try_new(ARTIFACT_KEYSPACE)?,
    );
    ScyllaPreparedManifestStore::create_schema(session, &keyspaces).await?;
    Ok(keyspaces)
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
        "read D-03b RF=3 status",
    )
}

async fn wait_for_three_up_normal() -> anyhow::Result<String> {
    for _ in 0..90 {
        let status = cluster_status()?;
        if status.lines().filter(|line| line.starts_with("UN ")).count() == 3 {
            return Ok(status);
        }
        sleep(Duration::from_secs(2)).await;
    }
    bail!("cluster did not return to three UN members")
}

fn repair_flush_compact_all() -> anyhow::Result<MaintenanceTiming> {
    let repair_started = Instant::now();
    for node in NODE_CONTAINERS {
        docker_exec(
            node,
            &["nodetool", "repair", "-pr", CONTROL_KEYSPACE],
            "repair D-03b vnode control keyspace",
        )?;
    }
    // Scylla 2026 rejects vnode repair for tablet keyspaces. One cluster-wide
    // repair invocation covers all tablet keyspaces, including artifacts.
    docker_exec(
        NODE_CONTAINERS[0],
        &["nodetool", "cluster", "repair"],
        "repair D-03b tablet artifact keyspace",
    )?;
    let repair_ms = repair_started.elapsed().as_millis() as u64;
    let flush_started = Instant::now();
    for node in NODE_CONTAINERS {
        for keyspace in [CONTROL_KEYSPACE, ARTIFACT_KEYSPACE] {
            docker_exec(
                node,
                &["nodetool", "flush", keyspace],
                "flush D-03b keyspace",
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
                "compact D-03b keyspace",
            )?;
        }
    }
    Ok(MaintenanceTiming {
        repair_ms,
        flush_ms,
        compact_ms: compact_started.elapsed().as_millis() as u64,
    })
}

fn assert_artifacts(
    package: &VerifiedPreparedManifestPackage<PHash>,
    loaded: &psy_node_scylla::rollback::VerifiedPersistedManifestArtifacts,
) -> anyhow::Result<()> {
    if let Some(set) = package.artifacts().chunked() {
        ensure!(
            loaded.locator() == Some(set.locator().verify_and_reassemble()?.as_slice()),
            "locator bytes differ"
        );
        ensure!(
            loaded.replay_record()
                == set.replay_record().verify_and_reassemble()?.as_slice(),
            "replay bytes differ"
        );
    } else {
        ensure!(loaded.locator().is_none(), "zero mutation has locator");
        ensure!(!loaded.replay_record().is_empty(), "zero receipt is empty");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize)]
struct MaintenanceTiming {
    repair_ms: u64,
    flush_ms: u64,
    compact_ms: u64,
}

#[derive(Debug, Serialize)]
struct D03bReport {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    chunk_write_consistency: &'static str,
    manifest_regular_consistency: &'static str,
    manifest_serial_consistency: &'static str,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    concurrent_writers: usize,
    concurrent_applied: usize,
    concurrent_idempotent: usize,
    concurrent_conflicts: usize,
    offline_write_us: u64,
    maintenance: MaintenanceTiming,
    scenarios_passed: Vec<&'static str>,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the destructive local three-node Scylla RF=3 harness"]
async fn d03b_prepared_manifest_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D03B_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d03b.sh"
    );
    let compose_file = std::env::var("PSY_D03B_COMPOSE_FILE")
        .context("PSY_D03B_COMPOSE_FILE is required")?;
    let report_path = std::env::var("PSY_D03B_REPORT_PATH")
        .context("PSY_D03B_REPORT_PATH is required")?;
    let started_unix_ms = unix_ms()?;
    ensure!(
        cluster_status()?.lines().filter(|line| line.starts_with("UN ")).count()
            == 3,
        "RF=3 cluster must start with three UN members"
    );

    let session = Arc::new(connect().await?);
    let keyspaces = create_schema(&session).await?;
    let store = Arc::new(
        ScyllaPreparedManifestStore::prepare(
            Arc::clone(&session),
            keyspaces.clone(),
        )
        .await?,
    );
    let contract = store.consistency_contract();
    ensure!(contract.chunk_write() == Consistency::Quorum);
    ensure!(contract.read() == Consistency::Quorum);

    let happy = package(7, 41, 0x21, Some(0x31), 1_000_001);
    ensure!(matches!(
        store.persist_prepared(&happy).await?,
        PreparedManifestWriteOutcome::Applied(_)
    ));
    ensure!(matches!(
        store.persist_prepared(&happy).await?,
        PreparedManifestWriteOutcome::Idempotent(_)
    ));
    let happy_record = store
        .read_manifest(*happy.record().identity())
        .await?
        .context("happy manifest missing")?;
    assert_artifacts(
        &happy,
        &store.load_verified_artifacts(&happy_record).await?,
    )?;

    // M15: verified chunks are durable but non-authoritative until the
    // separate PREPARED LWT succeeds.
    let crash_window = package(7, 42, 0x22, Some(0x32), 1_000_002);
    store.persist_artifacts(&crash_window).await?;
    ensure!(
        store
            .read_manifest(*crash_window.record().identity())
            .await?
            .is_none(),
        "orphan chunks unexpectedly published a manifest"
    );
    drop(store);
    drop(session);
    let restarted_session = Arc::new(connect().await?);
    let restarted = Arc::new(
        ScyllaPreparedManifestStore::prepare(
            Arc::clone(&restarted_session),
            keyspaces,
        )
        .await?,
    );
    ensure!(
        restarted
            .read_manifest(*crash_window.record().identity())
            .await?
            .is_none()
    );
    let recovered_receipt = restarted
        .verify_existing_artifacts(&crash_window)
        .await?;
    ensure!(matches!(
        restarted
            .insert_prepared(crash_window.record(), &recovered_receipt)
            .await?,
        PreparedManifestWriteOutcome::Applied(_)
    ));

    // Two different manifests deliberately share the exact chain identity.
    // Immutable chunks stay isolated by manifest digest; one LWT row wins.
    let candidate_a = Arc::new(package(7, 43, 0x23, Some(0x41), 1_000_003));
    let candidate_b = Arc::new(package(7, 43, 0x23, Some(0x42), 1_000_003));
    let receipt_a = Arc::new(restarted.persist_artifacts(&candidate_a).await?);
    let receipt_b = Arc::new(restarted.persist_artifacts(&candidate_b).await?);
    ensure!(matches!(
        restarted
            .insert_prepared(candidate_b.record(), &receipt_a)
            .await,
        Err(psy_node_scylla::rollback::ManifestPreparedError::VerifiedChunkReceiptMismatch)
    ));
    let attempts = (0..CONCURRENT_WRITERS).map(|index| {
        let store = Arc::clone(&restarted);
        let package = if index % 2 == 0 {
            Arc::clone(&candidate_a)
        } else {
            Arc::clone(&candidate_b)
        };
        let receipt = if index % 2 == 0 {
            Arc::clone(&receipt_a)
        } else {
            Arc::clone(&receipt_b)
        };
        async move {
            store
                .insert_prepared(package.record(), &receipt)
                .await
        }
    });
    let mut applied = 0usize;
    let mut idempotent = 0usize;
    let mut conflicts = 0usize;
    for result in join_all(attempts).await {
        match result? {
            PreparedManifestWriteOutcome::Applied(_) => applied += 1,
            PreparedManifestWriteOutcome::Idempotent(_) => idempotent += 1,
            PreparedManifestWriteOutcome::Conflict(_) => conflicts += 1,
        }
    }
    ensure!(applied == 1, "concurrent PREPARED LWT had {applied} winners");
    ensure!(
        applied + idempotent + conflicts == CONCURRENT_WRITERS,
        "concurrent outcome count mismatch"
    );
    let winner = restarted
        .read_manifest(*candidate_a.record().identity())
        .await?
        .context("concurrent winner missing")?;
    let winner_package = if winner == *candidate_a.record() {
        &*candidate_a
    } else {
        ensure!(winner == *candidate_b.record(), "unexpected winner payload");
        &*candidate_b
    };
    assert_artifacts(
        winner_package,
        &restarted.load_verified_artifacts(&winner).await?,
    )?;

    let zero = package(7, 44, 0x24, None, 1_000_004);
    ensure!(matches!(
        restarted.persist_prepared(&zero).await?,
        PreparedManifestWriteOutcome::Applied(_)
    ));
    let zero_record = restarted
        .read_manifest(*zero.record().identity())
        .await?
        .context("zero manifest missing")?;
    assert_artifacts(
        &zero,
        &restarted.load_verified_artifacts(&zero_record).await?,
    )?;

    compose(
        Path::new(&compose_file),
        &["stop", "--timeout", "30", "scylla3"],
        "stop one D-03b replica",
    )?;
    sleep(Duration::from_secs(3)).await;
    let offline = package(7, 45, 0x25, Some(0x51), 1_000_005);
    let offline_started = Instant::now();
    ensure!(matches!(
        restarted.persist_prepared(&offline).await?,
        PreparedManifestWriteOutcome::Applied(_)
    ));
    let offline_write_us = offline_started.elapsed().as_micros() as u64;
    // Simulate a lost success response: exact retry must observe the winner.
    ensure!(matches!(
        restarted.persist_prepared(&offline).await?,
        PreparedManifestWriteOutcome::Idempotent(_)
    ));
    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
        "restart D-03b replica",
    )?;
    wait_for_three_up_normal().await?;
    let maintenance = repair_flush_compact_all()?;
    let offline_record = restarted
        .read_manifest(*offline.record().identity())
        .await?
        .context("offline manifest missing after repair")?;
    assert_artifacts(
        &offline,
        &restarted.load_verified_artifacts(&offline_record).await?,
    )?;

    let scylla_release = docker_exec(
        NODE_CONTAINERS[0],
        &["scylla", "--version"],
        "read Scylla version",
    )?
    .trim()
    .to_owned();
    let report = D03bReport {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release,
        replication_factor: 3,
        chunk_write_consistency: "QUORUM",
        manifest_regular_consistency: "QUORUM",
        manifest_serial_consistency: "LOCAL_SERIAL",
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        concurrent_writers: CONCURRENT_WRITERS,
        concurrent_applied: applied,
        concurrent_idempotent: idempotent,
        concurrent_conflicts: conflicts,
        offline_write_us,
        maintenance,
        scenarios_passed: vec![
            "chunk write/read-back then PREPARED LWT",
            "M15 orphan chunks are non-authoritative across restart",
            "same-identity conflicting digests have one PREPARED winner",
            "exact retry is idempotent",
            "zero-mutation PREPARED has no chunks",
            "one replica offline QUORUM chunks and LWT",
            "restart repair flush compact preserves verified artifacts",
        ],
        qualification: "D-03b durable PREPARED substrate only; no production writer, lifecycle transition, archive, or executor wiring",
    };
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("write D-03b report {report_path}"))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
