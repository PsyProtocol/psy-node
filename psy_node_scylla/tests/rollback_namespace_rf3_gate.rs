use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context};
use psy_node_core::store::{timestamp::CommitWriteTimestampUs, typed::CheckpointId};
use psy_node_scylla::rollback::*;
use scylla::{
    client::{execution_profile::ExecutionProfile, session::Session, session_builder::SessionBuilder},
    statement::Consistency,
};
use serde::Serialize;

const CONTROL_KEYSPACE: &str = "psy_g003_control";
const BINDING_TABLE: &str = "g003_authority_active_binding";
const CATALOG_TABLE: &str = "g003_recovery_namespace_catalog";
const BASELINE: &str = "daffd6b425424a7c3c73338c346a608d626017e9";
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
const LOAD_TIMESTAMP_US: i64 = 7_000_000;

fn checkpoint(value: u64) -> CheckpointId {
    CheckpointId::try_new(value).expect("G0-03 checkpoint fits CQL BIGINT")
}

fn generation(value: u64) -> BindingGeneration {
    BindingGeneration::try_new(value).expect("G0-03 generation fits CQL BIGINT")
}

fn commit_timestamp(value: i64) -> CommitWriteTimestampUs {
    CommitWriteTimestampUs::try_from_i128(value as i128).expect("G0-03 timestamp fits CQL timestamp")
}

fn authority() -> anyhow::Result<StorageAuthority> {
    Ok(StorageAuthority::try_new("g003-rf3", StorageAuthorityKind::Realm, 7)?)
}

fn recovery(
    authority: &StorageAuthority,
    seed: u64,
    target: u64,
    expected_generation: u64,
) -> anyhow::Result<(RepresentativeDataset, RecoveryNamespaceDescriptor)> {
    let dataset = RepresentativeDataset::artificial(seed, checkpoint(target), 8, 48, 4)?;
    let descriptor = RecoveryNamespaceDescriptor::from_dataset(
        authority.clone(),
        checkpoint(target),
        NamespaceCheckpointHash::new([seed as u8; 32]),
        generation(expected_generation),
        &dataset,
    )?;
    Ok((dataset, descriptor))
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
        .context("connect to isolated G0-03 RF=3 Scylla cluster")
}

async fn prepare_control(session: &Session) -> anyhow::Result<NamespaceControlAdapter> {
    NamespaceControlAdapter::prepare(session, CqlKeyspaceName::try_new(CONTROL_KEYSPACE)?).await.map_err(Into::into)
}

async fn create_and_load(
    session: &Session,
    control: &NamespaceControlAdapter,
    descriptor: RecoveryNamespaceDescriptor,
    dataset: &RepresentativeDataset,
    now_ms: i64,
) -> anyhow::Result<(VerifiedRecoveryNamespace, Duration, Duration, Duration)> {
    let create_started = Instant::now();
    RepresentativeNamespaceStore::create_schema(session, descriptor.namespace()).await?;
    let create_elapsed = create_started.elapsed();
    let loading = control.begin_loading(session, descriptor.clone(), now_ms).await?;
    let store = RepresentativeNamespaceStore::prepare(
        session,
        descriptor.namespace().clone(),
        Consistency::Quorum,
    )
    .await?;
    let load_started = Instant::now();
    store
        .load_dataset(session, &loading, dataset, commit_timestamp(LOAD_TIMESTAMP_US))
        .await?;
    let load_elapsed = load_started.elapsed();
    let verify_started = Instant::now();
    let verified = store
        .verify_and_mark(session, control, &loading, dataset, now_ms + 1)
        .await?;
    let verify_elapsed = verify_started.elapsed();
    Ok((verified, create_elapsed, load_elapsed, verify_elapsed))
}

fn run_command(mut command: Command, description: &str) -> anyhow::Result<String> {
    let output = command.output().with_context(|| format!("start {description}"))?;
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

fn docker_exec(container: &str, args: &[&str], description: &str) -> anyhow::Result<String> {
    let mut command = Command::new("docker");
    command.arg("exec").arg(container).args(args);
    run_command(command, description)
}

fn flush_keyspaces(namespaces: &[AuthorityStorageNamespace]) -> anyhow::Result<()> {
    for node in NODE_CONTAINERS {
        for namespace in namespaces {
            for keyspace in [namespace.standard(), namespace.no_tablet()] {
                docker_exec(node, &["nodetool", "flush", keyspace.as_str()], "flush G0-03 namespace")?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
struct NamespaceDiskBytes {
    namespace_id: String,
    standard_keyspace: String,
    no_tablet_keyspace: String,
    per_node_standard: Vec<u64>,
    per_node_no_tablet: Vec<u64>,
}

fn disk_bytes(path: &str, container: &str) -> anyhow::Result<u64> {
    let output = docker_exec(container, &["du", "-sb", path], "measure G0-03 namespace disk bytes")?;
    output
        .split_whitespace()
        .next()
        .context("du output had no byte count")?
        .parse::<u64>()
        .context("parse namespace disk byte count")
}

fn namespace_disk_bytes(namespace: &AuthorityStorageNamespace) -> anyhow::Result<NamespaceDiskBytes> {
    let mut standard = Vec::new();
    let mut no_tablet = Vec::new();
    for node in NODE_CONTAINERS {
        standard.push(disk_bytes(
            &format!("/var/lib/scylla/data/{}", namespace.standard().as_str()),
            node,
        )?);
        no_tablet.push(disk_bytes(
            &format!("/var/lib/scylla/data/{}", namespace.no_tablet().as_str()),
            node,
        )?);
    }
    Ok(NamespaceDiskBytes {
        namespace_id: namespace.id().to_hex(),
        standard_keyspace: namespace.standard().as_str().to_owned(),
        no_tablet_keyspace: namespace.no_tablet().as_str().to_owned(),
        per_node_standard: standard,
        per_node_no_tablet: no_tablet,
    })
}

#[derive(Clone, Debug, Serialize)]
struct LatencySummary {
    samples: usize,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

impl LatencySummary {
    fn from_samples(mut values: Vec<u64>) -> Self {
        values.sort_unstable();
        let percentile = |percent: usize| {
            let index = ((values.len() * percent).div_ceil(100)).saturating_sub(1);
            values[index]
        };
        Self {
            samples: values.len(),
            p50_us: percentile(50),
            p95_us: percentile(95),
            p99_us: percentile(99),
            max_us: *values.last().expect("latency report has samples"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct NamespaceTiming {
    namespace_id: String,
    create_ms: u64,
    load_ms: u64,
    verify_ms: u64,
    rows: u64,
    payload_bytes: u64,
    load_rows_per_second: f64,
}

fn payload_bytes(dataset: &RepresentativeDataset) -> u64 {
    dataset.checkpoint_leaves().iter().map(|row| row.value().len() as u64).sum::<u64>()
        + dataset.global_user_merkle().len() as u64 * 32
        + dataset.no_tablet_counters().len() as u64 * 16
}

fn namespace_timing(
    descriptor: &RecoveryNamespaceDescriptor,
    dataset: &RepresentativeDataset,
    create: Duration,
    load: Duration,
    verify: Duration,
) -> NamespaceTiming {
    NamespaceTiming {
        namespace_id: descriptor.namespace().id().to_hex(),
        create_ms: create.as_millis() as u64,
        load_ms: load.as_millis() as u64,
        verify_ms: verify.as_millis() as u64,
        rows: dataset.counts().total(),
        payload_bytes: payload_bytes(dataset),
        load_rows_per_second: dataset.counts().total() as f64 / load.as_secs_f64(),
    }
}

#[derive(Debug, Serialize)]
struct G003Report {
    baseline: &'static str,
    image: &'static str,
    scylla_release: String,
    replication_factor: u8,
    regular_consistency: &'static str,
    serial_consistency: &'static str,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    representative_tables: Vec<&'static str>,
    namespace_timings: Vec<NamespaceTiming>,
    binding_cas: LatencySummary,
    reconnect_binding_reload: LatencySummary,
    namespace_disk_bytes: Vec<NamespaceDiskBytes>,
    old_namespace_still_physical: bool,
    final_binding_generation: u64,
    final_namespace_id: String,
    scenarios_passed: Vec<&'static str>,
    g14: &'static str,
    cleanup_policy: &'static str,
    qualification: &'static str,
}

async fn set_binding_i64(session: &Session, column: &str, value: i64, authority: &StorageAuthority) -> anyhow::Result<()> {
    ensure!(matches!(column, "binding_generation" | "checkpoint_id"), "unsafe test column");
    session
        .query_unpaged(
            format!(
                "UPDATE {CONTROL_KEYSPACE}.{BINDING_TABLE} SET {column} = ? \
                 WHERE network_id = ? AND authority_kind = ? AND authority_id = ?"
            ),
            (
                value,
                authority.network_id(),
                authority.kind().as_i8(),
                authority.authority_id() as i64,
            ),
        )
        .await?;
    Ok(())
}

async fn set_binding_blob(session: &Session, column: &str, value: &[u8], authority: &StorageAuthority) -> anyhow::Result<()> {
    ensure!(matches!(column, "checkpoint_hash" | "dataset_digest"), "unsafe test column");
    session
        .query_unpaged(
            format!(
                "UPDATE {CONTROL_KEYSPACE}.{BINDING_TABLE} SET {column} = ? \
                 WHERE network_id = ? AND authority_kind = ? AND authority_id = ?"
            ),
            (
                value,
                authority.network_id(),
                authority.kind().as_i8(),
                authority.authority_id() as i64,
            ),
        )
        .await?;
    Ok(())
}

async fn assert_stale_token_conflicts(
    session: &Session,
    control: &NamespaceControlAdapter,
    expected: &AuthorityStorageBinding,
    candidate: &VerifiedRecoveryNamespace,
    cas_samples: &mut Vec<u64>,
) -> anyhow::Result<()> {
    let authority = expected.authority();

    set_binding_i64(session, "binding_generation", expected.generation().get() as i64 + 9, authority).await?;
    let started = Instant::now();
    ensure!(matches!(
        control.cutover(session, expected, candidate, 30_001).await?,
        BindingCasOutcome::Conflict(_)
    ));
    cas_samples.push(started.elapsed().as_micros() as u64);
    set_binding_i64(session, "binding_generation", expected.generation().get() as i64, authority).await?;

    set_binding_i64(session, "checkpoint_id", expected.checkpoint().get() as i64 + 1, authority).await?;
    let started = Instant::now();
    ensure!(matches!(
        control.cutover(session, expected, candidate, 30_002).await?,
        BindingCasOutcome::Conflict(_)
    ));
    cas_samples.push(started.elapsed().as_micros() as u64);
    set_binding_i64(session, "checkpoint_id", expected.checkpoint().get() as i64, authority).await?;

    set_binding_blob(session, "checkpoint_hash", &[0xa5; 32], authority).await?;
    let started = Instant::now();
    ensure!(matches!(
        control.cutover(session, expected, candidate, 30_003).await?,
        BindingCasOutcome::Conflict(_)
    ));
    cas_samples.push(started.elapsed().as_micros() as u64);
    set_binding_blob(session, "checkpoint_hash", expected.checkpoint_hash().as_bytes(), authority).await?;

    set_binding_blob(session, "dataset_digest", &[0xd5; 32], authority).await?;
    let started = Instant::now();
    ensure!(matches!(
        control.cutover(session, expected, candidate, 30_004).await?,
        BindingCasOutcome::Conflict(_)
    ));
    cas_samples.push(started.elapsed().as_micros() as u64);
    set_binding_blob(session, "dataset_digest", expected.dataset_digest().as_bytes(), authority).await?;

    ensure!(control.get_binding(session, authority).await?.as_ref() == Some(expected));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the isolated tests/rf3 Docker Compose cluster"]
async fn rollback_namespace_rf3_gate() -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_G0_03_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-g0-03.sh"
    );
    let started_unix_ms = unix_ms()?;
    let report_path = std::env::var("PSY_G0_03_REPORT_PATH").context("PSY_G0_03_REPORT_PATH")?;
    let authority = authority()?;
    let session = connect().await?;
    let control_keyspace = CqlKeyspaceName::try_new(CONTROL_KEYSPACE)?;
    NamespaceControlAdapter::create_schema(&session, &control_keyspace).await?;
    let control = prepare_control(&session).await?;
    ensure!(control.lwt_contract().regular() == Consistency::Quorum);
    ensure!(control.prepared_lwt_contracts().iter().all(|entry| {
        entry.0 == Some(Consistency::Quorum) && entry.1 == Some(scylla::statement::SerialConsistency::LocalSerial)
    }));

    let mut timings = Vec::new();
    let mut namespaces = Vec::new();
    let mut cas_samples = Vec::new();
    let mut reconnect_samples = Vec::new();

    // Bootstrap an old, fully verified namespace and make it the unique active binding.
    let (old_dataset, old_descriptor) = recovery(&authority, 1, 200, 0)?;
    let (old_verified, create, load, verify) =
        create_and_load(&session, &control, old_descriptor.clone(), &old_dataset, 10_000).await?;
    timings.push(namespace_timing(&old_descriptor, &old_dataset, create, load, verify));
    namespaces.push(old_descriptor.namespace().clone());
    let old_binding = match control.initialize_binding(&session, &old_verified, generation(0), 10_002).await? {
        BindingInitializationOutcome::InitializedOrAlreadyPresent(binding) => binding,
        BindingInitializationOutcome::Conflict(binding) => bail!("unexpected initial binding conflict: {binding:?}"),
    };
    let old_bound = BoundAuthorityStore::bind_active(&session, &control, &authority, Consistency::Quorum).await?;
    ensure!(old_bound.read_serving_dataset(&session, &control).await? == old_dataset);

    // Partial load: no Merkle/counter rows means read-back cannot produce VERIFIED.
    let (partial_dataset, partial_descriptor) = recovery(&authority, 2, 190, 0)?;
    RepresentativeNamespaceStore::create_schema(&session, partial_descriptor.namespace()).await?;
    namespaces.push(partial_descriptor.namespace().clone());
    let partial_loading = control.begin_loading(&session, partial_descriptor.clone(), 11_000).await?;
    let partial_store = RepresentativeNamespaceStore::prepare(
        &session,
        partial_descriptor.namespace().clone(),
        Consistency::Quorum,
    )
    .await?;
    partial_store
        .load_checkpoint_leaves(
            &session,
            partial_dataset.checkpoint_leaves(),
            commit_timestamp(LOAD_TIMESTAMP_US),
        )
        .await?;
    ensure!(
        partial_store
            .verify_and_mark(&session, &control, &partial_loading, &partial_dataset, 11_001)
            .await
            .is_err()
    );
    ensure!(matches!(
        control
            .get_verified(&session, &authority, partial_descriptor.namespace().id())
            .await,
        Err(NamespacePrototypeError::NamespaceNotVerified(RecoveryNamespaceStatus::Failed))
    ));
    ensure!(control.get_binding(&session, &authority).await?.as_ref() == Some(&old_binding));

    // A physically missing representative table prevents adapter preparation,
    // so the catalog can only be marked FAILED, never VERIFIED.
    let (_missing_table_dataset, missing_table_descriptor) = recovery(&authority, 9, 175, 0)?;
    RepresentativeNamespaceStore::create_schema(&session, missing_table_descriptor.namespace()).await?;
    namespaces.push(missing_table_descriptor.namespace().clone());
    let missing_table_loading = control
        .begin_loading(&session, missing_table_descriptor.clone(), 11_500)
        .await?;
    session
        .query_unpaged(
            format!(
                "DROP TABLE {}.u64_counter_singleton_table",
                missing_table_descriptor.namespace().no_tablet().as_str()
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    ensure!(
        RepresentativeNamespaceStore::prepare(
            &session,
            missing_table_descriptor.namespace().clone(),
            Consistency::Quorum,
        )
        .await
        .is_err()
    );
    control.mark_failed(&session, &missing_table_loading).await?;
    ensure!(matches!(
        control
            .get_verified(&session, &authority, missing_table_descriptor.namespace().id())
            .await,
        Err(NamespacePrototypeError::NamespaceNotVerified(RecoveryNamespaceStatus::Failed))
    ));

    // Full load followed by one higher-timestamp value corruption also fails verification.
    let (corrupt_dataset, corrupt_descriptor) = recovery(&authority, 3, 180, 0)?;
    RepresentativeNamespaceStore::create_schema(&session, corrupt_descriptor.namespace()).await?;
    namespaces.push(corrupt_descriptor.namespace().clone());
    let corrupt_loading = control.begin_loading(&session, corrupt_descriptor.clone(), 12_000).await?;
    let corrupt_store = RepresentativeNamespaceStore::prepare(
        &session,
        corrupt_descriptor.namespace().clone(),
        Consistency::Quorum,
    )
    .await?;
    corrupt_store
        .load_dataset(
            &session,
            &corrupt_loading,
            &corrupt_dataset,
            commit_timestamp(LOAD_TIMESTAMP_US),
        )
        .await?;
    let first_leaf = corrupt_dataset.checkpoint_leaves()[0].checkpoint();
    let corrupt_leaf = CheckpointLeafSnapshotRow::try_new(first_leaf, vec![0xff; 32])?;
    corrupt_store
        .load_checkpoint_leaves(&session, &[corrupt_leaf], commit_timestamp(LOAD_TIMESTAMP_US + 1))
        .await?;
    ensure!(matches!(
        corrupt_store
            .verify_and_mark(&session, &control, &corrupt_loading, &corrupt_dataset, 12_001)
            .await,
        Err(NamespacePrototypeError::DatasetVerificationMismatch { .. })
    ));
    ensure!(control.get_binding(&session, &authority).await?.as_ref() == Some(&old_binding));

    // An out-of-band mutation of immutable catalog content is detected on read.
    let (_immutable_dataset, immutable_descriptor) = recovery(&authority, 4, 170, 0)?;
    control.begin_loading(&session, immutable_descriptor.clone(), 13_000).await?;
    session
        .query_unpaged(
            format!(
                "UPDATE {CONTROL_KEYSPACE}.{CATALOG_TABLE} SET target_checkpoint_id = ? \
                 WHERE network_id = ? AND authority_kind = ? AND authority_id = ? AND namespace_id = ?"
            ),
            (
                171_i64,
                authority.network_id(),
                authority.kind().as_i8(),
                authority.authority_id() as i64,
                immutable_descriptor.namespace().id().as_bytes().as_slice(),
            ),
        )
        .await?;
    ensure!(control
        .get_catalog(&session, &authority, immutable_descriptor.namespace().id())
        .await
        .is_err());

    // G11: load and verify a recovery namespace without changing active binding.
    let (new_dataset, new_descriptor) = recovery(&authority, 5, 100, 0)?;
    let (new_verified, create, load, verify) =
        create_and_load(&session, &control, new_descriptor.clone(), &new_dataset, 14_000).await?;
    timings.push(namespace_timing(&new_descriptor, &new_dataset, create, load, verify));
    namespaces.push(new_descriptor.namespace().clone());
    ensure!(control.get_binding(&session, &authority).await?.as_ref() == Some(&old_binding));
    ensure!(matches!(
        control.begin_loading(&session, new_descriptor.clone(), 14_002).await,
        Err(NamespacePrototypeError::CatalogAlreadyVerified)
    ));
    ensure!(matches!(
        control.initialize_binding(&session, &new_verified, generation(0), 14_003).await?,
        BindingInitializationOutcome::Conflict(ref binding) if binding == &old_binding
    ));

    // G12: discard every session/handle before CAS; durable binding still constructs only old.
    drop(control);
    drop(session);
    let reconnect_started = Instant::now();
    let session = connect().await?;
    let control = prepare_control(&session).await?;
    let pre_cas_bound = BoundAuthorityStore::bind_active(&session, &control, &authority, Consistency::Quorum).await?;
    reconnect_samples.push(reconnect_started.elapsed().as_micros() as u64);
    ensure!(pre_cas_bound.namespace() == old_descriptor.namespace());
    ensure!(pre_cas_bound.read_serving_dataset(&session, &control).await? == old_dataset);

    // Apply CAS and deliberately discard its response and all new in-memory handles.
    let cas_started = Instant::now();
    let _discarded_response = control.cutover(&session, &old_binding, &new_verified, 15_000).await?;
    cas_samples.push(cas_started.elapsed().as_micros() as u64);
    drop(pre_cas_bound);
    drop(control);
    drop(session);

    // G13 response-lost/post-CAS crash: durable binding reconstructs only the complete new handle.
    let reconnect_started = Instant::now();
    let session = connect().await?;
    let control = prepare_control(&session).await?;
    let post_cas = control.get_binding(&session, &authority).await?.context("post-CAS binding")?;
    let post_cas_bound = BoundAuthorityStore::bind_active(&session, &control, &authority, Consistency::Quorum).await?;
    reconnect_samples.push(reconnect_started.elapsed().as_micros() as u64);
    ensure!(post_cas.generation() == generation(1));
    ensure!(post_cas.namespace() == new_descriptor.namespace());
    ensure!(post_cas_bound.namespace() == new_descriptor.namespace());
    ensure!(post_cas_bound.read_serving_dataset(&session, &control).await? == new_dataset);

    // Retrying the same unknown-result request reconciles current state and never increments twice.
    let cas_started = Instant::now();
    let reconciled = control.cutover(&session, &old_binding, &new_verified, 15_001).await?;
    cas_samples.push(cas_started.elapsed().as_micros() as u64);
    ensure!(reconciled.was_applied_or_reconciled());
    ensure!(reconciled.current().generation() == generation(1));

    // The old physical namespace remains readable, while its canonical handle is stale.
    ensure!(matches!(
        old_bound.assert_serving_current(&session, &control).await,
        Err(NamespacePrototypeError::StaleBoundStore { .. })
    ));
    let physical_old = RepresentativeNamespaceStore::prepare(
        &session,
        old_descriptor.namespace().clone(),
        Consistency::Quorum,
    )
    .await?;
    ensure!(physical_old.read_dataset(&session).await? == old_dataset);

    // Two candidates race from exactly the same expected binding. One and only one wins.
    let (candidate_a_data, candidate_a_descriptor) = recovery(&authority, 6, 90, 1)?;
    let (candidate_a, create, load, verify) = create_and_load(
        &session,
        &control,
        candidate_a_descriptor.clone(),
        &candidate_a_data,
        16_000,
    )
    .await?;
    timings.push(namespace_timing(
        &candidate_a_descriptor,
        &candidate_a_data,
        create,
        load,
        verify,
    ));
    namespaces.push(candidate_a_descriptor.namespace().clone());
    let (candidate_b_data, candidate_b_descriptor) = recovery(&authority, 7, 80, 1)?;
    let (candidate_b, create, load, verify) = create_and_load(
        &session,
        &control,
        candidate_b_descriptor.clone(),
        &candidate_b_data,
        17_000,
    )
    .await?;
    timings.push(namespace_timing(
        &candidate_b_descriptor,
        &candidate_b_data,
        create,
        load,
        verify,
    ));
    namespaces.push(candidate_b_descriptor.namespace().clone());
    ensure!(control.get_binding(&session, &authority).await?.as_ref() == Some(&post_cas));
    let (race_a, race_b) = tokio::join!(
        async {
            let started = Instant::now();
            (
                control.cutover(&session, &post_cas, &candidate_a, 18_000).await,
                started.elapsed().as_micros() as u64,
            )
        },
        async {
            let started = Instant::now();
            (
                control.cutover(&session, &post_cas, &candidate_b, 18_001).await,
                started.elapsed().as_micros() as u64,
            )
        },
    );
    let (race_a_result, race_a_us) = race_a;
    let (race_b_result, race_b_us) = race_b;
    let race_a = race_a_result?;
    let race_b = race_b_result?;
    cas_samples.extend([race_a_us, race_b_us]);
    ensure!(
        usize::from(race_a.was_applied_or_reconciled()) + usize::from(race_b.was_applied_or_reconciled()) == 1,
        "concurrent CAS did not have exactly one winner: {race_a:?} {race_b:?}"
    );
    let race_binding = control.get_binding(&session, &authority).await?.context("race binding")?;
    ensure!(race_binding.generation() == generation(2));

    // A third verified target checks each exact token predicate independently.
    let (token_data, token_descriptor) = recovery(&authority, 8, 70, 2)?;
    let (token_candidate, create, load, verify) =
        create_and_load(&session, &control, token_descriptor.clone(), &token_data, 19_000).await?;
    timings.push(namespace_timing(&token_descriptor, &token_data, create, load, verify));
    namespaces.push(token_descriptor.namespace().clone());
    assert_stale_token_conflicts(&session, &control, &race_binding, &token_candidate, &mut cas_samples).await?;
    let cas_started = Instant::now();
    ensure!(control
        .cutover(&session, &race_binding, &token_candidate, 20_000)
        .await?
        .was_applied_or_reconciled());
    cas_samples.push(cas_started.elapsed().as_micros() as u64);
    let final_binding = control.get_binding(&session, &authority).await?.context("final binding")?;
    ensure!(final_binding.generation() == generation(3));
    ensure!(final_binding.namespace() == token_descriptor.namespace());
    let final_bound = BoundAuthorityStore::bind_active(&session, &control, &authority, Consistency::Quorum).await?;
    ensure!(final_bound.read_serving_dataset(&session, &control).await? == token_data);

    flush_keyspaces(&namespaces)?;
    let namespace_disk_bytes = namespaces.iter().map(namespace_disk_bytes).collect::<Result<Vec<_>, _>>()?;
    let release = docker_exec(NODE_CONTAINERS[0], &["scylla", "--version"], "read Scylla version")?
        .trim()
        .to_owned();
    let report = G003Report {
        baseline: BASELINE,
        image: IMAGE,
        scylla_release: release,
        replication_factor: 3,
        regular_consistency: "QUORUM",
        serial_consistency: "LOCAL_SERIAL",
        started_unix_ms,
        finished_unix_ms: unix_ms()?,
        representative_tables: vec!["checkpoint_leaf_table", "global_user_tree_table", "u64_counter_singleton_table"],
        namespace_timings: timings,
        binding_cas: LatencySummary::from_samples(cas_samples),
        reconnect_binding_reload: LatencySummary::from_samples(reconnect_samples),
        namespace_disk_bytes,
        old_namespace_still_physical: physical_old.read_dataset(&session).await? == old_dataset,
        final_binding_generation: final_binding.generation().get(),
        final_namespace_id: final_binding.namespace().id().to_hex(),
        scenarios_passed: vec![
            "G11_LOAD_VERIFY_WITHOUT_EARLY_BINDING",
            "G12_PRE_CAS_CRASH_OLD_ONLY",
            "G13_POST_CAS_RESPONSE_LOST_NEW_ONLY",
            "PARTIAL_LOAD_REJECTED",
            "VALUE_DIGEST_ROOT_COUNT_REJECTED",
            "IMMUTABLE_CATALOG_FAIL_CLOSED",
            "NON_VERIFIED_CANNOT_CUTOVER",
            "EXACT_TOKEN_STALE_CONFLICTS",
            "CONCURRENT_CAS_EXACTLY_ONE_WINNER",
            "MIXED_HANDLE_UNCONSTRUCTABLE",
            "STALE_HANDLE_REJECTED",
            "OLD_NAMESPACE_REMAINS_PHYSICAL",
        ],
        g14: "NOT_TRIGGERED: G0-02 retained viable in-place candidates; no snapshot-only product decision made.",
        cleanup_policy: "run-g0-03.sh removes containers, network, and named volumes unless PSY_G0_03_KEEP_CLUSTER=1",
        qualification: "Directional G0-03 artificial-data spike; not a production snapshot RTO/SLO or complete P0b Gate closure.",
    };
    let report_path = Path::new(&report_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
