//! h23c4c2b3b2: Realm claim-admission close fence on a real RF=3 cluster.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure, Context};
use parth_core::{protocol::core_types::Q256BitHash, PHash};
use psy_data::protocol::{
    canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    },
    chain_context::{
        AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
        AuthorityStateRoot, PendingContext, WorkProcCheckpointUniqueId,
        WorkUniquePendingId,
    },
};
use psy_node_core::{
    queue::{
        realm_user_update_admission::{
            RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
            RealmUserUpdateAdmissionPhase, RealmUserUpdateAdmissionShard,
            RealmUserUpdateGenerationQualification,
            RealmUserUpdateQualificationFence, StoredRealmUserUpdateAdmission,
        },
        realm_user_update_claim::{
            RealmUserUpdateAdmissionOrdinal, RealmUserUpdateClaimBucket,
            RealmUserUpdateCreatedAtSeconds, StoredRealmUserUpdateClaim,
        },
        realm_user_update_publish::{
            RealmUserUpdatePublishAdmission, RealmUserUpdateRequestDigest,
        },
        recoverable_ephemeral::PendingQueueCaptureContext,
    },
    store::{
        pending_generation_identity::{
            PendingGenerationActivationDigest,
            PendingGenerationBootstrapReason, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingPipelineBootstrap, StoredPendingPipeline,
        },
        pending_generation::ProcNamespacePrefix,
        typed::{UniquePendingId, UserId},
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
use tokio::{sync::Semaphore, task::JoinSet, time::sleep};

use crate::rollback::realm_generation_scope::REALM_AUTHORITY_KIND;
use super::*;

const DATA: &str = "psy_h23c4c2b3b2";
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
const CLAIMS: u64 = 1_000;

fn control() -> String { format!("{DATA}_no_tablet") }

fn realm() -> AuthorityScope {
    AuthorityScope::Realm {
        realm_id: 7,
        realm_sub_id: 2,
    }
}

fn admission(
    generation: u64,
) -> anyhow::Result<RealmUserUpdatePublishAdmission<PHash>> {
    let network = NetworkId::try_from_chain_id(1337)?;
    let authority = realm();
    let pending_id = 100 + generation;
    let proc_id = 0x1_0000_u128 + u128::from(generation);
    let pending = PendingContext::new(
        CanonicalChainRef::new(
            network,
            ChainEpoch::new(generation),
            CheckpointRef::new(
                CheckpointId::new(1_000 + generation),
                CheckpointHash::from_last_chain_hash(
                    PHash::from_owned_32bytes([generation as u8; 32]),
                ),
            ),
        ),
        authority,
        WorkUniquePendingId::new(pending_id),
        WorkProcCheckpointUniqueId::from_u128(proc_id),
    );
    let capture = PendingQueueCaptureContext::try_new(
        PendingGenerationLedgerKey::new(network, authority),
        PendingGenerationActivationDigest::try_new([
            (generation as u8).wrapping_add(1);
            32
        ])?,
        PendingGenerationContext::try_from_legacy(
            UniquePendingId::try_new(pending_id)?.get(),
            proc_id,
        )?,
    )?;
    Ok(RealmUserUpdatePublishAdmission::try_from_pipeline(
        pending, capture,
    )?)
}

fn qualification_pipeline(
    admission: &RealmUserUpdatePublishAdmission<PHash>,
) -> anyhow::Result<StoredPendingPipeline<PHash>> {
    let capture = admission.capture();
    let gathering = capture.processing();
    let processing_pending = gathering
        .pending_id()
        .get()
        .checked_sub(1)
        .context("qualification fixture gathering must have a predecessor")?;
    let processing_proc = gathering
        .proc_checkpoint_id()
        .as_u128()
        .checked_sub(1)
        .context("qualification fixture proc must have a predecessor")?;
    let chain = *admission.pending().chain();
    let observation = AuthorityObservation::try_new(
        chain,
        admission.pending().authority(),
        AuthorityStateCheckpointId::new(chain.checkpoint().checkpoint_id().get()),
        AuthorityStateRoot::from_local_state_root(PHash::from_owned_32bytes([
            0x4d;
            32
        ])),
    )?;
    Ok(PendingPipelineBootstrap::try_new(
        capture.key(),
        capture.activation(),
        ProcNamespacePrefix::for_authority(
            capture.key().network(),
            capture.key().authority(),
        ),
        PendingGenerationBootstrapReason::LegacyActivation,
        PendingGenerationContext::try_from_legacy(
            processing_pending,
            processing_proc,
        )?,
        gathering,
        observation,
        processing_pending,
    )?
    .candidate()
    .clone())
}

fn request(user: u64) -> anyhow::Result<RealmUserUpdateRequestDigest> {
    Ok(RealmUserUpdateRequestDigest::derive(
        &user.to_be_bytes(),
        &user.wrapping_mul(17).to_be_bytes(),
    )?)
}

fn user_in_bucket(bucket: u16, start: u64) -> u64 {
    (start..)
        .find(|user| {
            RealmUserUpdateClaimBucket::for_user(UserId::new(*user)).get()
                == bucket
        })
        .expect("a user must exist in every bucket")
}

fn close_intent(
    key: RealmUserUpdateAdmissionKey,
) -> anyhow::Result<RealmUserUpdateAdmissionCloseIntent> {
    Ok(RealmUserUpdateAdmissionCloseIntent::derive(key, [0x5a; 32])?)
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
        .known_nodes_addr(
            NODE_IPS.map(|ip| SocketAddr::new(IpAddr::V4(ip), 9042)),
        )
        .default_execution_profile_handle(profile.build().into_handle())
        .connection_timeout(Duration::from_secs(120))
        .schema_agreement_timeout(Duration::from_secs(120))
        .build()
        .await?)
}

fn compose(compose_file: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .args(args)
        .status()
        .context("docker compose")?;
    ensure!(status.success(), "docker compose failed with {status}");
    Ok(())
}

fn docker_exec(container: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("exec")
        .arg(container)
        .args(args)
        .status()
        .context("docker exec")?;
    ensure!(status.success(), "docker exec failed with {status}");
    Ok(())
}

fn docker_exec_retry(
    container: &str,
    args: &[&str],
    attempts: usize,
) -> anyhow::Result<()> {
    let mut last = None;
    for _ in 0..attempts {
        match docker_exec(container, args) {
            Ok(()) => return Ok(()),
            Err(error) => last = Some(error),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no repair attempt executed")))
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

async fn claim_with_retry(
    guard: &ScyllaRealmUserUpdateAdmissionGuard,
    admission: &RealmUserUpdatePublishAdmission<PHash>,
    user: u64,
) -> Result<StoredRealmUserUpdateClaim<PHash>, RealmUserUpdateAdmissionGuardError>
{
    let request = request(user)
        .map_err(|error| RealmUserUpdateAdmissionGuardError::Claim(error.to_string()))?;
    for _ in 0..2_000 {
        match guard
            .claim(
                admission.clone(),
                UserId::new(user),
                request,
                RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_000)
                    .map_err(|error| {
                        RealmUserUpdateAdmissionGuardError::Claim(error.to_string())
                    })?,
            )
            .await
        {
            Err(RealmUserUpdateAdmissionGuardError::AdmissionRace) => {
                tokio::task::yield_now().await;
            }
            result => return result,
        }
    }
    Err(RealmUserUpdateAdmissionGuardError::StepLimit)
}

async fn provisioned(
    session: Arc<Session>,
    generation: u64,
) -> anyhow::Result<(
    Arc<ScyllaRealmUserUpdateAdmissionStore>,
    Arc<ScyllaRealmUserUpdateClaimStore>,
    Arc<ScyllaRealmUserUpdateAdmissionGuard>,
    RealmUserUpdatePublishAdmission<PHash>,
    RealmUserUpdateAdmissionKey,
)> {
    let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(control())?;
    let gates = Arc::new(
        ScyllaRealmUserUpdateAdmissionStore::prepare(
            session.clone(),
            keyspace.clone(),
        )
        .await?,
    );
    let claims = Arc::new(
        ScyllaRealmUserUpdateClaimStore::prepare(session, keyspace).await?,
    );
    let guard = Arc::new(ScyllaRealmUserUpdateAdmissionGuard::new(
        gates.clone(),
        claims.clone(),
    ));
    let admission = admission(generation)?;
    let key = RealmUserUpdateAdmissionKey::try_new(admission.capture())?;
    guard.provision_generation::<PHash>(key).await?;
    Ok((gates, claims, guard, admission, key))
}

#[derive(Serialize)]
struct Report {
    image: &'static str,
    replication_factor: u8,
    schema_version: u16,
    target_tables: usize,
    total_claims: u64,
    claim_ms: u64,
    close_ms: u64,
    response_loss_retry: bool,
    crash_before_claim_recovered: bool,
    crash_after_claim_recovered: bool,
    duplicate_user_race_recovered: bool,
    missing_row_rejected: bool,
    extra_row_rejected: bool,
    closed_rejects_new: bool,
    one_replica_offline_write: bool,
    repair_flush_compact: bool,
    direct_one_nodes_equal: usize,
    qualification: &'static str,
}

#[derive(Debug, Eq, PartialEq)]
struct DirectSnapshot {
    gates: Vec<(i16, i64, Vec<u8>)>,
    claims: Vec<(i16, i64, i64, Vec<u8>)>,
}

async fn direct_snapshot(
    session: &Session,
    capture: PendingQueueCaptureContext,
) -> anyhow::Result<DirectSnapshot> {
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        bail!("RF=3 capture must be Realm-scoped")
    };
    let prefix = (
        i64::from(capture.key().network().chain_id()),
        REALM_AUTHORITY_KIND,
        i64::from(realm_id),
        i32::from(realm_sub_id),
        capture.activation().as_bytes().to_vec(),
        i64::try_from(capture.processing().pending_id().get())?,
        capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
    );
    let mut gates = Vec::with_capacity(257);
    for shard in 0_i16..=256 {
        let mut rows = session
            .query_unpaged(
                format!(
                    "SELECT admission_shard, revision, admission_payload FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND admission_shard = ?",
                    control(), REALM_USER_UPDATE_ADMISSION_TABLE
                ),
                (
                    prefix.0,
                    prefix.1,
                    prefix.2,
                    prefix.3,
                    prefix.4.clone(),
                    prefix.5,
                    prefix.6.clone(),
                    shard,
                ),
            )
            .await?
            .into_rows_result()?
            .rows::<(i16, i64, Vec<u8>)>()?
            .collect::<Result<Vec<_>, _>>()?;
        gates.append(&mut rows);
    }
    let mut claims = Vec::new();
    for bucket in 0_i16..256 {
        let rows = session
            .query_unpaged(
                format!(
                    "SELECT claim_bucket, user_id, revision, claim_payload FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ?",
                    control(), REALM_USER_UPDATE_CLAIM_TABLE
                ),
                (
                    prefix.0,
                    prefix.1,
                    prefix.2,
                    prefix.3,
                    prefix.4.clone(),
                    prefix.5,
                    prefix.6.clone(),
                    bucket,
                ),
            )
            .await?
            .into_rows_result()?
            .rows::<(i16, i64, i64, Vec<u8>)>()?
            .collect::<Result<Vec<_>, _>>()?;
        claims.extend(rows);
    }
    claims.sort_by_key(|row| (row.0, row.1));
    Ok(DirectSnapshot { gates, claims })
}

async fn delete_claim_fixture(
    session: &Session,
    claim: &StoredRealmUserUpdateClaim<PHash>,
) -> anyhow::Result<()> {
    let partition = claim.partition()?;
    let capture = partition.capture();
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        bail!("RF=3 claim must be Realm-scoped")
    };
    session
        .query_unpaged(
            format!(
                "DELETE FROM {}.{} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND activation_digest = ? AND unique_pending_id = ? AND proc_checkpoint_id = ? AND claim_bucket = ? AND user_id = ?",
                control(), REALM_USER_UPDATE_CLAIM_TABLE
            ),
            (
                i64::from(capture.key().network().chain_id()),
                REALM_AUTHORITY_KIND,
                i64::from(realm_id),
                i32::from(realm_sub_id),
                capture.activation().as_bytes().to_vec(),
                i64::try_from(capture.processing().pending_id().get())?,
                capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
                partition.bucket().as_i16()?,
                i64::try_from(claim.user_id().get())?,
            ),
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c2b3b2_claim_admission_close_rf3_gate(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B3B2_RF3").as_deref() == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c2b3b2.sh"
    );
    let compose_file =
        std::env::var("PSY_D04B6H23C4C2B3B2_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {DATA} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}", control()),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    let keyspaces = PendingQueueSidecarKeyspaces::try_new(DATA, control())?;
    PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        keyspaces,
    )
    .await?;

    let (_, _, guard, live, live_key) =
        provisioned(session.clone(), 1).await?;

    // A caller may lose the response after the durable LWT. Exact retry must
    // return the first winner rather than allocate a second ordinal.
    let lost = claim_with_retry(&guard, &live, 1).await?;
    let retried = claim_with_retry(&guard, &live, 1).await?;
    let response_loss_retry = lost == retried;
    ensure!(response_loss_retry);

    // Real concurrent LWT pressure across all 256 buckets, with roughly four
    // claims per bucket and deterministic retry of transient Claiming races.
    let claim_started = Instant::now();
    let mut work = JoinSet::new();
    let concurrency = Arc::new(Semaphore::new(64));
    for user in 2..=CLAIMS {
        let guard = guard.clone();
        let admission = live.clone();
        let concurrency = concurrency.clone();
        work.spawn(async move {
            let _permit = concurrency.acquire_owned().await.unwrap();
            claim_with_retry(&guard, &admission, user).await
        });
    }
    let mut admitted = 1_u64;
    while let Some(result) = work.join_next().await {
        result??;
        admitted += 1;
    }
    ensure!(admitted == CLAIMS);
    let claim_ms = claim_started.elapsed().as_millis() as u64;

    // Crash window 1: BucketClaiming is durable, claim row is absent.
    let (gates2, _, guard2, second, second_key) =
        provisioned(session.clone(), 2).await?;
    let before = StoredRealmUserUpdateClaim::claimed(
        second.clone(),
        UserId::new(20_001),
        request(20_001)?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_001)?,
        RealmUserUpdateAdmissionOrdinal::FIRST,
    )?;
    let claiming = StoredRealmUserUpdateAdmission::bucket_claiming(before)?;
    ensure!(gates2.bootstrap(&claiming).await?.applied());
    let recovered = claim_with_retry(&guard2, &second, 20_001).await?;
    let crash_before_claim_recovered = recovered.user_id() == UserId::new(20_001);
    ensure!(crash_before_claim_recovered);

    // Crash window 2: claim IFNE is durable, BucketClaiming was not reopened.
    let (gates3, claims3, guard3, third, third_key) =
        provisioned(session.clone(), 3).await?;
    let after = StoredRealmUserUpdateClaim::claimed(
        third.clone(),
        UserId::new(30_001),
        request(30_001)?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_002)?,
        RealmUserUpdateAdmissionOrdinal::FIRST,
    )?;
    let claiming = StoredRealmUserUpdateAdmission::bucket_claiming(after)?;
    let outcome = gates3.bootstrap(&claiming).await?;
    let receipt =
        ScyllaRealmUserUpdateAdmissionStore::claiming_receipt(outcome)?;
    ensure!(matches!(
        claims3.claim(&receipt).await?,
        RealmUserUpdateClaimWriteOutcome::Applied(_)
            | RealmUserUpdateClaimWriteOutcome::Resumed(_)
    ));
    let recovered = claim_with_retry(&guard3, &third, 30_001).await?;
    let crash_after_claim_recovered = recovered.user_id() == UserId::new(30_001);
    ensure!(crash_after_claim_recovered);

    // A legal stale-empty first-winner race must release the losing ordinal,
    // not permanently block the bucket.
    let (gates5, _, guard5, fifth, fifth_key) =
        provisioned(session.clone(), 5).await?;
    let duplicate_user = 50_001;
    let winner = claim_with_retry(&guard5, &fifth, duplicate_user).await?;
    let duplicate_bucket = winner.bucket();
    let open = match gates5
        .read::<PHash>(
            fifth_key,
            RealmUserUpdateAdmissionShard::Bucket(duplicate_bucket),
        )
        .await?
    {
        RealmUserUpdateAdmissionReadState::Current(current) => current,
        RealmUserUpdateAdmissionReadState::Uninitialized => {
            bail!("winner bucket must be open")
        }
    };
    let loser = StoredRealmUserUpdateClaim::claimed(
        fifth.clone(),
        UserId::new(duplicate_user),
        RealmUserUpdateRequestDigest::derive(b"different", b"loser")?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_003)?,
        RealmUserUpdateAdmissionOrdinal::try_new(2)?,
    )?;
    let claiming = StoredRealmUserUpdateAdmission::begin_claim(&open, loser)?;
    let receipt = ScyllaRealmUserUpdateAdmissionStore::claiming_receipt(
        gates5.compare_and_set(&open, &claiming).await?,
    )?;
    ensure!(matches!(
        guard5.recover_claiming_fixture(receipt).await,
        Err(RealmUserUpdateAdmissionGuardError::ClaimConflict)
    ));
    let duplicate_user_race_recovered = matches!(
        gates5
            .read::<PHash>(
                fifth_key,
                RealmUserUpdateAdmissionShard::Bucket(duplicate_bucket),
            )
            .await?,
        RealmUserUpdateAdmissionReadState::Current(ref current)
            if current.phase() == RealmUserUpdateAdmissionPhase::BucketOpen
                && current.accepted_set().unwrap().count() == 1
    );
    ensure!(duplicate_user_race_recovered);
    guard5
        .close_generation::<PHash>(fifth_key, close_intent(fifth_key)?)
        .await?;

    // A missing accepted row and an untracked residual row must both prevent
    // generation membership from becoming closed/verified.
    let (gates6, _, guard6, sixth, sixth_key) =
        provisioned(session.clone(), 6).await?;
    let missing_user = user_in_bucket(0, 60_000);
    let missing = claim_with_retry(&guard6, &sixth, missing_user).await?;
    delete_claim_fixture(&session, &missing).await?;
    let missing_result = guard6
        .close_generation::<PHash>(sixth_key, close_intent(sixth_key)?)
        .await;
    println!("missing-row close result: {missing_result:?}");
    let missing_row_rejected = missing_result.is_err()
        && !matches!(
            gates6
                .read::<PHash>(
                    sixth_key,
                    RealmUserUpdateAdmissionShard::Generation,
                )
                .await?,
            RealmUserUpdateAdmissionReadState::Current(ref current)
                if current.phase()
                    == RealmUserUpdateAdmissionPhase::GenerationClosed
        );
    ensure!(missing_row_rejected);

    let (gates7, claims7, guard7, seventh, seventh_key) =
        provisioned(session.clone(), 7).await?;
    let extra_user = user_in_bucket(0, 70_000);
    let extra = StoredRealmUserUpdateClaim::claimed(
        seventh,
        UserId::new(extra_user),
        request(extra_user)?,
        RealmUserUpdateCreatedAtSeconds::try_new(1_700_000_004)?,
        RealmUserUpdateAdmissionOrdinal::FIRST,
    )?;
    ensure!(matches!(
        claims7.claim_retired_v5_fixture(&extra).await?,
        RealmUserUpdateClaimWriteOutcome::Applied(_)
    ));
    let extra_result = guard7
        .close_generation::<PHash>(seventh_key, close_intent(seventh_key)?)
        .await;
    println!("extra-row close result: {extra_result:?}");
    let extra_row_rejected = extra_result.is_err()
        && !matches!(
            gates7
                .read::<PHash>(
                    seventh_key,
                    RealmUserUpdateAdmissionShard::Generation,
                )
                .await?,
            RealmUserUpdateAdmissionReadState::Current(ref current)
                if current.phase()
                    == RealmUserUpdateAdmissionPhase::GenerationClosed
        );
    ensure!(extra_row_rejected);

    compose(
        Path::new(&compose_file),
        &["stop", "scylla3"],
    )?;
    wait_up(2).await?;
    let (_, _, offline_guard, offline, offline_key) =
        provisioned(session.clone(), 4).await?;
    let one_replica_offline_write =
        claim_with_retry(&offline_guard, &offline, 40_001).await?.user_id()
            == UserId::new(40_001);
    ensure!(one_replica_offline_write);
    offline_guard
        .close_generation::<PHash>(offline_key, close_intent(offline_key)?)
        .await?;

    let close_started = Instant::now();
    let closed = guard
        .close_generation::<PHash>(live_key, close_intent(live_key)?)
        .await?;
    let close_ms = close_started.elapsed().as_millis() as u64;
    ensure!(closed.phase() == RealmUserUpdateAdmissionPhase::GenerationClosed);
    ensure!(closed.generation_manifest().unwrap().total().count() == CLAIMS);
    // Closed response loss is also idempotent.
    ensure!(
        guard
            .close_generation::<PHash>(live_key, close_intent(live_key)?)
            .await?
            == closed
    );
    let closed_rejects_new = matches!(
        claim_with_retry(&guard, &live, CLAIMS + 1).await,
        Err(RealmUserUpdateAdmissionGuardError::AdmissionClosed)
    );
    ensure!(closed_rejects_new);

    // Also close both explicit crash-window generations so every durable
    // Claiming journal is proven recoverable before repair.
    guard2
        .close_generation::<PHash>(second_key, close_intent(second_key)?)
        .await?;
    guard3
        .close_generation::<PHash>(third_key, close_intent(third_key)?)
        .await?;

    compose(
        Path::new(&compose_file),
        &["start", "scylla3"],
    )?;
    wait_up(3).await?;
    for node in NODE_CONTAINERS {
        docker_exec_retry(
            node,
            &["nodetool", "repair", "-pr", &control()],
            24,
        )?;
        docker_exec(node, &["nodetool", "flush", &control()])?;
        docker_exec(node, &["nodetool", "compact", &control()])?;
    }

    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        direct.push(direct_snapshot(&local, live.capture()).await?);
    }
    let direct_one_nodes_equal = direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(direct.len())
        .unwrap_or(0);
    ensure!(direct_one_nodes_equal == 3);
    ensure!(direct[0].gates.len() == 257);
    ensure!(direct[0].claims.len() == CLAIMS as usize);

    let report = Report {
        image: IMAGE,
        replication_factor: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: 15,
        total_claims: CLAIMS,
        claim_ms,
        close_ms,
        response_loss_retry,
        crash_before_claim_recovered,
        crash_after_claim_recovered,
        duplicate_user_race_recovered,
        missing_row_rejected,
        extra_row_rejected,
        closed_rejects_new,
        one_replica_offline_write,
        repair_flush_compact: true,
        direct_one_nodes_equal,
        qualification: "H23C4C2B3B2_ADMISSION_MEMBERSHIP_RF3_PASSED",
    };
    let report_path =
        std::env::var("PSY_D04B6H23C4C2B3B2_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[derive(Serialize)]
struct QualificationStoreReport {
    image: &'static str,
    replication_factor: u8,
    schema_version: u16,
    target_tables: usize,
    terminal_claims: usize,
    concurrent_qualifiers: usize,
    response_loss_retry: bool,
    stale_frontier_rejected: bool,
    one_replica_offline_qualified: bool,
    repair_flush_compact: bool,
    direct_one_nodes_equal: usize,
    qualification: &'static str,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires isolated Scylla RF=3 docker-compose cluster"]
async fn d04b6h23c4c2b3b2c2a_qualification_store_rf3_gate(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_D04B6H23C4C2B3B2C2A_RF3").as_deref()
            == Ok("1"),
        "run through tests/rf3/run-d04b6h23c4c2b3b2c2a.sh"
    );
    let compose_file =
        std::env::var("PSY_D04B6H23C4C2B3B2C2A_COMPOSE_FILE")?;
    wait_up(3).await?;
    let session = Arc::new(connect(None, Consistency::Quorum).await?);
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {DATA} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}}"),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!("CREATE KEYSPACE IF NOT EXISTS {} WITH replication = {{'class': 'NetworkTopologyStrategy', 'datacenter1': 3}} AND tablets = {{'enabled': false}}", control()),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    PendingQueueSidecarDeploymentExecutor::deploy(
        session.clone(),
        PendingQueueSidecarKeyspaces::try_new(DATA, control())?,
    )
    .await?;

    let (_, _, guard, publish_admission, key) = provisioned(session.clone(), 8).await?;
    let close = close_intent(key)?;
    let closed = guard.close_generation::<PHash>(key, close).await?;
    ensure!(closed.phase() == RealmUserUpdateAdmissionPhase::GenerationClosed);
    ensure!(closed.generation_manifest().unwrap().total().count() == 0);

    let first = guard.qualification_input::<PHash>(key, close).await?;
    let second = guard.qualification_input::<PHash>(key, close).await?;
    let RealmUserUpdateQualificationInput::Closed(first) = first else {
        bail!("first qualification input was not Closed")
    };
    let RealmUserUpdateQualificationInput::Closed(second) = second else {
        bail!("second qualification input was not Closed")
    };
    let pipeline = qualification_pipeline(&publish_admission)?;
    let fence = RealmUserUpdateQualificationFence::try_from_pipeline(key, &pipeline)?;
    let membership = first
        .header()
        .generation_manifest()
        .context("closed generation missing manifest")?;
    ensure!(second.header().generation_manifest() == Some(membership));
    let qualification = RealmUserUpdateGenerationQualification::from_terminal_evidence(
        key,
        close,
        membership,
        fence,
        &[],
    )?;

    compose(Path::new(&compose_file), &["stop", "scylla3"])?;
    wait_up(2).await?;
    let (first_result, second_result) = tokio::join!(
        guard.persist_qualification(first, qualification),
        guard.persist_qualification(second, qualification),
    );
    let first_receipt = first_result?;
    let second_receipt = second_result?;
    first_receipt.revalidate_pipeline(&pipeline)?;
    second_receipt.revalidate_pipeline(&pipeline)?;
    ensure!(first_receipt.current() == second_receipt.current());
    ensure!(
        first_receipt.current().phase()
            == RealmUserUpdateAdmissionPhase::GenerationQualified
    );
    let one_replica_offline_qualified = true;

    let response_loss_retry = match guard
        .qualification_input::<PHash>(key, close)
        .await?
    {
        RealmUserUpdateQualificationInput::Qualified(receipt) => {
            receipt.revalidate_pipeline(&pipeline)?;
            receipt.current() == first_receipt.current()
        }
        RealmUserUpdateQualificationInput::Closed(_) => false,
    };
    ensure!(response_loss_retry);

    let foreign = admission(9)?;
    let foreign_pending = PendingContext::new(
        *foreign.pending().chain(),
        publish_admission.pending().authority(),
        publish_admission.pending().unique_pending_id(),
        publish_admission.pending().proc_checkpoint_unique_id(),
    );
    let foreign_frontier = RealmUserUpdatePublishAdmission::try_from_pipeline(
        foreign_pending,
        publish_admission.capture(),
    )?;
    let stale_pipeline = qualification_pipeline(&foreign_frontier)?;
    let stale_frontier_rejected = first_receipt
        .revalidate_pipeline(&stale_pipeline)
        .is_err();
    ensure!(stale_frontier_rejected);

    compose(Path::new(&compose_file), &["start", "scylla3"])?;
    wait_up(3).await?;
    for node in NODE_CONTAINERS {
        docker_exec_retry(node, &["nodetool", "repair", "-pr", &control()], 24)?;
        docker_exec(node, &["nodetool", "flush", &control()])?;
        docker_exec(node, &["nodetool", "compact", &control()])?;
    }
    let mut direct = Vec::new();
    for ip in NODE_IPS {
        let local = connect(Some(ip), Consistency::One).await?;
        direct.push(direct_snapshot(&local, publish_admission.capture()).await?);
    }
    let direct_one_nodes_equal = direct
        .windows(2)
        .all(|pair| pair[0] == pair[1])
        .then_some(direct.len())
        .unwrap_or(0);
    ensure!(direct_one_nodes_equal == 3);
    ensure!(direct[0].gates.len() == 257);
    ensure!(direct[0].claims.is_empty());

    let report = QualificationStoreReport {
        image: IMAGE,
        replication_factor: 3,
        schema_version: PENDING_QUEUE_SIDECAR_SCHEMA_VERSION,
        target_tables: PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT,
        terminal_claims: 0,
        concurrent_qualifiers: 2,
        response_loss_retry,
        stale_frontier_rejected,
        one_replica_offline_qualified,
        repair_flush_compact: true,
        direct_one_nodes_equal,
        qualification: "H23C4C2B3B2C2A_QUALIFICATION_STORE_RF3_PASSED",
    };
    let report_path =
        std::env::var("PSY_D04B6H23C4C2B3B2C2A_REPORT_PATH")?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
