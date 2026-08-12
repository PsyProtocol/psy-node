//! Crash-resumable operator composition for the post-genesis branch-exact
//! schema migration.
//!
//! The lower-level adapters deliberately expose separate typed operations.
//! This module fixes their production ordering without exposing a raw Session,
//! caller-authored lifecycle state, or an unverified cutover capability.  It
//! stops at `BackfillVerified`; writer activation and route cutover remain
//! separate, evidence-gated operations.

use std::sync::Arc;

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;
use psy_node_core::store::authority_commit::{
    AuthorityClockSampleUs, AuthorityCommitIntentDigest,
    AuthorityIntentObservation, AuthorityTimestampKey,
    AuthorityTimestampReadState, AuthorityTimestampWriteOutcome,
    SealedAuthorityTimestampCompletion, SealedAuthorityTimestampReservation,
    StoredAuthorityTimestampState,
};
use psy_node_core::store::timestamp::CommitWriteTimestampUs;
use scylla::client::session::Session;
use sha2::{Digest, Sha256};

use super::{
    inspect_branch_exact_local_node_postflight, BranchExactBackfillArtifact,
    BranchExactBackfillPlan, BranchExactBackfillVerifiedReceipt,
    BranchExactDeploymentIntent, BranchExactDeploymentLifecycleBootstrap,
    BranchExactDeploymentLifecycleReadState, BranchExactDeploymentLifecycleState,
    BranchExactDeploymentLifecycleWriteOutcome,
    BranchExactDeploymentNoTabletKeyspace, BranchExactExpectedTopology,
    BranchExactSchemaMaterializationRequest, BranchExactSchemaMaterializer,
    BranchExactTopologyAttestation, BranchExactVerifiedDeploymentReceipt,
    ScyllaAuthorityTimestampStore, ScyllaBranchExactBackfillExecutor,
    ScyllaBranchExactDeploymentLifecycleStore, SealedBranchExactBackfillChunkCas,
    SealedBranchExactBackfillPlanCas, SealedBranchExactBackfillVerifiedCas,
    SealedBranchExactSchemaVerifiedCas, StoredBranchExactDeploymentLifecycle,
};

const MIGRATION_TIMESTAMP_INTENT_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-schema-migration-timestamp/v1";

/// All inputs whose identity must remain stable across an operator retry.
///
/// Targeted sessions must each be pinned to one operator-declared Scylla
/// node. The topology attestation rejects missing, duplicate, foreign or
/// schema-divergent nodes before the lifecycle can reach `SchemaVerified`.
pub(crate) struct BranchExactPostGenesisMigration<'a, Hash> {
    pub(crate) request: &'a BranchExactSchemaMaterializationRequest,
    pub(crate) artifact: &'a BranchExactBackfillArtifact<Hash>,
    pub(crate) expected_topology: BranchExactExpectedTopology,
    pub(crate) total_chunks: u32,
}

/// Resume one exact post-genesis migration until its full readback is
/// durably `BackfillVerified`.
///
/// The control lifecycle schema and the three target tables are the only DDL
/// this function may issue. Callers must already have created both keyspaces
/// with the intended production replication policy.
pub(crate) async fn resume_post_genesis_branch_exact_migration<Hash>(
    session: Arc<Session>,
    targeted_sessions: &[Arc<Session>],
    control_keyspace: BranchExactDeploymentNoTabletKeyspace,
    timestamps: &ScyllaAuthorityTimestampStore,
    clock_sample: AuthorityClockSampleUs,
    migration: BranchExactPostGenesisMigration<'_, Hash>,
) -> anyhow::Result<BranchExactBackfillVerifiedReceipt>
where
    Hash: Q256BitHash,
{
    if migration.artifact.authority() != migration.request.plan().authority() {
        anyhow::bail!("branch-exact migration artifact authority mismatch");
    }
    if targeted_sessions.len() != migration.expected_topology.nodes().len() {
        anyhow::bail!(
            "branch-exact migration expected {} targeted Scylla sessions, received {}",
            migration.expected_topology.nodes().len(),
            targeted_sessions.len(),
        );
    }

    // The lifecycle intent is the point of no reinterpretation. Persist it
    // before target DDL so a crash cannot leave unowned new tables whose
    // profile/topology is selected differently on retry.
    ScyllaBranchExactDeploymentLifecycleStore::create_schema(
        &session,
        &control_keyspace,
    )
    .await?;
    let lifecycle = ScyllaBranchExactDeploymentLifecycleStore::prepare(
        Arc::clone(&session),
        control_keyspace,
    )
    .await?;
    let intent = BranchExactDeploymentIntent::new(
        migration.request,
        migration.expected_topology.clone(),
    );
    let bootstrap = BranchExactDeploymentLifecycleBootstrap::new(intent.clone());
    let mut current = current_after_write(lifecycle.bootstrap(&bootstrap).await?);
    require_intent(&current, &intent)?;

    let schema = BranchExactSchemaMaterializer::materialize_schema(
        &session,
        migration.request,
    )
    .await?;
    let mut observations = Vec::with_capacity(targeted_sessions.len());
    for targeted in targeted_sessions {
        observations.push(
            inspect_branch_exact_local_node_postflight(
                targeted,
                migration.request.keyspace(),
                migration.request.plan().authority(),
            )
            .await?,
        );
    }
    let attestation = BranchExactTopologyAttestation::try_new(
        &schema,
        migration.expected_topology.clone(),
        observations,
    )?;
    let deployment = BranchExactVerifiedDeploymentReceipt::try_new(
        intent,
        attestation,
    )?;
    validate_migration_inputs_before_timestamp_reservation(
        &migration,
        &deployment,
        clock_sample,
    )?;
    let timestamp_key = migration_timestamp_key::<Hash>(
        migration.request,
    )?;
    let timestamp_intent = migration_timestamp_intent(&deployment);
    let persisted_plan = lifecycle_plan(current.state());
    let write_timestamp = match persisted_plan {
        Some(plan) => plan.write_timestamp().ok_or_else(|| {
            anyhow::anyhow!(
                "post-genesis branch-exact lifecycle plan has no write timestamp"
            )
        })?,
        None => {
            reserve_migration_timestamp(
                timestamps,
                timestamp_key,
                timestamp_intent,
                clock_sample,
            )
            .await?
        }
    };
    let plan = BranchExactBackfillPlan::post_genesis_artifact(
        migration.request,
        deployment.clone(),
        migration.artifact.dataset_digest(),
        write_timestamp,
        migration.total_chunks,
        migration.artifact.pair_rows_per_direction(),
        migration.artifact.proof_rows(),
    )?;
    // Validate the complete artifact/plan relationship before persisting the
    // plan. Otherwise a future plan-field addition could durably select work
    // that every executor retry must reject.
    migration.artifact.validate_plan(&plan)?;
    if let Some(persisted_plan) = persisted_plan {
        require_plan(persisted_plan, &plan)?;
        if !matches!(
            current.state(),
            BranchExactDeploymentLifecycleState::BackfillVerified(_)
        ) {
            require_replay_timestamp_safe(
                timestamps,
                timestamp_key,
                timestamp_intent,
                write_timestamp,
            )
            .await?;
        }
    }
    let executor = ScyllaBranchExactBackfillExecutor::prepare(
        Arc::clone(&session),
        &plan,
    )
    .await?;

    loop {
        require_intent(&current, deployment.intent())?;
        current = match current.state() {
            BranchExactDeploymentLifecycleState::Intent(_) => {
                let sealed = SealedBranchExactSchemaVerifiedCas::try_new(
                    &current,
                    deployment.clone(),
                )?;
                current_after_write(lifecycle.mark_schema_verified(&sealed).await?)
            }
            BranchExactDeploymentLifecycleState::SchemaVerified(observed) => {
                if observed != &deployment {
                    anyhow::bail!("branch-exact verified deployment conflict");
                }
                let sealed = SealedBranchExactBackfillPlanCas::try_new(
                    &current,
                    plan.clone(),
                )?;
                current_after_write(lifecycle.plan_backfill(&sealed).await?)
            }
            BranchExactDeploymentLifecycleState::BackfillPlanned(observed) => {
                require_plan(observed, &plan)?;
                let receipt = executor
                    .execute_chunk(&plan, migration.artifact, 0)
                    .await?;
                let sealed = SealedBranchExactBackfillChunkCas::try_new(
                    &current,
                    receipt,
                )?;
                current_after_write(lifecycle.record_backfill_chunk(&sealed).await?)
            }
            BranchExactDeploymentLifecycleState::BackfillProgress(progress) => {
                require_plan(progress.plan(), &plan)?;
                if progress.is_complete() {
                    let observation = executor
                        .verify_artifact_readback(&plan, migration.artifact)
                        .await?;
                    let sealed = SealedBranchExactBackfillVerifiedCas::try_new(
                        &current,
                        observation,
                    )?;
                    current_after_write(
                        lifecycle.mark_backfill_verified(&sealed).await?,
                    )
                } else {
                    let receipt = executor
                        .execute_chunk(
                            &plan,
                            migration.artifact,
                            progress.next_chunk_index(),
                        )
                        .await?;
                    let sealed = SealedBranchExactBackfillChunkCas::try_new(
                        &current,
                        receipt,
                    )?;
                    current_after_write(
                        lifecycle.record_backfill_chunk(&sealed).await?,
                    )
                }
            }
            BranchExactDeploymentLifecycleState::BackfillVerified(receipt) => {
                require_plan(receipt.plan(), &plan)?;
                // A final exact point read prevents a stale in-memory LWT
                // outcome from becoming the operator's activation evidence.
                let BranchExactDeploymentLifecycleReadState::Current(readback) =
                    lifecycle.read(current.slot()).await?
                else {
                    anyhow::bail!("branch-exact lifecycle disappeared after verification");
                };
                if readback != current {
                    current = readback;
                    continue;
                }
                let BranchExactDeploymentLifecycleState::BackfillVerified(
                    readback_receipt,
                ) = readback.state()
                else {
                    anyhow::bail!("branch-exact lifecycle regressed after verification");
                };
                let receipt = readback_receipt.clone();
                complete_migration_timestamp_if_active(
                    timestamps,
                    timestamp_key,
                    timestamp_intent,
                    write_timestamp,
                )
                .await?;
                return Ok(receipt);
            }
        };
    }
}

fn migration_timestamp_key<Hash: Q256BitHash>(
    request: &BranchExactSchemaMaterializationRequest,
) -> anyhow::Result<AuthorityTimestampKey> {
    let anchor = CanonicalChainRef::<Hash>::from_canonical_bytes(
        request.plan().anchor_payload(),
    )?;
    Ok(AuthorityTimestampKey::new(
        anchor.network_id(),
        request.plan().authority(),
    ))
}

fn validate_migration_inputs_before_timestamp_reservation<Hash: Q256BitHash>(
    migration: &BranchExactPostGenesisMigration<'_, Hash>,
    deployment: &BranchExactVerifiedDeploymentReceipt,
    clock_sample: AuthorityClockSampleUs,
) -> anyhow::Result<()> {
    // A clock sample is already range-checked but is not an allocated write
    // timestamp. Use it only to exercise every plan/artifact invariant before
    // reserving durable allocator state. The executable plan below is rebuilt
    // with the allocator-owned timestamp.
    let validation_timestamp =
        CommitWriteTimestampUs::try_from_i128(clock_sample.as_i64() as i128)?;
    let validation_plan = BranchExactBackfillPlan::post_genesis_artifact(
        migration.request,
        deployment.clone(),
        migration.artifact.dataset_digest(),
        validation_timestamp,
        migration.total_chunks,
        migration.artifact.pair_rows_per_direction(),
        migration.artifact.proof_rows(),
    )?;
    migration.artifact.validate_plan(&validation_plan)?;
    Ok(())
}

fn migration_timestamp_intent(
    deployment: &BranchExactVerifiedDeploymentReceipt,
) -> AuthorityCommitIntentDigest {
    let mut hasher = Sha256::new();
    hasher.update(MIGRATION_TIMESTAMP_INTENT_DOMAIN);
    hasher.update(deployment.intent().digest().as_bytes());
    AuthorityCommitIntentDigest::from_sealed_commit_digest(
        hasher.finalize().into(),
    )
}

fn lifecycle_plan(
    state: &BranchExactDeploymentLifecycleState,
) -> Option<&BranchExactBackfillPlan> {
    match state {
        BranchExactDeploymentLifecycleState::Intent(_)
        | BranchExactDeploymentLifecycleState::SchemaVerified(_) => None,
        BranchExactDeploymentLifecycleState::BackfillPlanned(plan) => {
            Some(plan)
        }
        BranchExactDeploymentLifecycleState::BackfillProgress(progress) => {
            Some(progress.plan())
        }
        BranchExactDeploymentLifecycleState::BackfillVerified(receipt) => {
            Some(receipt.plan())
        }
    }
}

async fn reserve_migration_timestamp(
    timestamps: &ScyllaAuthorityTimestampStore,
    key: AuthorityTimestampKey,
    intent: AuthorityCommitIntentDigest,
    clock_sample: AuthorityClockSampleUs,
) -> anyhow::Result<psy_node_core::store::timestamp::CommitWriteTimestampUs> {
    loop {
        let AuthorityTimestampReadState::Current(current) =
            timestamps.read(key).await?
        else {
            anyhow::bail!(
                "branch-exact authority timestamp allocator is uninitialized"
            );
        };
        match plan_migration_timestamp_reservation(
            current,
            key,
            intent,
            clock_sample,
        )? {
            MigrationTimestampReservation::Ready(timestamp) => {
                return Ok(timestamp)
            }
            MigrationTimestampReservation::Reserve(sealed) => {
                match timestamps.reserve(sealed).await? {
                    AuthorityTimestampWriteOutcome::Applied(_)
                    | AuthorityTimestampWriteOutcome::Idempotent(_)
                    | AuthorityTimestampWriteOutcome::Conflict(_) => {}
                }
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum MigrationTimestampReservation {
    Ready(CommitWriteTimestampUs),
    Reserve(SealedAuthorityTimestampReservation),
}

fn plan_migration_timestamp_reservation(
    current: StoredAuthorityTimestampState,
    key: AuthorityTimestampKey,
    intent: AuthorityCommitIntentDigest,
    clock_sample: AuthorityClockSampleUs,
) -> anyhow::Result<MigrationTimestampReservation> {
    match current.observe_intent(key, intent) {
        AuthorityIntentObservation::Active(lease) => Ok(
            MigrationTimestampReservation::Ready(lease.timestamp()),
        ),
        AuthorityIntentObservation::Completed { timestamp, .. } => {
            anyhow::bail!(
                "branch-exact migration timestamp is completed before a durable backfill plan exists: {}",
                timestamp.as_i64(),
            )
        }
        AuthorityIntentObservation::BlockedByActive {
            active_intent,
            ..
        } => {
            anyhow::bail!(
                "branch-exact migration timestamp allocator is owned by another intent: {}",
                hex::encode(active_intent.as_bytes()),
            )
        }
        AuthorityIntentObservation::Idle { .. } => Ok(
            MigrationTimestampReservation::Reserve(
                current.seal_reservation(key, intent, clock_sample)?,
            ),
        ),
    }
}

async fn require_replay_timestamp_safe(
    timestamps: &ScyllaAuthorityTimestampStore,
    key: AuthorityTimestampKey,
    intent: AuthorityCommitIntentDigest,
    persisted_timestamp: psy_node_core::store::timestamp::CommitWriteTimestampUs,
) -> anyhow::Result<()> {
    let AuthorityTimestampReadState::Current(current) =
        timestamps.read(key).await?
    else {
        anyhow::bail!(
            "branch-exact authority timestamp allocator disappeared during migration replay"
        );
    };
    validate_migration_timestamp_replay(
        current,
        key,
        intent,
        persisted_timestamp,
    )
}

fn validate_migration_timestamp_replay(
    current: StoredAuthorityTimestampState,
    key: AuthorityTimestampKey,
    intent: AuthorityCommitIntentDigest,
    persisted_timestamp: CommitWriteTimestampUs,
) -> anyhow::Result<()> {
    if current.high_water().as_i64() < persisted_timestamp.as_i64() {
        anyhow::bail!(
            "branch-exact persisted backfill timestamp exceeds authority high-water"
        );
    }
    match current.observe_intent(key, intent) {
        AuthorityIntentObservation::Active(lease)
            if lease.timestamp() == persisted_timestamp => {}
        AuthorityIntentObservation::Active(_) => anyhow::bail!(
            "branch-exact active migration timestamp differs from persisted backfill plan"
        ),
        AuthorityIntentObservation::Completed { .. }
        | AuthorityIntentObservation::Idle { .. } => anyhow::bail!(
            "branch-exact incomplete migration no longer owns its timestamp lease"
        ),
        AuthorityIntentObservation::BlockedByActive { .. } => anyhow::bail!(
            "branch-exact migration replay is blocked by another active authority write"
        ),
    }
    Ok(())
}

async fn complete_migration_timestamp_if_active(
    timestamps: &ScyllaAuthorityTimestampStore,
    key: AuthorityTimestampKey,
    intent: AuthorityCommitIntentDigest,
    persisted_timestamp: psy_node_core::store::timestamp::CommitWriteTimestampUs,
) -> anyhow::Result<()> {
    loop {
        let AuthorityTimestampReadState::Current(current) =
            timestamps.read(key).await?
        else {
            anyhow::bail!(
                "branch-exact authority timestamp allocator disappeared after backfill verification"
            );
        };
        match plan_migration_timestamp_completion(
            current,
            key,
            intent,
            persisted_timestamp,
        )? {
            MigrationTimestampCompletion::Complete(sealed) => {
                match timestamps.complete(sealed).await? {
                    AuthorityTimestampWriteOutcome::Applied(_)
                    | AuthorityTimestampWriteOutcome::Idempotent(_)
                    | AuthorityTimestampWriteOutcome::Conflict(_) => {}
                }
            }
            MigrationTimestampCompletion::Done => return Ok(()),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum MigrationTimestampCompletion {
    Done,
    Complete(SealedAuthorityTimestampCompletion),
}

fn plan_migration_timestamp_completion(
    current: StoredAuthorityTimestampState,
    key: AuthorityTimestampKey,
    intent: AuthorityCommitIntentDigest,
    persisted_timestamp: CommitWriteTimestampUs,
) -> anyhow::Result<MigrationTimestampCompletion> {
    if current.high_water().as_i64() < persisted_timestamp.as_i64() {
        anyhow::bail!(
            "branch-exact verified backfill timestamp exceeds authority high-water"
        );
    }
    match current.observe_intent(key, intent) {
        AuthorityIntentObservation::Active(lease) => {
            if lease.timestamp() != persisted_timestamp {
                anyhow::bail!(
                    "branch-exact active migration timestamp differs after verification"
                );
            }
            Ok(MigrationTimestampCompletion::Complete(
                current.seal_completion(key, lease)?,
            ))
        }
        AuthorityIntentObservation::Completed { timestamp, .. } => {
            if timestamp != persisted_timestamp {
                anyhow::bail!(
                    "branch-exact completed migration timestamp differs after verification"
                );
            }
            Ok(MigrationTimestampCompletion::Done)
        }
        AuthorityIntentObservation::Idle { .. }
        | AuthorityIntentObservation::BlockedByActive { .. } => {
            // A later authority operation proves this migration lease was
            // already released. Never interfere with that operation.
            Ok(MigrationTimestampCompletion::Done)
        }
    }
}

fn current_after_write(
    outcome: BranchExactDeploymentLifecycleWriteOutcome,
) -> StoredBranchExactDeploymentLifecycle {
    match outcome {
        BranchExactDeploymentLifecycleWriteOutcome::Applied(current)
        | BranchExactDeploymentLifecycleWriteOutcome::Idempotent(current)
        | BranchExactDeploymentLifecycleWriteOutcome::Conflict(current) => current,
    }
}

fn require_intent(
    current: &StoredBranchExactDeploymentLifecycle,
    expected: &BranchExactDeploymentIntent,
) -> anyhow::Result<()> {
    if current.state().intent() != expected {
        anyhow::bail!("branch-exact migration intent conflict");
    }
    Ok(())
}

fn require_plan(
    observed: &BranchExactBackfillPlan,
    expected: &BranchExactBackfillPlan,
) -> anyhow::Result<()> {
    if observed != expected {
        anyhow::bail!("branch-exact backfill plan conflict");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_node_core::store::authority_commit::{
        AuthorityTimestampBootstrap, AuthorityTimestampBootstrapReason,
        NetworkId,
    };

    use super::*;

    fn timestamp_key() -> AuthorityTimestampKey {
        AuthorityTimestampKey::new(
            NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet),
            psy_node_core::store::branch_exact_schema::AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
        )
    }

    fn timestamp(value: i64) -> CommitWriteTimestampUs {
        CommitWriteTimestampUs::try_from_i128(value as i128).unwrap()
    }

    fn clock_sample(value: i64) -> AuthorityClockSampleUs {
        AuthorityClockSampleUs::try_from_i128(value as i128).unwrap()
    }

    fn timestamp_intent(value: u8) -> AuthorityCommitIntentDigest {
        AuthorityCommitIntentDigest::from_sealed_commit_digest([value; 32])
    }

    fn initial_timestamp_state() -> StoredAuthorityTimestampState {
        AuthorityTimestampBootstrap::new(
            timestamp_key(),
            timestamp(100),
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        )
        .candidate()
    }

    #[test]
    fn operator_sequence_is_intent_first_resumable_and_stops_before_cutover() {
        let source = include_str!("branch_exact_schema_operator.rs");
        let body = source
            .split("pub(crate) async fn resume_post_genesis_branch_exact_migration")
            .nth(1)
            .unwrap()
            .split("fn current_after_write")
            .next()
            .unwrap();
        let intent = body.find("lifecycle.bootstrap").unwrap();
        let target_ddl = body.find("materialize_schema").unwrap();
        let topology = body.find("inspect_branch_exact_local_node_postflight").unwrap();
        let backfill = body.find("execute_chunk").unwrap();
        let readback = body.find("verify_artifact_readback").unwrap();
        assert!(intent < target_ddl);
        assert!(target_ddl < topology);
        assert!(topology < backfill);
        assert!(backfill < readback);
        for forbidden in [
            "BranchExactWriterActivationExecutor",
            "BranchExactCutoverBootstrap",
            "transition_route",
            "seal_rotation",
        ] {
            assert!(!body.contains(forbidden));
        }
    }

    #[test]
    fn operator_never_accepts_untyped_lifecycle_or_raw_cql() {
        let source = include_str!("branch_exact_schema_operator.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "query_unpaged",
            "execute_unpaged",
            "StoredBranchExactDeploymentLifecycle::try_new",
            "BranchExactBackfillReadbackObservation::new",
        ] {
            assert!(!production.contains(forbidden));
        }
        assert!(production.contains("require_intent"));
        assert!(production.contains("require_plan"));
        assert!(production.contains("lifecycle.read(current.slot())"));
    }

    #[test]
    fn all_durable_phases_are_handled_without_wildcard_fallback() {
        let source = include_str!("branch_exact_schema_operator.rs");
        let body = source
            .split("loop {")
            .nth(1)
            .unwrap()
            .split("fn current_after_write")
            .next()
            .unwrap();
        for phase in [
            "Intent(_)",
            "SchemaVerified(observed)",
            "BackfillPlanned(observed)",
            "BackfillProgress(progress)",
            "BackfillVerified(receipt)",
        ] {
            assert!(body.contains(phase), "missing phase {phase}");
        }
        assert!(!body.contains("_ =>"));
    }

    #[test]
    fn migration_is_post_genesis_and_requires_exact_targeted_topology() {
        let source = include_str!("branch_exact_schema_operator.rs");
        assert!(source.contains("BranchExactBackfillPlan::post_genesis_artifact"));
        assert!(source.contains("targeted_sessions.len()"));
        assert!(source.contains("migration.expected_topology.nodes().len()"));
        assert!(source.contains("BranchExactTopologyAttestation::try_new"));
        let validate = source.find("migration.artifact.validate_plan(&plan)").unwrap();
        let persist = source.find("lifecycle.plan_backfill").unwrap();
        assert!(validate < persist);
    }

    #[test]
    fn backfill_timestamp_is_allocator_owned_until_full_verification() {
        let source = include_str!("branch_exact_schema_operator.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let validate_inputs = production
            .find("validate_migration_inputs_before_timestamp_reservation(")
            .unwrap();
        let reserve = production.find("reserve_migration_timestamp(").unwrap();
        let plan = production
            .find("BranchExactBackfillPlan::post_genesis_artifact")
            .unwrap();
        let verify = production.find("verify_artifact_readback").unwrap();
        let complete = production
            .find("complete_migration_timestamp_if_active(")
            .unwrap();
        assert!(validate_inputs < reserve);
        assert!(reserve < plan);
        assert!(plan < verify);
        assert!(verify < complete);
        assert!(!production.contains("pub(crate) write_timestamp"));
        assert!(production.contains("incomplete migration no longer owns its timestamp lease"));
        assert!(production.contains("migration_timestamp_key::<Hash>"));
    }

    #[test]
    fn timestamp_reservation_recovers_same_intent_and_rejects_unsafe_replay() {
        let key = timestamp_key();
        let intent = timestamp_intent(1);
        let MigrationTimestampReservation::Reserve(reservation) =
            plan_migration_timestamp_reservation(
                initial_timestamp_state(),
                key,
                intent,
                clock_sample(200),
            )
            .unwrap()
        else {
            panic!("idle allocator must request one durable reservation")
        };
        assert_eq!(reservation.lease().timestamp(), timestamp(200));

        let active = reservation.candidate();
        assert_eq!(
            plan_migration_timestamp_reservation(
                active,
                key,
                intent,
                clock_sample(999),
            )
            .unwrap(),
            MigrationTimestampReservation::Ready(timestamp(200)),
        );
        assert!(validate_migration_timestamp_replay(
            active,
            key,
            intent,
            timestamp(200),
        )
        .is_ok());
        assert!(validate_migration_timestamp_replay(
            active,
            key,
            timestamp_intent(2),
            timestamp(200),
        )
        .is_err());

        let completed = active
            .seal_completion(key, reservation.lease())
            .unwrap()
            .candidate();
        assert!(plan_migration_timestamp_reservation(
            completed,
            key,
            intent,
            clock_sample(300),
        )
        .is_err());
        assert!(validate_migration_timestamp_replay(
            completed,
            key,
            intent,
            timestamp(200),
        )
        .is_err());
    }

    #[test]
    fn timestamp_completion_is_exact_and_never_interferes_with_later_work() {
        let key = timestamp_key();
        let intent = timestamp_intent(1);
        let reservation = initial_timestamp_state()
            .seal_reservation(key, intent, clock_sample(200))
            .unwrap();
        let active = reservation.candidate();
        let MigrationTimestampCompletion::Complete(completion) =
            plan_migration_timestamp_completion(
                active,
                key,
                intent,
                timestamp(200),
            )
            .unwrap()
        else {
            panic!("active exact lease must be completed")
        };
        let completed = completion.candidate();
        assert_eq!(
            plan_migration_timestamp_completion(
                completed,
                key,
                intent,
                timestamp(200),
            )
            .unwrap(),
            MigrationTimestampCompletion::Done,
        );

        let later = completed
            .seal_reservation(
                key,
                timestamp_intent(2),
                clock_sample(300),
            )
            .unwrap()
            .candidate();
        assert_eq!(
            plan_migration_timestamp_completion(
                later,
                key,
                intent,
                timestamp(200),
            )
            .unwrap(),
            MigrationTimestampCompletion::Done,
        );
        assert!(plan_migration_timestamp_completion(
            initial_timestamp_state(),
            key,
            intent,
            timestamp(200),
        )
        .is_err());
    }
}
