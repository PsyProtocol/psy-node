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
use psy_node_core::store::timestamp::CommitWriteTimestampUs;
use scylla::client::session::Session;

use super::{
    inspect_branch_exact_local_node_postflight, BranchExactBackfillArtifact,
    BranchExactBackfillPlan, BranchExactBackfillVerifiedReceipt,
    BranchExactDeploymentIntent, BranchExactDeploymentLifecycleBootstrap,
    BranchExactDeploymentLifecycleReadState, BranchExactDeploymentLifecycleState,
    BranchExactDeploymentLifecycleWriteOutcome,
    BranchExactDeploymentNoTabletKeyspace, BranchExactExpectedTopology,
    BranchExactSchemaMaterializationRequest, BranchExactSchemaMaterializer,
    BranchExactTopologyAttestation, BranchExactVerifiedDeploymentReceipt,
    ScyllaBranchExactBackfillExecutor,
    ScyllaBranchExactDeploymentLifecycleStore, SealedBranchExactBackfillChunkCas,
    SealedBranchExactBackfillPlanCas, SealedBranchExactBackfillVerifiedCas,
    SealedBranchExactSchemaVerifiedCas, StoredBranchExactDeploymentLifecycle,
};

/// All inputs whose identity must remain stable across an operator retry.
///
/// Targeted sessions must each be pinned to one operator-declared Scylla
/// node. The topology attestation rejects missing, duplicate, foreign or
/// schema-divergent nodes before the lifecycle can reach `SchemaVerified`.
pub(crate) struct BranchExactPostGenesisMigration<'a, Hash> {
    pub(crate) request: &'a BranchExactSchemaMaterializationRequest,
    pub(crate) artifact: &'a BranchExactBackfillArtifact<Hash>,
    pub(crate) expected_topology: BranchExactExpectedTopology,
    pub(crate) write_timestamp: CommitWriteTimestampUs,
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
        migration.expected_topology,
        observations,
    )?;
    let deployment = BranchExactVerifiedDeploymentReceipt::try_new(
        intent,
        attestation,
    )?;
    let plan = BranchExactBackfillPlan::post_genesis_artifact(
        migration.request,
        deployment.clone(),
        migration.artifact.dataset_digest(),
        migration.write_timestamp,
        migration.total_chunks,
        migration.artifact.pair_rows_per_direction(),
        migration.artifact.proof_rows(),
    )?;
    // Validate the complete artifact/plan relationship before persisting the
    // plan. Otherwise a future plan-field addition could durably select work
    // that every executor retry must reject.
    migration.artifact.validate_plan(&plan)?;
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
                return Ok(readback_receipt.clone());
            }
        };
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
    use super::*;

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
}
