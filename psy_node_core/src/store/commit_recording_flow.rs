//! Assembles the PREPARED half of a Coordinator commit record.
//!
//! `commit_state` calls this before touching any hot table, which is the whole
//! point of design-r1 §3: a crash after the state writes but before the manifest
//! would leave physical rows that no manifest names, and rollback would then have
//! no way to find them.
//!
//! The order below is not a preference, it is forced by the types.  The lease
//! binds an intent digest, so the intent must be sealed first; the intent commits
//! to an artifact set, so the plan must be encoded before that; and the PREPARED
//! record needs the lease, so it comes last.  Nothing here can be reordered
//! without the compiler noticing.

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;

use super::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap, AuthorityTimestampKey,
        AuthorityTimestampBootstrapReason, AuthorityTimestampLease, AuthorityTimestampReadState,
        AuthorityTimestampWriteOutcome,
    },
    commit_planner::{CollectingPhysicalMutationSink, CoordinatorCommitPlanInputs},
    manifest_intent::{
        AuthorityHeadPayload, AuthorityStateTransition, ManifestArtifactSetCommitment,
        SealedAuthorityCommitIntent,
    },
    manifest_record::{AuthorityManifestIdentity, PreparedAuthorityManifestRecord},
    manifest_store::{CoordinatorCommitRecording, ManifestArtifactKind},
};

/// A commit whose manifest is durable and whose timestamp lease is held.
///
/// Holding the lease is what makes the commit exclusive: another writer cannot
/// reserve while this one is active, so two Coordinators cannot both believe they
/// own the same checkpoint.
pub struct PreparedCommitRecording<Hash: Q256BitHash> {
    record: PreparedAuthorityManifestRecord<Hash>,
    lease: AuthorityTimestampLease,
}

impl<Hash: Q256BitHash> PreparedCommitRecording<Hash> {
    pub const fn record(&self) -> &PreparedAuthorityManifestRecord<Hash> {
        &self.record
    }

    pub const fn lease(&self) -> AuthorityTimestampLease {
        self.lease
    }

    pub const fn identity(&self) -> &AuthorityManifestIdentity<Hash> {
        self.record.identity()
    }
}

/// Read the allocator row, materialising it on first use.
///
/// A missing row means this authority has never committed under the recording
/// scheme.  Bootstrapping here is what places design-r1 §13 Q1's
/// `POST_GENESIS_FLOOR`: rollback becomes possible from this commit onward and
/// not before, because earlier checkpoints have no manifest.
async fn read_or_bootstrap_timestamp_state<Hash: Q256BitHash>(
    recording: &CoordinatorCommitRecording<Hash>,
    key: AuthorityTimestampKey,
    clock_sample: AuthorityClockSampleUs,
    bootstrap_reason: AuthorityTimestampBootstrapReason,
) -> anyhow::Result<super::authority_commit::StoredAuthorityTimestampState> {
    match recording.timestamp().read_timestamp_state(key).await? {
        AuthorityTimestampReadState::Current(state) => Ok(state),
        AuthorityTimestampReadState::Uninitialized => {
            // The initial high water is the caller's observed clock, never a
            // default: the allocator's own contract forbids guessing one, because
            // a guess below the real clock would let a later commit reuse a
            // timestamp a discarded branch had already used.
            let initial_high_water = super::timestamp::CommitWriteTimestampUs::try_from_i128(
                clock_sample.as_i64() as i128,
            )?;
            let bootstrap =
                AuthorityTimestampBootstrap::new(key, initial_high_water, bootstrap_reason);
            match recording
                .timestamp()
                .bootstrap_timestamp_state(&bootstrap)
                .await?
            {
                AuthorityTimestampWriteOutcome::Applied(state)
                | AuthorityTimestampWriteOutcome::Idempotent(state) => Ok(state),
                // Somebody else materialised it first.  Their row is as valid as
                // ours would have been, so take it rather than failing: the
                // reservation below is what actually establishes exclusivity.
                AuthorityTimestampWriteOutcome::Conflict(state) => Ok(state),
            }
        }
    }
}

/// Plan the commit, make its manifest durable, and take the timestamp lease.
///
/// Returns once the artifact chunks and the PREPARED row are both readable.  The
/// caller may then perform its state writes knowing every row it is about to
/// write is already named on disk.
pub async fn prepare_commit_recording<Hash: Q256BitHash>(
    recording: &CoordinatorCommitRecording<Hash>,
    key: AuthorityTimestampKey,
    inputs: &CoordinatorCommitPlanInputs<'_>,
    expected_chain: CanonicalChainRef<Hash>,
    candidate_chain: CanonicalChainRef<Hash>,
    state_transition: AuthorityStateTransition<Hash>,
    head_payload: AuthorityHeadPayload,
    clock_sample: AuthorityClockSampleUs,
    // How this authority's allocator row came to exist, if it has to be created
    // now.  GenesisNative only for a chain that starts under the recording
    // scheme; an existing chain adopting it is ControlledWriterCutover, which is
    // what places the rollback floor at this commit (design-r1 §13 Q1).
    bootstrap_reason: AuthorityTimestampBootstrapReason,
) -> anyhow::Result<PreparedCommitRecording<Hash>> {
    // 1. Enumerate what the commit will write, then encode and summarise it.
    let sink = CollectingPhysicalMutationSink::new();
    recording
        .planner()
        .plan_coordinator_commit(inputs, &sink)?;
    let planned = recording.planner().encode_planned_locators(sink.take())?;
    if planned.affected_row_count == 0 {
        anyhow::bail!("a Coordinator commit that writes no row cannot be recorded");
    }

    // 2. Commit to that artifact set, and seal the intent so it has a digest.
    let artifacts = ManifestArtifactSetCommitment::from_verified_artifact_summary(
        &planned.canonical_summary,
        planned.mutation_digest,
        planned.chunk_count(),
        // R1 has no replay artifact: replay served the snapshot fallback, which
        // design-r1 §0.0 removed from scope.
        0,
        // The singleton before images ride in the head payload rather than in a
        // separate chunk set, so there is no durable-payload artifact either.
        0,
        planned.affected_row_count,
    )?;
    let intent = SealedAuthorityCommitIntent::seal_normal_advance(
        key,
        expected_chain,
        candidate_chain,
        state_transition,
        head_payload,
        artifacts,
    )?;

    // 3. Take the lease.  It binds the intent digest, so it cannot be reused for
    //    a different commit, and it fails closed if another writer holds it.
    let state =
        read_or_bootstrap_timestamp_state(recording, key, clock_sample, bootstrap_reason).await?;
    let reservation = state.seal_reservation(key, intent.digest(), clock_sample)?;
    match recording
        .timestamp()
        .reserve_timestamp(&reservation)
        .await?
    {
        AuthorityTimestampWriteOutcome::Applied(_)
        | AuthorityTimestampWriteOutcome::Idempotent(_) => {}
        AuthorityTimestampWriteOutcome::Conflict(current) => {
            anyhow::bail!(
                "another writer holds the commit timestamp lease for this authority \
                 (observed revision {})",
                current.revision().get()
            );
        }
    }

    // 4. Seal the PREPARED record against the exact summary the intent committed
    //    to, then make the chunks durable before the row that names them.
    let prepared_intent = intent.attach_timestamp_lease(reservation.lease())?;
    let record = PreparedAuthorityManifestRecord::seal(
        &prepared_intent,
        planned.canonical_summary.clone(),
    )?;
    recording
        .manifest_artifact()
        .persist_artifact_chunks(
            record.identity(),
            ManifestArtifactKind::Locator,
            &planned.chunks,
        )
        .await?;
    recording.manifest().append_prepared(&record).await?;

    Ok(PreparedCommitRecording {
        record,
        lease: reservation.lease(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::commit_planner::PhysicalMutationSink;

    #[test]
    fn a_planned_set_must_not_be_empty() {
        // Every commit writes the unconditional rows, so an empty plan means the
        // planner failed to enumerate rather than that nothing changed.  Sealing
        // a manifest that claims zero rows would make the commit look
        // rollback-clean while its state writes still landed.
        let sink = CollectingPhysicalMutationSink::new();
        assert!(sink.is_empty());
        sink.record_physical_put(1, vec![1, 2, 3]).unwrap();
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn a_sink_refuses_a_row_without_a_locator() {
        let sink = CollectingPhysicalMutationSink::new();
        assert!(sink.record_physical_put(1, Vec::new()).is_err());
        assert!(sink.is_empty());
    }
}
