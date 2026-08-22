//! Assembles the PREPARED half of a Realm commit.
//!
//! The same order as the Coordinator's, and forced by the same types: the lease
//! binds an intent digest, so the intent is sealed first; the intent commits to
//! an artifact set, so the plan is encoded before that; the PREPARED record needs
//! the lease, so it comes last.
//!
//! Two differences, both from §6.
//!
//! The chain reference is the Coordinator's, not the Realm's.  A Realm commits
//! *at* a checkpoint the Coordinator published; it does not choose one.  Passing
//! the Coordinator's `CanonicalChainRef` through means a Realm manifest names the
//! same `(chain_epoch, checkpoint)` the Coordinator's does, which is what lets a
//! rollback line the two up rather than infer a correspondence.
//!
//! There is no floor and no commit source.  Both are the Coordinator's, and a
//! Realm that established its own would be asserting an authority §6 gives it no
//! way to hold.

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::CanonicalChainRef;

use super::authority_commit::{
    AuthorityClockSampleUs, AuthorityTimestampBootstrap, AuthorityTimestampBootstrapReason,
    AuthorityTimestampKey, AuthorityTimestampLease, AuthorityTimestampReadState,
    AuthorityTimestampWriteOutcome, StoredAuthorityTimestampState,
};
use super::commit_planner::{CollectingPhysicalMutationSink, RealmCommitPlanInputs};
use super::manifest_intent::{
    AuthorityHeadPayload, AuthorityStateTransition, ManifestArtifactSetCommitment,
    SealedAuthorityCommitIntent,
};
use super::manifest_record::{AuthorityManifestIdentity, PreparedAuthorityManifestRecord};
use super::manifest_store::ManifestArtifactKind;
use super::realm_commit_recording::RealmCommitRecording;

/// A Realm commit whose manifest is durable and whose lease is held.
pub struct PreparedRealmCommit<Hash: Q256BitHash> {
    record: PreparedAuthorityManifestRecord<Hash>,
    lease: AuthorityTimestampLease,
    planned_rows: Vec<(u16, Vec<u8>)>,
}

impl<Hash: Q256BitHash> PreparedRealmCommit<Hash> {
    pub const fn record(&self) -> &PreparedAuthorityManifestRecord<Hash> {
        &self.record
    }

    pub const fn lease(&self) -> AuthorityTimestampLease {
        self.lease
    }

    pub const fn identity(&self) -> &AuthorityManifestIdentity<Hash> {
        self.record.identity()
    }

    pub fn planned_rows(&self) -> &[(u16, Vec<u8>)] {
        &self.planned_rows
    }
}

async fn read_or_bootstrap<Hash: Q256BitHash>(
    recording: &RealmCommitRecording<Hash>,
    key: AuthorityTimestampKey,
    clock_sample: AuthorityClockSampleUs,
    bootstrap_reason: AuthorityTimestampBootstrapReason,
) -> anyhow::Result<StoredAuthorityTimestampState> {
    match recording.timestamp().read_timestamp_state(key).await? {
        AuthorityTimestampReadState::Current(state) => Ok(state),
        AuthorityTimestampReadState::Uninitialized => {
            let initial =
                super::timestamp::CommitWriteTimestampUs::try_from_i128(clock_sample.as_i64() as i128)?;
            let bootstrap = AuthorityTimestampBootstrap::new(key, initial, bootstrap_reason);
            match recording
                .timestamp()
                .bootstrap_timestamp_state(&bootstrap)
                .await?
            {
                AuthorityTimestampWriteOutcome::Applied(state)
                | AuthorityTimestampWriteOutcome::Idempotent(state)
                | AuthorityTimestampWriteOutcome::Conflict(state) => Ok(state),
            }
        }
    }
}

/// Plan the Realm commit, make its manifest durable, and take its lease.
pub async fn prepare_realm_commit<Hash: Q256BitHash>(
    recording: &RealmCommitRecording<Hash>,
    key: AuthorityTimestampKey,
    inputs: &RealmCommitPlanInputs<'_>,
    // Both come from the Coordinator: a Realm records the checkpoint it was told
    // to commit, so its manifest and the Coordinator's name the same coordinate.
    expected_chain: CanonicalChainRef<Hash>,
    candidate_chain: CanonicalChainRef<Hash>,
    state_transition: AuthorityStateTransition<Hash>,
    head_payload: AuthorityHeadPayload,
    clock_sample: AuthorityClockSampleUs,
    bootstrap_reason: AuthorityTimestampBootstrapReason,
) -> anyhow::Result<PreparedRealmCommit<Hash>> {
    let sink = CollectingPhysicalMutationSink::new();
    recording.planner().plan_realm_commit(inputs, &sink)?;
    let planned_rows = sink.take();
    if planned_rows.is_empty() {
        anyhow::bail!("a Realm commit that writes no row cannot be recorded");
    }
    let planned = recording
        .planner()
        .encode_planned_locators(planned_rows.clone())?;

    let artifacts = ManifestArtifactSetCommitment::from_verified_artifact_summary(
        &planned.canonical_summary,
        planned.mutation_digest,
        planned.chunk_count(),
        0,
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

    let state = read_or_bootstrap(recording, key, clock_sample, bootstrap_reason).await?;
    let reservation = state.seal_reservation(key, intent.digest(), clock_sample)?;
    match recording.timestamp().reserve_timestamp(&reservation).await? {
        AuthorityTimestampWriteOutcome::Applied(_)
        | AuthorityTimestampWriteOutcome::Idempotent(_) => {}
        AuthorityTimestampWriteOutcome::Conflict(current) => {
            anyhow::bail!(
                "another writer holds this Realm's commit timestamp lease (observed revision {})",
                current.revision().get()
            );
        }
    }

    let prepared_intent = intent.attach_timestamp_lease(reservation.lease())?;
    let record =
        PreparedAuthorityManifestRecord::seal(&prepared_intent, planned.canonical_summary.clone())?;
    crate::store::manifest_store::persist_artifact_chunks_replacing_abandoned(
        recording.manifest(),
        recording.manifest_artifact(),
        record.identity(),
        ManifestArtifactKind::Locator,
        &planned.chunks,
    )
    .await?;
    recording.manifest().append_prepared(&record).await?;

    Ok(PreparedRealmCommit {
        record,
        lease: reservation.lease(),
        planned_rows,
    })
}
