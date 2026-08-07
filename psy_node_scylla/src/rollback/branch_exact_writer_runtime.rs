//! Default-off production-shaped branch-exact writer runtime.
//!
//! The facade owns all Scylla adapters needed for one authority and exposes no
//! raw `Session`. Construction replays the h20 readiness gate from the exact
//! backfill receipt persisted in h22d0. A publish barrier is issued only after
//! the h22c 6/8-leg write has an exact durable `WritesVerified` observation.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampKey,
        AuthorityTimestampPhase, AuthorityTimestampWriteOutcome,
        ObservedAuthorityTimestampState,
    },
    branch_exact_dual_write::{
        BranchExactDualWriteIntent, BranchExactDualWriteIntentDigest,
    },
    branch_exact_schema::AuthorityScope,
};
use scylla::client::session::Session;

use super::{
    AuthorityTimestampNoTabletKeyspace, BranchExactDeploymentNoTabletKeyspace,
    BranchExactSchemaSetupRequest, BranchExactTimestampReservationRecovery,
    BranchExactWriterActivationDigest,
    BranchExactWriterAuthorityKey, BranchExactWriterLifecycleError,
    BranchExactWriterReadState, BranchExactWriterRevision,
    BranchExactWriterState, BranchExactWriterWriteOutcome,
    ScyllaAuthorityTimestampStore, ScyllaBranchExactSchemaSetupGate,
    ScyllaBranchExactWriterLifecycleStore, SealedBranchExactWriterCas,
    StoredBranchExactWriterLifecycle,
};
use super::branch_exact_dual_write_executor::{
    BranchExactDualWriteExecutionError, ScyllaBranchExactDualWriteAdapter,
    ScyllaBranchExactDualWriteExecutor,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterRuntimeRequest<Hash> {
    network: NetworkId,
    authority: AuthorityScope,
    expected_activation_digest: BranchExactWriterActivationDigest,
    _hash: std::marker::PhantomData<Hash>,
}

impl<Hash> BranchExactWriterRuntimeRequest<Hash> {
    pub const fn new(
        network: NetworkId,
        authority: AuthorityScope,
        expected_activation_digest: BranchExactWriterActivationDigest,
    ) -> Self {
        Self {
            network,
            authority,
            expected_activation_digest,
            _hash: std::marker::PhantomData,
        }
    }

    pub const fn network(&self) -> NetworkId {
        self.network
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn expected_activation_digest(&self) -> BranchExactWriterActivationDigest {
        self.expected_activation_digest
    }
}

/// Opaque authorization for the narrow branch-exact compatibility publish.
/// Its fields are private and every use performs a fresh durable lifecycle
/// read, so retaining an old value cannot authorize a later checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactPublishBarrier<Hash> {
    key: BranchExactWriterAuthorityKey,
    activation_digest: BranchExactWriterActivationDigest,
    writer_revision: BranchExactWriterRevision,
    candidate: CanonicalChainRef<Hash>,
    intent_digest: BranchExactDualWriteIntentDigest,
    prepared_digest: [u8; 32],
    verified_digest: [u8; 32],
}

impl<Hash> BranchExactPublishBarrier<Hash> {
    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub const fn writer_revision(&self) -> BranchExactWriterRevision {
        self.writer_revision
    }
}

pub struct ScyllaBranchExactWriterRuntime<Hash> {
    writer: ScyllaBranchExactWriterLifecycleStore,
    timestamps: ScyllaAuthorityTimestampStore,
    adapter: ScyllaBranchExactDualWriteAdapter,
    key: BranchExactWriterAuthorityKey,
    activation_digest: BranchExactWriterActivationDigest,
    _hash: std::marker::PhantomData<Hash>,
}

impl<Hash: Q256BitHash> ScyllaBranchExactWriterRuntime<Hash> {
    /// Prepare-only factory. It never creates schema, bootstraps rows or
    /// activates a writer. Missing/non-active durable state fails closed.
    pub async fn prepare(
        session: Arc<Session>,
        standard_keyspace: &str,
        no_tablet_keyspace: &str,
        request: BranchExactWriterRuntimeRequest<Hash>,
    ) -> Result<Self, BranchExactWriterRuntimeError> {
        let key = BranchExactWriterAuthorityKey::new(request.network, request.authority);
        let control_keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| BranchExactWriterRuntimeError::Setup(error.to_string()))?;
        let writer = ScyllaBranchExactWriterLifecycleStore::prepare(
            session.clone(),
            control_keyspace,
        )
        .await
        .map_err(store)?;
        let BranchExactWriterReadState::Current(current) =
            writer.read::<Hash>(key).await.map_err(store)?
        else {
            return Err(BranchExactWriterRuntimeError::WriterUninitialized);
        };
        if current.plan().digest() != request.expected_activation_digest {
            return Err(BranchExactWriterRuntimeError::ActivationPlanMismatch);
        }
        let expected_plan = current.plan().clone();
        match current.state() {
            BranchExactWriterState::Active(_)
            | BranchExactWriterState::WritePrepared(_)
            | BranchExactWriterState::WritesVerified(_) => {}
            BranchExactWriterState::ActivationPrepared => {
                return Err(BranchExactWriterRuntimeError::WriterNotActive)
            }
            BranchExactWriterState::Blocked(_) => {
                return Err(BranchExactWriterRuntimeError::WriterBlocked)
            }
        }

        let setup_request = BranchExactSchemaSetupRequest::new(
            expected_plan.backfill_receipt().clone(),
        );
        let ready = ScyllaBranchExactSchemaSetupGate::authorize(
            session.clone(),
            standard_keyspace,
            no_tablet_keyspace,
            expected_plan.authority(),
            &setup_request,
        )
        .await
        .map_err(|error| BranchExactWriterRuntimeError::Setup(error.to_string()))?;
        if ready.view().digest() != expected_plan.schema_ready_digest() {
            return Err(BranchExactWriterRuntimeError::ReadyDigestMismatch);
        }
        let timestamp_keyspace = AuthorityTimestampNoTabletKeyspace::try_new(
            no_tablet_keyspace.to_owned(),
        )
        .map_err(|error| BranchExactWriterRuntimeError::Timestamp(error.to_string()))?;
        let timestamps = ScyllaAuthorityTimestampStore::prepare(
            session.clone(),
            timestamp_keyspace,
        )
        .await
        .map_err(timestamp)?;
        let adapter = ScyllaBranchExactDualWriteAdapter::prepare(session, &ready)
            .await
            .map_err(executor)?;

        Ok(Self {
            writer,
            timestamps,
            adapter,
            key,
            activation_digest: expected_plan.digest(),
            _hash: std::marker::PhantomData,
        })
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.key.authority()
    }

    pub(crate) async fn prepare_and_verify(
        &self,
        intent: BranchExactDualWriteIntent<Hash>,
        clock_sample: AuthorityClockSampleUs,
    ) -> Result<BranchExactPublishBarrier<Hash>, BranchExactWriterRuntimeError> {
        let current = self.read_writer().await?;
        let prepared = match current.state() {
            BranchExactWriterState::Active(active) => {
                if intent.authority() != self.key.authority()
                    || intent.predecessor() != active.watermark()
                {
                    return Err(BranchExactWriterRuntimeError::IntentMismatch);
                }
                let timestamp_key = AuthorityTimestampKey::new(
                    intent.candidate().canonical_chain().network_id(),
                    intent.authority(),
                );
                let observed = self
                    .timestamps
                    .read_observed(timestamp_key)
                    .await
                    .map_err(timestamp)?
                    .ok_or(BranchExactWriterRuntimeError::TimestampUninitialized)?;
                let state = observed.state();
                if state.high_water() != active.timestamp_high_water()
                    || !matches!(state.phase(), AuthorityTimestampPhase::Idle { .. })
                {
                    return Err(BranchExactWriterRuntimeError::TimestampNotIdleAtWatermark);
                }
                let reservation = state
                    .seal_reservation(
                        timestamp_key,
                        intent.intent_digest().authority_intent(),
                        clock_sample,
                    )
                    .map_err(|error| BranchExactWriterRuntimeError::Model(error.to_string()))?;
                let sealed = intent
                    .clone()
                    .attach_timestamp_lease(reservation.lease())
                    .map_err(|error| BranchExactWriterRuntimeError::Model(error.to_string()))?;
                let cas = SealedBranchExactWriterCas::prepare_write(
                    &current,
                    &sealed,
                    reservation,
                )
                .map_err(lifecycle)?;
                match self.writer.compare_and_set(&cas).await.map_err(store)? {
                    BranchExactWriterWriteOutcome::Applied(next)
                    | BranchExactWriterWriteOutcome::Idempotent(next) => next,
                    BranchExactWriterWriteOutcome::Conflict(next)
                        if state_matches_intent(&next, &intent) => next,
                    BranchExactWriterWriteOutcome::Conflict(_) => {
                        return Err(BranchExactWriterRuntimeError::LifecycleConflict)
                    }
                }
            }
            BranchExactWriterState::WritePrepared(prepared)
                if prepared.intent() == &intent => current,
            BranchExactWriterState::WritesVerified(verified)
                if verified.prepared().intent() == &intent => {
                    return self.barrier_from_verified(&current)
                }
            _ => return Err(BranchExactWriterRuntimeError::IntentMismatch),
        };

        if matches!(prepared.state(), BranchExactWriterState::WritesVerified(_)) {
            return self.barrier_from_verified(&prepared);
        }
        let BranchExactWriterState::WritePrepared(prepared_state) = prepared.state() else {
            return Err(BranchExactWriterRuntimeError::LifecycleConflict);
        };
        let timestamp_key = AuthorityTimestampKey::new(
            prepared_state
                .intent()
                .candidate()
                .canonical_chain()
                .network_id(),
            prepared_state.intent().authority(),
        );
        let observed = self
            .timestamps
            .read_observed(timestamp_key)
            .await
            .map_err(timestamp)?
            .ok_or(BranchExactWriterRuntimeError::TimestampUninitialized)?;
        match prepared_state
            .reconcile_timestamp_reservation(observed)
            .map_err(lifecycle)?
        {
            BranchExactTimestampReservationRecovery::Active(_) => {}
            BranchExactTimestampReservationRecovery::Apply { reservation, .. } => {
                match self.timestamps.reserve(reservation).await.map_err(timestamp)? {
                    AuthorityTimestampWriteOutcome::Applied(_)
                    | AuthorityTimestampWriteOutcome::Idempotent(_) => {}
                    AuthorityTimestampWriteOutcome::Conflict(_) => {
                        return Err(BranchExactWriterRuntimeError::TimestampConflict)
                    }
                }
            }
        }

        let verified = ScyllaBranchExactDualWriteExecutor::run::<Hash>(
            &self.writer,
            &self.timestamps,
            &self.adapter,
            self.key,
        )
        .await
        .map_err(executor)?;
        self.barrier_from_verified(&verified)
    }

    /// Re-read the exact lifecycle row immediately before any compatibility
    /// singleton or authority marker is published.
    pub(crate) async fn require_fresh_barrier(
        &self,
        barrier: &BranchExactPublishBarrier<Hash>,
    ) -> Result<(), BranchExactWriterRuntimeError> {
        let current = self.require_matching_verified(barrier).await?;
        let BranchExactWriterState::WritesVerified(verified) = current.state() else {
            unreachable!("require_matching_verified accepts only WritesVerified")
        };
        let prepared = verified.prepared();
        let timestamp_key = AuthorityTimestampKey::new(
            prepared
                .intent()
                .candidate()
                .canonical_chain()
                .network_id(),
            prepared.intent().authority(),
        );
        let observed = self
            .timestamps
            .read_observed(timestamp_key)
            .await
            .map_err(timestamp)?
            .ok_or(BranchExactWriterRuntimeError::TimestampUninitialized)?;
        prepared.reseal(observed).map_err(lifecycle)?;
        Ok(())
    }

    /// Re-read and match the exact verified lifecycle state without requiring
    /// the allocator lease to remain Active. Finalization uses this after the
    /// authority marker is durable because a crash may have already completed
    /// the allocator lease while leaving the writer in WritesVerified.
    async fn require_matching_verified(
        &self,
        barrier: &BranchExactPublishBarrier<Hash>,
    ) -> Result<StoredBranchExactWriterLifecycle<Hash>, BranchExactWriterRuntimeError> {
        if barrier.key != self.key || barrier.activation_digest != self.activation_digest {
            return Err(BranchExactWriterRuntimeError::BarrierMismatch);
        }
        let current = self.read_writer().await?;
        if current.revision() != barrier.writer_revision {
            return Err(BranchExactWriterRuntimeError::StaleBarrier);
        }
        let BranchExactWriterState::WritesVerified(verified) = current.state() else {
            return Err(BranchExactWriterRuntimeError::StaleBarrier);
        };
        if verified.prepared().intent().candidate().canonical_chain() != &barrier.candidate
            || verified.prepared().intent().intent_digest() != barrier.intent_digest
            || verified.prepared().digest() != &barrier.prepared_digest
            || verified.digest() != &barrier.verified_digest
        {
            return Err(BranchExactWriterRuntimeError::BarrierMismatch);
        }
        Ok(current)
    }

    /// Complete the timestamp lease only after the caller has durably
    /// published the exact candidate authority marker, then advance the writer
    /// watermark. Both steps are idempotent after response loss.
    pub(crate) async fn finish_published(
        &self,
        barrier: &BranchExactPublishBarrier<Hash>,
        published: &CanonicalChainRef<Hash>,
    ) -> Result<(), BranchExactWriterRuntimeError> {
        if published != barrier.candidate() {
            return Err(BranchExactWriterRuntimeError::PublishedMarkerMismatch);
        }
        let current = self.read_writer().await?;
        if let BranchExactWriterState::Active(active) = current.state() {
            if active.watermark().canonical_chain() == published
                && active.last_intent().map(|digest| *digest.as_bytes())
                    == Some(*barrier.intent_digest.as_bytes())
            {
                return Ok(());
            }
            return Err(BranchExactWriterRuntimeError::StaleBarrier);
        }
        // Do not require an Active lease here. A previous attempt may have
        // completed it and crashed before the writer lifecycle CAS.
        let current = self.require_matching_verified(barrier).await?;
        let BranchExactWriterState::WritesVerified(verified) = current.state() else {
            return Err(BranchExactWriterRuntimeError::StaleBarrier);
        };
        let prepared = verified.prepared();
        let timestamp_key = AuthorityTimestampKey::new(
            published.network_id(),
            prepared.intent().authority(),
        );
        let observed = self
            .timestamps
            .read_observed(timestamp_key)
            .await
            .map_err(timestamp)?
            .ok_or(BranchExactWriterRuntimeError::TimestampUninitialized)?;
        let completed = match observed.observe_intent(
            prepared.intent().intent_digest().authority_intent(),
        ) {
            psy_node_core::store::authority_commit::AuthorityIntentObservation::Active(lease) => {
                let completion = observed
                    .state()
                    .seal_completion(timestamp_key, lease)
                    .map_err(|error| BranchExactWriterRuntimeError::Model(error.to_string()))?;
                match self.timestamps.complete(completion).await.map_err(timestamp)? {
                    AuthorityTimestampWriteOutcome::Applied(state)
                    | AuthorityTimestampWriteOutcome::Idempotent(state) => state,
                    AuthorityTimestampWriteOutcome::Conflict(_) => {
                        return Err(BranchExactWriterRuntimeError::TimestampConflict)
                    }
                }
            }
            psy_node_core::store::authority_commit::AuthorityIntentObservation::Completed { .. } => {
                observed.state()
            }
            _ => return Err(BranchExactWriterRuntimeError::TimestampConflict),
        };
        let completed = ObservedAuthorityTimestampState::from_selected_row(
            timestamp_key,
            completed,
        );
        let cas = SealedBranchExactWriterCas::commit_published(
            &current,
            published,
            completed,
        )
        .map_err(lifecycle)?;
        match self.writer.compare_and_set(&cas).await.map_err(store)? {
            BranchExactWriterWriteOutcome::Applied(_)
            | BranchExactWriterWriteOutcome::Idempotent(_) => Ok(()),
            BranchExactWriterWriteOutcome::Conflict(next) => {
                let BranchExactWriterState::Active(active) = next.state() else {
                    return Err(BranchExactWriterRuntimeError::LifecycleConflict);
                };
                if active.watermark().canonical_chain() == published
                    && active.last_intent().map(|digest| *digest.as_bytes())
                        == Some(*barrier.intent_digest.as_bytes())
                {
                    Ok(())
                } else {
                    Err(BranchExactWriterRuntimeError::LifecycleConflict)
                }
            }
        }
    }

    async fn read_writer(
        &self,
    ) -> Result<StoredBranchExactWriterLifecycle<Hash>, BranchExactWriterRuntimeError> {
        let BranchExactWriterReadState::Current(current) =
            self.writer.read(self.key).await.map_err(store)?
        else {
            return Err(BranchExactWriterRuntimeError::WriterUninitialized);
        };
        if current.plan().digest() != self.activation_digest {
            return Err(BranchExactWriterRuntimeError::ActivationPlanMismatch);
        }
        Ok(current)
    }

    fn barrier_from_verified(
        &self,
        current: &StoredBranchExactWriterLifecycle<Hash>,
    ) -> Result<BranchExactPublishBarrier<Hash>, BranchExactWriterRuntimeError> {
        let BranchExactWriterState::WritesVerified(verified) = current.state() else {
            return Err(BranchExactWriterRuntimeError::LifecycleConflict);
        };
        let prepared = verified.prepared();
        Ok(BranchExactPublishBarrier {
            key: self.key,
            activation_digest: self.activation_digest,
            writer_revision: current.revision(),
            candidate: *prepared.intent().candidate().canonical_chain(),
            intent_digest: prepared.intent().intent_digest(),
            prepared_digest: *prepared.digest(),
            verified_digest: *verified.digest(),
        })
    }
}

fn state_matches_intent<Hash: Q256BitHash>(
    state: &StoredBranchExactWriterLifecycle<Hash>,
    intent: &BranchExactDualWriteIntent<Hash>,
) -> bool {
    matches!(
        state.state(),
        BranchExactWriterState::WritePrepared(prepared) if prepared.intent() == intent
    ) || matches!(
        state.state(),
        BranchExactWriterState::WritesVerified(verified)
            if verified.prepared().intent() == intent
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactWriterRuntimeError {
    Setup(String),
    Store(String),
    Timestamp(String),
    Executor(String),
    Model(String),
    WriterUninitialized,
    WriterNotActive,
    WriterBlocked,
    ActivationPlanMismatch,
    ReadyDigestMismatch,
    TimestampUninitialized,
    TimestampNotIdleAtWatermark,
    TimestampConflict,
    IntentMismatch,
    LifecycleConflict,
    BarrierMismatch,
    StaleBarrier,
    PublishedMarkerMismatch,
}

impl fmt::Display for BranchExactWriterRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactWriterRuntimeError {}

fn store(error: impl fmt::Display) -> BranchExactWriterRuntimeError {
    BranchExactWriterRuntimeError::Store(error.to_string())
}

fn timestamp(error: impl fmt::Display) -> BranchExactWriterRuntimeError {
    BranchExactWriterRuntimeError::Timestamp(error.to_string())
}

fn executor(error: BranchExactDualWriteExecutionError) -> BranchExactWriterRuntimeError {
    BranchExactWriterRuntimeError::Executor(error.to_string())
}

fn lifecycle(error: BranchExactWriterLifecycleError) -> BranchExactWriterRuntimeError {
    BranchExactWriterRuntimeError::Model(error.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn production_setup_is_still_default_off_and_runtime_is_not_auto_wired() {
        let setup = include_str!("../psy_setup.rs");
        assert!(setup.contains("BranchExactSchemaSetupMode::Disabled"));
        assert!(!setup.contains("ScyllaBranchExactWriterRuntime::prepare"));

        let core = include_str!("../core.rs");
        assert!(!core.contains("branch_exact_writer_runtime"));
    }

    #[test]
    fn barrier_fields_are_private_and_no_raw_session_is_exposed() {
        let source = include_str!("branch_exact_writer_runtime.rs");
        assert!(source.contains("pub struct BranchExactPublishBarrier<Hash>"));
        let public_session_field = ["pub ", "session", ":"].concat();
        assert!(!source.contains(&public_session_field));
        let public_session_method = ["pub fn ", "session"].concat();
        assert!(!source.contains(&public_session_method));
        let public_barrier_constructor = ["pub fn new_", "barrier"].concat();
        assert!(!source.contains(&public_barrier_constructor));
        assert!(source.contains("require_fresh_barrier"));
    }

    #[test]
    fn finalize_does_not_require_the_allocator_lease_to_still_be_active() {
        let source = include_str!("branch_exact_writer_runtime.rs");
        let finish = source
            .split("pub(crate) async fn finish_published")
            .nth(1)
            .unwrap()
            .split("async fn read_writer")
            .next()
            .unwrap();
        assert!(finish.contains("require_matching_verified(barrier)"));
        assert!(!finish.contains("require_fresh_barrier(barrier)"));
        assert!(finish.contains("AuthorityIntentObservation::Completed"));
    }
}
