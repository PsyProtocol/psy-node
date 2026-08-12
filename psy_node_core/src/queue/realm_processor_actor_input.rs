//! Complete, storage-qualified input consumed by the Realm command-only actor.
//!
//! Deferred carryover and the closed external generation are selected through
//! different durable indexes.  This non-Clone value joins them before the
//! actor boundary so neither half can be paired with another generation.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use super::{
    realm_processor_deferred_actor_input::{
        RealmProcessorDeferredActorInput, RealmProcessorDeferredActorInputDigest,
        RealmProcessorDeferredActorInputSource,
    },
    realm_processor_external_dependency_input::{
        RealmProcessorQualifiedExternalActorInput,
        RealmProcessorQualifiedExternalActorInputDigest,
    },
    recoverable_ephemeral::PendingQueueCaptureContext,
};

const ACTOR_INPUT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-qualified-actor-input/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorActorInputDigest([u8; 32]);

impl RealmProcessorActorInputDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorActorInputError> {
        if bytes == [0; 32] {
            Err(RealmProcessorActorInputError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub fn try_from_exact_parts(
        context: PendingQueueCaptureContext,
        deferred: RealmProcessorDeferredActorInputDigest,
        external: RealmProcessorQualifiedExternalActorInputDigest,
    ) -> Result<Self, RealmProcessorActorInputError> {
        let mut hasher = Sha256::new();
        hasher.update(ACTOR_INPUT_DIGEST_DOMAIN);
        hasher.update(context.digest().as_bytes());
        hasher.update(deferred.as_bytes());
        hasher.update(external.as_bytes());
        Self::try_new(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The sole actor input for one branch-exact execution.  Construction checks
/// data identity only; mutation authority still comes from the controlled,
/// affine Processor iteration that calls the crate-private actor command.
#[derive(Debug)]
pub struct RealmProcessorActorInput {
    context: PendingQueueCaptureContext,
    deferred: RealmProcessorDeferredActorInput,
    external: RealmProcessorQualifiedExternalActorInput,
    digest: RealmProcessorActorInputDigest,
}

impl RealmProcessorActorInput {
    pub fn try_new(
        deferred: RealmProcessorDeferredActorInput,
        external: RealmProcessorQualifiedExternalActorInput,
    ) -> Result<Self, RealmProcessorActorInputError> {
        let context = external.context();
        if deferred.successor() != context.processing() {
            return Err(RealmProcessorActorInputError::GenerationMismatch);
        }
        let digest = RealmProcessorActorInputDigest::try_from_exact_parts(
            context,
            deferred.digest(),
            external.digest(),
        )?;
        Ok(Self {
            context,
            deferred,
            external,
            digest,
        })
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn deferred_digest(&self) -> RealmProcessorDeferredActorInputDigest {
        self.deferred.digest()
    }

    pub const fn deferred_source(&self) -> RealmProcessorDeferredActorInputSource {
        self.deferred.source()
    }

    pub const fn external_digest(&self) -> RealmProcessorQualifiedExternalActorInputDigest {
        self.external.digest()
    }

    pub const fn digest(&self) -> RealmProcessorActorInputDigest {
        self.digest
    }

    pub fn into_parts(
        self,
    ) -> (
        RealmProcessorDeferredActorInput,
        RealmProcessorQualifiedExternalActorInput,
    ) {
        (self.deferred, self.external)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorActorInputError {
    EmptyDigest,
    GenerationMismatch,
}

impl fmt::Display for RealmProcessorActorInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorActorInputError {}

#[cfg(test)]
mod tests {
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };

    use crate::{
        queue::{
            realm_processor_deferred_actor_input::RealmProcessorDeferredActorInput,
            realm_processor_durable_capture::RealmProcessorDurableCapturedGeneration,
            realm_processor_external_dependency_input::{
                RealmProcessorExternalDependencyProjection,
                RealmProcessorQualifiedExternalActorInput,
            },
            realm_processor_generation_terminal::RealmProcessorDeferredCarryover,
            realm_user_update_admission::{
                RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
                RealmUserUpdateQualificationDigest,
            },
            recoverable_ephemeral::{
                PendingQueueBoundaryObservation, PendingQueueCaptureContext,
                PendingQueueGenerationBoundary, PendingQueueSourceIdentity,
            },
        },
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
            PendingGenerationContext, PendingGenerationLedgerKey,
        },
    };

    use super::*;

    fn context(processing: PendingGenerationContext) -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1).unwrap(),
                AuthorityScope::Realm {
                    realm_id: 2,
                    realm_sub_id: 3,
                },
            ),
            PendingGenerationActivationDigest::try_new([4; 32]).unwrap(),
            processing,
        )
        .unwrap()
    }

    fn deferred(
        processing: PendingGenerationContext,
    ) -> RealmProcessorDeferredActorInput {
        let context = context(processing);
        let reason = PendingGenerationBootstrapReason::LegacyActivation;
        let carryover = RealmProcessorDeferredCarryover::try_bootstrap_empty(
            context.key(),
            context.activation(),
            processing,
            reason,
        )
        .unwrap();
        RealmProcessorDeferredActorInput::try_from_storage(
            processing,
            reason,
            carryover,
            None,
        )
        .unwrap()
    }

    fn external(
        processing: PendingGenerationContext,
        assignment_marker: u8,
    ) -> RealmProcessorQualifiedExternalActorInput {
        let context = context(processing);
        let source = PendingQueueSourceIdentity::nats_jetstream(
            "psy",
            "realm-updates-r2-s3",
            "psy.realm-updates.r2.s3.processing",
        )
        .unwrap();
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context,
            crate::store::pending_generation_pipeline::PendingQueueCloseIntentDigest::try_new(
                [7; 32],
            )
            .unwrap(),
            source,
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: 1,
                last_data_stream_sequence: 0,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap();
        let generation =
            RealmProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
                context,
                Vec::new(),
                boundary,
            )
            .unwrap();
        let key = RealmUserUpdateAdmissionKey::try_new(context).unwrap();
        let projection = RealmProcessorExternalDependencyProjection::try_new(
            context,
            RealmUserUpdateAdmissionCloseIntent::derive(key, [9; 32]).unwrap(),
            RealmUserUpdateQualificationDigest::try_new([10; 32]).unwrap(),
            [assignment_marker; 32],
            Vec::new(),
        )
        .unwrap();
        RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
            generation,
            projection,
        )
        .unwrap()
    }

    #[test]
    fn complete_input_rejects_cross_generation_pairing_and_commits_both_halves() {
        let processing = PendingGenerationContext::try_from_legacy(5, 6).unwrap();
        let first = RealmProcessorActorInput::try_new(
            deferred(processing),
            external(processing, 11),
        )
        .unwrap();
        let second = RealmProcessorActorInput::try_new(
            deferred(processing),
            external(processing, 12),
        )
        .unwrap();
        assert_eq!(first.context().processing(), processing);
        assert_ne!(first.external_digest(), second.external_digest());
        assert_ne!(first.digest(), second.digest());

        let other = PendingGenerationContext::try_from_legacy(7, 8).unwrap();
        assert!(matches!(
            RealmProcessorActorInput::try_new(
                deferred(other),
                external(processing, 11),
            ),
            Err(RealmProcessorActorInputError::GenerationMismatch),
        ));
    }
}
