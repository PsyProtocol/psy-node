//! Storage-selected projection of exact Realm Edge dependencies for a future
//! generation rotation record.
//!
//! This adapter is read-only. It rebuilds queue payloads and contract-update
//! bytes through the qualified durable consumer, brackets the complete scan,
//! and returns a storage-private receipt. It cannot mint a terminal, reserve a
//! generation, rotate a pipeline, or authorize a writer/head transition.

use std::{error::Error, fmt, marker::PhantomData, sync::Arc};

use parth_core::{
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::queue::{
    realm_processor_external_dependency_input::{
        RealmProcessorExternalDependencyCommitment,
        RealmProcessorExternalDependencyProjection,
    },
    realm_user_update_admission::{
        RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
    },
    realm_user_update_consumer::{
        RealmUserUpdateDurableConsumerError, RealmUserUpdateDurableConsumerPort,
    },
    realm_user_update_publish::GlobalUserTreeHeight,
    recoverable_ephemeral::PendingQueueCaptureContext,
};
use psy_node_nats::recoverable_segment::RecoverableNatsStreamSegment;
use scylla::client::session::Session;
use sha2::{Digest, Sha256};

use super::{
    PendingQueueSidecarReady, ScyllaRealmUserUpdateDurableConsumer,
};

const PROJECTOR_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-external-dependency-projector/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RealmProcessorExternalDependencyProjectorFingerprint([u8; 32]);

impl RealmProcessorExternalDependencyProjectorFingerprint {
    fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorExternalDependencyProjectionError> {
        if bytes == [0; 32] {
            Err(RealmProcessorExternalDependencyProjectionError::IdentityMismatch)
        } else {
            Ok(Self(bytes))
        }
    }
}

/// Storage-private exact-read receipt. Future terminal code may consume its
/// compact commitment, but public DTOs alone must never substitute for this
/// receipt at a mutation boundary.
pub(super) struct PersistedRealmProcessorExternalDependencyProjection {
    projector_fingerprint: RealmProcessorExternalDependencyProjectorFingerprint,
    selection: RealmProcessorExternalDependencySelection,
    projection: RealmProcessorExternalDependencyProjection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RealmProcessorExternalDependencySelection {
    CurrentGathering,
    CurrentProcessing,
    Committed,
}

impl PersistedRealmProcessorExternalDependencyProjection {
    pub(super) const fn commitment(&self) -> RealmProcessorExternalDependencyCommitment {
        self.projection.commitment()
    }

    pub(super) fn projection(&self) -> &RealmProcessorExternalDependencyProjection {
        &self.projection
    }

    pub(super) fn into_projection(self) -> RealmProcessorExternalDependencyProjection {
        self.projection
    }
}

pub(super) struct ScyllaRealmProcessorExternalDependencyProjector<F, Hash> {
    fingerprint: RealmProcessorExternalDependencyProjectorFingerprint,
    consumer: ScyllaRealmUserUpdateDurableConsumer<F, Hash>,
    _types: PhantomData<(F, Hash)>,
}

impl<F, Hash> ScyllaRealmProcessorExternalDependencyProjector<F, Hash>
where
    F: QFelt64 + Send + Sync,
    Hash: Q256BitHash + QFHashBase<F> + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        global_user_tree_height: GlobalUserTreeHeight,
        ready: Arc<PendingQueueSidecarReady>,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, RealmProcessorExternalDependencyProjectionError> {
        if !matches!(authority, AuthorityScope::Realm { .. })
            || ready.view().authority() != authority
            || segment.generation_key().network() != network
            || segment.generation_key().authority() != authority
        {
            return Err(RealmProcessorExternalDependencyProjectionError::IdentityMismatch);
        }
        let fingerprint = projector_fingerprint(
            network,
            authority,
            global_user_tree_height,
            *ready.view().ready_digest(),
            *segment.digest().as_bytes(),
        )?;
        let consumer = ScyllaRealmUserUpdateDurableConsumer::prepare(
            session,
            network,
            authority,
            global_user_tree_height,
            ready,
            segment,
        )
        .await
        .map_err(RealmProcessorExternalDependencyProjectionError::Consumer)?;
        Ok(Self {
            fingerprint,
            consumer,
            _types: PhantomData,
        })
    }

    pub(super) async fn read_exact(
        &self,
        context: PendingQueueCaptureContext,
        close: RealmUserUpdateAdmissionCloseIntent,
        expected_assignment_digest: [u8; 32],
    ) -> Result<
        PersistedRealmProcessorExternalDependencyProjection,
        RealmProcessorExternalDependencyProjectionError,
    > {
        let first = self
            .consumer
            .read_qualified_generation(
                RealmUserUpdateAdmissionKey::try_new(context).map_err(model)?,
                close,
            )
            .await
            .map_err(RealmProcessorExternalDependencyProjectionError::Consumer)?;
        let first = RealmProcessorExternalDependencyProjection::try_from_qualified_generation(
            context,
            expected_assignment_digest,
            &first,
        )
        .map_err(model)?;
        let second = self
            .consumer
            .read_qualified_generation(
                RealmUserUpdateAdmissionKey::try_new(context).map_err(model)?,
                close,
            )
            .await
            .map_err(RealmProcessorExternalDependencyProjectionError::Consumer)?;
        let second = RealmProcessorExternalDependencyProjection::try_from_qualified_generation(
            context,
            expected_assignment_digest,
            &second,
        )
        .map_err(model)?;
        if first != second {
            return Err(RealmProcessorExternalDependencyProjectionError::ConcurrentMutation);
        }
        Ok(PersistedRealmProcessorExternalDependencyProjection {
            projector_fingerprint: self.fingerprint,
            selection: RealmProcessorExternalDependencySelection::CurrentGathering,
            projection: second,
        })
    }

    /// Select and rebuild the currently-processing qualified generation. The
    /// close identity is read from the durable admission header rather than
    /// accepted from the caller; this is the bootstrap counterpart to the
    /// predecessor-terminal commitment path below.
    pub(super) async fn read_current_selected_exact(
        &self,
        context: PendingQueueCaptureContext,
        expected_assignment_digest: [u8; 32],
    ) -> Result<
        PersistedRealmProcessorExternalDependencyProjection,
        RealmProcessorExternalDependencyProjectionError,
    > {
        let key = RealmUserUpdateAdmissionKey::try_new(context).map_err(model)?;
        let first = self
            .consumer
            .read_current_selected(key)
            .await
            .map_err(RealmProcessorExternalDependencyProjectionError::Consumer)?;
        let first = RealmProcessorExternalDependencyProjection::try_from_qualified_generation(
            context,
            expected_assignment_digest,
            &first,
        )
        .map_err(model)?;
        let second = self
            .consumer
            .read_current_selected(key)
            .await
            .map_err(RealmProcessorExternalDependencyProjectionError::Consumer)?;
        let second = RealmProcessorExternalDependencyProjection::try_from_qualified_generation(
            context,
            expected_assignment_digest,
            &second,
        )
        .map_err(model)?;
        if first != second {
            return Err(RealmProcessorExternalDependencyProjectionError::ConcurrentMutation);
        }
        Ok(PersistedRealmProcessorExternalDependencyProjection {
            projector_fingerprint: self.fingerprint,
            selection: RealmProcessorExternalDependencySelection::CurrentProcessing,
            projection: second,
        })
    }

    pub(super) async fn revalidate_exact(
        &self,
        receipt: &PersistedRealmProcessorExternalDependencyProjection,
    ) -> Result<(), RealmProcessorExternalDependencyProjectionError> {
        if receipt.projector_fingerprint != self.fingerprint {
            return Err(RealmProcessorExternalDependencyProjectionError::IdentityMismatch);
        }
        let commitment = receipt.commitment();
        let fresh = match receipt.selection {
            RealmProcessorExternalDependencySelection::CurrentGathering => {
                self.read_exact(
                    commitment.context(),
                    commitment.admission_close_intent(),
                    *commitment.assignment_digest(),
                )
                .await?
            }
            RealmProcessorExternalDependencySelection::CurrentProcessing => {
                self.read_current_selected_exact(
                    commitment.context(),
                    *commitment.assignment_digest(),
                )
                .await?
            }
            RealmProcessorExternalDependencySelection::Committed => {
                self.read_committed_exact(commitment).await?
            }
        };
        if fresh.projection != receipt.projection {
            return Err(RealmProcessorExternalDependencyProjectionError::ConcurrentMutation);
        }
        Ok(())
    }

    /// Rebuild a projection selected by a terminal authorization after the
    /// gathering generation has rotated into processing. The complete
    /// commitment is the expected value: a matching qualification digest
    /// alone is insufficient.
    pub(super) async fn read_committed_exact(
        &self,
        expected: RealmProcessorExternalDependencyCommitment,
    ) -> Result<
        PersistedRealmProcessorExternalDependencyProjection,
        RealmProcessorExternalDependencyProjectionError,
    > {
        let key = RealmUserUpdateAdmissionKey::try_new(expected.context())
            .map_err(model)?;
        let first = self
            .consumer
            .read_historical_exact(
                key,
                expected.admission_close_intent(),
                expected.qualification_digest(),
            )
            .await
            .map_err(RealmProcessorExternalDependencyProjectionError::Consumer)?;
        let first = RealmProcessorExternalDependencyProjection::try_from_qualified_generation(
            expected.context(),
            *expected.assignment_digest(),
            &first,
        )
        .map_err(model)?;
        if first.commitment() != expected {
            return Err(RealmProcessorExternalDependencyProjectionError::CommitmentMismatch);
        }

        let second = self
            .consumer
            .read_historical_exact(
                key,
                expected.admission_close_intent(),
                expected.qualification_digest(),
            )
            .await
            .map_err(RealmProcessorExternalDependencyProjectionError::Consumer)?;
        let second = RealmProcessorExternalDependencyProjection::try_from_qualified_generation(
            expected.context(),
            *expected.assignment_digest(),
            &second,
        )
        .map_err(model)?;
        if second.commitment() != expected || first != second {
            return Err(RealmProcessorExternalDependencyProjectionError::ConcurrentMutation);
        }
        Ok(PersistedRealmProcessorExternalDependencyProjection {
            projector_fingerprint: self.fingerprint,
            selection: RealmProcessorExternalDependencySelection::Committed,
            projection: second,
        })
    }
}

fn projector_fingerprint(
    network: NetworkId,
    authority: AuthorityScope,
    global_user_tree_height: GlobalUserTreeHeight,
    ready_digest: [u8; 32],
    segment_digest: [u8; 32],
) -> Result<
    RealmProcessorExternalDependencyProjectorFingerprint,
    RealmProcessorExternalDependencyProjectionError,
> {
    if ready_digest == [0; 32] || segment_digest == [0; 32] {
        return Err(RealmProcessorExternalDependencyProjectionError::IdentityMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(PROJECTOR_FINGERPRINT_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    match authority {
        AuthorityScope::Coordinator => {
            return Err(RealmProcessorExternalDependencyProjectionError::IdentityMismatch)
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
    hasher.update([global_user_tree_height.get()]);
    hasher.update(ready_digest);
    hasher.update(segment_digest);
    RealmProcessorExternalDependencyProjectorFingerprint::try_new(hasher.finalize().into())
}

fn model(error: impl fmt::Display) -> RealmProcessorExternalDependencyProjectionError {
    RealmProcessorExternalDependencyProjectionError::Model(error.to_string())
}

#[derive(Debug)]
pub(super) enum RealmProcessorExternalDependencyProjectionError {
    IdentityMismatch,
    CommitmentMismatch,
    ConcurrentMutation,
    Consumer(RealmUserUpdateDurableConsumerError),
    Model(String),
}

impl fmt::Display for RealmProcessorExternalDependencyProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorExternalDependencyProjectionError {}

#[cfg(test)]
mod tests {
    use psy_data::protocol::canonical_chain::NetworkId;

    use super::*;

    #[test]
    fn projector_fingerprint_binds_runtime_readiness_segment_and_height() {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        let authority = AuthorityScope::Realm {
            realm_id: 2,
            realm_sub_id: 3,
        };
        let height = GlobalUserTreeHeight::try_new(32).unwrap();
        let first = projector_fingerprint(network, authority, height, [4; 32], [5; 32])
            .unwrap();
        assert_eq!(
            first,
            projector_fingerprint(network, authority, height, [4; 32], [5; 32])
                .unwrap(),
        );
        assert_ne!(
            first,
            projector_fingerprint(network, authority, height, [4; 32], [6; 32])
                .unwrap(),
        );
        assert!(projector_fingerprint(
            network,
            AuthorityScope::Coordinator,
            height,
            [4; 32],
            [5; 32],
        )
        .is_err());
    }

    #[test]
    fn historical_projection_is_selected_by_the_complete_commitment() {
        let source = include_str!("realm_processor_external_dependency_projection.rs");
        let method = source
            .split("pub(super) async fn read_committed_exact")
            .nth(1)
            .unwrap()
            .split("fn projector_fingerprint")
            .next()
            .unwrap();
        assert_eq!(method.matches("read_historical_exact").count(), 2);
        assert_eq!(method.matches("commitment() != expected").count(), 2);
        assert!(method.contains("first != second"));
        assert!(!method.contains("read_qualified_generation("));
    }
}
