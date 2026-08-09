//! Opaque Scylla + recoverable-NATS Realm Edge publisher.
//!
//! The Edge is a reader of generation assignment authority. It may publish
//! only into the pipeline's exact write-open gathering generation and may not
//! reserve a missing generation, retarget to a fresh counter, or fall back to
//! the legacy subject.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::{
        AuthorityScope, PendingContext, WorkProcCheckpointUniqueId,
        WorkUniquePendingId,
    },
};
use psy_node_core::{
    queue::{
        realm_user_update_publish::{
            RealmUserUpdatePublishAdmission,
            RealmUserUpdatePublishError, RealmUserUpdatePublishPort,
            RealmUserUpdatePublishReceipt, RealmUserUpdatePublishRequest,
        },
        recoverable_ephemeral::PendingQueueCaptureContext,
    },
    store::{
        pending_generation_identity::PendingGenerationLedgerKey,
        pending_generation_pipeline::{
            PendingPipelineReadState, StoredPendingPipeline,
        },
    },
};
use psy_node_nats::{
    recoverable_assignment::PendingQueueSegmentLedgerKey,
    recoverable_publish::{
        PendingQueuePublishIntentId, PendingQueuePublisherKind,
    },
    recoverable_segment::RecoverableNatsStreamSegment,
    recoverable_transport::RecoverablePendingQueueNatsPublisher,
};
use scylla::client::session::Session;

use super::{
    BranchExactDeploymentNoTabletKeyspace, PendingQueuePublishDataKeyspace,
    PendingQueuePublishKeyspaces, PendingQueuePublishStoreError,
    PendingQueueSidecarReady, ScyllaPendingPipelineStore,
    ScyllaPendingQueuePublishStore, ScyllaPendingQueueSegmentLedgerStore,
};

const MAX_BIND_ATTEMPTS: usize = 64;

pub struct ScyllaRealmEdgeDurablePublisher<F, Hash> {
    network: NetworkId,
    authority: AuthorityScope,
    setup_ready_digest: [u8; 32],
    pipeline: ScyllaPendingPipelineStore,
    ledger: ScyllaPendingQueueSegmentLedgerStore,
    ledger_key: PendingQueueSegmentLedgerKey,
    publish: ScyllaPendingQueuePublishStore,
    segment: RecoverableNatsStreamSegment,
    _types: PhantomData<(F, Hash)>,
}

/// Authorizing publication evidence. Unlike the public DTO, this type can
/// only be minted after the concrete Scylla/NATS publisher has completed its
/// exact commit/readback path.
pub(crate) struct ScyllaRealmUserUpdatePublicationPermit {
    receipt: RealmUserUpdatePublishReceipt,
}

impl ScyllaRealmUserUpdatePublicationPermit {
    pub(crate) const fn receipt(&self) -> &RealmUserUpdatePublishReceipt {
        &self.receipt
    }

    fn into_receipt(self) -> RealmUserUpdatePublishReceipt {
        self.receipt
    }
}

impl<F: QFelt64, Hash: Q256BitHash> ScyllaRealmEdgeDurablePublisher<F, Hash> {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        ready: Arc<PendingQueueSidecarReady>,
        nats: Arc<RecoverablePendingQueueNatsPublisher>,
        segment: RecoverableNatsStreamSegment,
    ) -> Result<Self, RealmUserUpdatePublishError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmUserUpdatePublishError::AuthorityMismatch);
        };
        if ready.view().authority() != authority {
            return Err(RealmUserUpdatePublishError::AuthorityMismatch);
        }
        let generation_key = PendingGenerationLedgerKey::new(network, authority);
        if segment.generation_key() != generation_key {
            return Err(RealmUserUpdatePublishError::NetworkMismatch);
        }
        if nats.segment() != &segment {
            return Err(RealmUserUpdatePublishError::NotReady(
                "NATS publisher segment does not match the configured assignment segment"
                    .to_owned(),
            ));
        }
        let keyspaces = ready
            .view()
            .verified()
            .stored()
            .keyspaces()
            .clone();
        let control = BranchExactDeploymentNoTabletKeyspace::try_new(
            keyspaces.control().as_str().to_owned(),
        )
        .map_err(|error| RealmUserUpdatePublishError::NotReady(error.to_string()))?;
        let publish_keyspaces = PendingQueuePublishKeyspaces::new(
            control.clone(),
            PendingQueuePublishDataKeyspace::try_new(
                keyspaces.data().as_str().to_owned(),
            )
            .map_err(storage)?,
        );
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            generation_key,
            segment.base_namespace().to_owned(),
        )
        .map_err(|error| RealmUserUpdatePublishError::Storage(error.to_string()))?;
        let pipeline = ScyllaPendingPipelineStore::prepare(session.clone(), control.clone())
            .await
            .map_err(|error| RealmUserUpdatePublishError::Storage(error.to_string()))?;
        let ledger = ScyllaPendingQueueSegmentLedgerStore::prepare(
            session.clone(),
            control,
        )
        .await
        .map_err(|error| RealmUserUpdatePublishError::Storage(error.to_string()))?;
        let publish = ScyllaPendingQueuePublishStore::prepare(
            session,
            nats,
            segment.clone(),
            publish_keyspaces,
        )
        .await
        .map_err(storage)?;
        Ok(Self {
            network,
            authority,
            setup_ready_digest: *ready.view().ready_digest(),
            pipeline,
            ledger,
            ledger_key,
            publish,
            segment,
            _types: PhantomData,
        })
    }

    pub const fn setup_ready_digest(&self) -> &[u8; 32] {
        &self.setup_ready_digest
    }

    async fn admit_exact(
        &self,
    ) -> Result<RealmUserUpdatePublishAdmission<Hash>, RealmUserUpdatePublishError> {
        let key = PendingGenerationLedgerKey::new(self.network, self.authority);
        let PendingPipelineReadState::Current(pipeline) =
            self.pipeline.read::<Hash>(key).await.map_err(|error| {
                RealmUserUpdatePublishError::Storage(error.to_string())
            })?
        else {
            return Err(RealmUserUpdatePublishError::NotReady(
                "pending pipeline is uninitialized".to_owned(),
            ));
        };
        if pipeline.blocked_reason().is_some() {
            return Err(RealmUserUpdatePublishError::NotReady(
                "pending pipeline is blocked".to_owned(),
            ));
        }
        let generation = pipeline.gathering();
        let capture = PendingQueueCaptureContext::try_new(
            key,
            pipeline.activation_digest(),
            generation,
        )
        .map_err(|error| RealmUserUpdatePublishError::Storage(error.to_string()))?;
        let assignment = self
            .ledger
            .read_assignment_exact(&self.ledger_key, capture)
            .await
            .map_err(|error| RealmUserUpdatePublishError::NotReady(error.to_string()))?;
        if assignment.assignment().segment_id() != self.segment.segment_id()
            || assignment.assignment().contract_digest() != self.segment.digest()
        {
            return Err(RealmUserUpdatePublishError::NotReady(
                "segment assignment does not match configured publisher".to_owned(),
            ));
        }
        RealmUserUpdatePublishAdmission::try_from_pipeline(
            PendingContext::new(
                *pipeline.frontier().chain(),
                self.authority,
                WorkUniquePendingId::new(generation.pending_id().get()),
                WorkProcCheckpointUniqueId::from_u128(
                    generation.proc_checkpoint_id().as_u128(),
                ),
            ),
            capture,
        )
    }

    pub(crate) async fn revalidate_admission(
        &self,
        admission: &RealmUserUpdatePublishAdmission<Hash>,
    ) -> Result<(), RealmUserUpdatePublishError> {
        let current = self.admit_exact().await?;
        if &current != admission {
            return Err(RealmUserUpdatePublishError::GenerationMismatch);
        }
        Ok(())
    }

    /// Fresh exact pipeline read used by terminal qualification and by its
    /// pre-publish consumer. It never reserves, retargets or mutates a
    /// generation.
    pub(crate) async fn qualification_pipeline(
        &self,
        capture: PendingQueueCaptureContext,
    ) -> Result<StoredPendingPipeline<Hash>, RealmUserUpdatePublishError> {
        let key = PendingGenerationLedgerKey::new(self.network, self.authority);
        if capture.key() != key {
            return Err(RealmUserUpdatePublishError::GenerationMismatch);
        }
        let PendingPipelineReadState::Current(pipeline) =
            self.pipeline.read::<Hash>(key).await.map_err(|error| {
                RealmUserUpdatePublishError::Storage(error.to_string())
            })?
        else {
            return Err(RealmUserUpdatePublishError::NotReady(
                "pending pipeline is uninitialized".to_owned(),
            ));
        };
        if pipeline.blocked_reason().is_some()
            || pipeline.activation_digest() != capture.activation()
            || pipeline.gathering() != capture.processing()
        {
            return Err(RealmUserUpdatePublishError::GenerationMismatch);
        }
        Ok(pipeline)
    }

    pub(crate) async fn publish_authorized(
        &self,
        request: RealmUserUpdatePublishRequest<F, Hash>,
    ) -> Result<ScyllaRealmUserUpdatePublicationPermit, RealmUserUpdatePublishError> {
        if request.pending().chain().network_id() != self.network {
            return Err(RealmUserUpdatePublishError::NetworkMismatch);
        }
        if request.pending().authority() != self.authority {
            return Err(RealmUserUpdatePublishError::AuthorityMismatch);
        }
        let key = PendingGenerationLedgerKey::new(self.network, self.authority);
        let PendingPipelineReadState::Current(pipeline) =
            self.pipeline.read::<Hash>(key).await.map_err(|error| {
                RealmUserUpdatePublishError::Storage(error.to_string())
            })?
        else {
            return Err(RealmUserUpdatePublishError::NotReady(
                "pending pipeline is uninitialized".to_owned(),
            ));
        };
        if pipeline.blocked_reason().is_some() {
            return Err(RealmUserUpdatePublishError::NotReady(
                "pending pipeline is blocked".to_owned(),
            ));
        }
        // Realm Edge ingress writes the gathering generation. Processor
        // capture consumes the same generation only after rotation promotes it
        // to processing; retargeting here would duplicate or lose a user item.
        if pipeline.gathering() != request.generation() {
            return Err(RealmUserUpdatePublishError::GenerationMismatch);
        }
        if pipeline.frontier().chain() != request.pending().chain()
            || pipeline.frontier().authority() != request.pending().authority()
        {
            return Err(RealmUserUpdatePublishError::BranchMismatch);
        }
        let capture = PendingQueueCaptureContext::try_new(
            key,
            pipeline.activation_digest(),
            pipeline.gathering(),
        )
        .map_err(|error| RealmUserUpdatePublishError::Storage(error.to_string()))?;
        if request.admission().capture() != capture {
            return Err(RealmUserUpdatePublishError::GenerationMismatch);
        }
        let assignment = self
            .ledger
            .read_assignment_exact(&self.ledger_key, capture)
            .await
            .map_err(|error| RealmUserUpdatePublishError::NotReady(error.to_string()))?;
        if assignment.assignment().segment_id() != self.segment.segment_id()
            || assignment.assignment().contract_digest() != self.segment.digest()
        {
            return Err(RealmUserUpdatePublishError::NotReady(
                "segment assignment does not match configured publisher".to_owned(),
            ));
        }
        let kind = PendingQueuePublisherKind::RealmUserUpdate;
        self.publish
            .bootstrap_source(&assignment, kind)
            .await
            .map_err(storage)?;
        let intent_id = PendingQueuePublishIntentId::try_new(
            *request.intent_id().as_bytes(),
        )
        .map_err(|error| RealmUserUpdatePublishError::Storage(error.to_string()))?;
        let intent_slot = self
            .publish
            .materialize_data(&assignment, kind, intent_id, request.payload())
            .await
            .map_err(storage)?;
        let PendingPipelineReadState::Current(fresh) =
            self.pipeline.read::<Hash>(key).await.map_err(|error| {
                RealmUserUpdatePublishError::Storage(error.to_string())
            })?
        else {
            return Err(RealmUserUpdatePublishError::NotReady(
                "pending pipeline disappeared".to_owned(),
            ));
        };
        if fresh.blocked_reason().is_some()
            || fresh.gathering() != request.generation()
            || fresh.activation_digest() != capture.activation()
            || fresh.frontier().chain() != request.pending().chain()
        {
            return Err(RealmUserUpdatePublishError::GenerationMismatch);
        }
        let permit = {
            let mut attempt = 0;
            loop {
                attempt += 1;
                match self
                    .publish
                    .bind_materialized(&assignment, kind, intent_slot)
                    .await
                {
                    Ok(permit) => break permit,
                    Err(PendingQueuePublishStoreError::CasConflict)
                        if attempt < MAX_BIND_ATTEMPTS =>
                    {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => return Err(storage(error)),
                }
            }
        };
        let committed = self
            .publish
            .publish_and_commit(&assignment, permit)
            .await
            .map_err(storage)?;
        let receipt = RealmUserUpdatePublishReceipt::durable(
            request.intent_id(),
            *assignment.assignment().digest().as_bytes(),
            committed.subject_sequence(),
            *committed.envelope_digest(),
            !matches!(
                committed.disposition(),
                super::PendingQueueNatsPublishDisposition::PubAck
            ),
        )?;
        Ok(ScyllaRealmUserUpdatePublicationPermit { receipt })
    }

    /// Read historical committed evidence without requiring the request's
    /// generation to remain the current gathering generation. This never
    /// materializes, binds, or publishes a new intent.
    pub(crate) async fn observe_authorized(
        &self,
        request: RealmUserUpdatePublishRequest<F, Hash>,
    ) -> Result<Option<ScyllaRealmUserUpdatePublicationPermit>, RealmUserUpdatePublishError> {
        if request.pending().chain().network_id() != self.network {
            return Err(RealmUserUpdatePublishError::NetworkMismatch);
        }
        if request.pending().authority() != self.authority {
            return Err(RealmUserUpdatePublishError::AuthorityMismatch);
        }
        let assignment = self
            .ledger
            .read_assignment_exact(&self.ledger_key, request.admission().capture())
            .await
            .map_err(|error| RealmUserUpdatePublishError::NotReady(error.to_string()))?;
        if assignment.assignment().segment_id() != self.segment.segment_id()
            || assignment.assignment().contract_digest() != self.segment.digest()
        {
            return Err(RealmUserUpdatePublishError::NotReady(
                "historical assignment does not match configured publisher".to_owned(),
            ));
        }
        let intent_id = PendingQueuePublishIntentId::try_new(
            *request.intent_id().as_bytes(),
        )
        .map_err(|error| RealmUserUpdatePublishError::Storage(error.to_string()))?;
        let committed = self
            .publish
            .observe_committed_data(
                &assignment,
                PendingQueuePublisherKind::RealmUserUpdate,
                intent_id,
                request.payload(),
            )
            .await
            .map_err(storage)?;
        let Some(committed) = committed else {
            return Ok(None);
        };
        let receipt = RealmUserUpdatePublishReceipt::durable(
            request.intent_id(),
            *assignment.assignment().digest().as_bytes(),
            committed.subject_sequence(),
            *committed.envelope_digest(),
            true,
        )?;
        Ok(Some(ScyllaRealmUserUpdatePublicationPermit { receipt }))
    }
}

#[async_trait]
impl<F, Hash> RealmUserUpdatePublishPort<F, Hash>
    for ScyllaRealmEdgeDurablePublisher<F, Hash>
where
    F: QFelt64 + Send + Sync,
    Hash: Q256BitHash,
{
    async fn admit(
        &self,
    ) -> Result<RealmUserUpdatePublishAdmission<Hash>, RealmUserUpdatePublishError> {
        self.admit_exact().await
    }

    async fn publish(
        &self,
        request: RealmUserUpdatePublishRequest<F, Hash>,
    ) -> Result<RealmUserUpdatePublishReceipt, RealmUserUpdatePublishError> {
        self.publish_authorized(request)
            .await
            .map(ScyllaRealmUserUpdatePublicationPermit::into_receipt)
    }
}

fn storage(error: PendingQueuePublishStoreError) -> RealmUserUpdatePublishError {
    match error {
        PendingQueuePublishStoreError::Nats(message) => {
            RealmUserUpdatePublishError::Transport(message)
        }
        other => RealmUserUpdatePublishError::Storage(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_facade_is_gathering_exact_and_has_no_legacy_fallback() {
        let source = include_str!("realm_edge_durable_publisher.rs");
        assert!(source.contains("pipeline.gathering() != request.generation()"));
        assert!(source.contains("read_assignment_exact"));
        assert!(source.contains("materialize_data"));
        assert!(source.contains("bind_materialized"));
        assert!(source.contains("publish_and_commit"));
        for forbidden in [
            ["reserve", "_generation("].concat(),
            ["publish_ephemeral", "_queue"].concat(),
            ["ensure", "_consumer"].concat(),
        ] {
            assert!(!source.contains(&forbidden), "forbidden escape {forbidden}");
        }
    }

    #[test]
    fn source_cas_retry_is_bounded() {
        assert_eq!(MAX_BIND_ATTEMPTS, 64);
    }
}
