//! Storage-owned durable capture authority for one Realm Processor iteration.
//!
//! This is intentionally not wired to the legacy gatherer yet.  It composes
//! the already-qualified assignment, stream binding, consumer gate, artifact
//! store and explicit-ACK transport behind the high-level core port.

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::{
        realm_processor_durable_capture::{
            RealmProcessorDurableCaptureError,
            RealmProcessorDurableCaptureFactory,
            RealmProcessorDurableCaptureOutcome,
            RealmProcessorDurableCapturePort,
            SealedRealmProcessorDurableCaptureRequest,
        },
        recoverable_artifact::{
            PendingQueueArtifactOwnerAttemptId,
            PendingQueueArtifactOwnerReasonDigest,
        },
        recoverable_ephemeral::PendingQueueArtifactIdentity,
    },
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_assignment::PendingQueueSegmentLedgerKey,
    recoverable_publish::{
        PendingQueuePublisherKind, RecoverableNatsSourceRoute,
    },
    recoverable_transport::{
        RecoverableNatsCaptureSpec,
        RecoverableNatsConsumerProvisioningOperationId,
    },
};
use scylla::client::session::Session;
use sha2::{Digest, Sha256};

use super::{
    PendingQueueArtifactStoreError, PendingQueueSidecarReady,
    ScyllaPendingPipelineStore, ScyllaPendingQueueArtifactStore,
    ScyllaPendingQueueSegmentLedgerStore,
};
use super::pending_queue_consumer_gate::{
    PendingQueueConsumerGateError, PendingQueueConsumerGateIdentity,
    ScyllaPendingQueueConsumerGateStore,
};
use super::pending_queue_nats_capture::{
    PendingQueueNatsCaptureOutcome, ScyllaBackedRecoverableNatsSource,
};
use super::pending_queue_stream_provision::ScyllaPendingQueueStreamProvisionStore;

const OWNER_ATTEMPT_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-capture-owner-attempt/v1";
const OWNER_REASON_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-capture-owner-reason/v1";
const CONSUMER_OPERATION_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-capture-consumer-operation/v1";
const CAPTURE_BATCH_LIMIT: usize = 1024;

/// Prepared high-level factory.  It is bound to one exact Realm, writer
/// activation, verified sidecar schema and NATS base namespace.
pub(crate) struct ScyllaRealmProcessorDurableCaptureFactory<Hash> {
    network: NetworkId,
    authority: AuthorityScope,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
    nats: Arc<NatsJetStreamClient>,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    ledger: Arc<ScyllaPendingQueueSegmentLedgerStore>,
    provision: Arc<ScyllaPendingQueueStreamProvisionStore>,
    artifact: Arc<ScyllaPendingQueueArtifactStore>,
    consumer_gate: Arc<ScyllaPendingQueueConsumerGateStore>,
    _hash: PhantomData<Hash>,
}

impl<Hash: Q256BitHash> ScyllaRealmProcessorDurableCaptureFactory<Hash> {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        network: NetworkId,
        authority: AuthorityScope,
        writer_activation_digest: [u8; 32],
        ready: &PendingQueueSidecarReady,
        nats: Arc<NatsJetStreamClient>,
    ) -> Result<Self, RealmProcessorDurableCaptureError> {
        let AuthorityScope::Realm { .. } = authority else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        if ready.view().authority() != authority
            || writer_activation_digest == [0; 32]
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let keyspaces = ready.view().verified().stored().keyspaces();
        let control = keyspaces.control().clone();
        let ledger = Arc::new(
            ScyllaPendingQueueSegmentLedgerStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let provision = Arc::new(
            ScyllaPendingQueueStreamProvisionStore::prepare_authorized(
                session.clone(),
                ready,
                ledger.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let pipeline = Arc::new(
            ScyllaPendingPipelineStore::prepare(
                session.clone(),
                control.clone(),
            )
            .await
            .map_err(backend)?,
        );
        let consumer_gate = Arc::new(
            ScyllaPendingQueueConsumerGateStore::prepare(
                session.clone(),
                control,
            )
            .await
            .map_err(backend)?,
        );
        let artifact = Arc::new(
            ScyllaPendingQueueArtifactStore::prepare(
                session,
                keyspaces.artifact_keyspaces().map_err(backend)?,
            )
            .await
            .map_err(backend)?,
        );
        Ok(Self {
            network,
            authority,
            writer_activation_digest,
            queue_readiness_digest: *ready.view().ready_digest(),
            nats,
            pipeline,
            ledger,
            provision,
            artifact,
            consumer_gate,
            _hash: PhantomData,
        })
    }

    async fn open_exact(
        &self,
        request: SealedRealmProcessorDurableCaptureRequest,
    ) -> Result<ScyllaRealmProcessorDurableCapture<Hash>, RealmProcessorDurableCaptureError> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.authority
        else {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        };
        let context = request.context();
        if request.network() != self.network
            || request.realm_id() != realm_id
            || request.realm_sub_id() != realm_sub_id
            || request.writer_activation_digest() != &self.writer_activation_digest
            || request.queue_readiness_digest() != &self.queue_readiness_digest
            || context.key().network() != self.network
            || context.key().authority() != self.authority
            || context.activation().as_bytes() != &self.writer_activation_digest
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }

        let close = self
            .pipeline
            .read_queue_close_exact::<Hash>(context)
            .await
            .map_err(backend)?;
        let ledger_key = PendingQueueSegmentLedgerKey::try_new(
            context.key(),
            self.nats.base_namespace(),
        )
        .map_err(backend)?;
        let route = self
            .ledger
            .read_assignment_route_exact(&ledger_key, context)
            .await
            .map_err(backend)?;
        let provisioned = self
            .provision
            .read_provisioned(route.ledger_key(), route.segment())
            .await
            .map_err(backend)?;
        let live = self
            .nats
            .observe_recoverable_segment_instance(route.segment().clone())
            .await
            .map_err(backend)?;
        if live.instance_id() != provisioned.instance_id() {
            return Err(RealmProcessorDurableCaptureError::RuntimeCapabilityMismatch);
        }

        let source_route = RecoverableNatsSourceRoute::try_new(
            context,
            PendingQueuePublisherKind::RealmUserUpdate,
            route.segment(),
        )
        .map_err(backend)?;
        let spec = RecoverableNatsCaptureSpec::for_segment(
            route.segment().clone(),
            source_route.subject(),
            CAPTURE_BATCH_LIMIT,
        )
        .map_err(backend)?;
        let gate_identity = PendingQueueConsumerGateIdentity::new(
            route.segment().segment_id(),
            route.segment().digest(),
            live.instance_id(),
        );
        let gate_open = self
            .consumer_gate
            .bootstrap_open(gate_identity)
            .await
            .map_err(backend)?;
        let consumer = match self
            .consumer_gate
            .resume_capture_consumer(
                &self.nats,
                &gate_open,
                &live,
                spec.clone(),
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(PendingQueueConsumerGateError::ProvisioningNotFound) => {
                self.consumer_gate
                    .provision_capture_consumer(
                        &self.nats,
                        &gate_open,
                        &live,
                        spec.clone(),
                        consumer_operation(&request, &spec)?,
                    )
                    .await
                    .map_err(backend)?
            }
            Err(error) => return Err(backend(error)),
        };

        let identity = PendingQueueArtifactIdentity::try_new(
            context,
            spec.source_identity().map_err(backend)?,
        )
        .map_err(backend)?;
        let attempt = owner_attempt(&request, &identity)?;
        let reason = owner_reason(&request, &identity)?;
        let owner = match self
            .artifact
            .claim_owner(&identity, attempt, reason)
            .await
        {
            Ok(owner) => owner,
            Err(PendingQueueArtifactStoreError::OwnerAlreadyHeld) => self
                .artifact
                .startup_takeover_owner(&identity, attempt, reason)
                .await
                .map_err(backend)?,
            Err(error) => return Err(backend(error)),
        };
        let source = ScyllaBackedRecoverableNatsSource::new(
            self.nats.clone(),
            self.artifact.clone(),
            self.consumer_gate.clone(),
            spec,
            consumer,
            owner,
        )
        .map_err(backend)?;
        Ok(ScyllaRealmProcessorDurableCapture {
            source,
            pipeline: self.pipeline.clone(),
            context,
            close,
            _hash: PhantomData,
        })
    }
}

#[async_trait]
impl<Hash> RealmProcessorDurableCaptureFactory
    for ScyllaRealmProcessorDurableCaptureFactory<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    fn network(&self) -> NetworkId {
        self.network
    }

    fn realm_id(&self) -> u32 {
        match self.authority {
            AuthorityScope::Realm { realm_id, .. } => realm_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn realm_sub_id(&self) -> u16 {
        match self.authority {
            AuthorityScope::Realm { realm_sub_id, .. } => realm_sub_id,
            AuthorityScope::Coordinator => unreachable!("Realm-only factory"),
        }
    }

    fn writer_activation_digest(&self) -> [u8; 32] {
        self.writer_activation_digest
    }

    fn queue_readiness_digest(&self) -> [u8; 32] {
        self.queue_readiness_digest
    }

    async fn open(
        &self,
        request: SealedRealmProcessorDurableCaptureRequest,
    ) -> Result<Box<dyn RealmProcessorDurableCapturePort>, RealmProcessorDurableCaptureError> {
        Ok(Box::new(self.open_exact(request).await?))
    }
}

struct ScyllaRealmProcessorDurableCapture<Hash> {
    source: ScyllaBackedRecoverableNatsSource,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    context: psy_node_core::queue::recoverable_ephemeral::PendingQueueCaptureContext,
    close: super::PersistedPendingQueueCloseReceipt,
    _hash: PhantomData<Hash>,
}

#[async_trait]
impl<Hash> RealmProcessorDurableCapturePort
    for ScyllaRealmProcessorDurableCapture<Hash>
where
    Hash: Q256BitHash + Send + Sync + 'static,
{
    async fn capture_next(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCaptureOutcome>, RealmProcessorDurableCaptureError> {
        self.source
            .capture_one::<Hash>(&self.pipeline, self.context, &self.close)
            .await
            .map(|outcome| {
                outcome.map(|outcome| match outcome {
                    PendingQueueNatsCaptureOutcome::Data(data) => {
                        RealmProcessorDurableCaptureOutcome::Data(data)
                    }
                    PendingQueueNatsCaptureOutcome::Sealed { data, boundary } => {
                        RealmProcessorDurableCaptureOutcome::Sealed { data, boundary }
                    }
                })
            })
            .map_err(backend)
    }
}

fn consumer_operation(
    request: &SealedRealmProcessorDurableCaptureRequest,
    spec: &RecoverableNatsCaptureSpec,
) -> Result<RecoverableNatsConsumerProvisioningOperationId, RealmProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(CONSUMER_OPERATION_DOMAIN);
    hasher.update(request.startup_permit_digest().as_bytes());
    hasher.update(request.context().digest().as_bytes());
    hasher.update(spec.consumer_digest());
    RecoverableNatsConsumerProvisioningOperationId::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn owner_attempt(
    request: &SealedRealmProcessorDurableCaptureRequest,
    identity: &PendingQueueArtifactIdentity,
) -> Result<PendingQueueArtifactOwnerAttemptId, RealmProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_ATTEMPT_DOMAIN);
    hasher.update(request.startup_permit_digest().as_bytes());
    hasher.update(identity.digest().as_bytes());
    PendingQueueArtifactOwnerAttemptId::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn owner_reason(
    request: &SealedRealmProcessorDurableCaptureRequest,
    identity: &PendingQueueArtifactIdentity,
) -> Result<PendingQueueArtifactOwnerReasonDigest, RealmProcessorDurableCaptureError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_REASON_DOMAIN);
    hasher.update(request.writer_activation_digest());
    hasher.update(request.queue_readiness_digest());
    hasher.update(identity.digest().as_bytes());
    PendingQueueArtifactOwnerReasonDigest::try_new(hasher.finalize().into())
        .map_err(backend)
}

fn backend(error: impl std::fmt::Display) -> RealmProcessorDurableCaptureError {
    RealmProcessorDurableCaptureError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn high_level_owner_exposes_no_raw_backend_or_ack_authority() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let port = production
            .split("impl<Hash> RealmProcessorDurableCapturePort")
            .nth(1)
            .unwrap();
        assert!(!port.contains("double_ack"));
        assert!(!port.contains("Session"));
        assert!(!production.contains("pub fn new("));
        assert!(!production.contains("impl Clone for ScyllaRealmProcessorDurableCapture"));
    }
}
