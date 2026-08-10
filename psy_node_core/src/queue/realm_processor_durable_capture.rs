//! Affine high-level boundary for Realm Processor durable queue capture.
//!
//! The backend owns the concrete delivery token, durable readback receipt and
//! ACK authority.  A Processor iteration can only ask for the next canonical
//! outcome; it cannot manufacture a receipt, select a raw subject, or ACK a
//! delivery independently.

use std::{error::Error, fmt};

use async_trait::async_trait;
use psy_data::protocol::canonical_chain::NetworkId;
use sha2::{Digest, Sha256};

use crate::store::realm_processor_startup::{
    RealmProcessorStartupPermitDigest,
};

use super::recoverable_ephemeral::{
    PendingQueueCaptureCandidate, PendingQueueCaptureContext,
    PendingQueueGenerationBoundary,
};

const COMPLETE_GENERATION_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-complete-generation/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorDurableGenerationDigest([u8; 32]);

impl RealmProcessorDurableGenerationDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One structurally verified artifact batch plus the exact business payloads
/// decoded from its transport envelopes.
///
/// The public constructor is checked because the concrete storage adapter
/// lives in another crate.  Possessing this value is not authority to mutate a
/// gatherer: that method remains crate-private to the real Processor path.
#[derive(Debug)]
pub struct RealmProcessorDurableCapturedBatch {
    candidate: PendingQueueCaptureCandidate,
    business_items: Vec<Vec<u8>>,
}

impl RealmProcessorDurableCapturedBatch {
    pub fn try_from_verified_envelopes(
        candidate: PendingQueueCaptureCandidate,
        business_items: Vec<Vec<u8>>,
    ) -> Result<Self, RealmProcessorDurableCaptureError> {
        if candidate.item_count() == 0
            || candidate.item_count() != business_items.len() as u64
            || business_items.iter().any(Vec::is_empty)
        {
            return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
        }
        Ok(Self {
            candidate,
            business_items,
        })
    }

    pub const fn candidate(&self) -> &PendingQueueCaptureCandidate {
        &self.candidate
    }

    pub fn business_items(&self) -> &[Vec<u8>] {
        &self.business_items
    }

    pub fn into_business_items(self) -> Vec<Vec<u8>> {
        self.business_items
    }
}

/// Full, ordered, restart-replayable input for one closed Realm source.
///
/// It is intentionally non-Clone.  The concrete adapter may return it only
/// after exhaustive artifact reconstruction; a live `capture_next` result is
/// insufficient because its NATS delivery may already have been ACKed.
#[derive(Debug)]
pub struct RealmProcessorDurableCapturedGeneration {
    context: PendingQueueCaptureContext,
    batches: Vec<RealmProcessorDurableCapturedBatch>,
    boundary: PendingQueueGenerationBoundary,
    item_count: u64,
    digest: RealmProcessorDurableGenerationDigest,
}

impl RealmProcessorDurableCapturedGeneration {
    pub fn try_from_exhaustive_readback(
        context: PendingQueueCaptureContext,
        batches: Vec<RealmProcessorDurableCapturedBatch>,
        boundary: PendingQueueGenerationBoundary,
    ) -> Result<Self, RealmProcessorDurableCaptureError> {
        if boundary.context() != context
            || batches.iter().any(|batch| {
                batch.candidate().context() != context
                    || batch.candidate().source_identity() != boundary.source_identity()
            })
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        let mut item_count = 0_u64;
        let mut hasher = Sha256::new();
        hasher.update(COMPLETE_GENERATION_DOMAIN);
        hasher.update(context.digest().as_bytes());
        hasher.update(boundary.digest().as_bytes());
        hasher.update((batches.len() as u64).to_be_bytes());
        for batch in &batches {
            item_count = item_count
                .checked_add(batch.candidate().item_count())
                .ok_or(RealmProcessorDurableCaptureError::MalformedCompleteGeneration)?;
            if batch.candidate().item_count() != batch.business_items().len() as u64 {
                return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
            }
            hasher.update(batch.candidate().batch_digest().as_bytes());
            hasher.update(batch.candidate().payload_digest().as_bytes());
            hasher.update(batch.candidate().item_count().to_be_bytes());
            for item in batch.business_items() {
                hasher.update((item.len() as u64).to_be_bytes());
                hasher.update(item);
            }
        }
        hasher.update(item_count.to_be_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        if digest == [0; 32] {
            return Err(RealmProcessorDurableCaptureError::MalformedCompleteGeneration);
        }
        Ok(Self {
            context,
            batches,
            boundary,
            item_count,
            digest: RealmProcessorDurableGenerationDigest(digest),
        })
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn boundary(&self) -> &PendingQueueGenerationBoundary {
        &self.boundary
    }

    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    pub const fn digest(&self) -> RealmProcessorDurableGenerationDigest {
        self.digest
    }

    pub fn batches(&self) -> &[RealmProcessorDurableCapturedBatch] {
        &self.batches
    }

    pub fn into_business_items(self) -> Vec<Vec<u8>> {
        self.batches
            .into_iter()
            .flat_map(RealmProcessorDurableCapturedBatch::into_business_items)
            .collect()
    }
}

/// The only outcomes visible above the durable backend boundary.
#[derive(Debug)]
pub enum RealmProcessorDurableCaptureOutcome {
    Data(PendingQueueCaptureCandidate),
    Sealed {
        data: Option<PendingQueueCaptureCandidate>,
        boundary: PendingQueueGenerationBoundary,
    },
}

/// One non-Clone backend owner.  Implementations must persist and exactly
/// read back a selected batch before consuming their private ACK token.
#[async_trait]
pub trait RealmProcessorDurableCapturePort: Send {
    async fn capture_next(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCaptureOutcome>, RealmProcessorDurableCaptureError>;

    /// Returns the complete ordered generation only after the exact source is
    /// durably closed and every artifact fragment has been enumerated and read
    /// back.  Implementations must make this idempotent across gather-task or
    /// process response loss.
    async fn replay_complete_generation(
        &mut self,
    ) -> Result<Option<RealmProcessorDurableCapturedGeneration>, RealmProcessorDurableCaptureError>;
}

/// Storage-owned factory installed by the same startup composition as the
/// commit runtime.  Opening a port is mutating authority, so callers only
/// receive it through an affine commit iteration.
#[async_trait]
pub trait RealmProcessorDurableCaptureFactory: Send + Sync {
    fn network(&self) -> NetworkId;
    fn realm_id(&self) -> u32;
    fn realm_sub_id(&self) -> u16;
    fn writer_activation_digest(&self) -> [u8; 32];
    fn queue_readiness_digest(&self) -> [u8; 32];

    async fn open(
        &self,
        request: SealedRealmProcessorDurableCaptureRequest,
    ) -> Result<Box<dyn RealmProcessorDurableCapturePort>, RealmProcessorDurableCaptureError>;
}

/// Unforgeable outside `psy_node_core`: all identity axes come from the
/// installed runtime and the one controlled Processor iteration.
#[derive(Debug)]
pub struct SealedRealmProcessorDurableCaptureRequest {
    startup_permit_digest: RealmProcessorStartupPermitDigest,
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    writer_activation_digest: [u8; 32],
    queue_readiness_digest: [u8; 32],
    context: PendingQueueCaptureContext,
}

impl SealedRealmProcessorDurableCaptureRequest {
    pub(crate) fn seal(
        startup_permit_digest: RealmProcessorStartupPermitDigest,
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        writer_activation_digest: [u8; 32],
        queue_readiness_digest: [u8; 32],
        context: PendingQueueCaptureContext,
    ) -> Result<Self, RealmProcessorDurableCaptureError> {
        if context.key().network() != network
            || context.key().authority()
                != (psy_data::protocol::chain_context::AuthorityScope::Realm {
                    realm_id,
                    realm_sub_id,
                })
        {
            return Err(RealmProcessorDurableCaptureError::IdentityMismatch);
        }
        Ok(Self {
            startup_permit_digest,
            network,
            realm_id,
            realm_sub_id,
            writer_activation_digest,
            queue_readiness_digest,
            context,
        })
    }

    pub const fn startup_permit_digest(&self) -> RealmProcessorStartupPermitDigest {
        self.startup_permit_digest
    }

    pub const fn network(&self) -> NetworkId {
        self.network
    }

    pub const fn realm_id(&self) -> u32 {
        self.realm_id
    }

    pub const fn realm_sub_id(&self) -> u16 {
        self.realm_sub_id
    }

    pub const fn writer_activation_digest(&self) -> &[u8; 32] {
        &self.writer_activation_digest
    }

    pub const fn queue_readiness_digest(&self) -> &[u8; 32] {
        &self.queue_readiness_digest
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorDurableCaptureError {
    IdentityMismatch,
    RuntimeCapabilityMismatch,
    MalformedCompleteGeneration,
    Backend(String),
}

impl fmt::Display for RealmProcessorDurableCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorDurableCaptureError {}

#[cfg(test)]
mod tests {
    #[test]
    fn request_has_no_public_unchecked_constructor_or_backend_token() {
        let source = include_str!("realm_processor_durable_capture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("pub fn new("));
        assert!(!production.contains("raw_session"));
        assert!(!production.contains("ack_token"));
        assert!(!production.contains("NatsJetStreamClient"));
        assert!(!production.contains("impl Clone for SealedRealmProcessorDurableCaptureRequest"));
    }
}
