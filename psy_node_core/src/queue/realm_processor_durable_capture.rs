//! Affine high-level boundary for Realm Processor durable queue capture.
//!
//! The backend owns the concrete delivery token, durable readback receipt and
//! ACK authority.  A Processor iteration can only ask for the next canonical
//! outcome; it cannot manufacture a receipt, select a raw subject, or ACK a
//! delivery independently.

use std::{error::Error, fmt};

use async_trait::async_trait;
use psy_data::protocol::canonical_chain::NetworkId;

use crate::store::realm_processor_startup::{
    RealmProcessorStartupPermitDigest,
};

use super::recoverable_ephemeral::{
    PendingQueueCaptureCandidate, PendingQueueCaptureContext,
    PendingQueueGenerationBoundary,
};

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
