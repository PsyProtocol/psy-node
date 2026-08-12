//! Driver-independent durable input boundary for one Coordinator generation.
//!
//! Coordinator processing consumes three independently published sources.  A
//! generation is replayable only when registration, deploy and GUTA have each
//! produced an exact durable close boundary and their ordered business bytes
//! have been reconstructed from the artifact store.  This module deliberately
//! contains no backend token, ACK method, pipeline transition or public
//! unchecked constructor.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::queue::recoverable_ephemeral::{
    PendingQueueBoundaryDigest, PendingQueueCaptureContext,
    PendingQueueSourceIdentityDigest,
};

const SOURCE_DOMAIN: &[u8] =
    b"psy/rollback/coordinator-processor-durable-source/v1";
const GENERATION_DOMAIN: &[u8] =
    b"psy/rollback/coordinator-processor-durable-generation/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CoordinatorProcessorSourceKind {
    Registration = 1,
    Deploy = 2,
    Guta = 3,
}

impl CoordinatorProcessorSourceKind {
    pub const ALL: [Self; 3] = [Self::Registration, Self::Deploy, Self::Guta];
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorProcessorDurableSourceDigest([u8; 32]);

impl CoordinatorProcessorDurableSourceDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, CoordinatorProcessorDurableCaptureError> {
        if bytes == [0; 32] {
            Err(CoordinatorProcessorDurableCaptureError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorProcessorDurableGenerationDigest([u8; 32]);

impl CoordinatorProcessorDurableGenerationDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, CoordinatorProcessorDurableCaptureError> {
        if bytes == [0; 32] {
            Err(CoordinatorProcessorDurableCaptureError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One exact business payload recovered from a committed Data envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorProcessorDurableCapturedItem {
    subject_sequence: u64,
    envelope_digest: [u8; 32],
    payload: Vec<u8>,
}

impl CoordinatorProcessorDurableCapturedItem {
    pub fn try_new(
        subject_sequence: u64,
        envelope_digest: [u8; 32],
        payload: Vec<u8>,
    ) -> Result<Self, CoordinatorProcessorDurableCaptureError> {
        if subject_sequence == 0 || envelope_digest == [0; 32] || payload.is_empty() {
            return Err(CoordinatorProcessorDurableCaptureError::MalformedItem);
        }
        Ok(Self {
            subject_sequence,
            envelope_digest,
            payload,
        })
    }

    pub const fn subject_sequence(&self) -> u64 {
        self.subject_sequence
    }

    pub const fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// One exhaustively reconstructed and durably closed Coordinator source.
/// Empty sources are valid, but absence of the source record is not.
#[derive(Debug)]
pub struct CoordinatorProcessorDurableCapturedSource {
    kind: CoordinatorProcessorSourceKind,
    context: PendingQueueCaptureContext,
    source_identity: PendingQueueSourceIdentityDigest,
    boundary: PendingQueueBoundaryDigest,
    items: Vec<CoordinatorProcessorDurableCapturedItem>,
    digest: CoordinatorProcessorDurableSourceDigest,
}

impl CoordinatorProcessorDurableCapturedSource {
    pub fn try_from_exhaustive_readback(
        kind: CoordinatorProcessorSourceKind,
        context: PendingQueueCaptureContext,
        source_identity: PendingQueueSourceIdentityDigest,
        boundary: PendingQueueBoundaryDigest,
        items: Vec<CoordinatorProcessorDurableCapturedItem>,
    ) -> Result<Self, CoordinatorProcessorDurableCaptureError> {
        if items.windows(2).any(|items| {
            items[0].subject_sequence() >= items[1].subject_sequence()
        }) {
            return Err(CoordinatorProcessorDurableCaptureError::NonCanonicalItemOrder);
        }
        let mut hasher = Sha256::new();
        hasher.update(SOURCE_DOMAIN);
        hasher.update([kind as u8]);
        hasher.update(context.digest().as_bytes());
        hasher.update(source_identity.as_bytes());
        hasher.update(boundary.as_bytes());
        hasher.update((items.len() as u64).to_be_bytes());
        for item in &items {
            hasher.update(item.subject_sequence().to_be_bytes());
            hasher.update(item.envelope_digest());
            hasher.update((item.payload().len() as u64).to_be_bytes());
            hasher.update(item.payload());
        }
        let digest = CoordinatorProcessorDurableSourceDigest::try_new(
            hasher.finalize().into(),
        )?;
        Ok(Self {
            kind,
            context,
            source_identity,
            boundary,
            items,
            digest,
        })
    }

    pub const fn kind(&self) -> CoordinatorProcessorSourceKind {
        self.kind
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn source_identity(&self) -> PendingQueueSourceIdentityDigest {
        self.source_identity
    }

    pub const fn boundary(&self) -> PendingQueueBoundaryDigest {
        self.boundary
    }

    pub fn items(&self) -> &[CoordinatorProcessorDurableCapturedItem] {
        &self.items
    }

    pub const fn digest(&self) -> CoordinatorProcessorDurableSourceDigest {
        self.digest
    }

    pub fn into_payloads(self) -> Vec<Vec<u8>> {
        self.items
            .into_iter()
            .map(CoordinatorProcessorDurableCapturedItem::into_payload)
            .collect()
    }
}

/// Complete three-source input selected for one Coordinator processing
/// generation.  It is non-Clone so a caller cannot silently apply it twice.
#[derive(Debug)]
pub struct CoordinatorProcessorDurableCapturedGeneration {
    context: PendingQueueCaptureContext,
    registration: CoordinatorProcessorDurableCapturedSource,
    deploy: CoordinatorProcessorDurableCapturedSource,
    guta: CoordinatorProcessorDurableCapturedSource,
    total_items: u64,
    digest: CoordinatorProcessorDurableGenerationDigest,
}

impl CoordinatorProcessorDurableCapturedGeneration {
    pub fn try_from_exhaustive_readback(
        context: PendingQueueCaptureContext,
        sources: Vec<CoordinatorProcessorDurableCapturedSource>,
    ) -> Result<Self, CoordinatorProcessorDurableCaptureError> {
        if sources.len() != CoordinatorProcessorSourceKind::ALL.len()
            || sources.iter().any(|source| source.context() != context)
            || sources
                .iter()
                .map(CoordinatorProcessorDurableCapturedSource::kind)
                .ne(CoordinatorProcessorSourceKind::ALL)
        {
            return Err(CoordinatorProcessorDurableCaptureError::SourceManifestMismatch);
        }
        let total_items = sources.iter().try_fold(0_u64, |total, source| {
            total
                .checked_add(source.items().len() as u64)
                .ok_or(CoordinatorProcessorDurableCaptureError::ItemCountOverflow)
        })?;
        let mut hasher = Sha256::new();
        hasher.update(GENERATION_DOMAIN);
        hasher.update(context.digest().as_bytes());
        hasher.update((sources.len() as u64).to_be_bytes());
        for source in &sources {
            hasher.update([source.kind() as u8]);
            hasher.update(source.digest().as_bytes());
            hasher.update((source.items().len() as u64).to_be_bytes());
        }
        hasher.update(total_items.to_be_bytes());
        let digest = CoordinatorProcessorDurableGenerationDigest::try_new(
            hasher.finalize().into(),
        )?;
        let mut sources = sources.into_iter();
        let registration = sources.next().expect("three-source cardinality checked");
        let deploy = sources.next().expect("three-source cardinality checked");
        let guta = sources.next().expect("three-source cardinality checked");
        Ok(Self {
            context,
            registration,
            deploy,
            guta,
            total_items,
            digest,
        })
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn total_items(&self) -> u64 {
        self.total_items
    }

    pub const fn digest(&self) -> CoordinatorProcessorDurableGenerationDigest {
        self.digest
    }

    pub const fn registration(&self) -> &CoordinatorProcessorDurableCapturedSource {
        &self.registration
    }

    pub const fn deploy(&self) -> &CoordinatorProcessorDurableCapturedSource {
        &self.deploy
    }

    pub const fn guta(&self) -> &CoordinatorProcessorDurableCapturedSource {
        &self.guta
    }

    pub fn into_payloads(self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        (
            self.registration.into_payloads(),
            self.deploy.into_payloads(),
            self.guta.into_payloads(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorProcessorDurableCaptureError {
    EmptyDigest,
    MalformedItem,
    NonCanonicalItemOrder,
    SourceManifestMismatch,
    ItemCountOverflow,
}

impl fmt::Display for CoordinatorProcessorDurableCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CoordinatorProcessorDurableCaptureError {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };

    use crate::store::{
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };

    fn context() -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                AuthorityScope::Coordinator,
            ),
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(7, 8).unwrap(),
        )
        .unwrap()
    }

    fn source(
        kind: CoordinatorProcessorSourceKind,
        marker: u8,
        item_count: usize,
    ) -> CoordinatorProcessorDurableCapturedSource {
        let items = (0..item_count)
            .map(|index| {
                CoordinatorProcessorDurableCapturedItem::try_new(
                    index as u64 + 1,
                    [marker; 32],
                    vec![marker, index as u8],
                )
                .unwrap()
            })
            .collect();
        CoordinatorProcessorDurableCapturedSource::try_from_exhaustive_readback(
            kind,
            context(),
            PendingQueueSourceIdentityDigest::try_new([marker + 10; 32]).unwrap(),
            PendingQueueBoundaryDigest::try_new([marker + 20; 32]).unwrap(),
            items,
        )
        .unwrap()
    }

    fn generation() -> CoordinatorProcessorDurableCapturedGeneration {
        CoordinatorProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
            context(),
            vec![
                source(CoordinatorProcessorSourceKind::Registration, 1, 2),
                source(CoordinatorProcessorSourceKind::Deploy, 2, 0),
                source(CoordinatorProcessorSourceKind::Guta, 3, 1),
            ],
        )
        .unwrap()
    }

    #[test]
    fn exact_three_source_generation_is_deterministic_and_allows_explicit_empty() {
        let first = generation();
        let second = generation();
        assert_eq!(first.context(), context());
        assert_eq!(first.total_items(), 3);
        assert_eq!(first.deploy().items().len(), 0);
        assert_eq!(first.digest(), second.digest());
        assert_ne!(first.digest().as_bytes(), &[0; 32]);
    }

    #[test]
    fn missing_duplicate_or_wrong_source_order_fails_closed() {
        let missing = vec![
            source(CoordinatorProcessorSourceKind::Registration, 1, 0),
            source(CoordinatorProcessorSourceKind::Deploy, 2, 0),
        ];
        assert_eq!(
            CoordinatorProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
                context(), missing,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableCaptureError::SourceManifestMismatch,
        );

        let wrong_order = vec![
            source(CoordinatorProcessorSourceKind::Guta, 3, 0),
            source(CoordinatorProcessorSourceKind::Deploy, 2, 0),
            source(CoordinatorProcessorSourceKind::Registration, 1, 0),
        ];
        assert_eq!(
            CoordinatorProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
                context(), wrong_order,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableCaptureError::SourceManifestMismatch,
        );
    }

    #[test]
    fn source_rejects_noncanonical_sequence_order_and_payload_drift_changes_digest() {
        let invalid = vec![
            CoordinatorProcessorDurableCapturedItem::try_new(2, [1; 32], vec![1]).unwrap(),
            CoordinatorProcessorDurableCapturedItem::try_new(1, [1; 32], vec![2]).unwrap(),
        ];
        assert_eq!(
            CoordinatorProcessorDurableCapturedSource::try_from_exhaustive_readback(
                CoordinatorProcessorSourceKind::Registration,
                context(),
                PendingQueueSourceIdentityDigest::try_new([4; 32]).unwrap(),
                PendingQueueBoundaryDigest::try_new([5; 32]).unwrap(),
                invalid,
            )
            .unwrap_err(),
            CoordinatorProcessorDurableCaptureError::NonCanonicalItemOrder,
        );

        let first = source(CoordinatorProcessorSourceKind::Guta, 3, 1);
        let changed = CoordinatorProcessorDurableCapturedSource::try_from_exhaustive_readback(
            CoordinatorProcessorSourceKind::Guta,
            context(),
            first.source_identity(),
            first.boundary(),
            vec![CoordinatorProcessorDurableCapturedItem::try_new(
                1,
                [3; 32],
                vec![3, 9],
            )
            .unwrap()],
        )
        .unwrap();
        assert_ne!(first.digest(), changed.digest());
    }

    #[test]
    fn model_exposes_no_backend_ack_or_unchecked_generation_constructor() {
        let source = include_str!("coordinator_processor_durable_capture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("Session"));
        assert!(!production.contains("NatsJetStreamClient"));
        assert!(!production.contains("ack_token"));
        assert!(!production.contains("pub fn new("));
        assert!(!production.contains(
            "impl Clone for CoordinatorProcessorDurableCapturedGeneration"
        ));
    }
}
