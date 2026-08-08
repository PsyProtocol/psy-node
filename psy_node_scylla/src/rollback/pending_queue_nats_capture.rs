//! Default-off composition of one dedicated JetStream pull consumer and the
//! Scylla pending-queue artifact store.
//!
//! The module is deliberately crate-private.  Keeping the unacknowledged NATS
//! messages, the opaque Scylla readback receipt, the terminal ACK, and the
//! header continuation in one boundary prevents a caller from manufacturing
//! an ACK claim.  Production setup and legacy queue publishers do not refer to
//! this module yet.

use std::{
    error::Error,
    fmt,
    sync::Arc,
    time::Duration,
};

use psy_node_core::queue::recoverable_ephemeral::{
    PendingQueueArtifactIdentity, PendingQueueCaptureCandidate,
    PendingQueueCaptureContext, PendingQueueSourceCursor,
    PendingQueueSourceCursorView,
};
use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_transport::{
        RecoverableNatsCaptureConsumer, RecoverableNatsCaptureSpec,
        RecoverableNatsDeliveryBatch, RecoverableNatsTransportError,
    },
};
use tokio::sync::Mutex;

use super::{
    DurablySelectedPendingQueueBatchReceipt, PendingQueueArtifactStoreError,
    PendingQueueArtifactOwnerPermit, ScyllaPendingQueueArtifactStore,
};

const DEFAULT_FETCH_EXPIRES: Duration = Duration::from_millis(250);

type RecoverableNatsConsumerContract = RecoverableNatsCaptureSpec;

fn verify_candidate<'candidate>(
    contract: &RecoverableNatsConsumerContract,
    candidate: &'candidate PendingQueueCaptureCandidate,
) -> Result<&'candidate [u64], PendingQueueNatsCaptureError> {
    if candidate.source_identity()
        != &contract
            .source_identity()
            .map_err(nats_transport)?
    {
        return Err(PendingQueueNatsCaptureError::SourceIdentityMismatch);
    }
    let PendingQueueSourceCursorView::NatsJetStream {
        consumer_digest,
        stream_sequences,
        ..
    } = candidate.source().view()
    else {
        return Err(PendingQueueNatsCaptureError::SourceCursorMismatch);
    };
    if consumer_digest != &contract.consumer_digest() {
        return Err(PendingQueueNatsCaptureError::ConsumerDigestMismatch);
    }
    Ok(stream_sequences)
}

/// Concrete default-off composition.  No constructor is exported from the
/// rollback module and production setup does not instantiate it.
pub(super) struct ScyllaBackedRecoverableNatsSource {
    client: Arc<NatsJetStreamClient>,
    store: Arc<ScyllaPendingQueueArtifactStore>,
    contract: RecoverableNatsConsumerContract,
    owner: PendingQueueArtifactOwnerPermit,
    fetch_expires: Duration,
    serial: Mutex<()>,
}

impl ScyllaBackedRecoverableNatsSource {
    pub(super) fn new(
        client: Arc<NatsJetStreamClient>,
        store: Arc<ScyllaPendingQueueArtifactStore>,
        contract: RecoverableNatsConsumerContract,
        owner: PendingQueueArtifactOwnerPermit,
    ) -> Result<Self, PendingQueueNatsCaptureError> {
        if client.base_namespace() != contract.namespace() {
            return Err(PendingQueueNatsCaptureError::ClientContractMismatch);
        }
        Ok(Self {
            client,
            store,
            contract,
            owner,
            fetch_expires: DEFAULT_FETCH_EXPIRES,
            serial: Mutex::new(()),
        })
    }

    /// Recovers a previously selected batch first; otherwise fetches one new
    /// unacknowledged batch.  Exact Scylla readback always precedes terminal
    /// NATS ACK, and the durable header advances only after ACK is confirmed.
    pub(super) async fn capture_one(
        &self,
        context: PendingQueueCaptureContext,
    ) -> Result<Option<PendingQueueCaptureCandidate>, PendingQueueNatsCaptureError> {
        let _serial = self.serial.lock().await;
        let identity = PendingQueueArtifactIdentity::try_new(
            context,
            self.contract
                .source_identity()
                .map_err(nats_transport)?,
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?;
        if self.owner.slot()
            != psy_node_core::queue::recoverable_artifact::slot_for(&identity)
        {
            return Err(PendingQueueNatsCaptureError::OwnerPermitMismatch);
        }
        self.store
            .validate_owner_permit(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;
        let mut consumer = self.ensure_attested_consumer().await?;
        // Consumer lookup/validation crosses systems and may take an
        // unbounded amount of time. Revalidate immediately before either
        // recovery fetch or a new pull so a completed takeover fences this
        // instance before it can consume max_ack_pending capacity.
        self.store
            .validate_owner_permit(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;

        if let Some((selected, receipt)) = self
            .store
            .recover_selected_batch(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?
        {
            verify_candidate(&self.contract, &selected)?;
            if self.ack_floor_covers(&mut consumer, &selected).await? {
                self.confirm_after_ack(receipt, &selected).await?;
                return Ok(Some(selected));
            }
            let token = self
                .fetch_exact_candidate(&mut consumer, &selected)
                .await?;
            self.ack_and_confirm(token, receipt, &selected, &mut consumer)
                .await?;
            return Ok(Some(selected));
        }

        self.store
            .validate_owner_permit(&self.owner, &identity)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;
        let Some((token, candidate)) = self.fetch_new(&mut consumer, context).await? else {
            return Ok(None);
        };
        let receipt = self
            .store
            .persist_selected_batch(&self.owner, &candidate)
            .await
            .map_err(PendingQueueNatsCaptureError::Store)?;
        self.ack_and_confirm(token, receipt, &candidate, &mut consumer)
            .await?;
        Ok(Some(candidate))
    }

    async fn ensure_attested_consumer(
        &self,
    ) -> Result<RecoverableNatsCaptureConsumer, PendingQueueNatsCaptureError> {
        self.client
            .open_recoverable_capture(self.contract.clone())
            .await
            .map_err(nats_transport)
    }

    async fn fetch_new(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        context: PendingQueueCaptureContext,
    ) -> Result<
        Option<(RecoverableNatsDeliveryBatch, PendingQueueCaptureCandidate)>,
        PendingQueueNatsCaptureError,
    > {
        let token = self
            .fetch_token(consumer, self.contract.max_batch_items())
            .await?;
        let Some(token) = token else {
            return Ok(None);
        };
        let items = token.payloads().to_vec();
        let cursor = PendingQueueSourceCursor::nats_jetstream(
            self.contract.consumer_digest(),
            token.stream_sequences(),
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?;
        let candidate = PendingQueueCaptureCandidate::try_new(
            context,
            self.contract
                .source_identity()
                .map_err(nats_transport)?,
            cursor,
            items,
        )
        .map_err(|error| PendingQueueNatsCaptureError::Core(error.to_string()))?;
        Ok(Some((token, candidate)))
    }

    async fn fetch_exact_candidate(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        selected: &PendingQueueCaptureCandidate,
    ) -> Result<RecoverableNatsDeliveryBatch, PendingQueueNatsCaptureError> {
        let expected_sequences = verify_candidate(&self.contract, selected)?;
        let ack_floor_stream_sequence = consumer
            .observation()
            .await
            .map_err(nats_transport)?
            .ack_floor_stream_sequence();
        let remaining = &expected_sequences[expected_sequences
            .partition_point(|sequence| *sequence <= ack_floor_stream_sequence)..];
        if remaining.is_empty() {
            return Err(PendingQueueNatsCaptureError::AckFloorAlreadyComplete);
        }
        let token = self
            .fetch_token(consumer, remaining.len())
            .await?
            .ok_or(PendingQueueNatsCaptureError::SelectedAwaitingRedelivery)?;
        verify_unacked_prefix(
            expected_sequences,
            selected.items(),
            ack_floor_stream_sequence,
            token.stream_sequences(),
            token.payloads().iter().map(Vec::as_slice),
        )
        .map_err(|_| PendingQueueNatsCaptureError::RedeliveryMismatch)?;
        Ok(token)
    }

    async fn fetch_token(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        max_items: usize,
    ) -> Result<Option<RecoverableNatsDeliveryBatch>, PendingQueueNatsCaptureError> {
        consumer
            .fetch(max_items, self.fetch_expires)
            .await
            .map_err(nats_transport)
    }

    async fn ack_and_confirm(
        &self,
        token: RecoverableNatsDeliveryBatch,
        receipt: DurablySelectedPendingQueueBatchReceipt,
        candidate: &PendingQueueCaptureCandidate,
        consumer: &mut RecoverableNatsCaptureConsumer,
    ) -> Result<(), PendingQueueNatsCaptureError> {
        let expected = verify_candidate(&self.contract, candidate)?;
        let before = consumer
            .observation()
            .await
            .map_err(nats_transport)?;
        verify_unacked_prefix(
            expected,
            candidate.items(),
            before.ack_floor_stream_sequence(),
            token.stream_sequences(),
            token.payloads().iter().map(Vec::as_slice),
        )
        .map_err(|_| PendingQueueNatsCaptureError::AckTokenMismatch)?;
        token
            .double_ack_all(consumer)
            .await
            .map_err(nats_transport)?;
        if !self.ack_floor_covers(consumer, candidate).await? {
            return Err(PendingQueueNatsCaptureError::SelectedAwaitingRedelivery);
        }
        self.confirm_after_ack(receipt, candidate).await
    }

    async fn ack_floor_covers(
        &self,
        consumer: &mut RecoverableNatsCaptureConsumer,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<bool, PendingQueueNatsCaptureError> {
        let sequences = verify_candidate(&self.contract, candidate)?;
        let last = *sequences
            .last()
            .ok_or(PendingQueueNatsCaptureError::SourceCursorMismatch)?;
        let info = consumer
            .observation()
            .await
            .map_err(nats_transport)?;
        Ok(info.ack_floor_consumer_sequence() > 0
            && info.ack_floor_stream_sequence() >= last)
    }

    async fn confirm_after_ack(
        &self,
        receipt: DurablySelectedPendingQueueBatchReceipt,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<(), PendingQueueNatsCaptureError> {
        self.store
            .confirm_selected_ack_after_backend(&self.owner, receipt, candidate)
            .await
            .map(|_| ())
            .map_err(PendingQueueNatsCaptureError::Store)
    }
}

fn verify_unacked_prefix<'payload>(
    expected_sequences: &[u64],
    expected_items: &[Vec<u8>],
    ack_floor_stream_sequence: u64,
    actual_sequences: &[u64],
    actual_items: impl Iterator<Item = &'payload [u8]>,
) -> Result<(), ()> {
    let first_unacked = expected_sequences
        .partition_point(|sequence| *sequence <= ack_floor_stream_sequence);
    let remaining_sequences = &expected_sequences[first_unacked..];
    if actual_sequences.is_empty()
        || actual_sequences.len() > remaining_sequences.len()
        || actual_sequences != &remaining_sequences[..actual_sequences.len()]
        || actual_items.ne(
            expected_items[first_unacked..first_unacked + actual_sequences.len()]
                .iter()
                .map(Vec::as_slice),
        )
    {
        Err(())
    } else {
        Ok(())
    }
}

fn nats_transport(error: RecoverableNatsTransportError) -> PendingQueueNatsCaptureError {
    PendingQueueNatsCaptureError::Nats(error.to_string())
}

#[derive(Debug)]
pub(super) enum PendingQueueNatsCaptureError {
    EmptyAddressComponent,
    InvalidReplicaRequirement(usize),
    InvalidBatchLimit(usize),
    EmptyConsumerDigest,
    ClientContractMismatch,
    OwnerPermitMismatch,
    StreamContract(String),
    ConsumerContract,
    SourceIdentityMismatch,
    SourceCursorMismatch,
    ConsumerDigestMismatch,
    DeliveryContract,
    SelectedAwaitingRedelivery,
    RedeliveryMismatch,
    AckTokenMismatch,
    AckFloorAlreadyComplete,
    AckIndeterminate(String),
    Core(String),
    Nats(String),
    Store(PendingQueueArtifactStoreError),
}

impl fmt::Display for PendingQueueNatsCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAddressComponent => formatter.write_str("empty NATS address component"),
            Self::InvalidReplicaRequirement(value) => {
                write!(formatter, "invalid minimum stream replicas {value}")
            }
            Self::InvalidBatchLimit(value) => write!(formatter, "invalid batch limit {value}"),
            Self::EmptyConsumerDigest => formatter.write_str("empty consumer digest"),
            Self::ClientContractMismatch => formatter.write_str("NATS client/contract mismatch"),
            Self::OwnerPermitMismatch => formatter.write_str("artifact owner permit mismatch"),
            Self::StreamContract(reason) => write!(formatter, "unsafe stream contract: {reason}"),
            Self::ConsumerContract => formatter.write_str("dedicated consumer contract mismatch"),
            Self::SourceIdentityMismatch => formatter.write_str("source identity mismatch"),
            Self::SourceCursorMismatch => formatter.write_str("source cursor mismatch"),
            Self::ConsumerDigestMismatch => formatter.write_str("consumer digest mismatch"),
            Self::DeliveryContract => formatter.write_str("NATS delivery contract mismatch"),
            Self::SelectedAwaitingRedelivery => formatter.write_str("selected batch awaits redelivery"),
            Self::RedeliveryMismatch => formatter.write_str("redelivery differs from durable selection"),
            Self::AckTokenMismatch => formatter.write_str("ACK token differs from durable selection"),
            Self::AckFloorAlreadyComplete => formatter.write_str("ACK floor already covers selected batch"),
            Self::AckIndeterminate(reason) => write!(formatter, "NATS ACK is indeterminate: {reason}"),
            Self::Core(reason) => write!(formatter, "core queue contract failed: {reason}"),
            Self::Nats(reason) => write!(formatter, "NATS operation failed: {reason}"),
            Self::Store(error) => write!(formatter, "artifact store failed: {error}"),
        }
    }
}

impl Error for PendingQueueNatsCaptureError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> RecoverableNatsConsumerContract {
        RecoverableNatsConsumerContract::try_new(
            "psy",
            "psy_stream",
            "psy.pq.r0.rs0.u1.qt1.g0",
            3,
            1024,
        )
        .unwrap()
    }

    #[test]
    fn typed_transport_contract_remains_deterministic() {
        let first = contract();
        let second = contract();
        assert_eq!(first, second);
        assert_eq!(first.durable(), second.durable());
        assert_eq!(first.namespace(), "psy");
        assert_eq!(first.stream(), "psy_stream");
        assert_eq!(first.subject(), "psy.pq.r0.rs0.u1.qt1.g0");
        assert_ne!(first.consumer_digest(), [0; 32]);
    }

    #[test]
    fn partial_ack_recovery_accepts_only_the_exact_remaining_prefix() {
        let sequences = [10, 12, 15, 19];
        let items = [b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];

        // No ACK: the complete delivery is valid.
        verify_unacked_prefix(
            &sequences,
            &items,
            0,
            &sequences,
            items.iter().map(Vec::as_slice),
        )
        .unwrap();
        // One ACK and N-1 ACKs: a partial redelivery prefix is valid and can
        // make bounded progress across repeated capture calls.
        verify_unacked_prefix(
            &sequences,
            &items,
            10,
            &[12, 15],
            items[1..3].iter().map(Vec::as_slice),
        )
        .unwrap();
        verify_unacked_prefix(
            &sequences,
            &items,
            15,
            &[19],
            items[3..].iter().map(Vec::as_slice),
        )
        .unwrap();

        assert!(verify_unacked_prefix(
            &sequences,
            &items,
            10,
            &[15],
            items[2..3].iter().map(Vec::as_slice),
        )
        .is_err());
        assert!(verify_unacked_prefix(
            &sequences,
            &items,
            10,
            &[12],
            items[2..3].iter().map(Vec::as_slice),
        )
        .is_err());
        assert!(verify_unacked_prefix(
            &sequences,
            &items,
            19,
            &[],
            std::iter::empty(),
        )
        .is_err());
    }

}
