//! Driver-independent Realm Edge user-update publication boundary.
//!
//! A branch-exact publisher receives the exact pending context captured before
//! proof verification.  It may not retarget the payload to whatever bare
//! pending/proc counters happen to be current after the asynchronous work.

use std::{error::Error, fmt, marker::PhantomData};

use async_trait::async_trait;
use parth_core::{
    data::queue::queue_key::PCoreQueueItemBase,
    felt::QFelt64,
    protocol::core_types::Q256BitHash,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    protocol::chain_context::{AuthorityScope, PendingContext},
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};
use sha2::{Digest, Sha256};

use crate::store::{
    pending_generation_identity::PendingGenerationContext,
    typed::{UniquePendingId, UserId},
};
use super::{
    realm_user_update_claim::{
        RealmUserUpdateClaimPhase, StoredRealmUserUpdateClaim,
    },
    realm_user_update_dependency::{
        RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyKind,
    },
    recoverable_ephemeral::{
        PendingQueueCaptureContext, PendingQueueCaptureContextDigest,
    },
};

const REQUEST_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-request/v1";
const INTENT_ID_DOMAIN: &[u8] = b"psy/rollback/realm-user-update-intent/v1";
const RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-receipt/v1";
const ADMISSION_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-admission/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateRequestDigest([u8; 32]);

impl RealmUserUpdateRequestDigest {
    /// Bind the stable submitted proof/input bytes. Callers must not include a
    /// random status or a server timestamp in either component.
    pub fn derive(input: &[u8], proof: &[u8]) -> Result<Self, RealmUserUpdatePublishError> {
        if input.is_empty() || proof.is_empty() {
            return Err(RealmUserUpdatePublishError::EmptyRequestComponent);
        }
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DIGEST_DOMAIN);
        update_len(&mut hasher, input);
        update_len(&mut hasher, proof);
        Self::try_new(hasher.finalize().into())
    }

    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmUserUpdatePublishError> {
        if bytes == [0; 32] {
            Err(RealmUserUpdatePublishError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Stable, non-zero legacy-compatible status for the exact semantic
    /// request. It is derived once from canonical request/proof material so a
    /// crash retry cannot mint a different fake checkpoint/status value.
    pub fn stable_status(self) -> u64 {
        let value = u64::from_be_bytes(
            self.0[..8]
                .try_into()
                .expect("request digest prefix has a fixed width"),
        );
        if value == 0 { 1 } else { value }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateIntentId([u8; 32]);

impl RealmUserUpdateIntentId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Protocol tree height carried by the Realm UserEndCap job identity.
///
/// Keeping this distinct from a raw `u8` prevents a caller from validating a
/// queue item against an unrelated height/configuration value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GlobalUserTreeHeight(u8);

impl GlobalUserTreeHeight {
    pub fn try_new(value: u8) -> Result<Self, RealmUserUpdatePublishError> {
        if value == 0 || value >= 64 {
            Err(RealmUserUpdatePublishError::InvalidGlobalUserTreeHeight(
                value,
            ))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Exact gathering-generation observation issued by the durable port before
/// proof verification. Construction validates the public identities, while
/// the concrete port must still re-read its pipeline/assignment before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdatePublishAdmission<Hash> {
    pending: PendingContext<Hash>,
    capture: PendingQueueCaptureContext,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RealmUserUpdatePublishAdmission<Hash> {
    pub fn try_from_pipeline(
        pending: PendingContext<Hash>,
        capture: PendingQueueCaptureContext,
    ) -> Result<Self, RealmUserUpdatePublishError> {
        if pending.chain().network_id() != capture.key().network() {
            return Err(RealmUserUpdatePublishError::NetworkMismatch);
        }
        if pending.authority() != capture.key().authority() {
            return Err(RealmUserUpdatePublishError::AuthorityMismatch);
        }
        if pending.unique_pending_id().get()
            != capture.processing().pending_id().get()
            || pending.proc_checkpoint_unique_id().as_u128()
                != capture.processing().proc_checkpoint_id().as_u128()
        {
            return Err(RealmUserUpdatePublishError::GenerationMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(ADMISSION_DIGEST_DOMAIN);
        hasher.update(pending.to_canonical_bytes());
        hasher.update(capture.digest().as_bytes());
        let digest = hasher.finalize().into();
        if digest == [0; 32] {
            return Err(RealmUserUpdatePublishError::EmptyDigest);
        }
        Ok(Self {
            pending,
            capture,
            digest,
        })
    }

    pub const fn pending(&self) -> &PendingContext<Hash> {
        &self.pending
    }

    pub const fn capture(&self) -> PendingQueueCaptureContext {
        self.capture
    }

    pub const fn capture_digest(&self) -> PendingQueueCaptureContextDigest {
        self.capture.digest()
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// A sealed publication command. Fields are private so a caller cannot pair a
/// payload with a bare height/proc ID or replace its intent identity on retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdatePublishRequest<F, Hash> {
    admission: RealmUserUpdatePublishAdmission<Hash>,
    generation: PendingGenerationContext,
    user_id: UserId,
    global_user_tree_height: GlobalUserTreeHeight,
    request_digest: RealmUserUpdateRequestDigest,
    payload_digest: [u8; 32],
    payload: Vec<u8>,
    intent_id: RealmUserUpdateIntentId,
    _felt: PhantomData<F>,
}

impl<F: QFelt64, Hash: Q256BitHash> RealmUserUpdatePublishRequest<F, Hash> {
    pub fn try_new(
        admission: RealmUserUpdatePublishAdmission<Hash>,
        user_id: UserId,
        request_digest: RealmUserUpdateRequestDigest,
        global_user_tree_height: GlobalUserTreeHeight,
        item: PsyRealmUserUpdateQueueItem<F, Hash>,
    ) -> Result<Self, RealmUserUpdatePublishError> {
        let pending = admission.pending();
        let pending_id = UniquePendingId::try_new(pending.unique_pending_id().get())
            .map_err(|_| RealmUserUpdatePublishError::PendingOutOfRange)?;
        let generation = PendingGenerationContext::try_from_legacy(
            pending_id.get(),
            pending.proc_checkpoint_unique_id().as_u128(),
        )
        .map_err(|error| RealmUserUpdatePublishError::InvalidGeneration(error.to_string()))?;
        u32::try_from(user_id.get())
            .map_err(|_| RealmUserUpdatePublishError::UserOutOfRange)?;
        let expected_job_id = QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            user_id.get(),
            global_user_tree_height.get(),
            pending.unique_pending_id().get(),
        )
        .map_err(|_| RealmUserUpdatePublishError::QueueItemIdentityMismatch)?;
        if item.job_id != expected_job_id {
            return Err(RealmUserUpdatePublishError::QueueItemIdentityMismatch);
        }
        if item.expected_fake_checkpoint_id != request_digest.stable_status() {
            return Err(RealmUserUpdatePublishError::StableStatusMismatch);
        }
        let payload = item
            .encode_queue_item_vec()
            .map_err(|error| RealmUserUpdatePublishError::QueueItemCodec(error.to_string()))?;
        let decoded = PsyRealmUserUpdateQueueItem::<F, Hash>::decode_queue_item_ref(&payload)
            .map_err(|error| RealmUserUpdatePublishError::QueueItemCodec(error.to_string()))?;
        let canonical = decoded
            .encode_queue_item_vec()
            .map_err(|error| RealmUserUpdatePublishError::QueueItemCodec(error.to_string()))?;
        if canonical != payload {
            return Err(RealmUserUpdatePublishError::QueueItemNotCanonical);
        }
        let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut hasher = Sha256::new();
        hasher.update(INTENT_ID_DOMAIN);
        // The global caller intent deliberately excludes branch/generation.
        // Source admission binds those identities later. If Seal wins, the
        // same semantic request must retain its global slot while retrying in
        // the next gathering generation; if Data already bound it, that exact
        // binding prevents duplicate publication on another branch.
        hasher.update(
            admission
                .pending()
                .chain()
                .network_id()
                .chain_id()
                .to_be_bytes(),
        );
        update_authority(&mut hasher, admission.pending().authority());
        hasher.update(user_id.get().to_be_bytes());
        hasher.update(request_digest.as_bytes());
        hasher.update(payload_digest);
        let intent_id = RealmUserUpdateIntentId(hasher.finalize().into());
        if intent_id.0 == [0; 32] {
            return Err(RealmUserUpdatePublishError::EmptyDigest);
        }
        Ok(Self {
            admission,
            generation,
            user_id,
            global_user_tree_height,
            request_digest,
            payload_digest,
            payload,
            intent_id,
            _felt: PhantomData,
        })
    }

    /// Rebuild the exact publish command after dependency readback.  The
    /// caller cannot replace admission, request identity, or payload: all are
    /// recovered from the full-payload claim and its digest-bound bundle.
    pub fn try_from_dependencies_ready(
        claim: &StoredRealmUserUpdateClaim<Hash>,
        bundle: &RealmUserUpdateDependencyBundle,
        global_user_tree_height: GlobalUserTreeHeight,
    ) -> Result<Self, RealmUserUpdatePublishError> {
        if claim.phase() != RealmUserUpdateClaimPhase::DependenciesReady {
            return Err(RealmUserUpdatePublishError::DependencyMismatch);
        }
        Self::try_from_persisted_dependencies(
            claim,
            bundle,
            global_user_tree_height,
        )
    }

    pub fn try_from_persisted_dependencies(
        claim: &StoredRealmUserUpdateClaim<Hash>,
        bundle: &RealmUserUpdateDependencyBundle,
        global_user_tree_height: GlobalUserTreeHeight,
    ) -> Result<Self, RealmUserUpdatePublishError> {
        if !matches!(
            claim.phase(),
            RealmUserUpdateClaimPhase::DependenciesReady
                | RealmUserUpdateClaimPhase::Published
        )
            || claim.dependency_digest() != Some(bundle.digest())
            || claim.slot() != bundle.claim_slot()
            || claim.request_digest().as_bytes() != bundle.request_digest()
            || claim.stable_status() != bundle.stable_status()
            || claim.created_at().get() != bundle.created_at_seconds()
        {
            return Err(RealmUserUpdatePublishError::DependencyMismatch);
        }
        let payload = bundle
            .component(RealmUserUpdateDependencyKind::QueuePayload)
            .bytes();
        let item = PsyRealmUserUpdateQueueItem::<F, Hash>::decode_queue_item_ref(payload)
            .map_err(|error| RealmUserUpdatePublishError::QueueItemCodec(error.to_string()))?;
        let request = Self::try_new(
            claim
                .reconstruct_admission()
                .map_err(|error| RealmUserUpdatePublishError::Claim(error.to_string()))?,
            claim.user_id(),
            claim.request_digest(),
            global_user_tree_height,
            item,
        )?;
        if request.payload() != payload {
            return Err(RealmUserUpdatePublishError::QueueItemNotCanonical);
        }
        Ok(request)
    }

    pub const fn pending(&self) -> &PendingContext<Hash> {
        self.admission.pending()
    }

    pub const fn admission(&self) -> &RealmUserUpdatePublishAdmission<Hash> {
        &self.admission
    }

    pub const fn generation(&self) -> PendingGenerationContext {
        self.generation
    }

    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub const fn global_user_tree_height(&self) -> GlobalUserTreeHeight {
        self.global_user_tree_height
    }

    pub const fn request_digest(&self) -> RealmUserUpdateRequestDigest {
        self.request_digest
    }

    pub const fn payload_digest(&self) -> &[u8; 32] {
        &self.payload_digest
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub const fn intent_id(&self) -> RealmUserUpdateIntentId {
        self.intent_id
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RealmUserUpdatePublishDisposition {
    DurableApplied,
    DurableResumed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdatePublishReceipt {
    intent_id: RealmUserUpdateIntentId,
    assignment_digest: [u8; 32],
    subject_sequence: u64,
    envelope_digest: [u8; 32],
    disposition: RealmUserUpdatePublishDisposition,
    receipt_digest: [u8; 32],
}

impl RealmUserUpdatePublishReceipt {
    /// Non-authorizing DTO returned after the Scylla/NATS durable path has
    /// completed. Downstream authority transitions must re-read their own
    /// durable receipts; this public constructor does not mint such a permit.
    pub fn durable(
        intent_id: RealmUserUpdateIntentId,
        assignment_digest: [u8; 32],
        subject_sequence: u64,
        envelope_digest: [u8; 32],
        resumed: bool,
    ) -> Result<Self, RealmUserUpdatePublishError> {
        if assignment_digest == [0; 32]
            || subject_sequence == 0
            || envelope_digest == [0; 32]
        {
            return Err(RealmUserUpdatePublishError::MalformedReceipt);
        }
        Ok(Self::new(
            intent_id,
            assignment_digest,
            subject_sequence,
            envelope_digest,
            if resumed {
                RealmUserUpdatePublishDisposition::DurableResumed
            } else {
                RealmUserUpdatePublishDisposition::DurableApplied
            },
        ))
    }

    fn new(
        intent_id: RealmUserUpdateIntentId,
        assignment_digest: [u8; 32],
        subject_sequence: u64,
        envelope_digest: [u8; 32],
        disposition: RealmUserUpdatePublishDisposition,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_DIGEST_DOMAIN);
        hasher.update(intent_id.as_bytes());
        hasher.update(assignment_digest);
        hasher.update(subject_sequence.to_be_bytes());
        hasher.update(envelope_digest);
        Self {
            intent_id,
            assignment_digest,
            subject_sequence,
            envelope_digest,
            disposition,
            receipt_digest: hasher.finalize().into(),
        }
    }

    pub const fn intent_id(&self) -> RealmUserUpdateIntentId {
        self.intent_id
    }

    pub const fn subject_sequence(&self) -> u64 {
        self.subject_sequence
    }

    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }

    pub const fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }

    pub const fn disposition(&self) -> RealmUserUpdatePublishDisposition {
        self.disposition
    }

    pub const fn receipt_digest(&self) -> &[u8; 32] {
        &self.receipt_digest
    }
}

#[async_trait]
pub trait RealmUserUpdatePublishPort<F: QFelt64, Hash: Q256BitHash>: Send + Sync {
    async fn admit(
        &self,
    ) -> Result<RealmUserUpdatePublishAdmission<Hash>, RealmUserUpdatePublishError>;

    async fn publish(
        &self,
        request: RealmUserUpdatePublishRequest<F, Hash>,
    ) -> Result<RealmUserUpdatePublishReceipt, RealmUserUpdatePublishError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdatePublishError {
    EmptyRequestComponent,
    EmptyDigest,
    QueueItemIdentityMismatch,
    QueueItemNotCanonical,
    QueueItemCodec(String),
    StableStatusMismatch,
    UserOutOfRange,
    PendingOutOfRange,
    InvalidGeneration(String),
    InvalidGlobalUserTreeHeight(u8),
    AuthorityMismatch,
    NetworkMismatch,
    GenerationMismatch,
    BranchMismatch,
    NotReady(String),
    Storage(String),
    Transport(String),
    MalformedReceipt,
    DependencyMismatch,
    Claim(String),
}

impl fmt::Display for RealmUserUpdatePublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdatePublishError {}

fn update_len(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn update_authority(hasher: &mut Sha256, authority: AuthorityScope) {
    match authority {
        AuthorityScope::Coordinator => hasher.update([0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([1]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{PF, PHash, utils::QPGenRandom};
    use psy_data::protocol::{
        canonical_chain::{CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId},
        chain_context::{AuthorityScope, PendingContext, WorkProcCheckpointUniqueId, WorkUniquePendingId},
    };

    use super::*;

    fn pending(epoch: u64, checkpoint: u64, pending_id: u64, proc_id: u128) -> PendingContext<PHash> {
        PendingContext::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint),
                    CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                        (checkpoint + epoch) as u8;
                        32
                    ])),
                ),
            ),
            AuthorityScope::Realm { realm_id: 7, realm_sub_id: 2 },
            WorkUniquePendingId::new(pending_id),
            WorkProcCheckpointUniqueId::from_u128(proc_id),
        )
    }

    fn admission(epoch: u64, checkpoint: u64, pending_id: u64, proc_id: u128) -> RealmUserUpdatePublishAdmission<PHash> {
        let pending = pending(epoch, checkpoint, pending_id, proc_id);
        let key = crate::store::pending_generation_identity::PendingGenerationLedgerKey::new(
            pending.chain().network_id(),
            pending.authority(),
        );
        let activation = crate::store::pending_generation_identity::PendingGenerationActivationDigest::try_new([9; 32]).unwrap();
        let generation = PendingGenerationContext::try_from_legacy(pending_id, proc_id).unwrap();
        RealmUserUpdatePublishAdmission::try_from_pipeline(
            pending,
            PendingQueueCaptureContext::try_new(key, activation, generation).unwrap(),
        ).unwrap()
    }

    fn queue_item(
        pending_id: u64,
        user_id: u64,
        status: u64,
    ) -> PsyRealmUserUpdateQueueItem<PF, PHash> {
        let mut item = PsyRealmUserUpdateQueueItem::<PF, PHash>::qp_rand_gen();
        item.job_id = psy_core::job::job_id::QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            user_id,
            32,
            pending_id,
        )
        .unwrap();
        item.expected_fake_checkpoint_id = status;
        item
    }

    fn tree_height() -> GlobalUserTreeHeight {
        GlobalUserTreeHeight::try_new(32).unwrap()
    }

    #[test]
    fn request_is_branch_generation_user_and_payload_exact() {
        let digest = RealmUserUpdateRequestDigest::derive(b"input", b"proof").unwrap();
        let item = queue_item(11, 13, digest.stable_status());
        let base = RealmUserUpdatePublishRequest::try_new(
            admission(1, 10, 11, 12),
            UserId::new(13),
            digest,
            tree_height(),
            item.clone(),
        )
        .unwrap();
        let same = RealmUserUpdatePublishRequest::try_new(
            admission(1, 10, 11, 12),
            UserId::new(13),
            digest,
            tree_height(),
            item.clone(),
        )
        .unwrap();
        assert_eq!(base, same);
        assert_eq!(base.intent_id(), same.intent_id());
        for same_intent_different_admission in [
            RealmUserUpdatePublishRequest::try_new(admission(2, 10, 11, 12), UserId::new(13), digest, tree_height(), item.clone()).unwrap(),
            RealmUserUpdatePublishRequest::try_new(admission(1, 10, 11, 15), UserId::new(13), digest, tree_height(), item.clone()).unwrap(),
        ] {
            assert_eq!(base.intent_id(), same_intent_different_admission.intent_id());
            assert_ne!(base.admission(), same_intent_different_admission.admission());
        }
        for different_intent in [
            RealmUserUpdatePublishRequest::try_new(admission(1, 10, 11, 12), UserId::new(16), digest, tree_height(), queue_item(11, 16, digest.stable_status())).unwrap(),
            {
                let mut changed = item.clone();
                changed.old_user_leaf_hash = PHash::from_owned_32bytes([42; 32]);
                RealmUserUpdatePublishRequest::try_new(admission(1, 10, 11, 12), UserId::new(13), digest, tree_height(), changed).unwrap()
            },
            {
                let other = RealmUserUpdateRequestDigest::derive(b"other", b"proof").unwrap();
                RealmUserUpdatePublishRequest::try_new(admission(1, 10, 11, 12), UserId::new(13), other, tree_height(), queue_item(11, 13, other.stable_status())).unwrap()
            },
        ] {
            assert_ne!(base.intent_id(), different_intent.intent_id());
        }
    }

    #[test]
    fn empty_and_out_of_range_inputs_fail_closed() {
        assert!(RealmUserUpdateRequestDigest::derive(&[], b"proof").is_err());
        assert!(RealmUserUpdateRequestDigest::try_new([0; 32]).is_err());
        let digest = RealmUserUpdateRequestDigest::derive(b"input", b"proof").unwrap();
        assert!(RealmUserUpdatePublishRequest::try_new(
            admission(1, 10, 12, 12), UserId::new(13), digest, tree_height(), queue_item(11, 13, digest.stable_status())
        ).is_err());
        let mut missing_status = queue_item(11, 13, digest.stable_status());
        missing_status.expected_fake_checkpoint_id = 0;
        assert!(RealmUserUpdatePublishRequest::try_new(
            admission(1, 10, 11, 12), UserId::new(13), digest, tree_height(), missing_status
        ).is_err());
        let mut wrong_group = queue_item(11, 13, digest.stable_status());
        wrong_group.job_id.group_id = 31;
        assert!(RealmUserUpdatePublishRequest::try_new(
            admission(1, 10, 11, 12), UserId::new(13), digest, tree_height(), wrong_group
        ).is_err());
        assert!(GlobalUserTreeHeight::try_new(0).is_err());
        assert!(GlobalUserTreeHeight::try_new(64).is_err());
        assert!(PendingGenerationContext::try_from_legacy(
            i64::MAX as u64 + 1,
            12,
        )
        .is_err());
    }

    #[test]
    fn stable_status_is_deterministic_nonzero_and_request_exact() {
        let first = RealmUserUpdateRequestDigest::derive(b"input", b"proof").unwrap();
        let same = RealmUserUpdateRequestDigest::derive(b"input", b"proof").unwrap();
        let changed = RealmUserUpdateRequestDigest::derive(b"input", b"other-proof").unwrap();
        assert_ne!(first.stable_status(), 0);
        assert_eq!(first.stable_status(), same.stable_status());
        assert_ne!(first.stable_status(), changed.stable_status());

        let mut zero_prefix = [0; 32];
        zero_prefix[31] = 1;
        assert_eq!(RealmUserUpdateRequestDigest::try_new(zero_prefix).unwrap().stable_status(), 1);
    }

    #[test]
    fn durable_receipt_is_exact_and_nonzero() {
        let intent = RealmUserUpdateIntentId([7; 32]);
        let first = RealmUserUpdatePublishReceipt::durable(intent, [6; 32], 9, [8; 32], false).unwrap();
        let resumed = RealmUserUpdatePublishReceipt::durable(intent, [6; 32], 9, [8; 32], true).unwrap();
        assert_eq!(first.receipt_digest(), resumed.receipt_digest());
        assert!(RealmUserUpdatePublishReceipt::durable(intent, [0; 32], 9, [8; 32], false).is_err());
        assert!(RealmUserUpdatePublishReceipt::durable(intent, [6; 32], 0, [8; 32], false).is_err());
        assert!(RealmUserUpdatePublishReceipt::durable(intent, [6; 32], 9, [0; 32], false).is_err());
    }
}
