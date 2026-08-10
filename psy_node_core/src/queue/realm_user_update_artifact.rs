//! Deterministic, typed artifacts for one durable Realm user update.
//!
//! This module is deliberately driver independent.  It seals the exact bytes
//! that the Scylla dependency store may persist, but does not itself authorize
//! a claim transition or execute any storage mutation.

use std::{error::Error, fmt, marker::PhantomData};

use parth_core::{
    crypto::hash::traits::FieldQHasher,
    data::queue::queue_key::PCoreQueueItemBase,
    protocol::core_types::{Q256BitHash, QFHashBase, QZKProofVerifier},
};
use psy_data::{
    proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
    protocol::chain_context::{AuthorityScope, PendingContext, PENDING_CONTEXT_V1_LEN},
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    qblob::{
        blob_type::{QBlobDataType, QBlobMerkleNodeTreeType},
        structs::common::{
            blob_metadata_header::QBlobWriterContextMetadataHeader,
            tree_node_batch_header::{
                QBlobMerkleTreeNodeBatchHeaderV1,
                QBLOB_TREE_NODE_BATCH_HEADER_SIZE,
            },
        },
    },
    store::typed::UserId,
};

use super::{
    realm_user_update_claim::{RealmUserUpdateClaimPhase, StoredRealmUserUpdateClaim},
    realm_user_update_dependency::{
        RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyKind,
    },
    realm_user_update_publish::{
        GlobalUserTreeHeight, RealmUserUpdatePublishRequest,
        RealmUserUpdateRequestDigest,
    },
    realm_user_update_verifier_profile::{
        BoundRealmUserUpdateVerifier, RealmUserUpdateVerifierProfileId,
    },
};

const SLOT_MAGIC: &[u8; 8] = b"PSYRUSLT";
const SLOT_VERSION: u16 = 1;
const SLOT_KIND_ABSENT: u8 = 0;
const SLOT_KIND_PRESENT: u8 = 1;
const SLOT_FIXED_PREFIX_BYTES: usize = 8 + 2 + 1 + 1 + PENDING_CONTEXT_V1_LEN + 8 + 4;
const MAX_SLOT_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

/// Durable QBlob artifacts are authority-created rather than Edge-created.
/// Node zero is the stable protocol sentinel for this default-off path; it is
/// validated on read and prevents failover to a different Edge node from
/// changing artifact bytes.
pub const DURABLE_REALM_ARTIFACT_CREATOR_NODE_ID: u32 = 0;

/// Receipt produced after the concrete Edge verifier has decoded a proof and
/// compared its public-input hash with the typed request input.  The router
/// consumes this receipt rather than accepting proof bytes directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRealmUserUpdateProof<Hash> {
    bytes: Vec<u8>,
    public_inputs_hash: Hash,
}

impl<Hash: Q256BitHash> VerifiedRealmUserUpdateProof<Hash> {
    /// Decode and verify the concrete proof before minting the receipt. There
    /// is no public constructor that accepts a caller-asserted "verified"
    /// hash.
    pub fn verify<Proof, Verifier>(
        bytes: Vec<u8>,
        expected_public_inputs_hash: Hash,
        verifier: &Verifier,
    ) -> Result<Self, RealmUserUpdateArtifactError>
    where
        Hash: std::fmt::Debug,
        Verifier: QZKProofVerifier<Hash, Proof>,
    {
        if bytes.is_empty() {
            return Err(RealmUserUpdateArtifactError::EmptyProof);
        }
        verifier
            .verify_zk_proof_from_slice_check_public_inputs_hash(
                ProvingJobCircuitType::UserEndCap as u32,
                &bytes,
                expected_public_inputs_hash,
            )
            .map_err(|error| {
                RealmUserUpdateArtifactError::ProofVerification(error.to_string())
            })?;
        Ok(Self {
            bytes,
            public_inputs_hash: expected_public_inputs_hash,
        })
    }

    #[cfg(test)]
    fn from_verified_for_test(
        bytes: Vec<u8>,
        expected_public_inputs_hash: Hash,
        verified_public_inputs_hash: Hash,
    ) -> Result<Self, RealmUserUpdateArtifactError> {
        if bytes.is_empty() {
            return Err(RealmUserUpdateArtifactError::EmptyProof);
        }
        if expected_public_inputs_hash != verified_public_inputs_hash {
            return Err(RealmUserUpdateArtifactError::ProofPublicInputsMismatch);
        }
        Ok(Self {
            bytes,
            public_inputs_hash: verified_public_inputs_hash,
        })
    }

    pub fn bytes(&self) -> &[u8] { &self.bytes }
    pub const fn public_inputs_hash(&self) -> Hash { self.public_inputs_hash }
}

/// Canonical input and a real UserEndCap proof verified before any durable
/// claim can be created.  The proof receipt alone is deliberately not enough
/// to claim a user slot: this type recomputes the expected public inputs from
/// the exact canonical input and fixes the circuit family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRealmUserUpdateRequest<F, Hash> {
    canonical_input: Vec<u8>,
    proof: VerifiedRealmUserUpdateProof<Hash>,
    user_id: UserId,
    request_digest: RealmUserUpdateRequestDigest,
    global_user_tree_height: GlobalUserTreeHeight,
    verifier_profile_id: RealmUserUpdateVerifierProfileId,
    _felt: PhantomData<F>,
}

impl<F, Hash> VerifiedRealmUserUpdateRequest<F, Hash>
where
    F: parth_core::felt::QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
{
    pub fn verify<Proof, Verifier, Hasher>(
        input: &SubmitUserEndCapNonProofInput<F, Hash>,
        proof_bytes: Vec<u8>,
        global_user_tree_height: GlobalUserTreeHeight,
        bound_verifier: &BoundRealmUserUpdateVerifier<Verifier>,
    ) -> Result<Self, RealmUserUpdateArtifactError>
    where
        Hash: std::fmt::Debug,
        Verifier: QZKProofVerifier<Hash, Proof>,
        Hasher: FieldQHasher<F, Hash>,
    {
        if bound_verifier.profile().global_user_tree_height()
            != global_user_tree_height.get()
        {
            return Err(RealmUserUpdateArtifactError::VerifierProfileMismatch);
        }
        let canonical_input = input
            .psy_ser_to_bytes_vec()
            .map_err(|error| RealmUserUpdateArtifactError::InputCodec(error.to_string()))?;
        let expected_public_inputs_hash = input
            .core
            .get_proof_public_inputs_hash::<Hasher>(global_user_tree_height.get());
        let proof = VerifiedRealmUserUpdateProof::verify(
            proof_bytes,
            expected_public_inputs_hash,
            bound_verifier.verifier().as_ref(),
        )?;
        Self::from_canonical_and_receipt::<Hasher>(
            canonical_input,
            proof,
            global_user_tree_height,
            bound_verifier.profile_id(),
        )
    }

    fn from_canonical_and_receipt<Hasher: FieldQHasher<F, Hash>>(
        canonical_input: Vec<u8>,
        proof: VerifiedRealmUserUpdateProof<Hash>,
        global_user_tree_height: GlobalUserTreeHeight,
        verifier_profile_id: RealmUserUpdateVerifierProfileId,
    ) -> Result<Self, RealmUserUpdateArtifactError> {
        let input = SubmitUserEndCapNonProofInput::<F, Hash>::psy_ser_from_slice(
            &canonical_input,
        )
        .map_err(|error| RealmUserUpdateArtifactError::InputCodec(error.to_string()))?;
        if input
            .psy_ser_to_bytes_vec()
            .map_err(|error| RealmUserUpdateArtifactError::InputCodec(error.to_string()))?
            != canonical_input
        {
            return Err(RealmUserUpdateArtifactError::InputNotCanonical);
        }
        let expected_public_inputs_hash = input
            .core
            .get_proof_public_inputs_hash::<Hasher>(global_user_tree_height.get());
        if proof.public_inputs_hash() != expected_public_inputs_hash {
            return Err(RealmUserUpdateArtifactError::ProofPublicInputsMismatch);
        }
        let new_leaf_user = input.core.new_user_leaf.user_id.to_u64_value();
        let transition_user = input.core.state_transition.user_id.to_u64_value();
        if new_leaf_user != transition_user || u32::try_from(new_leaf_user).is_err() {
            return Err(RealmUserUpdateArtifactError::RequestMismatch);
        }
        let request_digest = RealmUserUpdateRequestDigest::derive(
            &canonical_input,
            proof.bytes(),
        )
        .map_err(|_| RealmUserUpdateArtifactError::RequestMismatch)?;
        Ok(Self {
            canonical_input,
            proof,
            user_id: UserId::new(new_leaf_user),
            request_digest,
            global_user_tree_height,
            verifier_profile_id,
            _felt: PhantomData,
        })
    }

    pub fn decode_input(
        &self,
    ) -> Result<SubmitUserEndCapNonProofInput<F, Hash>, RealmUserUpdateArtifactError> {
        SubmitUserEndCapNonProofInput::psy_ser_from_slice(&self.canonical_input)
            .map_err(|error| RealmUserUpdateArtifactError::InputCodec(error.to_string()))
    }

    pub fn canonical_input(&self) -> &[u8] { &self.canonical_input }
    pub fn proof(&self) -> &VerifiedRealmUserUpdateProof<Hash> { &self.proof }
    pub const fn user_id(&self) -> UserId { self.user_id }
    pub const fn request_digest(&self) -> RealmUserUpdateRequestDigest {
        self.request_digest
    }
    pub const fn global_user_tree_height(&self) -> GlobalUserTreeHeight {
        self.global_user_tree_height
    }
    pub const fn verifier_profile_id(&self) -> RealmUserUpdateVerifierProfileId {
        self.verifier_profile_id
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateSlotUpdate {
    slot: u64,
    old_value: u64,
    new_value: u64,
}

impl RealmUserUpdateSlotUpdate {
    pub const fn new(slot: u64, old_value: u64, new_value: u64) -> Self {
        Self {
            slot,
            old_value,
            new_value,
        }
    }

    pub const fn slot(self) -> u64 { self.slot }
    pub const fn old_value(self) -> u64 { self.old_value }
    pub const fn new_value(self) -> u64 { self.new_value }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateContractSlots {
    contract_id: u32,
    updates: Vec<RealmUserUpdateSlotUpdate>,
}

impl RealmUserUpdateContractSlots {
    pub fn try_new(
        contract_id: u32,
        updates: Vec<RealmUserUpdateSlotUpdate>,
    ) -> Result<Self, RealmUserUpdateArtifactError> {
        if updates.is_empty() {
            return Err(RealmUserUpdateArtifactError::EmptyContractSlots);
        }
        Ok(Self {
            contract_id,
            updates,
        })
    }

    pub const fn contract_id(&self) -> u32 { self.contract_id }
    pub fn updates(&self) -> &[RealmUserUpdateSlotUpdate] { &self.updates }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateSlotState {
    AbsentNoChanges,
    Present(Vec<RealmUserUpdateContractSlots>),
}

/// Versioned slot artifact.  `AbsentNoChanges` is encoded explicitly and can
/// never be confused with an omitted, failed, or truncated persistence write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateSlotEnvelope<Hash> {
    pending: PendingContext<Hash>,
    user_id: UserId,
    state: RealmUserUpdateSlotState,
}

impl<Hash: Q256BitHash> RealmUserUpdateSlotEnvelope<Hash> {
    pub fn try_new(
        pending: PendingContext<Hash>,
        user_id: UserId,
        contracts: Vec<RealmUserUpdateContractSlots>,
    ) -> Result<Self, RealmUserUpdateArtifactError> {
        let AuthorityScope::Realm { .. } = pending.authority() else {
            return Err(RealmUserUpdateArtifactError::RealmOnly);
        };
        let state = if contracts.is_empty() {
            RealmUserUpdateSlotState::AbsentNoChanges
        } else {
            if contracts.iter().any(|contract| contract.updates.is_empty()) {
                return Err(RealmUserUpdateArtifactError::EmptyContractSlots);
            }
            RealmUserUpdateSlotState::Present(contracts)
        };
        let envelope = Self {
            pending,
            user_id,
            state,
        };
        if envelope.to_canonical_bytes()?.len() > MAX_SLOT_ARTIFACT_BYTES {
            return Err(RealmUserUpdateArtifactError::SlotPayloadTooLarge);
        }
        Ok(envelope)
    }

    pub const fn pending(&self) -> &PendingContext<Hash> { &self.pending }
    pub const fn user_id(&self) -> UserId { self.user_id }
    pub const fn state(&self) -> &RealmUserUpdateSlotState { &self.state }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, RealmUserUpdateArtifactError> {
        let contract_count = match &self.state {
            RealmUserUpdateSlotState::AbsentNoChanges => 0usize,
            RealmUserUpdateSlotState::Present(contracts) => contracts.len(),
        };
        let mut bytes = Vec::with_capacity(SLOT_FIXED_PREFIX_BYTES);
        bytes.extend_from_slice(SLOT_MAGIC);
        bytes.extend_from_slice(&SLOT_VERSION.to_be_bytes());
        bytes.push(match self.state {
            RealmUserUpdateSlotState::AbsentNoChanges => SLOT_KIND_ABSENT,
            RealmUserUpdateSlotState::Present(_) => SLOT_KIND_PRESENT,
        });
        bytes.push(0);
        bytes.extend_from_slice(&self.pending.to_canonical_bytes());
        bytes.extend_from_slice(&self.user_id.get().to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(contract_count)
                .map_err(|_| RealmUserUpdateArtifactError::SlotPayloadTooLarge)?
                .to_be_bytes(),
        );
        if let RealmUserUpdateSlotState::Present(contracts) = &self.state {
            for contract in contracts {
                bytes.extend_from_slice(&contract.contract_id.to_be_bytes());
                bytes.extend_from_slice(
                    &u32::try_from(contract.updates.len())
                        .map_err(|_| RealmUserUpdateArtifactError::SlotPayloadTooLarge)?
                        .to_be_bytes(),
                );
                for update in &contract.updates {
                    bytes.extend_from_slice(&update.slot.to_be_bytes());
                    bytes.extend_from_slice(&update.old_value.to_be_bytes());
                    bytes.extend_from_slice(&update.new_value.to_be_bytes());
                }
            }
        }
        if bytes.len() > MAX_SLOT_ARTIFACT_BYTES {
            return Err(RealmUserUpdateArtifactError::SlotPayloadTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, RealmUserUpdateArtifactError> {
        if bytes.len() < SLOT_FIXED_PREFIX_BYTES || bytes.len() > MAX_SLOT_ARTIFACT_BYTES {
            return Err(RealmUserUpdateArtifactError::MalformedSlotEnvelope);
        }
        if &bytes[..8] != SLOT_MAGIC
            || u16::from_be_bytes(bytes[8..10].try_into().expect("fixed slice"))
                != SLOT_VERSION
            || bytes[11] != 0
        {
            return Err(RealmUserUpdateArtifactError::MalformedSlotEnvelope);
        }
        let kind = bytes[10];
        let pending_end = 12 + PENDING_CONTEXT_V1_LEN;
        let pending = PendingContext::from_canonical_bytes(&bytes[12..pending_end])
            .map_err(|_| RealmUserUpdateArtifactError::MalformedSlotEnvelope)?;
        let mut cursor = pending_end;
        let user_id = UserId::new(read_u64(bytes, &mut cursor)?);
        let contract_count = usize::try_from(read_u32(bytes, &mut cursor)?)
            .map_err(|_| RealmUserUpdateArtifactError::MalformedSlotEnvelope)?;
        let state = match kind {
            SLOT_KIND_ABSENT if contract_count == 0 && cursor == bytes.len() => {
                RealmUserUpdateSlotState::AbsentNoChanges
            }
            SLOT_KIND_PRESENT if contract_count > 0 => {
                if contract_count > (bytes.len() - cursor) / 8 {
                    return Err(RealmUserUpdateArtifactError::MalformedSlotEnvelope);
                }
                let mut contracts = Vec::with_capacity(contract_count);
                for _ in 0..contract_count {
                    let contract_id = read_u32(bytes, &mut cursor)?;
                    let update_count = usize::try_from(read_u32(bytes, &mut cursor)?)
                        .map_err(|_| RealmUserUpdateArtifactError::MalformedSlotEnvelope)?;
                    if update_count == 0 {
                        return Err(RealmUserUpdateArtifactError::EmptyContractSlots);
                    }
                    let remaining_updates = (bytes.len() - cursor) / 24;
                    if update_count > remaining_updates {
                        return Err(RealmUserUpdateArtifactError::MalformedSlotEnvelope);
                    }
                    let mut updates = Vec::with_capacity(update_count);
                    for _ in 0..update_count {
                        updates.push(RealmUserUpdateSlotUpdate::new(
                            read_u64(bytes, &mut cursor)?,
                            read_u64(bytes, &mut cursor)?,
                            read_u64(bytes, &mut cursor)?,
                        ));
                    }
                    contracts.push(RealmUserUpdateContractSlots::try_new(
                        contract_id,
                        updates,
                    )?);
                }
                if cursor != bytes.len() {
                    return Err(RealmUserUpdateArtifactError::MalformedSlotEnvelope);
                }
                RealmUserUpdateSlotState::Present(contracts)
            }
            _ => return Err(RealmUserUpdateArtifactError::MalformedSlotEnvelope),
        };
        let envelope = Self {
            pending,
            user_id,
            state,
        };
        if envelope.to_canonical_bytes()? != bytes {
            return Err(RealmUserUpdateArtifactError::NonCanonicalSlotEnvelope);
        }
        Ok(envelope)
    }
}

/// Exact five artifacts after typed and canonical validation.  Its fields are
/// private so raw byte arrays cannot be passed directly to the durable router.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRealmUserUpdateArtifacts<Hash> {
    claim_slot: super::realm_user_update_claim::RealmUserUpdateClaimSlot,
    created_at_seconds: u32,
    pending: PendingContext<Hash>,
    user_id: UserId,
    request_digest: RealmUserUpdateRequestDigest,
    canonical_input: Vec<u8>,
    proof: Vec<u8>,
    contract_updates: Vec<u8>,
    slot_updates: Vec<u8>,
    queue_payload: Vec<u8>,
}

impl<Hash: Q256BitHash> ValidatedRealmUserUpdateArtifacts<Hash> {
    pub fn try_new<F>(
        claim: &StoredRealmUserUpdateClaim<Hash>,
        verified_request: &VerifiedRealmUserUpdateRequest<F, Hash>,
        contract_updates: Vec<u8>,
        slot_envelope: RealmUserUpdateSlotEnvelope<Hash>,
        publish_request: &RealmUserUpdatePublishRequest<F, Hash>,
    ) -> Result<Self, RealmUserUpdateArtifactError>
    where
        F: parth_core::felt::QFelt64,
        Hash: QFHashBase<F>,
    {
        if !matches!(
            claim.phase(),
            RealmUserUpdateClaimPhase::Claimed
                | RealmUserUpdateClaimPhase::DependenciesPlanned
                | RealmUserUpdateClaimPhase::DependenciesReady
                | RealmUserUpdateClaimPhase::Published
        ) {
            return Err(RealmUserUpdateArtifactError::ClaimNotOpen);
        }
        let input = verified_request.decode_input()?;
        let canonical_input = verified_request.canonical_input().to_vec();
        let request_digest = verified_request.request_digest();
        if request_digest != claim.request_digest()
            || verified_request.verifier_profile_id() != claim.verifier_profile_id()
            || verified_request.user_id() != claim.user_id()
            || verified_request.global_user_tree_height()
                != publish_request.global_user_tree_height()
            || claim.pending() != slot_envelope.pending()
            || claim.user_id() != slot_envelope.user_id()
            || claim.pending() != publish_request.pending()
            || claim.user_id() != publish_request.user_id()
            || request_digest != publish_request.request_digest()
        {
            return Err(RealmUserUpdateArtifactError::RequestMismatch);
        }
        validate_contract_update_qblob(
            &deterministic_qblob_context(claim)?,
            &contract_updates,
        )?;
        let slot_updates = slot_envelope.to_canonical_bytes()?;
        let decoded_slot = RealmUserUpdateSlotEnvelope::<Hash>::from_canonical_bytes(
            &slot_updates,
        )?;
        if decoded_slot != slot_envelope {
            return Err(RealmUserUpdateArtifactError::NonCanonicalSlotEnvelope);
        }
        let queue_payload = publish_request.payload().to_vec();
        let queue_item = PsyRealmUserUpdateQueueItem::<F, Hash>::decode_queue_item_ref(
            &queue_payload,
        )
        .map_err(|error| RealmUserUpdateArtifactError::QueueCodec(error.to_string()))?;
        let canonical_queue = queue_item
            .encode_queue_item_vec()
            .map_err(|error| RealmUserUpdateArtifactError::QueueCodec(error.to_string()))?;
        if canonical_queue != queue_payload {
            return Err(RealmUserUpdateArtifactError::QueueNotCanonical);
        }
        if input.core.new_user_leaf.user_id.to_u64_value() != claim.user_id().get()
            || input.core.state_transition.user_id.to_u64_value()
                != claim.user_id().get()
            || queue_item.expected_fake_checkpoint_id != claim.stable_status()
            || queue_item.old_user_leaf_hash
                != input.core.state_transition.start_user_leaf_hash
            || queue_item.new_user_leaf_hash
                != input.core.state_transition.end_user_leaf_hash
            || queue_item.new_user_leaf != input.core.new_user_leaf
            || queue_item.stats != input.core.stats
            || queue_item.events != input.events
        {
            return Err(RealmUserUpdateArtifactError::QueueSemanticMismatch);
        }
        Ok(Self {
            claim_slot: claim.slot(),
            created_at_seconds: claim.created_at().get(),
            pending: claim.pending().clone(),
            user_id: claim.user_id(),
            request_digest,
            canonical_input,
            proof: verified_request.proof().bytes().to_vec(),
            contract_updates,
            slot_updates,
            queue_payload,
        })
    }

    pub const fn claim_slot(
        &self,
    ) -> super::realm_user_update_claim::RealmUserUpdateClaimSlot {
        self.claim_slot
    }
    pub const fn created_at_seconds(&self) -> u32 {
        self.created_at_seconds
    }
    pub const fn pending(&self) -> &PendingContext<Hash> { &self.pending }
    pub const fn user_id(&self) -> UserId { self.user_id }
    pub const fn request_digest(&self) -> RealmUserUpdateRequestDigest {
        self.request_digest
    }
    pub fn canonical_input(&self) -> &[u8] { &self.canonical_input }
    pub fn proof(&self) -> &[u8] { &self.proof }
    pub fn contract_updates(&self) -> &[u8] { &self.contract_updates }
    pub fn slot_updates(&self) -> &[u8] { &self.slot_updates }
    pub fn queue_payload(&self) -> &[u8] { &self.queue_payload }
}

/// Result of semantically revalidating a persisted dependency bundle.  The
/// publish request is rebuilt from the stored claim instead of from current
/// pipeline counters, so recovery cannot retarget an old request.
pub struct RehydratedRealmUserUpdateArtifacts<F, Hash> {
    artifacts: ValidatedRealmUserUpdateArtifacts<Hash>,
    publish_request: RealmUserUpdatePublishRequest<F, Hash>,
}

impl<F, Hash> RehydratedRealmUserUpdateArtifacts<F, Hash> {
    pub const fn artifacts(&self) -> &ValidatedRealmUserUpdateArtifacts<Hash> {
        &self.artifacts
    }

    pub fn into_publish_request(self) -> RealmUserUpdatePublishRequest<F, Hash> {
        self.publish_request
    }
}

/// Decode and re-run every semantic artifact check after Scylla readback.
/// The caller must obtain `verified_proof` from the concrete ZK verifier; a
/// dependency digest alone is deliberately insufficient to authorize resume.
pub fn verify_and_rehydrate_persisted_realm_user_update_artifacts<
    F,
    Hash,
    Hasher,
    Proof,
    Verifier,
>(
    claim: &StoredRealmUserUpdateClaim<Hash>,
    bundle: &RealmUserUpdateDependencyBundle,
    global_user_tree_height: GlobalUserTreeHeight,
    bound_verifier: &BoundRealmUserUpdateVerifier<Verifier>,
) -> Result<RehydratedRealmUserUpdateArtifacts<F, Hash>, RealmUserUpdateArtifactError>
where
    F: parth_core::felt::QFelt64,
    Hash: Q256BitHash + QFHashBase<F> + std::fmt::Debug,
    Hasher: FieldQHasher<F, Hash>,
    Verifier: QZKProofVerifier<Hash, Proof>,
{
    let verified_request = verify_persisted_realm_user_update_request::<
        F,
        Hash,
        Hasher,
        Proof,
        Verifier,
    >(claim, bundle, global_user_tree_height, bound_verifier)?;
    rehydrate_realm_user_update_artifacts::<F, Hash, Hasher>(
        claim,
        bundle,
        verified_request.proof,
        global_user_tree_height,
    )
}

/// Verify the canonical input/proof pair stored in the durable dependency
/// bundle without constructing a publish request. This narrower boundary is
/// valid while the claim is DependenciesPlanned and must run before the Ready
/// CAS; publishing remains gated on Ready/Published by the rehydrate path.
pub fn verify_persisted_realm_user_update_request<
    F,
    Hash,
    Hasher,
    Proof,
    Verifier,
>(
    claim: &StoredRealmUserUpdateClaim<Hash>,
    bundle: &RealmUserUpdateDependencyBundle,
    global_user_tree_height: GlobalUserTreeHeight,
    bound_verifier: &BoundRealmUserUpdateVerifier<Verifier>,
) -> Result<VerifiedRealmUserUpdateRequest<F, Hash>, RealmUserUpdateArtifactError>
where
    F: parth_core::felt::QFelt64,
    Hash: Q256BitHash + QFHashBase<F> + std::fmt::Debug,
    Hasher: FieldQHasher<F, Hash>,
    Verifier: QZKProofVerifier<Hash, Proof>,
{
    if !matches!(
        claim.phase(),
        RealmUserUpdateClaimPhase::DependenciesPlanned
            | RealmUserUpdateClaimPhase::DependenciesReady
            | RealmUserUpdateClaimPhase::Published
    ) || claim.dependency_digest() != Some(bundle.digest())
    {
        return Err(RealmUserUpdateArtifactError::DependencyMismatch);
    }
    if claim.verifier_profile_id() != bound_verifier.profile_id()
        || claim.pending().chain().network_id() != bound_verifier.profile().network()
        || global_user_tree_height.get()
            != bound_verifier.profile().global_user_tree_height()
    {
        return Err(RealmUserUpdateArtifactError::VerifierProfileMismatch);
    }
    let canonical_input = bundle
        .component(RealmUserUpdateDependencyKind::CanonicalInput)
        .bytes();
    let input = SubmitUserEndCapNonProofInput::<F, Hash>::psy_ser_from_slice(
        canonical_input,
    )
    .map_err(|error| RealmUserUpdateArtifactError::InputCodec(error.to_string()))?;
    let verified_request = VerifiedRealmUserUpdateRequest::verify::<
        Proof,
        Verifier,
        Hasher,
    >(
        &input,
        bundle
            .component(RealmUserUpdateDependencyKind::Proof)
            .bytes()
            .to_vec(),
        global_user_tree_height,
        bound_verifier,
    )?;
    if verified_request.canonical_input() != canonical_input
        || verified_request.request_digest() != claim.request_digest()
        || verified_request.user_id() != claim.user_id()
    {
        return Err(RealmUserUpdateArtifactError::DependencyMismatch);
    }
    Ok(verified_request)
}

/// Rehydrate with an already verified proof receipt. New durable recovery
/// code must prefer `verify_and_rehydrate_persisted_realm_user_update_artifacts`
/// so the router, rather than its caller, owns proof revalidation.
pub fn rehydrate_realm_user_update_artifacts<F, Hash, Hasher>(
    claim: &StoredRealmUserUpdateClaim<Hash>,
    bundle: &RealmUserUpdateDependencyBundle,
    verified_proof: VerifiedRealmUserUpdateProof<Hash>,
    global_user_tree_height: GlobalUserTreeHeight,
) -> Result<RehydratedRealmUserUpdateArtifacts<F, Hash>, RealmUserUpdateArtifactError>
where
    F: parth_core::felt::QFelt64,
    Hash: Q256BitHash + QFHashBase<F>,
    Hasher: FieldQHasher<F, Hash>,
{
    if !matches!(
        claim.phase(),
        RealmUserUpdateClaimPhase::DependenciesReady
            | RealmUserUpdateClaimPhase::Published
    )
        || claim.dependency_digest() != Some(bundle.digest())
    {
        return Err(RealmUserUpdateArtifactError::DependencyMismatch);
    }
    let canonical_input = bundle
        .component(RealmUserUpdateDependencyKind::CanonicalInput)
        .bytes();
    let contract_updates = bundle
        .component(RealmUserUpdateDependencyKind::ContractUpdates)
        .bytes()
        .to_vec();
    let slot_updates = bundle
        .component(RealmUserUpdateDependencyKind::SlotUpdates)
        .bytes();
    let slot = RealmUserUpdateSlotEnvelope::<Hash>::from_canonical_bytes(slot_updates)?;
    let publish_request = RealmUserUpdatePublishRequest::try_from_persisted_dependencies(
        claim,
        bundle,
        global_user_tree_height,
    )
    .map_err(|error| RealmUserUpdateArtifactError::Publish(error.to_string()))?;
    let verified_request = VerifiedRealmUserUpdateRequest::from_canonical_and_receipt::<Hasher>(
        canonical_input.to_vec(),
        verified_proof,
        global_user_tree_height,
        claim.verifier_profile_id(),
    )?;
    let artifacts = ValidatedRealmUserUpdateArtifacts::try_new::<F>(
        claim,
        &verified_request,
        contract_updates,
        slot,
        &publish_request,
    )?;
    for (kind, actual) in [
        (
            RealmUserUpdateDependencyKind::CanonicalInput,
            artifacts.canonical_input(),
        ),
        (RealmUserUpdateDependencyKind::Proof, artifacts.proof()),
        (
            RealmUserUpdateDependencyKind::ContractUpdates,
            artifacts.contract_updates(),
        ),
        (
            RealmUserUpdateDependencyKind::SlotUpdates,
            artifacts.slot_updates(),
        ),
        (
            RealmUserUpdateDependencyKind::QueuePayload,
            artifacts.queue_payload(),
        ),
    ] {
        if bundle.component(kind).bytes() != actual {
            return Err(RealmUserUpdateArtifactError::DependencyMismatch);
        }
    }
    Ok(RehydratedRealmUserUpdateArtifacts {
        artifacts,
        publish_request,
    })
}

pub fn deterministic_qblob_context<Hash: Q256BitHash>(
    claim: &StoredRealmUserUpdateClaim<Hash>,
) -> Result<QBlobWriterContextMetadataHeader, RealmUserUpdateArtifactError> {
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = claim.pending().authority()
    else {
        return Err(RealmUserUpdateArtifactError::RealmOnly);
    };
    let chain_id = u32::try_from(
        claim.pending().chain().network_id().chain_id(),
    )
    .map_err(|_| RealmUserUpdateArtifactError::ChainIdOutOfRange)?;
    Ok(QBlobWriterContextMetadataHeader::new(
        chain_id,
        DURABLE_REALM_ARTIFACT_CREATOR_NODE_ID,
        claim.created_at().get(),
        u64::from(realm_id),
        u64::from(realm_sub_id),
        claim.pending().unique_pending_id().get(),
        claim.stable_status(),
        claim.user_id().get(),
    ))
}

pub fn validate_contract_update_qblob(
    expected: &QBlobWriterContextMetadataHeader,
    bytes: &[u8],
) -> Result<(), RealmUserUpdateArtifactError> {
    let (single, _, remaining) = read_qblob(
        bytes,
        QBlobDataType::GenericSingleIdMerkleNodeBatch,
        QBlobMerkleNodeTreeType::UserContractTree,
    )?;
    validate_header_context(expected, &single)?;
    let (double, _, remaining) = read_qblob(
        remaining,
        QBlobDataType::GenericDoubleIdMerkleNodeBatch,
        QBlobMerkleNodeTreeType::UserContractStateTree,
    )?;
    validate_header_context(expected, &double)?;
    if remaining.is_empty() {
        return Ok(());
    }
    let (imt, imt_payload, remaining) = read_qblob(
        remaining,
        QBlobDataType::GenericIMTLeafBatch,
        QBlobMerkleNodeTreeType::IMTContractStateLeaf,
    )?;
    validate_header_context(expected, &imt)?;
    for entry in imt_payload.chunks_exact(psy_data::v1::qdata::contract::IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        if entry[160] > 1
            || u64::from_le_bytes(entry[0..8].try_into().expect("fixed slice"))
                != expected.for_target_id
        {
            return Err(RealmUserUpdateArtifactError::MalformedImtLeaf);
        }
    }
    if !remaining.is_empty() {
        return Err(RealmUserUpdateArtifactError::TrailingQBlobData);
    }
    Ok(())
}

fn read_qblob<'a>(
    bytes: &'a [u8],
    blob_type: QBlobDataType,
    tree_type: QBlobMerkleNodeTreeType,
) -> Result<
    (QBlobMerkleTreeNodeBatchHeaderV1, &'a [u8], &'a [u8]),
    RealmUserUpdateArtifactError,
> {
    let (header, payload) =
        QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree_ref(
            bytes,
            blob_type,
            tree_type,
            false,
        )
        .map_err(|error| RealmUserUpdateArtifactError::MalformedQBlob(error.to_string()))?;
    let total = usize::try_from(header.total_size)
        .map_err(|_| RealmUserUpdateArtifactError::MalformedQBlob("size overflow".to_owned()))?;
    if total < QBLOB_TREE_NODE_BATCH_HEADER_SIZE || total > bytes.len() {
        return Err(RealmUserUpdateArtifactError::MalformedQBlob(
            "invalid total size".to_owned(),
        ));
    }
    Ok((header, payload, &bytes[total..]))
}

fn validate_header_context(
    expected: &QBlobWriterContextMetadataHeader,
    actual: &QBlobMerkleTreeNodeBatchHeaderV1,
) -> Result<(), RealmUserUpdateArtifactError> {
    if actual.chain_id != expected.chain_id
        || actual.created_by_node_id != expected.created_by_node_id
        || actual.created_at_seconds != expected.created_at_seconds
        || actual.realm_id != expected.realm_id
        || actual.realm_sub_id != expected.realm_sub_id
        || actual.unique_pending_id != expected.unique_pending_id
        || actual.checkpoint_id != expected.checkpoint_id
        || actual.for_target_id != expected.for_target_id
    {
        return Err(RealmUserUpdateArtifactError::QBlobContextMismatch);
    }
    Ok(())
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, RealmUserUpdateArtifactError> {
    let end = cursor
        .checked_add(4)
        .ok_or(RealmUserUpdateArtifactError::MalformedSlotEnvelope)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(RealmUserUpdateArtifactError::MalformedSlotEnvelope)?;
    *cursor = end;
    Ok(u32::from_be_bytes(slice.try_into().expect("fixed slice")))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, RealmUserUpdateArtifactError> {
    let end = cursor
        .checked_add(8)
        .ok_or(RealmUserUpdateArtifactError::MalformedSlotEnvelope)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(RealmUserUpdateArtifactError::MalformedSlotEnvelope)?;
    *cursor = end;
    Ok(u64::from_be_bytes(slice.try_into().expect("fixed slice")))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateArtifactError {
    RealmOnly,
    ClaimNotOpen,
    ChainIdOutOfRange,
    EmptyContractSlots,
    SlotPayloadTooLarge,
    MalformedSlotEnvelope,
    NonCanonicalSlotEnvelope,
    EmptyProof,
    ProofPublicInputsMismatch,
    ProofVerification(String),
    VerifierProfileMismatch,
    EmptyQueuePayload,
    InputCodec(String),
    InputNotCanonical,
    RequestMismatch,
    QueueCodec(String),
    QueueNotCanonical,
    QueueSemanticMismatch,
    MalformedQBlob(String),
    QBlobContextMismatch,
    TrailingQBlobData,
    MalformedImtLeaf,
    DependencyMismatch,
    Publish(String),
}

impl fmt::Display for RealmUserUpdateArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateArtifactError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parth_core::{
        felt::FromPrimitiveValuesFelt,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QZKProofPublicInputsHasherReader,
        utils::QPGenRandom,
        PHash, PF,
    };

    #[derive(Clone, Copy, Debug)]
    struct DeterministicEndCapVerifier;

    impl QZKProofPublicInputsHasherReader<PHash, PHash>
        for DeterministicEndCapVerifier
    {
        fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
            Ok(*proof)
        }

        fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
            PHash::from_slice_32bytes(bytes)
        }
    }

    impl QZKProofVerifier<PHash, PHash> for DeterministicEndCapVerifier {
        fn verify_zk_proof(
            &self,
            circuit_type: u32,
            proof: &PHash,
        ) -> anyhow::Result<PHash> {
            if circuit_type != ProvingJobCircuitType::UserEndCap as u32 {
                anyhow::bail!("unexpected circuit")
            }
            Ok(*proof)
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct RejectingEndCapVerifier;

    impl QZKProofPublicInputsHasherReader<PHash, PHash>
        for RejectingEndCapVerifier
    {
        fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
            Ok(*proof)
        }

        fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
            PHash::from_slice_32bytes(bytes)
        }
    }

    impl QZKProofVerifier<PHash, PHash> for RejectingEndCapVerifier {
        fn verify_zk_proof(
            &self,
            _circuit_type: u32,
            _proof: &PHash,
        ) -> anyhow::Result<PHash> {
            anyhow::bail!("rejected persisted proof")
        }
    }
    use psy_data::{
        proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput,
        protocol::{
            canonical_chain::{
                CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
                CheckpointRef, NetworkId,
            },
            chain_context::{
                AuthorityScope, PendingContext, WorkProcCheckpointUniqueId,
                WorkUniquePendingId,
            },
        },
        queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    };

    use super::*;
    use crate::{
        qblob::data_views::{
            double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView,
            single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView,
        },
        queue::{
            realm_user_update_claim::RealmUserUpdateCreatedAtSeconds,
            realm_user_update_publish::{
                GlobalUserTreeHeight, RealmUserUpdatePublishAdmission,
            },
            recoverable_ephemeral::PendingQueueCaptureContext,
            realm_user_update_verifier_profile::{
                BoundRealmUserUpdateVerifier, RealmUserUpdateVerifierBackend,
                RealmUserUpdateVerifierProfile, RealmUserUpdateVerifierRegistry,
            },
        },
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };

    fn verifier_profile() -> RealmUserUpdateVerifierProfile {
        RealmUserUpdateVerifierProfile::try_new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            32,
            RealmUserUpdateVerifierBackend::DeterministicTest,
            1,
            1,
            [0x71; 32],
            [0x72; 32],
        )
        .unwrap()
    }

    fn bound<Verifier>(verifier: Verifier) -> BoundRealmUserUpdateVerifier<Verifier> {
        let profile = verifier_profile();
        bound_with_profile(verifier, profile)
    }

    fn bound_with_profile<Verifier>(
        verifier: Verifier,
        profile: RealmUserUpdateVerifierProfile,
    ) -> BoundRealmUserUpdateVerifier<Verifier> {
        RealmUserUpdateVerifierRegistry::try_new([(profile.clone(), Arc::new(verifier))])
            .unwrap()
            .resolve(profile.id())
            .unwrap()
    }

    fn pending() -> PendingContext<PHash> {
        PendingContext::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(2),
                CheckpointRef::new(
                    CheckpointId::new(7),
                    CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([8; 32])),
                ),
            ),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 4,
            },
            WorkUniquePendingId::new(9),
            WorkProcCheckpointUniqueId::from_u128(10),
        )
    }

    fn admission() -> RealmUserUpdatePublishAdmission<PHash> {
        let pending = pending();
        let generation = PendingGenerationContext::try_from_legacy(9, 10).unwrap();
        let capture = PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                pending.chain().network_id(),
                pending.authority(),
            ),
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            generation,
        )
        .unwrap();
        RealmUserUpdatePublishAdmission::try_from_pipeline(pending, capture).unwrap()
    }

    fn qblob(context: QBlobWriterContextMetadataHeader) -> Vec<u8> {
        let mut bytes =
            QBlobSingleMerkleNodeBatchDataView::generate_single_merkle_node_batch_blob_data_from_ref::<PHash>(
                context,
                QBlobMerkleNodeTreeType::UserContractTree,
                &[],
            );
        bytes.extend_from_slice(
            &QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref::<PHash>(
                context,
                &[],
            ),
        );
        bytes
    }

    #[test]
    fn absent_and_present_slot_envelopes_round_trip_canonically() {
        let absent = RealmUserUpdateSlotEnvelope::<PHash>::try_new(
            pending(),
            UserId::new(11),
            Vec::new(),
        )
        .unwrap();
        let bytes = absent.to_canonical_bytes().unwrap();
        assert!(matches!(
            RealmUserUpdateSlotEnvelope::<PHash>::from_canonical_bytes(&bytes)
                .unwrap()
                .state(),
            RealmUserUpdateSlotState::AbsentNoChanges
        ));

        let present = RealmUserUpdateSlotEnvelope::<PHash>::try_new(
            pending(),
            UserId::new(11),
            vec![RealmUserUpdateContractSlots::try_new(
                12,
                vec![RealmUserUpdateSlotUpdate::new(13, 14, 15)],
            )
            .unwrap()],
        )
        .unwrap();
        let bytes = present.to_canonical_bytes().unwrap();
        assert_eq!(
            RealmUserUpdateSlotEnvelope::<PHash>::from_canonical_bytes(&bytes).unwrap(),
            present
        );
    }

    #[test]
    fn slot_envelope_rejects_unknown_version_trailing_and_ambiguous_absence() {
        let absent = RealmUserUpdateSlotEnvelope::<PHash>::try_new(
            pending(),
            UserId::new(11),
            Vec::new(),
        )
        .unwrap();
        let mut version = absent.to_canonical_bytes().unwrap();
        version[9] = 2;
        assert!(RealmUserUpdateSlotEnvelope::<PHash>::from_canonical_bytes(&version).is_err());
        let mut trailing = absent.to_canonical_bytes().unwrap();
        trailing.push(0);
        assert!(RealmUserUpdateSlotEnvelope::<PHash>::from_canonical_bytes(&trailing).is_err());
        let mut ambiguous = absent.to_canonical_bytes().unwrap();
        ambiguous[10] = SLOT_KIND_PRESENT;
        assert!(RealmUserUpdateSlotEnvelope::<PHash>::from_canonical_bytes(&ambiguous).is_err());
    }

    #[test]
    fn imt_header_from_context_reuses_every_identity_field() {
        let context = QBlobWriterContextMetadataHeader::new(1, 2, 3, 4, 5, 6, 7, 8);
        let header = QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header_from_context(
            &context,
            QBlobMerkleNodeTreeType::IMTContractStateLeaf,
        );
        assert_eq!(header.chain_id, context.chain_id);
        assert_eq!(header.created_by_node_id, context.created_by_node_id);
        assert_eq!(header.created_at_seconds, context.created_at_seconds);
        assert_eq!(header.realm_id, context.realm_id);
        assert_eq!(header.realm_sub_id, context.realm_sub_id);
        assert_eq!(header.unique_pending_id, context.unique_pending_id);
        assert_eq!(header.checkpoint_id, context.checkpoint_id);
        assert_eq!(header.for_target_id, context.for_target_id);
        let _ = std::marker::PhantomData::<PF>;
    }

    #[test]
    fn strict_qblob_validator_consumes_all_segments_and_every_context_field() {
        let context = QBlobWriterContextMetadataHeader::new(1, 2, 3, 4, 5, 6, 7, 8);
        let bytes = qblob(context);
        validate_contract_update_qblob(&context, &bytes).unwrap();
        for offset in [4usize, 16, 20, 28, 36, 44, 52, 60] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(validate_contract_update_qblob(&context, &changed).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(validate_contract_update_qblob(&context, &trailing).is_err());

        let mut with_imt = qblob(context);
        let mut header = QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header_from_context(
            &context,
            QBlobMerkleNodeTreeType::IMTContractStateLeaf,
        );
        header.modify_for_final_count_and_size(
            psy_data::v1::qdata::contract::IMT_LEAF_FFS_ENTRY_SIZE_V2 as u32,
            1,
        );
        with_imt.extend_from_slice(&header.to_bytes_fixed_size_array());
        let mut entry =
            [0u8; psy_data::v1::qdata::contract::IMT_LEAF_FFS_ENTRY_SIZE_V2];
        entry[..8].copy_from_slice(&context.for_target_id.to_le_bytes());
        with_imt.extend_from_slice(&entry);
        validate_contract_update_qblob(&context, &with_imt).unwrap();
        *with_imt.last_mut().unwrap() = 2;
        assert!(validate_contract_update_qblob(&context, &with_imt).is_err());
    }

    #[test]
    fn full_artifact_validator_binds_input_claim_qblob_slot_and_queue() {
        assert!(VerifiedRealmUserUpdateProof::from_verified_for_test(
            vec![1],
            PHash::from_owned_32bytes([1; 32]),
            PHash::from_owned_32bytes([2; 32]),
        )
        .is_err());
        let mut input = SubmitUserEndCapNonProofInput::<PF, PHash>::qp_rand_gen();
        input.core.new_user_leaf.user_id = PF::from_u64_value(11);
        input.core.state_transition.user_id = PF::from_u64_value(11);
        let input_bytes = input.psy_ser_to_bytes_vec().unwrap();
        let tree_height = GlobalUserTreeHeight::try_new(32).unwrap();
        let proof_public_inputs_hash = input
            .core
            .get_proof_public_inputs_hash::<PoseidonHasher>(tree_height.get());
        let proof = proof_public_inputs_hash.into_owned_32bytes().to_vec();
        assert_eq!(
            VerifiedRealmUserUpdateRequest::<PF, PHash>::from_canonical_and_receipt::<
                PoseidonHasher,
            >(
                input_bytes.clone(),
                VerifiedRealmUserUpdateProof::from_verified_for_test(
                    proof.clone(),
                    PHash::from_owned_32bytes([7; 32]),
                    PHash::from_owned_32bytes([7; 32]),
                )
                .unwrap(),
                tree_height,
                verifier_profile().id(),
            )
            .unwrap_err(),
            RealmUserUpdateArtifactError::ProofPublicInputsMismatch,
        );
        let verified_request =
            VerifiedRealmUserUpdateRequest::<PF, PHash>::from_canonical_and_receipt::<
                PoseidonHasher,
            >(
                input_bytes,
                VerifiedRealmUserUpdateProof::from_verified_for_test(
                    proof,
                    proof_public_inputs_hash,
                    proof_public_inputs_hash,
                )
                .unwrap(),
                tree_height,
                verifier_profile().id(),
            )
            .unwrap();
        let request_digest = verified_request.request_digest();
        let admitted = admission();
        let claim = StoredRealmUserUpdateClaim::claimed(
            admitted.clone(),
            verifier_profile().id(),
            UserId::new(11),
            request_digest,
            RealmUserUpdateCreatedAtSeconds::try_new(12).unwrap(),
            crate::queue::realm_user_update_claim::RealmUserUpdateAdmissionOrdinal::FIRST,
        )
        .unwrap();
        let queue_item = PsyRealmUserUpdateQueueItem::new(
            psy_core::job::job_id::QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(11, 32, 9).unwrap(),
            claim.stable_status(),
            input.core.state_transition.start_user_leaf_hash,
            input.core.state_transition.end_user_leaf_hash,
            input.core.new_user_leaf.clone(),
            input.core.stats,
            input.events.clone(),
        );
        let publish = RealmUserUpdatePublishRequest::try_new(
            admitted,
            UserId::new(11),
            request_digest,
            GlobalUserTreeHeight::try_new(32).unwrap(),
            queue_item,
        )
        .unwrap();
        let context = deterministic_qblob_context(&claim).unwrap();
        let slot = RealmUserUpdateSlotEnvelope::try_new(
            claim.pending().clone(),
            claim.user_id(),
            Vec::new(),
        )
        .unwrap();
        let artifacts = ValidatedRealmUserUpdateArtifacts::try_new::<PF>(
            &claim,
            &verified_request,
            qblob(context),
            slot,
            &publish,
        )
        .unwrap();
        assert_eq!(artifacts.pending(), claim.pending());
        assert_eq!(artifacts.request_digest(), claim.request_digest());
        assert_eq!(artifacts.claim_slot(), claim.slot());
        assert_eq!(artifacts.created_at_seconds(), claim.created_at().get());

        let same_request_losing_time = StoredRealmUserUpdateClaim::claimed(
            admission(),
            verifier_profile().id(),
            claim.user_id(),
            claim.request_digest(),
            RealmUserUpdateCreatedAtSeconds::try_new(13).unwrap(),
            claim.admission_ordinal(),
        )
        .unwrap();
        assert!(claim.same_request_as(&same_request_losing_time));
        assert!(RealmUserUpdateDependencyBundle::try_new_validated(
            &same_request_losing_time,
            &artifacts,
        )
        .is_err());

        let bundle = RealmUserUpdateDependencyBundle::try_new_validated(
            &claim,
            &artifacts,
        )
        .unwrap();
        let planned = StoredRealmUserUpdateClaim::dependencies_planned(
            &claim,
            bundle.digest(),
        )
        .unwrap();
        let ready = StoredRealmUserUpdateClaim::dependencies_ready(&planned).unwrap();
        let rehydrated = rehydrate_realm_user_update_artifacts::<
            PF,
            PHash,
            PoseidonHasher,
        >(
            &ready,
            &bundle,
            VerifiedRealmUserUpdateProof::from_verified_for_test(
                artifacts.proof().to_vec(),
                proof_public_inputs_hash,
                proof_public_inputs_hash,
            )
            .unwrap(),
            GlobalUserTreeHeight::try_new(32).unwrap(),
        )
        .unwrap();
        assert_eq!(rehydrated.artifacts().queue_payload(), artifacts.queue_payload());
        assert_eq!(
            rehydrated.into_publish_request().payload(),
            artifacts.queue_payload(),
        );
        let verified_from_durable =
            verify_persisted_realm_user_update_request::<
                PF,
                PHash,
                PoseidonHasher,
                PHash,
                DeterministicEndCapVerifier,
            >(
                &planned,
                &bundle,
                GlobalUserTreeHeight::try_new(32).unwrap(),
                &bound(DeterministicEndCapVerifier),
            )
            .unwrap();
        assert_eq!(verified_from_durable.request_digest(), claim.request_digest());
        assert_eq!(verified_from_durable.canonical_input(), artifacts.canonical_input());
        let alternate_profile = RealmUserUpdateVerifierProfile::try_new(
            verifier_profile().network(),
            32,
            RealmUserUpdateVerifierBackend::DeterministicTest,
            1,
            2,
            [0x71; 32],
            [0x72; 32],
        )
        .unwrap();
        assert_eq!(
            verify_persisted_realm_user_update_request::<
                PF,
                PHash,
                PoseidonHasher,
                PHash,
                DeterministicEndCapVerifier,
            >(
                &planned,
                &bundle,
                GlobalUserTreeHeight::try_new(32).unwrap(),
                &bound_with_profile(DeterministicEndCapVerifier, alternate_profile),
            ),
            Err(RealmUserUpdateArtifactError::VerifierProfileMismatch)
        );
        assert!(verify_persisted_realm_user_update_request::<
            PF,
            PHash,
            PoseidonHasher,
            PHash,
            DeterministicEndCapVerifier,
        >(
            &planned,
            &bundle,
            GlobalUserTreeHeight::try_new(31).unwrap(),
            &bound(DeterministicEndCapVerifier),
        )
        .is_err());
        assert!(matches!(
            verify_persisted_realm_user_update_request::<
                PF,
                PHash,
                PoseidonHasher,
                PHash,
                RejectingEndCapVerifier,
            >(
                &planned,
                &bundle,
                GlobalUserTreeHeight::try_new(32).unwrap(),
                &bound(RejectingEndCapVerifier),
            ),
            Err(RealmUserUpdateArtifactError::ProofVerification(_)),
        ));
        assert!(verify_and_rehydrate_persisted_realm_user_update_artifacts::<
            PF,
            PHash,
            PoseidonHasher,
            PHash,
            DeterministicEndCapVerifier,
        >(
            &ready,
            &bundle,
            GlobalUserTreeHeight::try_new(32).unwrap(),
            &bound(DeterministicEndCapVerifier),
        )
        .is_ok());

        let wrong_queue_item = PsyRealmUserUpdateQueueItem::new(
            psy_core::job::job_id::QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(11, 32, 9).unwrap(),
            claim.stable_status(),
            PHash::from_owned_32bytes([42; 32]),
            input.core.state_transition.end_user_leaf_hash,
            input.core.new_user_leaf.clone(),
            input.core.stats,
            input.events.clone(),
        );
        let wrong_publish = RealmUserUpdatePublishRequest::try_new(
            admission(),
            UserId::new(11),
            request_digest,
            GlobalUserTreeHeight::try_new(32).unwrap(),
            wrong_queue_item,
        )
        .unwrap();
        assert!(ValidatedRealmUserUpdateArtifacts::try_new::<PF>(
            &claim,
            &verified_request,
            qblob(context),
            RealmUserUpdateSlotEnvelope::try_new(
                claim.pending().clone(),
                claim.user_id(),
                Vec::new(),
            )
            .unwrap(),
            &wrong_publish,
        )
        .is_err());
    }

    #[test]
    fn verified_receipt_has_no_public_asserted_hash_constructor() {
        let source = include_str!("realm_user_update_artifact.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("pub fn verify<Proof, Verifier>("));
        assert!(!production.contains("circuit_type: u32"));
        assert!(production.contains("ProvingJobCircuitType::UserEndCap as u32"));
        assert_eq!(ProvingJobCircuitType::UserEndCap as u32, 6);
        assert!(!production.contains("pub fn try_new(\n        bytes: Vec<u8>,\n        expected_public_inputs_hash"));
        assert!(production.contains("verify_zk_proof_from_slice_check_public_inputs_hash"));
        let module_source = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(module_source.contains("verify_persisted_realm_user_update_request"));
        assert!(module_source.contains("VerifiedRealmUserUpdateRequest::verify::<"));
    }
}
