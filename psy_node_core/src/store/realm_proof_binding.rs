//! Typed binding between a Realm prepared update, its verified GUTA proof and
//! the Realm root included by a canonical Coordinator checkpoint.
//!
//! This module deliberately performs no database I/O.  A sealed value can only
//! be created while the caller still has the exact prepared payload, submitted
//! GUTA header, proof bytes, verifier and Coordinator sync response.  Decoding
//! a durable record yields [`PersistedRealmProofBinding`], never a sealed value:
//! recovery code must still match it to the manifest and committed rows.

use std::{error::Error, fmt};

use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    data::hash::merkle_node_key::{
        SimpleMerkleNode, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE,
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase, QZKProofVerifier},
};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
    prepared_block::realm::{
        PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate,
    },
    protocol::{
        canonical_chain::{CanonicalChainRef, CANONICAL_CHAIN_REF_V1_LEN},
        chain_context::{AuthorityScope, AuthorityStateCheckpointId},
    },
};
use psy_serialize::{
    FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingle,
};
use sha2::{Digest, Sha256};

pub const REALM_PROOF_BINDING_MAGIC: [u8; 8] = *b"PSYRMPB1";
pub const REALM_PROOF_BINDING_CODEC_VERSION: u16 = 1;

const BINDING_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-proof-binding.v1\0";
const PREPARED_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-prepared-payload.v1\0";
const SUBMISSION_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-guta-submission.v1\0";
const PROOF_DIGEST_DOMAIN: &[u8] = b"psy.rollback.realm-guta-proof.v1\0";
const COORDINATOR_UPDATE_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-coordinator-update.v1\0";
const INCLUSION_PROOF_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-inclusion-proof.v1\0";

const AUTHORITY_LEN: usize = 6;
const ROOTS_LEN: usize = 64;
const DIGEST_FIELDS_LEN: usize = 32 * 6;
const REALM_PROOF_BINDING_PAYLOAD_LEN: usize = 8
    + 2
    + AUTHORITY_LEN
    + CANONICAL_CHAIN_REF_V1_LEN
    + 8
    + ROOTS_LEN
    + 1
    + 4
    + DIGEST_FIELDS_LEN;
pub const REALM_PROOF_BINDING_V1_LEN: usize =
    REALM_PROOF_BINDING_PAYLOAD_LEN + 32;

/// Hash of the exact GUTA public input verified by the supplied circuit.
/// This is not a Coordinator checkpoint hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GutaProofPublicInputsHash<Hash>(Hash);

impl<Hash> GutaProofPublicInputsHash<Hash> {
    pub const fn as_inner(&self) -> &Hash {
        &self.0
    }
}

/// Content commitment for a canonical Realm proof-binding record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProofBindingDigest([u8; 32]);

impl RealmProofBindingDigest {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Durable representation.  Digest verification proves that the bytes are
/// self-consistent; it does not repeat the ZK verification and therefore does
/// not grant the authority carried by [`SealedRealmProofBinding`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRealmProofBinding<Hash> {
    authority: AuthorityScope,
    canonical_chain: CanonicalChainRef<Hash>,
    state_checkpoint: AuthorityStateCheckpointId,
    old_realm_root: Hash,
    new_realm_root: Hash,
    coordinator_tree_height: u8,
    circuit_type: u32,
    proof_public_inputs_hash: GutaProofPublicInputsHash<Hash>,
    prepared_payload_digest: [u8; 32],
    submission_header_digest: [u8; 32],
    proof_bytes_digest: [u8; 32],
    coordinator_update_digest: [u8; 32],
    inclusion_proof_digest: [u8; 32],
    canonical_bytes: Vec<u8>,
    digest: RealmProofBindingDigest,
}

impl<Hash: Q256BitHash> PersistedRealmProofBinding<Hash> {
    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmProofBindingError> {
        if bytes.len() != REALM_PROOF_BINDING_V1_LEN {
            return Err(RealmProofBindingError::InvalidCanonicalLength {
                expected: REALM_PROOF_BINDING_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[..8] != REALM_PROOF_BINDING_MAGIC {
            return Err(RealmProofBindingError::InvalidMagic);
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed"));
        if version != REALM_PROOF_BINDING_CODEC_VERSION {
            return Err(RealmProofBindingError::UnknownCodecVersion(version));
        }

        let mut offset = 10;
        let realm_id = u32::from_le_bytes(
            bytes[offset..offset + 4].try_into().expect("fixed"),
        );
        offset += 4;
        let realm_sub_id = u16::from_le_bytes(
            bytes[offset..offset + 2].try_into().expect("fixed"),
        );
        offset += 2;
        let authority = AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        };

        let canonical_chain_bytes: [u8; CANONICAL_CHAIN_REF_V1_LEN] = bytes
            [offset..offset + CANONICAL_CHAIN_REF_V1_LEN]
            .try_into()
            .expect("fixed");
        let canonical_chain = CanonicalChainRef::from_canonical_bytes(
            &canonical_chain_bytes,
        )
        .map_err(|_| RealmProofBindingError::InvalidCanonicalChain)?;
        offset += CANONICAL_CHAIN_REF_V1_LEN;

        let state_checkpoint = AuthorityStateCheckpointId::new(
            u64::from_le_bytes(
                bytes[offset..offset + 8].try_into().expect("fixed"),
            ),
        );
        offset += 8;
        let old_realm_root = Hash::from_owned_32bytes(
            bytes[offset..offset + 32].try_into().expect("fixed"),
        );
        offset += 32;
        let new_realm_root = Hash::from_owned_32bytes(
            bytes[offset..offset + 32].try_into().expect("fixed"),
        );
        offset += 32;
        let coordinator_tree_height = bytes[offset];
        offset += 1;
        let circuit_type = u32::from_le_bytes(
            bytes[offset..offset + 4].try_into().expect("fixed"),
        );
        offset += 4;
        let proof_public_inputs_hash = GutaProofPublicInputsHash(
            Hash::from_owned_32bytes(
                bytes[offset..offset + 32].try_into().expect("fixed"),
            ),
        );
        offset += 32;
        let prepared_payload_digest = take_digest(bytes, &mut offset);
        let submission_header_digest = take_digest(bytes, &mut offset);
        let proof_bytes_digest = take_digest(bytes, &mut offset);
        let coordinator_update_digest = take_digest(bytes, &mut offset);
        let inclusion_proof_digest = take_digest(bytes, &mut offset);
        debug_assert_eq!(offset, REALM_PROOF_BINDING_PAYLOAD_LEN);
        let stored_digest = take_digest(bytes, &mut offset);
        debug_assert_eq!(offset, REALM_PROOF_BINDING_V1_LEN);

        let expected_digest = digest(BINDING_DIGEST_DOMAIN, &bytes[..REALM_PROOF_BINDING_PAYLOAD_LEN]);
        if stored_digest != expected_digest {
            return Err(RealmProofBindingError::BindingDigestMismatch);
        }
        validate_persisted_fields(
            authority,
            &canonical_chain,
            state_checkpoint,
            old_realm_root,
            new_realm_root,
            coordinator_tree_height,
            circuit_type,
        )?;

        Ok(Self {
            authority,
            canonical_chain,
            state_checkpoint,
            old_realm_root,
            new_realm_root,
            coordinator_tree_height,
            circuit_type,
            proof_public_inputs_hash,
            prepared_payload_digest,
            submission_header_digest,
            proof_bytes_digest,
            coordinator_update_digest,
            inclusion_proof_digest,
            canonical_bytes: bytes.to_vec(),
            digest: RealmProofBindingDigest(stored_digest),
        })
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn canonical_chain(&self) -> &CanonicalChainRef<Hash> {
        &self.canonical_chain
    }

    pub const fn state_checkpoint(&self) -> AuthorityStateCheckpointId {
        self.state_checkpoint
    }

    pub const fn old_realm_root(&self) -> &Hash {
        &self.old_realm_root
    }

    pub const fn new_realm_root(&self) -> &Hash {
        &self.new_realm_root
    }

    pub const fn coordinator_tree_height(&self) -> u8 {
        self.coordinator_tree_height
    }

    pub const fn circuit_type(&self) -> u32 {
        self.circuit_type
    }

    pub const fn proof_public_inputs_hash(
        &self,
    ) -> GutaProofPublicInputsHash<Hash>
    where
        Hash: Copy,
    {
        self.proof_public_inputs_hash
    }

    pub const fn prepared_payload_digest(&self) -> &[u8; 32] {
        &self.prepared_payload_digest
    }

    pub const fn submission_header_digest(&self) -> &[u8; 32] {
        &self.submission_header_digest
    }

    pub const fn proof_bytes_digest(&self) -> &[u8; 32] {
        &self.proof_bytes_digest
    }

    pub const fn coordinator_update_digest(&self) -> &[u8; 32] {
        &self.coordinator_update_digest
    }

    pub const fn inclusion_proof_digest(&self) -> &[u8; 32] {
        &self.inclusion_proof_digest
    }

    pub fn encode_canonical(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> RealmProofBindingDigest {
        self.digest
    }
}

/// Capability produced only after the exact proof bytes pass the supplied ZK
/// verifier and the Coordinator inclusion proof is checked against the
/// checkpoint's global-user-tree root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedRealmProofBinding<Hash> {
    record: PersistedRealmProofBinding<Hash>,
}

impl<Hash: Q256BitHash> SealedRealmProofBinding<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_seal<F, Hasher, Proof, Verifier>(
        authority: AuthorityScope,
        prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
        submission: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<
            F,
            Hash,
        >,
        proof_bytes: &[u8],
        proof_verifier: &Verifier,
        coordinator: &PsyRealmCoordinatorUpdate<F, Hash>,
        coordinator_tree_height: u8,
    ) -> Result<Self, RealmProofBindingError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: FieldQHasher<F, Hash>,
        Verifier: QZKProofVerifier<Hash, Proof>,
    {
        let (realm_id, realm_sub_id) = match authority {
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } => (realm_id, realm_sub_id),
            AuthorityScope::Coordinator => {
                return Err(RealmProofBindingError::RealmAuthorityRequired)
            }
        };
        if u64::from(realm_id) != prepared.realm_id
            || u64::from(realm_sub_id) != prepared.realm_sub_id
        {
            return Err(RealmProofBindingError::PreparedAuthorityMismatch);
        }
        if prepared.old_realm_root == prepared.new_realm_root {
            return Err(RealmProofBindingError::ChangedRealmStateRequired);
        }
        if prepared.update_contract_state_imt_leaves_ffs.is_empty() {
            return Err(RealmProofBindingError::ImtPreparedMutationRequired);
        }
        if prepared.update_global_user_tree_nodes_ffs.is_empty() {
            return Err(RealmProofBindingError::RealmRootMutationRequired);
        }

        validate_tree_position(
            prepared.realm_id,
            coordinator_tree_height,
        )?;
        validate_realm_root_mutation(
            &prepared.update_global_user_tree_nodes_ffs,
            prepared.realm_id,
            coordinator_tree_height,
            prepared.new_realm_root,
        )?;
        let transition = submission.header.header.state_transition;
        if transition.node_index.to_u64_value() != prepared.realm_id {
            return Err(RealmProofBindingError::SubmissionRealmIndexMismatch);
        }
        if transition.node_level.to_u64_value()
            != u64::from(coordinator_tree_height)
        {
            return Err(RealmProofBindingError::SubmissionRealmLevelMismatch);
        }
        if transition.old_node_value != prepared.old_realm_root {
            return Err(RealmProofBindingError::SubmissionOldRootMismatch);
        }
        if transition.new_node_value != prepared.new_realm_root {
            return Err(RealmProofBindingError::SubmissionNewRootMismatch);
        }
        validate_guta_circuit(submission.job_type_u32)?;

        let sync = &coordinator.checkpoint_sync_info;
        let chain_checkpoint = coordinator
            .canonical_chain_ref
            .checkpoint()
            .checkpoint_id()
            .get();
        if chain_checkpoint != sync.checkpoint_id {
            return Err(RealmProofBindingError::CanonicalCheckpointMismatch);
        }
        if sync.block_state.checkpoint_id != sync.checkpoint_id {
            return Err(RealmProofBindingError::L2CheckpointMismatch);
        }
        if sync.state_roots.qfhash::<Hasher>()
            != sync.checkpoint_leaf.global_chain_root
        {
            return Err(RealmProofBindingError::CheckpointStateRootsMismatch);
        }
        if sync.checkpoint_leaf.qfhash::<Hasher>() != sync.checkpoint_leaf_hash {
            return Err(RealmProofBindingError::CheckpointLeafHashMismatch);
        }

        let inclusion = &coordinator.merkle_proof_to_realm_root;
        if inclusion.value != prepared.new_realm_root {
            return Err(RealmProofBindingError::InclusionValueMismatch);
        }
        if inclusion.index != prepared.realm_id {
            return Err(RealmProofBindingError::InclusionIndexMismatch);
        }
        if inclusion.siblings.len() != usize::from(coordinator_tree_height) {
            return Err(RealmProofBindingError::InclusionHeightMismatch {
                expected: coordinator_tree_height,
                actual: inclusion.siblings.len(),
            });
        }
        if inclusion.root != sync.state_roots.user_tree_root {
            return Err(RealmProofBindingError::InclusionRootMismatch);
        }
        if !inclusion.verify::<Hasher>() {
            return Err(RealmProofBindingError::InvalidInclusionProof);
        }

        if proof_bytes.is_empty() {
            return Err(RealmProofBindingError::EmptyProofBytes);
        }
        let expected_public_inputs_hash = submission.qfhash::<Hasher>();
        proof_verifier
            .verify_zk_proof_from_slice_check_public_inputs_hash(
                submission.job_type_u32,
                proof_bytes,
                expected_public_inputs_hash,
            )
            .map_err(|_| RealmProofBindingError::ZkProofVerificationFailed)?;

        let prepared_bytes = prepared
            .psy_ser_to_bytes_vec()
            .map_err(|_| RealmProofBindingError::PreparedSerializationFailed)?;
        let submission_bytes = submission
            .psy_ser_to_bytes_vec()
            .map_err(|_| RealmProofBindingError::SubmissionSerializationFailed)?;
        let coordinator_bytes = coordinator
            .psy_ser_to_bytes_vec()
            .map_err(|_| RealmProofBindingError::CoordinatorSerializationFailed)?;
        let inclusion_bytes = inclusion
            .psy_ser_to_bytes_vec()
            .map_err(|_| RealmProofBindingError::InclusionSerializationFailed)?;

        let state_checkpoint = AuthorityStateCheckpointId::new(sync.checkpoint_id);
        let prepared_payload_digest =
            digest(PREPARED_DIGEST_DOMAIN, &prepared_bytes);
        let submission_header_digest =
            digest(SUBMISSION_DIGEST_DOMAIN, &submission_bytes);
        let proof_bytes_digest = digest(PROOF_DIGEST_DOMAIN, proof_bytes);
        let coordinator_update_digest =
            digest(COORDINATOR_UPDATE_DIGEST_DOMAIN, &coordinator_bytes);
        let inclusion_proof_digest =
            digest(INCLUSION_PROOF_DIGEST_DOMAIN, &inclusion_bytes);

        let mut canonical_bytes = Vec::with_capacity(REALM_PROOF_BINDING_V1_LEN);
        canonical_bytes.extend_from_slice(&REALM_PROOF_BINDING_MAGIC);
        canonical_bytes.extend_from_slice(
            &REALM_PROOF_BINDING_CODEC_VERSION.to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(&realm_id.to_le_bytes());
        canonical_bytes.extend_from_slice(&realm_sub_id.to_le_bytes());
        canonical_bytes.extend_from_slice(
            &coordinator.canonical_chain_ref.to_canonical_bytes(),
        );
        canonical_bytes.extend_from_slice(&state_checkpoint.get().to_le_bytes());
        canonical_bytes.extend_from_slice(
            &prepared.old_realm_root.into_owned_32bytes(),
        );
        canonical_bytes.extend_from_slice(
            &prepared.new_realm_root.into_owned_32bytes(),
        );
        canonical_bytes.push(coordinator_tree_height);
        canonical_bytes.extend_from_slice(&submission.job_type_u32.to_le_bytes());
        canonical_bytes.extend_from_slice(
            &expected_public_inputs_hash.into_owned_32bytes(),
        );
        canonical_bytes.extend_from_slice(&prepared_payload_digest);
        canonical_bytes.extend_from_slice(&submission_header_digest);
        canonical_bytes.extend_from_slice(&proof_bytes_digest);
        canonical_bytes.extend_from_slice(&coordinator_update_digest);
        canonical_bytes.extend_from_slice(&inclusion_proof_digest);
        debug_assert_eq!(
            canonical_bytes.len(),
            REALM_PROOF_BINDING_PAYLOAD_LEN
        );
        let binding_digest = digest(BINDING_DIGEST_DOMAIN, &canonical_bytes);
        canonical_bytes.extend_from_slice(&binding_digest);
        debug_assert_eq!(canonical_bytes.len(), REALM_PROOF_BINDING_V1_LEN);

        Ok(Self {
            record: PersistedRealmProofBinding {
                authority,
                canonical_chain: coordinator.canonical_chain_ref,
                state_checkpoint,
                old_realm_root: prepared.old_realm_root,
                new_realm_root: prepared.new_realm_root,
                coordinator_tree_height,
                circuit_type: submission.job_type_u32,
                proof_public_inputs_hash: GutaProofPublicInputsHash(
                    expected_public_inputs_hash,
                ),
                prepared_payload_digest,
                submission_header_digest,
                proof_bytes_digest,
                coordinator_update_digest,
                inclusion_proof_digest,
                canonical_bytes,
                digest: RealmProofBindingDigest(binding_digest),
            },
        })
    }

    pub const fn record(&self) -> &PersistedRealmProofBinding<Hash> {
        &self.record
    }

    pub const fn digest(&self) -> RealmProofBindingDigest {
        self.record.digest
    }

    pub fn encode_canonical(&self) -> &[u8] {
        self.record.encode_canonical()
    }
}

fn validate_persisted_fields<Hash: Q256BitHash>(
    authority: AuthorityScope,
    canonical_chain: &CanonicalChainRef<Hash>,
    state_checkpoint: AuthorityStateCheckpointId,
    old_realm_root: Hash,
    new_realm_root: Hash,
    coordinator_tree_height: u8,
    circuit_type: u32,
) -> Result<(), RealmProofBindingError> {
    let realm_id = match authority {
        AuthorityScope::Realm { realm_id, .. } => u64::from(realm_id),
        AuthorityScope::Coordinator => {
            return Err(RealmProofBindingError::RealmAuthorityRequired)
        }
    };
    validate_tree_position(realm_id, coordinator_tree_height)?;
    validate_guta_circuit(circuit_type)?;
    if canonical_chain.checkpoint().checkpoint_id().get()
        != state_checkpoint.get()
    {
        return Err(RealmProofBindingError::CanonicalCheckpointMismatch);
    }
    if old_realm_root == new_realm_root {
        return Err(RealmProofBindingError::ChangedRealmStateRequired);
    }
    Ok(())
}

fn validate_tree_position(
    realm_id: u64,
    coordinator_tree_height: u8,
) -> Result<(), RealmProofBindingError> {
    if coordinator_tree_height == 0 || coordinator_tree_height >= 64 {
        return Err(RealmProofBindingError::InvalidCoordinatorTreeHeight(
            coordinator_tree_height,
        ));
    }
    let leaf_count = 1u64 << coordinator_tree_height;
    if realm_id >= leaf_count {
        return Err(RealmProofBindingError::RealmIndexOutOfRange {
            realm_id,
            coordinator_tree_height,
        });
    }
    Ok(())
}

fn validate_realm_root_mutation<Hash: Q256BitHash>(
    bytes: &[u8],
    realm_id: u64,
    coordinator_tree_height: u8,
    expected_root: Hash,
) -> Result<(), RealmProofBindingError> {
    if bytes.len() % PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE != 0 {
        return Err(RealmProofBindingError::InvalidRealmRootMutationEncoding);
    }
    let mut observed_root = None;
    for chunk in bytes.chunks_exact(PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE) {
        let node = SimpleMerkleNode::<Hash>::ffs_try_from_slice(chunk)
            .map_err(|_| RealmProofBindingError::InvalidRealmRootMutationEncoding)?;
        if node.key.level == coordinator_tree_height && node.key.index == realm_id {
            if observed_root.replace(node.value).is_some() {
                return Err(RealmProofBindingError::DuplicateRealmRootMutation);
            }
        }
    }
    match observed_root {
        None => Err(RealmProofBindingError::RealmRootMutationMissing),
        Some(actual) if actual != expected_root => {
            Err(RealmProofBindingError::RealmRootMutationValueMismatch)
        }
        Some(_) => Ok(()),
    }
}

fn validate_guta_circuit(circuit_type: u32) -> Result<(), RealmProofBindingError> {
    let circuit = ProvingJobCircuitType::try_from_u32(circuit_type)
        .map_err(|_| RealmProofBindingError::NonGutaCircuit(circuit_type))?;
    match circuit {
        ProvingJobCircuitType::GUTATwoEndCap
        | ProvingJobCircuitType::GUTATwoGUTA
        | ProvingJobCircuitType::GUTALeftEndCapRightGUTA
        | ProvingJobCircuitType::GUTALeftGUTARightEndCap
        | ProvingJobCircuitType::GUTASingleEndCap
        | ProvingJobCircuitType::GUTARegisterUsers
        | ProvingJobCircuitType::GUTAVerifyToCap
        | ProvingJobCircuitType::GUTAOnlyRegisterUsers
        | ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
        | ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade
        | ProvingJobCircuitType::GUTATwoGUTALinear
        | ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint
        | ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint
        | ProvingJobCircuitType::GUTAVerifyLeftLeafRightLinearUpgradeCheckpoint => {
            Ok(())
        }
        _ => Err(RealmProofBindingError::NonGutaCircuit(circuit_type)),
    }
}

fn take_digest(bytes: &[u8], offset: &mut usize) -> [u8; 32] {
    let value = bytes[*offset..*offset + 32]
        .try_into()
        .expect("validated fixed binding length");
    *offset += 32;
    value
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProofBindingError {
    RealmAuthorityRequired,
    PreparedAuthorityMismatch,
    ChangedRealmStateRequired,
    ImtPreparedMutationRequired,
    RealmRootMutationRequired,
    InvalidRealmRootMutationEncoding,
    RealmRootMutationMissing,
    DuplicateRealmRootMutation,
    RealmRootMutationValueMismatch,
    InvalidCoordinatorTreeHeight(u8),
    RealmIndexOutOfRange {
        realm_id: u64,
        coordinator_tree_height: u8,
    },
    SubmissionRealmIndexMismatch,
    SubmissionRealmLevelMismatch,
    SubmissionOldRootMismatch,
    SubmissionNewRootMismatch,
    NonGutaCircuit(u32),
    CanonicalCheckpointMismatch,
    L2CheckpointMismatch,
    CheckpointStateRootsMismatch,
    CheckpointLeafHashMismatch,
    InclusionValueMismatch,
    InclusionIndexMismatch,
    InclusionHeightMismatch { expected: u8, actual: usize },
    InclusionRootMismatch,
    InvalidInclusionProof,
    EmptyProofBytes,
    ZkProofVerificationFailed,
    PreparedSerializationFailed,
    SubmissionSerializationFailed,
    CoordinatorSerializationFailed,
    InclusionSerializationFailed,
    InvalidCanonicalLength { expected: usize, actual: usize },
    InvalidMagic,
    UnknownCodecVersion(u16),
    InvalidCanonicalChain,
    BindingDigestMismatch,
}

impl fmt::Display for RealmProofBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RealmAuthorityRequired => write!(formatter, "Realm authority required"),
            Self::PreparedAuthorityMismatch => write!(formatter, "prepared Realm authority mismatch"),
            Self::ChangedRealmStateRequired => write!(formatter, "changed Realm state required"),
            Self::ImtPreparedMutationRequired => write!(formatter, "prepared IMT mutation required"),
            Self::RealmRootMutationRequired => write!(formatter, "prepared Realm-root mutation required"),
            Self::InvalidRealmRootMutationEncoding => write!(formatter, "invalid prepared Realm-root FFS encoding"),
            Self::RealmRootMutationMissing => write!(formatter, "prepared Realm-root row is missing"),
            Self::DuplicateRealmRootMutation => write!(formatter, "prepared Realm-root row is duplicated"),
            Self::RealmRootMutationValueMismatch => write!(formatter, "prepared Realm-root value mismatch"),
            Self::InvalidCoordinatorTreeHeight(height) => write!(formatter, "invalid Coordinator tree height {height}"),
            Self::RealmIndexOutOfRange { realm_id, coordinator_tree_height } => write!(formatter, "Realm index {realm_id} is outside Coordinator tree height {coordinator_tree_height}"),
            Self::SubmissionRealmIndexMismatch => write!(formatter, "GUTA submission Realm index mismatch"),
            Self::SubmissionRealmLevelMismatch => write!(formatter, "GUTA submission Realm level mismatch"),
            Self::SubmissionOldRootMismatch => write!(formatter, "GUTA submission old root mismatch"),
            Self::SubmissionNewRootMismatch => write!(formatter, "GUTA submission new root mismatch"),
            Self::NonGutaCircuit(value) => write!(formatter, "circuit {value} is not an accepted GUTA root circuit"),
            Self::CanonicalCheckpointMismatch => write!(formatter, "canonical/state checkpoint mismatch"),
            Self::L2CheckpointMismatch => write!(formatter, "L2 block-state checkpoint mismatch"),
            Self::CheckpointStateRootsMismatch => write!(formatter, "checkpoint state-roots commitment mismatch"),
            Self::CheckpointLeafHashMismatch => write!(formatter, "checkpoint leaf hash mismatch"),
            Self::InclusionValueMismatch => write!(formatter, "Realm inclusion value mismatch"),
            Self::InclusionIndexMismatch => write!(formatter, "Realm inclusion index mismatch"),
            Self::InclusionHeightMismatch { expected, actual } => write!(formatter, "Realm inclusion height mismatch: expected {expected}, actual {actual}"),
            Self::InclusionRootMismatch => write!(formatter, "Realm inclusion root is not checkpoint user-tree root"),
            Self::InvalidInclusionProof => write!(formatter, "invalid Realm inclusion proof"),
            Self::EmptyProofBytes => write!(formatter, "GUTA proof bytes are empty"),
            Self::ZkProofVerificationFailed => write!(formatter, "GUTA ZK proof verification failed"),
            Self::PreparedSerializationFailed => write!(formatter, "failed to serialize Realm prepared payload"),
            Self::SubmissionSerializationFailed => write!(formatter, "failed to serialize GUTA submission"),
            Self::CoordinatorSerializationFailed => write!(formatter, "failed to serialize Coordinator sync response"),
            Self::InclusionSerializationFailed => write!(formatter, "failed to serialize Realm inclusion proof"),
            Self::InvalidCanonicalLength { expected, actual } => write!(formatter, "invalid binding length: expected {expected}, actual {actual}"),
            Self::InvalidMagic => write!(formatter, "invalid Realm proof-binding magic"),
            Self::UnknownCodecVersion(version) => write!(formatter, "unknown Realm proof-binding codec version {version}"),
            Self::InvalidCanonicalChain => write!(formatter, "invalid canonical chain reference"),
            Self::BindingDigestMismatch => write!(formatter, "Realm proof-binding digest mismatch"),
        }
    }
}

impl Error for RealmProofBindingError {}
