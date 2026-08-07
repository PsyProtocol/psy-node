//! One fail-closed capability binding a verified Realm proof envelope to the
//! independently verified prepared IMT mutation graph.
//!
//! Decoding the durable record does not recreate either live seal and cannot
//! grant commit authority. Production manifest integration remains a separate
//! step.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::{AuthorityScope, AuthorityStateCheckpointId},
};
use sha2::{Digest, Sha256};

use super::{
    realm_imt_mutation_graph::{
        RealmImtMutationGraphDigest, SealedRealmImtMutationGraph,
    },
    realm_prepared_payload::RealmPreparedPayloadCommitment,
    realm_proof_binding::{RealmProofBindingDigest, SealedRealmProofBinding},
};

pub const REALM_COMMIT_EVIDENCE_MAGIC: [u8; 8] = *b"PSYRCEV1";
pub const REALM_COMMIT_EVIDENCE_CODEC_VERSION: u16 = 1;

const BUNDLE_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-commit-evidence.v1\0";
const AUTHORITY_LEN: usize = 6;
const ROOTS_LEN: usize = 64;
const DIGEST_FIELDS_LEN: usize = 32 * 3;
const REALM_COMMIT_EVIDENCE_PAYLOAD_LEN: usize = 8
    + 2
    + AUTHORITY_LEN
    + CANONICAL_CHAIN_REF_V1_LEN
    + 8
    + 8
    + ROOTS_LEN
    + 1
    + DIGEST_FIELDS_LEN;
pub const REALM_COMMIT_EVIDENCE_V1_LEN: usize =
    REALM_COMMIT_EVIDENCE_PAYLOAD_LEN + 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmCommitEvidenceDigest([u8; 32]);

impl RealmCommitEvidenceDigest {
    pub const fn as_bytes(self) -> [u8; 32] { self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRealmCommitEvidence<Hash> {
    authority: AuthorityScope,
    canonical_chain: CanonicalChainRef<Hash>,
    predecessor_checkpoint: AuthorityStateCheckpointId,
    state_checkpoint: AuthorityStateCheckpointId,
    old_realm_root: Hash,
    new_realm_root: Hash,
    coordinator_tree_height: u8,
    prepared_payload_commitment: RealmPreparedPayloadCommitment,
    proof_binding_digest: RealmProofBindingDigest,
    mutation_graph_digest: RealmImtMutationGraphDigest,
    canonical_bytes: Vec<u8>,
    digest: RealmCommitEvidenceDigest,
}

impl<Hash: Q256BitHash> PersistedRealmCommitEvidence<Hash> {
    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmCommitEvidenceError> {
        if bytes.len() != REALM_COMMIT_EVIDENCE_V1_LEN {
            return Err(RealmCommitEvidenceError::InvalidCanonicalLength {
                expected: REALM_COMMIT_EVIDENCE_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[..8] != REALM_COMMIT_EVIDENCE_MAGIC {
            return Err(RealmCommitEvidenceError::InvalidMagic);
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed"));
        if version != REALM_COMMIT_EVIDENCE_CODEC_VERSION {
            return Err(RealmCommitEvidenceError::UnknownCodecVersion(version));
        }

        let mut offset = 10;
        let authority = AuthorityScope::Realm {
            realm_id: u32::from_le_bytes(
                bytes[offset..offset + 4].try_into().expect("fixed"),
            ),
            realm_sub_id: u16::from_le_bytes(
                bytes[offset + 4..offset + 6].try_into().expect("fixed"),
            ),
        };
        offset += AUTHORITY_LEN;
        let canonical_chain_bytes: [u8; CANONICAL_CHAIN_REF_V1_LEN] = bytes
            [offset..offset + CANONICAL_CHAIN_REF_V1_LEN]
            .try_into()
            .expect("fixed");
        let canonical_chain = CanonicalChainRef::from_canonical_bytes(
            &canonical_chain_bytes,
        )
        .map_err(|_| RealmCommitEvidenceError::InvalidCanonicalChain)?;
        offset += CANONICAL_CHAIN_REF_V1_LEN;
        let predecessor_checkpoint = AuthorityStateCheckpointId::new(
            u64::from_le_bytes(
                bytes[offset..offset + 8].try_into().expect("fixed"),
            ),
        );
        offset += 8;
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
        let prepared_payload_commitment =
            RealmPreparedPayloadCommitment::from_bytes(take_digest(bytes, &mut offset));
        let proof_binding_digest = RealmProofBindingDigest::from_bytes(
            take_digest(bytes, &mut offset),
        );
        let mutation_graph_digest = RealmImtMutationGraphDigest::from_bytes(
            take_digest(bytes, &mut offset),
        );
        debug_assert_eq!(offset, REALM_COMMIT_EVIDENCE_PAYLOAD_LEN);
        let stored_digest = take_digest(bytes, &mut offset);
        let expected_digest = digest(
            BUNDLE_DIGEST_DOMAIN,
            &bytes[..REALM_COMMIT_EVIDENCE_PAYLOAD_LEN],
        );
        if stored_digest != expected_digest {
            return Err(RealmCommitEvidenceError::BundleDigestMismatch);
        }
        validate_identity(
            authority,
            &canonical_chain,
            predecessor_checkpoint,
            state_checkpoint,
            old_realm_root,
            new_realm_root,
            coordinator_tree_height,
        )?;

        Ok(Self {
            authority,
            canonical_chain,
            predecessor_checkpoint,
            state_checkpoint,
            old_realm_root,
            new_realm_root,
            coordinator_tree_height,
            prepared_payload_commitment,
            proof_binding_digest,
            mutation_graph_digest,
            canonical_bytes: bytes.to_vec(),
            digest: RealmCommitEvidenceDigest(stored_digest),
        })
    }

    pub const fn authority(&self) -> AuthorityScope { self.authority }
    pub const fn canonical_chain(&self) -> &CanonicalChainRef<Hash> { &self.canonical_chain }
    pub const fn predecessor_checkpoint(&self) -> AuthorityStateCheckpointId { self.predecessor_checkpoint }
    pub const fn state_checkpoint(&self) -> AuthorityStateCheckpointId { self.state_checkpoint }
    pub const fn old_realm_root(&self) -> &Hash { &self.old_realm_root }
    pub const fn new_realm_root(&self) -> &Hash { &self.new_realm_root }
    pub const fn coordinator_tree_height(&self) -> u8 { self.coordinator_tree_height }
    pub const fn prepared_payload_commitment(&self) -> RealmPreparedPayloadCommitment { self.prepared_payload_commitment }
    pub const fn proof_binding_digest(&self) -> RealmProofBindingDigest { self.proof_binding_digest }
    pub const fn mutation_graph_digest(&self) -> RealmImtMutationGraphDigest { self.mutation_graph_digest }
    pub fn encode_canonical(&self) -> &[u8] { &self.canonical_bytes }
    pub const fn digest(&self) -> RealmCommitEvidenceDigest { self.digest }
}

#[derive(Clone, Debug)]
pub struct SealedRealmCommitEvidence<Hash, Hasher> {
    proof: SealedRealmProofBinding<Hash>,
    graph: SealedRealmImtMutationGraph<Hash, Hasher>,
    record: PersistedRealmCommitEvidence<Hash>,
}

impl<Hash: Q256BitHash, Hasher> SealedRealmCommitEvidence<Hash, Hasher> {
    pub fn try_bind(
        proof: SealedRealmProofBinding<Hash>,
        graph: SealedRealmImtMutationGraph<Hash, Hasher>,
    ) -> Result<Self, RealmCommitEvidenceError> {
        let proof_record = proof.record();
        if proof_record.authority() != graph.authority() {
            return Err(RealmCommitEvidenceError::AuthorityMismatch);
        }
        if proof_record.state_checkpoint() != graph.state_checkpoint() {
            return Err(RealmCommitEvidenceError::StateCheckpointMismatch {
                proof: proof_record.state_checkpoint(),
                graph: graph.state_checkpoint(),
            });
        }
        let proof_height = proof_record.coordinator_tree_height();
        let graph_height = graph.config().coordinator_tree_height();
        if proof_height != graph_height {
            return Err(RealmCommitEvidenceError::CoordinatorTreeHeightMismatch {
                proof: proof_height,
                graph: graph_height,
            });
        }
        if proof_record.old_realm_root() != graph.old_realm_root() {
            return Err(RealmCommitEvidenceError::OldRealmRootMismatch);
        }
        if proof_record.new_realm_root() != graph.new_realm_root() {
            return Err(RealmCommitEvidenceError::NewRealmRootMismatch);
        }
        if proof.prepared_payload_commitment()
            != graph.prepared_payload_commitment()
        {
            return Err(RealmCommitEvidenceError::PreparedPayloadMismatch);
        }

        let authority = proof_record.authority();
        let canonical_chain = *proof_record.canonical_chain();
        let predecessor_checkpoint = graph.predecessor_checkpoint();
        let state_checkpoint = graph.state_checkpoint();
        let old_realm_root = *graph.old_realm_root();
        let new_realm_root = *graph.new_realm_root();
        let prepared_payload_commitment =
            graph.prepared_payload_commitment();
        let proof_binding_digest = proof.digest();
        let mutation_graph_digest = graph.digest();

        validate_identity(
            authority,
            &canonical_chain,
            predecessor_checkpoint,
            state_checkpoint,
            old_realm_root,
            new_realm_root,
            graph_height,
        )?;
        let mut canonical_bytes =
            Vec::with_capacity(REALM_COMMIT_EVIDENCE_V1_LEN);
        canonical_bytes.extend_from_slice(&REALM_COMMIT_EVIDENCE_MAGIC);
        canonical_bytes.extend_from_slice(
            &REALM_COMMIT_EVIDENCE_CODEC_VERSION.to_le_bytes(),
        );
        let (realm_id, realm_sub_id) = match authority {
            AuthorityScope::Realm { realm_id, realm_sub_id } => {
                (realm_id, realm_sub_id)
            }
            AuthorityScope::Coordinator => unreachable!("both seals require Realm authority"),
        };
        canonical_bytes.extend_from_slice(&realm_id.to_le_bytes());
        canonical_bytes.extend_from_slice(&realm_sub_id.to_le_bytes());
        canonical_bytes.extend_from_slice(&canonical_chain.to_canonical_bytes());
        canonical_bytes.extend_from_slice(
            &predecessor_checkpoint.get().to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(&state_checkpoint.get().to_le_bytes());
        canonical_bytes.extend_from_slice(&old_realm_root.into_owned_32bytes());
        canonical_bytes.extend_from_slice(&new_realm_root.into_owned_32bytes());
        canonical_bytes.push(graph_height);
        canonical_bytes.extend_from_slice(
            &prepared_payload_commitment.as_bytes(),
        );
        canonical_bytes.extend_from_slice(&proof_binding_digest.as_bytes());
        canonical_bytes.extend_from_slice(&mutation_graph_digest.as_bytes());
        debug_assert_eq!(canonical_bytes.len(), REALM_COMMIT_EVIDENCE_PAYLOAD_LEN);
        let bundle_digest = digest(BUNDLE_DIGEST_DOMAIN, &canonical_bytes);
        canonical_bytes.extend_from_slice(&bundle_digest);
        debug_assert_eq!(canonical_bytes.len(), REALM_COMMIT_EVIDENCE_V1_LEN);
        let record = PersistedRealmCommitEvidence {
            authority,
            canonical_chain,
            predecessor_checkpoint,
            state_checkpoint,
            old_realm_root,
            new_realm_root,
            coordinator_tree_height: graph_height,
            prepared_payload_commitment,
            proof_binding_digest,
            mutation_graph_digest,
            canonical_bytes,
            digest: RealmCommitEvidenceDigest(bundle_digest),
        };
        Ok(Self { proof, graph, record })
    }

    pub const fn proof(&self) -> &SealedRealmProofBinding<Hash> { &self.proof }
    pub const fn graph(&self) -> &SealedRealmImtMutationGraph<Hash, Hasher> { &self.graph }
    pub const fn record(&self) -> &PersistedRealmCommitEvidence<Hash> { &self.record }
    pub const fn digest(&self) -> RealmCommitEvidenceDigest { self.record.digest }
    pub fn encode_canonical(&self) -> &[u8] { self.record.encode_canonical() }

    pub fn into_record(self) -> PersistedRealmCommitEvidence<Hash> {
        self.record
    }
}

fn validate_identity<Hash: Q256BitHash>(
    authority: AuthorityScope,
    canonical_chain: &CanonicalChainRef<Hash>,
    predecessor_checkpoint: AuthorityStateCheckpointId,
    state_checkpoint: AuthorityStateCheckpointId,
    old_realm_root: Hash,
    new_realm_root: Hash,
    coordinator_tree_height: u8,
) -> Result<(), RealmCommitEvidenceError> {
    let realm_id = match authority {
        AuthorityScope::Realm { realm_id, .. } => u64::from(realm_id),
        AuthorityScope::Coordinator => {
            return Err(RealmCommitEvidenceError::RealmAuthorityRequired)
        }
    };
    if canonical_chain.checkpoint().checkpoint_id().get()
        != state_checkpoint.get()
    {
        return Err(RealmCommitEvidenceError::CanonicalStateCheckpointMismatch);
    }
    if predecessor_checkpoint.get() >= state_checkpoint.get() {
        return Err(RealmCommitEvidenceError::InvalidCheckpointOrder);
    }
    if old_realm_root == new_realm_root {
        return Err(RealmCommitEvidenceError::ChangedRealmStateRequired);
    }
    if coordinator_tree_height == 0 || coordinator_tree_height >= 64 {
        return Err(RealmCommitEvidenceError::InvalidCoordinatorTreeHeight(
            coordinator_tree_height,
        ));
    }
    if realm_id >= 1u64 << coordinator_tree_height {
        return Err(RealmCommitEvidenceError::RealmIndexOutOfRange {
            realm_id,
            coordinator_tree_height,
        });
    }
    Ok(())
}

fn take_digest(bytes: &[u8], offset: &mut usize) -> [u8; 32] {
    let value = bytes[*offset..*offset + 32].try_into().expect("fixed");
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
pub enum RealmCommitEvidenceError {
    AuthorityMismatch,
    StateCheckpointMismatch {
        proof: AuthorityStateCheckpointId,
        graph: AuthorityStateCheckpointId,
    },
    CoordinatorTreeHeightMismatch { proof: u8, graph: u8 },
    OldRealmRootMismatch,
    NewRealmRootMismatch,
    PreparedPayloadMismatch,
    RealmAuthorityRequired,
    CanonicalStateCheckpointMismatch,
    InvalidCheckpointOrder,
    ChangedRealmStateRequired,
    InvalidCoordinatorTreeHeight(u8),
    RealmIndexOutOfRange {
        realm_id: u64,
        coordinator_tree_height: u8,
    },
    InvalidCanonicalLength { expected: usize, actual: usize },
    InvalidMagic,
    UnknownCodecVersion(u16),
    InvalidCanonicalChain,
    BundleDigestMismatch,
}

impl fmt::Display for RealmCommitEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RealmCommitEvidenceError {}
