//! Immutable completion record for one fully materialized Coordinator commit.
//!
//! The record joins an exact 23-domain manifest with a source-bound local
//! checkpoint backup observation. It still cannot mark the source COMMITTED
//! or publish the canonical head; those remain later affine-owner actions.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CANONICAL_CHAIN_REF_V1_LEN, CanonicalChainRef,
};
use psy_node_core::store::coordinator_commit_source::CoordinatorCheckpointBackupEvidence;
use sha2::{Digest, Sha256};

use super::coordinator_commit_full_manifest::CoordinatorCommitFullManifest;

const MAGIC: [u8; 8] = *b"PSYCFWCP";
const CODEC_VERSION: u16 = 1;
const REVISION: u64 = 1;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.coordinator-full-completion-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.coordinator-full-completion.v1\0";
const MAX_PAYLOAD_BYTES: usize = 640;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CoordinatorCommitFullCompletionSlot([u8; 32]);

impl CoordinatorCommitFullCompletionSlot {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitFullCompletion<Hash> {
    slot: CoordinatorCommitFullCompletionSlot,
    revision: u64,
    candidate: CanonicalChainRef<Hash>,
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    manifest_slot: [u8; 32],
    manifest_digest: [u8; 32],
    full_observation_digest: [u8; 32],
    checkpoint_id: u64,
    checkpoint_hash: Hash,
    old_root: Hash,
    new_root: Hash,
    min_backed_up_checkpoint_id: u64,
    next_backup_checkpoint_id: u64,
    backup_evidence_digest: [u8; 32],
    canonical_payload: Vec<u8>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> CoordinatorCommitFullCompletion<Hash> {
    pub(crate) fn try_from_manifest_and_backup(
        manifest: &CoordinatorCommitFullManifest<Hash>,
        backup: &CoordinatorCheckpointBackupEvidence<Hash>,
    ) -> Result<Self, CoordinatorCommitFullCompletionError> {
        if backup.source_slot() != manifest.source_slot()
            || backup.source_digest() != manifest.source_digest()
            || backup.candidate() != manifest.candidate()
            || backup.checkpoint_id()
                != manifest.candidate().checkpoint().checkpoint_id().get()
        {
            return Err(CoordinatorCommitFullCompletionError::IdentityMismatch);
        }
        let mut completion = Self {
            slot: completion_slot(*manifest.source_slot(), manifest.candidate()),
            revision: REVISION,
            candidate: *manifest.candidate(),
            source_slot: *manifest.source_slot(),
            source_digest: *manifest.source_digest(),
            manifest_slot: *manifest.slot().as_bytes(),
            manifest_digest: *manifest.digest(),
            full_observation_digest: *manifest.full_observation_digest(),
            checkpoint_id: backup.checkpoint_id(),
            checkpoint_hash: *backup.checkpoint_hash(),
            old_root: *backup.old_root(),
            new_root: *backup.new_root(),
            min_backed_up_checkpoint_id: backup.min_backed_up_checkpoint_id(),
            next_backup_checkpoint_id: backup.next_backup_checkpoint_id(),
            backup_evidence_digest: *backup.digest(),
            canonical_payload: Vec::new(),
            digest: [0; 32],
        };
        completion.canonical_payload = encode_completion(&completion);
        completion.digest = completion.canonical_payload
            [completion.canonical_payload.len() - 32..]
            .try_into()
            .expect("completion codec appends digest");
        Ok(completion)
    }

    pub(crate) fn decode_persisted(
        selected_slot: &[u8],
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, CoordinatorCommitFullCompletionError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(CoordinatorCommitFullCompletionError::PayloadTooLarge {
                actual: payload.len(),
            });
        }
        if revision != REVISION as i64 {
            return Err(CoordinatorCommitFullCompletionError::RevisionMismatch);
        }
        let body_len = payload
            .len()
            .checked_sub(32)
            .ok_or(CoordinatorCommitFullCompletionError::TruncatedPayload)?;
        let (body, encoded_digest) = payload.split_at(body_len);
        let digest = digest_bytes(DIGEST_DOMAIN, body);
        if encoded_digest != digest {
            return Err(CoordinatorCommitFullCompletionError::DigestMismatch);
        }
        let mut decoder = Decoder::new(body);
        if decoder.take(8)? != MAGIC {
            return Err(CoordinatorCommitFullCompletionError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(CoordinatorCommitFullCompletionError::UnknownCodecVersion);
        }
        if decoder.u64()? != REVISION {
            return Err(CoordinatorCommitFullCompletionError::RevisionMismatch);
        }
        let candidate = CanonicalChainRef::from_canonical_bytes(
            decoder.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|_| CoordinatorCommitFullCompletionError::InvalidCandidate)?;
        let source_slot = decoder.array32()?;
        let source_digest = decoder.nonzero_digest()?;
        let manifest_slot = decoder.array32()?;
        let manifest_digest = decoder.nonzero_digest()?;
        let full_observation_digest = decoder.nonzero_digest()?;
        let checkpoint_id = decoder.u64()?;
        let checkpoint_hash = Hash::from_ref_32bytes(&decoder.array32()?);
        let old_root = Hash::from_ref_32bytes(&decoder.array32()?);
        let new_root = Hash::from_ref_32bytes(&decoder.array32()?);
        let min_backed_up_checkpoint_id = decoder.u64()?;
        let next_backup_checkpoint_id = decoder.u64()?;
        let backup_evidence_digest = decoder.nonzero_digest()?;
        let slot = CoordinatorCommitFullCompletionSlot(decoder.array32()?);
        if !decoder.is_done() {
            return Err(CoordinatorCommitFullCompletionError::TrailingBytes);
        }
        if checkpoint_id != candidate.checkpoint().checkpoint_id().get()
            || next_backup_checkpoint_id != checkpoint_id.checked_add(1).ok_or(
                CoordinatorCommitFullCompletionError::CheckpointOverflow,
            )?
            || min_backed_up_checkpoint_id > checkpoint_id
            || old_root == new_root
            || slot != completion_slot(source_slot, &candidate)
            || selected_slot != slot.as_bytes()
        {
            return Err(CoordinatorCommitFullCompletionError::IdentityMismatch);
        }
        Ok(Self {
            slot,
            revision: REVISION,
            candidate,
            source_slot,
            source_digest,
            manifest_slot,
            manifest_digest,
            full_observation_digest,
            checkpoint_id,
            checkpoint_hash,
            old_root,
            new_root,
            min_backed_up_checkpoint_id,
            next_backup_checkpoint_id,
            backup_evidence_digest,
            canonical_payload: payload.to_vec(),
            digest,
        })
    }

    pub(crate) fn revalidate_manifest_and_backup(
        &self,
        manifest: &CoordinatorCommitFullManifest<Hash>,
        backup: &CoordinatorCheckpointBackupEvidence<Hash>,
    ) -> Result<(), CoordinatorCommitFullCompletionError> {
        let expected = Self::try_from_manifest_and_backup(manifest, backup)?;
        if self != &expected {
            return Err(CoordinatorCommitFullCompletionError::SourceChanged);
        }
        Ok(())
    }

    pub(crate) const fn slot(&self) -> CoordinatorCommitFullCompletionSlot {
        self.slot
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub(crate) const fn source_slot(&self) -> &[u8; 32] {
        &self.source_slot
    }

    pub(crate) const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(crate) const fn manifest_slot(&self) -> &[u8; 32] {
        &self.manifest_slot
    }

    pub(crate) const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    pub(crate) const fn checkpoint_id(&self) -> u64 {
        self.checkpoint_id
    }

    pub(crate) const fn checkpoint_hash(&self) -> &Hash {
        &self.checkpoint_hash
    }

    pub(crate) const fn backup_evidence_digest(&self) -> &[u8; 32] {
        &self.backup_evidence_digest
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

pub(crate) fn coordinator_commit_full_completion_slot<Hash: Q256BitHash>(
    source_slot: [u8; 32],
    candidate: &CanonicalChainRef<Hash>,
) -> CoordinatorCommitFullCompletionSlot {
    completion_slot(source_slot, candidate)
}

fn completion_slot<Hash: Q256BitHash>(
    source_slot: [u8; 32],
    candidate: &CanonicalChainRef<Hash>,
) -> CoordinatorCommitFullCompletionSlot {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(source_slot);
    hasher.update(candidate.to_canonical_bytes());
    CoordinatorCommitFullCompletionSlot(hasher.finalize().into())
}

fn encode_completion<Hash: Q256BitHash>(
    completion: &CoordinatorCommitFullCompletion<Hash>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(544);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    bytes.extend_from_slice(&completion.revision.to_be_bytes());
    bytes.extend_from_slice(&completion.candidate.to_canonical_bytes());
    bytes.extend_from_slice(&completion.source_slot);
    bytes.extend_from_slice(&completion.source_digest);
    bytes.extend_from_slice(&completion.manifest_slot);
    bytes.extend_from_slice(&completion.manifest_digest);
    bytes.extend_from_slice(&completion.full_observation_digest);
    bytes.extend_from_slice(&completion.checkpoint_id.to_be_bytes());
    bytes.extend_from_slice(&completion.checkpoint_hash.into_owned_32bytes());
    bytes.extend_from_slice(&completion.old_root.into_owned_32bytes());
    bytes.extend_from_slice(&completion.new_root.into_owned_32bytes());
    bytes.extend_from_slice(&completion.min_backed_up_checkpoint_id.to_be_bytes());
    bytes.extend_from_slice(&completion.next_backup_checkpoint_id.to_be_bytes());
    bytes.extend_from_slice(&completion.backup_evidence_digest);
    bytes.extend_from_slice(completion.slot.as_bytes());
    let digest = digest_bytes(DIGEST_DOMAIN, &bytes);
    bytes.extend_from_slice(&digest);
    bytes
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CoordinatorCommitFullCompletionError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CoordinatorCommitFullCompletionError::TruncatedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CoordinatorCommitFullCompletionError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, CoordinatorCommitFullCompletionError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("u16")))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorCommitFullCompletionError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("u64")))
    }

    fn array32(&mut self) -> Result<[u8; 32], CoordinatorCommitFullCompletionError> {
        Ok(self.take(32)?.try_into().expect("array32"))
    }

    fn nonzero_digest(&mut self) -> Result<[u8; 32], CoordinatorCommitFullCompletionError> {
        let value = self.array32()?;
        if value == [0; 32] {
            return Err(CoordinatorCommitFullCompletionError::ZeroDigest);
        }
        Ok(value)
    }

    fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitFullCompletionError {
    PayloadTooLarge { actual: usize },
    TruncatedPayload,
    InvalidMagic,
    UnknownCodecVersion,
    RevisionMismatch,
    DigestMismatch,
    InvalidCandidate,
    ZeroDigest,
    CheckpointOverflow,
    IdentityMismatch,
    TrailingBytes,
    SourceChanged,
}

impl fmt::Display for CoordinatorCommitFullCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator full completion: {self:?}")
    }
}

impl Error for CoordinatorCommitFullCompletionError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
    };
    use psy_node_core::store::coordinator_commit_source::CoordinatorCommitSource;
    use psy_node_core::store::canonical_head::{
        CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
    };

    use super::*;

    fn canonical(checkpoint: u64, byte: u8) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(0),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                    byte; 32
                ])),
            ),
        )
    }

    fn head() -> psy_node_core::store::canonical_head::StoredCanonicalHead<PHash> {
        *CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            canonical(7, 7),
        )
        .unwrap()
        .candidate()
    }

    #[test]
    fn completion_roundtrips_and_binds_manifest_backup_and_slot() {
        let source = CoordinatorCommitSource::try_new(
            head(),
            canonical(8, 8),
            vec![1, 2, 3],
        )
        .unwrap();
        let manifest = CoordinatorCommitFullManifest::test_fixture(
            *source.candidate(),
            source.slot().as_bytes(),
            source.digest().as_bytes(),
        );
        let backup = CoordinatorCheckpointBackupEvidence::try_from_exact_source(
            &source,
            8,
            PHash::from_owned_32bytes([0x51; 32]),
            PHash::from_owned_32bytes([0x52; 32]),
            PHash::from_owned_32bytes([0x53; 32]),
            2,
            9,
        )
        .unwrap();
        let completion = CoordinatorCommitFullCompletion::try_from_manifest_and_backup(
            &manifest, &backup,
        )
        .unwrap();
        let decoded = CoordinatorCommitFullCompletion::decode_persisted(
            completion.slot().as_bytes(),
            completion.revision() as i64,
            completion.canonical_payload(),
        )
        .unwrap();
        assert_eq!(decoded, completion);
        assert_eq!(decoded.manifest_slot(), manifest.slot().as_bytes());
        assert_eq!(decoded.manifest_digest(), manifest.digest());
        assert_eq!(decoded.backup_evidence_digest(), backup.digest());

        let mut forged = completion.canonical_payload().to_vec();
        forged[200] ^= 1;
        assert!(CoordinatorCommitFullCompletion::<PHash>::decode_persisted(
            completion.slot().as_bytes(),
            1,
            &forged,
        )
        .is_err());
        assert!(CoordinatorCommitFullCompletion::<PHash>::decode_persisted(
            &[0x99; 32],
            1,
            completion.canonical_payload(),
        )
        .is_err());
    }
}
