//! Canonical narrow intent for branch-exact operational dual writes.
//!
//! This is deliberately not the full 22-domain authority manifest.  It binds
//! every compatibility and target mutation needed to migrate the operational
//! checkpoint/pending mapping (plus the Realm reward proof) to one exact
//! branch, pending/proc namespace, predecessor watermark and durable timestamp
//! lease.  Scylla execution and Processor wiring are later h22 slices.

use std::{error::Error, fmt};

use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    protocol::core_types::Q256BitHash,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use sha2::{Digest, Sha256};

use super::{
    authority_commit::{
        AuthorityCommitIntentDigest, AuthorityTimestampKey,
        AuthorityTimestampLease,
    },
    branch_exact_schema::AuthorityScope,
    branch_pending_mapping::{
        BranchPendingMapping, BRANCH_PENDING_CANONICAL_REF_LEN,
    },
    timestamp::CommitWriteTimestampUs,
    typed::{ProcCheckpointUniqueId, UniquePendingId},
};

const MAGIC: [u8; 8] = *b"PSYBEXDW";
const CODEC_VERSION: u16 = 1;
const MUTATION_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-dual-write-mutation/v1";
const MANIFEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-dual-write-manifest/v1";
const INTENT_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-dual-write-intent/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BranchExactDualWriteMutationKind {
    LegacyCheckpointToPending = 1,
    LegacyPendingToCheckpoint = 2,
    LegacyPendingToProc = 3,
    LegacyProcToPending = 4,
    TargetBranchToPending = 5,
    TargetPendingToBranch = 6,
    LegacyPendingRewardProof = 7,
    TargetPendingRewardProof = 8,
}

impl BranchExactDualWriteMutationKind {
    pub const COORDINATOR: [Self; 6] = [
        Self::LegacyCheckpointToPending,
        Self::LegacyPendingToCheckpoint,
        Self::LegacyPendingToProc,
        Self::LegacyProcToPending,
        Self::TargetBranchToPending,
        Self::TargetPendingToBranch,
    ];

    pub const REALM: [Self; 8] = [
        Self::LegacyCheckpointToPending,
        Self::LegacyPendingToCheckpoint,
        Self::LegacyPendingToProc,
        Self::LegacyProcToPending,
        Self::TargetBranchToPending,
        Self::TargetPendingToBranch,
        Self::LegacyPendingRewardProof,
        Self::TargetPendingRewardProof,
    ];

    pub const fn table_name(self) -> &'static str {
        match self {
            Self::LegacyCheckpointToPending => {
                "checkpoint_id_to_pending_id_table"
            }
            Self::LegacyPendingToCheckpoint => {
                "pending_id_to_checkpoint_id_table"
            }
            Self::LegacyPendingToProc => {
                "pending_id_to_pending_proc_id_table_u64_to_u128"
            }
            Self::LegacyProcToPending => {
                "pending_id_to_pending_proc_id_table_u128_to_u64"
            }
            Self::TargetBranchToPending => {
                "canonical_chain_ref_to_pending_id_table"
            }
            Self::TargetPendingToBranch => {
                "pending_id_to_canonical_chain_ref_table"
            }
            Self::LegacyPendingRewardProof => "checkpointed_object_table",
            Self::TargetPendingRewardProof => "pending_reward_top_proof_table",
        }
    }

    fn try_from_u8(value: u8) -> Result<Self, BranchExactDualWriteError> {
        match value {
            1 => Ok(Self::LegacyCheckpointToPending),
            2 => Ok(Self::LegacyPendingToCheckpoint),
            3 => Ok(Self::LegacyPendingToProc),
            4 => Ok(Self::LegacyProcToPending),
            5 => Ok(Self::TargetBranchToPending),
            6 => Ok(Self::TargetPendingToBranch),
            7 => Ok(Self::LegacyPendingRewardProof),
            8 => Ok(Self::TargetPendingRewardProof),
            other => Err(BranchExactDualWriteError::UnknownMutationKind(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BranchExactExpectedBefore {
    /// A retry may observe the exact candidate, but any different value is a
    /// conflict.  This is encoded into every mutation commitment.
    AbsentOrExactCandidate,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactDualWriteMutationDigest([u8; 32]);

impl BranchExactDualWriteMutationDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactDualWriteMutationCommitment {
    kind: BranchExactDualWriteMutationKind,
    expected_before: BranchExactExpectedBefore,
    key_digest: [u8; 32],
    value_digest: [u8; 32],
    digest: BranchExactDualWriteMutationDigest,
}

impl BranchExactDualWriteMutationCommitment {
    pub const fn kind(&self) -> BranchExactDualWriteMutationKind {
        self.kind
    }

    pub const fn expected_before(&self) -> BranchExactExpectedBefore {
        self.expected_before
    }

    pub const fn key_digest(&self) -> &[u8; 32] {
        &self.key_digest
    }

    pub const fn value_digest(&self) -> &[u8; 32] {
        &self.value_digest
    }

    pub const fn digest(&self) -> BranchExactDualWriteMutationDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactDualWriteManifestDigest([u8; 32]);

impl BranchExactDualWriteManifestDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactDualWriteIntentDigest([u8; 32]);

impl BranchExactDualWriteIntentDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn authority_intent(self) -> AuthorityCommitIntentDigest {
        AuthorityCommitIntentDigest::from_sealed_commit_digest(self.0)
    }
}

/// Complete immutable content of one narrow operational dual-write intent.
/// There is intentionally no constructor taking a timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactDualWriteIntent<Hash> {
    authority: AuthorityScope,
    predecessor: BranchPendingMapping<Hash>,
    candidate: BranchPendingMapping<Hash>,
    proc_checkpoint_id: ProcCheckpointUniqueId,
    reward_proof_canonical: Option<Vec<u8>>,
    mutations: Vec<BranchExactDualWriteMutationCommitment>,
    manifest_digest: BranchExactDualWriteManifestDigest,
    intent_digest: BranchExactDualWriteIntentDigest,
    canonical_bytes: Vec<u8>,
}

impl<Hash: Q256BitHash> BranchExactDualWriteIntent<Hash> {
    pub fn try_coordinator(
        predecessor: BranchPendingMapping<Hash>,
        candidate: BranchPendingMapping<Hash>,
        proc_checkpoint_id: ProcCheckpointUniqueId,
    ) -> Result<Self, BranchExactDualWriteError> {
        Self::try_new(
            AuthorityScope::Coordinator,
            predecessor,
            candidate,
            proc_checkpoint_id,
            None,
        )
    }

    pub fn try_realm(
        authority: AuthorityScope,
        predecessor: BranchPendingMapping<Hash>,
        candidate: BranchPendingMapping<Hash>,
        proc_checkpoint_id: ProcCheckpointUniqueId,
        reward_proof: &TagTreeMerkleProof<Hash>,
    ) -> Result<Self, BranchExactDualWriteError> {
        if !matches!(authority, AuthorityScope::Realm { .. }) {
            return Err(BranchExactDualWriteError::RealmAuthorityRequired);
        }
        let proof = reward_proof
            .psy_ser_to_bytes_vec()
            .map_err(|error| BranchExactDualWriteError::ProofCodec(error.to_string()))?;
        Self::try_new(
            authority,
            predecessor,
            candidate,
            proc_checkpoint_id,
            Some(proof),
        )
    }

    fn try_new(
        authority: AuthorityScope,
        predecessor: BranchPendingMapping<Hash>,
        candidate: BranchPendingMapping<Hash>,
        proc_checkpoint_id: ProcCheckpointUniqueId,
        reward_proof_canonical: Option<Vec<u8>>,
    ) -> Result<Self, BranchExactDualWriteError> {
        validate_successor(authority, &predecessor, &candidate)?;
        match (authority, reward_proof_canonical.as_ref()) {
            (AuthorityScope::Coordinator, Some(_)) => {
                return Err(BranchExactDualWriteError::CoordinatorProofForbidden)
            }
            (AuthorityScope::Realm { .. }, None) => {
                return Err(BranchExactDualWriteError::RealmProofRequired)
            }
            _ => {}
        }
        if let Some(proof) = &reward_proof_canonical {
            if proof.len() > u32::MAX as usize {
                return Err(BranchExactDualWriteError::ProofTooLarge(proof.len()));
            }
            TagTreeMerkleProof::<Hash>::psy_ser_from_owned_bytes_vec(proof.clone())
                .map_err(|error| BranchExactDualWriteError::ProofCodec(error.to_string()))?;
        }
        let mutations = mutation_commitments(
            authority,
            &candidate,
            proc_checkpoint_id,
            reward_proof_canonical.as_deref(),
        );
        let manifest_digest = manifest_digest(&mutations);
        let without_digest = encode_without_digest(
            authority,
            &predecessor,
            &candidate,
            proc_checkpoint_id,
            reward_proof_canonical.as_deref(),
            &mutations,
            manifest_digest,
        );
        let intent_digest = intent_digest(&without_digest);
        let mut canonical_bytes = without_digest;
        canonical_bytes.extend_from_slice(intent_digest.as_bytes());
        Ok(Self {
            authority,
            predecessor,
            candidate,
            proc_checkpoint_id,
            reward_proof_canonical,
            mutations,
            manifest_digest,
            intent_digest,
            canonical_bytes,
        })
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn predecessor(&self) -> &BranchPendingMapping<Hash> {
        &self.predecessor
    }

    pub const fn candidate(&self) -> &BranchPendingMapping<Hash> {
        &self.candidate
    }

    pub const fn proc_checkpoint_id(&self) -> ProcCheckpointUniqueId {
        self.proc_checkpoint_id
    }

    pub fn reward_proof_canonical(&self) -> Option<&[u8]> {
        self.reward_proof_canonical.as_deref()
    }

    pub fn mutations(&self) -> &[BranchExactDualWriteMutationCommitment] {
        &self.mutations
    }

    pub const fn manifest_digest(&self) -> BranchExactDualWriteManifestDigest {
        self.manifest_digest
    }

    pub const fn intent_digest(&self) -> BranchExactDualWriteIntentDigest {
        self.intent_digest
    }

    pub fn to_canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn decode_persisted(bytes: &[u8]) -> Result<Self, BranchExactDualWriteError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(BranchExactDualWriteError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != CODEC_VERSION {
            return Err(BranchExactDualWriteError::UnknownCodecVersion(version));
        }
        let authority = decoder.authority()?;
        let predecessor = decoder.mapping::<Hash>()?;
        let candidate = decoder.mapping::<Hash>()?;
        let proc_checkpoint_id = ProcCheckpointUniqueId::from_bytes(decoder.array16()?);
        let proof = match decoder.u8()? {
            0 => None,
            1 => {
                let length = decoder.u32()? as usize;
                Some(decoder.take(length)?.to_vec())
            }
            value => return Err(BranchExactDualWriteError::InvalidProofPresence(value)),
        };
        let count = decoder.u8()? as usize;
        let mut encoded_kinds = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = BranchExactDualWriteMutationKind::try_from_u8(decoder.u8()?)?;
            let digest = BranchExactDualWriteMutationDigest(decoder.array32()?);
            encoded_kinds.push((kind, digest));
        }
        let encoded_manifest = BranchExactDualWriteManifestDigest(decoder.array32()?);
        let encoded_intent = BranchExactDualWriteIntentDigest(decoder.array32()?);
        if !decoder.is_done() {
            return Err(BranchExactDualWriteError::TrailingBytes);
        }
        let rebuilt = Self::try_new(
            authority,
            predecessor,
            candidate,
            proc_checkpoint_id,
            proof,
        )?;
        let rebuilt_kinds = rebuilt
            .mutations
            .iter()
            .map(|mutation| (mutation.kind, mutation.digest))
            .collect::<Vec<_>>();
        if encoded_kinds != rebuilt_kinds
            || encoded_manifest != rebuilt.manifest_digest
            || encoded_intent != rebuilt.intent_digest
            || rebuilt.canonical_bytes != bytes
        {
            return Err(BranchExactDualWriteError::DigestMismatch);
        }
        Ok(rebuilt)
    }

    pub fn attach_timestamp_lease(
        self,
        lease: AuthorityTimestampLease,
    ) -> Result<SealedBranchExactDualWrite<Hash>, BranchExactDualWriteError> {
        let expected_key = AuthorityTimestampKey::new(
            self.candidate.canonical_chain().network_id(),
            self.authority,
        );
        if lease.key() != expected_key
            || lease.intent() != self.intent_digest.authority_intent()
        {
            return Err(BranchExactDualWriteError::TimestampLeaseMismatch);
        }
        Ok(SealedBranchExactDualWrite { intent: self, lease })
    }
}

/// Executable capability.  Its timestamp can only come from the exact durable
/// allocator lease that owns this intent digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactDualWrite<Hash> {
    intent: BranchExactDualWriteIntent<Hash>,
    lease: AuthorityTimestampLease,
}

impl<Hash> SealedBranchExactDualWrite<Hash> {
    pub const fn intent(&self) -> &BranchExactDualWriteIntent<Hash> {
        &self.intent
    }

    pub const fn lease(&self) -> AuthorityTimestampLease {
        self.lease
    }

    pub const fn write_timestamp(&self) -> CommitWriteTimestampUs {
        self.lease.timestamp()
    }
}

fn validate_successor<Hash: Q256BitHash>(
    authority: AuthorityScope,
    predecessor: &BranchPendingMapping<Hash>,
    candidate: &BranchPendingMapping<Hash>,
) -> Result<(), BranchExactDualWriteError> {
    let previous = predecessor.canonical_chain();
    let next = candidate.canonical_chain();
    if previous.network_id() != next.network_id() {
        return Err(BranchExactDualWriteError::NetworkChanged);
    }
    if previous.chain_epoch() != next.chain_epoch() {
        return Err(BranchExactDualWriteError::EpochChanged);
    }
    let previous_checkpoint = previous.checkpoint().checkpoint_id().get();
    let next_checkpoint = next.checkpoint().checkpoint_id().get();
    if next_checkpoint <= previous_checkpoint {
        return Err(BranchExactDualWriteError::CheckpointDidNotAdvance);
    }
    if matches!(authority, AuthorityScope::Coordinator)
        && next_checkpoint != previous_checkpoint.saturating_add(1)
    {
        return Err(BranchExactDualWriteError::CoordinatorCheckpointSkipped);
    }
    if candidate.pending_id() <= predecessor.pending_id() {
        return Err(BranchExactDualWriteError::PendingDidNotAdvance);
    }
    Ok(())
}

fn mutation_commitments<Hash: Q256BitHash>(
    authority: AuthorityScope,
    candidate: &BranchPendingMapping<Hash>,
    proc_checkpoint_id: ProcCheckpointUniqueId,
    proof: Option<&[u8]>,
) -> Vec<BranchExactDualWriteMutationCommitment> {
    let canonical = candidate.canonical_chain_bytes();
    let pending = candidate.pending_id().get().to_be_bytes();
    let checkpoint = candidate
        .canonical_chain()
        .checkpoint()
        .checkpoint_id()
        .get()
        .to_be_bytes();
    let mut result = vec![
        mutation(BranchExactDualWriteMutationKind::LegacyCheckpointToPending, &checkpoint, &pending),
        mutation(BranchExactDualWriteMutationKind::LegacyPendingToCheckpoint, &pending, &checkpoint),
        mutation(BranchExactDualWriteMutationKind::LegacyPendingToProc, &pending, proc_checkpoint_id.as_bytes()),
        mutation(BranchExactDualWriteMutationKind::LegacyProcToPending, proc_checkpoint_id.as_bytes(), &pending),
        mutation(BranchExactDualWriteMutationKind::TargetBranchToPending, &canonical, &pending),
        mutation(BranchExactDualWriteMutationKind::TargetPendingToBranch, &pending, &canonical),
    ];
    if let AuthorityScope::Realm { .. } = authority {
        let proof = proof.expect("Realm proof checked before commitment expansion");
        let mut legacy_key = Vec::with_capacity(16);
        legacy_key.extend_from_slice(&2_u64.to_be_bytes());
        legacy_key.extend_from_slice(&pending);
        result.push(mutation(
            BranchExactDualWriteMutationKind::LegacyPendingRewardProof,
            &legacy_key,
            proof,
        ));
        result.push(mutation(
            BranchExactDualWriteMutationKind::TargetPendingRewardProof,
            &pending,
            proof,
        ));
    }
    result
}

fn mutation(
    kind: BranchExactDualWriteMutationKind,
    key: &[u8],
    value: &[u8],
) -> BranchExactDualWriteMutationCommitment {
    let key_digest: [u8; 32] = Sha256::digest(key).into();
    let value_digest: [u8; 32] = Sha256::digest(value).into();
    let mut hasher = Sha256::new();
    hasher.update(MUTATION_DOMAIN);
    hasher.update([kind as u8, 1]);
    hasher.update(key_digest);
    hasher.update(value_digest);
    BranchExactDualWriteMutationCommitment {
        kind,
        expected_before: BranchExactExpectedBefore::AbsentOrExactCandidate,
        key_digest,
        value_digest,
        digest: BranchExactDualWriteMutationDigest(hasher.finalize().into()),
    }
}

fn manifest_digest(
    mutations: &[BranchExactDualWriteMutationCommitment],
) -> BranchExactDualWriteManifestDigest {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update((mutations.len() as u32).to_be_bytes());
    for mutation in mutations {
        hasher.update(mutation.digest.as_bytes());
    }
    BranchExactDualWriteManifestDigest(hasher.finalize().into())
}

fn intent_digest(bytes: &[u8]) -> BranchExactDualWriteIntentDigest {
    let mut hasher = Sha256::new();
    hasher.update(INTENT_DOMAIN);
    hasher.update(bytes);
    BranchExactDualWriteIntentDigest(hasher.finalize().into())
}

fn encode_without_digest<Hash: Q256BitHash>(
    authority: AuthorityScope,
    predecessor: &BranchPendingMapping<Hash>,
    candidate: &BranchPendingMapping<Hash>,
    proc_checkpoint_id: ProcCheckpointUniqueId,
    proof: Option<&[u8]>,
    mutations: &[BranchExactDualWriteMutationCommitment],
    manifest: BranchExactDualWriteManifestDigest,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    encode_authority(authority, &mut out);
    encode_mapping(predecessor, &mut out);
    encode_mapping(candidate, &mut out);
    out.extend_from_slice(proc_checkpoint_id.as_bytes());
    match proof {
        None => out.push(0),
        Some(proof) => {
            out.push(1);
            out.extend_from_slice(&(proof.len() as u32).to_be_bytes());
            out.extend_from_slice(proof);
        }
    }
    out.push(mutations.len() as u8);
    for mutation in mutations {
        out.push(mutation.kind as u8);
        out.extend_from_slice(mutation.digest.as_bytes());
    }
    out.extend_from_slice(manifest.as_bytes());
    out
}

fn encode_authority(authority: AuthorityScope, out: &mut Vec<u8>) {
    match authority {
        AuthorityScope::Coordinator => out.push(1),
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            out.push(2);
            out.extend_from_slice(&realm_id.to_be_bytes());
            out.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
}

fn encode_mapping<Hash: Q256BitHash>(
    mapping: &BranchPendingMapping<Hash>,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&mapping.canonical_chain_bytes());
    out.extend_from_slice(&mapping.pending_id().get().to_be_bytes());
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BranchExactDualWriteError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BranchExactDualWriteError::TruncatedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BranchExactDualWriteError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, BranchExactDualWriteError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BranchExactDualWriteError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, BranchExactDualWriteError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn array16(&mut self) -> Result<[u8; 16], BranchExactDualWriteError> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    fn array32(&mut self) -> Result<[u8; 32], BranchExactDualWriteError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn authority(&mut self) -> Result<AuthorityScope, BranchExactDualWriteError> {
        match self.u8()? {
            1 => Ok(AuthorityScope::Coordinator),
            2 => Ok(AuthorityScope::Realm {
                realm_id: self.u32()?,
                realm_sub_id: self.u16()?,
            }),
            value => Err(BranchExactDualWriteError::UnknownAuthority(value)),
        }
    }

    fn mapping<Hash: Q256BitHash>(
        &mut self,
    ) -> Result<BranchPendingMapping<Hash>, BranchExactDualWriteError> {
        let canonical = self.take(BRANCH_PENDING_CANONICAL_REF_LEN)?;
        let pending = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
        let pending = UniquePendingId::try_new(pending)
            .map_err(|error| BranchExactDualWriteError::TypedKey(error.to_string()))?;
        BranchPendingMapping::from_canonical_chain_bytes(canonical, pending)
            .map_err(|error| BranchExactDualWriteError::CanonicalRef(error.to_string()))
    }

    const fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactDualWriteError {
    RealmAuthorityRequired,
    CoordinatorProofForbidden,
    RealmProofRequired,
    ProofTooLarge(usize),
    ProofCodec(String),
    NetworkChanged,
    EpochChanged,
    CheckpointDidNotAdvance,
    CoordinatorCheckpointSkipped,
    PendingDidNotAdvance,
    TimestampLeaseMismatch,
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownAuthority(u8),
    UnknownMutationKind(u8),
    InvalidProofPresence(u8),
    TruncatedPayload,
    TrailingBytes,
    DigestMismatch,
    TypedKey(String),
    CanonicalRef(String),
}

impl fmt::Display for BranchExactDualWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactDualWriteError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };

    use super::*;
    use crate::store::authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap,
        AuthorityTimestampBootstrapReason,
    };

    fn chain(epoch: u64, height: u64, seed: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(height),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    seed,
                    seed + 1,
                    seed + 2,
                    seed + 3,
                )),
            ),
        )
    }

    fn mapping(epoch: u64, height: u64, pending: u64, seed: u64) -> BranchPendingMapping<PHash> {
        BranchPendingMapping::new(
            chain(epoch, height, seed),
            UniquePendingId::try_new(pending).unwrap(),
        )
    }

    fn realm_intent() -> BranchExactDualWriteIntent<PHash> {
        BranchExactDualWriteIntent::try_realm(
            AuthorityScope::Realm { realm_id: 7, realm_sub_id: 2 },
            mapping(0, 10, 100, 10),
            mapping(0, 12, 101, 12),
            ProcCheckpointUniqueId::from_u128(9001),
            &TagTreeMerkleProof::<PHash>::new_empty(),
        )
        .unwrap()
    }

    fn lease(intent: &BranchExactDualWriteIntent<PHash>) -> AuthorityTimestampLease {
        let key = AuthorityTimestampKey::new(
            intent.candidate().canonical_chain().network_id(),
            intent.authority(),
        );
        let bootstrap = AuthorityTimestampBootstrap::new(
            key,
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        );
        bootstrap
            .candidate()
            .seal_reservation(
                key,
                intent.intent_digest().authority_intent(),
                AuthorityClockSampleUs::try_from_i128(2_000).unwrap(),
            )
            .unwrap()
            .lease()
    }

    #[test]
    fn realm_intent_covers_all_eight_mutations_and_round_trips() {
        let intent = realm_intent();
        assert_eq!(
            intent.mutations().iter().map(|item| item.kind()).collect::<Vec<_>>(),
            BranchExactDualWriteMutationKind::REALM
        );
        assert_eq!(intent.reward_proof_canonical().is_some(), true);
        let decoded = BranchExactDualWriteIntent::<PHash>::decode_persisted(
            intent.to_canonical_bytes(),
        )
        .unwrap();
        assert_eq!(decoded, intent);
    }

    #[test]
    fn coordinator_has_six_mutations_and_no_proof() {
        let intent = BranchExactDualWriteIntent::try_coordinator(
            mapping(0, 10, 100, 10),
            mapping(0, 11, 101, 11),
            ProcCheckpointUniqueId::from_u128(9001),
        )
        .unwrap();
        assert_eq!(
            intent.mutations().iter().map(|item| item.kind()).collect::<Vec<_>>(),
            BranchExactDualWriteMutationKind::COORDINATOR
        );
        assert_eq!(intent.reward_proof_canonical(), None);
    }

    #[test]
    fn branch_pending_proc_and_proof_each_change_retry_identity() {
        let baseline = realm_intent();
        let changed_branch = BranchExactDualWriteIntent::try_realm(
            baseline.authority(),
            *baseline.predecessor(),
            mapping(0, 12, 101, 99),
            baseline.proc_checkpoint_id(),
            &TagTreeMerkleProof::<PHash>::new_empty(),
        )
        .unwrap();
        let changed_pending = BranchExactDualWriteIntent::try_realm(
            baseline.authority(),
            *baseline.predecessor(),
            mapping(0, 12, 102, 12),
            baseline.proc_checkpoint_id(),
            &TagTreeMerkleProof::<PHash>::new_empty(),
        )
        .unwrap();
        let changed_proc = BranchExactDualWriteIntent::try_realm(
            baseline.authority(),
            *baseline.predecessor(),
            *baseline.candidate(),
            ProcCheckpointUniqueId::from_u128(9002),
            &TagTreeMerkleProof::<PHash>::new_empty(),
        )
        .unwrap();
        assert_ne!(baseline.intent_digest(), changed_branch.intent_digest());
        assert_ne!(baseline.intent_digest(), changed_pending.intent_digest());
        assert_ne!(baseline.intent_digest(), changed_proc.intent_digest());
    }

    #[test]
    fn continuity_and_authority_fail_closed() {
        let proof = TagTreeMerkleProof::<PHash>::new_empty();
        let proc_id = ProcCheckpointUniqueId::from_u128(1);
        assert_eq!(
            BranchExactDualWriteIntent::try_realm(
                AuthorityScope::Coordinator,
                mapping(0, 10, 100, 10),
                mapping(0, 11, 101, 11),
                proc_id,
                &proof,
            ),
            Err(BranchExactDualWriteError::RealmAuthorityRequired)
        );
        assert_eq!(
            BranchExactDualWriteIntent::try_coordinator(
                mapping(0, 10, 100, 10),
                mapping(1, 11, 101, 11),
                proc_id,
            ),
            Err(BranchExactDualWriteError::EpochChanged)
        );
        assert_eq!(
            BranchExactDualWriteIntent::try_coordinator(
                mapping(0, 10, 100, 10),
                mapping(0, 10, 101, 11),
                proc_id,
            ),
            Err(BranchExactDualWriteError::CheckpointDidNotAdvance)
        );
        assert_eq!(
            BranchExactDualWriteIntent::try_coordinator(
                mapping(0, 10, 100, 10),
                mapping(0, 12, 101, 12),
                proc_id,
            ),
            Err(BranchExactDualWriteError::CoordinatorCheckpointSkipped)
        );
        BranchExactDualWriteIntent::try_realm(
            AuthorityScope::Realm { realm_id: 1, realm_sub_id: 0 },
            mapping(0, 10, 100, 10),
            mapping(0, 12, 101, 12),
            proc_id,
            &proof,
        )
        .expect("Realm checkpoints are sparse and may advance by more than one");
        assert_eq!(
            BranchExactDualWriteIntent::try_coordinator(
                mapping(0, 10, 100, 10),
                mapping(0, 11, 100, 11),
                proc_id,
            ),
            Err(BranchExactDualWriteError::PendingDidNotAdvance)
        );
    }

    #[test]
    fn timestamp_only_arrives_from_matching_durable_lease() {
        let intent = realm_intent();
        let expected_lease = lease(&intent);
        let sealed = intent.clone().attach_timestamp_lease(expected_lease).unwrap();
        assert_eq!(sealed.write_timestamp().as_i64(), 2_000);

        let other = BranchExactDualWriteIntent::try_realm(
            intent.authority(),
            *intent.predecessor(),
            mapping(0, 13, 102, 13),
            intent.proc_checkpoint_id(),
            &TagTreeMerkleProof::<PHash>::new_empty(),
        )
        .unwrap();
        assert_eq!(
            intent.attach_timestamp_lease(lease(&other)),
            Err(BranchExactDualWriteError::TimestampLeaseMismatch)
        );
    }

    #[test]
    fn codec_tamper_unknown_version_and_trailing_fail_closed() {
        let intent = realm_intent();
        let mut tampered = intent.to_canonical_bytes().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            BranchExactDualWriteIntent::<PHash>::decode_persisted(&tampered),
            Err(BranchExactDualWriteError::DigestMismatch)
        );
        let mut unknown = intent.to_canonical_bytes().to_vec();
        unknown[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            BranchExactDualWriteIntent::<PHash>::decode_persisted(&unknown),
            Err(BranchExactDualWriteError::UnknownCodecVersion(2))
        );
        let mut trailing = intent.to_canonical_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            BranchExactDualWriteIntent::<PHash>::decode_persisted(&trailing),
            Err(BranchExactDualWriteError::TrailingBytes)
        );
    }
}
