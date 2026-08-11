//! Canonical application-semantic output for one closed Realm Processor generation.
//!
//! The type is driver-independent and contains the complete payload needed by
//! the later Scylla archive.  Constructing it is not storage authority: c4a2
//! must revalidate the closed queue generation, persist these exact bytes, and
//! read them back before the pending pipeline can advance.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use super::{
    realm_processor_deferred_actor_input::RealmProcessorDeferredActorInputDigest,
    realm_processor_durable_capture::RealmProcessorDurableGenerationDigest,
    recoverable_ephemeral::{
        PendingQueueBoundaryDigest, PendingQueueCaptureContextDigest,
    },
};

const MAGIC: &[u8; 8] = b"PSYRSMO1";
const LEGACY_CODEC_VERSION: u16 = 1;
const BOUND_CODEC_VERSION: u16 = 2;
const LEGACY_DIGEST_DOMAIN: &[u8] = b"psy/rollback/realm-semantic-output/v1";
const BOUND_DIGEST_DOMAIN: &[u8] = b"psy/rollback/realm-semantic-output/v2";
const MAX_COMPONENTS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorSemanticOutputDigest([u8; 32]);

impl RealmProcessorSemanticOutputDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorSemanticOutputError> {
        if bytes == [0; 32] {
            return Err(RealmProcessorSemanticOutputError::EmptyDigest);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorSemanticJob {
    level: u16,
    ordinal: u32,
    metadata: Vec<u8>,
    witness: Vec<u8>,
}

impl RealmProcessorSemanticJob {
    pub fn try_new(
        level: u16,
        ordinal: u32,
        metadata: Vec<u8>,
        witness: Vec<u8>,
    ) -> Result<Self, RealmProcessorSemanticOutputError> {
        require_component(&metadata)?;
        require_component(&witness)?;
        Ok(Self { level, ordinal, metadata, witness })
    }

    pub const fn level(&self) -> u16 { self.level }
    pub const fn ordinal(&self) -> u32 { self.ordinal }
    pub fn metadata(&self) -> &[u8] { &self.metadata }
    pub fn witness(&self) -> &[u8] { &self.witness }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorDeferredJob {
    ordinal: u32,
    queue_item: Vec<u8>,
    contract_updates: Vec<u8>,
}

/// Canonical provenance of the actor input used to produce this semantic
/// output. Version-1 archives decode as `LegacyUnbound` for predecessor
/// recovery only; new branch-exact publication must require the v2 bound
/// variant and must never synthesize a zero digest for legacy bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorSemanticInputBinding {
    LegacyUnbound,
    SuccessorDeferred(RealmProcessorDeferredActorInputDigest),
}

impl RealmProcessorDeferredJob {
    pub fn try_new(
        ordinal: u32,
        queue_item: Vec<u8>,
        contract_updates: Vec<u8>,
    ) -> Result<Self, RealmProcessorSemanticOutputError> {
        require_component(&queue_item)?;
        require_component(&contract_updates)?;
        Ok(Self { ordinal, queue_item, contract_updates })
    }

    pub const fn ordinal(&self) -> u32 { self.ordinal }
    pub fn queue_item(&self) -> &[u8] { &self.queue_item }
    pub fn contract_updates(&self) -> &[u8] { &self.contract_updates }
}

/// Candidate inputs assembled by the command-only gatherer plus temp-store
/// readback.
///
/// This public transport type is intentionally not an authority receipt.
/// c4a2 must independently revalidate the durable source generation and seal
/// the resulting canonical bytes inside the storage-owned archive boundary.
pub struct RealmProcessorSemanticOutputParts {
    pub context_digest: PendingQueueCaptureContextDigest,
    pub generation_digest: RealmProcessorDurableGenerationDigest,
    pub boundary_digest: PendingQueueBoundaryDigest,
    pub item_count: u64,
    pub input_binding: RealmProcessorSemanticInputBinding,
    pub processing_checkpoint_id: u64,
    pub processing_checkpoint_root: [u8; 32],
    pub processing_realm_start_root: [u8; 32],
    pub old_realm_root: [u8; 32],
    pub new_realm_root: [u8; 32],
    pub total_users_updated: u64,
    pub total_proofs_generated: u64,
    pub global_user_tree_nodes: Vec<u8>,
    pub user_contract_tree_nodes: Vec<u8>,
    pub contract_state_tree_nodes: Vec<u8>,
    pub user_leaves: Vec<u8>,
    pub contract_state_imt_leaves: Vec<u8>,
    pub guta_header: Vec<u8>,
    pub jobs: Vec<RealmProcessorSemanticJob>,
    pub deferred_jobs: Vec<RealmProcessorDeferredJob>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorSemanticOutput {
    context_digest: PendingQueueCaptureContextDigest,
    generation_digest: RealmProcessorDurableGenerationDigest,
    boundary_digest: PendingQueueBoundaryDigest,
    item_count: u64,
    input_binding: RealmProcessorSemanticInputBinding,
    processing_checkpoint_id: u64,
    processing_checkpoint_root: [u8; 32],
    processing_realm_start_root: [u8; 32],
    old_realm_root: [u8; 32],
    new_realm_root: [u8; 32],
    total_users_updated: u64,
    total_proofs_generated: u64,
    global_user_tree_nodes: Vec<u8>,
    user_contract_tree_nodes: Vec<u8>,
    contract_state_tree_nodes: Vec<u8>,
    user_leaves: Vec<u8>,
    contract_state_imt_leaves: Vec<u8>,
    guta_header: Vec<u8>,
    jobs: Vec<RealmProcessorSemanticJob>,
    deferred_jobs: Vec<RealmProcessorDeferredJob>,
    digest: RealmProcessorSemanticOutputDigest,
}

impl RealmProcessorSemanticOutput {
    pub fn try_from_candidate_parts(
        parts: RealmProcessorSemanticOutputParts,
    ) -> Result<Self, RealmProcessorSemanticOutputError> {
        if parts.old_realm_root != parts.processing_realm_start_root
            || parts.jobs.len() > MAX_COMPONENTS
            || parts.deferred_jobs.len() > MAX_COMPONENTS
            || parts.total_proofs_generated != parts.jobs.len() as u64
        {
            return Err(RealmProcessorSemanticOutputError::InvalidIdentityOrCount);
        }
        require_component(&parts.guta_header)?;
        for component in [
            &parts.global_user_tree_nodes,
            &parts.user_contract_tree_nodes,
            &parts.contract_state_tree_nodes,
            &parts.user_leaves,
            &parts.contract_state_imt_leaves,
        ] {
            require_optional_component(component)?;
        }
        validate_jobs(&parts.jobs)?;
        validate_deferred(&parts.deferred_jobs)?;
        let mut output = Self {
            context_digest: parts.context_digest,
            generation_digest: parts.generation_digest,
            boundary_digest: parts.boundary_digest,
            item_count: parts.item_count,
            input_binding: parts.input_binding,
            processing_checkpoint_id: parts.processing_checkpoint_id,
            processing_checkpoint_root: parts.processing_checkpoint_root,
            processing_realm_start_root: parts.processing_realm_start_root,
            old_realm_root: parts.old_realm_root,
            new_realm_root: parts.new_realm_root,
            total_users_updated: parts.total_users_updated,
            total_proofs_generated: parts.total_proofs_generated,
            global_user_tree_nodes: parts.global_user_tree_nodes,
            user_contract_tree_nodes: parts.user_contract_tree_nodes,
            contract_state_tree_nodes: parts.contract_state_tree_nodes,
            user_leaves: parts.user_leaves,
            contract_state_imt_leaves: parts.contract_state_imt_leaves,
            guta_header: parts.guta_header,
            jobs: parts.jobs,
            deferred_jobs: parts.deferred_jobs,
            digest: RealmProcessorSemanticOutputDigest([1; 32]),
        };
        output.digest = digest(output.input_binding, &output.encode_unsigned())?;
        Ok(output)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RealmProcessorSemanticOutputError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(RealmProcessorSemanticOutputError::InvalidMagic);
        }
        let codec_version = decoder.u16()?;
        if codec_version != LEGACY_CODEC_VERSION && codec_version != BOUND_CODEC_VERSION {
            return Err(RealmProcessorSemanticOutputError::UnknownCodecVersion);
        }
        let context_digest = PendingQueueCaptureContextDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmProcessorSemanticOutputError::EmptyDigest)?;
        let generation_digest = RealmProcessorDurableGenerationDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmProcessorSemanticOutputError::EmptyDigest)?;
        let boundary_digest = PendingQueueBoundaryDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmProcessorSemanticOutputError::EmptyDigest)?;
        let item_count = decoder.u64()?;
        let input_binding = if codec_version == BOUND_CODEC_VERSION {
            RealmProcessorSemanticInputBinding::SuccessorDeferred(
                RealmProcessorDeferredActorInputDigest::try_new(decoder.array32()?)
                    .map_err(|_| RealmProcessorSemanticOutputError::EmptyDigest)?,
            )
        } else {
            RealmProcessorSemanticInputBinding::LegacyUnbound
        };
        let processing_checkpoint_id = decoder.u64()?;
        let processing_checkpoint_root = decoder.array32()?;
        let processing_realm_start_root = decoder.array32()?;
        let old_realm_root = decoder.array32()?;
        let new_realm_root = decoder.array32()?;
        let total_users_updated = decoder.u64()?;
        let total_proofs_generated = decoder.u64()?;
        let global_user_tree_nodes = decoder.bytes()?;
        let user_contract_tree_nodes = decoder.bytes()?;
        let contract_state_tree_nodes = decoder.bytes()?;
        let user_leaves = decoder.bytes()?;
        let contract_state_imt_leaves = decoder.bytes()?;
        let guta_header = decoder.bytes()?;
        let job_count = decoder.count()?;
        let mut jobs = Vec::with_capacity(job_count);
        for _ in 0..job_count {
            jobs.push(RealmProcessorSemanticJob::try_new(
                decoder.u16()?, decoder.u32()?, decoder.bytes()?, decoder.bytes()?,
            )?);
        }
        let deferred_count = decoder.count()?;
        let mut deferred_jobs = Vec::with_capacity(deferred_count);
        for _ in 0..deferred_count {
            deferred_jobs.push(RealmProcessorDeferredJob::try_new(
                decoder.u32()?, decoder.bytes()?, decoder.bytes()?,
            )?);
        }
        let encoded_digest = RealmProcessorSemanticOutputDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(RealmProcessorSemanticOutputError::TrailingBytes);
        }
        let output = Self::try_from_candidate_parts(RealmProcessorSemanticOutputParts {
            context_digest,
            generation_digest,
            boundary_digest,
            item_count,
            input_binding,
            processing_checkpoint_id,
            processing_checkpoint_root,
            processing_realm_start_root,
            old_realm_root,
            new_realm_root,
            total_users_updated,
            total_proofs_generated,
            global_user_tree_nodes,
            user_contract_tree_nodes,
            contract_state_tree_nodes,
            user_leaves,
            contract_state_imt_leaves,
            guta_header,
            jobs,
            deferred_jobs,
        })?;
        if output.digest != encoded_digest {
            return Err(RealmProcessorSemanticOutputError::DigestMismatch);
        }
        Ok(output)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.encode_unsigned();
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes
    }

    /// Exact encoded length without allocating a second copy of the payload.
    /// Archive adapters must check their aggregate byte cap through this
    /// method before calling `to_canonical_bytes`.
    pub fn canonical_len(&self) -> Result<usize, RealmProcessorSemanticOutputError> {
        // Fixed fields, six u32 byte-length prefixes, two vector counts and
        // the trailing digest. Bound v2 adds one exact 32-byte input digest.
        let mut len = match self.input_binding {
            RealmProcessorSemanticInputBinding::LegacyUnbound => 330_usize,
            RealmProcessorSemanticInputBinding::SuccessorDeferred(_) => 362_usize,
        };
        for bytes in [
            &self.global_user_tree_nodes,
            &self.user_contract_tree_nodes,
            &self.contract_state_tree_nodes,
            &self.user_leaves,
            &self.contract_state_imt_leaves,
            &self.guta_header,
        ] {
            len = len.checked_add(bytes.len())
                .ok_or(RealmProcessorSemanticOutputError::CountOverflow)?;
        }
        for job in &self.jobs {
            len = len.checked_add(14)
                .and_then(|value| value.checked_add(job.metadata.len()))
                .and_then(|value| value.checked_add(job.witness.len()))
                .ok_or(RealmProcessorSemanticOutputError::CountOverflow)?;
        }
        for job in &self.deferred_jobs {
            len = len.checked_add(12)
                .and_then(|value| value.checked_add(job.queue_item.len()))
                .and_then(|value| value.checked_add(job.contract_updates.len()))
                .ok_or(RealmProcessorSemanticOutputError::CountOverflow)?;
        }
        Ok(len)
    }

    pub const fn digest(&self) -> RealmProcessorSemanticOutputDigest { self.digest }
    pub const fn context_digest(&self) -> PendingQueueCaptureContextDigest { self.context_digest }
    pub const fn generation_digest(&self) -> RealmProcessorDurableGenerationDigest { self.generation_digest }
    pub const fn boundary_digest(&self) -> PendingQueueBoundaryDigest { self.boundary_digest }
    pub const fn item_count(&self) -> u64 { self.item_count }
    pub const fn input_binding(&self) -> RealmProcessorSemanticInputBinding { self.input_binding }
    pub const fn actor_input_digest(&self) -> Option<RealmProcessorDeferredActorInputDigest> {
        match self.input_binding {
            RealmProcessorSemanticInputBinding::LegacyUnbound => None,
            RealmProcessorSemanticInputBinding::SuccessorDeferred(digest) => Some(digest),
        }
    }
    pub const fn processing_checkpoint_id(&self) -> u64 { self.processing_checkpoint_id }
    pub fn old_realm_root(&self) -> &[u8; 32] { &self.old_realm_root }
    pub fn new_realm_root(&self) -> &[u8; 32] { &self.new_realm_root }
    pub fn jobs(&self) -> &[RealmProcessorSemanticJob] { &self.jobs }
    pub fn deferred_jobs(&self) -> &[RealmProcessorDeferredJob] { &self.deferred_jobs }

    /// Work classification is based on application semantics, never transport
    /// Data count.  A deferred job is work even when the current tree is a no-op.
    pub fn has_application_work(&self) -> bool {
        self.old_realm_root != self.new_realm_root
            || self.total_users_updated != 0
            || self.total_proofs_generated != 0
            || !self.global_user_tree_nodes.is_empty()
            || !self.user_contract_tree_nodes.is_empty()
            || !self.contract_state_tree_nodes.is_empty()
            || !self.user_leaves.is_empty()
            || !self.contract_state_imt_leaves.is_empty()
            || !self.jobs.is_empty()
            || !self.deferred_jobs.is_empty()
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        let codec_version = match self.input_binding {
            RealmProcessorSemanticInputBinding::LegacyUnbound => LEGACY_CODEC_VERSION,
            RealmProcessorSemanticInputBinding::SuccessorDeferred(_) => BOUND_CODEC_VERSION,
        };
        out.extend_from_slice(&codec_version.to_be_bytes());
        out.extend_from_slice(self.context_digest.as_bytes());
        out.extend_from_slice(self.generation_digest.as_bytes());
        out.extend_from_slice(self.boundary_digest.as_bytes());
        out.extend_from_slice(&self.item_count.to_be_bytes());
        if let RealmProcessorSemanticInputBinding::SuccessorDeferred(digest) = self.input_binding {
            out.extend_from_slice(digest.as_bytes());
        }
        out.extend_from_slice(&self.processing_checkpoint_id.to_be_bytes());
        out.extend_from_slice(&self.processing_checkpoint_root);
        out.extend_from_slice(&self.processing_realm_start_root);
        out.extend_from_slice(&self.old_realm_root);
        out.extend_from_slice(&self.new_realm_root);
        out.extend_from_slice(&self.total_users_updated.to_be_bytes());
        out.extend_from_slice(&self.total_proofs_generated.to_be_bytes());
        for bytes in [
            &self.global_user_tree_nodes,
            &self.user_contract_tree_nodes,
            &self.contract_state_tree_nodes,
            &self.user_leaves,
            &self.contract_state_imt_leaves,
            &self.guta_header,
        ] {
            put_bytes(&mut out, bytes);
        }
        out.extend_from_slice(&(self.jobs.len() as u32).to_be_bytes());
        for job in &self.jobs {
            out.extend_from_slice(&job.level.to_be_bytes());
            out.extend_from_slice(&job.ordinal.to_be_bytes());
            put_bytes(&mut out, &job.metadata);
            put_bytes(&mut out, &job.witness);
        }
        out.extend_from_slice(&(self.deferred_jobs.len() as u32).to_be_bytes());
        for job in &self.deferred_jobs {
            out.extend_from_slice(&job.ordinal.to_be_bytes());
            put_bytes(&mut out, &job.queue_item);
            put_bytes(&mut out, &job.contract_updates);
        }
        out
    }
}

fn validate_jobs(jobs: &[RealmProcessorSemanticJob]) -> Result<(), RealmProcessorSemanticOutputError> {
    if jobs.first().is_some_and(|job| job.level != 0) {
        return Err(RealmProcessorSemanticOutputError::NonCanonicalOrder);
    }
    let mut expected_level = 0_u16;
    let mut expected_ordinal = 0_u32;
    for job in jobs {
        if job.level != expected_level {
            if job.level != expected_level.saturating_add(1) || job.ordinal != 0 {
                return Err(RealmProcessorSemanticOutputError::NonCanonicalOrder);
            }
            expected_level = job.level;
            expected_ordinal = 0;
        }
        if job.ordinal != expected_ordinal {
            return Err(RealmProcessorSemanticOutputError::NonCanonicalOrder);
        }
        expected_ordinal = expected_ordinal
            .checked_add(1)
            .ok_or(RealmProcessorSemanticOutputError::CountOverflow)?;
    }
    Ok(())
}

fn validate_deferred(jobs: &[RealmProcessorDeferredJob]) -> Result<(), RealmProcessorSemanticOutputError> {
    for (expected, job) in jobs.iter().enumerate() {
        if job.ordinal != u32::try_from(expected).map_err(|_| RealmProcessorSemanticOutputError::CountOverflow)? {
            return Err(RealmProcessorSemanticOutputError::NonCanonicalOrder);
        }
    }
    Ok(())
}

fn require_component(bytes: &[u8]) -> Result<(), RealmProcessorSemanticOutputError> {
    require_component_len(bytes.len(), false)
}

fn require_optional_component(bytes: &[u8]) -> Result<(), RealmProcessorSemanticOutputError> {
    require_component_len(bytes.len(), true)
}

fn require_component_len(
    len: usize,
    allow_empty: bool,
) -> Result<(), RealmProcessorSemanticOutputError> {
    if (!allow_empty && len == 0) || u32::try_from(len).is_err() {
        return Err(RealmProcessorSemanticOutputError::InvalidComponent);
    }
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn digest(
    binding: RealmProcessorSemanticInputBinding,
    bytes: &[u8],
) -> Result<RealmProcessorSemanticOutputDigest, RealmProcessorSemanticOutputError> {
    let mut hasher = Sha256::new();
    hasher.update(match binding {
        RealmProcessorSemanticInputBinding::LegacyUnbound => LEGACY_DIGEST_DOMAIN,
        RealmProcessorSemanticInputBinding::SuccessorDeferred(_) => BOUND_DIGEST_DOMAIN,
    });
    hasher.update(bytes);
    RealmProcessorSemanticOutputDigest::try_new(hasher.finalize().into())
}

struct Decoder<'a> { bytes: &'a [u8], cursor: usize }

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmProcessorSemanticOutputError> {
        let end = self.cursor.checked_add(len).ok_or(RealmProcessorSemanticOutputError::Truncated)?;
        let value = self.bytes.get(self.cursor..end).ok_or(RealmProcessorSemanticOutputError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, RealmProcessorSemanticOutputError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, RealmProcessorSemanticOutputError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, RealmProcessorSemanticOutputError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array32(&mut self) -> Result<[u8; 32], RealmProcessorSemanticOutputError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, RealmProcessorSemanticOutputError> {
        let len = usize::try_from(self.u32()?).map_err(|_| RealmProcessorSemanticOutputError::CountOverflow)?;
        Ok(self.take(len)?.to_vec())
    }
    fn count(&mut self) -> Result<usize, RealmProcessorSemanticOutputError> {
        let count = usize::try_from(self.u32()?).map_err(|_| RealmProcessorSemanticOutputError::CountOverflow)?;
        if count > MAX_COMPONENTS { return Err(RealmProcessorSemanticOutputError::CountOverflow); }
        Ok(count)
    }
    fn done(&self) -> bool { self.cursor == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorSemanticOutputError {
    InvalidMagic,
    UnknownCodecVersion,
    EmptyDigest,
    InvalidIdentityOrCount,
    InvalidComponent,
    NonCanonicalOrder,
    CountOverflow,
    Truncated,
    TrailingBytes,
    DigestMismatch,
}

impl fmt::Display for RealmProcessorSemanticOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for RealmProcessorSemanticOutputError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(deferred: bool) -> RealmProcessorSemanticOutputParts {
        RealmProcessorSemanticOutputParts {
            context_digest: PendingQueueCaptureContextDigest::try_new([1; 32]).unwrap(),
            generation_digest: RealmProcessorDurableGenerationDigest::try_new([2; 32]).unwrap(),
            boundary_digest: PendingQueueBoundaryDigest::try_new([3; 32]).unwrap(),
            item_count: 2,
            input_binding: RealmProcessorSemanticInputBinding::LegacyUnbound,
            processing_checkpoint_id: 17,
            processing_checkpoint_root: [4; 32],
            processing_realm_start_root: [5; 32],
            old_realm_root: [5; 32],
            new_realm_root: if deferred { [5; 32] } else { [6; 32] },
            total_users_updated: if deferred { 0 } else { 1 },
            total_proofs_generated: if deferred { 0 } else { 1 },
            global_user_tree_nodes: if deferred { vec![] } else { vec![7] },
            user_contract_tree_nodes: vec![],
            contract_state_tree_nodes: vec![],
            user_leaves: vec![],
            contract_state_imt_leaves: vec![],
            guta_header: vec![8, 9],
            jobs: if deferred { vec![] } else { vec![RealmProcessorSemanticJob::try_new(0, 0, vec![10], vec![11]).unwrap()] },
            deferred_jobs: if deferred { vec![RealmProcessorDeferredJob::try_new(0, vec![12], vec![13]).unwrap()] } else { vec![] },
        }
    }

    #[test]
    fn canonical_roundtrip_and_tamper_fail_closed() {
        let output = RealmProcessorSemanticOutput::try_from_candidate_parts(parts(false)).unwrap();
        let bytes = output.to_canonical_bytes();
        assert_eq!(output.canonical_len().unwrap(), bytes.len());
        assert_eq!(bytes.len(), 349);
        assert_eq!(
            hex::encode(output.digest().as_bytes()),
            "ad00f963a2c9c52439a5df1e46883b388e01b8e258b3d8f58e668a39f3fe4062"
        );
        assert_eq!(RealmProcessorSemanticOutput::decode_canonical(&bytes).unwrap(), output);
        assert_eq!(output.to_canonical_bytes(), bytes);

        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(RealmProcessorSemanticOutput::decode_canonical(&tampered), Err(RealmProcessorSemanticOutputError::DigestMismatch));
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert_eq!(RealmProcessorSemanticOutput::decode_canonical(&bad_magic), Err(RealmProcessorSemanticOutputError::InvalidMagic));
        let mut unknown = bytes.clone();
        unknown[8..10].copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(RealmProcessorSemanticOutput::decode_canonical(&unknown), Err(RealmProcessorSemanticOutputError::UnknownCodecVersion));
        assert_eq!(RealmProcessorSemanticOutput::decode_canonical(&bytes[..bytes.len() - 1]), Err(RealmProcessorSemanticOutputError::Truncated));
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(RealmProcessorSemanticOutput::decode_canonical(&trailing), Err(RealmProcessorSemanticOutputError::TrailingBytes));
    }

    #[test]
    fn bound_v2_commits_actor_input_while_v1_remains_read_only_compatible() {
        let legacy = RealmProcessorSemanticOutput::try_from_candidate_parts(parts(false)).unwrap();
        let legacy_bytes = legacy.to_canonical_bytes();
        assert_eq!(u16::from_be_bytes(legacy_bytes[8..10].try_into().unwrap()), 1);
        assert_eq!(legacy.actor_input_digest(), None);
        assert_eq!(
            RealmProcessorSemanticOutput::decode_canonical(&legacy_bytes).unwrap(),
            legacy
        );

        let input_digest = RealmProcessorDeferredActorInputDigest::try_new([42; 32]).unwrap();
        let mut bound_parts = parts(false);
        bound_parts.input_binding =
            RealmProcessorSemanticInputBinding::SuccessorDeferred(input_digest);
        let bound = RealmProcessorSemanticOutput::try_from_candidate_parts(bound_parts).unwrap();
        let bound_bytes = bound.to_canonical_bytes();
        assert_eq!(u16::from_be_bytes(bound_bytes[8..10].try_into().unwrap()), 2);
        assert_eq!(bound.actor_input_digest(), Some(input_digest));
        assert_eq!(bound.canonical_len().unwrap(), bound_bytes.len());
        assert_eq!(bound_bytes.len(), legacy_bytes.len() + 32);
        assert_ne!(bound.digest(), legacy.digest());
        assert_eq!(
            RealmProcessorSemanticOutput::decode_canonical(&bound_bytes).unwrap(),
            bound
        );

        let mut changed_parts = parts(false);
        changed_parts.input_binding = RealmProcessorSemanticInputBinding::SuccessorDeferred(
            RealmProcessorDeferredActorInputDigest::try_new([43; 32]).unwrap(),
        );
        let changed = RealmProcessorSemanticOutput::try_from_candidate_parts(changed_parts).unwrap();
        assert_ne!(bound.digest(), changed.digest());
    }

    #[test]
    fn deferred_job_is_application_work_even_with_no_tree_change() {
        let output = RealmProcessorSemanticOutput::try_from_candidate_parts(parts(true)).unwrap();
        assert!(output.has_application_work());
        assert_eq!(output.jobs().len(), 0);
        assert_eq!(output.deferred_jobs().len(), 1);
    }

    #[test]
    fn empty_application_output_is_not_inferred_from_transport_count() {
        let mut empty = parts(true);
        empty.deferred_jobs.clear();
        let output = RealmProcessorSemanticOutput::try_from_candidate_parts(empty).unwrap();
        assert_eq!(output.item_count(), 2);
        assert!(!output.has_application_work());
    }

    #[test]
    fn identity_and_dependency_drift_fail_closed_or_change_digest() {
        let reference = RealmProcessorSemanticOutput::try_from_candidate_parts(parts(false)).unwrap();

        let mut wrong_start = parts(false);
        wrong_start.old_realm_root = [42; 32];
        assert_eq!(
            RealmProcessorSemanticOutput::try_from_candidate_parts(wrong_start),
            Err(RealmProcessorSemanticOutputError::InvalidIdentityOrCount)
        );

        let mut wrong_count = parts(false);
        wrong_count.total_proofs_generated = 2;
        assert_eq!(
            RealmProcessorSemanticOutput::try_from_candidate_parts(wrong_count),
            Err(RealmProcessorSemanticOutputError::InvalidIdentityOrCount)
        );

        let mut changed_checkpoint = parts(false);
        changed_checkpoint.processing_checkpoint_root = [43; 32];
        let changed_checkpoint =
            RealmProcessorSemanticOutput::try_from_candidate_parts(changed_checkpoint).unwrap();
        assert_ne!(reference.digest(), changed_checkpoint.digest());

        let mut changed_witness = parts(false);
        changed_witness.jobs[0].witness[0] ^= 1;
        let changed_witness =
            RealmProcessorSemanticOutput::try_from_candidate_parts(changed_witness).unwrap();
        assert_ne!(reference.digest(), changed_witness.digest());

        let deferred = RealmProcessorSemanticOutput::try_from_candidate_parts(parts(true)).unwrap();
        let mut changed_contract_update = parts(true);
        changed_contract_update.deferred_jobs[0].contract_updates[0] ^= 1;
        let changed_contract_update =
            RealmProcessorSemanticOutput::try_from_candidate_parts(changed_contract_update).unwrap();
        assert_ne!(deferred.digest(), changed_contract_update.digest());
    }

    #[test]
    fn non_canonical_job_and_deferred_order_fail_closed() {
        let mut bad_jobs = parts(false);
        bad_jobs.jobs[0].ordinal = 1;
        assert_eq!(RealmProcessorSemanticOutput::try_from_candidate_parts(bad_jobs), Err(RealmProcessorSemanticOutputError::NonCanonicalOrder));
        let mut bad_deferred = parts(true);
        bad_deferred.deferred_jobs[0].ordinal = 2;
        assert_eq!(RealmProcessorSemanticOutput::try_from_candidate_parts(bad_deferred), Err(RealmProcessorSemanticOutputError::NonCanonicalOrder));
    }

    #[test]
    fn every_length_prefixed_component_is_u32_bounded() {
        assert!(require_component_len(0, true).is_ok());
        assert_eq!(
            require_component_len(0, false),
            Err(RealmProcessorSemanticOutputError::InvalidComponent)
        );
        assert!(require_component_len(u32::MAX as usize, true).is_ok());
        if usize::BITS > 32 {
            assert_eq!(
                require_component_len(u32::MAX as usize + 1, true),
                Err(RealmProcessorSemanticOutputError::InvalidComponent)
            );
        }
    }
}
