//! Deterministic, bounded archive plan for one Realm Processor application output.
//!
//! The transport generation remains a separate durable commitment.  This
//! module binds exactly one canonical application output to that commitment,
//! splits the potentially large payload into fixed-size fragments, and
//! reconstructs it only from an exhaustive observation.  These values are
//! plans and content identities; storage is still responsible for minting the
//! opaque receipt that can advance the pending pipeline.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use super::realm_processor_semantic_output::{
    RealmProcessorSemanticOutput, RealmProcessorSemanticOutputDigest,
    RealmProcessorSemanticOutputError,
};

const SLOT_DOMAIN: &[u8] = b"psy/rollback/realm-application-archive-slot/v1";
const HEADER_DOMAIN: &[u8] = b"psy/rollback/realm-application-archive-header/v1";
const FRAGMENT_DOMAIN: &[u8] = b"psy/rollback/realm-application-archive-fragment/v1";
const DATASET_DOMAIN: &[u8] = b"psy/rollback/realm-application-archive-dataset/v1";
const MAGIC: &[u8; 8] = b"PSYRAA01";
const CODEC_VERSION: u16 = 1;

pub const REALM_APPLICATION_ARCHIVE_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
pub const REALM_APPLICATION_ARCHIVE_FRAGMENTS_PER_BUCKET: u32 = 16;
/// Default-off operational cap. The first production RF=3 sizing pass may
/// raise this only together with a measured peak-RSS/RTO budget.
pub const REALM_APPLICATION_ARCHIVE_MAX_FRAGMENTS: u32 = 16;
pub const REALM_APPLICATION_ARCHIVE_MAX_BUCKETS: u32 =
    (REALM_APPLICATION_ARCHIVE_MAX_FRAGMENTS
        + REALM_APPLICATION_ARCHIVE_FRAGMENTS_PER_BUCKET
        - 1)
        / REALM_APPLICATION_ARCHIVE_FRAGMENTS_PER_BUCKET;
pub const REALM_APPLICATION_ARCHIVE_MAX_BYTES: usize =
    REALM_APPLICATION_ARCHIVE_FRAGMENT_BYTES
        * REALM_APPLICATION_ARCHIVE_MAX_FRAGMENTS as usize;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorApplicationArchiveSlot([u8; 32]);

impl RealmProcessorApplicationArchiveSlot {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorApplicationArchiveError> {
        if bytes == [0; 32] {
            Err(RealmProcessorApplicationArchiveError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorApplicationArchiveDigest([u8; 32]);

impl RealmProcessorApplicationArchiveDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorApplicationArchiveError> {
        if bytes == [0; 32] {
            Err(RealmProcessorApplicationArchiveError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorApplicationFragmentDigest([u8; 32]);

impl RealmProcessorApplicationFragmentDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorApplicationArchiveError> {
        if bytes == [0; 32] {
            Err(RealmProcessorApplicationArchiveError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// Storage-independent provenance supplied only after the transport archive
/// has been exactly persisted and read back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorApplicationArchiveBinding {
    network_chain_id: u32,
    realm_id: u32,
    realm_sub_id: u16,
    transport_store_fingerprint: [u8; 32],
    transport_slot: [u8; 32],
    transport_digest: [u8; 32],
    assignment_digest: [u8; 32],
    pipeline_store_fingerprint: [u8; 32],
    pipeline_close_revision: u64,
    pipeline_close_receipt_digest: [u8; 32],
    close_intent_digest: [u8; 32],
}

impl RealmProcessorApplicationArchiveBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        network_chain_id: u32,
        realm_id: u32,
        realm_sub_id: u16,
        transport_store_fingerprint: [u8; 32],
        transport_slot: [u8; 32],
        transport_digest: [u8; 32],
        assignment_digest: [u8; 32],
        pipeline_store_fingerprint: [u8; 32],
        pipeline_close_revision: u64,
        pipeline_close_receipt_digest: [u8; 32],
        close_intent_digest: [u8; 32],
    ) -> Result<Self, RealmProcessorApplicationArchiveError> {
        if network_chain_id == 0
            || pipeline_close_revision == 0
            || [
                transport_store_fingerprint,
                transport_slot,
                transport_digest,
                assignment_digest,
                pipeline_store_fingerprint,
                pipeline_close_receipt_digest,
                close_intent_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(RealmProcessorApplicationArchiveError::InvalidBinding);
        }
        Ok(Self {
            network_chain_id,
            realm_id,
            realm_sub_id,
            transport_store_fingerprint,
            transport_slot,
            transport_digest,
            assignment_digest,
            pipeline_store_fingerprint,
            pipeline_close_revision,
            pipeline_close_receipt_digest,
            close_intent_digest,
        })
    }

    pub const fn network_chain_id(&self) -> u32 { self.network_chain_id }
    pub const fn realm_id(&self) -> u32 { self.realm_id }
    pub const fn realm_sub_id(&self) -> u16 { self.realm_sub_id }
    pub const fn transport_store_fingerprint(&self) -> &[u8; 32] { &self.transport_store_fingerprint }
    pub const fn transport_slot(&self) -> &[u8; 32] { &self.transport_slot }
    pub const fn transport_digest(&self) -> &[u8; 32] { &self.transport_digest }
    pub const fn assignment_digest(&self) -> &[u8; 32] { &self.assignment_digest }
    pub const fn pipeline_store_fingerprint(&self) -> &[u8; 32] { &self.pipeline_store_fingerprint }
    pub const fn pipeline_close_revision(&self) -> u64 { self.pipeline_close_revision }
    pub const fn pipeline_close_receipt_digest(&self) -> &[u8; 32] { &self.pipeline_close_receipt_digest }
    pub const fn close_intent_digest(&self) -> &[u8; 32] { &self.close_intent_digest }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorApplicationArchiveHeader {
    slot: RealmProcessorApplicationArchiveSlot,
    binding: RealmProcessorApplicationArchiveBinding,
    semantic_digest: RealmProcessorSemanticOutputDigest,
    semantic_bytes: u64,
    fragment_count: u32,
    fragment_set_digest: RealmProcessorApplicationArchiveDigest,
    context_digest: [u8; 32],
    generation_digest: [u8; 32],
    boundary_digest: [u8; 32],
    item_count: u64,
    has_application_work: bool,
    digest: RealmProcessorApplicationArchiveDigest,
}

impl RealmProcessorApplicationArchiveHeader {
    pub const fn slot(&self) -> RealmProcessorApplicationArchiveSlot { self.slot }
    pub const fn binding(&self) -> &RealmProcessorApplicationArchiveBinding { &self.binding }
    pub const fn semantic_digest(&self) -> RealmProcessorSemanticOutputDigest { self.semantic_digest }
    pub const fn semantic_bytes(&self) -> u64 { self.semantic_bytes }
    pub const fn fragment_count(&self) -> u32 { self.fragment_count }
    pub const fn fragment_set_digest(&self) -> RealmProcessorApplicationArchiveDigest { self.fragment_set_digest }
    pub const fn context_digest(&self) -> &[u8; 32] { &self.context_digest }
    pub const fn generation_digest(&self) -> &[u8; 32] { &self.generation_digest }
    pub const fn boundary_digest(&self) -> &[u8; 32] { &self.boundary_digest }
    pub const fn item_count(&self) -> u64 { self.item_count }
    pub const fn has_application_work(&self) -> bool { self.has_application_work }
    pub const fn digest(&self) -> RealmProcessorApplicationArchiveDigest { self.digest }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = encode_header_without_digest(self);
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes
    }

    pub fn decode_selected(
        selected_slot: RealmProcessorApplicationArchiveSlot,
        bytes: &[u8],
    ) -> Result<Self, RealmProcessorApplicationArchiveError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(RealmProcessorApplicationArchiveError::MalformedHeader);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(RealmProcessorApplicationArchiveError::UnknownCodecVersion);
        }
        let slot = RealmProcessorApplicationArchiveSlot::try_new(decoder.array32()?)?;
        if slot != selected_slot {
            return Err(RealmProcessorApplicationArchiveError::SlotMismatch);
        }
        let binding = RealmProcessorApplicationArchiveBinding::try_new(
            decoder.u32()?,
            decoder.u32()?,
            decoder.u16()?,
            decoder.array32()?,
            decoder.array32()?,
            decoder.array32()?,
            decoder.array32()?,
            decoder.array32()?,
            decoder.u64()?,
            decoder.array32()?,
            decoder.array32()?,
        )?;
        let semantic_digest = RealmProcessorSemanticOutputDigest::try_new(decoder.array32()?)
            .map_err(|_| RealmProcessorApplicationArchiveError::EmptyDigest)?;
        let semantic_bytes = decoder.u64()?;
        let fragment_count = decoder.u32()?;
        let fragment_set_digest = RealmProcessorApplicationArchiveDigest::try_new(decoder.array32()?)?;
        let context_digest = decoder.array32()?;
        let generation_digest = decoder.array32()?;
        let boundary_digest = decoder.array32()?;
        let item_count = decoder.u64()?;
        let has_application_work = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(RealmProcessorApplicationArchiveError::MalformedHeader),
        };
        let digest = RealmProcessorApplicationArchiveDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(RealmProcessorApplicationArchiveError::TrailingBytes);
        }
        let header = Self {
            slot,
            binding,
            semantic_digest,
            semantic_bytes,
            fragment_count,
            fragment_set_digest,
            context_digest,
            generation_digest,
            boundary_digest,
            item_count,
            has_application_work,
            digest,
        };
        validate_header(&header)?;
        if header.digest != header_digest(&header)? {
            return Err(RealmProcessorApplicationArchiveError::DigestMismatch);
        }
        Ok(header)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorApplicationArchiveFragment {
    slot: RealmProcessorApplicationArchiveSlot,
    bucket: u32,
    index: u32,
    semantic_digest: RealmProcessorSemanticOutputDigest,
    fragment_count: u32,
    semantic_bytes: u64,
    payload: Vec<u8>,
    payload_digest: RealmProcessorApplicationFragmentDigest,
}

impl RealmProcessorApplicationArchiveFragment {
    #[allow(clippy::too_many_arguments)]
    pub fn decode_observed(
        slot: RealmProcessorApplicationArchiveSlot,
        bucket: i64,
        index: i32,
        semantic_digest: Vec<u8>,
        fragment_count: i32,
        semantic_bytes: i64,
        payload: Vec<u8>,
        payload_digest: Vec<u8>,
    ) -> Result<Self, RealmProcessorApplicationArchiveError> {
        let fragment = Self {
            slot,
            bucket: u32::try_from(bucket).map_err(|_| RealmProcessorApplicationArchiveError::CoordinateOutOfRange)?,
            index: u32::try_from(index).map_err(|_| RealmProcessorApplicationArchiveError::CoordinateOutOfRange)?,
            semantic_digest: RealmProcessorSemanticOutputDigest::try_new(
                semantic_digest.try_into().map_err(|_| RealmProcessorApplicationArchiveError::DigestMismatch)?,
            ).map_err(|_| RealmProcessorApplicationArchiveError::EmptyDigest)?,
            fragment_count: u32::try_from(fragment_count).map_err(|_| RealmProcessorApplicationArchiveError::CoordinateOutOfRange)?,
            semantic_bytes: u64::try_from(semantic_bytes).map_err(|_| RealmProcessorApplicationArchiveError::CoordinateOutOfRange)?,
            payload,
            payload_digest: RealmProcessorApplicationFragmentDigest::try_new(
                payload_digest.try_into().map_err(|_| RealmProcessorApplicationArchiveError::DigestMismatch)?,
            )?,
        };
        validate_fragment(&fragment)?;
        Ok(fragment)
    }

    pub const fn slot(&self) -> RealmProcessorApplicationArchiveSlot { self.slot }
    pub const fn bucket(&self) -> u32 { self.bucket }
    pub const fn index(&self) -> u32 { self.index }
    pub const fn semantic_digest(&self) -> RealmProcessorSemanticOutputDigest { self.semantic_digest }
    pub const fn fragment_count(&self) -> u32 { self.fragment_count }
    pub const fn semantic_bytes(&self) -> u64 { self.semantic_bytes }
    pub fn payload(&self) -> &[u8] { &self.payload }
    pub const fn payload_digest(&self) -> RealmProcessorApplicationFragmentDigest { self.payload_digest }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorApplicationArchivePlan {
    header: RealmProcessorApplicationArchiveHeader,
    fragments: Vec<RealmProcessorApplicationArchiveFragment>,
}

impl RealmProcessorApplicationArchivePlan {
    pub fn try_new(
        binding: RealmProcessorApplicationArchiveBinding,
        semantic: &RealmProcessorSemanticOutput,
    ) -> Result<Self, RealmProcessorApplicationArchiveError> {
        if semantic.actor_input_digest().is_none() {
            return Err(RealmProcessorApplicationArchiveError::UnboundSemantic);
        }
        if semantic.canonical_len()? > REALM_APPLICATION_ARCHIVE_MAX_BYTES {
            return Err(RealmProcessorApplicationArchiveError::PayloadTooLarge);
        }
        let bytes = semantic.to_canonical_bytes();
        if bytes.is_empty() || bytes.len() > REALM_APPLICATION_ARCHIVE_MAX_BYTES {
            return Err(RealmProcessorApplicationArchiveError::PayloadTooLarge);
        }
        let slot = archive_slot(&binding)?;
        let fragment_count = u32::try_from(bytes.len().div_ceil(REALM_APPLICATION_ARCHIVE_FRAGMENT_BYTES))
            .map_err(|_| RealmProcessorApplicationArchiveError::PayloadTooLarge)?;
        if fragment_count == 0 || fragment_count > REALM_APPLICATION_ARCHIVE_MAX_FRAGMENTS {
            return Err(RealmProcessorApplicationArchiveError::PayloadTooLarge);
        }
        let semantic_bytes = u64::try_from(bytes.len())
            .map_err(|_| RealmProcessorApplicationArchiveError::PayloadTooLarge)?;
        let fragments = bytes
            .chunks(REALM_APPLICATION_ARCHIVE_FRAGMENT_BYTES)
            .enumerate()
            .map(|(index, payload)| {
                let index = u32::try_from(index)
                    .map_err(|_| RealmProcessorApplicationArchiveError::CoordinateOutOfRange)?;
                let bucket = index / REALM_APPLICATION_ARCHIVE_FRAGMENTS_PER_BUCKET;
                let payload_digest = fragment_digest(
                    slot,
                    semantic.digest(),
                    index,
                    payload,
                )?;
                Ok(RealmProcessorApplicationArchiveFragment {
                    slot,
                    bucket,
                    index,
                    semantic_digest: semantic.digest(),
                    fragment_count,
                    semantic_bytes,
                    payload: payload.to_vec(),
                    payload_digest,
                })
            })
            .collect::<Result<Vec<_>, RealmProcessorApplicationArchiveError>>()?;
        let fragment_set_digest = fragment_set_digest(&fragments)?;
        let mut header = RealmProcessorApplicationArchiveHeader {
            slot,
            binding,
            semantic_digest: semantic.digest(),
            semantic_bytes,
            fragment_count,
            fragment_set_digest,
            context_digest: *semantic.context_digest().as_bytes(),
            generation_digest: *semantic.generation_digest().as_bytes(),
            boundary_digest: *semantic.boundary_digest().as_bytes(),
            item_count: semantic.item_count(),
            has_application_work: semantic.has_application_work(),
            digest: RealmProcessorApplicationArchiveDigest([1; 32]),
        };
        header.digest = header_digest(&header)?;
        Ok(Self { header, fragments })
    }

    pub const fn header(&self) -> &RealmProcessorApplicationArchiveHeader { &self.header }
    pub fn fragments(&self) -> &[RealmProcessorApplicationArchiveFragment] { &self.fragments }

    /// Requires the exact legal coordinate set. Missing, duplicate, extra,
    /// reordered or wrong-content rows all fail closed.
    pub fn reconstruct_exact(
        &self,
        mut observed: Vec<RealmProcessorApplicationArchiveFragment>,
    ) -> Result<RealmProcessorSemanticOutput, RealmProcessorApplicationArchiveError> {
        if observed.len() != self.fragments.len() {
            return Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch);
        }
        observed.sort_by_key(|fragment| (fragment.index, *fragment.semantic_digest.as_bytes()));
        for (expected, actual) in self.fragments.iter().zip(&observed) {
            if expected != actual {
                return Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch);
            }
        }
        reconstruct(&self.header, &observed)
    }
}

pub fn reconstruct_realm_application_archive(
    header: &RealmProcessorApplicationArchiveHeader,
    mut observed: Vec<RealmProcessorApplicationArchiveFragment>,
) -> Result<RealmProcessorSemanticOutput, RealmProcessorApplicationArchiveError> {
    observed.sort_by_key(|fragment| (fragment.index, *fragment.semantic_digest.as_bytes()));
    reconstruct(header, &observed)
}

fn reconstruct(
    header: &RealmProcessorApplicationArchiveHeader,
    observed: &[RealmProcessorApplicationArchiveFragment],
) -> Result<RealmProcessorSemanticOutput, RealmProcessorApplicationArchiveError> {
    if observed.len() != header.fragment_count as usize {
        return Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(header.semantic_bytes)
            .map_err(|_| RealmProcessorApplicationArchiveError::PayloadTooLarge)?,
    );
    for (expected_index, fragment) in observed.iter().enumerate() {
        let expected_index = u32::try_from(expected_index)
            .map_err(|_| RealmProcessorApplicationArchiveError::CoordinateOutOfRange)?;
        if fragment.slot != header.slot
            || fragment.index != expected_index
            || fragment.bucket
                != expected_index / REALM_APPLICATION_ARCHIVE_FRAGMENTS_PER_BUCKET
            || fragment.semantic_digest != header.semantic_digest
            || fragment.fragment_count != header.fragment_count
            || fragment.semantic_bytes != header.semantic_bytes
        {
            return Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch);
        }
        validate_fragment(fragment)?;
        bytes.extend_from_slice(&fragment.payload);
    }
    if bytes.len() as u64 != header.semantic_bytes
        || fragment_set_digest(observed)? != header.fragment_set_digest
    {
        return Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch);
    }
    let semantic = RealmProcessorSemanticOutput::decode_canonical(&bytes)?;
    if semantic.digest() != header.semantic_digest
        || semantic.context_digest().as_bytes() != &header.context_digest
        || semantic.generation_digest().as_bytes() != &header.generation_digest
        || semantic.boundary_digest().as_bytes() != &header.boundary_digest
        || semantic.item_count() != header.item_count
        || semantic.has_application_work() != header.has_application_work
    {
        return Err(RealmProcessorApplicationArchiveError::SemanticMismatch);
    }
    Ok(semantic)
}

fn archive_slot(
    binding: &RealmProcessorApplicationArchiveBinding,
) -> Result<RealmProcessorApplicationArchiveSlot, RealmProcessorApplicationArchiveError> {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(binding.transport_store_fingerprint);
    hasher.update(binding.transport_slot);
    hasher.update(binding.transport_digest);
    RealmProcessorApplicationArchiveSlot::try_new(hasher.finalize().into())
}

fn fragment_digest(
    slot: RealmProcessorApplicationArchiveSlot,
    semantic_digest: RealmProcessorSemanticOutputDigest,
    index: u32,
    payload: &[u8],
) -> Result<RealmProcessorApplicationFragmentDigest, RealmProcessorApplicationArchiveError> {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DOMAIN);
    hasher.update(slot.as_bytes());
    hasher.update(semantic_digest.as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    RealmProcessorApplicationFragmentDigest::try_new(hasher.finalize().into())
}

fn fragment_set_digest(
    fragments: &[RealmProcessorApplicationArchiveFragment],
) -> Result<RealmProcessorApplicationArchiveDigest, RealmProcessorApplicationArchiveError> {
    let mut hasher = Sha256::new();
    hasher.update(DATASET_DOMAIN);
    hasher.update((fragments.len() as u32).to_be_bytes());
    for fragment in fragments {
        hasher.update(fragment.index.to_be_bytes());
        hasher.update(fragment.bucket.to_be_bytes());
        hasher.update(fragment.payload_digest.as_bytes());
        hasher.update((fragment.payload.len() as u64).to_be_bytes());
    }
    RealmProcessorApplicationArchiveDigest::try_new(hasher.finalize().into())
}

fn header_digest(
    header: &RealmProcessorApplicationArchiveHeader,
) -> Result<RealmProcessorApplicationArchiveDigest, RealmProcessorApplicationArchiveError> {
    let mut hasher = Sha256::new();
    hasher.update(HEADER_DOMAIN);
    hasher.update(encode_header_without_digest(header));
    RealmProcessorApplicationArchiveDigest::try_new(hasher.finalize().into())
}

fn encode_header_without_digest(header: &RealmProcessorApplicationArchiveHeader) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(header.slot.as_bytes());
    out.extend_from_slice(&header.binding.network_chain_id.to_be_bytes());
    out.extend_from_slice(&header.binding.realm_id.to_be_bytes());
    out.extend_from_slice(&header.binding.realm_sub_id.to_be_bytes());
    out.extend_from_slice(&header.binding.transport_store_fingerprint);
    out.extend_from_slice(&header.binding.transport_slot);
    out.extend_from_slice(&header.binding.transport_digest);
    out.extend_from_slice(&header.binding.assignment_digest);
    out.extend_from_slice(&header.binding.pipeline_store_fingerprint);
    out.extend_from_slice(&header.binding.pipeline_close_revision.to_be_bytes());
    out.extend_from_slice(&header.binding.pipeline_close_receipt_digest);
    out.extend_from_slice(&header.binding.close_intent_digest);
    out.extend_from_slice(header.semantic_digest.as_bytes());
    out.extend_from_slice(&header.semantic_bytes.to_be_bytes());
    out.extend_from_slice(&header.fragment_count.to_be_bytes());
    out.extend_from_slice(header.fragment_set_digest.as_bytes());
    out.extend_from_slice(&header.context_digest);
    out.extend_from_slice(&header.generation_digest);
    out.extend_from_slice(&header.boundary_digest);
    out.extend_from_slice(&header.item_count.to_be_bytes());
    out.push(u8::from(header.has_application_work));
    out
}

fn validate_header(
    header: &RealmProcessorApplicationArchiveHeader,
) -> Result<(), RealmProcessorApplicationArchiveError> {
    if header.slot != archive_slot(&header.binding)?
        || header.semantic_bytes == 0
        || header.semantic_bytes > REALM_APPLICATION_ARCHIVE_MAX_BYTES as u64
        || header.fragment_count == 0
        || header.fragment_count > REALM_APPLICATION_ARCHIVE_MAX_FRAGMENTS
        || [header.context_digest, header.generation_digest, header.boundary_digest]
            .contains(&[0; 32])
    {
        return Err(RealmProcessorApplicationArchiveError::MalformedHeader);
    }
    Ok(())
}

fn validate_fragment(
    fragment: &RealmProcessorApplicationArchiveFragment,
) -> Result<(), RealmProcessorApplicationArchiveError> {
    if fragment.fragment_count == 0
        || fragment.fragment_count > REALM_APPLICATION_ARCHIVE_MAX_FRAGMENTS
        || fragment.index >= fragment.fragment_count
        || fragment.bucket
            != fragment.index / REALM_APPLICATION_ARCHIVE_FRAGMENTS_PER_BUCKET
        || fragment.bucket >= REALM_APPLICATION_ARCHIVE_MAX_BUCKETS
        || fragment.payload.is_empty()
        || fragment.payload.len() > REALM_APPLICATION_ARCHIVE_FRAGMENT_BYTES
        || fragment.semantic_bytes == 0
        || fragment.semantic_bytes > REALM_APPLICATION_ARCHIVE_MAX_BYTES as u64
        || fragment.payload_digest
            != fragment_digest(
                fragment.slot,
                fragment.semantic_digest,
                fragment.index,
                &fragment.payload,
            )?
    {
        return Err(RealmProcessorApplicationArchiveError::MalformedFragment);
    }
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmProcessorApplicationArchiveError> {
        let end = self.cursor.checked_add(len)
            .ok_or(RealmProcessorApplicationArchiveError::Truncated)?;
        let value = self.bytes.get(self.cursor..end)
            .ok_or(RealmProcessorApplicationArchiveError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, RealmProcessorApplicationArchiveError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, RealmProcessorApplicationArchiveError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, RealmProcessorApplicationArchiveError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, RealmProcessorApplicationArchiveError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array32(&mut self) -> Result<[u8; 32], RealmProcessorApplicationArchiveError> { Ok(self.take(32)?.try_into().unwrap()) }
    fn done(&self) -> bool { self.cursor == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorApplicationArchiveError {
    EmptyDigest,
    InvalidBinding,
    UnboundSemantic,
    PayloadTooLarge,
    CoordinateOutOfRange,
    MalformedHeader,
    MalformedFragment,
    UnknownCodecVersion,
    Truncated,
    TrailingBytes,
    SlotMismatch,
    DigestMismatch,
    FragmentSetMismatch,
    SemanticMismatch,
    Semantic(RealmProcessorSemanticOutputError),
}

impl From<RealmProcessorSemanticOutputError> for RealmProcessorApplicationArchiveError {
    fn from(error: RealmProcessorSemanticOutputError) -> Self { Self::Semantic(error) }
}

impl fmt::Display for RealmProcessorApplicationArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorApplicationArchiveError {}

#[cfg(test)]
mod tests {
    use crate::queue::{
        realm_processor_durable_capture::RealmProcessorDurableGenerationDigest,
        realm_processor_semantic_output::{
            RealmProcessorDeferredJob, RealmProcessorSemanticOutputParts,
        },
        recoverable_ephemeral::{PendingQueueBoundaryDigest, PendingQueueCaptureContextDigest},
    };

    use super::*;

    fn binding() -> RealmProcessorApplicationArchiveBinding {
        RealmProcessorApplicationArchiveBinding::try_new(
            31337, 7, 2, [1; 32], [2; 32], [3; 32], [4; 32], [5; 32], 11,
            [6; 32], [7; 32],
        ).unwrap()
    }

    fn semantic(payload_bytes: usize) -> RealmProcessorSemanticOutput {
        RealmProcessorSemanticOutput::try_from_candidate_parts(
            RealmProcessorSemanticOutputParts {
                context_digest: PendingQueueCaptureContextDigest::try_new([8; 32]).unwrap(),
                generation_digest: RealmProcessorDurableGenerationDigest::try_new([9; 32]).unwrap(),
                boundary_digest: PendingQueueBoundaryDigest::try_new([10; 32]).unwrap(),
                item_count: 0,
                input_binding: crate::queue::realm_processor_semantic_output::RealmProcessorSemanticInputBinding::SuccessorQualified(
                    crate::queue::realm_processor_actor_input::RealmProcessorActorInputDigest::try_new([17; 32]).unwrap(),
                ),
                processing_checkpoint_id: 42,
                processing_checkpoint_root: [11; 32],
                processing_realm_start_root: [12; 32],
                old_realm_root: [12; 32],
                new_realm_root: [12; 32],
                total_users_updated: 0,
                total_proofs_generated: 0,
                global_user_tree_nodes: vec![13; payload_bytes],
                user_contract_tree_nodes: vec![],
                contract_state_tree_nodes: vec![],
                user_leaves: vec![],
                contract_state_imt_leaves: vec![],
                guta_header: vec![14],
                jobs: vec![],
                deferred_jobs: if payload_bytes == 0 {
                    vec![RealmProcessorDeferredJob::try_new(0, vec![15], vec![16]).unwrap()]
                } else {
                    vec![]
                },
            },
        ).unwrap()
    }

    #[test]
    fn new_archive_plan_rejects_historical_unbound_semantics() {
        let historical = |input_binding| {
            RealmProcessorSemanticOutput::try_from_candidate_parts(
                RealmProcessorSemanticOutputParts {
                context_digest: PendingQueueCaptureContextDigest::try_new([8; 32]).unwrap(),
                generation_digest: RealmProcessorDurableGenerationDigest::try_new([9; 32]).unwrap(),
                boundary_digest: PendingQueueBoundaryDigest::try_new([10; 32]).unwrap(),
                item_count: 0,
                input_binding,
                processing_checkpoint_id: 42,
                processing_checkpoint_root: [11; 32],
                processing_realm_start_root: [12; 32],
                old_realm_root: [12; 32],
                new_realm_root: [12; 32],
                total_users_updated: 0,
                total_proofs_generated: 0,
                global_user_tree_nodes: vec![],
                user_contract_tree_nodes: vec![],
                contract_state_tree_nodes: vec![],
                user_leaves: vec![],
                contract_state_imt_leaves: vec![],
                guta_header: vec![14],
                jobs: vec![],
                deferred_jobs: vec![],
                },
            )
            .unwrap()
        };
        for semantic in [
            historical(
                crate::queue::realm_processor_semantic_output::RealmProcessorSemanticInputBinding::LegacyUnbound,
            ),
            historical(
                crate::queue::realm_processor_semantic_output::RealmProcessorSemanticInputBinding::SuccessorDeferred(
                    crate::queue::realm_processor_deferred_actor_input::RealmProcessorDeferredActorInputDigest::try_new([18; 32]).unwrap(),
                ),
            ),
        ] {
            assert_eq!(
                RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic),
                Err(RealmProcessorApplicationArchiveError::UnboundSemantic),
            );
        }
    }

    #[test]
    fn deterministic_plan_header_and_exact_reconstruction() {
        let semantic = semantic(REALM_APPLICATION_ARCHIVE_FRAGMENT_BYTES + 17);
        let first = RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic).unwrap();
        let second = RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.fragments().len(), 2);
        assert_eq!(first.header().fragment_count(), 2);
        assert_eq!(first.header().semantic_digest(), semantic.digest());
        assert_eq!(
            RealmProcessorApplicationArchiveHeader::decode_selected(
                first.header().slot(),
                &first.header().to_canonical_bytes(),
            ).unwrap(),
            *first.header(),
        );
        assert_eq!(first.reconstruct_exact(first.fragments().to_vec()).unwrap(), semantic);
    }

    #[test]
    fn slot_is_transport_owned_and_header_conflicts_on_different_application() {
        let first = RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic(1)).unwrap();
        let second = RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic(2)).unwrap();
        assert_eq!(first.header().slot(), second.header().slot());
        assert_ne!(first.header().semantic_digest(), second.header().semantic_digest());
        assert_ne!(first.header().digest(), second.header().digest());
    }

    #[test]
    fn missing_extra_and_tamper_fail_closed() {
        let semantic = semantic(REALM_APPLICATION_ARCHIVE_FRAGMENT_BYTES + 17);
        let plan = RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic).unwrap();
        let mut missing = plan.fragments().to_vec();
        missing.pop();
        assert_eq!(plan.reconstruct_exact(missing), Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch));
        let mut extra = plan.fragments().to_vec();
        extra.push(extra[0].clone());
        assert_eq!(plan.reconstruct_exact(extra), Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch));
        let mut tampered = plan.fragments().to_vec();
        tampered[0].payload[0] ^= 1;
        assert_eq!(plan.reconstruct_exact(tampered), Err(RealmProcessorApplicationArchiveError::FragmentSetMismatch));
    }

    #[test]
    fn header_codec_rejects_unknown_trailing_and_tamper() {
        let plan = RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic(1)).unwrap();
        let bytes = plan.header().to_canonical_bytes();
        let mut unknown = bytes.clone();
        unknown[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            RealmProcessorApplicationArchiveHeader::decode_selected(plan.header().slot(), &unknown),
            Err(RealmProcessorApplicationArchiveError::UnknownCodecVersion),
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            RealmProcessorApplicationArchiveHeader::decode_selected(plan.header().slot(), &trailing),
            Err(RealmProcessorApplicationArchiveError::TrailingBytes),
        );
        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            RealmProcessorApplicationArchiveHeader::decode_selected(plan.header().slot(), &tampered),
            Err(RealmProcessorApplicationArchiveError::DigestMismatch),
        );
    }

    #[test]
    fn deferred_only_output_is_archived_as_application_work() {
        let semantic = semantic(0);
        let plan = RealmProcessorApplicationArchivePlan::try_new(binding(), &semantic).unwrap();
        assert!(plan.header().has_application_work());
        assert_eq!(plan.reconstruct_exact(plan.fragments().to_vec()).unwrap(), semantic);
    }
}
