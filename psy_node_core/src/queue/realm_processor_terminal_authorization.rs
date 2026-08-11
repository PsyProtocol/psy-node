//! Canonical evidence envelope consumed by the Realm terminal owner.
//!
//! The envelope commits the exact successor dependency projection together
//! with the durable writer and authority-head rows that closed its
//! predecessor. It is deliberately a checked data model, not an authority
//! token: only the storage adapter may mint a terminal after freshly reading
//! and validating all three durable sources.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use super::{
    realm_processor_external_dependency_input::RealmProcessorExternalDependencyCommitment,
    realm_processor_generation_terminal::REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES,
};

const MAGIC: &[u8; 8] = b"PSYRAUTH";
const CODEC_VERSION: u16 = 1;
const DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-terminal-authorization-envelope/v1";
const MAX_COMPONENT_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorTerminalAuthorizationEnvelopeDigest([u8; 32]);

impl RealmProcessorTerminalAuthorizationEnvelopeDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorTerminalAuthorizationError> {
        if bytes == [0; 32] {
            Err(RealmProcessorTerminalAuthorizationError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorTerminalAuthorizationEnvelope {
    external_dependency: RealmProcessorExternalDependencyCommitment,
    writer_slot: [u8; 32],
    writer_revision: u64,
    writer_payload: Vec<u8>,
    authority_head_revision: u64,
    authority_head_payload: Vec<u8>,
    digest: RealmProcessorTerminalAuthorizationEnvelopeDigest,
}

impl RealmProcessorTerminalAuthorizationEnvelope {
    pub fn try_new(
        external_dependency: RealmProcessorExternalDependencyCommitment,
        writer_slot: [u8; 32],
        writer_revision: u64,
        writer_payload: Vec<u8>,
        authority_head_revision: u64,
        authority_head_payload: Vec<u8>,
    ) -> Result<Self, RealmProcessorTerminalAuthorizationError> {
        if writer_slot == [0; 32] {
            return Err(RealmProcessorTerminalAuthorizationError::EmptyWriterSlot);
        }
        if writer_payload.is_empty()
            || authority_head_payload.is_empty()
            || writer_payload.len() > MAX_COMPONENT_BYTES
            || authority_head_payload.len() > MAX_COMPONENT_BYTES
        {
            return Err(RealmProcessorTerminalAuthorizationError::InvalidComponentSize);
        }
        let mut envelope = Self {
            external_dependency,
            writer_slot,
            writer_revision,
            writer_payload,
            authority_head_revision,
            authority_head_payload,
            digest: RealmProcessorTerminalAuthorizationEnvelopeDigest([1; 32]),
        };
        envelope.digest = authorization_digest(&envelope.encode_unsigned())?;
        if envelope.to_canonical_bytes().len()
            > REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES
        {
            return Err(RealmProcessorTerminalAuthorizationError::EnvelopeTooLarge);
        }
        Ok(envelope)
    }

    pub const fn external_dependency(
        &self,
    ) -> RealmProcessorExternalDependencyCommitment {
        self.external_dependency
    }

    pub const fn writer_slot(&self) -> &[u8; 32] {
        &self.writer_slot
    }

    pub const fn writer_revision(&self) -> u64 {
        self.writer_revision
    }

    pub fn writer_payload(&self) -> &[u8] {
        &self.writer_payload
    }

    pub const fn authority_head_revision(&self) -> u64 {
        self.authority_head_revision
    }

    pub fn authority_head_payload(&self) -> &[u8] {
        &self.authority_head_payload
    }

    pub const fn digest(&self) -> RealmProcessorTerminalAuthorizationEnvelopeDigest {
        self.digest
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmProcessorTerminalAuthorizationError> {
        if bytes.len() > REALM_GENERATION_TERMINAL_MAX_AUTHORIZATION_BYTES {
            return Err(RealmProcessorTerminalAuthorizationError::EnvelopeTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(RealmProcessorTerminalAuthorizationError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != CODEC_VERSION {
            return Err(RealmProcessorTerminalAuthorizationError::UnknownCodecVersion(
                version,
            ));
        }
        let external_dependency = RealmProcessorExternalDependencyCommitment::decode_canonical(
            decoder.bytes(MAX_COMPONENT_BYTES)?,
        )
        .map_err(|error| {
            RealmProcessorTerminalAuthorizationError::Dependency(error.to_string())
        })?;
        let writer_slot = decoder.array32()?;
        let writer_revision = decoder.u64()?;
        let writer_payload = decoder.bytes(MAX_COMPONENT_BYTES)?.to_vec();
        let authority_head_revision = decoder.u64()?;
        let authority_head_payload = decoder.bytes(MAX_COMPONENT_BYTES)?.to_vec();
        let digest = RealmProcessorTerminalAuthorizationEnvelopeDigest::try_new(
            decoder.array32()?,
        )?;
        if !decoder.done() {
            return Err(RealmProcessorTerminalAuthorizationError::TrailingBytes);
        }
        let envelope = Self::try_new(
            external_dependency,
            writer_slot,
            writer_revision,
            writer_payload,
            authority_head_revision,
            authority_head_payload,
        )?;
        if envelope.digest != digest || envelope.to_canonical_bytes() != bytes {
            return Err(RealmProcessorTerminalAuthorizationError::DigestMismatch);
        }
        Ok(envelope)
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let dependency = self.external_dependency.to_canonical_bytes();
        let mut out = Vec::with_capacity(
            128 + dependency.len() + self.writer_payload.len()
                + self.authority_head_payload.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        encode_bytes(&mut out, &dependency);
        out.extend_from_slice(&self.writer_slot);
        out.extend_from_slice(&self.writer_revision.to_be_bytes());
        encode_bytes(&mut out, &self.writer_payload);
        out.extend_from_slice(&self.authority_head_revision.to_be_bytes());
        encode_bytes(&mut out, &self.authority_head_payload);
        out
    }
}

fn authorization_digest(
    unsigned: &[u8],
) -> Result<RealmProcessorTerminalAuthorizationEnvelopeDigest, RealmProcessorTerminalAuthorizationError>
{
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(unsigned);
    RealmProcessorTerminalAuthorizationEnvelopeDigest::try_new(hasher.finalize().into())
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("validated component length fits u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(
        &mut self,
        len: usize,
    ) -> Result<&'a [u8], RealmProcessorTerminalAuthorizationError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RealmProcessorTerminalAuthorizationError::Truncated)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RealmProcessorTerminalAuthorizationError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, RealmProcessorTerminalAuthorizationError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, RealmProcessorTerminalAuthorizationError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RealmProcessorTerminalAuthorizationError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], RealmProcessorTerminalAuthorizationError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn bytes(
        &mut self,
        maximum: usize,
    ) -> Result<&'a [u8], RealmProcessorTerminalAuthorizationError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| RealmProcessorTerminalAuthorizationError::InvalidComponentSize)?;
        if len == 0 || len > maximum {
            return Err(RealmProcessorTerminalAuthorizationError::InvalidComponentSize);
        }
        self.take(len)
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorTerminalAuthorizationError {
    EmptyDigest,
    EmptyWriterSlot,
    InvalidComponentSize,
    EnvelopeTooLarge,
    InvalidMagic,
    UnknownCodecVersion(u16),
    Truncated,
    TrailingBytes,
    DigestMismatch,
    Dependency(String),
}

impl fmt::Display for RealmProcessorTerminalAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorTerminalAuthorizationError {}

#[cfg(test)]
mod tests {
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };

    use crate::{
        queue::{
            realm_processor_external_dependency_input::RealmProcessorExternalDependencyProjection,
            realm_user_update_admission::{
                RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
                RealmUserUpdateQualificationDigest,
            },
            recoverable_ephemeral::PendingQueueCaptureContext,
        },
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };

    use super::*;

    fn dependency() -> RealmProcessorExternalDependencyCommitment {
        let context = PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1).unwrap(),
                AuthorityScope::Realm {
                    realm_id: 2,
                    realm_sub_id: 3,
                },
            ),
            PendingGenerationActivationDigest::try_new([4; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(5, 6).unwrap(),
        )
        .unwrap();
        let close = RealmUserUpdateAdmissionCloseIntent::derive(
            RealmUserUpdateAdmissionKey::try_new(context).unwrap(),
            [7; 32],
        )
        .unwrap();
        RealmProcessorExternalDependencyProjection::try_new(
            context,
            close,
            RealmUserUpdateQualificationDigest::try_new([8; 32]).unwrap(),
            [9; 32],
            Vec::new(),
        )
        .unwrap()
        .commitment()
    }

    #[test]
    fn envelope_roundtrip_binds_dependency_writer_and_head() {
        let envelope = RealmProcessorTerminalAuthorizationEnvelope::try_new(
            dependency(),
            [10; 32],
            11,
            vec![12; 17],
            13,
            vec![14; 19],
        )
        .unwrap();
        let bytes = envelope.to_canonical_bytes();
        assert_eq!(
            RealmProcessorTerminalAuthorizationEnvelope::decode_canonical(&bytes)
                .unwrap(),
            envelope,
        );
        assert_ne!(envelope.digest().as_bytes(), &[0; 32]);

        let changed_dependency = RealmProcessorExternalDependencyProjection::try_new(
            dependency().context(),
            dependency().admission_close_intent(),
            dependency().qualification_digest(),
            [9; 32],
            Vec::new(),
        )
        .unwrap();
        let changed = RealmProcessorTerminalAuthorizationEnvelope::try_new(
            changed_dependency.commitment(),
            [10; 32],
            11,
            vec![12; 17],
            13,
            vec![15; 19],
        )
        .unwrap();
        assert_ne!(envelope.digest(), changed.digest());
    }

    #[test]
    fn envelope_rejects_tamper_trailing_and_invalid_components() {
        let envelope = RealmProcessorTerminalAuthorizationEnvelope::try_new(
            dependency(),
            [10; 32],
            11,
            vec![12; 17],
            13,
            vec![14; 19],
        )
        .unwrap();
        let mut tampered = envelope.to_canonical_bytes();
        tampered[40] ^= 1;
        assert!(matches!(
            RealmProcessorTerminalAuthorizationEnvelope::decode_canonical(&tampered),
            Err(RealmProcessorTerminalAuthorizationError::Dependency(_))
                | Err(RealmProcessorTerminalAuthorizationError::DigestMismatch)
        ));
        let mut trailing = envelope.to_canonical_bytes();
        trailing.push(0);
        assert_eq!(
            RealmProcessorTerminalAuthorizationEnvelope::decode_canonical(&trailing)
                .unwrap_err(),
            RealmProcessorTerminalAuthorizationError::TrailingBytes,
        );
        assert_eq!(
            RealmProcessorTerminalAuthorizationEnvelope::try_new(
                dependency(),
                [0; 32],
                1,
                vec![1],
                1,
                vec![1],
            )
            .unwrap_err(),
            RealmProcessorTerminalAuthorizationError::EmptyWriterSlot,
        );
    }
}
