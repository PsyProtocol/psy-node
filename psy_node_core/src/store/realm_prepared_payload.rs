//! Shared content commitment for one exact Realm prepared-update payload.
//!
//! The proof and mutation-graph seals retain their existing domain-specific
//! digests. This additional commitment gives the commit-evidence binder one
//! common value to compare without changing either durable V1 codec.

use sha2::{Digest, Sha256};

const REALM_PREPARED_PAYLOAD_COMMITMENT_DOMAIN: &[u8] =
    b"psy.rollback.realm-prepared-payload-commitment.v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmPreparedPayloadCommitment([u8; 32]);

impl RealmPreparedPayloadCommitment {
    pub const fn as_bytes(self) -> [u8; 32] { self.0 }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }

    pub(crate) fn from_serialized(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(REALM_PREPARED_PAYLOAD_COMMITMENT_DOMAIN);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }
}
