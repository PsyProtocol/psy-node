//! Canonical deployment-topology snapshot used to verify global rollback scope.
//!
//! Constructing this value only validates bytes.  Durable authority comes from
//! exact persistence and read-back by the Coordinator topology store.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::NetworkId;
use sha2::{Digest, Sha256};

use super::rollback_participant_plan::{
    RollbackParticipantPlan, RollbackRealmParticipant,
};

const TOPOLOGY_MAGIC: &[u8; 8] = b"PSYRBT01";
const TOPOLOGY_VERSION: u16 = 1;
const TOPOLOGY_DIGEST_DOMAIN: &[u8] = b"psy.rollback.deployment-topology.v1\0";
const MAX_REALMS: usize = 1_048_576;
const MAX_TOPOLOGY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackTopologySnapshot {
    network: NetworkId,
    revision: u64,
    realms: Vec<RollbackRealmParticipant>,
    canonical_bytes: Vec<u8>,
    digest: [u8; 32],
}

impl RollbackTopologySnapshot {
    pub fn try_new(
        network: NetworkId,
        revision: u64,
        mut realms: Vec<RollbackRealmParticipant>,
    ) -> Result<Self, RollbackTopologyError> {
        if revision > i64::MAX as u64 {
            return Err(RollbackTopologyError::RevisionOutOfRange(revision));
        }
        if realms.is_empty() || realms.len() > MAX_REALMS {
            return Err(RollbackTopologyError::InvalidRealmCount(realms.len()));
        }
        realms.sort_unstable();
        if realms.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RollbackTopologyError::DuplicateRealm);
        }
        let mut canonical_bytes = Vec::with_capacity(58 + realms.len() * 6);
        canonical_bytes.extend_from_slice(TOPOLOGY_MAGIC);
        canonical_bytes.extend_from_slice(&TOPOLOGY_VERSION.to_be_bytes());
        canonical_bytes.extend_from_slice(&network.chain_id().to_be_bytes());
        canonical_bytes.extend_from_slice(&revision.to_be_bytes());
        canonical_bytes.extend_from_slice(
            &u32::try_from(realms.len())
                .map_err(|_| RollbackTopologyError::LengthOverflow)?
                .to_be_bytes(),
        );
        for realm in &realms {
            canonical_bytes.extend_from_slice(&realm.realm_id().to_be_bytes());
            canonical_bytes.extend_from_slice(&realm.realm_sub_id().to_be_bytes());
        }
        let digest = topology_digest(&canonical_bytes);
        canonical_bytes.extend_from_slice(&digest);
        if canonical_bytes.len() > MAX_TOPOLOGY_BYTES {
            return Err(RollbackTopologyError::TooLarge);
        }
        Ok(Self {
            network,
            revision,
            realms,
            canonical_bytes,
            digest,
        })
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RollbackTopologyError> {
        if bytes.len() > MAX_TOPOLOGY_BYTES {
            return Err(RollbackTopologyError::TooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != TOPOLOGY_MAGIC {
            return Err(RollbackTopologyError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != TOPOLOGY_VERSION {
            return Err(RollbackTopologyError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?)
            .map_err(|error| RollbackTopologyError::Network(error.to_string()))?;
        let revision = cursor.u64()?;
        let count = cursor.u32()? as usize;
        if count == 0 || count > MAX_REALMS {
            return Err(RollbackTopologyError::InvalidRealmCount(count));
        }
        let mut realms = Vec::with_capacity(count);
        for _ in 0..count {
            realms.push(RollbackRealmParticipant::new(
                cursor.u32()?,
                cursor.u16()?,
            ));
        }
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RollbackTopologyError::TrailingBytes);
        }
        if bytes.len() < 32 || topology_digest(&bytes[..bytes.len() - 32]) != digest {
            return Err(RollbackTopologyError::DigestMismatch);
        }
        let decoded = Self::try_new(network, revision, realms)?;
        if decoded.digest != digest || decoded.canonical_bytes != bytes {
            return Err(RollbackTopologyError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    pub const fn network(&self) -> NetworkId {
        self.network
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn realms(&self) -> &[RollbackRealmParticipant] {
        &self.realms
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn validates_plan<Hash: Q256BitHash>(
        &self,
        plan: &RollbackParticipantPlan<Hash>,
    ) -> bool {
        plan.expected_head().canonical_ref().network_id() == self.network
            && plan.topology_revision() == self.revision
            && plan.topology_digest() == &self.digest
            && plan.realms() == self.realms
    }
}

fn topology_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOPOLOGY_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RollbackTopologyError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RollbackTopologyError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(RollbackTopologyError::Truncated);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, RollbackTopologyError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed u16")))
    }

    fn u32(&mut self) -> Result<u32, RollbackTopologyError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed u32")))
    }

    fn u64(&mut self) -> Result<u64, RollbackTopologyError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed u64")))
    }

    fn array_32(&mut self) -> Result<[u8; 32], RollbackTopologyError> {
        Ok(self.take(32)?.try_into().expect("fixed digest"))
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RollbackTopologyError {
    Network(String),
    RevisionOutOfRange(u64),
    InvalidRealmCount(usize),
    DuplicateRealm,
    InvalidMagic,
    UnknownVersion(u16),
    TooLarge,
    LengthOverflow,
    Truncated,
    TrailingBytes,
    DigestMismatch,
    NonCanonicalEncoding,
}

impl fmt::Display for RollbackTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid rollback topology: {self:?}")
    }
}

impl Error for RollbackTopologyError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef,
    };

    use super::*;
    use crate::store::{
        canonical_head::StoredCanonicalHead,
        rollback_control::RollbackControlState,
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    fn snapshot() -> RollbackTopologySnapshot {
        RollbackTopologySnapshot::try_new(
            NetworkId::try_from_chain_id(1).unwrap(),
            7,
            vec![
                RollbackRealmParticipant::new(2, 1),
                RollbackRealmParticipant::new(0, 1),
            ],
        )
        .unwrap()
    }

    fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
        CheckpointRef::new(
            CheckpointId::new(height),
            CheckpointHash::from_last_chain_hash(PHash::from_values(
                seed,
                seed + 1,
                seed + 2,
                seed + 3,
            )),
        )
    }

    #[test]
    fn topology_roundtrips_and_sorts_realms() {
        let snapshot = snapshot();
        assert_eq!(snapshot.realms()[0], RollbackRealmParticipant::new(0, 1));
        assert_eq!(
            RollbackTopologySnapshot::decode_canonical(snapshot.canonical_bytes()).unwrap(),
            snapshot,
        );
    }

    #[test]
    fn topology_rejects_empty_duplicate_and_tampered_content() {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        assert_eq!(
            RollbackTopologySnapshot::try_new(network, 1, Vec::new()),
            Err(RollbackTopologyError::InvalidRealmCount(0)),
        );
        assert_eq!(
            RollbackTopologySnapshot::try_new(
                network,
                1,
                vec![
                    RollbackRealmParticipant::new(1, 1),
                    RollbackRealmParticipant::new(1, 1),
                ],
            ),
            Err(RollbackTopologyError::DuplicateRealm),
        );
        let mut bytes = snapshot().canonical_bytes().to_vec();
        bytes[26] ^= 1;
        assert_eq!(
            RollbackTopologySnapshot::decode_canonical(&bytes),
            Err(RollbackTopologyError::DigestMismatch),
        );
    }

    #[test]
    fn only_exact_topology_revision_digest_and_realm_set_validate_plan() {
        let topology = snapshot();
        let network = topology.network();
        let expected_ref =
            CanonicalChainRef::new(network, ChainEpoch::new(3), checkpoint(10, 10));
        let expected = StoredCanonicalHead::decode_persisted(
            network,
            4,
            &expected_ref.to_canonical_bytes(),
            &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
        )
        .unwrap();
        let plan = RollbackParticipantPlan::try_new(
            expected,
            CanonicalChainRef::new(network, ChainEpoch::new(3), checkpoint(7, 20)),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            topology.revision(),
            *topology.digest(),
            topology.realms().to_vec(),
        )
        .unwrap();
        assert!(topology.validates_plan(&plan));

        let different = RollbackTopologySnapshot::try_new(
            network,
            topology.revision() + 1,
            topology.realms().to_vec(),
        )
        .unwrap();
        assert!(!different.validates_plan(&plan));
    }

    #[test]
    fn topology_model_grants_no_barrier_or_delete_authority() {
        let source = include_str!("rollback_topology.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["advance_archive_barrier(", "delete_hot_suffix(", "publish_target("] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }
}
