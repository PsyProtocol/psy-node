//! Canonical participant-set commitment for one explicit global rollback.
//!
//! The plan freezes exactly one Coordinator plus an ordered set of Realm
//! identities before admission.  It does not claim that the supplied topology
//! snapshot is authoritative; a storage-owned topology reader must verify the
//! topology revision/digest before this plan can be offered to the rollback
//! inbox or accepted by a global archive barrier.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, NetworkId, CANONICAL_CHAIN_REF_V1_LEN,
};
use sha2::{Digest, Sha256};

use super::{
    canonical_head::StoredCanonicalHead,
    rollback_control::{
        RollbackControlState, RollbackExecutionMode, RollbackPlanDigest,
        RollbackRequest,
    },
    timestamp::{
        CommitWriteTimestampUs, TimestampFenceWindow, TimestampOrderingError,
        TimestampOutOfCqlRange,
    },
};

const PLAN_MAGIC: &[u8; 8] = b"PSYRBPP1";
const PLAN_VERSION: u16 = 1;
const PLAN_DIGEST_DOMAIN: &[u8] = b"psy.rollback.global-participant-plan.v1\0";
const MAX_REALM_PARTICIPANTS: usize = 1_048_576;
const MAX_PLAN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RollbackRealmParticipant {
    realm_id: u32,
    realm_sub_id: u16,
}

impl RollbackRealmParticipant {
    pub const fn new(realm_id: u32, realm_sub_id: u16) -> Self {
        Self {
            realm_id,
            realm_sub_id,
        }
    }

    pub const fn realm_id(self) -> u32 {
        self.realm_id
    }

    pub const fn realm_sub_id(self) -> u16 {
        self.realm_sub_id
    }
}

/// Non-clone canonical plan.  Coordinator participation is implicit and
/// mandatory; `realms` is the exact topology-selected Realm set.
#[derive(Debug, Eq, PartialEq)]
pub struct RollbackParticipantPlan<Hash> {
    expected_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    fence_window: TimestampFenceWindow,
    topology_revision: u64,
    topology_digest: [u8; 32],
    realms: Vec<RollbackRealmParticipant>,
    canonical_bytes: Vec<u8>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RollbackParticipantPlan<Hash> {
    pub fn try_new(
        expected_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        fence_window: TimestampFenceWindow,
        topology_revision: u64,
        topology_digest: [u8; 32],
        mut realms: Vec<RollbackRealmParticipant>,
    ) -> Result<Self, RollbackParticipantPlanError> {
        if !expected_head.rollback_control().is_idle()
            || target.network_id() != expected_head.canonical_ref().network_id()
            || target.chain_epoch() != expected_head.canonical_ref().chain_epoch()
            || target.checkpoint().checkpoint_id().get()
                >= expected_head
                    .canonical_ref()
                    .checkpoint()
                    .checkpoint_id()
                    .get()
        {
            return Err(RollbackParticipantPlanError::InvalidScope);
        }
        if topology_revision > i64::MAX as u64 {
            return Err(RollbackParticipantPlanError::TopologyRevisionOutOfRange(
                topology_revision,
            ));
        }
        if topology_digest == [0; 32] {
            return Err(RollbackParticipantPlanError::ZeroTopologyDigest);
        }
        if realms.is_empty() || realms.len() > MAX_REALM_PARTICIPANTS {
            return Err(RollbackParticipantPlanError::InvalidRealmCount(
                realms.len(),
            ));
        }
        realms.sort_unstable();
        if realms.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RollbackParticipantPlanError::DuplicateRealm);
        }

        let mut plan = Self {
            expected_head,
            target,
            fence_window,
            topology_revision,
            topology_digest,
            realms,
            canonical_bytes: Vec::new(),
            digest: [0; 32],
        };
        let commitment = plan.encode_without_digest()?;
        plan.digest = participant_plan_digest(&commitment);
        plan.canonical_bytes = commitment;
        plan.canonical_bytes.extend_from_slice(&plan.digest);
        if plan.canonical_bytes.len() > MAX_PLAN_BYTES {
            return Err(RollbackParticipantPlanError::PlanTooLarge);
        }
        Ok(plan)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RollbackParticipantPlanError> {
        if bytes.len() > MAX_PLAN_BYTES {
            return Err(RollbackParticipantPlanError::PlanTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != PLAN_MAGIC {
            return Err(RollbackParticipantPlanError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != PLAN_VERSION {
            return Err(RollbackParticipantPlanError::UnknownVersion(version));
        }
        let network = NetworkId::try_from_chain_id(cursor.u32()?)
            .map_err(|error| RollbackParticipantPlanError::Canonical(error.to_string()))?;
        let expected_revision = cursor.i64()?;
        let expected_canonical = cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?;
        let expected_control = cursor.bytes()?;
        let expected_head = StoredCanonicalHead::decode_persisted(
            network,
            expected_revision,
            expected_canonical,
            expected_control,
        )
        .map_err(|error| RollbackParticipantPlanError::Canonical(error.to_string()))?;
        let target = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|error| RollbackParticipantPlanError::Canonical(error.to_string()))?;
        let fence_window = TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(i128::from(cursor.i64()?))?,
            i128::from(cursor.i64()?),
            i128::from(cursor.i64()?),
        )?;
        let topology_revision = cursor.u64()?;
        let topology_digest = cursor.array_32()?;
        let realm_count = cursor.u32()? as usize;
        if realm_count == 0 || realm_count > MAX_REALM_PARTICIPANTS {
            return Err(RollbackParticipantPlanError::InvalidRealmCount(
                realm_count,
            ));
        }
        let mut realms = Vec::with_capacity(realm_count);
        for _ in 0..realm_count {
            realms.push(RollbackRealmParticipant::new(
                cursor.u32()?,
                cursor.u16()?,
            ));
        }
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(RollbackParticipantPlanError::TrailingBytes);
        }
        if bytes.len() < 32 || participant_plan_digest(&bytes[..bytes.len() - 32]) != digest {
            return Err(RollbackParticipantPlanError::DigestMismatch);
        }
        let decoded = Self::try_new(
            expected_head,
            target,
            fence_window,
            topology_revision,
            topology_digest,
            realms,
        )?;
        if decoded.digest != digest || decoded.canonical_bytes != bytes {
            return Err(RollbackParticipantPlanError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    pub const fn expected_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.expected_head
    }

    pub const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.target
    }

    pub const fn fence_window(&self) -> TimestampFenceWindow {
        self.fence_window
    }

    pub const fn topology_revision(&self) -> u64 {
        self.topology_revision
    }

    pub const fn topology_digest(&self) -> &[u8; 32] {
        &self.topology_digest
    }

    pub fn realms(&self) -> &[RollbackRealmParticipant] {
        &self.realms
    }

    pub const fn participant_count(&self) -> usize {
        // Coordinator is always participant zero.
        self.realms.len() + 1
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn rollback_request(&self) -> Result<RollbackRequest<Hash>, RollbackParticipantPlanError> {
        Ok(RollbackRequest::try_new(
            *self.expected_head.canonical_ref().checkpoint(),
            *self.target.checkpoint(),
            self.fence_window,
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new(self.digest)
                .map_err(RollbackParticipantPlanError::Control)?,
        )
        .map_err(RollbackParticipantPlanError::Control)?)
    }

    fn encode_without_digest(&self) -> Result<Vec<u8>, RollbackParticipantPlanError> {
        let expected_control = self.expected_head.rollback_control_bytes();
        let mut bytes = Vec::with_capacity(320 + self.realms.len() * 6);
        bytes.extend_from_slice(PLAN_MAGIC);
        bytes.extend_from_slice(&PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .expected_head
                .canonical_ref()
                .network_id()
                .chain_id()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.expected_head.revision().as_i64().to_be_bytes());
        bytes.extend_from_slice(&self.expected_head.canonical_ref_bytes());
        encode_bytes(&mut bytes, &expected_control)?;
        bytes.extend_from_slice(&self.target.to_canonical_bytes());
        bytes.extend_from_slice(
            &self
                .fence_window
                .delete_fence()
                .orphan_write_max()
                .as_i64()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.fence_window.delete_fence().as_i64().to_be_bytes());
        bytes.extend_from_slice(
            &self
                .fence_window
                .new_branch_write()
                .as_commit_timestamp()
                .as_i64()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.topology_revision.to_be_bytes());
        bytes.extend_from_slice(&self.topology_digest);
        bytes.extend_from_slice(
            &u32::try_from(self.realms.len())
                .map_err(|_| RollbackParticipantPlanError::LengthOverflow)?
                .to_be_bytes(),
        );
        for realm in &self.realms {
            bytes.extend_from_slice(&realm.realm_id.to_be_bytes());
            bytes.extend_from_slice(&realm.realm_sub_id.to_be_bytes());
        }
        Ok(bytes)
    }
}

fn encode_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), RollbackParticipantPlanError> {
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| RollbackParticipantPlanError::LengthOverflow)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn participant_plan_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], RollbackParticipantPlanError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RollbackParticipantPlanError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(RollbackParticipantPlanError::Truncated);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, RollbackParticipantPlanError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed u16")))
    }

    fn u32(&mut self) -> Result<u32, RollbackParticipantPlanError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed u32")))
    }

    fn u64(&mut self) -> Result<u64, RollbackParticipantPlanError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed u64")))
    }

    fn i64(&mut self) -> Result<i64, RollbackParticipantPlanError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("fixed i64")))
    }

    fn array_32(&mut self) -> Result<[u8; 32], RollbackParticipantPlanError> {
        Ok(self.take(32)?.try_into().expect("fixed array"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], RollbackParticipantPlanError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RollbackParticipantPlanError {
    Canonical(String),
    Control(super::rollback_control::RollbackControlError),
    Timestamp(TimestampOrderingError),
    InvalidScope,
    TopologyRevisionOutOfRange(u64),
    ZeroTopologyDigest,
    InvalidRealmCount(usize),
    DuplicateRealm,
    InvalidMagic,
    UnknownVersion(u16),
    PlanTooLarge,
    LengthOverflow,
    Truncated,
    TrailingBytes,
    DigestMismatch,
    NonCanonicalEncoding,
}

impl From<TimestampOutOfCqlRange> for RollbackParticipantPlanError {
    fn from(error: TimestampOutOfCqlRange) -> Self {
        Self::Timestamp(TimestampOrderingError::OutOfCqlRange(error))
    }
}

impl From<TimestampOrderingError> for RollbackParticipantPlanError {
    fn from(error: TimestampOrderingError) -> Self {
        Self::Timestamp(error)
    }
}

impl fmt::Display for RollbackParticipantPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid rollback participant plan: {self:?}")
    }
}

impl Error for RollbackParticipantPlanError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };

    use super::*;
    use crate::store::timestamp::CommitWriteTimestampUs;

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

    fn fixture(
        realms: Vec<RollbackRealmParticipant>,
    ) -> Result<RollbackParticipantPlan<PHash>, RollbackParticipantPlanError> {
        let network = NetworkId::try_from_chain_id(1).unwrap();
        let expected = expected_head(network);
        RollbackParticipantPlan::try_new(
            expected,
            CanonicalChainRef::new(network, ChainEpoch::new(7), checkpoint(90, 20)),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            9,
            [0xA5; 32],
            realms,
        )
    }

    fn expected_head(network: NetworkId) -> StoredCanonicalHead<PHash> {
        StoredCanonicalHead::decode_persisted(
            network,
            7,
            &CanonicalChainRef::new(network, ChainEpoch::new(7), checkpoint(100, 10))
                .to_canonical_bytes(),
            &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn participant_plan_roundtrips_and_drives_exact_rollback_plan_digest() {
        let plan = fixture(vec![
            RollbackRealmParticipant::new(7, 2),
            RollbackRealmParticipant::new(1, 0),
        ])
        .unwrap();
        assert_eq!(plan.participant_count(), 3);
        assert_eq!(plan.realms()[0], RollbackRealmParticipant::new(1, 0));
        assert_eq!(plan.realms()[1], RollbackRealmParticipant::new(7, 2));
        assert_eq!(plan.rollback_request().unwrap().plan_digest().as_bytes(), plan.digest());
        assert_eq!(
            RollbackParticipantPlan::decode_canonical(plan.canonical_bytes()).unwrap(),
            plan,
        );
    }

    #[test]
    fn participant_plan_rejects_empty_duplicate_and_zero_topology() {
        assert_eq!(
            fixture(Vec::new()),
            Err(RollbackParticipantPlanError::InvalidRealmCount(0)),
        );
        assert_eq!(
            fixture(vec![
                RollbackRealmParticipant::new(2, 1),
                RollbackRealmParticipant::new(2, 1),
            ]),
            Err(RollbackParticipantPlanError::DuplicateRealm),
        );

        let network = NetworkId::try_from_chain_id(1).unwrap();
        let expected = expected_head(network);
        assert_eq!(
            RollbackParticipantPlan::try_new(
                expected,
                CanonicalChainRef::new(network, ChainEpoch::new(7), checkpoint(90, 20)),
                TimestampFenceWindow::try_new(
                    CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                    1_001,
                    1_002,
                )
                .unwrap(),
                9,
                [0; 32],
                vec![RollbackRealmParticipant::new(1, 0)],
            ),
            Err(RollbackParticipantPlanError::ZeroTopologyDigest),
        );
    }

    #[test]
    fn participant_plan_codec_rejects_tamper_trailing_and_reordered_realms() {
        let plan = fixture(vec![
            RollbackRealmParticipant::new(1, 0),
            RollbackRealmParticipant::new(7, 2),
        ])
        .unwrap();
        let mut corrupt = plan.canonical_bytes().to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            RollbackParticipantPlan::<PHash>::decode_canonical(&corrupt),
            Err(RollbackParticipantPlanError::DigestMismatch),
        );
        let mut trailing = plan.canonical_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            RollbackParticipantPlan::<PHash>::decode_canonical(&trailing),
            Err(RollbackParticipantPlanError::TrailingBytes),
        );

        let realm_start = 8 + 2 + 4 + 8 + CANONICAL_CHAIN_REF_V1_LEN + 4
            + RollbackControlState::<PHash>::Idle.to_canonical_bytes().len()
            + CANONICAL_CHAIN_REF_V1_LEN
            + 24
            + 8
            + 32
            + 4;
        let mut reordered = plan.canonical_bytes().to_vec();
        let first = reordered[realm_start..realm_start + 6].to_vec();
        let second = reordered[realm_start + 6..realm_start + 12].to_vec();
        reordered[realm_start..realm_start + 6].copy_from_slice(&second);
        reordered[realm_start + 6..realm_start + 12].copy_from_slice(&first);
        let digest_start = reordered.len() - 32;
        let digest = participant_plan_digest(&reordered[..digest_start]);
        reordered[digest_start..].copy_from_slice(&digest);
        assert_eq!(
            RollbackParticipantPlan::<PHash>::decode_canonical(&reordered),
            Err(RollbackParticipantPlanError::NonCanonicalEncoding),
        );
    }

    #[test]
    fn participant_plan_grants_no_barrier_or_destructive_authority() {
        let source = include_str!("rollback_participant_plan.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains(
            "Clone, Debug, Eq, PartialEq)]\npub struct RollbackParticipantPlan",
        ));
        for forbidden in [
            "advance_archive_barrier(",
            "start_deleting(",
            "delete_hot_suffix(",
            "restore_target_head(",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }
}
